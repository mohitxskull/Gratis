//! Minimal SOCKS5 proxy engine (RFC 1928), CONNECT-only, no-auth.
//!
//! Every outbound connection is opened through a live [`crate::wireguard::Tunnel`] — a
//! userspace WireGuard session, not a real network interface — so traffic egresses through
//! that tunnel regardless of the host's routing table. Domain names are resolved on the host
//! using normal (unbound) resolution; only the actual TCP connection goes through the tunnel.
//!
//! Scope, deliberately minimal:
//! - Handshake: no-auth only. We always reply with method `0x00` (no authentication required)
//!   regardless of what the client offered — this proxy is only ever reachable on
//!   loopback/localhost by a trusted local client.
//! - Commands: `CONNECT` (`0x01`) only. `BIND` (`0x02`) and `UDP ASSOCIATE` (`0x03`) are
//!   rejected with reply code `0x07` (command not supported) and the connection is closed.
//! - Address types: IPv4, IPv6, and domain name are all supported.
//! - Relay: a plain bidirectional byte pipe with **no idle timeout** — streaming / SSE /
//!   WebSocket connections with long quiet gaps must survive for as long as both ends keep the
//!   connection open.
//!
//! One instance of [`run_socks5`] is intended to be spawned per server by the tunnel manager,
//! bound for the lifetime of the process. Each accepted client connection is handled on its own
//! spawned task, so there is no artificial concurrency cap. The listener never owns a tunnel
//! directly — see [`TunnelSource`] — so it can keep accepting connections whether or not a
//! tunnel currently happens to be up.

use crate::wireguard::{SharedTunnel, TunnelStats};
use async_trait::async_trait;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SOCKS_VERSION: u8 = 0x05;

const METHOD_NO_AUTH: u8 = 0x00;

const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
/// Used specifically for [`crate::errors::ProtonError::AtCapacity`] — see `reply_code_for`.
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Opaque error from [`TunnelSource::acquire`] — boxed rather than `()` so callers (tests,
/// logs, and `reply_code_for` below) can still inspect what went wrong, even though most of
/// them map to the same generic SOCKS5 failure reply.
pub type SourceError = Box<dyn std::error::Error + Send + Sync>;

/// Which SOCKS5 reply code to send for an `acquire` failure. Almost everything gets the
/// generic `GENERAL FAILURE` (0x01) — a client has no way to act differently on a more precise
/// code for most of these anyway. The one deliberate exception is
/// [`crate::errors::ProtonError::AtCapacity`]: it gets `CONNECTION REFUSED` (0x05) instead, so
/// a client that cares (e.g. `zen-relay`, which otherwise can't tell "gratis is at its
/// MaxConnect cap right now" apart from "this exit is broken" and was mistakenly banning
/// perfectly healthy exits for hours over it) can treat the two differently.
fn reply_code_for(err: &SourceError) -> u8 {
    match err.downcast_ref::<crate::errors::ProtonError>() {
        Some(crate::errors::ProtonError::AtCapacity(_)) => REP_CONNECTION_REFUSED,
        _ => REP_GENERAL_FAILURE,
    }
}

/// Where a SOCKS5 listener gets the tunnel to relay a connection through, decoupling
/// `run_socks5`'s accept loop from how — or whether — that tunnel is already up.
/// `TunnelManager`'s per-server slot is the production implementation: `acquire` connects a
/// WireGuard tunnel on first use and reuses it for as long as at least one connection is open;
/// `release` is how the slot learns when to start its idle-teardown countdown.
#[async_trait]
pub trait TunnelSource: Send + Sync {
    /// Get a tunnel to relay this connection through, connecting one if none is currently up.
    /// Called once per accepted connection, before any bytes are relayed. Every `Ok` must be
    /// paired with exactly one later call to `release` (regardless of how the connection ends
    /// afterwards); an `Err` return is never paired with a `release` call.
    async fn acquire(&self) -> std::result::Result<SharedTunnel, SourceError>;

    /// Marks the connection the matching `acquire` call returned a tunnel for as finished.
    fn release(&self);
}

/// Calls [`TunnelSource::release`] exactly once when dropped — RAII pairing for the `acquire`
/// call that produced the tunnel this guard is holding open, so `release` still fires even if
/// the connection's handling exits early via `?` or a panic.
///
/// `pub(crate)` (not private) — `http_connect.rs` reuses this exact type rather than
/// duplicating the same RAII pairing for its own front end.
pub(crate) struct ReleaseGuard(pub(crate) Arc<dyn TunnelSource>);

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Run the SOCKS5 proxy: bind `listen_addr`, accept clients forever, and relay each `CONNECT`
/// through a tunnel obtained from `source` — lazily connected on first use, per
/// [`TunnelSource`].
///
/// This future only returns (with `Err`) if the listener fails to bind; otherwise it runs
/// forever, spawning one task per accepted connection.
pub async fn run_socks5(
    listen_addr: &str,
    source: Arc<dyn TunnelSource>,
    stats: Arc<TunnelStats>,
) -> io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;

    loop {
        let (client, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(err) => {
                // Transient accept errors (EMFILE/ENFILE/ECONNABORTED, etc.) must not take
                // down the whole listener.
                log::warn!("socks5: accept() failed, continuing to listen: {err}");
                continue;
            }
        };
        let source = source.clone();
        let stats = stats.clone();
        let label = listen_addr.to_string();
        tokio::spawn(async move {
            // Best-effort relay: an I/O error just ends this connection's task — `handle_client`
            // (via `relay`) already logs anything worth a human's attention before returning it,
            // so there's nothing more to do with the error here.
            let _ = handle_client(client, source, stats.clone(), label).await;
        });
    }
}

async fn handle_client(
    mut client: TcpStream,
    source: Arc<dyn TunnelSource>,
    stats: Arc<TunnelStats>,
    label: String,
) -> io::Result<()> {
    negotiate_method(&mut client).await?;

    let (cmd, target) = match read_request(&mut client).await {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => {
            send_reply(&mut client, REP_ADDRESS_TYPE_NOT_SUPPORTED, local_v4_zero()).await?;
            return Ok(());
        }
        Err(_) => {
            send_reply(&mut client, REP_GENERAL_FAILURE, local_v4_zero()).await?;
            return Ok(());
        }
    };

    if cmd == CMD_BIND || cmd == CMD_UDP_ASSOCIATE {
        send_reply(&mut client, REP_COMMAND_NOT_SUPPORTED, local_v4_zero()).await?;
        client.shutdown().await?;
        return Ok(());
    }

    if cmd != CMD_CONNECT {
        send_reply(&mut client, REP_COMMAND_NOT_SUPPORTED, local_v4_zero()).await?;
        client.shutdown().await?;
        return Ok(());
    }

    let addr = match resolve_target(&target).await {
        Ok(a) => a,
        Err(_) => {
            send_reply(&mut client, REP_GENERAL_FAILURE, local_v4_zero()).await?;
            return Ok(());
        }
    };

    let tunnel = match source.acquire().await {
        Ok(t) => t,
        Err(err) => {
            send_reply(&mut client, reply_code_for(&err), local_v4_zero()).await?;
            return Ok(());
        }
    };
    let _release_guard = ReleaseGuard(source);

    let outbound = match tunnel.connect_tcp(addr).await {
        Ok(c) => c,
        Err(_) => {
            send_reply(&mut client, REP_GENERAL_FAILURE, local_v4_zero()).await?;
            return Ok(());
        }
    };

    send_reply(&mut client, REP_SUCCEEDED, local_v4_zero()).await?;

    relay(client, outbound, stats, &label).await
}

/// The target of a `CONNECT` request: either an already-resolved socket address, or a
/// domain name + port to be resolved on the host.
enum Target {
    Addr(SocketAddr),
    Domain(String, u16),
}

/// RFC 1928 method negotiation. We always select "no authentication required" (`0x00`),
/// regardless of what the client offered — see module docs.
async fn negotiate_method(client: &mut TcpStream) -> io::Result<()> {
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;
    let nmethods = header[1] as usize;

    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    client.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
    Ok(())
}

/// Read a SOCKS5 request (VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT) and return the command byte
/// plus the parsed target.
async fn read_request(client: &mut TcpStream) -> io::Result<(u8, Target)> {
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    let (ver, cmd, _rsv, atyp) = (head[0], head[1], head[2], head[3]);

    if ver != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SOCKS version",
        ));
    }

    let target = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await?;
            let ip = IpAddr::V4(Ipv4Addr::from(buf));
            let port = read_port(client).await?;
            Target::Addr(SocketAddr::new(ip, port))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            client.read_exact(&mut buf).await?;
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(buf));
            let port = read_port(client).await?;
            Target::Addr(SocketAddr::new(ip, port))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; len];
            client.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8(domain_buf)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad domain"))?;
            let port = read_port(client).await?;
            Target::Domain(domain, port)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "unsupported address type",
            ));
        }
    };

    Ok((cmd, target))
}

async fn read_port(client: &mut TcpStream) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

async fn resolve_target(target: &Target) -> io::Result<SocketAddr> {
    match target {
        Target::Addr(addr) => Ok(*addr),
        Target::Domain(domain, port) => {
            // Normal (unbound) resolution on the host — the tunnel's own DNS path returns a
            // diagnostic "MTU Probe" message rather than real answers (verified live), so
            // domain names are resolved outside the tunnel; only the TCP connection itself
            // goes through it.
            let mut addrs = tokio::net::lookup_host((domain.as_str(), *port)).await?;
            addrs
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses resolved"))
        }
    }
}

async fn send_reply(client: &mut TcpStream, rep: u8, bound: SocketAddr) -> io::Result<()> {
    let mut buf = vec![SOCKS_VERSION, rep, 0x00];
    match bound {
        SocketAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    client.write_all(&buf).await?;
    Ok(())
}

fn local_v4_zero() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

/// Bidirectional byte relay with **no idle timeout**, between the real client `TcpStream` and
/// a [`crate::wireguard::TunnelConnection`] through the tunnel.
///
/// `TunnelConnection` isn't `AsyncRead`/`AsyncWrite`, so this is a manual pump rather than
/// `tokio::io::copy_bidirectional`, but the streaming-safety property is the same: no timeout
/// is ever applied to either direction, so quiet gaps (SSE/WebSocket) don't kill the relay.
///
/// Ends as soon as **either** direction finishes — deliberately not full-duplex half-close
/// aware, which would be wrong for general-purpose TCP but is *correct* for what this actually
/// proxies: one `zen-relay` HTTP request/response pair per connection. A normal HTTP client
/// never half-closes its write side mid-request while still waiting on the response — it keeps
/// the whole socket open until the exchange is fully done — so if `to_tunnel` (client → tunnel)
/// ends before `to_client` (tunnel → client) does, that only means the client's connection is
/// actually gone (its own request timeout fired, it crashed, whatever), not that it finished
/// sending and is patiently waiting to read. In that case there is no one left to deliver
/// `to_client`'s bytes to, so continuing to wait on it just leaks the connection.
///
/// That leak was real, not theoretical: `to_client` reads via
/// [`crate::wireguard::TunnelConnection::read`], which retries past the underlying crate's
/// internal `ReadTimeout` indefinitely (see that method's doc comment) so a merely-slow upstream
/// (a "thinking" LLM response) isn't mistaken for a dead one. Combined with the previous
/// `tokio::join!`, which waits for *both* directions unconditionally, an abandoned client left
/// `to_client` spinning forever waiting for a tunnel that was still alive but simply had nothing
/// to send yet — never returning, never releasing its connection slot. Confirmed live:
/// connections piled up on exits nobody was using anymore, which then made every *new* request
/// landing on the same exit slower for no reason (see
/// `releases_the_connection_promptly_when_the_client_disconnects_mid_relay` in
/// `tests/socks5_relay.rs`).
///
/// Byte counts are tracked in shared atomics rather than returned from the futures themselves,
/// since `select!` drops whichever one loses the race mid-flight — its local state would
/// otherwise be lost and the log below would have no count for that side.
///
/// `pub(crate)` — `http_connect.rs`'s front end reuses this verbatim rather than reimplementing
/// the same leak-safety/logging behavior for its own protocol.
pub(crate) async fn relay(
    client: TcpStream,
    outbound: Box<dyn crate::wireguard::TunnelConnection>,
    stats: Arc<TunnelStats>,
    label: &str,
) -> io::Result<()> {
    let started = std::time::Instant::now();
    let (mut client_rd, mut client_wr) = client.into_split();
    let sent = std::sync::atomic::AtomicU64::new(0);
    let received = std::sync::atomic::AtomicU64::new(0);

    let to_tunnel = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = client_rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            outbound.write_all(&buf[..n]).await?;
            stats.add_sent(n as u64);
            sent.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        outbound.shutdown();
        Ok::<(), io::Error>(())
    };

    let to_client = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = outbound.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_wr.write_all(&buf[..n]).await?;
            stats.add_received(n as u64);
            received.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        let _ = client_wr.shutdown().await;
        Ok::<(), io::Error>(())
    };

    tokio::pin!(to_tunnel);
    tokio::pin!(to_client);

    let (result, which) = tokio::select! {
        result = &mut to_tunnel => (result, "client->tunnel"),
        result = &mut to_client => (result, "tunnel->client"),
    };

    let sent = sent.load(std::sync::atomic::Ordering::Relaxed);
    let received = received.load(std::sync::atomic::Ordering::Relaxed);

    match &result {
        Ok(()) => log::debug!(
            "{label}: relay closed cleanly ({which} finished first), sent {sent} \
             byte(s)/received {received} byte(s) in {:?}",
            started.elapsed()
        ),
        Err(err) => log::warn!(
            "{label}: relay ended with an error on {which} after sent {sent} byte(s)/received \
             {received} byte(s) in {:?}: {err}",
            started.elapsed()
        ),
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ProtonError;

    #[test]
    fn at_capacity_gets_connection_refused_not_general_failure() {
        let err: SourceError = Box::new(ProtonError::AtCapacity("max reached".into()));
        assert_eq!(reply_code_for(&err), REP_CONNECTION_REFUSED);
    }

    #[test]
    fn every_other_error_gets_the_generic_general_failure() {
        let err: SourceError = Box::new(ProtonError::Config("tunnel connect failed".into()));
        assert_eq!(reply_code_for(&err), REP_GENERAL_FAILURE);
    }

    #[test]
    fn an_error_that_isnt_a_protonerror_at_all_also_gets_general_failure() {
        let err: SourceError = Box::new(io::Error::other("boom"));
        assert_eq!(reply_code_for(&err), REP_GENERAL_FAILURE);
    }
}
