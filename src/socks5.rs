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
//! One instance of [`run_socks5`] is intended to be spawned per WireGuard location by the
//! tunnel manager. Each accepted client connection is handled on its own spawned task, so
//! there is no artificial concurrency cap.

use crate::wireguard::SharedTunnel;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Run the SOCKS5 proxy: bind `listen_addr`, accept clients forever, and relay each `CONNECT`
/// through `tunnel`.
///
/// This future only returns (with `Err`) if the listener fails to bind; otherwise it runs
/// forever, spawning one task per accepted connection.
pub async fn run_socks5(listen_addr: &str, tunnel: SharedTunnel) -> io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;

    loop {
        let (client, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(err) => {
                // Transient accept errors (EMFILE/ENFILE/ECONNABORTED, etc.) must not take
                // down the whole listener.
                eprintln!("socks5: accept() failed, continuing to listen: {err}");
                continue;
            }
        };
        let tunnel = tunnel.clone();
        tokio::spawn(async move {
            if let Err(_err) = handle_client(client, tunnel).await {
                // Best-effort relay: any I/O error just ends this connection's task.
            }
        });
    }
}

async fn handle_client(mut client: TcpStream, tunnel: SharedTunnel) -> io::Result<()> {
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

    let outbound = match tunnel.connect_tcp(addr).await {
        Ok(c) => c,
        Err(_) => {
            send_reply(&mut client, REP_GENERAL_FAILURE, local_v4_zero()).await?;
            return Ok(());
        }
    };

    send_reply(&mut client, REP_SUCCEEDED, local_v4_zero()).await?;

    relay(client, outbound).await
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
async fn relay(
    client: TcpStream,
    outbound: Box<dyn crate::wireguard::TunnelConnection>,
) -> io::Result<()> {
    let (mut client_rd, mut client_wr) = client.into_split();

    let to_tunnel = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = client_rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            outbound.write_all(&buf[..n]).await?;
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
        }
        let _ = client_wr.shutdown().await;
        Ok::<(), io::Error>(())
    };

    let _ = tokio::join!(to_tunnel, to_client);
    Ok(())
}
