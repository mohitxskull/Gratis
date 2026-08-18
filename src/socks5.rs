//! Minimal SOCKS5 proxy engine (RFC 1928), CONNECT-only, no-auth.
//!
//! The proxy is interface-pinned: every *outbound* TCP connection it opens on behalf of a
//! client is bound to a specific network interface (typically a WireGuard interface) via
//! `SO_BINDTODEVICE`, so traffic egresses through that tunnel regardless of routing table
//! state. Domain names are resolved on the host using normal (unbound) resolution — only the
//! outbound connect socket itself is interface-bound.
//!
//! Scope, deliberately minimal:
//! - Handshake: no-auth only. We always reply with method `0x00` (no authentication required)
//!   regardless of what the client offered, per the brief's "no-auth simplification" — this
//!   keeps the handshake trivial and matches the fact that this proxy is only ever reachable
//!   on loopback/localhost by a trusted local client (the daemon's own consumers).
//! - Commands: `CONNECT` (`0x01`) only. `BIND` (`0x02`) and `UDP ASSOCIATE` (`0x03`) are
//!   rejected with reply code `0x07` (command not supported) and the connection is closed.
//! - Address types: IPv4, IPv6, and domain name are all supported.
//! - Relay: a plain bidirectional byte pipe with **no idle timeout** — streaming / SSE /
//!   WebSocket connections with long quiet gaps must survive for as long as both ends keep the
//!   TCP connection open.
//!
//! One instance of [`run_socks5`] is intended to be spawned per WireGuard location by the
//! tunnel manager (see Task 05). Each accepted client connection is handled on its own spawned
//! task, so there is no artificial concurrency cap.

use socket2::{Domain, Protocol, Socket, Type};
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
/// through an outbound socket bound to `interface`.
///
/// This future only returns (with `Err`) if the listener fails to bind; otherwise it runs
/// forever, spawning one task per accepted connection.
pub async fn run_socks5(listen_addr: &str, interface: &str) -> io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;

    loop {
        let (client, _peer) = listener.accept().await?;
        let interface = interface.to_string();
        tokio::spawn(async move {
            if let Err(_err) = handle_client(client, &interface).await {
                // Best-effort relay: any I/O error just ends this connection's task. Nothing
                // else in the process depends on a single client connection's outcome.
            }
        });
    }
}

async fn handle_client(mut client: TcpStream, interface: &str) -> io::Result<()> {
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

    let outbound = match dial_via_interface(addr, interface).await {
        Ok(s) => s,
        Err(_) => {
            send_reply(&mut client, REP_GENERAL_FAILURE, local_v4_zero()).await?;
            return Ok(());
        }
    };

    let bound = outbound.local_addr().unwrap_or_else(|_| local_v4_zero());
    send_reply(&mut client, REP_SUCCEEDED, bound).await?;

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
            // Normal (unbound) resolution on the host — only the outbound connect socket is
            // pinned to the tunnel interface.
            let mut addrs = tokio::net::lookup_host((domain.as_str(), *port)).await?;
            addrs
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses resolved"))
        }
    }
}

/// Open an outbound TCP connection to `addr`, bound to `interface` via `SO_BINDTODEVICE`, so
/// the connection egresses through that interface (typically a WireGuard tunnel).
///
/// The blocking `socket2` connect happens on a `spawn_blocking` thread so it never stalls a
/// tokio worker thread.
async fn dial_via_interface(addr: SocketAddr, interface: &str) -> io::Result<TcpStream> {
    let interface = interface.to_string();
    let std_stream = tokio::task::spawn_blocking(move || -> io::Result<std::net::TcpStream> {
        let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
        sock.bind_device(Some(interface.as_bytes()))?; // SO_BINDTODEVICE (needs CAP_NET_RAW)
        sock.connect(&addr.into())?;
        sock.set_nonblocking(true)?;
        Ok(sock.into())
    })
    .await
    .map_err(io::Error::other)??;

    TcpStream::from_std(std_stream)
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

/// Bidirectional byte relay with **no idle timeout**. Streaming / SSE / WebSocket connections
/// must survive arbitrarily long quiet gaps as long as both TCP endpoints stay open.
async fn relay(mut client: TcpStream, mut outbound: TcpStream) -> io::Result<()> {
    match tokio::io::copy_bidirectional(&mut client, &mut outbound).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}
