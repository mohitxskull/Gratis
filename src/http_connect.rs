//! HTTP CONNECT proxy front end (RFC 7231 §4.3.6) — opt-in alternative to the default SOCKS5
//! listener (`socks5.rs`), toggled per-daemon by `gratis up --http-proxy`. Same tunnel/relay
//! machinery underneath (`TunnelSource`, `socks5::relay`) — only the front-end handshake
//! differs: parse a `CONNECT host:port HTTP/1.1` request line + headers instead of SOCKS5's
//! binary framing, and reply with an HTTP status line instead of a SOCKS5 reply byte. Exists
//! because some clients (and some frameworks, e.g. Pingora's `Peer::proxy`) only speak HTTP
//! CONNECT for proxying, not SOCKS5.
//!
//! Scope, deliberately minimal, matching `socks5.rs`:
//! - `CONNECT` only. Any other method gets `405 Method Not Allowed`.
//! - No `Proxy-Authenticate` — this proxy is only ever reachable on loopback by a trusted local
//!   client, same rationale as `socks5.rs`'s no-auth SOCKS5 handshake.
//! - The CONNECT request's own headers (besides the request line) are read and discarded, never
//!   relayed — correct per RFC 7231: they're for the proxy, not the tunnel.
//! - Relay: identical no-idle-timeout guarantee as `socks5.rs`, since it's the exact same
//!   `relay()` function underneath.

use crate::socks5::{ReleaseGuard, SourceError, TunnelSource, relay};
use crate::wireguard::TunnelStats;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Run the HTTP CONNECT proxy: bind `listen_addr`, accept clients forever, and relay each
/// `CONNECT` through a tunnel obtained from `source` — lazily connected on first use, per
/// [`TunnelSource`]. Mirrors [`crate::socks5::run_socks5`] exactly; see that function's doc
/// comment for the accept-loop/error-handling rationale, which is identical here.
pub async fn run_http_connect(
    listen_addr: &str,
    source: Arc<dyn TunnelSource>,
    stats: Arc<TunnelStats>,
) -> io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    let label = listen_addr.to_string();

    loop {
        let (client, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(err) => {
                log::warn!("http-connect: accept() failed, continuing to listen: {err}");
                continue;
            }
        };
        let source = source.clone();
        let stats = stats.clone();
        let label = label.clone();
        tokio::spawn(async move {
            // Best-effort relay, same as socks5.rs: `relay()` already logs anything worth a
            // human's attention before returning, so there's nothing more to do with the error
            // here.
            let _ = handle_client(client, source, stats, label).await;
        });
    }
}

async fn handle_client(
    mut client: TcpStream,
    source: Arc<dyn TunnelSource>,
    stats: Arc<TunnelStats>,
    label: String,
) -> io::Result<()> {
    let target = match read_connect_request(&mut client).await {
        Ok(RequestLine::Connect(target)) => target,
        Ok(RequestLine::OtherMethod) => {
            send_status(&mut client, 405, "Method Not Allowed").await?;
            return Ok(());
        }
        Err(_) => {
            send_status(&mut client, 400, "Bad Request").await?;
            return Ok(());
        }
    };

    let addr = match resolve_target(&target).await {
        Ok(a) => a,
        Err(_) => {
            send_status(&mut client, 502, "Bad Gateway").await?;
            return Ok(());
        }
    };

    let tunnel = match source.acquire().await {
        Ok(t) => t,
        Err(err) => {
            let (code, reason) = status_for(&err);
            send_status(&mut client, code, reason).await?;
            return Ok(());
        }
    };
    let _release_guard = ReleaseGuard(source);

    let outbound = match tunnel.connect_tcp(addr).await {
        Ok(c) => c,
        Err(_) => {
            send_status(&mut client, 502, "Bad Gateway").await?;
            return Ok(());
        }
    };

    send_status(&mut client, 200, "Connection Established").await?;

    relay(client, outbound, stats, &label).await
}

enum RequestLine {
    Connect(String),
    OtherMethod,
}

/// Reads exactly through the blank line ending the request's headers, one byte at a time.
///
/// Deliberately byte-by-byte rather than a buffered/line reader: a buffered reader can read
/// past the header terminator into whatever the client sends immediately after (a client that
/// doesn't wait for the `200` before starting to send tunnel bytes) — those bytes would then be
/// stuck in the buffer instead of reaching `relay()`, silently corrupting/truncating the start
/// of the tunneled stream. One byte at a time guarantees we stop reading at exactly the
/// boundary this protocol defines, at the cost of more syscalls for a request line that's only
/// ever a few hundred bytes.
async fn read_connect_request(client: &mut TcpStream) -> io::Result<RequestLine> {
    const MAX_HEADER_BYTES: usize = 8192;

    let mut buf = Vec::with_capacity(256);
    let mut window = [0u8; 4];
    loop {
        let mut byte = [0u8; 1];
        let n = client.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before headers finished",
            ));
        }
        buf.push(byte[0]);
        window.rotate_left(1);
        window[3] = byte[0];
        if &window == b"\r\n\r\n" {
            break;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers too large",
            ));
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let request_line = text.lines().next().unwrap_or("");
    // A well-formed request line is exactly `METHOD TARGET HTTP-VERSION` — three tokens, no
    // more, no fewer. Checking only "is there a method and *something* after it" (an earlier,
    // less strict version of this parser) let `CONNECT HTTP/1.1` — method plus the HTTP version
    // with no real target in between — through as if `HTTP/1.1` were the target, which then
    // failed confusingly at DNS resolution instead of being rejected here as the malformed
    // request it actually is.
    let tokens: Vec<&str> = request_line.split_whitespace().collect();
    let [method, target, _version] = tokens[..] else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    };

    if !method.eq_ignore_ascii_case("CONNECT") {
        return Ok(RequestLine::OtherMethod);
    }
    Ok(RequestLine::Connect(target.to_string()))
}

/// `target` is `host:port`, per RFC 7231's CONNECT request-target — resolved the same way (and
/// for the same reason) as `socks5.rs`'s own domain resolution: on the host, not through the
/// tunnel.
async fn resolve_target(target: &str) -> io::Result<SocketAddr> {
    let (host, port) = target.rsplit_once(':').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "CONNECT target missing a port")
    })?;
    let port: u16 = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CONNECT target has a bad port"))?;
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    addrs
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses resolved"))
}

/// Which HTTP status to reply with for a [`TunnelSource::acquire`] failure. Mirrors
/// `socks5.rs`'s `reply_code_for`'s one deliberate special case: `AtCapacity` (gratis's own
/// `MaxConnect` cap, not the exit itself being broken) gets `503 Service Unavailable` — a
/// client-recognizable "try again shortly" — instead of the generic `502 Bad Gateway` everything
/// else gets.
fn status_for(err: &SourceError) -> (u16, &'static str) {
    match err.downcast_ref::<crate::errors::ProtonError>() {
        Some(crate::errors::ProtonError::AtCapacity(_)) => (503, "Service Unavailable"),
        _ => (502, "Bad Gateway"),
    }
}

async fn send_status(client: &mut TcpStream, code: u16, reason: &str) -> io::Result<()> {
    let response = format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\n\r\n");
    client.write_all(response.as_bytes()).await
}
