//! Integration tests for the HTTP CONNECT proxy front end (`gratis::http_connect`) — the
//! opt-in alternative to the default SOCKS5 listener (`gratis up --http-proxy`). Same structure
//! as `tests/socks5_relay.rs`: real sockets, real bytes relayed through a loopback test tunnel,
//! hand-rolled client side (raw HTTP over `TcpStream`) rather than pulling in a client crate.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

async fn spawn_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });

    port
}

struct FixedTunnel(gratis::wireguard::SharedTunnel);

#[async_trait::async_trait]
impl gratis::socks5::TunnelSource for FixedTunnel {
    async fn acquire(
        &self,
    ) -> Result<gratis::wireguard::SharedTunnel, gratis::socks5::SourceError> {
        Ok(self.0.clone())
    }

    fn release(&self) {}
}

async fn spawn_proxy() -> u16 {
    let port = free_port();
    let listen_addr = format!("127.0.0.1:{port}");
    let tunnel = std::sync::Arc::new(gratis::wireguard::Tunnel::loopback_for_testing());
    let source: std::sync::Arc<dyn gratis::socks5::TunnelSource> =
        std::sync::Arc::new(FixedTunnel(tunnel));
    tokio::spawn(async move {
        let _ = gratis::http_connect::run_http_connect(
            &listen_addr,
            source,
            std::sync::Arc::new(gratis::wireguard::TunnelStats::default()),
        )
        .await;
    });

    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    port
}

/// Hand-rolled HTTP CONNECT request, returning the response's status code.
async fn http_connect(stream: &mut TcpStream, target_port: u16) -> u16 {
    let req = format!(
        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    // Read up to the blank line ending the response headers, byte by byte so we don't overread
    // into whatever the relay sends next (mirrors how the server itself must parse CONNECT).
    let mut buf = Vec::new();
    let mut window = [0u8; 4];
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        buf.push(byte[0]);
        window.rotate_left(1);
        window[3] = byte[0];
        if &window == b"\r\n\r\n" {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let status_line = text.lines().next().unwrap();
    // "HTTP/1.1 200 Connection Established" -> 200
    status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn http_connect_relays_tcp_and_survives_idle() {
    let echo_port = spawn_echo_server().await;
    let proxy_port = spawn_proxy().await;

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let status = http_connect(&mut client, echo_port).await;
    assert_eq!(status, 200, "CONNECT should succeed with 200");

    let msg = b"hello through http connect and back through lo";
    client.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, msg);

    // No idle timeout, matching socks5.rs's same guarantee — a quiet gap must not kill the
    // relay (streaming/SSE/WebSocket safety).
    tokio::time::sleep(Duration::from_secs(3)).await;

    let msg2 = b"still alive after idle gap";
    client.write_all(msg2).await.unwrap();
    let mut buf2 = vec![0u8; msg2.len()];
    client.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, msg2);
}

#[tokio::test]
async fn a_non_connect_method_is_rejected_with_405() {
    let proxy_port = spawn_proxy().await;
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();

    let mut buf = [0u8; 64];
    // Matches the 400 test below's use of `timeout` — a server-side hang here would otherwise
    // hang the whole test suite instead of failing this one test fast.
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("must not hang on a non-CONNECT method")
        .unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(
        text.starts_with("HTTP/1.1 405"),
        "expected a 405 response, got: {text}"
    );
}

/// Mirrors `tests/socks5_relay.rs`'s equivalent — the upstream-refuses path is where a hang or
/// unhandled `Err` is most likely to hide. Slow (~5s): see that test's doc comment for why
/// (integration tests link the production, non-shortened `TCP_CONNECT_RETRY_BUDGET`).
#[tokio::test]
async fn http_connect_reports_502_when_the_upstream_refuses() {
    let dead_port = free_port();
    let proxy_port = spawn_proxy().await;
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

    let status = tokio::time::timeout(
        Duration::from_secs(10),
        http_connect(&mut client, dead_port),
    )
    .await
    .expect("connect_tcp must give up within its retry budget, not hang forever");
    assert_eq!(
        status, 502,
        "CONNECT to a refusing upstream must report Bad Gateway, not success"
    );

    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("connection must be closed promptly after a failure reply")
        .unwrap();
    assert_eq!(n, 0, "connection should be closed after a failed CONNECT");
}

#[tokio::test]
async fn a_malformed_request_is_rejected_with_400_not_a_hang() {
    let proxy_port = spawn_proxy().await;
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();

    // No target at all after the method.
    client.write_all(b"CONNECT HTTP/1.1\r\n\r\n").await.unwrap();

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("must not hang on a malformed request")
        .unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(
        text.starts_with("HTTP/1.1 400"),
        "expected a 400 response, got: {text}"
    );
}
