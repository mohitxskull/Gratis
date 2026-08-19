//! Integration tests for the SOCKS5 proxy engine (`gratis::socks5`).
//!
//! These tests bind the proxy to the loopback interface (`interface = "lo"`) so they run
//! without root/`CAP_NET_RAW` and without a live WireGuard interface. The SOCKS5 client side is
//! hand-rolled (raw bytes over `TcpStream`) rather than pulling in a client crate, per the task
//! brief.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Reserve a free localhost port by binding a std listener and immediately dropping it. There
/// is a small unavoidable race between reservation and the real bind, but it's fine for tests.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Spin up a trivial TCP echo server on loopback; returns its port.
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

/// A `TunnelSource` that always hands back the same loopback test tunnel (no WireGuard/root
/// involved — see `wireguard::Tunnel::loopback_for_testing`) and never tears it down —
/// `run_socks5`'s relay behavior is what's under test here, not the lazy-connect/idle-teardown
/// bookkeeping `gratis::manager::ServerSlot` layers on top in production.
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

/// Start the SOCKS5 proxy against a loopback test tunnel, returning the port it is listening
/// on.
async fn spawn_proxy() -> u16 {
    let port = free_port();
    let listen_addr = format!("127.0.0.1:{port}");
    let tunnel = std::sync::Arc::new(gratis::wireguard::Tunnel::loopback_for_testing());
    let source: std::sync::Arc<dyn gratis::socks5::TunnelSource> =
        std::sync::Arc::new(FixedTunnel(tunnel));
    tokio::spawn(async move {
        let _ = gratis::socks5::run_socks5(
            &listen_addr,
            source,
            std::sync::Arc::new(gratis::wireguard::TunnelStats::default()),
        )
        .await;
    });

    // Give the listener a moment to bind before clients try to connect.
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    port
}

/// Hand-rolled SOCKS5 no-auth handshake, returning the connected stream ready for a request.
async fn socks5_handshake(stream: &mut TcpStream) {
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00], "expected no-auth method selected");
}

/// Hand-rolled SOCKS5 CONNECT request to an IPv4 address, returning the reply's REP byte.
async fn socks5_connect(stream: &mut TcpStream, target_port: u16) -> u8 {
    socks5_request(stream, 0x01, target_port).await
}

/// Hand-rolled SOCKS5 request with an arbitrary command byte, returning the reply's REP byte.
/// Also consumes the rest of the reply (BND.ADDR/BND.PORT) so the stream is left clean.
async fn socks5_request(stream: &mut TcpStream, cmd: u8, target_port: u16) -> u8 {
    let mut req = vec![0x05, cmd, 0x00, 0x01];
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    let rep = head[1];
    let atyp = head[3];

    match atyp {
        0x01 => {
            let mut rest = [0u8; 6]; // 4-byte IPv4 + 2-byte port
            let _ = stream.read_exact(&mut rest).await;
        }
        0x04 => {
            let mut rest = [0u8; 18]; // 16-byte IPv6 + 2-byte port
            let _ = stream.read_exact(&mut rest).await;
        }
        _ => {}
    }

    rep
}

#[tokio::test]
async fn socks5_relays_tcp_and_survives_idle() {
    let echo_port = spawn_echo_server().await;
    let proxy_port = spawn_proxy().await;

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    socks5_handshake(&mut client).await;

    let rep = socks5_connect(&mut client, echo_port).await;
    assert_eq!(rep, 0x00, "CONNECT should succeed");

    // Relay data one way.
    let msg = b"hello through socks5 and back through lo";
    client.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, msg);

    // Deliberate idle gap: no traffic for a few seconds. The relay must not impose any idle
    // timeout — the connection must survive quiet periods (streaming/SSE/WebSocket safety).
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Confirm the connection is still alive and still relays correctly after the idle gap.
    let msg2 = b"still alive after idle gap";
    client.write_all(msg2).await.unwrap();
    let mut buf2 = vec![0u8; msg2.len()];
    client.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, msg2);
}

#[tokio::test]
async fn socks5_rejects_unsupported_command() {
    let echo_port = spawn_echo_server().await;
    let proxy_port = spawn_proxy().await;

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    socks5_handshake(&mut client).await;

    // BIND (0x02) is not supported.
    let rep = socks5_request(&mut client, 0x02, echo_port).await;
    assert_eq!(
        rep, 0x07,
        "BIND must be rejected with command-not-supported"
    );

    // The proxy must close the connection after rejecting the command.
    let mut buf = [0u8; 1];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(
        n, 0,
        "connection should be closed after an unsupported command"
    );
}
