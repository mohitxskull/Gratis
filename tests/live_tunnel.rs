//! Live end-to-end test against a real Proton account: login -> connect straight to a server's
//! assigned SOCKS5 port (which lazily brings its tunnel up) -> real HTTP request through it ->
//! assert a real response comes back.
//!
//! Requires a `.env` file (repo root) with `EMAIL=...`/`PASSWORD=...` for a real Proton
//! account, real network access, and is NOT run by default `cargo test` (marked `#[ignore]`,
//! and skips with a clear message if `.env` is absent even when explicitly requested) — it
//! makes real login/network calls against Proton's production API and a real Proton VPN
//! account, which is inappropriate for a normal CI/dev-loop test run.
//!
//! Run explicitly with: `cargo test --test live_tunnel -- --ignored --nocapture`
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn read_dotenv_var(key: &str) -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    let content = std::fs::read_to_string(path).ok()?;
    content
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")).map(str::to_string))
}

/// Minimal blocking SOCKS5 client: no-auth handshake + CONNECT to `target`, then relays a
/// plain HTTP GET and returns the raw response bytes. Blocking `std::net` (not tokio) so the
/// test body reads top-to-bottom without async ceremony — this is a one-shot diagnostic/
/// regression check, not a throughput test.
fn socks5_http_get(
    proxy_addr: &str,
    target_ip: [u8; 4],
    target_port: u16,
    host_header: &str,
) -> Vec<u8> {
    let mut sock = TcpStream::connect(proxy_addr).expect("connect to socks5 proxy");
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();

    // Method negotiation: no-auth.
    sock.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).unwrap();
    assert_eq!(resp, [0x05, 0x00], "expected no-auth method selected");

    // CONNECT request to the raw IPv4 target (no domain resolution involved, isolating the
    // relay/tunnel path from DNS).
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&target_ip);
    req.extend_from_slice(&target_port.to_be_bytes());
    sock.write_all(&req).unwrap();

    let mut head = [0u8; 4];
    sock.read_exact(&mut head).unwrap();
    assert_eq!(head[1], 0x00, "CONNECT should succeed");
    let mut rest = [0u8; 6]; // IPv4 BND.ADDR + BND.PORT
    sock.read_exact(&mut rest).unwrap();

    // Real HTTP GET through the relay.
    let request =
        format!("GET /?format=json HTTP/1.0\r\nHost: {host_header}\r\nConnection: close\r\n\r\n");
    sock.write_all(request.as_bytes()).unwrap();

    let mut response = Vec::new();
    sock.read_to_end(&mut response).unwrap();
    response
}

#[tokio::test]
#[ignore = "requires .env with real Proton credentials + real network access"]
async fn live_tunnel_relays_real_http_request() {
    let Some(email) = read_dotenv_var("EMAIL") else {
        eprintln!("skipping: no .env with EMAIL/PASSWORD found");
        return;
    };
    let password = read_dotenv_var("PASSWORD").expect(".env has EMAIL but no PASSWORD");

    let manager = gratis::manager::TunnelManager::new(19900, false, false);
    println!("logging in...");
    manager.login(&email, &password).await.expect("login");
    // `login()` already assigned every free-tier server a port and spawned its listener (see
    // `TunnelManager::login`) — nothing further to wire up. Pick the first US server's port;
    // connecting to it below is what lazily brings its tunnel up.
    let socks_port = manager
        .servers()
        .into_iter()
        .find(|s| s.country_code.eq_ignore_ascii_case("US"))
        .expect("at least one US server in the free-tier list")
        .port;
    println!("US server assigned port 127.0.0.1:{socks_port}");

    // api.ipify.org's resolved IP, hardcoded to isolate the relay/tunnel path from this
    // environment's flaky DNS resolver (verified separately as a live-account concern, not
    // a gratis one).
    let target_ip = [104, 26, 12, 205];

    println!("sending real HTTP GET through the SOCKS5 proxy...");
    let response = tokio::task::spawn_blocking(move || {
        socks5_http_get(
            &format!("127.0.0.1:{socks_port}"),
            target_ip,
            80,
            "api.ipify.org",
        )
    })
    .await
    .expect("blocking task panicked");

    let response_text = String::from_utf8_lossy(&response);
    println!(
        "=== response ({} bytes) ===\n{response_text}",
        response.len()
    );

    assert!(
        response_text.starts_with("HTTP/1."),
        "expected a real HTTP response, got: {response_text:?}"
    );
    assert!(
        response_text.contains("\"ip\":"),
        "expected api.ipify.org's JSON body, got: {response_text:?}"
    );
}
