//! WireGuard tunnel config tests, updated for the userspace WireGuard redesign (no more
//! `sudo wg-quick`/text config generation — see `wireguard.rs`'s doc comment for why). No root
//! privileges and no live WireGuard interface are required.
use gratis::models::{PhysicalServer, VPNCredentials, VPNServer};
use gratis::wireguard::{CLIENT_ADDRESS, Tunnel};

const TEST_CERT_PEM: &str =
    "-----BEGIN CERTIFICATE-----\ntest-only-placeholder\n-----END CERTIFICATE-----";

fn test_server() -> VPNServer {
    VPNServer {
        id: "srv-1".into(),
        name: "US-FREE#1".into(),
        country: "United States".into(),
        country_code: "US".into(),
        city: None,
        tier: 0,
        load: 12.0,
        features: vec![],
        status: 1,
        physical: vec![PhysicalServer {
            entry_ip: "203.0.113.9".into(),
            domain: "node1.us.protonvpn.net".into(),
            x25519_public_key: "SERVERPUBKEYBASE64==".into(),
            enabled: true,
        }],
    }
}

fn test_creds() -> VPNCredentials {
    VPNCredentials {
        username: "testuser".into(),
        ed25519_seed_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        wg_public_key: "CLIENTPUBKEYBASE64==".into(),
        wg_private_key: "CLIENTPRIVKEYBASE64==".into(),
        certificate: TEST_CERT_PEM.into(),
        certificate_expires_at: 9_999_999_999,
    }
}

#[test]
fn client_address_is_the_fixed_proton_address() {
    // Verified against proton.vpn.backend.networkmanager.protocol.wireguard.wireguard:
    // every Proton WireGuard connection uses this fixed address, never anything derived
    // per-account or per-connection.
    assert_eq!(CLIENT_ADDRESS, "10.2.0.2");
    // `Tunnel::connect` parses this with `.expect(...)` rather than propagating a `Result` —
    // tolerable only because it's a fixed literal, never user input. Lock that assumption with
    // a test rather than discovering a typo via a runtime panic.
    assert!(
        CLIENT_ADDRESS.parse::<std::net::Ipv4Addr>().is_ok(),
        "CLIENT_ADDRESS must always be a valid IPv4 literal — Tunnel::connect expect()s this"
    );
}

#[tokio::test]
async fn tunnel_connect_errors_without_a_physical_server() {
    let mut server = test_server();
    server.physical.clear();
    let creds = test_creds();

    let Err(err) = Tunnel::connect(&server, &creds).await else {
        panic!("expected an error")
    };
    assert!(format!("{err}").contains("no physical servers"));
}

#[tokio::test]
async fn tunnel_connect_errors_on_malformed_key() {
    let server = test_server();
    let mut creds = test_creds();
    creds.wg_private_key = "not valid base64!!".into();

    let Err(err) = Tunnel::connect(&server, &creds).await else {
        panic!("expected an error")
    };
    assert!(format!("{err}").contains("invalid base64 key"));
}

/// `connect_tcp` retries a failed attempt internally (see `wireguard.rs`'s
/// `TCP_CONNECT_RETRY_BUDGET` doc comment for why: a fresh WireGuard tunnel needs a brief
/// settling window before it reliably passes traffic, verified live against a real `gratis`
/// daemon). This proves that retry actually recovers, using a real TCP listener that only
/// starts accepting after a short delay to stand in for that settling window.
///
/// This is an integration test (not a `src/`-level unit test), so it links a normal
/// (non-`cfg(test)`) build of the library — `TCP_CONNECT_RETRY_BUDGET` here is the real
/// production value, not the shortened one `cargo test --lib` sees. Timings below are sized
/// for that.
#[tokio::test]
async fn loopback_connect_tcp_retries_past_a_transient_refusal() {
    // Reserve a port, then release it immediately — for a moment after this, connecting to it
    // is refused (nothing listening), exactly like a tunnel whose data path isn't ready yet.
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = reserved.local_addr().unwrap();
    drop(reserved);

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        if let Ok(listener) = tokio::net::TcpListener::bind(addr).await {
            let _ = listener.accept().await;
        }
    });

    let result = Tunnel::loopback_for_testing().connect_tcp(addr).await;
    assert!(
        result.is_ok(),
        "a connect that's refused before the listener comes up must still succeed once it does, \
         within the retry budget"
    );
}

/// The other half of the same guarantee: `connect_tcp` must not retry forever when nothing is
/// ever going to answer. See the note on the sibling test above about production-scale timing.
#[tokio::test]
async fn loopback_connect_tcp_gives_up_when_nothing_ever_listens() {
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = reserved.local_addr().unwrap();
    drop(reserved); // nothing listens on `addr` from here on

    let started = std::time::Instant::now();
    let result = Tunnel::loopback_for_testing().connect_tcp(addr).await;
    assert!(
        result.is_err(),
        "a genuinely dead target must eventually fail, not hang forever"
    );
    // Generous upper bound: this only needs to prove the wait is actually bounded, not pin the
    // exact production retry budget.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(15),
        "must give up promptly rather than exhausting some much larger budget"
    );
}
