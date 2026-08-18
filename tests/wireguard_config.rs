//! WireGuard config generation + active-tunnel state persistence tests (Task 03, updated
//! after live-account verification revealed the original server-list/credential model was
//! wrong — see `models.rs`/`wireguard.rs` doc comments for what changed and why).
//!
//! No root privileges and no live WireGuard interface are required: these tests exercise
//! `generate_config`'s output string and the SQLite-backed `credentials::Store` directly,
//! against a tempdir DB path (never the real `~/.config/proton-proxy/` directory).
use proton_proxy::credentials::Store;
use proton_proxy::models::{PhysicalServer, VPNCredentials, VPNServer};
use proton_proxy::wireguard::{CLIENT_ADDRESS, WG_PORT, generate_config, interface_name};

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
            // Deliberately distinct from `entry_ip` so a test that accidentally reads the
            // wrong field is caught immediately.
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
fn config_has_correct_peer_public_key_not_ip() {
    let server = test_server();
    let creds = test_creds();
    let iface = interface_name("us");

    let config = generate_config(&server, &creds, &iface).expect("generate_config");

    assert!(
        config.contains("PublicKey = SERVERPUBKEYBASE64=="),
        "config must use the physical server's real X25519 pubkey field:\n{config}"
    );
    assert!(
        !config.contains("PublicKey = 203.0.113.9"),
        "config must NEVER use entry_ip as the peer public key:\n{config}"
    );
    assert!(
        config.contains(&format!("Endpoint = 203.0.113.9:{WG_PORT}")),
        "Endpoint must be the picked physical server's entry_ip:{WG_PORT}:\n{config}"
    );
    assert!(
        config.contains("AllowedIPs = 0.0.0.0/0, ::/0"),
        "AllowedIPs must route everything through the tunnel:\n{config}"
    );
    assert!(
        config.contains("Table = off"),
        "this is a split tunnel: Table = off must be present:\n{config}"
    );
}

#[test]
fn config_uses_fixed_client_address() {
    // Flagged gap #3's earlier resolution (deriving the client address from the account
    // certificate's X.509 SAN) was a best-effort guess made without a live account. Verified
    // against a live login + the official client's source: every Proton WireGuard connection
    // uses the same fixed address, not anything derived per-account.
    let server = test_server();
    let creds = test_creds();
    let iface = interface_name("us");

    let config = generate_config(&server, &creds, &iface).expect("generate_config");

    assert_eq!(CLIENT_ADDRESS, "10.2.0.2");
    assert!(
        config.contains("Address = 10.2.0.2/32"),
        "[Interface] Address must be the fixed CLIENT_ADDRESS:\n{config}"
    );
    assert!(
        !config.contains("Address = 10.8.0.1"),
        "config must not fall back to the old hardcoded 10.8.0.1/24:\n{config}"
    );
}

#[test]
fn generate_config_errors_without_a_physical_server() {
    let mut server = test_server();
    server.physical.clear();
    let creds = test_creds();
    let iface = interface_name("us");

    let err = generate_config(&server, &creds, &iface).unwrap_err();
    assert!(format!("{err}").contains("no physical servers"));
}

#[test]
fn active_connection_state_persist_and_clear() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("proton-proxy.db");
    let store = Store::open(&db_path).expect("open store");

    // No active tunnels initially.
    assert!(store.list_active().unwrap().is_empty());

    store
        .set_active("us", "proton-us", 1080)
        .expect("set_active");

    let active = store.list_active().expect("list_active");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].location, "us");
    assert_eq!(active[0].interface, "proton-us");
    assert_eq!(active[0].socks_port, 1080);
    assert!(active[0].started_at > 0);

    store.clear_active("us").expect("clear_active");
    assert!(store.list_active().unwrap().is_empty());
}

#[test]
fn credentials_roundtrip_via_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("proton-proxy.db");
    let store = Store::open(&db_path).expect("open store");

    let creds = test_creds();
    store.save_credentials(&creds).expect("save_credentials");

    let loaded = store.load_credentials().expect("load_credentials");
    assert_eq!(loaded.username, creds.username);
    assert_eq!(loaded.ed25519_seed_b64, creds.ed25519_seed_b64);
    assert_eq!(loaded.wg_public_key, creds.wg_public_key);
    assert_eq!(loaded.wg_private_key, creds.wg_private_key);
    assert_eq!(loaded.certificate_expires_at, creds.certificate_expires_at);

    // File must be 0600 (owner read/write only).
    let mode = std::fs::metadata(&db_path).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(mode.permissions().mode() & 0o777, 0o600);
}
