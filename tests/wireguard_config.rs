//! WireGuard tunnel + active-tunnel state persistence tests, updated for the userspace
//! WireGuard redesign (no more `sudo wg-quick`/text config generation — see `wireguard.rs`'s
//! doc comment for why). No root privileges and no live WireGuard interface are required.
use proton_proxy::credentials::Store;
use proton_proxy::models::{PhysicalServer, VPNCredentials, VPNServer};
use proton_proxy::wireguard::{CLIENT_ADDRESS, Tunnel, interface_name};

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
fn interface_name_is_a_stable_lowercase_label() {
    assert_eq!(interface_name("US"), "proton-us");
    assert_eq!(interface_name("us"), "proton-us");
}

#[test]
fn client_address_is_the_fixed_proton_address() {
    // Verified against proton.vpn.backend.networkmanager.protocol.wireguard.wireguard:
    // every Proton WireGuard connection uses this fixed address, never anything derived
    // per-account or per-connection.
    assert_eq!(CLIENT_ADDRESS, "10.2.0.2");
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
