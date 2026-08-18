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
