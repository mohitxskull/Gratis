//! WireGuard config generation + active-tunnel state persistence tests (Task 03).
//!
//! No root privileges and no live WireGuard interface are required: these tests exercise
//! `generate_config`'s output string and the SQLite-backed `credentials::Store` directly,
//! against a tempdir DB path (never the real `~/.config/proton-proxy/` directory).
use proton_proxy::credentials::Store;
use proton_proxy::models::{VPNCredentials, VPNServer, client_address_from_certificate};
use proton_proxy::wireguard::{WG_PORT, generate_config, interface_name};

/// A self-signed test certificate (RSA-2048, `CN=proton-test`) with a single SAN IP entry
/// of `10.2.0.5`, generated with:
/// `openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=proton-test" \
///    -addext "subjectAltName=IP:10.2.0.5"`.
/// Contains no real account data; it is a throwaway fixture.
const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIUa/5mCrPYf855/Ob4AvhLmbKnZwAwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLcHJvdG9uLXRlc3QwHhcNMjYwODE4MTAxNDA4WhcNMzYw
ODE1MTAxNDA4WjAWMRQwEgYDVQQDDAtwcm90b24tdGVzdDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAJ7s1rNtRRsqNoiIt9ov2P+J0sy8Cl68Y1YmM7lG
aQZ7rqajQqBlF0HSEv2OTF5biPHb9aaTxeZoPeoull7qWPbQwmqXxLSWu0Swtxga
KWXclWrXlh3zPsoVcTZDarhHk0oTs4v9fXkuctacNB/sHm0Auv8DshAJLXNYpoWH
peaUzDsd5/jT375E7RRkCeInov7c7hso5JyMxY7U8EFawUexObbe6Q5WELpTcIFz
rino9srIz6+bhx5cIltluPXoTH279Lmr9q1sXTedwMbtrErJxZrAiP/JmsPeaNvc
JUxwSt6lvgMAJZSWT8vQKMbEuwLYYzrMrKtn5c0sJrPDW+MCAwEAAaNkMGIwHQYD
VR0OBBYEFABogFWxB2xkPbxu9+mJPG9uTIqKMB8GA1UdIwQYMBaAFABogFWxB2xk
Pbxu9+mJPG9uTIqKMA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0RBAgwBocECgIABTAN
BgkqhkiG9w0BAQsFAAOCAQEAVgl0pqpn0wfdxBC/m07PA8+ngXXN4eLHypQYePSF
QsEiyu8ZfSPy2CRaIa/660Z9cMcwxaMABesO4Cu0R0GEvuSQSE5ZCSfiAQqmb/nw
/OGp7+4zfDqbaaxuZSoozAgj1VoOCp1OCUWxfcdvoXwqUbwslS+BrdymNOdr1d7y
TJcG6MxOvCjdoIEyDVsXmOFhqEtpvte7jRvPncz8DdG1n4ukl5cdVvuAzY4jHP8j
rxA/XsUNPp08PNpGI34w1X7prwi/VLkAkGEeY1wNufP1/IVXW+ahOfNvcGLJQJVf
eRd1dKRVcDggq2K+vBNH5fXpGufy8FPBsFFnA5ZDGFrqpg==
-----END CERTIFICATE-----";

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
        ips: vec!["203.0.113.9".into()],
        status: 1,
        // Deliberately distinct from `ips[0]` so a test that accidentally reads the wrong
        // field is caught immediately.
        wg_public_key: "SERVERPUBKEYBASE64==".into(),
    }
}

fn test_creds() -> VPNCredentials {
    VPNCredentials {
        username: "testuser".into(),
        password: "unused-in-wg-config".into(),
        certificate: TEST_CERT_PEM.into(),
        wg_public_key: "CLIENTPUBKEYBASE64==".into(),
        wg_private_key: "CLIENTPRIVKEYBASE64==".into(),
    }
}

#[test]
fn config_has_correct_peer_public_key_not_ip() {
    let server = test_server();
    let creds = test_creds();
    let iface = interface_name("us");

    let config = generate_config(&server, &creds, "10.2.0.5", &iface);

    assert!(
        config.contains("PublicKey = SERVERPUBKEYBASE64=="),
        "config must use the server's real WG pubkey field:\n{config}"
    );
    assert!(
        !config.contains("PublicKey = 203.0.113.9"),
        "config must NEVER use ips[0] as the peer public key:\n{config}"
    );
    assert!(
        config.contains(&format!("Endpoint = 203.0.113.9:{WG_PORT}")),
        "Endpoint must be ips[0]:{WG_PORT}:\n{config}"
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
fn config_uses_derived_client_address() {
    let server = test_server();
    let creds = test_creds();
    let iface = interface_name("us");

    let client_address =
        client_address_from_certificate(&creds.certificate).expect("SAN IP must be present");
    assert_eq!(
        client_address, "10.2.0.5",
        "derived address must match the fixture certificate's SAN IP"
    );

    let config = generate_config(&server, &creds, &client_address, &iface);

    assert!(
        config.contains("Address = 10.2.0.5/32"),
        "[Interface] Address must be the derived client address, not a hardcoded value:\n{config}"
    );
    assert!(
        !config.contains("Address = 10.8.0.1"),
        "config must not fall back to the old hardcoded 10.8.0.1/24:\n{config}"
    );
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
    assert_eq!(loaded.wg_public_key, creds.wg_public_key);
    assert_eq!(loaded.wg_private_key, creds.wg_private_key);

    // File must be 0600 (owner read/write only).
    let mode = std::fs::metadata(&db_path).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(mode.permissions().mode() & 0o777, 0o600);
}
