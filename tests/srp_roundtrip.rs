//! SRP-6a wiring + API DTO parsing tests (Task 02).
//!
//! These tests prove the crate is correctly wired to `proton-srp 0.8.2` and that the API
//! response DTOs parse as the client expects. They contain no secrets; fixtures are inline.
//!
//! The signed modulus below is a PGP-signed SRP modulus fixture borrowed from the
//! `proton-srp` crate's own test-suite (MIT/Apache). It is verified by `RPGPVerifier`, the
//! same verifier the real flow uses, so `prove` exercises the genuine PGP path.
use proton_proxy::models::{features_to_strings, AccountResponse, AuthResponse, ServersResponse, VPNServer};
use proton_proxy::srp::prove;
use proton_srp::SrpHashVersion;
use base64::Engine as _;

/// PGP-signed SRP modulus fixture (proton-srp test-suite). Verified by `RPGPVerifier`.
const TEST_SIGNED_MODULUS: &str = "-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

y6TtufhYg2mIeauZYOti+GPbd/0vP66kP34TgE6elK/kXkTW/Yfrp1jMmtLiWWSq5cszTMRIEighuwPbZ/z3RrWPxsOg0+jYgbFu8yZ8vOAwrPtLxZl94x0PFTAZBrVapmCn+VYcM+UXdO9v70xFDLwj34tpPbvpODHVWHSlGlhOwndWg3XBE2D9PJopFZajNZiqOScBXree5rDgzU5BBaPbIb6nySpyaeThMCcNzpcEqE8r3ro+E/VdXBvSSJpusr1dvAwHc3IDGUzAhodqV5mjYy9nXwq/9gHWpYNtm76Ols7ReWAhZwy1+cQllQZwGfzzOVGpc+3WutOntQjM6Q==
-----BEGIN PGP SIGNATURE-----
Version: ProtonMail
Comment: https://protonmail.com

wl4EARYIABAFAlwB1j8JEDUFhcTpUY8mAADfEAD8DFdNXn4TsgbfbAZRDa9a
yywqa/2W9Qyg5MJaNZd2a+0BAPg04gEZI+G8RaoPVh/SYvWx7jpP3L1O8bEi
M/j1cjIO
=5RYw
-----END PGP SIGNATURE-----";

/// Build a 256-byte server ephemeral (value 2, little-endian) that is non-zero and safely
/// below the SRP modulus N. It decodes to exactly `SRP_LEN_BYTES` and lets `generate_proofs`
/// run to completion.
fn test_server_ephemeral_b64() -> String {
    let mut buf = [0u8; proton_srp::SRP_LEN_BYTES];
    buf[0] = 2;
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// A valid base64 salt (16 bytes), borrowed from the `proton-srp` test-suite.
const TEST_SALT_B64: &str = "SzHkg+YYA/eN1A==";

#[test]
fn srp_proof_roundtrip_generates_ephemeral_and_proof() {
    let (client_ephemeral, client_proof, _expected_server_proof) = prove(
        Some("user@example.com"),
        "hunter2-correct-horse",
        SrpHashVersion::V4,
        TEST_SALT_B64,
        TEST_SIGNED_MODULUS,
        &test_server_ephemeral_b64(),
    )
    .expect("prove must succeed against the PGP-verified modulus");

    // Both proofs must be exactly SRP_LEN_BYTES (256) bytes once base64-decoded, which
    // confirms the crate is wired to proton-srp 0.8.2 (not a stub).
    let a = base64::engine::general_purpose::STANDARD
        .decode(&client_ephemeral)
        .expect("client_ephemeral is valid base64");
    let m1 = base64::engine::general_purpose::STANDARD
        .decode(&client_proof)
        .expect("client_proof is valid base64");
    assert_eq!(a.len(), proton_srp::SRP_LEN_BYTES);
    assert_eq!(m1.len(), proton_srp::SRP_LEN_BYTES);
}

#[test]
fn auth_response_parses_with_response_code_1000() {
    let json = r#"{
        "AccessToken": "at-123",
        "RefreshToken": "rt-123",
        "UID": "uid-123",
        "ResponseCode": 1000,
        "ServerProof": "c2VyaWZpZWRwcm9vZg=="
    }"#;
    let auth: AuthResponse = serde_json::from_str(json).expect("AuthResponse must parse");
    assert_eq!(auth.response_code, Some(1000));
    assert!(auth.access_token.is_some());
    assert_eq!(auth.server_proof.as_deref(), Some("c2VyaWZpZWRwcm9vZg=="));
}

#[test]
fn servers_response_parses_and_filters_status() {
    let json = r#"{
        "Servers": [
            {
                "ID": "gW1lbsdQwWvQ...AAEASg==",
                "Name": "CH#1",
                "EntryCountry": "CH",
                "City": "Zurich",
                "Tier": 2,
                "Load": 17.0,
                "Features": 1,
                "IsSecureCore": false,
                "Status": 1,
                "Addresses": [{ "IP": "185.1.2.3" }],
                "WGPublicKey": "WgPubKeyCH"
            },
            {
                "ID": "de-2",
                "Name": "DE#2",
                "EntryCountry": "DE",
                "City": "Frankfurt",
                "Tier": 0,
                "Load": 42.0,
                "Features": 8,
                "IsSecureCore": false,
                "Status": 0,
                "Addresses": [{ "IP": "185.9.9.9" }],
                "WGPublicKey": "WgPubKeyDE"
            },
            {
                "ID": "sc-3",
                "Name": "SE-SC#3",
                "EntryCountry": "SE",
                "City": "Stockholm",
                "Tier": 2,
                "Load": 5.0,
                "Features": 0,
                "IsSecureCore": true,
                "Status": 1,
                "Addresses": [{ "IP": "185.7.7.7" }],
                "WGPublicKey": "WgPubKeySC"
            }
        ]
    }"#;
    let resp: ServersResponse = serde_json::from_str(json).expect("ServersResponse must parse");
    let active: Vec<VPNServer> = resp
        .servers
        .into_iter()
        .filter(|dto| dto.status == 1)
        .map(|dto| VPNServer {
            id: dto.id,
            name: dto.name,
            country: dto.entry_country.clone(),
            country_code: dto.entry_country,
            city: dto.city,
            tier: dto.tier,
            load: dto.load,
            features: features_to_strings(dto.features, dto.is_secure_core),
            ips: dto.addresses.into_iter().map(|a| a.ip).collect(),
            status: dto.status,
            wg_public_key: dto.wg_public_key,
        })
        .collect();

    // Only the two Status == 1 servers survive; the Status == 0 one is dropped.
    assert_eq!(active.len(), 2);
    assert!(active.iter().all(|s| s.status == 1));
    assert!(active.iter().any(|s| s.country_code == "CH"));
    assert!(active.iter().any(|s| s.country_code == "SE"));

    // Feature mapping: P2P (bit 1), TOR (bit 8), secure-core (IsSecureCore).
    let ch = active.iter().find(|s| s.country_code == "CH").unwrap();
    assert_eq!(ch.features, vec!["p2p".to_string()]);
    assert_eq!(ch.ips, vec!["185.1.2.3".to_string()]);
    assert_eq!(ch.wg_public_key, "WgPubKeyCH");

    let sc = active.iter().find(|s| s.country_code == "SE").unwrap();
    assert_eq!(sc.features, vec!["secure-core".to_string()]);
}

#[test]
fn account_response_parses_vpn_credentials() {
    let json = r#"{
        "VPN": {
            "UserName": "vpn-user",
            "Password": "vpn-pass",
            "PubKeyCredential": {
                "CertificatePEM": "CERT",
                "PublicKey": "WGPUB",
                "PrivateKey": "WGPUD"
            }
        }
    }"#;
    let account: AccountResponse = serde_json::from_str(json).expect("AccountResponse must parse");
    assert_eq!(account.vpn.user_name, "vpn-user");
    assert_eq!(account.vpn.pub_key_credential.private_key, "WGPUD");
}
