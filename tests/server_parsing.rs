//! Server-list parsing + `find_servers` filtering/sorting tests (Task 02, updated after
//! live-account verification found the original `/vpn/v1/servers` flat-shape model was wrong
//! — see `models.rs` doc comments).
//!
//! No network access is required: these tests deserialize the checked-in fixtures in
//! `tests/fixtures/` and exercise `ProtonVPNClient::find_servers` (a pure function over
//! `server_list`) directly.
use gratis::client::ProtonVPNClient;
use gratis::models::{
    CertificateResponse, LogicalServersResponse, PhysicalServer, VPNServer, features_to_strings,
};

const SERVERS_FIXTURE: &str = include_str!("fixtures/servers.json");
const CERTIFICATE_FIXTURE: &str = include_str!("fixtures/certificate.json");

/// Feature bitmask mapping, verified against `proton.vpn.session.servers.types.
/// ServerFeatureEnum`: `SECURE_CORE=1, TOR=2, P2P=4, STREAMING=8, IPV6=16`. Bits can combine,
/// and a server with no matching bits gets an empty feature list.
#[test]
fn logicals_response_parses_feature_bitmask() {
    assert_eq!(features_to_strings(1), vec!["secure-core".to_string()]);
    assert_eq!(features_to_strings(2), vec!["tor".to_string()]);
    assert_eq!(features_to_strings(4), vec!["p2p".to_string()]);
    assert_eq!(features_to_strings(8), vec!["streaming".to_string()]);
    assert_eq!(features_to_strings(16), vec!["ipv6".to_string()]);
    assert_eq!(
        features_to_strings(6),
        vec!["tor".to_string(), "p2p".to_string()]
    );
    assert_eq!(features_to_strings(0), Vec::<String>::new());
}

/// Deserialize the checked-in `servers.json` fixture end-to-end and confirm the Status
/// filter + per-physical-server field pairing (Flagged gap #2's root cause: an IP and a
/// WireGuard key must always come from the SAME physical server entry).
#[test]
fn servers_fixture_deserializes_and_maps_fields() {
    let resp: LogicalServersResponse =
        serde_json::from_str(SERVERS_FIXTURE).expect("servers.json must parse");

    // 6 logical servers in the fixture, one with Status == 0 (maintenance).
    assert_eq!(resp.logical_servers.len(), 6);
    let active: Vec<_> = resp
        .logical_servers
        .iter()
        .filter(|s| s.status == 1)
        .collect();
    assert_eq!(active.len(), 5);
    assert!(resp.logical_servers.iter().any(|s| s.status == 0));

    let us_plus = resp
        .logical_servers
        .iter()
        .find(|s| s.id == "srv-us-plus-1")
        .expect("srv-us-plus-1 present");
    assert_eq!(us_plus.entry_country, "US");
    assert_eq!(us_plus.tier, 2);
    assert_eq!(features_to_strings(us_plus.features), vec!["tor", "p2p"]);

    // Two physical servers, each keeping its own IP paired with its own key — never mixed.
    assert_eq!(us_plus.servers.len(), 2);
    let enabled = &us_plus.servers[0];
    assert_eq!(enabled.entry_ip, "203.0.113.12");
    assert_eq!(
        enabled.x25519_public_key,
        "USplus1WgPubKeyBase64CCCCCCCCCCCCCCCCCCCCCC="
    );
    // The WG peer public key must never be confused with the server's IP address.
    assert_ne!(enabled.x25519_public_key, enabled.entry_ip);
    let disabled = &us_plus.servers[1];
    assert_eq!(disabled.status, 0);
    assert_ne!(disabled.x25519_public_key, enabled.x25519_public_key);
}

/// `VPNServer::pick_physical` picks the first *enabled* physical server, not just the first
/// one listed — and keeps its IP/key paired.
#[test]
fn pick_physical_prefers_enabled_server() {
    let server = VPNServer {
        id: "s".into(),
        name: "s".into(),
        country: "US".into(),
        country_code: "US".into(),
        city: None,
        tier: 0,
        load: 0.0,
        features: vec![],
        status: 1,
        physical: vec![
            PhysicalServer {
                entry_ip: "10.0.0.1".into(),
                domain: "down.example.net".into(),
                x25519_public_key: "down-key".into(),
                enabled: false,
            },
            PhysicalServer {
                entry_ip: "10.0.0.2".into(),
                domain: "up.example.net".into(),
                x25519_public_key: "up-key".into(),
                enabled: true,
            },
        ],
    };

    let picked = server.pick_physical().expect("a physical server");
    assert_eq!(picked.entry_ip, "10.0.0.2");
    assert_eq!(picked.x25519_public_key, "up-key");
}

/// Deserialize `certificate.json` (the `POST /vpn/v1/certificate` response shape) and confirm
/// the fields `VPNCredentials` needs are present.
#[test]
fn certificate_fixture_deserializes() {
    let cert: CertificateResponse =
        serde_json::from_str(CERTIFICATE_FIXTURE).expect("certificate.json must parse");

    assert!(cert.certificate.contains("BEGIN CERTIFICATE"));
    assert_eq!(cert.expiration_time, 1999999999);
}

fn server(id: &str, country_code: &str, tier: i32, load: f64) -> VPNServer {
    VPNServer {
        id: id.into(),
        name: id.into(),
        country: country_code.into(),
        country_code: country_code.into(),
        city: None,
        tier,
        load,
        features: vec![],
        status: 1,
        physical: vec![PhysicalServer {
            entry_ip: "203.0.113.1".into(),
            domain: format!("{id}.protonvpn.net"),
            x25519_public_key: format!("{id}-pubkey"),
            enabled: true,
        }],
    }
}

/// `find_servers` excludes servers above the caller's tier, excludes servers whose
/// `country_code` doesn't match, and sorts the remainder ascending by `load`.
#[test]
fn find_servers_filters_tier_and_country_and_sorts_by_load() {
    let mut client = ProtonVPNClient::new("test").unwrap();
    client.server_list = vec![
        server("us-1", "US", 0, 42.0),
        server("us-2", "US", 0, 11.0),
        server("us-3", "US", 2, 5.0), // tier 2, excluded when user_tier == 0
        server("nl-1", "NL", 0, 1.0), // wrong country, excluded
        server("us-4", "US", 0, 20.0),
    ];

    let results = client.find_servers(Some("US"), None, None, 0);

    let ids: Vec<&str> = results.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["us-2", "us-4", "us-1"],
        "must be sorted ascending by load and exclude tier-2/non-US servers"
    );
    assert!(results.iter().all(|s| s.tier <= 0));
    assert!(results.iter().all(|s| s.country_code == "US"));
}
