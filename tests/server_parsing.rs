//! Server-list parsing + `find_servers` filtering/sorting tests (Task 02).
//!
//! No network access is required: these tests deserialize the checked-in fixtures in
//! `tests/fixtures/` and exercise `ProtonVPNClient::find_servers` (a pure function over
//! `server_list`) directly.
use proton_proxy::client::ProtonVPNClient;
use proton_proxy::models::{
    AccountResponse, ServersResponse, VPNServer, client_address_from_certificate,
    features_to_strings,
};

const SERVERS_FIXTURE: &str = include_str!("fixtures/servers.json");
const ACCOUNT_FIXTURE: &str = include_str!("fixtures/account.json");

/// Feature bitmask mapping (per `proton-vpn-cli`): `Features & 1 => "p2p"`,
/// `Features & 8 => "tor"`, `IsSecureCore => "secure-core"`. Bits can combine, and a server
/// with no matching bits/flag gets an empty feature list.
#[test]
fn servers_response_parses_feature_bitmask() {
    assert_eq!(features_to_strings(1, false), vec!["p2p".to_string()]);
    assert_eq!(features_to_strings(8, false), vec!["tor".to_string()]);
    assert_eq!(
        features_to_strings(0, true),
        vec!["secure-core".to_string()]
    );
    assert_eq!(
        features_to_strings(9, false),
        vec!["p2p".to_string(), "tor".to_string()]
    );
    assert_eq!(features_to_strings(0, false), Vec::<String>::new());
}

/// Deserialize the checked-in `servers.json` fixture end-to-end and confirm the
/// Status-filter + field mapping (Flagged gap #2: `WGPublicKey`, never `ips[0]`).
#[test]
fn servers_fixture_deserializes_and_maps_fields() {
    let resp: ServersResponse =
        serde_json::from_str(SERVERS_FIXTURE).expect("servers.json must parse");

    // 6 servers in the fixture, one with Status == 0 (maintenance).
    assert_eq!(resp.servers.len(), 6);
    let active: Vec<_> = resp.servers.iter().filter(|s| s.status == 1).collect();
    assert_eq!(active.len(), 5);
    assert!(resp.servers.iter().any(|s| s.status == 0));

    let us_plus = resp
        .servers
        .iter()
        .find(|s| s.id == "srv-us-plus-1")
        .expect("srv-us-plus-1 present");
    assert_eq!(us_plus.entry_country, "US");
    assert_eq!(us_plus.tier, 2);
    assert_eq!(
        us_plus.wg_public_key,
        "USplus1WgPubKeyBase64CCCCCCCCCCCCCCCCCCCCCC="
    );
    // The WG peer public key must never be confused with the server's IP address.
    assert_ne!(us_plus.wg_public_key, us_plus.addresses[0].ip);
    assert_eq!(
        features_to_strings(us_plus.features, us_plus.is_secure_core),
        vec!["p2p".to_string(), "tor".to_string()]
    );
}

/// Deserialize `account.json` and confirm `VPNCredentials`-shaped fields are non-empty and
/// that the client tunnel address can be derived from the fixture's certificate SAN.
#[test]
fn account_fixture_deserializes_and_derives_client_address() {
    let account: AccountResponse =
        serde_json::from_str(ACCOUNT_FIXTURE).expect("account.json must parse");

    assert_eq!(account.vpn.user_name, "fixture-vpn-user");
    assert!(!account.vpn.pub_key_credential.public_key.is_empty());
    assert!(!account.vpn.pub_key_credential.private_key.is_empty());
    assert!(!account.vpn.pub_key_credential.certificate_pem.is_empty());

    let address = client_address_from_certificate(&account.vpn.pub_key_credential.certificate_pem)
        .expect("fixture certificate carries a SAN IP");
    assert_eq!(address, "10.2.0.5");
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
        ips: vec!["203.0.113.1".into()],
        status: 1,
        wg_public_key: format!("{id}-pubkey"),
    }
}

/// `find_servers` excludes servers above the caller's tier, excludes servers whose
/// `country_code` doesn't match, and sorts the remainder ascending by `load`.
#[test]
fn find_servers_filters_tier_and_country_and_sorts_by_load() {
    let mut client = ProtonVPNClient::new("test");
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
