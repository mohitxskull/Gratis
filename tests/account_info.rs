//! `GET /vpn/v2` (account tier/plan/connection-limit) and `POST /auth/2fa` response parsing.
//!
//! No network access required: these deserialize the checked-in `tests/fixtures/` files
//! directly. Field shapes verified live against a real free-tier account — see the doc
//! comments on `VPNSettings`/`VPNAccountInfo` in `models.rs`.
use gratis::models::{TwoFactorResponse, VPNSettings};

const VPN_SETTINGS_FIXTURE: &str = include_str!("fixtures/vpn_settings.json");

#[test]
fn vpn_settings_fixture_deserializes_tier_and_connect_limit() {
    let settings: VPNSettings =
        serde_json::from_str(VPN_SETTINGS_FIXTURE).expect("vpn_settings.json must parse");
    assert_eq!(settings.vpn.plan_name, "free");
    assert_eq!(settings.vpn.max_tier, 0);
    assert_eq!(settings.vpn.max_connect, 2);
}

#[test]
fn two_factor_response_parses_success_code() {
    let json = r#"{ "Code": 1000, "Scopes": ["full"] }"#;
    let resp: TwoFactorResponse = serde_json::from_str(json).expect("must parse");
    assert_eq!(resp.response_code, Some(1000));
}

#[test]
fn two_factor_response_parses_rejected_code() {
    // A wrong TOTP code: Proton returns a non-1000 Code, not an HTTP error — the caller
    // (`ProtonVPNClient::submit_2fa`) treats anything but 1000 as `ProtonError::Auth`.
    let json = r#"{ "Code": 12087, "Error": "Invalid verification code" }"#;
    let resp: TwoFactorResponse = serde_json::from_str(json).expect("must parse");
    assert_ne!(resp.response_code, Some(1000));
}

/// No test previously asserted that a malformed `VPNSettings` payload actually *fails* to
/// parse rather than silently defaulting some field — a wrong-type `MaxTier` reaching
/// `manager::finish_login` undetected could pick a tier the account isn't entitled to.
#[test]
fn vpn_settings_rejects_a_string_max_tier() {
    let json = r#"{ "VPN": { "PlanName": "free", "MaxTier": "zero", "MaxConnect": 2 } }"#;
    assert!(
        serde_json::from_str::<VPNSettings>(json).is_err(),
        "MaxTier as a string must fail to parse, not silently coerce"
    );
}

#[test]
fn vpn_settings_rejects_truncated_json() {
    let json = r#"{ "VPN": { "PlanName": "free", "MaxTier": 0"#; // missing closing braces
    assert!(serde_json::from_str::<VPNSettings>(json).is_err());
}

#[test]
fn vpn_settings_rejects_a_missing_required_field() {
    // MaxConnect has no #[serde(default)] — its absence must be a parse error, not a silent 0
    // (which would look identical to a legitimately zero-connect account).
    let json = r#"{ "VPN": { "PlanName": "free", "MaxTier": 0 } }"#;
    assert!(serde_json::from_str::<VPNSettings>(json).is_err());
}

#[test]
fn two_factor_response_rejects_a_non_numeric_code() {
    let json = r#"{ "Code": "1000" }"#;
    assert!(serde_json::from_str::<TwoFactorResponse>(json).is_err());
}
