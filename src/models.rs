//! Data models and API DTOs.
//!
//! Field names and endpoint shapes were originally sourced from `tmp/proton-vpn-cli`, which
//! turned out to be the wrong layer (the CLI, not the API client) and got several things
//! wrong. They are now verified against the real API and the official client's source
//! (`proton-core`/`proton-vpn-api-core`, installed system-wide on the dev machine at
//! `/usr/lib/python3/dist-packages/proton/`), and against a real live login.
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const PROTON_API_URL: &str = "https://api.protonvpn.ch";
pub const USER_AGENT: &str = "ProtonVPN-CustomClient/1.0";

/// Proton's API-wide "this call succeeded" sentinel, carried in the response body's `Code`
/// field (distinct from the HTTP status, which is a plain 200 either way) — verified against
/// `proton-core`'s `proton.session.exceptions`. `client.rs` checks it after `login`/`submit_2fa`/
/// `refresh`; a mismatch there means the request reached the API but Proton itself rejected it.
pub const PROTON_SUCCESS_CODE: i32 = 1000;

/// One physical server backing a logical server. A logical server ("CH#10") can be served by
/// several physical machines; the entry IP and WireGuard peer public key are properties of the
/// *physical* server, never mixed across two different physical entries (this was the root
/// cause of Flagged gap #2 in the old Python: pairing `ips[0]` with a key that belonged to a
/// different physical server, or simply reading the wrong field).
#[derive(Debug, Clone)]
pub struct PhysicalServer {
    pub entry_ip: String,
    pub domain: String,
    /// Base64-encoded X25519 public key — verified live field name `X25519PublicKey`.
    pub x25519_public_key: String,
    pub enabled: bool,
}

/// A logical VPN server ("CH#10"), aggregating one or more physical servers.
#[derive(Debug, Clone)]
pub struct VPNServer {
    pub id: String,
    pub name: String,
    pub country: String,
    pub country_code: String,
    pub city: Option<String>,
    pub tier: i32,
    pub load: f64,
    pub features: Vec<String>,
    pub status: i32,
    pub physical: Vec<PhysicalServer>,
}

impl VPNServer {
    /// Pick a physical server to connect through: the first enabled one, or (if none are
    /// marked enabled) the first one at all. Returns `None` only if the logical has no
    /// physical servers listed.
    pub fn pick_physical(&self) -> Option<&PhysicalServer> {
        self.physical
            .iter()
            .find(|p| p.enabled)
            .or_else(|| self.physical.first())
    }
}

/// Client-side WireGuard/certificate identity plus the certificate Proton issued for it.
///
/// Verified against `proton-vpn-api-core`: Proton's API never hands back a WireGuard private
/// key. The client generates an ed25519 seed locally (see `crate::keys::ClientIdentity`),
/// derives the WireGuard (X25519) keypair from it, and asks `/vpn/v1/certificate` to sign the
/// corresponding ed25519 public key. `wg_private_key`/`wg_public_key` here are that locally
/// derived keypair, base64-encoded — never anything read off the wire.
/// Zeroized on drop (except `username` and `certificate_expires_at`, neither of which is key
/// material): this struct is cloned into every `ServerSlot` for the lifetime of the daemon (see
/// `manager.rs`), so without this, the seed and derived WireGuard private key would sit in
/// process memory — and potentially swap/core dumps — in as many copies as there are servers,
/// for as long as the process runs.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VPNCredentials {
    #[zeroize(skip)]
    pub username: String,
    /// Raw 32-byte ed25519 seed, base64-encoded. `client::issue_credentials` always mints a
    /// fresh identity rather than restoring one from this (see `ClientIdentity`'s doc comment) —
    /// stored here anyway since it's part of what `/vpn/v1/certificate` was issued for.
    pub ed25519_seed_b64: String,
    pub wg_private_key: String,
    pub wg_public_key: String,
    /// PEM certificate from `/vpn/v1/certificate`, authorizing `wg_public_key`'s corresponding
    /// ed25519 identity to connect. Not currently required to bring up a bare WireGuard
    /// tunnel (verified: the NetworkManager WireGuard backend's `_set_wireguard_properties`
    /// never touches the certificate), but Proton's "local agent" protocol — which the real
    /// client uses post-connect for keepalive/feature negotiation/kill-switch — does use it,
    /// and that protocol is not implemented here (no accessible source for its wire format
    /// beyond a compiled Rust extension). Whether a tunnel stays usable without it is unverified.
    pub certificate: String,
    #[zeroize(skip)]
    pub certificate_expires_at: i64,
}

/// `POST /vpn/v1/certificate` response. Field names verified against
/// `proton.vpn.session.dataclasses.VPNCertificate`.
#[derive(Debug, Deserialize)]
pub struct CertificateResponse {
    #[serde(rename = "Certificate")]
    pub certificate: String,
    #[serde(rename = "ExpirationTime")]
    pub expiration_time: i64,
}

/// `POST /auth/info` response (SRP parameters). Endpoint and field names verified live and
/// against `proton.session.api.Session.async_authenticate`.
#[derive(Debug, Deserialize)]
pub struct AuthInfo {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "Salt")]
    pub salt: String,
    #[serde(rename = "ServerEphemeral")]
    pub server_ephemeral: String,
    #[serde(rename = "SRPSession")]
    pub srp_session: String,
    #[serde(rename = "Modulus")]
    pub modulus: String,
}

/// `POST /auth` response.
#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    #[serde(rename = "AccessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "RefreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "UID")]
    pub uid: Option<String>,
    // Verified live against api.protonvpn.ch: every response (success and error alike) uses
    // "Code", not "ResponseCode" (the field name this flow's docs/reference used to cite).
    #[serde(rename = "Code")]
    pub response_code: Option<i32>,
    #[serde(rename = "Error")]
    pub error: Option<String>,
    #[serde(rename = "ServerProof", default)]
    pub server_proof: Option<String>,
    /// Present on every successful `/auth` (and `/auth/refresh`) response. Verified against
    /// `proton.session.api.Session.needs_twofa`: 2FA is required exactly when this list
    /// contains `"twofactor"` — there is no separate boolean flag for it.
    #[serde(rename = "Scopes", default)]
    pub scopes: Vec<String>,
}

/// `POST /auth/2fa` response. Verified against
/// `proton.session.api.Session._async_validate_2fa`: success is `Code == 1000`; the response
/// also carries an updated `Scopes` list (now without `"twofactor"`), which this client
/// doesn't need to inspect since a non-1000 code already means the code was rejected.
#[derive(Debug, Deserialize)]
pub struct TwoFactorResponse {
    #[serde(rename = "Code")]
    pub response_code: Option<i32>,
}

/// `GET /vpn/v2` response. Verified live against a real free-tier account (`MaxTier: 0,
/// MaxConnect: 2, PlanName: "free", Groups: ["vpn-free"]`) and against the field shape in
/// `proton.vpn.session.dataclasses.settings.VPNSettings`/`VPNInfo`
/// (`/usr/lib/python3/dist-packages/proton/vpn/session/dataclasses/settings.py`).
#[derive(Debug, Deserialize)]
pub struct VPNSettings {
    #[serde(rename = "VPN")]
    pub vpn: VPNAccountInfo,
}

#[derive(Debug, Deserialize)]
pub struct VPNAccountInfo {
    #[serde(rename = "PlanName")]
    pub plan_name: String,
    /// The highest server tier this account can connect to (`0` = free). This is what
    /// `manager.rs` filters the server list by — never a hardcoded assumption.
    #[serde(rename = "MaxTier")]
    pub max_tier: i32,
    /// Proton's cap on simultaneous VPN sessions for this account. `manager.rs` enforces this
    /// as the default cap on how many servers can have a live tunnel at once (bypassable via
    /// `--unlimited-connections`) — gratis's "any number of servers at once" design otherwise
    /// has no relationship to what the account is actually allowed.
    #[serde(rename = "MaxConnect")]
    pub max_connect: i32,
}

/// Bitmask values for `LogicalServerDto.features`, verified against
/// `proton.vpn.session.servers.types.ServerFeatureEnum` — the old `1=P2P, 8=TOR` assumption
/// (never verified against a live account) was wrong. Named rather than inlined so a new
/// feature bit can't be added as a bare, unexplained literal.
const FEATURE_SECURE_CORE: i32 = 1;
const FEATURE_TOR: i32 = 2;
const FEATURE_P2P: i32 = 4;
const FEATURE_STREAMING: i32 = 8;
const FEATURE_IPV6: i32 = 16;

/// Map a `LogicalServerDto.features` bitmask into strings.
pub fn features_to_strings(features: i32) -> Vec<String> {
    let mut out = Vec::new();
    if features & FEATURE_SECURE_CORE != 0 {
        out.push("secure-core".to_string());
    }
    if features & FEATURE_TOR != 0 {
        out.push("tor".to_string());
    }
    if features & FEATURE_P2P != 0 {
        out.push("p2p".to_string());
    }
    if features & FEATURE_STREAMING != 0 {
        out.push("streaming".to_string());
    }
    if features & FEATURE_IPV6 != 0 {
        out.push("ipv6".to_string());
    }
    out
}

/// `GET /vpn/v1/logicals?SecureCoreFilter=all&WithState=true` response. Endpoint and shape
/// verified against `proton.vpn.session.servers.server_list_fetcher.MixinEndpointV1` and
/// `proton.vpn.session.servers.types`. This is a NESTED shape (logical -> physical servers),
/// not the flat per-server list the old model assumed.
#[derive(Debug, Deserialize)]
pub struct LogicalServersResponse {
    #[serde(rename = "LogicalServers")]
    pub logical_servers: Vec<LogicalServerDto>,
}

#[derive(Debug, Deserialize)]
pub struct LogicalServerDto {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "EntryCountry")]
    pub entry_country: String,
    #[serde(rename = "City")]
    pub city: Option<String>,
    #[serde(rename = "Tier")]
    pub tier: i32,
    #[serde(rename = "Load")]
    pub load: f64,
    #[serde(rename = "Features")]
    pub features: i32,
    #[serde(rename = "Status")]
    pub status: i32,
    #[serde(rename = "Servers", default)]
    pub servers: Vec<PhysicalServerDto>,
}

#[derive(Debug, Deserialize)]
pub struct PhysicalServerDto {
    #[serde(rename = "EntryIP")]
    pub entry_ip: String,
    #[serde(rename = "Domain")]
    pub domain: String,
    #[serde(rename = "Status")]
    pub status: i32,
    #[serde(rename = "X25519PublicKey", default)]
    pub x25519_public_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn vpn_credentials_zeroize_clears_secrets_but_keeps_username_and_expiry() {
        let mut creds = VPNCredentials {
            username: "user@example.com".into(),
            ed25519_seed_b64: "seed".into(),
            wg_private_key: "privkey".into(),
            wg_public_key: "pubkey".into(),
            certificate: "cert".into(),
            certificate_expires_at: 1_700_000_000,
        };

        creds.zeroize();

        assert_eq!(creds.ed25519_seed_b64, "");
        assert_eq!(creds.wg_private_key, "");
        assert_eq!(creds.wg_public_key, "");
        assert_eq!(creds.certificate, "");
        // Neither is secret material — must survive zeroize untouched.
        assert_eq!(creds.username, "user@example.com");
        assert_eq!(creds.certificate_expires_at, 1_700_000_000);
    }
}
