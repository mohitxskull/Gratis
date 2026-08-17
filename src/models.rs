//! Data models and API DTOs.
//!
//! Field names follow the JSON from Proton's API. The correctness reference for the
//! auth/session/WireGuard flow is the official client:
//! <https://github.com/ProtonVPN/proton-vpn-cli>
use serde::Deserialize;

pub const PROTON_API_URL: &str = "https://api.protonvpn.ch";
pub const USER_AGENT: &str = "ProtonVPN-CustomClient/1.0";

/// A VPN server as returned by `GET /vpn/v1/servers`.
#[derive(Debug, Clone, Deserialize)]
pub struct VPNServer {
    pub id: String,
    pub name: String,
    pub country: String,
    pub country_code: String,
    pub city: Option<String>,
    pub tier: i32,
    pub load: f64,
    pub features: Vec<String>,
    pub ips: Vec<String>,
    pub status: i32,
    // Captured from the live /vpn/v1/servers response (Flagged gap #2): the real
    // WireGuard peer public key field is confirmed against proton-vpn-cli at impl time.
    // It must NOT be `ips[0]` (that is the server IP, not the WG key).
    pub wg_public_key: String,
}

/// Per-account VPN credentials from `GET /vpn/v2/account`.
#[derive(Debug, Clone, Deserialize)]
pub struct VPNCredentials {
    pub username: String,
    pub password: String,
    pub certificate: String,
    pub wg_public_key: String,
    pub wg_private_key: String,
}

/// `POST /auth/v4/info` response (SRP parameters).
#[derive(Debug, Deserialize)]
pub struct AuthInfo {
    pub version: u32, // Protocol version (e.g. 4)
    pub salt: String, // base64
    pub server_ephemeral: String, // base64 (B)
    pub srp_session: String,
    pub modulus: String, // PGP-signed modulus message
}

/// `POST /auth/v4/authenticate` response.
#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub uid: Option<String>,
    #[serde(rename = "ResponseCode")]
    pub response_code: Option<i32>,
    #[serde(rename = "Error")]
    pub error: Option<String>,
}

/// `GET /vpn/v2/account` -> `VPN` sub-object.
#[derive(Debug, Deserialize)]
pub struct AccountResponse {
    #[serde(rename = "VPN")]
    pub vpn: VpnAccount,
}

#[derive(Debug, Deserialize)]
pub struct VpnAccount {
    #[serde(rename = "UserName")]
    pub user_name: String,
    #[serde(rename = "Password")]
    pub password: String,
    #[serde(rename = "PubKeyCredential")]
    pub pub_key_credential: PubKeyCredential,
}

#[derive(Debug, Deserialize)]
pub struct PubKeyCredential {
    #[serde(rename = "CertificatePEM")]
    pub certificate_pem: String,
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
}

/// `GET /vpn/v1/servers` response.
#[derive(Debug, Deserialize)]
pub struct ServersResponse {
    #[serde(rename = "Servers")]
    pub servers: Vec<ServerDto>,
}

/// Raw server DTO before mapping into `VPNServer`.
#[derive(Debug, Deserialize)]
pub struct ServerDto {
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
    pub features: i32, // bitmask: 1=P2P, 8=TOR
    #[serde(rename = "IsSecureCore")]
    pub is_secure_core: bool,
    #[serde(rename = "Status")]
    pub status: i32,
    #[serde(rename = "Addresses")]
    pub addresses: Vec<ServerAddress>,
    // Field name confirmed against proton-vpn-cli at impl time (Flagged gap #2).
    #[serde(rename = "WGPublicKey", default)]
    pub wg_public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerAddress {
    #[serde(rename = "IP")]
    pub ip: String,
}
