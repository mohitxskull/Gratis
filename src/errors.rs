//! Error types for the Proton VPN client.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtonError {
    #[error("API error: {0}")]
    Api(String),

    #[error("authentication failed")]
    Auth,

    /// The account has two-factor authentication enabled and `/auth` succeeded but returned
    /// the `"twofactor"` scope — the caller must collect a TOTP code and call
    /// `ProtonVPNClient::submit_2fa` before anything else will work.
    #[error("two-factor authentication required")]
    TwoFactorRequired,

    #[error("SRP error: {0}")]
    Srp(#[from] proton_srp::SRPError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("config/state error: {0}")]
    Config(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("tunnel error: {0}")]
    Tunnel(#[from] wireguard_netstack::Error),

    /// Failure anywhere in the Proton "local agent" handshake (`agent.rs`) — TLS setup,
    /// the handshake itself, framing, or a reply that reports the session as jailed/restricted.
    /// Always a soft failure from the caller's point of view: `manager.rs` falls back to the
    /// readiness-probe wait rather than failing the connection outright.
    #[error("local agent error: {0}")]
    LocalAgent(String),

    /// `ServerSlot::acquire` rejected a connection because the account's `MaxConnect` cap is
    /// already fully used by *active* tunnels (nothing idle to evict, or `--evict-lru` isn't
    /// on) — not a sign that this particular server/exit is broken. `socks5.rs` checks for
    /// this specific variant to reply with SOCKS5 `CONNECTION REFUSED` (0x05) instead of
    /// `GENERAL FAILURE` (0x01), so a SOCKS5 client (e.g. `zen-relay`) can tell "gratis is at
    /// capacity right now" apart from "this exit doesn't work" instead of treating both
    /// identically — verified live: without this distinction, a capacity-cap rejection (which
    /// clears the moment another connection frees up) was indistinguishable from a genuinely
    /// dead exit, and got a client-side multi-hour ban it didn't deserve.
    #[error("at capacity: {0}")]
    AtCapacity(String),
}

pub type Result<T> = std::result::Result<T, ProtonError>;
