//! Error types for the Proton VPN client.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtonError {
    #[error("API error: {0}")]
    Api(String),

    #[error("authentication failed")]
    Auth,

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
}

pub type Result<T> = std::result::Result<T, ProtonError>;
