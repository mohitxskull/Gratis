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

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, ProtonError>;
