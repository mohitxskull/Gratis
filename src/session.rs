//! Stored login session: the tokens `gratis login` gets back from Proton, kept in the OS
//! keychain (Secret Service on Linux) so `gratis up`/`gratis run` never touch the account
//! password again. The password itself is never stored — only what SRP login already hands
//! back (`uid`, `access_token`, `refresh_token`), serialized as one JSON blob under one
//! keychain entry. Only one stored session at a time, matching "log in once".
use crate::errors::*;
use serde::{Deserialize, Serialize};

const SERVICE: &str = "gratis";
const USERNAME: &str = "session";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub email: String,
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
}

fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, USERNAME)
        .map_err(|e| ProtonError::Config(format!("keychain unavailable: {e}")))
}

/// `None` if no session is stored yet (not an error — the normal state before `gratis login`).
pub fn load() -> Result<Option<Session>> {
    match entry()?.get_password() {
        Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(ProtonError::Config(format!("keychain read failed: {e}"))),
    }
}

pub fn store(session: &Session) -> Result<()> {
    let json = serde_json::to_string(session)?;
    entry()?
        .set_password(&json)
        .map_err(|e| ProtonError::Config(format!("keychain write failed: {e}")))
}

/// No-op (not an error) if nothing was stored.
pub fn delete() -> Result<()> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(ProtonError::Config(format!("keychain delete failed: {e}"))),
    }
}
