//! Credentials + active-connection state file storage.
//!
//! Credentials are written to `~/.config/proton-proxy/credentials.json` with `0600`
//! permissions. The active interface name is tracked separately so `disconnect`/`status`
//! (separate process invocations) can find the live tunnel.
use crate::errors::*;
use crate::models::VPNCredentials;
use std::path::PathBuf;

fn config_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|d| d.join("proton-proxy"))
        .ok_or_else(|| ProtonError::Config("cannot resolve config dir".into()))
}

pub fn credentials_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("credentials.json"))
}

pub fn active_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("active.json"))
}

/// Persist credentials with `0600` permissions. Implemented in Task 03.
pub fn save_credentials(_creds: &VPNCredentials) -> Result<()> {
    todo!("Task 03: persist credentials (0600)")
}

/// Load saved credentials. Implemented in Task 03.
pub fn load_credentials() -> Result<VPNCredentials> {
    todo!("Task 03: load credentials")
}

/// Record the active WireGuard interface name. Implemented in Task 03.
pub fn set_active(_interface: &str) -> Result<()> {
    todo!("Task 03: record active interface")
}

/// Clear the active-interface marker. Implemented in Task 03.
pub fn clear_active() -> Result<()> {
    todo!("Task 03: clear active interface")
}
