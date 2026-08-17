//! WireGuard config generation and `wg-quick` up/down control.
//!
//! Correctness reference for the config shape: <https://github.com/ProtonVPN/proton-vpn-cli>
use crate::errors::*;
use crate::models::{VPNCredentials, VPNServer};

/// Fixed interface name so `disconnect`/`status` work across process invocations.
pub const INTERFACE: &str = "proton0";

/// Generate a WireGuard `[Interface]`/`[Peer]` config.
///
/// Correctness notes (Flagged gaps vs the old Python stub):
/// - `Peer.PublicKey` must be the server's WireGuard public key (`server.wg_public_key`),
///   NEVER `ips[0]` (that is the server IP).
/// - `Interface.Address` is derived from the account/certificate, not hardcoded.
/// - `Endpoint` host is `ips[0]`, port `51820`.
pub fn generate_config(
    _server: &VPNServer,
    _creds: &VPNCredentials,
    _client_address: &str,
) -> String {
    todo!("Task 03: generate WireGuard config")
}

/// `sudo wg-quick up <config>` and record the active interface. Implemented in Task 03.
pub fn up(_config: &str) -> Result<()> {
    todo!("Task 03: wg-quick up")
}

/// `sudo wg-quick down <interface>` and clear the active marker. Implemented in Task 03.
pub fn down(_interface: &str) -> Result<()> {
    todo!("Task 03: wg-quick down")
}
