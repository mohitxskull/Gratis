//! SRP-6a authentication wrapper.
//!
//! Real Proton SRP-6a is implemented by the `proton-srp` crate (feature `pgpinternal`
//! provides `RPGPVerifier` to check the PGP-signed modulus). This module is the seam the
//! real implementation (Task 02) plugs into; the stub here keeps the crate compiling.
//!
//! Reference: <https://github.com/ProtonVPN/proton-vpn-cli>
use crate::errors::*;

/// Produce the SRP client ephemeral (A) and client proof (M1) for a login attempt.
///
/// `modulus` is the PGP-signed message from `/auth/v4/info`; `server_ephemeral` is B.
/// Implemented in Task 02 on top of `proton_srp::{SRPAuth, RPGPVerifier}`.
pub fn prove(
    _password: &str,
    _version: u32,
    _modulus: &str,
    _server_ephemeral: &str,
) -> Result<(String, String)> {
    todo!("Task 02: implement SRP-6a via proton-srp")
}
