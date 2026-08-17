//! SRP-6a authentication wrapper.
//!
//! Real Proton SRP-6a is implemented by the `proton-srp` crate (feature `pgpinternal`
//! provides `RPGPVerifier` to check the PGP-signed modulus). The modulus Proton ships in
//! `/auth/v4/info` is wrapped in a PGP-signed message; `SRPAuth::with_pgp` verifies that
//! signature via `RPGPVerifier` before trusting it, so we never run SRP against a tampered
//! modulus.
//!
//! Reference: <https://github.com/ProtonVPN/proton-vpn-cli>
use crate::errors::*;
use proton_srp::{SRPAuth, SRPProofB64, SrpHashVersion};

/// Produce the SRP client ephemeral (A), client proof (M1) and expected server proof for a
/// login attempt.
///
/// `modulus` is the PGP-signed message from `/auth/v4/info`; `server_ephemeral` is B.
/// `username` is obsolete for `SrpHashVersion >= V3` (the current default `V4`) and may be
/// `None`, but we pass `Some(email)` to be safe for older accounts.
pub fn prove(
    username: Option<&str>,
    password: &str,
    version: SrpHashVersion,
    salt: &str,
    modulus: &str,
    server_ephemeral: &str,
) -> Result<(String, String, String)> {
    let auth = SRPAuth::with_pgp(username, password, version, salt, modulus, server_ephemeral)?;
    let proof = auth.generate_proofs()?;
    let b64: SRPProofB64 = proof.into();
    Ok((
        b64.client_ephemeral,
        b64.client_proof,
        b64.expected_server_proof,
    ))
}
