//! SRP-6a wiring + API DTO parsing tests (Task 02).
//!
//! These tests prove the crate is correctly wired to `proton-srp 0.8.2` and that the API
//! response DTOs parse as the client expects. They contain no secrets; fixtures are inline.
//!
//! The signed modulus below is a PGP-signed SRP modulus fixture borrowed from the
//! `proton-srp` crate's own test-suite (MIT/Apache). It is verified by `RPGPVerifier`, the
//! same verifier the real flow uses, so `prove` exercises the genuine PGP path.
use base64::Engine as _;
use gratis::models::{AuthInfo, AuthResponse};
use gratis::srp::prove;
use proton_srp::{SRPProofB64, SrpHashVersion};

const AUTH_INFO_FIXTURE: &str = include_str!("fixtures/auth_info.json");
const AUTH_RESPONSE_FIXTURE: &str = include_str!("fixtures/auth_response.json");

/// PGP-signed SRP modulus fixture (proton-srp test-suite). Verified by `RPGPVerifier`.
const TEST_SIGNED_MODULUS: &str = "-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

y6TtufhYg2mIeauZYOti+GPbd/0vP66kP34TgE6elK/kXkTW/Yfrp1jMmtLiWWSq5cszTMRIEighuwPbZ/z3RrWPxsOg0+jYgbFu8yZ8vOAwrPtLxZl94x0PFTAZBrVapmCn+VYcM+UXdO9v70xFDLwj34tpPbvpODHVWHSlGlhOwndWg3XBE2D9PJopFZajNZiqOScBXree5rDgzU5BBaPbIb6nySpyaeThMCcNzpcEqE8r3ro+E/VdXBvSSJpusr1dvAwHc3IDGUzAhodqV5mjYy9nXwq/9gHWpYNtm76Ols7ReWAhZwy1+cQllQZwGfzzOVGpc+3WutOntQjM6Q==
-----BEGIN PGP SIGNATURE-----
Version: ProtonMail
Comment: https://protonmail.com

wl4EARYIABAFAlwB1j8JEDUFhcTpUY8mAADfEAD8DFdNXn4TsgbfbAZRDa9a
yywqa/2W9Qyg5MJaNZd2a+0BAPg04gEZI+G8RaoPVh/SYvWx7jpP3L1O8bEi
M/j1cjIO
=5RYw
-----END PGP SIGNATURE-----";

/// Build a 256-byte server ephemeral (value 2, little-endian) that is non-zero and safely
/// below the SRP modulus N. It decodes to exactly `SRP_LEN_BYTES` and lets `generate_proofs`
/// run to completion.
fn test_server_ephemeral_b64() -> String {
    let mut buf = [0u8; proton_srp::SRP_LEN_BYTES];
    buf[0] = 2;
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// A valid base64 salt (16 bytes), borrowed from the `proton-srp` test-suite.
const TEST_SALT_B64: &str = "SzHkg+YYA/eN1A==";

#[test]
fn srp_proof_roundtrip_generates_ephemeral_and_proof() {
    let (client_ephemeral, client_proof, _expected_server_proof) = prove(
        Some("user@example.com"),
        "hunter2-correct-horse",
        SrpHashVersion::V4,
        TEST_SALT_B64,
        TEST_SIGNED_MODULUS,
        &test_server_ephemeral_b64(),
    )
    .expect("prove must succeed against the PGP-verified modulus");

    // Both proofs must be exactly SRP_LEN_BYTES (256) bytes once base64-decoded, which
    // confirms the crate is wired to proton-srp 0.8.2 (not a stub).
    let a = base64::engine::general_purpose::STANDARD
        .decode(&client_ephemeral)
        .expect("client_ephemeral is valid base64");
    let m1 = base64::engine::general_purpose::STANDARD
        .decode(&client_proof)
        .expect("client_proof is valid base64");
    assert_eq!(a.len(), proton_srp::SRP_LEN_BYTES);
    assert_eq!(m1.len(), proton_srp::SRP_LEN_BYTES);
}

/// `prove` trusts the modulus only after `RPGPVerifier` checks its PGP signature
/// (`SRPAuth::with_pgp`, see `srp.rs`'s module doc). If that check were ever skipped or broken,
/// `prove` would run real SRP math against a modulus an attacker fully controls — a modulus
/// substitution attack. Flipping a byte in the signature (not the signed message) must be
/// rejected before any SRP computation happens.
#[test]
fn prove_rejects_a_modulus_with_a_tampered_pgp_signature() {
    // Flip one byte inside the base64 signature body — corrupts the signature without
    // corrupting the ASCII-armor framing, so this still parses as a PGP message and reaches
    // signature verification rather than failing earlier on malformed input.
    let tampered_modulus = TEST_SIGNED_MODULUS.replacen(
        "wl4EARYIABAFAlwB1j8JEDUFhcTpUY8mAADfEAD8DFdNXn4TsgbfbAZRDa9a",
        "wl4EARYIABAFAlwB1j8JEDUFhcTpUY8mAADfEAD8DFdNXn4TsgbfbAZRDa9b",
        1,
    );
    assert_ne!(
        tampered_modulus, TEST_SIGNED_MODULUS,
        "test setup: the replacement must actually change the fixture"
    );

    let result = prove(
        Some("user@example.com"),
        "hunter2-correct-horse",
        SrpHashVersion::V4,
        TEST_SALT_B64,
        &tampered_modulus,
        &test_server_ephemeral_b64(),
    );

    assert!(
        result.is_err(),
        "a modulus with an invalid PGP signature must never be trusted for SRP math"
    );
}

/// The server-proof (M2) check is the *only* defense against an active MITM during login —
/// `client.rs::login` calls `.compare_server_proof(sp)` on the API's returned `ServerProof` and
/// fails the login if it doesn't match. Before this test, nothing asserted that comparison
/// actually distinguishes a correct proof from a wrong one (the roundtrip test above discards
/// `expected_server_proof` into `_expected_server_proof`) — if `compare_server_proof` were ever
/// broken (e.g. always returning `true`), login would silently succeed against a malicious
/// server and no test would catch it.
#[test]
fn server_proof_comparison_accepts_correct_and_rejects_tampered() {
    let (client_ephemeral, client_proof, expected_server_proof) = prove(
        Some("user@example.com"),
        "hunter2-correct-horse",
        SrpHashVersion::V4,
        TEST_SALT_B64,
        TEST_SIGNED_MODULUS,
        &test_server_ephemeral_b64(),
    )
    .expect("prove must succeed against the PGP-verified modulus");

    let proofs = SRPProofB64 {
        client_ephemeral,
        client_proof,
        expected_server_proof: expected_server_proof.clone(),
    };

    // The only "genuine" server proof available without a live server is the client's own
    // computed expectation — a real server that knows the password would compute this exact
    // value and return it as `ServerProof`.
    assert!(
        proofs.compare_server_proof(&expected_server_proof),
        "the correct M2 must be accepted"
    );

    // An active MITM (or a server that doesn't actually know the password) can't produce this
    // value — any other string must be rejected, not silently accepted.
    let mut tampered = expected_server_proof.clone();
    tampered.push('X');
    assert!(
        !proofs.compare_server_proof(&tampered),
        "a tampered/wrong M2 must be rejected — this is the MITM guard"
    );
    assert!(
        !proofs.compare_server_proof(""),
        "an empty server proof must be rejected, not treated as a match"
    );
}

#[test]
fn auth_response_parses_with_response_code_1000() {
    let json = r#"{
        "AccessToken": "at-123",
        "RefreshToken": "rt-123",
        "UID": "uid-123",
        "Code": 1000,
        "ServerProof": "c2VyaWZpZWRwcm9vZg=="
    }"#;
    let auth: AuthResponse = serde_json::from_str(json).expect("AuthResponse must parse");
    assert_eq!(auth.response_code, Some(1000));
    assert!(auth.access_token.is_some());
    assert_eq!(auth.server_proof.as_deref(), Some("c2VyaWZpZWRwcm9vZg=="));
}

/// `AuthInfo` (the `/auth/info` step-1 DTO) is parsed at `client.rs:126` but was never
/// deserialized in any test — including the critical `Version` field, which `client.rs` casts
/// to a `SrpHashVersion` right after this parse. `auth_info.json` existed as a checked-in
/// fixture but had zero references anywhere before this test.
#[test]
fn auth_info_fixture_deserializes() {
    let info: AuthInfo =
        serde_json::from_str(AUTH_INFO_FIXTURE).expect("auth_info.json must parse");
    assert_eq!(info.version, 4);
    assert_eq!(info.salt, "tkCXC7BqxwRPMKxGf+oRyw==");
    assert!(info.server_ephemeral.starts_with("AgB5C46khpJfBn67"));
    assert_eq!(info.srp_session, "synthetic-srp-session-id-0001");
    assert!(info.modulus.contains("BEGIN PGP SIGNED MESSAGE"));

    // The `Version` -> `SrpHashVersion` cast `client.rs` does immediately after this parse
    // (`client.rs:151`) must succeed for a real Proton response's version value.
    assert!(SrpHashVersion::try_from(info.version as u8).is_ok());
}

/// `auth_response.json` carries `RefreshToken`/`UID`/`ServerProof` together, which the inline
/// JSON in `auth_response_parses_with_response_code_1000` above also happens to cover — but the
/// fixture itself had zero references anywhere before this test (dead checked-in file).
#[test]
fn auth_response_fixture_deserializes_refresh_token_uid_and_server_proof() {
    let auth: AuthResponse =
        serde_json::from_str(AUTH_RESPONSE_FIXTURE).expect("auth_response.json must parse");
    assert_eq!(auth.response_code, Some(1000));
    assert_eq!(
        auth.access_token.as_deref(),
        Some("synthetic-access-token-0001")
    );
    assert_eq!(
        auth.refresh_token.as_deref(),
        Some("synthetic-refresh-token-0001")
    );
    assert_eq!(auth.uid.as_deref(), Some("synthetic-uid-0001"));
    assert_eq!(auth.server_proof.as_deref(), Some("c2VyaWZpZWRwcm9vZg=="));
}

// Server-list parsing (now the nested LogicalServers shape) and certificate-response parsing
// moved to tests/server_parsing.rs, alongside the fixtures that exercise them end-to-end.
