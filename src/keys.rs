//! Client-side WireGuard identity generation.
//!
//! Verified against the official `proton-vpn-api-core` client's `key_mgr.py`/`credentials.py`:
//! Proton's API never hands back a WireGuard private key. The client generates its own
//! identity locally — an ed25519 seed, from which both an ed25519 keypair (used to request a
//! signed certificate) and an x25519/WireGuard keypair (used for the actual tunnel) are
//! derived. The x25519 private key is *not* a separate secret: it is
//! `clamp(SHA512(ed25519_seed)[..32])`, the same scalar Ed25519 already derives internally
//! from its seed — this is the standard Ed25519/X25519 birational correspondence, and it means
//! the x25519 public key computed from that scalar is identical to converting the ed25519
//! public key via the usual point map, without needing a separate conversion routine.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

/// ASN.1 SubjectPublicKeyInfo prefix for a raw ed25519 public key (matches the constant used
/// by Proton's own client for PEM-encoding `ClientPublicKey`).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// A freshly generated client WireGuard/certificate identity. `client::issue_credentials`
/// generates a new one on every login (fresh SRP or session resume alike) — there is no restore
/// path from a persisted seed, even though `VPNCredentials::ed25519_seed_b64` is itself stored.
pub struct ClientIdentity {
    /// Raw 32-byte ed25519 seed.
    pub ed25519_seed: [u8; 32],
}

impl ClientIdentity {
    /// Generate a fresh identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            ed25519_seed: signing_key.to_bytes(),
        }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.ed25519_seed)
    }

    /// The X25519 (WireGuard) private key, base64-encoded — this is what goes in the
    /// `[Interface] PrivateKey` line of a WireGuard config.
    pub fn wg_private_key_b64(&self) -> String {
        BASE64.encode(self.x25519_static_secret().to_bytes())
    }

    /// The X25519 (WireGuard) public key, base64-encoded.
    pub fn wg_public_key_b64(&self) -> String {
        let secret = self.x25519_static_secret();
        let public = X25519PublicKey::from(&secret);
        BASE64.encode(public.to_bytes())
    }

    fn x25519_static_secret(&self) -> X25519StaticSecret {
        let hash = Sha512::digest(self.signing_key().to_bytes());
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[..32]);
        // Explicit clamp: x25519-dalek 2.0.1's `StaticSecret::from` does NOT clamp on
        // construction (verified empirically — without this, the derived key differed from
        // Proton's reference `KeyHandler` byte-for-byte). This is the standard X25519 clamp,
        // matching Proton's own `tmp[0] &= 248; tmp[31] &= 127; tmp[31] |= 64`.
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        X25519StaticSecret::from(scalar)
    }

    /// The ed25519 public key, PEM-encoded as a SubjectPublicKeyInfo block — this is the
    /// `ClientPublicKey` value Proton's `/vpn/v1/certificate` endpoint expects.
    pub fn ed25519_public_key_pem(&self) -> String {
        let verifying_key = self.signing_key().verifying_key();
        let mut der = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
        der.extend_from_slice(&ED25519_SPKI_PREFIX);
        der.extend_from_slice(verifying_key.as_bytes());
        let b64 = BASE64.encode(&der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        pem
    }
}
