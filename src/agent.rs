//! Proton's "local agent" handshake — the fast, correct fix for the restricted-session bug
//! documented in `wireguard.rs`'s `Tunnel::wait_until_data_path_ready`.
//!
//! ## The problem this replaces
//!
//! Proton admits a fresh WireGuard session in a **restricted state**: TCP and plain HTTP work
//! immediately, but external TLS specifically fails for the session's first ~4-5 seconds (the
//! peer ACKs a full ClientHello and then closes with a bare FIN — no alert). Proton's own client
//! lifts this restriction immediately by authenticating to a "local agent" service reachable
//! only through the tunnel, at `10.2.0.1:65432`. `wireguard.rs`'s readiness probe worked around
//! the restriction by polling external TLS until it started succeeding; this module removes the
//! wait entirely by doing what the official client does.
//!
//! Verified live (see the spike this module was built from): the agent TLS handshake and
//! one `status-get`/reply exchange complete in well under a second, after which the very first
//! external TLS attempt succeeds — versus ~4-5s and several failures with no agent contact at
//! all.
//!
//! ## Protocol, verified against recovered fragments of Proton's own Rust client
//!
//! - Endpoint: `10.2.0.1:65432`, reached *through* the tunnel like any other destination (see
//!   [`Tunnel::connect_tcp`]) — it is not reachable from outside the tunnel.
//! - TLS SNI: the connected physical server's own domain (e.g. `node-xx.protonvpn.net`), *not*
//!   its IP — Proton's cert for this endpoint is issued for the node's domain name.
//! - Server verification: against Proton's own pinned CAs (`ROOT_CA_PEM`,
//!   `INTERMEDIATE_CA_PEM`), never system roots. This endpoint is Proton-internal
//!   infrastructure with no reason to ever be trusted by the public web PKI, and pinning is what
//!   the official client does too.
//! - Client auth: the per-device X509 certificate Proton issues at `/vpn/v1/certificate`
//!   ([`VPNCredentials::certificate`]) plus the ed25519 identity backing it
//!   ([`VPNCredentials::ed25519_seed_b64`]) — see `pkcs8_der_from_ed25519_seed` for how the
//!   raw 32-byte seed becomes a PKCS#8 key `rustls` can load.
//! - Framing: every message (both directions) is a 4-byte big-endian length prefix followed by
//!   that many bytes of JSON. Verified against the official client's `transport_stream.rs`.
//! - Request/reply: send `{"status-get":{}}`, expect back a `{"status": {...}}` (or
//!   `{"error": {...}}`) reply. A live example, captured from this exact codebase:
//!   `{"status":{"state":"connected","features":{"jail":false,...},"restrictions":[],...}}`.
//!
//! ## Fallback, not replacement
//!
//! Every failure mode here — network error, TLS/cert failure, a protocol change, or (novel) a
//! reply that reports the session as genuinely jailed/restricted — is treated as "this approach
//! didn't work this time", never as a fatal error for the caller. `manager.rs` falls back to
//! `Tunnel::wait_until_data_path_ready`'s polling probe on any [`Err`] from
//! [`unlock`], so a protocol change on Proton's side degrades gratis back to its
//! previous (slower, but working) behaviour instead of breaking connections outright.
use crate::errors::*;
use crate::models::VPNCredentials;
use crate::wireguard::{Tunnel, TunnelConnection};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

/// Fixed address of Proton's local-agent service, reachable only through the tunnel. Verified
/// against the official client's `agent_connector.rs` (`SERVER_ADDR = "10.2.0.1:65432"`) — like
/// [`crate::wireguard::CLIENT_ADDRESS`], this is a constant Proton's own client hard-codes, not
/// something derived per-account or per-connection.
pub const AGENT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)), 65432);

/// Overall budget for connect + TLS handshake + one request/reply round trip. Measured live at
/// well under a second; this is generous headroom, not a target — [`unlock`]
/// returning slowly is itself a signal something's wrong, and the caller falls back either way.
const AGENT_TIMEOUT: Duration = Duration::from_secs(8);

/// Refuse to allocate a reply buffer larger than this. The real agent's replies are a few hundred
/// bytes; this is only a guard against a corrupted/malicious length prefix causing an unbounded
/// allocation, not a realistic protocol limit.
const MAX_REPLY_LEN: usize = 1 << 20;

/// Proton's root CA for `*.protonvpn.net`'s local-agent service, pinned rather than trusted via
/// system roots — this endpoint is Proton-internal infrastructure, never meant to be reachable
/// or verifiable via the public web PKI. Copied verbatim from a live TLS handshake to the real
/// endpoint (see the module doc comment); Proton's official client embeds the same PEM.
const ROOT_CA_PEM: &str = include_str!("../assets/certs/proton-root-ca.pem");
/// Intermediate CA completing the chain from `ROOT_CA_PEM` to the leaf cert the agent actually
/// presents.
const INTERMEDIATE_CA_PEM: &str = include_str!("../assets/certs/proton-intermediate-ca.pem");

/// The literal 16-byte ASN.1 prefix that turns a raw 32-byte Ed25519 private key seed into a
/// complete PKCS#8 v1 `PrivateKeyInfo` DER structure, per RFC 8410 §7 / RFC 5958. Ed25519 PKCS#8
/// has no variable-length fields around the key itself (no parameters, no optional attributes in
/// this shape), so this prefix is always exactly these bytes for any 32-byte seed — there's
/// nothing account-specific in it. `rustls` (via `rustls-pki-types`) only accepts keys in
/// standard DER containers (PKCS#8/SEC1/PKCS#1), not a bare seed, and Proton's API hands back
/// only the raw seed (see [`VPNCredentials::ed25519_seed_b64`]), so this construction is
/// required to bridge the two.
const ED25519_PKCS8_V1_HEADER: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The framed request body this module always sends: a status query with no extra options. See
/// [`crate::agent`]'s module doc comment for the framing format.
const STATUS_GET_REQUEST: &[u8] = br#"{"status-get":{}}"#;

/// Prefix a raw 32-byte Ed25519 seed with [`ED25519_PKCS8_V1_HEADER`] to produce a PKCS#8 DER
/// key `rustls` can load directly.
fn pkcs8_der_from_ed25519_seed(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(ED25519_PKCS8_V1_HEADER.len() + seed.len());
    der.extend_from_slice(&ED25519_PKCS8_V1_HEADER);
    der.extend_from_slice(seed);
    der
}

/// 4-byte big-endian length prefix followed by `payload` — the framing every local-agent message
/// uses in both directions.
fn frame_message(payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    framed
}

/// Build the pinned root store from `ROOT_CA_PEM` and `INTERMEDIATE_CA_PEM` — never system
/// roots (see the module doc comment for why).
fn build_root_store() -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for pem in [ROOT_CA_PEM, INTERMEDIATE_CA_PEM] {
        for cert in rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes())) {
            let cert =
                cert.map_err(|e| ProtonError::LocalAgent(format!("bad pinned CA pem: {e}")))?;
            store
                .add(cert)
                .map_err(|e| ProtonError::LocalAgent(format!("bad pinned CA cert: {e}")))?;
        }
    }
    Ok(store)
}

/// Build the client TLS config: pinned server verification plus client-certificate auth from
/// `creds`.
fn build_client_config(creds: &VPNCredentials) -> Result<ClientConfig> {
    let root_store = build_root_store()?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut Cursor::new(creds.certificate.as_bytes()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| ProtonError::LocalAgent(format!("bad client cert pem: {e}")))?;
    if certs.is_empty() {
        return Err(ProtonError::LocalAgent(
            "client certificate PEM contained no certificates".into(),
        ));
    }

    let seed_bytes = BASE64
        .decode(&creds.ed25519_seed_b64)
        .map_err(|e| ProtonError::LocalAgent(format!("bad ed25519 seed base64: {e}")))?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| ProtonError::LocalAgent("ed25519 seed is not 32 bytes".into()))?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der_from_ed25519_seed(&seed)));

    // Use an explicit crypto provider rather than relying on a process-wide default having been
    // installed (via `CryptoProvider::install_default`) by the time this runs — `reqwest`'s
    // rustls-tls stack may or may not have installed one first depending on request ordering,
    // and `ClientConfig::builder()` panics if none is installed. `ring` is already in the
    // dependency graph (both `reqwest` and this module resolve to the same rustls 0.23 major —
    // see `Cargo.toml`), so this adds no new crypto backend to the binary.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ProtonError::LocalAgent(format!("tls protocol versions: {e}")))?
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .map_err(|e| ProtonError::LocalAgent(format!("bad client cert/key: {e}")))?;

    Ok(config)
}

/// Keeps the pump tasks (and the underlying tunnel connection) alive for as long as a
/// [`PumpedConnection`]'s duplex half is in use, and tears both down on drop.
struct PumpGuard {
    conn: Arc<dyn TunnelConnection>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl Drop for PumpGuard {
    fn drop(&mut self) {
        // `shutdown()` unblocks the reader pump's `conn.read()` if it's still waiting on the
        // tunnel; `abort()` on both is a backstop in case either pump is stuck for some other
        // reason (e.g. a `TunnelConnection` impl whose `read`/`write_all` never returns). Without
        // this, using `unlock` in a loop (as `ServerSlot::acquire` re-verification
        // does over a tunnel's lifetime) would leak two tasks and one open tunnel connection per
        // call.
        self.conn.shutdown();
        self.reader.abort();
        self.writer.abort();
    }
}

/// Bridge a [`TunnelConnection`] (a custom `&self`-based async trait — see its doc comment in
/// `wireguard.rs`) to a real `tokio::io::AsyncRead + AsyncWrite` type `tokio_rustls` can drive.
///
/// `TunnelConnection` can't implement `AsyncRead`/`AsyncWrite` directly: those traits are
/// poll-based and need `&mut self`, while `TunnelConnection`'s methods are plain `async fn`s
/// on `&self` (to match `wireguard_netstack::TcpConnection`'s shape). Hand-rolling
/// `poll_read`/`poll_write` on top of `async fn`s would need a manual per-call future/waker state
/// machine to bridge "poll-driven" and "async fn-driven" I/O correctly. Spawning two small copy
/// loops between the tunnel connection and one end of an in-process `tokio::io::duplex` pipe
/// sidesteps that entirely: the other end of the pipe is a genuine `AsyncRead + AsyncWrite`, and
/// `tokio_rustls::TlsConnector` needs nothing more than that. The cost is two extra tasks and one
/// extra in-memory copy per direction, which is irrelevant at this message's size and frequency.
fn spawn_pump(conn: Arc<dyn TunnelConnection>) -> (tokio::io::DuplexStream, PumpGuard) {
    let (tls_side, net_side) = tokio::io::duplex(16 * 1024);
    let (mut net_read, mut net_write) = tokio::io::split(net_side);

    let reader = {
        let conn = conn.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if net_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        })
    };

    let writer = {
        let conn = conn.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match net_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if conn.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        })
    };

    (
        tls_side,
        PumpGuard {
            conn,
            reader,
            writer,
        },
    )
}

/// Reply shape this module actually cares about. Deliberately smaller than the official client's
/// `StatusMessage` (see the recovered `_src_message.rs` fragment this was checked against) —
/// only the fields needed to decide "unrestricted" vs. "not" are modeled; anything else in the
/// real reply is ignored rather than rejected, so an unrelated field Proton adds later doesn't
/// break this parse.
#[derive(Debug, Deserialize)]
struct AgentReply {
    status: Option<AgentStatus>,
    error: Option<AgentErrorMsg>,
}

#[derive(Debug, Deserialize)]
struct AgentStatus {
    state: String,
    #[serde(default)]
    features: Option<AgentFeaturesFlags>,
    #[serde(default)]
    restrictions: Vec<serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct AgentFeaturesFlags {
    #[serde(default)]
    jail: bool,
}

#[derive(Debug, Deserialize)]
struct AgentErrorMsg {
    code: u32,
    description: String,
}

/// Decide whether a framed reply body means "this session is genuinely unrestricted".
///
/// Three ways to fail, all `Err`: a `{"error": ...}` reply, a `{"status": ...}` reply whose state
/// isn't `"connected"`, or — worth calling out specifically, since it's a real finding rather
/// than a plumbing failure — a `"connected"` reply that nonetheless reports `jail: true` or a
/// non-empty `restrictions` list, meaning the account/session actually is restricted and no
/// amount of retrying the handshake will fix that.
fn validate_reply(body: &[u8]) -> Result<()> {
    let reply: AgentReply = serde_json::from_slice(body)
        .map_err(|e| ProtonError::LocalAgent(format!("malformed agent reply: {e}")))?;

    if let Some(err) = reply.error {
        return Err(ProtonError::LocalAgent(format!(
            "agent returned error {}: {}",
            err.code, err.description
        )));
    }

    let Some(status) = reply.status else {
        return Err(ProtonError::LocalAgent(
            "agent reply had neither status nor error".into(),
        ));
    };

    if status.state != "connected" {
        return Err(ProtonError::LocalAgent(format!(
            "agent reports state {:?}, not connected",
            status.state
        )));
    }

    let jailed = status.features.map(|f| f.jail).unwrap_or(false);
    if jailed || !status.restrictions.is_empty() {
        // Unlike a network hiccup, this means the account/session is actually restricted by
        // Proton — worth a human noticing. The descriptive `Err` below carries that detail; it's
        // the caller's job to decide whether/how often to log it (see `manager.rs`), so this
        // function itself stays silent rather than printing on every single call.
        return Err(ProtonError::LocalAgent(format!(
            "session jailed/restricted (jail={jailed}, restrictions={:?})",
            status.restrictions
        )));
    }

    Ok(())
}

/// Complete Proton's local agent handshake through `tunnel`, using `sni` (the connected physical
/// server's own domain — see the module doc comment) and `creds` for client-cert auth.
///
/// `Ok(())` means the agent confirmed this session is unrestricted *right now*; the caller can
/// proceed immediately, with no need for `Tunnel::wait_until_data_path_ready`'s wait. Any
/// `Err` — including a reply that reports the session as jailed — means the caller should fall
/// back to that probe instead (see the module doc comment).
pub async fn unlock(tunnel: &Tunnel, sni: &str, creds: &VPNCredentials) -> Result<()> {
    if matches!(tunnel, Tunnel::Loopback) {
        // The test loopback tunnel is a plain local `TcpStream` with no WireGuard session behind
        // it, so there is no local agent to talk to — fail fast and let the caller fall back
        // (which is itself a no-op for the loopback tunnel).
        return Err(ProtonError::LocalAgent(
            "no local agent on the test loopback tunnel".into(),
        ));
    }

    match tokio::time::timeout(AGENT_TIMEOUT, unlock_inner(tunnel, sni, creds)).await {
        Ok(result) => result,
        Err(_) => Err(ProtonError::LocalAgent(format!(
            "timed out after {AGENT_TIMEOUT:?}"
        ))),
    }
}

async fn unlock_inner(tunnel: &Tunnel, sni: &str, creds: &VPNCredentials) -> Result<()> {
    let config = build_client_config(creds)?;
    let connector = TlsConnector::from(Arc::new(config));

    let raw_conn = tunnel
        .connect_tcp(AGENT_ADDR)
        .await
        .map_err(|e| ProtonError::LocalAgent(format!("connect to agent endpoint: {e}")))?;
    let conn: Arc<dyn TunnelConnection> = Arc::from(raw_conn);
    let (tls_side, _pump_guard) = spawn_pump(conn);

    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| ProtonError::LocalAgent(format!("bad SNI {sni:?}: {e}")))?;

    let mut tls = connector
        .connect(server_name, tls_side)
        .await
        .map_err(|e| ProtonError::LocalAgent(format!("tls handshake: {e}")))?;

    tls.write_all(&frame_message(STATUS_GET_REQUEST))
        .await
        .map_err(|e| ProtonError::LocalAgent(format!("send status-get: {e}")))?;

    let mut len_buf = [0u8; 4];
    tls.read_exact(&mut len_buf)
        .await
        .map_err(|e| ProtonError::LocalAgent(format!("read reply length: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_REPLY_LEN {
        return Err(ProtonError::LocalAgent(format!(
            "agent reply claims implausible length {len}"
        )));
    }

    let mut body = vec![0u8; len];
    tls.read_exact(&mut body)
        .await
        .map_err(|e| ProtonError::LocalAgent(format!("read reply body: {e}")))?;

    validate_reply(&body)?;

    // Best-effort: the connection is about to be dropped (tearing down `_pump_guard` with it)
    // either way, so a failed shutdown here isn't worth surfacing as an error.
    let _ = tls.shutdown().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs8_wrapping_produces_the_expected_header_and_length() {
        let seed = [0x42u8; 32];
        let der = pkcs8_der_from_ed25519_seed(&seed);

        assert_eq!(der.len(), 48, "16-byte header + 32-byte seed");
        assert_eq!(&der[..16], &ED25519_PKCS8_V1_HEADER);
        assert_eq!(&der[16..], &seed);
    }

    #[test]
    fn pkcs8_wrapping_is_parseable_by_rustls() {
        // Round-trip through rustls's own key loader rather than just asserting the byte layout,
        // so this test would actually fail if the header were wrong in a way that byte-length
        // assertions alone wouldn't catch.
        let seed = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng).to_bytes();
        let der = pkcs8_der_from_ed25519_seed(&seed);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der));
        // `rustls::crypto::ring::sign::any_eddsa_type` is the codepath `with_client_auth_cert`
        // uses internally to validate a supplied private key.
        assert!(
            rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(
                key.secret_der().to_vec()
            ))
            .is_ok(),
            "PKCS#8 wrapping of a raw ed25519 seed must be loadable as an EdDSA signing key"
        );
    }

    #[test]
    fn frame_message_is_a_4_byte_be_length_prefix_then_the_payload() {
        let payload = STATUS_GET_REQUEST;
        let framed = frame_message(payload);

        assert_eq!(framed.len(), 4 + payload.len());
        let len = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
        assert_eq!(len, payload.len());
        assert_eq!(&framed[4..], payload);
    }

    #[test]
    fn embedded_ca_pems_parse() {
        build_root_store().expect("both pinned CA PEMs must parse as valid certificates");
    }

    /// Guards against an accidental *or malicious* swap of either pinned trust anchor: if either
    /// embedded PEM ever changes to a certificate other than the exact one this codebase was
    /// reviewed and shipped with, this must fail loudly in CI rather than silently changing who
    /// `agent`'s TLS verification trusts. Expected values verified independently with
    /// `openssl x509 -in <file> -noout -fingerprint -sha256` — see `assets/certs/README.md` for
    /// full provenance (both certs were extracted from the embedded `rustls::RootCertStore`
    /// compiled into Proton's own official client, `local_agent.abi3.so`).
    #[test]
    fn embedded_ca_pems_have_the_expected_sha256_fingerprint() {
        use sha2::{Digest, Sha256};

        fn fingerprint(pem: &str) -> String {
            let cert = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
                .next()
                .expect("pem must contain a certificate")
                .expect("pem must parse");
            let digest = Sha256::digest(cert.as_ref());
            digest
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        }

        assert_eq!(
            fingerprint(ROOT_CA_PEM),
            "47:47:92:C8:6C:A0:E7:2F:6C:04:EA:87:CB:FD:49:9D:A3:8C:58:F4:46:6E:7B:25:8C:DF:67:DA:34:65:6E:31",
            "ProtonVPN Root CA fingerprint changed — verify independently before updating this test"
        );
        assert_eq!(
            fingerprint(INTERMEDIATE_CA_PEM),
            "A3:70:5C:D0:79:0C:8A:66:5A:E7:E8:E4:26:99:74:C2:EE:31:8A:ED:03:CF:0C:7E:86:0C:22:28:CF:17:E4:AB",
            "ProtonVPN Intermediate CA 1 fingerprint changed — verify independently before updating this test"
        );
    }

    #[test]
    fn validate_reply_accepts_a_connected_unrestricted_reply() {
        let body =
            br#"{"status":{"state":"connected","features":{"jail":false},"restrictions":[]}}"#;
        assert!(validate_reply(body).is_ok());
    }

    #[test]
    fn validate_reply_rejects_a_jailed_reply_even_though_state_is_connected() {
        let body =
            br#"{"status":{"state":"connected","features":{"jail":true},"restrictions":[]}}"#;
        let err =
            validate_reply(body).expect_err("a jailed session must not be treated as unlocked");
        assert!(format!("{err}").contains("jail"));
    }

    #[test]
    fn validate_reply_rejects_a_reply_with_active_restrictions() {
        let body =
            br#"{"status":{"state":"connected","features":{"jail":false},"restrictions":["net"]}}"#;
        assert!(validate_reply(body).is_err());
    }

    #[test]
    fn validate_reply_rejects_a_non_connected_state() {
        let body =
            br#"{"status":{"state":"hard-jailed","features":{"jail":true},"restrictions":[]}}"#;
        assert!(validate_reply(body).is_err());
    }

    #[test]
    fn validate_reply_rejects_an_error_reply() {
        let body = br#"{"error":{"code":86203,"description":"session has no fingerprint"}}"#;
        assert!(validate_reply(body).is_err());
    }

    #[test]
    fn validate_reply_rejects_malformed_json() {
        assert!(validate_reply(b"not json").is_err());
    }
}
