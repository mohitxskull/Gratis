//! Userspace WireGuard tunnel — no root, no `sudo`, no real network interface.
//!
//! Verified live: a raw WireGuard handshake plus a real HTTP request/response through a
//! tunnel built from exactly this key/config shape both succeeded, without performing the
//! "local agent" authorization step Proton's official client does. That is *nearly* true, with
//! one important caveat found later: skipping the local agent leaves each new session in a
//! restricted state for its first few seconds, during which external TLS specifically is
//! blocked — see `Tunnel::wait_until_data_path_ready`, which waits that window out. That means
//! this daemon can speak WireGuard entirely in-process via [`wireguard_netstack`] (itself
//! built on `gotatun` + `smoltcp`) instead of shelling out to `sudo wg-quick` against a real
//! kernel interface — a much better fit for "just run the binary" than the plan's original
//! root-requiring design, and it structurally removes the whole class of bugs the earlier
//! `sudo wg-quick`-based implementation had (leaked kernel interfaces on teardown failure,
//! `is_up` requiring root to even ask the question, boot reconciliation of stale interfaces —
//! none of that state exists to leak when there is no real interface: a tunnel is just
//! in-process memory + a UDP socket, and it cannot outlive the daemon process that holds it).
use crate::errors::*;
use crate::models::{VPNCredentials, VPNServer};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;
use wireguard_netstack::{ManagedTunnel, WireGuardConfig};

/// Standard Proton WireGuard UDP port.
pub const WG_PORT: u16 = 51820;

/// Fixed client tunnel address Proton's own client uses for every WireGuard connection.
///
/// Verified against `proton.vpn.backend.networkmanager.protocol.wireguard.wireguard`
/// (`wg_config.ipv4.address = "10.2.0.2"`, prefix `/32`): this is NOT derived per-account or
/// per-connection at all.
pub const CLIENT_ADDRESS: &str = "10.2.0.2";

/// Endpoint used by [`Tunnel::wait_until_data_path_ready`]'s readiness probe.
///
/// A hard-coded anycast IP rather than a hostname on purpose: the probe runs while a tunnel is
/// still coming up, and resolving a name first would add a DNS round trip (and a DNS failure
/// mode) to a health check whose whole job is to answer one narrow question. `1.1.1.1:443` is a
/// stable, globally anycast TLS endpoint, and the probe only needs *some* well-known TLS peer —
/// no data is exchanged with it beyond a ClientHello and the first record of the reply.
const PROBE_ENDPOINT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);

/// How long a fresh tunnel is given to become usable before it is served anyway. Measured
/// live at ~4-5s across independent servers, so this is generous headroom for a slow one.
const PROBE_BUDGET: Duration = Duration::from_secs(30);

/// Gap between readiness probes.
const PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// How long a single probe waits for the peer's first TLS record before giving up on it.
const PROBE_READ_TIMEOUT: Duration = Duration::from_secs(4);

/// TLS record content type for `Handshake` (RFC 8446 §5.1) — what a ServerHello arrives as.
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// How long [`Tunnel::connect_tcp`] retries a fresh TCP connect through the tunnel before
/// giving up.
///
/// Verified live: a `connect_tcp` attempt made immediately after a tunnel's WireGuard
/// handshake completes regularly failed outright (SYN never answered, socket state going
/// straight to `Closed`) while a retry moments later succeeded — for **plain, non-TLS**
/// destinations too, so this is a different, more basic phenomenon than the TLS-specific
/// restricted-session block `wait_until_data_path_ready`'s doc comment describes (that one
/// claims bare TCP is unaffected). It also only reproduced reliably while many tunnels were
/// being brought up concurrently, so it may be this process's userspace WireGuard/netstack
/// tasks (each polling every 1ms — see `run_poll_loop` in the `wireguard-netstack` crate)
/// losing the race for CPU time under load rather than anything server-side. Either way, a
/// short retry here is the same defensive answer regardless of which it is, and unlike
/// `wait_until_data_path_ready`'s ~30s TLS-probe budget (which only runs as a fallback when
/// the local-agent unlock fails — see `manager.rs::unlock_tunnel`), this covers *every*
/// `connect_tcp` call, including ones made right after a successful agent unlock that
/// `unlock_tunnel` currently trusts without any further readiness check.
#[cfg(not(test))]
const TCP_CONNECT_RETRY_BUDGET: Duration = Duration::from_secs(5);
#[cfg(test)]
const TCP_CONNECT_RETRY_BUDGET: Duration = Duration::from_millis(60);

/// Pause between `connect_tcp` retries within [`TCP_CONNECT_RETRY_BUDGET`].
#[cfg(not(test))]
const TCP_CONNECT_RETRY_BACKOFF: Duration = Duration::from_millis(200);
#[cfg(test)]
const TCP_CONNECT_RETRY_BACKOFF: Duration = Duration::from_millis(5);

/// A minimal, static TLS 1.2 ClientHello used solely as a readiness probe.
///
/// Hand-built rather than pulled from a TLS library because the probe never completes a
/// handshake: it only needs enough of a valid ClientHello for the peer to answer with a
/// ServerHello record, which is the signal that the tunnel's data path is live. Deliberately
/// small (~90 bytes, one TCP segment) so the probe tests tunnel readiness rather than
/// segmentation behaviour.
fn probe_client_hello() -> Vec<u8> {
    const SNI_HOST: &[u8] = b"one.one.one.one";

    let mut extensions = Vec::new();
    // server_name (0x0000)
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&((SNI_HOST.len() + 5) as u16).to_be_bytes());
    extensions.extend_from_slice(&((SNI_HOST.len() + 3) as u16).to_be_bytes());
    extensions.push(0x00); // host_name
    extensions.extend_from_slice(&(SNI_HOST.len() as u16).to_be_bytes());
    extensions.extend_from_slice(SNI_HOST);
    // supported_groups (0x000a): secp256r1
    extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17]);
    // ec_point_formats (0x000b): uncompressed
    extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    // signature_algorithms (0x000d): rsa_pkcs1_sha256
    extensions.extend_from_slice(&[0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x01]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version: TLS 1.2
    body.extend_from_slice(&[0xAA; 32]); // random (fixed: nothing is negotiated)
    body.push(0x00); // session_id: empty
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0xc0, 0x2f]); // ECDHE_RSA_WITH_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![0x01]; // ClientHello
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // u24 length
    handshake.extend_from_slice(&body);

    let mut record = vec![TLS_CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn decode_key(b64: &str) -> Result<[u8; 32]> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| ProtonError::Config(format!("invalid base64 key: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| ProtonError::Config("key is not 32 bytes".into()))
}

/// One TCP connection opened through a [`Tunnel`]. `wireguard_netstack::TcpConnection`
/// doesn't implement `tokio::io::AsyncRead`/`AsyncWrite`, so this small trait — rather than a
/// concrete type — is what `socks5.rs`'s relay code works against; it's also what lets
/// [`Tunnel::loopback_for_testing`] substitute a real local `TcpStream` for integration tests
/// that need genuine byte-for-byte relay correctness without a live WireGuard tunnel.
#[async_trait]
pub trait TunnelConnection: Send + Sync {
    async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    async fn write_all(&self, data: &[u8]) -> std::io::Result<()>;
    fn shutdown(&self);
}

#[async_trait]
impl TunnelConnection for wireguard_netstack::TcpConnection {
    /// `wireguard_netstack::TcpConnection::read` enforces its own hardcoded 30-second no-data
    /// timeout internally (see its `netstack.rs`) and returns `Error::ReadTimeout` even though
    /// the connection itself is still fully alive — genuine closes are already reported
    /// separately (`Ok(0)`, checked via `may_recv` before the timeout check even runs), so a
    /// `ReadTimeout` specifically means "no bytes in this particular 30s window," not "this
    /// connection is dead." Left unhandled, that directly contradicts `socks5.rs`'s own
    /// documented "no idle timeout — streaming/SSE/WebSocket connections with long quiet gaps
    /// must survive" guarantee: a relayed SSE stream (e.g. Zen's free-tier models, which
    /// routinely pause 30-90s mid-response during "thinking") would get cut after 30 seconds of
    /// silence, indistinguishable downstream from the exit itself failing. Retrying past it
    /// keeps this call blocked exactly as long as the caller's own actual idle tolerance
    /// dictates, matching the module's stated intent instead of the crate's internal default.
    async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match wireguard_netstack::TcpConnection::read(self, buf).await {
                Ok(n) => return Ok(n),
                Err(wireguard_netstack::Error::ReadTimeout) => continue,
                Err(err) => return Err(std::io::Error::other(err)),
            }
        }
    }

    /// Deliberately NOT retried on `WriteTimeout` the way `read` retries `ReadTimeout` above:
    /// the crate's internal `write()` tracks how many bytes it got through before timing out,
    /// but `Err(WriteTimeout)` discards that count rather than returning it — so blindly
    /// retrying with the same full `data` here would re-send whatever prefix already made it
    /// out, corrupting the stream. Safely retrying would need the crate itself to report partial
    /// progress on timeout; without that, surfacing the error as-is (ending this connection) is
    /// the only correct option.
    async fn write_all(&self, data: &[u8]) -> std::io::Result<()> {
        wireguard_netstack::TcpConnection::write_all(self, data)
            .await
            .map_err(std::io::Error::other)
    }

    fn shutdown(&self) {
        wireguard_netstack::TcpConnection::shutdown(self)
    }
}

/// Test-only [`TunnelConnection`] wrapping a plain local `TcpStream` — no WireGuard involved.
/// `tokio::io::AsyncRead`/`AsyncWrite` need `&mut self`, but this trait's methods take `&self`
/// (to match `wireguard_netstack::TcpConnection`'s shape), so calls serialize through a mutex
/// — but read and write get SEPARATE mutexes over split halves. A single mutex over the whole
/// stream would deadlock a full-duplex relay: `to_client`'s `read()` blocks (holding the lock)
/// waiting for data that only arrives after `to_tunnel`'s `write_all()` runs, which needs that
/// same lock. Fine for a test fixture, not meant for production traffic volumes.
struct LoopbackConnection {
    read_half: AsyncMutex<tokio::net::tcp::OwnedReadHalf>,
    write_half: AsyncMutex<tokio::net::tcp::OwnedWriteHalf>,
}

impl LoopbackConnection {
    fn new(stream: tokio::net::TcpStream) -> Self {
        let (read_half, write_half) = stream.into_split();
        Self {
            read_half: AsyncMutex::new(read_half),
            write_half: AsyncMutex::new(write_half),
        }
    }
}

#[async_trait]
impl TunnelConnection for LoopbackConnection {
    async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncReadExt;
        self.read_half.lock().await.read(buf).await
    }

    async fn write_all(&self, data: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.write_half.lock().await.write_all(data).await
    }

    fn shutdown(&self) {
        // Best-effort: a std-level shutdown needs `&mut`, which we can't get through `&self`
        // without blocking on the async mutex from a sync context. Dropping the connection
        // (which happens once the relay task holding it exits) closes it anyway; this is a
        // test-only fixture, not a path production traffic takes.
    }
}

/// A live tunnel that TCP connections can be opened through.
pub enum Tunnel {
    /// A real userspace WireGuard session.
    Real(ManagedTunnel),
    /// Test-only: connects with a plain local `TcpStream`, no WireGuard involved at all. Used
    /// by `tests/socks5_relay.rs` to test SOCKS5 relay correctness (bytes flow, idle survives)
    /// against a local echo server on `lo`, without needing a live WireGuard tunnel or a
    /// Proton account. Never constructed by production code — `manager.rs` only ever builds a
    /// tunnel via [`Tunnel::connect`].
    Loopback,
}

impl Tunnel {
    /// Bring up a tunnel to `server`'s picked physical server, using `creds`' locally
    /// generated WireGuard keypair. Performs the handshake before returning.
    pub async fn connect(server: &VPNServer, creds: &VPNCredentials) -> Result<Self> {
        let physical = server.pick_physical().ok_or_else(|| {
            ProtonError::Config(format!("server {} has no physical servers", server.name))
        })?;

        let peer_endpoint: SocketAddr = format!("{}:{WG_PORT}", physical.entry_ip)
            .parse()
            .map_err(|e| ProtonError::Config(format!("bad peer endpoint: {e}")))?;

        let config = WireGuardConfig {
            private_key: decode_key(&creds.wg_private_key)?,
            peer_public_key: decode_key(&physical.x25519_public_key)?,
            peer_endpoint,
            tunnel_ip: CLIENT_ADDRESS
                .parse()
                .expect("CLIENT_ADDRESS is a valid IPv4 literal"),
            preshared_key: None,
            keepalive_seconds: Some(25),
            mtu: None,
        };

        let managed = ManagedTunnel::connect(config).await?;
        Ok(Self::Real(managed))
    }

    /// Block until external TLS actually works through this tunnel, or [`PROBE_BUDGET`] elapses.
    ///
    /// ## The bug this fixes
    ///
    /// Proton admits a new WireGuard session in a **restricted state** and only lifts that
    /// restriction once its "local agent" authenticates — or, if no agent ever shows up, after a
    /// grace period of roughly four seconds. `gratis` does not implement the local agent (see
    /// [`crate::models::VPNCredentials::certificate`]), so every fresh session spends those first
    /// seconds restricted, and whichever client connection arrives first lands in that window and
    /// fails.
    ///
    /// The restriction is oddly selective, which is what made this look like a random TLS bug:
    ///
    /// - TCP through the tunnel connects normally, and the far end even ACKs application data.
    /// - Plain-HTTP requests succeed, including large multi-packet ones.
    /// - But an external TLS handshake dies — the peer ACKs the entire ClientHello and then
    ///   closes with a bare FIN, surfacing to users as `curl: (35)` /
    ///   `SSL routines::unexpected eof while reading`.
    ///
    /// Evidence that this is Proton-side session state and not a local transport fault: during
    /// the failing window a TLS connection to Proton's own local-agent endpoint
    /// (`10.2.0.1:65432`) is answered *immediately* with a well-formed TLS alert, i.e. the tunnel
    /// and its TLS path are fully functional while external TLS is being blocked.
    ///
    /// Ruled out by direct experiment: payload size (a hand-built 93-byte single-packet
    /// ClientHello fails too), TCP segmentation and packet reordering (single packets fail, and a
    /// 100 KiB plain-HTTP download through the same tunnel is byte-identical to a direct one),
    /// tunnel MTU (1420 and 900 both tested; 1420 breaks the tunnel outright by exceeding the
    /// path MTU after encapsulation), and destination reputation (two unrelated destinations fail
    /// and then recover in lockstep on the same tunnel).
    ///
    /// ## Why a TLS probe
    ///
    /// The restriction only affects external TLS, so the readiness check has to *be* an external
    /// TLS handshake. A bare TCP connect succeeds throughout the restricted window and would be a
    /// useless signal. Measured live, a fresh tunnel passes after ~4 probes / 4-5s, consistently
    /// across independent servers.
    ///
    /// Implementing the local agent would remove the wait entirely rather than wait it out, and
    /// is the natural follow-up; it needs client-certificate TLS over the userspace tunnel plus
    /// Proton's proprietary agent protocol, which is well beyond this fix.
    ///
    /// Best-effort by design: if the budget runs out the tunnel is still used, so a slow or
    /// unhealthy server surfaces as a normal connection error rather than a silent stall.
    pub(crate) async fn wait_until_data_path_ready(&self, server_name: &str) {
        // The test loopback "tunnel" is a plain local TcpStream with no WireGuard session, so
        // there is no warm-up window to wait out and no external endpoint to probe.
        if matches!(self, Self::Loopback) {
            return;
        }

        // Escape hatch for diagnosing the readiness window itself (see this method's docs):
        // with the probe skipped, a fresh tunnel exhibits the raw upstream behaviour.
        if std::env::var_os("GRATIS_SKIP_READINESS_PROBE").is_some() {
            return;
        }

        let started = std::time::Instant::now();
        let mut attempts = 0u32;

        while started.elapsed() < PROBE_BUDGET {
            attempts += 1;
            if self.probe_once().await {
                return;
            }
            tokio::time::sleep(PROBE_INTERVAL).await;
        }

        log::warn!(
            "tunnel to {server_name} did not pass its readiness probe after {attempts} \
             attempt(s) in {:?}; serving it anyway",
            started.elapsed()
        );
    }

    /// One readiness probe: open a TCP connection through the tunnel and perform the start of a
    /// real TLS handshake, returning `true` only once the peer answers with a TLS record.
    async fn probe_once(&self) -> bool {
        let Ok(conn) = self.connect_tcp(PROBE_ENDPOINT).await else {
            return false;
        };

        if conn.write_all(&probe_client_hello()).await.is_err() {
            return false;
        }

        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(PROBE_READ_TIMEOUT, conn.read(&mut buf)).await;
        conn.shutdown();

        // TLS content type 0x16 = Handshake: the peer answered our ClientHello, so the data
        // path genuinely works in both directions. Anything else (timeout, EOF, error) is
        // exactly the failure mode being waited out.
        matches!(read, Ok(Ok(n)) if n > 0 && buf[0] == TLS_CONTENT_TYPE_HANDSHAKE)
    }

    /// A tunnel stand-in for tests — see [`Tunnel::Loopback`]'s doc comment.
    pub fn loopback_for_testing() -> Self {
        Self::Loopback
    }

    /// Open a TCP connection to `addr` through this tunnel, retrying a failed attempt for a
    /// short bounded window (see `TCP_CONNECT_RETRY_BUDGET`'s doc comment in this module's
    /// source for why).
    pub async fn connect_tcp(&self, addr: SocketAddr) -> Result<Box<dyn TunnelConnection>> {
        let deadline = std::time::Instant::now() + TCP_CONNECT_RETRY_BUDGET;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(ProtonError::Config(format!(
                    "connect attempt to {addr} did not finish within {TCP_CONNECT_RETRY_BUDGET:?}"
                )));
            }
            // Bound each individual attempt to whatever's left of the overall budget —
            // `wireguard_netstack::TcpConnection::connect` has its own internal polling but no
            // *enforced* deadline in this code, so a single hung handshake could otherwise burn
            // the whole retry budget on one attempt with no chance for the loop below to retry.
            let err = match tokio::time::timeout(remaining, self.connect_tcp_once(addr)).await {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(err)) => err,
                Err(_elapsed) => ProtonError::Config(format!(
                    "connect attempt to {addr} did not finish within {remaining:?}"
                )),
            };
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(err);
            }
            tokio::time::sleep(TCP_CONNECT_RETRY_BACKOFF.min(remaining)).await;
        }
    }

    async fn connect_tcp_once(&self, addr: SocketAddr) -> Result<Box<dyn TunnelConnection>> {
        match self {
            Self::Real(managed) => {
                let conn =
                    wireguard_netstack::TcpConnection::connect(managed.netstack(), addr).await?;
                Ok(Box::new(conn))
            }
            Self::Loopback => {
                let stream = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(ProtonError::Io)?;
                Ok(Box::new(LoopbackConnection::new(stream)))
            }
        }
    }

    /// Seconds since the last successful WireGuard handshake, or `None` if the
    /// tunnel isn't a real WireGuard session (e.g. the test Loopback).
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        match self {
            Self::Real(managed) => managed.time_since_last_handshake(),
            Self::Loopback => None,
        }
    }
}

/// Cumulative bytes relayed through a tunnel's SOCKS5 proxy.
///
/// Atomic counters rather than a `Mutex`-guarded struct: `relay`'s two directions each bump
/// one of these on every single read, and a blocking lock has no reason to sit on that path
/// when a lock-free `fetch_add` does the same job.
#[derive(Default)]
pub struct TunnelStats {
    /// Bytes from the local client out to the tunnel/Internet (upload).
    bytes_sent: std::sync::atomic::AtomicU64,
    /// Bytes from the tunnel/Internet back to the local client (download).
    bytes_received: std::sync::atomic::AtomicU64,
}

impl TunnelStats {
    pub fn add_sent(&self, n: u64) {
        self.bytes_sent
            .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn add_received(&self, n: u64) {
        self.bytes_received
            .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Shared handle to a running tunnel, so both the manager and the SOCKS5 relay tasks it spawns
/// can hold a reference without cloning the tunnel itself.
///
/// No explicit teardown method: `ManagedTunnel` holds its background tasks in a
/// `tokio::task::JoinSet`, which aborts every task it contains when dropped. Dropping the last
/// `SharedTunnel` reference (once the manager has stopped spawning new SOCKS5 relay tasks
/// against it and those tasks have exited) is sufficient to tear the tunnel down.
pub type SharedTunnel = Arc<Tunnel>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The readiness probe is only meaningful if what it sends is a well-formed ClientHello —
    /// a malformed one would draw an alert (or a close) from any peer and read as "still
    /// restricted" forever, silently turning the readiness gate into a fixed delay.
    #[test]
    fn probe_client_hello_is_a_well_formed_handshake_record() {
        let hello = probe_client_hello();

        assert_eq!(
            hello[0], TLS_CONTENT_TYPE_HANDSHAKE,
            "TLS record: Handshake"
        );
        assert_eq!(
            &hello[1..3],
            &[0x03, 0x01],
            "record version TLS 1.0 (compat)"
        );

        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(
            record_len,
            hello.len() - 5,
            "record length must cover exactly the handshake that follows"
        );

        assert_eq!(hello[5], 0x01, "handshake type: ClientHello");
        let handshake_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) as usize;
        assert_eq!(
            handshake_len,
            hello.len() - 9,
            "ClientHello body length must cover exactly the rest"
        );

        // Small enough to be a single TCP segment even at the tunnel's conservative MTU, so the
        // probe measures Proton's session restriction rather than segmentation behaviour.
        assert!(
            hello.len() < 400,
            "probe must fit one segment, got {}",
            hello.len()
        );
    }
}
