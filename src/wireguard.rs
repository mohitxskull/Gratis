//! Userspace WireGuard tunnel — no root, no `sudo`, no real network interface.
//!
//! Verified live: a raw WireGuard handshake plus a real HTTP request/response through a
//! tunnel built from exactly this key/config shape both succeeded, with no additional
//! "Local Agent" authorization step Proton's official client otherwise performs. That means
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
use std::net::SocketAddr;
use std::sync::Arc;
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

/// A purely descriptive, location-derived label (e.g. for `GET /api/tunnels` and the SQLite
/// `active_tunnels.interface` column) — NOT a real OS network interface name any more. Kept as
/// a small helper so displays/logs still have a stable, readable per-location tag.
pub fn interface_name(location: &str) -> String {
    format!("proton-{}", location.to_ascii_lowercase())
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
    async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        wireguard_netstack::TcpConnection::read(self, buf)
            .await
            .map_err(std::io::Error::other)
    }

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

    /// A tunnel stand-in for tests — see [`Tunnel::Loopback`]'s doc comment.
    pub fn loopback_for_testing() -> Self {
        Self::Loopback
    }

    /// Open a TCP connection to `addr` through this tunnel.
    pub async fn connect_tcp(&self, addr: SocketAddr) -> Result<Box<dyn TunnelConnection>> {
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
}

/// Shared handle to a running tunnel, so both the manager and the SOCKS5 relay tasks it spawns
/// can hold a reference without cloning the tunnel itself.
///
/// No explicit teardown method: `ManagedTunnel` holds its background tasks in a
/// `tokio::task::JoinSet`, which aborts every task it contains when dropped. Dropping the last
/// `SharedTunnel` reference (once the manager has stopped spawning new SOCKS5 relay tasks
/// against it and those tasks have exited) is sufficient to tear the tunnel down.
pub type SharedTunnel = Arc<Tunnel>;

/// A location's live tunnel, behind an indirection that lets the manager hot-swap which
/// server a running SOCKS5 listener relays through — without rebinding the listener (so its
/// port never changes) and without disturbing already-open client connections (each one
/// captured its own `SharedTunnel` clone at accept time via [`crate::socks5::run_socks5`], so
/// a swap here only changes which tunnel *new* connections get; old ones keep flowing through
/// the tunnel they started on until they finish, and that tunnel tears down on its own once
/// its last `SharedTunnel` clone — including this slot's, once overwritten — is dropped).
pub type CurrentTunnel = Arc<std::sync::Mutex<SharedTunnel>>;
