//! The [`TunnelDriver`] seam — swaps a real WireGuard tunnel + real listener for a test double
//! without `TunnelManager`/`ServerSlot` needing to know the difference. Split out of the old
//! monolithic `manager.rs` — see that module's history.
use crate::errors::*;
use crate::models::{VPNCredentials, VPNServer};
use crate::socks5::{self, TunnelSource};
use crate::wireguard::{SharedTunnel, Tunnel, TunnelStats};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::task::JoinHandle;

/// Which local proxy protocol a daemon's listeners speak — one choice for the whole daemon
/// (`gratis up --http-proxy`), applied uniformly to every port. SOCKS5 is the default because
/// it's what most proxy-aware clients and CLI tools (`curl --socks5-hostname`, etc.) already
/// support out of the box; HTTP CONNECT exists for the clients/frameworks that only speak that
/// (e.g. Pingora's `Peer::proxy`, which supports CONNECT proxies but not SOCKS5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyProtocol {
    #[default]
    Socks5,
    Http,
}

/// Seam for testing `TunnelManager` without root/live WireGuard/network access. Production code
/// uses `RealDriver` (which just calls through to `wireguard`/`socks5`/`http_connect`), and
/// tests use a `FakeDriver` that records calls and spawns an inert task instead of a real
/// tunnel/listener.
#[async_trait]
pub trait TunnelDriver: Send + Sync {
    /// Bring up a userspace WireGuard tunnel to `server`, using `creds`.
    async fn connect_tunnel(
        &self,
        server: &VPNServer,
        creds: &VPNCredentials,
    ) -> Result<SharedTunnel>;

    /// Spawn whatever serves this slot's proxy listener (SOCKS5 or HTTP CONNECT, per
    /// `protocol`), returning its `JoinHandle`. `source` is how the listener gets a tunnel per
    /// accepted connection — see [`crate::socks5::TunnelSource`] — rather than a fixed tunnel,
    /// so it can run for the entire process lifetime whether or not a tunnel currently happens
    /// to be up.
    fn spawn_listener(
        &self,
        listen_addr: String,
        source: Arc<dyn TunnelSource>,
        stats: Arc<TunnelStats>,
        protocol: ProxyProtocol,
    ) -> JoinHandle<()>;
}

/// Production driver: brings up a real userspace WireGuard tunnel and binds a real listener.
pub struct RealDriver;

#[async_trait]
impl TunnelDriver for RealDriver {
    async fn connect_tunnel(
        &self,
        server: &VPNServer,
        creds: &VPNCredentials,
    ) -> Result<SharedTunnel> {
        let tunnel = Tunnel::connect(server, creds).await?;
        Ok(Arc::new(tunnel))
    }

    fn spawn_listener(
        &self,
        listen_addr: String,
        source: Arc<dyn TunnelSource>,
        stats: Arc<TunnelStats>,
        protocol: ProxyProtocol,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let result = match protocol {
                ProxyProtocol::Socks5 => socks5::run_socks5(&listen_addr, source, stats).await,
                ProxyProtocol::Http => {
                    crate::http_connect::run_http_connect(&listen_addr, source, stats).await
                }
            };
            if let Err(err) = result {
                log::warn!("{protocol:?} listener on {listen_addr} exited: {err}");
            }
        })
    }
}
