//! Ties together auth (`client.rs`), the userspace WireGuard tunnel (`wireguard.rs`), and the
//! SOCKS5 proxy (`socks5.rs`) into per-server "slots" (`ServerSlot`) driven by the control API
//! (`src/api.rs`).
//!
//! ## Port-per-server, lazily-connected, self-idling
//!
//! Right after login, `TunnelManager` assigns every free-tier server a fixed port (sequential
//! from `port_range_start`) and immediately spawns an always-on SOCKS5 listener for it — no
//! separate "connect" call is needed to make a server reachable. What *is* lazy is the
//! WireGuard tunnel behind that listener: the first client connection to a server's port brings
//! the tunnel up (see `ServerSlot::acquire`), and it's torn back down automatically once the
//! last client connection to it closes and `IDLE_TIMEOUT` passes with no new one arriving (see
//! `ServerSlot::release`) — the listener itself keeps running the whole time, ready to
//! reconnect on the next hit. Any number of servers can have a live tunnel at once; each slot
//! is entirely independent.
//!
//! ## No-root architecture
//!
//! Tunnels here are in-process userspace WireGuard sessions (see `wireguard.rs`), not real
//! kernel network interfaces brought up via `sudo wg-quick`. A tunnel is exactly as long-lived
//! as the `Arc<Tunnel>` referencing it and cannot outlive the daemon process — so there is no
//! "leaked interface" failure mode, no privileged `is_up` check, and no boot reconciliation of
//! stale kernel state to get wrong.
//!
//! ## No persistence
//!
//! Nothing here is written to disk. Login is always a fresh `.env`-driven login at daemon
//! startup (see `main.rs`); there is no saved-session restore, and no record of which slots
//! were connected survives a restart — there wouldn't be anything meaningful to restore, since
//! a tunnel cannot outlive the process that holds it anyway.
use crate::client::ProtonVPNClient;
use crate::errors::*;
use crate::models::{VPNCredentials, VPNServer};
use crate::socks5::{self, SourceError, TunnelSource};
use crate::wireguard::{SharedTunnel, Tunnel, TunnelStats};
use async_trait::async_trait;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

/// How long a slot's tunnel is kept up with zero open connections before it's torn down. The
/// listener stays bound the whole time; only the WireGuard session underneath it is dropped.
///
/// Shortened under `cfg(test)` so idle-teardown behavior can actually be exercised in a unit
/// test without a multi-minute sleep.
#[cfg(not(test))]
const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
#[cfg(test)]
const IDLE_TIMEOUT: Duration = Duration::from_millis(150);

/// How long a successful readiness check is trusted before `acquire` re-checks.
///
/// Proton's restricted-session window is not a one-off at connect time: WireGuard rekeys roughly
/// every two minutes, and a connection opened just after a rekey hits the same restriction (
/// verified live — a slot idle for ~2 minutes failed its next 3-4 TLS connections, while a
/// continuously-used slot stayed at 5/5). Re-verifying after this much inactivity covers that
/// without charging the probe to back-to-back connections, which are the common case.
const READINESS_TTL: Duration = Duration::from_secs(30);

/// Account tier used to filter the server list to what's actually reachable.
///
/// `client.rs`/`models.rs` don't currently surface the account's actual tier anywhere the
/// manager can read it. This was previously `i32::MAX` (disabling the filter entirely) — **
/// confirmed live to be a real bug, not just a theoretical gap**: with the filter disabled,
/// server selection picked servers regardless of tier, which for a free-tier test account
/// selected a tier-2 (paid) server. The WireGuard handshake succeeded (it authenticates by
/// keypair, not by tier), but Proton silently dropped all subsequent data traffic — the symptom
/// was indistinguishable from a relay bug until traced back to server selection. Defaulting to
/// `0` (free tier) is the safe, conservative choice: it never selects a server above what every
/// account is entitled to.
const PERMISSIVE_TIER: i32 = 0;

/// Seam for testing `TunnelManager` without root/live WireGuard/network access.
///
/// Production code uses `RealDriver` (which just calls through to `wireguard`/`socks5`), and
/// tests use a `FakeDriver` that records calls and spawns an inert task instead of a real
/// tunnel/SOCKS5 listener.
#[async_trait]
pub trait TunnelDriver: Send + Sync {
    /// Bring up a userspace WireGuard tunnel to `server`, using `creds`.
    async fn connect_tunnel(
        &self,
        server: &VPNServer,
        creds: &VPNCredentials,
    ) -> Result<SharedTunnel>;

    /// Spawn whatever serves this slot's SOCKS5 proxy, returning its `JoinHandle`. `source` is
    /// how the listener gets a tunnel per accepted connection — see
    /// [`crate::socks5::TunnelSource`] — rather than a fixed tunnel, so it can run for the
    /// entire process lifetime whether or not a tunnel currently happens to be up.
    fn spawn_socks5(
        &self,
        listen_addr: String,
        source: Arc<dyn TunnelSource>,
        stats: Arc<Mutex<TunnelStats>>,
    ) -> JoinHandle<()>;
}

/// Production driver: brings up a real userspace WireGuard tunnel and binds a real SOCKS5
/// listener.
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

    fn spawn_socks5(
        &self,
        listen_addr: String,
        source: Arc<dyn TunnelSource>,
        stats: Arc<Mutex<TunnelStats>>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(err) = socks5::run_socks5(&listen_addr, source, stats).await {
                eprintln!("socks5 listener on {listen_addr} exited: {err}");
            }
        })
    }
}

/// One free-tier server: a fixed port with an always-on SOCKS5 listener, whose WireGuard tunnel
/// is connected lazily on first use and torn down after `IDLE_TIMEOUT` idle (see the module
/// doc comment). Implements [`TunnelSource`] so `run_socks5`'s accept loop can drive it
/// directly.
struct ServerSlot {
    server: VPNServer,
    creds: VPNCredentials,
    driver: Arc<dyn TunnelDriver>,
    port: u16,
    stats: Arc<Mutex<TunnelStats>>,

    tunnel: Mutex<Option<SharedTunnel>>,
    connected_at: Mutex<Option<Instant>>,
    /// When the tunnel will be torn down if `open_connections` stays at zero — set the moment
    /// it hits zero, cleared the moment a new connection arrives. `None` whenever there's no
    /// tunnel, or at least one connection is open.
    idle_deadline: Mutex<Option<Instant>>,
    open_connections: AtomicU32,
    /// Bumped on every `acquire` (including reuses of an already-connected tunnel). An
    /// idle-teardown timer only acts if this hasn't moved since it was spawned — see
    /// `release`'s doc comment for why that matters.
    idle_generation: AtomicU64,
    /// When external TLS through this slot's tunnel was last confirmed to work. Drives
    /// re-verification in `acquire` — see [`READINESS_TTL`].
    verified_at: Mutex<Option<Instant>>,
    /// Whether the current run of local-agent handshake failures for this slot has already been
    /// logged — see `unlock_tunnel`. Set on the first failure, cleared on the next success, so a
    /// persistent problem (e.g. a genuinely jailed account) prints once instead of on every
    /// `READINESS_TTL` re-verification.
    agent_failure_logged: AtomicBool,
    /// Serializes the actual `connect_tunnel` call — and the readiness check that follows it —
    /// so concurrent connections to the same server can't race each other into two tunnels or
    /// into redundant probes.
    connect_lock: AsyncMutex<()>,
    /// Lets `release` spawn a self-referencing idle-teardown task without `ServerSlot` needing
    /// to already know its own `Arc` at construction time (see `ServerSlot::new`).
    self_ref: Weak<ServerSlot>,
}

impl ServerSlot {
    fn new(
        server: VPNServer,
        creds: VPNCredentials,
        driver: Arc<dyn TunnelDriver>,
        port: u16,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            server,
            creds,
            driver,
            port,
            stats: Arc::new(Mutex::new(TunnelStats::default())),
            tunnel: Mutex::new(None),
            connected_at: Mutex::new(None),
            idle_deadline: Mutex::new(None),
            open_connections: AtomicU32::new(0),
            idle_generation: AtomicU64::new(0),
            verified_at: Mutex::new(None),
            agent_failure_logged: AtomicBool::new(false),
            connect_lock: AsyncMutex::new(()),
            self_ref: weak.clone(),
        })
    }

    /// Whether external TLS through this slot was confirmed working recently enough to trust
    /// without re-checking — see [`READINESS_TTL`].
    fn recently_verified(&self) -> bool {
        self.verified_at
            .lock()
            .unwrap()
            .is_some_and(|t| t.elapsed() < READINESS_TTL)
    }

    /// Make a freshly (re)connected tunnel immediately usable.
    ///
    /// Primary path: Proton's "local agent" handshake (`agent.rs`), which — verified live
    /// — lifts Proton's restricted-session block in well under a second instead of the ~4-5s the
    /// old readiness probe had to wait out. Any failure there (network hiccup, TLS/cert issue, a
    /// protocol change on Proton's side, or a reply that reports the session as genuinely
    /// jailed/restricted) is logged and followed by the readiness probe as a fallback, so a
    /// broken local-agent path degrades gratis back to its previous behaviour rather than
    /// breaking connections.
    async fn unlock_tunnel(&self, tunnel: &Tunnel) {
        let sni = self.server.pick_physical().map(|p| p.domain.as_str());

        let agent_result = match sni {
            Some(sni) => crate::agent::unlock(tunnel, sni, &self.creds).await,
            None => Err(ProtonError::Config(format!(
                "server {} has no physical servers to derive a local-agent SNI from",
                self.server.name
            ))),
        };

        match agent_result {
            Ok(()) => {
                // A successful handshake means whatever was previously failing (if anything) is
                // no longer happening — clear the flag so a genuinely new failure later gets
                // logged again rather than staying silent because of an old one.
                self.agent_failure_logged.store(false, Ordering::SeqCst);
            }
            Err(err) => {
                // Log the first occurrence of a given failure loudly, but not every single
                // acquire while the same problem persists (e.g. a jailed account gets
                // re-verified every `READINESS_TTL`) — that would just be the same message
                // repeated forever alongside the ~5s fallback wait it already costs.
                if !self.agent_failure_logged.swap(true, Ordering::SeqCst) {
                    eprintln!(
                        "gratis: local-agent handshake for {} failed ({err}); falling back to \
                         the readiness probe (further repeats of this failure will be silent \
                         until it clears)",
                        self.server.name
                    );
                }
                tunnel.wait_until_data_path_ready(&self.server.name).await;
            }
        }
    }

    fn status(&self) -> ServerStatus {
        let tunnel = self.tunnel.lock().unwrap().clone();
        let connected_at = *self.connected_at.lock().unwrap();
        let idle_deadline = *self.idle_deadline.lock().unwrap();
        let stats = self.stats.lock().unwrap();
        ServerStatus {
            name: self.server.name.clone(),
            country: self.server.country.clone(),
            country_code: self.server.country_code.clone(),
            city: self.server.city.clone(),
            port: self.port,
            load: self.server.load,
            connected: tunnel.is_some(),
            open_connections: self.open_connections.load(Ordering::SeqCst),
            uptime_secs: connected_at.map(|t| t.elapsed().as_secs()),
            handshake_age_secs: tunnel
                .as_ref()
                .and_then(|t| t.time_since_last_handshake())
                .map(|d| d.as_secs()),
            idle_countdown_secs: idle_deadline
                .map(|d| d.saturating_duration_since(Instant::now()).as_secs()),
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
        }
    }
}

#[async_trait]
impl TunnelSource for ServerSlot {
    async fn acquire(&self) -> std::result::Result<SharedTunnel, SourceError> {
        self.open_connections.fetch_add(1, Ordering::SeqCst);
        // Invalidates any idle-teardown timer spawned by a previous `release` — see that
        // method's doc comment. There's now at least one open connection, so no teardown is
        // pending any more either way.
        self.idle_generation.fetch_add(1, Ordering::SeqCst);
        *self.idle_deadline.lock().unwrap() = None;

        // Fast path: an already-connected tunnel that was recently confirmed working. This is
        // every connection after the first, so the common case takes no locks beyond these.
        let existing = self.tunnel.lock().unwrap().clone();
        if let Some(tunnel) = existing
            && self.recently_verified()
        {
            return Ok(tunnel);
        }

        // Only one connect-and-verify per slot at a time; concurrent connections arriving while
        // the first is still establishing wait here rather than racing into two tunnels or
        // firing redundant readiness probes.
        let _connect_guard = self.connect_lock.lock().await;

        // Bind the clone out of the guard first: holding a std MutexGuard across the `await`
        // below would make this future non-Send.
        let already_connected = self.tunnel.lock().unwrap().clone();
        let tunnel = match already_connected {
            Some(tunnel) => tunnel,
            None => match self.driver.connect_tunnel(&self.server, &self.creds).await {
                Ok(tunnel) => {
                    *self.tunnel.lock().unwrap() = Some(tunnel.clone());
                    *self.connected_at.lock().unwrap() = Some(Instant::now());
                    // A newly connected tunnel is restricted by Proton until it proves otherwise.
                    *self.verified_at.lock().unwrap() = None;
                    tunnel
                }
                Err(err) => {
                    // Undo the increment above: this connection never got a tunnel, so it must
                    // not be counted as "open" for idle-teardown purposes.
                    self.open_connections.fetch_sub(1, Ordering::SeqCst);
                    return Err(Box::new(err));
                }
            },
        };

        // Re-check under the lock: a concurrent caller may have just verified this tunnel.
        if !self.recently_verified() {
            self.unlock_tunnel(tunnel.as_ref()).await;
            *self.verified_at.lock().unwrap() = Some(Instant::now());
        }

        Ok(tunnel)
    }

    fn release(&self) {
        let remaining = self.open_connections.fetch_sub(1, Ordering::SeqCst) - 1;
        if remaining != 0 {
            return;
        }

        // Snapshot the generation now, at the moment the connection count hit zero. If a new
        // connection arrives before the sleep below finishes, `acquire` bumps the generation,
        // so the check on wake won't match and this timer becomes a no-op — without this, a
        // *stale* timer from an earlier idle window could tear down a tunnel that's only been
        // idle for a few seconds of a brand new window (`open_connections == 0` alone can't
        // distinguish "still the same idle period" from "a fresh one that also happens to be
        // momentarily at zero").
        let generation = self.idle_generation.load(Ordering::SeqCst);
        // Set synchronously, right as the count hits zero, so it's always the correct deadline
        // for the current idle window — a subsequent `acquire` clears it immediately, before
        // this window's countdown could ever be read as stale.
        *self.idle_deadline.lock().unwrap() = Some(Instant::now() + IDLE_TIMEOUT);

        let Some(slot) = self.self_ref.upgrade() else {
            return;
        };
        tokio::spawn(async move {
            tokio::time::sleep(IDLE_TIMEOUT).await;
            if slot.open_connections.load(Ordering::SeqCst) == 0
                && slot.idle_generation.load(Ordering::SeqCst) == generation
            {
                *slot.tunnel.lock().unwrap() = None;
                *slot.connected_at.lock().unwrap() = None;
                *slot.idle_deadline.lock().unwrap() = None;
            }
        });
    }
}

/// A snapshot of one server, as surfaced by `GET /api/servers` — the sole read API. Static
/// fields (name/location/port/load) never change once assigned; the rest reflects live state.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ServerStatus {
    pub name: String,
    pub country: String,
    pub country_code: String,
    pub city: Option<String>,
    /// Fixed for this server's whole process lifetime — connect a SOCKS5 client to
    /// `127.0.0.1:<port>` to use it; the first connection lazily brings the tunnel up.
    pub port: u16,
    pub load: f64,
    /// Whether a WireGuard tunnel is currently up for this server.
    pub connected: bool,
    pub open_connections: u32,
    /// Seconds the current tunnel has been up, or `None` if not currently connected.
    pub uptime_secs: Option<u64>,
    /// Seconds since the last WireGuard handshake, or `None` if not currently connected.
    pub handshake_age_secs: Option<u64>,
    /// Seconds until this server's tunnel tears itself down, or `None` unless it's currently
    /// connected with zero open connections (i.e. actively counting down to idle teardown).
    pub idle_countdown_secs: Option<u64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

pub struct TunnelManager {
    client: AsyncMutex<Option<ProtonVPNClient>>,
    driver: Arc<dyn TunnelDriver>,
    /// First port handed out; each free-tier server gets one more than the last, in a stable
    /// (server-id-sorted) order.
    port_range_start: u16,
    slots: Mutex<Vec<Arc<ServerSlot>>>,
}

impl TunnelManager {
    /// Build a manager using the real tunnel/SOCKS5 driver.
    pub fn new(port_range_start: u16) -> Self {
        Self::with_driver(port_range_start, Arc::new(RealDriver))
    }

    /// Build a manager with an injected driver (used by tests to avoid touching real
    /// WireGuard/network state).
    pub fn with_driver(port_range_start: u16, driver: Arc<dyn TunnelDriver>) -> Self {
        Self {
            client: AsyncMutex::new(None),
            driver,
            port_range_start,
            slots: Mutex::new(Vec::new()),
        }
    }

    /// Authenticate via SRP, fetch the server list, and bind one port + one always-on SOCKS5
    /// listener per free-tier server (see the module doc comment). Replaces any slots from a
    /// previous login.
    pub async fn login(&self, email: &str, password: &str) -> Result<()> {
        let mut client = ProtonVPNClient::new(email);
        let creds = client.login(email, password).await?;
        client.fetch_servers().await?;

        let mut servers: Vec<VPNServer> = client
            .server_list
            .iter()
            .filter(|s| s.tier <= PERMISSIVE_TIER)
            .cloned()
            .collect();
        servers.sort_by(|a, b| a.id.cmp(&b.id));

        let mut slots = Vec::with_capacity(servers.len());
        for (i, server) in servers.into_iter().enumerate() {
            let offset = u16::try_from(i)
                .map_err(|_| ProtonError::Config("too many servers for the port range".into()))?;
            let port = self.port_range_start.checked_add(offset).ok_or_else(|| {
                ProtonError::Config("ran out of ports for the free-tier server list".into())
            })?;

            let slot = ServerSlot::new(server, creds.clone(), self.driver.clone(), port);
            // Fire-and-forget: this listener is meant to run for the rest of the process's
            // life, so there's nothing useful to do with the JoinHandle (dropping it detaches
            // the task rather than aborting it).
            let _handle = self.driver.spawn_socks5(
                format!("127.0.0.1:{port}"),
                slot.clone(),
                slot.stats.clone(),
            );
            slots.push(slot);
        }

        *self.slots.lock().unwrap() = slots;
        *self.client.lock().await = Some(client);
        Ok(())
    }

    /// Every free-tier server this account can reach, each with its assigned port and current
    /// connection status. The sole read API — see the module doc comment.
    pub fn servers(&self) -> Vec<ServerStatus> {
        self.slots
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.status())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records `connect_tunnel` calls (no real WireGuard/network) and spawns an inert task
    /// instead of a real SOCKS5 listener, so `TunnelManager` bookkeeping can be tested without
    /// root or network access.
    #[derive(Default)]
    struct FakeDriver {
        connect_calls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl TunnelDriver for FakeDriver {
        async fn connect_tunnel(
            &self,
            server: &VPNServer,
            _creds: &VPNCredentials,
        ) -> Result<SharedTunnel> {
            self.connect_calls
                .lock()
                .unwrap()
                .push(server.country_code.clone());
            Ok(Arc::new(Tunnel::loopback_for_testing()))
        }

        fn spawn_socks5(
            &self,
            _listen_addr: String,
            _source: Arc<dyn TunnelSource>,
            _stats: Arc<Mutex<TunnelStats>>,
        ) -> JoinHandle<()> {
            tokio::spawn(async {
                // Stand in for `run_socks5`'s infinite accept loop: never returns on its own.
                std::future::pending::<()>().await;
            })
        }
    }

    const TEST_CERT_PEM: &str =
        "-----BEGIN CERTIFICATE-----\ntest-only-placeholder\n-----END CERTIFICATE-----";

    fn test_server(id: &str, location: &str) -> VPNServer {
        VPNServer {
            id: id.into(),
            name: format!("{location}-FREE#1"),
            country: "Testland".into(),
            country_code: location.into(),
            city: None,
            tier: 0,
            load: 12.0,
            features: vec![],
            status: 1,
            physical: vec![crate::models::PhysicalServer {
                entry_ip: "203.0.113.9".into(),
                domain: "test.protonvpn.net".into(),
                x25519_public_key: "SERVERPUBKEYBASE64==".into(),
                enabled: true,
            }],
        }
    }

    fn test_creds() -> VPNCredentials {
        VPNCredentials {
            username: "testuser".into(),
            ed25519_seed_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            wg_public_key: "CLIENTPUBKEYBASE64==".into(),
            wg_private_key: "CLIENTPRIVKEYBASE64==".into(),
            certificate: TEST_CERT_PEM.into(),
            certificate_expires_at: 9_999_999_999,
        }
    }

    /// Builds a `TunnelManager` with a `FakeDriver` and one slot already inserted directly
    /// (bypassing `login()`'s network path), for exercising `TunnelSource`/`servers()`
    /// bookkeeping in isolation.
    fn manager_with_one_slot(port: u16) -> (Arc<TunnelManager>, Arc<ServerSlot>) {
        let driver = Arc::new(FakeDriver::default());
        let manager = Arc::new(TunnelManager::with_driver(
            port,
            driver.clone() as Arc<dyn TunnelDriver>,
        ));
        let slot = ServerSlot::new(test_server("srv-1", "US"), test_creds(), driver, port);
        manager.slots.lock().unwrap().push(slot.clone());
        (manager, slot)
    }

    #[test]
    fn servers_reports_assigned_port_and_disconnected_by_default() {
        let (manager, _slot) = manager_with_one_slot(20000);
        let servers = manager.servers();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].port, 20000);
        assert_eq!(servers[0].country_code, "US");
        assert!(!servers[0].connected);
        assert_eq!(servers[0].open_connections, 0);
    }

    #[tokio::test]
    async fn acquire_connects_once_and_reuses_for_concurrent_callers() {
        let (manager, slot) = manager_with_one_slot(20100);

        let (t1, t2) = tokio::join!(slot.acquire(), slot.acquire());
        assert!(t1.is_ok());
        assert!(t2.is_ok());
        assert!(Arc::ptr_eq(&t1.unwrap(), &t2.unwrap()));

        let servers = manager.servers();
        assert!(servers[0].connected);
        assert_eq!(servers[0].open_connections, 2);
    }

    #[tokio::test]
    async fn release_to_zero_tears_down_after_idle_timeout() {
        let (manager, slot) = manager_with_one_slot(20200);

        slot.acquire().await.unwrap();
        assert!(manager.servers()[0].connected);

        slot.release();
        assert_eq!(manager.servers()[0].open_connections, 0);
        // Still connected immediately after the last connection closes — teardown only
        // happens after the idle timer elapses, not the instant the count hits zero.
        assert!(manager.servers()[0].connected);

        tokio::time::sleep(IDLE_TIMEOUT * 3).await;
        assert!(
            !manager.servers()[0].connected,
            "tunnel must be torn down once the idle timeout has elapsed with no new connection"
        );
    }

    #[tokio::test]
    async fn a_new_connection_before_idle_timeout_keeps_the_tunnel_up() {
        let (manager, slot) = manager_with_one_slot(20300);

        slot.acquire().await.unwrap();
        slot.release();
        // A second connection arrives well before the idle timer fires.
        slot.acquire().await.unwrap();

        // Wait past the *first* connection's idle deadline — its now-stale timer must not tear
        // the tunnel down out from under the second, still-open connection.
        tokio::time::sleep(IDLE_TIMEOUT * 3).await;
        assert!(
            manager.servers()[0].connected,
            "a fresh connection must invalidate the previous idle timer"
        );
        assert_eq!(manager.servers()[0].open_connections, 1);
    }
}
