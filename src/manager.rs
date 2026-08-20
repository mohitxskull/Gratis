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
//! ## No slot-state persistence
//!
//! Nothing about *slots* is written to disk: no record of which slots were connected survives
//! a restart — there wouldn't be anything meaningful to restore, since a tunnel cannot outlive
//! the process that holds it anyway. The Proton *session* (tokens, not slot state) can be
//! persisted separately by the caller (see `session.rs`) and handed back in via
//! `login_with_session` to skip a full SRP login on the next start.
use crate::client::ProtonVPNClient;
use crate::errors::*;
use crate::models::{VPNCredentials, VPNServer};
use crate::session::Session;
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

/// How long `acquire` keeps retrying a fresh WireGuard connect attempt for a cold slot before
/// giving up and failing the caller's SOCKS5 connection.
///
/// Free-tier Proton exits are flaky enough that a single failed handshake attempt often just
/// means "try again," not "this server is down" — verified live: a cold port's very first
/// touch regularly failed outright while a retry moments later succeeded. Without this, every
/// caller unlucky enough to be first to touch a cold slot ate that one failed attempt instead
/// of the tunnel it asked for.
///
/// Shortened under `cfg(test)` for the same reason as [`IDLE_TIMEOUT`]: exercising the
/// give-up-after-budget path shouldn't require a real multi-second sleep in the test suite.
#[cfg(not(test))]
const CONNECT_RETRY_BUDGET: Duration = Duration::from_secs(10);
#[cfg(test)]
const CONNECT_RETRY_BUDGET: Duration = Duration::from_millis(100);

/// Pause between connect retries within [`CONNECT_RETRY_BUDGET`], so a persistently-dead server
/// doesn't get hammered with back-to-back handshake attempts for the whole budget.
#[cfg(not(test))]
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_millis(300);
#[cfg(test)]
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_millis(10);

/// Hard cap on a single connect attempt within the retry loop, enforced by wrapping the
/// attempt in [`tokio::time::timeout`] ourselves rather than trusting `wireguard-netstack`'s
/// own internal timing.
///
/// This matters because `wireguard-netstack::Tunnel::connect()` defaults to a **10-second**
/// handshake timeout, and its `netstack.rs` has several more internal 30-second polling loops
/// that aren't even bounded by that parameter — so a single attempt against a genuinely
/// unresponsive server (the dominant failure mode for free-tier exits, as opposed to an instant
/// rejection) could otherwise burn most or all of [`CONNECT_RETRY_BUDGET`] on its own, leaving
/// no room to actually retry. Capping each attempt well below the overall budget guarantees
/// multiple independent attempts fit inside it.
#[cfg(not(test))]
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(test)]
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(25);

/// How long a successful readiness check is trusted before `acquire` re-checks.
///
/// Proton's restricted-session window is not a one-off at connect time: WireGuard rekeys roughly
/// every two minutes, and a connection opened just after a rekey hits the same restriction (
/// verified live — a slot idle for ~2 minutes failed its next 3-4 TLS connections, while a
/// continuously-used slot stayed at 5/5). Re-verifying after this much inactivity covers that
/// without charging the probe to back-to-back connections, which are the common case.
const READINESS_TTL: Duration = Duration::from_secs(30);

/// Fallback account tier used to filter the server list, only if `GET /vpn/v2` (see
/// `client::fetch_account_info`) can't be reached — the manager otherwise always uses the
/// account's real `MaxTier` from that call. This was previously the *only* tier value used at
/// all (hardcoded, `i32::MAX` before that) — **confirmed live to be a real bug, not just a
/// theoretical gap**: with the filter disabled, server selection picked servers regardless of
/// tier, which for a free-tier test account selected a tier-2 (paid) server. The WireGuard
/// handshake succeeded (it authenticates by keypair, not by tier), but Proton silently dropped
/// all subsequent data traffic — the symptom was indistinguishable from a relay bug until traced
/// back to server selection. `0` (free tier) is the safe, conservative fallback: it never
/// selects a server above what every account is entitled to.
const FALLBACK_TIER: i32 = 0;

/// Caps how many servers can have a live WireGuard tunnel at the same time, matching Proton's
/// per-account `MaxConnect` limit. Without this, gratis's "any number of servers at once"
/// design has no relationship to what the account is actually allowed to run simultaneously —
/// on a free-tier account (`MaxConnect: 1` in Proton's ToS, `2` observed live) that's a clean
/// simultaneous-connections violation, not just a theoretical one. `None` bypasses the cap
/// entirely (`gratis up --unlimited-connections`) — a deliberate, opt-in choice the user makes
/// knowingly, not the default.
struct ConnectionLimiter {
    max: Option<u32>,
    current: AtomicU32,
}

impl ConnectionLimiter {
    fn new(max: Option<u32>) -> Self {
        Self {
            max,
            current: AtomicU32::new(0),
        }
    }

    /// Reserve one connection slot. Returns `false` (reserving nothing) if already at `max`;
    /// always succeeds if `max` is `None`.
    fn try_acquire(&self) -> bool {
        let Some(max) = self.max else {
            self.current.fetch_add(1, Ordering::SeqCst);
            return true;
        };
        loop {
            let cur = self.current.load(Ordering::SeqCst);
            if cur >= max {
                return false;
            }
            if self
                .current
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Release a slot reserved by a successful `try_acquire` — call exactly once per tunnel
    /// that goes from connected back to disconnected (a failed connect attempt that never
    /// actually reserved doesn't call this; see the two call sites in `ServerSlot`).
    fn release(&self) {
        self.current.fetch_sub(1, Ordering::SeqCst);
    }
}

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
        stats: Arc<TunnelStats>,
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
        stats: Arc<TunnelStats>,
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
    stats: Arc<TunnelStats>,

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
    /// Shared across every slot from the same login — see [`ConnectionLimiter`].
    limiter: Arc<ConnectionLimiter>,
}

impl ServerSlot {
    fn new(
        server: VPNServer,
        creds: VPNCredentials,
        driver: Arc<dyn TunnelDriver>,
        port: u16,
        limiter: Arc<ConnectionLimiter>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            server,
            creds,
            driver,
            port,
            stats: Arc::new(TunnelStats::default()),
            tunnel: Mutex::new(None),
            connected_at: Mutex::new(None),
            idle_deadline: Mutex::new(None),
            open_connections: AtomicU32::new(0),
            idle_generation: AtomicU64::new(0),
            verified_at: Mutex::new(None),
            agent_failure_logged: AtomicBool::new(false),
            connect_lock: AsyncMutex::new(()),
            self_ref: weak.clone(),
            limiter,
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

    /// Bring up a fresh tunnel for this slot, retrying a failed handshake attempt rather than
    /// failing the caller on the first miss — see [`CONNECT_RETRY_BUDGET`]. Only called with
    /// `connect_lock` already held, so retries here never race a concurrent connect attempt for
    /// the same slot.
    async fn connect_with_retry(&self) -> Result<SharedTunnel> {
        let deadline = Instant::now() + CONNECT_RETRY_BUDGET;
        let mut last_err = ProtonError::Config("connect retry budget was zero".into());

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(last_err);
            }

            // Cap each attempt well below the overall budget ourselves — see
            // `CONNECT_ATTEMPT_TIMEOUT`'s doc comment for why the underlying crate's own
            // timeout can't be trusted to bound this on its own.
            let attempt_timeout = remaining.min(CONNECT_ATTEMPT_TIMEOUT);
            match tokio::time::timeout(
                attempt_timeout,
                self.driver.connect_tunnel(&self.server, &self.creds),
            )
            .await
            {
                Ok(Ok(tunnel)) => return Ok(tunnel),
                Ok(Err(err)) => last_err = err,
                Err(_elapsed) => {
                    last_err = ProtonError::Config(format!(
                        "connect attempt did not finish within {attempt_timeout:?}"
                    ));
                }
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(last_err);
            }
            tokio::time::sleep(CONNECT_RETRY_BACKOFF.min(remaining)).await;
        }
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
                         the readiness probe, so connections still work but the first one to \
                         each server is ~5s slower (further repeats of this failure will be \
                         silent until it clears).\n\
                         gratis: if this persists, Proton has most likely changed the agent \
                         protocol or rotated its pinned CAs — please report it with this \
                         message at https://github.com/mohitxskull/Gratis/issues so it can be \
                         updated.",
                        self.server.name
                    );
                    crate::notify::notify_clickable(
                        "gratis: local-agent handshake failed",
                        &format!(
                            "Falling back to the slower readiness probe for {} — connections \
                             still work, just slower. Click to report it (Proton may have \
                             changed the agent protocol or rotated its pinned CAs).",
                            self.server.name
                        ),
                        "https://github.com/mohitxskull/Gratis/issues/new",
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
            bytes_sent: self.stats.bytes_sent(),
            bytes_received: self.stats.bytes_received(),
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
            None => {
                // A fresh tunnel counts against the account's simultaneous-connection cap —
                // reserve a slot before connecting, not after, so two servers can't race past
                // the limit. Reusing an already-connected tunnel (the `Some` arm above) never
                // reaches here, since it doesn't open a new session with Proton.
                if !self.limiter.try_acquire() {
                    self.open_connections.fetch_sub(1, Ordering::SeqCst);
                    return Err(Box::new(ProtonError::Config(format!(
                        "max simultaneous tunnels reached ({}) — disconnect another server \
                         first, or start gratis with --unlimited-connections",
                        self.limiter.max.unwrap_or(0)
                    ))));
                }
                match self.connect_with_retry().await {
                    Ok(tunnel) => {
                        *self.tunnel.lock().unwrap() = Some(tunnel.clone());
                        *self.connected_at.lock().unwrap() = Some(Instant::now());
                        // A newly connected tunnel is restricted by Proton until it proves
                        // otherwise.
                        *self.verified_at.lock().unwrap() = None;
                        tunnel
                    }
                    Err(err) => {
                        // Undo both reservations: this connection never got a tunnel, so it
                        // must not be counted as "open" for idle-teardown purposes, nor as a
                        // live session against the connection cap.
                        self.limiter.release();
                        self.open_connections.fetch_sub(1, Ordering::SeqCst);
                        return Err(Box::new(err));
                    }
                }
            }
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
                // The connection-cap reservation this tunnel held (see `acquire`) is now free
                // for another server to use.
                slot.limiter.release();
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

/// Which Proton account is logged in and what it's entitled to — surfaced on the web UI so
/// it's obvious at a glance which account gratis is running as. Set once per login (see
/// `finish_login`); `None` only if `GET /vpn/v2` couldn't be reached at login time.
#[derive(Debug, Clone, Serialize)]
pub struct AccountSummary {
    pub email: String,
    pub plan_name: String,
    pub max_tier: i32,
    pub max_connect: i32,
}

pub struct TunnelManager {
    client: AsyncMutex<Option<ProtonVPNClient>>,
    driver: Arc<dyn TunnelDriver>,
    /// First port handed out; each free-tier server gets one more than the last, in a stable
    /// (server-id-sorted) order.
    port_range_start: u16,
    slots: Mutex<Vec<Arc<ServerSlot>>>,
    /// Bypasses the account's `MaxConnect` cap entirely — see [`ConnectionLimiter`]. Set once
    /// at construction from `gratis up --unlimited-connections`; a deliberate, opt-in choice.
    unlimited: bool,
    account: Mutex<Option<AccountSummary>>,
}

impl TunnelManager {
    /// Build a manager using the real tunnel/SOCKS5 driver.
    pub fn new(port_range_start: u16, unlimited_connections: bool) -> Self {
        Self::with_driver(
            port_range_start,
            Arc::new(RealDriver),
            unlimited_connections,
        )
    }

    /// Build a manager with an injected driver (used by tests to avoid touching real
    /// WireGuard/network state).
    pub fn with_driver(
        port_range_start: u16,
        driver: Arc<dyn TunnelDriver>,
        unlimited_connections: bool,
    ) -> Self {
        Self {
            client: AsyncMutex::new(None),
            driver,
            port_range_start,
            account: Mutex::new(None),
            slots: Mutex::new(Vec::new()),
            unlimited: unlimited_connections,
        }
    }

    /// Authenticate via SRP, fetch the server list, and bind one port + one always-on SOCKS5
    /// listener per free-tier server (see the module doc comment). Replaces any slots from a
    /// previous login.
    pub async fn login(&self, email: &str, password: &str) -> Result<()> {
        let mut client = ProtonVPNClient::new(email);
        let creds = client.login(email, password).await?;
        client.fetch_servers().await?;
        self.finish_login(client, creds).await
    }

    /// Resume a stored session (see `session.rs`) instead of running SRP again. Tries the
    /// stored `access_token` first; on a `401` (expired token), exchanges the stored
    /// `refresh_token` for a new one and retries once. Returns the session to persist back
    /// (unchanged if no refresh was needed, updated tokens if it was) — the caller is
    /// responsible for writing it back to the keychain via `session::store`.
    pub async fn login_with_session(&self, session: &Session) -> Result<Session> {
        let mut client = ProtonVPNClient::new(&session.email);
        client.auth_token = Some(session.access_token.clone());
        client.uid = Some(session.uid.clone());

        let mut updated = session.clone();
        if matches!(client.fetch_servers().await, Err(ProtonError::Auth)) {
            let auth = client.refresh(&session.uid, &session.refresh_token).await?;
            updated.access_token = auth.access_token.ok_or(ProtonError::Auth)?;
            updated.refresh_token = auth
                .refresh_token
                .unwrap_or_else(|| session.refresh_token.clone());
            updated.uid = auth.uid.unwrap_or_else(|| session.uid.clone());
            client.fetch_servers().await?;
        }

        let creds = client
            .authenticate_with_session(&updated.uid, &updated.access_token)
            .await?;
        self.finish_login(client, creds).await?;
        Ok(updated)
    }

    /// Shared tail of `login`/`login_with_session`: bind one port + one always-on SOCKS5
    /// listener per free-tier server, replacing any slots from a previous login.
    async fn finish_login(&self, client: ProtonVPNClient, creds: VPNCredentials) -> Result<()> {
        // The account's real tier/connection-limit — see `client::fetch_account_info` and
        // `FALLBACK_TIER`'s doc comment for why this can't just be assumed. If the fetch
        // itself fails, fall back to the *most conservative* free-tier assumptions (tier 0,
        // 1 simultaneous connection) rather than silently defaulting to "unlimited" — an
        // account-info outage should never be the thing that disables the connection cap.
        let account = client.fetch_account_info().await.ok();
        let max_tier = account.as_ref().map_or(FALLBACK_TIER, |a| a.vpn.max_tier);
        let max_connect = account
            .as_ref()
            .map_or(1, |a| a.vpn.max_connect.max(0) as u32);

        let limiter = Arc::new(ConnectionLimiter::new(if self.unlimited {
            None
        } else {
            Some(max_connect)
        }));

        *self.account.lock().unwrap() = account.map(|a| AccountSummary {
            email: client.username.clone(),
            plan_name: a.vpn.plan_name,
            max_tier: a.vpn.max_tier,
            max_connect: a.vpn.max_connect,
        });

        let mut servers: Vec<VPNServer> = client
            .server_list
            .iter()
            .filter(|s| s.tier <= max_tier)
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

            let slot = ServerSlot::new(
                server,
                creds.clone(),
                self.driver.clone(),
                port,
                limiter.clone(),
            );
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

    /// Whether this daemon bypasses the account's simultaneous-connection cap
    /// (`gratis up --unlimited-connections`) — surfaced to the web UI as a persistent
    /// ToS-risk banner.
    pub fn unlimited(&self) -> bool {
        self.unlimited
    }

    /// The logged-in account's email/plan/tier/connection-limit, or `None` before the first
    /// successful login of the process. Surfaced on the web UI.
    pub fn account(&self) -> Option<AccountSummary> {
        self.account.lock().unwrap().clone()
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
            _stats: Arc<TunnelStats>,
        ) -> JoinHandle<()> {
            tokio::spawn(async {
                // Stand in for `run_socks5`'s infinite accept loop: never returns on its own.
                std::future::pending::<()>().await;
            })
        }
    }

    /// Fails `connect_tunnel` the first `fail_count` times it's called, then succeeds — stands
    /// in for a flaky free-tier server that answers on a retry rather than the first attempt.
    struct FlakyDriver {
        remaining_failures: std::sync::atomic::AtomicU32,
    }

    #[async_trait]
    impl TunnelDriver for FlakyDriver {
        async fn connect_tunnel(
            &self,
            _server: &VPNServer,
            _creds: &VPNCredentials,
        ) -> Result<SharedTunnel> {
            if self
                .remaining_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    if n == 0 { None } else { Some(n - 1) }
                })
                .is_ok()
            {
                return Err(ProtonError::Config("simulated flaky handshake".into()));
            }
            Ok(Arc::new(Tunnel::loopback_for_testing()))
        }

        fn spawn_socks5(
            &self,
            _listen_addr: String,
            _source: Arc<dyn TunnelSource>,
            _stats: Arc<TunnelStats>,
        ) -> JoinHandle<()> {
            tokio::spawn(async {
                std::future::pending::<()>().await;
            })
        }
    }

    /// Always fails `connect_tunnel` — stands in for a genuinely dead server.
    #[derive(Default)]
    struct AlwaysFailDriver;

    #[async_trait]
    impl TunnelDriver for AlwaysFailDriver {
        async fn connect_tunnel(
            &self,
            _server: &VPNServer,
            _creds: &VPNCredentials,
        ) -> Result<SharedTunnel> {
            Err(ProtonError::Config("simulated dead server".into()))
        }

        fn spawn_socks5(
            &self,
            _listen_addr: String,
            _source: Arc<dyn TunnelSource>,
            _stats: Arc<TunnelStats>,
        ) -> JoinHandle<()> {
            tokio::spawn(async {
                std::future::pending::<()>().await;
            })
        }
    }

    /// Never resolves on its first call, then succeeds instantly after that — stands in for a
    /// server whose handshake just never completes (as opposed to failing outright), which is
    /// the failure mode [`CONNECT_ATTEMPT_TIMEOUT`] exists to bound.
    struct HangsOnceThenSucceedsDriver {
        hung_once: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl TunnelDriver for HangsOnceThenSucceedsDriver {
        async fn connect_tunnel(
            &self,
            _server: &VPNServer,
            _creds: &VPNCredentials,
        ) -> Result<SharedTunnel> {
            if !self.hung_once.swap(true, Ordering::SeqCst) {
                std::future::pending::<()>().await;
                unreachable!("pending() never resolves");
            }
            Ok(Arc::new(Tunnel::loopback_for_testing()))
        }

        fn spawn_socks5(
            &self,
            _listen_addr: String,
            _source: Arc<dyn TunnelSource>,
            _stats: Arc<TunnelStats>,
        ) -> JoinHandle<()> {
            tokio::spawn(async {
                std::future::pending::<()>().await;
            })
        }
    }

    /// Never resolves, ever — stands in for a server that's completely unresponsive on every
    /// attempt.
    #[derive(Default)]
    struct AlwaysHangsDriver;

    #[async_trait]
    impl TunnelDriver for AlwaysHangsDriver {
        async fn connect_tunnel(
            &self,
            _server: &VPNServer,
            _creds: &VPNCredentials,
        ) -> Result<SharedTunnel> {
            std::future::pending::<()>().await;
            unreachable!("pending() never resolves");
        }

        fn spawn_socks5(
            &self,
            _listen_addr: String,
            _source: Arc<dyn TunnelSource>,
            _stats: Arc<TunnelStats>,
        ) -> JoinHandle<()> {
            tokio::spawn(async {
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
        slot_with_driver(port, Arc::new(FakeDriver::default()))
    }

    fn slot_with_driver(
        port: u16,
        driver: Arc<dyn TunnelDriver>,
    ) -> (Arc<TunnelManager>, Arc<ServerSlot>) {
        let manager = Arc::new(TunnelManager::with_driver(port, driver.clone(), false));
        let limiter = Arc::new(ConnectionLimiter::new(None));
        let slot = ServerSlot::new(
            test_server("srv-1", "US"),
            test_creds(),
            driver,
            port,
            limiter,
        );
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

    #[tokio::test]
    async fn acquire_retries_past_a_transient_connect_failure() {
        let driver = Arc::new(FlakyDriver {
            remaining_failures: std::sync::atomic::AtomicU32::new(2),
        });
        let (manager, slot) = slot_with_driver(20400, driver);

        let result = slot.acquire().await;
        assert!(
            result.is_ok(),
            "a connect attempt that fails twice then succeeds must still yield a tunnel \
             within the retry budget"
        );
        assert!(manager.servers()[0].connected);
    }

    #[tokio::test]
    async fn acquire_gives_up_once_the_retry_budget_is_exceeded() {
        let (_manager, slot) = slot_with_driver(20500, Arc::new(AlwaysFailDriver));

        let started = Instant::now();
        let result = slot.acquire().await;
        assert!(
            result.is_err(),
            "a permanently dead server must eventually fail"
        );
        assert!(
            started.elapsed() >= CONNECT_RETRY_BUDGET,
            "must not give up before spending the full retry budget"
        );
    }

    #[tokio::test]
    async fn acquire_abandons_an_attempt_that_never_finishes_and_retries() {
        let driver = Arc::new(HangsOnceThenSucceedsDriver {
            hung_once: std::sync::atomic::AtomicBool::new(false),
        });
        let (manager, slot) = slot_with_driver(20600, driver);

        let started = Instant::now();
        let result = slot.acquire().await;
        assert!(
            result.is_ok(),
            "an attempt stuck past CONNECT_ATTEMPT_TIMEOUT must be abandoned and retried, not \
             left to block the whole retry budget"
        );
        assert!(manager.servers()[0].connected);
        assert!(
            started.elapsed() < CONNECT_RETRY_BUDGET,
            "recovering on the second attempt must not cost the entire retry budget"
        );
    }

    #[tokio::test]
    async fn acquire_gives_up_promptly_when_every_attempt_hangs_forever() {
        let (_manager, slot) = slot_with_driver(20700, Arc::new(AlwaysHangsDriver));

        let started = Instant::now();
        let result = slot.acquire().await;
        let elapsed = started.elapsed();

        assert!(
            result.is_err(),
            "a server that never responds must eventually fail, not hang the caller forever"
        );
        assert!(
            elapsed < CONNECT_RETRY_BUDGET * 3,
            "must give up close to the retry budget even when every individual attempt hangs \
             indefinitely (elapsed: {elapsed:?})"
        );
    }

    /// Two slots (different servers) sharing one `ConnectionLimiter`, standing in for two
    /// `ServerSlot`s built from the same login — see `finish_login`.
    fn two_slots_with_limiter(max: Option<u32>) -> (Arc<ServerSlot>, Arc<ServerSlot>) {
        let driver: Arc<dyn TunnelDriver> = Arc::new(FakeDriver::default());
        let limiter = Arc::new(ConnectionLimiter::new(max));
        let a = ServerSlot::new(
            test_server("srv-a", "US"),
            test_creds(),
            driver.clone(),
            20800,
            limiter.clone(),
        );
        let b = ServerSlot::new(
            test_server("srv-b", "FR"),
            test_creds(),
            driver,
            20801,
            limiter,
        );
        (a, b)
    }

    #[tokio::test]
    async fn acquire_is_rejected_once_the_connection_cap_is_reached() {
        let (a, b) = two_slots_with_limiter(Some(1));

        assert!(a.acquire().await.is_ok(), "first tunnel is within the cap");
        let result = b.acquire().await;
        assert!(
            result.is_err(),
            "a second simultaneous tunnel must be rejected once the account's MaxConnect cap \
             (here: 1) is already in use by a different server"
        );

        // Rejection must not have counted against `open_connections` (see the fetch_sub next
        // to the rejection in `acquire`) — otherwise a rejected caller would still show as
        // "connected" in `servers()`.
        assert_eq!(b.status().open_connections, 0);
        assert!(!b.status().connected);
    }

    #[tokio::test]
    async fn acquire_succeeds_again_after_a_capped_slot_releases() {
        let (a, b) = two_slots_with_limiter(Some(1));

        a.acquire().await.unwrap();
        assert!(b.acquire().await.is_err());

        // Releasing every connection on `a` and letting its idle-teardown run frees the
        // reservation for `b`.
        a.release();
        tokio::time::sleep(IDLE_TIMEOUT + std::time::Duration::from_millis(50)).await;

        assert!(
            b.acquire().await.is_ok(),
            "the connection cap must free up once the slot holding it tears down"
        );
    }

    #[tokio::test]
    async fn acquire_ignores_the_cap_when_unlimited() {
        let (a, b) = two_slots_with_limiter(None);

        assert!(a.acquire().await.is_ok());
        assert!(
            b.acquire().await.is_ok(),
            "a `None` limiter (--unlimited-connections) must never reject a connect"
        );
    }

    #[tokio::test]
    async fn acquire_reusing_an_already_connected_tunnel_does_not_recount_against_the_cap() {
        let (a, _b) = two_slots_with_limiter(Some(1));

        a.acquire().await.unwrap();
        // A second caller reusing the same already-connected tunnel must not need (or
        // consume) a second reservation — only a genuinely new tunnel does.
        assert!(a.acquire().await.is_ok());
    }
}
