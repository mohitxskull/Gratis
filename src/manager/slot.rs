//! One server's proxy port + lazily-connected tunnel — the state machine `TunnelManager`
//! (`super`) drives. Split out of the old monolithic `manager.rs` (see that module's history)
//! as its own file since it's independently testable and the single largest concern living
//! there.
use super::{ConnectionLimiter, TunnelDriver};
use crate::errors::*;
use crate::models::{VPNCredentials, VPNServer};
use crate::socks5::{SourceError, TunnelSource};
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
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
#[cfg(test)]
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_millis(150);

/// Overall budget for `connect_with_retry` to bring up a tunnel before giving up entirely —
/// bounds the total time a single `acquire` can spend retrying a flaky/cold server, so a
/// persistently broken exit fails a connection attempt in bounded time instead of retrying
/// forever.
///
/// Shortened under `cfg(test)`, same reasoning as `IDLE_TIMEOUT`.
#[cfg(not(test))]
pub(crate) const CONNECT_RETRY_BUDGET: Duration = Duration::from_secs(10);
#[cfg(test)]
pub(crate) const CONNECT_RETRY_BUDGET: Duration = Duration::from_millis(100);

/// Delay between retry attempts inside `connect_with_retry` — long enough that a flaky server
/// isn't hammered, short enough that it doesn't eat much of `CONNECT_RETRY_BUDGET`.
///
/// Shortened under `cfg(test)`, same reasoning as `IDLE_TIMEOUT`.
#[cfg(not(test))]
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_millis(300);
#[cfg(test)]
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_millis(10);

/// Per-attempt timeout inside `connect_with_retry` — caps a single connect attempt so a hung
/// handshake can't itself burn the whole `CONNECT_RETRY_BUDGET` on one try, leaving no time for
/// a retry that might have succeeded.
///
/// Shortened under `cfg(test)`, same reasoning as `IDLE_TIMEOUT`.
#[cfg(not(test))]
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(test)]
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(25);

/// How long a slot's most recent successful external-TLS verification is trusted before
/// `acquire` re-verifies. Proton's restricted-session window re-arms after a tunnel goes idle
/// every two minutes, and a connection opened just after a rekey hits the same restriction (
/// verified live — a slot idle for ~2 minutes failed its next 3-4 TLS connections, while a
/// continuously-used slot stayed at 5/5). Re-verifying after this much inactivity covers that
/// without charging the probe to back-to-back connections, which are the common case.
pub(crate) const READINESS_TTL: Duration = Duration::from_secs(30);

/// One server the account can reach: a fixed port with an always-on SOCKS5 listener, whose WireGuard tunnel
/// is connected lazily on first use and torn down after `IDLE_TIMEOUT` idle (see the module
/// doc comment). Implements [`TunnelSource`] so `run_socks5`'s accept loop can drive it
/// directly.
pub(crate) struct ServerSlot {
    /// Immutable identity — never changes for this slot's lifetime, unlike the rest of
    /// `server`'s fields (load, physical entries, ...), which `apply_refreshed_servers`
    /// updates in place. Kept as a plain field so identity checks don't need to lock.
    pub(crate) id: String,
    pub(crate) server: Mutex<VPNServer>,
    /// Set by `apply_refreshed_servers` when this server no longer appears in a fresh fetch
    /// — Proton removed it, or it dropped out of the account's tier. `acquire` refuses new
    /// connections once this is true (see there for why), and it's cleared automatically if
    /// the server reappears in a later refresh. The port itself is never reused for a
    /// different server, so a client's SOCKS5 config pointing here gets a clear, stable
    /// error instead of silently starting to mean a different server later.
    pub(crate) removed: AtomicBool,
    /// Mutable so a token/certificate renewal (see `TunnelManager::renew_credentials`) can
    /// update every existing slot in place — a slot's `creds` otherwise never expires on its
    /// own, and the WireGuard certificate Proton issues is only valid for 168 minutes.
    creds: Mutex<VPNCredentials>,
    pub(crate) driver: Arc<dyn TunnelDriver>,
    port: u16,
    pub(crate) stats: Arc<TunnelStats>,

    pub(crate) tunnel: Mutex<Option<SharedTunnel>>,
    pub(crate) connected_at: Mutex<Option<Instant>>,
    /// When the tunnel will be torn down if `open_connections` stays at zero — set the moment
    /// it hits zero, cleared the moment a new connection arrives. `None` whenever there's no
    /// tunnel, or at least one connection is open.
    pub(crate) idle_deadline: Mutex<Option<Instant>>,
    pub(crate) open_connections: AtomicU32,
    /// Bumped on every `acquire` (including reuses of an already-connected tunnel). An
    /// idle-teardown timer only acts if this hasn't moved since it was spawned — see
    /// `release`'s doc comment for why that matters.
    pub(crate) idle_generation: AtomicU64,
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
    pub(crate) limiter: Arc<ConnectionLimiter>,
    /// The listener task's handle, so a re-login (`TunnelManager::finish_login`) can abort the
    /// old listener before re-binding its port — without this, `finish_login` running a second
    /// time in one process would leave the old (now orphaned) listener bound and fail to bind
    /// the new one with `EADDRINUSE`. `None` only for the brief window between construction and
    /// `set_listener_handle` (the caller that creates a slot always spawns its listener next).
    listener_handle: Mutex<Option<JoinHandle<()>>>,
}

impl ServerSlot {
    pub(crate) fn new(
        server: VPNServer,
        creds: VPNCredentials,
        driver: Arc<dyn TunnelDriver>,
        port: u16,
        limiter: Arc<ConnectionLimiter>,
    ) -> Arc<Self> {
        let id = server.id.clone();
        Arc::new_cyclic(|weak| Self {
            id,
            server: Mutex::new(server),
            removed: AtomicBool::new(false),
            creds: Mutex::new(creds),
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
            listener_handle: Mutex::new(None),
        })
    }

    /// Record the listener task's handle — call once, right after spawning it. See
    /// `listener_handle`'s doc comment for why this exists.
    pub(crate) fn set_listener_handle(&self, handle: JoinHandle<()>) {
        *self.listener_handle.lock().unwrap() = Some(handle);
    }

    /// Abort this slot's listener task, freeing its port immediately — call before a re-login
    /// re-binds the same port for a fresh slot. A no-op if no handle was ever recorded.
    pub(crate) fn abort_listener(&self) {
        if let Some(handle) = self.listener_handle.lock().unwrap().take() {
            handle.abort();
        }
    }

    /// Swap in freshly renewed credentials (new access token, new WireGuard certificate) —
    /// see `TunnelManager::renew_credentials`. Does not disturb an already-connected tunnel;
    /// the new creds take effect the next time this slot connects or unlocks one.
    pub(crate) fn update_creds(&self, creds: VPNCredentials) {
        *self.creds.lock().unwrap() = creds;
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
    pub(crate) async fn connect_with_retry(&self) -> Result<SharedTunnel> {
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
            // Clone out of the lock rather than holding a guard across the `.await` below.
            let server = self.server.lock().unwrap().clone();
            let creds = self.creds.lock().unwrap().clone();
            match tokio::time::timeout(attempt_timeout, self.driver.connect_tunnel(&server, &creds))
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
        let server = self.server.lock().unwrap().clone();
        let sni = server.pick_physical().map(|p| p.domain.clone());
        let creds = self.creds.lock().unwrap().clone();

        let agent_result = match &sni {
            Some(sni) => crate::agent::unlock(tunnel, sni, &creds).await,
            None => Err(ProtonError::NoPhysicalServer(format!(
                "server {} has no physical servers to derive a local-agent SNI from",
                server.name
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
                    log::warn!(
                        "local-agent handshake for {} failed ({err}); falling back to the \
                         readiness probe, so connections still work but the first one to each \
                         server is ~5s slower (further repeats of this failure will be silent \
                         until it clears). If this persists, Proton has most likely changed the \
                         agent protocol or rotated its pinned CAs — please report it with this \
                         message at https://github.com/mohitxskull/Gratis/issues so it can be \
                         updated.",
                        server.name
                    );
                    crate::notify::notify_clickable(
                        "gratis: local-agent handshake failed",
                        &format!(
                            "Falling back to the slower readiness probe for {} — connections \
                             still work, just slower. Click to report it (Proton may have \
                             changed the agent protocol or rotated its pinned CAs).",
                            server.name
                        ),
                        "https://github.com/mohitxskull/Gratis/issues/new",
                    );
                }
                tunnel.wait_until_data_path_ready(&server.name).await;
            }
        }
    }

    pub(crate) fn status(&self) -> ServerStatus {
        let server = self.server.lock().unwrap();
        let tunnel = self.tunnel.lock().unwrap().clone();
        let connected_at = *self.connected_at.lock().unwrap();
        let idle_deadline = *self.idle_deadline.lock().unwrap();
        ServerStatus {
            name: server.name.clone(),
            country: server.country.clone(),
            country_code: server.country_code.clone(),
            city: server.city.clone(),
            port: self.port,
            load: server.load,
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
            removed: self.removed.load(Ordering::SeqCst),
        }
    }

    /// Force this (idle, connected) slot's tunnel down to free its connection-cap reservation
    /// for another server — called only by `ConnectionLimiter::evict_least_recently_used`,
    /// which has already confirmed `open_connections == 0`, so this never interrupts active
    /// traffic. Bumps `idle_generation` so the idle-teardown task `release` already scheduled
    /// for this slot (if any) sees a stale generation on wake and skips its own teardown —
    /// without that, both this eviction and that later timer would call `limiter.release()`,
    /// double-releasing the same reservation.
    pub(crate) fn evict(&self) {
        *self.tunnel.lock().unwrap() = None;
        *self.connected_at.lock().unwrap() = None;
        *self.idle_deadline.lock().unwrap() = None;
        self.idle_generation.fetch_add(1, Ordering::SeqCst);
        self.limiter.release();
    }
}

#[async_trait]
impl TunnelSource for ServerSlot {
    async fn acquire(&self) -> std::result::Result<SharedTunnel, SourceError> {
        // Rejected unconditionally, before anything else — see the `removed` field's doc
        // comment. A stale/reused tunnel object for a server Proton no longer serves isn't
        // something worth trying to route through.
        if self.removed.load(Ordering::SeqCst) {
            return Err(Box::new(ProtonError::Config(format!(
                "{} is no longer available on your account — Proton removed it, or it's no \
                 longer within your account's tier; this port will keep failing until the \
                 server list changes again",
                self.id
            ))));
        }

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
                    let hint = if self.limiter.evict_lru {
                        "every connected server is actively in use — disconnect one, or start \
                         gratis with --unlimited-connections"
                    } else {
                        "disconnect another server first, start gratis with \
                         --unlimited-connections, or --evict-lru to free up the \
                         least-recently-used idle one automatically"
                    };
                    return Err(Box::new(ProtonError::AtCapacity(format!(
                        "max simultaneous tunnels reached ({}) — {hint}",
                        // `try_acquire` only returns `false` (reaching this branch) when `max`
                        // is `Some` — see its doc comment — so this can never actually
                        // substitute a value; `expect` makes that invariant explicit instead of
                        // `unwrap_or(0)` silently printing a misleading "reached (0)" if it ever
                        // did.
                        self.limiter
                            .max
                            .expect("AtCapacity is only returned when max is Some")
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
        let prev = self.open_connections.fetch_sub(1, Ordering::SeqCst);
        // `AtomicU32::fetch_sub` wraps on underflow rather than panicking. A `release` with no
        // matching `acquire` should never happen (see `ReleaseGuard`'s RAII pairing), but if it
        // ever did, wrapping to `u32::MAX` would make the `== 0` check below never fire again —
        // a silent, permanent leak of this slot's tunnel and its connection-cap reservation.
        // Restoring the count and bailing turns that failure mode into a contained no-op
        // instead.
        if prev == 0 {
            self.open_connections.fetch_add(1, Ordering::SeqCst);
            log::warn!(
                "server {}: release() called with open_connections already at 0 — ignoring an \
                 unbalanced release instead of corrupting the counter",
                self.id
            );
            return;
        }
        let remaining = prev - 1;
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
    /// True once this server no longer appears in a fresh fetch (Proton removed it, or it
    /// dropped out of the account's tier) — see `ServerSlot`'s `removed` field. The port
    /// keeps existing but refuses new connections rather than being reassigned to a
    /// different server later.
    pub removed: bool,
}
