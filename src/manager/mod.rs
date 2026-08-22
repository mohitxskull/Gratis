//! Ties together auth (`client.rs`), the userspace WireGuard tunnel (`wireguard.rs`), and the
//! SOCKS5 proxy (`socks5.rs`) into per-server "slots" (`ServerSlot`) driven by the control API
//! (`src/api.rs`).
//!
//! ## Port-per-server, lazily-connected, self-idling
//!
//! Right after login, `TunnelManager` assigns every server the account's real tier can reach
//! (see `finish_login`) a fixed port (sequential from `port_range_start`) and immediately
//! spawns an always-on SOCKS5 listener for it — no separate "connect" call is needed to make a
//! server reachable. What *is* lazy is the WireGuard tunnel behind that listener: the first
//! client connection to a server's port brings the tunnel up (see `ServerSlot::acquire`), and
//! it's torn back down automatically once the last client connection to it closes and
//! `IDLE_TIMEOUT` passes with no new one arriving (see `ServerSlot::release`) — the listener
//! itself keeps running the whole time, ready to reconnect on the next hit. How many servers
//! can have a *live tunnel* at once is capped at the account's real `MaxConnect` by default
//! (see `ConnectionLimiter`, private to this module); each slot is otherwise entirely
//! independent.
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
//!
//! ## Module layout
//!
//! Split across files by concern (previously one 1788-line file): `limiter` owns the
//! `MaxConnect` cap + LRU eviction, `driver` is the seam that swaps a real tunnel/listener for
//! a test double, `slot` is the per-server state machine, and this file (`mod.rs`) is the
//! `TunnelManager` facade that ties them together and is the only `pub` surface consumers
//! (`api.rs`, `main.rs`, `tray.rs`) see.
mod driver;
mod limiter;
mod slot;
#[cfg(test)]
mod tests;

use crate::client::ProtonVPNClient;
use crate::errors::*;
use crate::models::{VPNCredentials, VPNServer};
use crate::session::Session;
pub use driver::{ProxyProtocol, RealDriver, TunnelDriver};
use limiter::ConnectionLimiter;
use slot::ServerSlot;
pub use slot::ServerStatus;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

/// How often `main.rs`'s background loop calls `TunnelManager::refresh_servers`. Without this,
/// a long-running daemon's server list (load numbers, newly-added servers, removed servers)
/// only ever reflects what Proton returned at the moment it logged in — confirmed a real gap,
/// not theoretical: no periodic re-fetch existed anywhere before this constant. 30 minutes
/// balances staleness against not hammering the API for something that doesn't change
/// minute-to-minute.
pub const SERVER_LIST_REFRESH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(30 * 60);

/// How long `main.rs`'s background loop waits before proactively calling
/// `TunnelManager::renew_credentials` again, even if nothing has failed yet. Proton issues the
/// WireGuard certificate (`issue_credentials`, `client.rs`) for a fixed 168-minute lifetime;
/// without a proactive renewal, a slot that goes quiet for longer than that would only discover
/// its certificate is dead the next time it tries to connect (falling back to the slower
/// readiness probe rather than the local-agent handshake — see `unlock_tunnel`). Comfortably
/// under 168 minutes so renewal always lands before expiry even accounting for the 30-minute
/// tick granularity above.
pub const CREDENTIAL_RENEWAL_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(150 * 60);

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

/// Which Proton account is logged in and what it's entitled to — surfaced on the web UI so
/// it's obvious at a glance which account gratis is running as. Set once per login (see
/// `finish_login`); `None` only if `GET /vpn/v2` couldn't be reached at login time.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountSummary {
    pub email: String,
    pub plan_name: String,
    pub max_tier: i32,
    pub max_connect: i32,
}

pub struct TunnelManager {
    client: AsyncMutex<Option<ProtonVPNClient>>,
    driver: Arc<dyn TunnelDriver>,
    /// First port ever handed out. Existing servers keep whatever port they were first
    /// assigned — see `next_port` — this is only the starting point.
    port_range_start: u16,
    slots: Mutex<Vec<Arc<ServerSlot>>>,
    /// Bypasses the account's `MaxConnect` cap entirely — see [`ConnectionLimiter`]. Set once
    /// at construction from `gratis up --unlimited-connections`; a deliberate, opt-in choice.
    unlimited: bool,
    /// Opt-in (`gratis up --evict-lru`): evict the least-recently-used idle connected server
    /// instead of rejecting a new connection once `MaxConnect` is reached. See
    /// `ConnectionLimiter::evict_least_recently_used`.
    evict_lru: bool,
    /// Which protocol every port's listener speaks — see [`ProxyProtocol`]. One choice for the
    /// whole daemon, set once at construction from `gratis up --http-proxy`.
    protocol: ProxyProtocol,
    account: Mutex<Option<AccountSummary>>,
    /// Set by `finish_login`, read by `refresh_servers` — the account's real tier, so a
    /// periodic refresh doesn't need to re-fetch account info (which rarely changes) on
    /// every cycle, just the server list itself (which does).
    max_tier: Mutex<i32>,
    /// The account's client identity + WireGuard certificate — the same for every server
    /// this account can reach. Stored so `apply_refreshed_servers` can build slots for
    /// newly-appeared servers without a fresh login. `None` before the first login.
    creds: Mutex<Option<VPNCredentials>>,
    /// Shared by every slot from the current login. Stored so `apply_refreshed_servers` can
    /// register newly-appeared servers against the same cap/eviction state. `None` before
    /// the first login.
    limiter: Mutex<Option<Arc<ConnectionLimiter>>>,
    /// Next port to hand out to a genuinely new server. Only ever increases — a port once
    /// assigned to a server ID is never reused for a different one, even if that server
    /// disappears and a different one appears later. See `apply_refreshed_servers`.
    next_port: Mutex<u16>,
    /// Set by `main.rs`'s periodic update-check task, read by the control API (and from there,
    /// the tray) — the newest available version string once one is found, so the tray can show
    /// it without making its own GitHub API call. `None` means either not yet checked or
    /// already on the latest release.
    update_available: Mutex<Option<String>>,
    /// Set by `main.rs`'s `resume_or_login` and periodic refresh loop, read by the control API
    /// (and from there, `gratis status`) — the live reason gratis currently can't reach Proton,
    /// if any. `None` means the last attempt succeeded.
    ///
    /// Exists specifically because `gratis status`'s "logged in" line used to read only the
    /// *static session file on disk* (`session::load()`), which just means "we have some stored
    /// credentials" — not "those credentials still work right now". Confirmed live: a session
    /// can expire (Proton invalidates it, or the machine's clock jumps after a long sleep) while
    /// the file on disk is untouched, so the daemon logs `"stored session is no longer valid"`
    /// and keeps running with zero servers while `status` still confidently prints
    /// `"logged in: yes"`. This field is the daemon's own live knowledge of that failure, so
    /// `status` can report what's actually true right now instead of what's merely on disk.
    auth_error: Mutex<Option<String>>,
}

impl TunnelManager {
    /// Build a manager using the real tunnel/SOCKS5 driver.
    pub fn new(
        port_range_start: u16,
        unlimited_connections: bool,
        evict_lru: bool,
        protocol: ProxyProtocol,
    ) -> Self {
        Self::with_driver(
            port_range_start,
            Arc::new(RealDriver),
            unlimited_connections,
            evict_lru,
            protocol,
        )
    }

    /// Build a manager with an injected driver (used by tests to avoid touching real
    /// WireGuard/network state).
    pub fn with_driver(
        port_range_start: u16,
        driver: Arc<dyn TunnelDriver>,
        unlimited_connections: bool,
        evict_lru: bool,
        protocol: ProxyProtocol,
    ) -> Self {
        Self {
            client: AsyncMutex::new(None),
            driver,
            port_range_start,
            account: Mutex::new(None),
            slots: Mutex::new(Vec::new()),
            unlimited: unlimited_connections,
            evict_lru,
            protocol,
            max_tier: Mutex::new(FALLBACK_TIER),
            creds: Mutex::new(None),
            limiter: Mutex::new(None),
            next_port: Mutex::new(port_range_start),
            update_available: Mutex::new(None),
            auth_error: Mutex::new(None),
        }
    }

    /// Record the newest available version found by the periodic update check (or clear it
    /// back to `None` if the check finds we're already current).
    pub fn set_update_available(&self, version: Option<String>) {
        *self.update_available.lock().unwrap() = version;
    }

    /// The newest available version, if the periodic update check has found one.
    pub fn update_available(&self) -> Option<String> {
        self.update_available.lock().unwrap().clone()
    }

    /// Record the live reason gratis currently can't reach Proton (`Some`), or clear it after a
    /// subsequent success (`None`) — see the field's doc comment for why this exists.
    pub fn set_auth_error(&self, error: Option<String>) {
        *self.auth_error.lock().unwrap() = error;
    }

    /// The live auth problem, if any, as of the last login attempt or periodic refresh.
    pub fn auth_error(&self) -> Option<String> {
        self.auth_error.lock().unwrap().clone()
    }

    /// Authenticate via SRP, fetch the server list, and bind one port + one always-on SOCKS5
    /// listener per reachable server (see the module doc comment). Replaces any slots from a
    /// previous login.
    pub async fn login(&self, email: &str, password: &str) -> Result<()> {
        let mut client = ProtonVPNClient::new(email)?;
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
        let mut client = ProtonVPNClient::new(&session.email)?;
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

    /// Re-authenticate a long-running daemon whose access token has expired (or whose
    /// WireGuard certificate is approaching its 168-minute expiry) — the periodic maintenance
    /// loop in `main.rs` calls this when `refresh_servers` comes back `ProtonError::Auth`.
    ///
    /// Deliberately does **not** call `finish_login`: that clears and rebuilds every slot,
    /// which would re-bind every listener port while the *old* listener tasks are still bound
    /// to them (a latent `EADDRINUSE` — see the concurrency review's finding on `finish_login`
    /// non-idempotency). Instead this swaps in a fresh `ProtonVPNClient` + `VPNCredentials` and
    /// pushes the new creds into every already-existing slot in place, leaving slots, ports,
    /// and listener tasks completely untouched. A currently-connected tunnel keeps running on
    /// its old (still-valid-for-now) certificate; only the *next* connect/unlock for that slot
    /// picks up the renewed one.
    pub async fn renew_credentials(&self, session: &Session) -> Result<Session> {
        let mut client = ProtonVPNClient::new(&session.email)?;
        client.auth_token = Some(session.access_token.clone());
        client.uid = Some(session.uid.clone());

        let mut updated = session.clone();
        // The token may or may not actually be expired yet — this call is also used
        // proactively for certificate rotation, not just reactively after an Auth error — so
        // probe with `fetch_servers` the same way `login_with_session` does, and only refresh
        // if the token has in fact lapsed.
        if matches!(client.fetch_servers().await, Err(ProtonError::Auth)) {
            let auth = client.refresh(&session.uid, &session.refresh_token).await?;
            updated.access_token = auth.access_token.ok_or(ProtonError::Auth)?;
            updated.refresh_token = auth
                .refresh_token
                .unwrap_or_else(|| session.refresh_token.clone());
            updated.uid = auth.uid.unwrap_or_else(|| session.uid.clone());
        }

        let creds = client
            .authenticate_with_session(&updated.uid, &updated.access_token)
            .await?;

        *self.creds.lock().unwrap() = Some(creds.clone());
        for slot in self.slots.lock().unwrap().iter() {
            slot.update_creds(creds.clone());
        }
        *self.client.lock().await = Some(client);

        Ok(updated)
    }

    /// Shared tail of `login`/`login_with_session`: bind one port + one always-on SOCKS5
    /// listener per reachable server, replacing any slots from a previous login.
    async fn finish_login(&self, client: ProtonVPNClient, creds: VPNCredentials) -> Result<()> {
        // The account's real tier/connection-limit — see `client::fetch_account_info` and
        // `FALLBACK_TIER`'s doc comment for why this can't just be assumed. If the fetch
        // itself fails, fall back to the *most conservative* free-tier assumptions (tier 0,
        // 1 simultaneous connection) rather than silently defaulting to "unlimited" — an
        // account-info outage should never be the thing that disables the connection cap.
        let account = match client.fetch_account_info().await {
            Ok(a) => Some(a),
            Err(err) => {
                // The fallback itself is intentional (see above) but was previously silent —
                // a transient Proton outage at login would quietly cap a paid account at
                // free-tier limits with nothing in the log explaining why.
                log::warn!("couldn't fetch account info ({err}); assuming free-tier limits");
                None
            }
        };
        let max_tier = account.as_ref().map_or(FALLBACK_TIER, |a| a.vpn.max_tier);
        let max_connect = account
            .as_ref()
            .map_or(1, |a| a.vpn.max_connect.max(0) as u32);

        let limiter = Arc::new(ConnectionLimiter::new(
            if self.unlimited {
                None
            } else {
                Some(max_connect)
            },
            self.evict_lru,
        ));

        *self.account.lock().unwrap() = account.map(|a| AccountSummary {
            email: client.username.clone(),
            plan_name: a.vpn.plan_name,
            max_tier: a.vpn.max_tier,
            max_connect: a.vpn.max_connect,
        });
        *self.max_tier.lock().unwrap() = max_tier;
        *self.creds.lock().unwrap() = Some(creds);
        *self.limiter.lock().unwrap() = Some(limiter);

        // A fresh login replaces everything from a previous one: discard old slots/port
        // assignments so `apply_refreshed_servers` (below) treats every fetched server as
        // brand new, handing out fresh sequential ports from `port_range_start`. Abort each old
        // slot's listener *before* clearing — otherwise, on a process that calls `finish_login`
        // more than once (a future re-login path; today's `resume_or_login` only calls it once
        // per process), the old listeners would stay bound and the fresh ones below would fail
        // to bind the same ports with `EADDRINUSE`.
        // `mem::take` (rather than holding the lock guard across the loop below) keeps the
        // guard's lifetime to this one statement — a guard held across a `for` loop here was
        // enough to make the whole `async fn`'s generated future non-`Send` (`MutexGuard` isn't
        // `Send`), which broke `tokio::spawn`ing anything that calls this.
        let old_slots = std::mem::take(&mut *self.slots.lock().unwrap());
        for slot in &old_slots {
            slot.abort_listener();
        }
        *self.next_port.lock().unwrap() = self.port_range_start;

        let server_list = client.server_list.clone();
        self.apply_refreshed_servers(server_list)?;

        *self.client.lock().await = Some(client);
        Ok(())
    }

    /// Re-fetch the server list from Proton and reconcile it against the live slots — see
    /// `apply_refreshed_servers` for the reconciliation rules. Call periodically (see
    /// `main.rs`'s refresh loop) so a long-running daemon's server list, ports, and load
    /// numbers don't go stale. A failure here (network hiccup) leaves the existing slots
    /// completely untouched — it never tears anything down on its own.
    pub async fn refresh_servers(&self) -> Result<()> {
        let mut client_guard = self.client.lock().await;
        let Some(client) = client_guard.as_mut() else {
            return Err(ProtonError::Config(
                "refresh_servers called before a successful login".into(),
            ));
        };
        client.fetch_servers().await?;
        let fetched = client.server_list.clone();
        drop(client_guard);

        self.apply_refreshed_servers(fetched)
    }

    /// Reconcile `fetched` (an unfiltered server list, as returned by `fetch_servers`)
    /// against the current slots. Three cases per server:
    ///
    /// - **Still present** (same ID as an existing slot): update that slot's live metadata
    ///   (load, physical entries, ...) in place. Its port never changes, and an active
    ///   tunnel through it is completely undisturbed.
    /// - **Genuinely new** (no existing slot has this ID): get the next never-before-used
    ///   port (see `next_port`) and a fresh listener.
    /// - **No longer present** (an existing slot's ID isn't in `fetched` at all, including
    ///   because it dropped out of the account's tier): marked `removed` (see
    ///   `ServerSlot::acquire`) rather than torn down — a client's SOCKS5 config pointing at
    ///   that port gets a clear, permanent error instead of the port silently starting to
    ///   serve a *different* server if it were reassigned later. Automatically un-marked if
    ///   the same server ID reappears in a later refresh.
    ///
    /// Pure reconciliation logic with no network call of its own — call via `refresh_servers`
    /// in production; tests call this directly with a synthetic list.
    fn apply_refreshed_servers(&self, fetched: Vec<VPNServer>) -> Result<()> {
        let max_tier = *self.max_tier.lock().unwrap();
        let creds = self.creds.lock().unwrap().clone().ok_or_else(|| {
            ProtonError::Config("apply_refreshed_servers called before a successful login".into())
        })?;
        let limiter = self.limiter.lock().unwrap().clone().ok_or_else(|| {
            ProtonError::Config("apply_refreshed_servers called before a successful login".into())
        })?;

        let mut servers: Vec<VPNServer> =
            fetched.into_iter().filter(|s| s.tier <= max_tier).collect();
        servers.sort_by(|a, b| a.id.cmp(&b.id));
        let fetched_ids: HashSet<&str> = servers.iter().map(|s| s.id.as_str()).collect();

        let mut slots = self.slots.lock().unwrap();

        // Mark servers no longer present as removed; un-mark ones that reappeared.
        for slot in slots.iter() {
            slot.removed
                .store(!fetched_ids.contains(slot.id.as_str()), Ordering::SeqCst);
        }

        let mut next_port = self.next_port.lock().unwrap();
        for server in servers {
            if let Some(slot) = slots.iter().find(|s| s.id == server.id) {
                *slot.server.lock().unwrap() = server;
                continue;
            }

            // Genuinely new server: hand out the next never-before-used port.
            let port = *next_port;
            *next_port = next_port.checked_add(1).ok_or_else(|| {
                ProtonError::Config("ran out of ports for the server list".into())
            })?;

            let slot = ServerSlot::new(
                server,
                creds.clone(),
                self.driver.clone(),
                port,
                limiter.clone(),
            );
            limiter.register(&slot);
            // Meant to run for the rest of the process's life under normal operation, but
            // recorded on the slot (rather than dropped) so a future re-login can abort it
            // before re-binding this port — see `ServerSlot::abort_listener`.
            let handle = self.driver.spawn_listener(
                format!("127.0.0.1:{port}"),
                slot.clone(),
                slot.stats.clone(),
                self.protocol,
            );
            slot.set_listener_handle(handle);
            slots.push(slot);
        }

        Ok(())
    }

    /// Every server this account can reach, each with its assigned port and current
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

    /// Whether this daemon evicts idle connections to make room at the cap instead of
    /// rejecting new ones (`gratis up --evict-lru`) — surfaced to the web UI so it's visible
    /// without needing to check `gratis status` or the unit file.
    pub fn evict_lru(&self) -> bool {
        self.evict_lru
    }

    /// The logged-in account's email/plan/tier/connection-limit, or `None` before the first
    /// successful login of the process. Surfaced on the web UI.
    pub fn account(&self) -> Option<AccountSummary> {
        self.account.lock().unwrap().clone()
    }
}
