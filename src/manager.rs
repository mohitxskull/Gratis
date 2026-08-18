//! Ties together auth (`client.rs`), the userspace WireGuard tunnel (`wireguard.rs`), the
//! SOCKS5 proxy (`socks5.rs`), and persisted credentials/state (`credentials.rs`) into a
//! per-location tunnel manager used by the control API (`src/api.rs`).
//!
//! ## No-root architecture
//!
//! Tunnels here are in-process userspace WireGuard sessions (see `wireguard.rs`), not real
//! kernel network interfaces brought up via `sudo wg-quick`. A tunnel is exactly as
//! long-lived as the `Arc<Tunnel>` referencing it and cannot outlive the daemon process — so
//! there is no "leaked interface" failure mode, no privileged `is_up` check, and no boot
//! reconciliation of stale kernel state to get wrong. `stop()` and process exit both simply
//! drop the tunnel.
//!
//! ## Restore-on-startup design decision
//!
//! `credentials::load_credentials()` returns a `VPNCredentials` (username/certificate/
//! WireGuard keypair) — it does **not** persist a session access token or the Proton server
//! list. `ProtonVPNClient::find_servers` operates on an in-memory `server_list` that is only
//! populated by an authenticated `fetch_servers()` call, and `fetch_servers()` requires a bearer
//! token from a live `login()`. There is therefore no way to serve `/api/locations` or `start()`
//! from persisted state alone without re-authenticating against the API.
//!
//! Saved credentials are informational only at startup (`TunnelManager::has_saved_credentials`
//! lets `main.rs` log "credentials found, but a fresh login is still required");
//! `list_locations`/`start` always require an in-process `login()` (via `POST /api/login`) to
//! populate `client` with a fresh token + server list. `POST /api/login` remains the single,
//! always-working primary path.
use crate::client::ProtonVPNClient;
use crate::credentials;
use crate::errors::*;
use crate::models::{VPNCredentials, VPNServer};
use crate::socks5;
use crate::wireguard::{self, CurrentTunnel, SharedTunnel, Tunnel};
use async_trait::async_trait;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

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

    /// Spawn whatever serves this location's SOCKS5 proxy, returning its `JoinHandle` so the
    /// manager can `abort()` it on `stop()`. `tunnel` is a swappable slot (see
    /// [`CurrentTunnel`]) rather than a fixed tunnel, so the manager can hot-swap which
    /// server it points at later without respawning this task.
    fn spawn_socks5(&self, listen_addr: String, tunnel: CurrentTunnel) -> JoinHandle<()>;
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

    fn spawn_socks5(&self, listen_addr: String, tunnel: CurrentTunnel) -> JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(err) = socks5::run_socks5(&listen_addr, tunnel).await {
                eprintln!("socks5 listener on {listen_addr} exited: {err}");
            }
        })
    }
}

/// The one currently active tunnel + SOCKS5 proxy, if any. `TunnelManager` runs at most one at
/// a time: starting a different location or server swaps this in place (same `socks_port`,
/// same SOCKS5 `task`, so already-open client connections are undisturbed — see
/// [`CurrentTunnel`]) rather than running multiple tunnels side by side.
struct RunningTunnel {
    location: String,
    server: String,
    interface: String,
    current: CurrentTunnel,
    task: JoinHandle<()>,
}

/// A country available to connect to, derived from the logged-in client's server list.
#[derive(Debug, Clone, Serialize)]
pub struct CountryInfo {
    pub code: String,
    pub name: String,
    /// Lowest load (0-100) among that country's servers.
    pub load: f64,
}

/// One individual server within a country, shown when its country row is expanded.
#[derive(Debug, Clone, Serialize)]
pub struct ServerSummary {
    pub name: String,
    pub load: f64,
}

/// A snapshot of one active tunnel, as surfaced by `GET /api/tunnels`.
#[derive(Debug, Clone, Serialize)]
pub struct TunnelInfo {
    pub location: String,
    pub interface: String,
    pub socks_port: u16,
    /// Name of the specific server this tunnel is connected to (e.g. `"US#1"`).
    pub server: String,
    /// Whether the SOCKS5 task backing this tunnel is still running, derived from
    /// `JoinHandle::is_finished()`.
    pub connected: bool,
}

/// Account tier used for `find_servers`'s `user_tier` filter.
///
/// `client.rs`/`models.rs` don't currently surface the account's actual tier anywhere the
/// manager can read it. This was previously `i32::MAX` (disabling the filter entirely) — **
/// confirmed live to be a real bug, not just a theoretical gap**: with the filter disabled,
/// `find_servers` picks the globally lowest-load server regardless of tier, which for a
/// free-tier test account selected a tier-2 (paid) server. The WireGuard handshake succeeded
/// (it authenticates by keypair, not by tier), but Proton silently dropped all subsequent
/// data traffic — the symptom was indistinguishable from a relay bug (TCP connects, a write
/// succeeds, no response ever arrives) until traced back to the server selection. Defaulting
/// to `0` (free tier) is the safe, conservative choice: it never selects a server above what
/// every account is entitled to, at the cost of paid-tier accounts not getting access to
/// plus-tier servers until the real account tier is threaded through from the API.
const PERMISSIVE_TIER: i32 = 0;

pub struct TunnelManager {
    client: AsyncMutex<Option<ProtonVPNClient>>,
    /// Fixed SOCKS5 port for the single tunnel this manager ever runs. Never changes across a
    /// location/server switch — only ever (re)bound once, the first time a tunnel starts.
    socks_port: u16,
    active: Mutex<Option<RunningTunnel>>,
    driver: Arc<dyn TunnelDriver>,
    /// Serializes `start_server()`/`stop()` end-to-end, so concurrent calls (e.g. a
    /// double-clicked button, or a switch racing a stop) can't interleave.
    switch_lock: AsyncMutex<()>,
}

impl TunnelManager {
    /// Build a manager using the real tunnel/SOCKS5 driver.
    pub fn new(socks_port: u16) -> Self {
        Self::with_driver(socks_port, Arc::new(RealDriver))
    }

    /// Build a manager with an injected driver (used by tests to avoid touching real
    /// WireGuard/network state).
    pub fn with_driver(socks_port: u16, driver: Arc<dyn TunnelDriver>) -> Self {
        Self {
            client: AsyncMutex::new(None),
            socks_port,
            active: Mutex::new(None),
            driver,
            switch_lock: AsyncMutex::new(()),
        }
    }

    /// Whether a previous session's credentials are present in the SQLite store. Informational
    /// only — see the module doc comment on why this can't drive an unattended restore.
    pub fn has_saved_credentials(&self) -> bool {
        credentials::load_credentials().is_ok()
    }

    /// Authenticate via SRP, fetch the server list, persist credentials, and store the live
    /// client for `list_locations`/`start` to use.
    pub async fn login(&self, email: &str, password: &str) -> Result<()> {
        let mut client = ProtonVPNClient::new(email);
        let creds = client.login(email, password).await?;
        client.fetch_servers().await?;
        credentials::save_credentials(&creds)?;
        *self.client.lock().await = Some(client);
        Ok(())
    }

    /// Distinct countries available from the logged-in client's server list, each with its
    /// lowest current load.
    pub async fn list_locations(&self) -> Result<Vec<CountryInfo>> {
        let guard = self.client.lock().await;
        let client = guard
            .as_ref()
            .ok_or_else(|| ProtonError::Config("not logged in".into()))?;

        let mut by_code: HashMap<String, CountryInfo> = HashMap::new();
        for server in client
            .server_list
            .iter()
            .filter(|s| s.tier <= PERMISSIVE_TIER)
        {
            by_code
                .entry(server.country_code.clone())
                .and_modify(|c| {
                    if server.load < c.load {
                        c.load = server.load;
                    }
                })
                .or_insert_with(|| CountryInfo {
                    code: server.country_code.clone(),
                    name: server.country.clone(),
                    load: server.load,
                });
        }

        let mut list: Vec<CountryInfo> = by_code.into_values().collect();
        list.sort_by(|a, b| a.code.cmp(&b.code));
        Ok(list)
    }

    /// Individual servers within `country_code`, lowest-load first — the detail list shown
    /// when a country row is expanded in the web UI. Informational only: starting a tunnel
    /// still operates at country granularity (`start` picks the lowest-load match itself),
    /// this doesn't let the caller pick a specific server yet.
    pub async fn list_servers_in(&self, country_code: &str) -> Result<Vec<ServerSummary>> {
        let guard = self.client.lock().await;
        let client = guard
            .as_ref()
            .ok_or_else(|| ProtonError::Config("not logged in".into()))?;

        Ok(client
            .find_servers(Some(country_code), None, None, PERMISSIVE_TIER)
            .into_iter()
            .map(|s| ServerSummary {
                name: s.name,
                load: s.load,
            })
            .collect())
    }

    /// Normalize a caller-supplied `location` (country code) to the canonical form used
    /// throughout (`active_tunnels` DB key, comparisons against the running tunnel's
    /// location): uppercase, exactly two ASCII letters.
    fn normalize_location(location: &str) -> Result<String> {
        let upper = location.to_ascii_uppercase();
        if upper.len() == 2 && upper.bytes().all(|b| b.is_ascii_alphabetic()) {
            Ok(upper)
        } else {
            Err(ProtonError::Config(format!(
                "invalid location {location:?}: expected a two-letter country code"
            )))
        }
    }

    /// Start the tunnel + SOCKS5 proxy pointed at `location` (a country code, e.g. `"US"`),
    /// picking whichever free-tier server there currently has the lowest load. Idempotent if
    /// already pointed at `location` (returns the existing port unchanged); otherwise brings
    /// up a tunnel (if none is running yet) or hot-swaps the running one over to `location`
    /// (see `start_server`). Returns the bound SOCKS5 port.
    pub async fn start(&self, location: &str) -> Result<u16> {
        self.start_server(location, None).await
    }

    /// Start the tunnel + SOCKS5 proxy pointed at `location`, connecting to `server_name`
    /// specifically (matched case-insensitively against `find_servers`' free-tier results)
    /// rather than letting `start` pick the lowest-load server. `None` behaves exactly like
    /// `start`.
    ///
    /// `TunnelManager` runs at most one tunnel at a time. If none is running, this brings one
    /// up. If one is already running — whether pointed at this same location or a completely
    /// different one — and the request names a different target (different location, or same
    /// location but a different server), this hot-swaps the underlying WireGuard tunnel in
    /// place: the SOCKS5 listener is never rebound (so the port never changes) and already-open
    /// client connections keep flowing through the tunnel they started on — see
    /// [`wireguard::CurrentTunnel`]. New connections after the swap use the new target.
    pub async fn start_server(&self, location: &str, server_name: Option<&str>) -> Result<u16> {
        let location = Self::normalize_location(location)?;
        let location = location.as_str();

        // Serialize the whole resolve -> connect_tunnel -> swap/spawn sequence so concurrent
        // calls (e.g. a double-clicked button in the web UI) can't race each other.
        let _guard = self.switch_lock.lock().await;

        let existing = self.active.lock().unwrap().as_ref().map(|a| {
            (
                a.current.clone(),
                a.location.clone(),
                a.server.clone(),
                a.task.is_finished(),
            )
        });

        if let Some((current, active_location, active_server, task_died)) = existing
            && !task_died
        {
            let already_there = active_location.eq_ignore_ascii_case(location)
                && match server_name {
                    None => true,
                    Some(name) => name.eq_ignore_ascii_case(&active_server),
                };
            if already_there {
                return Ok(self.socks_port);
            }

            let (server, creds) = self.resolve_server(location, server_name).await?;
            let tunnel = self.driver.connect_tunnel(&server, &creds).await?;
            // Swapping this slot's contents is the entire switch: `run_socks5` reads it fresh
            // per accepted connection, so this alone redirects future connections to the new
            // target. The old `SharedTunnel` this overwrites stays alive for as long as
            // already-accepted connections still hold their own clone of it, then tears down
            // on its own once the last one finishes.
            *current.lock().unwrap() = tunnel;

            let interface = wireguard::interface_name(location);
            if !active_location.eq_ignore_ascii_case(location) {
                credentials::clear_active(&active_location)?;
            }
            credentials::set_active(location, &interface, self.socks_port)?;

            if let Some(a) = self.active.lock().unwrap().as_mut() {
                a.location = location.to_string();
                a.server = server.name;
                a.interface = interface;
            }
            return Ok(self.socks_port);
        }

        let (server, creds) = self.resolve_server(location, server_name).await?;
        let tunnel = self.driver.connect_tunnel(&server, &creds).await?;

        let interface = wireguard::interface_name(location);

        // Record the active tunnel in the persisted store first, then spawn the proxy.
        //
        // If this fails (disk full, DB locked, permissions), nothing else has happened yet
        // that needs cleanup: `tunnel` is our only reference to it, so returning here simply
        // drops it — its background tasks abort via `Drop` (see `wireguard::SharedTunnel`'s
        // doc comment). Unlike the old `sudo wg-quick`-based design, there is no real
        // interface that could be left up with nothing tracking it.
        credentials::set_active(location, &interface, self.socks_port)?;

        let listen_addr = format!("127.0.0.1:{}", self.socks_port);
        let current: CurrentTunnel = Arc::new(std::sync::Mutex::new(tunnel));
        let task = self.driver.spawn_socks5(listen_addr, current.clone());

        // No race to check for here any more: `_guard` has held the switch lock for the
        // entire sequence above, so no concurrent call could have run any of it meanwhile.
        *self.active.lock().unwrap() = Some(RunningTunnel {
            location: location.to_string(),
            server: server.name,
            interface,
            current,
            task,
        });
        Ok(self.socks_port)
    }

    /// Resolve `server_name` (or, if `None`, the lowest-load server) within `location` to a
    /// `VPNServer` + the account's `VPNCredentials`. Shared by `start_server`'s cold-start and
    /// hot-swap paths.
    async fn resolve_server(
        &self,
        location: &str,
        server_name: Option<&str>,
    ) -> Result<(VPNServer, VPNCredentials)> {
        let guard = self.client.lock().await;
        let client = guard
            .as_ref()
            .ok_or_else(|| ProtonError::Config("not logged in".into()))?;
        let candidates = client.find_servers(Some(location), None, None, PERMISSIVE_TIER);
        let server = match server_name {
            Some(name) => candidates
                .into_iter()
                .find(|s| s.name.eq_ignore_ascii_case(name))
                .ok_or_else(|| {
                    ProtonError::Config(format!(
                        "server {name:?} not found in location {location}"
                    ))
                })?,
            None => candidates.into_iter().next().ok_or_else(|| {
                ProtonError::Config(format!("no servers found for location {location}"))
            })?,
        };
        let creds = client
            .vpn_credentials
            .clone()
            .ok_or_else(|| ProtonError::Config("logged in but missing vpn credentials".into()))?;
        Ok((server, creds))
    }

    /// Tear down the running tunnel + SOCKS5 proxy, if it's currently pointed at `location`.
    ///
    /// Unlike the old `sudo wg-quick`-based design, teardown cannot fail: there is no external
    /// process to shell out to. Aborting the SOCKS5 task and dropping the tunnel's last
    /// `Arc` reference is teardown.
    pub async fn stop(&self, location: &str) -> Result<()> {
        let location = Self::normalize_location(location)?;
        let location = location.as_str();

        // Shares the switch lock `start_server()` uses, so a `stop()` racing a start/switch
        // can't interleave with the latter's connect/set_active/spawn sequence.
        let _guard = self.switch_lock.lock().await;

        let matches = self
            .active
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|a| a.location.eq_ignore_ascii_case(location));
        if !matches {
            return Err(ProtonError::Config(format!(
                "no active tunnel for location {location}"
            )));
        }
        let running = self.active.lock().unwrap().take().unwrap();
        running.task.abort();
        drop(running); // drops the tunnel's Arc reference; background tasks abort via Drop

        credentials::clear_active(location)?;
        Ok(())
    }

    /// Snapshot of the currently-running tunnel, if any (0 or 1 entries — `TunnelManager` never
    /// runs more than one at a time).
    pub fn tunnels(&self) -> Vec<TunnelInfo> {
        self.active
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| TunnelInfo {
                location: a.location.clone(),
                interface: a.interface.clone(),
                socks_port: self.socks_port,
                server: a.server.clone(),
                connected: !a.task.is_finished(),
            })
            .into_iter()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `HOME`/`XDG_CONFIG_HOME` are process-global, but `cargo test` runs tests in this file
    /// concurrently on separate OS threads by default. Every test below that points
    /// `credentials::*`'s free functions (which read `HOME`/`XDG_CONFIG_HOME` on every call)
    /// at a scratch tempdir must hold this lock for its *entire* body — not just while calling
    /// `env::set_var` — so no two such tests interleave. A `tokio::sync::Mutex` (not
    /// `std::sync::Mutex`) is used specifically so the guard can be held safely across `.await`
    /// points.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

        fn spawn_socks5(&self, _listen_addr: String, _tunnel: CurrentTunnel) -> JoinHandle<()> {
            tokio::spawn(async {
                // Stand in for `run_socks5`'s infinite accept loop: never returns on its own,
                // only via `abort()`, matching the real driver's task shape.
                std::future::pending::<()>().await;
            })
        }
    }

    fn test_manager() -> TunnelManager {
        TunnelManager::with_driver(11000, Arc::new(FakeDriver::default()))
    }

    /// Directly exercises the tunnel-tracking bookkeeping without going through `start()`'s
    /// network/login path (which needs a live client): inserts a tunnel directly through the
    /// same private fields `start`/`stop` use.
    #[tokio::test]
    async fn manager_start_stop_tracks_state() {
        let _env_guard = ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: env vars are process-global; `_env_guard` (held for this whole test)
        // serializes this test against the other `HOME`/`XDG_CONFIG_HOME`-mutating tests in
        // this module so they never interleave.
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }

        let manager = test_manager();

        {
            let current: CurrentTunnel =
                Arc::new(std::sync::Mutex::new(Arc::new(Tunnel::loopback_for_testing())));
            let task = manager
                .driver
                .spawn_socks5("127.0.0.1:11000".to_string(), current.clone());
            *manager.active.lock().unwrap() = Some(RunningTunnel {
                location: "US".to_string(),
                server: "US#1".to_string(),
                interface: wireguard::interface_name("US"),
                current,
                task,
            });
        }

        let snapshot = manager.tunnels();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].location, "US");
        assert_eq!(snapshot[0].socks_port, 11000);
        assert!(snapshot[0].connected);

        // start() on an already-tracked location is idempotent and returns the existing port
        // without touching the (unset) client.
        let port = manager.start("US").await.unwrap();
        assert_eq!(port, 11000);

        manager.stop("US").await.unwrap();
        assert!(manager.tunnels().is_empty());

        // stop() on a location that isn't tracked is an error, not a panic.
        assert!(manager.stop("US").await.is_err());
    }

    const TEST_CERT_PEM: &str =
        "-----BEGIN CERTIFICATE-----\ntest-only-placeholder\n-----END CERTIFICATE-----";

    fn test_server(location: &str) -> crate::models::VPNServer {
        crate::models::VPNServer {
            id: "srv-1".into(),
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

    fn test_creds() -> crate::models::VPNCredentials {
        crate::models::VPNCredentials {
            username: "testuser".into(),
            ed25519_seed_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            wg_public_key: "CLIENTPUBKEYBASE64==".into(),
            wg_private_key: "CLIENTPRIVKEYBASE64==".into(),
            certificate: TEST_CERT_PEM.into(),
            certificate_expires_at: 9_999_999_999,
        }
    }

    /// Builds a `ProtonVPNClient` pre-populated with a fake server list + credentials, without
    /// any network call (`ProtonVPNClient`'s fields are all `pub`, so this bypasses `login()`/
    /// `fetch_servers()` entirely).
    fn fake_logged_in_client(location: &str) -> ProtonVPNClient {
        let mut client = ProtonVPNClient::new("test-user");
        client.vpn_credentials = Some(test_creds());
        client.server_list = vec![test_server(location)];
        client
    }

    /// Like `fake_logged_in_client`, but with two distinct free-tier servers in the same
    /// location (`"{location}-FREE#1"` and `"{location}-FREE#2"`), for exercising
    /// `start_server`'s hot-swap-between-servers path.
    fn fake_logged_in_client_two_servers(location: &str) -> ProtonVPNClient {
        let mut client = ProtonVPNClient::new("test-user");
        client.vpn_credentials = Some(test_creds());
        let mut second = test_server(location);
        second.name = format!("{location}-FREE#2");
        client.server_list = vec![test_server(location), second];
        client
    }

    /// Like `fake_logged_in_client`, but with one server per given location, for exercising
    /// `start_server`'s hot-swap-*across-locations* path.
    fn fake_logged_in_client_multi(locations: &[&str]) -> ProtonVPNClient {
        let mut client = ProtonVPNClient::new("test-user");
        client.vpn_credentials = Some(test_creds());
        client.server_list = locations.iter().map(|l| test_server(l)).collect();
        client
    }

    fn scratch_manager_with_driver(socks_port: u16, driver: Arc<FakeDriver>) -> TunnelManager {
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: see the note in `manager_start_stop_tracks_state` above.
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        // Leak the tempdir so it outlives the test (it's process-local scratch space cleaned
        // up when the test process exits; nothing else depends on it being removed sooner).
        std::mem::forget(tmp);
        TunnelManager::with_driver(socks_port, driver)
    }

    fn scratch_manager(socks_port: u16) -> TunnelManager {
        scratch_manager_with_driver(socks_port, Arc::new(FakeDriver::default()))
    }

    /// Drives `start()`'s real new-tunnel path (not just the idempotent short-circuit
    /// `manager_start_stop_tracks_state` exercises): a logged-in (faked) client selects a
    /// server, `connect_tunnel`/`spawn_socks5` are faked via `FakeDriver`, and the tunnel ends
    /// up tracked with a deterministic port.
    #[tokio::test]
    async fn manager_start_drives_new_tunnel_path() {
        let _env_guard = ENV_LOCK.lock().await;
        let manager = scratch_manager(12000);
        *manager.client.lock().await = Some(fake_logged_in_client("US"));

        let port = manager.start("US").await.unwrap();
        assert_eq!(port, 12000, "always the manager's fixed socks_port");

        let snapshot = manager.tunnels();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].location, "US");
        assert_eq!(snapshot[0].interface, wireguard::interface_name("US"));
        assert_eq!(snapshot[0].socks_port, 12000);
        assert!(snapshot[0].connected);

        // The active-tunnel row was actually persisted (via the real `credentials::set_active`
        // free function, pointed at the scratch HOME).
        let active = credentials::list_active().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].location, "US");
        assert_eq!(active[0].socks_port, 12000);

        manager.stop("US").await.unwrap();
        assert!(manager.tunnels().is_empty());
        assert!(credentials::list_active().unwrap().is_empty());
    }

    /// Reproduces the double-start race a prior review flagged: two concurrent `start()` calls
    /// for a location that isn't tracked yet (e.g. a double-clicked "Start" button) must not
    /// both bring a tunnel up / both write `credentials::set_active` rows — the per-location
    /// lock in `location_lock` must serialize them so exactly one `TunnelHandle` and one
    /// persisted `active_tunnels` row result, both agreeing on the same port.
    #[tokio::test]
    async fn manager_start_concurrent_same_location_is_serialized() {
        let _env_guard = ENV_LOCK.lock().await;
        let manager = Arc::new(scratch_manager(13000));
        *manager.client.lock().await = Some(fake_logged_in_client("NL"));

        let a = manager.clone();
        let b = manager.clone();
        let (port_a, port_b) = tokio::join!(
            tokio::spawn(async move { a.start("NL").await.unwrap() }),
            tokio::spawn(async move { b.start("NL").await.unwrap() }),
        );
        let (port_a, port_b) = (port_a.unwrap(), port_b.unwrap());

        // Both callers must observe the same winning port.
        assert_eq!(port_a, port_b);

        let snapshot = manager.tunnels();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].socks_port, port_a);

        let active = credentials::list_active().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].socks_port, port_a);
    }

    /// If the post-`connect_tunnel` step (`credentials::set_active`) fails, `start()` must
    /// leave nothing tracked/persisted — the tunnel `connect_tunnel` returned is simply
    /// dropped (no real interface exists that could leak).
    #[tokio::test]
    async fn manager_start_cleans_up_on_set_active_failure() {
        let _env_guard = ENV_LOCK.lock().await;
        let driver = Arc::new(FakeDriver::default());
        let manager = scratch_manager_with_driver(14200, driver.clone());
        *manager.client.lock().await = Some(fake_logged_in_client("US"));

        // Force the DB file into existence, then make it read-only so the `set_active` call
        // inside `start()` fails with a permissions error.
        credentials::set_active("ZZ", "proton-zz", 1).unwrap();
        let db_path = credentials::db_path().unwrap();
        let mut perms = std::fs::metadata(&db_path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o400);
        std::fs::set_permissions(&db_path, perms).unwrap();

        let result = manager.start("US").await;

        assert!(
            result.is_err(),
            "start() must propagate the set_active failure"
        );
        assert!(
            manager.tunnels().is_empty(),
            "nothing should be left tracked"
        );
        assert_eq!(
            driver.connect_calls.lock().unwrap().as_slice(),
            ["US"],
            "connect_tunnel must have been called once before the failure"
        );
    }

    /// `"us"` and `"US"` must resolve to the same tracked entry, closing the idempotence bug
    /// where two distinct casings of the same location were tracked as two distinct entries
    /// under two distinct per-location locks.
    #[tokio::test]
    async fn manager_start_normalizes_location_case() {
        let _env_guard = ENV_LOCK.lock().await;
        let manager = scratch_manager(14300);
        *manager.client.lock().await = Some(fake_logged_in_client("US"));

        let port_lower = manager.start("us").await.unwrap();
        let port_upper = manager.start("US").await.unwrap();
        assert_eq!(
            port_lower, port_upper,
            "\"us\" and \"US\" must resolve to the same tunnel"
        );

        let snapshot = manager.tunnels();
        assert_eq!(
            snapshot.len(),
            1,
            "only one tracked entry, not one per casing"
        );
        assert_eq!(snapshot[0].location, "US");

        // stop() with the other casing must find and tear down the same entry.
        manager.stop("us").await.unwrap();
        assert!(manager.tunnels().is_empty());
    }

    /// An invalid location must be rejected before it ever reaches `connect_tunnel` — proven
    /// here by asserting the driver's `connect_tunnel` was never called for a
    /// path-traversal-shaped value.
    #[tokio::test]
    async fn manager_start_rejects_invalid_location() {
        let _env_guard = ENV_LOCK.lock().await;
        let driver = Arc::new(FakeDriver::default());
        let manager = scratch_manager_with_driver(14400, driver.clone());

        let err = manager.start("../../x").await.unwrap_err();
        assert!(err.to_string().contains("invalid location"));

        let err = manager.start("usa").await.unwrap_err();
        assert!(err.to_string().contains("invalid location"));

        assert!(
            driver.connect_calls.lock().unwrap().is_empty(),
            "an invalid location must never reach connect_tunnel"
        );
        assert!(manager.tunnels().is_empty());
    }

    /// Switching to a different server in an already-connected location must hot-swap the
    /// underlying tunnel in place: same `socks_port` (the SOCKS5 listener is never rebound),
    /// same `TunnelHandle`'s `task` (never respawned — proven by it still being tracked as
    /// connected after the swap), and `tunnels()` must report the new server name.
    #[tokio::test]
    async fn manager_start_server_switches_without_changing_port() {
        let _env_guard = ENV_LOCK.lock().await;
        let manager = scratch_manager(15000);
        *manager.client.lock().await = Some(fake_logged_in_client_two_servers("US"));

        let port1 = manager
            .start_server("US", Some("US-FREE#1"))
            .await
            .unwrap();
        assert_eq!(manager.tunnels()[0].server, "US-FREE#1");

        let port2 = manager
            .start_server("US", Some("US-FREE#2"))
            .await
            .unwrap();

        assert_eq!(port1, port2, "switching servers must not change the port");
        let snapshot = manager.tunnels();
        assert_eq!(snapshot.len(), 1, "still exactly one tunnel for US");
        assert_eq!(snapshot[0].server, "US-FREE#2");
        assert!(
            snapshot[0].connected,
            "the SOCKS5 task must still be the original one, never respawned"
        );

        // Re-requesting the server it's already on is a no-op, not a third connect_tunnel call.
        let port3 = manager
            .start_server("US", Some("US-FREE#2"))
            .await
            .unwrap();
        assert_eq!(port3, port2);
    }

    /// `TunnelManager` runs at most one tunnel at a time: starting a *different* location while
    /// one is already running must swap it in place (same port, no second tunnel tracked), and
    /// the persisted `active_tunnels` row must move from the old location to the new one, not
    /// accumulate both.
    #[tokio::test]
    async fn manager_start_switches_across_locations_keeping_one_tunnel() {
        let _env_guard = ENV_LOCK.lock().await;
        let manager = scratch_manager(15100);
        *manager.client.lock().await = Some(fake_logged_in_client_multi(&["CH", "CA"]));

        let port1 = manager.start("CH").await.unwrap();
        assert_eq!(manager.tunnels()[0].location, "CH");

        let port2 = manager.start("CA").await.unwrap();
        assert_eq!(port1, port2, "switching locations must not change the port");

        let snapshot = manager.tunnels();
        assert_eq!(snapshot.len(), 1, "never more than one tunnel at a time");
        assert_eq!(snapshot[0].location, "CA");
        assert!(snapshot[0].connected);

        let active = credentials::list_active().unwrap();
        assert_eq!(
            active.len(),
            1,
            "the old location's active_tunnels row must be cleared, not left stranded"
        );
        assert_eq!(active[0].location, "CA");
    }
}
