//! Ties together auth (Task 02: `client.rs`), WireGuard (Task 03: `wireguard.rs`), the SOCKS5
//! proxy (Task 04: `socks5.rs`), and persisted credentials/state (`credentials.rs`) into a
//! per-location tunnel manager used by the control API (`src/api.rs`).
//!
//! ## Restore-on-startup design decision
//!
//! `credentials::load_credentials()` returns a `VPNCredentials` (username/password/certificate/
//! WireGuard keypair) — it does **not** persist a session access token or the Proton server
//! list. `ProtonVPNClient::find_servers` operates on an in-memory `server_list` that is only
//! populated by an authenticated `fetch_servers()` call, and `fetch_servers()` requires a bearer
//! token from a live `login()`. There is therefore no way to serve `/api/locations` or `start()`
//! from persisted state alone without re-authenticating against the API.
//!
//! We take option (b) from the task brief: saved credentials are informational only at
//! startup (`TunnelManager::has_saved_credentials` lets `main.rs` log "credentials found, but a
//! fresh login is still required"); `list_locations`/`start` always require an in-process
//! `login()` (via `POST /api/login`) to populate `client` with a fresh token + server list.
//! `POST /api/login` remains the single, always-working primary path.
use crate::client::ProtonVPNClient;
use crate::credentials;
use crate::errors::*;
use crate::models;
use crate::socks5;
use crate::wireguard;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

/// Seam for testing `TunnelManager` without root/live WireGuard/network access.
///
/// `wireguard::up`/`down` are free functions (not trait objects), and `socks5::run_socks5`
/// binds a real listener and runs forever. To unit-test `TunnelManager`'s bookkeeping
/// (`manager_start_stop_tracks_state`) without any of that, the manager is generic over this
/// trait: production code uses `RealDriver` (which just calls through to `wireguard`/
/// `socks5`), and tests use a `FakeDriver` that records calls and spawns an inert task instead
/// of a real SOCKS5 listener.
pub trait TunnelDriver: Send + Sync {
    /// Bring the WireGuard interface up. Blocking (shells to `sudo wg-quick`); callers must
    /// run this inside `spawn_blocking`.
    fn wg_up(&self, interface: &str, config: &str) -> Result<()>;

    /// Tear the WireGuard interface down. Blocking; same calling convention as `wg_up`.
    fn wg_down(&self, interface: &str) -> Result<()>;

    /// Whether `interface` currently has a live WireGuard device. Blocking; same calling
    /// convention as `wg_up`/`wg_down`. Used by `stop()` to make teardown idempotent against
    /// an interface that's already down (e.g. torn down externally, or by boot reconciliation
    /// in a previous process).
    fn is_up(&self, interface: &str) -> bool;

    /// Spawn whatever serves this location's SOCKS5 proxy, returning its `JoinHandle` so the
    /// manager can `abort()` it on `stop()`.
    fn spawn_socks5(&self, listen_addr: String, interface: String) -> JoinHandle<()>;
}

/// Production driver: shells to real `wg-quick` and binds a real SOCKS5 listener.
pub struct RealDriver;

impl TunnelDriver for RealDriver {
    fn wg_up(&self, interface: &str, config: &str) -> Result<()> {
        wireguard::up(interface, config)
    }

    fn wg_down(&self, interface: &str) -> Result<()> {
        wireguard::down(interface)
    }

    fn is_up(&self, interface: &str) -> bool {
        wireguard::is_up(interface)
    }

    fn spawn_socks5(&self, listen_addr: String, interface: String) -> JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(err) = socks5::run_socks5(&listen_addr, &interface).await {
                // Secrets are never in scope here (listen_addr/interface only); safe to log.
                eprintln!("socks5 listener on {listen_addr} ({interface}) exited: {err}");
            }
        })
    }
}

/// A tracked, running tunnel: the WireGuard interface it uses, the SOCKS5 port it's bound to,
/// and the `JoinHandle` of the task serving that SOCKS5 proxy.
struct TunnelHandle {
    interface: String,
    socks_port: u16,
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

/// A snapshot of one active tunnel, as surfaced by `GET /api/tunnels`.
#[derive(Debug, Clone, Serialize)]
pub struct TunnelInfo {
    pub location: String,
    pub interface: String,
    pub socks_port: u16,
    /// Whether the SOCKS5 task backing this tunnel is still running. Derived from
    /// `JoinHandle::is_finished()` rather than shelling out to `wg show` (`wireguard::is_up`)
    /// on every poll — it's in-process, free, and good enough for the admin UI's purposes; a
    /// tunnel whose WireGuard interface died independently of its SOCKS5 task would still show
    /// `connected: true` here (a known limitation, documented rather than silently assumed
    /// away).
    pub connected: bool,
}

/// Permissive account tier used for `find_servers`'s `user_tier` filter: `client.rs`/
/// `models.rs` don't currently surface the account's actual tier anywhere the manager can read
/// it (Task 02's `VPNCredentials`/`AccountResponse` don't carry it), so we pass the maximum
/// possible tier to effectively disable the tier filter. This means `start()` may pick servers
/// above the account's actual entitlement if Proton's `/vpn/v1/servers` response includes them
/// (it may not — free-tier accounts likely only see servers they can use) — documented as a
/// known gap for a future task once the account response's plan/tier field is confirmed.
const PERMISSIVE_TIER: i32 = i32::MAX;

pub struct TunnelManager {
    client: AsyncMutex<Option<ProtonVPNClient>>,
    socks_base_port: u16,
    tunnels: Mutex<HashMap<String, TunnelHandle>>,
    /// Monotonically increasing port index; a location's assigned port is
    /// `socks_base_port + index`. Deliberately never reused after `stop()`, so a rapid
    /// stop/start of the same location can't collide with another location's still-shutting-
    /// down listener on the same port.
    next_port_index: AtomicU16,
    driver: Arc<dyn TunnelDriver>,
    /// Per-location async locks serializing `start()`/`stop()` for a given location, so the
    /// whole `wg_up -> credentials::set_active -> spawn_socks5 -> tunnels.insert` sequence
    /// (and the mirrored `stop()` sequence) is atomic with respect to concurrent calls for the
    /// *same* location — see `location_lock`. Distinct locations proceed independently: each
    /// gets its own `tokio::sync::Mutex`. Entries are never removed once created (the key
    /// space is bounded by the small, roughly-fixed set of country codes Proton exposes, so
    /// this is a deliberate, harmless simplification rather than an unbounded leak).
    start_locks: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl TunnelManager {
    /// Build a manager using the real WireGuard/SOCKS5 driver.
    pub fn new(socks_base_port: u16) -> Self {
        Self::with_driver(socks_base_port, Arc::new(RealDriver))
    }

    /// Build a manager with an injected driver (used by tests to avoid touching real
    /// WireGuard/network state).
    pub fn with_driver(socks_base_port: u16, driver: Arc<dyn TunnelDriver>) -> Self {
        Self {
            client: AsyncMutex::new(None),
            socks_base_port,
            tunnels: Mutex::new(HashMap::new()),
            next_port_index: AtomicU16::new(0),
            driver,
            start_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Get (creating if absent) the per-location async lock used to serialize `start()`/
    /// `stop()` for `location`.
    fn location_lock(&self, location: &str) -> Arc<AsyncMutex<()>> {
        self.start_locks
            .lock()
            .unwrap()
            .entry(location.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    /// Whether a previous session's credentials are present in the SQLite store. Informational
    /// only — see the module doc comment on why this can't drive an unattended restore.
    pub fn has_saved_credentials(&self) -> bool {
        credentials::load_credentials().is_ok()
    }

    /// Authenticate via SRP (Task 02), fetch the server list, persist credentials, and store
    /// the live client for `list_locations`/`start` to use.
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
        for server in &client.server_list {
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

    /// Normalize a caller-supplied `location` (country code) to the canonical form used as the
    /// `tunnels`/`start_locks`/`active_tunnels` key: uppercase, exactly two ASCII letters.
    ///
    /// Fixes finding #5: `find_servers` already compares country codes case-insensitively, but
    /// without this, `"US"` and `"us"` would be tracked as two distinct entries (two distinct
    /// per-location locks, two distinct map keys) that both resolve to the same
    /// `wireguard::interface_name` (which lowercases internally) — the second `wg-quick up`
    /// for that interface then fails, silently defeating the double-start protection
    /// `location_lock` provides. Validating the shape here also means an invalid value (e.g.
    /// `"../../x"`) is rejected before it ever reaches `wireguard::interface_name`/
    /// `wireguard::config_path`, rather than being incidentally blocked only because it happens
    /// to match no server's `country_code`.
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

    /// Start a tunnel + SOCKS5 proxy for `location` (a country code, e.g. `"US"`) if not
    /// already running; idempotent (returns the existing port if already up). Returns the
    /// bound SOCKS5 port.
    pub async fn start(&self, location: &str) -> Result<u16> {
        let location = Self::normalize_location(location)?;
        let location = location.as_str();

        if let Some(port) = self.existing_port(location) {
            return Ok(port);
        }

        // Serialize the whole wg_up -> set_active -> spawn -> insert sequence per location so
        // two concurrent `start()` calls for a location that isn't tracked yet (e.g. a
        // double-clicked "Start" button in the web UI, which has no in-flight guard) can't
        // both bring the WireGuard interface up and both write a `credentials::set_active`
        // row keyed by the same location — whichever write landed second used to silently win
        // in SQLite regardless of which racer's in-memory `TunnelHandle` ended up tracked.
        // Distinct locations use distinct locks and are unaffected.
        let lock = self.location_lock(location);
        let _guard = lock.lock().await;

        // Re-check after acquiring the lock: another `start()` call may have completed the
        // full sequence for this location while we were waiting for it.
        if let Some(port) = self.existing_port(location) {
            return Ok(port);
        }

        let (server, creds) = {
            let guard = self.client.lock().await;
            let client = guard
                .as_ref()
                .ok_or_else(|| ProtonError::Config("not logged in".into()))?;
            let server = client
                .find_servers(Some(location), None, None, PERMISSIVE_TIER)
                .into_iter()
                .next()
                .ok_or_else(|| {
                    ProtonError::Config(format!("no servers found for location {location}"))
                })?;
            let creds = client.vpn_credentials.clone().ok_or_else(|| {
                ProtonError::Config("logged in but missing vpn credentials".into())
            })?;
            (server, creds)
        };

        let interface = wireguard::interface_name(location);
        let client_address = models::client_address_from_certificate(&creds.certificate)?;
        let config = wireguard::generate_config(&server, &creds, &client_address, &interface);

        let driver = self.driver.clone();
        let up_interface = interface.clone();
        tokio::task::spawn_blocking(move || driver.wg_up(&up_interface, &config))
            .await
            .map_err(|e| ProtonError::Config(format!("wg up task panicked: {e}")))??;

        let idx = self.next_port_index.fetch_add(1, Ordering::SeqCst);
        let socks_port = self.socks_base_port + idx;

        // Record the active tunnel in the persisted store first (so `list_active`/other
        // process invocations see it as soon as WireGuard is up), then spawn the proxy.
        //
        // Fixes finding #4: if this fails (disk full, DB locked, permissions) `wg_up` above
        // has already succeeded, so without cleanup the interface would be left up with
        // nothing tracked/persisted for it — a leak `stop()` can never find, since nothing is
        // tracked for this location. Best-effort bring the interface back down before
        // propagating the original error; a cleanup failure is logged but never masks it.
        if let Err(err) = credentials::set_active(location, &interface, socks_port) {
            let driver = self.driver.clone();
            let cleanup_interface = interface.clone();
            match tokio::task::spawn_blocking(move || driver.wg_down(&cleanup_interface)).await {
                Ok(Ok(())) => {}
                Ok(Err(cleanup_err)) => eprintln!(
                    "proton-proxy: failed to clean up interface {interface} after start() failed for location {location}: {cleanup_err}"
                ),
                Err(join_err) => eprintln!(
                    "proton-proxy: cleanup task panicked after start() failed for location {location}: {join_err}"
                ),
            }
            return Err(err);
        }

        let listen_addr = format!("127.0.0.1:{socks_port}");
        let task = self.driver.spawn_socks5(listen_addr, interface.clone());

        // No race to check for here any more: `_guard` has held this location's lock for the
        // entire `wg_up -> set_active -> spawn` sequence above, so no concurrent `start()` for
        // `location` could have run any of it in the meantime.
        self.tunnels.lock().unwrap().insert(
            location.to_string(),
            TunnelHandle {
                interface,
                socks_port,
                task,
            },
        );
        Ok(socks_port)
    }

    fn existing_port(&self, location: &str) -> Option<u16> {
        self.tunnels
            .lock()
            .unwrap()
            .get(location)
            .map(|h| h.socks_port)
    }

    /// Tear down the tunnel + SOCKS5 proxy for `location`.
    ///
    /// Fixes finding #2: state (the in-memory `TunnelHandle` and the persisted
    /// `active_tunnels` row) is only dropped *after* teardown is confirmed, not before. The
    /// old ordering removed the handle and aborted the SOCKS5 task before the fallible
    /// `wg_down` call ran; if `wg_down` failed for any reason, the tunnel was permanently
    /// orphaned — no handle to retry with, no way back except manual intervention. Now, if
    /// `wg_down` fails, the tunnel is left tracked (still marked up) and the error is
    /// propagated so the caller can retry `stop()`.
    ///
    /// Also idempotent against an interface that's already down (e.g. torn down externally, or
    /// by a previous process's boot reconciliation that didn't get to clear the DB row): checks
    /// `driver.is_up` first, and treats "already down" as a no-op success rather than erroring.
    pub async fn stop(&self, location: &str) -> Result<()> {
        let location = Self::normalize_location(location)?;
        let location = location.as_str();

        // Shares the same per-location lock `start()` uses, so a `stop()` racing a `start()`
        // for the same location can't interleave with the latter's wg_up/set_active/spawn
        // sequence.
        let lock = self.location_lock(location);
        let _guard = lock.lock().await;

        let interface = {
            let tunnels = self.tunnels.lock().unwrap();
            match tunnels.get(location) {
                Some(handle) => handle.interface.clone(),
                None => {
                    return Err(ProtonError::Config(format!(
                        "no active tunnel for location {location}"
                    )));
                }
            }
        };

        let driver = self.driver.clone();
        let check_interface = interface.clone();
        let is_up = tokio::task::spawn_blocking(move || driver.is_up(&check_interface))
            .await
            .map_err(|e| ProtonError::Config(format!("wg is_up task panicked: {e}")))?;

        if is_up {
            let driver = self.driver.clone();
            let down_interface = interface.clone();
            // If this fails, deliberately return *before* touching `self.tunnels` or the DB
            // below: the tunnel stays tracked so the caller can retry.
            tokio::task::spawn_blocking(move || driver.wg_down(&down_interface))
                .await
                .map_err(|e| ProtonError::Config(format!("wg down task panicked: {e}")))??;
        }

        // Teardown confirmed (or was already a no-op because the interface was already down):
        // only now is it safe to drop in-memory/persisted state.
        if let Some(handle) = self.tunnels.lock().unwrap().remove(location) {
            handle.task.abort();
        }

        credentials::clear_active(location)?;
        Ok(())
    }

    /// Snapshot of all currently-tracked tunnels.
    pub fn tunnels(&self) -> Vec<TunnelInfo> {
        self.tunnels
            .lock()
            .unwrap()
            .iter()
            .map(|(location, h)| TunnelInfo {
                location: location.clone(),
                interface: h.interface.clone(),
                socks_port: h.socks_port,
                connected: !h.task.is_finished(),
            })
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
    /// `env::set_var` — so no two such tests interleave (one test's tempdir could otherwise be
    /// torn down, or its env vars overwritten, mid another test's `credentials::set_active`/
    /// `list_active` call). A `tokio::sync::Mutex` (not `std::sync::Mutex`) is used
    /// specifically so the guard can be held safely across `.await` points.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Records `wg_up`/`wg_down`/`is_up` calls (no real WireGuard) and spawns an inert task
    /// instead of a real SOCKS5 listener, so `TunnelManager` bookkeeping can be tested without
    /// root.
    ///
    /// Configurable so tests can simulate the failure modes findings #2/#4 fixed: `fail_down`
    /// makes `wg_down` return `Err` (simulating a hung `sudo`/a `wg-quick down` failure), and
    /// `already_down` lets a test mark specific interfaces as already-torn-down so `is_up`
    /// reports `false` for them (simulating an interface that died externally).
    #[derive(Default)]
    struct FakeDriver {
        up_calls: Mutex<Vec<String>>,
        down_calls: Mutex<Vec<String>>,
        fail_down: std::sync::atomic::AtomicBool,
        already_down: Mutex<std::collections::HashSet<String>>,
    }

    impl TunnelDriver for FakeDriver {
        fn wg_up(&self, interface: &str, _config: &str) -> Result<()> {
            self.up_calls.lock().unwrap().push(interface.to_string());
            Ok(())
        }

        fn wg_down(&self, interface: &str) -> Result<()> {
            self.down_calls.lock().unwrap().push(interface.to_string());
            if self.fail_down.load(Ordering::SeqCst) {
                return Err(ProtonError::Config(
                    "simulated wg-quick down failure".into(),
                ));
            }
            Ok(())
        }

        fn is_up(&self, interface: &str) -> bool {
            !self.already_down.lock().unwrap().contains(interface)
        }

        fn spawn_socks5(&self, _listen_addr: String, _interface: String) -> JoinHandle<()> {
            tokio::spawn(async {
                // Stand in for `run_socks5`'s infinite accept loop: never returns on its own,
                // only via `abort()`, matching the real driver's task shape.
                std::future::pending::<()>().await;
            })
        }
    }

    fn test_manager() -> TunnelManager {
        // Use a scratch HOME so credentials::set_active/clear_active (which hit the real
        // `~/.config/proton-proxy/proton-proxy.db`) don't touch the developer's actual store.
        TunnelManager::with_driver(11000, Arc::new(FakeDriver::default()))
    }

    /// Directly exercises the tunnel-tracking bookkeeping without going through `start()`'s
    /// network/login path (which needs a live client) — this is the "lower-level test-only
    /// bypass" seam variant, layered on top of the `TunnelDriver` injection so the WireGuard
    /// and SOCKS5 side effects are faked too.
    #[tokio::test]
    async fn manager_start_stop_tracks_state() {
        let _env_guard = ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: env vars are process-global; `_env_guard` (held for this whole test)
        // serializes this test against the other `HOME`/`XDG_CONFIG_HOME`-mutating tests in
        // this module so they never interleave. Tests elsewhere in the crate that touch
        // credentials use `Store::open` with an explicit path, not the free functions, so
        // they're unaffected either way.
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }

        let manager = test_manager();

        // Bypass login/find_servers (no live account) by inserting a tunnel directly through
        // the same code path `start()` uses after server selection, minus the client lookup:
        // simplest is to fake a full server+creds pair and drive the rest of `start()`'s body
        // via a second, minimal constructor-free helper. Since `start()` requires a logged-in
        // client, and building one needs the network, we instead assert the *documented*
        // contract at the level available without a live account: manual bookkeeping via the
        // same private fields `start`/`stop` use, proving `tunnels()`/`stop()` behave
        // correctly given a tracked tunnel.
        {
            let task = manager.driver.spawn_socks5(
                "127.0.0.1:11000".to_string(),
                wireguard::interface_name("US"),
            );
            manager.tunnels.lock().unwrap().insert(
                "US".to_string(),
                TunnelHandle {
                    interface: wireguard::interface_name("US"),
                    socks_port: 11000,
                    task,
                },
            );
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

    /// A self-signed test certificate (RSA-2048, `CN=proton-test`) with a single SAN IP entry
    /// of `10.2.0.5` — the same fixture `tests/wireguard_config.rs` uses (duplicated here
    /// since unit tests in `src/` can't reach files under `tests/`). Contains no real account
    /// data.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIUa/5mCrPYf855/Ob4AvhLmbKnZwAwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLcHJvdG9uLXRlc3QwHhcNMjYwODE4MTAxNDA4WhcNMzYw
ODE1MTAxNDA4WjAWMRQwEgYDVQQDDAtwcm90b24tdGVzdDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAJ7s1rNtRRsqNoiIt9ov2P+J0sy8Cl68Y1YmM7lG
aQZ7rqajQqBlF0HSEv2OTF5biPHb9aaTxeZoPeoull7qWPbQwmqXxLSWu0Swtxga
KWXclWrXlh3zPsoVcTZDarhHk0oTs4v9fXkuctacNB/sHm0Auv8DshAJLXNYpoWH
peaUzDsd5/jT375E7RRkCeInov7c7hso5JyMxY7U8EFawUexObbe6Q5WELpTcIFz
rino9srIz6+bhx5cIltluPXoTH279Lmr9q1sXTedwMbtrErJxZrAiP/JmsPeaNvc
JUxwSt6lvgMAJZSWT8vQKMbEuwLYYzrMrKtn5c0sJrPDW+MCAwEAAaNkMGIwHQYD
VR0OBBYEFABogFWxB2xkPbxu9+mJPG9uTIqKMB8GA1UdIwQYMBaAFABogFWxB2xk
Pbxu9+mJPG9uTIqKMA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0RBAgwBocECgIABTAN
BgkqhkiG9w0BAQsFAAOCAQEAVgl0pqpn0wfdxBC/m07PA8+ngXXN4eLHypQYePSF
QsEiyu8ZfSPy2CRaIa/660Z9cMcwxaMABesO4Cu0R0GEvuSQSE5ZCSfiAQqmb/nw
/OGp7+4zfDqbaaxuZSoozAgj1VoOCp1OCUWxfcdvoXwqUbwslS+BrdymNOdr1d7y
TJcG6MxOvCjdoIEyDVsXmOFhqEtpvte7jRvPncz8DdG1n4ukl5cdVvuAzY4jHP8j
rxA/XsUNPp08PNpGI34w1X7prwi/VLkAkGEeY1wNufP1/IVXW+ahOfNvcGLJQJVf
eRd1dKRVcDggq2K+vBNH5fXpGufy8FPBsFFnA5ZDGFrqpg==
-----END CERTIFICATE-----";

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
            ips: vec!["203.0.113.9".into()],
            status: 1,
            wg_public_key: "SERVERPUBKEYBASE64==".into(),
        }
    }

    fn test_creds() -> crate::models::VPNCredentials {
        crate::models::VPNCredentials {
            username: "testuser".into(),
            password: "unused-in-wg-config".into(),
            certificate: TEST_CERT_PEM.into(),
            wg_public_key: "CLIENTPUBKEYBASE64==".into(),
            wg_private_key: "CLIENTPRIVKEYBASE64==".into(),
        }
    }

    /// Builds a `ProtonVPNClient` pre-populated with a fake server list + credentials, without
    /// any network call (`ProtonVPNClient`'s fields are all `pub`, so this bypasses `login()`/
    /// `fetch_servers()` entirely — the same trick Task 02/03's own tests use for the DTOs).
    fn fake_logged_in_client(location: &str) -> ProtonVPNClient {
        let mut client = ProtonVPNClient::new("test-user");
        client.vpn_credentials = Some(test_creds());
        client.server_list = vec![test_server(location)];
        client
    }

    /// Like `scratch_manager`, but lets the caller keep hold of the `Arc<FakeDriver>` (rather
    /// than a type-erased `Arc<dyn TunnelDriver>`) so it can inspect recorded calls / flip
    /// `fail_down` / mark interfaces `already_down` after building the manager.
    fn scratch_manager_with_driver(base_port: u16, driver: Arc<FakeDriver>) -> TunnelManager {
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: see the note in `manager_start_stop_tracks_state` above.
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        // Leak the tempdir so it outlives the test (it's process-local scratch space cleaned
        // up when the test process exits; nothing else depends on it being removed sooner).
        std::mem::forget(tmp);
        TunnelManager::with_driver(base_port, driver)
    }

    fn scratch_manager(base_port: u16) -> TunnelManager {
        scratch_manager_with_driver(base_port, Arc::new(FakeDriver::default()))
    }

    /// Drives `start()`'s real new-tunnel path (not just the idempotent short-circuit
    /// `manager_start_stop_tracks_state` exercises): a logged-in (faked) client selects a
    /// server, `wg_up`/`spawn_socks5` are faked via `FakeDriver`, and the tunnel ends up
    /// tracked with a deterministic port.
    #[tokio::test]
    async fn manager_start_drives_new_tunnel_path() {
        let _env_guard = ENV_LOCK.lock().await;
        let manager = scratch_manager(12000);
        *manager.client.lock().await = Some(fake_logged_in_client("US"));

        let port = manager.start("US").await.unwrap();
        assert_eq!(port, 12000, "first location gets socks_base_port + 0");

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

    /// Reproduces the double-start race the review flagged: two concurrent `start()` calls for
    /// a location that isn't tracked yet (e.g. a double-clicked "Start" button) must not both
    /// bring the tunnel up / both write `credentials::set_active` rows — the per-location lock
    /// in `location_lock` must serialize them so exactly one `TunnelHandle` and one persisted
    /// `active_tunnels` row result, both agreeing on the same port.
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

        // Exactly one tracked tunnel, and the persisted store agrees with the in-memory map on
        // which port won — this is the specific desync the review flagged (`set_active` being
        // called unconditionally by both racers, independent of which racer's in-memory
        // `TunnelHandle` ended up tracked).
        let snapshot = manager.tunnels();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].socks_port, port_a);

        let active = credentials::list_active().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].socks_port, port_a);
    }

    /// Finding #2: if `wg_down` fails, `stop()` must leave the tunnel tracked (not orphan it)
    /// and propagate the error, rather than removing the in-memory/persisted state first and
    /// then discovering teardown failed.
    #[tokio::test]
    async fn manager_stop_leaves_tunnel_tracked_when_wg_down_fails() {
        let _env_guard = ENV_LOCK.lock().await;
        let driver = Arc::new(FakeDriver::default());
        driver.fail_down.store(true, Ordering::SeqCst);
        let manager = scratch_manager_with_driver(14000, driver.clone());

        // Bypass start()'s network/login path (same technique as
        // `manager_start_stop_tracks_state`): insert a tunnel directly.
        let task = manager.driver.spawn_socks5(
            "127.0.0.1:14000".to_string(),
            wireguard::interface_name("US"),
        );
        manager.tunnels.lock().unwrap().insert(
            "US".to_string(),
            TunnelHandle {
                interface: wireguard::interface_name("US"),
                socks_port: 14000,
                task,
            },
        );
        credentials::set_active("US", &wireguard::interface_name("US"), 14000).unwrap();

        // wg_down fails -> stop() must error, and the tunnel must still be tracked/persisted.
        assert!(manager.stop("US").await.is_err());
        assert_eq!(
            manager.tunnels().len(),
            1,
            "tunnel must stay tracked after a failed teardown"
        );
        assert_eq!(
            credentials::list_active().unwrap().len(),
            1,
            "active_tunnels row must stay persisted after a failed teardown"
        );

        // Retrying after the underlying failure clears must succeed and actually tear down.
        driver.fail_down.store(false, Ordering::SeqCst);
        manager.stop("US").await.unwrap();
        assert!(manager.tunnels().is_empty());
        assert!(credentials::list_active().unwrap().is_empty());
    }

    /// Finding #2: `stop()` must be idempotent against an interface that's already down (e.g.
    /// torn down externally) — it should treat that as a no-op success (never calling
    /// `wg_down`) rather than erroring, and still clear tracked/persisted state.
    #[tokio::test]
    async fn manager_stop_is_idempotent_when_interface_already_down() {
        let _env_guard = ENV_LOCK.lock().await;
        let driver = Arc::new(FakeDriver::default());
        let iface = wireguard::interface_name("US");
        driver.already_down.lock().unwrap().insert(iface.clone());
        let manager = scratch_manager_with_driver(14100, driver.clone());

        let task = manager
            .driver
            .spawn_socks5("127.0.0.1:14100".to_string(), iface.clone());
        manager.tunnels.lock().unwrap().insert(
            "US".to_string(),
            TunnelHandle {
                interface: iface.clone(),
                socks_port: 14100,
                task,
            },
        );
        credentials::set_active("US", &iface, 14100).unwrap();

        manager.stop("US").await.unwrap();

        assert!(
            driver.down_calls.lock().unwrap().is_empty(),
            "wg_down must not be called for an already-down interface"
        );
        assert!(manager.tunnels().is_empty());
        assert!(credentials::list_active().unwrap().is_empty());
    }

    /// Finding #4: if the post-`wg_up` step (`credentials::set_active`) fails, `start()` must
    /// best-effort bring the interface back down rather than leaking it with nothing
    /// tracked/persisted for it.
    #[tokio::test]
    async fn manager_start_cleans_up_interface_on_set_active_failure() {
        let _env_guard = ENV_LOCK.lock().await;
        let driver = Arc::new(FakeDriver::default());
        let manager = scratch_manager_with_driver(14200, driver.clone());
        *manager.client.lock().await = Some(fake_logged_in_client("US"));

        // Force the DB file into existence, then make it read-only so the `set_active` call
        // inside `start()` fails with a permissions error, simulating "disk full/DB
        // locked/permissions" from the finding.
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
            driver.up_calls.lock().unwrap().as_slice(),
            [wireguard::interface_name("US")],
            "wg_up must have been called once before the failure"
        );
        assert_eq!(
            driver.down_calls.lock().unwrap().as_slice(),
            [wireguard::interface_name("US")],
            "best-effort cleanup must have called wg_down for the interface wg_up brought up"
        );
    }

    /// Finding #5: `"us"` and `"US"` must resolve to the same tracked entry / the same
    /// WireGuard interface, closing the idempotence bug where two distinct casings of the same
    /// location were tracked as two distinct entries under two distinct per-location locks.
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
        assert_eq!(snapshot[0].interface, wireguard::interface_name("US"));

        // stop() with the other casing must find and tear down the same entry.
        manager.stop("us").await.unwrap();
        assert!(manager.tunnels().is_empty());
    }

    /// Finding #5: an invalid location must be rejected before it ever reaches
    /// `wireguard::interface_name`/`wireguard::config_path` — proven here by asserting the
    /// driver's `wg_up` was never called for a path-traversal-shaped value.
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
            driver.up_calls.lock().unwrap().is_empty(),
            "an invalid location must never reach wg_up"
        );
        assert!(manager.tunnels().is_empty());
    }
}
