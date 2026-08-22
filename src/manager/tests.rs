//! Tests for the whole `manager` module — `TunnelManager`/`ConnectionLimiter`/`ServerSlot`
//! together, since most behavior here (acquire/release/eviction/refresh) spans more than one of
//! them. Kept as one file rather than split per-submodule so the fake-driver test harness below
//! stays in one place.
use super::slot::{CONNECT_RETRY_BUDGET, IDLE_TIMEOUT};
use super::*;
use crate::socks5::TunnelSource;
use crate::wireguard::{SharedTunnel, Tunnel, TunnelStats};
use async_trait::async_trait;
use std::time::Instant;
use tokio::task::JoinHandle;

#[test]
fn auth_error_starts_clear_and_reflects_the_last_set_call() {
    let manager = TunnelManager::new(20000, false, false, ProxyProtocol::default());
    assert_eq!(manager.auth_error(), None);

    manager.set_auth_error(Some("stored session is no longer valid".to_string()));
    assert_eq!(
        manager.auth_error(),
        Some("stored session is no longer valid".to_string())
    );

    // A later success must clear it — `gratis status`'s "logged in: yes" bug was exactly
    // this: nothing ever cleared a stale problem, so it read from a static file instead of
    // live daemon state.
    manager.set_auth_error(None);
    assert_eq!(manager.auth_error(), None);
}

/// Records `connect_tunnel` calls (no real WireGuard/network) and spawns an inert task
/// instead of a real SOCKS5 listener, so `TunnelManager` bookkeeping can be tested without
/// root or network access.
#[derive(Default)]
struct FakeDriver {
    connect_calls: Mutex<Vec<String>>,
    /// Records each `connect_tunnel` call's `wg_public_key` — lets a test observe which
    /// credentials a slot actually used to connect (e.g. to confirm `update_creds` took
    /// effect on the next connection rather than only updating in-memory state unused).
    creds_used: Mutex<Vec<String>>,
}

#[async_trait]
impl TunnelDriver for FakeDriver {
    async fn connect_tunnel(
        &self,
        server: &VPNServer,
        creds: &VPNCredentials,
    ) -> Result<SharedTunnel> {
        self.connect_calls
            .lock()
            .unwrap()
            .push(server.country_code.clone());
        self.creds_used
            .lock()
            .unwrap()
            .push(creds.wg_public_key.clone());
        Ok(Arc::new(Tunnel::loopback_for_testing()))
    }

    fn spawn_listener(
        &self,
        _listen_addr: String,
        _source: Arc<dyn TunnelSource>,
        _stats: Arc<TunnelStats>,
        _protocol: ProxyProtocol,
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

    fn spawn_listener(
        &self,
        _listen_addr: String,
        _source: Arc<dyn TunnelSource>,
        _stats: Arc<TunnelStats>,
        _protocol: ProxyProtocol,
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

    fn spawn_listener(
        &self,
        _listen_addr: String,
        _source: Arc<dyn TunnelSource>,
        _stats: Arc<TunnelStats>,
        _protocol: ProxyProtocol,
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

    fn spawn_listener(
        &self,
        _listen_addr: String,
        _source: Arc<dyn TunnelSource>,
        _stats: Arc<TunnelStats>,
        _protocol: ProxyProtocol,
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

    fn spawn_listener(
        &self,
        _listen_addr: String,
        _source: Arc<dyn TunnelSource>,
        _stats: Arc<TunnelStats>,
        _protocol: ProxyProtocol,
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
    let manager = Arc::new(TunnelManager::with_driver(
        port,
        driver.clone(),
        false,
        false,
        ProxyProtocol::default(),
    ));
    let limiter = Arc::new(ConnectionLimiter::new(None, false));
    let slot = ServerSlot::new(
        test_server("srv-1", "US"),
        test_creds(),
        driver,
        port,
        limiter.clone(),
    );
    limiter.register(&slot);
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

#[test]
fn server_slot_release_with_no_matching_acquire_does_not_underflow() {
    let (_manager, slot) = manager_with_one_slot(20051);
    assert_eq!(slot.open_connections.load(Ordering::SeqCst), 0);

    // No `acquire` happened — this must be a contained no-op, not wrap to u32::MAX.
    slot.release();
    assert_eq!(
        slot.open_connections.load(Ordering::SeqCst),
        0,
        "an unbalanced release must not corrupt the connection counter"
    );
}

#[test]
fn connection_limiter_release_with_no_matching_acquire_does_not_underflow() {
    let limiter = ConnectionLimiter::new(Some(1), false);
    assert_eq!(limiter.current.load(Ordering::SeqCst), 0);

    limiter.release();
    assert_eq!(
        limiter.current.load(Ordering::SeqCst),
        0,
        "an unbalanced release must not corrupt the MaxConnect cap counter"
    );
    // The cap must still work correctly afterwards — not saturated at u32::MAX.
    assert!(limiter.try_acquire());
}

#[tokio::test]
async fn update_creds_takes_effect_on_the_next_connect() {
    let driver = Arc::new(FakeDriver::default());
    let (_manager, slot) = slot_with_driver(20050, driver.clone());

    slot.connect_with_retry().await.unwrap();
    let mut new_creds = test_creds();
    new_creds.wg_public_key = "RENEWEDPUBKEYBASE64==".into();
    slot.update_creds(new_creds);
    slot.connect_with_retry().await.unwrap();

    // `renew_credentials` (main.rs's periodic loop) must reach every existing slot's live
    // creds, not just `TunnelManager`'s own copy used for slots created later — assert the
    // second connect actually used the renewed public key, not the original one.
    let used = driver.creds_used.lock().unwrap();
    assert_eq!(
        used.as_slice(),
        ["CLIENTPUBKEYBASE64==", "RENEWEDPUBKEYBASE64=="]
    );
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
fn two_slots_with_limiter(max: Option<u32>, evict_lru: bool) -> (Arc<ServerSlot>, Arc<ServerSlot>) {
    let driver: Arc<dyn TunnelDriver> = Arc::new(FakeDriver::default());
    let limiter = Arc::new(ConnectionLimiter::new(max, evict_lru));
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
        limiter.clone(),
    );
    limiter.register(&a);
    limiter.register(&b);
    (a, b)
}

#[tokio::test]
async fn acquire_is_rejected_once_the_connection_cap_is_reached() {
    let (a, b) = two_slots_with_limiter(Some(1), false);

    assert!(a.acquire().await.is_ok(), "first tunnel is within the cap");
    let result = b.acquire().await;
    let Err(err) = result else {
        panic!(
            "a second simultaneous tunnel must be rejected once the account's MaxConnect \
             cap (here: 1) is already in use by a different server"
        );
    };
    assert!(
        matches!(
            err.downcast_ref::<ProtonError>(),
            Some(ProtonError::AtCapacity(_))
        ),
        "must be the AtCapacity variant specifically — socks5.rs relies on it to reply \
         with a distinct SOCKS5 code (see socks5.rs's reply_code_for)"
    );

    // Rejection must not have counted against `open_connections` (see the fetch_sub next
    // to the rejection in `acquire`) — otherwise a rejected caller would still show as
    // "connected" in `servers()`.
    assert_eq!(b.status().open_connections, 0);
    assert!(!b.status().connected);
}

#[tokio::test]
async fn acquire_succeeds_again_after_a_capped_slot_releases() {
    let (a, b) = two_slots_with_limiter(Some(1), false);

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
    let (a, b) = two_slots_with_limiter(None, false);

    assert!(a.acquire().await.is_ok());
    assert!(
        b.acquire().await.is_ok(),
        "a `None` limiter (--unlimited-connections) must never reject a connect"
    );
}

#[tokio::test]
async fn acquire_reusing_an_already_connected_tunnel_does_not_recount_against_the_cap() {
    let (a, _b) = two_slots_with_limiter(Some(1), false);

    a.acquire().await.unwrap();
    // A second caller reusing the same already-connected tunnel must not need (or
    // consume) a second reservation — only a genuinely new tunnel does.
    assert!(a.acquire().await.is_ok());
}

#[tokio::test]
async fn evict_lru_disconnects_an_idle_slot_to_make_room_for_a_new_one() {
    let (a, b) = two_slots_with_limiter(Some(1), true);

    a.acquire().await.unwrap();
    a.release(); // a is now connected but idle (zero open connections).

    assert!(
        b.acquire().await.is_ok(),
        "b must succeed by evicting the idle a, not be rejected"
    );
    assert!(
        !a.status().connected,
        "evicting a must have torn its tunnel down"
    );
    assert!(b.status().connected);
}

#[tokio::test]
async fn evict_lru_never_evicts_a_slot_with_active_connections() {
    let (a, b) = two_slots_with_limiter(Some(1), true);

    // a stays "acquired" — open_connections is 1, standing in for an active transfer.
    a.acquire().await.unwrap();

    let result = b.acquire().await;
    assert!(
        result.is_err(),
        "with no idle slot to evict (a has active traffic), b must be rejected — eviction \
         must never interrupt an in-progress connection"
    );
    assert!(a.status().connected, "a must be untouched");
}

#[tokio::test]
async fn evict_lru_picks_the_longest_idle_slot_when_several_are_idle() {
    let driver: Arc<dyn TunnelDriver> = Arc::new(FakeDriver::default());
    let limiter = Arc::new(ConnectionLimiter::new(Some(2), true));
    let oldest = ServerSlot::new(
        test_server("srv-old", "US"),
        test_creds(),
        driver.clone(),
        20900,
        limiter.clone(),
    );
    let newest = ServerSlot::new(
        test_server("srv-new", "FR"),
        test_creds(),
        driver.clone(),
        20901,
        limiter.clone(),
    );
    let incoming = ServerSlot::new(
        test_server("srv-in", "DE"),
        test_creds(),
        driver,
        20902,
        limiter.clone(),
    );
    limiter.register(&oldest);
    limiter.register(&newest);
    limiter.register(&incoming);

    // `oldest` goes idle first, so its idle_deadline is earlier — it must be the one
    // evicted, not `newest`, even though both are idle candidates.
    oldest.acquire().await.unwrap();
    oldest.release();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    newest.acquire().await.unwrap();
    newest.release();

    assert!(incoming.acquire().await.is_ok());
    assert!(
        !oldest.status().connected,
        "the longer-idle slot must be evicted"
    );
    assert!(
        newest.status().connected,
        "the more-recently-idle slot must survive"
    );
}

fn test_server_tier(id: &str, location: &str, tier: i32) -> VPNServer {
    VPNServer {
        tier,
        ..test_server(id, location)
    }
}

/// Builds a `TunnelManager` as if `finish_login` had already run — populates `max_tier`/
/// `creds`/`limiter` directly (bypassing the real login/network path) and applies
/// `initial_servers` via `apply_refreshed_servers`, exactly like `finish_login` does — so
/// tests can exercise `apply_refreshed_servers` (the refresh reconciliation logic) and
/// `refresh_servers`'s effects directly and in isolation.
fn manager_after_login(
    port_range_start: u16,
    initial_servers: Vec<VPNServer>,
    max_tier: i32,
    evict_lru: bool,
) -> Arc<TunnelManager> {
    let manager = Arc::new(TunnelManager::with_driver(
        port_range_start,
        Arc::new(FakeDriver::default()),
        false,
        evict_lru,
        ProxyProtocol::default(),
    ));
    *manager.max_tier.lock().unwrap() = max_tier;
    *manager.creds.lock().unwrap() = Some(test_creds());
    *manager.limiter.lock().unwrap() = Some(Arc::new(ConnectionLimiter::new(None, evict_lru)));
    manager.apply_refreshed_servers(initial_servers).unwrap();
    manager
}

fn find_status(manager: &TunnelManager, id: &str) -> ServerStatus {
    manager
        .servers()
        .into_iter()
        .find(|s| s.name.starts_with(id) || s.name == format!("{id}-FREE#1"))
        .unwrap_or_else(|| panic!("no server named like {id} in servers()"))
}

#[tokio::test]
async fn refresh_keeps_the_same_port_and_updates_live_metadata() {
    let manager = manager_after_login(30000, vec![test_server("A", "US")], 0, false);
    let original_port = manager.servers()[0].port;

    let mut updated = test_server("A", "US");
    updated.load = 77.0;
    manager.apply_refreshed_servers(vec![updated]).unwrap();

    let status = manager.servers();
    assert_eq!(
        status.len(),
        1,
        "must not create a duplicate slot for the same ID"
    );
    assert_eq!(
        status[0].port, original_port,
        "port must never change for an existing server"
    );
    assert_eq!(
        status[0].load, 77.0,
        "load must reflect the refreshed value"
    );
    assert!(!status[0].removed);
}

#[tokio::test]
async fn refresh_assigns_a_new_port_to_a_genuinely_new_server() {
    let manager = manager_after_login(30000, vec![test_server("A", "US")], 0, false);
    let port_a = manager.servers()[0].port;

    manager
        .apply_refreshed_servers(vec![test_server("A", "US"), test_server("B", "FR")])
        .unwrap();

    let statuses = manager.servers();
    assert_eq!(statuses.len(), 2);
    let a = statuses.iter().find(|s| s.port == port_a).unwrap();
    let b = statuses.iter().find(|s| s.port != port_a).unwrap();
    assert_eq!(a.country_code, "US");
    assert_eq!(b.country_code, "FR");
    assert_ne!(
        b.port, port_a,
        "the new server must get its own, different port"
    );
}

#[tokio::test]
async fn refresh_marks_a_disappeared_server_removed_but_keeps_its_port_and_slot() {
    let manager = manager_after_login(
        30000,
        vec![test_server("A", "US"), test_server("B", "FR")],
        0,
        false,
    );
    let before = manager.servers();
    assert_eq!(before.len(), 2);

    // B no longer comes back from Proton.
    manager
        .apply_refreshed_servers(vec![test_server("A", "US")])
        .unwrap();

    let after = manager.servers();
    assert_eq!(
        after.len(),
        2,
        "the disappeared server's slot/port must still exist, just marked removed"
    );
    let a = after.iter().find(|s| s.country_code == "US").unwrap();
    let b = after.iter().find(|s| s.country_code == "FR").unwrap();
    assert!(!a.removed);
    assert!(b.removed);
}

#[tokio::test]
async fn removed_server_rejects_new_connections_even_though_the_driver_would_succeed() {
    let manager = manager_after_login(30000, vec![test_server("A", "US")], 0, false);
    let slot = manager.slots.lock().unwrap()[0].clone();

    manager.apply_refreshed_servers(vec![]).unwrap();
    assert!(find_status(&manager, "US").removed);

    let result = slot.acquire().await;
    assert!(
        result.is_err(),
        "a removed server must reject new connections outright, even with a driver that \
         would otherwise succeed instantly"
    );
}

#[tokio::test]
async fn refresh_unmarks_removed_when_a_server_reappears_with_the_same_port() {
    let manager = manager_after_login(30000, vec![test_server("A", "US")], 0, false);
    let original_port = manager.servers()[0].port;

    manager.apply_refreshed_servers(vec![]).unwrap();
    assert!(manager.servers()[0].removed);

    manager
        .apply_refreshed_servers(vec![test_server("A", "US")])
        .unwrap();

    let status = manager.servers();
    assert_eq!(status.len(), 1, "reappearing must not create a second slot");
    assert!(!status[0].removed);
    assert_eq!(
        status[0].port, original_port,
        "a reappeared server must get back its original port, not a new one"
    );
}

#[tokio::test]
async fn refresh_applies_the_tier_filter_same_as_initial_login() {
    // max_tier is 0 (free) — a tier-2 server in the fetched list must be excluded exactly
    // like at initial login, not just let through because it's a "refresh."
    let manager = manager_after_login(30000, vec![test_server_tier("A", "US", 0)], 0, false);

    manager
        .apply_refreshed_servers(vec![
            test_server_tier("A", "US", 0),
            test_server_tier("B", "FR", 2),
        ])
        .unwrap();

    let statuses = manager.servers();
    assert_eq!(
        statuses.len(),
        1,
        "a server above the account's tier must never get a slot, refresh or not"
    );
    assert_eq!(statuses[0].country_code, "US");
}

#[tokio::test]
async fn refresh_does_not_touch_an_existing_slots_open_connection_state() {
    // Sanity check that apply_refreshed_servers only ever writes `server`/`removed` —
    // never open_connections/tunnel/idle bookkeeping for a server that's still present.
    let manager = manager_after_login(30000, vec![test_server("A", "US")], 0, false);
    let slot = manager.slots.lock().unwrap()[0].clone();

    let mut updated = test_server("A", "US");
    updated.load = 99.0;
    manager.apply_refreshed_servers(vec![updated]).unwrap();

    assert_eq!(slot.open_connections.load(Ordering::SeqCst), 0);
    assert!(slot.tunnel.lock().unwrap().is_none());
}
