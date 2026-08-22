//! Simultaneous-connection cap (Proton's `MaxConnect`), split out of the old monolithic
//! `manager.rs` — see that module's history.
use super::slot::ServerSlot;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Caps how many servers can have a live WireGuard tunnel at the same time, matching Proton's
/// per-account `MaxConnect` limit. Without this, gratis's "any number of servers at once"
/// design has no relationship to what the account is actually allowed to run simultaneously —
/// on a free-tier account (`MaxConnect: 1` in Proton's ToS, `2` observed live) that's a clean
/// simultaneous-connections violation, not just a theoretical one. `None` bypasses the cap
/// entirely (`gratis up --unlimited-connections`) — a deliberate, opt-in choice the user makes
/// knowingly, not the default.
pub(crate) struct ConnectionLimiter {
    pub(crate) max: Option<u32>,
    pub(crate) current: AtomicU32,
    /// Opt-in (`gratis up --evict-lru`): when the cap is reached, evict the least-recently-used
    /// *idle* connected slot instead of rejecting the new connection. Every slot from one login
    /// registers itself here (see `register`) so eviction can scan across all of them.
    pub(crate) evict_lru: bool,
    /// Lock-ordering contract: `evict_least_recently_used` holds this lock for the *entire*
    /// duration of the victim's `slot.evict()` call, not just the scan. That's what lets two
    /// concurrent `try_acquire` callers avoid double-evicting the same victim (the second
    /// caller re-locks `slots`, sees the victim's `tunnel` is now `None`, and picks a
    /// different/no victim) and lets `evict()` safely bump `idle_generation` before any other
    /// caller can observe a half-evicted slot. Do not call back into `TunnelManager` (which
    /// locks `manager.slots`) from inside code that holds this lock — the crate-wide ordering
    /// is `manager.slots -> limiter.slots`, never the reverse, and reversing it would deadlock.
    slots: Mutex<Vec<Weak<ServerSlot>>>,
}

impl ConnectionLimiter {
    pub(crate) fn new(max: Option<u32>, evict_lru: bool) -> Self {
        Self {
            max,
            current: AtomicU32::new(0),
            evict_lru,
            slots: Mutex::new(Vec::new()),
        }
    }

    /// Register a slot as an eviction candidate. Only needed when `evict_lru` is set, but
    /// harmless to call unconditionally — an unused registry is never scanned.
    pub(crate) fn register(&self, slot: &Arc<ServerSlot>) {
        self.slots.lock().unwrap().push(Arc::downgrade(slot));
    }

    /// Reserve one connection slot. If at capacity and `evict_lru` is set, first tears down
    /// the least-recently-used *idle* (zero open connections) connected slot to make room —
    /// never one with active traffic, so this can never interrupt an in-progress transfer.
    /// Returns `false` (reserving nothing) if still at capacity after that — either eviction is
    /// off, or every connected slot is actively busy; always succeeds if `max` is `None`.
    pub(crate) fn try_acquire(&self) -> bool {
        let Some(max) = self.max else {
            self.current.fetch_add(1, Ordering::SeqCst);
            return true;
        };
        loop {
            let cur = self.current.load(Ordering::SeqCst);
            if cur < max {
                if self
                    .current
                    .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    return true;
                }
                continue;
            }
            if !self.evict_lru || !self.evict_least_recently_used() {
                return false;
            }
            // `evict_least_recently_used` already called `release()` for the victim it tore
            // down — loop back around to reserve the slot it just freed.
        }
    }

    /// Tear down the connected slot that's been idle (zero open connections) the longest,
    /// chosen by the earliest `idle_deadline` — that's already exactly "been idle since the
    /// longest ago" (see `ServerSlot::release`), so no separate last-used timestamp is needed.
    /// Returns `false` if no idle connected slot exists (every connected slot has active
    /// traffic) — eviction never touches those.
    fn evict_least_recently_used(&self) -> bool {
        let victim = self
            .slots
            .lock()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|s| {
                s.tunnel.lock().unwrap().is_some() && s.open_connections.load(Ordering::SeqCst) == 0
            })
            .min_by_key(|s| *s.idle_deadline.lock().unwrap());

        match victim {
            Some(slot) => {
                slot.evict();
                true
            }
            None => false,
        }
    }

    /// Release a slot reserved by a successful `try_acquire` — call exactly once per tunnel
    /// that goes from connected back to disconnected (a failed connect attempt that never
    /// actually reserved doesn't call this; see the call sites in `ServerSlot`).
    ///
    /// Guards against underflow the same way `ServerSlot::release` does: an unbalanced call
    /// here would otherwise wrap `current` to `u32::MAX` and permanently (silently) disable
    /// the account's `MaxConnect` cap instead of just under-counting by one.
    pub(crate) fn release(&self) {
        let prev = self.current.fetch_sub(1, Ordering::SeqCst);
        if prev == 0 {
            self.current.fetch_add(1, Ordering::SeqCst);
            log::warn!(
                "ConnectionLimiter::release called with current already at 0 — ignoring an \
                 unbalanced release instead of corrupting the cap counter"
            );
        }
    }
}
