//! Error types for the Proton VPN client.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtonError {
    #[error("API error: {0}")]
    Api(String),

    #[error("authentication failed")]
    Auth,

    /// The account has two-factor authentication enabled and `/auth` succeeded but returned
    /// the `"twofactor"` scope — the caller must collect a TOTP code and call
    /// `ProtonVPNClient::submit_2fa` before anything else will work.
    #[error("two-factor authentication required")]
    TwoFactorRequired,

    #[error("SRP error: {0}")]
    Srp(#[from] proton_srp::SRPError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all for everything that doesn't fit a more specific variant below — mostly
    /// transient connect/retry-budget failures and other runtime state. Deliberately not split
    /// further: this crate isn't large enough for callers to need to `match` on error
    /// *category* for anything but the handful of cases that already have their own variant
    /// (`Auth`, `AtCapacity`, `Keychain`, `NoPhysicalServer`, `OutOfPorts`, `BadUnit`) — adding
    /// a distinct variant per failure site would just move the same string text into more enum
    /// arms without giving any caller a new decision to make.
    #[error("config/state error: {0}")]
    Config(String),

    /// OS keychain (Secret Service) read/write/delete failure — `session.rs`. Distinct from
    /// `Config` because "no secret-service daemon running" / "keychain locked" is a specific,
    /// actionable diagnosis (the user's desktop session, not gratis's own state) that's worth
    /// telling apart from generic runtime errors in logs.
    #[error("keychain error: {0}")]
    Keychain(String),

    /// A server has no physical entries to derive a local-agent SNI or WireGuard peer from —
    /// `wireguard.rs`/`manager.rs`. Distinct because it names a specific, checkable precondition
    /// ("this server's data is incomplete") rather than an arbitrary runtime failure.
    #[error("server has no physical entries: {0}")]
    NoPhysicalServer(String),

    /// `TunnelManager::apply_refreshed_servers` ran out of `u16` ports to hand a genuinely new
    /// server (`next_port` overflowed) — a fixed, nameable condition rather than a formatted
    /// runtime message.
    #[error("ran out of ports for the server list")]
    OutOfPorts,

    /// systemd unit-file / installation-path problem — `service.rs` (missing `HOME`, a binary
    /// path that isn't valid UTF-8, or a failed `systemctl --user` invocation). Distinct because
    /// these are all "the installed service is misconfigured" in a way a user could act on
    /// (reinstall, check `$HOME`), unlike a transient connect failure.
    #[error("service/unit error: {0}")]
    BadUnit(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("tunnel error: {0}")]
    Tunnel(#[from] wireguard_netstack::Error),

    /// Failure anywhere in the Proton "local agent" handshake (`agent.rs`) — TLS setup,
    /// the handshake itself, framing, or a reply that reports the session as jailed/restricted.
    /// Always a soft failure from the caller's point of view: `manager.rs` falls back to the
    /// readiness-probe wait rather than failing the connection outright.
    #[error("local agent error: {0}")]
    LocalAgent(String),

    /// `ServerSlot::acquire` rejected a connection because the account's `MaxConnect` cap is
    /// already fully used by *active* tunnels (nothing idle to evict, or `--evict-lru` isn't
    /// on) — not a sign that this particular server/exit is broken. `socks5.rs` checks for
    /// this specific variant to reply with SOCKS5 `CONNECTION REFUSED` (0x05) instead of
    /// `GENERAL FAILURE` (0x01), so a SOCKS5 client (e.g. `zen-relay`) can tell "gratis is at
    /// capacity right now" apart from "this exit doesn't work" instead of treating both
    /// identically — verified live: without this distinction, a capacity-cap rejection (which
    /// clears the moment another connection frees up) was indistinguishable from a genuinely
    /// dead exit, and got a client-side multi-hour ban it didn't deserve.
    #[error("at capacity: {0}")]
    AtCapacity(String),
}

pub type Result<T> = std::result::Result<T, ProtonError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The targeted variants exist so a caller *can* tell these apart from a generic `Config`
    /// (and from each other) — lock that they actually are distinguishable via `matches!`,
    /// not just differently-worded `Config(String)`s.
    #[test]
    fn targeted_variants_are_distinguishable_from_config_and_each_other() {
        let keychain = ProtonError::Keychain("x".into());
        let no_physical = ProtonError::NoPhysicalServer("x".into());
        let out_of_ports = ProtonError::OutOfPorts;
        let bad_unit = ProtonError::BadUnit("x".into());
        let config = ProtonError::Config("x".into());

        assert!(matches!(keychain, ProtonError::Keychain(_)));
        assert!(!matches!(keychain, ProtonError::Config(_)));
        assert!(matches!(no_physical, ProtonError::NoPhysicalServer(_)));
        assert!(matches!(out_of_ports, ProtonError::OutOfPorts));
        assert!(matches!(bad_unit, ProtonError::BadUnit(_)));
        assert!(matches!(config, ProtonError::Config(_)));
    }

    #[test]
    fn out_of_ports_has_a_fixed_message_with_no_formatting_gap() {
        // The only variant with no associated data — confirm `#[error(...)]` doesn't require
        // one (a common thiserror mistake when adding a fieldless variant to an enum where
        // every other arm has one).
        assert_eq!(
            ProtonError::OutOfPorts.to_string(),
            "ran out of ports for the server list"
        );
    }
}
