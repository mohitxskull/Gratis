//! WireGuard config generation and `wg-quick` up/down control.
//!
//! Correctness reference for the config shape: <https://github.com/ProtonVPN/proton-vpn-cli>
use crate::errors::*;
use crate::models::{VPNCredentials, VPNServer};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;

/// Standard Proton WireGuard UDP port.
pub const WG_PORT: u16 = 51820;

/// Fixed, location-derived interface name so `disconnect`/`status` and the daemon work
/// across process invocations (Flagged gap #4), even across separate CLI invocations that
/// don't share in-memory state.
pub fn interface_name(location: &str) -> String {
    format!("proton-{}", location.to_ascii_lowercase())
}

/// Generate a WireGuard `[Interface]`/`[Peer]` config.
///
/// Correctness notes (Flagged gaps vs the old Python stub):
/// - `Peer.PublicKey` must be the server's WireGuard public key (`server.wg_public_key`),
///   NEVER `ips[0]` (that is the server IP).
/// - `Interface.Address` is `client_address`, derived by the caller from the account
///   certificate (see `models::client_address_from_certificate`), not hardcoded.
/// - `Table = off`: this is a split tunnel. `wg-quick`'s `add_route` early-returns when
///   `Table = off`, so no default route is installed; only proxy-bound sockets use the
///   tunnel (Task 04/05).
/// - `Endpoint` host is `ips[0]`, port `51820`.
pub fn generate_config(
    server: &VPNServer,
    creds: &VPNCredentials,
    client_address: &str,
    interface: &str,
) -> String {
    // `interface` is not embedded in the config body (wg-quick derives the interface name
    // from the config file's name/path), but is accepted here so callers have a single
    // place to thread the interface name through to `up`/`down`/`set_active`.
    let _ = interface;
    format!(
        "[Interface]\nPrivateKey = {pk}\nAddress = {addr}/32\nTable = off\n\n\
         [Peer]\nPublicKey = {peer}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {ip}:{port}\n",
        pk = creds.wg_private_key,
        addr = client_address,
        peer = server.wg_public_key,
        ip = server.ips.first().map(String::as_str).unwrap_or(""),
        port = WG_PORT,
    )
}

/// Bring the tunnel up: write `config` to a temp file named after `interface` and run
/// `sudo wg-quick up <tempfile>`.
///
/// This function only drives `wg-quick`; it does not touch persisted state. Recording the
/// active tunnel (location/interface/socks_port) is the caller's responsibility via
/// `credentials::set_active`, since this layer has no `location`/`socks_port` to record —
/// those are only known one layer up (the connect flow in Task 05).
///
/// Security: the config embeds the client's WireGuard private key, and the temp path
/// (`<tmp>/<interface>.conf`) is predictable in a world-writable directory. The file is
/// created with `O_CREAT | O_EXCL` and mode `0600` in a single syscall (`OpenOptions` with
/// `create_new(true)` + `mode(0o600)`), so there is never a window where the file exists
/// world-readable, and a pre-placed file/symlink at that path makes `open` fail instead of
/// being silently written through or followed (no TOCTOU between "create" and "chmod", and
/// no race between "write" and `wg-quick`'s read — the content is fully written, with
/// owner-only permissions already in force, before `wg-quick` is ever invoked). The file is
/// removed again once `wg-quick` has run, whether it succeeded or failed, so the private key
/// doesn't linger on disk.
pub fn up(interface: &str, config: &str) -> Result<()> {
    let path = std::env::temp_dir().join(format!("{interface}.conf"));

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(ProtonError::Io)?;
    file.write_all(config.as_bytes()).map_err(ProtonError::Io)?;
    file.sync_all().map_err(ProtonError::Io)?;
    drop(file);

    let run = || -> Result<()> {
        let status = Command::new("sudo")
            .arg("wg-quick")
            .arg("up")
            .arg(&path)
            .status()
            .map_err(ProtonError::Io)?;

        if !status.success() {
            return Err(ProtonError::Config(format!(
                "wg-quick up {} failed with status {status}",
                path.display()
            )));
        }
        Ok(())
    };
    let result = run();

    // Always clean up: the file contains the client's private key, whether `wg-quick`
    // succeeded or failed.
    let _ = std::fs::remove_file(&path);

    result
}

/// Tear the tunnel down: `sudo wg-quick down <interface>`.
///
/// Does not touch persisted state; the caller clears the `active_tunnels` row via
/// `credentials::clear_active` after this returns `Ok`.
pub fn down(interface: &str) -> Result<()> {
    let status = Command::new("sudo")
        .arg("wg-quick")
        .arg("down")
        .arg(interface)
        .status()
        .map_err(ProtonError::Io)?;

    if !status.success() {
        return Err(ProtonError::Config(format!(
            "wg-quick down {interface} failed with status {status}"
        )));
    }

    Ok(())
}

/// Check whether `interface` currently has a live WireGuard device (via `wg show
/// <interface>`, which exits non-zero if the interface doesn't exist).
pub fn is_up(interface: &str) -> bool {
    Command::new("wg")
        .arg("show")
        .arg(interface)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
