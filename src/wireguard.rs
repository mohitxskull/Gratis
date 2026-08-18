//! WireGuard config generation and `wg-quick` up/down control.
//!
//! Correctness reference for the config shape: <https://github.com/ProtonVPN/proton-vpn-cli>
use crate::errors::*;
use crate::models::{VPNCredentials, VPNServer};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

/// Standard Proton WireGuard UDP port.
pub const WG_PORT: u16 = 51820;

/// Fixed, location-derived interface name so `disconnect`/`status` and the daemon work
/// across process invocations (Flagged gap #4), even across separate CLI invocations that
/// don't share in-memory state.
pub fn interface_name(location: &str) -> String {
    format!("proton-{}", location.to_ascii_lowercase())
}

/// Fixed client tunnel address Proton's own client uses for every WireGuard connection.
///
/// Verified against `proton.vpn.backend.networkmanager.protocol.wireguard.wireguard`
/// (`wg_config.ipv4.address = "10.2.0.2"`, prefix `/32`): this is NOT derived per-account or
/// per-connection at all. Flagged gap #3's earlier resolution (deriving it from the account
/// certificate's X.509 SAN, `models::client_address_from_certificate`) was a best-effort
/// guess made without a live account and is now confirmed wrong — replaced with this fixed
/// address, which every Proton client uses.
pub const CLIENT_ADDRESS: &str = "10.2.0.2";

/// Generate a WireGuard `[Interface]`/`[Peer]` config.
///
/// Correctness notes (Flagged gaps vs the old Python stub, now verified against a live
/// account and the official client's source):
/// - `Peer.PublicKey` is the specific physical server's `X25519PublicKey`
///   (`server.pick_physical()`), never mixed with a different physical server's entry IP —
///   the root cause of Flagged gap #2 in the old Python.
/// - `Interface.Address` is the fixed `CLIENT_ADDRESS` (see its doc comment) — not derived
///   from anything, and not `10.8.0.1` (the old Python's unrelated wrong guess) either.
/// - `Table = off`: this is a split tunnel. `wg-quick`'s `add_route` early-returns when
///   `Table = off`, so no default route is installed; only proxy-bound sockets use the
///   tunnel (Task 04/05).
/// - `Endpoint` host is the picked physical server's `entry_ip`, port `51820`.
///
/// Returns an error if `server` has no physical server to connect through.
pub fn generate_config(
    server: &VPNServer,
    creds: &VPNCredentials,
    interface: &str,
) -> Result<String> {
    let physical = server.pick_physical().ok_or_else(|| {
        ProtonError::Config(format!("server {} has no physical servers", server.name))
    })?;
    // `interface` is not embedded in the config body (wg-quick derives the interface name
    // from the config file's name/path), but is accepted here so callers have a single
    // place to thread the interface name through to `up`/`down`/`set_active`.
    let _ = interface;
    Ok(format!(
        "[Interface]\nPrivateKey = {pk}\nAddress = {addr}/32\nTable = off\n\n\
         [Peer]\nPublicKey = {peer}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {ip}:{port}\n",
        pk = creds.wg_private_key,
        addr = CLIENT_ADDRESS,
        peer = physical.x25519_public_key,
        ip = physical.entry_ip,
        port = WG_PORT,
    ))
}

/// Directory the daemon owns for WireGuard config files, one per live interface.
///
/// Defaults to `/run/proton-proxy` — root-owned (the daemon shells to `wg-quick` via `sudo`
/// already), tmpfs, and cleared on reboot, which is appropriate: a config file surviving a
/// reboot would be meaningless anyway since the interface itself doesn't survive one. This is
/// *not* `std::env::temp_dir()` (world-writable `/tmp`, and previously deleted right after
/// `up()` returned — see the `down()` doc comment below for why that was the root cause of
/// finding #1: `down` had nothing to pass `wg-quick` but a bare interface name, which
/// `wg-quick` resolves to `/etc/wireguard/<name>.conf`, a path this daemon never wrote to).
///
/// Overridable via `PROTON_PROXY_TUNNEL_DIR` so tests (and any environment where `/run` isn't
/// writable, e.g. non-root `cargo test`) can point this at a tempdir instead.
fn tunnel_config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PROTON_PROXY_TUNNEL_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from("/run/proton-proxy")
}

/// The deterministic config-file path for `interface`. `up()` and `down()` both derive this
/// path from `interface` alone (rather than threading a path through `TunnelHandle`), so they
/// always agree on where the file lives without the manager needing to track it separately.
pub fn config_path(interface: &str) -> PathBuf {
    tunnel_config_dir().join(format!("{interface}.conf"))
}

/// Ensure `tunnel_config_dir()` exists with `0700` permissions (owner rwx only — the config
/// files inside it contain private keys). Best-effort on the `chmod`: if the directory already
/// exists with different permissions (e.g. pre-created by a packaging script), we still try to
/// tighten it, but a failure to do so is not fatal on its own since `up()`'s file creation
/// below still forces `0600` on the file itself.
fn ensure_tunnel_config_dir() -> Result<PathBuf> {
    let dir = tunnel_config_dir();
    std::fs::create_dir_all(&dir).map_err(ProtonError::Io)?;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    Ok(dir)
}

/// Bring the tunnel up: write `config` to `config_path(interface)` and run
/// `sudo wg-quick up <path>`.
///
/// This function only drives `wg-quick`; it does not touch persisted state. Recording the
/// active tunnel (location/interface/socks_port) is the caller's responsibility via
/// `credentials::set_active`, since this layer has no `location`/`socks_port` to record —
/// those are only known one layer up (the connect flow in Task 05).
///
/// Security: the config embeds the client's WireGuard private key. The file is created with
/// `O_CREAT | O_EXCL` and mode `0600` in a single syscall (`OpenOptions` with
/// `create_new(true)` + `mode(0o600)`), so there is never a window where the file exists
/// world-readable, and a pre-placed file/symlink at that path makes `open` fail instead of
/// being silently written through or followed. If a file is already present at that path (a
/// leftover from a previous crashed run — boot reconciliation in `main.rs` is expected to have
/// cleared this in the common case, but we don't rely on that here), it is removed first on a
/// best-effort basis so `create_new` doesn't spuriously fail on stale state; the directory
/// itself is root-owned `0700`, not world-writable, so this doesn't reopen the TOCTOU/symlink
/// risk the original `/tmp`-based implementation had to guard against as its *primary*
/// defense.
///
/// Lifetime: unlike the old implementation (which deleted the file immediately after `up`
/// returned, success or failure), the file is only removed here if `up` itself fails — nothing
/// will call `down()` for an interface that never came up, so there is nothing else to clean
/// it up later. If `up` succeeds, the file is deliberately left in place for the tunnel's
/// entire lifetime so `down()` can pass the same path to `wg-quick down`; `down()` is
/// responsible for removing it once `wg-quick down` has run.
pub fn up(interface: &str, config: &str) -> Result<()> {
    ensure_tunnel_config_dir()?;
    let path = config_path(interface);

    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(ProtonError::Io)?;
    file.write_all(config.as_bytes()).map_err(ProtonError::Io)?;
    file.sync_all().map_err(ProtonError::Io)?;
    drop(file);

    let status = Command::new("sudo")
        .arg("wg-quick")
        .arg("up")
        .arg(&path)
        .status()
        .map_err(ProtonError::Io)?;

    if !status.success() {
        // `up` failed: no interface came up, so no `down()` call will ever follow for it.
        // Clean up now instead of leaving the private key on disk indefinitely.
        let _ = std::fs::remove_file(&path);
        return Err(ProtonError::Config(format!(
            "wg-quick up {} failed with status {status}",
            path.display()
        )));
    }

    Ok(())
}

/// Tear the tunnel down: `sudo wg-quick down <path>`, using the same `config_path(interface)`
/// that `up()` wrote to.
///
/// This is the fix for finding #1: the previous implementation ran `sudo wg-quick down
/// <interface>` with a bare interface name. The real `wg-quick` resolves a bare name (as
/// opposed to a path) to `/etc/wireguard/<name>.conf` for both `up` and `down` — but this
/// daemon never wrote anything there (it wrote to, and then immediately deleted, a file under
/// `std::env::temp_dir()`), so `down` unconditionally failed against a real `wg-quick` binary.
/// Passing the same path to both `up` and `down`, and keeping that file alive for the
/// interface's whole lifetime, is what the plan's own Task 03 text specified.
///
/// Does not touch persisted state; the caller clears the `active_tunnels` row via
/// `credentials::clear_active` after this returns `Ok`. The config file (which holds the
/// client's private key) is removed once `wg-quick down` has run, whether it succeeded or
/// failed — mirroring the "always clean up" discipline `up()` used to apply right after `up`,
/// just moved to after `down` instead.
pub fn down(interface: &str) -> Result<()> {
    let path = config_path(interface);

    let status = Command::new("sudo")
        .arg("wg-quick")
        .arg("down")
        .arg(&path)
        .status()
        .map_err(ProtonError::Io);

    let result = match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(ProtonError::Config(format!(
            "wg-quick down {} failed with status {status}",
            path.display()
        ))),
        Err(err) => Err(err),
    };

    let _ = std::fs::remove_file(&path);

    result
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `PROTON_PROXY_TUNNEL_DIR`/`PATH` are process-global; serialize tests that mutate them so
    /// they never interleave (mirrors the `ENV_LOCK` pattern in `manager.rs`'s test module).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Finding #1's core invariant at the Rust-function-signature level: `up()` and `down()`
    /// must derive the identical path from the same `interface`, with no separate state to go
    /// out of sync.
    #[test]
    fn up_and_down_agree_on_config_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: serialized by `_guard`, held for the whole test.
        unsafe {
            std::env::set_var("PROTON_PROXY_TUNNEL_DIR", "/fixed/dir/for/this/test");
        }
        let iface = "proton-test-agree";
        let path_a = config_path(iface);
        let path_b = config_path(iface);
        unsafe {
            std::env::remove_var("PROTON_PROXY_TUNNEL_DIR");
        }
        assert_eq!(path_a, path_b);
        assert!(path_a.ends_with(format!("{iface}.conf")));
    }

    /// Exercises `up()`/`down()` against a fake `wg-quick` (and a `sudo` that just execs
    /// through to it) on `PATH`, proving path-agreement at the actual process-invocation
    /// level rather than only at the Rust-function-signature level: the fake `wg-quick`
    /// records its argv to a log file, and this test asserts the `up` and `down` invocations
    /// named the exact same config path, and that `down()` removed the file afterward.
    #[test]
    fn up_then_down_invoke_wg_quick_with_the_same_path() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = ENV_LOCK.lock().unwrap();

        let scratch = tempfile::tempdir().unwrap();
        let tunnel_dir = scratch.path().join("tunnels");
        let bin_dir = scratch.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let log_path = scratch.path().join("argv.log");

        // Fake `sudo`: no real privilege escalation available/needed in a test sandbox, so it
        // just execs straight through to its arguments.
        let sudo_script = bin_dir.join("sudo");
        std::fs::write(&sudo_script, "#!/bin/sh\nexec \"$@\"\n").unwrap();
        std::fs::set_permissions(&sudo_script, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Fake `wg-quick`: records `<up|down> <path>` to `log_path` and exits 0.
        let wg_quick_script = bin_dir.join("wg-quick");
        std::fs::write(
            &wg_quick_script,
            format!(
                "#!/bin/sh\necho \"$1 $2\" >> {}\nexit 0\n",
                log_path.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&wg_quick_script, std::fs::Permissions::from_mode(0o700)).unwrap();

        let original_path = std::env::var("PATH").unwrap_or_default();
        // SAFETY: serialized by `_guard`, held for the whole test; PATH/PROTON_PROXY_TUNNEL_DIR
        // are restored before the test returns.
        unsafe {
            std::env::set_var("PROTON_PROXY_TUNNEL_DIR", &tunnel_dir);
            std::env::set_var("PATH", format!("{}:{}", bin_dir.display(), original_path));
        }

        let iface = "proton-faketest";
        let result = (|| -> Result<()> {
            up(iface, "[Interface]\nPrivateKey = x\n")?;
            down(iface)
        })();

        let expected_path = tunnel_dir.join(format!("{iface}.conf"));

        unsafe {
            std::env::set_var("PATH", &original_path);
            std::env::remove_var("PROTON_PROXY_TUNNEL_DIR");
        }

        result.expect("up/down against the fake wg-quick should succeed");

        let log = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected exactly one `up` and one `down` invocation:\n{log}"
        );

        let up_arg = lines[0]
            .strip_prefix("up ")
            .expect("first invocation should be `up`");
        let down_arg = lines[1]
            .strip_prefix("down ")
            .expect("second invocation should be `down`");

        assert_eq!(
            up_arg, down_arg,
            "wg-quick up and down must be invoked with the exact same config path"
        );
        assert_eq!(up_arg, expected_path.to_str().unwrap());

        // down() must have removed the config file (containing the private key) after running.
        assert!(!expected_path.exists());
    }
}
