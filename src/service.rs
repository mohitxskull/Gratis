//! systemd `--user` unit management for the background daemon and its tray icon. `gratis up`
//! writes/starts a unit that runs `gratis run` (the actual foreground daemon, see `main.rs`)
//! with the flags it was given baked into `ExecStart` — that's the one place daemon settings
//! live, there is no separate config file. `gratis up` also writes/starts a second, independent
//! unit that runs `gratis tray` — kept as a separate unit (not merged into the same process) so
//! `gratis run` itself stays a pure headless service with no GUI/D-Bus-tray dependency; the tray
//! unit degrades harmlessly (see `tray.rs`) on a machine with no desktop session to show it in.
//! `up`/`down`/`persist`/`uninstall` manage both units together so they always move as a pair.
use crate::errors::*;
use std::path::PathBuf;
use std::process::Command;

const UNIT_NAME: &str = "gratis.service";
const TRAY_UNIT_NAME: &str = "gratis-tray.service";

fn unit_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| ProtonError::Config("HOME is not set".into()))?;
    Ok(PathBuf::from(home).join(".config/systemd/user"))
}

pub fn unit_path() -> Result<PathBuf> {
    Ok(unit_dir()?.join(UNIT_NAME))
}

pub fn tray_unit_path() -> Result<PathBuf> {
    Ok(unit_dir()?.join(TRAY_UNIT_NAME))
}

pub fn is_installed() -> Result<bool> {
    Ok(unit_path()?.is_file())
}

pub fn tray_is_installed() -> Result<bool> {
    Ok(tray_unit_path()?.is_file())
}

/// The installed unit file's `ExecStart=` line, if the unit exists and can be read — the one
/// place a running service's flags/settings live (see this module's doc comment). Centralizes
/// the "read the unit file, find the `ExecStart=` line" step that `main.rs`'s `unit_has_flag`
/// and `control_port_from_unit` used to each do independently, which meant a change to the unit
/// format had to be kept in sync in two places by hand. `None` (not an error) covers every
/// "nothing to read" case a caller like `gratis status` treats the same way anyway: not
/// installed, unreadable, or a unit with no `ExecStart=` line at all.
pub fn exec_start_line() -> Option<String> {
    let path = unit_path().ok()?;
    let contents = std::fs::read_to_string(path).ok()?;
    contents
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .map(str::to_string)
}

/// Absolute path to the currently-running `gratis` binary — what `ExecStart` points at.
fn binary_path() -> Result<PathBuf> {
    std::env::current_exe().map_err(ProtonError::Io)
}

fn unit_contents(
    control_port: u16,
    port_range_start: u16,
    unlimited_connections: bool,
    evict_lru: bool,
    http_proxy: bool,
) -> Result<String> {
    let bin = binary_path()?;
    let bin = bin
        .to_str()
        .ok_or_else(|| ProtonError::Config("gratis binary path is not valid UTF-8".into()))?;
    let mut flags = String::new();
    if unlimited_connections {
        flags.push_str(" --unlimited-connections");
    }
    if evict_lru {
        flags.push_str(" --evict-lru");
    }
    if http_proxy {
        flags.push_str(" --http-proxy");
    }
    Ok(format!(
        "[Unit]\n\
         Description=gratis - SOCKS5 proxy over your Proton VPN account\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={bin} run --control-port {control_port} --port-range-start \
         {port_range_start}{flags}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    ))
}

/// Write (or overwrite) the unit file with the given flags, then `daemon-reload` so systemd
/// picks up the change. Does not start or enable it.
pub fn install(
    control_port: u16,
    port_range_start: u16,
    unlimited_connections: bool,
    evict_lru: bool,
    http_proxy: bool,
) -> Result<()> {
    let dir = unit_dir()?;
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        unit_path()?,
        unit_contents(
            control_port,
            port_range_start,
            unlimited_connections,
            evict_lru,
            http_proxy,
        )?,
    )?;
    daemon_reload()
}

/// Stop + disable if installed, delete the unit file, `daemon-reload`. A no-op if the unit was
/// never installed.
pub fn uninstall() -> Result<()> {
    if !is_installed()? {
        return Ok(());
    }
    let _ = stop();
    let _ = disable();
    std::fs::remove_file(unit_path()?)?;
    daemon_reload()
}

fn tray_unit_contents(control_port: u16) -> Result<String> {
    let bin = binary_path()?;
    let bin = bin
        .to_str()
        .ok_or_else(|| ProtonError::Config("gratis binary path is not valid UTF-8".into()))?;
    Ok(format!(
        "[Unit]\n\
         Description=gratis - tray icon\n\
         After=gratis.service\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={bin} tray --control-port {control_port}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    ))
}

/// Same shape as `install`, for the tray unit.
pub fn install_tray(control_port: u16) -> Result<()> {
    let dir = unit_dir()?;
    std::fs::create_dir_all(&dir)?;
    std::fs::write(tray_unit_path()?, tray_unit_contents(control_port)?)?;
    daemon_reload()
}

/// Same shape as `uninstall`, for the tray unit.
pub fn uninstall_tray() -> Result<()> {
    if !tray_is_installed()? {
        return Ok(());
    }
    let _ = tray_stop();
    let _ = tray_disable();
    std::fs::remove_file(tray_unit_path()?)?;
    daemon_reload()
}

fn systemctl(args: &[&str]) -> Result<std::process::Output> {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .map_err(ProtonError::Io)
}

fn run_ok(args: &[&str]) -> Result<()> {
    let out = systemctl(args)?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    Err(ProtonError::Config(format!(
        "systemctl --user {} failed: {}",
        args.join(" "),
        stderr.trim()
    )))
}

fn daemon_reload() -> Result<()> {
    run_ok(&["daemon-reload"])
}

pub fn start() -> Result<()> {
    run_ok(&["start", UNIT_NAME])
}

pub fn stop() -> Result<()> {
    run_ok(&["stop", UNIT_NAME])
}

pub fn restart() -> Result<()> {
    run_ok(&["restart", UNIT_NAME])
}

pub fn enable() -> Result<()> {
    run_ok(&["enable", UNIT_NAME])
}

pub fn disable() -> Result<()> {
    run_ok(&["disable", UNIT_NAME])
}

/// `systemctl --user is-active` exits non-zero for every state that isn't "active" (inactive,
/// failed, activating, ...) — that's expected, not an error, so this reports `false` rather
/// than propagating the exit code as a `Result::Err`.
pub fn is_active() -> Result<bool> {
    Ok(systemctl(&["is-active", "--quiet", UNIT_NAME])?
        .status
        .success())
}

/// Same reasoning as `is_active`: a non-zero exit means "not enabled", not a failure.
pub fn is_enabled() -> Result<bool> {
    Ok(systemctl(&["is-enabled", "--quiet", UNIT_NAME])?
        .status
        .success())
}

pub fn tray_start() -> Result<()> {
    run_ok(&["start", TRAY_UNIT_NAME])
}

pub fn tray_stop() -> Result<()> {
    run_ok(&["stop", TRAY_UNIT_NAME])
}

pub fn tray_restart() -> Result<()> {
    run_ok(&["restart", TRAY_UNIT_NAME])
}

pub fn tray_enable() -> Result<()> {
    run_ok(&["enable", TRAY_UNIT_NAME])
}

pub fn tray_disable() -> Result<()> {
    run_ok(&["disable", TRAY_UNIT_NAME])
}

/// Same reasoning as `is_active`.
pub fn tray_is_active() -> Result<bool> {
    Ok(systemctl(&["is-active", "--quiet", TRAY_UNIT_NAME])?
        .status
        .success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_contents_bakes_the_given_flags_into_exec_start() {
        let unit = unit_contents(9500, 21000, false, false, false)
            .expect("binary_path must resolve in tests");
        let exec_start = unit
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("unit must have an ExecStart line");
        assert!(exec_start.ends_with("run --control-port 9500 --port-range-start 21000"));
        assert!(!exec_start.contains("--unlimited-connections"));
        assert!(!exec_start.contains("--evict-lru"));
    }

    #[test]
    fn unit_contents_includes_the_unlimited_flag_when_requested() {
        let unit = unit_contents(9500, 21000, true, false, false).unwrap();
        let exec_start = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        assert!(
            exec_start.ends_with(
                "run --control-port 9500 --port-range-start 21000 --unlimited-connections"
            )
        );
    }

    #[test]
    fn unit_contents_includes_the_evict_lru_flag_when_requested() {
        let unit = unit_contents(9500, 21000, false, true, false).unwrap();
        let exec_start = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        assert!(
            exec_start.ends_with("run --control-port 9500 --port-range-start 21000 --evict-lru")
        );
    }

    #[test]
    fn unit_contents_includes_both_flags_when_both_requested() {
        let unit = unit_contents(9500, 21000, true, true, false).unwrap();
        let exec_start = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        assert!(exec_start.ends_with(
            "run --control-port 9500 --port-range-start 21000 --unlimited-connections --evict-lru"
        ));
    }

    #[test]
    fn unit_contents_includes_the_http_proxy_flag_when_requested() {
        let unit = unit_contents(9500, 21000, false, false, true).unwrap();
        let exec_start = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        assert!(
            exec_start.ends_with("run --control-port 9500 --port-range-start 21000 --http-proxy")
        );
    }

    #[test]
    fn unit_contents_is_a_valid_systemd_unit_shape() {
        // Not a full systemd parser — just the section headers a real unit file needs, so a
        // typo in the format string (e.g. a missing newline collapsing two sections) is caught.
        let unit = unit_contents(9000, 20000, false, false, false).unwrap();
        assert!(unit.contains("[Unit]\n"));
        assert!(unit.contains("[Service]\n"));
        assert!(unit.contains("[Install]\n"));
        assert!(unit.contains("Type=simple\n"));
        assert!(unit.contains("WantedBy=default.target\n"));
    }

    #[test]
    fn tray_unit_contents_runs_the_tray_subcommand_with_the_given_port() {
        let unit = tray_unit_contents(9500).expect("binary_path must resolve in tests");
        let exec_start = unit
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("unit must have an ExecStart line");
        assert!(exec_start.ends_with("tray --control-port 9500"));
        assert!(unit.contains("After=gratis.service\n"));
    }
}
