//! systemd `--user` unit management for the background daemon. `gratis up` writes/starts a
//! unit that runs `gratis run` (the actual foreground daemon, see `main.rs`) with the flags it
//! was given baked into `ExecStart` — that's the one place daemon settings live, there is no
//! separate config file.
use crate::errors::*;
use std::path::PathBuf;
use std::process::Command;

const UNIT_NAME: &str = "gratis.service";

fn unit_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| ProtonError::Config("HOME is not set".into()))?;
    Ok(PathBuf::from(home).join(".config/systemd/user"))
}

pub fn unit_path() -> Result<PathBuf> {
    Ok(unit_dir()?.join(UNIT_NAME))
}

pub fn is_installed() -> Result<bool> {
    Ok(unit_path()?.is_file())
}

/// Absolute path to the currently-running `gratis` binary — what `ExecStart` points at.
fn binary_path() -> Result<PathBuf> {
    std::env::current_exe().map_err(ProtonError::Io)
}

fn unit_contents(
    control_port: u16,
    port_range_start: u16,
    unlimited_connections: bool,
) -> Result<String> {
    let bin = binary_path()?;
    let bin = bin
        .to_str()
        .ok_or_else(|| ProtonError::Config("gratis binary path is not valid UTF-8".into()))?;
    let unlimited_flag = if unlimited_connections {
        " --unlimited-connections"
    } else {
        ""
    };
    Ok(format!(
        "[Unit]\n\
         Description=gratis - Proton VPN client\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={bin} run --control-port {control_port} --port-range-start \
         {port_range_start}{unlimited_flag}\n\
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
) -> Result<()> {
    let dir = unit_dir()?;
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        unit_path()?,
        unit_contents(control_port, port_range_start, unlimited_connections)?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_contents_bakes_the_given_flags_into_exec_start() {
        let unit = unit_contents(9500, 21000, false).expect("binary_path must resolve in tests");
        let exec_start = unit
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("unit must have an ExecStart line");
        assert!(exec_start.ends_with("run --control-port 9500 --port-range-start 21000"));
        assert!(!exec_start.contains("--unlimited-connections"));
    }

    #[test]
    fn unit_contents_includes_the_unlimited_flag_when_requested() {
        let unit = unit_contents(9500, 21000, true).unwrap();
        let exec_start = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        assert!(
            exec_start.ends_with(
                "run --control-port 9500 --port-range-start 21000 --unlimited-connections"
            )
        );
    }

    #[test]
    fn unit_contents_is_a_valid_systemd_unit_shape() {
        // Not a full systemd parser — just the section headers a real unit file needs, so a
        // typo in the format string (e.g. a missing newline collapsing two sections) is caught.
        let unit = unit_contents(9000, 20000, false).unwrap();
        assert!(unit.contains("[Unit]\n"));
        assert!(unit.contains("[Service]\n"));
        assert!(unit.contains("[Install]\n"));
        assert!(unit.contains("Type=simple\n"));
        assert!(unit.contains("WantedBy=default.target\n"));
    }
}
