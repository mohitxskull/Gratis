//! System tray icon: a small, separate, optional process — not part of `gratis run` itself.
//! `gratis run` stays a pure headless service with no GUI dependency (works fine over SSH, in
//! a container, on a minimal window manager with no tray). This talks to the already-running
//! daemon's control API (read-only, same as the web UI) and to `systemctl` (via `service.rs`,
//! same as `gratis up`/`gratis down`) — it has no privileged access the CLI didn't already have.
//!
//! Uses `ksni` (a pure-Rust, D-Bus `StatusNotifierItem` implementation, same zbus foundation as
//! `session.rs`'s keychain access and `notify.rs`'s notifications) rather than a GTK/Qt tray
//! library, so this stays dependency-light. Note for users: GNOME Shell has no built-in tray
//! support since 3.26 — the icon only shows up there with an extension installed (e.g. "AppIndicator
//! and KStatusNotifierItem Support"). This is a Linux desktop ecosystem limitation, not
//! something gratis can work around; verified working live with that extension active.
use crate::errors::*;
use crate::service;
use ksni::TrayMethods;
use ksni::menu::{MenuItem, StandardItem};
use std::time::Duration;

/// How often the tray polls the control API + `systemctl` for fresh status.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
struct GratisTray {
    control_port: u16,
    status: String,
    service_active: bool,
    /// Newest available version, if the daemon's periodic update check has found one — see
    /// `api::update_status`. `None` shows no update-related menu item at all.
    update_available: Option<String>,
}

impl ksni::Tray for GratisTray {
    fn id(&self) -> String {
        "gratis".into()
    }

    fn icon_name(&self) -> String {
        "network-vpn".into()
    }

    fn title(&self) -> String {
        "gratis".into()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "gratis".into(),
            description: self.status.clone(),
            ..Default::default()
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let control_port = self.control_port;
        let service_active = self.service_active;
        let mut items = vec![
            StandardItem {
                label: self.status.clone(),
                enabled: false,
                ..Default::default()
            }
            .into(),
        ];
        if let Some(version) = &self.update_available {
            items.push(
                StandardItem {
                    label: format!("Update available: v{version}"),
                    icon_name: "software-update-available".into(),
                    activate: Box::new(|_: &mut Self| {
                        let _ = std::process::Command::new("xdg-open")
                            .arg("https://github.com/mohitxskull/Gratis/releases/latest")
                            .spawn();
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }
        items.push(MenuItem::Separator);
        items.extend([
            StandardItem {
                label: "Open Dashboard".into(),
                icon_name: "network-vpn".into(),
                activate: Box::new(move |_: &mut Self| {
                    let url = format!("http://127.0.0.1:{control_port}/");
                    // Fire-and-forget, same as notify.rs's click-through — no browser
                    // configured is a shrug, not an error worth surfacing from a tray click.
                    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: if service_active {
                    "Stop Service".into()
                } else {
                    "Start Service".into()
                },
                icon_name: if service_active {
                    "media-playback-stop".into()
                } else {
                    "media-playback-start".into()
                },
                activate: Box::new(move |_: &mut Self| {
                    let result = if service_active {
                        service::stop()
                    } else {
                        service::start()
                    };
                    if let Err(err) = result {
                        log::warn!("tray action failed: {err}");
                    }
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit Tray".into(),
                icon_name: "application-exit".into(),
                // Exits only this tray process — the background service (if running) is
                // untouched, same relationship as closing a taskbar clock doesn't stop the
                // system clock.
                activate: Box::new(|_: &mut Self| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        ]);
        items
    }
}

/// Ask the control API how many servers are ready. `None` if it can't be reached (service not
/// running yet, or not running at all) — not an error worth failing the tray over.
async fn server_count(control_port: u16) -> Option<usize> {
    let servers: Vec<serde_json::Value> =
        reqwest::get(format!("http://127.0.0.1:{control_port}/api/servers"))
            .await
            .ok()?
            .json()
            .await
            .ok()?;
    Some(servers.len())
}

#[derive(serde::Deserialize)]
struct UpdateStatus {
    available: Option<String>,
}

/// Ask the control API whether a newer release is available, per its periodic check — see
/// `api::update_status`. `None` if the API can't be reached; treated the same as "no update
/// known" rather than an error worth failing the tray over.
async fn update_available(control_port: u16) -> Option<String> {
    let status: UpdateStatus = reqwest::get(format!("http://127.0.0.1:{control_port}/api/update"))
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    status.available
}

fn status_line(service_active: bool, servers: Option<usize>) -> String {
    match (service_active, servers) {
        (false, _) => "Not running".to_string(),
        (true, Some(n)) => format!("Running — {n} servers ready"),
        (true, None) => "Running — starting up...".to_string(),
    }
}

/// Run the tray icon until killed. Polls `systemctl`/the control API every `POLL_INTERVAL`
/// (private to this module) to keep the status line and Start/Stop label current — nothing
/// here pushes updates, the same "poll, don't push" choice the web UI's htmx polling makes.
pub async fn run(control_port: u16) -> Result<()> {
    let tray = GratisTray {
        control_port,
        status: "checking status...".to_string(),
        service_active: false,
        update_available: None,
    };
    let handle = tray
        .spawn()
        .await
        .map_err(|e| ProtonError::Config(format!("failed to register tray icon: {e}")))?;

    loop {
        let active = service::is_active().unwrap_or(false);
        let servers = if active {
            server_count(control_port).await
        } else {
            None
        };
        let update = if active {
            update_available(control_port).await
        } else {
            None
        };
        let status = status_line(active, servers);

        handle
            .update(|tray: &mut GratisTray| {
                tray.status = status;
                tray.service_active = active;
                tray.update_available = update;
            })
            .await;

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line_covers_not_running_starting_and_ready() {
        assert_eq!(status_line(false, None), "Not running");
        assert_eq!(status_line(false, Some(5)), "Not running");
        assert_eq!(status_line(true, None), "Running — starting up...");
        assert_eq!(status_line(true, Some(42)), "Running — 42 servers ready");
    }
}
