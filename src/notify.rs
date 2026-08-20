//! Desktop notifications via the FreeDesktop.org `org.freedesktop.Notifications` D-Bus
//! interface — the same standard `notify-send` and every major Linux notification daemon
//! (GNOME Shell, KDE Plasma, `xfce4-notifyd`, `dunst`, `mako`, ...) implement, not tied to any
//! one desktop environment. `gratis run` shares its `systemd --user` session's D-Bus, so this
//! works with no extra setup. Every call here is best-effort: a headless box with no
//! notification daemon logs a warning and moves on, never fails or blocks the caller.
use notify_rust::Notification;

/// Show a notification with no click action.
pub fn notify(summary: &str, body: &str) {
    if let Err(err) = Notification::new().summary(summary).body(body).show() {
        log::warn!("desktop notification failed ({err}); continuing without it");
    }
}

/// Show a notification whose click opens `url` in the default browser (`xdg-open`).
///
/// Waiting for the click (`NotificationHandle::wait_for_action`) blocks the calling thread
/// until the notification is dismissed or times out, so this spawns its own short-lived OS
/// thread and returns immediately — safe to call from async code without a `spawn_blocking`.
pub fn notify_clickable(summary: &str, body: &str, url: &str) {
    let summary = summary.to_string();
    let body = body.to_string();
    let url = url.to_string();
    std::thread::spawn(move || {
        let notification = match Notification::new()
            .summary(&summary)
            .body(&body)
            .action("default", "Open")
            .show()
        {
            Ok(n) => n,
            Err(err) => {
                log::warn!("desktop notification failed ({err}); continuing without it");
                return;
            }
        };
        notification.wait_for_action(|action| {
            if action == "default" {
                // Fire-and-forget: a failed launch (no `xdg-open`, no browser configured)
                // isn't worth surfacing as an error over what was already a best-effort
                // notification.
                let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
            }
        });
    });
}
