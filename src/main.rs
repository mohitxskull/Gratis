//! `gratis` CLI entry point. `login`/`logout`/`up`/`down`/`status`/`persist`/`update`/
//! `uninstall` manage gratis as an installed pair of systemd `--user` services (the daemon and
//! its tray icon); `run` is the actual foreground daemon (today's control API + web UI) and
//! `tray` the foreground tray process (see `tray.rs`) — both invoked by their respective
//! unit's `ExecStart`, not meant to be run directly by a user (though `tray` is also fine to
//! run manually for debugging).
//!
//! Credentials are only ever asked for once, by `gratis login` — never as CLI arguments (they'd
//! leak into `ps`/shell history) — and the password itself is never stored: `login` exchanges it
//! for Proton session tokens (`uid`, `access_token`, `refresh_token`) and stores those in the OS
//! keychain (`session.rs`), which is also what makes every later `up`/`run` fast (no SRP, no
//! password prompt).
use clap::{Parser, Subcommand};
use gratis::api;
use gratis::client::ProtonVPNClient;
use gratis::errors::ProtonError;
use gratis::manager::TunnelManager;
use gratis::session::{self, Session};
use gratis::{service, update};
use std::io::Write;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "gratis",
    version,
    about = "Local SOCKS5 proxy over your Proton VPN account's servers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log in to Proton and store the session in the OS keychain.
    Login,
    /// Stop the service (if running) and forget the stored session.
    Logout,
    /// Start the background service.
    Up {
        /// Port the localhost control API + web UI listen on.
        #[arg(long, default_value = "9000")]
        control_port: u16,
        /// First port handed out to the server list.
        #[arg(long, default_value = "20000")]
        port_range_start: u16,
        /// Don't cap simultaneous server tunnels at the account's Proton MaxConnect limit.
        /// gratis's "any number of servers at once" design otherwise stays within what the
        /// account is actually allowed to run concurrently — only bypass this if you
        /// understand and accept the ToS risk of exceeding it.
        #[arg(long)]
        unlimited_connections: bool,
        /// When the MaxConnect cap is reached, disconnect the least-recently-used idle server
        /// to make room for a new one instead of refusing the new connection. Never evicts a
        /// server with active traffic. Has no effect with --unlimited-connections (nothing
        /// ever hits the cap).
        #[arg(long)]
        evict_lru: bool,
    },
    /// Stop the background service.
    Down,
    /// Show whether gratis is logged in, running, and set to start on login.
    Status,
    /// Start the service automatically on login.
    Persist {
        /// Stop starting automatically on login.
        #[arg(long)]
        off: bool,
    },
    /// Download and install the latest release.
    Update,
    /// Stop and remove the service, the stored session, and this binary.
    Uninstall,
    /// Show a system tray icon (dashboard shortcut, start/stop, live status). A separate
    /// foreground process, not part of the background service — run it manually or add it to
    /// your desktop environment's autostart. Requires a tray/StatusNotifierItem host; plain
    /// GNOME Shell needs the "AppIndicator and KStatusNotifierItem Support" extension.
    Tray {
        /// Control-port to poll for status. Defaults to whatever `gratis up` was last given.
        #[arg(long)]
        control_port: Option<u16>,
    },
    /// Run the foreground daemon. Invoked by the systemd unit's `ExecStart` — not meant to be
    /// run directly.
    #[command(hide = true)]
    Run {
        #[arg(long, default_value = "9000")]
        control_port: u16,
        #[arg(long, default_value = "20000")]
        port_range_start: u16,
        #[arg(long)]
        unlimited_connections: bool,
        #[arg(long)]
        evict_lru: bool,
    },
}

// Single-threaded runtime: every subcommand here is I/O-bound (HTTP, SOCKS5 relay, D-Bus),
// not CPU-bound — the default multi-threaded runtime was spawning ~num_cpus worker threads
// (11 total on an 8-core box, confirmed via /proc/<pid>/status) for work that never needed
// parallelism across cores. `gratis tray` in particular does almost nothing (a 5s poll loop)
// and had no business paying for that. Verified live (release build): threads 11->4 (daemon)
// and 11->3 (tray), RSS 17.2MB->15.8MB and 12.0MB->11.2MB; real concurrent SOCKS5 relays
// through two simultaneous tunnels still complete with identical timing (not serialized).

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Login => cmd_login().await,
        Command::Logout => cmd_logout(),
        Command::Up {
            control_port,
            port_range_start,
            unlimited_connections,
            evict_lru,
        } => cmd_up(
            control_port,
            port_range_start,
            unlimited_connections,
            evict_lru,
        ),
        Command::Down => cmd_down(),
        Command::Status => cmd_status().await,
        Command::Persist { off } => cmd_persist(off),
        Command::Update => cmd_update().await,
        Command::Uninstall => cmd_uninstall(),
        Command::Tray { control_port } => cmd_tray(control_port).await,
        Command::Run {
            control_port,
            port_range_start,
            unlimited_connections,
            evict_lru,
        } => {
            cmd_run(
                control_port,
                port_range_start,
                unlimited_connections,
                evict_lru,
            )
            .await
        }
    };

    if let Err(err) = result {
        eprintln!("gratis: {err}");
        std::process::exit(1);
    }
}

fn prompt(label: &str) -> anyhow::Result<String> {
    print!("{label}: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Like `prompt`, but echoes `*` per keystroke instead of the real character — real terminal
/// echo can't be told "show `*`" (only on/off), so this reads one key at a time via `console`
/// (which puts the terminal in raw/no-echo mode itself) and does the masking by hand. Falls
/// back to a plain hidden read (`console::Term::read_secure_line`, no stars at all — the
/// conventional `ssh`/`sudo` behavior) when stdin isn't a real terminal (e.g. piped input in
/// a script), since there's no keystroke stream to mask there.
fn prompt_password_masked(label: &str) -> anyhow::Result<String> {
    use console::{Key, Term};

    print!("{label}: ");
    std::io::stdout().flush()?;

    let term = Term::stdout();
    if !term.is_term() {
        return Ok(term.read_secure_line()?);
    }

    let mut password = String::new();
    loop {
        match term.read_key()? {
            Key::Char(c) => {
                password.push(c);
                print!("*");
                std::io::stdout().flush()?;
            }
            Key::Backspace => {
                if password.pop().is_some() {
                    // Move left, overwrite the `*` with a space, move left again.
                    print!("\u{8} \u{8}");
                    std::io::stdout().flush()?;
                }
            }
            Key::Enter => {
                println!();
                break;
            }
            Key::CtrlC => {
                println!();
                anyhow::bail!("cancelled");
            }
            _ => {}
        }
    }
    Ok(password)
}

/// Deliberately loose — this only needs to catch "empty" and "obviously not an email" (typos,
/// a pasted password, hitting Enter blank) before spending a round trip on Proton's API to
/// find out. Proton's own account-creation rules are the actual source of truth for what's a
/// valid address; this never needs to be stricter than "has a local part, an `@`, and a
/// domain with a dot in it, no whitespace."
fn looks_like_email(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !s.contains(char::is_whitespace)
        && s.matches('@').count() == 1
}

/// Email/password source for `login`: `EMAIL`/`PASSWORD` env vars for scripted use, falling
/// back to an interactive prompt — same non-CLI-argument rule as before. The email is
/// validated (non-empty, plausible shape) before it's ever sent anywhere — a blank or
/// malformed address should fail locally and immediately, not after a round trip to Proton's
/// API returns a confusing error.
fn read_credentials() -> anyhow::Result<(String, String)> {
    let email = match std::env::var("EMAIL") {
        Ok(v) if !v.is_empty() => {
            if !looks_like_email(&v) {
                anyhow::bail!("EMAIL={v:?} doesn't look like a valid email address");
            }
            v
        }
        _ => loop {
            let candidate = prompt("Proton email")?;
            if looks_like_email(&candidate) {
                break candidate;
            }
            println!("gratis: that doesn't look like a valid email address, try again");
        },
    };
    let password = match std::env::var("PASSWORD") {
        Ok(v) if !v.is_empty() => v,
        _ => prompt_password_masked("Proton password")?,
    };
    Ok((email, password))
}

async fn cmd_login() -> anyhow::Result<()> {
    let (email, password) = read_credentials()?;

    println!("gratis: authenticating...");
    let mut client = ProtonVPNClient::new(&email);
    match client.login(&email, &password).await {
        Ok(_) => {}
        Err(ProtonError::TwoFactorRequired) => {
            let code = match std::env::var("TOTP") {
                Ok(v) if !v.is_empty() => v,
                _ => prompt("2FA code")?,
            };
            println!("gratis: verifying 2FA code...");
            client.submit_2fa(&code).await?;
        }
        Err(err) => return Err(err.into()),
    }

    let session = Session {
        email: email.clone(),
        uid: client.uid.ok_or_else(|| ProtonError::Auth)?,
        access_token: client.auth_token.ok_or_else(|| ProtonError::Auth)?,
        refresh_token: client.refresh_token.ok_or_else(|| ProtonError::Auth)?,
    };
    session::store(&session)?;

    println!("gratis: logged in as {email}");
    Ok(())
}

fn cmd_logout() -> anyhow::Result<()> {
    if service::is_installed()? && service::is_active().unwrap_or(false) {
        service::stop()?;
    }
    if service::tray_is_installed().unwrap_or(false) && service::tray_is_active().unwrap_or(false) {
        let _ = service::tray_stop();
    }
    session::delete()?;
    println!("gratis: logged out");
    Ok(())
}

fn cmd_up(
    control_port: u16,
    port_range_start: u16,
    unlimited_connections: bool,
    evict_lru: bool,
) -> anyhow::Result<()> {
    if session::load()?.is_none() {
        anyhow::bail!("not logged in — run `gratis login` first");
    }
    service::install(
        control_port,
        port_range_start,
        unlimited_connections,
        evict_lru,
    )?;
    service::start()?;

    // The tray is a convenience, not core functionality — a failure to install/start it
    // (e.g. no systemd user session quirk) shouldn't fail `up` itself.
    if let Err(err) = service::install_tray(control_port) {
        eprintln!("gratis: tray failed to install ({err}); continuing without it");
    } else if let Err(err) = service::tray_start() {
        eprintln!("gratis: tray failed to start ({err}); continuing without it");
    }

    println!("gratis: service starting — see `gratis status`");
    Ok(())
}

fn cmd_down() -> anyhow::Result<()> {
    if !service::is_installed()? {
        anyhow::bail!("service not installed — run `gratis up` first");
    }
    service::stop()?;
    if service::tray_is_installed().unwrap_or(false) {
        let _ = service::tray_stop();
    }
    println!("gratis: service stopped");
    Ok(())
}

async fn cmd_status() -> anyhow::Result<()> {
    let session = session::load()?;
    match &session {
        Some(s) => println!("logged in: yes ({})", mask_email(&s.email)),
        None => println!("logged in: no"),
    }

    let installed = service::is_installed()?;
    if !installed {
        println!("service: not installed (run `gratis up`)");
        return Ok(());
    }

    let active = service::is_active().unwrap_or(false);
    let enabled = service::is_enabled().unwrap_or(false);
    println!("service: {}", if active { "running" } else { "stopped" });
    println!(
        "persist (start on login): {}",
        if enabled { "on" } else { "off" }
    );

    if active {
        match server_count().await {
            Ok((count, url)) => println!("servers: {count} ready, control API at {url}"),
            Err(err) => println!("servers: could not reach control API ({err})"),
        }
    }

    if service::tray_is_installed().unwrap_or(false) {
        let tray_active = service::tray_is_active().unwrap_or(false);
        println!("tray: {}", if tray_active { "running" } else { "stopped" });
    }

    Ok(())
}

/// Reads the control port out of the installed unit file's `ExecStart` line rather than
/// hardcoding the default — `up` can be given a non-default `--control-port`. Falls back to
/// 9000 (the default) if the unit isn't installed or the line can't be parsed.
fn control_port_from_unit() -> u16 {
    service::unit_path()
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|unit| {
            unit.lines()
                .find_map(|l| l.split("--control-port").nth(1))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|p| p.parse().ok())
        })
        .unwrap_or(9000)
}

async fn server_count() -> anyhow::Result<(usize, String)> {
    let port = control_port_from_unit();
    let url = format!("http://127.0.0.1:{port}");
    let servers: Vec<serde_json::Value> = reqwest::get(format!("{url}/api/servers"))
        .await?
        .json()
        .await?;
    Ok((servers.len(), url))
}

fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((user, domain)) if !user.is_empty() => {
            format!("{}***@{domain}", &user[..1])
        }
        _ => "***".to_string(),
    }
}

fn cmd_persist(off: bool) -> anyhow::Result<()> {
    if !service::is_installed()? {
        anyhow::bail!("service not installed — run `gratis up` first");
    }
    if off {
        service::disable()?;
        if service::tray_is_installed().unwrap_or(false) {
            let _ = service::tray_disable();
        }
        println!("gratis: will not start automatically on login");
    } else {
        service::enable()?;
        if service::tray_is_installed().unwrap_or(false) {
            let _ = service::tray_enable();
        }
        println!("gratis: will start automatically on login");
    }
    Ok(())
}

async fn cmd_update() -> anyhow::Result<()> {
    match update::run().await? {
        update::UpdateOutcome::AlreadyLatest { version } => {
            println!("gratis: already up to date (v{version})");
        }
        update::UpdateOutcome::Updated { from, to } => {
            println!("gratis: updated v{from} -> v{to}");
            if service::is_installed()? && service::is_active().unwrap_or(false) {
                service::restart()?;
                println!("gratis: service restarted");
            }
            if service::tray_is_installed().unwrap_or(false)
                && service::tray_is_active().unwrap_or(false)
            {
                let _ = service::tray_restart();
            }
        }
    }
    Ok(())
}

fn cmd_uninstall() -> anyhow::Result<()> {
    print!(
        "This removes the gratis service, tray, stored login, and this binary. Continue? [y/N] "
    );
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !answer.trim().eq_ignore_ascii_case("y") {
        println!("aborted");
        return Ok(());
    }

    service::uninstall()?;
    service::uninstall_tray()?;
    session::delete()?;

    let exe = std::env::current_exe()?;
    println!("gratis: removing {}", exe.display());
    std::fs::remove_file(&exe)?;

    println!("gratis: uninstalled");
    Ok(())
}

async fn cmd_tray(control_port: Option<u16>) -> anyhow::Result<()> {
    let control_port = control_port.unwrap_or_else(control_port_from_unit);
    println!("gratis: tray running (control port {control_port}) — Ctrl-C to quit");
    gratis::tray::run(control_port).await?;
    Ok(())
}

/// Read `KEY=value` lines directly from a `.env` file, with NO shell interpretation — sourcing
/// a `.env` through a shell (`source .env`) can mangle values containing `\`, `$`, `#`, etc.
/// Kept only as a fallback for `gratis run` so a pre-existing `.env`-based workflow (or a
/// stored session that's missing/unavailable, e.g. no Secret Service running) still works.
fn read_dotenv_var(path: &std::path::Path, key: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    content
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")).map(|v| v.to_string()))
}

/// Resume the stored session (or fall back to a `.env`) and populate `manager`'s server list.
/// Split out of `cmd_run` so it can run *concurrently* with the control API instead of
/// blocking the listener bind — this is a real ~15-20s network round trip (session-resume:
/// fetch_servers + certificate minting) against Proton's live API, during which `gratis
/// status`'s HTTP probe would otherwise see "connection refused" even though the service is
/// genuinely starting up correctly (confirmed live: `systemctl` marks a `Type=simple` unit
/// active the instant the process starts, with no readiness signal, so there's no way to
/// distinguish "still starting" from "broken" without the port already being open).
async fn resume_or_login(manager: Arc<TunnelManager>, control_port: u16) {
    match session::load() {
        Ok(Some(session)) => match manager.login_with_session(&session).await {
            Ok(updated) => {
                if updated.access_token != session.access_token {
                    // The stored access token had expired and got refreshed — persist the new
                    // one so the next `run` doesn't have to refresh again immediately.
                    if let Err(err) = session::store(&updated) {
                        eprintln!("gratis: failed to persist refreshed session: {err}");
                    }
                }
                let count = manager.servers().len();
                println!(
                    "gratis: resumed session ({}), {count} servers ready",
                    session.email
                );
            }
            Err(err) => {
                eprintln!(
                    "gratis: stored session is no longer valid ({err}) — run `gratis login` again"
                );
                gratis::notify::notify_clickable(
                    "gratis: session expired",
                    "Run `gratis login` again to reconnect. Click to open the dashboard.",
                    &format!("http://127.0.0.1:{control_port}/"),
                );
            }
        },
        Ok(None) => {
            // No stored session — fall back to a `.env` in the current directory, matching
            // the daemon's original (pre-CLI) behavior.
            let dotenv_path = std::path::Path::new(".env");
            match (
                read_dotenv_var(dotenv_path, "EMAIL"),
                read_dotenv_var(dotenv_path, "PASSWORD"),
            ) {
                (Some(email), Some(password)) => match manager.login(&email, &password).await {
                    Ok(()) => {
                        let count = manager.servers().len();
                        println!("gratis: logged in from .env ({email}), {count} servers ready");
                    }
                    Err(err) => eprintln!("gratis: login from .env failed: {err}"),
                },
                _ => eprintln!(
                    "gratis: no stored session and no .env (EMAIL + PASSWORD) — run `gratis login`"
                ),
            }
        }
        Err(err) => {
            eprintln!("gratis: failed to read stored session ({err}), starting with no servers")
        }
    }
}

async fn cmd_run(
    control_port: u16,
    port_range_start: u16,
    unlimited_connections: bool,
    evict_lru: bool,
) -> anyhow::Result<()> {
    let manager = Arc::new(TunnelManager::new(
        port_range_start,
        unlimited_connections,
        evict_lru,
    ));

    // Bind and start serving *before* logging in — see `resume_or_login`'s doc comment for
    // why. `manager` starts with an empty server list, which the web UI and `/api/servers`
    // already render as a normal (not error) empty state.
    let router = api::router(manager.clone());

    let addr = format!("127.0.0.1:{control_port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(err) => {
            eprintln!("gratis: failed to bind {addr}: {err}");
            gratis::notify::notify(
                "gratis: failed to start",
                &format!("Could not bind {addr}: {err}"),
            );
            std::process::exit(1);
        }
    };

    println!("gratis: control API + web UI listening on http://{addr}");

    // One task: the initial login/session-resume, then (whether or not it succeeded — a
    // stored session can still be fixed later by a fresh `gratis login` elsewhere) periodic
    // re-fetches so a long-running daemon's server list doesn't go stale — see
    // SERVER_LIST_REFRESH_INTERVAL's doc comment for why this matters (load numbers frozen
    // at login time, new servers invisible, removed servers left dangling forever without
    // it — confirmed gaps, not theoretical).
    tokio::spawn({
        let manager = manager.clone();
        async move {
            resume_or_login(manager.clone(), control_port).await;

            let mut interval = tokio::time::interval(gratis::manager::SERVER_LIST_REFRESH_INTERVAL);
            interval.tick().await; // first tick fires immediately; the line above just refreshed.
            loop {
                interval.tick().await;
                if let Err(err) = manager.refresh_servers().await {
                    eprintln!(
                        "gratis: periodic server-list refresh failed ({err}); keeping the \
                         existing list until the next attempt"
                    );
                }
            }
        }
    });

    // Separate task from the login/server-refresh one above: an update check hitting GitHub
    // shouldn't share fate with, or wait behind, Proton API calls. Check-only — see
    // `update::check_for_update`'s doc comment for why this never downloads or applies
    // anything on its own, just notifies. Also records the result on `manager` so `/api/update`
    // (and from there, the tray) can show it without making a second GitHub API call.
    tokio::spawn({
        let manager = manager.clone();
        async move {
            let mut interval = tokio::time::interval(gratis::update::UPDATE_CHECK_INTERVAL);
            interval.tick().await; // skip the immediate first tick: a fresh `gratis up` is already running the version the user just installed/updated to.
            let mut last_notified: Option<String> = None;
            loop {
                interval.tick().await;
                match gratis::update::check_for_update().await {
                    Ok(latest) => {
                        manager.set_update_available(latest.clone());
                        if latest.is_some() && latest != last_notified {
                            let version = latest.clone().unwrap();
                            gratis::notify::notify_clickable(
                                "gratis: update available",
                                &format!(
                                    "v{version} is out — run `gratis update` to install it, or click for release notes."
                                ),
                                "https://github.com/mohitxskull/Gratis/releases/latest",
                            );
                        }
                        last_notified = latest;
                    }
                    Err(err) => {
                        eprintln!(
                            "gratis: periodic update check failed ({err}); will retry next interval"
                        );
                    }
                }
            }
        }
    });

    tokio::select! {
        result = axum::serve(listener, router) => {
            if let Err(err) = result {
                eprintln!("gratis: server error: {err}");
                std::process::exit(1);
            }
        }
        signal_result = tokio::signal::ctrl_c() => {
            if let Err(err) = signal_result {
                eprintln!("gratis: failed to install Ctrl-C handler: {err}");
                return Ok(());
            }
            eprintln!("gratis: received shutdown signal, exiting");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_email_accepts_plausible_addresses() {
        assert!(looks_like_email("user@proton.me"));
        assert!(looks_like_email("first.last+tag@sub.example.com"));
    }

    #[test]
    fn looks_like_email_rejects_empty_and_malformed_input() {
        assert!(!looks_like_email(""));
        assert!(!looks_like_email("   "));
        assert!(!looks_like_email("not-an-email"));
        assert!(!looks_like_email("@proton.me"));
        assert!(!looks_like_email("user@"));
        assert!(!looks_like_email("user@nodot"));
        assert!(!looks_like_email("user@.com"));
        assert!(!looks_like_email("user@com."));
        assert!(!looks_like_email("two@at@signs.com"));
        assert!(!looks_like_email("has space@proton.me"));
        assert!(!looks_like_email("user@proton.me\n"));
    }
}
