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
use anyhow::Context;
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
        /// Speak HTTP CONNECT on every port instead of the default SOCKS5. For clients/
        /// frameworks that only support proxying through an HTTP CONNECT proxy (e.g. Pingora's
        /// `Peer::proxy`) rather than SOCKS5. One choice for the whole daemon — every port
        /// switches together.
        #[arg(long)]
        http_proxy: bool,
    },
    /// Stop the background service.
    Down,
    /// Show whether gratis is logged in, running, and set to start on login.
    Status,
    /// Show the service's (and its tray's) systemd journal logs.
    Logs {
        /// Keep following new log lines instead of exiting after showing recent history —
        /// same idea as `journalctl -f`.
        #[arg(long)]
        watch: bool,
    },
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
        #[arg(long)]
        http_proxy: bool,
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
    // `gratis=info` by default — plain `env_logger::init()` defaults to `error`-only, which
    // would silently swallow every `log::info!`/`log::warn!` line below unless the user already
    // knew to set `RUST_LOG`. Scoped to this crate specifically (not a blanket `info`) so a
    // dependency's own verbose logging (e.g. `zbus`, used by the tray/keychain/notifications)
    // doesn't flood `journalctl --user -u gratis` by default. `RUST_LOG` still overrides this
    // entirely, e.g. `RUST_LOG=debug` for more detail or `RUST_LOG=warn` for less.
    //
    // Log level policy: `info!` for daemon lifecycle events (listening address, session
    // resumed/logged in, service starting) — visible by default. `warn!` for something a human
    // should notice but that the daemon already recovered from (a periodic refresh/update-check
    // that failed and will retry, a local-agent handshake falling back to the slower readiness
    // probe, a desktop notification that couldn't be shown). CLI-subcommand output (`gratis
    // status`, `gratis login`, etc.) is unaffected — those print directly to the terminal as a
    // command's own response, not as log output.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("gratis=info"))
        .init();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Login => cmd_login().await,
        Command::Logout => cmd_logout(),
        Command::Up {
            control_port,
            port_range_start,
            unlimited_connections,
            evict_lru,
            http_proxy,
        } => cmd_up(
            control_port,
            port_range_start,
            unlimited_connections,
            evict_lru,
            http_proxy,
        ),
        Command::Down => cmd_down(),
        Command::Status => cmd_status().await,
        Command::Logs { watch } => cmd_logs(watch),
        Command::Persist { off } => cmd_persist(off),
        Command::Update => cmd_update().await,
        Command::Uninstall => cmd_uninstall(),
        Command::Tray { control_port } => cmd_tray(control_port).await,
        Command::Run {
            control_port,
            port_range_start,
            unlimited_connections,
            evict_lru,
            http_proxy,
        } => {
            cmd_run(
                control_port,
                port_range_start,
                unlimited_connections,
                evict_lru,
                http_proxy,
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
/// The password comes back wrapped in `Zeroizing` — it's cleared from memory the moment it
/// goes out of scope in the caller, rather than lingering in the allocator's freed memory (and
/// potentially swap/core dumps) for the rest of the process's life.
fn read_credentials() -> anyhow::Result<(String, zeroize::Zeroizing<String>)> {
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
    Ok((email, zeroize::Zeroizing::new(password)))
}

async fn cmd_login() -> anyhow::Result<()> {
    let (email, password) = read_credentials()?;

    println!("gratis: authenticating...");
    let mut client = ProtonVPNClient::new(&email)?;
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
    http_proxy: bool,
) -> anyhow::Result<()> {
    if session::load()?.is_none() {
        anyhow::bail!("not logged in — run `gratis login` first");
    }

    // `systemctl start` on an already-active unit is a no-op — it does NOT restart the service
    // to pick up a rewritten `ExecStart`. Silently rewriting the unit file while the old
    // process keeps running with its old flags would leave `gratis status` (which reads the
    // unit file) claiming flags the live process doesn't actually have. Refuse outright instead
    // — `gratis down` first makes the intent explicit.
    if service::is_installed()? && service::is_active().unwrap_or(false) {
        anyhow::bail!(
            "gratis is already running — run `gratis down` first if you want to change flags \
             and start again"
        );
    }

    service::install(
        control_port,
        port_range_start,
        unlimited_connections,
        evict_lru,
        http_proxy,
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
    let installed = service::is_installed()?;
    let active = installed && service::is_active().unwrap_or(false);

    // Prefer the running daemon's own *live* knowledge of whether Proton auth actually works
    // right now (`/api/health`) over just checking whether a session file happens to exist on
    // disk. Those are different questions — confirmed live: a stored session can expire (or the
    // machine's clock jumps after a long sleep) while the file on disk is untouched, so the old
    // disk-only check kept printing "logged in: yes" for a daemon that had already logged
    // "stored session is no longer valid" and was running with zero servers. Only fall back to
    // the disk-only check when there's no running daemon to ask at all.
    let live_health = if active { Some(health().await) } else { None };

    match (&live_health, &session) {
        (Some(Ok(h)), _) if h.auth_ok => match &session {
            Some(s) => println!("logged in: yes ({})", mask_email(&s.email)),
            None => println!("logged in: yes (session file missing, but daemon is authenticated)"),
        },
        (Some(Ok(h)), _) => {
            let reason = h.auth_error.as_deref().unwrap_or("unknown reason");
            println!("logged in: NO — {reason}");
        }
        (Some(Err(_)), Some(s)) => println!(
            "logged in: yes ({}) [unverified — daemon not responding on control port]",
            mask_email(&s.email)
        ),
        (Some(Err(_)), None) => println!("logged in: no"),
        (None, Some(s)) => println!(
            "logged in: yes ({}) [unverified — service not running, this is just what's on disk]",
            mask_email(&s.email)
        ),
        (None, None) => println!("logged in: no"),
    }

    if !installed {
        println!("service: not installed (run `gratis up`)");
        return Ok(());
    }

    let enabled = service::is_enabled().unwrap_or(false);
    println!("service: {}", if active { "running" } else { "stopped" });
    println!(
        "persist (start on login): {}",
        if enabled { "on" } else { "off" }
    );
    println!(
        "unlimited connections: {}",
        if unit_has_flag("--unlimited-connections") {
            "on (ToS risk — see README)"
        } else {
            "off"
        }
    );
    println!(
        "evict least-recently-used: {}",
        if unit_has_flag("--evict-lru") {
            "on"
        } else {
            "off"
        }
    );
    println!(
        "proxy protocol: {}",
        if unit_has_flag("--http-proxy") {
            "http-connect"
        } else {
            "socks5"
        }
    );

    if active {
        match &live_health {
            Some(Ok(h)) => println!(
                "servers: {} ready, control API at http://127.0.0.1:{}",
                h.servers_ready,
                control_port_from_unit()
            ),
            Some(Err(_)) | None => println!("servers: could not reach control API"),
        }
    }

    if service::tray_is_installed().unwrap_or(false) {
        let tray_active = service::tray_is_active().unwrap_or(false);
        println!("tray: {}", if tray_active { "running" } else { "stopped" });
    }

    Ok(())
}

/// Whether the installed unit file's `ExecStart` line includes `flag` — since that's the one
/// place a running service's settings live (see `service.rs`), this is how `gratis status`
/// shows what a service was actually started with, without the user needing to grep the unit
/// file by hand. `false` (not an error) if the unit can't be read at all.
fn unit_has_flag(flag: &str) -> bool {
    service::exec_start_line().is_some_and(|line| line.contains(flag))
}

/// Reads the control port out of the installed unit file's `ExecStart` line rather than
/// hardcoding the default — `up` can be given a non-default `--control-port`. Falls back to
/// 9000 (the default) if the unit isn't installed or the line can't be parsed.
fn control_port_from_unit() -> u16 {
    service::exec_start_line()
        .and_then(|line| line.split("--control-port").nth(1).map(str::to_string))
        .and_then(|rest| rest.split_whitespace().next().map(str::to_string))
        .and_then(|p| p.parse().ok())
        .unwrap_or(9000)
}

async fn health() -> anyhow::Result<gratis::api::HealthStatus> {
    let port = control_port_from_unit();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reqwest::get(format!("http://127.0.0.1:{port}/api/health")),
    )
    .await
    .context("timed out waiting for the control API to respond")??;
    Ok(response.json().await?)
}

fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((user, domain)) if !user.is_empty() => {
            format!("{}***@{domain}", &user[..1])
        }
        _ => "***".to_string(),
    }
}

/// Shows the daemon's (and its tray's) systemd journal — exactly what `journalctl --user -u
/// gratis -u gratis-tray` would, since that's what this runs. Not a re-implementation of log
/// viewing: journald already does retention, filtering, and (with `--watch`) following, so this
/// is just a shorter, memorable way to reach it without knowing the unit names.
fn cmd_logs(watch: bool) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new("journalctl");
    cmd.args(["--user", "-u", "gratis", "-u", "gratis-tray"]);
    if watch {
        cmd.arg("-f");
    } else {
        // Bounded by default (unlike a bare `journalctl -u ...`, which prints the unit's
        // entire retained history) — recent context is almost always what you actually want;
        // `--watch` or a raw `journalctl` invocation are both still there for everything else.
        cmd.args(["-n", "200"]);
    }
    let status = cmd
        .status()
        .context("failed to run journalctl (is systemd/journald installed?)")?;
    if !status.success() {
        anyhow::bail!("journalctl exited with {status}");
    }
    Ok(())
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

/// `Some((email, password))` only when a `.env` in the current directory has *both* keys — a
/// partial pair (e.g. `EMAIL` set but not `PASSWORD`) is treated the same as neither being set,
/// since half a credential pair can't log in either way.
fn read_dotenv_credentials() -> Option<(String, String)> {
    let path = std::path::Path::new(".env");
    let email = read_dotenv_var(path, "EMAIL")?;
    let password = read_dotenv_var(path, "PASSWORD")?;
    Some((email, password))
}

/// Resume the stored session (or fall back to a `.env`) and populate `manager`'s server list.
/// Split out of `cmd_run` so it can run *concurrently* with the control API instead of
/// blocking the listener bind — this is a real ~15-20s network round trip (session-resume:
/// fetch_servers + certificate minting) against Proton's live API, during which `gratis
/// status`'s HTTP probe would otherwise see "connection refused" even though the service is
/// genuinely starting up correctly (confirmed live: `systemctl` marks a `Type=simple` unit
/// active the instant the process starts, with no readiness signal, so there's no way to
/// distinguish "still starting" from "broken" without the port already being open).
///
/// Returns the session actually in use, if any — the periodic refresh loop in `cmd_run` needs
/// it to re-authenticate later (see `TunnelManager::renew_credentials`). `None` when this
/// process has no session to fall back on (the `.env`-credentials path, or no credentials at
/// all): the daemon can still run, but a later token expiry has no automatic recovery for it —
/// only `gratis login` supplies a re-authenticatable session.
async fn resume_or_login(manager: Arc<TunnelManager>, control_port: u16) -> Option<Session> {
    match session::load_async().await {
        Ok(Some(session)) => match manager.login_with_session(&session).await {
            Ok(updated) => {
                if updated.access_token != session.access_token {
                    // The stored access token had expired and got refreshed — persist the new
                    // one so the next `run` doesn't have to refresh again immediately.
                    if let Err(err) = session::store_async(updated.clone()).await {
                        log::warn!("failed to persist refreshed session: {err}");
                    }
                }
                let count = manager.servers().len();
                log::info!("resumed session ({}), {count} servers ready", session.email);
                manager.set_auth_error(None);
                Some(updated)
            }
            Err(err) => {
                log::warn!("stored session is no longer valid ({err}) — run `gratis login` again");
                manager.set_auth_error(Some(format!(
                    "stored session is no longer valid: {err} — run `gratis login` again"
                )));
                gratis::notify::notify_clickable(
                    "gratis: session expired",
                    "Run `gratis login` again to reconnect. Click to open the dashboard.",
                    &format!("http://127.0.0.1:{control_port}/"),
                );
                None
            }
        },
        Ok(None) => {
            // No stored session — fall back to a `.env` in the current directory, matching
            // the daemon's original (pre-CLI) behavior. Off the async runtime for the same
            // reason as `session::load_async` — `std::fs::read_to_string` blocks the only
            // worker thread on a `current_thread` runtime, freezing every live relay/the
            // control API for however long that read takes.
            let dotenv_creds = tokio::task::spawn_blocking(read_dotenv_credentials)
                .await
                .unwrap_or(None);
            match dotenv_creds {
                Some((email, password)) => match manager.login(&email, &password).await {
                    Ok(()) => {
                        let count = manager.servers().len();
                        log::info!("logged in from .env ({email}), {count} servers ready");
                        manager.set_auth_error(None);
                    }
                    Err(err) => {
                        log::warn!("login from .env failed: {err}");
                        manager.set_auth_error(Some(format!("login from .env failed: {err}")));
                    }
                },
                None => {
                    let msg = "no stored session and no .env (EMAIL + PASSWORD) — run \
                                `gratis login`";
                    log::warn!("{msg}");
                    manager.set_auth_error(Some(msg.to_string()));
                }
            }
            // The `.env` path never produces a re-authenticatable `Session` (no refresh
            // token/UID pair is minted for it) — the periodic loop has nothing to renew with.
            None
        }
        Err(err) => {
            log::warn!("failed to read stored session ({err}), starting with no servers");
            manager.set_auth_error(Some(format!("failed to read stored session: {err}")));
            None
        }
    }
}

async fn cmd_run(
    control_port: u16,
    port_range_start: u16,
    unlimited_connections: bool,
    evict_lru: bool,
    http_proxy: bool,
) -> anyhow::Result<()> {
    let protocol = if http_proxy {
        gratis::manager::ProxyProtocol::Http
    } else {
        gratis::manager::ProxyProtocol::Socks5
    };
    let manager = Arc::new(TunnelManager::new(
        port_range_start,
        unlimited_connections,
        evict_lru,
        protocol,
    ));

    // Bind and start serving *before* logging in — see `resume_or_login`'s doc comment for
    // why. `manager` starts with an empty server list, which the web UI and `/api/servers`
    // already render as a normal (not error) empty state.
    let router = api::router(manager.clone());

    let addr = format!("127.0.0.1:{control_port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(err) => {
            log::warn!("failed to bind {addr}: {err}");
            gratis::notify::notify(
                "gratis: failed to start",
                &format!("Could not bind {addr}: {err}"),
            );
            std::process::exit(1);
        }
    };

    log::info!("control API + web UI listening on http://{addr}");
    log::info!("per-server listeners speak {protocol:?} (pass --http-proxy for HTTP CONNECT)");

    // One task: the initial login/session-resume, then (whether or not it succeeded — a
    // stored session can still be fixed later by a fresh `gratis login` elsewhere) periodic
    // re-fetches so a long-running daemon's server list doesn't go stale — see
    // SERVER_LIST_REFRESH_INTERVAL's doc comment for why this matters (load numbers frozen
    // at login time, new servers invisible, removed servers left dangling forever without
    // it — confirmed gaps, not theoretical).
    tokio::spawn({
        let manager = manager.clone();
        async move {
            let mut session = resume_or_login(manager.clone(), control_port).await;
            let mut last_cred_renewal = std::time::Instant::now();

            let mut interval = tokio::time::interval(gratis::manager::SERVER_LIST_REFRESH_INTERVAL);
            interval.tick().await; // first tick fires immediately; the line above just refreshed.
            loop {
                interval.tick().await;

                // Proactively rotate the WireGuard certificate before its fixed 168-minute
                // lifetime runs out, rather than waiting to discover it's dead the next time a
                // slot tries to connect — see `CREDENTIAL_RENEWAL_INTERVAL`'s doc comment.
                if let Some(current) = &session
                    && last_cred_renewal.elapsed() >= gratis::manager::CREDENTIAL_RENEWAL_INTERVAL
                {
                    match manager.renew_credentials(current).await {
                        Ok(updated) => {
                            if updated.access_token != current.access_token
                                && let Err(err) = session::store_async(updated.clone()).await
                            {
                                log::warn!("failed to persist renewed session: {err}");
                            }
                            session = Some(updated);
                            last_cred_renewal = std::time::Instant::now();
                            log::info!("proactively renewed WireGuard certificate/credentials");
                        }
                        Err(err) => {
                            log::warn!("proactive credential renewal failed ({err})");
                        }
                    }
                }

                let was_broken = manager.auth_error().is_some();
                let mut result = manager.refresh_servers().await;

                // The access token (or the WireGuard certificate `finish_login`/
                // `login_with_session` minted) can lapse on a daemon meant to run for weeks —
                // without this, a single expiry permanently degrades `gratis run` to "logged in:
                // NO" until a human re-runs `gratis login` (see error_handling.md F1/F2). Only
                // possible when this process actually resumed a `Session` (not the `.env`
                // fallback, which has no refresh token to re-authenticate with).
                if let (Err(ProtonError::Auth), Some(current)) = (&result, &session) {
                    log::warn!("periodic refresh hit an expired token; re-authenticating...");
                    match manager.renew_credentials(current).await {
                        Ok(updated) => {
                            if updated.access_token != current.access_token
                                && let Err(err) = session::store_async(updated.clone()).await
                            {
                                log::warn!("failed to persist renewed session: {err}");
                            }
                            session = Some(updated);
                            last_cred_renewal = std::time::Instant::now();
                            log::info!("re-authenticated successfully; retrying server refresh");
                            result = manager.refresh_servers().await;
                        }
                        Err(err) => {
                            log::warn!(
                                "re-authentication failed ({err}) — stored session is likely \
                                 no longer valid; run `gratis login` again"
                            );
                        }
                    }
                }

                match result {
                    Ok(()) => {
                        if was_broken {
                            // Loud on the way back up, not just the way down — a silent
                            // recovery is just as confusing to debug live as a silent failure:
                            // `gratis status` would keep showing the old error indefinitely
                            // with nothing in the log explaining when or why it cleared.
                            log::info!(
                                "periodic server-list refresh succeeded, {} server(s) ready — \
                                 auth problem has cleared",
                                manager.servers().len()
                            );
                        }
                        manager.set_auth_error(None);
                    }
                    Err(err) => {
                        log::warn!(
                            "periodic server-list refresh failed ({err}); keeping the existing \
                             list until the next attempt"
                        );
                        // Don't clobber a more specific pre-existing error (e.g. "stored session
                        // is no longer valid — run `gratis login` again") with this refresh's
                        // own diagnostic — that's often just "never logged in successfully in
                        // the first place", which is less actionable than what's already there.
                        if manager.auth_error().is_none() {
                            manager.set_auth_error(Some(format!(
                                "periodic server-list refresh failed: {err}"
                            )));
                        }
                    }
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
                        log::warn!(
                            "periodic update check failed ({err}); will retry next interval"
                        );
                    }
                }
            }
        }
    });

    tokio::select! {
        result = axum::serve(listener, router) => {
            if let Err(err) = result {
                log::error!("server error: {err}");
                std::process::exit(1);
            }
        }
        signal_result = tokio::signal::ctrl_c() => {
            if let Err(err) = signal_result {
                log::warn!("failed to install Ctrl-C handler: {err}");
                return Ok(());
            }
            log::info!("received shutdown signal, exiting");
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
