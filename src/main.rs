//! `gratis` CLI entry point. `login`/`logout`/`up`/`down`/`status`/`persist`/`update`/
//! `uninstall` manage gratis as an installed systemd `--user` service; `run` is the actual
//! foreground daemon (today's control API + web UI), invoked by the unit's `ExecStart`, not
//! meant to be run directly by a user.
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
#[command(name = "gratis", version, about = "Proton VPN (free tier) client")]
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
        /// First port handed out to the free-tier server list.
        #[arg(long, default_value = "20000")]
        port_range_start: u16,
        /// Don't cap simultaneous server tunnels at the account's Proton MaxConnect limit.
        /// gratis's "any number of servers at once" design otherwise stays within what the
        /// account is actually allowed to run concurrently — only bypass this if you
        /// understand and accept the ToS risk of exceeding it.
        #[arg(long)]
        unlimited_connections: bool,
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
    },
}

#[tokio::main]
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
        } => cmd_up(control_port, port_range_start, unlimited_connections),
        Command::Down => cmd_down(),
        Command::Status => cmd_status().await,
        Command::Persist { off } => cmd_persist(off),
        Command::Update => cmd_update().await,
        Command::Uninstall => cmd_uninstall(),
        Command::Run {
            control_port,
            port_range_start,
            unlimited_connections,
        } => cmd_run(control_port, port_range_start, unlimited_connections).await,
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
    session::delete()?;
    println!("gratis: logged out");
    Ok(())
}

fn cmd_up(
    control_port: u16,
    port_range_start: u16,
    unlimited_connections: bool,
) -> anyhow::Result<()> {
    if session::load()?.is_none() {
        anyhow::bail!("not logged in — run `gratis login` first");
    }
    service::install(control_port, port_range_start, unlimited_connections)?;
    service::start()?;
    println!("gratis: service starting — see `gratis status`");
    Ok(())
}

fn cmd_down() -> anyhow::Result<()> {
    if !service::is_installed()? {
        anyhow::bail!("service not installed — run `gratis up` first");
    }
    service::stop()?;
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
    Ok(())
}

/// Reads the control port out of the installed unit file's `ExecStart` line rather than
/// hardcoding the default — `up` can be given a non-default `--control-port`.
async fn server_count() -> anyhow::Result<(usize, String)> {
    let unit = std::fs::read_to_string(service::unit_path()?)?;
    let port: u16 = unit
        .lines()
        .find_map(|l| l.split("--control-port").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|p| p.parse().ok())
        .unwrap_or(9000);
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
        println!("gratis: will not start automatically on login");
    } else {
        service::enable()?;
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
        }
    }
    Ok(())
}

fn cmd_uninstall() -> anyhow::Result<()> {
    print!("This removes the gratis service, stored login, and this binary. Continue? [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !answer.trim().eq_ignore_ascii_case("y") {
        println!("aborted");
        return Ok(());
    }

    service::uninstall()?;
    session::delete()?;

    let exe = std::env::current_exe()?;
    println!("gratis: removing {}", exe.display());
    std::fs::remove_file(&exe)?;

    println!("gratis: uninstalled");
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

async fn cmd_run(
    control_port: u16,
    port_range_start: u16,
    unlimited_connections: bool,
) -> anyhow::Result<()> {
    let manager = Arc::new(TunnelManager::new(port_range_start, unlimited_connections));

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

    let router = api::router(manager.clone());

    let addr = format!("127.0.0.1:{control_port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(err) => {
            eprintln!("gratis: failed to bind {addr}: {err}");
            std::process::exit(1);
        }
    };

    println!("gratis: control API + web UI listening on http://{addr}");

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
