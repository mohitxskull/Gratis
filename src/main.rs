//! `gratis` daemon entry point. No CLI subcommands: a single `serve`-style entrypoint
//! that starts the localhost control API + embedded web UI, optionally pre-starting a list of
//! locations passed via `--locations`. There is no login route or login form — authentication
//! happens exactly once, automatically, from a `.env` file in the current directory
//! (`EMAIL=...` / `PASSWORD=...`, read literally with no shell interpretation) at startup.
//! Credentials are never accepted as CLI arguments (they'd leak into `ps`/shell history).
//!
//! Runs entirely unprivileged: tunnels are in-process userspace WireGuard sessions (see
//! `wireguard.rs`), not real kernel interfaces, so there is nothing here to reconcile at boot
//! or tear down at shutdown beyond normal process exit — a tunnel cannot outlive the process
//! that holds it. `active_tunnels` rows from a previous run are therefore always stale (no
//! process restart can "adopt" a tunnel that necessarily died with its process), so they're
//! cleared unconditionally on startup, not reconciled against any live external state.
use clap::Parser;
use gratis::api;
use gratis::manager::TunnelManager;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "gratis", about = "Proton VPN client (WireGuard) daemon")]
struct Cli {
    /// Port the localhost control API + web UI listen on.
    #[arg(long, default_value = "9000")]
    control_port: u16,

    /// Base SOCKS5 port; each started location gets `socks_base_port + index`.
    #[arg(long, default_value = "1080")]
    socks_base_port: u16,

    /// Comma-separated location (country) codes to start immediately at boot, e.g. `US,NL`.
    #[arg(long, value_delimiter = ',')]
    locations: Vec<String>,
}

/// Clear any `active_tunnels` rows left over from a previous run. They're always stale: a
/// tunnel is in-process state that cannot survive its process exiting, so there is nothing to
/// reconcile against — unlike the old `sudo wg-quick`-based design, no kernel interface could
/// have outlived the previous process for this to check against.
fn clear_stale_active_tunnels() {
    let active = match gratis::credentials::list_active() {
        Ok(rows) => rows,
        Err(err) => {
            eprintln!("gratis: failed to read active-tunnel state at boot: {err}");
            return;
        }
    };

    for row in active {
        eprintln!(
            "gratis: clearing stale active_tunnels row for location {} (from a previous run)",
            row.location
        );
        if let Err(err) = gratis::credentials::clear_active(&row.location) {
            eprintln!(
                "gratis: failed to clear stale active-tunnel row for location {}: {err}",
                row.location
            );
        }
    }
}

/// Read `KEY=value` lines directly from a `.env` file, with NO shell interpretation — sourcing
/// a `.env` through a shell (`source .env`) can mangle values containing `\`, `$`, `#`, etc.
/// (verified: it silently dropped a backslash and expanded an unset `$var` in a real password
/// during development). Returns `None` if the file doesn't exist; missing keys inside an
/// existing file are also `None` for that key.
fn read_dotenv_var(path: &std::path::Path, key: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    content
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")).map(|v| v.to_string()))
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    clear_stale_active_tunnels();

    let manager = Arc::new(TunnelManager::new(cli.socks_base_port));

    // Auto-login from `.env` in the current directory, if present — the common "just run it"
    // path. Restore-on-startup from *saved* credentials (below) still can't work (no session
    // token or server list is persisted — see the design-decision doc comment on
    // `manager.rs`/`TunnelManager`), but re-deriving a fresh login from `.env` on every start
    // sidesteps that limitation entirely for anyone willing to keep a `.env` next to the
    // binary.
    let dotenv_path = std::path::Path::new(".env");
    let dotenv_creds = (
        read_dotenv_var(dotenv_path, "EMAIL"),
        read_dotenv_var(dotenv_path, "PASSWORD"),
    );
    let logged_in_from_dotenv = match dotenv_creds {
        (Some(email), Some(password)) => match manager.login(&email, &password).await {
            Ok(()) => {
                println!("gratis: logged in automatically from .env ({email})");
                true
            }
            Err(err) => {
                eprintln!("gratis: auto-login from .env failed: {err}");
                false
            }
        },
        (Some(_), None) | (None, Some(_)) => {
            eprintln!("gratis: .env found but must set both EMAIL and PASSWORD; ignoring it");
            false
        }
        (None, None) => false,
    };

    // Saved credentials (from a *previous* run's .env login) are informational only when
    // .env didn't just log us in — see the module doc comment on why this can't drive an
    // unattended restore on its own. With no login route, a missing/incomplete `.env` means
    // no tunnel can ever be started this run.
    if !logged_in_from_dotenv {
        if manager.has_saved_credentials() {
            eprintln!(
                "gratis: found saved credentials from a previous run, but no valid .env this time — no tunnel can be started until a valid .env (EMAIL + PASSWORD) is present at startup"
            );
        } else {
            eprintln!(
                "gratis: no .env (EMAIL + PASSWORD) found — no tunnel can be started until one is present at startup"
            );
        }
    }

    // Attempt to pre-start each requested location. Succeeds immediately if .env just logged
    // us in; otherwise fails with "not logged in" (no login route exists to fix this after
    // the fact — restart with a valid .env). Per the brief: a failure here must never crash
    // the daemon.
    for location in &cli.locations {
        if let Err(err) = manager.start(location).await {
            eprintln!("gratis: failed to pre-start location {location}: {err}");
        }
    }

    let router = api::router(manager.clone());

    let addr = format!("127.0.0.1:{}", cli.control_port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(err) => {
            eprintln!("gratis: failed to bind {addr}: {err}");
            std::process::exit(1);
        }
    };

    println!("gratis: control API + web UI listening on http://{addr}");
    println!("gratis: running unprivileged — no root/sudo required");

    // Ctrl-C stops tracked tunnels before exiting, purely so `GET /api/tunnels` and the
    // active_tunnels DB rows reflect reality if something outlives the process shutdown
    // sequence briefly (e.g. a slow disk flush) — not required for correctness, since process
    // exit alone already reclaims every tunnel's memory/sockets.
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
                return;
            }
            eprintln!("gratis: received shutdown signal, stopping tracked tunnels...");
            for info in manager.tunnels() {
                if let Err(err) = manager.stop(&info.location).await {
                    eprintln!(
                        "gratis: failed to stop tunnel for location {}: {err}",
                        info.location
                    );
                }
            }
            eprintln!("gratis: shutdown complete");
        }
    }
}
