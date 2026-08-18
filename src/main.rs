//! `gratis` daemon entry point. No CLI subcommands: a single `serve`-style entrypoint that
//! starts the localhost control API + embedded web UI. There is no login route or login form —
//! authentication happens exactly once, automatically, from a `.env` file in the current
//! directory (`EMAIL=...` / `PASSWORD=...`, read literally with no shell interpretation) at
//! startup. Credentials are never accepted as CLI arguments (they'd leak into `ps`/shell
//! history), and nothing is persisted to disk — a fresh login (and a fresh port assignment for
//! every free-tier server) happens on every start.
//!
//! Runs entirely unprivileged: tunnels are in-process userspace WireGuard sessions (see
//! `wireguard.rs`), not real kernel interfaces, so there is nothing here to reconcile at boot
//! or tear down at shutdown beyond normal process exit — a tunnel cannot outlive the process
//! that holds it.
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

    /// First port handed out to the free-tier server list — each server gets a fixed port of
    /// its own, one more than the last, in a stable order. Connecting a SOCKS5 client to a
    /// server's port lazily brings its tunnel up; see `manager.rs`.
    #[arg(long, default_value = "20000")]
    port_range_start: u16,
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

    let manager = Arc::new(TunnelManager::new(cli.port_range_start));

    // Auto-login from `.env` in the current directory, if present — the common "just run it"
    // path. Logging in also assigns every free-tier server its port and spawns its listener
    // (see `TunnelManager::login`), so nothing further is needed to make the daemon usable.
    let dotenv_path = std::path::Path::new(".env");
    let dotenv_creds = (
        read_dotenv_var(dotenv_path, "EMAIL"),
        read_dotenv_var(dotenv_path, "PASSWORD"),
    );
    match dotenv_creds {
        (Some(email), Some(password)) => match manager.login(&email, &password).await {
            Ok(()) => {
                let count = manager.servers().len();
                println!(
                    "gratis: logged in automatically from .env ({email}), {count} servers ready"
                );
            }
            Err(err) => {
                eprintln!("gratis: auto-login from .env failed: {err}");
            }
        },
        (Some(_), None) | (None, Some(_)) => {
            eprintln!("gratis: .env found but must set both EMAIL and PASSWORD; ignoring it");
        }
        (None, None) => {
            eprintln!(
                "gratis: no .env (EMAIL + PASSWORD) found — no servers can be listed or connected to until one is present at startup"
            );
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
            eprintln!("gratis: received shutdown signal, exiting");
        }
    }
}
