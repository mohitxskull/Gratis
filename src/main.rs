//! `proton-proxy` daemon entry point. No CLI subcommands: a single `serve`-style entrypoint
//! that starts the localhost control API + embedded web UI, optionally pre-starting a list of
//! locations passed via `--locations`. Authentication happens through `POST /api/login` (or
//! the web UI's login form), never via CLI arguments.
use clap::Parser;
use proton_proxy::api;
use proton_proxy::manager::TunnelManager;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "proton-proxy", about = "Proton VPN client (WireGuard) daemon")]
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let manager = Arc::new(TunnelManager::new(cli.socks_base_port));

    // Restore-on-startup: saved credentials (if any) cannot alone drive a fresh server list
    // or an authenticated session (see the design-decision doc comment on
    // `manager.rs`/`TunnelManager`), so we only report their presence here; a real login via
    // `POST /api/login` (or the web UI) is still required before `--locations` pre-start can
    // succeed.
    if manager.has_saved_credentials() {
        eprintln!(
            "proton-proxy: found saved credentials, but a fresh login (POST /api/login or the web UI) is still required to fetch a server list before any tunnel can be started"
        );
    }

    // Attempt to pre-start each requested location. With no persisted session token (see the
    // restore-on-startup note above), this will fail with "not logged in" until a login
    // happens through the API/UI unless a previous call already populated the in-process
    // client (it can't have, this early) — so today this loop effectively always logs and
    // moves on. It's kept as a real attempt (not skipped outright) so that if a future task
    // adds session-token persistence, pre-start starts working with no changes here. Per the
    // brief: a failure here must never crash the daemon.
    for location in &cli.locations {
        if let Err(err) = manager.start(location).await {
            eprintln!("proton-proxy: failed to pre-start location {location}: {err}");
        }
    }

    let router = api::router(manager);

    let addr = format!("127.0.0.1:{}", cli.control_port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(err) => {
            eprintln!("proton-proxy: failed to bind {addr}: {err}");
            std::process::exit(1);
        }
    };

    println!("proton-proxy: control API + web UI listening on http://{addr}");

    if let Err(err) = axum::serve(listener, router).await {
        eprintln!("proton-proxy: server error: {err}");
        std::process::exit(1);
    }
}
