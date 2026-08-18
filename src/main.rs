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

/// Boot reconciliation (finding #3, part 1): a previous process's `active_tunnels` rows may be
/// stale — the daemon doesn't persist a session token, so a restart can never "adopt" a live
/// tunnel back into a running SOCKS5 proxy anyway (see the design-decision doc comment on
/// `manager::TunnelManager`), and a hard kill (SIGKILL, power loss) leaves both the WireGuard
/// interface up and the DB row behind with nothing tracking either. So reconciling at startup
/// here means *cleaning up*, not resuming: for each persisted row, tear down the interface if
/// it's still up, then clear the row. Synchronous/blocking (shells to `wg`/`wg-quick`), so the
/// caller runs it inside `spawn_blocking`.
fn reconcile_boot_state() {
    let active = match proton_proxy::credentials::list_active() {
        Ok(rows) => rows,
        Err(err) => {
            eprintln!("proton-proxy: failed to read active-tunnel state at boot: {err}");
            return;
        }
    };

    for row in active {
        if proton_proxy::wireguard::is_up(&row.interface) {
            eprintln!(
                "proton-proxy: found interface {} (location {}) still up from a previous run; tearing it down",
                row.interface, row.location
            );
            if let Err(err) = proton_proxy::wireguard::down(&row.interface) {
                eprintln!(
                    "proton-proxy: failed to tear down stale interface {} for location {}: {err} (leaving its active_tunnels row for a future retry)",
                    row.interface, row.location
                );
                continue;
            }
        } else {
            eprintln!(
                "proton-proxy: clearing stale active_tunnels row for location {} (interface {} already down)",
                row.location, row.interface
            );
        }

        if let Err(err) = proton_proxy::credentials::clear_active(&row.location) {
            eprintln!(
                "proton-proxy: failed to clear stale active-tunnel row for location {}: {err}",
                row.location
            );
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(err) = tokio::task::spawn_blocking(reconcile_boot_state).await {
        eprintln!("proton-proxy: boot reconciliation task panicked: {err}");
    }

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

    let router = api::router(manager.clone());

    let addr = format!("127.0.0.1:{}", cli.control_port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(err) => {
            eprintln!("proton-proxy: failed to bind {addr}: {err}");
            std::process::exit(1);
        }
    };

    println!("proton-proxy: control API + web UI listening on http://{addr}");

    // Shutdown teardown (finding #3, part 2): without this, killing the daemon (Ctrl-C/
    // SIGTERM) leaves every WireGuard interface up and every `active_tunnels` row stale — the
    // machine keeps routing tunnel traffic with no proxy listening on it, and the next boot's
    // `reconcile_boot_state` above is the only thing that would ever clean it up. Catching
    // SIGINT via `tokio::signal::ctrl_c()` and tearing down every tracked tunnel before
    // exiting closes that gap for the common "Ctrl-C" / graceful-stop case.
    //
    // This deliberately does not also install a SIGTERM handler (`tokio::signal::ctrl_c()`
    // only catches SIGINT) — a first pass sufficient per the review's own scope; a process
    // killed via SIGTERM (e.g. `systemctl stop`/`kill` without `-INT`) still relies on
    // `reconcile_boot_state` at the next boot.
    tokio::select! {
        result = axum::serve(listener, router) => {
            if let Err(err) = result {
                eprintln!("proton-proxy: server error: {err}");
                std::process::exit(1);
            }
        }
        signal_result = tokio::signal::ctrl_c() => {
            if let Err(err) = signal_result {
                eprintln!("proton-proxy: failed to install Ctrl-C handler: {err}");
                return;
            }
            eprintln!("proton-proxy: received shutdown signal, tearing down tracked tunnels...");
            for info in manager.tunnels() {
                if let Err(err) = manager.stop(&info.location).await {
                    eprintln!(
                        "proton-proxy: failed to stop tunnel for location {}: {err}",
                        info.location
                    );
                }
            }
            eprintln!("proton-proxy: shutdown teardown complete");
        }
    }
}
