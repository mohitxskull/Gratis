//! CLI entry point. Subcommands are wired to stubs in Task 01; real behavior lands in
//! Tasks 02-04. Reference for the intended flow: <https://github.com/ProtonVPN/proton-vpn-cli>
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "proton-proxy", about = "Proton VPN client (WireGuard)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Authenticate and store credentials to a file.
    Login { email: String, password: String },
    /// Connect to the fastest server (or by country code).
    Connect { country: Option<String> },
    /// Disconnect the active tunnel.
    Disconnect,
    /// List available servers.
    Servers { country: Option<String> },
    /// Show tunnel status.
    Status,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Login { .. } => println!("[stub] login: not implemented (Task 02/04)"),
        Command::Connect { .. } => println!("[stub] connect: not implemented (Task 03/04)"),
        Command::Disconnect => println!("[stub] disconnect: not implemented (Task 03/04)"),
        Command::Servers { .. } => println!("[stub] servers: not implemented (Task 02/04)"),
        Command::Status => println!("[stub] status: not implemented (Task 04)"),
    }
}
