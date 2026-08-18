//! Throwaway, non-committed verification script: logs in with real credentials from
//! EMAIL/PASSWORD env vars, then reports ONLY non-sensitive derived data (never the
//! certificate, private key, tokens, or password). Not part of the crate's public
//! surface or plan; delete after use.
use proton_proxy::client::ProtonVPNClient;

/// Read KEY=value lines directly from `.env`, with NO shell interpretation — a previous
/// attempt at sourcing this file through bash mangled the password (bash unquoted-word
/// expansion ate a literal backslash and expanded `$jin` as an empty, unset shell variable).
fn read_env_file_var(key: &str) -> String {
    let content =
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"))
            .expect("failed to read .env");
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}=")) {
            return rest.to_string();
        }
    }
    panic!("{key} not found in .env");
}

#[tokio::main]
async fn main() {
    let email = read_env_file_var("EMAIL");
    let password = read_env_file_var("PASSWORD");

    let mut client = ProtonVPNClient::new(&email);
    println!("logging in...");
    match client.login(&email, &password).await {
        Ok(creds) => {
            println!("login: OK");
            println!("username: {}", creds.username);
            println!("certificate length: {} bytes", creds.certificate.len());
            println!("certificate_expires_at: {}", creds.certificate_expires_at);
            println!("wg_public_key length: {} chars", creds.wg_public_key.len());
            println!("wg_public_key: {}", creds.wg_public_key);

            match client.fetch_servers().await {
                Ok(()) => {
                    println!("fetch_servers: OK, {} servers", client.server_list.len());
                    if let Some(s) = client.server_list.first() {
                        let physical = s.pick_physical();
                        println!(
                            "sample server: name={} country={} tier={} load={} physical_count={} picked_ip={:?} picked_key_len={:?} key==ip? {}",
                            s.name,
                            s.country,
                            s.tier,
                            s.load,
                            s.physical.len(),
                            physical.map(|p| p.entry_ip.as_str()),
                            physical.map(|p| p.x25519_public_key.len()),
                            physical.is_some_and(|p| p.entry_ip == p.x25519_public_key),
                        );

                        if let Some(server) = client
                            .server_list
                            .iter()
                            .find(|s| s.country_code.eq_ignore_ascii_case("US"))
                        {
                            match proton_proxy::wireguard::generate_config(
                                server,
                                &creds,
                                &proton_proxy::wireguard::interface_name("US"),
                            ) {
                                Ok(cfg) => {
                                    // Print only the shape, never the private key line.
                                    let safe: Vec<&str> = cfg
                                        .lines()
                                        .filter(|l| !l.starts_with("PrivateKey"))
                                        .collect();
                                    println!("generate_config (PrivateKey redacted):");
                                    for l in safe {
                                        println!("  {l}");
                                    }
                                }
                                Err(e) => println!("generate_config FAILED: {e}"),
                            }
                        }
                    }
                }
                Err(e) => println!("fetch_servers FAILED: {e}"),
            }
        }
        Err(e) => println!("login FAILED: {e}"),
    }
}
