//! `gratis update`: downloads the latest GitHub Release tarball for the running platform and
//! replaces the installed binary in place. No package manager, no external updater tool.
use crate::errors::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const REPO: &str = "mohitxskull/Gratis";

/// Ed25519 public key that every release tarball's detached signature (`<asset>.sig`, produced
/// by `.github/workflows/release.yml`'s signing step) must verify against. The matching private
/// key lives only in the `RELEASE_SIGNING_KEY` GitHub Actions secret — it never touches this
/// repo. Without this check, `gratis update` would trust and execute whatever bytes a
/// compromised GitHub account/release/CDN handed back (a supply-chain RCE waiting to happen).
const RELEASE_SIGNING_PUBLIC_KEY: [u8; 32] =
    hex_literal(b"7bda6f23a8efd54a301e55b34f320aca5e84039ed13cd872ef52595e61d3a917");

const fn hex_literal(hex: &[u8]) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex digit in RELEASE_SIGNING_PUBLIC_KEY"),
        }
    }
    if hex.len() != 64 {
        panic!("RELEASE_SIGNING_PUBLIC_KEY must be exactly 64 hex chars (32 bytes)");
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]);
        i += 1;
    }
    out
}

/// How often `gratis run` checks GitHub for a newer release and, if one exists, fires a
/// desktop notification. Deliberately never downloads or applies anything on its own — see
/// `check_for_update`'s doc comment for why auto-*applying* is out of scope.
pub const UPDATE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

pub enum UpdateOutcome {
    AlreadyLatest { version: String },
    Updated { from: String, to: String },
}

/// Current platform's release-tarball target triple. Only the two triples the release
/// workflow actually builds (see `.github/workflows/release.yml`) are supported.
fn target_triple() -> Result<&'static str> {
    triple_for_arch(std::env::consts::ARCH)
}

/// `target_triple`'s logic, parameterized on the arch string so it's testable without
/// depending on the architecture the test suite happens to run on.
fn triple_for_arch(arch: &str) -> Result<&'static str> {
    match arch {
        "x86_64" => Ok("x86_64-unknown-linux-gnu"),
        "aarch64" => Ok("aarch64-unknown-linux-gnu"),
        other => Err(ProtonError::Config(format!(
            "no release build for architecture {other}"
        ))),
    }
}

/// `println!` a stage-progress line and flush immediately — see `run`'s doc comment on why
/// the flush matters here specifically.
fn print_progress(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

/// Fetch the latest GitHub release's metadata. Shared by `run` (which needs the asset list to
/// download) and `check_for_update` (which only needs the version).
async fn fetch_latest_release() -> Result<Release> {
    // Without a timeout, a stalled GitHub connection (or a MITM/proxy that never responds)
    // hangs this call forever. check_for_update runs from the daemon's periodic task
    // (main.rs) inside a loop with no other timeout of its own — a hang here would silently
    // stop all future update checks for the rest of the process's life.
    let client = reqwest::Client::builder()
        .user_agent("gratis-updater")
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let release: Release = client
        .get(format!(
            "https://api.github.com/repos/{REPO}/releases/latest"
        ))
        .send()
        .await?
        .json()
        .await?;
    Ok(release)
}

/// Check whether a newer release exists, without downloading or installing anything. Returns
/// the newer version string (without the leading `v`), or `None` if already current.
///
/// Deliberately check-only: `gratis run` polls this periodically and, on `Some`, fires a
/// desktop notification pointing at `gratis update` — it never applies the update itself.
/// Auto-*applying* would mean silently replacing the binary and restarting the service (the
/// proxy) out from under whatever's actively using it, with no warning, on a tool that holds
/// your VPN credentials. That's a materially different (and worse) trust/disruption trade-off
/// than a notification, so it stays a manual, deliberate `gratis update` run.
pub async fn check_for_update() -> Result<Option<String>> {
    let current = env!("CARGO_PKG_VERSION");
    let release = fetch_latest_release().await?;
    let latest = release.tag_name.trim_start_matches('v').to_string();
    if latest == current {
        Ok(None)
    } else {
        Ok(Some(latest))
    }
}

pub async fn run() -> Result<UpdateOutcome> {
    let current = env!("CARGO_PKG_VERSION").to_string();

    // Each of these stages is a network round-trip or a multi-hundred-KB download with no
    // other output in between — printing before each one is the difference between "gratis
    // update looks stuck" and a visible progression. An explicit flush after each line: Rust's
    // stdout is only line-buffered when attached to a terminal — piped/redirected (e.g. into a
    // log file) it's block-buffered, so without this a line could sit unflushed for the whole
    // multi-second step it's describing.
    print_progress("gratis: checking for updates...");
    // Longer than `fetch_latest_release`'s 15s — this client also downloads the tarball/sig
    // (multi-hundred-KB), which needs more headroom than a metadata fetch, but still bounded
    // rather than hanging forever on a stalled connection.
    let client = reqwest::Client::builder()
        .user_agent("gratis-updater")
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let release = fetch_latest_release().await?;
    let latest = release.tag_name.trim_start_matches('v').to_string();

    if latest == current {
        return Ok(UpdateOutcome::AlreadyLatest { version: current });
    }

    let target = target_triple()?;
    let asset = release
        .assets
        .iter()
        .find(|a| a.name.contains(target) && a.name.ends_with(".tar.gz"))
        .ok_or_else(|| {
            ProtonError::Config(format!(
                "release {} has no tarball for {target}",
                release.tag_name
            ))
        })?;
    let sig_name = format!("{}.sig", asset.name);
    let sig_asset = release
        .assets
        .iter()
        .find(|a| a.name == sig_name)
        .ok_or_else(|| {
            ProtonError::Config(format!(
                "release {} has no {sig_name} — refusing to install an unsigned update",
                release.tag_name
            ))
        })?;

    print_progress(&format!(
        "gratis: downloading {} ({target})...",
        release.tag_name
    ));
    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await?
        .bytes()
        .await?;
    let sig_bytes = client
        .get(&sig_asset.browser_download_url)
        .send()
        .await?
        .bytes()
        .await?;

    verify_signature(&bytes, &sig_bytes)?;

    print_progress("gratis: installing...");
    let work_dir = std::env::temp_dir().join(format!("gratis-update-{}", std::process::id()));
    std::fs::create_dir_all(&work_dir)?;
    let tarball_path = work_dir.join(&asset.name);
    std::fs::write(&tarball_path, &bytes)?;

    reject_unsafe_tar_entries(&tarball_path)?;

    let status = Command::new("tar")
        .arg("xzf")
        .arg(&tarball_path)
        .arg("-C")
        .arg(&work_dir)
        .status()
        .map_err(ProtonError::Io)?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&work_dir);
        return Err(ProtonError::Config(
            "failed to extract update tarball".into(),
        ));
    }

    let new_binary = match find_binary(&work_dir, &asset.name) {
        Ok(path) => path,
        Err(err) => {
            let _ = std::fs::remove_dir_all(&work_dir);
            return Err(err);
        }
    };
    replace_running_binary(&new_binary)?;

    let _ = std::fs::remove_dir_all(&work_dir);

    Ok(UpdateOutcome::Updated {
        from: current,
        to: latest,
    })
}

/// Verifies `sig_bytes` (a raw 64-byte Ed25519 signature) over `tarball_bytes` against the
/// embedded `RELEASE_SIGNING_PUBLIC_KEY`. This is the entire trust boundary for `gratis update`:
/// a tampered tarball, a compromised release, or a MITM'd download all fail here before a single
/// byte gets extracted.
fn verify_signature(tarball_bytes: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(&RELEASE_SIGNING_PUBLIC_KEY)
        .map_err(|e| ProtonError::Config(format!("embedded release public key invalid: {e}")))?;
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        ProtonError::Config(format!(
            "release signature has the wrong length ({} bytes, expected 64)",
            sig_bytes.len()
        ))
    })?;
    let signature = Signature::from_bytes(&sig_array);
    verifying_key
        .verify(tarball_bytes, &signature)
        .map_err(|_| {
            ProtonError::Config(
                "release signature verification failed — refusing to install".into(),
            )
        })
}

/// Rejects a tarball containing any entry with a `..` path component or an absolute path
/// ("tar slip") *before* `tar xzf` ever runs — those entries could otherwise write outside
/// `work_dir` (e.g. into the user's home directory or crontab). Uses `tar tzf` (list-only, never
/// extracts) so this check runs on fully untrusted input.
fn reject_unsafe_tar_entries(tarball_path: &Path) -> Result<()> {
    let output = Command::new("tar")
        .arg("tzf")
        .arg(tarball_path)
        .output()
        .map_err(ProtonError::Io)?;
    if !output.status.success() {
        return Err(ProtonError::Config(
            "failed to list update tarball contents".into(),
        ));
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    for entry in listing.lines() {
        let path = Path::new(entry);
        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(ProtonError::Config(format!(
                "update tarball contains an unsafe path entry ({entry}) — refusing to extract"
            )));
        }
    }
    Ok(())
}

/// The tarball extracts to `<asset-name-without-.tar.gz>/gratis` (see the release workflow's
/// `Package` step) — pin that exact path rather than scanning subdirectories for a file named
/// `gratis`, so a crafted tarball can't influence which extracted file gets treated as the new
/// binary by adding a decoy top-level directory.
fn find_binary(work_dir: &Path, asset_name: &str) -> Result<std::path::PathBuf> {
    let expected_dir = asset_name.strip_suffix(".tar.gz").unwrap_or(asset_name);
    let candidate = work_dir.join(expected_dir).join("gratis");
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(ProtonError::Config(format!(
            "update tarball did not contain {expected_dir}/gratis"
        )))
    }
}

/// Replace the currently-running binary's file. Writes the new binary next to the current
/// one and renames over it — a rename within the same directory is atomic on Linux, so a
/// process that's still running the old binary (its inode stays open) or a concurrent `gratis`
/// invocation never sees a partially-written file.
fn replace_running_binary(new_binary: &Path) -> Result<()> {
    let current = std::env::current_exe().map_err(ProtonError::Io)?;
    let staged = current.with_extension("update");
    std::fs::copy(new_binary, &staged)?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(&staged, &current)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_for_arch_covers_the_two_release_targets() {
        assert_eq!(
            triple_for_arch("x86_64").unwrap(),
            "x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            triple_for_arch("aarch64").unwrap(),
            "aarch64-unknown-linux-gnu"
        );
    }

    #[test]
    fn triple_for_arch_rejects_an_unsupported_architecture() {
        let err = triple_for_arch("riscv64").unwrap_err();
        assert!(err.to_string().contains("riscv64"));
    }

    #[test]
    fn find_binary_locates_gratis_at_the_pinned_asset_directory() {
        let work_dir = tempfile::tempdir().unwrap();
        let asset_name = "gratis-v9.9.9-x86_64-unknown-linux-gnu.tar.gz";
        let extracted = work_dir
            .path()
            .join("gratis-v9.9.9-x86_64-unknown-linux-gnu");
        std::fs::create_dir_all(&extracted).unwrap();
        std::fs::write(extracted.join("gratis"), b"fake binary").unwrap();
        // A decoy top-level file/dir must not be mistaken for the real one.
        std::fs::write(work_dir.path().join("gratis"), b"not the real one").unwrap();

        let found = find_binary(work_dir.path(), asset_name).unwrap();
        assert_eq!(found, extracted.join("gratis"));
    }

    #[test]
    fn find_binary_rejects_a_decoy_directory_not_matching_the_asset_name() {
        let work_dir = tempfile::tempdir().unwrap();
        let asset_name = "gratis-v9.9.9-x86_64-unknown-linux-gnu.tar.gz";
        // An attacker-controlled tarball puts the binary under an unexpected directory name.
        let decoy = work_dir.path().join("evil-payload");
        std::fs::create_dir_all(&decoy).unwrap();
        std::fs::write(decoy.join("gratis"), b"trojan").unwrap();

        assert!(find_binary(work_dir.path(), asset_name).is_err());
    }

    #[test]
    fn find_binary_errors_when_the_tarball_has_no_gratis_binary() {
        let work_dir = tempfile::tempdir().unwrap();
        let asset_name = "gratis-v9.9.9-x86_64-unknown-linux-gnu.tar.gz";
        let extracted = work_dir
            .path()
            .join("gratis-v9.9.9-x86_64-unknown-linux-gnu");
        std::fs::create_dir_all(&extracted).unwrap();
        std::fs::write(extracted.join("README.md"), b"no binary here").unwrap();

        assert!(find_binary(work_dir.path(), asset_name).is_err());
    }

    // Signature fixed over the fixed payload below, produced once with the real release
    // signing private key (`openssl pkeyutl -sign -rawin`) — the private key itself never
    // touches this repo, only this one known-good signature over a fixed test message.
    const TEST_PAYLOAD: &[u8] = b"gratis test payload";
    const TEST_PAYLOAD_SIGNATURE_HEX: &str = "59d83d540a7eda148de288dd5a16c4cd0a96985f557c25c5820f3ebfeb7529e24ce4686199aae67df56082b87702d7062310ff0461bd9b62f225f3ca24aebf04";

    fn decode_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn verify_signature_accepts_a_genuine_signature() {
        let sig = decode_hex(TEST_PAYLOAD_SIGNATURE_HEX);
        verify_signature(TEST_PAYLOAD, &sig).expect("known-good signature must verify");
    }

    #[test]
    fn verify_signature_rejects_a_tampered_payload() {
        let sig = decode_hex(TEST_PAYLOAD_SIGNATURE_HEX);
        let mut tampered = TEST_PAYLOAD.to_vec();
        tampered.push(b'!');
        assert!(verify_signature(&tampered, &sig).is_err());
    }

    #[test]
    fn verify_signature_rejects_a_signature_from_a_different_key() {
        use ed25519_dalek::Signer;
        let other_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let bogus_sig = other_key.sign(TEST_PAYLOAD);
        assert!(verify_signature(TEST_PAYLOAD, &bogus_sig.to_bytes()).is_err());
    }

    #[test]
    fn verify_signature_rejects_a_malformed_length() {
        assert!(verify_signature(TEST_PAYLOAD, b"too short").is_err());
    }

    #[test]
    fn reject_unsafe_tar_entries_allows_a_normal_tarball() {
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("payload");
        std::fs::create_dir_all(payload.join("gratis-v1.0.0-x86_64-unknown-linux-gnu")).unwrap();
        std::fs::write(
            payload
                .join("gratis-v1.0.0-x86_64-unknown-linux-gnu")
                .join("gratis"),
            b"binary",
        )
        .unwrap();
        let tarball = dir.path().join("safe.tar.gz");
        let status = Command::new("tar")
            .arg("czf")
            .arg(&tarball)
            .arg("-C")
            .arg(&payload)
            .arg("gratis-v1.0.0-x86_64-unknown-linux-gnu")
            .status()
            .unwrap();
        assert!(status.success());

        reject_unsafe_tar_entries(&tarball).expect("a normal tarball must be accepted");
    }

    #[test]
    fn reject_unsafe_tar_entries_rejects_a_parent_dir_escape() {
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("payload");
        std::fs::create_dir_all(&payload).unwrap();
        std::fs::write(payload.join("evil"), b"pwned").unwrap();
        let tarball = dir.path().join("evil.tar.gz");
        // `--transform` renames the entry inside the archive to escape the extraction dir —
        // simulates a malicious tarball without needing root or a real filesystem escape.
        let status = Command::new("tar")
            .arg("czf")
            .arg(&tarball)
            .arg("--transform")
            .arg("s,^evil$,../../etc/evil,")
            .arg("-C")
            .arg(&payload)
            .arg("evil")
            .status()
            .unwrap();
        assert!(status.success());

        assert!(reject_unsafe_tar_entries(&tarball).is_err());
    }
}
