//! `gratis update`: downloads the latest GitHub Release tarball for the running platform and
//! replaces the installed binary in place. No package manager, no external updater tool.
use crate::errors::*;
use serde::Deserialize;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const REPO: &str = "mohitxskull/Gratis";

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

pub async fn run() -> Result<UpdateOutcome> {
    let current = env!("CARGO_PKG_VERSION").to_string();

    // Each of these stages is a network round-trip or a multi-hundred-KB download with no
    // other output in between — printing before each one is the difference between "gratis
    // update looks stuck" and a visible progression. An explicit flush after each line: Rust's
    // stdout is only line-buffered when attached to a terminal — piped/redirected (e.g. into a
    // log file) it's block-buffered, so without this a line could sit unflushed for the whole
    // multi-second step it's describing.
    print_progress("gratis: checking for updates...");
    let client = reqwest::Client::builder()
        .user_agent("gratis-updater")
        .build()?;
    let release: Release = client
        .get(format!(
            "https://api.github.com/repos/{REPO}/releases/latest"
        ))
        .send()
        .await?
        .json()
        .await?;
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

    print_progress("gratis: installing...");
    let work_dir = std::env::temp_dir().join(format!("gratis-update-{}", std::process::id()));
    std::fs::create_dir_all(&work_dir)?;
    let tarball_path = work_dir.join(&asset.name);
    std::fs::write(&tarball_path, &bytes)?;

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

    let new_binary = find_binary(&work_dir)?;
    replace_running_binary(&new_binary)?;

    let _ = std::fs::remove_dir_all(&work_dir);

    Ok(UpdateOutcome::Updated {
        from: current,
        to: latest,
    })
}

/// The tarball extracts to `gratis-<tag>-<target>/gratis` (see the release workflow's
/// `Package` step) — search for a file literally named `gratis` rather than hardcoding that
/// directory name, so a packaging-layout change doesn't silently break this.
fn find_binary(work_dir: &Path) -> Result<std::path::PathBuf> {
    for entry in std::fs::read_dir(work_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let candidate = entry.path().join("gratis");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(ProtonError::Config(
        "update tarball did not contain a gratis binary".into(),
    ))
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
    fn find_binary_locates_gratis_inside_the_extracted_directory() {
        let work_dir = tempfile::tempdir().unwrap();
        let extracted = work_dir
            .path()
            .join("gratis-v9.9.9-x86_64-unknown-linux-gnu");
        std::fs::create_dir_all(&extracted).unwrap();
        std::fs::write(extracted.join("gratis"), b"fake binary").unwrap();
        // A same-named sibling file (e.g. README.md) must not be mistaken for a directory.
        std::fs::write(work_dir.path().join("gratis"), b"not the real one").unwrap();

        let found = find_binary(work_dir.path()).unwrap();
        assert_eq!(found, extracted.join("gratis"));
    }

    #[test]
    fn find_binary_errors_when_the_tarball_has_no_gratis_binary() {
        let work_dir = tempfile::tempdir().unwrap();
        let extracted = work_dir
            .path()
            .join("gratis-v9.9.9-x86_64-unknown-linux-gnu");
        std::fs::create_dir_all(&extracted).unwrap();
        std::fs::write(extracted.join("README.md"), b"no binary here").unwrap();

        assert!(find_binary(work_dir.path()).is_err());
    }
}
