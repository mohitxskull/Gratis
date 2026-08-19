# Gratis

[![CI](https://github.com/mohitxskull/Gratis/actions/workflows/ci.yml/badge.svg)](https://github.com/mohitxskull/Gratis/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/mohitxskull/Gratis)](https://github.com/mohitxskull/Gratis/releases/latest)

A no-root Proton VPN (free tier) client. It logs in once, then exposes every free-tier
server as its own local SOCKS5 proxy port — connect to a server's port and its WireGuard
tunnel comes up on its own; leave it idle for 5 minutes and it tears itself back down.

## Why

Proton's official client brings up one tunnel at a time and needs root to manage a real
kernel WireGuard interface. `gratis` runs entirely unprivileged (WireGuard is a userspace
session, not a real network interface — see `src/wireguard.rs`) and lets you use as many
servers at once as you want, simply by connecting to different ports.

## Installation

Grab the tarball for your platform from the
[latest release](https://github.com/mohitxskull/Gratis/releases/latest) and extract it —
no build tools, no Rust toolchain needed. Pick one of `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, or `aarch64-apple-darwin`:

```sh
# with the GitHub CLI (always fetches the current latest release):
gh release download --repo mohitxskull/Gratis --pattern "*x86_64-unknown-linux-gnu*"

# or with curl, filling in the exact filename from the releases page:
curl -LO https://github.com/mohitxskull/Gratis/releases/latest/download/<filename>.tar.gz

tar xzf gratis-*.tar.gz && cd gratis-*/
./gratis --help
```

Move the extracted `gratis` binary onto your `PATH` (e.g. `~/.local/bin` or `/usr/local/bin`)
if you want to run it as just `gratis` from anywhere.

<details>
<summary>Building from source instead</summary>

```sh
cargo install --git https://github.com/mohitxskull/Gratis
```

</details>

## Usage

Create a `.env` file next to the `gratis` binary with your Proton account credentials:

```
EMAIL=you@example.com
PASSWORD=your-password
```

Then run it:

```sh
./gratis
```

(If you built from source instead of downloading a release: `cargo run --release`.)

On startup it logs in, fetches the free-tier server list, and assigns each server a fixed
port starting from `20000` (configurable — see below). Point any SOCKS5 client at
`127.0.0.1:<port>` for the server you want; the first connection brings that server's
tunnel up, and it stays up for as long as there's at least one open connection, plus 5
idle minutes after the last one closes.

A read-only web UI is served at `http://127.0.0.1:9000` (also configurable), showing every
server, its port, load, and live connection status. The same data is available as JSON at
`GET /api/servers`.

### CLI options

| Flag | Default | Meaning |
| --- | --- | --- |
| `--control-port` | `9000` | Port the web UI + `/api/servers` listen on |
| `--port-range-start` | `20000` | First port assigned to the server list (one port per server, sequential) |

Both the control API and every server's SOCKS5 port are bound to `127.0.0.1` only.

## Development

```
cargo test      # unit + integration tests (no network/root required)
cargo clippy
```

`tests/live_tunnel.rs` is `#[ignore]`d by default — it performs a real login and a real
HTTP request through a live Proton tunnel. Run it explicitly with a valid `.env` present:

```
cargo test --test live_tunnel -- --ignored --nocapture
```

Enable the pre-commit hook once per clone (`core.hooksPath` is local config, so it doesn't
come with the repository):

```sh
git config core.hooksPath .githooks
```

`.githooks/pre-commit` runs the same checks as CI's `check` job — rustfmt, clippy at
`-D warnings`, rustdoc at `-D warnings`, and the test suite. Bypass with
`git commit --no-verify` for work-in-progress commits on a branch, not for anything about
to reach `main`.

## Contributing

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(manager): add per-server idle countdown to GET /api/servers
fix(socks5): don't leak a connection count on a failed acquire
docs: document the port-range-start flag
```

The changelog and GitHub release notes are generated from these, so the subject line is
what users read. `chore:`, `ci:` and `style:` are excluded from the changelog; anything
with a `!` suffix or a `BREAKING CHANGE:` footer is flagged as breaking.

## How it works

- **`src/manager.rs`** — one `ServerSlot` per free-tier server: a fixed port, an always-on
  SOCKS5 listener, and a WireGuard tunnel that connects lazily on first use and tears down
  after being idle (zero open connections) for 5 minutes.
- **`src/wireguard.rs`** — an in-process userspace WireGuard session (via
  `wireguard-netstack`), not a real kernel interface.
- **`src/socks5.rs`** — a minimal SOCKS5 (CONNECT-only) proxy that relays traffic through
  whichever tunnel a `ServerSlot` currently holds.
- **`src/client.rs`** — the Proton API client (SRP login, certificate issuance, server
  list).
- **`src/agent.rs`** — Proton's "local agent" handshake. Proton admits a new WireGuard
  session in a *restricted* state in which external TLS is blocked for a few seconds;
  authenticating to the agent (client-certificate TLS to `10.2.0.1:65432`, verified against
  Proton's pinned CAs in `assets/certs/`) lifts that immediately, which is what makes the
  first connection to a server fast.

Nothing is persisted to disk: every run is a fresh login, and no tunnel or server-list
state survives a restart.

## If gratis gets slow — please report it

`gratis` depends on one piece of Proton behaviour that is undocumented and could change
without warning: the local-agent handshake described above, including the Proton CA
certificates pinned in `assets/certs/`.

If Proton rotates those CAs or changes that protocol, **gratis keeps working** — it falls
back to simply waiting out the restriction instead. You lose speed, not function. The
symptom is that the **first** connection to each server becomes noticeably slower (roughly
5 seconds instead of ~2), while later connections to the same server stay fast.

When that happens the daemon prints, once per server, a line like:

```
gratis: local-agent handshake for US-FREE#1 failed (...); falling back to the readiness probe
```

**Please [open an issue](https://github.com/mohitxskull/Gratis/issues) and include that
line**, plus the version you are running (`gratis --version` or the release you downloaded).
The fallback means nothing is broken for you, so this is easy to miss — but it is the only
signal that the pinned CAs or the agent protocol need updating, and a report is what makes
that fix possible.

## Releasing

Changelog and release notes come from [git-cliff](https://git-cliff.org) (config in
`cliff.toml`).

```sh
cargo install git-cliff          # once
```

1. Fold the new commits into the changelog and review the result:

   ```sh
   git cliff --unreleased --prepend CHANGELOG.md
   ```

   Rename the `## [Unreleased]` heading it produces to the version being released.

2. Bump `version` in `Cargo.toml`, then `cargo update -p gratis --offline` so
   `Cargo.lock` follows.

3. Commit, tag, push:

   ```sh
   git commit -am "chore(release): v0.1.0"
   git tag -a v0.1.0 -m "v0.1.0"
   git push && git push --tags
   ```

The tag is the only trigger. Pushing it runs `.github/workflows/release.yml`, which
verifies the tag matches `Cargo.toml` and that `CHANGELOG.md` has a section for the
version, runs tests and clippy, builds a binary for each of
`x86_64`/`aarch64-unknown-linux-gnu` and `x86_64`/`aarch64-apple-darwin`, and publishes a
GitHub Release with all four tarballs attached and notes generated by git-cliff.

Preview the notes for an unreleased set of commits at any time:

```sh
git cliff --unreleased --strip header
```

## License

MIT — see [LICENSE](LICENSE).
