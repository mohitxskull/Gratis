# Gratis

[![CI](https://github.com/mohitxskull/Gratis/actions/workflows/ci.yml/badge.svg)](https://github.com/mohitxskull/Gratis/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/mohitxskull/Gratis)](https://github.com/mohitxskull/Gratis/releases/latest)

A local SOCKS5 proxy over your Proton VPN account's servers — no root required. It logs
in once, then exposes every server your account can reach — free or paid tier, gratis
reads your account's real limits — as its own local SOCKS5 proxy port. Connect to a
server's port and its WireGuard tunnel comes up on its own; leave it idle for 5 minutes
and it tears itself back down.

Note: unlike a conventional VPN client, gratis doesn't take over your system's routing —
nothing is protected system-wide by default. It's opt-in per application: only traffic
you explicitly point at a `127.0.0.1:<port>` goes through it.

## Why

Proton's official client brings up one tunnel at a time and needs root to manage a real
kernel WireGuard interface. `gratis` runs entirely unprivileged (WireGuard is a userspace
session, not a real network interface — see `src/wireguard.rs`) and lets you use as many
servers at once as you want, simply by connecting to different ports.

## Installation

gratis is Linux-only, and installs as a background `systemd --user` service — no terminal
window to keep open.

```sh
curl -fsSL https://raw.githubusercontent.com/mohitxskull/Gratis/main/install.sh | sh
```

This downloads the latest release for your architecture (`x86_64` or `aarch64`) and places
the `gratis` binary at `~/.local/bin/gratis` — no build tools, no Rust toolchain needed. It
does not log in or start anything; that's `gratis login` and `gratis up` below.

<details>
<summary>Installing manually instead</summary>

Grab the tarball for your architecture from the
[latest release](https://github.com/mohitxskull/Gratis/releases/latest), extract it, and
move the `gratis` binary onto your `PATH` yourself:

```sh
curl -LO https://github.com/mohitxskull/Gratis/releases/latest/download/<filename>.tar.gz
tar xzf gratis-*.tar.gz
mv gratis-*/gratis ~/.local/bin/gratis
```

</details>

<details>
<summary>Building from source instead</summary>

```sh
cargo install --git https://github.com/mohitxskull/Gratis
```

</details>

## Usage

```sh
gratis login       # authenticate once — email/password prompt, or EMAIL/PASSWORD env vars
gratis up          # start the background service
gratis status       # logged in? running? starting on login?
gratis down          # stop it
```

`login` exchanges your password for a Proton session (stored in the OS keychain, via the
Secret Service — GNOME Keyring, KWallet, etc.) and never stores the password itself. Every
later `up`/service restart reuses that stored session instead of logging in again, which is
also what makes startup fast.

Once `up`, point any SOCKS5 client at `127.0.0.1:<port>` for the server you want (see the
web UI or `status` for the list); the first connection brings that server's tunnel up, and
it stays up for as long as there's at least one open connection, plus 5 idle minutes after
the last one closes.

A read-only web UI is served at `http://127.0.0.1:9000` (configurable via `gratis up
--control-port`), showing the logged-in account, every server, its port, load, and live
connection status. The same server data is available as JSON at `GET /api/servers`. Both
the control API and every server's SOCKS5 port are bound to `127.0.0.1` only.

### Connection limit

By default, gratis caps how many servers can have a live tunnel **at the same time** at
your account's real Proton `MaxConnect` limit (free tier: 2, at last check) — fetched at
startup, not hardcoded. A server beyond that cap simply refuses new SOCKS5 connections
until another one idles out; nothing already connected gets dropped to make room, unless
you opt into `--evict-lru` (below).

`gratis up --unlimited-connections` bypasses this cap entirely. **Running more concurrent
tunnels than your account's plan allows is likely a violation of Proton's Terms of
Service** (§2.10 permits automation that's "indistinguishable from the standard client,"
but explicitly reserves the right to act on usage that "deviates significantly from normal
usage patterns") **and risks account action, up to termination on the free tier.** This
flag exists for people who understand and accept that risk — the web UI shows a persistent
warning banner whenever it's active, and the default (capped) behavior is what most people
should run.

`gratis up --evict-lru` is the middle ground: stay within the cap, but instead of
rejecting a new connection once it's reached, disconnect the least-recently-used **idle**
server to make room. It never touches a server with active traffic — if every connected
server is actually busy, the new connection is still rejected, same as the default. Useful
if you'd rather gratis manage which servers stay connected than see connection errors.

### System tray

`gratis up` also installs and starts a small tray icon — a menu with the connected server
count, "Open Dashboard", and "Start/Stop Service". It's a separate `systemd --user` unit
(`gratis-tray.service`), not part of the daemon itself, so `gratis run` stays a pure
headless service with no GUI dependency — the tray unit just polls the already-running
daemon's control API and `systemctl`, the same way the CLI does. `gratis down`/`persist`/
`uninstall` all manage it together with the main service, so there's nothing separate to
remember.

Requires a tray/`StatusNotifierItem` host. Plain GNOME Shell has had no built-in tray
support since 3.26 — the icon only appears there with an extension installed (e.g.
"AppIndicator and KStatusNotifierItem Support"). That's a Linux desktop ecosystem gap, not
something gratis can work around; most other desktop environments (KDE, XFCE, etc.) support
it natively.

### All commands

| Command | Does |
| --- | --- |
| `gratis login` | Authenticate and store the session in the OS keychain |
| `gratis logout` | Stop the service (and tray) and forget the stored session |
| `gratis up [--control-port] [--port-range-start] [--unlimited-connections] [--evict-lru]` | Start the background service and tray |
| `gratis down` | Stop them |
| `gratis status` | Show login/running/persist/tray state, and server count if running |
| `gratis persist` / `gratis persist --off` | Start (or stop starting) both automatically on login |
| `gratis update` | Download and install the latest release, restarting the service (and tray) if running |
| `gratis uninstall` | Remove the service, tray, stored session, and this binary |
| `gratis tray [--control-port]` | Run the tray icon directly in the foreground (mainly for debugging — normally managed by `up`/`down`) |

### Running in the foreground instead

If you'd rather not install the service (e.g. for local development), `EMAIL`/`PASSWORD`
env vars or a `.env` file still work directly with `cargo run`:

```sh
EMAIL=you@example.com PASSWORD=your-password cargo run --release -- run
```

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

- **`src/manager.rs`** — one `ServerSlot` per server the account's real tier (fetched via
  `GET /vpn/v2`, not assumed) can reach: a fixed port, an always-on SOCKS5 listener, and a
  WireGuard tunnel that connects lazily on first use and tears down after being idle (zero
  open connections) for 5 minutes. Also enforces the connection limit described above. The
  server list itself is re-fetched every 30 minutes (not just once at login), so load numbers
  stay current, newly-added servers show up, and servers Proton removes get flagged
  ("no longer available") — a port, once assigned to a server, is never reused for a
  different one, so removal never silently repurposes a client's existing connection.
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
- **`src/session.rs`** — the stored Proton session (`uid`/`access_token`/`refresh_token`,
  never the password) in the OS keychain, and what `gratis run` resumes on startup instead
  of a full SRP login.
- **`src/service.rs`** — writes/starts/stops/enables both `systemd --user` units (the daemon
  and the tray) that `up`/`down`/`persist` control together.
- **`src/update.rs`** — `gratis update`'s self-replace: downloads the matching release
  tarball and swaps the running binary in place. `gratis run` also polls GitHub every 6
  hours and fires a desktop notification when a newer release exists (shown in the tray
  menu too) — check-only, it never downloads or applies anything on its own; updating stays
  a manual `gratis update`.
- **`src/tray.rs`** — the system tray icon (`gratis tray`): polls the control API and
  `systemctl` for status, no capabilities beyond what the CLI already has.
- **`src/notify.rs`** — desktop notifications for the daemon's silent-failure cases
  (session expired, local-agent fallback, control-port bind failure).

No tunnel or server-list *state* survives a restart — those are always rebuilt fresh on
`gratis run` startup. The Proton *session* does persist (in the keychain), which is what
lets a restart skip the SRP login.

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
`x86_64`/`aarch64-unknown-linux-gnu`, and publishes a
GitHub Release with both tarballs attached and notes generated by git-cliff.

Preview the notes for an unreleased set of commits at any time:

```sh
git cliff --unreleased --strip header
```

## License

MIT — see [LICENSE](LICENSE).
