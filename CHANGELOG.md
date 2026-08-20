# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.3] — 2026-08-20

### Added

- Show which flags a running gratis service was started with

### Fixed

- **socks5**: Distinguish "at capacity" from "genuinely broken" over SOCKS5
- **ux**: Show flags as readable state, not a raw ExecStart dump

## [0.5.2] — 2026-08-20

### Added

- **logging**: Consistent log:: levels for the daemon, add `gratis logs`

### Fixed

- **install**: Avoid ETXTBSY when overwriting a running gratis binary

## [0.5.1] — 2026-08-20

### Changed

- **license**: Relicense under GPL-3.0-or-later (was MIT) — the auth/session/API-shape logic
  was worked out against `proton-vpn-cli` (GPLv3) and Proton's GPL-licensed Python packages,
  not developed independently

## [0.5.0] — 2026-08-20

### Added

- **manager**: Periodically refresh the server list instead of fetching once at login
- **update**: Periodically check for new releases and notify
- **tray**: Surface update availability in the tray menu

## [0.4.0] — 2026-08-20

### Added

- Add OS-keychain session storage, systemd unit management, and self-update
- **client**: Support session-resume login, token refresh, and 2FA
- **manager**: Filter by real account tier, enforce MaxConnect, show account on web UI
- **cli**: Replace the single daemon entrypoint with login/up/down/status/etc **(breaking)**
- Add desktop notifications for silent background failures
- **manager**: Add opt-in LRU eviction for the connection cap
- Add a system tray icon (gratis tray)
- **cli**: Manage the tray alongside the main service in up/down/persist/uninstall

### Build

- **deps**: Add keyring and console; shrink dev build debug info

### Documentation

- Document the new CLI/install workflow; drop macOS from the release matrix
- Drop "free tier" from gratis's identity — it works for any account tier
- Reframe gratis as a SOCKS5 proxy, not a VPN client

### Fixed

- **cli**: Bind the control port before logging in, not after

### Testing

- Cover the 2FA/session-resume, unit-templating, and self-update logic

## [0.3.0] — 2026-08-19

### Added

- **manager**: Implement retry logic for tunnel connections

### Fixed

- **wireguard**: Retry connect_tcp through a freshly-connected tunnel

## [0.2.0] — 2026-08-19

### Added

- **bench**: Add a latency/throughput benchmark example

### Documentation

- Add CI/release badges, lead installation with binary download

### Fixed

- Lift Proton's restricted-session block via the local agent (#1)

### Performance

- **socks5**: Use atomic counters for tunnel stats instead of a mutex

## [0.1.0] — 2026-08-18

### Added

- Implement SRP-6a auth and API client (Task 02)
- SQLite credentials/state store + WireGuard config and up/down (Task 03)
- Implement SOCKS5 proxy engine (Task 04)
- Daemon with tunnel manager, control API, and embedded web UI
- Implement local WireGuard identity generation
- Rename project to gratis and add web UI
- **ui**: Redesign web interface and add lazy-loaded server lists
- Update UI theme and add loading states
- Implement per-server tunnel connections and hot-swapping
- **manager**: Restrict to single active tunnel
- Add tunnel telemetry and visual updates
- Per-server ports with lazy-connect + idle teardown, drop SQLite
- **ui**: Split connected/idle servers, show idle-teardown countdown

### Changed

- **wireguard**: Replace wg-quick with userspace tunnel

### Documentation

- Add README

### Fixed

- Create wg-quick temp config atomically at 0600 and clean it up
- Don't kill SOCKS5 listener on transient accept() errors
- Serialize per-location start/stop, remove real login call from route test
- Redesign WireGuard tunnel lifecycle for final review findings

### Testing

- Add API fixtures and server-list parsing/filtering coverage (Task 06)


[0.1.0]: https://github.com/mohitxskull/Gratis/releases/tag/v0.1.0

