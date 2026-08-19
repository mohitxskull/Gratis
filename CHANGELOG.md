# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

