# Gratis

A no-root Proton VPN (free tier) client. It logs in once, then exposes every free-tier
server as its own local SOCKS5 proxy port — connect to a server's port and its WireGuard
tunnel comes up on its own; leave it idle for 5 minutes and it tears itself back down.

## Why

Proton's official client brings up one tunnel at a time and needs root to manage a real
kernel WireGuard interface. `gratis` runs entirely unprivileged (WireGuard is a userspace
session, not a real network interface — see `src/wireguard.rs`) and lets you use as many
servers at once as you want, simply by connecting to different ports.

## Usage

Create a `.env` file next to the binary with your Proton account credentials:

```
EMAIL=you@example.com
PASSWORD=your-password
```

Then run the daemon:

```
cargo run --release
```

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

Nothing is persisted to disk: every run is a fresh login, and no tunnel or server-list
state survives a restart.
