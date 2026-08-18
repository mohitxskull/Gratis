//! Credentials + active-connection state storage.
//!
//! Backed by a single-file SQLite database at `~/.config/gratis/gratis.db`,
//! created with `0600` permissions (owner read/write only) so secrets on disk are not
//! world/group readable. There is one Proton account at a time, so the `credentials` table
//! is a single upserted row (`id = 1`); `active_tunnels` tracks zero or more live WireGuard
//! interfaces (one per location) so `disconnect`/`status` (separate process invocations, and
//! eventually the daemon) can find and tear down live tunnels.
//!
//! Secrets (password, certificate, WireGuard keys, tokens) are never logged: nothing in this
//! module calls `println!`/`eprintln!`/`tracing` on credential data.
use crate::errors::*;
use crate::models::VPNCredentials;
use rusqlite::{Connection, params};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn config_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|d| d.join("gratis"))
        .ok_or_else(|| ProtonError::Config("cannot resolve config dir".into()))
}

/// Path to the SQLite database used by the real (non-test) `save_credentials` etc.
pub fn db_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("gratis.db"))
}

/// One row of `active_tunnels`: a live (or recently-started) WireGuard interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveTunnel {
    pub location: String,
    pub interface: String,
    pub socks_port: u16,
    pub started_at: i64,
}

/// The SQLite-backed credentials/state store.
///
/// `Store::open` takes an explicit path so tests can point it at a tempdir instead of the
/// real `~/.config/gratis/` directory; the free functions in this module (
/// `save_credentials`, `load_credentials`, `set_active`, `clear_active`, `list_active`) are
/// thin wrappers that call `Store::open(&db_path()?)`.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if absent) the SQLite DB at `path`, ensure the schema exists, set
    /// `0600` permissions and `PRAGMA secure_delete = ON`.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let is_new = !path.exists();
        let conn = Connection::open(path)?;

        if is_new {
            // Owner read/write only. Set right after creation, before any secrets are
            // written, so the file is never briefly world/group readable.
            let mut perms = std::fs::metadata(path)?.permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
            std::fs::set_permissions(path, perms)?;
        }

        conn.execute_batch(
            "PRAGMA secure_delete = ON;
             CREATE TABLE IF NOT EXISTS credentials (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 username TEXT NOT NULL,
                 ed25519_seed_b64 TEXT NOT NULL,
                 wg_public_key TEXT NOT NULL,
                 wg_private_key TEXT NOT NULL,
                 certificate TEXT NOT NULL,
                 certificate_expires_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS active_tunnels (
                 location TEXT PRIMARY KEY,
                 interface TEXT NOT NULL,
                 socks_port INTEGER NOT NULL,
                 started_at INTEGER NOT NULL
             );",
        )?;

        Ok(Self { conn })
    }

    /// Upsert the single credentials row.
    pub fn save_credentials(&self, creds: &VPNCredentials) -> Result<()> {
        self.conn.execute(
            "INSERT INTO credentials
                 (id, username, ed25519_seed_b64, wg_public_key, wg_private_key,
                  certificate, certificate_expires_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (id) DO UPDATE SET
                 username = excluded.username,
                 ed25519_seed_b64 = excluded.ed25519_seed_b64,
                 wg_public_key = excluded.wg_public_key,
                 wg_private_key = excluded.wg_private_key,
                 certificate = excluded.certificate,
                 certificate_expires_at = excluded.certificate_expires_at",
            params![
                creds.username,
                creds.ed25519_seed_b64,
                creds.wg_public_key,
                creds.wg_private_key,
                creds.certificate,
                creds.certificate_expires_at,
            ],
        )?;
        Ok(())
    }

    /// Load the single credentials row.
    pub fn load_credentials(&self) -> Result<VPNCredentials> {
        self.conn
            .query_row(
                "SELECT username, ed25519_seed_b64, wg_public_key, wg_private_key,
                        certificate, certificate_expires_at
                 FROM credentials WHERE id = 1",
                [],
                |row| {
                    Ok(VPNCredentials {
                        username: row.get(0)?,
                        ed25519_seed_b64: row.get(1)?,
                        wg_public_key: row.get(2)?,
                        wg_private_key: row.get(3)?,
                        certificate: row.get(4)?,
                        certificate_expires_at: row.get(5)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    ProtonError::Config("no saved credentials".into())
                }
                other => ProtonError::Sqlite(other),
            })
    }

    /// Record (or replace) the active tunnel for `location`.
    pub fn set_active(&self, location: &str, interface: &str, socks_port: u16) -> Result<()> {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.conn.execute(
            "INSERT INTO active_tunnels (location, interface, socks_port, started_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (location) DO UPDATE SET
                 interface = excluded.interface,
                 socks_port = excluded.socks_port,
                 started_at = excluded.started_at",
            params![location, interface, socks_port, started_at],
        )?;
        Ok(())
    }

    /// Clear the active-tunnel row for `location`, if any.
    pub fn clear_active(&self, location: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM active_tunnels WHERE location = ?1",
            params![location],
        )?;
        Ok(())
    }

    /// List all currently-active tunnels.
    pub fn list_active(&self) -> Result<Vec<ActiveTunnel>> {
        let mut stmt = self.conn.prepare(
            "SELECT location, interface, socks_port, started_at FROM active_tunnels ORDER BY location",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ActiveTunnel {
                    location: row.get(0)?,
                    interface: row.get(1)?,
                    socks_port: row.get(2)?,
                    started_at: row.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

/// Persist credentials to the real (`~/.config/gratis/gratis.db`) store.
pub fn save_credentials(creds: &VPNCredentials) -> Result<()> {
    Store::open(&db_path()?)?.save_credentials(creds)
}

/// Load credentials from the real store.
pub fn load_credentials() -> Result<VPNCredentials> {
    Store::open(&db_path()?)?.load_credentials()
}

/// Record the active tunnel for `location` in the real store.
pub fn set_active(location: &str, interface: &str, socks_port: u16) -> Result<()> {
    Store::open(&db_path()?)?.set_active(location, interface, socks_port)
}

/// Clear the active-tunnel marker for `location` in the real store.
pub fn clear_active(location: &str) -> Result<()> {
    Store::open(&db_path()?)?.clear_active(location)
}

/// List active tunnels from the real store.
pub fn list_active() -> Result<Vec<ActiveTunnel>> {
    Store::open(&db_path()?)?.list_active()
}
