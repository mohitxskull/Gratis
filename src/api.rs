//! Localhost control API (axum 0.7) — a single read endpoint over `TunnelManager`'s live
//! server list (as JSON, under `/api/servers`). Also serves the Askama+htmx+Tailwind read-only
//! web UI: `GET /` renders the full page, `GET /ui/servers` renders the htmx-polled table
//! fragment. `main.rs` binds this router to `127.0.0.1:<control_port>` only — never `0.0.0.0`.
//!
//! There is no connect/disconnect/start/stop route: a server's tunnel comes up on its own the
//! moment a client connects to that server's assigned port (see `manager.rs`), so this API only
//! ever needs to answer "what's here and what's it doing right now."
//!
//! No login route: authentication happens once, automatically, at daemon startup — from a
//! stored keychain session if one exists (see `session.rs`), otherwise falling back to a
//! `.env` file (see `main.rs::resume_or_login`) — there is no supported way to log in via this
//! API or the web UI, and `TunnelManager::login`/`login_with_session` are only ever called from
//! `main.rs`'s startup and periodic-refresh sequences.
use crate::manager::{ServerStatus, TunnelManager};
use crate::webui::{IndexTemplate, ServersTemplate};
use askama::Template;
use axum::http::StatusCode;
use axum::{
    Json, Router,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Render an Askama template to an HTML response, mapping a render failure (should never
/// happen for these templates — they don't do anything fallible) to a 500.
fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("template error: {e}"),
        )
            .into_response(),
    }
}

/// Build the router: `/` + `/ui/servers` (the web UI), `/api/servers` (the JSON API).
pub fn router(manager: Arc<TunnelManager>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/ui/servers", get(ui_servers))
        .route("/api/servers", get(list_servers))
        .route("/api/update", get(update_status))
        .route("/api/health", get(health_status))
        .with_state(manager)
}

/// Full page: the server table rendered inline. An empty list (not logged in, or `.env`
/// auto-login failed at startup) renders as an inline empty-state message in the template
/// rather than a distinct error banner — there's nothing actionable to say beyond "nothing to
/// show," and the daemon's stderr already carries the actual login failure reason.
async fn index(
    axum::extract::State(manager): axum::extract::State<Arc<TunnelManager>>,
) -> Response {
    render(IndexTemplate::new(
        manager.servers(),
        manager.unlimited(),
        manager.evict_lru(),
        manager.account(),
    ))
}

/// The server table fragment, polled by the page every few seconds so status (connected,
/// open connections, telemetry) stays live without a manual refresh.
async fn ui_servers(
    axum::extract::State(manager): axum::extract::State<Arc<TunnelManager>>,
) -> Response {
    render(ServersTemplate::new(manager.servers()))
}

async fn list_servers(
    axum::extract::State(manager): axum::extract::State<Arc<TunnelManager>>,
) -> Json<Vec<ServerStatus>> {
    Json(manager.servers())
}

/// `pub` (not private) so `main.rs` and `tray.rs` — separate processes that deserialize this
/// same JSON shape over HTTP rather than calling into `api.rs` directly — can share one
/// definition instead of each hand-rolling their own, which could silently drift from this one
/// on a schema change (see maintainability review F8/F10).
#[derive(Serialize, Deserialize)]
pub struct UpdateStatus {
    /// The newest available version, if the daemon's periodic check has found one; `None`
    /// means either not yet checked or already current. See `update::check_for_update`.
    pub available: Option<String>,
}

/// Exists so `gratis tray` can show "update available" without making its own GitHub API
/// call — it just reads whatever `gratis run`'s periodic check last found.
async fn update_status(
    axum::extract::State(manager): axum::extract::State<Arc<TunnelManager>>,
) -> Json<UpdateStatus> {
    Json(UpdateStatus {
        available: manager.update_available(),
    })
}

/// `pub` for the same reason as [`UpdateStatus`] — `main.rs`'s `gratis status` deserializes
/// this exact shape over HTTP from a separate process.
#[derive(Serialize, Deserialize)]
pub struct HealthStatus {
    /// Whether Proton auth is currently working, as of the last login attempt or periodic
    /// refresh — not merely "a session file exists on disk" (see `TunnelManager::auth_error`'s
    /// doc comment for the bug this replaces).
    pub auth_ok: bool,
    /// The live reason auth is broken, if `auth_ok` is false.
    pub auth_error: Option<String>,
    pub servers_ready: usize,
}

/// Exists so `gratis status` can report what's actually true *right now* instead of just
/// whether a session file happens to exist on disk — see `TunnelManager::auth_error`'s doc
/// comment.
async fn health_status(
    axum::extract::State(manager): axum::extract::State<Arc<TunnelManager>>,
) -> Json<HealthStatus> {
    let auth_error = manager.auth_error();
    Json(HealthStatus {
        auth_ok: auth_error.is_none(),
        auth_error,
        servers_ready: manager.servers().len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::RealDriver;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn stub_manager() -> Arc<TunnelManager> {
        // `RealDriver` only stands in for the WireGuard/SOCKS5 side of `TunnelManager` (see
        // `manager.rs`) — it does not touch `ProtonVPNClient`/the network. That's fine here:
        // no login is performed, so `servers()` simply returns an empty list.
        Arc::new(TunnelManager::with_driver(
            9500,
            Arc::new(RealDriver),
            false,
            false,
            crate::manager::ProxyProtocol::default(),
        ))
    }

    #[tokio::test]
    async fn api_routes_wired() {
        let app = router(stub_manager());

        // GET /
        let resp = app
            .clone()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET /api/servers — empty (nothing logged in), but still 200, not an error.
        let resp = app
            .clone()
            .oneshot(Request::get("/api/servers").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let servers: Vec<ServerStatus> = serde_json::from_slice(&body).unwrap();
        assert!(servers.is_empty());

        // There is no start/stop/login route any more — confirm they're genuinely gone (404).
        for path in ["/api/login", "/api/tunnels", "/ui/tunnels/US/start"] {
            let resp = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "path: {path}");
        }

        // GET /ui/servers
        let resp = app
            .clone()
            .oneshot(Request::get("/ui/servers").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_endpoint_reflects_live_auth_state_not_just_server_count() {
        let manager = stub_manager();
        let app = router(manager.clone());

        // Nothing has gone wrong yet (no login attempted at all in this test) — auth_ok must
        // default to true, not false, since "never tried" isn't the same as "known broken".
        let resp = app
            .clone()
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let health: HealthStatus = serde_json::from_slice(&body).unwrap();
        assert!(health.auth_ok);
        assert_eq!(health.auth_error, None);
        assert_eq!(health.servers_ready, 0);

        // Now simulate what `resume_or_login` does on a real failure — the exact bug this
        // endpoint exists to fix: `servers()`/session-file-on-disk alone can't show this.
        manager.set_auth_error(Some("stored session is no longer valid".to_string()));
        let resp = app
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let health: HealthStatus = serde_json::from_slice(&body).unwrap();
        assert!(!health.auth_ok);
        assert_eq!(
            health.auth_error.as_deref(),
            Some("stored session is no longer valid")
        );
    }
}
