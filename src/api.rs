//! Localhost control API (axum 0.7) — the primary way to drive `TunnelManager`: list
//! locations, and start/stop per-location tunnels (as JSON, under `/api/*`). Also serves the
//! Askama+htmx+Tailwind web UI: `GET /` renders the full page, `GET/POST /ui/*` renders HTML
//! fragments htmx swaps into it. `main.rs` binds this router to `127.0.0.1:<control_port>`
//! only — never `0.0.0.0`.
//!
//! No login route: authentication happens once, automatically, at daemon startup from a
//! `.env` file (see `main.rs`) — there is no supported way to log in via this API or the web
//! UI, and `TunnelManager::login` is only ever called from `main.rs`'s startup sequence.
use crate::errors::ProtonError;
use crate::manager::{CountryInfo, TunnelInfo, TunnelManager};
use crate::webui::{IndexTemplate, LocationsTemplate, ServersTemplate, TunnelsTemplate};
use askama::Template;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
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

/// Build the router: `/` + `/ui/*` (the web UI), `/api/*` (the JSON control API).
pub fn router(manager: Arc<TunnelManager>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/ui/locations", get(ui_locations))
        .route("/ui/locations/:code/servers", get(ui_location_servers))
        .route("/ui/tunnels", get(ui_tunnels))
        .route("/ui/tunnels/:location/start", post(ui_start_tunnel))
        .route(
            "/ui/tunnels/:location/start/:server",
            post(ui_start_tunnel_server),
        )
        .route("/ui/tunnels/:location/stop", post(ui_stop_tunnel))
        .route("/api/locations", get(locations))
        .route("/api/tunnels", get(list_tunnels).post(start_tunnel))
        .route("/api/tunnels/:location", delete(stop_tunnel))
        .with_state(manager)
}

/// Full page: locations + tunnels rendered inline. `list_locations()` fails with
/// "not logged in" if `.env` auto-login didn't succeed at startup — shown as an inline error
/// banner rather than a 500, since it's an expected, recoverable-by-restarting state.
async fn index(State(manager): State<Arc<TunnelManager>>) -> Response {
    let (login_error, locations) = match manager.list_locations().await {
        Ok(locs) => (None, locs),
        Err(e) => (Some(e.to_string()), Vec::new()),
    };
    render(IndexTemplate::new(
        login_error,
        locations,
        manager.tunnels(),
    ))
}

/// Locations table fragment, for the "Refresh" button.
async fn ui_locations(State(manager): State<Arc<TunnelManager>>) -> Response {
    let locations = manager.list_locations().await.unwrap_or_default();
    render(LocationsTemplate { locations })
}

/// Individual-server list for one country, lazy-loaded the first time its row is expanded.
async fn ui_location_servers(
    State(manager): State<Arc<TunnelManager>>,
    Path(code): Path<String>,
) -> Response {
    let servers = manager.list_servers_in(&code).await.unwrap_or_default();
    render(ServersTemplate {
        location: code,
        servers,
    })
}

/// Tunnels table fragment, for the "Refresh" button and after start/stop actions.
async fn ui_tunnels(State(manager): State<Arc<TunnelManager>>) -> Response {
    render(TunnelsTemplate {
        tunnels: manager.tunnels(),
    })
}

/// Start a tunnel from the web UI. Renders the refreshed tunnels fragment regardless of
/// success — a failed start simply leaves the table unchanged; there's no per-action error
/// surface in the fragment-swap model yet (a reasonable v1 scope limit, not a bug: the JSON
/// `/api/tunnels` route below is available for callers that need the failure reason).
async fn ui_start_tunnel(
    State(manager): State<Arc<TunnelManager>>,
    Path(location): Path<String>,
) -> Response {
    let _ = manager.start(&location).await;
    render(TunnelsTemplate {
        tunnels: manager.tunnels(),
    })
}

/// Start a tunnel to one specific server within a location, from the web UI. Same
/// fragment-rendering contract as `ui_start_tunnel`.
async fn ui_start_tunnel_server(
    State(manager): State<Arc<TunnelManager>>,
    Path((location, server)): Path<(String, String)>,
) -> Response {
    let _ = manager.start_server(&location, Some(&server)).await;
    render(TunnelsTemplate {
        tunnels: manager.tunnels(),
    })
}

/// Stop a tunnel from the web UI. Same fragment-rendering contract as `ui_start_tunnel`.
async fn ui_stop_tunnel(
    State(manager): State<Arc<TunnelManager>>,
    Path(location): Path<String>,
) -> Response {
    let _ = manager.stop(&location).await;
    render(TunnelsTemplate {
        tunnels: manager.tunnels(),
    })
}

async fn locations(
    State(manager): State<Arc<TunnelManager>>,
) -> Result<Json<Vec<CountryInfo>>, ApiError> {
    Ok(Json(manager.list_locations().await?))
}

async fn list_tunnels(State(manager): State<Arc<TunnelManager>>) -> Json<Vec<TunnelInfo>> {
    Json(manager.tunnels())
}

#[derive(Deserialize)]
struct StartRequest {
    location: String,
    /// Specific server to connect to (e.g. `"US#1"`), matched case-insensitively. Omit to let
    /// `TunnelManager` pick the lowest-load free-tier server in `location`, as before.
    #[serde(default)]
    server: Option<String>,
}

#[derive(Serialize)]
struct StartResponse {
    location: String,
    socks_port: u16,
}

async fn start_tunnel(
    State(manager): State<Arc<TunnelManager>>,
    Json(body): Json<StartRequest>,
) -> Result<Json<StartResponse>, ApiError> {
    let socks_port = manager
        .start_server(&body.location, body.server.as_deref())
        .await?;
    Ok(Json(StartResponse {
        location: body.location,
        socks_port,
    }))
}

async fn stop_tunnel(
    State(manager): State<Arc<TunnelManager>>,
    Path(location): Path<String>,
) -> Result<StatusCode, ApiError> {
    manager.stop(&location).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Wraps `ProtonError` for `IntoResponse`, mapping it to a JSON `{"error": "..."}` body with
/// an appropriate status code. Error text may describe *what* failed ("no servers found for
/// location XX", "not logged in") but per `credentials.rs`'s no-secrets-logged discipline,
/// `ProtonError`'s `Display` impls never embed passwords/keys/certificates/tokens, so it's
/// safe to echo back to the (localhost-only) caller.
struct ApiError(ProtonError);

impl From<ProtonError> for ApiError {
    fn from(e: ProtonError) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            ProtonError::Auth => StatusCode::UNAUTHORIZED,
            ProtonError::Config(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(serde_json::json!({ "error": self.0.to_string() }));
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{RealDriver, TunnelManager};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn stub_manager() -> Arc<TunnelManager> {
        // `RealDriver` only stands in for the WireGuard/SOCKS5 side of `TunnelManager` (see
        // `manager.rs`) — it does not touch `ProtonVPNClient`/the network. That's fine here:
        // no login is performed, so every handler this test exercises short-circuits on
        // "not logged in" before ever consulting the driver or the network.
        Arc::new(TunnelManager::with_driver(9500, Arc::new(RealDriver)))
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

        // There is no /api/login route — confirm it's genuinely gone (404), not just
        // unreachable for some other reason.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/login")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // GET /api/locations (not logged in -> 400, not 404)
        let resp = app
            .clone()
            .oneshot(Request::get("/api/locations").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // GET /api/tunnels
        let resp = app
            .clone()
            .oneshot(Request::get("/api/tunnels").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // POST /api/tunnels (not logged in -> 400, not 404)
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/tunnels")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"location": "US"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // DELETE /api/tunnels/:location (nothing active -> 400, not 404)
        let resp = app
            .clone()
            .oneshot(
                Request::delete("/api/tunnels/US")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // GET /ui/locations — a fragment, always 200 even when not logged in (falls back to
        // an empty list rather than erroring, per ui_locations's contract).
        let resp = app
            .clone()
            .oneshot(Request::get("/ui/locations").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET /ui/tunnels
        let resp = app
            .clone()
            .oneshot(Request::get("/ui/tunnels").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // POST /ui/tunnels/:location/start — always 200 (renders the tunnels fragment
        // regardless of whether the start actually succeeded, per its documented contract).
        let resp = app
            .clone()
            .oneshot(
                Request::post("/ui/tunnels/US/start")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // POST /ui/tunnels/:location/start/:server — per-server start, same contract.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/ui/tunnels/US/start/US%231")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // POST /ui/tunnels/:location/stop — same contract.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/ui/tunnels/US/stop")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
