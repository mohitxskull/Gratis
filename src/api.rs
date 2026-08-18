//! Localhost control API (axum 0.7) — the primary way to drive `TunnelManager`: login,
//! list locations, and start/stop per-location tunnels. Also serves the embedded web UI at
//! `/`. `main.rs` binds this router to `127.0.0.1:<control_port>` only — never `0.0.0.0`.
use crate::errors::ProtonError;
use crate::manager::{CountryInfo, TunnelInfo, TunnelManager};
use crate::webui;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Build the router: `/`, `POST /api/login`, `GET /api/locations`, `GET /api/tunnels`,
/// `POST /api/tunnels`, `DELETE /api/tunnels/:location`.
pub fn router(manager: Arc<TunnelManager>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/login", post(login))
        .route("/api/locations", get(locations))
        .route("/api/tunnels", get(list_tunnels).post(start_tunnel))
        .route("/api/tunnels/:location", delete(stop_tunnel))
        .with_state(manager)
}

async fn index() -> Html<&'static str> {
    Html(webui::INDEX_HTML)
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

async fn login(
    State(manager): State<Arc<TunnelManager>>,
    Json(body): Json<LoginRequest>,
) -> Result<StatusCode, ApiError> {
    manager.login(&body.email, &body.password).await?;
    Ok(StatusCode::OK)
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
    let socks_port = manager.start(&body.location).await?;
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
        // no login is performed, so every handler this test exercises other than
        // `POST /api/login` short-circuits on "not logged in" before ever consulting the
        // driver or the network. The login route itself is exercised with a body that never
        // reaches the handler (see below), so `RealDriver` here never actually drives a real
        // `wg-quick`/socket call either.
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

        // POST /api/login — deliberately sent with a malformed JSON body so axum's `Json`
        // extractor rejects it *before* the handler runs, proving the route is wired without
        // ever calling `TunnelManager::login` (which would otherwise call
        // `ProtonVPNClient::login` and make a real outbound HTTPS request to Proton's
        // production API — unacceptable in an offline/sandboxed `cargo test` run). A rejected
        // extraction is a 4xx that is never 404 (route not found) or 200 (would imply the
        // handler ran).
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/login")
                    .header("content-type", "application/json")
                    .body(Body::from("not valid json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
        assert_ne!(resp.status(), StatusCode::OK);
        assert!(resp.status().is_client_error());

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
    }
}
