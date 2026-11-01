//! Local trusted consent UI for UOMP.
//!
//! `aegis-os memory ui` serves a loopback-only approval page. It reads pending consent requests with
//! the local admin token, so the agent-facing MCP bridge never needs to expose the admin secret.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderName, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use uuid::Uuid;

pub struct UiConfig {
    pub listen: String,
    pub memory_url: String,
    pub admin_token: String,
    pub pid_file: PathBuf,
    pub url_file: PathBuf,
    pub open_on_start: bool,
}

struct UiState {
    memory_url: String,
    admin_token: String,
    ui_token: String,
    /// Request ids for which the browser has already been opened. This prevents
    /// re-opening the browser on every poll while still opening it for each new
    /// request (including requests that arrive after the page was closed).
    opened_ids: Mutex<HashSet<String>>,
}

type ApiError = (StatusCode, Json<Value>);

pub async fn run(config: UiConfig) -> anyhow::Result<()> {
    let listener = match tokio::net::TcpListener::bind(&config.listen).await {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            if let Ok(url) = std::fs::read_to_string(&config.url_file) {
                let url = url.trim();
                if url.starts_with("http://") && ui_health_ok(&config.listen) {
                    if config.open_on_start {
                        open_browser(url);
                    }
                    println!("Aegis consent UI already running: {url}");
                    return Ok(());
                }
            }
            return Err(error.into());
        }
        Err(error) => return Err(error.into()),
    };
    let addr = listener.local_addr()?;
    let ui_token = Uuid::new_v4().to_string();
    let state = Arc::new(UiState {
        memory_url: config.memory_url.trim_end_matches('/').to_string(),
        admin_token: config.admin_token,
        ui_token,
        opened_ids: Mutex::new(HashSet::new()),
    });
    let url = format!("http://{addr}/?token={}", state.ui_token);

    if let Some(parent) = config.pid_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config.pid_file, std::process::id().to_string())?;
    write_private(&config.url_file, &url)?;

    if config.open_on_start {
        let initial = fetch_pending(&state).unwrap_or_default();
        if open_browser(&url) {
            mark_opened(&state, &initial);
        }
    }

    let poll_state = Arc::clone(&state);
    let poll_url = url.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Ok(requests) = fetch_pending(&poll_state) {
                maybe_open_browser(&poll_state, &poll_url, &requests);
            }
        }
    });

    println!("Aegis consent UI listening on {url}");
    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/api/pending", get(pending))
        .route("/api/approve/:id", post(approve))
        .route("/api/deny/:id", post(deny))
        .layer(middleware::from_fn(loopback_only))
        .with_state(state);
    axum::serve(listener, app).await?;
    let _ = std::fs::remove_file(&config.url_file);
    Ok(())
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": "aegis-memory-ui" }))
}

async fn index() -> impl IntoResponse {
    let csp = HeaderName::from_static("content-security-policy");
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (
                csp,
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            ),
        ],
        Html(INDEX_HTML),
    )
}

fn is_loopback_host(host: &str) -> bool {
    let hostname = host
        .rsplit_once(':')
        .map(|(hostname, _)| hostname)
        .unwrap_or(host);
    matches!(hostname, "127.0.0.1" | "localhost" | "[::1]")
}

async fn loopback_only(request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if is_loopback_host(host) {
        next.run(request).await
    } else {
        (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "code": "FORBIDDEN_HOST", "message": "loopback host required" } })),
        )
            .into_response()
    }
}

fn check_token(state: &UiState, query: &HashMap<String, String>) -> Result<(), ApiError> {
    if query.get("token").map(String::as_str) == Some(state.ui_token.as_str()) {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": { "code": "UNAUTHORIZED", "message": "invalid UI token" } })),
        ))
    }
}

fn memory_json(
    state: &UiState,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> anyhow::Result<Value> {
    let url = format!("{}{}", state.memory_url, path);
    let request = ureq::request(method, &url)
        .timeout(Duration::from_secs(5))
        .set("x-uomp-admin-token", &state.admin_token);
    let response = match body {
        Some(body) => request.send_json(body),
        None => request.call(),
    };
    match response {
        Ok(response) => Ok(response.into_json::<Value>()?),
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_string().unwrap_or_default();
            anyhow::bail!("HTTP {status}: {body}")
        }
        Err(error) => Err(error.into()),
    }
}

fn fetch_pending(state: &UiState) -> anyhow::Result<Vec<Value>> {
    let response = memory_json(state, "GET", "/v1/consent/requests?status=pending", None)?;
    Ok(response["requests"].as_array().cloned().unwrap_or_default())
}

fn request_ids(requests: &[Value]) -> Vec<String> {
    requests
        .iter()
        .filter_map(|request| request["request_id"].as_str().map(str::to_string))
        .collect()
}

fn mark_opened(state: &UiState, requests: &[Value]) {
    let mut opened = state
        .opened_ids
        .lock()
        .unwrap_or_else(|value| value.into_inner());
    opened.extend(request_ids(requests));
}

fn maybe_open_browser(state: &UiState, url: &str, requests: &[Value]) {
    let has_new = {
        let opened = state
            .opened_ids
            .lock()
            .unwrap_or_else(|value| value.into_inner());
        request_ids(requests)
            .iter()
            .any(|request_id| !opened.contains(request_id))
    };
    if has_new && open_browser(url) {
        mark_opened(state, requests);
    }
}

fn ui_health_ok(listen: &str) -> bool {
    let url = format!("http://{listen}/health");
    let Ok(response) = ureq::get(&url).timeout(Duration::from_secs(1)).call() else {
        return false;
    };
    response
        .into_json::<Value>()
        .map(|value| value["service"] == "aegis-memory-ui")
        .unwrap_or(false)
}

fn write_private(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn open_browser(url: &str) -> bool {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(program)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

async fn pending(
    State(state): State<Arc<UiState>>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    check_token(&state, &query)?;
    let requests = fetch_pending(&state).map_err(|error| {
        (
            StatusCode::BAD_GATEWAY,
            Json(
                json!({ "error": { "code": "MEMORY_UNAVAILABLE", "message": error.to_string() } }),
            ),
        )
    })?;
    Ok(Json(json!({ "requests": requests })))
}

async fn approve(
    State(state): State<Arc<UiState>>,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    check_token(&state, &query)?;
    let response = memory_json(
        &state,
        "POST",
        &format!("/v1/consent/requests/{id}/approve"),
        Some(body),
    )
    .map_err(|error| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": { "code": "APPROVE_FAILED", "message": error.to_string() } })),
        )
    })?;
    Ok(Json(response))
}

async fn deny(
    State(state): State<Arc<UiState>>,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    check_token(&state, &query)?;
    let response = memory_json(
        &state,
        "POST",
        &format!("/v1/consent/requests/{id}/deny"),
        Some(json!({})),
    )
    .map_err(|error| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": { "code": "DENY_FAILED", "message": error.to_string() } })),
        )
    })?;
    Ok(Json(response))
}

const INDEX_HTML: &str = include_str!("assets/memory_consent.html");

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> UiState {
        UiState {
            memory_url: "http://127.0.0.1:9374".to_string(),
            admin_token: "admin".to_string(),
            ui_token: "ui-token".to_string(),
            opened_ids: Mutex::new(HashSet::new()),
        }
    }

    #[test]
    fn ui_token_is_required() {
        let state = state();
        let mut query = HashMap::new();
        assert!(check_token(&state, &query).is_err());
        query.insert("token".to_string(), "wrong".to_string());
        assert!(check_token(&state, &query).is_err());
        query.insert("token".to_string(), "ui-token".to_string());
        assert!(check_token(&state, &query).is_ok());
    }

    #[test]
    fn only_loopback_hosts_are_accepted() {
        assert!(is_loopback_host("127.0.0.1:9375"));
        assert!(is_loopback_host("localhost:9375"));
        assert!(is_loopback_host("[::1]:9375"));
        assert!(!is_loopback_host("evil.example:9375"));
        assert!(!is_loopback_host("127.0.0.1.evil.example"));
    }

    #[test]
    fn opened_ids_are_tracked_per_request() {
        let state = state();
        let requests = vec![json!({ "request_id": "a" })];
        mark_opened(&state, &requests);
        assert!(state.opened_ids.lock().unwrap().contains("a"));
        assert!(!state.opened_ids.lock().unwrap().contains("b"));
    }
}
