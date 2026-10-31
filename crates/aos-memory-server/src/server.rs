use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aos_memory::{MemoryScope, MemoryScopes, RemoteTokenClaims};
use aos_memory_store::SqliteMemoryStore;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::auth::{IssueClaims, TokenIssuer};
use crate::auth_store::AuthStore;

pub struct ServerConfig {
    pub listen: String,
    pub store_path: std::path::PathBuf,
    pub auth_db_path: std::path::PathBuf,
    pub secrets_dir: std::path::PathBuf,
    pub admin_token: String,
    pub bridge_token: String,
    pub public_url: String,
}

pub struct AppState {
    store: Mutex<SqliteMemoryStore>,
    auth: Mutex<AuthStore>,
    issuer: TokenIssuer,
    admin_token: String,
    bridge_token: String,
    public_url: String,
}

type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

pub fn build_state(config: ServerConfig) -> anyhow::Result<Arc<AppState>> {
    let store = SqliteMemoryStore::open(&config.store_path)?;
    let auth = AuthStore::open(&config.auth_db_path)?;
    let issuer = TokenIssuer::load_or_generate(&config.secrets_dir)?;
    Ok(Arc::new(AppState {
        store: Mutex::new(store),
        auth: Mutex::new(auth),
        issuer,
        admin_token: config.admin_token,
        bridge_token: config.bridge_token,
        public_url: config.public_url,
    }))
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/sessions", get(list_sessions).post(create_session))
        .route("/v1/sessions/:id/grant", post(grant_session))
        .route("/v1/sessions/:id/revoke", post(revoke_session))
        .route("/v1/sessions/revoke-by-task", post(revoke_sessions_by_task))
        .route("/v1/tokens/validate", post(validate_token))
        .route(
            "/v1/consent/requests",
            get(list_consent).post(create_consent),
        )
        .route("/v1/consent/requests/:id/status", get(consent_status))
        .route("/v1/consent/requests/:id/approve", post(approve_consent))
        .route("/v1/consent/requests/:id/deny", post(deny_consent))
        .route("/v1/memory/:key", get(get_memory).put(stage_write))
        .route("/v1/memory", get(list_memory))
        .route("/v1/staged-writes", get(list_staged_writes))
        .route("/v1/staged-writes/:id/approve", post(approve_staged_write))
        .route("/v1/staged-writes/:id/deny", post(deny_staged_write))
        .route("/v1/payload", get(list_payloads).post(upload_payload))
        .route("/v1/payload/:id", get(get_payload).delete(delete_payload))
        .route("/v1/audit", get(list_audit).post(record_audit))
        .with_state(state)
}

pub async fn run_server(config: ServerConfig) -> anyhow::Result<()> {
    let listen = config.listen.clone();
    let state = build_state(config)?;
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    println!("Aegis memory server listening on {listen}");
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": "aegis-memory" }))
}

fn api_error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
}

fn check_admin(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    let provided = headers
        .get("x-uomp-admin-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if provided == state.admin_token {
        Ok(())
    } else {
        Err(api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "admin token required",
        ))
    }
}

fn check_bridge(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    let provided = headers
        .get("x-uomp-bridge-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if provided == state.bridge_token {
        Ok(())
    } else {
        Err(api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "bridge token required",
        ))
    }
}

fn claims_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<RemoteTokenClaims, (StatusCode, Json<Value>)> {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let token = authorization.strip_prefix("Bearer ").ok_or_else(|| {
        api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "bearer token required",
        )
    })?;
    let claims = state
        .issuer
        .verify(token)
        .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "invalid token"))?;
    let active = state
        .auth
        .lock()
        .unwrap_or_else(|value| value.into_inner())
        .is_active(&claims.session_id)
        .unwrap_or(false);
    if !active {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_NOT_ACTIVE",
            "session is not active",
        ));
    }
    Ok(claims)
}

fn log_audit(
    state: &AppState,
    session_id: &str,
    agent_id: &str,
    action: &str,
    resource: &str,
    decision: &str,
    reason: &str,
) {
    let _ = state
        .auth
        .lock()
        .unwrap_or_else(|value| value.into_inner())
        .log_audit(session_id, agent_id, action, resource, decision, reason);
}

fn check_task_revoke(headers: &HeaderMap, task_id: &str) -> bool {
    let Ok(secret) = std::env::var("AOS_MEMORY_TASK_SECRET") else {
        return false;
    };
    if secret.is_empty() {
        return false;
    }
    let Some(token) = headers
        .get("x-aegis-task-token")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let mut parts = token.split(':');
    let Some(token_task) = parts.next() else {
        return false;
    };
    let Some(timestamp) = parts.next().and_then(|value| value.parse::<i64>().ok()) else {
        return false;
    };
    let Some(signature) = parts.next().and_then(|value| hex::decode(value).ok()) else {
        return false;
    };
    if parts.next().is_some() || token_task != task_id {
        return false;
    }
    if (Utc::now().timestamp() - timestamp).abs() > 120 {
        return false;
    }
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(format!("{task_id}:{timestamp}").as_bytes());
    mac.verify_slice(&signature).is_ok()
}

fn item_allowed(scope: &MemoryScope, item: &aos_memory_store::MemoryItem) -> bool {
    if scope.deny_keys.iter().any(|key| key == &item.key) {
        return false;
    }
    if item
        .tags
        .iter()
        .any(|tag| scope.deny_tags.iter().any(|denied| denied == tag))
    {
        return false;
    }
    if scope.keys.iter().any(|key| key == &item.key) {
        return true;
    }
    if item.sensitivity == aos_memory::Sensitivity::High {
        return false;
    }
    item.tags
        .iter()
        .any(|tag| scope.tags.iter().any(|granted| granted == tag))
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    check_admin(&state, &headers)?;
    let agent_id = body
        .get("agent_id")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if agent_id.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "agent_id is required",
        ));
    }
    let agent_name = body.get("agent_name").and_then(|value| value.as_str());
    let task_id = body.get("task_id").and_then(|value| value.as_str());
    let requested: MemoryScopes =
        serde_json::from_value(body.get("requested_scopes").cloned().unwrap_or_else(|| {
            json!({
                "read": { "tags": [], "keys": [], "denyTags": [], "denyKeys": [] },
                "write": { "tags": [], "keys": [], "denyTags": [], "denyKeys": [] }
            })
        }))
        .map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "invalid requested_scopes",
            )
        })?;
    let duration = body
        .get("duration_minutes")
        .and_then(|value| value.as_i64())
        .unwrap_or(30)
        .clamp(1, 1440);

    let session = state
        .auth
        .lock()
        .unwrap_or_else(|value| value.into_inner())
        .create_session(agent_id, agent_name, &requested, duration, task_id)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?;
    Ok(Json(json!({
        "session_id": session.session_id,
        "status": session.status,
        "expires_at": session.expires_at
    })))
}

async fn grant_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult {
    check_admin(&state, &headers)?;
    let granted: MemoryScopes =
        serde_json::from_value(body.get("granted_scopes").cloned().ok_or_else(|| {
            api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "granted_scopes is required",
            )
        })?)
        .map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "invalid granted_scopes",
            )
        })?;
    let session = state
        .auth
        .lock()
        .unwrap_or_else(|value| value.into_inner())
        .get_session(&id)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "SESSION_NOT_FOUND",
                "session not found",
            )
        })?;
    if session.status != "created" {
        return Err(api_error(
            StatusCode::NOT_FOUND,
            "SESSION_NOT_FOUND",
            "session is not in created state",
        ));
    }
    let expires_at_ms = chrono::DateTime::parse_from_rfc3339(&session.expires_at)
        .map(|value| value.timestamp_millis())
        .unwrap_or_else(|_| Utc::now().timestamp_millis() + 30 * 60 * 1000);
    let token = state
        .issuer
        .issue(&IssueClaims {
            session_id: session.session_id.clone(),
            agent_id: session.agent_id.clone(),
            expires_at_ms,
            scopes: granted.clone(),
            profile: "local".to_string(),
            audience: state.public_url.clone(),
        })
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "TOKEN_ERROR",
                &error.to_string(),
            )
        })?;
    let token_hash = format!("{:x}", sha2::Sha256::digest(token.as_bytes()));
    let updated = state
        .auth
        .lock()
        .unwrap_or_else(|value| value.into_inner())
        .grant_session(&id, &granted, &token_hash)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?;
    if !updated {
        return Err(api_error(
            StatusCode::NOT_FOUND,
            "SESSION_NOT_FOUND",
            "session not found",
        ));
    }
    Ok(Json(json!({
        "token": token,
        "token_type": "Bearer",
        "session_id": session.session_id,
        "expires_at": session.expires_at
    })))
}

async fn revoke_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    check_admin(&state, &headers)?;
    let auth = state.auth.lock().unwrap_or_else(|value| value.into_inner());
    let session = auth.get_session(&id).map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STORE_ERROR",
            &error.to_string(),
        )
    })?;
    let revoked = auth.revoke_session(&id).map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STORE_ERROR",
            &error.to_string(),
        )
    })?;
    if !revoked {
        return Err(api_error(
            StatusCode::NOT_FOUND,
            "SESSION_NOT_FOUND",
            "session not found",
        ));
    }
    if let Some(ref session) = session {
        let _ = auth.log_audit(
            &session.session_id,
            &session.agent_id,
            "revoke",
            &format!("session:{}", session.session_id),
            "allow",
            "user revoked the session",
        );
    }
    Ok(Json(json!({
        "session_id": id,
        "status": "revoked",
        "task_id": session.and_then(|session| session.task_id)
    })))
}

async fn revoke_sessions_by_task(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    let task_id = body
        .get("task_id")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if task_id.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "task_id is required",
        ));
    }
    if check_bridge(&state, &headers).is_err() && !check_task_revoke(&headers, task_id) {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "bridge token or task-scoped revoke token required",
        ));
    }
    let auth = state.auth.lock().unwrap_or_else(|value| value.into_inner());
    let sessions = auth.revoke_sessions_for_task(task_id).map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STORE_ERROR",
            &error.to_string(),
        )
    })?;
    for session in &sessions {
        let _ = auth.log_audit(
            &session.session_id,
            &session.agent_id,
            "revoke",
            &format!("session:{}", session.session_id),
            "allow",
            &format!("A2A task {task_id} reached a terminal state"),
        );
    }
    let ids: Vec<&str> = sessions
        .iter()
        .map(|session| session.session_id.as_str())
        .collect();
    Ok(Json(json!({
        "task_id": task_id,
        "status": "revoked",
        "count": ids.len(),
        "session_ids": ids
    })))
}

async fn list_sessions(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult {
    check_admin(&state, &headers)?;
    let sessions = state
        .auth
        .lock()
        .unwrap_or_else(|value| value.into_inner())
        .list_sessions(false)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?;
    Ok(Json(json!({ "sessions": sessions })))
}

async fn validate_token(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult {
    let token = body
        .get("token")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let claims = state.issuer.verify(token).ok();
    let valid = claims
        .as_ref()
        .map(|claims| {
            state
                .auth
                .lock()
                .unwrap_or_else(|value| value.into_inner())
                .is_active(&claims.session_id)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    Ok(Json(json!({
        "valid": valid,
        "session_id": claims.as_ref().map(|value| value.session_id.clone()),
    })))
}

async fn create_consent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    check_bridge(&state, &headers)?;
    let agent_id = body
        .get("agent_id")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if agent_id.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "agent_id is required",
        ));
    }
    let requested: MemoryScopes =
        serde_json::from_value(body.get("requested_scopes").cloned().ok_or_else(|| {
            api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "requested_scopes is required",
            )
        })?)
        .map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "invalid requested_scopes",
            )
        })?;
    let duration = body
        .get("duration_minutes")
        .and_then(|value| value.as_i64())
        .unwrap_or(10)
        .clamp(1, 1440);
    let agent_name = body.get("agent_name").and_then(|value| value.as_str());
    let task_id = body.get("task_id").and_then(|value| value.as_str());

    let auth = state.auth.lock().unwrap_or_else(|value| value.into_inner());
    let session = auth
        .create_session(agent_id, agent_name, &requested, duration, task_id)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?;
    let consent = auth.create_consent(&session, &requested).map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STORE_ERROR",
            &error.to_string(),
        )
    })?;
    Ok(Json(json!({
        "request_id": consent.request_id,
        "status": consent.status,
        "expires_at": consent.expires_at,
        "approval_required": true
    })))
}

async fn consent_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    check_bridge(&state, &headers)?;
    let auth = state.auth.lock().unwrap_or_else(|value| value.into_inner());
    let consent = auth
        .get_consent(&id)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "REQUEST_NOT_FOUND",
                "consent request not found",
            )
        })?;
    let token = auth.take_consent_token(&id).map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STORE_ERROR",
            &error.to_string(),
        )
    })?;
    Ok(Json(json!({
        "request_id": consent.request_id,
        "status": consent.status,
        "token": token,
        "expires_at": consent.expires_at
    })))
}

async fn list_consent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    check_admin(&state, &headers)?;
    let status = query.get("status").map(String::as_str);
    let requests = state
        .auth
        .lock()
        .unwrap_or_else(|value| value.into_inner())
        .list_consent(status)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?;
    Ok(Json(json!({ "requests": requests })))
}

async fn approve_consent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult {
    check_admin(&state, &headers)?;
    let auth = state.auth.lock().unwrap_or_else(|value| value.into_inner());
    let consent = auth
        .get_consent(&id)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "REQUEST_NOT_FOUND",
                "consent request not found",
            )
        })?;
    let granted: MemoryScopes = body
        .get("granted_scopes")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "invalid granted_scopes",
            )
        })?
        .unwrap_or_else(|| consent.requested_scopes.clone());
    let session = auth
        .get_session(&consent.session_id)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "SESSION_NOT_FOUND",
                "session not found",
            )
        })?;
    let expires_at_ms = chrono::DateTime::parse_from_rfc3339(&session.expires_at)
        .map(|value| value.timestamp_millis())
        .unwrap_or_else(|_| Utc::now().timestamp_millis() + 30 * 60 * 1000);
    let token = state
        .issuer
        .issue(&IssueClaims {
            session_id: session.session_id.clone(),
            agent_id: session.agent_id.clone(),
            expires_at_ms,
            scopes: granted.clone(),
            profile: "local".to_string(),
            audience: state.public_url.clone(),
        })
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "TOKEN_ERROR",
                &error.to_string(),
            )
        })?;
    let token_hash = format!("{:x}", sha2::Sha256::digest(token.as_bytes()));
    auth.grant_session(&session.session_id, &granted, &token_hash)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?;
    auth.approve_consent(&id, &granted, &token)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?;
    let _ = auth.log_audit(
        &session.session_id,
        &session.agent_id,
        "consent",
        &format!("consent:{id}"),
        "allow",
        "user approved the consent request",
    );
    Ok(Json(json!({ "request_id": id, "status": "approved" })))
}

async fn deny_consent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    check_admin(&state, &headers)?;
    let auth = state.auth.lock().unwrap_or_else(|value| value.into_inner());
    let consent = auth.get_consent(&id).map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STORE_ERROR",
            &error.to_string(),
        )
    })?;
    let denied = auth.deny_consent(&id).map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STORE_ERROR",
            &error.to_string(),
        )
    })?;
    if !denied {
        return Err(api_error(
            StatusCode::NOT_FOUND,
            "REQUEST_NOT_FOUND",
            "consent request not found",
        ));
    }
    if let Some(consent) = consent {
        let _ = auth.log_audit(
            &consent.session_id,
            &consent.agent_id,
            "consent",
            &format!("consent:{id}"),
            "deny",
            "user denied the consent request",
        );
    }
    Ok(Json(json!({ "request_id": id, "status": "denied" })))
}

async fn get_memory(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> ApiResult {
    let claims = claims_from_headers(&state, &headers)?;
    let store = state
        .store
        .lock()
        .unwrap_or_else(|value| value.into_inner());
    let item = store
        .get(&key)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "memory item not found"))?;
    if !item_allowed(&claims.scopes.read, &item) {
        log_audit(
            &state,
            &claims.session_id,
            &claims.agent_id,
            "read",
            &format!("memory:key:{key}"),
            "deny",
            "key is outside the token scope",
        );
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "ACCESS_DENIED",
            "key is outside the token scope",
        ));
    }
    log_audit(
        &state,
        &claims.session_id,
        &claims.agent_id,
        "read",
        &format!("memory:key:{key}"),
        "allow",
        "key allowed",
    );
    Ok(Json(json!({ "item": item })))
}

async fn list_memory(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    let claims = claims_from_headers(&state, &headers)?;
    let tag = query.get("tag").ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "tag is required",
        )
    })?;
    if !claims.scopes.read.tags.iter().any(|granted| granted == tag)
        && !claims
            .scopes
            .read
            .tags
            .iter()
            .any(|granted| tag.starts_with(granted))
    {
        log_audit(
            &state,
            &claims.session_id,
            &claims.agent_id,
            "read",
            &format!("memory:tag:{tag}"),
            "deny",
            "tag is outside the token scope",
        );
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "ACCESS_DENIED",
            "tag is outside the token scope",
        ));
    }
    let store = state
        .store
        .lock()
        .unwrap_or_else(|value| value.into_inner());
    let items = store.get_by_tag(tag).map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STORE_ERROR",
            &error.to_string(),
        )
    })?;
    let visible: Vec<aos_memory_store::MemoryItem> = items
        .into_iter()
        .filter(|item| item_allowed(&claims.scopes.read, item))
        .collect();
    log_audit(
        &state,
        &claims.session_id,
        &claims.agent_id,
        "read",
        &format!("memory:tag:{tag}"),
        "allow",
        "tag allowed",
    );
    Ok(Json(json!({ "items": visible })))
}

async fn stage_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult {
    let claims = claims_from_headers(&state, &headers)?;
    let value = body.get("value").cloned().ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "value is required",
        )
    })?;
    let tags: Vec<String> = body
        .get("tags")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default();
    let sensitivity = body
        .get("sensitivity")
        .and_then(|value| value.as_str())
        .unwrap_or("medium");
    if sensitivity == "high" {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "HIGH_SENSITIVITY_WRITE_DENIED",
            "high-sensitivity writes are not allowed",
        ));
    }
    let scope = &claims.scopes.write;
    let key_allowed = scope.keys.iter().any(|granted| granted == &key)
        && !scope.deny_keys.iter().any(|denied| denied == &key);
    let tag_allowed = tags
        .iter()
        .any(|tag| scope.tags.iter().any(|granted| granted == tag));
    if !key_allowed && !tag_allowed {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "ACCESS_DENIED",
            "write is outside the token scope",
        ));
    }
    let sensitivity = match sensitivity {
        "low" => aos_memory::Sensitivity::Low,
        "medium" => aos_memory::Sensitivity::Medium,
        _ => aos_memory::Sensitivity::High,
    };
    let store = state
        .store
        .lock()
        .unwrap_or_else(|value| value.into_inner());
    let staged = store
        .stage_write(aos_memory_store::StageWriteInput {
            session_id: claims.session_id.clone(),
            agent_id: claims.agent_id.clone(),
            key,
            value,
            tags,
            sensitivity,
            description: body
                .get("description")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        })
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?;
    log_audit(
        &state,
        &claims.session_id,
        &claims.agent_id,
        "write",
        &format!("memory:key:{}", staged.key),
        "allow",
        "staged for approval",
    );
    Ok(Json(json!({
        "staged_write_id": staged.id,
        "status": staged.status,
        "approval_required": true
    })))
}

async fn list_staged_writes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    check_admin(&state, &headers)?;
    let store = state
        .store
        .lock()
        .unwrap_or_else(|value| value.into_inner());
    let writes = store
        .list_staged_writes(query.get("status").map(String::as_str))
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?;
    Ok(Json(json!({ "staged_writes": writes })))
}

async fn approve_staged_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult {
    check_admin(&state, &headers)?;
    let reviewed_by = body
        .get("reviewed_by")
        .and_then(|value| value.as_str())
        .unwrap_or("user");
    let store = state
        .store
        .lock()
        .unwrap_or_else(|value| value.into_inner());
    let item = store
        .approve_staged_write(&id, reviewed_by)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "STAGED_WRITE_NOT_FOUND",
                "staged write not found",
            )
        })?;
    Ok(Json(json!({ "status": "approved", "item": item })))
}

async fn deny_staged_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult {
    check_admin(&state, &headers)?;
    let reviewed_by = body
        .get("reviewed_by")
        .and_then(|value| value.as_str())
        .unwrap_or("user");
    let store = state
        .store
        .lock()
        .unwrap_or_else(|value| value.into_inner());
    let write = store
        .deny_staged_write(&id, reviewed_by)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "STAGED_WRITE_NOT_FOUND",
                "staged write not found",
            )
        })?;
    Ok(Json(json!({ "status": "denied", "staged_write": write })))
}

async fn upload_payload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    let claims = claims_from_headers(&state, &headers)?;
    if body
        .get("ciphertext")
        .and_then(|value| value.as_str())
        .is_none()
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "ciphertext is required",
        ));
    }
    if body
        .get("encryption")
        .and_then(|value| value.as_object())
        .is_none()
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "encryption metadata is required",
        ));
    }
    let store = state
        .store
        .lock()
        .unwrap_or_else(|value| value.into_inner());
    let payload_id = store
        .store_payload(&claims.session_id, &claims.agent_id, body)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?;
    log_audit(
        &state,
        &claims.session_id,
        &claims.agent_id,
        "write",
        &format!("payload:{payload_id}"),
        "allow",
        "encrypted payload stored",
    );
    Ok(Json(
        json!({ "payload_id": payload_id, "status": "stored" }),
    ))
}

async fn get_payload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let claims = claims_from_headers(&state, &headers).ok();
    let admin = check_admin(&state, &headers).is_ok();
    let store = state
        .store
        .lock()
        .unwrap_or_else(|value| value.into_inner());
    let envelope = store
        .get_payload(&id)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "PAYLOAD_NOT_FOUND",
                "payload not found",
            )
        })?;
    let owner = envelope
        .get("session_id")
        .and_then(|value: &Value| value.as_str());
    if !admin
        && claims
            .as_ref()
            .map(|claims| Some(claims.session_id.as_str()) == owner)
            .unwrap_or(false)
            == false
    {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "ACCESS_DENIED",
            "payload belongs to another session",
        ));
    }
    Ok(Json(envelope))
}

async fn list_payloads(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult {
    check_admin(&state, &headers)?;
    let store = state
        .store
        .lock()
        .unwrap_or_else(|value| value.into_inner());
    let payloads = store.list_payloads().map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STORE_ERROR",
            &error.to_string(),
        )
    })?;
    Ok(Json(json!({ "payloads": payloads })))
}

async fn delete_payload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    check_admin(&state, &headers)?;
    let store = state
        .store
        .lock()
        .unwrap_or_else(|value| value.into_inner());
    if !store.delete_payload(&id).map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STORE_ERROR",
            &error.to_string(),
        )
    })? {
        return Err(api_error(
            StatusCode::NOT_FOUND,
            "PAYLOAD_NOT_FOUND",
            "payload not found",
        ));
    }
    Ok(Json(json!({ "status": "deleted", "payload_id": id })))
}

async fn list_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    check_admin(&state, &headers)?;
    let limit = query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50)
        .min(500);
    let events = state
        .auth
        .lock()
        .unwrap_or_else(|value| value.into_inner())
        .list_audit(limit)
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORE_ERROR",
                &error.to_string(),
            )
        })?;
    Ok(Json(json!({ "events": events })))
}

async fn record_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    let (session_id, agent_id) = if let Ok(claims) = claims_from_headers(&state, &headers) {
        (claims.session_id, claims.agent_id)
    } else if check_admin(&state, &headers).is_ok() || check_bridge(&state, &headers).is_ok() {
        (
            body.get("session_id")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string(),
            body.get("agent_id")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string(),
        )
    } else {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "memory token, admin token, or bridge token required",
        ));
    };
    let action = body
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or("access");
    let resource = body
        .get("resource")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let decision = body
        .get("decision")
        .and_then(|value| value.as_str())
        .unwrap_or("allow");
    let reason = body
        .get("reason")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    log_audit(
        &state,
        &session_id,
        &agent_id,
        action,
        resource,
        decision,
        reason,
    );
    Ok(Json(json!({ "status": "recorded" })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_revoke_token_is_bound_to_task_and_time() {
        std::env::set_var("AOS_MEMORY_TASK_SECRET", "test-secret");
        let task_id = "task-1";
        let timestamp = Utc::now().timestamp();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"test-secret").unwrap();
        mac.update(format!("{task_id}:{timestamp}").as_bytes());
        let token = format!(
            "{task_id}:{timestamp}:{}",
            hex::encode(mac.finalize().into_bytes())
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-aegis-task-token", token.parse().unwrap());
        assert!(check_task_revoke(&headers, task_id));
        assert!(!check_task_revoke(&headers, "task-2"));

        let stale = timestamp - 300;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"test-secret").unwrap();
        mac.update(format!("{task_id}:{stale}").as_bytes());
        let token = format!(
            "{task_id}:{stale}:{}",
            hex::encode(mac.finalize().into_bytes())
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-aegis-task-token", token.parse().unwrap());
        assert!(!check_task_revoke(&headers, task_id));
    }
}
