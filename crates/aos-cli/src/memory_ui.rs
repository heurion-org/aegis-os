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

const INDEX_HTML: &str = r##"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis OS · Consent</title>
<style>
  :root { --bg:#FAF8F4; --ink:#151C19; --muted:#646D68; --line:#DFDAD0; --accent:#233E33; --soft:#E3ECE7; --warn:#8F5638; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
  .wrap { max-width:860px; margin:0 auto; padding:44px 22px 80px; }
  .top { display:flex; align-items:flex-start; justify-content:space-between; gap:20px; }
  .kicker { font:11px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.12em; text-transform:uppercase; color:var(--muted); }
  h1 { font:400 34px/1.2 Georgia,"Times New Roman",serif; margin:8px 0 6px; }
  .sub { color:var(--muted); margin:0 0 26px; max-width:44rem; }
  .lang { border:1px solid var(--line); background:transparent; color:var(--muted); padding:5px 10px; font:11px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.08em; cursor:pointer; }
  .lang:hover { border-color:var(--accent); color:var(--accent); }
  .card { background:#FDFCF9; border:1px solid var(--line); padding:18px 20px; margin:14px 0; }
  .row { display:flex; justify-content:space-between; gap:18px; align-items:flex-start; }
  .agent { font-weight:600; font-size:17px; }
  .meta { color:var(--muted); font-size:13px; margin-top:2px; overflow-wrap:anywhere; }
  .scope { border-top:1px solid var(--line); margin-top:14px; padding-top:12px; }
  .scope-title { font:11px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; letter-spacing:.1em; text-transform:uppercase; color:var(--muted); margin-bottom:8px; }
  .scope-empty { color:var(--muted); font-size:13px; }
  .checks { display:flex; flex-wrap:wrap; gap:8px 16px; margin:4px 0 10px; }
  .check { display:inline-flex; align-items:center; gap:7px; font-size:14px; overflow-wrap:anywhere; }
  .check input { accent-color:var(--accent); }
  .scope-note { color:var(--muted); font-size:12px; margin-top:6px; }
  .warn { color:var(--warn); font-size:13px; margin-top:10px; }
  .actions { display:flex; flex-wrap:wrap; gap:10px; margin-top:16px; }
  button.action { border:0; padding:9px 16px; cursor:pointer; font-size:14px; }
  button.action:disabled { opacity:.45; cursor:not-allowed; }
  .allow { background:var(--accent); color:#F4F1EA; }
  .deny { background:transparent; color:var(--ink); border:1px solid var(--line); }
  .empty { color:var(--muted); padding:40px 0; }
  .error { color:var(--warn); }
  .notice { min-height:22px; margin:0 0 10px; font-size:13px; color:var(--muted); }
  .notice.ok { color:var(--accent); }
  .notice.bad { color:var(--warn); }
  @media (max-width:640px) { .wrap { padding-top:30px; } .row { flex-direction:column; gap:4px; } h1 { font-size:28px; } }
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div>
      <div class="kicker" id="kicker">Aegis OS · UOMP consent</div>
      <h1 id="title">Approve memory access</h1>
      <p class="sub" id="sub">Only the scope you select below is granted. The agent cannot approve its own request.</p>
    </div>
    <button class="lang" id="lang" type="button">中文</button>
  </div>
  <div class="notice" id="notice"></div>
  <div id="list" class="empty">Loading pending requests…</div>
</div>
<script>
const I18N = {
  en: {
    kicker: 'Aegis OS · UOMP consent',
    title: 'Approve memory access',
    sub: 'Only the scope you select below is granted. The agent cannot approve its own request.',
    loading: 'Loading pending requests…',
    noPending: 'No pending requests.',
    read: 'Read',
    write: 'Write',
    tags: 'Tags',
    keys: 'Specific keys',
    none: 'No scope requested.',
    task: 'task',
    session: 'session',
    expires: 'expires',
    expired: 'expired',
    allow: 'Allow selected',
    deny: 'Deny',
    highKeyHint: 'Specific keys are required for high-sensitivity items and must be approved one by one.',
    selectOne: 'Select at least one tag or key.',
    approved: 'Approved. The agent can continue.',
    denied: 'Denied.',
    memoryDown: 'Cannot reach the memory server',
    requestFailed: 'Request failed',
    lang: '中文'
  },
  zh: {
    kicker: 'Aegis OS · UOMP 同意',
    title: '批准记忆访问',
    sub: '只授予下方勾选的范围。Agent 无法批准自己的请求。',
    loading: '正在加载待审批请求…',
    noPending: '当前没有待审批请求。',
    read: '读取',
    write: '写入',
    tags: '标签',
    keys: '具体 Key',
    none: '未请求任何范围。',
    task: '任务',
    session: '会话',
    expires: '过期',
    expired: '已过期',
    allow: '允许所选范围',
    deny: '拒绝',
    highKeyHint: '高敏数据必须使用具体 Key，并逐 key 批准。',
    selectOne: '至少选择一个标签或 Key。',
    approved: '已批准，Agent 可以继续。',
    denied: '已拒绝。',
    memoryDown: '无法连接 memory server',
    requestFailed: '操作失败',
    lang: 'EN'
  }
};
let lang = (navigator.language || 'en').toLowerCase().startsWith('zh') ? 'zh' : 'en';
const token = new URLSearchParams(location.search).get('token') || '';
const listEl = document.getElementById('list');
const noticeEl = document.getElementById('notice');
let requests = [];
let selection = new Map();
let loading = false;

function t() { return I18N[lang]; }

function applyStatic() {
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  document.getElementById('kicker').textContent = t().kicker;
  document.getElementById('title').textContent = t().title;
  document.getElementById('sub').textContent = t().sub;
  document.getElementById('lang').textContent = t().lang;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function keyFor(requestId, action, kind, value) {
  return requestId + '|' + action + '|' + kind + '|' + value;
}

function isSelected(requestId, action, kind, value) {
  return selection.get(keyFor(requestId, action, kind, value)) !== false;
}

function collectScopes(request) {
  const scopes = JSON.parse(JSON.stringify(request.requested_scopes || {}));
  for (const action of ['read', 'write']) {
    const scope = scopes[action] || (scopes[action] = {});
    scope.tags = (scope.tags || []).filter(value => isSelected(request.request_id, action, 'tags', value));
    scope.keys = (scope.keys || []).filter(value => isSelected(request.request_id, action, 'keys', value));
  }
  return scopes;
}

function hasSelection(request) {
  const scopes = collectScopes(request);
  return ['read', 'write'].some(action => {
    const scope = scopes[action] || {};
    return (scope.tags || []).length + (scope.keys || []).length > 0;
  });
}

function checkbox(requestId, action, kind, value) {
  const label = el('label', 'check');
  const input = document.createElement('input');
  input.type = 'checkbox';
  input.checked = isSelected(requestId, action, kind, value);
  input.onchange = () => {
    selection.set(keyFor(requestId, action, kind, value), input.checked);
    updateAllowButtons();
  };
  label.appendChild(input);
  label.appendChild(document.createTextNode(value));
  return label;
}

function scopeBlock(request, action) {
  const scope = (request.requested_scopes || {})[action] || {};
  const tags = scope.tags || [];
  const keys = scope.keys || [];
  const block = el('div', 'scope');
  block.appendChild(el('div', 'scope-title', t()[action]));
  if (!tags.length && !keys.length) {
    block.appendChild(el('div', 'scope-empty', t().none));
    return block;
  }
  if (tags.length) {
    block.appendChild(el('div', 'meta', t().tags));
    const checks = el('div', 'checks');
    for (const tag of tags) checks.appendChild(checkbox(request.request_id, action, 'tags', tag));
    block.appendChild(checks);
  }
  if (keys.length) {
    block.appendChild(el('div', 'meta', t().keys));
    const checks = el('div', 'checks');
    for (const key of keys) checks.appendChild(checkbox(request.request_id, action, 'keys', key));
    block.appendChild(checks);
    block.appendChild(el('div', 'scope-note', t().highKeyHint));
  }
  return block;
}

function formatExpiry(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const seconds = Math.max(0, Math.floor((date.getTime() - Date.now()) / 1000));
  const remain = seconds > 0
    ? Math.floor(seconds / 60) + 'm ' + String(seconds % 60).padStart(2, '0') + 's'
    : t().expired;
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' · ' + remain;
}

function card(request) {
  const node = el('div', 'card');
  const row = el('div', 'row');
  const left = el('div');
  left.appendChild(el('div', 'agent', request.agent_name || request.agent_id || 'agent'));
  left.appendChild(el('div', 'meta', t().task + ' ' + (request.task_id || '-') + ' · ' + t().session + ' ' + (request.session_id || '-')));
  const right = el('div', 'meta', t().expires + ' ' + formatExpiry(request.expires_at));
  row.appendChild(left);
  row.appendChild(right);
  node.appendChild(row);
  node.appendChild(scopeBlock(request, 'read'));
  node.appendChild(scopeBlock(request, 'write'));

  const actions = el('div', 'actions');
  const allow = el('button', 'action allow', t().allow);
  allow.type = 'button';
  allow.dataset.requestId = request.request_id;
  allow.disabled = !hasSelection(request);
  allow.onclick = () => decide(request, 'approve', allow);
  const deny = el('button', 'action deny', t().deny);
  deny.type = 'button';
  deny.onclick = () => decide(request, 'deny', deny);
  actions.appendChild(allow);
  actions.appendChild(deny);
  node.appendChild(actions);
  return node;
}

function render() {
  listEl.innerHTML = '';
  if (!requests.length) {
    listEl.className = 'empty';
    listEl.textContent = t().noPending;
    return;
  }
  listEl.className = '';
  for (const request of requests) listEl.appendChild(card(request));
}

function updateAllowButtons() {
  document.querySelectorAll('button.allow').forEach(button => {
    const request = requests.find(item => item.request_id === button.dataset.requestId);
    button.disabled = !request || !hasSelection(request);
  });
}

function showNotice(message, kind) {
  noticeEl.textContent = message;
  noticeEl.className = 'notice ' + kind;
  window.setTimeout(() => {
    if (noticeEl.textContent === message) {
      noticeEl.textContent = '';
      noticeEl.className = 'notice';
    }
  }, 4500);
}

function api(path, options = {}) {
  const separator = path.includes('?') ? '&' : '?';
  return fetch(path + separator + 'token=' + encodeURIComponent(token), {
    cache: 'no-store',
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) }
  }).then(async response => {
    const text = await response.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (_) { data = {}; }
    if (!response.ok) {
      const message = (data.error && data.error.message) || text || response.statusText;
      throw new Error(message);
    }
    return data;
  });
}

async function decide(request, action, button) {
  button.disabled = true;
  try {
    const body = action === 'approve' ? { granted_scopes: collectScopes(request) } : {};
    await api('/api/' + action + '/' + encodeURIComponent(request.request_id), {
      method: 'POST',
      body: JSON.stringify(body)
    });
    showNotice(action === 'approve' ? t().approved : t().denied, 'ok');
    await load();
  } catch (error) {
    showNotice(t().requestFailed + ': ' + error.message, 'bad');
    button.disabled = false;
  }
}

async function load() {
  if (loading) return;
  loading = true;
  try {
    const data = await api('/api/pending');
    requests = data.requests || [];
    render();
  } catch (error) {
    listEl.className = 'empty error';
    listEl.textContent = t().memoryDown + ': ' + error.message;
  } finally {
    loading = false;
  }
}

document.getElementById('lang').onclick = () => {
  lang = lang === 'zh' ? 'en' : 'zh';
  applyStatic();
  render();
  updateAllowButtons();
};
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) load();
});
applyStatic();
load();
window.setInterval(load, 2000);
</script>
</body>
</html>"##;
