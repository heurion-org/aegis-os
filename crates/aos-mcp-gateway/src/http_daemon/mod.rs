use crate::*;
use axum::extract::{DefaultBodyLimit, Extension, Path as AxumPath, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post, put};
use axum::Router;

mod approvals;
mod auth;
mod billing;
mod mcp;
mod relay;
mod status;
mod workspaces;

pub use auth::DaemonAuth;
pub(crate) use auth::{requested_org, requested_orgs, route_path, AuthContext};

pub(crate) const MAX_TOOL_LEASE_TTL_SECS: i64 = 24 * 3600;

/// HTTP daemon limits: the declared body size is trusted only up to this bound, and the whole
/// request (head + body) must arrive within the timeout.
pub(crate) const MAX_HTTP_BODY_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const HTTP_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone)]
pub(super) struct DaemonState {
    pub kernel: Arc<AegisRuntimeKernel>,
    pub default_workspace: PathBuf,
    pub auth_mode: DaemonAuth,
    pub local_addr: std::net::SocketAddr,
}

pub(super) fn json_string_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))],
        body,
    )
        .into_response()
}

pub(super) fn json_response(status: StatusCode, value: Value) -> Response {
    json_string_response(status, value.to_string())
}

pub(super) fn html_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

pub(super) fn shell_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/x-shellscript; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

async fn not_found_handler() -> Response {
    json_response(StatusCode::NOT_FOUND, json!({ "error": "Not found" }))
}

pub(super) fn build_router(state: DaemonState) -> Router {
    Router::new()
        // Static / status / discovery / telemetry
        .route("/", get(status::dashboard))
        .route("/app", get(relay::get_mobile_app_page))
        .route("/app/manifest.json", get(relay::get_mobile_app_manifest))
        .route("/dashboard", get(status::dashboard))
        .route("/dashboard/*rest", get(status::dashboard))
        .route("/ui", get(status::dashboard))
        .route("/ui/*rest", get(status::dashboard))
        .route("/approve", get(status::approve_page))
        .route("/install.sh", get(status::install_sh))
        .route("/health", get(status::health))
        .route("/.well-known/agent.json", get(status::agent_card))
        .route("/.well-known/agent-card.json", get(status::agent_card))
        .route("/releases/*name", get(status::get_release))
        .route("/api/status", get(status::api_status))
        .route("/v1/status", get(status::api_status))
        .route("/v1/telemetry/friction", post(status::post_friction))
        .route(
            "/v1/telemetry/friction/stats",
            get(status::get_friction_stats),
        )
        .route("/v1/telemetry/ping", post(status::post_telemetry_ping))
        .route("/v1/telemetry/stats", get(status::get_telemetry_stats))
        .route("/v1/desktop/entitlements", any(status::desktop_entitlements))
        // Tenants, billing, orgs, vault secrets
        .route("/v1/tenants/plan", post(billing::post_tenants_plan))
        .route(
            "/v1/tenants/keys",
            post(billing::post_tenants_keys).get(billing::get_tenants_keys),
        )
        .route("/v1/billing/status", any(billing::billing_status))
        .route("/v1/billing/checkout", any(billing::billing_checkout))
        .route("/v1/billing/webhook", post(billing::post_billing_webhook))
        .route("/v1/billing/claim", post(billing::post_billing_claim))
        .route("/v1/orgs", delete(billing::delete_org))
        .route(
            "/v1/vault/secrets",
            post(billing::post_vault_secrets).get(billing::get_vault_secrets),
        )
        // Workspaces
        .route(
            "/v1/workspaces",
            post(workspaces::post_workspaces).get(workspaces::get_workspaces),
        )
        .route("/v1/workspaces/gc-idle", post(workspaces::post_gc_idle))
        .route("/v1/workspaces/hibernate", post(workspaces::post_hibernate))
        .route("/v1/workspaces/delete", post(workspaces::post_delete))
        .route("/v1/workspaces/wake", post(workspaces::post_wake))
        .route("/v1/workspaces/sync-up", post(workspaces::post_sync_up))
        .route("/v1/workspaces/diff", any(workspaces::workspaces_diff))
        .route("/v1/workspaces/pr", post(workspaces::post_pr))
        // Devices, sessions & zero-knowledge E2EE WebSocket relay
        .route("/v1/devices/register", post(relay::post_device_register))
        .route("/v1/devices/pair/start", post(relay::post_pair_start))
        .route("/v1/devices/pair/claim", post(relay::post_pair_claim))
        .route("/v1/devices/pair/approve", post(relay::post_pair_approve))
        .route("/v1/devices/pair/:pair_id", get(relay::get_pair_status))
        .route("/v1/devices", get(relay::get_devices))
        .route("/v1/devices/:id", delete(relay::delete_device))
        .route(
            "/v1/sessions",
            post(relay::post_sessions).get(relay::get_sessions),
        )
        .route(
            "/v1/sessions/:id/heartbeat",
            post(relay::post_session_heartbeat),
        )
        .route("/v1/sessions/:id", delete(relay::delete_session))
        .route("/v1/relay/tickets", post(relay::post_relay_tickets))
        .route("/v1/relay/ws", get(relay::get_relay_ws))
        .route(
            "/v1/sessions/:id/handoff/chunks/check",
            post(relay::post_handoff_chunks_check),
        )
        .route(
            "/v1/sessions/:id/handoff/chunks/:sha256",
            put(relay::put_handoff_chunk).get(relay::get_handoff_chunk),
        )
        .route(
            "/v1/sessions/:id/handoff",
            post(relay::post_handoff_commit).get(relay::get_handoff_manifest),
        )
        .route("/v1/handoffs", get(relay::get_handoffs_list))
        .route("/v1/handoffs/:handoff_id", delete(relay::delete_handoff))
        // Approvers, escalations, leases
        .route(
            "/approver/enroll",
            get(approvals::get_enroll_page).post(approvals::post_enroll),
        )
        .route("/v1/approver", any(approvals::approver_dispatch))
        .route("/v1/approver/email", any(approvals::approver_dispatch))
        .route("/v1/approver/*rest", any(approvals::approver_dispatch))
        .route("/v1/approvals/diff", get(approvals::get_approvals_diff))
        .route("/v1/approvals/decide", post(approvals::post_approvals_decide))
        .route(
            "/v1/approvals/simulate",
            post(approvals::post_approvals_simulate),
        )
        .route("/v1/leases/revoke", post(approvals::post_leases_revoke))
        // MCP governance + JSON-RPC endpoints
        .route("/v1/mcp/inventory", get(mcp::get_inventory))
        .route("/v1/mcp/logout", post(mcp::post_logout))
        .route("/v1/mcp/oauth/start", post(mcp::post_oauth_start))
        .route("/v1/mcp/oauth/status", get(mcp::get_oauth_status))
        .route("/v1/mcp/login-token", post(mcp::post_login_token))
        .route("/v1/mcp/policy", post(mcp::post_policy))
        .route("/v1/mcp/outbox", get(mcp::get_outbox))
        .route("/v1/mcp/outbox/decide", post(mcp::post_outbox_decide))
        .route("/mcp", post(mcp::post_rpc))
        .route("/v1/mcp", post(mcp::post_rpc))
        .route("/a2a", post(mcp::post_rpc))
        .route("/v1/a2a", post(mcp::post_rpc))
        .fallback(not_found_handler)
        .method_not_allowed_fallback(not_found_handler)
        .layer(DefaultBodyLimit::disable())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::guard_and_auth_middleware,
        ))
        .with_state(state)
}

impl AegisRuntimeKernel {
    /// Start the multi-tenant Aegis OS HTTP Daemon (`POST /mcp` Streamable HTTP & `GET /api/status`).
    /// Starts the HTTP daemon with authentication required (see [`DaemonAuth::Required`]).
    pub async fn start_http_daemon(
        self: Arc<Self>,
        bind_addr: &str,
        default_workspace: PathBuf,
    ) -> anyhow::Result<std::net::SocketAddr> {
        self.start_http_daemon_with_auth(bind_addr, default_workspace, DaemonAuth::Required)
            .await
    }

    /// The operator credential (`Authorization: Bearer <token>` or `X-Aegis-Admin-Secret`):
    /// `AOS_ADMIN_SECRET`, or a random token generated when the daemon starts without one.
    pub fn operator_token(&self) -> String {
        self.paas.admin_secret()
    }

    pub async fn start_http_daemon_with_auth(
        self: Arc<Self>,
        bind_addr: &str,
        default_workspace: PathBuf,
        auth_mode: DaemonAuth,
    ) -> anyhow::Result<std::net::SocketAddr> {
        if auth_mode == DaemonAuth::Required && self.paas.admin_secret().is_empty() {
            // Held only in memory and printed by the CLI; never written where a sandbox could read it.
            let generated = format!("aop_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            self.paas.set_ephemeral_admin_secret(&generated);
        }
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;

        // Background Scale-to-Zero Idle Workspace & Expired Handoff GC Daemon (scans every 60s)
        let k_gc = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let _ = k_gc.paas.hibernate_idle_workspaces(&k_gc, None).await;
                let _ = k_gc.relay.handoff.gc_expired(Utc::now().timestamp_millis()).await;
            }
        });

        let router = build_router(DaemonState {
            kernel: self,
            default_workspace,
            auth_mode,
            local_addr,
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        Ok(local_addr)
    }
}
