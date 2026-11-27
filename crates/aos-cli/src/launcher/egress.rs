use super::*;

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct DlpFileConfig {
    #[serde(default)]
    pub(super) pseudonym_mode: Option<String>,
    #[serde(default)]
    pub(super) budget_usd: Option<f64>,
    #[serde(default)]
    pub(super) max_tokens: Option<u64>,
    #[serde(default)]
    pub(super) max_requests: Option<u32>,
    #[serde(default)]
    pub(super) max_identical_loop_streak: Option<u32>,
    #[serde(default)]
    pub(super) custom_literals: Vec<DlpFileLiteralEntry>,
    #[serde(default)]
    pub(super) pricing: std::collections::HashMap<String, ModelRate>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(super) enum DlpFileLiteralEntry {
    Rule(CustomRedactionRule),
    Literal(String),
}

pub(super) fn usd_to_micro_usd(usd: f64, source: &str) -> anyhow::Result<u64> {
    if !usd.is_finite() || usd < 0.0 {
        bail!("invalid {source} USD budget '{usd}'; must be a finite non-negative number");
    }
    let scaled = (usd * 1_000_000.0).round();
    if scaled >= u64::MAX as f64 {
        Ok(u64::MAX - 1)
    } else {
        Ok(scaled as u64)
    }
}

pub(super) fn read_dlp_config_file(path: &Path) -> anyhow::Result<DlpFileConfig> {
    const MAX_DLP_CONFIG_BYTES: u64 = 256 * 1024;
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting DLP config {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("refusing symlinked DLP config at {}", path.display());
    }
    if !meta.file_type().is_file() {
        bail!("DLP config path {} is not a regular file", path.display());
    }
    if meta.len() > MAX_DLP_CONFIG_BYTES {
        bail!(
            "DLP config {} exceeds 256 KiB limit ({} bytes)",
            path.display(),
            meta.len()
        );
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading DLP config {}", path.display()))?;
    serde_json::from_str::<DlpFileConfig>(&raw)
        .with_context(|| format!("parsing DLP config JSON {}", path.display()))
}

pub(crate) fn resolve_session_dlp_settings_with_env(
    project: &Path,
    opts: &RunEgressOptions,
    env_dlp_mode: Option<&str>,
    env_budget_usd: Option<&str>,
    env_max_tokens: Option<&str>,
) -> anyhow::Result<(DlpGatewayConfig, std::collections::HashMap<String, ModelRate>)> {
    let file_cfg = if let Some(ref explicit) = opts.dlp_config {
        read_dlp_config_file(explicit)?
    } else {
        let default_path = project.join(".aegis").join("dlp.json");
        match std::fs::symlink_metadata(&default_path) {
            Ok(_) => read_dlp_config_file(&default_path)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => DlpFileConfig::default(),
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("inspecting default DLP config {}", default_path.display())
                });
            }
        }
    };

    let mode_raw = opts
        .dlp_mode
        .as_deref()
        .or(env_dlp_mode.filter(|s| !s.trim().is_empty()))
        .or(file_cfg.pseudonym_mode.as_deref())
        .unwrap_or("block");
    let pseudonym_mode: PseudonymMode = mode_raw
        .parse()
        .map_err(|e: String| anyhow::anyhow!("{e}"))?;

    let env_usd_parsed = match env_budget_usd.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(
            raw.parse::<f64>()
                .with_context(|| format!("parsing AOS_BUDGET_USD='{raw}'"))?,
        ),
        None => None,
    };
    let env_tokens_parsed = match env_max_tokens.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(
            raw.parse::<u64>()
                .with_context(|| format!("parsing AOS_MAX_TOKENS='{raw}'"))?,
        ),
        None => None,
    };

    let eff_budget_usd = opts.budget_usd.or(env_usd_parsed).or(file_cfg.budget_usd);
    let max_cost_micro_usd = match eff_budget_usd {
        Some(usd) => Some(usd_to_micro_usd(usd, "budget_usd")?),
        None => None,
    };
    let max_tokens = opts.max_tokens.or(env_tokens_parsed).or(file_cfg.max_tokens);
    let max_requests = file_cfg.max_requests;
    let explicit_streak = opts.max_loop_streak.or(file_cfg.max_identical_loop_streak);

    let budget = if max_cost_micro_usd.is_some()
        || max_tokens.is_some()
        || max_requests.is_some()
        || explicit_streak.is_some()
    {
        Some(BudgetPolicy {
            max_tokens,
            max_cost_micro_usd,
            max_requests,
            max_identical_loop_streak: explicit_streak.unwrap_or(4),
        })
    } else {
        None
    };

    let custom_patterns: Vec<CustomRedactionRule> = file_cfg
        .custom_literals
        .into_iter()
        .enumerate()
        .filter_map(|(idx, entry)| match entry {
            DlpFileLiteralEntry::Rule(r) if !r.literal.trim().is_empty() => Some(r),
            DlpFileLiteralEntry::Literal(s) if !s.trim().is_empty() => Some(CustomRedactionRule {
                name: format!("literal_{idx}"),
                literal: s,
                tag: None,
            }),
            _ => None,
        })
        .collect();

    Ok((
        DlpGatewayConfig {
            pseudonym_mode,
            custom_patterns,
            budget,
        },
        file_cfg.pricing,
    ))
}

pub(crate) fn resolve_session_dlp_settings(
    project: &Path,
    opts: &RunEgressOptions,
) -> anyhow::Result<(DlpGatewayConfig, std::collections::HashMap<String, ModelRate>)> {
    let env_mode = std::env::var("AOS_DLP_MODE").ok();
    let env_usd = std::env::var("AOS_BUDGET_USD").ok();
    let env_tok = std::env::var("AOS_MAX_TOKENS").ok();
    resolve_session_dlp_settings_with_env(
        project,
        opts,
        env_mode.as_deref(),
        env_usd.as_deref(),
        env_tok.as_deref(),
    )
}

pub(super) async fn persist_egress_usage(
    telemetry: Option<&ExitTelemetryContext>,
    session_dir: &Path,
) -> Option<UsageSnapshot> {
    let ctx = telemetry?;
    let snap = ctx.gateway.usage_snapshot(&ctx.identity).await;
    let usage_path = session_dir.join("egress_usage.json");
    let has_activity = snap.requests > 0
        || snap.dlp_blocks > 0
        || snap.pseudonym_replacements > 0
        || snap.tripped.is_some()
        || usage_path.exists();
    if !has_activity {
        return None;
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(&snap) {
        let _ = aos_core::session::write_bytes_atomic_synced(&usage_path, &bytes);
    }
    Some(snap)
}

pub(super) struct EgressGuard {
    pub(super) gateway: Arc<AegisEgressGateway>,
    pub(super) handle: Option<tokio::task::JoinHandle<()>>,
    pub(super) cred_watch_handle: Option<tokio::task::JoinHandle<()>>,
    pub(super) sock: Option<PathBuf>,
    pub(super) egress_dir: PathBuf,
    pub(super) temp_dir: Option<PathBuf>,
}

impl Drop for EgressGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.cred_watch_handle.take() {
            handle.abort();
        }
        if let Some(ref sock) = self.sock {
            let _ = std::fs::remove_file(sock);
        }
        if let Some(ref dir) = self.temp_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

pub(super) struct PreviewGuard {
    pub(super) handles: Vec<tokio::task::JoinHandle<()>>,
    pub(super) dir: PathBuf,
}

impl Drop for PreviewGuard {
    fn drop(&mut self) {
        for handle in self.handles.drain(..) {
            handle.abort();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub(super) const BOUNDARY_SECRET_SPECS: &[(&str, &str, &str, &[&str])] = &[
    (
        "ANTHROPIC_API_KEY",
        "$AOS_SECRET_ANTHROPIC_API_KEY",
        "api.anthropic.com",
        &["/v1/"],
    ),
    (
        "ANTHROPIC_AUTH_TOKEN",
        "$AOS_SECRET_ANTHROPIC_AUTH_TOKEN",
        "api.anthropic.com",
        &["/v1/"],
    ),
    // Format-preserving `sk-ant-oat01-` prefix so Claude Code and Hermes select the OAuth
    // `Bearer` + `anthropic-beta: oauth-2025-04-20` wire path without holding the real token.
    (
        "CLAUDE_CODE_OAUTH_TOKEN",
        "sk-ant-oat01-$AOS_SECRET_CLAUDE_CODE_OAUTH_TOKEN",
        "api.anthropic.com",
        &["/v1/", "/api/"],
    ),
    (
        "OPENAI_API_KEY",
        "$AOS_SECRET_OPENAI_API_KEY",
        "api.openai.com",
        &["/v1/"],
    ),
    (
        "DEEPSEEK_API_KEY",
        "$AOS_SECRET_DEEPSEEK_API_KEY",
        "api.deepseek.com",
        &["/v1/", "/chat/"],
    ),
    (
        "OPENROUTER_API_KEY",
        "$AOS_SECRET_OPENROUTER_API_KEY",
        "openrouter.ai",
        &["/api/v1/", "/v1/"],
    ),
    (
        "GROQ_API_KEY",
        "$AOS_SECRET_GROQ_API_KEY",
        "api.groq.com",
        &["/openai/v1/", "/v1/"],
    ),
    (
        "MISTRAL_API_KEY",
        "$AOS_SECRET_MISTRAL_API_KEY",
        "api.mistral.ai",
        &["/v1/"],
    ),
    (
        "XAI_API_KEY",
        "$AOS_SECRET_XAI_API_KEY",
        "api.x.ai",
        &["/v1/"],
    ),
    (
        "GEMINI_API_KEY",
        "$AOS_SECRET_GEMINI_API_KEY",
        "generativelanguage.googleapis.com",
        &["/v1/", "/v1beta/"],
    ),
    (
        "GOOGLE_API_KEY",
        "$AOS_SECRET_GOOGLE_API_KEY",
        "generativelanguage.googleapis.com",
        &["/v1/", "/v1beta/"],
    ),
];

pub(super) fn boundary_secret_placeholder(env_key: &str) -> Option<&'static str> {
    BOUNDARY_SECRET_SPECS
        .iter()
        .find(|(k, _, _, _)| *k == env_key)
        .map(|(_, ph, _, _)| *ph)
}

pub(super) fn opencode_provider_secret_spec(provider: &str) -> Option<(&'static str, &'static str)> {
    let env_key = match provider.trim().to_ascii_lowercase().as_str() {
        "anthropic" => "ANTHROPIC_API_KEY",
        "openai" => "OPENAI_API_KEY",
        "deepseek" => "DEEPSEEK_API_KEY",
        "openrouter" => "OPENROUTER_API_KEY",
        "groq" => "GROQ_API_KEY",
        "mistral" => "MISTRAL_API_KEY",
        "xai" => "XAI_API_KEY",
        "google" | "gemini" => "GEMINI_API_KEY",
        _ => return None,
    };
    boundary_secret_placeholder(env_key).map(|ph| (env_key, ph))
}

pub(crate) fn harvest_host_secrets(
    host_home: &Path,
    command: &[String],
) -> std::collections::HashMap<String, String> {
    let mut secrets = std::collections::HashMap::new();

    // 1. Explicit caller environment variables take top priority.
    for &(env_key, _, _, _) in BOUNDARY_SECRET_SPECS {
        if let Ok(val) = std::env::var(env_key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() && !trimmed.contains("$AOS_SECRET_") {
                secrets.insert(env_key.to_string(), trimmed.to_string());
            }
        }
    }

    // 2. Host `~/.hermes/.env`
    if let Ok(raw) = std::fs::read_to_string(host_home.join(".hermes/.env")) {
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed);
            if let Some((k, v)) = stripped.split_once('=') {
                let key = k.trim();
                let val = v.trim().trim_matches('"').trim_matches('\'');
                if boundary_secret_placeholder(key).is_some()
                    && !val.is_empty()
                    && !val.contains("$AOS_SECRET_")
                    && !secrets.contains_key(key)
                {
                    secrets.insert(key.to_string(), val.to_string());
                }
            }
        }
    }

    // 3. Host `~/.local/share/opencode/auth.json`
    if let Ok(raw) = std::fs::read_to_string(host_home.join(".local/share/opencode/auth.json")) {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&raw) {
            for (prov, entry) in map {
                let Some((env_key, _)) = opencode_provider_secret_spec(&prov) else {
                    continue;
                };
                if secrets.contains_key(env_key) {
                    continue;
                }
                if let Some(val) = entry.get("key").and_then(|v| v.as_str()) {
                    let trimmed = val.trim();
                    if !trimmed.is_empty() && !trimmed.contains("$AOS_SECRET_") {
                        secrets.insert(env_key.to_string(), trimmed.to_string());
                    }
                }
            }
        }
    }

    // 4. Host `~/.claude/.credentials.json` (Linux / cross-platform OAuth store)
    // When running `claude` itself without an explicit `CLAUDE_CODE_OAUTH_TOKEN` in the caller's
    // environment, do not inject `CLAUDE_CODE_OAUTH_TOKEN` into `process.env`. Setting
    // `CLAUDE_CODE_OAUTH_TOKEN` in `process.env` prevents Claude Code from auto-refreshing
    // expired OAuth tokens via `refreshToken`, triggers a warning during `/login`, and breaks
    // direct HTTPS CONNECT calls to `api.anthropic.com/api/oauth/*`. Instead, `claude` uses its
    // isolated `agent_home/.claude/.credentials.json` (while non-Claude agents like `hermes`
    // continue to receive the boundary-injected placeholder if valid).
    let has_anthropic = secrets.contains_key("ANTHROPIC_API_KEY")
        || secrets.contains_key("ANTHROPIC_AUTH_TOKEN")
        || secrets.contains_key("CLAUDE_CODE_OAUTH_TOKEN");
    if !has_anthropic && !is_claude_command(command) {
        if let Ok(raw) = std::fs::read_to_string(host_home.join(".claude/.credentials.json")) {
            if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                let now_ms = chrono::Utc::now().timestamp_millis();
                let expired = val
                    .pointer("/claudeAiOauth/expiresAt")
                    .and_then(|v| v.as_i64())
                    .is_some_and(|exp| exp > 0 && exp <= now_ms + 60_000);
                if !expired {
                    if let Some(tok) = val
                        .pointer("/claudeAiOauth/accessToken")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty() && !s.contains("$AOS_SECRET_"))
                    {
                        secrets.insert("CLAUDE_CODE_OAUTH_TOKEN".to_string(), tok.to_string());
                    }
                }
            }
        }
    }

    // 5. Optional opt-in macOS Keychain `Claude Code-credentials` -> host-side boundary vault bridge.
    // Disabled by default (`AOS_MACOS_KEYCHAIN_BRIDGE=1` required) because `/usr/bin/security`
    // triggers interactive macOS Keychain ACL dialogs when spawned under a non-Terminal parent app.
    #[cfg(target_os = "macos")]
    if std::env::var("AOS_MACOS_KEYCHAIN_BRIDGE").as_deref() == Ok("1") {
        let is_claude = command
            .first()
            .and_then(|c| Path::new(c).file_name())
            .and_then(|s| s.to_str())
            .is_some_and(|name| name.contains("claude"));
        let has_anthropic_now = secrets.contains_key("ANTHROPIC_API_KEY")
            || secrets.contains_key("ANTHROPIC_AUTH_TOKEN")
            || secrets.contains_key("CLAUDE_CODE_OAUTH_TOKEN");
        if is_claude && !has_anthropic_now {
            if let Ok(out) = std::process::Command::new("/usr/bin/security")
                .args([
                    "find-generic-password",
                    "-s",
                    "Claude Code-credentials",
                    "-w",
                ])
                .stdin(Stdio::null())
                .output()
            {
                if out.status.success() {
                    let raw = String::from_utf8_lossy(&out.stdout);
                    if let Ok(val) = serde_json::from_str::<Value>(raw.trim()) {
                        if let Some(tok) = val
                            .pointer("/claudeAiOauth/accessToken")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty() && !s.contains("$AOS_SECRET_"))
                        {
                            secrets.insert("CLAUDE_CODE_OAUTH_TOKEN".to_string(), tok.to_string());
                        }
                    }
                }
            }
        }
    }
    let _ = command;
    secrets
}

pub(crate) async fn register_boundary_secrets(
    gateway: &AegisEgressGateway,
    identity: &AgentIdentity,
    harvested: &std::collections::HashMap<String, String>,
) {
    for &(env_key, placeholder, domain, paths) in BOUNDARY_SECRET_SPECS {
        let Some(value) = harvested.get(env_key) else {
            continue;
        };
        if value.trim().is_empty() {
            continue;
        }
        gateway
            .register_scoped_secret(
                SecretVaultEntry {
                    org_id: identity.org_id.clone(),
                    placeholder: placeholder.to_string(),
                    real_secret_value: value.clone(),
                    allowed_domains: vec![domain.to_string()],
                },
                vec![
                    "GET".to_string(),
                    "POST".to_string(),
                    "PUT".to_string(),
                    "PATCH".to_string(),
                    "DELETE".to_string(),
                ],
                paths.iter().map(|s| (*s).to_string()).collect(),
            )
            .await;
    }
}

pub(crate) fn default_egress_allow_domains() -> Vec<String> {
    let mut domains: Vec<String> = [
        "api.anthropic.com",
        "api.openai.com",
        "generativelanguage.googleapis.com",
        "cloudcode-pa.googleapis.com",
        "daily-cloudcode-pa.googleapis.com",
        "aicode.googleapis.com",
        "aiplatform.googleapis.com",
        "www.googleapis.com",
        "sts.googleapis.com",
        "iamcredentials.googleapis.com",
        "play.googleapis.com",
        "antigravity.google.com",
        "antigravity-cli-auto-updater-974169037036.us-central1.run.app",
        "api.deepseek.com",
        "api.mistral.ai",
        "api.groq.com",
        "api.x.ai",
        "openrouter.ai",
        "api.openrouter.ai",
        "opencode.ai",
        "api.opencode.ai",
        "models.dev",
        "portal.nousresearch.com",
        "inference-api.nousresearch.com",
        "api.nousresearch.com",
        "api.together.xyz",
        "api.fireworks.ai",
        "huggingface.co",
        "router.huggingface.co",
        "api.githubcopilot.com",
        "copilot-proxy.githubusercontent.com",
        "claude.ai",
        "platform.claude.com",
        "console.anthropic.com",
        "chatgpt.com",
        "auth.openai.com",
        "platform.openai.com",
        "accounts.google.com",
        "oauth2.googleapis.com",
        "api.github.com",
        "github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "crates.io",
        "static.crates.io",
        "index.crates.io",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    if let Ok(extra) = std::env::var("AOS_EGRESS_ALLOW") {
        domains.extend(
            extra
                .split(',')
                .map(str::trim)
                .filter(|domain| !domain.is_empty())
                .map(str::to_string),
        );
    }
    domains
}

pub(crate) fn build_egress_event_sink(
    sink_session_dir: PathBuf,
) -> aos_egress::EgressEventSink {
    Arc::new(move |ev| {
        let effects_path = sink_session_dir.join("effects.jsonl");
        let is_not_symlink = std::fs::symlink_metadata(&effects_path)
            .map(|m| !m.file_type().is_symlink())
            .unwrap_or(true);
        if is_not_symlink {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&effects_path)
            {
                let row = json!({
                    "event": "egress.guard",
                    "detail": ev,
                    "timestamp_ms": chrono::Utc::now().timestamp_millis(),
                });
                let _ = writeln!(file, "{row}");
            }
        }
        if let EgressGuardEvent::CircuitTripped { ref usage, .. } = ev {
            if let Ok(bytes) = serde_json::to_vec_pretty(usage) {
                let _ = aos_core::session::write_bytes_atomic_synced(
                    &sink_session_dir.join("egress_usage.json"),
                    &bytes,
                );
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn start_egress(
    identity: &AgentIdentity,
    session_dir: &Path,
    agent_home: &Path,
    host_home: &Path,
    command: &[String],
    harvested_secrets: &std::collections::HashMap<String, String>,
    dlp_cfg: &DlpGatewayConfig,
    pricing_overrides: &std::collections::HashMap<String, ModelRate>,
) -> anyhow::Result<(EgressGuard, String, String)> {
    let gateway = Arc::new(AegisEgressGateway::new());
    if !pricing_overrides.is_empty() {
        gateway.set_pricing_overrides(pricing_overrides.clone()).await;
    }
    if dlp_cfg.pseudonym_mode != PseudonymMode::Block || dlp_cfg.budget.is_some() {
        gateway
            .set_dlp_config_for_agent(identity, dlp_cfg.clone(), None, None)
            .await;
    }
    gateway
        .set_event_sink(build_egress_event_sink(session_dir.to_path_buf()))
        .await;
    gateway
        .allow_domains(&identity.org_id, default_egress_allow_domains())
        .await;
    register_boundary_secrets(&gateway, identity, harvested_secrets).await;
    let watch_enabled = is_claude_command(command)
        || is_codex_command(command)
        || is_hermes_command(command)
        || is_agy_or_gemini_command(command)
        || is_opencode_command(command);
    let cred_watch_handle = if watch_enabled {
        let gw_watch = gateway.clone();
        let id_watch = identity.clone();
        let agent_home_watch = agent_home.to_path_buf();
        let host_home_watch = host_home.to_path_buf();
        let cmd_watch = command.to_vec();
        Some(tokio::spawn(async move {
            let mut last_creds = read_sandbox_json_object_no_symlink(
                &agent_home_watch,
                ".claude/.credentials.json",
                false,
            )
            .map(|(raw, _)| raw)
            .unwrap_or_default();
            let mut last_claude_json = read_sandbox_json_object_with_limit_no_symlink(
                &agent_home_watch,
                ".claude.json",
                false,
                MAX_SETTINGS_SYNC_BYTES,
            )
            .map(|(raw, _)| raw)
            .unwrap_or_default();
            let mut last_codex_auth = read_sandbox_json_object_no_symlink(
                &agent_home_watch,
                ".codex/auth.json",
                false,
            )
            .map(|(raw, _)| raw)
            .unwrap_or_default();
            let mut last_agy_gemini_fp =
                agy_gemini_watch_fingerprint(&agent_home_watch, is_agy_command(&cmd_watch));
            let mut last_oc_auth = read_sandbox_json_object_no_symlink(
                &agent_home_watch,
                ".local/share/opencode/auth.json",
                true,
            )
            .map(|(raw, _)| raw)
            .unwrap_or_default();
            let mut last_hermes_auth = read_sandbox_json_object_no_symlink(
                &agent_home_watch,
                ".hermes/auth.json",
                false,
            )
            .map(|(raw, _)| raw)
            .unwrap_or_default();
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                let mut need_sync = false;
                if is_claude_command(&cmd_watch) {
                    if let Some((raw, map)) = read_sandbox_json_object_no_symlink(
                        &agent_home_watch,
                        ".claude/.credentials.json",
                        false,
                    ) {
                        if raw != last_creds {
                            last_creds = raw;
                            need_sync = true;
                            let val = Value::Object(map);
                            if let Some(tok) = val
                                .pointer("/claudeAiOauth/accessToken")
                                .and_then(|v| v.as_str())
                                .map(str::trim)
                                .filter(|s| !s.is_empty() && !s.contains("$AOS_SECRET_"))
                            {
                                let mut secret_map = std::collections::HashMap::new();
                                secret_map.insert(
                                    "CLAUDE_CODE_OAUTH_TOKEN".to_string(),
                                    tok.to_string(),
                                );
                                register_boundary_secrets(&gw_watch, &id_watch, &secret_map).await;
                            }
                        }
                    }
                    if let Some((raw_json, _)) = read_sandbox_json_object_with_limit_no_symlink(
                        &agent_home_watch,
                        ".claude.json",
                        false,
                        MAX_SETTINGS_SYNC_BYTES,
                    ) {
                        if raw_json != last_claude_json {
                            last_claude_json = raw_json;
                            need_sync = true;
                        }
                    }
                } else if is_codex_command(&cmd_watch) {
                    if let Some((raw_codex, _)) = read_sandbox_json_object_no_symlink(
                        &agent_home_watch,
                        ".codex/auth.json",
                        false,
                    ) {
                        if raw_codex != last_codex_auth {
                            last_codex_auth = raw_codex;
                            need_sync = true;
                        }
                    }
                } else if is_agy_or_gemini_command(&cmd_watch) {
                    let fp = agy_gemini_watch_fingerprint(
                        &agent_home_watch,
                        is_agy_command(&cmd_watch),
                    );
                    if fp != last_agy_gemini_fp {
                        last_agy_gemini_fp = fp;
                        need_sync = true;
                    }
                } else if is_opencode_command(&cmd_watch) {
                    if let Some((raw_oc, map)) = read_sandbox_json_object_no_symlink(
                        &agent_home_watch,
                        ".local/share/opencode/auth.json",
                        true,
                    ) {
                        if raw_oc != last_oc_auth {
                            last_oc_auth = raw_oc;
                            need_sync = true;
                            let mut new_secrets = std::collections::HashMap::new();
                            for (prov, entry) in map {
                                if !is_valid_opencode_auth_entry(&entry) {
                                    continue;
                                }
                                if let Some((env_key, _)) = opencode_provider_secret_spec(&prov) {
                                    if let Some(val) = entry
                                        .get("key")
                                        .and_then(|v| v.as_str())
                                        .map(str::trim)
                                        .filter(|s| !s.is_empty() && !s.contains("$AOS_SECRET_"))
                                    {
                                        new_secrets.insert(env_key.to_string(), val.to_string());
                                    }
                                }
                            }
                            if !new_secrets.is_empty() {
                                register_boundary_secrets(&gw_watch, &id_watch, &new_secrets).await;
                            }
                        }
                    }
                } else if is_hermes_command(&cmd_watch) {
                    if let Some((raw_hermes, _)) = read_sandbox_json_object_no_symlink(
                        &agent_home_watch,
                        ".hermes/auth.json",
                        false,
                    ) {
                        if raw_hermes != last_hermes_auth {
                            last_hermes_auth = raw_hermes;
                            need_sync = true;
                        }
                    }
                }
                if need_sync {
                    sync_credentials(&agent_home_watch, &host_home_watch, &cmd_watch);
                }
            }
        }))
    } else {
        None
    };
    let proxy = gateway
        .clone()
        .start_local_proxy_with_bound_identity("127.0.0.1:0", Some(identity.clone()))
        .await?;
    let proxy = proxy.to_string();
    #[cfg(target_os = "macos")]
    {
        // macOS Seatbelt sessions connect directly to the loopback TCP proxy (`127.0.0.1:<port>`);
        // skipping the Linux netns Unix-socket bridge avoids macOS `SUN_LEN` (104-byte) failures
        // when `--runtime-dir` lives under deep `$TMPDIR` (`/var/folders/...`) paths.
        let egress_dir = session_dir.join("egress");
        std::fs::create_dir_all(&egress_dir)?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&egress_dir, std::fs::Permissions::from_mode(0o700));
        Ok((
            EgressGuard {
                gateway,
                handle: None,
                cred_watch_handle,
                sock: None,
                egress_dir,
                temp_dir: None,
            },
            proxy,
            String::new(),
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut egress_dir = session_dir.join("egress");
        let mut temp_dir = None;
        if egress_dir.join("bridge.sock").as_os_str().len() >= 96 {
            let short = PathBuf::from(format!(
                "/tmp/aos-eg-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            ));
            temp_dir = Some(short.clone());
            egress_dir = short;
        }
        std::fs::create_dir_all(&egress_dir)?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&egress_dir, std::fs::Permissions::from_mode(0o700));
        let sock = egress_dir.join("bridge.sock");
        let token = aos_sandbox::bridge::new_token();
        let handle = aos_sandbox::bridge::spawn_host_bridge(&sock, proxy.clone(), token.clone())?;
        Ok((
            EgressGuard {
                gateway,
                handle: Some(handle),
                cred_watch_handle,
                sock: Some(sock),
                egress_dir,
                temp_dir,
            },
            proxy,
            token,
        ))
    }
}

pub(crate) fn l7_base_url_envs(proxy: &str) -> Vec<(&'static str, String)> {
    let base = format!("http://{proxy}/__aegis/base");
    vec![
        ("ANTHROPIC_BASE_URL", format!("{base}/anthropic")),
        ("OPENAI_BASE_URL", format!("{base}/openai")),
        ("OPENAI_API_BASE", format!("{base}/openai")),
        ("DEEPSEEK_BASE_URL", format!("{base}/deepseek/v1")),
        ("OPENROUTER_BASE_URL", format!("{base}/openrouter/api/v1")),
        ("GROQ_BASE_URL", format!("{base}/groq/openai/v1")),
        ("MISTRAL_BASE_URL", format!("{base}/mistral/v1")),
        ("XAI_BASE_URL", format!("{base}/xai/v1")),
        ("GOOGLE_GEMINI_BASE_URL", format!("{base}/gemini")),
        ("GEMINI_BASE_URL", format!("{base}/gemini/v1beta")),
    ]
}

pub(super) fn strip_jsonc_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == '/' && chars.peek() == Some(&'/') {
            let _ = chars.next();
            for nc in chars.by_ref() {
                if nc == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            let _ = chars.next();
            while let Some(nc) = chars.next() {
                if nc == '*' && chars.peek() == Some(&'/') {
                    let _ = chars.next();
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub(super) fn opencode_l7_config_content(proxy: &str, existing: Option<&str>) -> String {
    let base = format!("http://{proxy}/__aegis/base");
    let mut root = existing
        .and_then(|raw| {
            serde_json::from_str::<Value>(raw)
                .or_else(|_| serde_json::from_str::<Value>(&strip_jsonc_comments(raw)))
                .ok()
        })
        .filter(|v| v.is_object())
        .unwrap_or_else(|| json!({}));
    let providers = json!({
        "deepseek": { "options": { "baseURL": format!("{base}/deepseek") } },
        "anthropic": { "options": { "baseURL": format!("{base}/anthropic/v1") } },
        "openai": { "options": { "baseURL": format!("{base}/openai/v1") } },
        "openrouter": { "options": { "baseURL": format!("{base}/openrouter/api/v1") } },
        "groq": { "options": { "baseURL": format!("{base}/groq/openai/v1") } },
        "mistral": { "options": { "baseURL": format!("{base}/mistral/v1") } },
        "xai": { "options": { "baseURL": format!("{base}/xai/v1") } },
    });
    if let Some(root_obj) = root.as_object_mut() {
        let prov_entry = root_obj
            .entry("provider".to_string())
            .or_insert_with(|| json!({}));
        if let (Some(dst), Some(src)) = (prov_entry.as_object_mut(), providers.as_object()) {
            for (k, v) in src {
                let entry = dst.entry(k.clone()).or_insert_with(|| json!({}));
                if let (Some(entry_obj), Some(src_opts)) = (
                    entry.as_object_mut(),
                    v.get("options").and_then(|o| o.as_object()),
                ) {
                    let opts = entry_obj
                        .entry("options".to_string())
                        .or_insert_with(|| json!({}));
                    if let Some(opts_obj) = opts.as_object_mut() {
                        for (ok, ov) in src_opts {
                            opts_obj.entry(ok.clone()).or_insert_with(|| ov.clone());
                        }
                    }
                }
            }
        }
    }
    serde_json::to_string(&root).unwrap_or_else(|_| "{}".to_string())
}
