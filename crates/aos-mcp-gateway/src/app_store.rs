//! Aegis Application Protocol (`AAP-1.0`) App Store Registry & Progressive MCP Proxy (`app_store.rs`)
//!
//! Provides:
//! 1. 3-Tier Application Catalog (`first_party`, `verified`, `community`) with built-in registration
//!    for `heurion` ("知衡 Heurion 2.0 — 临床与科研智能工作台").
//! 2. Persistent App Store & Credential State (`<runtime_data_root>/app_store_state.json`) storing:
//!    - Node key identity (`node_id`, `node_public_key`)
//!    - Installed `AAP-1.0` applications & manifests (`/.well-known/aegis-app.json`)
//!    - Scoped user-bound access tokens (`aegis_at_<app_id>.*`)
//!    - Active per-agent mounted application sessions
//! 3. Progressive Disclosure MCP Tools:
//!    - `app_catalog_search`: Search built-in & installed `AAP-1.0` applications
//!    - `app_mount_session`: Mount an application into the current Agent session and inspect its
//!      `zero_prompt` vs `lease_gated` tools and recommended SOP skills
//!    - `app_call_tool`: Invoke an MCP tool on an `AAP-1.0` application over `POST /api/aegis/mcp`
//!      with automatic injection of `Authorization: Bearer aegis_at_...`, `X-Aegis-Agent-Id`,
//!      `X-Aegis-Session-Id`, and `X-Aegis-Lease-Token`.

use crate::AegisRuntimeKernel;
use anyhow::{bail, Context};
use aos_core::{AgentIdentity, PolicyDecision};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSkillDescriptor {
    pub id: String,
    pub name: String,
    pub description: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogAppTemplate {
    pub app_id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub trust_tier: String,
    pub categories: Vec<String>,
    pub default_endpoint: String,
    pub zero_prompt_tools: Vec<String>,
    pub lease_gated_tools: Vec<String>,
    pub skills: Vec<AppSkillDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledAppRecord {
    pub app_id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub trust_tier: String,
    pub endpoint: String,
    pub manifest: Value,
    #[serde(default)]
    pub installed_skills: Vec<String>,
    pub installed_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCredentialRecord {
    pub app_id: String,
    pub endpoint: String,
    pub access_token: String,
    pub token_prefix: String,
    pub token_id: Option<String>,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub org_id: Option<String>,
    pub trust_tier: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountedAppSession {
    pub app_id: String,
    pub org_id: String,
    pub agent_id: String,
    pub endpoint: String,
    pub mounted_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedAppStoreState {
    pub node_id: String,
    pub node_public_key: String,
    #[serde(default)]
    pub installed_apps: Vec<InstalledAppRecord>,
    #[serde(default)]
    pub credentials: Vec<AppCredentialRecord>,
    #[serde(default)]
    pub mounted_sessions: Vec<MountedAppSession>,
}

impl Default for PersistedAppStoreState {
    fn default() -> Self {
        let random_seed = Uuid::new_v4().to_string();
        let mut hasher = Sha256::new();
        hasher.update(random_seed.as_bytes());
        let pub_hex = hex::encode(hasher.finalize());
        Self {
            node_id: format!("aegis-node-{}", &random_seed[..8]),
            node_public_key: format!("ed25519:{}", &pub_hex[..32]),
            installed_apps: Vec::new(),
            credentials: Vec::new(),
            mounted_sessions: Vec::new(),
        }
    }
}

pub struct AppStoreRegistry {
    state_file: PathBuf,
    state: RwLock<PersistedAppStoreState>,
}

impl AppStoreRegistry {
    pub fn new(runtime_data_root: &Path) -> Self {
        let state_file = runtime_data_root.join("app_store_state.json");
        let initial = std::fs::read(&state_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedAppStoreState>(&b).ok())
            .unwrap_or_default();
        Self {
            state_file,
            state: RwLock::new(initial),
        }
    }

    async fn reload(&self) {
        if let Ok(bytes) = tokio::fs::read(&self.state_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedAppStoreState>(&bytes) {
                *self.state.write().await = parsed;
            }
        }
    }

    async fn flush(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.state_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let snapshot = self.state.read().await.clone();
        let bytes = serde_json::to_vec_pretty(&snapshot)?;
        tokio::fs::write(&self.state_file, bytes).await?;
        Ok(())
    }

    /// Returns the built-in 3-Tier `AAP-1.0` Application Catalog.
    pub fn builtin_catalog() -> Vec<CatalogAppTemplate> {
        vec![
            CatalogAppTemplate {
                app_id: "heurion".to_string(),
                name: "知衡 (Heurion 2.0) — 临床与科研智能工作台".to_string(),
                version: "2.0.0".to_string(),
                description: "Aegis-OS 官方第一方医学临床研究、统计建模 (Cox/KM/Logistic/Table 1)、证据链审计与可复现论文图表生成平台。".to_string(),
                trust_tier: "first_party".to_string(),
                categories: vec![
                    "first-party".to_string(),
                    "medical".to_string(),
                    "clinical-research".to_string(),
                    "biostatistics".to_string(),
                ],
                default_endpoint: std::env::var("HEURION_BASE_URL")
                    .unwrap_or_else(|_| "http://127.0.0.1:8787".to_string()),
                zero_prompt_tools: vec![
                    "doc_list".to_string(),
                    "doc_create".to_string(),
                    "doc_read".to_string(),
                    "doc_edit".to_string(),
                    "doc_revert_turn".to_string(),
                    "patient_create".to_string(),
                    "report_upload".to_string(),
                    "dataset_open".to_string(),
                    "labs_open".to_string(),
                    "asset_upload".to_string(),
                    "heurion_system_overview".to_string(),
                    "heurion_list_projects".to_string(),
                    "heurion_create_project".to_string(),
                    "heurion_get_project_workspace".to_string(),
                    "heurion_search_literature".to_string(),
                    "heurion_run_biostats".to_string(),
                    "heurion_generate_publication_figure".to_string(),
                    "heurion_run_agent_workflow".to_string(),
                    "heurion_verify_evidence_chain".to_string(),
                ],
                lease_gated_tools: vec![
                    "report_resolve".to_string(),
                    "lab_resolve".to_string(),
                    "heurion_publish_artifact".to_string(),
                    "heurion_admin_sync_knowledge".to_string(),
                    "heurion_admin_rebuild_index".to_string(),
                ],
                skills: vec![AppSkillDescriptor {
                    id: "heurion-clinical-research".to_string(),
                    name: "Heurion 2.0 Clinical & Biomedical Research Workflow".to_string(),
                    description: "Standard operating procedure for conducting clinical research, biostatistics (Cox/KM/Logistic/Table 1), publication figure generation, and evidence chain verification via Heurion 2.0 on Aegis-OS.".to_string(),
                    path: "/.well-known/aegis-skills/heurion-clinical-research/SKILL.md".to_string(),
                }],
            },
            CatalogAppTemplate {
                app_id: "biomed-pubmed-radar".to_string(),
                name: "BioMed PubMed & ClinicalTrials Evidence Radar".to_string(),
                version: "1.2.0".to_string(),
                description: "Aegis Verified 生物医学文献与 NCT 临床试验注册库增量同步与系统综述筛查扩展应用。".to_string(),
                trust_tier: "verified".to_string(),
                categories: vec![
                    "verified".to_string(),
                    "medical".to_string(),
                    "literature".to_string(),
                ],
                default_endpoint: "http://127.0.0.1:8791".to_string(),
                zero_prompt_tools: vec![
                    "pubmed_radar_search".to_string(),
                    "pubmed_radar_prisma_screen".to_string(),
                ],
                lease_gated_tools: vec!["pubmed_radar_export_cohort".to_string()],
                skills: vec![],
            },
            CatalogAppTemplate {
                app_id: "redcap-edc-bridge".to_string(),
                name: "REDCap & CDISC Clinical EDC Bridge".to_string(),
                version: "1.0.4".to_string(),
                description: "Aegis Verified 临床电子数据采集 (EDC / CDISC ODM) 脱敏导入与入排标准核验连接器。".to_string(),
                trust_tier: "verified".to_string(),
                categories: vec![
                    "verified".to_string(),
                    "clinical-trials".to_string(),
                    "edc".to_string(),
                ],
                default_endpoint: "http://127.0.0.1:8792".to_string(),
                zero_prompt_tools: vec![
                    "redcap_list_instruments".to_string(),
                    "redcap_preview_deidentified_cohort".to_string(),
                ],
                lease_gated_tools: vec!["redcap_commit_cdisc_export".to_string()],
                skills: vec![],
            },
        ]
    }

    pub fn build_default_manifest(tpl: &CatalogAppTemplate) -> Value {
        json!({
            "aap_version": "1.0",
            "app_id": tpl.app_id,
            "name": tpl.name,
            "version": tpl.version,
            "description": tpl.description,
            "trust_tier": tpl.trust_tier,
            "endpoints": {
                "mcp_http": "/api/aegis/mcp",
                "auth_device": "/api/aegis/auth/device",
                "auth_device_approve": "/api/aegis/auth/device/approve",
                "auth_token": "/api/aegis/auth/token",
                "health": "/api/health"
            },
            "auth": {
                "type": "aegis_user_token",
                "token_prefix": format!("aegis_at_{}.", tpl.app_id),
                "supports_node_key_binding": true,
                "supports_session_exchange": true,
                "supported_scopes": [
                    "projects:read",
                    "projects:write",
                    "biostats:run",
                    "literature:read",
                    "artifacts:publish",
                    "admin:knowledge"
                ]
            },
            "capabilities": {
                "zero_prompt": tpl.zero_prompt_tools,
                "lease_gated": tpl.lease_gated_tools
            },
            "skills": tpl.skills
        })
    }

    /// Searches the `AAP-1.0` catalog and merges installation + user authentication status.
    pub async fn search_catalog(
        &self,
        query: Option<&str>,
        category: Option<&str>,
        trust_tier: Option<&str>,
    ) -> Value {
        self.reload().await;
        let state = self.state.read().await;
        let q = query.unwrap_or("").trim().to_lowercase();
        let cat_filter = category.unwrap_or("").trim().to_lowercase();
        let tier_filter = trust_tier.unwrap_or("").trim().to_lowercase();

        let mut entries: Vec<Value> = Vec::new();
        let builtins = Self::builtin_catalog();

        for tpl in &builtins {
            if !q.is_empty() {
                let hay = format!(
                    "{} {} {} {}",
                    tpl.app_id,
                    tpl.name,
                    tpl.description,
                    tpl.categories.join(" ")
                )
                .to_lowercase();
                if !hay.contains(&q) {
                    continue;
                }
            }
            if !cat_filter.is_empty()
                && !tpl
                    .categories
                    .iter()
                    .any(|c| c.to_lowercase() == cat_filter)
            {
                continue;
            }
            if !tier_filter.is_empty() && tpl.trust_tier.to_lowercase() != tier_filter {
                continue;
            }

            let installed_rec = state
                .installed_apps
                .iter()
                .find(|a| a.app_id == tpl.app_id);
            let cred_rec = state.credentials.iter().find(|c| c.app_id == tpl.app_id);

            entries.push(json!({
                "app_id": tpl.app_id,
                "name": tpl.name,
                "version": installed_rec.map(|i| i.version.as_str()).unwrap_or(&tpl.version),
                "description": tpl.description,
                "trust_tier": tpl.trust_tier,
                "categories": tpl.categories,
                "endpoint": installed_rec.map(|i| i.endpoint.as_str()).unwrap_or(&tpl.default_endpoint),
                "installed": installed_rec.is_some(),
                "authenticated": cred_rec.is_some(),
                "bound_user": cred_rec.and_then(|c| c.username.clone().or_else(|| c.user_id.clone())),
                "token_prefix": cred_rec.map(|c| c.token_prefix.clone()),
                "capabilities": {
                    "zero_prompt": tpl.zero_prompt_tools,
                    "lease_gated": tpl.lease_gated_tools
                },
                "skills": tpl.skills
            }));
        }

        // Also include any custom installed 3rd-party apps not in `builtins`
        for inst in &state.installed_apps {
            if builtins.iter().any(|b| b.app_id == inst.app_id) {
                continue;
            }
            if !q.is_empty() {
                let hay = format!("{} {} {}", inst.app_id, inst.name, inst.description).to_lowercase();
                if !hay.contains(&q) {
                    continue;
                }
            }
            if !tier_filter.is_empty() && inst.trust_tier.to_lowercase() != tier_filter {
                continue;
            }
            let cred_rec = state.credentials.iter().find(|c| c.app_id == inst.app_id);
            entries.push(json!({
                "app_id": inst.app_id,
                "name": inst.name,
                "version": inst.version,
                "description": inst.description,
                "trust_tier": inst.trust_tier,
                "categories": ["custom"],
                "endpoint": inst.endpoint,
                "installed": true,
                "authenticated": cred_rec.is_some(),
                "bound_user": cred_rec.and_then(|c| c.username.clone().or_else(|| c.user_id.clone())),
                "token_prefix": cred_rec.map(|c| c.token_prefix.clone()),
                "capabilities": inst.manifest.get("capabilities").cloned().unwrap_or_else(|| json!({})),
                "skills": inst.manifest.get("skills").cloned().unwrap_or_else(|| json!([]))
            }));
        }

        json!({
            "aap_version": "1.0",
            "node_id": state.node_id,
            "apps_count": entries.len(),
            "apps": entries
        })
    }

    /// Returns detailed `AAP-1.0` information for a specific `app_id`.
    pub async fn get_app_info(&self, app_id: &str) -> anyhow::Result<Value> {
        self.reload().await;
        let state = self.state.read().await;
        let clean_id = app_id.trim();

        let installed = state.installed_apps.iter().find(|a| a.app_id == clean_id);
        let builtin = Self::builtin_catalog()
            .into_iter()
            .find(|b| b.app_id == clean_id);
        let cred = state.credentials.iter().find(|c| c.app_id == clean_id);

        if installed.is_none() && builtin.is_none() {
            bail!(
                "AAP-1.0 application '{}' not found in catalog or installed apps",
                clean_id
            );
        }

        let endpoint = installed
            .map(|i| i.endpoint.clone())
            .or_else(|| builtin.as_ref().map(|b| b.default_endpoint.clone()))
            .unwrap_or_else(|| "http://127.0.0.1:8787".to_string());

        let live_manifest = Self::fetch_manifest_from_endpoint(&endpoint).await.ok();
        let manifest = live_manifest
            .clone()
            .or_else(|| installed.map(|i| i.manifest.clone()))
            .or_else(|| builtin.as_ref().map(Self::build_default_manifest))
            .unwrap_or_else(|| json!({}));

        Ok(json!({
            "aap_version": "1.0",
            "app_id": clean_id,
            "endpoint": endpoint,
            "online": live_manifest.is_some(),
            "installed": installed.is_some(),
            "installed_skills": installed.map(|i| i.installed_skills.clone()).unwrap_or_default(),
            "authenticated": cred.is_some(),
            "credential": cred.map(|c| json!({
                "token_prefix": c.token_prefix,
                "token_id": c.token_id,
                "user_id": c.user_id,
                "username": c.username,
                "org_id": c.org_id,
                "trust_tier": c.trust_tier,
                "scopes": c.scopes,
                "expires_at": c.expires_at,
                "updated_at_ms": c.updated_at_ms
            })),
            "manifest": manifest
        }))
    }

    /// Installs an `AAP-1.0` application by `app_id` or endpoint URL, caches its manifest,
    /// and optionally downloads declared `skills` into `<workspace_dir>/.agents/skills/<skill_id>/SKILL.md`.
    pub async fn install_app(
        &self,
        app_id_or_url: &str,
        endpoint_override: Option<&str>,
        workspace_dir: Option<&Path>,
    ) -> anyhow::Result<Value> {
        self.reload().await;
        let builtins = Self::builtin_catalog();

        let (resolved_id_hint, endpoint) = if app_id_or_url.starts_with("http://")
            || app_id_or_url.starts_with("https://")
        {
            (
                None,
                app_id_or_url.trim().trim_end_matches('/').to_string(),
            )
        } else {
            let clean_id = app_id_or_url.trim().to_string();
            let ep = endpoint_override
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .or_else(|| {
                    builtins
                        .iter()
                        .find(|b| b.app_id == clean_id)
                        .map(|b| b.default_endpoint.clone())
                })
                .unwrap_or_else(|| "http://127.0.0.1:8787".to_string());
            (Some(clean_id), ep)
        };

        let live_manifest = Self::fetch_manifest_from_endpoint(&endpoint).await.ok();
        let manifest = match live_manifest {
            Some(m) => m,
            None => {
                if let Some(ref id_hint) = resolved_id_hint {
                    if let Some(tpl) = builtins.iter().find(|b| &b.app_id == id_hint) {
                        Self::build_default_manifest(tpl)
                    } else {
                        bail!(
                            "Failed to fetch `/.well-known/aegis-app.json` from {} and '{}' is not in built-in catalog",
                            endpoint,
                            id_hint
                        );
                    }
                } else {
                    bail!(
                        "Failed to fetch `/.well-known/aegis-app.json` from {}",
                        endpoint
                    );
                }
            }
        };

        let app_id = manifest
            .get("app_id")
            .and_then(|v| v.as_str())
            .or(resolved_id_hint.as_deref())
            .context("Manifest missing `app_id`")?
            .to_string();
        let name = manifest
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&app_id)
            .to_string();
        let version = manifest
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("1.0.0")
            .to_string();
        let description = manifest
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let trust_tier = manifest
            .get("trust_tier")
            .and_then(|v| v.as_str())
            .unwrap_or("community")
            .to_string();

        // Install any declared skills into `<workspace_dir>/.agents/skills/<skill_id>/SKILL.md`
        let mut installed_skills = Vec::new();
        if let Some(ws) = workspace_dir {
            if let Some(skills_arr) = manifest.get("skills").and_then(|v| v.as_array()) {
                for sk in skills_arr {
                    let Some(skill_id) = sk
                        .get("id")
                        .or_else(|| sk.get("name"))
                        .and_then(|v| v.as_str())
                    else {
                        continue;
                    };
                    let skill_path = sk
                        .get("path")
                        .or_else(|| sk.get("url"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("/.well-known/aegis-skills/SKILL.md");

                    let skill_md = match Self::app_http_text("GET", &endpoint, skill_path).await {
                        Ok((status, text)) if (200..300).contains(&status) && !text.trim().is_empty() => {
                            Some(text)
                        }
                        _ => {
                            let local_candidate = ws
                                .join("skills")
                                .join(skill_id)
                                .join("SKILL.md");
                            tokio::fs::read_to_string(&local_candidate).await.ok()
                        }
                    };

                    if let Some(content) = skill_md {
                        let target_skill_file = ws
                            .join(".agents")
                            .join("skills")
                            .join(skill_id)
                            .join("SKILL.md");
                        if let Some(parent) = target_skill_file.parent() {
                            let _ = tokio::fs::create_dir_all(parent).await;
                        }
                        if tokio::fs::write(&target_skill_file, content.as_bytes())
                            .await
                            .is_ok()
                        {
                            installed_skills.push(target_skill_file.display().to_string());
                        }
                    }
                }
            }
        }

        let record = InstalledAppRecord {
            app_id: app_id.clone(),
            name: name.clone(),
            version: version.clone(),
            description,
            trust_tier: trust_tier.clone(),
            endpoint: endpoint.clone(),
            manifest: manifest.clone(),
            installed_skills: installed_skills.clone(),
            installed_at_ms: Utc::now().timestamp_millis(),
        };

        {
            let mut guard = self.state.write().await;
            guard.installed_apps.retain(|a| a.app_id != app_id);
            guard.installed_apps.push(record.clone());
        }
        self.flush().await?;

        Ok(json!({
            "status": "app_installed",
            "app_id": app_id,
            "name": name,
            "version": version,
            "trust_tier": trust_tier,
            "endpoint": endpoint,
            "installed_skills": installed_skills,
            "capabilities": manifest.get("capabilities").cloned().unwrap_or_else(|| json!({}))
        }))
    }

    /// Authenticates and binds an `AAP-1.0` application user credential (`aegis_at_<app_id>.*`)
    /// via direct token, web session token exchange, or username/password exchange.
    pub async fn login_app(
        &self,
        app_id: &str,
        endpoint_override: Option<&str>,
        token: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
        scopes: Vec<String>,
    ) -> anyhow::Result<Value> {
        self.reload().await;
        let clean_id = app_id.trim();
        let endpoint = self.resolve_app_endpoint(clean_id, endpoint_override).await;
        let (node_id, node_public_key) = {
            let guard = self.state.read().await;
            (guard.node_id.clone(), guard.node_public_key.clone())
        };

        // Case 1: Direct `aegis_at_<app_id>.*` token passed on CLI
        if let Some(raw_tok) = token {
            let trimmed = raw_tok.trim();
            if trimmed.starts_with("aegis_at_") {
                let prefix = trimmed.chars().take(24).collect::<String>();
                let rec = AppCredentialRecord {
                    app_id: clean_id.to_string(),
                    endpoint: endpoint.clone(),
                    access_token: trimmed.to_string(),
                    token_prefix: prefix.clone(),
                    token_id: None,
                    user_id: None,
                    username: username.map(|s| s.to_string()),
                    org_id: None,
                    trust_tier: None,
                    scopes: if scopes.is_empty() {
                        vec![
                            "projects:read".to_string(),
                            "projects:write".to_string(),
                            "biostats:run".to_string(),
                            "literature:read".to_string(),
                            "artifacts:publish".to_string(),
                        ]
                    } else {
                        scopes
                    },
                    expires_at: None,
                    updated_at_ms: Utc::now().timestamp_millis(),
                };
                self.save_credential(rec.clone()).await?;
                return Ok(json!({
                    "status": "app_logged_in",
                    "mode": "direct_aegis_token",
                    "app_id": clean_id,
                    "endpoint": endpoint,
                    "token_prefix": prefix,
                    "node_id": node_id
                }));
            }
        }

        // Case 2: Exchange Web session token or username/password via `POST /api/aegis/auth/token`
        let mut req_body = json!({
            "node_id": node_id,
            "node_public_key": node_public_key,
            "node_pubkey": node_public_key,
            "name": format!("Aegis-OS CLI ({})", clean_id),
            "label": format!("Aegis-OS CLI ({})", clean_id),
            "tool_scope": "all",
        });
        if !scopes.is_empty() {
            req_body["scopes"] = json!(scopes);
        }
        if let Some(s_tok) = token {
            req_body["session_token"] = json!(s_tok.trim());
        }
        if let Some(u) = username {
            req_body["username"] = json!(u.trim());
        }
        if let Some(p) = password {
            req_body["password"] = json!(p);
        }

        let (status, resp) = Self::app_http_json(
            "POST",
            &endpoint,
            "/api/aegis/auth/token",
            token,
            &[],
            Some(&req_body),
        )
        .await?;
        if !(200..300).contains(&status) {
            let err_msg = resp
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Failed to exchange AAP-1.0 token");
            bail!("AAP-1.0 token exchange failed (HTTP {}): {}", status, err_msg);
        }

        let access_token = resp
            .get("access_token")
            .and_then(|v| v.as_str())
            .context("Response from `/api/aegis/auth/token` missing `access_token`")?
            .to_string();
        let rec = Self::credential_from_token_response(clean_id, &endpoint, &access_token, &resp);
        self.save_credential(rec.clone()).await?;

        Ok(json!({
            "status": "app_logged_in",
            "mode": "token_exchange",
            "app_id": clean_id,
            "endpoint": endpoint,
            "token_prefix": rec.token_prefix,
            "user_id": rec.user_id,
            "username": rec.username,
            "org_id": rec.org_id,
            "trust_tier": rec.trust_tier,
            "scopes": rec.scopes,
            "expires_at": rec.expires_at,
            "node_id": node_id
        }))
    }

    /// Initiates RFC 8628 Device Code Flow (`POST /api/aegis/auth/device`) and optionally polls
    /// `POST /api/aegis/auth/token` until approved.
    pub async fn login_app_device_code(
        &self,
        app_id: &str,
        endpoint_override: Option<&str>,
        scopes: Vec<String>,
        wait_secs: u64,
        auto_approve_session_token: Option<&str>,
    ) -> anyhow::Result<Value> {
        self.reload().await;
        let clean_id = app_id.trim();
        let endpoint = self.resolve_app_endpoint(clean_id, endpoint_override).await;
        let (node_id, node_public_key) = {
            let guard = self.state.read().await;
            (guard.node_id.clone(), guard.node_public_key.clone())
        };

        let mut init_body = json!({
            "node_id": node_id,
            "node_public_key": node_public_key,
            "node_pubkey": node_public_key,
            "name": format!("Aegis-OS Device Login ({})", clean_id),
            "label": format!("Aegis-OS Device Login ({})", clean_id),
            "tool_scope": "all",
            "write_mode": "tracked"
        });
        if !scopes.is_empty() {
            init_body["scopes"] = json!(scopes);
        }

        let (status, init_resp) = Self::app_http_json(
            "POST",
            &endpoint,
            "/api/aegis/auth/device",
            None,
            &[],
            Some(&init_body),
        )
        .await?;
        if !(200..300).contains(&status) {
            bail!(
                "Failed to initiate AAP-1.0 device code flow (HTTP {}): {}",
                status,
                init_resp
            );
        }

        let device_code = init_resp
            .get("device_code")
            .and_then(|v| v.as_str())
            .context("Missing `device_code` in `/api/aegis/auth/device` response")?
            .to_string();
        let user_code = init_resp
            .get("user_code")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let verification_uri = init_resp
            .get("verification_uri_complete")
            .or_else(|| init_resp.get("verification_uri"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Optional automated approval helper when user passes a web session token
        if let Some(sess_tok) = auto_approve_session_token {
            let _ = Self::app_http_json(
                "POST",
                &endpoint,
                "/api/aegis/auth/device/approve",
                Some(sess_tok),
                &[],
                Some(&json!({ "user_code": user_code })),
            )
            .await;
        }

        if wait_secs == 0 {
            return Ok(json!({
                "status": "authorization_pending",
                "app_id": clean_id,
                "endpoint": endpoint,
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": verification_uri,
                "hint": format!("Open {}{} and enter code `{}` to bind your account.", endpoint, verification_uri, user_code)
            }));
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
        loop {
            let (poll_status, poll_resp) = Self::app_http_json(
                "POST",
                &endpoint,
                "/api/aegis/auth/token",
                None,
                &[],
                Some(&json!({
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code
                })),
            )
            .await?;

            if (200..300).contains(&poll_status) {
                if let Some(access_token) = poll_resp.get("access_token").and_then(|v| v.as_str())
                {
                    let rec = Self::credential_from_token_response(
                        clean_id,
                        &endpoint,
                        access_token,
                        &poll_resp,
                    );
                    self.save_credential(rec.clone()).await?;
                    return Ok(json!({
                        "status": "app_logged_in",
                        "mode": "device_code",
                        "app_id": clean_id,
                        "endpoint": endpoint,
                        "user_code": user_code,
                        "token_prefix": rec.token_prefix,
                        "user_id": rec.user_id,
                        "username": rec.username,
                        "org_id": rec.org_id,
                        "trust_tier": rec.trust_tier,
                        "scopes": rec.scopes,
                        "expires_at": rec.expires_at
                    }));
                }
            }

            let err_code = poll_resp
                .get("code")
                .or_else(|| poll_resp.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if err_code != "authorization_pending" && poll_status != 428 && !err_code.is_empty() {
                bail!("Device code authorization failed: {}", poll_resp);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(json!({
                    "status": "authorization_pending",
                    "app_id": clean_id,
                    "endpoint": endpoint,
                    "device_code": device_code,
                    "user_code": user_code,
                    "verification_uri": verification_uri,
                    "hint": format!("Enter user_code `{}` in the Web UI Account Center ({}{})", user_code, endpoint, verification_uri)
                }));
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    /// Revokes and removes the stored `aegis_at_<app_id>.*` credential for `app_id`.
    pub async fn logout_app(&self, app_id: &str) -> anyhow::Result<Value> {
        self.reload().await;
        let clean_id = app_id.trim();
        let removed = {
            let mut guard = self.state.write().await;
            let existing = guard
                .credentials
                .iter()
                .find(|c| c.app_id == clean_id)
                .cloned();
            guard.credentials.retain(|c| c.app_id != clean_id);
            existing
        };
        self.flush().await?;

        let mut server_revoked = false;
        if let Some(ref cred) = removed {
            if let Ok((status, _)) = Self::app_http_json(
                "DELETE",
                &cred.endpoint,
                "/api/aegis/auth/token",
                Some(&cred.access_token),
                &[],
                None,
            )
            .await
            {
                server_revoked = (200..300).contains(&status);
            }
        }

        Ok(json!({
            "status": "app_logged_out",
            "app_id": clean_id,
            "had_local_credential": removed.is_some(),
            "server_token_revoked": server_revoked
        }))
    }

    /// Mounts an `AAP-1.0` application into the calling Agent's active session (`app_mount_session`),
    /// returning its `zero_prompt` vs `lease_gated` tool catalog, live tool schemas (if online),
    /// and bound user authentication state.
    pub async fn mount_session(
        &self,
        identity: &AgentIdentity,
        app_id: &str,
        endpoint_override: Option<&str>,
    ) -> anyhow::Result<Value> {
        self.reload().await;
        let clean_id = app_id.trim();
        let endpoint = self.resolve_app_endpoint(clean_id, endpoint_override).await;

        let info = self.get_app_info(clean_id).await?;
        let cred = {
            let guard = self.state.read().await;
            guard
                .credentials
                .iter()
                .find(|c| c.app_id == clean_id)
                .cloned()
        };

        // Record active session mount
        {
            let mut guard = self.state.write().await;
            guard.mounted_sessions.retain(|m| {
                !(m.app_id == clean_id
                    && m.org_id == identity.org_id
                    && m.agent_id == identity.agent_id)
            });
            guard.mounted_sessions.push(MountedAppSession {
                app_id: clean_id.to_string(),
                org_id: identity.org_id.clone(),
                agent_id: identity.agent_id.clone(),
                endpoint: endpoint.clone(),
                mounted_at_ms: Utc::now().timestamp_millis(),
            });
        }
        self.flush().await?;

        // Best-effort query of `tools/list` from `POST <endpoint>/api/aegis/mcp`
        let bearer = cred.as_ref().map(|c| c.access_token.as_str());
        let live_tools = match Self::app_http_json(
            "POST",
            &endpoint,
            "/api/aegis/mcp",
            bearer,
            &[
                ("X-Aegis-Agent-Id", &identity.fqn()),
                ("X-Aegis-Session-Id", &format!("ses-{}-{}", identity.org_id, identity.agent_id)),
            ],
            Some(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            })),
        )
        .await
        {
            Ok((status, rpc_resp)) if (200..300).contains(&status) => rpc_resp
                .get("result")
                .and_then(|r| r.get("tools"))
                .cloned(),
            _ => None,
        };

        let manifest = info.get("manifest").cloned().unwrap_or_else(|| json!({}));
        Ok(json!({
            "status": "app_session_mounted",
            "aap_version": "1.0",
            "app_id": clean_id,
            "endpoint": endpoint,
            "agent": identity.fqn(),
            "authenticated": cred.is_some(),
            "bound_user": cred.as_ref().and_then(|c| c.username.clone().or_else(|| c.user_id.clone())),
            "trust_tier": manifest.get("trust_tier").and_then(|v| v.as_str()).unwrap_or("first_party"),
            "capabilities": manifest.get("capabilities").cloned().unwrap_or_else(|| json!({})),
            "skills": manifest.get("skills").cloned().unwrap_or_else(|| json!([])),
            "live_mcp_tools": live_tools,
            "usage_hint": format!(
                "Call `app_call_tool` with `app_id: \"{}\", tool_name: \"<tool>\", arguments: {{...}}`.",
                clean_id
            )
        }))
    }

    /// Invokes a tool on an `AAP-1.0` application (`POST <endpoint>/api/aegis/mcp`) with:
    /// 1. Automatic `Authorization: Bearer aegis_at_<app_id>.*` header injection
    /// 2. Automatic `X-Aegis-Agent-Id` & `X-Aegis-Session-Id` audit header injection
    /// 3. Pre-flight Policy Kernel lease check for `lease_gated` capabilities and automatic
    ///    `X-Aegis-Lease-Token` injection when an active lease is held by the Agent.
    pub async fn call_app_tool(
        &self,
        kernel: &AegisRuntimeKernel,
        identity: &AgentIdentity,
        app_id: &str,
        tool_name: &str,
        arguments: Value,
        endpoint_override: Option<&str>,
        lease_token_override: Option<&str>,
    ) -> anyhow::Result<Value> {
        self.reload().await;
        let clean_app = app_id.trim();
        let clean_tool = tool_name.trim();
        let endpoint = self.resolve_app_endpoint(clean_app, endpoint_override).await;

        let (cred, is_lease_gated) = {
            let guard = self.state.read().await;
            let c = guard
                .credentials
                .iter()
                .find(|c| c.app_id == clean_app)
                .cloned();
            let gated_in_installed = guard
                .installed_apps
                .iter()
                .find(|a| a.app_id == clean_app)
                .map(|a| {
                    let in_cap = a
                        .manifest
                        .get("capabilities")
                        .and_then(|cap| cap.get("lease_gated"))
                        .and_then(|arr| arr.as_array())
                        .map(|arr| arr.iter().any(|x| x.as_str() == Some(clean_tool)))
                        .unwrap_or(false);
                    let in_preview = a
                        .manifest
                        .get("capabilities_preview")
                        .and_then(|arr| arr.as_array())
                        .map(|arr| {
                            arr.iter().any(|item| {
                                item.get("name").and_then(|v| v.as_str()) == Some(clean_tool)
                                    && item.get("tier").and_then(|v| v.as_str()) == Some("lease_gated")
                            })
                        })
                        .unwrap_or(false);
                    in_cap || in_preview
                });
            let gated_in_builtin = Self::builtin_catalog()
                .into_iter()
                .find(|b| b.app_id == clean_app)
                .map(|b| b.lease_gated_tools.iter().any(|t| t == clean_tool));
            (
                c,
                gated_in_installed.or(gated_in_builtin).unwrap_or(false),
            )
        };

        // Resolve active lease token from override or AegisPolicyKernel
        let mut active_lease_token: Option<String> = lease_token_override
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if active_lease_token.is_none() {
            if let Ok(leases) = kernel
                .policy
                .list_leases(&identity.org_id, Some(&identity.agent_id))
                .await
            {
                let fq_action = format!("{}:{}", clean_app, clean_tool);
                for l in leases {
                    if l.action_pattern == "*"
                        || l.action_pattern == fq_action
                        || l.action_pattern == clean_tool
                        || l.action_pattern == "app_call_tool"
                    {
                        active_lease_token = Some(l.lease_id);
                        break;
                    }
                }
            }
        }

        // If tool is declared `lease_gated` in the AAP-1.0 manifest and no active lease exists,
        // escalate through AegisPolicyKernel so the human operator can approve via `aegis-os policy approve <esc_id>`!
        if is_lease_gated && active_lease_token.is_none() {
            let fq_action = format!("{}:{}", clean_app, clean_tool);
            let target_res = format!("app://{}/{}", clean_app, clean_tool);
            let decision = kernel
                .authorize_and_audit(
                    identity,
                    &fq_action,
                    &identity.org_id,
                    &target_res,
                    json!({
                        "app_id": clean_app,
                        "tool_name": clean_tool,
                        "arguments": arguments
                    }),
                )
                .await?;
            match decision {
                PolicyDecision::Allow { matched_rule } => {
                    active_lease_token = Some(matched_rule);
                }
                PolicyDecision::Ask {
                    escalation_id,
                    reason,
                    suggested_lease_scope,
                } => {
                    return Ok(json!({
                        "status": "approval_required",
                        "aap_version": "1.0",
                        "app_id": clean_app,
                        "tool_name": clean_tool,
                        "capability_tier": "lease_gated",
                        "escalation_id": escalation_id,
                        "reason": reason,
                        "suggested_lease_scope": suggested_lease_scope,
                        "hint": format!(
                            "Tool `{}:{}` is lease-gated under AAP-1.0. Ask the user to approve in their terminal: `aegis-os --org {} policy approve {}`.",
                            clean_app, clean_tool, identity.org_id, escalation_id
                        )
                    }));
                }
                PolicyDecision::Deny { reason } => {
                    bail!(
                        "Policy Kernel denied AAP-1.0 tool `{}:{}`: {}",
                        clean_app,
                        clean_tool,
                        reason
                    );
                }
            }
        }

        // Resolve bearer token from stored credential or environment fallback
        let env_key = format!("AEGIS_APP_TOKEN_{}", clean_app.to_uppercase().replace('-', "_"));
        let env_token = std::env::var(&env_key)
            .ok()
            .or_else(|| {
                if clean_app == "heurion" {
                    std::env::var("HEURION_ACCESS_TOKEN").ok()
                } else {
                    None
                }
            });
        let bearer_token = cred
            .as_ref()
            .map(|c| c.access_token.clone())
            .or(env_token);

        let agent_hdr = identity.fqn();
        let session_hdr = format!("ses-{}-{}", identity.org_id, identity.agent_id);
        let mut headers: Vec<(&str, &str)> = vec![
            ("X-Aegis-Agent-Id", &agent_hdr),
            ("X-Aegis-Session-Id", &session_hdr),
        ];
        if let Some(ref lt) = active_lease_token {
            headers.push(("X-Aegis-Lease-Token", lt.as_str()));
        }

        let rpc_req = json!({
            "jsonrpc": "2.0",
            "id": Uuid::new_v4().to_string(),
            "method": "tools/call",
            "params": {
                "name": clean_tool,
                "arguments": arguments
            }
        });

        let (status, rpc_resp) = Self::app_http_json(
            "POST",
            &endpoint,
            "/api/aegis/mcp",
            bearer_token.as_deref(),
            &headers,
            Some(&rpc_req),
        )
        .await?;

        if status == 401 {
            return Ok(json!({
                "status": "authentication_required",
                "app_id": clean_app,
                "tool_name": clean_tool,
                "endpoint": endpoint,
                "error": rpc_resp.get("error").cloned().unwrap_or_else(|| json!("Unauthorized")),
                "hint": format!(
                    "Authenticate your `{}` account with `aegis-os app login {} --device-code` or `aegis-os app login {} --token <aegis_at_...>`.",
                    clean_app, clean_app, clean_app
                )
            }));
        }

        // Unwrap JSON-RPC `result.content[0].text` if it is JSON
        let unwrapped_result = if let Some(text) = rpc_resp
            .get("result")
            .and_then(|r| r.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|item| item.get("text"))
            .and_then(|t| t.as_str())
        {
            serde_json::from_str::<Value>(text).unwrap_or_else(|_| json!({ "text": text }))
        } else {
            rpc_resp
                .get("result")
                .cloned()
                .unwrap_or_else(|| rpc_resp.clone())
        };

        let is_error = rpc_resp
            .get("result")
            .and_then(|r| r.get("isError"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || !(200..300).contains(&status);

        Ok(json!({
            "status": if is_error { "app_tool_error" } else { "ok" },
            "app_id": clean_app,
            "tool_name": clean_tool,
            "endpoint": endpoint,
            "authenticated_user": cred.as_ref().and_then(|c| c.username.clone().or_else(|| c.user_id.clone())),
            "lease_token_injected": active_lease_token.is_some(),
            "result": unwrapped_result
        }))
    }

    async fn resolve_app_endpoint(&self, app_id: &str, endpoint_override: Option<&str>) -> String {
        if let Some(ep) = endpoint_override {
            if !ep.trim().is_empty() {
                return ep.trim().trim_end_matches('/').to_string();
            }
        }
        let guard = self.state.read().await;
        if let Some(inst) = guard.installed_apps.iter().find(|a| a.app_id == app_id) {
            return inst.endpoint.clone();
        }
        if let Some(cred) = guard.credentials.iter().find(|c| c.app_id == app_id) {
            return cred.endpoint.clone();
        }
        Self::builtin_catalog()
            .into_iter()
            .find(|b| b.app_id == app_id)
            .map(|b| b.default_endpoint)
            .unwrap_or_else(|| "http://127.0.0.1:8787".to_string())
    }

    async fn save_credential(&self, rec: AppCredentialRecord) -> anyhow::Result<()> {
        {
            let mut guard = self.state.write().await;
            guard.credentials.retain(|c| c.app_id != rec.app_id);
            guard.credentials.push(rec);
        }
        self.flush().await
    }

    fn credential_from_token_response(
        app_id: &str,
        endpoint: &str,
        access_token: &str,
        resp: &Value,
    ) -> AppCredentialRecord {
        let prefix = access_token.chars().take(24).collect::<String>();
        let scopes: Vec<String> = resp
            .get("scopes")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let user_obj = resp.get("user").or_else(|| resp.get("bound_user"));
        AppCredentialRecord {
            app_id: app_id.to_string(),
            endpoint: endpoint.to_string(),
            access_token: access_token.to_string(),
            token_prefix: prefix,
            token_id: resp
                .get("token_id")
                .or_else(|| resp.get("grant_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            user_id: user_obj
                .and_then(|u| u.get("user_id").or_else(|| u.get("id")))
                .or_else(|| resp.get("user_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            username: user_obj
                .and_then(|u| u.get("username"))
                .or_else(|| resp.get("username"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            org_id: user_obj
                .and_then(|u| u.get("org_id"))
                .or_else(|| resp.get("org_id"))
                .or_else(|| resp.get("bound_org_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            trust_tier: resp
                .get("trust_tier")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            scopes,
            expires_at: resp
                .get("expires_at")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            updated_at_ms: Utc::now().timestamp_millis(),
        }
    }

    pub async fn fetch_manifest_from_endpoint(endpoint: &str) -> anyhow::Result<Value> {
        let (status, val) =
            Self::app_http_json("GET", endpoint, "/.well-known/aegis-app.json", None, &[], None)
                .await?;
        if !(200..300).contains(&status) {
            bail!(
                "GET /.well-known/aegis-app.json returned HTTP {}",
                status
            );
        }
        Ok(val)
    }

    /// Lightweight HTTP/HTTPS JSON client for `AAP-1.0` endpoints.
    pub async fn app_http_json(
        method: &str,
        endpoint: &str,
        path: &str,
        bearer_token: Option<&str>,
        extra_headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> anyhow::Result<(u16, Value)> {
        let (status, raw_body) =
            Self::app_http_raw(method, endpoint, path, bearer_token, extra_headers, body).await?;
        let parsed = serde_json::from_str::<Value>(raw_body.trim())
            .unwrap_or_else(|_| json!({ "raw": raw_body }));
        Ok((status, parsed))
    }

    pub async fn app_http_text(
        method: &str,
        endpoint: &str,
        path: &str,
    ) -> anyhow::Result<(u16, String)> {
        Self::app_http_raw(method, endpoint, path, None, &[], None).await
    }

    async fn app_http_raw(
        method: &str,
        endpoint: &str,
        path: &str,
        bearer_token: Option<&str>,
        extra_headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> anyhow::Result<(u16, String)> {
        let base = endpoint.trim().trim_end_matches('/');
        let full_url = format!("{}{}", base, path);

        if let Some(rest) = base.strip_prefix("http://") {
            let (host_port, base_path) = match rest.split_once('/') {
                Some((hp, bp)) => (hp, format!("/{}", bp.trim_end_matches('/'))),
                None => (rest, String::new()),
            };
            let addr = if host_port.contains(':') {
                host_port.to_string()
            } else {
                format!("{}:80", host_port)
            };
            let target_path = format!("{}{}", base_path, path);
            let body_bytes = body
                .map(|b| serde_json::to_vec(b).unwrap_or_default())
                .unwrap_or_default();

            let stream = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            .with_context(|| format!("Connection timeout to {}", full_url))?
            .with_context(|| format!("Failed to connect to {}", full_url))?;
            let mut stream = stream;

            let mut req_str = format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                method,
                target_path,
                host_port,
                body_bytes.len()
            );
            if let Some(tok) = bearer_token {
                if !tok.trim().is_empty() {
                    req_str.push_str(&format!("Authorization: Bearer {}\r\n", tok.trim()));
                }
            }
            for (hk, hv) in extra_headers {
                req_str.push_str(&format!("{}: {}\r\n", hk, hv));
            }
            req_str.push_str("\r\n");

            stream.write_all(req_str.as_bytes()).await?;
            if !body_bytes.is_empty() {
                stream.write_all(&body_bytes).await?;
            }
            stream.flush().await?;

            let mut resp_buf = Vec::new();
            stream.read_to_end(&mut resp_buf).await?;
            let raw_resp = String::from_utf8_lossy(&resp_buf).to_string();
            let (head, resp_body) = raw_resp.split_once("\r\n\r\n").unwrap_or(("", &raw_resp));
            let status_code = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(200);
            return Ok((status_code, resp_body.to_string()));
        }

        // Fallback to `curl` for `https://` endpoints
        let mut cmd = std::process::Command::new("curl");
        cmd.args([
            "-sS",
            "-i",
            "-X",
            method,
            &full_url,
            "-H",
            "Content-Type: application/json",
        ]);
        if let Some(tok) = bearer_token {
            if !tok.trim().is_empty() {
                cmd.args(["-H", &format!("Authorization: Bearer {}", tok.trim())]);
            }
        }
        for (hk, hv) in extra_headers {
            cmd.args(["-H", &format!("{}: {}", hk, hv)]);
        }
        if let Some(b) = body {
            cmd.args(["-d", &serde_json::to_string(b)?]);
        }
        let out = cmd
            .output()
            .context("Failed to execute `curl` for HTTPS AAP-1.0 endpoint")?;
        if !out.status.success() {
            bail!(
                "HTTPS request to {} failed: {}",
                full_url,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let raw = String::from_utf8_lossy(&out.stdout).to_string();
        let (head, body_str) = raw.rsplit_once("\r\n\r\n").unwrap_or(("", &raw));
        let status_code = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(200);
        Ok((status_code, body_str.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::IsolationTier;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_aap_app_store_catalog_install_device_login_and_lease_gated_mcp_proxy() {
        let temp = tempfile::tempdir().unwrap();
        let ws_dir = temp.path().join("workspace");
        let rt_dir = temp.path().join("runtime");
        tokio::fs::create_dir_all(&ws_dir).await.unwrap();

        // Start a mock AAP-1.0 HTTP server (simulating Heurion 2.0)
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock_ep = format!("http://{}", addr);

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::with_capacity(8192);
                    let mut chunk = [0u8; 4096];
                    let header_end = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        let Ok(n) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end - 4]).to_string();
                    let content_len: usize = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    while buf.len() < header_end + content_len {
                        let Ok(n) = stream.read(&mut chunk).await else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let body_str =
                        String::from_utf8_lossy(&buf[header_end..header_end + content_len])
                            .to_string();
                    let first_line = head.lines().next().unwrap_or("");
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    let method = parts.first().copied().unwrap_or("GET");
                    let path = parts.get(1).copied().unwrap_or("/");
                    let head_lower = head.to_lowercase();

                    let (status, content_type, resp_body) = if method == "GET"
                        && path == "/.well-known/aegis-app.json"
                    {
                        let tpl = &AppStoreRegistry::builtin_catalog()[0];
                        (
                            "200 OK",
                            "application/json",
                            AppStoreRegistry::build_default_manifest(tpl).to_string(),
                        )
                    } else if method == "GET"
                        && path.starts_with("/.well-known/aegis-skills/")
                    {
                        (
                            "200 OK",
                            "text/markdown",
                            "---\nname: heurion-clinical-research\ndescription: Heurion 2.0 SOP\n---\n# Heurion 2.0 Skill\n".to_string(),
                        )
                    } else if method == "POST" && path == "/api/aegis/auth/device" {
                        (
                            "200 OK",
                            "application/json",
                            json!({
                                "device_code": "aegis_dc_test123",
                                "user_code": "ABCD-1234",
                                "verification_uri": "/#account",
                                "verification_uri_complete": "/#account?device_code=ABCD-1234",
                                "expires_in": 600,
                                "interval": 1
                            })
                            .to_string(),
                        )
                    } else if method == "POST" && path == "/api/aegis/auth/token" {
                        (
                            "200 OK",
                            "application/json",
                            json!({
                                "status": "issued",
                                "token_type": "Bearer",
                                "access_token": "aegis_at_heurion.test_secret_token_999",
                                "token_id": "agt-mock-1",
                                "trust_tier": "first_party",
                                "scopes": ["projects:read", "projects:write", "biostats:run", "artifacts:publish"],
                                "user": {
                                    "user_id": "usr-clinician-1",
                                    "username": "dr_zhang",
                                    "org_id": "pumch-cardiology"
                                }
                            })
                            .to_string(),
                        )
                    } else if method == "POST" && path == "/api/aegis/mcp" {
                        let req_json: Value =
                            serde_json::from_str(&body_str).unwrap_or_else(|_| json!({}));
                        let rpc_method = req_json
                            .get("method")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if rpc_method == "tools/list" {
                            (
                                "200 OK",
                                "application/json",
                                json!({
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "result": {
                                        "tools": [
                                            { "name": "heurion_list_projects" },
                                            { "name": "heurion_publish_artifact" }
                                        ]
                                    }
                                })
                                .to_string(),
                            )
                        } else {
                            let t_name = req_json
                                .get("params")
                                .and_then(|p| p.get("name"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let has_auth = head_lower
                                .contains("authorization: bearer aegis_at_heurion.test_secret_token_999");
                            let has_lease = head_lower.contains("x-aegis-lease-token:");
                            (
                                "200 OK",
                                "application/json",
                                json!({
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "result": {
                                        "content": [{
                                            "type": "text",
                                            "text": json!({
                                                "tool_executed": t_name,
                                                "authenticated": has_auth,
                                                "lease_verified": has_lease
                                            }).to_string()
                                        }]
                                    }
                                })
                                .to_string(),
                            )
                        }
                    } else {
                        ("404 Not Found", "application/json", "{}".to_string())
                    };

                    let resp = format!(
                        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        content_type,
                        resp_body.len(),
                        resp_body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt_dir).await.unwrap());
        let identity = AgentIdentity::new("heurion2", "agy-agent", "Lead Agent");
        kernel
            .ensure_agent_environment(
                identity.clone(),
                &ws_dir,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. Search catalog via MCP tool `app_catalog_search`
        let search_res = kernel
            .call_tool(
                &identity,
                "app_catalog_search",
                json!({ "query": "heurion" }),
            )
            .await
            .unwrap();
        assert_eq!(search_res["apps_count"], 1);
        assert_eq!(search_res["apps"][0]["app_id"], "heurion");
        assert_eq!(search_res["apps"][0]["trust_tier"], "first_party");

        // 2. Install `heurion` from mock endpoint (also downloads SKILL.md into `.agents/skills/heurion-clinical-research/SKILL.md`)
        let install_res = kernel
            .app_store
            .install_app("heurion", Some(&mock_ep), Some(&ws_dir))
            .await
            .unwrap();
        assert_eq!(install_res["status"], "app_installed");
        assert_eq!(install_res["installed_skills"].as_array().unwrap().len(), 1);
        assert!(ws_dir
            .join(".agents/skills/heurion-clinical-research/SKILL.md")
            .exists());

        // 3. Authenticate via RFC 8628 Device Code Flow (`login_app_device_code`)
        let login_res = kernel
            .app_store
            .login_app_device_code("heurion", Some(&mock_ep), vec![], 5, None)
            .await
            .unwrap();
        assert_eq!(login_res["status"], "app_logged_in");
        assert_eq!(login_res["username"], "dr_zhang");

        // 4. Mount session via MCP tool `app_mount_session`
        let mount_res = kernel
            .call_tool(
                &identity,
                "app_mount_session",
                json!({ "app_id": "heurion" }),
            )
            .await
            .unwrap();
        assert_eq!(mount_res["status"], "app_session_mounted");
        assert_eq!(mount_res["authenticated"], true);
        assert_eq!(mount_res["bound_user"], "dr_zhang");

        // 5. Call a Zero-Prompt tool (`heurion_list_projects`) via MCP tool `app_call_tool`
        let zp_res = kernel
            .call_tool(
                &identity,
                "app_call_tool",
                json!({
                    "app_id": "heurion",
                    "tool_name": "heurion_list_projects",
                    "arguments": {}
                }),
            )
            .await
            .unwrap();
        assert_eq!(zp_res["status"], "ok");
        assert_eq!(zp_res["result"]["tool_executed"], "heurion_list_projects");
        assert_eq!(zp_res["result"]["authenticated"], true);

        // 6. Call a Lease-Gated tool (`heurion_publish_artifact`) -> triggers Policy Kernel escalation!
        let gated_ask = kernel
            .call_tool(
                &identity,
                "app_call_tool",
                json!({
                    "app_id": "heurion",
                    "tool_name": "heurion_publish_artifact",
                    "arguments": { "project_id": "prj-1" }
                }),
            )
            .await
            .unwrap();
        assert_eq!(gated_ask["status"], "approval_required");
        assert_eq!(gated_ask["capability_tier"], "lease_gated");
        let esc_id = gated_ask["escalation_id"].as_str().unwrap().to_string();

        // Approve the escalation in Policy Kernel -> grants active session lease for `heurion:heurion_publish_artifact`
        kernel
            .policy
            .approve_escalation(&esc_id, 3600, "cli_human_operator")
            .await
            .unwrap();

        // Retry `heurion_publish_artifact` -> automatically injects `X-Aegis-Lease-Token` and succeeds!
        let gated_ok = kernel
            .call_tool(
                &identity,
                "app_call_tool",
                json!({
                    "app_id": "heurion",
                    "tool_name": "heurion_publish_artifact",
                    "arguments": { "project_id": "prj-1" }
                }),
            )
            .await
            .unwrap();
        assert_eq!(gated_ok["status"], "ok");
        assert_eq!(gated_ok["lease_token_injected"], true);
        assert_eq!(gated_ok["result"]["lease_verified"], true);
    }
}
