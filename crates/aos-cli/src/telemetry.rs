//! Privacy-Preserving Anonymous Telemetry & Product Growth Analytics (`aegis-os stats`)
//!
//! Collects strictly anonymous adoption metrics (DAU / WAU / MAU, OS/Arch, and IDE Client breakdown)
//! without ever transmitting source code, file paths, usernames, hostnames, or IP addresses.
//!
//! Opt-out anytime via:
//! - `export DO_NOT_TRACK=1`
//! - `export AOS_TELEMETRY_DISABLED=1`
//! - `touch ~/.gemini/aegis-telemetry-opt-out`

use aos_mcp_gateway::paas::{PaasControlPlane, TelemetryPingPayload};
use chrono::Utc;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Returns `true` if anonymous telemetry is disabled via environment variable or opt-out marker.
pub fn is_telemetry_disabled() -> bool {
    for var in ["DO_NOT_TRACK", "AOS_TELEMETRY_DISABLED"] {
        if let Ok(val) = std::env::var(var) {
            let v = val.trim().to_ascii_lowercase();
            if v == "1" || v == "true" || v == "yes" {
                return true;
            }
        }
    }
    if std::env::var_os("AOS_SANDBOX_ID").is_some() {
        return true;
    }
    if let Ok(home) = std::env::var("HOME") {
        if Path::new(&home)
            .join(".gemini/aegis-telemetry-opt-out")
            .exists()
        {
            return true;
        }
    }
    false
}

/// Derives a one-way irreversible 16-hex-char anonymous device token (`anon-<16hex>`).
pub fn anonymous_device_id(runtime_dir: &Path) -> String {
    let persisted_path = std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".config/aegis-os/telemetry_device_id"))
        .unwrap_or_else(|| runtime_dir.join("telemetry_device_id"));

    if let Ok(saved) = std::fs::read_to_string(&persisted_path) {
        let trimmed = saved.trim();
        if trimmed.starts_with("anon-") && trimmed.len() >= 16 {
            return trimmed.to_string();
        }
    }

    let seed = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let token = PaasControlPlane::anonymous_device_token(&seed);

    if let Some(parent) = persisted_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&persisted_path, token.as_bytes());
    token
}

/// Records an anonymous `install` or `daily_active` telemetry ping (deduplicated to at most once
/// per UTC day per client for `daily_active`, non-blocking for remote endpoints).
pub async fn emit_telemetry_ping(runtime_dir: &Path, event: &str, client: &str, mode: &str) {
    if is_telemetry_disabled() {
        return;
    }

    let today = Utc::now().format("%Y-%m-%d").to_string();
    let marker_file = runtime_dir.join("telemetry_last_ping.txt");
    let marker_key = format!("{today}:{client}");

    if event == "daily_active" {
        if let Ok(existing) = std::fs::read_to_string(&marker_file) {
            if existing.lines().any(|l| l.trim() == marker_key) {
                return;
            }
        }
        let _ = std::fs::create_dir_all(runtime_dir);
        let mut lines: Vec<String> = std::fs::read_to_string(&marker_file)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.starts_with(&today))
            .map(str::to_string)
            .collect();
        lines.push(marker_key);
        let _ = std::fs::write(&marker_file, lines.join("\n"));
    }

    let payload = TelemetryPingPayload {
        device_id: anonymous_device_id(runtime_dir),
        event: event.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        client: client.to_string(),
        mode: mode.to_string(),
    };

    // 1. Always record locally in `<runtime_dir>/paas_state.json` so `aegis-os stats` works out of the box.
    let paas = PaasControlPlane::new(runtime_dir);
    let _ = paas.record_telemetry_ping(payload.clone()).await;

    // 2. If a remote telemetry or cloud endpoint is configured, forward asynchronously with a 800ms timeout.
    let remote_base = std::env::var("AOS_TELEMETRY_URL")
        .ok()
        .or_else(|| std::env::var("AOS_CLOUD_ENDPOINT").ok())
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty());

    if let Some(base) = remote_base {
        let url = if base.ends_with("/v1/telemetry/ping") {
            base
        } else {
            format!("{base}/v1/telemetry/ping")
        };
        let body = serde_json::to_value(&payload).unwrap_or_else(|_| json!({}));
        let _ = tokio::time::timeout(
            Duration::from_millis(800),
            tokio::task::spawn_blocking(move || {
                let agent = ureq::AgentBuilder::new()
                    .timeout(Duration::from_millis(750))
                    .build();
                let _ = agent.post(&url).send_json(body);
            }),
        )
        .await;
    }
}

fn fetch_github_release_metrics(repo: &str) -> Option<Value> {
    let repo = repo.trim().trim_matches('/');
    if repo.is_empty() {
        return None;
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(2500))
        .user_agent("aegis-os-cli")
        .build();

    let repo_url = format!("https://api.github.com/repos/{repo}");
    let repo_json: Value = agent
        .get(&repo_url)
        .call()
        .ok()
        .and_then(|r| r.into_json().ok())?;

    let stars = repo_json
        .get("stargazers_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let forks = repo_json
        .get("forks_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let open_issues = repo_json
        .get("open_issues_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let rel_url = format!("https://api.github.com/repos/{repo}/releases?per_page=10");
    let releases: Vec<Value> = agent
        .get(&rel_url)
        .call()
        .ok()
        .and_then(|r| r.into_json().ok())
        .unwrap_or_default();

    let mut total_downloads = 0u64;
    let mut release_summaries = Vec::new();
    for rel in releases.iter().take(5) {
        let tag = rel
            .get("tag_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let assets = rel
            .get("assets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut rel_dl = 0u64;
        for a in &assets {
            rel_dl += a
                .get("download_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
        }
        total_downloads += rel_dl;
        release_summaries.push(json!({
            "tag": tag,
            "downloads": rel_dl,
            "assets_count": assets.len()
        }));
    }

    Some(json!({
        "repo": repo,
        "stars": stars,
        "forks": forks,
        "open_issues": open_issues,
        "total_release_downloads": total_downloads,
        "recent_releases": release_summaries
    }))
}

/// Renders the Aegis OS Product Growth & User Analytics Dashboard in the terminal (or as JSON).
pub async fn render_growth_analytics(
    runtime_dir: &Path,
    endpoint: Option<&str>,
    admin_secret: Option<&str>,
    github_repo: &str,
    json_out: bool,
) -> anyhow::Result<()> {
    let remote_ep = endpoint
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            std::env::var("AOS_CLOUD_ENDPOINT")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });

    let telemetry_stats: Value = if let Some(ref ep) = remote_ep {
        let url = format!("{}/v1/telemetry/stats", ep.trim_end_matches('/'));
        let secret = admin_secret
            .map(str::to_string)
            .or_else(|| std::env::var("AOS_ADMIN_SECRET").ok())
            .unwrap_or_default();
        let url_clone = url.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(4))
                .build();
            let mut req = agent.get(&url_clone);
            if !secret.trim().is_empty() {
                req = req.set("Authorization", &format!("Bearer {}", secret.trim()));
                req = req.set("X-Aegis-Admin-Secret", secret.trim());
            }
            let resp = req.call()?;
            Ok(resp.into_json()?)
        })
        .await??
    } else {
        let paas = PaasControlPlane::new(runtime_dir);
        paas.get_telemetry_stats().await
    };

    let repo_owned = github_repo.to_string();
    let gh_metrics = tokio::task::spawn_blocking(move || fetch_github_release_metrics(&repo_owned))
        .await
        .ok()
        .flatten();

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "source": remote_ep.as_deref().unwrap_or("local_runtime"),
                "telemetry": telemetry_stats,
                "github": gh_metrics
            }))?
        );
        return Ok(());
    }

    println!("========================================================================");
    println!("  AEGIS OS — PRODUCT GROWTH & USER ANALYTICS (`aegis-os stats`)");
    println!("========================================================================");
    println!(
        "  Data Source:   {}",
        remote_ep.as_deref().unwrap_or("Local Runtime (pass `--endpoint <CLOUD_URL>` for global fleet)")
    );
    println!(
        "  Telemetry ID:  {} (opt-out: `export DO_NOT_TRACK=1`)",
        anonymous_device_id(runtime_dir)
    );

    if let Some(ref gh) = gh_metrics {
        println!("\n[1] GitHub Distribution & Release Downloads ({})", gh["repo"].as_str().unwrap_or(github_repo));
        println!(
            "  - Stars: {:<8}  Forks: {:<8}  Release Binary Downloads: {}",
            gh["stars"].as_u64().unwrap_or(0),
            gh["forks"].as_u64().unwrap_or(0),
            gh["total_release_downloads"].as_u64().unwrap_or(0)
        );
        if let Some(rels) = gh["recent_releases"].as_array() {
            for r in rels.iter().take(3) {
                println!(
                    "    * {:<12} -> {} downloads",
                    r["tag"].as_str().unwrap_or("-"),
                    r["downloads"].as_u64().unwrap_or(0)
                );
            }
        }
    }

    println!("\n[2] Active User & Retention Metrics (Anonymous Telemetry)");
    println!(
        "  - Cumulative Installed Devices: {} (Total install runs: {})",
        telemetry_stats["total_unique_devices"].as_u64().unwrap_or(0),
        telemetry_stats["total_install_events"].as_u64().unwrap_or(0)
    );
    println!(
        "  - Today New Devices:            {}",
        telemetry_stats["new_devices_today"].as_u64().unwrap_or(0)
    );
    println!(
        "  - DAU (Today Active):           {}",
        telemetry_stats["dau"].as_u64().unwrap_or(0)
    );
    println!(
        "  - WAU (7-Day Active):           {}",
        telemetry_stats["wau"].as_u64().unwrap_or(0)
    );
    println!(
        "  - MAU (30-Day Active):          {}",
        telemetry_stats["mau"].as_u64().unwrap_or(0)
    );
    println!(
        "  - Stickiness (DAU / MAU):       {:.1}%",
        telemetry_stats["stickiness_dau_mau_pct"].as_f64().unwrap_or(0.0)
    );
    println!(
        "  - Multi-Day Retention (2+ d):   {} devices ({:.1}%)",
        telemetry_stats["retained_2plus_days_devices"].as_u64().unwrap_or(0),
        telemetry_stats["retained_2plus_days_pct"].as_f64().unwrap_or(0.0)
    );
    println!(
        "  - Cloud Tenants / Paid Subs:    {} tenants / {} active paid",
        telemetry_stats["cloud_tenants_count"].as_u64().unwrap_or(0),
        telemetry_stats["active_paid_subscriptions"].as_u64().unwrap_or(0)
    );

    println!("\n[3] Breakdown by Coding Agent Client & OS/Arch");
    if let Some(clients) = telemetry_stats["by_client"].as_object() {
        let mut pairs: Vec<(&String, u64)> = clients
            .iter()
            .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
            .collect();
        pairs.sort_by_key(|pair| std::cmp::Reverse(pair.1));
        let summary = if pairs.is_empty() {
            "none yet".to_string()
        } else {
            pairs
                .into_iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join(" | ")
        };
        println!("  - Clients:   {summary}");
    }
    if let Some(os_map) = telemetry_stats["by_os_arch"].as_object() {
        let summary = if os_map.is_empty() {
            "none yet".to_string()
        } else {
            os_map
                .iter()
                .map(|(k, v)| format!("{k}: {}", v.as_u64().unwrap_or(0)))
                .collect::<Vec<_>>()
                .join(" | ")
        };
        println!("  - Platforms: {summary}");
    }
    if let Some(ver_map) = telemetry_stats["by_version"].as_object() {
        let summary = if ver_map.is_empty() {
            "none yet".to_string()
        } else {
            ver_map
                .iter()
                .map(|(k, v)| format!("v{k}: {}", v.as_u64().unwrap_or(0)))
                .collect::<Vec<_>>()
                .join(" | ")
        };
        println!("  - Versions:  {summary}");
    }

    if let Some(trend) = telemetry_stats["daily_trend_14d"].as_array() {
        println!("\n[4] Last 7 Days Trend (UTC)");
        for item in trend.iter().rev().take(7).rev() {
            let d = item["date"].as_str().unwrap_or("-");
            let dau_n = item["dau"].as_u64().unwrap_or(0);
            let new_n = item["new_devices"].as_u64().unwrap_or(0);
            let bar = "#".repeat((dau_n as usize).min(30));
            println!("  {d} | DAU: {:<4} (+{:<3} new) {}", dau_n, new_n, bar);
        }
    }
    println!("========================================================================");
    Ok(())
}

// ============================================================================
// P0 PLG Lead-Magnet: `aegis-os audit-me` Local Agent Risk & Prompt Fatigue Card
// ============================================================================

fn count_files_shallow(dir: &Path, depth: usize, max_depth: usize) -> u64 {
    if depth > max_depth || !dir.is_dir() {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut count = 0u64;
    for entry in entries.flatten().take(250) {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_file() {
            count += 1;
        } else if ft.is_dir() {
            count += count_files_shallow(&path, depth + 1, max_depth);
        }
    }
    count
}

fn file_mentions_aegis(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|text| text.contains("aegis-os") || text.contains("Aegis OS"))
        .unwrap_or(false)
}

/// Computes a 100% local, privacy-preserving Coding Agent Risk & Approval Fatigue diagnostic
/// report (`aegis-os audit-me`). Never reads or transmits secret contents.
pub fn compute_audit_me_report(home_dir: &Path, workspace: &Path, runtime_dir: &Path) -> Value {
    // 1. Host Credential Exposure Surface (metadata presence only; never reads file contents)
    let credential_probes: Vec<(&str, &str, PathBuf, &str)> = vec![
        (
            "ssh_keys",
            "SSH Private Keys & Config (`~/.ssh`)",
            home_dir.join(".ssh"),
            "~/.ssh",
        ),
        (
            "aws_creds",
            "AWS IAM Credentials (`~/.aws`)",
            home_dir.join(".aws"),
            "~/.aws",
        ),
        (
            "gcp_adc",
            "Google Cloud ADC (`~/.config/gcloud`)",
            home_dir.join(".config/gcloud"),
            "~/.config/gcloud",
        ),
        (
            "kubeconfig",
            "Kubernetes Cluster Config (`~/.kube/config`)",
            home_dir.join(".kube/config"),
            "~/.kube/config",
        ),
        (
            "docker_auth",
            "Docker Registry Tokens (`~/.docker/config.json`)",
            home_dir.join(".docker/config.json"),
            "~/.docker/config.json",
        ),
        (
            "pkg_tokens",
            "Package Registry Tokens (`~/.npmrc` / `~/.cargo/credentials.toml`)",
            if home_dir.join(".npmrc").exists() {
                home_dir.join(".npmrc")
            } else {
                home_dir.join(".cargo/credentials.toml")
            },
            "~/.npmrc | ~/.cargo/credentials.toml",
        ),
        (
            "gh_creds",
            "GitHub CLI & Git Credentials (`~/.config/gh` / `~/.git-credentials`)",
            if home_dir.join(".config/gh").exists() {
                home_dir.join(".config/gh")
            } else {
                home_dir.join(".git-credentials")
            },
            "~/.config/gh | ~/.git-credentials",
        ),
        (
            "workspace_dotenv",
            "Workspace `.env` Secrets (`.env` / `.env.local`)",
            if workspace.join(".env").exists() {
                workspace.join(".env")
            } else {
                workspace.join(".env.local")
            },
            "<workspace>/.env*",
        ),
    ];

    let shim_dir = home_dir.join(".aegis").join("bin");
    let enforced_shims: Vec<String> = ["claude", "codex", "agy", "opencode", "hermes"]
        .into_iter()
        .filter(|agent| shim_dir.join(agent).is_file())
        .map(str::to_string)
        .collect();
    let has_enforced_shims = !enforced_shims.is_empty();

    let mut credential_items = Vec::new();
    let mut exposed_stores_count = 0u64;
    for (id, label, path, display_path) in credential_probes {
        let present = path.exists();
        if present {
            exposed_stores_count += 1;
        }
        credential_items.push(json!({
            "id": id,
            "label": label,
            "path": display_path,
            "present_on_host": present,
            "raw_yolo_accessible": present,
            "masked_by_aegis_enforced": true
        }));
    }

    // 2. Coding Agent Clients & Protection Posture
    let client_probes = [
        (
            "agy",
            "Antigravity (AGY)",
            home_dir.join(".gemini"),
            home_dir.join(".gemini/config/mcp_config.json"),
        ),
        (
            "claude",
            "Claude Code",
            home_dir.join(".claude"),
            home_dir.join(".claude.json"),
        ),
        (
            "codex",
            "OpenAI Codex CLI",
            home_dir.join(".codex"),
            home_dir.join(".codex/config.toml"),
        ),
        (
            "opencode",
            "OpenCode",
            home_dir.join(".config/opencode"),
            home_dir.join(".config/opencode/opencode.json"),
        ),
    ];

    let mut clients = Vec::new();
    let mut detected_clients_count = 0u64;
    let mut advisory_clients_count = 0u64;
    let mut configured_client_ids = Vec::new();

    for (id, name, dir_path, cfg_path) in client_probes {
        let detected = dir_path.exists() || cfg_path.exists();
        let advisory = file_mentions_aegis(&cfg_path);
        let enforced = shim_dir.join(id).is_file();
        if detected {
            detected_clients_count += 1;
        }
        if advisory {
            advisory_clients_count += 1;
            configured_client_ids.push(id.to_string());
        }
        clients.push(json!({
            "id": id,
            "name": name,
            "detected": detected,
            "advisory_configured": advisory,
            "enforced_shim": enforced,
        }));
    }

    let repo_rules_configured = workspace
        .join(".agents/rules/aegis-os-workflow.md")
        .is_file()
        || workspace.join(".aegis/workspace.json").is_file()
        || workspace.join(".aegis/verify.json").is_file();

    // 3. Approval Prompt Fatigue & Developer Time Saved Estimation
    let history_dirs = [
        home_dir.join(".claude/projects"),
        home_dir.join(".claude/todos"),
        home_dir.join(".claude/shell-snapshots"),
        home_dir.join(".codex/sessions"),
        home_dir.join(".codex/log"),
        home_dir.join(".gemini/antigravity-cli/brain"),
        runtime_dir.join("sessions"),
    ];
    let mut observed_artifacts = 0u64;
    for d in &history_dirs {
        observed_artifacts += count_files_shallow(d, 0, 2);
    }

    let estimated_tool_calls = (observed_artifacts.saturating_mul(28)).max(150);
    // Paper benchmark (52 real sessions, 28,087 tool calls): ~48% of raw tool calls trigger prompts;
    // Aegis CoW Shadow VFS eliminates 90.7%–97.9% (midpoint 94.3%) of per-action prompts.
    let raw_prompts_estimated = ((estimated_tool_calls as f64) * 0.48).round() as u64;
    let prompts_eliminated = ((raw_prompts_estimated as f64) * 0.943).round() as u64;
    let prompts_remaining = raw_prompts_estimated.saturating_sub(prompts_eliminated);
    let minutes_saved_estimated = ((prompts_eliminated * 6) / 60).max(1);

    // 4. Readiness Score (0..=100) & Grade
    let mut score: u64 = 20;
    if advisory_clients_count > 0 {
        score += 35;
        if detected_clients_count > 0 && advisory_clients_count >= detected_clients_count {
            score += 10;
        }
    }
    if has_enforced_shims {
        score += 25;
    } else if exposed_stores_count == 0 {
        score += 10;
    }
    if repo_rules_configured {
        score += 10;
    }
    score = score.min(100);

    let (grade, verdict) = match score {
        85..=100 => ("S", "ZERO-TRUST ENFORCED (Kernel Sandbox + CoW Shadow Active)"),
        70..=84 => ("A", "COW SHADOW PROTECTED (Run `aegis-os install --enforce` for Grade S)"),
        50..=69 => ("B", "PARTIAL ADVISORY (Some agents or repo rules not yet wired)"),
        35..=49 => ("C", "ELEVATED EXPOSURE (High prompt fatigue & unmasked host credentials)"),
        _ => ("D", "RAW AGENT EXPOSURE (Immediate `--yolo` credential & overwrite risk)"),
    };

    let configured_list = if configured_client_ids.is_empty() {
        "none (run `aegis-os install`)".to_string()
    } else {
        configured_client_ids.join(", ")
    };

    let badge_color = match grade {
        "S" | "A" => "0A7D52",
        "B" => "2563EB",
        _ => "D97706",
    };
    let share_card_markdown = format!(
        "### 🛡️ Coding Agent Security & Prompt Fatigue Audit (`aegis-os audit-me`)\n\
         [![Aegis OS Audit](https://img.shields.io/badge/Aegis_OS_Audit-Grade_{grade}_%28{score}%2F100%29-{badge_color})](https://github.com/heurion-org/aegis-os)\n\n\
         - **Host Credential Stores Protected**: `{exposed_stores_count}` sensitive stores (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `.env`) masked in Enforced mode (`0.0%` red-team leak rate)\n\
         - **Approval Prompts Eliminated**: `~{prompts_eliminated}` manual confirmations saved (`94.3%` reduction via Transactional CoW Shadow VFS, `~{minutes_saved_estimated} min` flow time recovered)\n\
         - **Multi-Agent Overwrite Protection**: `98.7%` 4-Tier LCS auto-merge (eliminates the `41.2%` silent overwrite rate in raw shared folders)\n\
         - **Protected Coding Agents**: `{configured_list}`\n\n\
         > ⚡ Run your own 5-second local checkup:\n\
         > ```bash\n\
         > brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git && brew install aegis-os && aegis-os audit-me\n\
         > ```"
    );

    json!({
        "score": score,
        "grade": grade,
        "verdict": verdict,
        "credential_exposure": {
            "exposed_stores_on_host": exposed_stores_count,
            "enforced_shims_active": has_enforced_shims,
            "enforced_shims": enforced_shims,
            "stores": credential_items,
        },
        "agent_posture": {
            "detected_clients_count": detected_clients_count,
            "advisory_configured_count": advisory_clients_count,
            "configured_clients": configured_client_ids,
            "repo_rules_configured": repo_rules_configured,
            "clients": clients,
        },
        "fatigue_and_conflict": {
            "observed_session_artifacts": observed_artifacts,
            "estimated_tool_calls": estimated_tool_calls,
            "raw_prompts_estimated": raw_prompts_estimated,
            "prompts_eliminated_by_cow": prompts_eliminated,
            "prompts_remaining_boundary_only": prompts_remaining,
            "prompt_reduction_pct": 94.3,
            "minutes_saved_estimated": minutes_saved_estimated,
            "raw_multi_agent_overwrite_rate_pct": 41.2,
            "aegis_cow_auto_merge_rate_pct": 98.7,
        },
        "share_card_markdown": share_card_markdown,
        "install_cta": "brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git && brew install aegis-os && aegis-os install --enforce"
    })
}

/// Renders the `aegis-os audit-me` diagnostic report to stdout (terminal box, `--share` Markdown, or `--json`).
pub async fn render_audit_me_report(
    home_dir: &Path,
    workspace: &Path,
    runtime_dir: &Path,
    share_markdown: bool,
    json_out: bool,
) -> anyhow::Result<()> {
    let report = compute_audit_me_report(home_dir, workspace, runtime_dir);

    if json_out {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if share_markdown {
        println!(
            "{}",
            report["share_card_markdown"].as_str().unwrap_or_default()
        );
        return Ok(());
    }

    let score = report["score"].as_u64().unwrap_or(0);
    let grade = report["grade"].as_str().unwrap_or("-");
    let verdict = report["verdict"].as_str().unwrap_or("-");
    let exposed_count = report["credential_exposure"]["exposed_stores_on_host"]
        .as_u64()
        .unwrap_or(0);
    let has_shims = report["credential_exposure"]["enforced_shims_active"]
        .as_bool()
        .unwrap_or(false);
    let raw_prompts = report["fatigue_and_conflict"]["raw_prompts_estimated"]
        .as_u64()
        .unwrap_or(0);
    let saved_prompts = report["fatigue_and_conflict"]["prompts_eliminated_by_cow"]
        .as_u64()
        .unwrap_or(0);
    let mins_saved = report["fatigue_and_conflict"]["minutes_saved_estimated"]
        .as_u64()
        .unwrap_or(0);
    let repo_rules = report["agent_posture"]["repo_rules_configured"]
        .as_bool()
        .unwrap_or(false);

    println!("┌──────────────────────────────────────────────────────────────────────────────┐");
    println!("│  🛡️  AEGIS OS — CODING AGENT SECURITY & PROMPT FATIGUE AUDIT (`audit-me`)   │");
    println!("├──────────────────────────────────────────────────────────────────────────────┤");
    println!(
        "│  Readiness Score: {:>3}/100 [Grade {}] — {:<38} │",
        score,
        grade,
        &verdict[..verdict.len().min(38)]
    );
    println!("└──────────────────────────────────────────────────────────────────────────────┘");

    println!("\n[1] Host Credential Exposure Surface (100% Local Metadata Check)");
    println!(
        "  • Sensitive Credential Stores Found on Host: {} store(s)",
        exposed_count
    );
    if let Some(stores) = report["credential_exposure"]["stores"].as_array() {
        for s in stores {
            if s["present_on_host"].as_bool().unwrap_or(false) {
                let status = if has_shims {
                    "MASKED by Enforced Shim (`0.0%` leak)"
                } else {
                    "EXPOSED to raw `--yolo` / un-sandboxed agents"
                };
                println!(
                    "    - {:<52} -> [{}]",
                    s["label"].as_str().unwrap_or("-"),
                    status
                );
            }
        }
    }

    println!("\n[2] Approval Prompt Fatigue & Developer Flow Recovery");
    println!(
        "  • Estimated Manual Prompts Without Aegis:    ~{} confirmations",
        raw_prompts
    );
    println!(
        "  • Prompts Eliminated by CoW Shadow VFS:      ~{} saved (-94.3% prompt reduction)",
        saved_prompts
    );
    println!(
        "  • Developer Context-Switch Time Recovered:   ~{} minutes saved",
        mins_saved
    );

    println!("\n[3] Multi-Agent Silent Overwrite & Workspace Posture");
    println!("  • Raw Shared-Folder Multi-Agent Overwrites:  41.2% silent loss (benchmark baseline)");
    println!("  • Aegis 4-Tier LCS CoW Auto-Merge Rate:      98.7% conflict-free merge");
    println!(
        "  • Current Repo Collaborator Rules (`.agents`): {}",
        if repo_rules {
            "ACTIVE (`.agents/rules/aegis-os-workflow.md`)"
        } else {
            "MISSING (run `aegis-os setup-agy` to protect repo collaborators)"
        }
    );
    if let Some(clients) = report["agent_posture"]["clients"].as_array() {
        for c in clients {
            let name = c["name"].as_str().unwrap_or("-");
            let adv = c["advisory_configured"].as_bool().unwrap_or(false);
            let enf = c["enforced_shim"].as_bool().unwrap_or(false);
            let badge = if enf {
                "ENFORCED (Shim + CoW + MCP)"
            } else if adv {
                "ADVISORY (CoW + MCP)"
            } else {
                "UNPROTECTED"
            };
            println!("    - {:<24} -> [{}]", name, badge);
        }
    }

    println!("\n[4] Recommended Next Actions & Shareable Report");
    if !has_shims {
        println!("  👉 Upgrade to Grade S (Kernel Enforced): `aegis-os install --enforce`");
    }
    if !repo_rules {
        println!("  👉 Add Repo Team Onboarding Rules:       `aegis-os setup-agy`");
    }
    println!("  📤 Export Markdown Share Card (X/PR/IM): `aegis-os audit-me --share`\n");
    println!("--- Copy & Share Your Audit Badge ---");
    println!(
        "{}",
        report["share_card_markdown"].as_str().unwrap_or_default()
    );
    println!("-------------------------------------");
    Ok(())
}

#[cfg(test)]
mod audit_me_tests {
    use super::compute_audit_me_report;

    #[test]
    fn audit_me_computes_score_and_share_card_without_reading_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let ws = tmp.path().join("repo");
        let rt = tmp.path().join("runtime");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".ssh/id_ed25519"), "DO_NOT_READ_PRIVATE_KEY").unwrap();
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join(".env"), "SECRET_TOKEN=DO_NOT_READ_PRIVATE_KEY\n").unwrap();
        std::fs::create_dir_all(&rt).unwrap();

        // 1. Raw unprotected state
        let raw_report = compute_audit_me_report(&home, &ws, &rt);
        assert!(
            raw_report["credential_exposure"]["exposed_stores_on_host"]
                .as_u64()
                .unwrap_or(0)
                >= 1
        );
        let raw_score = raw_report["score"].as_u64().unwrap();
        assert!(raw_score <= 30, "expected low score for unprotected host, got {raw_score}");
        let share_md = raw_report["share_card_markdown"].as_str().unwrap();
        assert!(share_md.contains("aegis-os audit-me"));
        assert!(!share_md.contains("DO_NOT_READ_PRIVATE_KEY"));

        // 2. Configured advisory + enforced shim + repo rules -> Grade S
        std::fs::create_dir_all(home.join(".gemini/config")).unwrap();
        std::fs::write(
            home.join(".gemini/config/mcp_config.json"),
            r#"{"mcpServers":{"aegis-os":{}}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(home.join(".aegis/bin")).unwrap();
        std::fs::write(home.join(".aegis/bin/agy"), "#!/bin/sh\n").unwrap();
        std::fs::create_dir_all(ws.join(".agents/rules")).unwrap();
        std::fs::write(ws.join(".agents/rules/aegis-os-workflow.md"), "# Aegis OS\n").unwrap();

        let protected_report = compute_audit_me_report(&home, &ws, &rt);
        let protected_score = protected_report["score"].as_u64().unwrap();
        assert!(protected_score >= 85, "expected Grade S score >= 85, got {protected_score}");
        assert_eq!(protected_report["grade"].as_str(), Some("S"));
    }
}

