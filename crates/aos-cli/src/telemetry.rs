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
