use super::*;

pub(super) async fn run_verify_for_session(
    runtime_dir: &Path,
    value: &Value,
    override_cmd: Option<&str>,
) -> anyhow::Result<()> {
    let workspace = value
        .get("workspace")
        .and_then(|v| v.as_str())
        .context("session is missing workspace")?;
    let shadow = value
        .get("shadow")
        .and_then(|v| v.as_str())
        .context("session is missing shadow")?;
    let org_id = value
        .get("org_id")
        .and_then(|v| v.as_str())
        .context("session is missing org_id")?;
    let agent_id = value
        .get("agent_id")
        .and_then(|v| v.as_str())
        .context("session is missing agent_id")?;
    let agent_home = value
        .get("agent_home")
        .and_then(|v| v.as_str())
        .context("session is missing agent_home")?;
    let Some((cmd, timeout_ms)) = resolved_verify_command(Path::new(workspace), override_cmd) else {
        println!("No verify_cmd configured; skipping domain verification gate.");
        return Ok(());
    };

    println!("Running domain verify gate: {cmd}");
    let org_shared = runtime_dir.join("orgs").join(org_id).join("shared_ro");
    let org_pub = runtime_dir.join("orgs").join(org_id).join("pub").join(agent_id);
    std::fs::create_dir_all(&org_shared)?;
    std::fs::create_dir_all(&org_pub)?;
    let driver = NativeOsSandboxDriver;
    let sandbox = driver
        .create_sandbox(SandboxConfig {
            identity: AgentIdentity::new(org_id, agent_id, "verify"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: PathBuf::from(shadow),
            agent_home_dir: PathBuf::from(agent_home),
            org_shared_ro_dir: org_shared,
            org_agent_pub_dir: org_pub,
            egress_proxy_addr: None,
            host_source_dir: Some(PathBuf::from(workspace)),
            tighten_home_read: true,
            allowed_loopback_ports: aos_sandbox::allocate_loopback_ports(2, &[]),
            isolate_loopback_only: true,
        })
        .await?;
    let out = sandbox
        .exec(ExecSpec {
            command: "sh".to_string(),
            args: vec!["-c".to_string(), cmd.clone()],
            cwd: Some(PathBuf::from(shadow)),
            env: std::collections::HashMap::new(),
            timeout_ms: Some(timeout_ms),
            background: false,
        })
        .await?;
    if !out.stdout.trim().is_empty() {
        println!("{}", out.stdout.trim_end());
    }
    if !out.stderr.trim().is_empty() {
        eprintln!("{}", out.stderr.trim_end());
    }
    if out.exit_code != Some(0) {
        bail!(
            "domain verification gate failed (exit {:?}): {}",
            out.exit_code,
            cmd
        );
    }
    println!("Domain verification gate passed.");
    Ok(())
}

pub(crate) async fn verify(
    runtime_dir: &Path,
    session_id: Option<&str>,
    override_cmd: Option<&str>,
) -> anyhow::Result<()> {
    let Some((_dir, value)) = find_session(runtime_dir, session_id)? else {
        bail!("Aegis: no sessions under {}", runtime_dir.display());
    };
    run_verify_for_session(runtime_dir, &value, override_cmd).await
}

/// Resolve an artifact path strictly inside the session shadow. `canonicalize` also rejects
/// symlinks that escape the shadow (e.g. a committed `figures/out -> ~/.ssh` link).
pub(super) fn shadow_artifact_path(shadow: &Path, rel: &str) -> anyhow::Result<Option<PathBuf>> {
    let canonical_shadow = std::fs::canonicalize(shadow)
        .with_context(|| format!("canonicalizing shadow {}", shadow.display()))?;
    let candidate = shadow.join(rel.trim_start_matches('/'));
    let Ok(canonical) = std::fs::canonicalize(&candidate) else {
        return Ok(None);
    };
    if !canonical.starts_with(&canonical_shadow) {
        bail!(
            "aos publish: refusing '{}' because it resolves outside the session shadow",
            rel
        );
    }
    Ok(Some(canonical))
}

pub(super) fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "csv" => "text/csv",
        "tsv" => "text/tab-separated-values",
        "json" => "application/json",
        "jsonl" => "application/x-ndjson",
        "md" | "markdown" => "text/markdown",
        "tex" => "application/x-tex",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "parquet" => "application/vnd.apache.parquet",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

pub(crate) async fn publish(
    runtime_dir: &Path,
    session_id: Option<&str>,
    requested_paths: Vec<String>,
) -> anyhow::Result<()> {
    let Some((dir, value)) = find_session(runtime_dir, session_id)? else {
        bail!("Aegis: no sessions under {}", runtime_dir.display());
    };
    let workspace = value
        .get("workspace")
        .and_then(|v| v.as_str())
        .context("session is missing workspace")?;
    let shadow = value
        .get("shadow")
        .and_then(|v| v.as_str())
        .context("session is missing shadow")?;
    let org_id = value
        .get("org_id")
        .and_then(|v| v.as_str())
        .context("session is missing org_id")?;
    let agent_id = value
        .get("agent_id")
        .and_then(|v| v.as_str())
        .context("session is missing agent_id")?;

    // Publishing to the organization CAS is a boundary action; run the configured domain gate
    // first so a failed schema/PHI/render check cannot be bypassed by publishing directly.
    run_verify_for_session(runtime_dir, &value, None).await?;

    let paths = if requested_paths.is_empty() {
        CoWWorkspace::diff_dirs(Path::new(workspace), Path::new(shadow), None)
            .await?
            .into_iter()
            .map(|d| d.relative_path)
            .collect::<Vec<_>>()
    } else {
        requested_paths
    };
    if paths.is_empty() {
        println!("Nothing to publish.");
        return Ok(());
    }

    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    let identity = AgentIdentity::new(org_id, agent_id, "publisher");
    let mut published = Vec::new();
    for rel in paths {
        let rel = rel.trim_start_matches('/').to_string();
        let Some(path) = shadow_artifact_path(Path::new(shadow), &rel)? else {
            println!("skip {rel} (not a regular file)");
            continue;
        };
        if !path.is_file() {
            println!("skip {rel} (not a regular file)");
            continue;
        }
        let meta = std::fs::metadata(&path)?;
        if meta.len() > 64 * 1024 * 1024 {
            println!("skip {rel} ({} bytes; publish limit is 64 MiB)", meta.len());
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let artifact = kernel
            .org_storage
            .publish_artifact(
                &identity,
                &rel,
                &bytes,
                content_type(&path),
                json!({ "session_id": value.get("session_id"), "path": rel }),
            )
            .await?;
        println!("{}  {}", artifact.uri, rel);
        published.push(json!({
            "path": rel,
            "uri": artifact.uri,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "content_type": artifact.content_type,
        }));
    }
    std::fs::write(
        dir.join("published.json"),
        serde_json::to_vec_pretty(&json!({
            "session_id": value.get("session_id"),
            "artifacts": published,
            "published_at_ms": chrono::Utc::now().timestamp_millis(),
        }))?,
    )?;
    Ok(())
}

pub(crate) async fn artifacts_list(runtime_dir: &Path, identity: &AgentIdentity) -> anyhow::Result<()> {
    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    let artifacts = kernel.org_storage.list_artifacts(&identity.org_id).await?;
    if artifacts.is_empty() {
        println!("No artifacts in org '{}'.", identity.org_id);
        return Ok(());
    }
    println!("{:<70} {:<12} NAME", "URI", "SIZE");
    for artifact in artifacts {
        println!(
            "{:<70} {:<12} {}",
            artifact.uri, artifact.size_bytes, artifact.name
        );
    }
    Ok(())
}

pub(crate) async fn artifacts_fetch(
    runtime_dir: &Path,
    identity: &AgentIdentity,
    uri: &str,
    out: Option<PathBuf>,
) -> anyhow::Result<()> {
    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    let (meta, bytes) = kernel.org_storage.fetch_artifact(identity, uri).await?;
    let target = out.unwrap_or_else(|| {
        PathBuf::from(
            meta.name
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or("artifact.bin"),
        )
    });
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&target, &bytes)?;
    println!(
        "{} -> {} ({} bytes, sha256:{})",
        meta.uri,
        target.display(),
        bytes.len(),
        meta.sha256
    );
    Ok(())
}

pub(super) async fn print_exit_summary(
    session_dir: &Path,
    project: &Path,
    shadow: &Path,
    telemetry: Option<&ExitTelemetryContext>,
) -> usize {
    let egress_snap = persist_egress_usage(telemetry, session_dir).await;
    let print_egress = |snap: &UsageSnapshot| {
        eprint!(
            "  egress:    {} req(s), {} in / {} out tok (${:.4}), {} pseudonym(s), {} dlp block(s)",
            snap.requests,
            snap.input_tokens,
            snap.output_tokens,
            snap.cost_micro_usd as f64 / 1_000_000.0,
            snap.pseudonyms_active,
            snap.dlp_blocks,
        );
        if let Some(ref tripped) = snap.tripped {
            eprintln!(" [TRIPPED: {:?}]", tripped);
        } else {
            eprintln!();
        }
    };

    let changes = match CoWWorkspace::diff_dirs(project, shadow, None).await {
        Ok(changes) => changes,
        Err(err) => {
            eprintln!("\nAgent exited; could not summarize shadow changes: {err}");
            if let Some(ref snap) = egress_snap {
                print_egress(snap);
            }
            return 0;
        }
    };
    if changes.is_empty() {
        eprintln!("\nAgent exited. No shadow changes.");
        if let Some(ref snap) = egress_snap {
            print_egress(snap);
        }
        return 0;
    }

    eprintln!(
        "\nAgent exited. {} artifact(s) changed in shadow:",
        changes.len()
    );
    for change in changes.iter().take(20) {
        eprintln!(
            "  {} {}",
            diff_label(&change.change_type),
            change.relative_path
        );
    }
    if changes.len() > 20 {
        eprintln!("  ... {} more", changes.len() - 20);
    }
    if let Some(ref snap) = egress_snap {
        print_egress(snap);
    }
    eprintln!("  session: {}", session_dir.display());
    eprintln!("  aegis-os diff      inspect");
    eprintln!("  aegis-os commit    land (approval required)");
    eprintln!("  aegis-os discard   drop this shadow");
    changes.len()
}


#[cfg(target_os = "macos")]
pub(super) fn install_macos_opencode_wrapper(agent_home: &Path) -> anyhow::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let dir = agent_home.join(".aegis-bin");
    std::fs::create_dir_all(&dir)?;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    let script = r#"#!/bin/sh
# Aegis macOS Seatbelt pinned-port OpenCode standalone launcher.
# Starts OpenCode's private server on the single Seatbelt-permitted loopback port
# (`AOS_OPENCODE_PORT`) with a per-session random `OPENCODE_PASSWORD`, waits for
# its ready line, runs the CLI against `--server http://127.0.0.1:$AOS_OPENCODE_PORT`,
# and tears down the private server on exit.
FIFO="$TMPDIR/.aos_oc_ready_$$"
KEEP="$TMPDIR/.aos_oc_stdin_$$"
rm -f "$FIFO" "$KEEP"
mkfifo "$FIFO" "$KEEP" || exit 1
"$AOS_REAL_OPENCODE" serve --stdio --port "$AOS_OPENCODE_PORT" <"$KEEP" >"$FIFO" 2>/dev/null &
SRV_PID=$!
exec 4>"$KEEP"
exec 3<"$FIFO"
IFS= read -r _READY_LINE <&3
rm -f "$FIFO" "$KEEP"
cleanup() {
  kill "$SRV_PID" 2>/dev/null || true
  exec 4>&- 2>/dev/null || true
  exec 3<&- 2>/dev/null || true
}
trap cleanup EXIT INT TERM
rc=0
"$AOS_REAL_OPENCODE" "$@" || rc=$?
cleanup
exit "$rc"
"#;
    let wrapper = dir.join("aegis-opencode-macos");
    if wrapper.exists() {
        let _ = std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::write(&wrapper, script)?;
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o555))?;
    if !aos_core::ablated("git_guard") {
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555));
    }
    Ok(wrapper)
}
