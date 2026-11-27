use super::*;

impl AegisRuntimeKernel {
    pub async fn call_tool(
        &self,
        identity: &AgentIdentity,
        tool_name: &str,
        args: Value,
    ) -> anyhow::Result<Value> {
        if tool_name == "memory_policy_evaluate" {
            return self.memory_policy_evaluate(identity, args).await;
        }
        if let Some(res) = self
            .handle_external_mcp_control_tool(identity, tool_name, &args)
            .await?
        {
            return Ok(res);
        }

        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        let env = self
            .agents
            .read()
            .await
            .get(&key)
            .cloned()
            .with_context(|| format!("Agent environment '{}' is not initialized", key))?;

        if tool_name == "workspace_commit" {
            let _ = env.workspace.refresh_from_host().await;
        }

        let mut target_org = args
            .get("target_org_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&identity.org_id)
            .to_string();
        let mut target_resource = args
            .get("path")
            .or_else(|| args.get("dst_host_path"))
            .or_else(|| args.get("target_domain"))
            .or_else(|| args.get("to_agent"))
            .or_else(|| args.get("topic"))
            .or_else(|| args.get("uri"))
            .or_else(|| args.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("/workspace")
            .to_string();

        type PreExportPlan = (
            PathBuf,
            Vec<u8>,
            &'static str,
            String,
            String,
            String,
            Option<PathBuf>,
        );
        let mut audit_metadata = args.clone();
        let mut pre_commit_diffs: Option<Vec<aos_core::FileDiffEntry>> = None;
        let mut pre_commit_evidence_hash: Option<String> = None;
        let mut pre_export_plan: Option<PreExportPlan> = None;
        let mut pre_switch_plan: Option<(PathBuf, String, Option<PathBuf>)> = None;
        let mut pre_git_plan: Option<HostGitPlan> = None;
        let mut pre_import_plan: Option<ImportFilePlan> = None;
        let mut pre_ci_rerun_plan: Option<GitHubCiRerunPlan> = None;
        let mut pre_pr_create_plan: Option<GitHubPrCreatePlan> = None;
        let mut pre_comment_create_plan: Option<GitHubCommentCreatePlan> = None;
        let mut pre_pr_merge_plan: Option<GitHubPrMergePlan> = None;
        let mut pre_pkg_install_plan: Option<PkgInstallPlan> = None;
        let mut pre_host_exec_plan: Option<HostExecPlan> = None;
        if tool_name == "workspace_commit" {
            let filter_paths: Option<Vec<String>> = args
                .get("paths")
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            let overwrite_binaries = args
                .get("overwrite_binaries")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let skip_verify = args
                .get("skip_verify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let host_verify_cfg: Option<serde_json::Value> = std::fs::read(
                env.workspace.host_source_root().join(".aegis/verify.json"),
            )
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
            let configured_verify_cmd = std::env::var("AOS_VERIFY_CMD")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    host_verify_cfg
                        .as_ref()
                        .and_then(|cfg| cfg.get("verify_cmd"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                });
            if let Ok(mut touched) = env.workspace.changed_since_baseline().await {
                if let Some(ref allow) = filter_paths {
                    touched.retain(|p| allow.contains(p));
                }
                // Check peer file claims BEFORE policy evaluation so a claim conflict fails fast
                // without minting a spurious escalation ticket or burning a One-Shot lease.
                if let Some(msg) = self.claim_conflict_for_paths(identity, &touched).await? {
                    bail!("{}", msg);
                }
                let base_dir = env
                    .workspace
                    .shadow_root()
                    .parent()
                    .map(|p| p.join("baseline_snapshot"))
                    .filter(|p| p.exists())
                    .unwrap_or_else(|| env.workspace.host_source_root().to_path_buf());
                let diffs = CoWWorkspace::diff_dirs(
                    &base_dir,
                    env.workspace.shadow_root(),
                    filter_paths.as_deref(),
                )
                .await
                .unwrap_or_default();
                let (_canonical_diff_payload, evidence_hash) =
                    aos_core::compute_diff_evidence(&diffs, overwrite_binaries, skip_verify);
                if let Some(obj) = audit_metadata.as_object_mut() {
                    obj.insert("paths".to_string(), json!(touched));
                    obj.insert(
                        "host_root".to_string(),
                        json!(env.workspace.host_source_root().display().to_string()),
                    );
                    obj.insert("overwrite_binaries".to_string(), json!(overwrite_binaries));
                    obj.insert("skip_verify".to_string(), json!(skip_verify));
                    obj.insert(
                        "has_configured_verify_cmd".to_string(),
                        json!(configured_verify_cmd.is_some()),
                    );
                    obj.insert("evidence_hash".to_string(), json!(evidence_hash));
                    obj.insert(
                        "evidence".to_string(),
                        json!({
                            "changed_files_count": diffs.len(),
                            "paths": touched,
                            "evidence_hash": evidence_hash,
                            "overwrite_binaries": overwrite_binaries,
                            "skip_verify": skip_verify,
                            "configured_verify_cmd": configured_verify_cmd,
                        }),
                    );
                }
                pre_commit_diffs = Some(diffs);
                pre_commit_evidence_hash = Some(evidence_hash);
            }
        } else if tool_name == "fs_export_file" {
            let src_path = args
                .get("src_path")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .context("Missing 'src_path'")?;
            let dst_host_path = args
                .get("dst_host_path")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .context("Missing 'dst_host_path'")?;
            let overwrite = args
                .get("overwrite")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let bytes = if src_path.starts_with("artifact://") {
                let (_meta, b) = self.org_storage.fetch_artifact(identity, src_path).await?;
                b
            } else {
                let (_resolved, b) = read_sandbox_file_bytes_no_symlink(
                    env.workspace.shadow_root(),
                    &env.sandbox.config().agent_home_dir,
                    &env.sandbox.config().org_agent_pub_dir,
                    src_path,
                )?;
                b
            };

            let (canon_dst, mime_type) =
                validate_export_payload_and_dest(dst_host_path, &bytes, overwrite)?;
            let canon_rt = std::fs::canonicalize(&self.runtime_data_root)
                .unwrap_or_else(|_| self.runtime_data_root.clone());
            if canon_dst.starts_with(&canon_rt) {
                bail!(
                    "Blocked by Aegis OS Ring-0 policy: exporting into Aegis runtime state directory '{}' is forbidden",
                    canon_dst.display()
                );
            }

            if let Some(rel) =
                strip_root_matching_macos_private(&canon_dst, env.workspace.host_source_root())
            {
                let rel_s = rel.to_string_lossy().replace('\\', "/");
                if !rel_s.is_empty() {
                    if let Some(msg) = self.claim_conflict_for_paths(identity, &[rel_s]).await? {
                        bail!("{}", msg);
                    }
                }
            }

            self.ensure_org_vault(&identity.org_id).await?;
            let file_name = canon_dst
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("export.bin");
            let artifact_meta = self
                .org_storage
                .publish_artifact(
                    identity,
                    file_name,
                    &bytes,
                    mime_type,
                    json!({
                        "export_src": src_path,
                        "export_dst": canon_dst.display().to_string(),
                    }),
                )
                .await?;

            let (change_type, old_size, old_sha256) = if canon_dst.is_file() {
                let old_bytes = tokio::fs::read(&canon_dst).await.unwrap_or_default();
                let mut h = Sha256::new();
                h.update(&old_bytes);
                (
                    DiffChangeType::Modified,
                    Some(old_bytes.len() as u64),
                    Some(format!("sha256:{}", hex::encode(h.finalize()))),
                )
            } else {
                (DiffChangeType::Added, None, None)
            };
            let short_sha = &artifact_meta.sha256[..artifact_meta.sha256.len().min(16)];
            let diff_entry = aos_core::FileDiffEntry {
                relative_path: canon_dst.display().to_string(),
                change_type,
                old_size,
                new_size: Some(bytes.len() as u64),
                preview_diff: Some(format!(
                    "Zero-Copy Artifact Export -> {} ({} bytes, {}, sha256:{})",
                    canon_dst.display(),
                    bytes.len(),
                    mime_type,
                    short_sha
                )),
                old_sha256,
                new_sha256: Some(format!("sha256:{}", artifact_meta.sha256)),
            };
            let (_payload, evidence_hash) =
                aos_core::compute_diff_evidence(std::slice::from_ref(&diff_entry), overwrite, false);
            target_resource = canon_dst.display().to_string();
            if let Some(obj) = audit_metadata.as_object_mut() {
                obj.insert("src_path".to_string(), json!(src_path));
                obj.insert("dst_host_path".to_string(), json!(target_resource.clone()));
                obj.insert("overwrite".to_string(), json!(overwrite));
                obj.insert("size_bytes".to_string(), json!(bytes.len()));
                obj.insert("content_type".to_string(), json!(mime_type));
                obj.insert("sha256".to_string(), json!(artifact_meta.sha256.clone()));
                obj.insert("artifact_uri".to_string(), json!(artifact_meta.uri.clone()));
                obj.insert("evidence_hash".to_string(), json!(evidence_hash.clone()));
                obj.insert(
                    "evidence".to_string(),
                    json!({
                        "changed_files_count": 1,
                        "paths": [target_resource.clone()],
                        "evidence_hash": evidence_hash.clone(),
                        "artifact_uri": artifact_meta.uri.clone(),
                        "sha256": artifact_meta.sha256.clone(),
                        "size_bytes": bytes.len(),
                        "content_type": mime_type,
                    }),
                );
            }
            let cas_blob_path = self
                .runtime_data_root
                .join("orgs")
                .join(&identity.org_id)
                .join("cas")
                .join(&artifact_meta.sha256);
            pre_commit_diffs = Some(vec![diff_entry]);
            pre_commit_evidence_hash = Some(evidence_hash.clone());
            pre_export_plan = Some((
                canon_dst,
                bytes,
                mime_type,
                artifact_meta.sha256,
                artifact_meta.uri,
                evidence_hash,
                cas_blob_path.is_file().then_some(cas_blob_path),
            ));
        } else if tool_name == "workspace_switch" {
            if std::env::var_os("AOS_SESSION_ID").is_some() {
                bail!(
                    "workspace_switch is unavailable inside a single-root 'aegis-os run' kernel sandbox session; use 'fs_export_file' to export files to external directories or start a new session in the target directory."
                );
            }
            let raw_path = args
                .get("path")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .context("Missing 'path'")?;

            let existing_binding =
                aos_core::session::resolve_session_workspace_binding(&self.runtime_data_root);
            let existing_umbrella = existing_binding.as_ref().and_then(|(_, u, _)| u.clone());
            let current_root = std::fs::canonicalize(env.workspace.host_source_root())
                .unwrap_or_else(|_| env.workspace.host_source_root().to_path_buf());

            let candidate = if Path::new(raw_path).is_absolute() {
                PathBuf::from(raw_path)
            } else if current_root.join(raw_path).is_dir() {
                current_root.join(raw_path)
            } else if existing_umbrella
                .as_ref()
                .is_some_and(|u| u.join(raw_path).is_dir())
            {
                existing_umbrella.as_ref().unwrap().join(raw_path)
            } else if let Some(parent) = current_root.parent() {
                parent.join(raw_path)
            } else {
                bail!(
                    "Relative workspace_switch path '{}' requires a parent or umbrella root",
                    raw_path
                );
            };
            let canon_target = std::fs::canonicalize(&candidate)
                .with_context(|| format!("Target workspace directory '{}' not found", candidate.display()))?;
            if !canon_target.is_dir() {
                bail!("Target workspace '{}' is not a directory", canon_target.display());
            }
            if canon_target == Path::new("/") {
                bail!("Refusing to switch workspace to '/'");
            }
            if let Some(home) = std::env::var_os("HOME")
                .map(PathBuf::from)
                .and_then(|h| std::fs::canonicalize(&h).ok())
            {
                if canon_target == home || home.starts_with(&canon_target) {
                    bail!(
                        "Refusing to switch workspace to '{}' (user home or ancestor)",
                        canon_target.display()
                    );
                }
            }
            let canon_rt = std::fs::canonicalize(&self.runtime_data_root)
                .unwrap_or_else(|_| self.runtime_data_root.clone());
            if canon_target.starts_with(&canon_rt) || canon_rt.starts_with(&canon_target) {
                bail!(
                    "Refusing to switch workspace to '{}' (overlaps Aegis runtime state)",
                    canon_target.display()
                );
            }
            let canon_s = canon_target.to_string_lossy();
            if is_forbidden_export_dest(&canon_s, &canon_s) {
                bail!(
                    "Refusing to switch workspace to protected directory '{}'",
                    canon_target.display()
                );
            }

            let next_umbrella = match existing_umbrella {
                Some(ref u) if canon_target.starts_with(u) => Some(u.clone()),
                _ if canon_target.starts_with(&current_root) && canon_target != current_root => {
                    Some(current_root.clone())
                }
                other => other,
            };
            let within_umbrella = next_umbrella
                .as_ref()
                .is_some_and(|u| canon_target.starts_with(u))
                || canon_target == current_root;
            let new_org_id = args
                .get("org_id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| identity.org_id.clone());

            target_resource = canon_target.display().to_string();
            if let Some(obj) = audit_metadata.as_object_mut() {
                obj.insert("within_umbrella".to_string(), json!(within_umbrella));
                obj.insert("target_org_id".to_string(), json!(new_org_id.clone()));
            }
            pre_switch_plan = Some((canon_target, new_org_id, next_umbrella));
        } else if tool_name == "workspace_git" {
            let (plan, resource, diffs, meta) =
                self.prepare_workspace_git_plan(&env, identity, &args).await?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_git_plan = Some(plan);
        } else if tool_name == "fs_import_file" {
            let (plan, resource, diffs, meta) =
                self.prepare_fs_import_file_plan(&env, identity, &args).await?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_import_plan = Some(plan);
        } else if matches!(
            tool_name,
            "github_ci_inspect" | "github_pr_inspect" | "github_issue_inspect"
        ) {
            let (resource, meta) =
                Self::prepare_github_inspect_context(env.workspace.host_source_root(), &args)?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            if let Some(ev) = audit_metadata.get("evidence_hash").and_then(|v| v.as_str()) {
                pre_commit_evidence_hash = Some(ev.to_string());
            }
        } else if tool_name == "github_ci_rerun" {
            let (plan, resource, meta) =
                Self::prepare_github_ci_rerun_plan(env.workspace.host_source_root(), &args)?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_ci_rerun_plan = Some(plan);
        } else if tool_name == "github_pr_create" {
            let (plan, resource, diffs, meta) =
                Self::prepare_github_pr_create_plan(env.workspace.host_source_root(), &args)?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_pr_create_plan = Some(plan);
        } else if tool_name == "github_comment_create" {
            let (plan, resource, diffs, meta) =
                Self::prepare_github_comment_create_plan(env.workspace.host_source_root(), &args)?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_comment_create_plan = Some(plan);
        } else if tool_name == "github_pr_merge" {
            let (plan, resource, diffs, meta) =
                Self::prepare_github_pr_merge_plan(env.workspace.host_source_root(), &args)?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_pr_merge_plan = Some(plan);
        } else if tool_name == "pkg_install" {
            let (plan, resource, diffs, meta) = match Self::prepare_pkg_install_plan(&env, &args) {
                Ok(planned) => planned,
                Err(err) => {
                    self.record_kernel_friction(
                        aos_core::friction::FrictionCategory::PkgInstallFailed,
                        aos_core::friction::CmdBucket::PkgInstall,
                        Some("mcp_gateway"),
                        None,
                        1,
                        false,
                    );
                    return Err(err);
                }
            };
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_pkg_install_plan = Some(plan);
        } else if tool_name == "host_exec" {
            let (plan, resource, diffs, meta) = match self.prepare_host_exec_plan(&env, &args).await {
                Ok(planned) => planned,
                Err(err) => {
                    self.record_kernel_friction(
                        aos_core::friction::FrictionCategory::HostExecDenied,
                        aos_core::friction::CmdBucket::HostExec,
                        Some("mcp_gateway"),
                        None,
                        1,
                        false,
                    );
                    return Err(err);
                }
            };
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_host_exec_plan = Some(plan);
        }
        let mut resolved_cross_org_peer: Option<(String, String)> = None;

        if matches!(tool_name, "ipc_send" | "ipc_request") {
            if let Some(raw_to) = args.get("to_agent").and_then(|v| v.as_str()) {
                let cleaned = raw_to.strip_prefix("agent:").unwrap_or(raw_to);
                let all_peers = self.ipc.list_all_peers().await.unwrap_or_default();
                let caller_is_workstation_peer = all_peers.iter().any(|p| {
                    p.org_id == identity.org_id
                        && p.agent_id == identity.agent_id
                        && p.pid.is_some()
                });
                let is_verified_workstation_pair = |org: &str, agent: &str| -> bool {
                    caller_is_workstation_peer
                        && all_peers
                            .iter()
                            .any(|p| p.org_id == org && p.agent_id == agent && p.pid.is_some())
                };
                if let Some((org_part, agent_part)) = cleaned.split_once('/') {
                    target_org = org_part.to_string();
                    resolved_cross_org_peer =
                        Some((org_part.to_string(), agent_part.to_string()));
                    if is_verified_workstation_pair(org_part, agent_part) {
                        if let Some(obj) = audit_metadata.as_object_mut() {
                            obj.insert("workstation_peer_verified".to_string(), json!(true));
                        }
                    }
                } else if args.get("target_org_id").is_none() {
                    // If not found in current org, auto-resolve unique peer ID from global peer list!
                    let same_org_peers = self
                        .ipc
                        .list_peers(&identity.org_id)
                        .await
                        .unwrap_or_default();
                    if !same_org_peers.iter().any(|p| p.agent_id == cleaned) {
                        let matches: Vec<_> = all_peers
                            .iter()
                            .filter(|p| p.online && p.agent_id == cleaned && p.pid.is_some())
                            .collect();
                        if caller_is_workstation_peer && matches.len() == 1 {
                            let matched = matches[0];
                            target_org = matched.org_id.clone();
                            resolved_cross_org_peer =
                                Some((matched.org_id.clone(), matched.agent_id.clone()));
                            if let Some(obj) = audit_metadata.as_object_mut() {
                                obj.insert("workstation_peer_verified".to_string(), json!(true));
                            }
                        }
                    }
                } else if args.get("scope").and_then(|v| v.as_str()) == Some("global")
                    && is_verified_workstation_pair(&target_org, cleaned)
                {
                    resolved_cross_org_peer =
                        Some((target_org.clone(), cleaned.to_string()));
                    if let Some(obj) = audit_metadata.as_object_mut() {
                        obj.insert("workstation_peer_verified".to_string(), json!(true));
                    }
                }
            }
        }

        let mut policy_matched_rule: Option<String> = None;
        if !matches!(
            tool_name,
            "policy_grant_lease" | "policy_approve_escalation" | "policy_list_escalations"
        ) {
            match self
                .authorize_and_audit(
                    identity,
                    tool_name,
                    &target_org,
                    &target_resource,
                    audit_metadata,
                )
                .await?
            {
                PolicyDecision::Allow { matched_rule } => {
                    policy_matched_rule = Some(matched_rule);
                }
                PolicyDecision::Ask {
                    escalation_id,
                    reason,
                    suggested_lease_scope,
                } => {
                    if matches!(
                        tool_name,
                        "workspace_commit"
                            | "fs_export_file"
                            | "fs_import_file"
                            | "workspace_git"
                            | "github_pr_create"
                            | "github_comment_create"
                            | "github_pr_merge"
                            | "pkg_install"
                            | "host_exec"
                    ) {
                        if let Some(ref diffs) = pre_commit_diffs {
                            let diff_dir = self.runtime_data_root.join("escalation_diffs");
                            let _ = tokio::fs::create_dir_all(&diff_dir).await;
                            let _ = aos_core::session::write_json_pretty_atomic(
                                &diff_dir.join(format!("{}.json", escalation_id)),
                                diffs,
                            )
                            .await;
                        }
                    }
                    let mut ask_payload = json!({
                        "status": "approval_required",
                        "escalation_id": escalation_id,
                        "approval_ticket": self.paas.issue_escalation_ticket(&identity.org_id, &escalation_id, 1_800_000).await,
                        "reason": reason,
                        "suggested_lease_scope": suggested_lease_scope,
                        "evidence_hash": pre_commit_evidence_hash,
                        "hint": format!(
                            "Approve in the auto-opened Web Approval Console (/approve?id={0}&org={1} or /dashboard) where you can inspect the Unified Diff and click Approve Once (SHA-256 pinned) or Approve 1h, or in Cloud Mode provide your 6-digit Authenticator TOTP code in chat and pass `totp` on retry (escalation: {0}). Agents cannot self-approve without human action.",
                            escalation_id,
                            identity.org_id
                        )
                    });
                    if let Some((_, _, _, _, ref uri, _, _)) = pre_export_plan {
                        if let Some(obj) = ask_payload.as_object_mut() {
                            obj.insert("artifact_uri".to_string(), json!(uri));
                        }
                    }
                    return Ok(ask_payload);
                }
                PolicyDecision::Deny { reason } => {
                    match tool_name {
                        "egress_http_request" => self.record_kernel_friction(
                            aos_core::friction::FrictionCategory::EgressDenied,
                            aos_core::friction::CmdBucket::Egress,
                            Some("mcp_gateway"),
                            None,
                            1,
                            false,
                        ),
                        "pkg_install" => self.record_kernel_friction(
                            aos_core::friction::FrictionCategory::PkgInstallFailed,
                            aos_core::friction::CmdBucket::PkgInstall,
                            Some("mcp_gateway"),
                            None,
                            1,
                            false,
                        ),
                        "host_exec" => self.record_kernel_friction(
                            aos_core::friction::FrictionCategory::HostExecDenied,
                            aos_core::friction::CmdBucket::HostExec,
                            Some("mcp_gateway"),
                            None,
                            1,
                            false,
                        ),
                        _ => {}
                    }
                    bail!("Policy Denied syscall '{}': {}", tool_name, reason);
                }
            }
        }

        match tool_name {
            // ----------------------------------------------------------------
            // 1. Transactional CoW File System Tools (Zero-Prompt in Sandbox)
            // ----------------------------------------------------------------
            "fs_read" => {
                let rel_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path'")?;
                let encoding = args
                    .get("encoding")
                    .and_then(|v| v.as_str())
                    .unwrap_or("utf8");
                let (scope, clean, full_path) = resolve_fs_path_for_read(
                    env.workspace.shadow_root(),
                    env.workspace.host_source_root(),
                    &env.sandbox.config().agent_home_dir,
                    rel_path,
                )?;
                let workspace_mode = match scope {
                    FsScope::Shadow => "cow_shadow",
                    FsScope::TmpDir => "agent_tmp",
                };
                let raw_bytes = tokio::fs::read(&full_path).await?;
                match encoding {
                    "base64" => Ok(json!({
                        "path": clean,
                        "encoding": "base64",
                        "size_bytes": raw_bytes.len(),
                        "content_base64": base64::engine::general_purpose::STANDARD.encode(&raw_bytes),
                        "workspace_mode": workspace_mode
                    })),
                    "utf8" => match String::from_utf8(raw_bytes) {
                        Ok(content) => Ok(json!({
                            "path": clean,
                            "content": content,
                            "workspace_mode": workspace_mode
                        })),
                        Err(e) => {
                            let size = e.into_bytes().len();
                            bail!(
                                "File '{}' is binary ({} bytes); inspect or process it with proc_exec, read small assets with encoding='base64', or export it via fs_export_file",
                                clean,
                                size
                            );
                        }
                    },
                    other => bail!(
                        "Unsupported fs_read encoding '{}'; expected 'utf8' or 'base64'",
                        other
                    ),
                }
            }

            "fs_write" => {
                let rel_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path'")?;
                let content = args
                    .get("content")
                    .and_then(|v| v.as_str())
                    .context("Missing 'content'")?;
                let encoding = args
                    .get("encoding")
                    .and_then(|v| v.as_str())
                    .unwrap_or("utf8");
                let raw_bytes = match encoding {
                    "utf8" => content.as_bytes().to_vec(),
                    "base64" => base64::engine::general_purpose::STANDARD
                        .decode(content.trim())
                        .context("Invalid base64 'content' in fs_write")?,
                    other => bail!(
                        "Unsupported fs_write encoding '{}'; expected 'utf8' or 'base64'",
                        other
                    ),
                };
                let byte_len = raw_bytes.len();
                let (scope, clean, _full_path) = resolve_fs_path_for_write(
                    env.workspace.shadow_root(),
                    &env.sandbox.config().agent_home_dir,
                    rel_path,
                )?;
                let (base_root, rel_in_base) = anchored_root_and_rel(
                    scope,
                    &clean,
                    env.workspace.shadow_root(),
                    &env.sandbox.config().agent_home_dir,
                )?;
                tokio::task::spawn_blocking(move || {
                    aos_core::security::write_file_no_symlink_under_root(
                        &base_root,
                        &rel_in_base,
                        &raw_bytes,
                    )
                })
                .await
                .context("fs_write task failed")??;
                let status = match scope {
                    FsScope::Shadow => "written_to_cow_shadow",
                    FsScope::TmpDir => "written_to_agent_tmp",
                };
                Ok(json!({
                    "status": status,
                    "path": clean,
                    "bytes": byte_len,
                    "encoding": encoding,
                    "host_modified": false
                }))
            }

            "fs_export_file" => {
                let (canon_dst, bytes, mime_type, sha256, artifact_uri, evidence_hash, cas_blob) =
                    pre_export_plan.context("Missing pre-staged fs_export_file plan")?;
                let size_bytes = bytes.len();
                export_file_atomic_from_cas_or_bytes(cas_blob, bytes, canon_dst.clone()).await?;
                Ok(json!({
                    "status": "exported_to_host",
                    "dst_host_path": canon_dst,
                    "size_bytes": size_bytes,
                    "content_type": mime_type,
                    "sha256": sha256,
                    "artifact_uri": artifact_uri,
                    "evidence_hash": evidence_hash,
                }))
            }

            "fs_import_file" => {
                let plan = pre_import_plan.context("Missing pre-staged fs_import_file plan")?;
                let sym = std::fs::symlink_metadata(&plan.canon_src)
                    .with_context(|| format!("Host source '{}' disappeared", plan.canon_src.display()))?;
                if sym.file_type().is_symlink() || !sym.is_file() {
                    bail!(
                        "Refusing import: host source '{}' is no longer a regular file",
                        plan.canon_src.display()
                    );
                }
                let bytes = tokio::fs::read(&plan.canon_src).await?;
                let actual_sha = hex::encode(Sha256::digest(&bytes));
                if actual_sha != plan.src_sha256 {
                    bail!(
                        "TOCTOU integrity error: host source file '{}' changed after approval (expected sha256:{}, got sha256:{})",
                        plan.canon_src.display(),
                        plan.src_sha256,
                        actual_sha
                    );
                }
                if let Some(parent) = plan.dst_full_path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let byte_len = bytes.len();
                aos_core::session::write_bytes_atomic_synced_async(&plan.dst_full_path, bytes).await?;
                Ok(json!({
                    "status": "imported_from_host",
                    "src_host_path": plan.canon_src,
                    "import_to": plan.import_to,
                    "dst_path": plan.clean_dst_rel,
                    "dst_full_path": plan.dst_full_path,
                    "size_bytes": byte_len,
                    "sha256": plan.src_sha256,
                    "evidence_hash": plan.evidence_hash,
                }))
            }

            "workspace_switch" => {
                let (canon_target, new_org_id, next_umbrella) =
                    pre_switch_plan.context("Missing pre-validated workspace_switch plan")?;
                let prev_workspace = env.workspace.host_source_root().to_path_buf();
                let prev_uncommitted_count =
                    env.workspace.diff(None).await.map(|d| d.len()).unwrap_or(0);
                let new_identity = AgentIdentity::new(
                    new_org_id,
                    identity.agent_id.clone(),
                    identity.role.clone(),
                );
                let new_env = self
                    .ensure_agent_environment(
                        new_identity.clone(),
                        &canon_target,
                        IsolationTier::NativeOsSandbox,
                        vec!["*".to_string()],
                    )
                    .await?;
                let _ = aos_core::session::bind_session_workspace(
                    &self.runtime_data_root,
                    "auto",
                    None,
                    &canon_target,
                    next_umbrella.as_deref(),
                    true,
                );
                Ok(json!({
                    "status": "workspace_switched",
                    "org_id": new_identity.org_id,
                    "agent_id": new_identity.agent_id,
                    "workspace_id": aos_core::session::workspace_id_for_path(&canon_target),
                    "host_source_root": canon_target,
                    "shadow_root": new_env.workspace.shadow_root(),
                    "tmp_dir": ensure_agent_tmp_dir_no_symlink(&new_env.sandbox.config().agent_home_dir)
                        .unwrap_or_else(|_| new_env.sandbox.config().agent_home_dir.join("tmp")),
                    "previous_workspace": prev_workspace,
                    "previous_uncommitted_count": prev_uncommitted_count,
                    "umbrella_root": next_umbrella,
                }))
            }

            "fs_edit" => match Self::execute_fs_edit(&env, &args).await {
                Ok(res) => {
                    self.reset_tool_streak_on_success(
                        &identity.agent_id,
                        "fs_edit",
                        aos_core::friction::CmdBucket::FsEdit,
                    )
                    .await;
                    Ok(res)
                }
                Err(err) => {
                    let streak = self
                        .record_tool_streak_failure(
                            &identity.agent_id,
                            "fs_edit",
                            aos_core::friction::FrictionCategory::EditMismatch,
                            aos_core::friction::CmdBucket::FsEdit,
                        )
                        .await;
                    if streak >= 3 {
                        bail!(
                            "{err}\n[aegis_hint (loop_thrash)]: Detected {streak} consecutive failing `fs_edit` attempts. Re-read the target file with `fs_read` before retrying `fs_edit`."
                        );
                    }
                    Err(err)
                }
            },

            "fs_delete" => {
                let rel_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path'")?;
                let (scope, clean, _full_path) = resolve_fs_path_for_write(
                    env.workspace.shadow_root(),
                    &env.sandbox.config().agent_home_dir,
                    rel_path,
                )?;
                let (base_root, rel_in_base) = anchored_root_and_rel(
                    scope,
                    &clean,
                    env.workspace.shadow_root(),
                    &env.sandbox.config().agent_home_dir,
                )?;
                tokio::task::spawn_blocking(move || {
                    aos_core::security::remove_file_no_symlink_under_root(&base_root, &rel_in_base)
                })
                .await
                .context("fs_delete task failed")??;
                let status = match scope {
                    FsScope::Shadow => "deleted_in_cow_shadow",
                    FsScope::TmpDir => "deleted_in_agent_tmp",
                };
                Ok(json!({
                    "status": status,
                    "path": clean,
                    "host_modified": false
                }))
            }

            "fs_glob" | "fs_list" => {
                let filter = args.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                let trimmed_filter = filter.trim();
                let tmp_sub_filter = if trimmed_filter == "$TMPDIR" || trimmed_filter == "${TMPDIR}"
                {
                    Some("")
                } else {
                    strip_tmpdir_prefix(trimmed_filter)
                };
                if let Some(sub_filter) = tmp_sub_filter {
                    let tmp_root =
                        ensure_agent_tmp_dir_no_symlink(&env.sandbox.config().agent_home_dir)?;
                    let files = CoWWorkspace::collect_files(&tmp_root).await?;
                    let matched: Vec<String> = files
                        .into_iter()
                        .map(|(rel, _)| rel)
                        .filter(|rel| sub_filter.is_empty() || rel.contains(sub_filter))
                        .map(|rel| format!("$TMPDIR/{rel}"))
                        .collect();
                    return Ok(json!({
                        "tmp_dir": tmp_root,
                        "files_count": matched.len(),
                        "files": matched
                    }));
                }
                let files = CoWWorkspace::collect_files(env.workspace.shadow_root()).await?;
                let matched: Vec<String> = files
                    .into_iter()
                    .map(|(rel, _)| rel)
                    .filter(|rel| filter.is_empty() || rel.contains(filter))
                    .collect();
                let diffs = env.workspace.diff(None).await?;
                Ok(json!({
                    "shadow_root": env.workspace.shadow_root(),
                    "files_count": matched.len(),
                    "files": matched,
                    "uncommitted_changes_count": diffs.len(),
                    "uncommitted_changes": diffs
                }))
            }

            "workspace_status" => {
                #[derive(Serialize)]
                struct SlimFileDiffEntry<'a> {
                    relative_path: &'a str,
                    change_type: &'a DiffChangeType,
                    old_size: Option<u64>,
                    new_size: Option<u64>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    old_sha256: Option<&'a str>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    new_sha256: Option<&'a str>,
                }

                let include_diffs = args
                    .get("include_diffs")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !env.workspace.shadow_root().exists() {
                    let _ = self.ensure_org_vault(&identity.org_id).await;
                }
                let refresh = env.workspace.refresh_from_host().await?;
                let diffs = env.workspace.diff(None).await?;
                let snapshots = env.workspace.list_snapshots().await?;
                let unread_ipc = self
                    .ipc
                    .recv_inbox(&identity.org_id, &identity.agent_id, true, 50)
                    .await?;
                let all_escalations = self.policy.list_escalations(&identity.org_id).await?;
                let total_escalations_count = all_escalations.len();
                let pending_escalations: Vec<_> = all_escalations
                    .into_iter()
                    .filter(|e| e.status == aos_core::EscalationStatus::Pending)
                    .collect();
                let (claims, _) = self.load_claims(&identity.org_id).await.unwrap_or_default();
                let vault_status = self.vault.status_org(&identity.org_id).ok();
                let orphaned = self
                    .detect_orphaned_shadows(identity, env.workspace.host_source_root())
                    .await;
                let umbrella_root = aos_core::session::resolve_session_workspace_binding(
                    &self.runtime_data_root,
                )
                .and_then(|(_, u, _)| u);
                let uncommitted_changes = if include_diffs {
                    serde_json::to_value(&diffs)?
                } else {
                    let slim: Vec<SlimFileDiffEntry<'_>> = diffs
                        .iter()
                        .map(|d| SlimFileDiffEntry {
                            relative_path: &d.relative_path,
                            change_type: &d.change_type,
                            old_size: d.old_size,
                            new_size: d.new_size,
                            old_sha256: d.old_sha256.as_deref(),
                            new_sha256: d.new_sha256.as_deref(),
                        })
                        .collect();
                    serde_json::to_value(slim)?
                };
                let tmp_dir = ensure_agent_tmp_dir_no_symlink(&env.sandbox.config().agent_home_dir)
                    .unwrap_or_else(|_| env.sandbox.config().agent_home_dir.join("tmp"));
                Ok(json!({
                    "identity": identity,
                    "workspace_id": aos_core::session::workspace_id_for_path(env.workspace.host_source_root()),
                    "shadow_root": env.workspace.shadow_root(),
                    "tmp_dir": tmp_dir,
                    "host_source_root": env.workspace.host_source_root(),
                    "umbrella_root": umbrella_root,
                    "child_repos": discover_child_git_repos_sync(env.workspace.host_source_root()),
                    "vault": vault_status,
                    "auto_refresh": refresh,
                    "uncommitted_changes_count": diffs.len(),
                    "uncommitted_changes": uncommitted_changes,
                    "recoverable_orphaned_shadows": orphaned,
                    "active_claims": claims,
                    "snapshots": snapshots,
                    "unread_ipc_messages_count": unread_ipc.len(),
                    "pending_escalations": pending_escalations,
                    "total_escalations_count": total_escalations_count
                }))
            }

            "workspace_sync" => {
                let orphan_recovery = if let Some(from_agent_id) = args
                    .get("adopt_orphaned_agent")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    Some(
                        self.recover_orphaned_agent_shadow(identity, from_agent_id)
                            .await?,
                    )
                } else {
                    None
                };
                let refresh = env.workspace.refresh_from_host().await?;
                let diffs = env.workspace.diff(None).await?;
                let (claims, _) = self.load_claims(&identity.org_id).await.unwrap_or_default();
                Ok(json!({
                    "status": if refresh.conflicts.is_empty() { "synced" } else { "conflicts_detected" },
                    "orphan_recovery": orphan_recovery,
                    "refresh_report": refresh,
                    "uncommitted_changes_count": diffs.len(),
                    "uncommitted_changes": diffs,
                    "active_claims": claims
                }))
            }

            "workspace_snapshot" => {
                let label = args
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("manual-checkpoint");
                let snap = env.workspace.create_snapshot(label).await?;
                Ok(serde_json::to_value(snap)?)
            }

            "workspace_diff" => {
                let snap_id = args.get("snapshot_id").and_then(|v| v.as_str());
                let refresh = if snap_id.is_none() {
                    Some(env.workspace.refresh_from_host().await?)
                } else {
                    None
                };
                let diffs = env.workspace.diff(snap_id).await?;
                Ok(json!({
                    "base": snap_id.unwrap_or("host_source"),
                    "auto_refresh": refresh,
                    "changes": diffs
                }))
            }

            "workspace_rollback" => {
                let snap_id = args
                    .get("snapshot_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'snapshot_id'")?;
                env.workspace.rollback(snap_id).await?;
                Ok(json!({
                    "status": "rolled_back",
                    "snapshot_id": snap_id
                }))
            }

            "workspace_commit" => {
                let filter_paths: Option<Vec<String>> = args
                    .get("paths")
                    .and_then(|v| serde_json::from_value(v.clone()).ok());
                let overwrite_binaries = args
                    .get("overwrite_binaries")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let release_claims = args
                    .get("release_claims")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let skip_verify = args
                    .get("skip_verify")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let host_verify_cfg: Option<serde_json::Value> = std::fs::read(
                    env.workspace.host_source_root().join(".aegis/verify.json"),
                )
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok());
                let verify_cmd = if skip_verify {
                    None
                } else {
                    args.get("verify_cmd")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .or_else(|| {
                            std::env::var("AOS_VERIFY_CMD")
                                .ok()
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                        })
                        .or_else(|| {
                            host_verify_cfg
                                .as_ref()
                                .and_then(|cfg| cfg.get("verify_cmd"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                        })
                };
                let verify_timeout_ms = args
                    .get("verify_timeout_ms")
                    .and_then(|v| v.as_u64())
                    .or_else(|| {
                        host_verify_cfg
                            .as_ref()
                            .and_then(|cfg| cfg.get("timeout_ms"))
                            .and_then(|v| v.as_u64())
                    })
                    .or(Some(30_000));
                let pre_verify_epoch = env.workspace.read_host_commit_epoch();
                // Refresh from host first so untouched peer-modified files (including binaries) fast-forward cleanly.
                let mut refresh = env.workspace.refresh_from_host().await?;
                // Coordination guard: refuse to land files that a live peer has claimed.
                let mut touched = env.workspace.changed_since_baseline().await?;
                if let Some(ref allow) = filter_paths {
                    touched.retain(|p| allow.contains(p));
                }
                if let Some(msg) = self.claim_conflict_for_paths(identity, &touched).await? {
                    bail!("{}", msg);
                }
                // Optional Pre-Commit Semantic Verification Gate: after `refresh_from_host` merges
                // disjoint peer changes into `shadow_root`, run `verify_cmd` inside the agent's OS
                // kernel sandbox before `commit_to_host_with_options` touches any host file.
                if refresh.conflicts.is_empty() {
                    if let Some(ref cmd) = verify_cmd {
                        let verify_out = env
                            .sandbox
                            .exec(ExecSpec {
                                command: "sh".to_string(),
                                args: vec!["-c".to_string(), cmd.clone()],
                                cwd: Some(env.workspace.shadow_root().to_path_buf()),
                                env: HashMap::new(),
                                timeout_ms: verify_timeout_ms,
                                background: false,
                            })
                            .await?;
                        if verify_out.exit_code != Some(0) {
                            let diag = if !verify_out.stderr.trim().is_empty() {
                                verify_out.stderr.trim()
                            } else {
                                verify_out.stdout.trim()
                            };
                            bail!(
                                "Pre-commit verification gate '{}' failed in shadow workspace (exit code {:?}; host repository untouched): {}",
                                cmd,
                                verify_out.exit_code,
                                diag
                            );
                        }
                    }
                }
                // Serialize host commits across processes and re-verify if another agent committed while
                // our pre-commit verification was running (Always-Green Trunk guarantee).
                let _host_commit_lock = env.workspace.acquire_host_commit_lock().await?;
                let mut epoch_reverified = false;
                if env.workspace.read_host_commit_epoch() != pre_verify_epoch {
                    let retry_refresh = env.workspace.refresh_from_host().await?;
                    if !retry_refresh.conflicts.is_empty() {
                        bail!(
                            "3-Way Merge Conflict detected against concurrent peer commit on {:?}: {:?}",
                            retry_refresh.conflicts,
                            retry_refresh.conflict_details
                        );
                    }
                    refresh.fast_forwarded.extend(retry_refresh.fast_forwarded);
                    refresh.merged.extend(retry_refresh.merged);
                    refresh.added_from_host.extend(retry_refresh.added_from_host);
                    refresh
                        .removed_from_host
                        .extend(retry_refresh.removed_from_host);
                    let mut retry_touched = env.workspace.changed_since_baseline().await?;
                    if let Some(ref allow) = filter_paths {
                        retry_touched.retain(|p| allow.contains(p));
                    }
                    if let Some(msg) = self
                        .claim_conflict_for_paths(identity, &retry_touched)
                        .await?
                    {
                        bail!("{}", msg);
                    }
                    if let Some(ref cmd) = verify_cmd {
                        let verify_out = env
                            .sandbox
                            .exec(ExecSpec {
                                command: "sh".to_string(),
                                args: vec!["-c".to_string(), cmd.clone()],
                                cwd: Some(env.workspace.shadow_root().to_path_buf()),
                                env: HashMap::new(),
                                timeout_ms: verify_timeout_ms,
                                background: false,
                            })
                            .await?;
                        if verify_out.exit_code != Some(0) {
                            let diag = if !verify_out.stderr.trim().is_empty() {
                                verify_out.stderr.trim()
                            } else {
                                verify_out.stdout.trim()
                            };
                            bail!(
                                "Pre-commit verification gate '{}' failed after concurrent peer commit rebase (exit code {:?}; host repository untouched): {}",
                                cmd,
                                verify_out.exit_code,
                                diag
                            );
                        }
                        epoch_reverified = true;
                    }
                }
                let base_dir = env
                    .workspace
                    .shadow_root()
                    .parent()
                    .map(|p| p.join("baseline_snapshot"))
                    .filter(|p| p.exists())
                    .unwrap_or_else(|| env.workspace.host_source_root().to_path_buf());
                let frozen_dir = env
                    .workspace
                    .shadow_root()
                    .parent()
                    .unwrap_or_else(|| env.workspace.shadow_root())
                    .join(format!("commit_frozen_{}", &Uuid::new_v4().to_string()[..8]));
                let commit_res: anyhow::Result<Vec<String>> = async {
                    CoWWorkspace::cow_sync_dir(env.workspace.shadow_root(), &frozen_dir).await?;
                    let frozen_diffs = CoWWorkspace::diff_dirs(
                        &base_dir,
                        &frozen_dir,
                        filter_paths.as_deref(),
                    )
                    .await
                    .unwrap_or_default();
                    let frozen_paths: Vec<String> = frozen_diffs
                        .iter()
                        .map(|d| d.relative_path.clone())
                        .collect();
                    if let Some(msg) = self.claim_conflict_for_paths(identity, &frozen_paths).await? {
                        bail!("{}", msg);
                    }
                    let pre_paths: std::collections::HashSet<&str> = pre_commit_diffs
                        .as_ref()
                        .map(|v| v.iter().map(|d| d.relative_path.as_str()).collect())
                        .unwrap_or_default();
                    let mut rebased_paths: std::collections::HashSet<&str> =
                        std::collections::HashSet::new();
                    for p in refresh
                        .fast_forwarded
                        .iter()
                        .chain(refresh.merged.iter())
                        .chain(refresh.added_from_host.iter())
                        .chain(refresh.removed_from_host.iter())
                    {
                        rebased_paths.insert(p.trim_start_matches('/'));
                    }
                    if let Some(bad) = frozen_diffs.iter().find(|d| {
                        let rel = d.relative_path.trim_start_matches('/');
                        AegisPolicyKernel::is_commit_poisoning_path(rel)
                            && !pre_paths.contains(d.relative_path.as_str())
                    }) {
                        bail!(
                            "Refusing commit: sensitive path '{}' was added to shadow workspace after authorization (TOCTOU guard)",
                            bad.relative_path
                        );
                    }
                    let sha_pinned = policy_matched_rule
                        .as_deref()
                        .is_some_and(|r| r.contains("#sha256:"));
                    if sha_pinned || (verify_cmd.is_none() && rebased_paths.is_empty() && !epoch_reverified) {
                        if let Some(ref expected_hash) = pre_commit_evidence_hash {
                            let (_, recomputed_hash) = aos_core::compute_diff_evidence(
                                &frozen_diffs,
                                overwrite_binaries,
                                skip_verify,
                            );
                            if &recomputed_hash != expected_hash {
                                bail!(
                                    "workspace_commit aborted: shadow workspace evidence drifted after approval (expected {}, got {})",
                                    expected_hash,
                                    recomputed_hash
                                );
                            }
                        }
                    } else if verify_cmd.is_none() {
                        if let Some(ref pre_diffs) = pre_commit_diffs {
                            let pre_map: std::collections::HashMap<&str, Option<&str>> = pre_diffs
                                .iter()
                                .map(|d| (d.relative_path.trim_start_matches('/'), d.new_sha256.as_deref()))
                                .collect();
                            for d in &frozen_diffs {
                                let rel = d.relative_path.trim_start_matches('/');
                                if rebased_paths.contains(rel) {
                                    continue;
                                }
                                match pre_map.get(rel) {
                                    Some(expected_sha) if *expected_sha == d.new_sha256.as_deref() => {}
                                    _ => bail!(
                                        "workspace_commit aborted: unapproved post-authorization modification on '{}'",
                                        rel
                                    ),
                                }
                            }
                        }
                    }
                    env.workspace
                        .commit_frozen_to_host_with_options(
                            &frozen_dir,
                            filter_paths,
                            overwrite_binaries,
                        )
                        .await
                }
                .await;
                let _ = tokio::fs::remove_dir_all(&frozen_dir).await;
                let committed = commit_res?;
                drop(_host_commit_lock);

                let released_claims = if release_claims && !committed.is_empty() {
                    self.release_claims_matching_committed_paths(identity, &committed)
                        .await
                } else {
                    Vec::new()
                };
                let include_source_files = args
                    .get("include_source_files")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let host_root = env.workspace.host_source_root();
                let mut committed_source_files = Vec::new();
                if include_source_files {
                    for rel in &committed {
                        let clean = rel.trim_start_matches('/').to_string();
                        let full = host_root.join(&clean);
                        if !full.exists() {
                            committed_source_files.push(paas::SourceFileEntry {
                                path: clean,
                                content: String::new(),
                                deleted: true,
                            });
                        } else if let Ok(raw) = tokio::fs::read(&full).await {
                            if !raw.iter().take(8000).any(|&b| b == 0) {
                                if let Ok(content) = String::from_utf8(raw) {
                                    committed_source_files.push(paas::SourceFileEntry {
                                        path: clean,
                                        content,
                                        deleted: false,
                                    });
                                }
                            }
                        }
                    }
                }
                let short_evidence = pre_commit_evidence_hash
                    .as_deref()
                    .map(|h| h.strip_prefix("sha256:").unwrap_or(h))
                    .map(|h| &h[..h.len().min(12)])
                    .unwrap_or("cow-3way");
                let git_trailer = format!(
                    "Aegis-OS-Verified: principal={}/{} files={} evidence=sha256:{} verify={}",
                    identity.org_id,
                    identity.agent_id,
                    committed.len(),
                    short_evidence,
                    if verify_cmd.is_some() { "passed" } else { "cow-3way" }
                );
                let pr_markdown_badge = format!(
                    "[![Verified by Aegis OS](https://img.shields.io/badge/Aegis_OS-CoW_Verified_%28{}_files%29-0A7D52)](https://github.com/heurion-org/aegis-os)\n\
                     > 🛡️ **Transactional Agent Commit (`{}/{}`)** · `{}` file(s) merged via 4-Tier CoW · Evidence: `sha256:{}` · [Run Agents Safely with Aegis OS](https://github.com/heurion-org/aegis-os)",
                    committed.len(),
                    identity.org_id,
                    identity.agent_id,
                    committed.len(),
                    short_evidence
                );
                let mut payload = json!({
                    "status": "committed_to_host",
                    "host_root": host_root,
                    "auto_refresh": refresh,
                    "verification_passed": verify_cmd.is_some(),
                    "epoch_reverified": epoch_reverified,
                    "committed_files_count": committed.len(),
                    "committed_files": committed,
                    "released_claims": released_claims,
                    "audit_receipt": {
                        "evidence_hash": pre_commit_evidence_hash,
                        "git_trailer": git_trailer,
                        "pr_markdown_badge": pr_markdown_badge,
                    }
                });
                if include_source_files {
                    if let Some(obj) = payload.as_object_mut() {
                        obj.insert(
                            "committed_source_files".to_string(),
                            json!(committed_source_files),
                        );
                    }
                }
                Ok(payload)
            }

            "workspace_export_pr" => {
                let branch_name = args
                    .get("branch_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let commit_title = args
                    .get("commit_title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let workspace_id = args.get("workspace_id").and_then(|v| v.as_str());
                let overwrite_binaries = args
                    .get("overwrite_binaries")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.paas
                    .export_workspace_pr(
                        self,
                        identity,
                        workspace_id,
                        branch_name,
                        commit_title,
                        overwrite_binaries,
                    )
                    .await
            }

            "workspace_git_inspect" => execute_workspace_git_inspect(&env, &args).await,

            "workspace_git" => {
                let plan = pre_git_plan.context("Missing pre-validated workspace_git plan")?;
                execute_workspace_git_plan(self, &env, plan, identity).await
            }

            "github_ci_inspect" => {
                execute_github_ci_inspect(env.workspace.host_source_root(), &args).await
            }

            "github_ci_rerun" => {
                let plan = pre_ci_rerun_plan.context("Missing pre-validated github_ci_rerun plan")?;
                execute_github_ci_rerun(plan).await
            }

            "github_pr_inspect" => {
                execute_github_pr_inspect(env.workspace.host_source_root(), &args).await
            }

            "github_issue_inspect" => {
                execute_github_issue_inspect(env.workspace.host_source_root(), &args).await
            }

            "github_pr_create" => {
                let plan = pre_pr_create_plan.context("Missing pre-validated github_pr_create plan")?;
                execute_github_pr_create(plan).await
            }

            "github_comment_create" => {
                let plan = pre_comment_create_plan
                    .context("Missing pre-validated github_comment_create plan")?;
                execute_github_comment_create(plan).await
            }

            "github_pr_merge" => {
                let plan = pre_pr_merge_plan
                    .context("Missing pre-validated github_pr_merge plan")?;
                execute_github_pr_merge(plan).await
            }

            "pkg_install" => {
                let plan = pre_pkg_install_plan.context("Missing pre-validated pkg_install plan")?;
                match execute_pkg_install(identity, plan).await {
                    Ok(val) => {
                        if val.get("status").and_then(|v| v.as_str()) == Some("pkg_install_failed") {
                            let exit_code = val
                                .get("exit_code")
                                .and_then(|v| v.as_i64())
                                .map(|c| c as i32);
                            self.record_kernel_friction(
                                aos_core::friction::FrictionCategory::PkgInstallFailed,
                                aos_core::friction::CmdBucket::PkgInstall,
                                Some("mcp_gateway"),
                                exit_code,
                                1,
                                false,
                            );
                        }
                        Ok(val)
                    }
                    Err(err) => {
                        self.record_kernel_friction(
                            aos_core::friction::FrictionCategory::PkgInstallFailed,
                            aos_core::friction::CmdBucket::PkgInstall,
                            Some("mcp_gateway"),
                            None,
                            1,
                            false,
                        );
                        Err(err)
                    }
                }
            }

            "host_exec" => {
                let plan = pre_host_exec_plan.context("Missing pre-validated host_exec plan")?;
                match self.execute_host_exec(&env, plan).await {
                    Ok(val) => Ok(val),
                    Err(err) => {
                        self.record_kernel_friction(
                            aos_core::friction::FrictionCategory::HostExecDenied,
                            aos_core::friction::CmdBucket::HostExec,
                            Some("mcp_gateway"),
                            None,
                            1,
                            false,
                        );
                        Err(err)
                    }
                }
            }

            // ----------------------------------------------------------------
            // 2. Sandboxed Command Execution Tools (Zero-Prompt in Sandbox)
            // ----------------------------------------------------------------
            "proc_exec" => {
                if let Some(poll_pid) = args.get("poll_pid").and_then(|v| v.as_u64()) {
                    let pid = poll_pid as u32;
                    let bg_dir = env.sandbox.config().agent_home_dir.join("bg_jobs");
                    let out_path = bg_dir.join(format!("{}.stdout.log", pid));
                    let err_path = bg_dir.join(format!("{}.stderr.log", pid));
                    let exit_path = bg_dir.join(format!("{}.exit", pid));
                    let out_bytes = tokio::fs::read(&out_path).await.unwrap_or_default();
                    let err_bytes = tokio::fs::read(&err_path).await.unwrap_or_default();
                    let tail_bytes = args
                        .get("tail_bytes")
                        .and_then(|v| v.as_u64())
                        .map(|n| usize::try_from(n).unwrap_or(usize::MAX).min(262_144))
                        .unwrap_or(32_768);
                    let stdout_offset = args
                        .get("stdout_offset")
                        .and_then(|v| v.as_u64())
                        .map(|n| usize::try_from(n).unwrap_or(usize::MAX));
                    let stderr_offset = args
                        .get("stderr_offset")
                        .and_then(|v| v.as_u64())
                        .map(|n| usize::try_from(n).unwrap_or(usize::MAX));
                    let (stdout, stdout_total_bytes, stdout_truncated, stdout_offset_returned) =
                        Self::slice_poll_log_bytes(&out_bytes, stdout_offset, tail_bytes);
                    let (stderr, stderr_total_bytes, stderr_truncated, stderr_offset_returned) =
                        Self::slice_poll_log_bytes(&err_bytes, stderr_offset, tail_bytes);
                    let recorded_exit = tokio::fs::read_to_string(&exit_path)
                        .await
                        .ok()
                        .and_then(|s| s.trim().parse::<i32>().ok());
                    #[cfg(unix)]
                    let running = recorded_exit.is_none() && {
                        extern "C" {
                            fn kill(pid: i32, sig: i32) -> i32;
                        }
                        unsafe { kill(pid as i32, 0) == 0 }
                    };
                    #[cfg(not(unix))]
                    let running = recorded_exit.is_none();
                    // No `.exit` record while the pid is gone means the job outlived the gateway that
                    // started it (or is being reaped right now): its status is unknown, not success.
                    let exit_status = match (recorded_exit, running) {
                        (Some(_), _) => "exited",
                        (None, true) => "running",
                        (None, false) => "unknown",
                    };
                    return Ok(json!({
                        "pid": pid,
                        "running": running,
                        "exit_code": recorded_exit,
                        "exit_status": exit_status,
                        "stdout": stdout,
                        "stderr": stderr,
                        "stdout_total_bytes": stdout_total_bytes,
                        "stderr_total_bytes": stderr_total_bytes,
                        "stdout_truncated": stdout_truncated,
                        "stderr_truncated": stderr_truncated,
                        "stdout_offset_returned": stdout_offset_returned,
                        "stderr_offset_returned": stderr_offset_returned,
                        "sandbox_profile_used": "background-job-poll"
                    }));
                }

                let command = args
                    .get("command")
                    .or_else(|| args.get("cmd"))
                    .and_then(|v| v.as_str())
                    .context("Missing 'command'")?
                    .to_string();
                let cmd_args: Vec<String> = args
                    .get("args")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let cwd = args
                    .get("cwd")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|rel| env.workspace.shadow_root().join(rel.trim_start_matches('/')));
                let background = args
                    .get("background")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let loopback_ports = args
                    .get("loopback_ports")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
                    .min(8);
                let mut exec_env = HashMap::new();
                if loopback_ports > 0 {
                    exec_env.insert(
                        "AOS_REQUEST_LOOPBACK_PORTS".to_string(),
                        loopback_ports.to_string(),
                    );
                }

                let exec_res = env
                    .sandbox
                    .exec(ExecSpec {
                        command: command.clone(),
                        args: cmd_args.clone(),
                        cwd,
                        env: exec_env,
                        timeout_ms: args.get("timeout_ms").and_then(|v| v.as_u64()),
                        background,
                    })
                    .await;
                let out = match exec_res {
                    Ok(out) => out,
                    Err(e) => {
                        let err_str = e.to_string();
                        let timed_out = err_str.to_ascii_lowercase().contains("timed out");
                        if !background {
                            if let Some((cat, hint, _streak)) = self
                                .update_proc_exec_friction(
                                    &identity.agent_id,
                                    &command,
                                    &cmd_args,
                                    None,
                                    timed_out,
                                    "",
                                    &err_str,
                                )
                                .await
                            {
                                bail!("{err_str}\n[aegis_hint ({})]: {hint}", cat.as_str());
                            }
                        }
                        return Err(e);
                    }
                };
                let diag = if !background {
                    self.update_proc_exec_friction(
                        &identity.agent_id,
                        &command,
                        &cmd_args,
                        out.exit_code,
                        false,
                        &out.stdout,
                        &out.stderr,
                    )
                    .await
                } else {
                    None
                };
                let mut out_val = serde_json::to_value(out)?;
                if let Some((cat, hint, streak)) = diag {
                    if let Some(obj) = out_val.as_object_mut() {
                        obj.insert("friction_category".to_string(), json!(cat.as_str()));
                        obj.insert("aegis_hint".to_string(), json!(hint));
                        if streak >= 2 {
                            obj.insert("friction_streak".to_string(), json!(streak));
                        }
                    }
                }
                let active_ports = env.sandbox.allocated_loopback_ports();
                if !active_ports.is_empty() {
                    if let Some(obj) = out_val.as_object_mut() {
                        obj.insert("allocated_loopback_ports".to_string(), json!(active_ports));
                    }
                }
                if !background {
                    if let Ok(changed) = env.workspace.changed_since_baseline().await {
                        if let Ok(Some(conflict_msg)) =
                            self.claim_conflict_for_paths(identity, &changed).await
                        {
                            if let Some(obj) = out_val.as_object_mut() {
                                obj.insert("coordination_warning".to_string(), json!(conflict_msg));
                            }
                        }
                    }
                }
                Ok(out_val)
            }

            // ----------------------------------------------------------------
            // 3. Intra-Organization Shared CAS Artifacts & KV Tools
            // ----------------------------------------------------------------
            "org_artifact_publish" => {
                self.ensure_org_vault(&identity.org_id).await?;
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name'")?;
                let (raw_bytes, inferred_ct): (Vec<u8>, Option<&'static str>) =
                    if let Some(src_path) = args
                        .get("source_path")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        let (resolved, bytes) = read_sandbox_file_bytes_no_symlink(
                            env.workspace.shadow_root(),
                            &env.sandbox.config().agent_home_dir,
                            &env.sandbox.config().org_agent_pub_dir,
                            src_path,
                        )?;
                        (bytes, Some(infer_mime_type(&resolved)))
                    } else if let Some(b64) = args
                        .get("content_base64")
                        .and_then(|v| v.as_str())
                    {
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(b64.trim())
                            .context("Invalid 'content_base64' in org_artifact_publish")?;
                        (bytes, Some("application/octet-stream"))
                    } else if let Some(content) = args.get("content").and_then(|v| v.as_str()) {
                        (content.as_bytes().to_vec(), None)
                    } else {
                        bail!("org_artifact_publish requires one of 'source_path', 'content_base64', or 'content'");
                    };
                let content_type = args
                    .get("content_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| inferred_ct.unwrap_or("text/plain"));
                let metadata = args.get("metadata").cloned().unwrap_or_else(|| json!({}));

                let meta = self
                    .org_storage
                    .publish_artifact(
                        identity,
                        name,
                        &raw_bytes,
                        content_type,
                        metadata,
                    )
                    .await?;
                Ok(serde_json::to_value(meta)?)
            }

            "org_artifact_fetch" => {
                self.ensure_org_vault(&identity.org_id).await?;
                let uri = args
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .context("Missing 'uri'")?;
                let (meta, bytes) = self.org_storage.fetch_artifact(identity, uri).await?;
                if let Some(dest_path) = args
                    .get("dest_path")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    let (clean, full_path) =
                        shadow_path_for_write(env.workspace.shadow_root(), dest_path)?;
                    let size_bytes = bytes.len();
                    aos_core::session::write_bytes_atomic_synced_async(&full_path, bytes).await?;
                    return Ok(json!({
                        "artifact": meta,
                        "written_to_shadow": clean,
                        "size_bytes": size_bytes,
                    }));
                }
                if let Ok(text) = String::from_utf8(bytes.clone()) {
                    return Ok(json!({
                        "artifact": meta,
                        "content": text,
                    }));
                }
                if bytes.len() <= MAX_INLINE_ARTIFACT_FETCH_BYTES {
                    return Ok(json!({
                        "artifact": meta,
                        "is_binary": true,
                        "size_bytes": bytes.len(),
                        "content_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
                        "content": String::from_utf8_lossy(&bytes),
                    }));
                }
                Ok(json!({
                    "artifact": meta,
                    "is_binary": true,
                    "size_bytes": bytes.len(),
                    "hint": "Pass dest_path to stage binary artifact directly into your CoW shadow workspace, or pass artifact URI to fs_export_file.",
                }))
            }

            "org_kv_put" => {
                self.ensure_org_vault(&identity.org_id).await?;
                let ns = args
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default");
                let key = args
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key'")?;
                let value = args.get("value").cloned().context("Missing 'value'")?;
                let exp_ver = args.get("expected_version").and_then(|v| v.as_u64());
                let entry = self
                    .org_storage
                    .kv_put(identity, ns, key, value, exp_ver)
                    .await?;
                Ok(serde_json::to_value(entry)?)
            }

            "org_kv_get" => {
                self.ensure_org_vault(&identity.org_id).await?;
                let ns = args
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default");
                let key = args
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key'")?;
                let entry = self.org_storage.kv_get(&identity.org_id, ns, key).await?;
                Ok(json!({ "entry": entry }))
            }

            // ----------------------------------------------------------------
            // 4. First-Class Inter-Agent Communication (IPC) Tools
            // ----------------------------------------------------------------
            "coord_claim" | "coord_release" => self.coord_claims_tool(identity, tool_name, &args).await,

            "ipc_list_peers" => {
                let scope = args
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all");
                let skill_tag = args
                    .get("skill_tag")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase());
                let peers = self.ipc.list_peers(&identity.org_id).await?;
                let all_peers = self.ipc.list_all_peers().await?;
                let global_peers: Vec<Value> = all_peers
                    .into_iter()
                    .filter(|p| p.online)
                    .filter(|p| {
                        skill_tag.as_ref().is_none_or(|tag| {
                            p.capabilities.iter().any(|c| c.to_lowercase().contains(tag))
                                || p.skills.iter().any(|s| {
                                    s.id.to_lowercase().contains(tag)
                                        || s.name.to_lowercase().contains(tag)
                                        || s.tags.iter().any(|t| t.to_lowercase().contains(tag))
                                })
                                || p.summary
                                    .as_ref()
                                    .is_some_and(|sum| sum.to_lowercase().contains(tag))
                        })
                    })
                    .map(|p| {
                        let card = p.to_agent_card("http://127.0.0.1:7080");
                        json!({
                            "address": p.address(),
                            "org_id": p.org_id,
                            "agent_id": p.agent_id,
                            "role": p.role,
                            "client": p.client,
                            "pid": p.pid,
                            "liveness": p.liveness,
                            "online": p.online,
                            "workspace_root": p.workspace_root,
                            "summary": p.summary,
                            "skills": card.skills,
                            "agent_card": card,
                            "last_seen_ms": p.last_seen_ms,
                            "is_self": p.org_id == identity.org_id && p.agent_id == identity.agent_id,
                        })
                    })
                    .collect();
                if scope == "org" {
                    Ok(json!({
                        "self_address": format!("{}/{}", identity.org_id, identity.agent_id),
                        "org_id": identity.org_id,
                        "peers": peers
                    }))
                } else {
                    Ok(json!({
                        "self_address": format!("{}/{}", identity.org_id, identity.agent_id),
                        "org_id": identity.org_id,
                        "peers": peers,
                        "global_peers_count": global_peers.len(),
                        "global_peers": global_peers
                    }))
                }
            }

            "ipc_update_card" => {
                let summary = args
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let skills: Vec<AgentSkill> = args
                    .get("skills")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let updated = self.ipc.update_agent_card(identity, summary, skills).await?;
                Ok(json!({
                    "status": "updated",
                    "address": updated.address(),
                    "agent_card": updated.to_agent_card("http://127.0.0.1:7080")
                }))
            }

            "ipc_task_update" => {
                let task_id = args
                    .get("task_id")
                    .or_else(|| args.get("id"))
                    .and_then(|v| v.as_str())
                    .context("Missing 'task_id'")?;
                let raw_state = args
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("working");
                let state = match raw_state {
                    "submitted" => A2ATaskState::Submitted,
                    "working" => A2ATaskState::Working,
                    "input-required" | "input_required" => A2ATaskState::InputRequired,
                    "completed" => A2ATaskState::Completed,
                    "failed" => A2ATaskState::Failed,
                    "canceled" | "cancelled" => A2ATaskState::Canceled,
                    "rejected" => A2ATaskState::Rejected,
                    other => bail!("Invalid A2A task state '{}'", other),
                };
                let message = args
                    .get("message")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let artifacts: Vec<A2AArtifact> = args
                    .get("artifacts")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let target_task = self.ipc.get_task(task_id).await?;
                let caller_is_requester = target_task
                    .as_ref()
                    .is_some_and(|t| t.is_requester(&identity.org_id, &identity.agent_id));
                if !caller_is_requester {
                    if let Some(active) = self.active_task_id(identity).await {
                        if active != task_id {
                            bail!(
                                "A2A task '{}' is not the agent's active task '{}'",
                                task_id,
                                active
                            );
                        }
                    }
                }
                let expected_revision = args
                    .get("expected_revision")
                    .and_then(|v| v.as_u64());
                let task = self
                    .ipc
                    .update_task_state_cas(
                        identity,
                        task_id,
                        expected_revision,
                        state,
                        message,
                        artifacts,
                    )
                    .await?;
                if task.state.is_terminal() {
                    self.cleanup_terminal_task(identity, &task.id).await;
                }
                Ok(serde_json::to_value(task)?)
            }

            "ipc_task_get" => {
                let task_id = args
                    .get("task_id")
                    .or_else(|| args.get("id"))
                    .and_then(|v| v.as_str())
                    .context("Missing 'task_id'")?;
                let include_audit = args
                    .get("include_audit_trace")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let task = self
                    .ipc
                    .get_task(task_id)
                    .await?
                    .filter(|t| t.visible_to_org(&identity.org_id))
                    .with_context(|| format!("A2A task '{}' not found", task_id))?;
                let mut out = serde_json::to_value(&task)?;
                let subtasks: Vec<_> = self
                    .ipc
                    .list_subtasks(task_id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|t| t.visible_to_org(&identity.org_id))
                    .collect();
                if let Some(obj) = out.as_object_mut() {
                    obj.insert("subtasks_count".to_string(), json!(subtasks.len()));
                    obj.insert("subtasks".to_string(), json!(subtasks));
                    if include_audit {
                        let trace = self
                            .recorder
                            .trace_task(&identity.org_id, task_id)
                            .await
                            .unwrap_or_default();
                        let chain_report = self
                            .recorder
                            .verify_chain(Some(&identity.org_id))
                            .await
                            .unwrap_or_else(|_| json!({ "verified": true }));
                        obj.insert(
                            "hash_chain_verified".to_string(),
                            chain_report
                                .get("verified")
                                .cloned()
                                .unwrap_or(json!(true)),
                        );
                        obj.insert("hash_chain_report".to_string(), chain_report);
                        obj.insert("audit_trace".to_string(), json!(trace));
                    }
                }
                Ok(out)
            }

            "ipc_task_list" => {
                let scope = args
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("org");
                if scope == "all" {
                    bail!(
                        "scope='all' is operator-only; agents may only list A2A tasks in their own organization (use scope='org')"
                    );
                }
                if scope != "org" {
                    bail!("Invalid task list scope '{}'; expected 'org'", scope);
                }
                let org_filter = Some(identity.org_id.as_str());
                let agent_filter = args.get("agent_id").and_then(|v| v.as_str());
                let tasks = self.ipc.list_tasks(org_filter, agent_filter).await?;
                let chain_report = self
                    .recorder
                    .verify_chain(Some(&identity.org_id))
                    .await
                    .unwrap_or_else(|_| json!({ "verified": true }));
                Ok(json!({
                    "tasks_count": tasks.len(),
                    "tasks": tasks,
                    "hash_chain_verified": chain_report.get("verified").cloned().unwrap_or(json!(true)),
                    "audit_chain": chain_report
                }))
            }

            "ipc_send" | "ipc_request" => {
                let raw_to_agent = args
                    .get("to_agent")
                    .and_then(|v| v.as_str())
                    .context("Missing 'to_agent'")?;
                let (dest_org, dest_agent) = match resolved_cross_org_peer {
                    Some((o, a)) => (o, a),
                    None => (target_org.clone(), raw_to_agent.to_string()),
                };
                let from_field = if dest_org != identity.org_id {
                    format!("{}/{}", identity.org_id, identity.agent_id)
                } else {
                    identity.agent_id.clone()
                };
                let subject = args
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no subject)");
                let mut payload = args.get("payload").cloned().unwrap_or_else(|| json!({}));
                if tool_name == "ipc_request" {
                    let active_tid = self.active_task_id(identity).await;
                    if let Some(obj) = payload.as_object_mut() {
                        if obj.get("parent_task_id").is_none() {
                            if let Some(explicit_parent) =
                                args.get("parent_task_id").and_then(|v| v.as_str())
                            {
                                obj.insert("parent_task_id".to_string(), json!(explicit_parent));
                            } else if let Some(tid) = active_tid {
                                obj.insert("parent_task_id".to_string(), json!(tid));
                            }
                        }
                        if obj.get("depends_on").is_none() {
                            if let Some(deps) = args.get("depends_on") {
                                obj.insert("depends_on".to_string(), deps.clone());
                            }
                        }
                        if obj.get("workspace_id").is_none() {
                            obj.insert(
                                "workspace_id".to_string(),
                                json!(env.workspace.shadow_root().display().to_string()),
                            );
                        }
                    }
                }
                let attachments: Vec<String> = args
                    .get("attachments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let kind = if tool_name == "ipc_request" {
                    IpcKind::TaskRequest {
                        timeout_secs: args.get("timeout_secs").and_then(|v| v.as_u64()),
                    }
                } else {
                    IpcKind::DirectMessage
                };

                let sent = self
                    .ipc
                    .send(IpcEnvelope {
                        msg_id: String::new(),
                        org_id: dest_org,
                        from_agent: from_field,
                        to_target: dest_agent,
                        kind,
                        subject: subject.to_string(),
                        payload,
                        attachments,
                        status: MessageDeliveryStatus::Unread,
                        created_at_ms: 0,
                    })
                    .await?;
                Ok(serde_json::to_value(sent)?)
            }

            "ipc_publish" => {
                let topic = args
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .context("Missing 'topic'")?;
                let subject = args
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .unwrap_or(topic);
                let payload = args.get("payload").cloned().unwrap_or_else(|| json!({}));
                let attachments: Vec<String> = args
                    .get("attachments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let sent = self
                    .ipc
                    .send(IpcEnvelope {
                        msg_id: String::new(),
                        org_id: target_org,
                        from_agent: identity.agent_id.clone(),
                        to_target: format!("topic:{}", topic),
                        kind: IpcKind::TopicBroadcast {
                            topic: topic.to_string(),
                        },
                        subject: subject.to_string(),
                        payload,
                        attachments,
                        status: MessageDeliveryStatus::Unread,
                        created_at_ms: 0,
                    })
                    .await?;
                Ok(serde_json::to_value(sent)?)
            }

            "ipc_recv" => {
                let unread_only = args
                    .get("unread_only")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let limit = args
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20) as usize;
                let messages = self
                    .ipc
                    .recv_inbox(&identity.org_id, &identity.agent_id, unread_only, limit)
                    .await?;
                Ok(json!({
                    "agent_id": identity.agent_id,
                    "messages_count": messages.len(),
                    "messages": messages
                }))
            }

            "ipc_reply" => {
                let original_msg_id = args
                    .get("msg_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'msg_id'")?;
                let success = args
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let payload = args.get("payload").cloned().unwrap_or_else(|| json!({}));
                let attachments: Vec<String> = args
                    .get("attachments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let reply = self
                    .ipc
                    .reply(identity, original_msg_id, success, payload, attachments)
                    .await?;
                self.cleanup_terminal_task(identity, original_msg_id).await;
                Ok(serde_json::to_value(reply)?)
            }

            "ipc_wait" => {
                let task_id = args
                    .get("task_id")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let since_revision = args.get("since_revision").and_then(|v| v.as_u64());
                let claim_paths: Vec<String> = args
                    .get("claim_paths")
                    .or_else(|| args.get("paths"))
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let auto_claim = args
                    .get("auto_claim")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let wait_for_inbox = args
                    .get("wait_for_inbox")
                    .and_then(|v| v.as_bool())
                    .unwrap_or_else(|| task_id.is_none() && claim_paths.is_empty());
                let timeout_ms = args
                    .get("timeout_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(15_000)
                    .min(120_000);

                let start = std::time::Instant::now();
                let deadline = start + std::time::Duration::from_millis(timeout_ms);

                let initial_task = if let Some(ref tid) = task_id {
                    let t = self
                        .ipc
                        .get_task(tid)
                        .await?
                        .filter(|t| t.visible_to_org(&identity.org_id))
                        .with_context(|| format!("A2A task '{}' not found", tid))?;
                    Some((t.revision, t.state))
                } else {
                    None
                };

                loop {
                    let elapsed_ms = start.elapsed().as_millis() as u64;

                    // 1. Check file claims availability
                    if !claim_paths.is_empty() {
                        let (mut table, _) = self.load_claims(&identity.org_id).await?;
                        let now_ms = Utc::now().timestamp_millis();
                        claims::prune_expired(&mut table, now_ms);
                        let live = self.live_peer_ids(&identity.org_id).await;
                        let any_conflict = claim_paths.iter().any(|glob| {
                            table.iter().any(|(g, c)| {
                                c.owner != identity.agent_id
                                    && live.contains(&c.owner)
                                    && claims::globs_may_overlap(g, glob, &[])
                            })
                        });
                        if !any_conflict {
                            if auto_claim {
                                let claim_res = self
                                    .coord_claims_tool(
                                        identity,
                                        "coord_claim",
                                        &json!({
                                            "paths": claim_paths,
                                            "note": "auto-claimed via ipc_wait"
                                        }),
                                    )
                                    .await?;
                                if claim_res
                                    .get("rejected")
                                    .and_then(|v| v.as_array())
                                    .is_some_and(|r| r.is_empty())
                                {
                                    let refresh =
                                        env.workspace.refresh_from_host().await.unwrap_or_default();
                                    return Ok(json!({
                                        "status": "ready",
                                        "reason": "claims_available",
                                        "claimed": claim_res,
                                        "auto_refresh": refresh,
                                        "waited_ms": elapsed_ms
                                    }));
                                }
                            } else {
                                let refresh =
                                    env.workspace.refresh_from_host().await.unwrap_or_default();
                                return Ok(json!({
                                    "status": "ready",
                                    "reason": "claims_available",
                                    "auto_refresh": refresh,
                                    "waited_ms": elapsed_ms
                                }));
                            }
                        }
                    }

                    // 2. Check A2A task state transition
                    if let Some(ref tid) = task_id {
                        let task = self
                            .ipc
                            .get_task(tid)
                            .await?
                            .filter(|t| t.visible_to_org(&identity.org_id))
                            .with_context(|| format!("A2A task '{}' not found", tid))?;
                        let ready = match since_revision {
                            Some(rev) => {
                                task.revision > rev
                                    || task.state.is_terminal()
                                    || task.state == A2ATaskState::InputRequired
                            }
                            None => {
                                task.state.is_terminal()
                                    || task.state == A2ATaskState::InputRequired
                                    || initial_task.is_some_and(|(init_rev, init_state)| {
                                        task.revision > init_rev && task.state != init_state
                                    })
                            }
                        };
                        if ready {
                            let refresh =
                                env.workspace.refresh_from_host().await.unwrap_or_default();
                            return Ok(json!({
                                "status": "ready",
                                "reason": "task_updated",
                                "task": task,
                                "auto_refresh": refresh,
                                "waited_ms": elapsed_ms
                            }));
                        }
                    }

                    // 3. Check unread inbox messages
                    if wait_for_inbox {
                        let msgs = self
                            .ipc
                            .peek_inbox(&identity.org_id, &identity.agent_id, 20)
                            .await
                            .unwrap_or_default();
                        if !msgs.is_empty() {
                            let refresh =
                                env.workspace.refresh_from_host().await.unwrap_or_default();
                            return Ok(json!({
                                "status": "ready",
                                "reason": "inbox_messages",
                                "messages_count": msgs.len(),
                                "messages": msgs,
                                "auto_refresh": refresh,
                                "waited_ms": elapsed_ms
                            }));
                        }
                    }

                    if std::time::Instant::now() >= deadline {
                        return Ok(json!({
                            "status": "timeout",
                            "waited_ms": start.elapsed().as_millis() as u64
                        }));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }

            "ipc_ack" => {
                let msg_id = args
                    .get("msg_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'msg_id'")?;
                self.ipc
                    .ack(&identity.org_id, &identity.agent_id, msg_id)
                    .await?;
                Ok(json!({ "status": "acked", "msg_id": msg_id }))
            }

            "ipc_subscribe" => {
                let topics: Vec<String> = args
                    .get("topics")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_else(|| vec!["*".to_string()]);
                self.ipc.register_peer(identity, topics.clone()).await?;
                Ok(json!({ "status": "subscribed", "topics": topics }))
            }

            "egress_http_request" => {
                match self.execute_egress_http_request(identity, &args).await {
                    Ok(val) => Ok(val),
                    Err(err) => {
                        self.record_kernel_friction(
                            aos_core::friction::FrictionCategory::EgressDenied,
                            aos_core::friction::CmdBucket::Egress,
                            Some("mcp_gateway"),
                            None,
                            1,
                            false,
                        );
                        Err(err)
                    }
                }
            }

            // ----------------------------------------------------------------
            // 5. Session Lease, Escalation Approval & Sub-MCP Aggregation
            // ----------------------------------------------------------------
            "policy_grant_lease" => {
                let action_pattern = args
                    .get("action_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("workspace_commit");
                let resource_pattern = args
                    .get("resource_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*");
                let ttl_secs = args
                    .get("ttl_secs")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(3600)
                    .clamp(1, MAX_TOOL_LEASE_TTL_SECS);
                let task_id = args
                    .get("task_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);

                let now_ms = Utc::now().timestamp_millis();
                let lease = self
                    .policy
                    .grant_lease(LeaseGrant {
                        lease_id: format!("lease-{}", &Uuid::new_v4().to_string()[..8]),
                        org_id: identity.org_id.clone(),
                        agent_id: identity.agent_id.clone(),
                        action_pattern: action_pattern.to_string(),
                        resource_pattern: resource_pattern.to_string(),
                        created_at_ms: now_ms,
                        expires_at_ms: now_ms + (ttl_secs * 1000),
                        granted_by: "session_owner".to_string(),
                        kind: if task_id.is_some() {
                            LeaseKind::TaskScoped
                        } else {
                            LeaseKind::Ttl
                        },
                        task_id,
                    })
                    .await?;
                if let Some(ref tid) = lease.task_id {
                    let _ = self.ipc.record_task_lease(tid, &lease.lease_id).await;
                }
                Ok(serde_json::to_value(lease)?)
            }

            "policy_approve_escalation" => {
                let esc_id = args
                    .get("escalation_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'escalation_id'")?;
                let ttl_secs = args
                    .get("ttl_secs")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(3600)
                    .clamp(1, MAX_TOOL_LEASE_TTL_SECS);
                let in_org = self
                    .policy
                    .list_escalations(&identity.org_id)
                    .await?
                    .iter()
                    .any(|e| e.escalation_id == esc_id);
                if !in_org {
                    bail!(
                        "Escalation '{}' not found in organization '{}'",
                        esc_id,
                        identity.org_id
                    );
                }
                let lease = self
                    .policy
                    .approve_escalation(esc_id, ttl_secs, "user_owner")
                    .await?;
                if let Some(ref tid) = lease.task_id {
                    let _ = self.ipc.record_task_lease(tid, &lease.lease_id).await;
                }
                let _ = self
                    .recorder
                    .record(AuditEvent {
                        event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                        timestamp_ms: Utc::now().timestamp_millis(),
                        org_id: lease.org_id.clone(),
                        agent_id: lease.agent_id.clone(),
                        action: lease.action_pattern.clone(),
                        resource: lease.resource_pattern.clone(),
                        policy_decision: format!("approved:{}:{}:user_owner", esc_id, lease.lease_id),
                        snapshot_id: None,
                        details: json!({
                            "escalation_id": esc_id,
                            "lease_id": lease.lease_id,
                            "approved_by": "user_owner",
                            "ttl_secs": ttl_secs,
                        }),
                        task_id: lease.task_id.clone(),
                        prev_hash: None,
                        event_hash: None,
                    })
                    .await;
                Ok(serde_json::to_value(lease)?)
            }

            "policy_list_escalations" => {
                let list = self.policy.list_escalations(&identity.org_id).await?;
                Ok(json!({ "escalations": list }))
            }

            "mcp_mount_server" => {
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name'")?;
                let endpoint = args
                    .get("endpoint")
                    .and_then(|v| v.as_str())
                    .context("Missing 'endpoint'")?;
                let scope = args
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("agent");

                let srv = MountedMcpServer {
                    name: name.to_string(),
                    endpoint: endpoint.to_string(),
                    scope: scope.to_string(),
                    mounted_by: identity.fqn(),
                };
                self.mounted_mcp_servers.write().await.push(srv.clone());
                Ok(serde_json::to_value(srv)?)
            }

            other => bail!("Unknown Aegis OS MCP tool '{}'", other),
        }
    }
}
