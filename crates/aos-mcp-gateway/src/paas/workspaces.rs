use super::*;

impl PaasControlPlane {
    pub async fn list_workspaces(&self, org_id: Option<&str>) -> Vec<CloudWorkspaceRecord> {
        self.reload().await;
        self.state
            .read()
            .await
            .workspaces
            .iter()
            .filter(|w| org_id.is_none_or(|o| o == "*" || w.org_id == o))
            .cloned()
            .collect()
    }

    pub async fn get_workspace(
        &self,
        org_id: &str,
        workspace_id: &str,
    ) -> Option<CloudWorkspaceRecord> {
        self.reload().await;
        self.state
            .read()
            .await
            .workspaces
            .iter()
            .find(|w| (org_id == "*" || w.org_id == org_id) && w.workspace_id == workspace_id)
            .cloned()
    }

    pub(super) fn validate_identifier(kind: &str, value: &str) -> anyhow::Result<()> {
        let trimmed = value.trim();
        if trimmed.is_empty()
            || trimmed == "."
            || trimmed == ".."
            || trimmed.starts_with('-')
            || trimmed.contains("..")
            || !trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            bail!(
                "Invalid {} '{}': only ASCII alphanumeric, '-', '_', and '.' are allowed",
                kind,
                value
            );
        }
        Ok(())
    }

    pub(super) fn validate_branch_name(branch: &str) -> anyhow::Result<()> {
        let trimmed = branch.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('-')
            || trimmed.starts_with('/')
            || trimmed.ends_with('/')
            || trimmed.ends_with('.')
            || trimmed.ends_with(".lock")
            || trimmed.contains("..")
            || trimmed.contains("//")
            || trimmed.contains("@{")
            || !trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
        {
            bail!("Invalid git branch name '{}'", branch);
        }
        Ok(())
    }

    fn extract_git_host_and_port(url: &str) -> Option<(String, u16)> {
        let trimmed = url.trim();
        let lower = trimmed.to_ascii_lowercase();
        let (default_port, authority_rest) = if let Some(r) = lower.strip_prefix("https://") {
            (443u16, r.split(['/', '?']).next().unwrap_or(""))
        } else if let Some(r) = lower.strip_prefix("http://") {
            (80u16, r.split(['/', '?']).next().unwrap_or(""))
        } else if let Some(r) = lower.strip_prefix("ssh://") {
            (22u16, r.split(['/', '?']).next().unwrap_or(""))
        } else if let Some(r) = lower.strip_prefix("git://") {
            (9418u16, r.split(['/', '?']).next().unwrap_or(""))
        } else if !lower.contains("://") && lower.contains('@') && lower.contains(':') {
            let after_at = lower.rsplit('@').next().unwrap_or("");
            let host_only = after_at.split(':').next().unwrap_or("");
            return (!host_only.is_empty()).then(|| (host_only.trim_end_matches('.').to_string(), 22));
        } else {
            return None;
        };

        let host_port = authority_rest.rsplit('@').next().unwrap_or(authority_rest);
        let (host, port) = if let Some(after_open) = host_port.strip_prefix('[') {
            let (h, after_close) = after_open.split_once(']')?;
            let p = if let Some(ps) = after_close.strip_prefix(':') {
                ps.parse::<u16>().ok()?
            } else {
                default_port
            };
            (h, p)
        } else if let Some((h, ps)) = host_port.rsplit_once(':') {
            if h.contains(':') {
                return None;
            }
            (h, ps.parse::<u16>().ok()?)
        } else {
            (host_port, default_port)
        };
        let clean = host.trim_end_matches('.');
        if clean.is_empty() || port == 0 {
            None
        } else {
            Some((clean.to_string(), port))
        }
    }

    fn is_obfuscated_ip_host(host: &str) -> bool {
        if host.parse::<u32>().is_ok()
            || host.starts_with("0x")
            || host.starts_with("0X")
        {
            return true;
        }
        let segs: Vec<&str> = host.split('.').collect();
        segs.len() == 4
            && segs
                .iter()
                .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'x' || b == b'X'))
            && segs.iter().any(|s| {
                (s.len() > 1 && s.starts_with('0')) || s.starts_with("0x") || s.starts_with("0X")
            })
    }

    pub(crate) fn is_ssrf_or_internal_git_url(url: &str) -> bool {
        let lower = url.trim().to_ascii_lowercase();
        if lower.starts_with("file://")
            || lower.starts_with("ext::")
            || lower.starts_with("fd::")
        {
            return true;
        }
        let Some((host, _port)) = Self::extract_git_host_and_port(&lower) else {
            return lower.contains("://") || lower.contains('@');
        };
        if host.is_empty()
            || host == "localhost"
            || host.ends_with(".localhost")
            || host == "metadata.google.internal"
            || host == "metadata.goog"
            || host.ends_with(".internal")
            || Self::is_obfuscated_ip_host(&host)
        {
            return true;
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return aos_core::security::is_forbidden_outbound_ip(ip);
        }
        false
    }

    pub(super) async fn validate_remote_git_url(url: &str) -> anyhow::Result<()> {
        let trimmed = url.trim();
        let lower = trimmed.to_ascii_lowercase();
        if trimmed.is_empty()
            || trimmed.starts_with('-')
            || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            bail!("Unsupported or unsafe workspace source_url '{}'", url);
        }
        if !lower.starts_with("https://")
            && !lower.starts_with("http://")
            && !lower.starts_with("git@")
        {
            bail!(
                "Unsupported remote git scheme in source_url '{}' (expected https:// or git@)",
                url
            );
        }
        if Self::is_ssrf_or_internal_git_url(trimmed) {
            bail!(
                "Refusing to clone internal or loopback git URL '{}'",
                url
            );
        }
        let (host, port) = Self::extract_git_host_and_port(trimmed)
            .with_context(|| format!("Invalid git URL '{}'", url))?;
        if host.parse::<std::net::IpAddr>().is_err() {
            let addrs: Vec<std::net::SocketAddr> =
                tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .with_context(|| format!("DNS lookup failed for git host '{}'", host))?
                    .collect();
            if addrs.is_empty() {
                bail!("No DNS records resolved for git host '{}'", host);
            }
            for addr in addrs {
                if aos_core::security::is_forbidden_outbound_ip(addr.ip()) {
                    bail!(
                        "Refusing to clone git URL '{}': host resolved to forbidden IP '{}'",
                        url,
                        addr.ip()
                    );
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_local_source_dir(&self, src_path: &Path) -> anyhow::Result<PathBuf> {
        let canon = std::fs::canonicalize(src_path)
            .with_context(|| format!("Failed to resolve source directory '{}'", src_path.display()))?;
        if let Some(rt_root) = self.state_file.parent() {
            let canon_rt = std::fs::canonicalize(rt_root).unwrap_or_else(|_| rt_root.to_path_buf());
            if canon.starts_with(&canon_rt) {
                bail!(
                    "Refusing to clone from inside Aegis runtime state directory '{}'",
                    canon.display()
                );
            }
        }
        if let Ok(canon_ws_root) = std::fs::canonicalize(&self.workspaces_root) {
            if canon.starts_with(&canon_ws_root) {
                bail!(
                    "Refusing to clone from another tenant workspace directory '{}'",
                    canon.display()
                );
            }
        }
        if let Some(home) = std::env::var_os("HOME")
            .map(PathBuf::from)
            .and_then(|h| std::fs::canonicalize(&h).ok())
        {
            if canon == home || home.starts_with(&canon) {
                bail!(
                    "Refusing to provision workspace from user home or ancestor '{}'",
                    canon.display()
                );
            }
        }
        let s = canon.to_string_lossy();
        const FORBIDDEN_PREFIXES: &[&str] = &[
            "/etc",
            "/private/etc",
            "/root",
            "/proc",
            "/sys",
            "/dev",
            "/boot",
            "/var/run",
            "/private/var/run",
            "/private/tmp",
            "/run",
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/system",
            "/library",
        ];
        let lower_s = s.to_ascii_lowercase();
        if s == "/"
            || FORBIDDEN_PREFIXES
                .iter()
                .any(|p| lower_s == *p || lower_s.starts_with(&format!("{p}/")))
            || aos_policy::AegisPolicyKernel::is_forbidden_import_source(&s)
            || crate::fs_transfer::is_forbidden_export_dest(&s, &s)
        {
            bail!(
                "Refusing to provision workspace from restricted host path '{}'",
                canon.display()
            );
        }
        Ok(canon)
    }

    pub(super) fn host_repo_path_for_write(root: &Path, rel: &str) -> anyhow::Result<(String, PathBuf)> {
        use std::path::Component;
        let mut rel_path = PathBuf::new();
        for comp in Path::new(rel.trim_start_matches('/')).components() {
            match comp {
                Component::Normal(c) => rel_path.push(c),
                Component::CurDir => {}
                _ => bail!("Path traversal outside workspace is forbidden: '{}'", rel),
            }
        }
        if rel_path.as_os_str().is_empty() {
            bail!("Empty relative path is forbidden");
        }
        if rel_path
            .components()
            .next()
            .is_some_and(|c| c.as_os_str() == ".git")
        {
            bail!("Refusing to write inside .git directory");
        }
        let mut cur = root.to_path_buf();
        for comp in rel_path.components() {
            cur.push(comp);
            match std::fs::symlink_metadata(&cur) {
                Ok(meta) if meta.file_type().is_symlink() => bail!(
                    "Refusing to write through symlink '{}' in cloud workspace",
                    cur.strip_prefix(root).unwrap_or(&cur).display()
                ),
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let full = root.join(&rel_path);
        Ok((rel_path.to_string_lossy().into_owned(), full))
    }

    /// Provision a Cloud Workspace from a local directory or remote Git URL, initialize a Git baseline,
    /// enforce tenant plan concurrency limits, and spawn isolated CoW shadow workspaces.
    pub async fn provision_workspace(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
        source_url_or_path: &str,
        branch: &str,
        agents: Vec<String>,
    ) -> anyhow::Result<CloudWorkspaceRecord> {
        self.provision_workspace_with_policy(
            kernel,
            org_id,
            workspace_id,
            source_url_or_path,
            branch,
            agents,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn provision_workspace_with_policy(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
        source_url_or_path: &str,
        branch: &str,
        agents: Vec<String>,
        allow_local_source: bool,
    ) -> anyhow::Result<CloudWorkspaceRecord> {
        self.reload().await;
        let org_id = org_id.trim();
        Self::validate_identifier("org_id", org_id)?;
        let ws_id = if workspace_id.trim().is_empty() {
            format!("ws-{}", &Uuid::new_v4().to_string()[..8])
        } else {
            workspace_id.trim().to_string()
        };
        Self::validate_identifier("workspace_id", &ws_id)?;
        let branch = if branch.trim().is_empty() {
            "main"
        } else {
            branch.trim()
        };
        Self::validate_branch_name(branch)?;
        let source_url_or_path = source_url_or_path.trim();
        let lower_source = source_url_or_path.to_ascii_lowercase();
        let is_cloud_sync = source_url_or_path == "." || source_url_or_path == "cloud-sync";
        let is_remote_git = lower_source.starts_with("http://")
            || lower_source.starts_with("https://")
            || lower_source.starts_with("git@");
        if source_url_or_path.starts_with('-') || lower_source.starts_with("file://") {
            bail!(
                "Unsupported or unsafe workspace source_url '{}'",
                source_url_or_path
            );
        }
        if Self::is_ssrf_or_internal_git_url(source_url_or_path) {
            bail!(
                "Refusing to clone internal or loopback git URL '{}'",
                source_url_or_path
            );
        }
        if is_remote_git {
            Self::validate_remote_git_url(source_url_or_path).await?;
        } else if !is_cloud_sync && !allow_local_source {
            bail!(
                "LOCAL_SOURCE_FORBIDDEN: Provisioning a cloud workspace from a local host directory ('{}') is restricted to the server operator; use source_url='cloud-sync' with /v1/workspaces/sync-up or an https:// Git URL",
                source_url_or_path
            );
        }

        let agent_list = if agents.is_empty() {
            vec!["cloud-coder-1".to_string()]
        } else {
            agents
        };
        for ag in &agent_list {
            Self::validate_identifier("agent_id", ag)?;
        }

        // Check tenant plan workspace count and concurrency limits
        let (plan_tier, max_agents, other_ws_count) = {
            let state = self.state.read().await;
            let tier = state
                .tenants
                .iter()
                .find(|t| t.org_id == org_id)
                .map(|t| t.plan_tier)
                .unwrap_or(PlanTier::Community);
            let max_ag = state
                .tenants
                .iter()
                .find(|t| t.org_id == org_id)
                .map(|t| t.max_concurrent_agents)
                .unwrap_or_else(|| tier.max_concurrent_agents());
            let other_ws = state
                .workspaces
                .iter()
                .filter(|w| w.org_id == org_id && w.workspace_id != ws_id)
                .count();
            (tier, max_ag, other_ws)
        };
        if other_ws_count >= plan_tier.max_workspaces() {
            bail!(
                "Tenant '{}' plan ({}) allows at most {} cloud workspace (upgrade to Pro for multiple workspaces)",
                org_id,
                plan_tier.as_str(),
                plan_tier.max_workspaces()
            );
        }
        if agent_list.len() > max_agents {
            bail!(
                "Tenant '{}' plan allows at most {} concurrent cloud agents (requested {})",
                org_id,
                max_agents,
                agent_list.len()
            );
        }

        let vault_status = kernel.ensure_org_vault(org_id).await?;
        let host_repo = if vault_status.encrypted {
            vault_status
                .mount_dir
                .join("paas_workspaces")
                .join(&ws_id)
                .join("host_repo")
        } else {
            self.workspaces_root
                .join(org_id)
                .join(&ws_id)
                .join("host_repo")
        };
        if host_repo.exists() {
            let _ = tokio::fs::remove_dir_all(&host_repo).await;
        }
        if let Some(parent) = host_repo.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let src_path = Path::new(source_url_or_path);
        if is_remote_git {
            let parent_dir = host_repo
                .parent()
                .map(|p| p.to_path_buf())
                .context("cloud workspace host_repo missing parent directory")?;
            let clone_url = source_url_or_path.to_string();
            let clone_branch = branch.to_string();
            let clone_dst = host_repo.to_string_lossy().into_owned();
            let output = tokio::task::spawn_blocking(move || -> anyhow::Result<std::process::Output> {
                let git_bin = crate::resolve_system_git_binary()?;
                let args = vec![
                    "clone".to_string(),
                    "--depth".to_string(),
                    "1".to_string(),
                    "--branch".to_string(),
                    clone_branch,
                    "--".to_string(),
                    clone_url,
                    clone_dst,
                ];
                crate::run_sanitized_host_git(
                    &git_bin,
                    &parent_dir,
                    &[
                        ("protocol.file.allow", "never"),
                        ("protocol.ext.allow", "never"),
                        ("http.followRedirects", "false"),
                    ],
                    &args,
                )
            })
            .await
            .context("git clone task failed")??;
            if !output.status.success() {
                bail!(
                    "git clone failed for '{}' (branch '{}'): {}",
                    source_url_or_path,
                    branch,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        } else if allow_local_source && !is_cloud_sync && src_path.exists() && src_path.is_dir() {
            let safe_src = self.validate_local_source_dir(src_path)?;
            CoWWorkspace::cow_sync_dir(&safe_src, &host_repo).await?;
        } else {
            tokio::fs::create_dir_all(&host_repo).await?;
            tokio::fs::write(
                host_repo.join("README.md"),
                format!("# Cloud Workspace `{}` (`{}`)\n", ws_id, source_url_or_path),
            )
            .await?;
        }

        if !host_repo.join(".git").exists() {
            let repo_init = host_repo.clone();
            let branch_owned = branch.to_string();
            tokio::task::spawn_blocking(move || {
                if let Ok(git_bin) = crate::resolve_system_git_binary() {
                    let _ = crate::run_sanitized_host_git(
                        &git_bin,
                        &repo_init,
                        &[],
                        &["init".into(), "-b".into(), branch_owned],
                    );
                    let _ = crate::run_sanitized_host_git(
                        &git_bin,
                        &repo_init,
                        &[],
                        &["config".into(), "user.name".into(), "Aegis Cloud PaaS".into()],
                    );
                    let _ = crate::run_sanitized_host_git(
                        &git_bin,
                        &repo_init,
                        &[],
                        &["config".into(), "user.email".into(), "paas@aegis-os.dev".into()],
                    );
                    let _ = crate::run_sanitized_host_git(&git_bin, &repo_init, &[], &["add".into(), "-A".into()]);
                    let _ = crate::run_sanitized_host_git(
                        &git_bin,
                        &repo_init,
                        &[],
                        &[
                            "commit".into(),
                            "-m".into(),
                            "chore: initial cloud workspace baseline".into(),
                            "--allow-empty".into(),
                        ],
                    );
                }
            })
            .await?;
        }

        for agent_id in &agent_list {
            let identity = AgentIdentity::new(org_id, agent_id.clone(), "Aegis Cloud Agent");
            kernel
                .ensure_agent_environment(
                    identity,
                    &host_repo,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await?;
        }

        let repo_bytes = Self::estimate_dir_bytes(&host_repo).await.max(4096);
        let cow_saved = repo_bytes.saturating_mul(agent_list.len() as u64);
        let now = Utc::now().timestamp_millis();

        let record = CloudWorkspaceRecord {
            workspace_id: ws_id.clone(),
            org_id: org_id.to_string(),
            source_url: source_url_or_path.to_string(),
            branch: branch.to_string(),
            host_repo_path: host_repo,
            agents: agent_list,
            created_at_ms: now,
            status: WorkspaceLifecycleState::Active,
            last_active_ms: now,
            hibernated_at_ms: None,
            cow_saved_bytes: cow_saved,
        };

        let org_owned = org_id.to_string();
        let ws_id_owned = ws_id.clone();
        let rec_insert = record.clone();
        self.with_state_mut(move |state| {
            state
                .workspaces
                .retain(|w| !(w.org_id == org_owned && w.workspace_id == ws_id_owned));
            state.workspaces.push(rec_insert);
            Ok(())
        })
        .await?;
        let _ = self
            .record_usage(org_id, Some(&ws_id), 1, 0, cow_saved)
            .await;
        Ok(record)
    }

    /// Transition a Cloud Workspace into Scale-to-Zero (`Hibernated`), releasing in-memory sandbox
    /// handles while preserving zero-copy CoW shadow directories on disk for instant wake-up.
    pub async fn hibernate_workspace(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
    ) -> anyhow::Result<CloudWorkspaceRecord> {
        let now = Utc::now().timestamp_millis();
        let org_owned = org_id.to_string();
        let ws_owned = workspace_id.to_string();
        let (record, has_other_active) = self
            .with_state_mut(move |state| {
                let ws = state
                    .workspaces
                    .iter_mut()
                    .find(|w| {
                        (org_owned == "*" || w.org_id == org_owned) && w.workspace_id == ws_owned
                    })
                    .with_context(|| {
                        format!("Cloud workspace '{}/{}' not found", org_owned, ws_owned)
                    })?;
                ws.status = WorkspaceLifecycleState::Hibernated;
                ws.hibernated_at_ms = Some(now);
                let cloned = ws.clone();
                if let Some(t) = state.tenants.iter_mut().find(|t| t.org_id == cloned.org_id) {
                    t.active_agents.clear();
                    t.updated_at_ms = now;
                }
                let has_other = state.workspaces.iter().any(|w| {
                    w.org_id == cloned.org_id
                        && w.workspace_id != cloned.workspace_id
                        && w.status == WorkspaceLifecycleState::Active
                });
                Ok((cloned, has_other))
            })
            .await?;
        kernel
            .evict_agent_environments(&record.org_id, &record.agents)
            .await;
        if !has_other_active {
            let vault = kernel.vault.clone();
            let lock_org_id = record.org_id.clone();
            let _ = tokio::task::spawn_blocking(move || vault.lock_org(&lock_org_id)).await;
        }
        Ok(record)
    }

    /// Automatically Scale-to-Zero (`Hibernate`) any active Cloud Workspaces whose inactivity
    /// exceeds their tenant plan's `idle_hibernate_timeout_ms` (Free = 15m, Pro = 2h, Team = 12h).
    pub async fn hibernate_idle_workspaces(
        &self,
        kernel: &AegisRuntimeKernel,
        idle_override_ms: Option<i64>,
    ) -> anyhow::Result<Vec<String>> {
        self.reload().await;
        let now = Utc::now().timestamp_millis();
        let candidates: Vec<(String, String)> = {
            let state = self.state.read().await;
            state
                .workspaces
                .iter()
                .filter(|w| w.status == WorkspaceLifecycleState::Active)
                .filter_map(|w| {
                    let tier = state
                        .tenants
                        .iter()
                        .find(|t| t.org_id == w.org_id)
                        .map(|t| t.plan_tier)
                        .unwrap_or(PlanTier::Community);
                    let threshold_ms =
                        idle_override_ms.unwrap_or_else(|| tier.idle_hibernate_timeout_ms());
                    let last = if w.last_active_ms > 0 {
                        w.last_active_ms
                    } else {
                        w.created_at_ms
                    };
                    if now.saturating_sub(last) >= threshold_ms {
                        Some((w.org_id.clone(), w.workspace_id.clone()))
                    } else {
                        None
                    }
                })
                .collect()
        };

        let mut hibernated_ids = Vec::new();
        for (org, ws_id) in candidates {
            if self.hibernate_workspace(kernel, &org, &ws_id).await.is_ok() {
                hibernated_ids.push(format!("{}/{}", org, ws_id));
            }
        }
        Ok(hibernated_ids)
    }

    /// Delete a Cloud Workspace and evict its in-memory sandbox handles.
    pub async fn delete_workspace(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
    ) -> anyhow::Result<Value> {
        let org_owned = org_id.to_string();
        let ws_owned = workspace_id.to_string();
        let removed = self
            .with_state_mut(move |state| {
                let idx = state
                    .workspaces
                    .iter()
                    .position(|w| {
                        (org_owned == "*" || w.org_id == org_owned) && w.workspace_id == ws_owned
                    })
                    .with_context(|| {
                        format!("Cloud workspace '{}/{}' not found", org_owned, ws_owned)
                    })?;
                Ok(state.workspaces.remove(idx))
            })
            .await?;
        kernel
            .evict_agent_environments(&removed.org_id, &removed.agents)
            .await;
        let _ = kernel.ensure_org_vault(&removed.org_id).await;
        if let Some(ws_dir) = removed.host_repo_path.parent() {
            let _ = tokio::fs::remove_dir_all(ws_dir).await;
        }
        Ok(json!({
            "status": "deleted",
            "org_id": removed.org_id,
            "workspace_id": removed.workspace_id
        }))
    }

    /// Remove every record of an org: keys, workspaces (and their files), usage, billing,
    /// pending claims and approver. Refuses an org with an active subscription unless `force`.
    pub async fn delete_org(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        force: bool,
    ) -> anyhow::Result<Value> {
        if org_id.is_empty()
            || org_id == "*"
            || org_id.contains('/')
            || org_id.contains("..")
            || aos_vfs::vault::sanitize_and_validate_org_id(org_id).is_err()
        {
            bail!("Invalid org_id '{}'", org_id);
        }
        let org_owned = org_id.to_string();
        let (workspaces, counts) = self
            .with_state_mut(move |state| {
                if !force
                    && state
                        .subscriptions
                        .iter()
                        .any(|s| s.org_id == org_owned && s.status == "active")
                {
                    bail!(
                        "Org '{}' has an active subscription; cancel it first or pass force",
                        org_owned
                    );
                }
                let mut counts = serde_json::Map::new();
                macro_rules! purge {
                    ($field:ident) => {{
                        let before = state.$field.len();
                        state.$field.retain(|r| r.org_id != org_owned);
                        counts.insert(stringify!($field).to_string(), json!(before - state.$field.len()));
                    }};
                }
                let workspaces: Vec<CloudWorkspaceRecord> = state
                    .workspaces
                    .iter()
                    .filter(|w| w.org_id == org_owned)
                    .cloned()
                    .collect();
                purge!(api_keys);
                purge!(workspaces);
                purge!(tenants);
                purge!(subscriptions);
                purge!(pending_claims);
                purge!(approvers);
                purge!(approver_enrollments);
                Ok((workspaces, counts))
            })
            .await?;
        let found = counts.values().any(|n| n.as_u64() != Some(0));
        for ws in &workspaces {
            kernel.evict_agent_environments(&ws.org_id, &ws.agents).await;
        }
        let _ = tokio::fs::remove_dir_all(self.workspaces_root.join(org_id)).await;
        let vault = kernel.vault.clone();
        let destroy_org_id = org_id.to_string();
        let _ = tokio::task::spawn_blocking(move || vault.destroy_org(&destroy_org_id)).await;
        Ok(json!({ "status": if found { "deleted" } else { "not_found" }, "org_id": org_id, "removed": counts }))
    }

    /// Wake a `Hibernated` Cloud Workspace back to `Active` in milliseconds by re-attaching CoW directories.
    pub async fn wake_workspace_if_needed(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
    ) -> anyhow::Result<(CloudWorkspaceRecord, u64)> {
        let started = std::time::Instant::now();
        let now = Utc::now().timestamp_millis();
        let org_owned = org_id.to_string();
        let ws_owned = workspace_id.to_string();
        let record = self
            .with_state_mut(move |state| {
                let ws = state
                    .workspaces
                    .iter_mut()
                    .find(|w| {
                        (org_owned == "*" || w.org_id == org_owned) && w.workspace_id == ws_owned
                    })
                    .with_context(|| {
                        format!("Cloud workspace '{}/{}' not found", org_owned, ws_owned)
                    })?;
                let was_hib = ws.status == WorkspaceLifecycleState::Hibernated;
                ws.status = WorkspaceLifecycleState::Active;
                ws.last_active_ms = now;
                ws.hibernated_at_ms = None;
                let cloned = ws.clone();
                if was_hib {
                    if let Some(t) = state.tenants.iter_mut().find(|t| t.org_id == cloned.org_id) {
                        t.wake_count = t.wake_count.saturating_add(1);
                        t.updated_at_ms = now;
                    }
                }
                Ok(cloned)
            })
            .await?;

        kernel.ensure_org_vault(&record.org_id).await?;
        for agent_id in &record.agents {
            let identity = AgentIdentity::new(&record.org_id, agent_id.clone(), "Aegis Cloud Agent");
            kernel
                .ensure_agent_environment(
                    identity,
                    &record.host_repo_path,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await?;
        }
        let wake_ms = started.elapsed().as_millis() as u64;
        Ok((record, wake_ms))
    }

    /// Upload a source-only bundle from the developer's local workstation into the Cloud Workspace's
    /// baseline repository and auto-rebase all active CoW agent branches.
    pub async fn sync_up_source_bundle(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
        files: Vec<SourceFileEntry>,
    ) -> anyhow::Result<Value> {
        let (ws, _) = self
            .wake_workspace_if_needed(kernel, org_id, workspace_id)
            .await?;
        let mut updated_paths = Vec::new();
        let mut deleted_paths = Vec::new();

        for entry in files {
            let Ok((clean, dest)) = Self::host_repo_path_for_write(&ws.host_repo_path, &entry.path)
            else {
                continue;
            };
            if entry.deleted {
                if dest.exists() {
                    let _ = tokio::fs::remove_file(&dest).await;
                    deleted_paths.push(clean);
                }
            } else {
                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(&dest, entry.content.as_bytes()).await?;
                updated_paths.push(clean);
            }
        }

        // Propagate updated host baseline into every agent's CoW shadow workspace
        let mut rebased_agents = Vec::new();
        for agent_id in &ws.agents {
            let id = AgentIdentity::new(&ws.org_id, agent_id.clone(), "Aegis Cloud Agent");
            if let Ok(report) = kernel.refresh_agent_workspace(&id).await {
                rebased_agents.push(json!({
                    "agent_id": agent_id,
                    "updates": report.total_updates(),
                    "conflicts": report.conflicts
                }));
            }
        }

        let _ = self
            .record_usage(&ws.org_id, Some(&ws.workspace_id), 1, 0, 0)
            .await;

        Ok(json!({
            "status": "synced_up",
            "org_id": ws.org_id,
            "workspace_id": ws.workspace_id,
            "updated_files_count": updated_paths.len(),
            "deleted_files_count": deleted_paths.len(),
            "updated_files": updated_paths,
            "deleted_files": deleted_paths,
            "rebased_agents": rebased_agents
        }))
    }

    /// Inspect an Agent's uncommitted CoW shadow workspace changes (or host repo changes) and export
    /// a unified source diff + verified text-only `changed_source_files` for safe `aegis-os cloud pull`.
    pub async fn inspect_agent_diff(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        agent_id: &str,
        workspace_id: Option<&str>,
    ) -> anyhow::Result<Value> {
        let mut target_host_repo = None;
        if let Some(ws_id) = workspace_id {
            if let Ok((ws, _)) = self.wake_workspace_if_needed(kernel, org_id, ws_id).await {
                target_host_repo = Some(ws.host_repo_path);
            }
        } else {
            let _ = kernel.ensure_org_vault(org_id).await;
            let list = self.list_workspaces(Some(org_id)).await;
            if let Some(first) = list.first() {
                target_host_repo = Some(first.host_repo_path.clone());
            }
        }

        let identity = AgentIdentity::new(org_id, agent_id, "Aegis Cloud Agent");
        if let Some(ref host_repo) = target_host_repo {
            let _ = kernel
                .ensure_agent_environment(
                    identity.clone(),
                    host_repo,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await;
        }

        let env = kernel.get_agent_environment(&identity).await?;
        let _ = env.workspace.refresh_from_host().await;
        let diffs = env.workspace.diff(None).await?;

        let shadow_root = env.workspace.shadow_root();
        let host_root = env.workspace.host_source_root();

        let mut unified_diff = String::new();
        let mut changed_source_files: Vec<SourceFileEntry> = Vec::new();
        let mut skipped_binaries: Vec<String> = Vec::new();

        for d in &diffs {
            let rel = d.relative_path.trim_start_matches('/').to_string();
            let shadow_file = shadow_root.join(&rel);
            let host_file = host_root.join(&rel);

            let change_tag = format!("{:?}", d.change_type).to_lowercase();
            if change_tag.contains("deleted") || !shadow_file.exists() {
                let old_text = tokio::fs::read_to_string(&host_file).await.unwrap_or_default();
                unified_diff.push_str(&format!("--- a/{rel}\n+++ /dev/null\n"));
                for line in old_text.lines().take(80) {
                    unified_diff.push_str(&format!("-{line}\n"));
                }
                changed_source_files.push(SourceFileEntry {
                    path: rel,
                    content: String::new(),
                    deleted: true,
                });
                continue;
            }

            let raw_bytes = tokio::fs::read(&shadow_file).await.unwrap_or_default();
            // Reject binary files (containing NUL bytes) from source-only sync
            if raw_bytes.iter().take(8000).any(|&b| b == 0) {
                skipped_binaries.push(rel);
                continue;
            }
            let Ok(new_text) = String::from_utf8(raw_bytes) else {
                skipped_binaries.push(rel);
                continue;
            };
            let old_text = tokio::fs::read_to_string(&host_file).await.unwrap_or_default();

            unified_diff.push_str(&format!("--- a/{rel}\n+++ b/{rel}\n"));
            let old_lines: Vec<&str> = old_text.lines().collect();
            let new_lines: Vec<&str> = new_text.lines().collect();
            let mut prefix = 0usize;
            while prefix < old_lines.len()
                && prefix < new_lines.len()
                && old_lines[prefix] == new_lines[prefix]
            {
                prefix += 1;
            }
            let mut old_end = old_lines.len();
            let mut new_end = new_lines.len();
            while old_end > prefix
                && new_end > prefix
                && old_lines[old_end - 1] == new_lines[new_end - 1]
            {
                old_end -= 1;
                new_end -= 1;
            }
            if prefix < old_end || prefix < new_end {
                unified_diff.push_str(&format!(
                    "@@ -{},{} +{},{} @@\n",
                    prefix + 1,
                    old_end.saturating_sub(prefix),
                    prefix + 1,
                    new_end.saturating_sub(prefix)
                ));
                for line in &old_lines[prefix..old_end] {
                    unified_diff.push_str(&format!("-{line}\n"));
                }
                for line in &new_lines[prefix..new_end] {
                    unified_diff.push_str(&format!("+{line}\n"));
                }
            }

            changed_source_files.push(SourceFileEntry {
                path: rel,
                content: new_text,
                deleted: false,
            });
        }

        Ok(json!({
            "org_id": org_id,
            "agent_id": agent_id,
            "workspace_id": workspace_id.unwrap_or("default"),
            "changes_count": diffs.len(),
            "changes": diffs,
            "unified_diff": unified_diff,
            "changed_source_files": changed_source_files,
            "skipped_binaries": skipped_binaries
        }))
    }

    /// Merge an Agent's CoW Shadow Workspace into the Cloud Workspace's Git repository,
    /// create a dedicated feature branch, commit the changes, and export a unified Git patch & PR bundle.
    pub async fn export_workspace_pr(
        &self,
        kernel: &AegisRuntimeKernel,
        identity: &AgentIdentity,
        workspace_id: Option<&str>,
        branch_name: &str,
        commit_title: &str,
        overwrite_binaries: bool,
    ) -> anyhow::Result<Value> {
        let target_branch = if branch_name.trim().is_empty() {
            format!("aegis/{}/{}", identity.org_id, identity.agent_id)
        } else {
            branch_name.trim().to_string()
        };
        Self::validate_branch_name(&target_branch)?;
        let title = if commit_title.trim().is_empty() {
            format!(
                "feat({}): automated multi-agent CoW merge commit",
                identity.agent_id
            )
        } else {
            commit_title.trim().to_string()
        };

        let env = kernel.get_agent_environment(identity).await?;
        let _ = env.workspace.refresh_from_host().await?;
        let touched = env.workspace.changed_since_baseline().await?;
        if let Some(msg) = kernel.claim_conflict_for_paths(identity, &touched).await? {
            bail!("{}", msg);
        }
        let base_dir = env
            .workspace
            .shadow_root()
            .parent()
            .map(|p| p.join("baseline_snapshot"))
            .filter(|p| p.exists())
            .unwrap_or_else(|| env.workspace.host_source_root().to_path_buf());
        let diffs = CoWWorkspace::diff_dirs(&base_dir, env.workspace.shadow_root(), None)
            .await
            .unwrap_or_default();
        let (_payload, evidence_hash) =
            aos_core::compute_diff_evidence(&diffs, overwrite_binaries, false);
        let audit_metadata = json!({
            "paths": touched.clone(),
            "host_root": env.workspace.host_source_root().display().to_string(),
            "overwrite_binaries": overwrite_binaries,
            "skip_verify": false,
            "evidence_hash": evidence_hash,
            "branch_name": target_branch,
            "evidence": {
                "changed_files_count": diffs.len(),
                "paths": touched.clone(),
                "evidence_hash": evidence_hash,
                "overwrite_binaries": overwrite_binaries,
                "skip_verify": false,
            }
        });

        let matched_rule = match kernel
            .authorize_and_audit(
                identity,
                "workspace_commit",
                &identity.org_id,
                "/workspace",
                audit_metadata,
            )
            .await?
        {
            PolicyDecision::Allow { matched_rule } => matched_rule,
            PolicyDecision::Ask {
                escalation_id,
                reason,
                suggested_lease_scope,
            } => {
                if let Some(diff_dir) = self.state_file.parent().map(|p| p.join("escalation_diffs")) {
                    let _ = tokio::fs::create_dir_all(&diff_dir).await;
                    let _ = aos_core::session::write_json_pretty_atomic(
                        &diff_dir.join(format!("{}.json", escalation_id)),
                        &diffs,
                    )
                    .await;
                }
                let approval_ticket = self
                    .issue_escalation_ticket(&identity.org_id, &escalation_id, 1_800_000)
                    .await;
                return Ok(json!({
                    "status": "approval_required",
                    "escalation_id": escalation_id,
                    "approval_ticket": approval_ticket,
                    "reason": reason,
                    "suggested_lease_scope": suggested_lease_scope,
                    "evidence_hash": evidence_hash
                }));
            }
            PolicyDecision::Deny { reason } => {
                bail!("Policy Denied syscall 'workspace_export_pr': {}", reason);
            }
        };

        let _host_commit_lock = env.workspace.acquire_host_commit_lock().await?;
        let frozen_dir = env
            .workspace
            .shadow_root()
            .parent()
            .unwrap_or_else(|| env.workspace.shadow_root())
            .join(format!("pr_frozen_{}", &Uuid::new_v4().to_string()[..8]));
        let commit_res: anyhow::Result<Vec<String>> = async {
            CoWWorkspace::cow_sync_dir(env.workspace.shadow_root(), &frozen_dir).await?;
            let frozen_diffs =
                CoWWorkspace::diff_dirs(&base_dir, &frozen_dir, None)
                    .await
                    .unwrap_or_default();
            let frozen_paths: Vec<String> = frozen_diffs
                .iter()
                .map(|d| d.relative_path.clone())
                .collect();
            if let Some(msg) = kernel
                .claim_conflict_for_paths(identity, &frozen_paths)
                .await?
            {
                bail!("{}", msg);
            }
            if let Some(bad) = frozen_paths.iter().find(|p| {
                AegisPolicyKernel::is_commit_poisoning_path(p)
                    && !touched.iter().any(|old| old == *p)
            }) {
                bail!(
                    "Refusing PR export: shadow path '{}' was introduced after authorization",
                    bad
                );
            }
            if matched_rule.contains("#sha256:") {
                let (_, recomputed) =
                    aos_core::compute_diff_evidence(&frozen_diffs, overwrite_binaries, false);
                if recomputed != evidence_hash {
                    bail!(
                        "PR export aborted: shadow workspace changed after SHA-256 pinned approval ({} != {})",
                        recomputed,
                        evidence_hash
                    );
                }
            }
            env.workspace
                .commit_frozen_to_host_with_options(&frozen_dir, None, overwrite_binaries)
                .await
        }
        .await;
        let _ = tokio::fs::remove_dir_all(&frozen_dir).await;
        drop(_host_commit_lock);
        let committed_files = commit_res?;

        let host_root = env.workspace.host_source_root().to_path_buf();
        let git_trailer = format!(
            "Aegis-OS-Verified: principal={}/{} workspace={} files={} merge=4tier-cow",
            identity.org_id,
            identity.agent_id,
            workspace_id.unwrap_or("default"),
            committed_files.len()
        );
        let pr_markdown_badge = format!(
            "[![Verified by Aegis OS](https://img.shields.io/badge/Aegis_OS-CoW_Verified_%28{}_files%29-0A7D52)](https://github.com/heurion-org/aegis-os)\n\
             > 🛡️ **Transactional Agent PR (`{}/{}`)** · `{}` file(s) merged with zero host-overwrite conflicts · Try locally: `brew install heurion-org/aegis-os/aegis-os && aegis-os audit-me`",
            committed_files.len(),
            identity.org_id,
            identity.agent_id,
            committed_files.len()
        );

        let host_root_git = host_root.clone();
        let agent_owned = identity.agent_id.clone();
        let org_owned = identity.org_id.clone();
        let branch_owned = target_branch.clone();
        let title_owned = title.clone();
        let trailer_owned = git_trailer.clone();
        let (commit_sha, unified_patch) = tokio::task::spawn_blocking(move || -> anyhow::Result<(String, String)> {
            let git_bin = crate::resolve_system_git_binary()?;
            if !host_root_git.join(".git").exists() {
                let _ = crate::run_sanitized_host_git(
                    &git_bin,
                    &host_root_git,
                    &[],
                    &["init".into(), "-b".into(), "main".into()],
                );
            }
            let _ = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &["config".into(), "user.name".into(), agent_owned.clone()],
            );
            let _ = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &[
                    "config".into(),
                    "user.email".into(),
                    format!("{}@{}.aegis-os.dev", agent_owned, org_owned),
                ],
            );
            let _ = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &["checkout".into(), "-B".into(), branch_owned],
            );
            let _ = crate::run_sanitized_host_git(&git_bin, &host_root_git, &[], &["add".into(), "-A".into()]);
            let _ = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &[
                    "commit".into(),
                    "-m".into(),
                    title_owned,
                    "-m".into(),
                    trailer_owned,
                    "--allow-empty".into(),
                ],
            );
            let commit_sha = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &["rev-parse".into(), "HEAD".into()],
            )
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
            let unified_patch = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &["format-patch".into(), "-1".into(), "--stdout".into()],
            )
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
            Ok((commit_sha, unified_patch))
        })
        .await
        .context("git PR export task failed")??;

        let _ = self
            .record_usage(&identity.org_id, workspace_id, 1, 0, 0)
            .await;

        Ok(json!({
            "status": "pr_bundle_exported",
            "org_id": identity.org_id,
            "agent_id": identity.agent_id,
            "workspace_id": workspace_id.unwrap_or("default"),
            "host_root": host_root,
            "committed_files": committed_files,
            "git_branch": target_branch,
            "git_commit_sha": commit_sha,
            "commit_title": title,
            "git_trailer": git_trailer,
            "pr_markdown_badge": pr_markdown_badge,
            "unified_patch": unified_patch,
            "github_pr_payload": {
                "title": title,
                "head": target_branch,
                "base": "main",
                "body": format!(
                    "Automated 4-Tier LCS Diff3 CoW merge committed by Aegis OS principal `{}/{}`.\n\nCommitted files ({}):\n{}\n\n---\n{}\n\n`{}`",
                    identity.org_id,
                    identity.agent_id,
                    committed_files.len(),
                    committed_files.iter().map(|f| format!("- `{}`", f)).collect::<Vec<_>>().join("\n"),
                    pr_markdown_badge,
                    git_trailer
                )
            }
        }))
    }
}
