use super::*;

pub(super) struct UnifiedMcpInstallArgs {
    pub(super) target: String,
    pub(super) server_id: Option<String>,
    pub(super) scope: String,
    pub(super) trust: String,
    pub(super) dlp: String,
    pub(super) token: Option<String>,
    pub(super) token_stdin: bool,
    pub(super) device_code: bool,
    pub(super) no_login: bool,
    pub(super) no_browser: bool,
    pub(super) no_client_sync: bool,
    pub(super) allow_local_http: bool,
    pub(super) home_dir: Option<PathBuf>,
    pub(super) dry_run: bool,
}

pub(super) async fn run_unified_mcp_install(
    identity: &AgentIdentity,
    workspace: &Path,
    runtime_dir: &Path,
    args: UnifiedMcpInstallArgs,
) -> anyhow::Result<Value> {
    let scope = args.scope.trim().to_ascii_lowercase();
    if !matches!(scope.as_str(), "org" | "workspace") {
        bail!("Invalid `--scope '{}'`: expected 'org' or 'workspace'", scope);
    }
    let trust_level = parse_trust_level(&args.trust)?;
    let dlp_mode: PseudonymMode = args.dlp.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let home = resolve_home_dir(args.home_dir);

    let static_token = if args.token_stdin {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Some(buf.trim().to_string())
    } else {
        args.token.clone()
    };

    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    let resolved = kernel
        .mcp_registry
        .resolve_install_target(&args.target, args.server_id.as_deref(), args.allow_local_http)
        .await?;

    if args.dry_run {
        return Ok(json!({
            "dry_run": true,
            "scope": scope,
            "trust": format!("{trust_level:?}"),
            "dlp": format!("{dlp_mode:?}"),
            "resolved": resolved,
        }));
    }

    match resolved {
        ResolvedInstallTarget::Bundle {
            source,
            allow_local_http,
        } => {
            let rec = kernel
                .mcp_bundles
                .install_bundle(
                    &identity.org_id,
                    &source,
                    BundleInstallOptions {
                        profile: None,
                        sync_clients: !args.no_client_sync,
                        sync_skills: true,
                        workspace_dir: Some(workspace.to_path_buf()),
                        home_dir: Some(home),
                        proxy_bin_path: std::env::current_exe().ok(),
                        allow_local_http,
                        dry_run: false,
                        airgap_allowed_origins: kernel.mcp_registry.airgap_allowed_origins(),
                        ..BundleInstallOptions::default()
                    },
                )
                .await?;

            let mut auth_status = "none".to_string();
            let mut next_hint: Option<String> = None;
            if let Some(ref realm_id) = rec.auth_realm_id {
                if let Some(ref raw_tok) = static_token {
                    kernel
                        .mcp_oauth
                        .login_static_token(
                            &identity.org_id,
                            realm_id,
                            raw_tok,
                            vec![],
                            allow_local_http,
                        )
                        .await?;
                    auth_status = "authenticated".to_string();
                } else if !args.no_login {
                    let use_device = args.device_code || !std::io::stdin().is_terminal();
                    let login_res = if use_device {
                        kernel
                            .mcp_oauth
                            .login_device_code(
                                &identity.org_id,
                                realm_id,
                                None,
                                None,
                                vec![],
                                vec![],
                                allow_local_http,
                                180,
                                None,
                            )
                            .await
                    } else {
                        kernel
                            .mcp_oauth
                            .login_pkce_loopback(
                                &identity.org_id,
                                realm_id,
                                None,
                                None,
                                vec![],
                                vec![],
                                allow_local_http,
                                !args.no_browser,
                                180,
                                None,
                            )
                            .await
                    };
                    match login_res {
                        Ok(_) => auth_status = "authenticated".to_string(),
                        Err(e) => {
                            auth_status = "needs_login".to_string();
                            next_hint = Some(format!(
                                "Bundle registered, but OAuth login did not complete ({e}). Run `aegis-os mcp login {realm_id}`."
                            ));
                        }
                    }
                } else {
                    auth_status = "needs_login".to_string();
                    next_hint = Some(format!("Run `aegis-os mcp login {realm_id}` to authenticate."));
                }
            }

            Ok(json!({
                "status": "installed",
                "kind": "bundle",
                "server_id": rec.bundle_id,
                "server_ids": rec.server_ids,
                "trust_tier": "bundle",
                "auth_status": auth_status,
                "scope": scope,
                "next_hint": next_hint,
            }))
        }
        ResolvedInstallTarget::Candidate(cand) => {
            let policy = McpServerPolicy {
                trust_level,
                dlp_mode,
                ..McpServerPolicy::default()
            };
            let mut auth_status = "none".to_string();
            let mut next_hint: Option<String> = None;

            if let Some(ref url) = cand.remote_url {
                let realm_id = cand.server_id.clone();
                kernel
                    .mcp_oauth
                    .upsert_realm_config(
                        &identity.org_id,
                        &realm_id,
                        RealmUpsertSpec {
                            allowed_hosts: cand.allowed_hosts.clone(),
                            allow_local_http: args.allow_local_http,
                            ..Default::default()
                        },
                    )
                    .await?;
                kernel
                    .mcp_firewall
                    .register_http_server_with_options(
                        &identity.org_id,
                        &cand.server_id,
                        url,
                        BTreeMap::new(),
                        policy,
                        Some(&realm_id),
                        None,
                        args.allow_local_http,
                    )
                    .await?;

                if let Some(ref raw_tok) = static_token {
                    kernel
                        .mcp_oauth
                        .login_static_token(
                            &identity.org_id,
                            &realm_id,
                            raw_tok,
                            cand.allowed_hosts.clone(),
                            args.allow_local_http,
                        )
                        .await?;
                    auth_status = "authenticated".to_string();
                } else if cand.auth_mode == "oauth2_or_auto" && !args.no_login {
                    let use_device = args.device_code || !std::io::stdin().is_terminal();
                    let login_res = if use_device {
                        kernel
                            .mcp_oauth
                            .login_device_code(
                                &identity.org_id,
                                &realm_id,
                                Some(url.as_str()),
                                None,
                                cand.allowed_hosts.clone(),
                                vec![],
                                args.allow_local_http,
                                180,
                                None,
                            )
                            .await
                    } else {
                        kernel
                            .mcp_oauth
                            .login_pkce_loopback(
                                &identity.org_id,
                                &realm_id,
                                Some(url.as_str()),
                                None,
                                cand.allowed_hosts.clone(),
                                vec![],
                                args.allow_local_http,
                                !args.no_browser,
                                180,
                                None,
                            )
                            .await
                    };
                    match login_res {
                        Ok(_) => auth_status = "authenticated".to_string(),
                        Err(e) => {
                            auth_status = "needs_login".to_string();
                            next_hint = Some(format!(
                                "Registered '{}'; run `aegis-os mcp login {}` or `--token-stdin` ({e}).",
                                cand.server_id, realm_id
                            ));
                        }
                    }
                } else if cand.auth_mode != "none" {
                    auth_status = "needs_login".to_string();
                    next_hint = Some(format!(
                        "Authenticate with `aegis-os mcp login {} --token-stdin`.",
                        realm_id
                    ));
                }
            } else if let Some(ref pkg) = cand.package_spec {
                let mut stdio_policy = policy;
                stdio_policy.isolate_upstream_network = true;
                stdio_policy.allowed_hosts =
                    aos_mcp_gateway::mcp_firewall::normalize_and_validate_stdio_allowed_hosts(
                        &cand.allowed_hosts,
                    )?;
                let (spawn_cmd, spawn_args, spawn_cwd, env_vars, req_envs) =
                    if pkg.registry_type == "mcpb" {
                        let installed = aos_mcp_gateway::mcp_mcpb::install_mcpb_archive(
                            &pkg.identifier,
                            pkg.file_sha256.as_deref(),
                            &cand.server_id,
                            kernel.mcp_registry.runtime_data_root(),
                            args.allow_local_http,
                        )
                        .await?;
                        let mut merged_req = pkg.required_env_vars.clone();
                        for k in installed.required_env_vars {
                            if !merged_req.iter().any(|existing| existing == &k) {
                                merged_req.push(k);
                            }
                        }
                        (
                            installed.command,
                            installed.args,
                            Some(installed.cwd.display().to_string()),
                            installed.env,
                            merged_req,
                        )
                    } else {
                        (
                            pkg.command.clone(),
                            pkg.args.clone(),
                            Some(workspace.display().to_string()),
                            BTreeMap::new(),
                            pkg.required_env_vars.clone(),
                        )
                    };
                kernel
                    .mcp_firewall
                    .register_stdio_server(
                        &identity.org_id,
                        &cand.server_id,
                        &spawn_cmd,
                        spawn_args,
                        spawn_cwd,
                        env_vars,
                        stdio_policy,
                    )
                    .await?;
                if !req_envs.is_empty() {
                    auth_status = "needs_env_secret".to_string();
                    next_hint = Some(format!(
                        "Required env vars [{}] can be Vault-sealed via `aegis-os mcp add {} ... --env KEY=VAL`.",
                        req_envs.join(", "),
                        cand.server_id
                    ));
                }
            }

            let cand_ver = cand
                .version
                .clone()
                .or_else(|| cand.package_spec.as_ref().and_then(|p| p.version.clone()));
            let _ = kernel
                .mcp_firewall
                .update_server_config(&identity.org_id, &cand.server_id, |rec| {
                    rec.registry_name = Some(cand.name.clone());
                    rec.installed_version = cand_ver;
                    rec.source_target = Some(args.target.clone());
                    rec.manifest_sha256 = Some(cand.manifest_sha256.clone());
                })
                .await;

            let workspace_manifest = if scope == "workspace" {
                Some(
                    McpRegistryClient::write_workspace_mcp_declaration(workspace, &cand)?
                        .display()
                        .to_string(),
                )
            } else {
                None
            };

            Ok(json!({
                "status": "installed",
                "kind": cand.transport_kind,
                "server_id": cand.server_id,
                "registry_name": cand.name,
                "trust_tier": cand.trust_tier.label(),
                "allowed_hosts": cand.allowed_hosts,
                "auth_status": auth_status,
                "scope": scope,
                "workspace_manifest": workspace_manifest,
                "next_hint": next_hint,
            }))
        }
    }
}

pub(super) async fn run_mcp_registry_action(
    runtime_dir: &Path,
    action: McpRegistryAction,
) -> anyhow::Result<Value> {
    let client = McpRegistryClient::new(runtime_dir);
    match action {
        McpRegistryAction::List { .. } => Ok(client.registry_status()),
        McpRegistryAction::Add {
            url,
            allow_local_http,
            ..
        } => {
            client.add_registry(&url, allow_local_http).await?;
            Ok(client.registry_status())
        }
        McpRegistryAction::Remove { url, .. } => {
            client.remove_registry(&url).await?;
            Ok(client.registry_status())
        }
        McpRegistryAction::Airgapped { enabled, .. } => {
            client.set_disable_public_registry(enabled).await?;
            Ok(client.registry_status())
        }
    }
}

pub(super) async fn remove_dir_if_non_symlink(path: &Path) {
    if let Ok(meta) = tokio::fs::symlink_metadata(path).await {
        if !meta.file_type().is_symlink() && meta.is_dir() {
            let _ = tokio::fs::remove_dir_all(path).await;
        }
    }
}

pub(super) async fn run_mcp_remove_lifecycle(
    org_id: &str,
    server_id: &str,
    home: &Path,
    workspace: &Path,
    runtime_dir: &Path,
    purge_auth: bool,
    keep_client_configs: bool,
) -> anyhow::Result<Value> {
    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    let clean_target = aos_mcp_gateway::mcp_firewall::sanitize_server_id(server_id);
    let rec = kernel
        .mcp_firewall
        .get_server(org_id, server_id)
        .await
        .or(kernel.mcp_firewall.get_server(org_id, &clean_target).await)
        .with_context(|| format!("MCP server '{}' is not registered in org '{}'", server_id, org_id))?;

    let mut removed_client_entries = 0usize;
    if !rec.adopted_origins.is_empty() && !keep_client_configs {
        let unadopted = kernel
            .mcp_firewall
            .unadopt_servers(org_id, Some(&rec.server_id), true)
            .await?;
        for u in unadopted {
            removed_client_entries += u["restored_origins"].as_u64().unwrap_or(0) as usize;
        }
    } else {
        if !keep_client_configs {
            for (client, cfg_path, _) in
                aos_mcp_gateway::mcp_firewall::client_config_candidates(home, workspace)
            {
                if aos_mcp_gateway::mcp_firewall::remove_client_proxy_entry(
                    client,
                    &cfg_path,
                    &rec.server_id,
                )
                .unwrap_or(false)
                {
                    removed_client_entries += 1;
                }
            }
        }
        kernel.mcp_firewall.remove_server(org_id, &rec.server_id).await?;
    }

    let safe_id = aos_mcp_gateway::mcp_firewall::sanitize_server_id(&rec.server_id);
    remove_dir_if_non_symlink(&runtime_dir.join("mcp_homes").join(&safe_id)).await;
    remove_dir_if_non_symlink(&runtime_dir.join("mcp_bundles_bin").join(&safe_id)).await;

    let mut purged_auth = false;
    if purge_auth {
        if let Some(ref realm_id) = rec.auth_realm {
            let still_used = kernel
                .mcp_firewall
                .list_servers(Some(org_id))
                .await
                .into_iter()
                .any(|s| s.auth_realm.as_deref() == Some(realm_id.as_str()));
            if !still_used {
                purged_auth = kernel.mcp_oauth.purge_realm(org_id, realm_id).await?;
            }
        }
    }

    Ok(json!({
        "status": "removed",
        "org_id": org_id,
        "server_id": rec.server_id,
        "removed_client_entries": removed_client_entries,
        "purged_auth": purged_auth,
    }))
}

pub(super) fn should_sync_detected_client_config(home: &Path, client: &str, cfg_path: &Path) -> bool {
    if cfg_path.is_file() {
        return true;
    }
    match client {
        "claude" => home.join(".claude").is_dir(),
        "agy" => home.join(".gemini").join("config").is_dir(),
        "agy-cli" => home.join(".gemini").join("antigravity-cli").is_dir(),
        "cursor-global" => home.join(".cursor").is_dir(),
        "opencode" => home.join(".config").join("opencode").is_dir(),
        "codex" => home.join(".codex").is_dir(),
        _ => false,
    }
}

pub(super) async fn run_mcp_sync_lifecycle(
    org_id: &str,
    home: &Path,
    workspace: &Path,
    runtime_dir: &Path,
    sync_clients: bool,
    allow_local_http: bool,
    dry_run: bool,
) -> anyhow::Result<Value> {
    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    let mut installed_ids: BTreeSet<String> = kernel
        .mcp_firewall
        .list_servers(Some(org_id))
        .await
        .into_iter()
        .map(|s| s.server_id)
        .collect();

    let mut results = Vec::<Value>::new();
    let mut installed_count = 0usize;
    let mut up_to_date_count = 0usize;
    let mut seen_manifest_ids = BTreeSet::<String>::new();

    for rel in [".aegis/mcp.json", ".mcp.json"] {
        let manifest_path = workspace.join(rel);
        let Ok(raw) = std::fs::read_to_string(&manifest_path) else {
            continue;
        };
        let Ok(doc) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let Some(servers) = doc.get("mcpServers").and_then(|v| v.as_object()) else {
            continue;
        };
        for (raw_id, entry) in servers {
            let sid = aos_mcp_gateway::mcp_firewall::sanitize_server_id(raw_id);
            if sid == "aegis-os" || !seen_manifest_ids.insert(sid.clone()) {
                continue;
            }
            if installed_ids.contains(&sid) {
                up_to_date_count += 1;
                results.push(json!({
                    "server_id": sid,
                    "source": rel,
                    "status": "up_to_date",
                }));
                continue;
            }
            if dry_run {
                results.push(json!({
                    "server_id": sid,
                    "source": rel,
                    "status": "would_install",
                }));
                continue;
            }

            let registry_name = entry
                .get("registryName")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let declared_hosts: Vec<String> = entry
                .get("allowedHosts")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();

            if let Some(url) = entry.get("url").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
                let effective_hosts = if declared_hosts.is_empty() {
                    aos_mcp_gateway::mcp_registry::derive_exact_allowed_hosts(url)
                } else {
                    declared_hosts
                };
                kernel
                    .mcp_oauth
                    .upsert_realm_config(
                        org_id,
                        &sid,
                        RealmUpsertSpec {
                            allowed_hosts: effective_hosts,
                            allow_local_http,
                            ..Default::default()
                        },
                    )
                    .await?;
                kernel
                    .mcp_firewall
                    .register_http_server_with_options(
                        org_id,
                        &sid,
                        url,
                        BTreeMap::new(),
                        McpServerPolicy::default(),
                        Some(&sid),
                        None,
                        allow_local_http,
                    )
                    .await?;
                let _ = kernel
                    .mcp_firewall
                    .update_server_config(org_id, &sid, |rec| {
                        rec.registry_name = registry_name.clone();
                        rec.source_target = Some(url.to_string());
                    })
                    .await;
                installed_ids.insert(sid.clone());
                installed_count += 1;
                results.push(json!({
                    "server_id": sid,
                    "source": rel,
                    "status": "installed",
                    "transport": "http",
                }));
            } else if let Some(cmd) = entry.get("command").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
                let cmd_args: Vec<String> = entry
                    .get("args")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let clean_hosts =
                    aos_mcp_gateway::mcp_firewall::normalize_and_validate_stdio_allowed_hosts(
                        &declared_hosts,
                    )?;
                let stdio_policy = McpServerPolicy {
                    isolate_upstream_network: true,
                    allowed_hosts: clean_hosts,
                    ..McpServerPolicy::default()
                };
                kernel
                    .mcp_firewall
                    .register_stdio_server(
                        org_id,
                        &sid,
                        cmd,
                        cmd_args,
                        Some(workspace.display().to_string()),
                        BTreeMap::new(),
                        stdio_policy,
                    )
                    .await?;
                let _ = kernel
                    .mcp_firewall
                    .update_server_config(org_id, &sid, |rec| {
                        rec.registry_name = registry_name.clone();
                    })
                    .await;
                installed_ids.insert(sid.clone());
                installed_count += 1;
                results.push(json!({
                    "server_id": sid,
                    "source": rel,
                    "status": "installed",
                    "transport": "stdio",
                }));
            } else if let Some(ref reg_name) = registry_name {
                let resolved = kernel
                    .mcp_registry
                    .resolve_install_target(reg_name, Some(&sid), allow_local_http)
                    .await?;
                if let ResolvedInstallTarget::Candidate(cand) = resolved {
                    if let Some(ref url) = cand.remote_url {
                        kernel
                            .mcp_oauth
                            .upsert_realm_config(
                                org_id,
                                &cand.server_id,
                                RealmUpsertSpec {
                                    allowed_hosts: cand.allowed_hosts.clone(),
                                    allow_local_http,
                                    ..Default::default()
                                },
                            )
                            .await?;
                        kernel
                            .mcp_firewall
                            .register_http_server_with_options(
                                org_id,
                                &cand.server_id,
                                url,
                                BTreeMap::new(),
                                McpServerPolicy::default(),
                                Some(&cand.server_id),
                                None,
                                allow_local_http,
                            )
                            .await?;
                    } else if let Some(ref pkg) = cand.package_spec {
                        let stdio_policy = McpServerPolicy {
                            isolate_upstream_network: true,
                            allowed_hosts:
                                aos_mcp_gateway::mcp_firewall::normalize_and_validate_stdio_allowed_hosts(
                                    &cand.allowed_hosts,
                                )?,
                            ..McpServerPolicy::default()
                        };
                        let (spawn_cmd, spawn_args, spawn_cwd, env_vars) =
                            if pkg.registry_type == "mcpb" {
                                let installed = aos_mcp_gateway::mcp_mcpb::install_mcpb_archive(
                                    &pkg.identifier,
                                    pkg.file_sha256.as_deref(),
                                    &cand.server_id,
                                    kernel.mcp_registry.runtime_data_root(),
                                    allow_local_http,
                                )
                                .await?;
                                (
                                    installed.command,
                                    installed.args,
                                    Some(installed.cwd.display().to_string()),
                                    installed.env,
                                )
                            } else {
                                (
                                    pkg.command.clone(),
                                    pkg.args.clone(),
                                    Some(workspace.display().to_string()),
                                    BTreeMap::new(),
                                )
                            };
                        kernel
                            .mcp_firewall
                            .register_stdio_server(
                                org_id,
                                &cand.server_id,
                                &spawn_cmd,
                                spawn_args,
                                spawn_cwd,
                                env_vars,
                                stdio_policy,
                            )
                            .await?;
                        let cand_ver = cand
                            .version
                            .clone()
                            .or_else(|| cand.package_spec.as_ref().and_then(|p| p.version.clone()));
                        let _ = kernel
                            .mcp_firewall
                            .update_server_config(org_id, &cand.server_id, |rec| {
                                rec.registry_name = Some(cand.name.clone());
                                rec.installed_version = cand_ver;
                                rec.manifest_sha256 = Some(cand.manifest_sha256.clone());
                            })
                            .await;
                    }
                    installed_ids.insert(cand.server_id.clone());
                    installed_count += 1;
                    results.push(json!({
                        "server_id": cand.server_id,
                        "source": rel,
                        "status": "installed",
                        "transport": cand.transport_kind,
                    }));
                }
            }
        }
    }

    let mut synced_client_entries = 0usize;
    if sync_clients && !dry_run {
        let bin_str = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("aegis-os"))
            .display()
            .to_string();
        let rt_str = runtime_dir.display().to_string();
        let org_servers = kernel.mcp_firewall.list_servers(Some(org_id)).await;
        for (client, cfg_path, _) in
            aos_mcp_gateway::mcp_firewall::client_config_candidates(home, workspace)
        {
            if !should_sync_detected_client_config(home, client, &cfg_path) {
                continue;
            }
            for srv in &org_servers {
                let proxy_args = vec![
                    "--org".to_string(),
                    org_id.to_string(),
                    "--agent".to_string(),
                    "auto".to_string(),
                    "--runtime-dir".to_string(),
                    rt_str.clone(),
                    "mcp".to_string(),
                    "proxy".to_string(),
                    srv.server_id.clone(),
                ];
                if aos_mcp_gateway::mcp_firewall::upsert_client_proxy_entry(
                    client,
                    &cfg_path,
                    &srv.server_id,
                    &bin_str,
                    &proxy_args,
                    None,
                )
                .unwrap_or(false)
                {
                    synced_client_entries += 1;
                }
            }
        }
    }

    Ok(json!({
        "status": "synced",
        "org_id": org_id,
        "dry_run": dry_run,
        "installed_count": installed_count,
        "up_to_date_count": up_to_date_count,
        "synced_client_entries": synced_client_entries,
        "items": results,
    }))
}

pub(super) async fn run_mcp_upgrade_lifecycle(
    org_id: &str,
    server_id_filter: Option<&str>,
    workspace: &Path,
    runtime_dir: &Path,
    allow_local_http: bool,
    dry_run: bool,
) -> anyhow::Result<Value> {
    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    kernel.mcp_registry.clear_cache().await;

    let airgap_origins = kernel.mcp_registry.airgap_allowed_origins();
    let servers = kernel.mcp_firewall.list_servers(Some(org_id)).await;
    let mut outcomes = Vec::<Value>::new();
    let mut upgraded_bundles = BTreeSet::<String>::new();

    for srv in servers {
        if let Some(target_id) = server_id_filter {
            if srv.server_id != target_id {
                continue;
            }
        }

        if let Some(ref bid) = srv.bundle_id {
            if !upgraded_bundles.insert(bid.clone()) {
                continue;
            }
            if let Some(existing_bundle) = kernel.mcp_bundles.get_bundle(org_id, bid).await {
                let eff_local = allow_local_http || srv.allow_local_http;
                let latest = kernel
                    .mcp_bundles
                    .install_bundle(
                        org_id,
                        &existing_bundle.source,
                        BundleInstallOptions {
                            profile: existing_bundle.profile.clone(),
                            sync_clients: false,
                            sync_skills: !dry_run,
                            workspace_dir: Some(workspace.to_path_buf()),
                            home_dir: None,
                            proxy_bin_path: None,
                            allow_local_http: eff_local,
                            dry_run,
                            preserve_existing_policies: true,
                            airgap_allowed_origins: airgap_origins.clone(),
                            ..BundleInstallOptions::default()
                        },
                    )
                    .await?;
                let changed = latest.version != existing_bundle.version
                    || serde_json::to_vec(&latest.manifest).ok()
                        != serde_json::to_vec(&existing_bundle.manifest).ok();
                let st = if !changed {
                    "up_to_date"
                } else if dry_run {
                    "upgrade_available"
                } else {
                    "upgraded"
                };
                outcomes.push(json!({
                    "server_id": srv.server_id,
                    "bundle_id": bid,
                    "status": st,
                    "from_version": existing_bundle.version,
                    "to_version": latest.version,
                }));
                continue;
            }
        }

        let lookup_target = srv
            .registry_name
            .as_deref()
            .filter(|n| n.contains('/') || n.starts_with("npm:") || n.starts_with("pypi:") || n.starts_with("oci:") || n.starts_with("mcpb:"))
            .or(srv.source_target.as_deref());
        let Some(lookup) = lookup_target else {
            outcomes.push(json!({
                "server_id": srv.server_id,
                "status": "skipped",
                "reason": "no_upstream_source",
            }));
            continue;
        };

        let eff_local = allow_local_http || srv.allow_local_http;
        let ResolvedInstallTarget::Candidate(cand) = kernel
            .mcp_registry
            .resolve_install_target(lookup, Some(&srv.server_id), eff_local)
            .await?
        else {
            outcomes.push(json!({
                "server_id": srv.server_id,
                "status": "skipped",
                "reason": "resolved_non_candidate",
            }));
            continue;
        };

        let next_ver = cand
            .version
            .clone()
            .or_else(|| cand.package_spec.as_ref().and_then(|p| p.version.clone()));
        let same_manifest = srv.manifest_sha256.as_deref() == Some(cand.manifest_sha256.as_str())
            && srv.installed_version == next_ver;
        if same_manifest {
            outcomes.push(json!({
                "server_id": srv.server_id,
                "status": "up_to_date",
                "version": srv.installed_version,
                "manifest_sha256": srv.manifest_sha256,
            }));
            continue;
        }
        if dry_run {
            outcomes.push(json!({
                "server_id": srv.server_id,
                "status": "upgrade_available",
                "from_version": srv.installed_version,
                "to_version": next_ver,
                "from_manifest_sha256": srv.manifest_sha256,
                "to_manifest_sha256": cand.manifest_sha256,
            }));
            continue;
        }

        if let Some(ref url) = cand.remote_url {
            kernel
                .mcp_firewall
                .upgrade_server_transport(
                    org_id,
                    &srv.server_id,
                    Some(url),
                    None,
                    Some(&cand.allowed_hosts),
                    next_ver.clone(),
                    Some(cand.manifest_sha256.clone()),
                    Some(cand.name.clone()),
                )
                .await?;
        } else if let Some(ref pkg) = cand.package_spec {
            if pkg.registry_type == "mcpb" {
                let installed = aos_mcp_gateway::mcp_mcpb::install_mcpb_archive(
                    &pkg.identifier,
                    pkg.file_sha256.as_deref(),
                    &srv.server_id,
                    kernel.mcp_registry.runtime_data_root(),
                    eff_local,
                )
                .await?;
                kernel
                    .mcp_firewall
                    .upgrade_server_transport(
                        org_id,
                        &srv.server_id,
                        None,
                        Some((
                            &installed.command,
                            installed.args,
                            Some(installed.cwd.display().to_string()),
                            installed.env,
                        )),
                        Some(&cand.allowed_hosts),
                        next_ver.clone(),
                        Some(cand.manifest_sha256.clone()),
                        Some(cand.name.clone()),
                    )
                    .await?;
            } else {
                kernel
                    .mcp_firewall
                    .upgrade_server_transport(
                        org_id,
                        &srv.server_id,
                        None,
                        Some((
                            &pkg.command,
                            pkg.args.clone(),
                            None,
                            BTreeMap::new(),
                        )),
                        Some(&cand.allowed_hosts),
                        next_ver.clone(),
                        Some(cand.manifest_sha256.clone()),
                        Some(cand.name.clone()),
                    )
                    .await?;
            }
        }
        outcomes.push(json!({
            "server_id": srv.server_id,
            "status": "upgraded",
            "from_version": srv.installed_version,
            "to_version": next_ver,
            "manifest_sha256": cand.manifest_sha256,
        }));
    }

    Ok(json!({
        "status": "ok",
        "org_id": org_id,
        "dry_run": dry_run,
        "checked": outcomes.len(),
        "servers": outcomes,
    }))
}
