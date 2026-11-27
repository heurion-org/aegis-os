use crate::*;

pub(crate) const PKG_MANIFEST_FILES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lockb",
    "bun.lock",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
];

pub(crate) struct PkgInstallPlan {
    pub(crate) manager: String,
    pub(crate) packages: Vec<String>,
    pub(crate) cwd_rel: String,
    pub(crate) target_dir: PathBuf,
    pub(crate) shadow_root: PathBuf,
    pub(crate) host_root: PathBuf,
    pub(crate) agent_home_dir: PathBuf,
    pub(crate) org_shared_ro_dir: PathBuf,
    pub(crate) org_agent_pub_dir: PathBuf,
    pub(crate) dev: bool,
    pub(crate) allow_scripts: bool,
    pub(crate) offline: bool,
    pub(crate) timeout_ms: u64,
    pub(crate) registry_domains: Vec<String>,
    pub(crate) pre_manifest_hashes: std::collections::BTreeMap<String, String>,
    pub(crate) evidence_hash: String,
}

pub(crate) struct ProxyAbortGuard(Option<tokio::task::JoinHandle<()>>);

impl Drop for ProxyAbortGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

pub(crate) fn is_safe_package_spec(spec: &str) -> bool {
    if spec.is_empty() || spec.len() > 160 || spec.trim() != spec {
        return false;
    }
    let Some(first) = spec.chars().next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || first == '@') {
        return false;
    }
    if spec.contains("..")
        || spec.contains("://")
        || spec.contains("git+")
        || spec.contains("file:")
        || spec.contains("ssh:")
    {
        return false;
    }
    spec.chars().all(|c| {
        c.is_ascii()
            && !c.is_control()
            && !c.is_whitespace()
            && !matches!(
                c,
                ';' | '|' | '&' | '$' | '`' | '(' | ')' | '{' | '}' | '<' | '>' | '\\' | '\'' | '"' | '?' | '#'
            )
    })
}

pub(crate) fn hash_pkg_manifests(target_dir: &Path) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    let mut hashes = std::collections::BTreeMap::new();
    for name in PKG_MANIFEST_FILES {
        let p = target_dir.join(name);
        match std::fs::symlink_metadata(&p) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!(
                    "Refusing package operation: manifest '{}' is a symlink",
                    p.display()
                );
            }
            Ok(meta) if meta.is_file() => {
                let bytes = std::fs::read(&p)?;
                hashes.insert((*name).to_string(), format!("sha256:{}", hex::encode(Sha256::digest(&bytes))));
            }
            Ok(_) => {
                hashes.insert((*name).to_string(), "NON_FILE".to_string());
            }
            Err(_) => {
                hashes.insert((*name).to_string(), "ABSENT".to_string());
            }
        }
    }
    Ok(hashes)
}

pub(crate) async fn execute_pkg_install(
    identity: &AgentIdentity,
    plan: PkgInstallPlan,
) -> anyhow::Result<Value> {
    let current_hashes = hash_pkg_manifests(&plan.target_dir)?;
    if current_hashes != plan.pre_manifest_hashes {
        bail!(
            "TOCTOU integrity error: package manifest/lockfile state in '{}' changed after approval",
            plan.cwd_rel
        );
    }

    let cache_root = plan.agent_home_dir.join("deps/cache");
    tokio::fs::create_dir_all(&cache_root).await?;

    let mut env = HashMap::new();
    let (cmd, cmd_args): (String, Vec<String>) = match plan.manager.as_str() {
        "npm" | "pnpm" | "yarn" | "bun" => {
            CoWWorkspace::isolate_shadow_dependency_dir(
                &plan.host_root,
                &plan.shadow_root,
                &plan.target_dir,
                "node_modules",
            )?;
            if plan.target_dir != plan.shadow_root {
                CoWWorkspace::isolate_shadow_dependency_dir(
                    &plan.host_root,
                    &plan.shadow_root,
                    &plan.shadow_root,
                    "node_modules",
                )?;
            }
            let mgr_cache = cache_root.join(&plan.manager);
            let pnpm_store = cache_root.join("pnpm-store");
            let pnpm_home = cache_root.join("pnpm-home");
            let xdg_cache = cache_root.join("xdg-cache");
            let xdg_data = cache_root.join("xdg-data");
            let xdg_state = cache_root.join("xdg-state");
            let yarn_cache = cache_root.join("yarn");
            let bun_cache = cache_root.join("bun");
            for dir in [
                &mgr_cache,
                &pnpm_store,
                &pnpm_home,
                &xdg_cache,
                &xdg_data,
                &xdg_state,
                &yarn_cache,
                &bun_cache,
            ] {
                tokio::fs::create_dir_all(dir).await?;
            }
            let cache_str = mgr_cache.display().to_string();
            let pnpm_store_str = pnpm_store.display().to_string();
            env.insert("NPM_CONFIG_USERCONFIG".to_string(), "/dev/null".to_string());
            env.insert("NPM_CONFIG_CACHE".to_string(), cache_str.clone());
            env.insert("npm_config_cache".to_string(), cache_str);
            env.insert("PNPM_STORE_DIR".to_string(), pnpm_store_str.clone());
            env.insert("npm_config_store_dir".to_string(), pnpm_store_str);
            env.insert("PNPM_HOME".to_string(), pnpm_home.display().to_string());
            env.insert("XDG_CACHE_HOME".to_string(), xdg_cache.display().to_string());
            env.insert("XDG_DATA_HOME".to_string(), xdg_data.display().to_string());
            env.insert("XDG_STATE_HOME".to_string(), xdg_state.display().to_string());
            env.insert("YARN_CACHE_FOLDER".to_string(), yarn_cache.display().to_string());
            env.insert("BUN_INSTALL_CACHE_DIR".to_string(), bun_cache.display().to_string());
            env.insert(
                "npm_config_registry".to_string(),
                "https://registry.npmjs.org/".to_string(),
            );
            env.insert("COREPACK_ENABLE_STRICT".to_string(), "0".to_string());
            env.insert("CI".to_string(), "true".to_string());
            if !plan.allow_scripts {
                env.insert("YARN_ENABLE_SCRIPTS".to_string(), "false".to_string());
            }

            let mut mgr_args: Vec<String> = match plan.manager.as_str() {
                "npm" => {
                    let mut a = vec![
                        "install".to_string(),
                        "--no-audit".to_string(),
                        "--no-fund".to_string(),
                    ];
                    if plan.dev && !plan.packages.is_empty() {
                        a.push("--save-dev".to_string());
                    }
                    a
                }
                _ => {
                    if plan.packages.is_empty() {
                        vec!["install".to_string()]
                    } else {
                        let mut a = vec!["add".to_string()];
                        if plan.dev {
                            a.push("-D".to_string());
                        }
                        a
                    }
                }
            };
            if !plan.allow_scripts {
                mgr_args.push("--ignore-scripts".to_string());
            }
            if plan.offline {
                mgr_args.push("--offline".to_string());
            }
            mgr_args.extend(plan.packages.iter().cloned());

            let mut sh_args = vec![
                "-c".to_string(),
                r#"cmd="$1"; shift; exec "$cmd" "$@""#.to_string(),
                "aegis-pkg".to_string(),
                plan.manager.clone(),
            ];
            sh_args.extend(mgr_args);
            ("sh".to_string(), sh_args)
        }
        "pip" | "uv" => {
            CoWWorkspace::isolate_shadow_dependency_dir(
                &plan.host_root,
                &plan.shadow_root,
                &plan.target_dir,
                ".venv",
            )?;
            let mgr_cache = cache_root.join(&plan.manager);
            tokio::fs::create_dir_all(&mgr_cache).await?;
            let cache_str = mgr_cache.display().to_string();
            env.insert("PIP_CONFIG_FILE".to_string(), "/dev/null".to_string());
            env.insert("PIP_CACHE_DIR".to_string(), cache_str.clone());
            env.insert("UV_CACHE_DIR".to_string(), cache_str);
            env.insert("UV_NO_CONFIG".to_string(), "1".to_string());
            env.insert(
                "PIP_INDEX_URL".to_string(),
                "https://pypi.org/simple".to_string(),
            );
            env.insert(
                "UV_INDEX_URL".to_string(),
                "https://pypi.org/simple".to_string(),
            );

            let mut py_args = Vec::new();
            let script = if plan.manager == "pip" {
                if plan.offline {
                    py_args.push("--no-index".to_string());
                }
                if !plan.allow_scripts {
                    py_args.push("--only-binary=:all:".to_string());
                }
                if plan.packages.is_empty() {
                    if plan.target_dir.join("requirements.txt").is_file() {
                        py_args.extend(["-r".to_string(), "requirements.txt".to_string()]);
                    } else {
                        py_args.push(".".to_string());
                    }
                } else {
                    py_args.extend(plan.packages.iter().cloned());
                }
                "if [ ! -x .venv/bin/python ]; then python3 -m venv .venv; fi; exec .venv/bin/pip install \"$@\""
            } else {
                if plan.offline {
                    py_args.push("--offline".to_string());
                }
                if plan.packages.is_empty() {
                    if plan.target_dir.join("requirements.txt").is_file() {
                        py_args.extend([
                            "--python".to_string(),
                            ".venv/bin/python".to_string(),
                            "-r".to_string(),
                            "requirements.txt".to_string(),
                        ]);
                        "if [ ! -x .venv/bin/python ]; then uv venv .venv; fi; exec uv pip install \"$@\""
                    } else {
                        "if [ ! -x .venv/bin/python ]; then uv venv .venv; fi; exec uv sync \"$@\""
                    }
                } else {
                    py_args.extend(["--python".to_string(), ".venv/bin/python".to_string()]);
                    py_args.extend(plan.packages.iter().cloned());
                    "if [ ! -x .venv/bin/python ]; then uv venv .venv; fi; exec uv pip install \"$@\""
                }
            };
            let mut sh_args = vec!["-c".to_string(), script.to_string(), "aegis-pkg".to_string()];
            sh_args.extend(py_args);
            ("sh".to_string(), sh_args)
        }
        "cargo" => {
            let cargo_home = plan.agent_home_dir.join("deps/cargo_home");
            tokio::fs::create_dir_all(cargo_home.join("registry")).await?;
            tokio::fs::create_dir_all(cargo_home.join("git")).await?;
            env.insert("CARGO_HOME".to_string(), cargo_home.display().to_string());
            env.insert("CARGO_NET_GIT_FETCH_WITH_CLI".to_string(), "false".to_string());

            let mut sh_args = Vec::new();
            let script = if plan.packages.is_empty() {
                if plan.offline {
                    sh_args.push("--offline".to_string());
                }
                r#"exec cargo fetch "$@""#
            } else {
                if plan.dev {
                    sh_args.push("--dev".to_string());
                }
                if plan.offline {
                    sh_args.push("--offline".to_string());
                }
                sh_args.extend(plan.packages.iter().cloned());
                if plan.offline {
                    r#"cargo add "$@" && cargo fetch --offline"#
                } else {
                    r#"cargo add "$@" && cargo fetch"#
                }
            };
            let mut full_args = vec!["-c".to_string(), script.to_string(), "aegis-pkg".to_string()];
            full_args.extend(sh_args);
            ("sh".to_string(), full_args)
        }
        "go" => {
            let go_path = plan.agent_home_dir.join("deps/go_path");
            let go_mod_cache = go_path.join("pkg/mod");
            let go_cache = cache_root.join("go-build");
            tokio::fs::create_dir_all(&go_mod_cache).await?;
            tokio::fs::create_dir_all(&go_cache).await?;
            env.insert("GOPATH".to_string(), go_path.display().to_string());
            env.insert("GOMODCACHE".to_string(), go_mod_cache.display().to_string());
            env.insert("GOCACHE".to_string(), go_cache.display().to_string());
            env.insert("GOTOOLCHAIN".to_string(), "local".to_string());
            env.insert(
                "GOPROXY".to_string(),
                if plan.offline {
                    "off".to_string()
                } else {
                    "https://proxy.golang.org,direct".to_string()
                },
            );
            env.insert(
                "GOSUMDB".to_string(),
                if plan.offline {
                    "off".to_string()
                } else {
                    "sum.golang.org".to_string()
                },
            );

            let mut go_args = Vec::new();
            if plan.packages.is_empty() {
                go_args.push("mod".to_string());
                go_args.push("download".to_string());
            } else {
                go_args.push("get".to_string());
                go_args.extend(plan.packages.iter().cloned());
            }
            let mut sh_args = vec![
                "-c".to_string(),
                r#"cmd="$1"; shift; exec "$cmd" "$@""#.to_string(),
                "aegis-pkg".to_string(),
                "go".to_string(),
            ];
            sh_args.extend(go_args);
            ("sh".to_string(), sh_args)
        }
        other => bail!("Unsupported package manager '{}'", other),
    };

    let (_proxy_guard, egress_proxy_addr) = if !plan.offline {
        let egress = Arc::new(AegisEgressGateway::new());
        egress
            .allow_domains(&identity.org_id, plan.registry_domains.clone())
            .await;
        let (addr, handle) = egress
            .start_local_proxy_abortable("127.0.0.1:0", Some(identity.clone()))
            .await?;
        (
            Some(ProxyAbortGuard(Some(handle))),
            Some(format!("http://{}", addr)),
        )
    } else {
        (None, None)
    };

    let sbx = NativeOsSandboxDriver
        .create_sandbox(SandboxConfig {
            identity: identity.clone(),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: plan.shadow_root.clone(),
            agent_home_dir: plan.agent_home_dir.clone(),
            org_shared_ro_dir: plan.org_shared_ro_dir.clone(),
            org_agent_pub_dir: plan.org_agent_pub_dir.clone(),
            egress_proxy_addr,
            host_source_dir: Some(plan.host_root.clone()),
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: true,
        })
        .await?;

    let out = sbx
        .exec(ExecSpec {
            command: cmd,
            args: cmd_args,
            cwd: Some(plan.target_dir.clone()),
            env,
            timeout_ms: Some(plan.timeout_ms),
            background: false,
        })
        .await?;

    let post_hashes = hash_pkg_manifests(&plan.target_dir).unwrap_or_default();
    let changed_manifests: Vec<String> = post_hashes
        .iter()
        .filter_map(|(k, v)| {
            if plan.pre_manifest_hashes.get(k) != Some(v) {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();
    let (stdout_redacted, _) = redact_dlp_secrets(&out.stdout);
    let (stderr_redacted, _) = redact_dlp_secrets(&out.stderr);
    let succeeded = out.exit_code == Some(0);

    Ok(json!({
        "status": if succeeded { "pkg_installed" } else { "pkg_install_failed" },
        "manager": plan.manager,
        "cwd": plan.cwd_rel,
        "packages": plan.packages,
        "exit_code": out.exit_code,
        "duration_ms": out.duration_ms,
        "sandbox_profile_used": out.sandbox_profile_used,
        "registry_domains": if plan.offline { Vec::<String>::new() } else { plan.registry_domains },
        "allow_scripts": plan.allow_scripts,
        "offline": plan.offline,
        "changed_manifests": changed_manifests,
        "host_modified": false,
        "stdout": stdout_redacted,
        "stderr": stderr_redacted,
        "evidence_hash": plan.evidence_hash,
    }))
}
