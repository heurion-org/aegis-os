use super::*;

pub(crate) struct UninstallOptions<'a> {
    pub home_dir: &'a Path,
    pub runtime_dir: &'a Path,
    pub workspace: &'a Path,
    pub shim_only: bool,
    pub purge: bool,
    pub workspace_clean: bool,
    pub dry_run: bool,
    pub yes: bool,
    /// Only `true` when uninstalling the real `$HOME` (`--home-dir` omitted), so isolated
    /// tests / `--home-dir` runs never touch the host Keychain KEK or `/tmp/aegis-os-runtime`.
    pub purge_host_credentials: bool,
}

pub(super) fn remove_marked_block(existing: &str, start: &str, end: &str) -> Option<String> {
    let s = existing.find(start)?;
    let search_from = s + start.len();
    let e_rel = existing[search_from..].find(end)?;
    let e = search_from + e_rel;
    let head = existing[..s].trim_end();
    let tail = existing[e + end.len()..].trim_start_matches(['\r', '\n']);
    let mut out = String::new();
    out.push_str(head);
    if !head.is_empty() && !tail.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(tail);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    Some(out)
}

pub(super) fn strip_all_marked_blocks(existing: &str, start: &str, end: &str) -> Option<String> {
    let mut current = remove_marked_block(existing, start, end)?;
    while let Some(next) = remove_marked_block(&current, start, end) {
        current = next;
    }
    Some(current)
}

pub(super) fn remove_marked_block_from_file(
    path: &Path,
    start: &str,
    end: &str,
    dry_run: bool,
) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let existing = std::fs::read_to_string(path)?;
    let Some(updated) = strip_all_marked_blocks(&existing, start, end) else {
        return Ok(false);
    };
    if !dry_run {
        if updated.trim().is_empty() {
            std::fs::remove_file(path)?;
        } else {
            std::fs::write(path, updated)?;
        }
    }
    Ok(true)
}

pub(super) fn remove_dir_if_empty(dir: &Path, dry_run: bool) {
    if !dir.is_dir() {
        return;
    }
    let is_empty = std::fs::read_dir(dir)
        .map(|mut rd| rd.next().is_none())
        .unwrap_or(false);
    if is_empty && !dry_run {
        let _ = std::fs::remove_dir(dir);
    }
}

pub(super) fn prune_if_empty(map: &mut serde_json::Map<String, Value>, key: &str) {
    let should_remove = match map.get(key) {
        Some(Value::Object(obj)) => obj.is_empty(),
        Some(Value::Array(arr)) => arr.is_empty(),
        _ => false,
    };
    if should_remove {
        map.remove(key);
    }
}

pub(super) fn clean_json_file(
    path: &Path,
    mutator: impl FnOnce(&mut Value) -> bool,
    delete_if_empty_obj: bool,
    dry_run: bool,
) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(path)?;
    let mut root: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(err) => {
            eprintln!(
                "  ! skipped {} (invalid JSON: {}; left untouched)",
                path.display(),
                err
            );
            return Ok(false);
        }
    };
    if !root.is_object() {
        return Ok(false);
    }
    if !mutator(&mut root) {
        return Ok(false);
    }
    let is_empty = delete_if_empty_obj
        && root
            .as_object()
            .map(|obj| obj.is_empty())
            .unwrap_or(false);
    if !dry_run {
        if is_empty {
            std::fs::remove_file(path)?;
        } else {
            std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
        }
    }
    Ok(true)
}

pub(super) fn strip_aegis_permissions(
    perms_val: &mut Value,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let Some(perms) = perms_val.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    for list_key in ["allow", "ask"] {
        if let Some(arr) = perms.get_mut(list_key).and_then(|v| v.as_array_mut()) {
            let before = arr.len();
            arr.retain(|v| v.as_str().map(|s| !predicate(s)).unwrap_or(true));
            if arr.len() != before {
                changed = true;
            }
        }
        prune_if_empty(perms, list_key);
    }
    changed
}

pub(super) fn strip_aegis_hooks_object(hooks_val: &mut Value) -> bool {
    let Some(hobj) = hooks_val.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    let keys: Vec<String> = hobj.keys().cloned().collect();
    for key in keys {
        if let Some(arr) = hobj.get_mut(&key).and_then(|v| v.as_array_mut()) {
            if strip_aegis_from_hook_array(arr) {
                changed = true;
            }
        }
        prune_if_empty(hobj, &key);
    }
    changed
}

pub(super) fn remove_shell_path_block(home_dir: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut modified = Vec::new();
    for name in [
        ".zshrc",
        ".bashrc",
        ".profile",
        ".config/fish/config.fish",
    ] {
        let path = home_dir.join(name);
        let Ok(existing) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Some(updated) = strip_all_marked_blocks(&existing, PATH_BLOCK_START, PATH_BLOCK_END) else {
            continue;
        };
        if !dry_run {
            std::fs::write(&path, updated)?;
        }
        modified.push(path);
    }
    Ok(modified)
}

pub(super) fn clean_agy_configs(home_dir: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut touched = Vec::new();
    let agy_dir = home_dir.join(".gemini").join("config");

    let mcp_path = agy_dir.join("mcp_config.json");
    if clean_json_file(
        &mcp_path,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            if let Some(servers) = obj.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
                if servers.remove("aegis-os").is_some() {
                    changed = true;
                }
            }
            prune_if_empty(obj, "mcpServers");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(mcp_path);
    }

    let hooks_path = agy_dir.join("hooks.json");
    if clean_json_file(
        &hooks_path,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            for key in ["aegis-os-runtime-guard", "aegis-os-global-guard"] {
                if obj.remove(key).is_some() {
                    changed = true;
                }
            }
            if let Some(hooks) = obj.get_mut("hooks") {
                if strip_aegis_hooks_object(hooks) {
                    changed = true;
                }
            }
            prune_if_empty(obj, "hooks");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(hooks_path);
    }

    let cli_settings_path = home_dir
        .join(".gemini")
        .join("antigravity-cli")
        .join("settings.json");
    if clean_json_file(
        &cli_settings_path,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let changed = obj
                .get_mut("permissions")
                .map(|p| strip_aegis_permissions(p, |s| s == "mcp(aegis-os)" || s.starts_with("mcp(aegis-os/")))
                .unwrap_or(false);
            prune_if_empty(obj, "permissions");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(cli_settings_path);
    }

    let gemini_md = agy_dir.join("GEMINI.md");
    if remove_marked_block_from_file(
        &gemini_md,
        "<!-- AEGIS-OS-RUNTIME-START -->",
        "<!-- AEGIS-OS-RUNTIME-END -->",
        dry_run,
    )? {
        touched.push(gemini_md);
    }
    if let Some(p) = clean_runtime_skill(&agy_dir.join("skills"), dry_run)? {
        touched.push(p);
    }
    Ok(touched)
}

pub(super) fn clean_claude_configs(home_dir: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut touched = Vec::new();

    let claude_mcp = home_dir.join(".claude.json");
    if clean_json_file(
        &claude_mcp,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            if let Some(servers) = obj.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
                if servers.remove("aegis-os").is_some() {
                    changed = true;
                }
            }
            prune_if_empty(obj, "mcpServers");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(claude_mcp);
    }

    let claude_dir = home_dir.join(".claude");
    let claude_settings = claude_dir.join("settings.json");
    if clean_json_file(
        &claude_settings,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            if let Some(perms) = obj.get_mut("permissions") {
                if strip_aegis_permissions(perms, |s| {
                    s == "mcp__aegis-os" || s.starts_with("mcp__aegis-os__")
                }) {
                    changed = true;
                }
            }
            prune_if_empty(obj, "permissions");
            if let Some(hooks) = obj.get_mut("hooks") {
                if strip_aegis_hooks_object(hooks) {
                    changed = true;
                }
            }
            prune_if_empty(obj, "hooks");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(claude_settings);
    }

    let claude_md = claude_dir.join("CLAUDE.md");
    if remove_marked_block_from_file(
        &claude_md,
        "<!-- AEGIS-OS-RUNTIME-START -->",
        "<!-- AEGIS-OS-RUNTIME-END -->",
        dry_run,
    )? {
        touched.push(claude_md);
    }
    if let Some(p) = clean_runtime_skill(&claude_dir.join("skills"), dry_run)? {
        touched.push(p);
    }
    Ok(touched)
}

pub(super) fn clean_codex_configs(home_dir: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut touched = Vec::new();
    let codex_dir = home_dir.join(".codex");

    let codex_toml = codex_dir.join("config.toml");
    if remove_marked_block_from_file(
        &codex_toml,
        "# --- AEGIS-OS-RUNTIME-START ---",
        "# --- AEGIS-OS-RUNTIME-END ---",
        dry_run,
    )? {
        touched.push(codex_toml);
    }

    let codex_md = codex_dir.join("AGENTS.md");
    if remove_marked_block_from_file(
        &codex_md,
        "<!-- AEGIS-OS-RUNTIME-START -->",
        "<!-- AEGIS-OS-RUNTIME-END -->",
        dry_run,
    )? {
        touched.push(codex_md);
    }
    if let Some(p) = clean_runtime_skill(&codex_dir.join("skills"), dry_run)? {
        touched.push(p);
    }
    Ok(touched)
}

pub(super) fn clean_opencode_configs(home_dir: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut touched = Vec::new();
    let opencode_dir = home_dir.join(".config").join("opencode");

    let plugins_dir = opencode_dir.join("plugins");
    let plugin = plugins_dir.join("aegis-os.js");
    if plugin.exists() {
        if !dry_run {
            std::fs::remove_file(&plugin)?;
        }
        remove_dir_if_empty(&plugins_dir, dry_run);
        touched.push(plugin);
    }

    let opencode_json = opencode_dir.join("opencode.json");
    if clean_json_file(
        &opencode_json,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            if let Some(mcp) = obj.get_mut("mcp").and_then(|v| v.as_object_mut()) {
                if let Some(servers) = mcp.get_mut("servers").and_then(|v| v.as_object_mut()) {
                    if servers.remove("aegis-os").is_some() {
                        changed = true;
                    }
                }
                prune_if_empty(mcp, "servers");
            }
            prune_if_empty(obj, "mcp");

            if let Some(plugins) = obj.get_mut("plugin").and_then(|v| v.as_array_mut()) {
                let before = plugins.len();
                plugins.retain(|v| {
                    v.as_str()
                        .map(|s| !s.ends_with("aegis-os.js"))
                        .unwrap_or(true)
                });
                if plugins.len() != before {
                    changed = true;
                }
            }
            prune_if_empty(obj, "plugin");

            // Drop Aegis-inserted top-level defaults if no user-owned settings remain.
            if changed {
                let only_aegis_defaults = obj.iter().all(|(k, v)| match k.as_str() {
                    "$schema" => v == &json!("https://opencode.ai/config.json"),
                    "snapshots" => v == &json!(false),
                    _ => false,
                });
                if only_aegis_defaults {
                    obj.clear();
                }
            }
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(opencode_json);
    }

    let opencode_md = opencode_dir.join("AGENTS.md");
    if remove_marked_block_from_file(
        &opencode_md,
        "<!-- AEGIS-OS-RUNTIME-START -->",
        "<!-- AEGIS-OS-RUNTIME-END -->",
        dry_run,
    )? {
        touched.push(opencode_md);
    }
    if let Some(p) = clean_runtime_skill(&opencode_dir.join("skills"), dry_run)? {
        touched.push(p);
    }
    Ok(touched)
}

pub(super) fn clean_workspace_agents(workspace: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut touched = Vec::new();
    let agents_dir = workspace.join(".agents");
    if !agents_dir.exists() {
        return Ok(touched);
    }

    let hooks_path = agents_dir.join("hooks.json");
    if clean_json_file(
        &hooks_path,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            for key in ["aegis-os-runtime-guard", "aegis-os-global-guard"] {
                if obj.remove(key).is_some() {
                    changed = true;
                }
            }
            if let Some(hooks) = obj.get_mut("hooks") {
                if strip_aegis_hooks_object(hooks) {
                    changed = true;
                }
            }
            prune_if_empty(obj, "hooks");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(hooks_path);
    }

    let rules_dir = agents_dir.join("rules");
    let rule_file = rules_dir.join("aegis-os-workflow.md");
    if rule_file.exists() && file_mentions_aegis(&rule_file) {
        if !dry_run {
            std::fs::remove_file(&rule_file)?;
        }
        remove_dir_if_empty(&rules_dir, dry_run);
        touched.push(rule_file);
    }

    let snippet = agents_dir.join("mcp_config.snippet.json");
    if clean_json_file(
        &snippet,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            if let Some(servers) = obj.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
                if servers.remove("aegis-os").is_some() {
                    changed = true;
                }
            }
            prune_if_empty(obj, "mcpServers");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(snippet);
    }

    let readme = agents_dir.join("README.md");
    if readme.exists() {
        let is_aegis_readme = std::fs::read_to_string(&readme)
            .map(|text| text.contains("Protected by Aegis OS"))
            .unwrap_or(false);
        if is_aegis_readme {
            if !dry_run {
                std::fs::remove_file(&readme)?;
            }
            touched.push(readme);
        }
    }

    remove_dir_if_empty(&agents_dir, dry_run);
    Ok(touched)
}

pub(super) fn is_tty_stdin() -> bool {
    #[cfg(test)]
    {
        false
    }
    #[cfg(all(unix, not(test)))]
    {
        unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
    }
    #[cfg(all(not(unix), not(test)))]
    {
        false
    }
}

pub(super) fn remove_kek_file_if_exists(path: &Path, dry_run: bool) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    if !dry_run {
        std::fs::remove_file(path)?;
        if let Some(parent) = path.parent() {
            remove_dir_if_empty(parent, false);
        }
    }
    Ok(true)
}

pub(super) fn delete_os_keychain_keks(dry_run: bool) -> Vec<String> {
    let mut actions = Vec::new();
    #[cfg(target_os = "macos")]
    {
        if dry_run {
            actions.push("macOS Keychain item `dev.aegis-os.vault.master-kek`".to_string());
        } else {
            let mut deleted = 0usize;
            for _ in 0..4 {
                let Ok(status) = std::process::Command::new("/usr/bin/security")
                    .args([
                        "delete-generic-password",
                        "-s",
                        "dev.aegis-os.vault.master-kek",
                        "-a",
                        "local-runtime",
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                else {
                    break;
                };
                if status.success() {
                    deleted += 1;
                } else {
                    break;
                }
            }
            if deleted > 0 {
                actions.push(format!(
                    "removed macOS Keychain item `dev.aegis-os.vault.master-kek` ({deleted} entry)"
                ));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if dry_run {
            actions.push("Linux Secret Service item `dev.aegis-os.vault.master-kek`".to_string());
        } else if let Ok(status) = std::process::Command::new("secret-tool")
            .args([
                "clear",
                "service",
                "dev.aegis-os.vault.master-kek",
                "account",
                "local-runtime",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            if status.success() {
                actions.push("removed Linux Secret Service item `dev.aegis-os.vault.master-kek`".to_string());
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = dry_run;
    actions
}

pub(super) fn purge_runtime_root(runtime_root: &Path, dry_run: bool, label: &str) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    let vault_mgr = aos_vfs::vault::OrgVaultManager::new(runtime_root);
    let statuses = vault_mgr.list_org_statuses().unwrap_or_default();

    if dry_run {
        if runtime_root.exists() || !statuses.is_empty() {
            logs.push(format!(
                "[dry-run] would lock/destroy {} OrgVault(s) and remove {} ({})",
                statuses.len(),
                runtime_root.display(),
                label
            ));
        }
        return Ok(logs);
    }

    if !statuses.is_empty() {
        if let Err(err) = vault_mgr.lock_all() {
            eprintln!("  ! warning: lock_all({}) failed before purge: {}", runtime_root.display(), err);
        }
        for st in &statuses {
            match vault_mgr.destroy_org(&st.org_id) {
                Ok(()) => logs.push(format!("destroyed OrgVault `{}` ({})", st.org_id, label)),
                Err(err) => eprintln!(
                    "  ! warning: destroy_org({}) failed: {}",
                    st.org_id, err
                ),
            }
        }
    }

    if runtime_root.exists() {
        std::fs::remove_dir_all(runtime_root).with_context(|| {
            format!("removing runtime directory {}", runtime_root.display())
        })?;
        logs.push(format!("removed {} ({})", runtime_root.display(), label));
    }
    Ok(logs)
}

pub(super) fn confirm_purge(runtime_dir: &Path, home_aegis: &Path, vault_count: usize) -> anyhow::Result<()> {
    if !is_tty_stdin() {
        anyhow::bail!(
            "`aegis-os uninstall --purge` permanently destroys runtime state and {} OrgVault(s) under {}; pass `--yes` (`-y`) to confirm",
            vault_count,
            runtime_dir.display()
        );
    }
    eprint!(
        "⚠️  Permanently lock/destroy {} OrgVault(s), delete {}, and remove KEK material? [y/N]: ",
        vault_count,
        if runtime_dir == home_aegis {
            runtime_dir.display().to_string()
        } else {
            format!("{} and {}", runtime_dir.display(), home_aegis.display())
        }
    );
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    if answer != "y" && answer != "yes" {
        anyhow::bail!("aborted `aegis-os uninstall --purge`");
    }
    Ok(())
}

pub(crate) async fn run_uninstall(opts: UninstallOptions<'_>) -> anyhow::Result<()> {
    let verb = if opts.dry_run { "would remove" } else { "removed" };
    let updated_verb = if opts.dry_run { "would update/clean" } else { "cleaned" };

    println!("=========================================================================");
    println!(
        "  Aegis OS Uninstaller{}",
        if opts.dry_run { " (dry-run)" } else { "" }
    );
    println!("  Home Dir:    {}", opts.home_dir.display());
    println!("  Runtime Dir: {}", opts.runtime_dir.display());
    println!("=========================================================================\n");

    // Pre-flight purge confirmation BEFORE mutating client configs or shims so an aborted
    // `--purge` leaves the user's installation intact.
    let vault_mgr = aos_vfs::vault::OrgVaultManager::new(opts.runtime_dir);
    let vault_statuses = vault_mgr.list_org_statuses().unwrap_or_default();
    let home_aegis = opts.home_dir.join(".aegis");
    if opts.purge
        && !opts.dry_run
        && !opts.yes
        && (opts.runtime_dir.exists() || home_aegis.exists() || !vault_statuses.is_empty())
    {
        confirm_purge(opts.runtime_dir, &home_aegis, vault_statuses.len())?;
    }

    // 1. Remove PATH shims and shell RC PATH block.
    let shim_dir = home_aegis.join("bin");
    let mut removed_shims = Vec::new();
    for agent in SUPPORTED_SHIM_AGENTS {
        let path = shim_dir.join(agent);
        if path.exists() {
            if !opts.dry_run {
                std::fs::remove_file(&path)?;
            }
            removed_shims.push(path);
        }
    }
    remove_dir_if_empty(&shim_dir, opts.dry_run);
    let modified_rc = remove_shell_path_block(opts.home_dir, opts.dry_run)?;

    println!("[1/4] PATH shims & shell profile:");
    if removed_shims.is_empty() && modified_rc.is_empty() {
        println!("      - none found");
    } else {
        for p in &removed_shims {
            println!("      - {} {}", verb, p.display());
        }
        for rc in &modified_rc {
            println!("      - {} PATH block in {}", updated_verb, rc.display());
        }
    }

    // 2. Surgically strip client MCP/Hook/rule integrations unless `--shim-only`.
    let mut cleaned_clients = Vec::new();
    if opts.shim_only {
        println!("\n[2/4] Client integrations: skipped (--shim-only)");
    } else {
        cleaned_clients.extend(clean_agy_configs(opts.home_dir, opts.dry_run)?);
        cleaned_clients.extend(clean_claude_configs(opts.home_dir, opts.dry_run)?);
        cleaned_clients.extend(clean_codex_configs(opts.home_dir, opts.dry_run)?);
        cleaned_clients.extend(clean_opencode_configs(opts.home_dir, opts.dry_run)?);
        println!("\n[2/4] Global client integrations (AGY, Claude Code, Codex, OpenCode):");
        if cleaned_clients.is_empty() {
            println!("      - no Aegis entries found");
        } else {
            for path in &cleaned_clients {
                let label = if opts.dry_run {
                    "would clean/remove"
                } else if path.exists() {
                    updated_verb
                } else {
                    verb
                };
                println!("      - {} {}", label, path.display());
            }
        }
    }

    // 3. Optional workspace `.agents/` cleanup (`--workspace-clean`).
    if opts.workspace_clean {
        let ws_touched = clean_workspace_agents(opts.workspace, opts.dry_run)?;
        println!("\n[3/4] Workspace `.agents/` ({}):", opts.workspace.display());
        if ws_touched.is_empty() {
            println!("      - no Aegis workspace integration files found");
        } else {
            for path in &ws_touched {
                let label = if opts.dry_run {
                    "would clean/remove"
                } else if path.exists() {
                    updated_verb
                } else {
                    verb
                };
                println!("      - {} {}", label, path.display());
            }
        }
    } else {
        println!("\n[3/4] Workspace `.agents/`: left untouched (pass --workspace-clean to remove)");
    }

    // 4. Optional full runtime, OrgVault, and KEK purge (`--purge`).
    if opts.purge {
        println!("\n[4/4] Runtime state, OrgVaults & KEK purge:");
        let mut purge_logs = purge_runtime_root(opts.runtime_dir, opts.dry_run, "runtime_dir")?;
        if home_aegis != opts.runtime_dir && home_aegis.exists() {
            purge_logs.extend(purge_runtime_root(&home_aegis, opts.dry_run, "home .aegis")?);
        }

        let local_kek = opts.home_dir.join(".config/aegis-os/master.kek");
        if remove_kek_file_if_exists(&local_kek, opts.dry_run)? {
            purge_logs.push(format!("{} {}", verb, local_kek.display()));
        }
        let runtime_kek = opts.runtime_dir.join(".master.kek");
        if remove_kek_file_if_exists(&runtime_kek, opts.dry_run)? {
            purge_logs.push(format!("{} {}", verb, runtime_kek.display()));
        }

        if opts.purge_host_credentials {
            if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
                let xdg_kek = PathBuf::from(xdg).join("aegis-os").join("master.kek");
                if xdg_kek != local_kek && remove_kek_file_if_exists(&xdg_kek, opts.dry_run)? {
                    purge_logs.push(format!("{} {}", verb, xdg_kek.display()));
                }
            }
            for legacy_tmp in ["/tmp/aegis-os-runtime", "/private/tmp/aegis-os-runtime"] {
                let tmp_path = Path::new(legacy_tmp);
                if tmp_path.exists() {
                    #[cfg(unix)]
                    let owned_by_user = {
                        use std::os::unix::fs::MetadataExt;
                        std::fs::symlink_metadata(tmp_path)
                            .map(|m| m.uid() == unsafe { libc::geteuid() })
                            .unwrap_or(false)
                    };
                    #[cfg(not(unix))]
                    let owned_by_user = true;
                    if owned_by_user {
                        purge_logs.extend(purge_runtime_root(
                            tmp_path,
                            opts.dry_run,
                            "legacy tmp runtime",
                        )?);
                    }
                }
            }
            purge_logs.extend(delete_os_keychain_keks(opts.dry_run));
        }

        if purge_logs.is_empty() {
            println!("      - no runtime state or vault artifacts found");
        } else {
            for line in &purge_logs {
                println!("      - {}", line);
            }
        }
    } else {
        println!("\n[4/4] Runtime state & OrgVaults: preserved");
        if opts.runtime_dir.exists() || home_aegis.exists() {
            println!(
                "      - Shadow workspaces and encrypted OrgVaults under `{}` were preserved.",
                opts.runtime_dir.display()
            );
            println!(
                "      - Pass `--purge --yes` to unmount/destroy all OrgVaults, shadow state, and KEKs."
            );
        }
    }

    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
    let remove_bin_hint = match detect_install_method(&current_exe, opts.workspace, "auto", None) {
        Ok(InstallMethod::Homebrew { .. }) => "brew uninstall aegis-os".to_string(),
        Ok(InstallMethod::CargoGit { .. }) => "cargo uninstall aos-cli".to_string(),
        _ if current_exe.to_string_lossy().contains("/.cargo/bin/") => {
            "cargo uninstall aos-cli".to_string()
        }
        _ => format!("rm -f \"{}\"", current_exe.display()),
    };
    println!("\nNote: The `aegis-os` binary itself cannot unlink while running.");
    println!("      To remove the CLI binary too, run: {}", remove_bin_hint);
    Ok(())
}
