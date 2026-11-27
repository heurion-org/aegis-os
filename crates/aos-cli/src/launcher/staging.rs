use super::*;

pub(super) fn copy_path(src: &Path, dst: &Path) -> anyhow::Result<()> {
    let meta = std::fs::symlink_metadata(src)
        .with_context(|| format!("reading {}", src.display()))?;
    // Never follow symlinks out of the seeded config tree; a `~/.claude/foo -> ~/.ssh/id_rsa`
    // link must not copy a credential into the session home.
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        std::fs::create_dir_all(dst)
            .with_context(|| format!("creating {}", dst.display()))?;
        for entry in std::fs::read_dir(src)
            .with_context(|| format!("listing {}", src.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            let name_lossy = name.to_string_lossy();
            if SEED_SKIP_NAMES.iter().any(|skip| name_lossy == *skip)
                || name_lossy.starts_with("venv.")
            {
                continue;
            }
            copy_path(&entry.path(), &dst.join(&name))?;
        }
    } else if meta.is_file() {
        if meta.len() > MAX_SEED_FILE_BYTES {
            return Ok(());
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)
            .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    }
    Ok(())
}

pub(super) fn sanitize_seeded_agent_home(agent_home: &Path) -> anyhow::Result<()> {
    if aos_core::ablated("secret_vault") {
        return Ok(());
    }

    // 1. Scrub `~/.hermes/.env`: convert boundary-managed keys into `$AOS_SECRET_*` placeholders
    // and redact any other `*_API_KEY` / `*_TOKEN` / `*_SECRET` values so plaintext credentials
    // never enter the sandbox home.
    let hermes_env = agent_home.join(".hermes/.env");
    if hermes_env.is_file() {
        if let Ok(raw) = std::fs::read_to_string(&hermes_env) {
            let mut out_lines = Vec::new();
            for line in raw.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    out_lines.push(line.to_string());
                    continue;
                }
                let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed);
                if let Some((k, v)) = stripped.split_once('=') {
                    let key = k.trim();
                    let val = v.trim().trim_matches('"').trim_matches('\'');
                    if let Some(ph) = boundary_secret_placeholder(key) {
                        if !val.is_empty() {
                            out_lines.push(format!("{key}={ph}"));
                        }
                        continue;
                    }
                    let upper = key.to_ascii_uppercase();
                    if upper.ends_with("_API_KEY")
                        || upper.ends_with("_TOKEN")
                        || upper.ends_with("_SECRET")
                        || upper.ends_with("_PASSWORD")
                        || upper.contains("SECRET")
                        || upper.contains("PRIVATE_KEY")
                    {
                        out_lines.push(format!("# {key} redacted by aegis-os boundary vault"));
                        continue;
                    }
                }
                out_lines.push(line.to_string());
            }
            let _ = std::fs::write(&hermes_env, out_lines.join("\n") + "\n");
        }
    }

    // 2. Scrub `~/.local/share/opencode/auth.json`: replace raw provider API keys with their
    // scoped `$AOS_SECRET_*` placeholders and drop unrecognized credential entries.
    let opencode_auth = agent_home.join(".local/share/opencode/auth.json");
    if opencode_auth.is_file() {
        if let Ok(raw) = std::fs::read_to_string(&opencode_auth) {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&raw) {
                let mut scrubbed = serde_json::Map::new();
                for (prov, entry) in map {
                    let has_key = entry
                        .get("key")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.trim().is_empty());
                    if has_key {
                        if let Some((_, ph)) = opencode_provider_secret_spec(&prov) {
                            scrubbed.insert(
                                prov,
                                json!({
                                    "type": "api",
                                    "key": ph,
                                }),
                            );
                        }
                    }
                }
                let _ = std::fs::write(&opencode_auth, serde_json::to_vec_pretty(&Value::Object(scrubbed))?);
            }
        }
    }

    // 3. Remove raw OAuth/credential pool files from the sandbox copy; only the active client's
    // native OAuth store is selectively restored in `restore_native_oauth_store_for_agent`.
    for rel in [
        ".hermes/auth.json",
        ".claude/.credentials.json",
        ".codex/auth.json",
    ] {
        let _ = std::fs::remove_file(agent_home.join(rel));
    }
    for rel in AGY_AND_GEMINI_OAUTH_STORE_FILES
        .iter()
        .chain(AGY_PLUGIN_SECRET_FILES.iter())
        .chain(AGY_USER_SCOPE_FILES.iter())
    {
        let _ = std::fs::remove_file(agent_home.join(rel));
    }
    for rel_settings in [
        ".gemini/antigravity-cli/settings.json",
        ".gemini/settings.json",
    ] {
        let p = agent_home.join(rel_settings);
        if p.is_file() {
            if let Ok(raw) = std::fs::read_to_string(&p) {
                if let Ok(Value::Object(mut map)) = serde_json::from_str::<Value>(&raw) {
                    if map.remove("google_credentials").is_some() {
                        if let Ok(bytes) = serde_json::to_vec_pretty(&Value::Object(map)) {
                            let _ = std::fs::write(&p, bytes);
                        }
                    }
                }
            }
        }
    }

    // 4. Scrub sensitive plaintext credentials from unadopted third-party MCP entries seeded from
    // host client configs so raw tokens never leak into the sandbox agent home.
    scrub_unadopted_mcp_secrets_in_agent_home(agent_home);
    Ok(())
}

pub(super) fn redact_url_userinfo_value(raw: &str) -> Option<String> {
    let (scheme, after) = raw.split_once("://")?;
    let (userinfo, host_and_rest) = after.split_once('@')?;
    if userinfo.contains('/') || userinfo.contains('?') || userinfo.contains('#') {
        return None;
    }
    if userinfo == "[REDACTED_BY_AEGIS_SANDBOX]" || userinfo.is_empty() {
        return None;
    }
    Some(format!(
        "{scheme}://[REDACTED_BY_AEGIS_SANDBOX]@{host_and_rest}"
    ))
}

pub(super) fn scrub_unadopted_args_array(arr: &mut [Value], skip_first: bool) -> bool {
    let mut changed = false;
    let mut prev_sensitive_flag = false;
    for (idx, item) in arr.iter_mut().enumerate() {
        if skip_first && idx == 0 {
            continue;
        }
        let Some(s) = item.as_str() else {
            prev_sensitive_flag = false;
            continue;
        };
        if s == "[REDACTED_BY_AEGIS_SANDBOX]" {
            prev_sensitive_flag = false;
            continue;
        }
        if prev_sensitive_flag {
            *item = Value::String("[REDACTED_BY_AEGIS_SANDBOX]".to_string());
            changed = true;
            prev_sensitive_flag = false;
            continue;
        }
        let lower = s.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "--token"
                | "--api-key"
                | "--apikey"
                | "--secret"
                | "--password"
                | "--auth"
                | "--bearer"
                | "-h"
                | "--header"
        ) {
            prev_sensitive_flag = true;
            continue;
        }
        if let Some(redacted_url) = redact_url_userinfo_value(s) {
            *item = Value::String(redacted_url);
            changed = true;
            continue;
        }
        if let Some((k, v)) = s.split_once('=') {
            if aos_mcp_gateway::mcp_firewall::is_sensitive_kv(k, v) {
                *item = Value::String(format!("{k}=[REDACTED_BY_AEGIS_SANDBOX]"));
                changed = true;
                continue;
            }
        }
        if aos_mcp_gateway::mcp_firewall::is_sensitive_kv("ARG", s) {
            *item = Value::String("[REDACTED_BY_AEGIS_SANDBOX]".to_string());
            changed = true;
        }
    }
    changed
}

pub(super) fn redact_sensitive_kv_map(obj: &mut serde_json::Map<String, Value>) -> bool {
    let mut changed = false;
    for (k, v) in obj.iter_mut() {
        if let Some(s) = v.as_str() {
            if s != "[REDACTED_BY_AEGIS_SANDBOX]"
                && aos_mcp_gateway::mcp_firewall::is_sensitive_kv(k, s)
            {
                *v = Value::String("[REDACTED_BY_AEGIS_SANDBOX]".to_string());
                changed = true;
            }
        }
    }
    changed
}

pub(super) fn scrub_unadopted_mcp_server_table(servers: &mut serde_json::Map<String, Value>) -> bool {
    let mut changed = false;
    for (server_key, entry) in servers.iter_mut() {
        if aos_mcp_gateway::mcp_firewall::is_already_aegis_proxy_entry(server_key, entry) {
            continue;
        }
        let Some(entry_obj) = entry.as_object_mut() else {
            continue;
        };
        for field in ["env", "environment", "headers", "http_headers"] {
            if let Some(map) = entry_obj.get_mut(field).and_then(|v| v.as_object_mut()) {
                if redact_sensitive_kv_map(map) {
                    changed = true;
                }
            }
        }
        for url_field in ["url", "serverUrl"] {
            if let Some(slot) = entry_obj.get_mut(url_field) {
                if let Some(raw_url) = slot.as_str() {
                    if let Some(clean_url) = redact_url_userinfo_value(raw_url) {
                        *slot = Value::String(clean_url);
                        changed = true;
                    }
                }
            }
        }
        if let Some(args_arr) = entry_obj.get_mut("args").and_then(|v| v.as_array_mut()) {
            if scrub_unadopted_args_array(args_arr, false) {
                changed = true;
            }
        }
        if let Some(cmd_arr) = entry_obj.get_mut("command").and_then(|v| v.as_array_mut()) {
            if scrub_unadopted_args_array(cmd_arr, true) {
                changed = true;
            }
        }
    }
    changed
}

pub(super) fn parse_toml_header_path(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') || trimmed.starts_with("[[") {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut parts = Vec::new();
    let mut chars = inner.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() || c == '.' {
            chars.next();
            continue;
        }
        if c == '"' || c == '\'' {
            let quote = c;
            chars.next();
            let mut part = String::new();
            while let Some(ch) = chars.next() {
                if ch == '\\' && quote == '"' {
                    if let Some(esc) = chars.next() {
                        part.push(esc);
                    }
                } else if ch == quote {
                    break;
                } else {
                    part.push(ch);
                }
            }
            parts.push(part);
        } else {
            let mut part = String::new();
            while let Some(&ch) = chars.peek() {
                if ch == '.' || ch.is_whitespace() {
                    break;
                }
                part.push(ch);
                chars.next();
            }
            if !part.is_empty() {
                parts.push(part);
            }
        }
    }
    Some(parts)
}

pub(super) fn redact_toml_inline_table_kv(rhs: &str) -> Option<String> {
    let trimmed = rhs.trim();
    if !(trimmed.starts_with('{') && trimmed.ends_with('}')) {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut changed = false;
    let mut parts = Vec::new();
    for entry in inner.split(',') {
        let e = entry.trim();
        if e.is_empty() {
            continue;
        }
        if let Some((k, v)) = e.split_once('=') {
            let k_trim = k.trim();
            let k_clean = k_trim.trim_matches('"').trim_matches('\'');
            let v_unquoted = v.trim().trim_matches('"').trim_matches('\'');
            if v_unquoted != "[REDACTED_BY_AEGIS_SANDBOX]"
                && aos_mcp_gateway::mcp_firewall::is_sensitive_kv(k_clean, v_unquoted)
            {
                parts.push(format!("{k_trim} = \"[REDACTED_BY_AEGIS_SANDBOX]\""));
                changed = true;
                continue;
            }
        }
        parts.push(e.to_string());
    }
    if changed {
        Some(format!("{{ {} }}", parts.join(", ")))
    } else {
        None
    }
}

pub(super) fn scrub_unadopted_mcp_secrets_in_agent_home(agent_home: &Path) {
    for rel in [
        ".claude.json",
        ".gemini/config/mcp_config.json",
        ".gemini/antigravity-cli/mcp_config.json",
        ".cursor/mcp.json",
    ] {
        let p = agent_home.join(rel);
        if !p.is_file() {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Ok(mut root) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let mut changed = false;
        if let Some(servers) = root.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
            if scrub_unadopted_mcp_server_table(servers) {
                changed = true;
            }
        }
        if rel == ".claude.json" {
            if let Some(projects) = root.get_mut("projects").and_then(|v| v.as_object_mut()) {
                for (_proj_path, proj_val) in projects.iter_mut() {
                    if let Some(proj_servers) = proj_val
                        .as_object_mut()
                        .and_then(|o| o.get_mut("mcpServers"))
                        .and_then(|v| v.as_object_mut())
                    {
                        if scrub_unadopted_mcp_server_table(proj_servers) {
                            changed = true;
                        }
                    }
                }
            }
        }
        if changed {
            if let Ok(pretty) = serde_json::to_string_pretty(&root) {
                let _ = std::fs::write(&p, format!("{pretty}\n"));
            }
        }
    }

    for rel in [".claude/settings.json", ".claude/settings.local.json"] {
        let p = agent_home.join(rel);
        if !p.is_file() {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Ok(mut root) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if let Some(env_obj) = root.get_mut("env").and_then(|v| v.as_object_mut()) {
            if redact_sensitive_kv_map(env_obj) {
                if let Ok(pretty) = serde_json::to_string_pretty(&root) {
                    let _ = std::fs::write(&p, format!("{pretty}\n"));
                }
            }
        }
    }

    for rel in [
        ".config/opencode/opencode.json",
        ".config/opencode/opencode.jsonc",
    ] {
        let opencode_cfg = agent_home.join(rel);
        if opencode_cfg.is_file() {
            if let Ok(raw) = std::fs::read_to_string(&opencode_cfg) {
                if let Ok(mut root) = serde_json::from_str::<Value>(&raw)
                    .or_else(|_| serde_json::from_str::<Value>(&strip_jsonc_comments(&raw)))
                {
                    let mut changed = false;
                    if let Some(servers) = root
                        .pointer_mut("/mcp/servers")
                        .and_then(|v| v.as_object_mut())
                    {
                        if scrub_unadopted_mcp_server_table(servers) {
                            changed = true;
                        }
                    } else if let Some(mcp_obj) =
                        root.get_mut("mcp").and_then(|v| v.as_object_mut())
                    {
                        if scrub_unadopted_mcp_server_table(mcp_obj) {
                            changed = true;
                        }
                    }
                    if changed {
                        if let Ok(pretty) = serde_json::to_string_pretty(&root) {
                            let _ = std::fs::write(&opencode_cfg, format!("{pretty}\n"));
                        }
                    }
                }
            }
        }
    }

    let codex_cfg = agent_home.join(".codex/config.toml");
    if codex_cfg.is_file() {
        if let Ok(raw) = std::fs::read_to_string(&codex_cfg) {
            // Pass 1: find adopted Codex `[mcp_servers.<name>]` blocks so they are preserved intact.
            let mut adopted = std::collections::HashSet::<String>::new();
            let mut cur_server: Option<String> = None;
            let mut in_base_section = false;
            for line in raw.lines() {
                if let Some(parts) = parse_toml_header_path(line) {
                    if parts.first().map(String::as_str) == Some("mcp_servers") && parts.len() >= 2
                    {
                        cur_server = Some(parts[1].clone());
                        in_base_section = parts.len() == 2;
                    } else {
                        cur_server = None;
                        in_base_section = false;
                    }
                    continue;
                }
                if in_base_section {
                    if let Some(ref key) = cur_server {
                        if key == "aegis-os"
                            || line.contains("mcp-stdio")
                            || (line.contains("\"mcp\"") && line.contains("\"proxy\""))
                        {
                            adopted.insert(key.clone());
                        }
                    }
                }
            }

            // Pass 2: redact sensitive env/header assignments, URL userinfo, and inline tables inside unadopted sections.
            let mut changed = false;
            let mut out = Vec::new();
            let mut active_sensitive_server: Option<String> = None;
            let mut active_base_server: Option<String> = None;
            for line in raw.lines() {
                if let Some(parts) = parse_toml_header_path(line) {
                    active_sensitive_server = if parts.first().map(String::as_str)
                        == Some("mcp_servers")
                        && parts.len() == 3
                        && matches!(parts[2].as_str(), "env" | "http_headers" | "headers")
                    {
                        Some(parts[1].clone())
                    } else {
                        None
                    };
                    active_base_server = if parts.first().map(String::as_str)
                        == Some("mcp_servers")
                        && parts.len() == 2
                    {
                        Some(parts[1].clone())
                    } else {
                        None
                    };
                    out.push(line.to_string());
                    continue;
                }
                let trimmed = line.trim();
                if let Some(ref server_key) = active_sensitive_server {
                    if !adopted.contains(server_key)
                        && !trimmed.is_empty()
                        && !trimmed.starts_with('#')
                    {
                        if let Some((k, v)) = trimmed.split_once('=') {
                            let k_trim = k.trim();
                            let v_unquoted = v.trim().trim_matches('"').trim_matches('\'');
                            if v_unquoted != "[REDACTED_BY_AEGIS_SANDBOX]"
                                && aos_mcp_gateway::mcp_firewall::is_sensitive_kv(
                                    k_trim,
                                    v_unquoted,
                                )
                            {
                                out.push(format!("{k_trim} = \"[REDACTED_BY_AEGIS_SANDBOX]\""));
                                changed = true;
                                continue;
                            }
                        }
                    }
                } else if let Some(ref server_key) = active_base_server {
                    if !adopted.contains(server_key)
                        && !trimmed.is_empty()
                        && !trimmed.starts_with('#')
                    {
                        if let Some((k, v)) = trimmed.split_once('=') {
                            let k_trim = k.trim();
                            if matches!(k_trim, "url" | "serverUrl") {
                                let v_unquoted = v.trim().trim_matches('"').trim_matches('\'');
                                if let Some(clean_url) = redact_url_userinfo_value(v_unquoted) {
                                    let q = serde_json::to_string(&clean_url)
                                        .unwrap_or_else(|_| format!("\"{clean_url}\""));
                                    out.push(format!("{k_trim} = {q}"));
                                    changed = true;
                                    continue;
                                }
                            } else if matches!(k_trim, "env" | "http_headers" | "headers") {
                                if let Some(clean_tbl) = redact_toml_inline_table_kv(v) {
                                    out.push(format!("{k_trim} = {clean_tbl}"));
                                    changed = true;
                                    continue;
                                }
                            }
                        }
                    }
                }
                out.push(line.to_string());
            }
            if changed {
                let mut joined = out.join("\n");
                if raw.ends_with('\n') {
                    joined.push('\n');
                }
                let _ = std::fs::write(&codex_cfg, joined);
            }
        }
    }
}

pub(super) fn write_mode_0600_no_symlink(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if let Ok(pmeta) = std::fs::symlink_metadata(parent) {
            if pmeta.file_type().is_symlink() {
                anyhow::bail!("refusing symlinked parent directory '{}'", parent.display());
            }
        }
        std::fs::create_dir_all(parent)?;
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            anyhow::bail!("refusing symlinked target file '{}'", path.display());
        }
    }
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("opening protected file '{}'", path.display()))?;
    file.write_all(contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub(super) fn ensure_protected_agent_configs(agent_home: &Path) -> anyhow::Result<()> {
    if aos_core::ablated("config_overmount") {
        return Ok(());
    }
    for (rel, stub) in [
        (".claude/settings.json", "{}\n"),
        (".claude/settings.local.json", "{}\n"),
        (".gemini/config/hooks.json", "{}\n"),
        (".gemini/config/mcp_config.json", "{}\n"),
        (".gemini/antigravity-cli/mcp_config.json", "{}\n"),
        (".cursor/mcp.json", "{}\n"),
        (".codex/config.toml", "# protected by aegis-os\n"),
    ] {
        let p = agent_home.join(rel);
        if !p.exists() {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&p, stub)?;
        }
    }
    let broker_file = agent_home.join(".run/aegis-broker.json");
    if !broker_file.exists() {
        write_mode_0600_no_symlink(&broker_file, b"{}\n")?;
    }
    let hermes_cfg = agent_home.join(".hermes/config.yaml");
    if !hermes_cfg.exists() {
        if let Some(parent) = hermes_cfg.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&hermes_cfg, "{}\n")?;
    }
    for rel_dir in PROTECTED_AGENT_PLUGIN_DIRS {
        std::fs::create_dir_all(agent_home.join(rel_dir))?;
    }
    Ok(())
}

pub(crate) enum ConfinedMcpTransport<'a> {
    EnforcedStdio {
        bin_path: &'a str,
        runtime_dir: &'a Path,
        control_socket: &'a str,
    },
    IsolatedHttp {
        proxy_addr: &'a str,
    },
}

pub(super) fn format_toml_key_part(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        s.to_string()
    } else {
        serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\""))
    }
}

pub(super) fn upsert_isolated_http_json_entry(
    config_path: &Path,
    is_opencode: bool,
    server_key: &str,
    url: &str,
    session_token: &str,
) -> anyhow::Result<()> {
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = if config_path.is_file() {
        std::fs::read_to_string(config_path)
            .with_context(|| format!("reading confined MCP config '{}'", config_path.display()))?
    } else {
        String::new()
    };
    if is_opencode {
        let mut root: Value = if text.trim().is_empty() {
            json!({ "mcp": { "servers": {} } })
        } else {
            serde_json::from_str(&text)
                .with_context(|| format!("parsing JSON config '{}'", config_path.display()))?
        };
        let entry = json!({
            "type": "remote",
            "url": url,
            "enabled": true,
            "headers": {
                "X-Aegis-Token": session_token
            }
        });
        if let Some(servers) = root
            .pointer_mut("/mcp/servers")
            .and_then(|v| v.as_object_mut())
        {
            servers.insert(server_key.to_string(), entry);
        } else if let Some(mcp_obj) = root.get_mut("mcp").and_then(|v| v.as_object_mut()) {
            mcp_obj.insert(server_key.to_string(), entry);
        } else if let Some(root_obj) = root.as_object_mut() {
            root_obj.insert(
                "mcp".to_string(),
                json!({ "servers": { server_key: entry } }),
            );
        } else {
            bail!(
                "opencode.json root is not an object in {}",
                config_path.display()
            );
        }
        std::fs::write(
            config_path,
            format!("{}\n", serde_json::to_string_pretty(&root)?),
        )?;
    } else {
        let mut root: Value = if text.trim().is_empty() {
            json!({ "mcpServers": {} })
        } else {
            serde_json::from_str(&text)
                .with_context(|| format!("parsing JSON config '{}'", config_path.display()))?
        };
        let root_obj = root.as_object_mut().with_context(|| {
            format!("JSON config root is not an object in {}", config_path.display())
        })?;
        let servers_val = root_obj
            .entry("mcpServers")
            .or_insert_with(|| json!({}));
        if !servers_val.is_object() {
            *servers_val = json!({});
        }
        let servers = servers_val
            .as_object_mut()
            .expect("mcpServers normalized to object");
        servers.insert(
            server_key.to_string(),
            json!({
                "type": "http",
                "url": url,
                "headers": {
                    "X-Aegis-Token": session_token
                }
            }),
        );
        std::fs::write(
            config_path,
            format!("{}\n", serde_json::to_string_pretty(&root)?),
        )?;
    }
    Ok(())
}

pub(super) fn upsert_isolated_http_codex_entry(
    config_path: &Path,
    server_key: &str,
    url: &str,
    session_token: &str,
) -> anyhow::Result<()> {
    let _ = aos_mcp_gateway::mcp_firewall::remove_client_proxy_entry(
        "codex",
        config_path,
        server_key,
    )?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = if config_path.is_file() {
        std::fs::read_to_string(config_path)?
    } else {
        String::new()
    };
    let key_part = format_toml_key_part(server_key);
    let url_json = serde_json::to_string(url)?;
    let tok_json = serde_json::to_string(session_token)?;
    let block = format!(
        "[mcp_servers.{key_part}]\nurl = {url_json}\n\n[mcp_servers.{key_part}.http_headers]\nX-Aegis-Token = {tok_json}\n"
    );
    let updated = if existing.trim().is_empty() {
        block
    } else {
        format!("{}\n\n{}", existing.trim_end(), block)
    };
    std::fs::write(config_path, updated)?;
    Ok(())
}

/// Stages confined session MCP client configurations inside `agent_home` (never mutating `shadow`
/// workspace files) and persists `0o600` `$HOME/.run/aegis-broker.json` fallback credentials so
/// child MCP processes spawned by `claude` / `agy` work even if env vars are stripped.
pub(crate) fn stage_confined_mcp_configs(
    agent_home: &Path,
    identity: &AgentIdentity,
    servers: &[aos_mcp_gateway::mcp_firewall::AdoptedMcpServerRecord],
    session_token: &str,
    tool_profile: Option<&str>,
    transport: ConfinedMcpTransport<'_>,
) -> anyhow::Result<()> {
    let run_dir = agent_home.join(".run");
    std::fs::create_dir_all(&run_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700));
    }

    let control_socket_str = match &transport {
        ConfinedMcpTransport::EnforcedStdio { control_socket, .. } => (*control_socket).to_string(),
        ConfinedMcpTransport::IsolatedHttp { proxy_addr } => {
            format!("http://{proxy_addr}/__aegis/mcp/_kernel")
        }
    };
    let broker_file = crate::session_broker::ConfinedBrokerFile {
        control_socket: control_socket_str,
        session_token: session_token.to_string(),
        tool_profile: tool_profile.map(str::to_string),
    };
    let broker_path = run_dir.join("aegis-broker.json");
    let broker_bytes = format!("{}\n", serde_json::to_string_pretty(&broker_file)?);
    write_mode_0600_no_symlink(&broker_path, broker_bytes.as_bytes())?;
    restage_confined_mcp_client_configs(
        agent_home,
        identity,
        servers,
        session_token,
        tool_profile,
        transport,
    )
}

pub(crate) fn restage_confined_mcp_client_configs(
    agent_home: &Path,
    identity: &AgentIdentity,
    servers: &[aos_mcp_gateway::mcp_firewall::AdoptedMcpServerRecord],
    session_token: &str,
    tool_profile: Option<&str>,
    transport: ConfinedMcpTransport<'_>,
) -> anyhow::Result<()> {

    let client_targets = [
        ("claude", agent_home.join(".claude.json")),
        ("agy", agent_home.join(".gemini/config/mcp_config.json")),
        (
            "agy-cli",
            agent_home.join(".gemini/antigravity-cli/mcp_config.json"),
        ),
        ("cursor", agent_home.join(".cursor/mcp.json")),
        ("opencode", agent_home.join(".config/opencode/opencode.json")),
        ("codex", agent_home.join(".codex/config.toml")),
    ];

    match transport {
        ConfinedMcpTransport::EnforcedStdio {
            bin_path,
            runtime_dir,
            control_socket,
        } => {
            let mut extra_env = std::collections::BTreeMap::new();
            extra_env.insert("AOS_CONTROL_SOCKET".to_string(), control_socket.to_string());
            extra_env.insert("AOS_SESSION_TOKEN".to_string(), session_token.to_string());
            if let Some(tp) = tool_profile.map(str::trim).filter(|s| !s.is_empty()) {
                extra_env.insert("AOS_MCP_TOOL_PROFILE".to_string(), tp.to_string());
            }
            let rt_str = runtime_dir.display().to_string();
            for (client, cfg_path) in &client_targets {
                let _ = aos_mcp_gateway::mcp_firewall::upsert_client_proxy_entry(
                    client,
                    cfg_path,
                    "aegis-os",
                    bin_path,
                    &["mcp-stdio".to_string()],
                    Some(&extra_env),
                )?;
                for srv in servers {
                    let args = vec![
                        "--org".to_string(),
                        identity.org_id.clone(),
                        "--agent".to_string(),
                        identity.agent_id.clone(),
                        "--runtime-dir".to_string(),
                        rt_str.clone(),
                        "mcp".to_string(),
                        "proxy".to_string(),
                        srv.server_id.clone(),
                    ];
                    let _ = aos_mcp_gateway::mcp_firewall::upsert_client_proxy_entry(
                        client,
                        cfg_path,
                        &srv.server_id,
                        bin_path,
                        &args,
                        Some(&extra_env),
                    )?;
                }
            }
        }
        ConfinedMcpTransport::IsolatedHttp { proxy_addr } => {
            let mut entries = Vec::with_capacity(1 + servers.len());
            entries.push((
                "aegis-os".to_string(),
                format!("http://{proxy_addr}/__aegis/mcp/_kernel"),
            ));
            for srv in servers {
                entries.push((
                    srv.server_id.clone(),
                    format!("http://{proxy_addr}/__aegis/mcp/{}", srv.server_id),
                ));
            }
            for (client, cfg_path) in &client_targets {
                for (key, url) in &entries {
                    if *client == "codex" {
                        upsert_isolated_http_codex_entry(cfg_path, key, url, session_token)?;
                    } else {
                        upsert_isolated_http_json_entry(
                            cfg_path,
                            *client == "opencode",
                            key,
                            url,
                            session_token,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
pub(super) enum OwnedConfinedMcpTransport {
    EnforcedStdio {
        bin_path: String,
        runtime_dir: PathBuf,
        control_socket: String,
    },
    IsolatedHttp {
        proxy_addr: String,
    },
}

pub(super) async fn register_confined_mcp_post_install_hook(
    kernel: std::sync::Arc<AegisRuntimeKernel>,
    agent_home: PathBuf,
    identity: AgentIdentity,
    session_token: String,
    tool_profile: Option<String>,
    owned_transport: OwnedConfinedMcpTransport,
) {
    let k_for_hook = kernel.clone();
    kernel
        .set_mcp_post_install_hook(std::sync::Arc::new(move |hook_org, _hook_srv| {
            let k = k_for_hook.clone();
            let agent_home = agent_home.clone();
            let identity = identity.clone();
            let session_token = session_token.clone();
            let tool_profile = tool_profile.clone();
            let owned_transport = owned_transport.clone();
            Box::pin(async move {
                let servers = k.mcp_firewall.list_servers(Some(&hook_org)).await;
                let t = match &owned_transport {
                    OwnedConfinedMcpTransport::EnforcedStdio {
                        bin_path,
                        runtime_dir,
                        control_socket,
                    } => ConfinedMcpTransport::EnforcedStdio {
                        bin_path,
                        runtime_dir,
                        control_socket,
                    },
                    OwnedConfinedMcpTransport::IsolatedHttp { proxy_addr } => {
                        ConfinedMcpTransport::IsolatedHttp { proxy_addr }
                    }
                };
                let _ = restage_confined_mcp_client_configs(
                    &agent_home,
                    &identity,
                    &servers,
                    &session_token,
                    tool_profile.as_deref(),
                    t,
                );
            })
        }))
        .await;
}

/// Prints a concise external MCP inventory + `.mcp.json` recommendation line into the
/// `aegis-os run` startup banner using only local cached/Vault state (zero network calls).
pub(super) async fn print_mcp_startup_banner(
    kernel: &AegisRuntimeKernel,
    org_id: &str,
    project: impl AsRef<Path>,
) {
    let project = project.as_ref();
    let inv = kernel.build_installed_mcp_inventory(org_id, None).await;
    let servers = inv["servers"].as_array().cloned().unwrap_or_default();
    let mut installed_ids = std::collections::BTreeSet::new();
    let mut ready = Vec::new();
    let mut needs_login = Vec::new();

    for s in &servers {
        let sid = s["server_id"].as_str().unwrap_or("").to_string();
        if sid.is_empty() {
            continue;
        }
        installed_ids.insert(sid.clone());
        if s["status"].as_str() == Some("needs_auth") {
            let realm = s["auth_realm"].as_str().unwrap_or(&sid).to_string();
            needs_login.push((sid, realm));
        } else {
            ready.push(sid);
        }
    }

    if !servers.is_empty() {
        let mut parts = Vec::new();
        if !ready.is_empty() {
            let shown: Vec<&str> = ready.iter().take(5).map(String::as_str).collect();
            let suffix = if ready.len() > 5 { ", …" } else { "" };
            parts.push(format!("{} ready ({}{suffix})", ready.len(), shown.join(", ")));
        }
        if !needs_login.is_empty() {
            let shown: Vec<String> = needs_login
                .iter()
                .take(3)
                .map(|(sid, realm)| format!("{sid} -> aegis-os mcp login {realm}"))
                .collect();
            parts.push(format!("{} needs login: {}", needs_login.len(), shown.join("; ")));
        }
        eprintln!("  mcps:    {}", parts.join(" | "));
    }

    let hints = aos_mcp_gateway::mcp_registry::McpRegistryClient::recommend_for_workspace(
        project,
        &installed_ids,
    );
    let uninstalled_manifest_hints: Vec<String> = hints
        .into_iter()
        .filter(|h| !h.already_installed && h.source.starts_with("repo_manifest:"))
        .map(|h| h.server_id)
        .collect();
    if !uninstalled_manifest_hints.is_empty() {
        eprintln!(
            "  mcp-hint: repo declares {} uninstalled MCP(s) ({}) -> aegis-os mcp recommend",
            uninstalled_manifest_hints.len(),
            uninstalled_manifest_hints.join(", ")
        );
    }
}

pub(crate) fn rewrite_hermes_config_for_l7(agent_home: &Path, proxy: &str, pinned_port: Option<u16>) {
    let cfg_path = agent_home.join(".hermes/config.yaml");
    let Ok(mut raw) = std::fs::read_to_string(&cfg_path) else {
        return;
    };
    if !aos_core::ablated("secret_vault") {
        let base = format!("http://{proxy}/__aegis/base");
        for (from, to) in [
            ("https://api.deepseek.com/v1", format!("{base}/deepseek/v1")),
            ("https://api.deepseek.com", format!("{base}/deepseek")),
            ("https://api.openai.com/v1", format!("{base}/openai/v1")),
            ("https://api.anthropic.com", format!("{base}/anthropic")),
            ("https://openrouter.ai/api/v1", format!("{base}/openrouter/api/v1")),
            ("https://api.x.ai/v1", format!("{base}/xai/v1")),
            ("https://api.groq.com/openai/v1", format!("{base}/groq/openai/v1")),
            ("https://api.mistral.ai/v1", format!("{base}/mistral/v1")),
            (
                "https://generativelanguage.googleapis.com/v1beta",
                format!("{base}/gemini/v1beta"),
            ),
        ] {
            raw = raw.replace(from, &to);
        }
    }
    if let Some(port) = pinned_port {
        if raw.trim() != "{}"
            && !raw.contains("\nwebapp:")
            && !raw.starts_with("webapp:")
        {
            if !raw.ends_with('\n') && !raw.is_empty() {
                raw.push('\n');
            }
            raw.push_str(&format!(
                "webapp:\n  enabled: true\n  host: 127.0.0.1\n  port: {port}\n"
            ));
        }
    }
    let _ = std::fs::write(&cfg_path, raw);
}

pub(crate) fn rewrite_opencode_config_for_l7(agent_home: &Path, proxy: &str) {
    if aos_core::ablated("secret_vault") {
        return;
    }
    for rel in [".config/opencode/opencode.json", ".config/opencode/opencode.jsonc"] {
        let cfg_path = agent_home.join(rel);
        if cfg_path.is_file() {
            if let Ok(existing) = std::fs::read_to_string(&cfg_path) {
                let merged = opencode_l7_config_content(proxy, Some(&existing));
                let _ = std::fs::write(&cfg_path, merged);
            }
        }
    }
}

pub(crate) fn seed_agent_home(host_home: &Path, agent_home: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(agent_home)?;
    for rel in SEEDED_AGENT_DIRS {
        let src = host_home.join(rel);
        if src.exists() {
            copy_path(&src, &agent_home.join(rel))?;
        }
    }
    for rel in SEEDED_AGENT_FILES {
        let src = host_home.join(rel);
        if src.is_file() {
            copy_path(&src, &agent_home.join(rel))?;
        }
    }
    #[cfg(target_os = "macos")]
    {
        for rel in [
            ".config/opencode/node_modules",
            ".hermes/hermes-agent",
            ".hermes/runtime",
            ".hermes/tools",
        ] {
            let host_dir = host_home.join(rel);
            let dst_dir = agent_home.join(rel);
            if host_dir.is_dir() && !dst_dir.exists() {
                if let Some(parent) = dst_dir.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::os::unix::fs::symlink(&host_dir, &dst_dir);
            }
        }
    }
    sanitize_seeded_agent_home(agent_home)?;
    ensure_protected_agent_configs(agent_home)?;
    Ok(())
}

pub(super) fn collect_configs(
    host_home: &Path,
    agent_home: &Path,
    command: &[String],
) -> anyhow::Result<Vec<FdMount>> {
    let host_oc_nm = host_home.join(".config/opencode/node_modules");
    let mut mounts = Vec::new();
    if host_oc_nm.is_dir() {
        std::fs::create_dir_all(agent_home.join(".config/opencode/node_modules"))?;
        mounts.push(fd_mount(
            &host_oc_nm,
            format!("{AGENT_STAGE}/.config/opencode/node_modules"),
            true,
        )?);
    }
    if aos_core::ablated("config_overmount") {
        return Ok(mounts);
    }
    let allow_hermes_cfg_write = is_hermes_config_subcommand(command);
    for rel in PROTECTED_AGENT_CONFIGS {
        if *rel == ".hermes/config.yaml" && allow_hermes_cfg_write {
            continue;
        }
        let staged = agent_home.join(rel);
        if staged.is_file() {
            mounts.push(fd_mount(
                &staged,
                format!("{AGENT_STAGE}/{rel}"),
                true,
            )?);
        }
    }
    for rel_dir in PROTECTED_AGENT_PLUGIN_DIRS {
        let staged = agent_home.join(rel_dir);
        if staged.is_dir() {
            mounts.push(fd_mount(
                &staged,
                format!("{AGENT_STAGE}/{rel_dir}"),
                true,
            )?);
        }
    }
    // Mount `.aegis-bin` read-only over `$HOME/.aegis-bin` so a sandboxed process cannot
    // overwrite or delete the hardened `git` shim inside its writable `agent_home`.
    let aegis_bin = agent_home.join(".aegis-bin");
    if aegis_bin.is_dir() && !aos_core::ablated("git_guard") {
        mounts.push(fd_mount(
            &aegis_bin,
            format!("{AGENT_STAGE}/.aegis-bin"),
            true,
        )?);
    }
    Ok(mounts)
}

pub(super) fn collect_project_configs(project: &Path, shadow: &Path) -> anyhow::Result<Vec<FdMount>> {
    if aos_core::ablated("config_overmount") {
        return Ok(Vec::new());
    }
    let mut mounts = Vec::new();
    for rel_dir in [".claude", ".gemini", ".codex", ".cursor", ".opencode"] {
        let staged_dir = shadow.join(rel_dir);
        std::fs::create_dir_all(&staged_dir)?;
        mounts.push(fd_mount(&staged_dir, project.join(rel_dir), true)?);
    }
    for rel in PROJECT_PROTECTED_CONFIGS {
        if rel.contains('/') {
            continue;
        }
        let staged = shadow.join(rel);
        if staged.is_file() {
            mounts.push(fd_mount(&staged, project.join(rel), true)?);
        }
    }
    Ok(mounts)
}

pub(super) fn collect_state_dirs(host_home: &Path) -> anyhow::Result<Vec<FdMount>> {
    let mut mounts = Vec::new();
    for rel in PERSISTED_AGENT_STATE_DIRS {
        let host = host_home.join(rel);
        if !host.is_dir() {
            // Only persist directories the client already created; do not manufacture state for
            // agents that are not used on this host.
            continue;
        }
        mounts.push(fd_mount(&host, format!("{AGENT_STAGE}/{rel}"), false)?);
    }
    Ok(mounts)
}

pub(super) fn collect_toolchains(host_home: &Path) -> anyhow::Result<Vec<FdMount>> {
    let mut mounts = Vec::new();
    // Only expose the parts of a toolchain that are needed to run tools. In particular do not
    // mount ~/.cargo or ~/.local wholesale: credentials.toml, keyrings and app state live there.
    for (rel, dest) in [
        (".local/bin", format!("{TOOLCHAIN_STAGE}/local/bin")),
        (".cargo/bin", format!("{TOOLCHAIN_STAGE}/cargo/bin")),
        (".cargo/registry", format!("{AGENT_STAGE}/.cargo/registry")),
        (".cargo/git", format!("{AGENT_STAGE}/.cargo/git")),
        (".rustup/toolchains", format!("{AGENT_STAGE}/.rustup/toolchains")),
        (".bun/bin", format!("{TOOLCHAIN_STAGE}/bun/bin")),
        (".bun/install/cache", format!("{AGENT_STAGE}/.bun/install/cache")),
        (".volta/bin", format!("{TOOLCHAIN_STAGE}/volta/bin")),
        (".volta/tools", format!("{TOOLCHAIN_STAGE}/volta/tools")),
        (".nvm/versions", format!("{TOOLCHAIN_STAGE}/nvm/versions")),
        (".npm/_cacache", format!("{TOOLCHAIN_STAGE}/npm/cache")),
    ] {
        let host = host_home.join(rel);
        if host.exists() {
            mounts.push(fd_mount(&host, dest, true)?);
        }
    }
    // Agent installation trees with embedded absolute RPATHs / Python venv shebangs.
    for rel in [
        ".hermes/hermes-agent",
        ".hermes/runtime",
        ".hermes/tools",
        ".local/share/claude",
        ".opencode",
    ] {
        let host = host_home.join(rel);
        if host.is_dir() {
            mounts.push(fd_mount(&host, host.clone(), true)?);
            if rel.starts_with(".hermes/") {
                mounts.push(fd_mount(&host, format!("{AGENT_STAGE}/{rel}"), true)?);
            }
        }
    }
    // Linuxbrew binaries carry absolute RPATHs under /home/linuxbrew; keep the original path.
    let linuxbrew = PathBuf::from("/home/linuxbrew/.linuxbrew");
    if linuxbrew.exists() {
        mounts.push(fd_mount(&linuxbrew, "/home/linuxbrew/.linuxbrew", true)?);
    }
    Ok(mounts)
}

pub(crate) fn install_git_shim(agent_home: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = agent_home.join(".aegis-bin");
    std::fs::create_dir_all(&dir)?;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    let script = r#"#!/bin/sh
# Aegis Enforced Runtime read-only git shim (V5 Defense).
# 1. Scrub environment variables that can override `-c` flags or execute arbitrary helpers.
unset GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT GIT_EXTERNAL_DIFF GIT_SSH_COMMAND GIT_ASKPASS SSH_ASKPASS GIT_EXEC_PATH GIT_TEMPLATE_DIR
real="${AOS_REAL_GIT:-/usr/bin/git}"
if [ ! -x "$real" ]; then
  real="/bin/git"
fi
# 2. Reject any `-c`, `--config-env`, `--exec-path`, or `--upload-pack` flag anywhere on the command line.
for arg in "$@"; do
  case "$arg" in
    -c|-c*|--config-env|--config-env=*|--exec-path|--exec-path=*|--upload-pack|--upload-pack=*)
      echo "aos: git config/exec override flag '$arg' is forbidden in enforced mode." >&2
      exit 126
      ;;
  esac
done
# 3. Allow benign global flags (`-C <dir>`, `--no-pager`, `--no-optional-locks`) before the subcommand.
chdir_arg=""
while [ $# -gt 0 ]; do
  case "$1" in
    -C)
      shift
      chdir_arg="$1"
      shift
      ;;
    --no-pager|--no-optional-locks)
      shift
      ;;
    *)
      break
      ;;
  esac
done
cmd="$1"
if [ $# -gt 0 ]; then
  shift
fi
run_ro_git() {
  if [ -n "$chdir_arg" ]; then
    exec "$real" -C "$chdir_arg" -c core.fsmonitor=false -c core.hooksPath=/dev/null -c protocol.file.allow=never "$@"
  else
    exec "$real" -c core.fsmonitor=false -c core.hooksPath=/dev/null -c protocol.file.allow=never "$@"
  fi
}
case "$cmd" in
  status)
    run_ro_git status "$@"
    ;;
  diff)
    run_ro_git diff --no-ext-diff --no-textconv "$@"
    ;;
  show|log)
    run_ro_git "$cmd" --no-ext-diff "$@"
    ;;
  branch)
    if [ "$1" = "--show-current" ] || [ "$1" = "-a" ] || [ "$1" = "-r" ]; then
      run_ro_git branch "$@"
    fi
    ;;
  rev-parse|ls-files|grep|blame|describe)
    run_ro_git "$cmd" "$@"
    ;;
  tag)
    if [ "$1" = "--list" ] || [ -z "$1" ]; then
      run_ro_git tag "$@"
    fi
    ;;
esac
echo "aos: git $cmd is disabled inside sandbox; use mcp_aegis-os_workspace_git (or host 'aos diff' / 'aos commit')." >&2
exit 126
"#;
    let path = dir.join("git");
    if path.exists() {
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::write(&path, script)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555))?;
    #[cfg(target_os = "macos")]
    {
        let sec_script = "#!/bin/sh\n# Aegis Enforced Runtime macOS Keychain CLI guard (V3 Defense).\nexit 44\n";
        let sec_path = dir.join("security");
        if sec_path.exists() {
            let _ = std::fs::set_permissions(&sec_path, std::fs::Permissions::from_mode(0o755));
        }
        std::fs::write(&sec_path, sec_script)?;
        std::fs::set_permissions(&sec_path, std::fs::Permissions::from_mode(0o555))?;
    }
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555));
    Ok(())
}

pub(super) fn dependency_mounts(project: &Path, shadow: &Path) -> anyhow::Result<Vec<FdMount>> {
    let mut mounts = Vec::new();
    for dep in ["node_modules", ".venv", "venv"] {
        let host = project.join(dep);
        if !host.exists() {
            continue;
        }
        let shadow_dep = shadow.join(dep);
        if let Ok(meta) = std::fs::symlink_metadata(&shadow_dep) {
            if meta.file_type().is_symlink() {
                // `link_host_dependency_dirs` creates a link to the host path. Once the shadow
                // is mounted at that same path, the link becomes self-referential (ELOOP).
                let _ = std::fs::remove_file(&shadow_dep);
            } else if meta.is_dir() {
                // A real shadow copy already exists; don't hide it with a ro mount.
                continue;
            }
        }
        mounts.push(fd_mount(&host, project.join(dep), true)?);
    }
    Ok(mounts)
}

pub(super) fn nixos_mounts() -> anyhow::Result<Vec<FdMount>> {
    let mut mounts = Vec::new();
    let current = Path::new("/run/current-system");
    if current.is_dir() {
        mounts.push(fd_mount(current, "/run/current-system", true)?);
    }
    Ok(mounts)
}

pub(super) fn resolv_conf_mounts() -> anyhow::Result<Vec<FdMount>> {
    // systemd-resolved / NetworkManager often make /etc/resolv.conf a symlink into /run.
    // /run is replaced by a tmpfs, so re-expose the target directory at the same path.
    let Ok(target) = std::fs::canonicalize("/etc/resolv.conf") else {
        return Ok(Vec::new());
    };
    if !target.starts_with("/run") {
        return Ok(Vec::new());
    }
    let Some(parent) = target.parent() else {
        return Ok(Vec::new());
    };
    if !parent.is_dir() {
        return Ok(Vec::new());
    }
    Ok(vec![fd_mount(parent, parent, true)?])
}
