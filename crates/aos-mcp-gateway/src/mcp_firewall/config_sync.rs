use super::*;

pub fn is_already_aegis_proxy_entry(server_key: &str, entry: &Value) -> bool {
    if server_key == "aegis-os" {
        return true;
    }
    let cmd = entry.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let args: Vec<&str> = entry
        .get("args")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    let arr_cmd: Vec<&str> = entry
        .get("command")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();

    let all_args: Vec<&str> = if !arr_cmd.is_empty() {
        arr_cmd
    } else {
        let mut combined = Vec::new();
        if !cmd.is_empty() {
            combined.push(cmd);
        }
        combined.extend(args);
        combined
    };

    all_args.windows(2).any(|w| w[0] == "mcp" && w[1] == "proxy")
        || all_args.contains(&"mcp-stdio")
}

pub(super) fn inspect_entry_secrets_and_transport(entry: &Value) -> Option<(String, Vec<String>)> {
    let url = entry
        .get("url")
        .or_else(|| entry.get("serverUrl"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let has_cmd = entry
        .get("command")
        .map(|v| {
            v.as_str().is_some_and(|s| !s.trim().is_empty())
                || v.as_array().is_some_and(|a| !a.is_empty())
        })
        .unwrap_or(false);

    let kind = if url.is_some() {
        "http"
    } else if has_cmd {
        "stdio"
    } else {
        return None;
    };

    let mut secret_keys = BTreeSet::new();
    for env_key_name in ["env", "environment"] {
        if let Some(env_map) = entry.get(env_key_name).and_then(|v| v.as_object()) {
            for (k, v) in env_map {
                let val_str = v.as_str().unwrap_or("");
                if is_sensitive_kv(k, val_str) {
                    secret_keys.insert(k.clone());
                }
            }
        }
    }
    for hdr_key_name in ["headers", "http_headers"] {
        if let Some(hdr_map) = entry.get(hdr_key_name).and_then(|v| v.as_object()) {
            for (k, v) in hdr_map {
                let val_str = v.as_str().unwrap_or("");
                if is_sensitive_kv(k, val_str) {
                    secret_keys.insert(k.clone());
                }
            }
        }
    }
    if let Some(raw_url) = url {
        if is_sensitive_kv("URL", raw_url) {
            secret_keys.insert("URL".to_string());
        }
    }
    if let Some(bearer_var) = entry.get("bearer_token_env_var").and_then(|v| v.as_str()) {
        if !bearer_var.trim().is_empty() {
            secret_keys.insert(bearer_var.trim().to_string());
        }
    }

    Some((kind.to_string(), secret_keys.into_iter().collect()))
}

// ============================================================================
// Lightweight Section-Aware TOML Helper for `~/.codex/config.toml`
// ============================================================================

#[derive(Debug, Clone)]
pub(super) struct CodexTomlSectionBlock {
    pub(super) server_key: String,
    pub(super) start_line: usize,
    pub(super) end_line: usize,
    pub(super) raw_block: String,
    pub(super) parsed_entry: Value,
}

pub(super) fn unquote_toml_str(s: &str) -> Option<String> {
    let t = s.trim();
    if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
        let inner = &t[1..t.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some(other) => out.push(other),
                    None => {}
                }
            } else {
                out.push(c);
            }
        }
        return Some(out);
    }
    if t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2 {
        return Some(t[1..t.len() - 1].to_string());
    }
    None
}

pub(super) fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escape = false;
    for (idx, ch) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if in_double && ch == '\\' {
            escape = true;
            continue;
        }
        if !in_single && ch == '"' {
            in_double = !in_double;
            continue;
        }
        if !in_double && ch == '\'' {
            in_single = !in_single;
            continue;
        }
        if !in_double && !in_single && ch == '#' {
            return &line[..idx];
        }
    }
    line
}

pub(super) fn split_toml_items(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_double = false;
    let mut in_single = false;
    let mut escape = false;
    let mut depth = 0i32;
    for ch in inner.chars() {
        if escape {
            cur.push(ch);
            escape = false;
            continue;
        }
        if in_double && ch == '\\' {
            cur.push(ch);
            escape = true;
            continue;
        }
        if !in_single && ch == '"' {
            in_double = !in_double;
            cur.push(ch);
            continue;
        }
        if !in_double && ch == '\'' {
            in_single = !in_single;
            cur.push(ch);
            continue;
        }
        if !in_double && !in_single {
            match ch {
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    if !cur.trim().is_empty() {
                        out.push(cur.trim().to_string());
                    }
                    cur.clear();
                    continue;
                }
                _ => {}
            }
        }
        cur.push(ch);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

pub(super) fn parse_toml_value(raw: &str) -> Value {
    let t = raw.trim();
    if let Some(s) = unquote_toml_str(t) {
        return Value::String(s);
    }
    if t == "true" {
        return Value::Bool(true);
    }
    if t == "false" {
        return Value::Bool(false);
    }
    if t.starts_with('[') && t.ends_with(']') {
        let items = split_toml_items(&t[1..t.len() - 1]);
        return Value::Array(items.into_iter().map(|i| parse_toml_value(&i)).collect());
    }
    if t.starts_with('{') && t.ends_with('}') {
        let mut map = Map::new();
        for item in split_toml_items(&t[1..t.len() - 1]) {
            if let Some((k, v)) = item.split_once('=') {
                let clean_k = unquote_toml_str(k).unwrap_or_else(|| k.trim().to_string());
                map.insert(clean_k, parse_toml_value(v));
            }
        }
        return Value::Object(map);
    }
    Value::String(t.to_string())
}

pub(super) fn parse_mcp_table_header(header_line: &str) -> Option<(String, Option<String>)> {
    let trimmed = strip_toml_comment(header_line).trim();
    if !(trimmed.starts_with('[') && !trimmed.starts_with("[[") && trimmed.ends_with(']')) {
        return None;
    }
    let body = trimmed[1..trimmed.len() - 1].trim();
    let rest = body.strip_prefix("mcp_servers.")?;
    let (key, sub) = if let Some(after_quote) = rest.strip_prefix('"') {
        let end_q = after_quote.find('"')?;
        let key = after_quote[..end_q].to_string();
        let rem = after_quote[end_q + 1..].trim();
        let sub = rem.strip_prefix('.').map(|s| s.trim().to_string());
        (key, sub)
    } else if let Some((k, s)) = rest.split_once('.') {
        (k.trim().to_string(), Some(s.trim().to_string()))
    } else {
        (rest.trim().to_string(), None)
    };
    if key.is_empty() {
        return None;
    }
    Some((key, sub))
}

pub(super) fn bracket_balance_delta(s: &str) -> i32 {
    let mut delta = 0i32;
    let mut in_double = false;
    let mut in_single = false;
    let mut escape = false;
    for ch in s.chars() {
        if escape {
            escape = false;
            continue;
        }
        if in_double && ch == '\\' {
            escape = true;
            continue;
        }
        if !in_single && ch == '"' {
            in_double = !in_double;
            continue;
        }
        if !in_double && ch == '\'' {
            in_single = !in_single;
            continue;
        }
        if !in_double && !in_single {
            match ch {
                '[' | '{' => delta += 1,
                ']' | '}' => delta -= 1,
                _ => {}
            }
        }
    }
    delta
}

pub(super) fn parse_codex_section_kv(lines: &[&str]) -> Value {
    let mut root = Map::new();
    let mut current_subtable: Option<String> = None;
    let mut pending_kv: Option<String> = None;
    let mut depth = 0i32;

    for &raw_line in lines {
        let code = strip_toml_comment(raw_line).trim();
        if let Some(mut buf) = pending_kv.take() {
            buf.push(' ');
            buf.push_str(code);
            depth += bracket_balance_delta(code);
            if depth > 0 {
                pending_kv = Some(buf);
                continue;
            }
            if let Some((k, v)) = buf.split_once('=') {
                let clean_k = unquote_toml_str(k).unwrap_or_else(|| k.trim().to_string());
                let val = parse_toml_value(v);
                if let Some(ref sub) = current_subtable {
                    let sub_obj = root
                        .entry(sub.clone())
                        .or_insert_with(|| Value::Object(Map::new()));
                    if let Some(m) = sub_obj.as_object_mut() {
                        m.insert(clean_k, val);
                    }
                } else {
                    root.insert(clean_k, val);
                }
            }
            continue;
        }
        if code.is_empty() {
            continue;
        }
        if let Some((_, sub)) = parse_mcp_table_header(code) {
            current_subtable = sub;
            continue;
        }
        if let Some((k, v)) = code.split_once('=') {
            depth = bracket_balance_delta(v);
            if depth > 0 {
                pending_kv = Some(code.to_string());
                continue;
            }
            let clean_k = unquote_toml_str(k).unwrap_or_else(|| k.trim().to_string());
            let val = parse_toml_value(v);
            if let Some(ref sub) = current_subtable {
                let sub_obj = root
                    .entry(sub.clone())
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Some(m) = sub_obj.as_object_mut() {
                    m.insert(clean_k, val);
                }
            } else {
                root.insert(clean_k, val);
            }
        }
    }

    Value::Object(root)
}

pub(super) fn scan_codex_mcp_sections(src: &str) -> Vec<CodexTomlSectionBlock> {
    let lines: Vec<&str> = src.lines().collect();
    let mut blocks = Vec::new();
    let mut in_managed_block = false;
    let mut i = 0usize;

    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed == "# --- AEGIS-OS-RUNTIME-START ---" {
            in_managed_block = true;
            i += 1;
            continue;
        }
        if trimmed == "# --- AEGIS-OS-RUNTIME-END ---" {
            in_managed_block = false;
            i += 1;
            continue;
        }
        if in_managed_block {
            i += 1;
            continue;
        }
        if let Some((key, _sub)) = parse_mcp_table_header(lines[i]) {
            let start = i;
            let mut end = i + 1;
            while end < lines.len() {
                let t = strip_toml_comment(lines[end]).trim();
                if t == "# --- AEGIS-OS-RUNTIME-START ---" || t == "# --- AEGIS-OS-RUNTIME-END ---" {
                    break;
                }
                if t.starts_with('[') && t.ends_with(']') {
                    if let Some((next_key, _)) = parse_mcp_table_header(lines[end]) {
                        if next_key != key {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                end += 1;
            }
            let slice = &lines[start..end];
            let mut raw_block = slice.join("\n");
            if end < lines.len() || src.ends_with('\n') {
                raw_block.push('\n');
            }
            let parsed_entry = parse_codex_section_kv(slice);
            blocks.push(CodexTomlSectionBlock {
                server_key: key,
                start_line: start,
                end_line: end,
                raw_block,
                parsed_entry,
            });
            i = end;
            continue;
        }
        i += 1;
    }

    blocks
}

pub(super) fn format_toml_key(key: &str) -> String {
    if !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        key.to_string()
    } else {
        serde_json::to_string(key).unwrap_or_else(|_| format!("\"{}\"", key))
    }
}

pub(super) fn render_codex_proxy_block(
    server_key: &str,
    bin_str: &str,
    proxy_args: &[String],
    extra_env: Option<&BTreeMap<String, String>>,
) -> String {
    let args_json = proxy_args
        .iter()
        .map(|a| serde_json::to_string(a).unwrap_or_else(|_| format!("\"{}\"", a)))
        .collect::<Vec<_>>()
        .join(", ");
    let bin_json = serde_json::to_string(bin_str).unwrap_or_else(|_| format!("\"{}\"", bin_str));
    let fmt_key = format_toml_key(server_key);
    let mut out = format!(
        "[mcp_servers.{}]\ncommand = {}\nargs = [{}]\nenabled = true\n",
        fmt_key, bin_json, args_json
    );
    if let Some(env_map) = extra_env.filter(|m| !m.is_empty()) {
        out.push_str(&format!("[mcp_servers.{}.env]\n", fmt_key));
        for (k, v) in env_map {
            let v_json = serde_json::to_string(v).unwrap_or_else(|_| format!("\"{}\"", v));
            out.push_str(&format!("{} = {}\n", format_toml_key(k), v_json));
        }
    }
    out
}

pub(super) fn replace_toml_line_range(src: &str, start_line: usize, end_line: usize, replacement: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = String::new();
    for line in lines.iter().take(start_line) {
        out.push_str(line);
        out.push('\n');
    }
    if !replacement.is_empty() {
        out.push_str(replacement.trim_end_matches('\n'));
        out.push('\n');
    }
    for line in lines.iter().skip(end_line) {
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormatKind {
    McpServersJson,
    OpenCodeJson,
    CodexToml,
}

pub fn client_config_candidates(
    home_dir: &Path,
    workspace: &Path,
) -> Vec<(&'static str, PathBuf, ConfigFormatKind)> {
    let mut out = vec![
        ("claude", home_dir.join(".claude.json"), ConfigFormatKind::McpServersJson),
        ("project-mcp", workspace.join(".mcp.json"), ConfigFormatKind::McpServersJson),
        (
            "agy",
            home_dir.join(".gemini").join("config").join("mcp_config.json"),
            ConfigFormatKind::McpServersJson,
        ),
        (
            "agy-cli",
            home_dir
                .join(".gemini")
                .join("antigravity-cli")
                .join("mcp_config.json"),
            ConfigFormatKind::McpServersJson,
        ),
        (
            "cursor-global",
            home_dir.join(".cursor").join("mcp.json"),
            ConfigFormatKind::McpServersJson,
        ),
        (
            "cursor-project",
            workspace.join(".cursor").join("mcp.json"),
            ConfigFormatKind::McpServersJson,
        ),
        (
            "opencode",
            home_dir
                .join(".config")
                .join("opencode")
                .join("opencode.json"),
            ConfigFormatKind::OpenCodeJson,
        ),
        (
            "codex",
            home_dir.join(".codex").join("config.toml"),
            ConfigFormatKind::CodexToml,
        ),
    ];
    // Deduplicate identical paths if workspace == home_dir.
    let mut seen = BTreeSet::new();
    out.retain(|(_, p, _)| seen.insert(p.clone()));
    out
}

pub(super) fn strip_aegis_codex_managed_block(src: &str) -> (String, bool) {
    let mut out = Vec::new();
    let mut in_managed_block = false;
    let mut removed = false;
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed == "# --- AEGIS-OS-RUNTIME-START ---" {
            in_managed_block = true;
            removed = true;
            continue;
        }
        if trimmed == "# --- AEGIS-OS-RUNTIME-END ---" {
            in_managed_block = false;
            removed = true;
            continue;
        }
        if !in_managed_block {
            out.push(line);
        }
    }
    if !removed {
        return (src.to_string(), false);
    }
    let mut joined = out.join("\n");
    if src.ends_with('\n') && !joined.is_empty() && !joined.ends_with('\n') {
        joined.push('\n');
    }
    (joined, true)
}

pub(super) fn claude_project_key(client: &str) -> Option<&str> {
    client.strip_prefix("claude-project:")
}

/// Scans all supported client MCP configurations without mutating files or exposing secret values.
pub fn scan_client_configs(home_dir: &Path, workspace: &Path) -> Vec<DiscoveredClientMcpServer> {
    let mut discovered = Vec::new();
    for (client, path, kind) in client_config_candidates(home_dir, workspace) {
        let Ok(raw_text) = std::fs::read_to_string(&path) else {
            continue;
        };
        match kind {
            ConfigFormatKind::McpServersJson => {
                let Ok(root) = serde_json::from_str::<Value>(&raw_text) else {
                    continue;
                };
                if let Some(servers) = root.get("mcpServers").and_then(|v| v.as_object()) {
                    for (key, entry) in servers {
                        if key == "aegis-os" {
                            continue;
                        }
                        let already_adopted = is_already_aegis_proxy_entry(key, entry);
                        let Some((transport_kind, plaintext_secret_keys)) =
                            inspect_entry_secrets_and_transport(entry)
                        else {
                            continue;
                        };
                        discovered.push(DiscoveredClientMcpServer {
                            server_id: sanitize_server_id(key),
                            client: client.to_string(),
                            config_path: path.clone(),
                            server_key: key.clone(),
                            already_adopted,
                            transport_kind,
                            plaintext_secret_keys,
                            raw_entry: entry.clone(),
                        });
                    }
                }
                if client == "claude" {
                    if let Some(projects) = root.get("projects").and_then(|v| v.as_object()) {
                        for (proj_path, proj_val) in projects {
                            let Some(proj_servers) =
                                proj_val.get("mcpServers").and_then(|v| v.as_object())
                            else {
                                continue;
                            };
                            for (key, entry) in proj_servers {
                                if key == "aegis-os" {
                                    continue;
                                }
                                let already_adopted = is_already_aegis_proxy_entry(key, entry);
                                let Some((transport_kind, plaintext_secret_keys)) =
                                    inspect_entry_secrets_and_transport(entry)
                                else {
                                    continue;
                                };
                                discovered.push(DiscoveredClientMcpServer {
                                    server_id: sanitize_server_id(key),
                                    client: format!("claude-project:{proj_path}"),
                                    config_path: path.clone(),
                                    server_key: key.clone(),
                                    already_adopted,
                                    transport_kind,
                                    plaintext_secret_keys,
                                    raw_entry: entry.clone(),
                                });
                            }
                        }
                    }
                }
            }
            ConfigFormatKind::OpenCodeJson => {
                let Ok(root) = serde_json::from_str::<Value>(&raw_text) else {
                    continue;
                };
                let Some(servers) = root
                    .pointer("/mcp/servers")
                    .or_else(|| root.get("mcp"))
                    .and_then(|v| v.as_object())
                else {
                    continue;
                };
                for (key, entry) in servers {
                    if key == "aegis-os" || key == "servers" {
                        continue;
                    }
                    let already_adopted = is_already_aegis_proxy_entry(key, entry);
                    let Some((transport_kind, plaintext_secret_keys)) =
                        inspect_entry_secrets_and_transport(entry)
                    else {
                        continue;
                    };
                    discovered.push(DiscoveredClientMcpServer {
                        server_id: sanitize_server_id(key),
                        client: client.to_string(),
                        config_path: path.clone(),
                        server_key: key.clone(),
                        already_adopted,
                        transport_kind,
                        plaintext_secret_keys,
                        raw_entry: entry.clone(),
                    });
                }
            }
            ConfigFormatKind::CodexToml => {
                for block in scan_codex_mcp_sections(&raw_text) {
                    if block.server_key == "aegis-os" {
                        continue;
                    }
                    let already_adopted =
                        is_already_aegis_proxy_entry(&block.server_key, &block.parsed_entry);
                    let Some((transport_kind, plaintext_secret_keys)) =
                        inspect_entry_secrets_and_transport(&block.parsed_entry)
                    else {
                        continue;
                    };
                    discovered.push(DiscoveredClientMcpServer {
                        server_id: sanitize_server_id(&block.server_key),
                        client: client.to_string(),
                        config_path: path.clone(),
                        server_key: block.server_key,
                        already_adopted,
                        transport_kind,
                        plaintext_secret_keys,
                        raw_entry: json!({
                            "format": "toml_block",
                            "raw_block": block.raw_block,
                            "parsed": block.parsed_entry,
                        }),
                    });
                }
            }
        }
    }
    discovered
}

// ============================================================================
// Client Config Writers for `adopt` / `unadopt` / `bundle` / Confined Staging
// ============================================================================

pub(super) fn build_json_proxy_entry(
    client: &str,
    bin_str: &str,
    proxy_args: &[String],
    extra_env: Option<&BTreeMap<String, String>>,
) -> Value {
    let mut entry = match client {
        "opencode" => {
            let mut cmd = Vec::with_capacity(proxy_args.len() + 1);
            cmd.push(bin_str.to_string());
            cmd.extend(proxy_args.iter().cloned());
            json!({
                "type": "local",
                "command": cmd,
            })
        }
        c if c == "claude" || claude_project_key(c).is_some() => json!({
            "type": "stdio",
            "command": bin_str,
            "args": proxy_args,
        }),
        _ => json!({
            "command": bin_str,
            "args": proxy_args,
        }),
    };
    if let Some(env_map) = extra_env.filter(|m| !m.is_empty()) {
        if let Some(obj) = entry.as_object_mut() {
            let key = if client == "opencode" {
                "environment"
            } else {
                "env"
            };
            obj.insert(key.to_string(), json!(env_map));
        }
    }
    entry
}

/// Inserts or updates a managed `aegis-os mcp proxy <server_id>` entry across all supported
/// client config formats (JSON `mcpServers`, OpenCode `mcp.servers`/`mcp`, and Codex TOML).
/// Creates the file with minimal valid structure if it does not yet exist.
pub fn upsert_client_proxy_entry(
    client: &str,
    config_path: &Path,
    server_key: &str,
    bin_str: &str,
    proxy_args: &[String],
    extra_env: Option<&BTreeMap<String, String>>,
) -> anyhow::Result<bool> {
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = if config_path.is_file() {
        std::fs::read_to_string(config_path)
            .with_context(|| format!("reading client MCP config '{}'", config_path.display()))?
    } else {
        String::new()
    };
    match client {
        "codex" => {
            let replacement = render_codex_proxy_block(server_key, bin_str, proxy_args, extra_env);
            let working_text = if server_key == "aegis-os" {
                strip_aegis_codex_managed_block(&text).0
            } else {
                text
            };
            let sections = scan_codex_mcp_sections(&working_text);
            let updated = if let Some(target) =
                sections.into_iter().find(|s| s.server_key == server_key)
            {
                replace_toml_line_range(
                    &working_text,
                    target.start_line,
                    target.end_line,
                    &replacement,
                )
            } else if working_text.trim().is_empty() {
                replacement
            } else {
                let mut out = working_text.trim_end().to_string();
                out.push_str("\n\n");
                out.push_str(&replacement);
                out
            };
            std::fs::write(config_path, updated)?;
        }
        "opencode" => {
            let mut root: Value = if text.trim().is_empty() {
                json!({ "mcp": { "servers": {} } })
            } else {
                serde_json::from_str(&text)
                    .with_context(|| format!("parsing JSON config '{}'", config_path.display()))?
            };
            let proxy_entry = build_json_proxy_entry(client, bin_str, proxy_args, extra_env);
            if let Some(servers) = root.pointer_mut("/mcp/servers").and_then(|v| v.as_object_mut()) {
                servers.insert(server_key.to_string(), proxy_entry);
            } else if let Some(mcp_obj) = root.get_mut("mcp").and_then(|v| v.as_object_mut()) {
                mcp_obj.insert(server_key.to_string(), proxy_entry);
            } else if let Some(root_obj) = root.as_object_mut() {
                root_obj.insert("mcp".to_string(), json!({ "servers": { server_key: proxy_entry } }));
            } else {
                bail!("opencode.json root is not an object in {}", config_path.display());
            }
            std::fs::write(config_path, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
        }
        c if claude_project_key(c).is_some() => {
            let proj = claude_project_key(c)
                .with_context(|| format!("missing Claude project key for client '{c}'"))?;
            let mut root: Value = if text.trim().is_empty() {
                json!({ "projects": {} })
            } else {
                serde_json::from_str(&text)
                    .with_context(|| format!("parsing JSON config '{}'", config_path.display()))?
            };
            let root_obj = root.as_object_mut().with_context(|| {
                format!("JSON config root is not an object in {}", config_path.display())
            })?;
            let projects_val = root_obj.entry("projects").or_insert_with(|| json!({}));
            if !projects_val.is_object() {
                *projects_val = json!({});
            }
            let projects_obj = projects_val
                .as_object_mut()
                .context("normalized projects entry is not a JSON object")?;
            let proj_val = projects_obj
                .entry(proj.to_string())
                .or_insert_with(|| json!({}));
            if !proj_val.is_object() {
                *proj_val = json!({});
            }
            let proj_obj = proj_val
                .as_object_mut()
                .context("normalized project entry is not a JSON object")?;
            let servers_val = proj_obj.entry("mcpServers").or_insert_with(|| json!({}));
            if !servers_val.is_object() {
                *servers_val = json!({});
            }
            let servers = servers_val
                .as_object_mut()
                .context("normalized mcpServers entry is not a JSON object")?;
            servers.insert(
                server_key.to_string(),
                build_json_proxy_entry(client, bin_str, proxy_args, extra_env),
            );
            std::fs::write(config_path, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
        }
        _ => {
            let mut root: Value = if text.trim().is_empty() {
                json!({ "mcpServers": {} })
            } else {
                serde_json::from_str(&text)
                    .with_context(|| format!("parsing JSON config '{}'", config_path.display()))?
            };
            let root_obj = root
                .as_object_mut()
                .with_context(|| format!("JSON config root is not an object in {}", config_path.display()))?;
            let servers_val = root_obj
                .entry("mcpServers")
                .or_insert_with(|| json!({}));
            if !servers_val.is_object() {
                *servers_val = json!({});
            }
            let servers = servers_val
                .as_object_mut()
                .context("normalized mcpServers entry is not a JSON object")?;
            servers.insert(
                server_key.to_string(),
                build_json_proxy_entry(client, bin_str, proxy_args, extra_env),
            );
            std::fs::write(config_path, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
        }
    }
    Ok(true)
}

/// Removes `server_key` from a client MCP configuration file without disturbing unrelated keys.
pub fn remove_client_proxy_entry(
    client: &str,
    config_path: &Path,
    server_key: &str,
) -> anyhow::Result<bool> {
    if !config_path.is_file() {
        return Ok(false);
    }
    let text = std::fs::read_to_string(config_path)?;
    if text.trim().is_empty() {
        return Ok(false);
    }
    match client {
        "codex" => {
            let (mut updated, mut changed) = if server_key == "aegis-os" {
                strip_aegis_codex_managed_block(&text)
            } else {
                (text, false)
            };
            let sections = scan_codex_mcp_sections(&updated);
            if let Some(target) = sections.into_iter().find(|s| s.server_key == server_key) {
                updated = replace_toml_line_range(&updated, target.start_line, target.end_line, "");
                changed = true;
            }
            if changed {
                std::fs::write(config_path, updated)?;
                return Ok(true);
            }
            Ok(false)
        }
        "opencode" => {
            let mut root: Value = serde_json::from_str(&text)?;
            let mut removed = false;
            if let Some(servers) = root.pointer_mut("/mcp/servers").and_then(|v| v.as_object_mut()) {
                removed = servers.remove(server_key).is_some();
            } else if let Some(mcp_obj) = root.get_mut("mcp").and_then(|v| v.as_object_mut()) {
                removed = mcp_obj.remove(server_key).is_some();
            }
            if removed {
                std::fs::write(config_path, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
            }
            Ok(removed)
        }
        c if claude_project_key(c).is_some() => {
            let proj = claude_project_key(c)
                .with_context(|| format!("missing Claude project key for client '{c}'"))?;
            let mut root: Value = serde_json::from_str(&text)?;
            let removed = root
                .get_mut("projects")
                .and_then(|p| p.get_mut(proj))
                .and_then(|pv| pv.get_mut("mcpServers"))
                .and_then(|v| v.as_object_mut())
                .is_some_and(|m| m.remove(server_key).is_some());
            if removed {
                std::fs::write(config_path, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
            }
            Ok(removed)
        }
        _ => {
            let mut root: Value = serde_json::from_str(&text)?;
            let removed = root
                .get_mut("mcpServers")
                .and_then(|v| v.as_object_mut())
                .is_some_and(|m| m.remove(server_key).is_some());
            if removed {
                std::fs::write(config_path, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
            }
            Ok(removed)
        }
    }
}

pub(super) fn restore_client_config_from_origin(
    origin: &AdoptedConfigOrigin,
    original_val: &Value,
) -> anyhow::Result<()> {
    let path = Path::new(&origin.config_path);
    if !path.exists() {
        return Ok(());
    }
    let text = std::fs::read_to_string(path)?;
    match origin.client.as_str() {
        "codex" => {
            let raw_block = original_val
                .get("raw_block")
                .and_then(|v| v.as_str())
                .context("missing raw_block in Codex unseal backup")?;
            let sections = scan_codex_mcp_sections(&text);
            if let Some(target) = sections.into_iter().find(|s| s.server_key == origin.server_key) {
                let updated = replace_toml_line_range(
                    &text,
                    target.start_line,
                    target.end_line,
                    raw_block,
                );
                std::fs::write(path, updated)?;
            } else {
                let mut appended = text.trim_end().to_string();
                appended.push_str("\n\n");
                appended.push_str(raw_block.trim_end());
                appended.push('\n');
                std::fs::write(path, appended)?;
            }
        }
        "opencode" => {
            let mut root: Value = serde_json::from_str(&text)?;
            if let Some(servers) = root.pointer_mut("/mcp/servers").and_then(|v| v.as_object_mut()) {
                servers.insert(origin.server_key.clone(), original_val.clone());
            } else if let Some(mcp_obj) = root.get_mut("mcp").and_then(|v| v.as_object_mut()) {
                mcp_obj.insert(origin.server_key.clone(), original_val.clone());
            }
            std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
        }
        c if claude_project_key(c).is_some() => {
            let proj = claude_project_key(c)
                .with_context(|| format!("missing Claude project key for client '{c}'"))?;
            let mut root: Value = serde_json::from_str(&text)?;
            if let Some(servers) = root
                .get_mut("projects")
                .and_then(|p| p.get_mut(proj))
                .and_then(|pv| pv.get_mut("mcpServers"))
                .and_then(|v| v.as_object_mut())
            {
                servers.insert(origin.server_key.clone(), original_val.clone());
                std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
            }
        }
        _ => {
            let mut root: Value = serde_json::from_str(&text)?;
            if let Some(servers) = root.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
                servers.insert(origin.server_key.clone(), original_val.clone());
                std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
            }
        }
    }
    Ok(())
}
