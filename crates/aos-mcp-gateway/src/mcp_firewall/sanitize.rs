use super::*;

/// Returns `true` when an env/header key name or value matches a credential/secret pattern.
pub fn is_sensitive_kv(key: &str, val: &str) -> bool {
    let key_upper = key.to_ascii_uppercase();
    const KEY_MARKERS: &[&str] = &[
        "TOKEN",
        "SECRET",
        "KEY",
        "PASSWORD",
        "PASSWD",
        "AUTH",
        "CREDENTIAL",
        "COOKIE",
        "DATABASE_URL",
        "DSN",
        "WEBHOOK",
        "PRIVATE",
    ];
    if KEY_MARKERS.iter().any(|m| key_upper.contains(m)) {
        return true;
    }

    let trimmed = val.trim();
    let val_lower = trimmed.to_ascii_lowercase();
    if trimmed.starts_with("sk-")
        || trimmed.starts_with("ghp_")
        || trimmed.starts_with("github_pat_")
        || trimmed.starts_with("xoxb-")
        || trimmed.starts_with("xoxp-")
        || trimmed.starts_with("AKIA")
        || val_lower.starts_with("bearer ")
    {
        return true;
    }
    if let Some((_, after_scheme)) = trimmed.split_once("://") {
        let authority = after_scheme.split('/').next().unwrap_or("");
        if let Some((userinfo, _host)) = authority.split_once('@') {
            if userinfo.contains(':') {
                return true;
            }
        }
    }
    false
}

/// Canonical JSON serialization with lexicographically sorted object keys for deterministic hashing.
pub fn canonical_json_bytes(val: &Value) -> Vec<u8> {
    fn normalize(v: &Value) -> Value {
        match v {
            Value::Array(arr) => Value::Array(arr.iter().map(normalize).collect()),
            Value::Object(map) => {
                let mut sorted = BTreeMap::new();
                for (k, inner) in map {
                    sorted.insert(k.clone(), normalize(inner));
                }
                let mut out = Map::new();
                for (k, inner) in sorted {
                    out.insert(k, inner);
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }
    serde_json::to_vec(&normalize(val)).unwrap_or_else(|_| b"{}".to_vec())
}

pub fn compute_outbox_payload_sha256(server_id: &str, tool_name: &str, args: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(server_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(tool_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(canonical_json_bytes(args));
    hex::encode(hasher.finalize())
}

pub(super) fn mask_high_risk_secrets_in_text(text: &str) -> (String, usize) {
    let (mut out, mut hits) = redact_dlp_secrets(text);
    if out.contains("-----BEGIN ") && out.contains("PRIVATE KEY-----") {
        let mut scrubbed = String::with_capacity(out.len());
        let mut rest = out.as_str();
        while let Some(start) = rest.find("-----BEGIN ") {
            if let Some(begin_end_rel) = rest[start..].find("PRIVATE KEY-----") {
                let block_search = &rest[start + begin_end_rel..];
                if let Some(end_rel) = block_search.find("-----END ") {
                    if let Some(final_rel) = block_search[end_rel..].find("-----") {
                        scrubbed.push_str(&rest[..start]);
                        scrubbed.push_str("[REDACTED_PRIVATE_KEY]");
                        rest = &rest[start + begin_end_rel + end_rel + final_rel + 5..];
                        hits.push("PEM Private Key");
                        continue;
                    }
                }
            }
            scrubbed.push_str(&rest[..start + 11]);
            rest = &rest[start + 11..];
        }
        scrubbed.push_str(rest);
        out = scrubbed;
    }
    (out, hits.len())
}

pub fn mask_secrets_for_preview(val: &Value) -> Value {
    match val {
        Value::String(s) => Value::String(mask_high_risk_secrets_in_text(s).0),
        Value::Array(arr) => Value::Array(arr.iter().map(mask_secrets_for_preview).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                out.insert(k.clone(), mask_secrets_for_preview(v));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

pub fn sanitize_server_id(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = clean.trim_matches('-');
    if trimmed.is_empty() {
        format!("mcp-{}", &Uuid::new_v4().simple().to_string()[..6])
    } else {
        trimmed.to_string()
    }
}

pub(super) fn strip_hidden_html_blocks(input: &str) -> (String, usize) {
    let mut current = input.to_string();
    let mut signals = 0usize;

    // 1. Strip `<script ...>...</script>`, `<style ...>...</style>`, and `<!-- ... -->`.
    for (open_tag, close_tag) in [
        ("<script", "</script>"),
        ("<style", "</style>"),
        ("<!--", "-->"),
    ] {
        let mut search_offset = 0usize;
        loop {
            let lower = current.to_ascii_lowercase();
            if search_offset >= lower.len() {
                break;
            }
            let Some(rel) = lower[search_offset..].find(open_tag) else {
                break;
            };
            let start = search_offset + rel;
            // Ensure `<script` matches `<script>` or `<script ...`, not `<scripting>`.
            if open_tag.starts_with('<') && open_tag != "<!--" {
                let after = lower.as_bytes().get(start + open_tag.len()).copied();
                if after.is_some_and(|b| !b.is_ascii_whitespace() && b != b'>' && b != b'/') {
                    search_offset = start + open_tag.len();
                    continue;
                }
            }
            let search_from = start + open_tag.len();
            let end = lower[search_from..]
                .find(close_tag)
                .map(|r| search_from + r + close_tag.len())
                .unwrap_or_else(|| {
                    lower[search_from..]
                        .find('>')
                        .map(|r| search_from + r + 1)
                        .unwrap_or(current.len())
                });
            current.replace_range(start..end, "");
            signals += 1;
            search_offset = start.min(current.len());
        }
    }

    // 2. Strip HTML tags carrying hidden inline CSS styles or 1x1 / 0x0 tracking <img> pixels.
    let mut out = String::with_capacity(current.len());
    let mut idx = 0usize;
    let bytes = current.as_bytes();
    while idx < bytes.len() {
        if bytes[idx] == b'<' {
            if let Some(close_rel) = current[idx..].find('>') {
                let tag_end = idx + close_rel + 1;
                let tag_raw = &current[idx..tag_end];
                let tag_compact: String = tag_raw
                    .to_ascii_lowercase()
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect();

                let is_hidden_style = tag_compact.contains("display:none")
                    || tag_compact.contains("visibility:hidden")
                    || tag_compact.contains("opacity:0;")
                    || tag_compact.contains("opacity:0\"")
                    || tag_compact.contains("opacity:0'")
                    || tag_compact.contains("font-size:0")
                    || tag_compact.contains("fontsize:0");
                let is_tracking_pixel = tag_compact.starts_with("<img")
                    && (tag_compact.contains("width=\"1\"")
                        || tag_compact.contains("width='1'")
                        || tag_compact.contains("width=1")
                        || tag_compact.contains("height=\"1\"")
                        || tag_compact.contains("height='1'")
                        || tag_compact.contains("width=\"0\"")
                        || tag_compact.contains("height=\"0\""));

                if is_hidden_style {
                    signals += 1;
                    // If paired tag, advance past matching closing tag when present.
                    let tag_name: String = tag_raw[1..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ':')
                        .collect::<String>()
                        .to_ascii_lowercase();
                    if !tag_raw.ends_with("/>") && !tag_name.is_empty() {
                        let closing = format!("</{tag_name}>");
                        let rest_lower = current[tag_end..].to_ascii_lowercase();
                        if let Some(close_tag_rel) = rest_lower.find(&closing) {
                            idx = tag_end + close_tag_rel + closing.len();
                            continue;
                        }
                    }
                    idx = tag_end;
                    continue;
                }
                if is_tracking_pixel {
                    signals += 1;
                    idx = tag_end;
                    continue;
                }
            }
        }
        let ch = current[idx..].chars().next().unwrap();
        out.push(ch);
        idx += ch.len_utf8();
    }

    (out, signals)
}

pub(super) fn is_zero_width_or_bidi_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

/// Sanitizes untrusted inbound MCP text against hidden HTML/CSS injections, tracking pixels,
/// zero-width / bidirectional override characters, and leaked raw secrets.
pub fn sanitize_inbound_mcp_text(text: &str) -> (String, usize) {
    let (html_cleaned, html_signals) = strip_hidden_html_blocks(text);
    let mut zw_count = 0usize;
    let mut cleaned = String::with_capacity(html_cleaned.len());
    for ch in html_cleaned.chars() {
        if is_zero_width_or_bidi_char(ch) {
            zw_count += 1;
        } else {
            cleaned.push(ch);
        }
    }
    let (secret_scrubbed, secret_hits) = mask_high_risk_secrets_in_text(&cleaned);
    (secret_scrubbed, html_signals + zw_count + secret_hits)
}

pub(super) fn apply_inbound_dlp(
    val: &mut Value,
    dlp_mode: PseudonymMode,
    pseudonym_table: &PseudonymSessionTable,
) -> (u64, bool) {
    match dlp_mode {
        PseudonymMode::Off => (0, false),
        PseudonymMode::Pseudonymize => (pseudonym_table.pseudonymize_json_value(val, &[]), false),
        PseudonymMode::Block => {
            let probe_table = PseudonymSessionTable::new();
            let mut probe_val = val.clone();
            let hits = probe_table.pseudonymize_json_value(&mut probe_val, &[]);
            (hits, hits > 0)
        }
    }
}

pub fn sanitize_inbound_mcp_value(val: &mut Value, strip_injection: bool) -> usize {
    sanitize_inbound_mcp_value_at(val, strip_injection, 0, false)
}

pub(super) fn sanitize_inbound_mcp_value_at(
    val: &mut Value,
    strip_injection: bool,
    depth: usize,
    in_content_item: bool,
) -> usize {
    let mut signals = 0usize;
    match val {
        Value::String(s) => {
            if strip_injection {
                let (clean, count) = sanitize_inbound_mcp_text(s);
                if clean != *s {
                    *s = clean;
                }
                signals += count;
            } else {
                let (clean, count) = mask_high_risk_secrets_in_text(s);
                if clean != *s {
                    *s = clean;
                }
                signals += count;
            }
        }
        Value::Array(arr) => {
            for item in arr {
                signals +=
                    sanitize_inbound_mcp_value_at(item, strip_injection, depth + 1, in_content_item);
            }
        }
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                let skip = (depth == 0 && matches!(k.as_str(), "jsonrpc" | "id" | "method"))
                    || (in_content_item && matches!(k.as_str(), "type" | "mimeType" | "role"));
                if skip {
                    continue;
                }
                let child_is_content_items = (depth <= 1
                    && matches!(k.as_str(), "content" | "contents" | "messages")
                    && v.is_array())
                    || (in_content_item && k == "content");
                signals += sanitize_inbound_mcp_value_at(
                    v,
                    strip_injection,
                    depth + 1,
                    child_is_content_items,
                );
            }
        }
        _ => {}
    }
    signals
}

pub(super) fn split_identifier_tokens(name: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (i, &ch) in chars.iter().enumerate() {
        if !ch.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                tokens.push(cur.to_ascii_lowercase());
                cur.clear();
            }
            continue;
        }
        if !cur.is_empty()
            && ch.is_ascii_uppercase()
            && chars
                .get(i.saturating_sub(1))
                .is_some_and(|prev| prev.is_ascii_lowercase() || prev.is_ascii_digit())
        {
            tokens.push(cur.to_ascii_lowercase());
            cur.clear();
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        tokens.push(cur.to_ascii_lowercase());
    }
    tokens
}

pub(super) fn strip_sql_comments_and_literals(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        // Line comment `-- ...`
        if ch == '-' && chars.get(i + 1) == Some(&'-') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            out.push(' ');
            continue;
        }
        // Block comment `/* ... */`
        if ch == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            out.push(' ');
            continue;
        }
        // Single-quoted string literal `'...'` (handles `''` and `\'` escapes)
        if ch == '\'' {
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 2;
                    continue;
                }
                if chars[i] == '\'' {
                    if chars.get(i + 1) == Some(&'\'') {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push(' ');
            continue;
        }
        out.push(ch);
        i += 1;
    }
    out
}

pub(super) fn sql_word_tokens(stmt: &str) -> Vec<String> {
    stmt.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_uppercase())
        .collect()
}

pub(super) fn is_sql_statement_starter(word: &str) -> bool {
    matches!(
        word,
        "SELECT"
            | "WITH"
            | "EXPLAIN"
            | "SHOW"
            | "DESCRIBE"
            | "DESC"
            | "PRAGMA"
            | "VALUES"
            | "INSERT"
            | "UPDATE"
            | "REPLACE"
            | "CREATE"
            | "MERGE"
            | "UPSERT"
            | "CALL"
            | "EXEC"
            | "EXECUTE"
            | "COPY"
            | "ATTACH"
            | "DO"
            | "PERFORM"
            | "DROP"
            | "TRUNCATE"
            | "ALTER"
            | "DELETE"
            | "GRANT"
            | "REVOKE"
            | "VACUUM"
            | "DETACH"
            | "BEGIN"
            | "COMMIT"
            | "ROLLBACK"
            | "SAVEPOINT"
    )
}

pub(super) fn classify_sql_text(sql: &str) -> Option<McpToolRiskClass> {
    let cleaned = strip_sql_comments_and_literals(sql);
    let stmts: Vec<Vec<String>> = cleaned
        .split(';')
        .map(sql_word_tokens)
        .filter(|toks| !toks.is_empty())
        .collect();
    if stmts.is_empty() {
        return None;
    }
    // Non-SQL prose in a single `query` parameter (e.g. search queries) must not trigger SQL rules.
    let any_sql_starter = stmts
        .iter()
        .any(|toks| is_sql_statement_starter(toks[0].as_str()));
    if !any_sql_starter {
        return None;
    }

    let mut seen_read = false;
    let mut seen_write = false;
    for tokens in &stmts {
        for word in tokens {
            if matches!(
                word.as_str(),
                "DROP" | "TRUNCATE" | "ALTER" | "DELETE" | "GRANT" | "REVOKE" | "VACUUM" | "DETACH"
            ) {
                return Some(McpToolRiskClass::Destructive);
            }
            if matches!(
                word.as_str(),
                "INSERT"
                    | "UPDATE"
                    | "REPLACE"
                    | "CREATE"
                    | "MERGE"
                    | "UPSERT"
                    | "CALL"
                    | "EXEC"
                    | "EXECUTE"
                    | "COPY"
                    | "ATTACH"
                    | "DO"
                    | "PERFORM"
                    | "INTO"
            ) {
                seen_write = true;
            }
        }
        let first_word = tokens[0].as_str();
        if matches!(
            first_word,
            "SELECT" | "WITH" | "EXPLAIN" | "SHOW" | "DESCRIBE" | "DESC" | "PRAGMA" | "VALUES"
        ) {
            seen_read = true;
        } else {
            seen_write = true;
        }
    }
    if seen_write {
        Some(McpToolRiskClass::StagedWrite)
    } else if seen_read {
        Some(McpToolRiskClass::ReadOnly)
    } else {
        None
    }
}

/// Deterministic zero-config tool risk classification.
/// Priority:
/// 1. Explicit `policy.tool_overrides`
/// 2. SQL inspection on `sql` / `query` / `statement` argument keys (never lets `DROP TABLE` ride on `query`!)
/// 3. Cached upstream MCP `annotations` (`destructiveHint`, `readOnlyHint`)
/// 4. Token heuristics on `tool_name`
/// 5. Fail-Closed default (`McpToolRiskClass::StagedWrite`)
pub fn classify_mcp_tool(
    policy: &McpServerPolicy,
    tool_name: &str,
    cached_annotations: Option<&CachedToolAnnotations>,
    arguments: &Value,
) -> McpToolRiskClass {
    if let Some(&overridden) = policy.tool_overrides.get(tool_name) {
        return overridden;
    }

    if let Some(obj) = arguments.as_object() {
        for key in ["sql", "query", "statement"] {
            if let Some(raw_sql) = obj.get(key).and_then(|v| v.as_str()) {
                if let Some(sql_class) = classify_sql_text(raw_sql) {
                    if sql_class != McpToolRiskClass::ReadOnly {
                        return sql_class;
                    }
                    let explicit_non_readonly = cached_annotations.is_some_and(|a| {
                        a.destructive_hint == Some(true) || a.read_only_hint == Some(false)
                    });
                    if !explicit_non_readonly {
                        return McpToolRiskClass::ReadOnly;
                    }
                }
            }
        }
    }

    if let Some(ann) = cached_annotations {
        if ann.destructive_hint == Some(true) {
            return McpToolRiskClass::Destructive;
        }
        if ann.read_only_hint == Some(true) {
            return McpToolRiskClass::ReadOnly;
        }
        if ann.read_only_hint == Some(false) {
            return McpToolRiskClass::StagedWrite;
        }
    }

    let tokens = split_identifier_tokens(tool_name);
    const DESTRUCTIVE_TOKENS: &[&str] = &[
        "delete", "remove", "drop", "destroy", "purge", "trash", "revoke", "wipe", "truncate",
        "erase", "nuke",
    ];
    if tokens.iter().any(|t| DESTRUCTIVE_TOKENS.contains(&t.as_str())) {
        return McpToolRiskClass::Destructive;
    }

    const WRITE_TOKENS: &[&str] = &[
        "send", "reply", "post", "create", "update", "edit", "patch", "modify", "write", "put",
        "merge", "close", "approve", "transfer", "pay", "refund", "deploy", "trigger", "comment",
        "archive", "insert", "upsert", "append", "publish", "invite", "assign", "label", "add",
        "set", "run", "exec", "execute", "call",
    ];
    if tokens.iter().any(|t| WRITE_TOKENS.contains(&t.as_str())) {
        return McpToolRiskClass::StagedWrite;
    }

    const READ_TOKENS: &[&str] = &[
        "get", "list", "search", "read", "fetch", "find", "inspect", "describe", "show", "count",
        "status", "whoami", "ping", "schema", "tables", "query", "lookup", "check", "view", "head",
        "tail", "diff",
    ];
    if tokens.iter().any(|t| READ_TOKENS.contains(&t.as_str())) {
        return McpToolRiskClass::ReadOnly;
    }

    // Fail-Closed default for unknown tools without readOnlyHint.
    McpToolRiskClass::StagedWrite
}

pub(super) fn summarize_args_for_taint(args: &Value) -> String {
    let masked = mask_secrets_for_preview(args);
    let compact = serde_json::to_string(&masked).unwrap_or_else(|_| "{}".to_string());
    if compact.len() > 140 {
        let mut cut = 140;
        while cut > 0 && !compact.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}...", &compact[..cut])
    } else {
        compact
    }
}
