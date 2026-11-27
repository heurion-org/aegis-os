use super::*;

/// Returns `true` for loopback, private RFC1918, CGNAT, link-local / cloud metadata, ULA,
/// unspecified, multicast, or IPv4-mapped equivalents that untrusted outbound proxy traffic
/// must never reach directly.
pub fn is_forbidden_outbound_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden_outbound_ip(IpAddr::V4(v4));
            }
            let segs = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6.is_unique_local()
                || (segs[0] & 0xffc0) == 0xfec0
                || (segs[0] == 0x2001 && segs[1] == 0x0db8)
        }
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || o[0] >= 240
        }
    }
}

pub(crate) fn replace_query_key_param(path_and_query: &str, placeholder: &str, replacement: &str) -> String {
    let Some((path, query)) = path_and_query.split_once('?') else {
        return path_and_query.to_string();
    };
    let mut updated = Vec::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "key" && v == placeholder {
                if replacement.is_empty() {
                    updated.push("key=".to_string());
                } else {
                    updated.push(format!("key={replacement}"));
                }
                continue;
            }
        }
        updated.push(pair.to_string());
    }
    format!("{path}?{}", updated.join("&"))
}

pub(crate) async fn read_bounded_http_line(
    reader: &mut BufReader<&mut TcpStream>,
    max_bytes: usize,
) -> std::io::Result<Option<String>> {
    let mut raw = Vec::new();
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        reader.take((max_bytes + 1) as u64).read_until(b'\n', &mut raw),
    )
    .await;
    let n = match res {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "HTTP header read timeout",
            ));
        }
    };
    if n == 0 {
        return Ok(None);
    }
    if raw.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP header line exceeded 64 KiB limit",
        ));
    }
    let s = String::from_utf8(raw).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF8 HTTP header line")
    })?;
    Ok(Some(s))
}

pub(crate) struct ParsedHttpHead {
    pub(crate) status_line: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) is_chunked: bool,
    pub(crate) content_length: Option<usize>,
    pub(crate) content_type: String,
    pub(crate) is_sse: bool,
    pub(crate) is_compressed: bool,
}

pub(crate) fn find_http_header_end(buf: &[u8]) -> Option<(usize, usize)> {
    let crlfcrlf = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| (p, p + 4));
    let lflf = buf
        .windows(2)
        .position(|w| w == b"\n\n")
        .map(|p| (p, p + 2));
    match (crlfcrlf, lflf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

pub(crate) fn parse_http_response_head(hdr_bytes: &[u8]) -> ParsedHttpHead {
    let text = String::from_utf8_lossy(hdr_bytes);
    let mut lines = text.lines();
    let status_line = lines
        .next()
        .unwrap_or("HTTP/1.1 200 OK")
        .trim_end_matches('\r')
        .to_string();
    let mut headers = Vec::new();
    let mut is_chunked = false;
    let mut content_length = None;
    let mut content_type = String::new();
    let mut content_encoding = String::new();
    for line in lines {
        let trimmed = line.trim_end_matches('\r');
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            let low = key.to_ascii_lowercase();
            let val_low = val.to_ascii_lowercase();
            if low == "transfer-encoding" && val_low.contains("chunked") {
                is_chunked = true;
            } else if low == "content-length" {
                content_length = val.parse::<usize>().ok();
            } else if low == "content-type" {
                content_type = val_low;
            } else if low == "content-encoding" {
                content_encoding = val_low;
            }
            headers.push((key, val));
        }
    }
    let is_sse = content_type.contains("text/event-stream");
    let is_compressed = !content_encoding.is_empty() && content_encoding != "identity";
    ParsedHttpHead {
        status_line,
        headers,
        is_chunked,
        content_length,
        content_type,
        is_sse,
        is_compressed,
    }
}

pub(crate) async fn write_downstream_body_slice(
    client: &mut TcpStream,
    is_chunked: bool,
    data: &[u8],
) -> std::io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    if is_chunked {
        let header = format!("{:x}\r\n", data.len());
        client.write_all(header.as_bytes()).await?;
        client.write_all(data).await?;
        client.write_all(b"\r\n").await?;
    } else {
        client.write_all(data).await?;
    }
    client.flush().await
}

pub(crate) const DLP_TOKEN_PREFIXES: &[(&str, &str, usize)] = &[
    ("github_pat_", "DLP:TOKEN_github_pat", 8),
    ("github_oauth_", "DLP:TOKEN_github_oauth", 8),
    ("ghp_", "DLP:TOKEN_ghp", 8),
    ("gho_", "DLP:TOKEN_gho", 8),
    ("ghu_", "DLP:TOKEN_ghu", 8),
    ("ghs_", "DLP:TOKEN_ghs", 8),
    ("ghr_", "DLP:TOKEN_ghr", 8),
    ("sk-ant-", "DLP:TOKEN_sk-ant", 8),
    ("sk-proj-", "DLP:TOKEN_sk-proj", 8),
    ("sk-live-", "DLP:TOKEN_sk-live", 8),
    ("xoxb-", "DLP:TOKEN_xoxb", 8),
    ("glpat-", "DLP:TOKEN_glpat", 8),
    ("npm_", "DLP:TOKEN_npm", 16),
];

pub(crate) fn dlp_token_span_bytes(s: &str, allow_extra_base64_chars: bool) -> usize {
    let mut end = 0usize;
    for (idx, ch) in s.char_indices() {
        let ok = ch.is_ascii_alphanumeric()
            || ch == '_'
            || ch == '-'
            || (allow_extra_base64_chars && matches!(ch, '.' | '=' | '+' | '/'));
        if !ok {
            break;
        }
        end = idx + ch.len_utf8();
    }
    end
}

pub(crate) fn has_bound_secret_placeholder(text: &str) -> Option<(usize, usize)> {
    const PREFIX: &str = "$AOS_SECRET_";
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(PREFIX) {
        let start = from + rel;
        let tail = &text[start + PREFIX.len()..];
        let mut ext = 0usize;
        let mut ident_chars = 0usize;
        for (i, ch) in tail.char_indices() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ext = i + ch.len_utf8();
                ident_chars += 1;
            } else {
                break;
            }
        }
        if ident_chars >= 2 && !tail[ext..].starts_with('*') {
            return Some((start, start + PREFIX.len() + ext));
        }
        from = start + PREFIX.len();
    }
    None
}

pub(crate) fn is_plausible_bearer_secret(tok: &str, after_tok: &str) -> bool {
    if tok.chars().count() < 8 {
        return false;
    }
    if after_tok.starts_with('<') || after_tok.starts_with('{') || after_tok.starts_with('*') {
        return false;
    }
    if tok.contains("...") || tok.ends_with("..") {
        return false;
    }
    let upper = tok.to_ascii_uppercase();
    const PLACEHOLDER_PREFIXES: &[&str] = &[
        "REDACTED",
        "YOUR_",
        "YOUR-",
        "EXAMPLE",
        "REPLACE",
        "PLACEHOLDER",
        "AEGIS_AT_",
        "SAMPLE_",
        "DUMMY_",
        "FAKE_",
        "TEST_TOKEN",
    ];
    if PLACEHOLDER_PREFIXES.iter().any(|p| upper.starts_with(p)) {
        return false;
    }
    if matches!(
        upper.as_str(),
        "AUTHENTICATION"
            | "AUTHORIZATION"
            | "CREDENTIALS"
            | "OPERATOR"
            | "PASSWORD"
            | "TOKEN_HERE"
            | "ACCESS_TOKEN"
            | "SECRET_TOKEN"
            | "BEARER_TOKEN"
    ) {
        return false;
    }
    let has_digit = tok.bytes().any(|b| b.is_ascii_digit());
    let has_structured_prefix = [
        "eyJ", "sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_", "xox", "glpat", "ya29.",
        "ak_live_", "aop_",
    ]
    .iter()
    .any(|p| tok.starts_with(p));
    let long_mixed_case = tok.len() >= 24
        && tok.bytes().any(|b| b.is_ascii_uppercase())
        && tok.bytes().any(|b| b.is_ascii_lowercase());
    has_digit || has_structured_prefix || long_mixed_case
}

pub(crate) fn find_auth_header_token_span(text: &str) -> Option<(usize, usize, String)> {
    let bytes = text.as_bytes();
    let mut best: Option<(usize, usize, String)> = None;
    let mut consider = |start: usize, end: usize, repl: String| {
        if best.as_ref().is_none_or(|(b_start, ..)| start < *b_start) {
            best = Some((start, end, repl));
        }
    };

    // Case A: Explicit `Authorization` header / JSON field context (`Authorization: Bearer <tok>`,
    // `"authorization": "Bearer <tok>"`, `Authorization: token <tok>`).
    const AUTH_KEY: &[u8] = b"authorization";
    if bytes.len() > AUTH_KEY.len() + 8 {
        let mut idx = 0usize;
        while idx + AUTH_KEY.len() < bytes.len() {
            let boundary_ok = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
            if boundary_ok && bytes[idx..idx + AUTH_KEY.len()].eq_ignore_ascii_case(AUTH_KEY) {
                let auth_end = idx + AUTH_KEY.len();
                let mut sep_len = 0usize;
                let mut has_kv_sep = false;
                while sep_len <= 8 && auth_end + sep_len < bytes.len() {
                    let pos = auth_end + sep_len;
                    if has_kv_sep {
                        let rest_bytes = &bytes[pos..];
                        let scheme_len = if rest_bytes.len() >= 7
                            && rest_bytes[..7].eq_ignore_ascii_case(b"bearer ")
                        {
                            Some(7usize)
                        } else if rest_bytes.len() >= 6
                            && rest_bytes[..6].eq_ignore_ascii_case(b"token ")
                        {
                            Some(6usize)
                        } else {
                            None
                        };
                        if let Some(slen) = scheme_len {
                            let tail = &text[pos + slen..];
                            let span = dlp_token_span_bytes(tail, true);
                            let tok = &tail[..span];
                            if is_plausible_bearer_secret(tok, &tail[span..]) {
                                consider(
                                    idx,
                                    pos + slen + span,
                                    format!("{}[REDACTED_BY_AEGIS_DLP]", &text[idx..pos + slen]),
                                );
                            }
                            break;
                        }
                    }
                    let b = bytes[pos];
                    if !matches!(b, b':' | b'=' | b' ' | b'\t' | b'"' | b'\'' | b'\\') {
                        break;
                    }
                    if matches!(b, b':' | b'=') {
                        has_kv_sep = true;
                    }
                    sep_len += 1;
                }
                idx = auth_end;
            } else {
                idx += 1;
            }
        }
    }

    // Case B: Standalone JWT Bearer token (`Bearer eyJ...`).
    for prefix in ["Bearer ", "bearer "] {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(prefix) {
            let start = from + rel;
            let tail = &text[start + prefix.len()..];
            if tail.starts_with("eyJ") {
                let span = dlp_token_span_bytes(tail, true);
                let tok = &tail[..span];
                if tok.contains('.')
                    && tok.len() >= 20
                    && is_plausible_bearer_secret(tok, &tail[span..])
                {
                    consider(
                        start,
                        start + prefix.len() + span,
                        format!("{prefix}[REDACTED_BY_AEGIS_DLP]"),
                    );
                    break;
                }
            }
            from = start + prefix.len();
        }
    }

    best
}

pub(crate) fn find_next_dlp_span(text: &str) -> Option<(usize, usize, String, &'static str)> {
    // `(match_start, match_end, replacement, rule_label)`
    let mut best: Option<(usize, usize, String, &'static str)> = None;
    let mut consider = |start: usize, end: usize, repl: String, label: &'static str| {
        if best
            .as_ref()
            .is_none_or(|(b_start, ..)| start < *b_start)
        {
            best = Some((start, end, repl, label));
        }
    };

    // 1. Virtual `$AOS_SECRET_*` placeholders (ignoring doc wildcards like `$AOS_SECRET_*`).
    if let Some((start, end)) = has_bound_secret_placeholder(text) {
        consider(
            start,
            end,
            "[REDACTED_BY_AEGIS_DLP:AOS_SECRET]".to_string(),
            "$AOS_SECRET_* (outbound DLP)",
        );
    }

    // 2. PEM private keys (`-----BEGIN ... PRIVATE KEY-----` ... optional `-----END ... PRIVATE KEY-----`).
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("-----BEGIN ") {
        let start = search_from + rel;
        let rest = &text[start..];
        let header_line_end = rest.find('\n').unwrap_or(rest.len());
        let header_line = &rest[..header_line_end];
        let pk_marker = "PRIVATE KEY-----";
        if let Some(pk_pos) = header_line.find(pk_marker) {
            let min_end = start + pk_pos + pk_marker.len();
            let full_end = if let Some(end_rel) = text[min_end..].find("-----END ") {
                let end_start = min_end + end_rel;
                let end_rest = &text[end_start..];
                let end_line_end = end_rest.find('\n').unwrap_or(end_rest.len());
                if let Some(end_pk_pos) = end_rest[..end_line_end].find(pk_marker) {
                    end_start + end_pk_pos + pk_marker.len()
                } else {
                    min_end
                }
            } else {
                min_end
            };
            consider(
                start,
                full_end,
                "[REDACTED_BY_AEGIS_DLP:PEM_PRIVATE_KEY]".to_string(),
                "DLP:PEM_PRIVATE_KEY",
            );
            break;
        }
        search_from = start + "-----BEGIN ".len();
    }

    // 3. AWS Access Key IDs (`AKIA` + >=12 uppercase/digits).
    let mut akia_from = 0usize;
    while let Some(rel) = text[akia_from..].find("AKIA") {
        let start = akia_from + rel;
        let tail = &text[start + 4..];
        let mut ext = 0usize;
        let mut count = 0usize;
        for (i, ch) in tail.char_indices() {
            if ch.is_ascii_uppercase() || ch.is_ascii_digit() {
                ext = i + ch.len_utf8();
                count += 1;
            } else {
                break;
            }
        }
        if count >= 12 {
            consider(
                start,
                start + 4 + ext,
                "[REDACTED_BY_AEGIS_DLP]".to_string(),
                "DLP:AWS_ACCESS_KEY",
            );
            break;
        }
        akia_from = start + 4;
    }

    // 4. Known provider token prefixes.
    for &(prefix, label, min_len) in DLP_TOKEN_PREFIXES {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(prefix) {
            let start = from + rel;
            let tail = &text[start + prefix.len()..];
            let span = dlp_token_span_bytes(tail, false);
            if tail[..span].chars().count() >= min_len {
                consider(
                    start,
                    start + prefix.len() + span,
                    "[REDACTED_BY_AEGIS_DLP]".to_string(),
                    label,
                );
                break;
            }
            from = start + prefix.len();
        }
    }

    // 5. HTTP `Authorization: Bearer <token>` / `Authorization: token <token>` / standalone JWT `Bearer eyJ...`.
    if let Some((start, end, repl)) = find_auth_header_token_span(text) {
        consider(start, end, repl, "DLP:AUTH_HEADER_TOKEN");
    }

    // 6. HTTP(S) URL embedded userinfo secrets (`https://user:secret@host`).
    for scheme in ["https://", "http://"] {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(scheme) {
            let start = from + rel;
            let after_scheme = start + scheme.len();
            let tail = &text[after_scheme..];
            let authority_end = tail
                .find(|c: char| matches!(c, '/' | '?' | '#' | '\'' | '"') || c.is_whitespace())
                .unwrap_or(tail.len());
            let authority = &tail[..authority_end];
            if let Some(at_pos) = authority.find('@') {
                let userinfo = &authority[..at_pos];
                if let Some((_user, secret)) = userinfo.split_once(':') {
                    if secret.len() >= 8 {
                        consider(
                            after_scheme,
                            after_scheme + at_pos + 1,
                            "[REDACTED_BY_AEGIS_DLP]@".to_string(),
                            "DLP:URL_USERINFO_SECRET",
                        );
                        break;
                    }
                }
            }
            from = after_scheme;
        }
    }

    best
}

/// Inspects a payload for secret/key signatures without requiring vault state.
/// Shared by outbound Egress DLP, MCP Gateway tool sanitization, and pre-publish PR gates.
pub fn detect_dlp_patterns(text: &str) -> Vec<&'static str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let mut rest = text;
    while let Some((_start, end, _repl, label)) = find_next_dlp_span(rest) {
        if !hits.contains(&label) {
            hits.push(label);
        }
        if end == 0 || end >= rest.len() {
            break;
        }
        rest = &rest[end..];
    }
    hits
}

/// Redacts all detected secret/key signatures in `text`, returning the scrubbed text
/// along with the deduplicated rule labels that triggered.
pub fn redact_dlp_secrets(text: &str) -> (String, Vec<&'static str>) {
    if text.is_empty() {
        return (String::new(), Vec::new());
    }
    let mut out = String::with_capacity(text.len());
    let mut hits = Vec::new();
    let mut rest = text;
    while let Some((start, end, repl, label)) = find_next_dlp_span(rest) {
        out.push_str(&rest[..start]);
        out.push_str(&repl);
        if !hits.contains(&label) {
            hits.push(label);
        }
        if end == 0 || end >= rest.len() {
            rest = "";
            break;
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    (out, hits)
}

/// Official package registry domain allowlist presets for controlled `pkg_install` egress.
pub fn registry_domains_for_ecosystem(ecosystem: &str) -> Option<&'static [&'static str]> {
    match ecosystem.trim().to_ascii_lowercase().as_str() {
        "npm" | "pnpm" | "yarn" | "bun" | "node" => {
            Some(&["registry.npmjs.org", "registry.yarnpkg.com"])
        }
        "pip" | "uv" | "python" => Some(&["pypi.org", "files.pythonhosted.org"]),
        "cargo" | "rust" => Some(&["crates.io", "static.crates.io", "index.crates.io"]),
        "go" | "golang" => Some(&["proxy.golang.org", "sum.golang.org", "storage.googleapis.com"]),
        _ => None,
    }
}
