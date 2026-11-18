//! Reversible session-scoped PII & custom-pattern pseudonymization for L7 model traffic.
//!
//! High-risk secrets (`$AOS_SECRET_*`, PEM private keys, `AKIA*`, `ghp_*`, `sk-*`) ALWAYS remain
//! hard-blocked (`403 Forbidden`) by `AegisEgressGateway::inspect_payload_dlp`. By contrast, when
//! `PseudonymMode::Pseudonymize` is enabled, emails, private/CGNAT IPv4 addresses, internal
//! hostnames, phone numbers, and operator-configured literal rules are replaced with deterministic
//! HMAC-SHA256 placeholders (`u_<hex>@aegis-redact.invalid`, `ip_<hex>.aegis-redact.invalid`,
//! `h_<hex>.aegis-redact.invalid`, `tel_<hex>`, `cid_<hex>`) before leaving the host, then restored
//! cleanly on both non-streaming JSON responses and chunk-split SSE token streams.

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Controls how `AegisEgressGateway` handles non-secret PII & custom patterns on L7 model routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PseudonymMode {
    /// Default v0.4+ behavior: hard-block `$AOS_SECRET_*` & secret signatures only.
    #[default]
    Block,
    /// Hard-block secrets AND reversibly pseudonymize PII / custom patterns on L7 model calls.
    Pseudonymize,
    /// Disable L7 PII transformation (secret DLP & SSRF checks remain enforced).
    Off,
}

impl FromStr for PseudonymMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "block" => Ok(Self::Block),
            "pseudonymize" | "pseudo" => Ok(Self::Pseudonymize),
            "off" | "disabled" => Ok(Self::Off),
            other => Err(format!(
                "invalid dlp_mode '{other}'; expected 'block', 'pseudonymize', or 'off'"
            )),
        }
    }
}

/// Operator-configured literal redaction entry loaded from `.aegis/dlp.json` or CLI config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomRedactionRule {
    pub name: String,
    pub literal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

#[derive(Default)]
struct PseudonymInner {
    forward: HashMap<String, String>,
    reverse: HashMap<String, String>,
    max_pseudonym_len: usize,
}

/// Thread-safe, session-scoped bidirectional mapping table backed by a zeroized CSPRNG salt.
pub struct PseudonymSessionTable {
    salt: Zeroizing<[u8; 32]>,
    inner: RwLock<PseudonymInner>,
    replacements_count: AtomicU64,
}

impl Default for PseudonymSessionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PseudonymSessionTable {
    pub fn new() -> Self {
        let mut salt = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *salt);
        Self {
            salt,
            inner: RwLock::new(PseudonymInner::default()),
            replacements_count: AtomicU64::new(0),
        }
    }

    pub fn active_count(&self) -> usize {
        self.inner.read().map(|g| g.reverse.len()).unwrap_or(0)
    }

    pub fn snapshot_stats(&self) -> (usize, u64) {
        (
            self.active_count(),
            self.replacements_count.load(Ordering::Relaxed),
        )
    }

    pub fn max_pseudonym_len(&self) -> usize {
        self.inner
            .read()
            .map(|g| g.max_pseudonym_len)
            .unwrap_or(0)
    }

    /// Returns true if `tail` is a strict byte prefix of any active pseudonym key in `reverse`.
    pub fn has_strict_prefix(&self, tail: &str) -> bool {
        if tail.is_empty() {
            return false;
        }
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        guard
            .reverse
            .keys()
            .any(|k| k.len() > tail.len() && k.starts_with(tail))
    }

    /// Deterministically assigns or returns the session pseudonym for `raw` under `kind`.
    pub fn get_or_insert(&self, kind: &str, raw: &str) -> String {
        if let Ok(guard) = self.inner.read() {
            if let Some(existing) = guard.forward.get(raw) {
                return existing.clone();
            }
        }
        let mut guard = self.inner.write().expect("pseudonym lock poisoned");
        if let Some(existing) = guard.forward.get(raw) {
            return existing.clone();
        }

        let mut chosen = String::new();
        for attempt in 0u32..32 {
            let mut mac =
                <HmacSha256 as Mac>::new_from_slice(&*self.salt).expect("HMAC key length valid");
            mac.update(kind.as_bytes());
            mac.update(b":");
            mac.update(raw.as_bytes());
            if attempt > 0 {
                mac.update(b"#");
                mac.update(&attempt.to_le_bytes());
            }
            let digest = mac.finalize().into_bytes();
            let hex8 = hex::encode(&digest[..4]);
            let candidate = match kind {
                "email" => format!("u_{hex8}@aegis-redact.invalid"),
                "ipv4" => format!("ip_{hex8}.aegis-redact.invalid"),
                "host" => format!("h_{hex8}.aegis-redact.invalid"),
                "phone" => format!("tel_{hex8}"),
                _ => format!("cid_{hex8}"),
            };
            match guard.reverse.get(&candidate) {
                Some(prev_raw) if prev_raw != raw => continue,
                _ => {
                    chosen = candidate;
                    break;
                }
            }
        }
        if chosen.is_empty() {
            chosen = format!("cid_{}", guard.reverse.len());
        }
        guard.max_pseudonym_len = guard.max_pseudonym_len.max(chosen.len());
        guard.forward.insert(raw.to_string(), chosen.clone());
        guard.reverse.insert(chosen.clone(), raw.to_string());
        chosen
    }

    /// Scans plain text and substitutes configured literals, emails, private/CGNAT IPv4s,
    /// internal hostnames, and phone numbers with deterministic session pseudonyms.
    /// Returns `None` if no replacements were made.
    pub fn pseudonymize_text(
        &self,
        text: &str,
        custom_rules: &[CustomRedactionRule],
    ) -> Option<String> {
        if text.is_empty() {
            return None;
        }
        let mut spans: Vec<(usize, usize, String)> = Vec::new();

        // Preserve any already-generated Aegis placeholders unchanged for idempotency.
        let preserved = find_existing_pseudonym_spans(text);

        let is_free = |spans: &[(usize, usize, String)], start: usize, end: usize| -> bool {
            start < end
                && !preserved
                    .iter()
                    .any(|&(ps, pe)| start < pe && ps < end)
                && !spans
                    .iter()
                    .any(|&(s, e, _)| start < e && s < end)
        };

        // 1. Custom literals (longest match first).
        let mut rules: Vec<&CustomRedactionRule> = custom_rules
            .iter()
            .filter(|r| !r.literal.trim().is_empty())
            .collect();
        rules.sort_by_key(|r| std::cmp::Reverse(r.literal.len()));
        for rule in rules {
            let pat = rule.literal.as_str();
            for (start, _) in text.match_indices(pat) {
                let end = start + pat.len();
                if is_free(&spans, start, end) {
                    let kind = rule.tag.as_deref().unwrap_or("custom");
                    let tok = self.get_or_insert(kind, pat);
                    spans.push((start, end, tok));
                }
            }
        }

        // 2. Emails.
        for (start, end, raw) in find_email_spans(text) {
            if is_free(&spans, start, end) {
                let tok = self.get_or_insert("email", &raw);
                spans.push((start, end, tok));
            }
        }

        // 3. Private & CGNAT IPv4 addresses.
        for (start, end, raw) in find_private_ipv4_spans(text) {
            if is_free(&spans, start, end) {
                let tok = self.get_or_insert("ipv4", &raw);
                spans.push((start, end, tok));
            }
        }

        // 4. Internal hostnames (*.internal, *.corp, *.lan, *.intranet, *.private, *.svc.cluster.local).
        for (start, end, raw) in find_internal_host_spans(text) {
            if is_free(&spans, start, end) {
                let tok = self.get_or_insert("host", &raw);
                spans.push((start, end, tok));
            }
        }

        // 5. E.164 international & 11-digit mobile phone numbers.
        for (start, end, raw) in find_phone_spans(text) {
            if is_free(&spans, start, end) {
                let tok = self.get_or_insert("phone", &raw);
                spans.push((start, end, tok));
            }
        }

        if spans.is_empty() {
            return None;
        }
        spans.sort_by_key(|(s, _, _)| *s);
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        let count = spans.len() as u64;
        for (start, end, repl) in spans {
            out.push_str(&text[cursor..start]);
            out.push_str(&repl);
            cursor = end;
        }
        out.push_str(&text[cursor..]);
        self.replacements_count.fetch_add(count, Ordering::Relaxed);
        Some(out)
    }

    /// Pseudonymizes string leaves of a model API JSON request body, skipping protocol
    /// metadata keys (`model`, `role`, `type`, `id`, etc.) and `$AOS_SECRET_*` tokens.
    pub fn pseudonymize_json_request_body(
        &self,
        body: &[u8],
        custom_rules: &[CustomRedactionRule],
    ) -> Option<Vec<u8>> {
        let mut val: Value = serde_json::from_slice(body).ok()?;
        let mut changed = false;
        self.walk_json_outbound(&mut val, custom_rules, false, &mut changed);
        if changed {
            serde_json::to_vec(&val).ok()
        } else {
            None
        }
    }

    fn walk_json_outbound(
        &self,
        val: &mut Value,
        custom_rules: &[CustomRedactionRule],
        skip_subtree: bool,
        changed: &mut bool,
    ) {
        if skip_subtree {
            return;
        }
        match val {
            Value::String(s) => {
                if s.contains("$AOS_SECRET_") {
                    return;
                }
                if let Some(updated) = self.pseudonymize_text(s, custom_rules) {
                    *s = updated;
                    *changed = true;
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    self.walk_json_outbound(item, custom_rules, false, changed);
                }
            }
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    let skip_key = matches!(
                        k.as_str(),
                        "model"
                            | "role"
                            | "type"
                            | "id"
                            | "tool_use_id"
                            | "call_id"
                            | "name"
                            | "stop_reason"
                            | "finish_reason"
                            | "encoding_format"
                            | "anthropic_version"
                    );
                    self.walk_json_outbound(v, custom_rules, skip_key, changed);
                }
            }
            _ => {}
        }
    }

    /// Restores every registered pseudonym in `text`. When `escape_for_inner_json` is true
    /// (e.g. `input_json_delta.partial_json` or OpenAI `function.arguments`), restored values
    /// are JSON-string-escaped so characters like `"`, `\`, or `\n` inside custom literals keep
    /// the streamed JSON argument fragment syntactically valid.
    pub fn restore_all_in_str(&self, text: &str, escape_for_inner_json: bool) -> String {
        if text.is_empty() {
            return String::new();
        }
        let Ok(guard) = self.inner.read() else {
            return text.to_string();
        };
        if guard.reverse.is_empty() {
            return text.to_string();
        }
        // Quick byte pre-check: all our pseudonyms contain ASCII `_`.
        if !text.contains('_') {
            return text.to_string();
        }

        let mut matches: Vec<(usize, usize, String)> = Vec::new();
        for (pseudo, raw) in &guard.reverse {
            if !text.contains(pseudo.as_str()) {
                continue;
            }
            for (start, _) in text.match_indices(pseudo.as_str()) {
                let end = start + pseudo.len();
                let replacement = if escape_for_inner_json {
                    escape_inner_json_string(raw)
                } else {
                    raw.clone()
                };
                matches.push((start, end, replacement));
            }
        }
        if matches.is_empty() {
            return text.to_string();
        }
        matches.sort_by_key(|(s, e, _)| (*s, std::cmp::Reverse(*e)));
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        for (start, end, repl) in matches {
            if start < cursor {
                continue;
            }
            out.push_str(&text[cursor..start]);
            out.push_str(&repl);
            cursor = end;
        }
        out.push_str(&text[cursor..]);
        out
    }

    /// Restores pseudonyms across a buffered non-streaming JSON response body.
    /// Returns `Some(updated_bytes)` only if at least one string leaf changed.
    pub fn restore_json_response_body(&self, body: &[u8]) -> Option<Vec<u8>> {
        if self.active_count() == 0 {
            return None;
        }
        let mut val: Value = serde_json::from_slice(body).ok()?;
        let mut changed = false;
        self.walk_json_restore(&mut val, false, &mut changed);
        if changed {
            serde_json::to_vec(&val).ok()
        } else {
            None
        }
    }

    fn walk_json_restore(&self, val: &mut Value, inner_json: bool, changed: &mut bool) {
        match val {
            Value::String(s) => {
                let restored = self.restore_all_in_str(s, inner_json);
                if restored != *s {
                    *s = restored;
                    *changed = true;
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    self.walk_json_restore(item, inner_json, changed);
                }
            }
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    let is_inner = k == "arguments";
                    self.walk_json_restore(v, is_inner, changed);
                }
            }
            _ => {}
        }
    }
}

fn escape_inner_json_string(raw: &str) -> String {
    match serde_json::to_string(raw) {
        Ok(quoted) if quoted.len() >= 2 && quoted.starts_with('"') && quoted.ends_with('"') => {
            quoted[1..quoted.len() - 1].to_string()
        }
        _ => raw.to_string(),
    }
}

/// Stateful prefix-holdback restorer for streaming token fragments (`delta.text`, `partial_json`).
#[derive(Debug, Clone)]
pub struct StreamingTextRestorer {
    pending: String,
    escape_for_inner_json: bool,
}

impl StreamingTextRestorer {
    pub fn new(escape_for_inner_json: bool) -> Self {
        Self {
            pending: String::new(),
            escape_for_inner_json,
        }
    }

    pub fn push_chunk(&mut self, text: &str, table: &PseudonymSessionTable) -> String {
        if text.is_empty() && self.pending.is_empty() {
            return String::new();
        }
        self.pending.push_str(text);
        let restored = table.restore_all_in_str(&self.pending, self.escape_for_inner_json);
        self.pending = restored;

        let max_len = table.max_pseudonym_len();
        if max_len == 0 || self.pending.is_empty() {
            return std::mem::take(&mut self.pending);
        }

        // Check from the longest candidate suffix (bounded by max_pseudonym_len - 1) down to 1
        // on valid UTF-8 boundaries so split pseudonyms across arbitrary chunk boundaries stay held
        // until completing bytes arrive.
        let min_start = self.pending.len().saturating_sub(max_len);
        let mut hold_from: Option<usize> = None;
        for (idx, _) in self.pending.char_indices() {
            if idx < min_start {
                continue;
            }
            let suffix = &self.pending[idx..];
            if table.has_strict_prefix(suffix) {
                hold_from = Some(idx);
                break;
            }
        }

        if let Some(split) = hold_from {
            let emit = self.pending[..split].to_string();
            let tail = self.pending[split..].to_string();
            self.pending = tail;
            emit
        } else {
            std::mem::take(&mut self.pending)
        }
    }

    pub fn finish(&mut self, table: &PseudonymSessionTable) -> String {
        if self.pending.is_empty() {
            return String::new();
        }
        let tail = std::mem::take(&mut self.pending);
        table.restore_all_in_str(&tail, self.escape_for_inner_json)
    }
}

/// Line-buffered SSE transformer restoring pseudonyms across split chunks for Anthropic, OpenAI,
/// OpenAI Responses API, and Gemini streaming responses.
pub struct SseResponseTransformer<'a> {
    table: &'a PseudonymSessionTable,
    raw_buf: Vec<u8>,
    slots: HashMap<String, StreamingTextRestorer>,
    pending_event_line: Option<String>,
}

impl<'a> SseResponseTransformer<'a> {
    pub fn new(table: &'a PseudonymSessionTable) -> Self {
        Self {
            table,
            raw_buf: Vec::new(),
            slots: HashMap::new(),
            pending_event_line: None,
        }
    }

    /// Feeds raw upstream SSE body bytes (already de-chunked if HTTP Transfer-Encoding was chunked)
    /// and returns transformed UTF-8 SSE bytes ready to send downstream.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.raw_buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(pos) = self.raw_buf.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = self.raw_buf.drain(..=pos).collect();
            let line_lossy = String::from_utf8_lossy(&line_bytes);
            self.process_line(&line_lossy, &mut out);
        }
        out
    }

    /// Flushes any buffered partial line or held pseudonym prefix at stream termination / EOF.
    pub fn finish_bytes(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.raw_buf.is_empty() {
            let rem = std::mem::take(&mut self.raw_buf);
            let line_lossy = String::from_utf8_lossy(&rem);
            self.process_line(&line_lossy, &mut out);
        }
        if let Some(ev_line) = self.pending_event_line.take() {
            out.extend_from_slice(ev_line.as_bytes());
        }
        self.flush_all_remaining_slots(&mut out);
        out
    }

    fn process_line(&mut self, raw_line: &str, out: &mut Vec<u8>) {
        let has_crlf = raw_line.ends_with("\r\n");
        let eol = if has_crlf {
            "\r\n"
        } else if raw_line.ends_with('\n') {
            "\n"
        } else {
            ""
        };
        let trimmed_eol = raw_line.trim_end_matches(['\r', '\n']);

        if trimmed_eol.starts_with("event:") {
            if let Some(prev) = self.pending_event_line.take() {
                out.extend_from_slice(prev.as_bytes());
            }
            self.pending_event_line = Some(raw_line.to_string());
            return;
        }

        if let Some(data_rest) = trimmed_eol.strip_prefix("data:") {
            let payload = data_rest.trim_start();
            if payload.trim() == "[DONE]" {
                self.flush_openai_before_done(eol, out);
                if let Some(ev_line) = self.pending_event_line.take() {
                    out.extend_from_slice(ev_line.as_bytes());
                }
                out.extend_from_slice(raw_line.as_bytes());
                return;
            }
            if let Ok(mut val) = serde_json::from_str::<Value>(payload) {
                let prefix_bytes = self.transform_sse_json_value(&mut val, eol);
                if !prefix_bytes.is_empty() {
                    out.extend_from_slice(&prefix_bytes);
                }
                if let Some(ev_line) = self.pending_event_line.take() {
                    out.extend_from_slice(ev_line.as_bytes());
                }
                if let Ok(serialized) = serde_json::to_string(&val) {
                    out.extend_from_slice(b"data: ");
                    out.extend_from_slice(serialized.as_bytes());
                    out.extend_from_slice(eol.as_bytes());
                    if val.get("type").and_then(|v| v.as_str()) == Some("message_stop") {
                        self.flush_all_remaining_slots(out);
                    }
                    return;
                }
            }
        }

        if let Some(ev_line) = self.pending_event_line.take() {
            out.extend_from_slice(ev_line.as_bytes());
        }
        out.extend_from_slice(raw_line.as_bytes());
    }

    fn slot_mut(&mut self, key: &str, escape_for_inner_json: bool) -> &mut StreamingTextRestorer {
        self.slots
            .entry(key.to_string())
            .or_insert_with(|| StreamingTextRestorer::new(escape_for_inner_json))
    }

    fn flush_slot(&mut self, key: &str) -> String {
        if let Some(restorer) = self.slots.get_mut(key) {
            restorer.finish(self.table)
        } else {
            String::new()
        }
    }

    fn transform_sse_json_value(&mut self, val: &mut Value, eol: &str) -> Vec<u8> {
        let mut synthetic_prefix = Vec::new();
        let ev_type = val
            .get("type")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        match ev_type.as_deref() {
            Some("content_block_delta") => {
                let idx = val.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                let delta_type = val
                    .pointer("/delta/type")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                match delta_type.as_deref() {
                    Some("text_delta") => {
                        if let Some(txt) = val.pointer("/delta/text").and_then(|v| v.as_str()) {
                            let txt_owned = txt.to_string();
                            let table = self.table;
                            let slot_key = format!("anthropic:text:{idx}");
                            let emitted = self.slot_mut(&slot_key, false).push_chunk(&txt_owned, table);
                            if let Some(target) = val.pointer_mut("/delta/text") {
                                *target = Value::String(emitted);
                            }
                        }
                    }
                    Some("input_json_delta") => {
                        if let Some(pj) =
                            val.pointer("/delta/partial_json").and_then(|v| v.as_str())
                        {
                            let pj_owned = pj.to_string();
                            let table = self.table;
                            let slot_key = format!("anthropic:json:{idx}");
                            let emitted = self.slot_mut(&slot_key, true).push_chunk(&pj_owned, table);
                            if let Some(target) = val.pointer_mut("/delta/partial_json") {
                                *target = Value::String(emitted);
                            }
                        }
                    }
                    Some("thinking_delta") => {
                        if let Some(th) = val.pointer("/delta/thinking").and_then(|v| v.as_str()) {
                            let th_owned = th.to_string();
                            let table = self.table;
                            let slot_key = format!("anthropic:thinking:{idx}");
                            let emitted = self.slot_mut(&slot_key, false).push_chunk(&th_owned, table);
                            if let Some(target) = val.pointer_mut("/delta/thinking") {
                                *target = Value::String(emitted);
                            }
                        }
                    }
                    _ => {}
                }
                return synthetic_prefix;
            }
            Some("content_block_stop") => {
                let idx = val.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                let flushed_text = self.flush_slot(&format!("anthropic:text:{idx}"));
                let flushed_json = self.flush_slot(&format!("anthropic:json:{idx}"));
                let flushed_thinking = self.flush_slot(&format!("anthropic:thinking:{idx}"));

                let has_pending_ev = self.pending_event_line.is_some();
                let emit_anthropic_delta = |buf: &mut Vec<u8>, body: Value| {
                    if has_pending_ev {
                        buf.extend_from_slice(b"event: content_block_delta");
                        buf.extend_from_slice(eol.as_bytes());
                    }
                    buf.extend_from_slice(b"data: ");
                    if let Ok(s) = serde_json::to_string(&body) {
                        buf.extend_from_slice(s.as_bytes());
                    }
                    buf.extend_from_slice(eol.as_bytes());
                    buf.extend_from_slice(eol.as_bytes());
                };

                if !flushed_text.is_empty() {
                    emit_anthropic_delta(
                        &mut synthetic_prefix,
                        json!({
                            "type": "content_block_delta",
                            "index": idx,
                            "delta": { "type": "text_delta", "text": flushed_text }
                        }),
                    );
                }
                if !flushed_json.is_empty() {
                    emit_anthropic_delta(
                        &mut synthetic_prefix,
                        json!({
                            "type": "content_block_delta",
                            "index": idx,
                            "delta": { "type": "input_json_delta", "partial_json": flushed_json }
                        }),
                    );
                }
                if !flushed_thinking.is_empty() {
                    emit_anthropic_delta(
                        &mut synthetic_prefix,
                        json!({
                            "type": "content_block_delta",
                            "index": idx,
                            "delta": { "type": "thinking_delta", "thinking": flushed_thinking }
                        }),
                    );
                }
                return synthetic_prefix;
            }
            Some("response.output_text.delta") => {
                let item_id = val
                    .get("item_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0")
                    .to_string();
                let out_idx = val.get("output_index").and_then(|v| v.as_u64()).unwrap_or(0);
                if let Some(delta) = val.get("delta").and_then(|v| v.as_str()) {
                    let delta_owned = delta.to_string();
                    let table = self.table;
                    let emitted = self
                        .slot_mut(&format!("responses:text:{item_id}:{out_idx}"), false)
                        .push_chunk(&delta_owned, table);
                    if let Some(d) = val.get_mut("delta") {
                        *d = Value::String(emitted);
                    }
                }
                return synthetic_prefix;
            }
            Some("response.output_text.done") => {
                let item_id = val
                    .get("item_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0")
                    .to_string();
                let out_idx = val.get("output_index").and_then(|v| v.as_u64()).unwrap_or(0);
                let _ = self.flush_slot(&format!("responses:text:{item_id}:{out_idx}"));
                if let Some(text) = val.get("text").and_then(|v| v.as_str()) {
                    let restored = self.table.restore_all_in_str(text, false);
                    if let Some(t) = val.get_mut("text") {
                        *t = Value::String(restored);
                    }
                }
                return synthetic_prefix;
            }
            Some("response.function_call_arguments.delta") => {
                let item_id = val
                    .get("item_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0")
                    .to_string();
                let out_idx = val.get("output_index").and_then(|v| v.as_u64()).unwrap_or(0);
                if let Some(delta) = val.get("delta").and_then(|v| v.as_str()) {
                    let delta_owned = delta.to_string();
                    let table = self.table;
                    let emitted = self
                        .slot_mut(&format!("responses:args:{item_id}:{out_idx}"), true)
                        .push_chunk(&delta_owned, table);
                    if let Some(d) = val.get_mut("delta") {
                        *d = Value::String(emitted);
                    }
                }
                return synthetic_prefix;
            }
            Some("response.function_call_arguments.done") => {
                let item_id = val
                    .get("item_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0")
                    .to_string();
                let out_idx = val.get("output_index").and_then(|v| v.as_u64()).unwrap_or(0);
                let _ = self.flush_slot(&format!("responses:args:{item_id}:{out_idx}"));
                if let Some(args) = val.get("arguments").and_then(|v| v.as_str()) {
                    let restored = self.table.restore_all_in_str(args, true);
                    if let Some(a) = val.get_mut("arguments") {
                        *a = Value::String(restored);
                    }
                }
                return synthetic_prefix;
            }
            _ => {}
        }

        // OpenAI Chat Completions chunks (`choices`).
        let mut openai_slots_to_flush: Vec<(u64, String, bool)> = Vec::new();
        if let Some(choices) = val.get_mut("choices").and_then(|v| v.as_array_mut()) {
            for (ci, choice) in choices.iter_mut().enumerate() {
                let choice_idx = choice
                    .get("index")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(ci as u64);
                let has_finish = !choice
                    .get("finish_reason")
                    .is_none_or(|v| v.is_null());

                if let Some(content) = choice.pointer("/delta/content").and_then(|v| v.as_str()) {
                    let content_owned = content.to_string();
                    let table = self.table;
                    let slot = format!("openai:content:{choice_idx}");
                    let mut emitted = self.slot_mut(&slot, false).push_chunk(&content_owned, table);
                    if has_finish {
                        let tail = self.flush_slot(&slot);
                        if !tail.is_empty() {
                            emitted.push_str(&tail);
                        }
                    }
                    if let Some(c) = choice.pointer_mut("/delta/content") {
                        *c = Value::String(emitted);
                    }
                } else if has_finish {
                    let tail = self.flush_slot(&format!("openai:content:{choice_idx}"));
                    if !tail.is_empty() {
                        openai_slots_to_flush.push((choice_idx, tail, false));
                    }
                }

                if let Some(tcs) = choice
                    .pointer_mut("/delta/tool_calls")
                    .and_then(|v| v.as_array_mut())
                {
                    for (ti, tc) in tcs.iter_mut().enumerate() {
                        let tc_idx = tc
                            .get("index")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(ti as u64);
                        if let Some(args) =
                            tc.pointer("/function/arguments").and_then(|v| v.as_str())
                        {
                            let args_owned = args.to_string();
                            let table = self.table;
                            let slot = format!("openai:args:{choice_idx}:{tc_idx}");
                            let mut emitted =
                                self.slot_mut(&slot, true).push_chunk(&args_owned, table);
                            if has_finish {
                                let tail = self.flush_slot(&slot);
                                if !tail.is_empty() {
                                    emitted.push_str(&tail);
                                }
                            }
                            if let Some(a) = tc.pointer_mut("/function/arguments") {
                                *a = Value::String(emitted);
                            }
                        }
                    }
                } else if has_finish {
                    let prefix = format!("openai:args:{choice_idx}:");
                    let matching_keys: Vec<String> = self
                        .slots
                        .keys()
                        .filter(|k| k.starts_with(&prefix))
                        .cloned()
                        .collect();
                    for key in matching_keys {
                        let tail = self.flush_slot(&key);
                        if !tail.is_empty() {
                            openai_slots_to_flush.push((choice_idx, tail, true));
                        }
                    }
                }
            }
        }
        for (choice_idx, tail, is_args) in openai_slots_to_flush {
            let chunk = if is_args {
                json!({
                    "choices": [{
                        "index": choice_idx,
                        "delta": { "tool_calls": [{ "index": 0, "function": { "arguments": tail } }] }
                    }]
                })
            } else {
                json!({
                    "choices": [{
                        "index": choice_idx,
                        "delta": { "content": tail }
                    }]
                })
            };
            if let Ok(s) = serde_json::to_string(&chunk) {
                synthetic_prefix.extend_from_slice(b"data: ");
                synthetic_prefix.extend_from_slice(s.as_bytes());
                synthetic_prefix.extend_from_slice(eol.as_bytes());
                synthetic_prefix.extend_from_slice(eol.as_bytes());
            }
        }

        // Gemini streaming chunks (`candidates`).
        if let Some(candidates) = val.get_mut("candidates").and_then(|v| v.as_array_mut()) {
            for (ci, cand) in candidates.iter_mut().enumerate() {
                let has_finish = !cand.get("finishReason").is_none_or(|v| v.is_null());
                if let Some(parts) = cand
                    .pointer_mut("/content/parts")
                    .and_then(|v| v.as_array_mut())
                {
                    for (pi, part) in parts.iter_mut().enumerate() {
                        if let Some(txt) = part.get("text").and_then(|v| v.as_str()) {
                            let txt_owned = txt.to_string();
                            let table = self.table;
                            let slot = format!("gemini:text:{ci}:{pi}");
                            let mut emitted =
                                self.slot_mut(&slot, false).push_chunk(&txt_owned, table);
                            if has_finish {
                                let tail = self.flush_slot(&slot);
                                if !tail.is_empty() {
                                    emitted.push_str(&tail);
                                }
                            }
                            if let Some(t) = part.get_mut("text") {
                                *t = Value::String(emitted);
                            }
                        }
                    }
                }
            }
        }

        synthetic_prefix
    }

    fn flush_openai_before_done(&mut self, eol: &str, out: &mut Vec<u8>) {
        let keys: Vec<String> = self
            .slots
            .keys()
            .filter(|k| k.starts_with("openai:"))
            .cloned()
            .collect();
        for key in keys {
            let tail = self.flush_slot(&key);
            if tail.is_empty() {
                continue;
            }
            let payload = if let Some(rest) = key.strip_prefix("openai:args:") {
                let mut parts = rest.split(':');
                let ci: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                let ti: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                json!({
                    "choices": [{
                        "index": ci,
                        "delta": { "tool_calls": [{ "index": ti, "function": { "arguments": tail } }] }
                    }]
                })
            } else {
                let ci: u64 = key
                    .strip_prefix("openai:content:")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                json!({
                    "choices": [{
                        "index": ci,
                        "delta": { "content": tail }
                    }]
                })
            };
            if let Ok(s) = serde_json::to_string(&payload) {
                out.extend_from_slice(b"data: ");
                out.extend_from_slice(s.as_bytes());
                out.extend_from_slice(eol.as_bytes());
                out.extend_from_slice(eol.as_bytes());
            }
        }
    }

    fn flush_all_remaining_slots(&mut self, out: &mut Vec<u8>) {
        let keys: Vec<String> = self.slots.keys().cloned().collect();
        for key in keys {
            let tail = self.flush_slot(&key);
            if tail.is_empty() {
                continue;
            }
            let payload = if let Some(idx_str) = key.strip_prefix("anthropic:text:") {
                let idx: u64 = idx_str.parse().unwrap_or(0);
                Some(json!({
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": { "type": "text_delta", "text": tail }
                }))
            } else if let Some(idx_str) = key.strip_prefix("anthropic:json:") {
                let idx: u64 = idx_str.parse().unwrap_or(0);
                Some(json!({
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": { "type": "input_json_delta", "partial_json": tail }
                }))
            } else if key.starts_with("openai:content:") {
                let ci: u64 = key
                    .strip_prefix("openai:content:")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                Some(json!({
                    "choices": [{
                        "index": ci,
                        "delta": { "content": tail }
                    }]
                }))
            } else if key.starts_with("gemini:text:") {
                Some(json!({
                    "candidates": [{
                        "content": { "parts": [{ "text": tail }] }
                    }]
                }))
            } else {
                None
            };
            if let Some(body) = payload {
                if let Ok(s) = serde_json::to_string(&body) {
                    out.extend_from_slice(b"data: ");
                    out.extend_from_slice(s.as_bytes());
                    out.extend_from_slice(b"\n\n");
                }
            }
        }
    }
}

fn find_existing_pseudonym_spans(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for marker in ["@aegis-redact.invalid", ".aegis-redact.invalid"] {
        for (m_pos, _) in text.match_indices(marker) {
            let end = m_pos + marker.len();
            let mut start = m_pos;
            while start > 0 {
                let b = text.as_bytes()[start - 1];
                if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                    start -= 1;
                } else {
                    break;
                }
            }
            if start < m_pos {
                out.push((start, end));
            }
        }
    }
    for prefix in ["tel_", "cid_"] {
        for (start, _) in text.match_indices(prefix) {
            let hex_start = start + prefix.len();
            if hex_start + 8 <= text.len()
                && text.as_bytes()[hex_start..hex_start + 8]
                    .iter()
                    .all(|b| b.is_ascii_hexdigit())
            {
                let end = hex_start + 8;
                out.push((start, end));
            }
        }
    }
    out
}

fn find_email_spans(text: &str) -> Vec<(usize, usize, String)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for (at, &b) in bytes.iter().enumerate() {
        if b != b'@' || at == 0 || at + 3 >= bytes.len() {
            continue;
        }
        let mut start = at;
        while start > 0 {
            let c = bytes[start - 1];
            if c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-') {
                start -= 1;
            } else {
                break;
            }
        }
        while start < at && bytes[start] == b'.' {
            start += 1;
        }
        if start >= at {
            continue;
        }
        if start > 0 {
            let prev = bytes[start - 1];
            if prev.is_ascii_alphanumeric() || prev == b'/' {
                continue;
            }
        }

        let mut end = at + 1;
        while end < bytes.len() {
            let c = bytes[end];
            if c.is_ascii_alphanumeric() || c == b'.' || c == b'-' {
                end += 1;
            } else {
                break;
            }
        }
        while end > at + 1 && matches!(bytes[end - 1], b'.' | b'-') {
            end -= 1;
        }
        if end <= at + 1 {
            continue;
        }
        if end < bytes.len() && matches!(bytes[end], b'@' | b'/') {
            continue;
        }

        let domain = &text[at + 1..end];
        if !domain.contains('.') {
            continue;
        }
        let Some(tld) = domain.rsplit('.').next() else {
            continue;
        };
        if !(2..=15).contains(&tld.len()) || !tld.bytes().all(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        let dom_lower = domain.to_ascii_lowercase();
        if dom_lower == "localhost"
            || dom_lower.ends_with(".localhost")
            || dom_lower == "aegis-redact.invalid"
            || dom_lower.ends_with(".aegis-redact.invalid")
            || dom_lower == "example.com"
            || dom_lower == "example.org"
            || dom_lower == "example.net"
        {
            continue;
        }
        out.push((start, end, text[start..end].to_string()));
    }
    out
}

fn find_private_ipv4_spans(text: &str) -> Vec<(usize, usize, String)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        if i > 0 {
            let prev = bytes[i - 1];
            if prev.is_ascii_alphanumeric() || matches!(prev, b'.' | b'_' | b'-') {
                while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                    i += 1;
                }
                continue;
            }
        }
        let start = i;
        let mut octets = [0u8; 4];
        let mut valid = true;
        let mut cur = i;
        for (slot_idx, slot) in octets.iter_mut().enumerate() {
            let seg_start = cur;
            while cur < bytes.len() && bytes[cur].is_ascii_digit() && cur - seg_start < 4 {
                cur += 1;
            }
            let seg = &text[seg_start..cur];
            if seg.is_empty() || seg.len() > 3 || (seg.len() > 1 && seg.starts_with('0')) {
                valid = false;
                break;
            }
            let Ok(num) = seg.parse::<u8>() else {
                valid = false;
                break;
            };
            *slot = num;
            if slot_idx < 3 {
                if cur >= bytes.len() || bytes[cur] != b'.' {
                    valid = false;
                    break;
                }
                cur += 1;
            }
        }
        if !valid {
            i = start + 1;
            continue;
        }
        if cur < bytes.len() {
            let next = bytes[cur];
            if next.is_ascii_alphanumeric() || matches!(next, b'.' | b'_' | b'-') {
                i = cur + 1;
                continue;
            }
        }
        let is_priv = octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
            || (octets[0] == 100 && (64..=127).contains(&octets[1]));
        if is_priv {
            out.push((start, cur, text[start..cur].to_string()));
            i = cur;
        } else {
            i = cur;
        }
    }
    out
}

fn find_internal_host_spans(text: &str) -> Vec<(usize, usize, String)> {
    const INTERNAL_SUFFIXES: &[&str] = &[
        ".internal",
        ".corp",
        ".lan",
        ".intranet",
        ".private",
        ".svc.cluster.local",
    ];
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if !(b.is_ascii_alphanumeric() || b == b'-') {
            i += 1;
            continue;
        }
        if i > 0 {
            let prev = bytes[i - 1];
            if prev.is_ascii_alphanumeric() || matches!(prev, b'.' | b'_' | b'-' | b'@') {
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'.' | b'-'))
                {
                    i += 1;
                }
                continue;
            }
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'.' | b'-'))
        {
            i += 1;
        }
        let mut end = i;
        while end > start && matches!(bytes[end - 1], b'.' | b'-') {
            end -= 1;
        }
        if end <= start {
            continue;
        }
        if end < bytes.len() && matches!(bytes[end], b'@' | b'_') {
            continue;
        }
        let cand = &text[start..end];
        let lower = cand.to_ascii_lowercase();
        if !lower.ends_with(".aegis-redact.invalid")
            && INTERNAL_SUFFIXES
                .iter()
                .any(|sfx| lower.len() > sfx.len() && lower.ends_with(sfx))
            && cand
                .split('.')
                .all(|lbl| !lbl.is_empty() && !lbl.starts_with('-') && !lbl.ends_with('-'))
        {
            out.push((start, end, cand.to_string()));
        }
    }
    out
}

fn find_phone_spans(text: &str) -> Vec<(usize, usize, String)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            let prev_ok =
                i == 0 || (!bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'+');
            if prev_ok && i + 1 < bytes.len() && (b'1'..=b'9').contains(&bytes[i + 1]) {
                let start = i;
                let mut cur = i + 1;
                let mut digits = 0usize;
                let mut bad_sep = false;
                let mut prev_sep = false;
                while cur < bytes.len() && cur - start <= 22 {
                    let c = bytes[cur];
                    if c.is_ascii_digit() {
                        digits += 1;
                        prev_sep = false;
                        cur += 1;
                    } else if matches!(c, b' ' | b'-') {
                        if prev_sep {
                            bad_sep = true;
                            break;
                        }
                        prev_sep = true;
                        cur += 1;
                    } else {
                        break;
                    }
                }
                while cur > start + 1 && !bytes[cur - 1].is_ascii_digit() {
                    cur -= 1;
                }
                let next_ok = cur == bytes.len()
                    || (!bytes[cur].is_ascii_alphanumeric() && !matches!(bytes[cur], b'.' | b'_'));
                if !bad_sep && next_ok && (9..=15).contains(&digits) {
                    out.push((start, cur, text[start..cur].to_string()));
                    i = cur;
                    continue;
                }
            }
        } else if bytes[i] == b'1' && i + 11 <= bytes.len() {
            let prev_ok = i == 0
                || (!bytes[i - 1].is_ascii_alphanumeric()
                    && !matches!(bytes[i - 1], b'.' | b'-' | b'_' | b'+'));
            let next_ok = i + 11 == bytes.len()
                || (!bytes[i + 11].is_ascii_alphanumeric()
                    && !matches!(bytes[i + 11], b'.' | b'-' | b'_'));
            if prev_ok
                && next_ok
                && (b'3'..=b'9').contains(&bytes[i + 1])
                && bytes[i + 2..i + 11].iter().all(|b| b.is_ascii_digit())
            {
                out.push((i, i + 11, text[i..i + 11].to_string()));
                i += 11;
                continue;
            }
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudonym_roundtrip_and_idempotency() {
        let table = PseudonymSessionTable::new();
        let rules = vec![CustomRedactionRule {
            name: "proj".to_string(),
            literal: "ProjectPhoenix".to_string(),
            tag: None,
        }];
        let input = "Contact alice@acme.org or 13812345678 / +1-415-555-2671, connect 192.168.10.25:5432 or db.internal for ProjectPhoenix (v10.2.3.4 example@example.com 127.0.0.1 untouched).";
        let masked = table.pseudonymize_text(input, &rules).unwrap();
        assert!(!masked.contains("alice@acme.org"), "{masked}");
        assert!(!masked.contains("13812345678"), "{masked}");
        assert!(!masked.contains("+1-415-555-2671"), "{masked}");
        assert!(!masked.contains("192.168.10.25"), "{masked}");
        assert!(masked.contains(":5432"), "port preserved: {masked}");
        assert!(!masked.contains("db.internal"), "{masked}");
        assert!(!masked.contains("ProjectPhoenix"), "{masked}");
        assert!(masked.contains("v10.2.3.4"), "version skipped: {masked}");
        assert!(
            masked.contains("example@example.com"),
            "example.com skipped: {masked}"
        );
        assert!(masked.contains("127.0.0.1"), "loopback skipped: {masked}");

        // Second pass on already-masked text must be an exact no-op.
        assert!(table.pseudonymize_text(&masked, &rules).is_none());

        // Same inputs produce identical pseudonyms in the same session.
        let masked_again = table
            .pseudonymize_text("Email alice@acme.org", &rules)
            .unwrap();
        let email_pseudo = table.get_or_insert("email", "alice@acme.org");
        assert!(masked_again.contains(&email_pseudo));

        // Restoring returns the exact original string.
        assert_eq!(table.restore_all_in_str(&masked, false), input);
    }

    #[test]
    fn sse_random_chunk_split_fuzz_restoration() {
        let table = PseudonymSessionTable::new();
        let rules = vec![CustomRedactionRule {
            name: "quote_literal".to_string(),
            literal: "quote\"and\\slash\nline".to_string(),
            tag: None,
        }];
        let orig_email = "alice@secret-corp.com";
        let orig_ip = "10.24.8.12";
        let orig_custom = "quote\"and\\slash\nline";
        let req = json!({
            "model": "claude-sonnet-4-5",
            "messages": [{
                "role": "user",
                "content": format!("Reach {orig_email} on {orig_ip} with {orig_custom}")
            }]
        });
        let req_bytes = serde_json::to_vec(&req).unwrap();
        let masked_req = table.pseudonymize_json_request_body(&req_bytes, &rules).unwrap();
        let masked_str = String::from_utf8(masked_req).unwrap();
        assert!(!masked_str.contains(orig_email));
        assert!(!masked_str.contains(orig_ip));
        assert!(!masked_str.contains("quote\\\"and"));

        let pseudo_email = table.get_or_insert("email", orig_email);
        let pseudo_ip = table.get_or_insert("ipv4", orig_ip);
        let pseudo_custom = table.get_or_insert("custom", orig_custom);

        // Simulate Anthropic text_delta + input_json_delta split mid-pseudonym (plus Chinese multi-byte UTF-8)
        let anthropic_sse = format!(
            "event: message_start\n\
             data: {{\"type\":\"message_start\",\"message\":{{\"model\":\"claude-sonnet-4-5\",\"usage\":{{\"input_tokens\":42}}}}}}\n\n\
             event: content_block_delta\n\
             data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"用户 {p1}\"}}}}\n\n\
             event: content_block_delta\n\
             data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{p2} 地址 {ip1}\"}}}}\n\n\
             event: content_block_delta\n\
             data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{ip2}\"}}}}\n\n\
             event: content_block_stop\n\
             data: {{\"type\":\"content_block_stop\",\"index\":0}}\n\n\
             event: content_block_delta\n\
             data: {{\"type\":\"content_block_delta\",\"index\":1,\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"{{\\\"msg\\\":\\\"{c1}\"}}}}\n\n\
             event: content_block_delta\n\
             data: {{\"type\":\"content_block_delta\",\"index\":1,\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"{c2}\\\"}}\"}}}}\n\n\
             event: content_block_stop\n\
             data: {{\"type\":\"content_block_stop\",\"index\":1}}\n\n\
             event: message_stop\n\
             data: {{\"type\":\"message_stop\"}}\n\n",
            p1 = &pseudo_email[..7],
            p2 = &pseudo_email[7..],
            ip1 = &pseudo_ip[..5],
            ip2 = &pseudo_ip[5..],
            c1 = &pseudo_custom[..6],
            c2 = &pseudo_custom[6..],
        );

        // Fuzz every TCP read chunk size from 1..=33 bytes!
        for step in 1usize..=33 {
            let mut tx = SseResponseTransformer::new(&table);
            let mut assembled = Vec::new();
            for chunk in anthropic_sse.as_bytes().chunks(step) {
                assembled.extend_from_slice(&tx.push_bytes(chunk));
            }
            assembled.extend_from_slice(&tx.finish_bytes());
            let full = String::from_utf8(assembled).expect("valid UTF-8 across chunk splits");

            let mut text_out = String::new();
            let mut partial_json_out = String::new();
            for line in full.lines() {
                if let Some(d) = line.strip_prefix("data:") {
                    let v: Value = serde_json::from_str(d.trim()).expect("every SSE data must be valid JSON");
                    if v.pointer("/delta/type").and_then(|x| x.as_str()) == Some("text_delta") {
                        text_out.push_str(v.pointer("/delta/text").and_then(|x| x.as_str()).unwrap_or(""));
                    } else if v.pointer("/delta/type").and_then(|x| x.as_str()) == Some("input_json_delta") {
                        partial_json_out.push_str(
                            v.pointer("/delta/partial_json")
                                .and_then(|x| x.as_str())
                                .unwrap_or(""),
                        );
                    }
                }
            }
            assert_eq!(
                text_out,
                format!("用户 {orig_email} 地址 {orig_ip}"),
                "step={step}"
            );
            let parsed_tool_args: Value =
                serde_json::from_str(&partial_json_out).expect("restored tool JSON must parse cleanly");
            assert_eq!(parsed_tool_args["msg"], orig_custom, "step={step}");
            assert!(!full.contains("aegis-redact.invalid"), "step={step}");
            assert!(!full.contains(&pseudo_custom), "step={step}");
        }

        // Verify OpenAI SSE chunk splitting before [DONE].
        let openai_sse = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"Mail {p1}\"}},\"finish_reason\":null}}]}}\n\n\
             data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{p2}\"}},\"finish_reason\":\"stop\"}}]}}\n\n\
             data: [DONE]\n\n",
            p1 = &pseudo_email[..6],
            p2 = &pseudo_email[6..],
        );
        let mut tx = SseResponseTransformer::new(&table);
        let mut out = tx.push_bytes(openai_sse.as_bytes());
        out.extend_from_slice(&tx.finish_bytes());
        let s = String::from_utf8(out).unwrap();
        let mut combined = String::new();
        for line in s.lines() {
            if let Some(d) = line.strip_prefix("data:") {
                let d = d.trim();
                if d == "[DONE]" {
                    continue;
                }
                let v: Value = serde_json::from_str(d).unwrap();
                combined.push_str(
                    v.pointer("/choices/0/delta/content")
                        .and_then(|x| x.as_str())
                        .unwrap_or(""),
                );
            }
        }
        assert_eq!(combined, format!("Mail {orig_email}"));
    }

    #[test]
    fn non_streaming_json_restoration_restores_arguments_with_escaping() {
        let table = PseudonymSessionTable::new();
        let orig_email = "ops@private.corp";
        let orig_lit = "hello\"world";
        let p_email = table.get_or_insert("email", orig_email);
        let p_lit = table.get_or_insert("custom", orig_lit);

        let resp = serde_json::to_vec(&json!({
            "id": "chatcmpl-1",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": format!("Sent to {p_email}"),
                    "tool_calls": [{
                        "function": {
                            "name": "notify",
                            "arguments": format!("{{\"note\":\"{p_lit}\"}}")
                        }
                    }]
                }
            }]
        }))
        .unwrap();

        let restored = table.restore_json_response_body(&resp).unwrap();
        let v: Value = serde_json::from_slice(&restored).unwrap();
        assert_eq!(v["choices"][0]["message"]["content"], format!("Sent to {orig_email}"));
        let args_str = v["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        let args_json: Value = serde_json::from_str(args_str).unwrap();
        assert_eq!(args_json["note"], orig_lit);
    }
}
