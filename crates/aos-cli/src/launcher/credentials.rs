use super::*;

pub(super) const MAX_CREDENTIAL_SYNC_BYTES: u64 = 256 * 1024;
pub(super) const MAX_SETTINGS_SYNC_BYTES: u64 = MAX_SEED_FILE_BYTES;

pub(super) const AGY_AND_GEMINI_OAUTH_STORE_FILES: &[&str] = &[
    ".gemini/oauth_creds.json",
    ".gemini/antigravity-cli/oauth_creds.json",
    ".gemini/antigravity-cli/antigravity-oauth-token",
    ".gemini/antigravity/antigravity-oauth-token",
    ".gemini/antigravity-ide/antigravity-oauth-token",
    ".gemini/jetski-standalone-oauth-token",
];

pub(super) const AGY_PLUGIN_SECRET_FILES: &[&str] = &[
    "Library/Application Support/antigravity/plugin-secrets.json",
    ".config/antigravity/plugin-secrets.json",
];

pub(super) const AGY_USER_SCOPE_FILES: &[&str] = &[
    "Library/Application Support/antigravity/credential-user-scope",
    ".config/antigravity/credential-user-scope",
];

pub(super) const ALLOWED_AGY_ONBOARDING_SYNC_KEYS: &[&str] = &[
    "onboardingComplete",
    "consumerOnboardingComplete",
    "enterpriseOnboardingComplete",
];

pub(super) const ALLOWED_CLAUDE_JSON_SYNC_KEYS: &[&str] = &[
    "oauthAccount",
    "hasCompletedOnboarding",
    "userID",
];

pub(super) const ALLOWED_GEMINI_SETTINGS_SYNC_KEYS: &[&str] = &[
    "google_credentials",
    "selectedAuthType",
    "auth_type",
    "oauthAccount",
    "userAccount",
    "hasCompletedOnboarding",
    "theme",
    "model",
    "default_model",
    "agentMode",
];

pub(super) const ALLOWED_OPENCODE_AUTH_ENTRY_KEYS: &[&str] = &[
    "type",
    "key",
    "access",
    "refresh",
    "expires",
    "accountId",
    "enterpriseUrl",
];

pub(super) fn walk_no_symlink_components(root: &Path, rel: &str) -> Result<Option<PathBuf>, ()> {
    let rel_path = Path::new(rel);
    let mut cur = root.to_path_buf();
    let mut saw_seg = false;
    for comp in rel_path.components() {
        let std::path::Component::Normal(seg) = comp else {
            return Err(());
        };
        cur.push(seg);
        saw_seg = true;
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(_) => return Err(()),
        }
    }
    if !saw_seg {
        return Err(());
    }
    Ok(Some(cur))
}

pub(super) fn read_existing_json_object_with_limit_no_symlink(
    root: &Path,
    rel: &str,
    allow_placeholders: bool,
    allow_empty: bool,
    max_bytes: u64,
) -> Option<(String, serde_json::Map<String, Value>)> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let cur = walk_no_symlink_components(root, rel).ok()??;
    let leaf_meta = std::fs::symlink_metadata(&cur).ok()?;
    if !leaf_meta.file_type().is_file() || leaf_meta.len() == 0 || leaf_meta.len() > max_bytes {
        return None;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&cur)
        .ok()?;
    let mut buf = Vec::with_capacity((leaf_meta.len() as usize).min(max_bytes as usize));
    file.take(max_bytes + 1).read_to_end(&mut buf).ok()?;
    if buf.is_empty() || (buf.len() as u64) > max_bytes {
        return None;
    }
    let raw = String::from_utf8(buf).ok()?;
    if !allow_placeholders && raw.contains("$AOS_SECRET_") {
        return None;
    }
    match serde_json::from_str::<Value>(&raw).ok()? {
        Value::Object(map) if allow_empty || !map.is_empty() => Some((raw, map)),
        _ => None,
    }
}

pub(super) fn read_sandbox_json_object_with_limit_no_symlink(
    root: &Path,
    rel: &str,
    allow_placeholders: bool,
    max_bytes: u64,
) -> Option<(String, serde_json::Map<String, Value>)> {
    read_existing_json_object_with_limit_no_symlink(root, rel, allow_placeholders, false, max_bytes)
}

/// Read and parse a non-empty JSON object from `root/rel` while rejecting any symlink component,
/// non-regular file, `O_NOFOLLOW` open failure, or file larger than `MAX_CREDENTIAL_SYNC_BYTES`.
/// Prevents Confused-Deputy symlink attacks where a sandboxed process points a credential path at
/// a host file (e.g., `~/.ssh/id_ed25519`) so the unconfined parent copies it onto `host_home`.
pub(super) fn read_sandbox_json_object_no_symlink(
    root: &Path,
    rel: &str,
    allow_placeholders: bool,
) -> Option<(String, serde_json::Map<String, Value>)> {
    read_sandbox_json_object_with_limit_no_symlink(
        root,
        rel,
        allow_placeholders,
        MAX_CREDENTIAL_SYNC_BYTES,
    )
}

/// Safely load an existing JSON object from `host_home/rel` for key-level merging, or initialize
/// an empty map when the path does not yet exist. Returns `None` if a symlink is encountered,
/// the file exceeds `max_bytes`, or existing JSON is unreadable/corrupt so host files are never
/// silently clobbered.
pub(super) fn load_or_init_host_json_for_merge(
    host_home: &Path,
    rel: &str,
    max_bytes: u64,
) -> Option<serde_json::Map<String, Value>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let rel_path = Path::new(rel);
    let comps: Vec<&std::ffi::OsStr> = rel_path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();
    if comps.is_empty() || comps.len() != rel_path.components().count() {
        return None;
    }

    let mut cur = host_home.to_path_buf();
    for (idx, seg) in comps.iter().enumerate() {
        cur.push(seg);
        let is_last = idx + 1 == comps.len();
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return None;
                }
                if !is_last && !meta.file_type().is_dir() {
                    return None;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Some(serde_json::Map::new());
            }
            Err(_) => return None,
        }
    }

    let leaf_meta = std::fs::symlink_metadata(&cur).ok()?;
    if !leaf_meta.file_type().is_file() || leaf_meta.len() > max_bytes {
        return None;
    }
    if leaf_meta.len() == 0 {
        return Some(serde_json::Map::new());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&cur)
        .ok()?;
    let mut buf = Vec::with_capacity((leaf_meta.len() as usize).min(max_bytes as usize));
    file.take(max_bytes + 1).read_to_end(&mut buf).ok()?;
    if (buf.len() as u64) > max_bytes {
        return None;
    }
    let raw = String::from_utf8(buf).ok()?;
    match serde_json::from_str::<Value>(&raw).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

pub(super) fn read_sandbox_scope_id_no_symlink(root: &Path, rel: &str) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    const MAX_SCOPE_ID_BYTES: u64 = 128;
    let cur = walk_no_symlink_components(root, rel).ok()??;
    let leaf_meta = std::fs::symlink_metadata(&cur).ok()?;
    if !leaf_meta.file_type().is_file()
        || leaf_meta.len() == 0
        || leaf_meta.len() > MAX_SCOPE_ID_BYTES
    {
        return None;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&cur)
        .ok()?;
    let mut buf = Vec::with_capacity(leaf_meta.len() as usize);
    file.take(MAX_SCOPE_ID_BYTES + 1)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.is_empty() || (buf.len() as u64) > MAX_SCOPE_ID_BYTES {
        return None;
    }
    let raw = String::from_utf8(buf).ok()?;
    if raw.contains("$AOS_SECRET_") {
        return None;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return None;
    }
    Some(trimmed.to_string())
}

pub(super) fn write_host_bytes_0600_no_symlink(host_home: &Path, rel: &str, bytes: &[u8]) -> bool {
    use std::io::Read;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let rel_path = Path::new(rel);
    let comps: Vec<&std::ffi::OsStr> = rel_path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();
    if comps.is_empty() || comps.len() != rel_path.components().count() {
        return false;
    }

    let mut parent = host_home.to_path_buf();
    for dir_seg in &comps[..comps.len() - 1] {
        parent.push(dir_seg);
        match std::fs::symlink_metadata(&parent) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                    return false;
                }
            }
            Err(_) => {
                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                if builder.create(&parent).is_err() {
                    return false;
                }
            }
        }
    }

    let dst = parent.join(comps[comps.len() - 1]);
    if let Ok(dst_meta) = std::fs::symlink_metadata(&dst) {
        if dst_meta.file_type().is_symlink() || dst_meta.file_type().is_dir() {
            return false;
        }
        if dst_meta.len() == bytes.len() as u64 {
            if let Ok(file) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&dst)
            {
                let mut existing = Vec::with_capacity(bytes.len());
                if file
                    .take(bytes.len() as u64 + 1)
                    .read_to_end(&mut existing)
                    .is_ok()
                    && existing.as_slice() == bytes
                {
                    return false;
                }
            }
        }
    }

    let tmp = parent.join(format!(
        ".aegis-cred-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let write_res = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(bytes)?;
            f.sync_all()
        });
    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    if let Err(err) = std::fs::rename(&tmp, &dst) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!(
            "aos run: warning: could not write back {}: {err}",
            dst.display()
        );
        return false;
    }
    true
}

/// True when `new` introduces no structure that `old` lacks: every object key of `new` exists in
/// `old` with a value of the same JSON shape, and arrays carry only scalars. Lets rotated OAuth
/// tokens (same keys, new string values) flow back while rejecting injected fields such as hooks,
/// plugin/MCP configuration, endpoints, or nested objects.
pub(super) fn json_shape_within(new: &Value, old: &Value) -> bool {
    match (new, old) {
        (Value::Object(n), Value::Object(o)) => n
            .iter()
            .all(|(k, v)| o.get(k).is_some_and(|ov| json_shape_within(v, ov))),
        (Value::Array(n), Value::Array(_)) => n
            .iter()
            .all(|v| matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null)),
        (Value::String(_), Value::String(_))
        | (Value::Number(_), Value::Number(_))
        | (Value::Bool(_), Value::Bool(_)) => true,
        (Value::Null, _) => true,
        (Value::String(_) | Value::Number(_) | Value::Bool(_), Value::Null) => true,
        _ => false,
    }
}

/// Whole-file credential write-back from a sandbox-writable `agent_home` to the host `$HOME`.
///
/// The sandbox controls these bytes, so they are only accepted when they do not *expand* the
/// host file's structure (see [`json_shape_within`]). A missing host file may be created only for
/// pure OAuth token stores (`allow_create`), never for free-form files such as plugin secrets or
/// client state. Note: this cannot detect a well-formed token for a *different* account
/// (account swap); that residual risk is documented.
pub(super) fn write_back_credential_object(
    host_home: &Path,
    rel: &str,
    sandbox_obj: &serde_json::Map<String, Value>,
    allow_create: bool,
) -> bool {
    let host_exists = std::fs::symlink_metadata(host_home.join(rel)).is_ok();
    match read_existing_json_object_with_limit_no_symlink(
        host_home,
        rel,
        true,
        true,
        MAX_CREDENTIAL_SYNC_BYTES,
    ) {
        Some((_, existing)) => {
            if !json_shape_within(
                &Value::Object(sandbox_obj.clone()),
                &Value::Object(existing),
            ) {
                eprintln!(
                    "aos: refusing credential write-back to ~/{rel}: sandbox copy adds fields or changes structure"
                );
                return false;
            }
        }
        None => {
            // Unreadable / oversized / non-object host file, or no file and creation not allowed.
            if host_exists || !allow_create {
                return false;
            }
        }
    }
    write_host_json_0600_no_symlink(host_home, rel, sandbox_obj)
}

pub(super) fn write_host_json_0600_no_symlink(
    host_home: &Path,
    rel: &str,
    obj: &serde_json::Map<String, Value>,
) -> bool {
    if let Some((_, existing)) = read_existing_json_object_with_limit_no_symlink(
        host_home,
        rel,
        true,
        true,
        MAX_SETTINGS_SYNC_BYTES,
    ) {
        if &existing == obj {
            return false;
        }
    }

    let Ok(mut serialized) = serde_json::to_vec_pretty(&Value::Object(obj.clone())) else {
        return false;
    };
    serialized.push(b'\n');
    write_host_bytes_0600_no_symlink(host_home, rel, &serialized)
}

pub(super) fn is_valid_opencode_auth_entry(entry: &Value) -> bool {
    let Value::Object(map) = entry else {
        return false;
    };
    if map.is_empty() {
        return false;
    }
    map.iter().all(|(k, v)| {
        ALLOWED_OPENCODE_AUTH_ENTRY_KEYS.contains(&k.as_str())
            && matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_))
            && !v.as_str().is_some_and(|s| s.contains("$AOS_SECRET_"))
    })
}

/// Controlled OAuth declassification gate from `agent_home` back to `host_home`.
/// Enforces four invariants:
/// 1. Symlink-free `O_NOFOLLOW` reads (`<= 256 KiB` for credential stores, `<= 8 MiB` for shared
///    settings JSON) and `0600` temp-file atomic writes;
/// 2. Active-client scoping (`command`) so an agent can never modify foreign-agent stores
///    (and non-agent commands like `python3`/`pytest` have zero write-back surface);
/// 3. Strict JSON AST parsing + field allowlists (never raw byte copy or denylists),
///    dropping `hooks`, `mcpServers`, `security`, `tools`, `coreTools`, and unknown keys;
/// 4. Opt-out via `AOS_NO_CREDENTIAL_SYNC=1`.
pub(crate) fn sync_credentials(agent_home: &Path, host_home: &Path, command: &[String]) {
    if std::env::var_os("AOS_NO_CREDENTIAL_SYNC")
        .and_then(|v| v.into_string().ok())
        .is_some_and(|s| matches!(s.trim(), "1" | "true" | "TRUE" | "yes"))
    {
        return;
    }

    if is_claude_command(command) {
        if let Some((_, cred_obj)) =
            read_sandbox_json_object_no_symlink(agent_home, ".claude/.credentials.json", false)
        {
            let _ = write_back_credential_object(
                host_home,
                ".claude/.credentials.json",
                &cred_obj,
                true,
            );
            if let Some(ses_dir) = agent_home.parent() {
                if let Some(sessions_dir) = ses_dir.parent() {
                    if sessions_dir.file_name().and_then(|n| n.to_str()) == Some("sessions") {
                        if let Some(runtime_dir) = sessions_dir.parent() {
                            sync_runtime_claude_oauth_from_agent_home(
                                runtime_dir,
                                agent_home,
                                command,
                            );
                        }
                    }
                }
            }
        }
        if let Some((_, agent_obj)) = read_sandbox_json_object_with_limit_no_symlink(
            agent_home,
            ".claude.json",
            false,
            MAX_SETTINGS_SYNC_BYTES,
        ) {
            if let Some(mut host_obj) =
                load_or_init_host_json_for_merge(host_home, ".claude.json", MAX_SETTINGS_SYNC_BYTES)
            {
                let mut changed = false;
                for key in ALLOWED_CLAUDE_JSON_SYNC_KEYS {
                    if let Some(val) = agent_obj.get(*key) {
                        if !val.is_null() && host_obj.get(*key) != Some(val) {
                            host_obj.insert((*key).to_string(), val.clone());
                            changed = true;
                        }
                    }
                }
                if changed {
                    let _ = write_host_json_0600_no_symlink(host_home, ".claude.json", &host_obj);
                }
            }
        }
    } else if is_codex_command(command) {
        if let Some((_, auth_obj)) =
            read_sandbox_json_object_no_symlink(agent_home, ".codex/auth.json", false)
        {
            let _ = write_back_credential_object(host_home, ".codex/auth.json", &auth_obj, true);
        }
    } else if is_hermes_command(command) {
        if let Some((_, auth_obj)) =
            read_sandbox_json_object_no_symlink(agent_home, ".hermes/auth.json", false)
        {
            let _ = write_back_credential_object(host_home, ".hermes/auth.json", &auth_obj, true);
        }
    } else if is_agy_or_gemini_command(command) {
        for rel in AGY_AND_GEMINI_OAUTH_STORE_FILES.iter().copied().chain([
            ".gemini/google_accounts.json",
            ".gemini/state.json",
            ".gemini/antigravity-cli/google_accounts.json",
            ".gemini/antigravity-cli/state.json",
        ]) {
            if let Some((_, cred_obj)) =
                read_sandbox_json_object_no_symlink(agent_home, rel, false)
            {
                // Token stores may be created on first login; free-form client state may not.
                let allow_create = !rel.ends_with("state.json");
                let _ = write_back_credential_object(host_home, rel, &cred_obj, allow_create);
            }
        }
        if is_agy_command(command) {
            for rel in AGY_PLUGIN_SECRET_FILES {
                if let Some((_, secrets_obj)) =
                    read_sandbox_json_object_no_symlink(agent_home, rel, false)
                {
                    // Plugin secrets are free-form plugin configuration: never created from the
                    // sandbox, and only updated without structural expansion.
                    let _ = write_back_credential_object(host_home, rel, &secrets_obj, false);
                }
            }
            for rel in AGY_USER_SCOPE_FILES {
                if let Some(scope) = read_sandbox_scope_id_no_symlink(agent_home, rel) {
                    let _ = write_host_bytes_0600_no_symlink(host_home, rel, scope.as_bytes());
                }
            }
            let onboarding_rel = ".gemini/antigravity-cli/cache/onboarding.json";
            if let Some((_, agent_onb)) =
                read_sandbox_json_object_no_symlink(agent_home, onboarding_rel, false)
            {
                if let Some(mut host_onb) = load_or_init_host_json_for_merge(
                    host_home,
                    onboarding_rel,
                    MAX_CREDENTIAL_SYNC_BYTES,
                ) {
                    let mut changed = false;
                    for key in ALLOWED_AGY_ONBOARDING_SYNC_KEYS {
                        if let Some(val) = agent_onb.get(*key) {
                            if val.is_boolean() && host_onb.get(*key) != Some(val) {
                                host_onb.insert((*key).to_string(), val.clone());
                                changed = true;
                            }
                        }
                    }
                    if changed {
                        let _ =
                            write_host_json_0600_no_symlink(host_home, onboarding_rel, &host_onb);
                    }
                }
            }
        }
        if let Some(ses_dir) = agent_home.parent() {
            if let Some(sessions_dir) = ses_dir.parent() {
                if sessions_dir.file_name().and_then(|n| n.to_str()) == Some("sessions") {
                    if let Some(runtime_dir) = sessions_dir.parent() {
                        sync_runtime_agy_oauth_from_agent_home(runtime_dir, agent_home, command);
                    }
                }
            }
        }
        for rel_settings in [
            ".gemini/antigravity-cli/settings.json",
            ".gemini/settings.json",
        ] {
            let Some((_, agent_obj)) = read_sandbox_json_object_with_limit_no_symlink(
                agent_home,
                rel_settings,
                false,
                MAX_SETTINGS_SYNC_BYTES,
            ) else {
                continue;
            };
            let Some(mut host_obj) = load_or_init_host_json_for_merge(
                host_home,
                rel_settings,
                MAX_SETTINGS_SYNC_BYTES,
            ) else {
                continue;
            };
            let mut changed = false;
            for key in ALLOWED_GEMINI_SETTINGS_SYNC_KEYS {
                if let Some(val) = agent_obj.get(*key) {
                    if !val.is_null() && host_obj.get(*key) != Some(val) {
                        host_obj.insert((*key).to_string(), val.clone());
                        changed = true;
                    }
                }
            }
            if changed {
                let _ = write_host_json_0600_no_symlink(host_home, rel_settings, &host_obj);
            }
        }
    } else if is_opencode_command(command) {
        if let Some((_, agent_obj)) = read_sandbox_json_object_no_symlink(
            agent_home,
            ".local/share/opencode/auth.json",
            true,
        ) {
            let Some(mut host_obj) = load_or_init_host_json_for_merge(
                host_home,
                ".local/share/opencode/auth.json",
                MAX_CREDENTIAL_SYNC_BYTES,
            ) else {
                return;
            };
            let headless_run = command.get(1).is_some_and(|sub| sub == "run");
            let mut changed = false;
            for (prov, entry) in agent_obj {
                if !is_valid_opencode_auth_entry(&entry) {
                    continue;
                }
                let is_api_entry = entry.get("type").and_then(|v| v.as_str()) == Some("api");
                if headless_run && is_api_entry && host_obj.contains_key(&prov) {
                    continue;
                }
                if host_obj.get(&prov) != Some(&entry) {
                    host_obj.insert(prov, entry);
                    changed = true;
                }
            }
            if changed {
                let _ = write_host_json_0600_no_symlink(
                    host_home,
                    ".local/share/opencode/auth.json",
                    &host_obj,
                );
            }
        }
    }
}

pub(super) fn agy_gemini_watch_fingerprint(agent_home: &Path, is_agy: bool) -> Vec<String> {
    let mut fp = Vec::new();
    for rel in AGY_AND_GEMINI_OAUTH_STORE_FILES.iter().copied().chain([
        ".gemini/google_accounts.json",
        ".gemini/antigravity-cli/google_accounts.json",
    ]) {
        fp.push(
            read_sandbox_json_object_no_symlink(agent_home, rel, false)
                .map(|(raw, _)| raw)
                .unwrap_or_default(),
        );
    }
    for rel_settings in [
        ".gemini/antigravity-cli/settings.json",
        ".gemini/settings.json",
    ] {
        fp.push(
            read_sandbox_json_object_with_limit_no_symlink(
                agent_home,
                rel_settings,
                false,
                MAX_SETTINGS_SYNC_BYTES,
            )
            .map(|(raw, _)| raw)
            .unwrap_or_default(),
        );
    }
    if is_agy {
        for rel in AGY_PLUGIN_SECRET_FILES {
            fp.push(
                read_sandbox_json_object_no_symlink(agent_home, rel, false)
                    .map(|(raw, _)| raw)
                    .unwrap_or_default(),
            );
        }
        for rel in AGY_USER_SCOPE_FILES {
            fp.push(read_sandbox_scope_id_no_symlink(agent_home, rel).unwrap_or_default());
        }
        fp.push(
            read_sandbox_json_object_no_symlink(
                agent_home,
                ".gemini/antigravity-cli/cache/onboarding.json",
                false,
            )
            .map(|(raw, _)| raw)
            .unwrap_or_default(),
        );
    }
    fp
}

pub(crate) fn backfill_host_agy_credentials_from_sessions(
    runtime_dir: &Path,
    host_home: &Path,
) -> bool {
    let token_rel = ".gemini/antigravity-cli/antigravity-oauth-token";
    if host_home.join(token_rel).is_file() {
        return false;
    }
    for dir in sorted_agy_session_dirs(runtime_dir) {
        let ses_agent_home = dir.join("agent_home");
        if read_sandbox_json_object_no_symlink(&ses_agent_home, token_rel, false).is_some() {
            sync_credentials(&ses_agent_home, host_home, &["agy".to_string()]);
            return host_home.join(token_rel).is_file();
        }
    }
    false
}

pub(super) const AGY_CACHE_TOKEN_PRIMARY: &str = ".gemini/antigravity-cli/antigravity-oauth-token";
pub(super) const MAX_CONVERSATION_FILE_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_CONVERSATION_TOTAL_BYTES: u64 = 768 * 1024 * 1024;

pub(super) fn sorted_agy_session_dirs(runtime_dir: &Path) -> Vec<PathBuf> {
    let sessions_dir = runtime_dir.join("sessions");
    if !std::fs::symlink_metadata(&sessions_dir)
        .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
    {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(&sessions_dir) else {
        return Vec::new();
    };
    let mut hits: Vec<(i64, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !std::fs::symlink_metadata(&dir)
            .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
        {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(dir.join("session.json")) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let is_agy = value
            .get("agent_id")
            .and_then(|v| v.as_str())
            .is_some_and(|id| id == "agy-agent" || id.starts_with("agy-"));
        if !is_agy {
            continue;
        }
        let ts = value
            .get("updated_at_ms")
            .or_else(|| value.get("created_at_ms"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        hits.push((ts, dir));
    }
    hits.sort_by_key(|b| std::cmp::Reverse(b.0));
    hits.into_iter().map(|(_, dir)| dir).collect()
}

pub(super) fn agy_runtime_credentials_dir(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("credentials").join("agy")
}

pub(super) fn claude_runtime_credentials_dir(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("credentials").join("claude")
}

/// Seal active Claude OAuth credentials into `<runtime_dir>/credentials/claude/credentials.json`
/// (`0700` dir, `0600` symlink-free file) so host Keychain sweeps or missing host `.credentials.json`
/// cannot strand subsequent sandboxed Claude sessions.
pub(crate) fn sync_runtime_claude_oauth_from_agent_home(
    runtime_dir: &Path,
    agent_home: &Path,
    command: &[String],
) {
    if !is_claude_command(command) {
        return;
    }
    if std::env::var_os("AOS_NO_CREDENTIAL_SYNC")
        .and_then(|v| v.into_string().ok())
        .is_some_and(|s| matches!(s.trim(), "1" | "true" | "TRUE" | "yes"))
    {
        return;
    }
    let creds_parent = runtime_dir.join("credentials");
    if !ensure_0700_dir_no_symlink(&creds_parent) {
        return;
    }
    let cache_dir = claude_runtime_credentials_dir(runtime_dir);
    if !ensure_0700_dir_no_symlink(&cache_dir) {
        return;
    }
    if let Some((_, cred_obj)) =
        read_sandbox_json_object_no_symlink(agent_home, ".claude/.credentials.json", false)
    {
        let _ = write_host_json_0600_no_symlink(&cache_dir, "credentials.json", &cred_obj);
    }
}

/// Ensure `agent_home` has `.claude/.credentials.json` even when host Claude sweeps credentials
/// into macOS Keychain.
pub(crate) fn restore_or_seed_claude_oauth_cache(
    runtime_dir: &Path,
    agent_home: &Path,
    command: &[String],
    harvested_secrets: &std::collections::HashMap<String, String>,
) {
    if !is_claude_command(command) || harvested_secrets.contains_key("CLAUDE_CODE_OAUTH_TOKEN") {
        return;
    }
    let rel = ".claude/.credentials.json";
    if read_sandbox_json_object_no_symlink(agent_home, rel, false).is_some() {
        sync_runtime_claude_oauth_from_agent_home(runtime_dir, agent_home, command);
        return;
    }
    let cache_dir = claude_runtime_credentials_dir(runtime_dir);
    if std::fs::symlink_metadata(&cache_dir)
        .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
    {
        if let Some((_, cred_obj)) =
            read_sandbox_json_object_no_symlink(&cache_dir, "credentials.json", false)
        {
            let _ = write_host_json_0600_no_symlink(agent_home, rel, &cred_obj);
            return;
        }
    }
    let sessions_dir = runtime_dir.join("sessions");
    if let Ok(entries) = std::fs::read_dir(&sessions_dir) {
        let mut hits: Vec<(i64, PathBuf)> = Vec::new();
        for entry in entries.flatten() {
            let dir = entry.path();
            if !std::fs::symlink_metadata(&dir)
                .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
            {
                continue;
            }
            let ts = std::fs::read_to_string(dir.join("session.json"))
                .ok()
                .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                .and_then(|val| {
                    val.get("updated_at_ms")
                        .or_else(|| val.get("created_at_ms"))
                        .and_then(|v| v.as_i64())
                })
                .unwrap_or(0);
            hits.push((ts, dir));
        }
        hits.sort_by_key(|b| std::cmp::Reverse(b.0));
        for (_, ses_dir) in hits {
            let Some(ses_home) = resolve_symlink_free_dir(&ses_dir, Path::new("agent_home")) else {
                continue;
            };
            if let Some((_, cred_obj)) =
                read_sandbox_json_object_no_symlink(&ses_home, rel, false)
            {
                let _ = write_host_json_0600_no_symlink(agent_home, rel, &cred_obj);
                sync_runtime_claude_oauth_from_agent_home(runtime_dir, agent_home, command);
                return;
            }
        }
    }
}

pub(super) fn ensure_0700_dir_no_symlink(dir: &Path) -> bool {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return false;
            }
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            true
        }
        Err(_) => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(dir).is_ok()
        }
    }
}

/// Seal active `agy` / `gemini` OAuth tokens into `<runtime_dir>/credentials/agy` (`0700` dir,
/// `0600` atomic symlink-free files) so host Keychain sweeps cannot strand subsequent sandboxed runs.
pub(crate) fn sync_runtime_agy_oauth_from_agent_home(
    runtime_dir: &Path,
    agent_home: &Path,
    command: &[String],
) {
    if !is_agy_or_gemini_command(command) {
        return;
    }
    if std::env::var_os("AOS_NO_CREDENTIAL_SYNC")
        .and_then(|v| v.into_string().ok())
        .is_some_and(|s| matches!(s.trim(), "1" | "true" | "TRUE" | "yes"))
    {
        return;
    }
    let creds_parent = runtime_dir.join("credentials");
    if !ensure_0700_dir_no_symlink(&creds_parent) {
        return;
    }
    let cache_dir = agy_runtime_credentials_dir(runtime_dir);
    if !ensure_0700_dir_no_symlink(&cache_dir) {
        return;
    }

    for rel in AGY_AND_GEMINI_OAUTH_STORE_FILES.iter().rev() {
        let Some(fname) = Path::new(rel).file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some((_, obj)) = read_sandbox_json_object_no_symlink(agent_home, rel, false) {
            let _ = write_host_json_0600_no_symlink(&cache_dir, fname, &obj);
        }
    }
    if is_agy_command(command) {
        for rel in AGY_USER_SCOPE_FILES.iter().rev() {
            if let Some(scope) = read_sandbox_scope_id_no_symlink(agent_home, rel) {
                let _ = write_host_bytes_0600_no_symlink(
                    &cache_dir,
                    "credential-user-scope",
                    scope.as_bytes(),
                );
            }
        }
        if let Some((_, onb)) = read_sandbox_json_object_no_symlink(
            agent_home,
            ".gemini/antigravity-cli/cache/onboarding.json",
            false,
        ) {
            let _ = write_host_json_0600_no_symlink(&cache_dir, "onboarding.json", &onb);
        }
    }
}

/// Ensure `agent_home` has `agy` / `gemini` OAuth credentials even after host `agy` sweeps
/// `~/.gemini/antigravity-cli/antigravity-oauth-token` into macOS Keychain.
pub(crate) fn restore_or_seed_agy_oauth_cache(
    runtime_dir: &Path,
    _host_home: &Path,
    agent_home: &Path,
    command: &[String],
) {
    if !is_agy_or_gemini_command(command) {
        return;
    }
    if read_sandbox_json_object_no_symlink(agent_home, AGY_CACHE_TOKEN_PRIMARY, false).is_some() {
        sync_runtime_agy_oauth_from_agent_home(runtime_dir, agent_home, command);
        return;
    }

    for ses_dir in sorted_agy_session_dirs(runtime_dir) {
        let Some(ses_home) = resolve_symlink_free_dir(&ses_dir, Path::new("agent_home")) else {
            continue;
        };
        let Some((_, tok)) =
            read_sandbox_json_object_no_symlink(&ses_home, AGY_CACHE_TOKEN_PRIMARY, false)
        else {
            continue;
        };
        let _ = write_host_json_0600_no_symlink(agent_home, AGY_CACHE_TOKEN_PRIMARY, &tok);
        for rel in AGY_AND_GEMINI_OAUTH_STORE_FILES {
            if *rel != AGY_CACHE_TOKEN_PRIMARY
                && read_sandbox_json_object_no_symlink(agent_home, rel, false).is_none()
            {
                if let Some((_, obj)) = read_sandbox_json_object_no_symlink(&ses_home, rel, false) {
                    let _ = write_host_json_0600_no_symlink(agent_home, rel, &obj);
                }
            }
        }
        if is_agy_command(command) {
            for rel in AGY_USER_SCOPE_FILES {
                if read_sandbox_scope_id_no_symlink(agent_home, rel).is_none() {
                    if let Some(scope) = read_sandbox_scope_id_no_symlink(&ses_home, rel) {
                        let _ =
                            write_host_bytes_0600_no_symlink(agent_home, rel, scope.as_bytes());
                    }
                }
            }
            let onb_rel = ".gemini/antigravity-cli/cache/onboarding.json";
            if read_sandbox_json_object_no_symlink(agent_home, onb_rel, false).is_none() {
                if let Some((_, onb)) =
                    read_sandbox_json_object_no_symlink(&ses_home, onb_rel, false)
                {
                    let _ = write_host_json_0600_no_symlink(agent_home, onb_rel, &onb);
                }
            }
        }
        sync_runtime_agy_oauth_from_agent_home(runtime_dir, agent_home, command);
        return;
    }

    let cache_dir = agy_runtime_credentials_dir(runtime_dir);
    if !std::fs::symlink_metadata(&cache_dir)
        .is_ok_and(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
    {
        return;
    }
    let Some((_, tok)) =
        read_sandbox_json_object_no_symlink(&cache_dir, "antigravity-oauth-token", false)
    else {
        return;
    };
    let _ = write_host_json_0600_no_symlink(agent_home, AGY_CACHE_TOKEN_PRIMARY, &tok);
    if let Some((_, oauth_creds)) =
        read_sandbox_json_object_no_symlink(&cache_dir, "oauth_creds.json", false)
    {
        for rel in [
            ".gemini/oauth_creds.json",
            ".gemini/antigravity-cli/oauth_creds.json",
        ] {
            if read_sandbox_json_object_no_symlink(agent_home, rel, false).is_none() {
                let _ = write_host_json_0600_no_symlink(agent_home, rel, &oauth_creds);
            }
        }
    }
    if let Some((_, jetski)) =
        read_sandbox_json_object_no_symlink(&cache_dir, "jetski-standalone-oauth-token", false)
    {
        let rel = ".gemini/jetski-standalone-oauth-token";
        if read_sandbox_json_object_no_symlink(agent_home, rel, false).is_none() {
            let _ = write_host_json_0600_no_symlink(agent_home, rel, &jetski);
        }
    }
    if is_agy_command(command) {
        if let Some(scope) = read_sandbox_scope_id_no_symlink(&cache_dir, "credential-user-scope") {
            for rel in AGY_USER_SCOPE_FILES {
                if read_sandbox_scope_id_no_symlink(agent_home, rel).is_none() {
                    let _ = write_host_bytes_0600_no_symlink(agent_home, rel, scope.as_bytes());
                }
            }
        }
        let onb_rel = ".gemini/antigravity-cli/cache/onboarding.json";
        if read_sandbox_json_object_no_symlink(agent_home, onb_rel, false).is_none() {
            if let Some((_, onb)) =
                read_sandbox_json_object_no_symlink(&cache_dir, "onboarding.json", false)
            {
                let _ = write_host_json_0600_no_symlink(agent_home, onb_rel, &onb);
            }
        }
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn extract_agy_conversation_id(command: &[String]) -> Option<String> {
    if !is_agy_command(command) {
        return None;
    }
    let mut i = 1;
    while i < command.len() {
        let arg = &command[i];
        if arg == "--" {
            break;
        }
        let raw_id = if let Some(val) = arg.strip_prefix("--conversation=") {
            Some(val)
        } else if arg == "--conversation" {
            i += 1;
            command.get(i).map(String::as_str)
        } else {
            None
        };
        if let Some(id) = raw_id {
            if !id.is_empty()
                && id.len() <= 128
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            {
                return Some(id.to_string());
            }
            return None;
        }
        i += 1;
    }
    None
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn resolve_symlink_free_dir(root: &Path, rel: &Path) -> Option<PathBuf> {
    let root_meta = std::fs::symlink_metadata(root).ok()?;
    if root_meta.file_type().is_symlink() || !root_meta.file_type().is_dir() {
        return None;
    }
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        let std::path::Component::Normal(seg) = comp else {
            return None;
        };
        cur.push(seg);
        let meta = std::fs::symlink_metadata(&cur).ok()?;
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return None;
        }
    }
    Some(cur)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn conversation_candidate_mtime(dir: &Path) -> std::time::SystemTime {
    if let Some(logs_dir) = resolve_symlink_free_dir(dir, Path::new(".system_generated/logs")) {
        let transcript = logs_dir.join("transcript.jsonl");
        if let Ok(meta) = std::fs::symlink_metadata(&transcript) {
            if !meta.file_type().is_symlink() && meta.file_type().is_file() {
                if let Ok(mtime) = meta.modified() {
                    return mtime;
                }
            }
        }
    }
    std::fs::symlink_metadata(dir)
        .and_then(|m| m.modified())
        .unwrap_or(std::time::UNIX_EPOCH)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn copy_conversation_tree_no_symlink(
    src: &Path,
    dst: &Path,
    remaining_bytes: &mut u64,
) -> std::io::Result<()> {
    let src_meta = std::fs::symlink_metadata(src)?;
    if src_meta.file_type().is_symlink() || !src_meta.file_type().is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let entry_path = entry.path();
        let name = entry.file_name();
        let meta = std::fs::symlink_metadata(&entry_path)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.file_type().is_dir() {
            copy_conversation_tree_no_symlink(&entry_path, &dst.join(name), remaining_bytes)?;
        } else if meta.file_type().is_file() {
            let len = meta.len();
            if len > MAX_CONVERSATION_FILE_BYTES || len > *remaining_bytes {
                continue;
            }
            *remaining_bytes -= len;
            std::fs::copy(&entry_path, dst.join(name))?;
        }
    }
    Ok(())
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn agent_home_chain_has_no_symlink(agent_home: &Path, segs: &[&str]) -> bool {
    let mut check = agent_home.to_path_buf();
    for seg in segs {
        check.push(seg);
        if let Ok(meta) = std::fs::symlink_metadata(&check) {
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return false;
            }
        }
    }
    true
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn stage_agy_conversation_db(
    session_dirs: &[PathBuf],
    host_home: &Path,
    agent_home: &Path,
    conv_id: &str,
) {
    use std::os::unix::fs::PermissionsExt;
    let db_dst_dir = agent_home.join(".gemini/antigravity-cli/conversations");
    let primary_db = format!("{conv_id}.db");
    let primary_pb = format!("{conv_id}.pb");
    if db_dst_dir.join(&primary_db).symlink_metadata().is_ok()
        || db_dst_dir.join(&primary_pb).symlink_metadata().is_ok()
    {
        return;
    }
    if !agent_home_chain_has_no_symlink(agent_home, &[".gemini", "antigravity-cli", "conversations"])
    {
        return;
    }

    let mut conv_candidates: Vec<PathBuf> = session_dirs
        .iter()
        .filter_map(|dir| {
            resolve_symlink_free_dir(dir, Path::new("agent_home/.gemini/antigravity-cli/conversations"))
        })
        .collect();
    for host_root in [
        ".gemini/antigravity-cli/conversations",
        ".gemini/antigravity/conversations",
        ".gemini/antigravity-ide/conversations",
    ] {
        if let Some(valid_dir) = resolve_symlink_free_dir(host_home, Path::new(host_root)) {
            conv_candidates.push(valid_dir);
        }
    }

    let valid_regular = |path: &Path| -> Option<std::time::SystemTime> {
        let meta = std::fs::symlink_metadata(path).ok()?;
        if meta.file_type().is_symlink()
            || !meta.file_type().is_file()
            || meta.len() > MAX_CONVERSATION_FILE_BYTES
        {
            return None;
        }
        Some(meta.modified().unwrap_or(std::time::UNIX_EPOCH))
    };

    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for cand in conv_candidates {
        let mtime = valid_regular(&cand.join(&primary_db))
            .or_else(|| valid_regular(&cand.join(&primary_pb)));
        let Some(mtime) = mtime else {
            continue;
        };
        if best.as_ref().is_none_or(|(best_mtime, _)| mtime > *best_mtime) {
            best = Some((mtime, cand));
        }
    }

    let Some((_, src_dir)) = best else {
        return;
    };
    if std::fs::create_dir_all(&db_dst_dir).is_err() {
        return;
    }
    for suffix in [".db", ".db-wal", ".db-shm", ".pb"] {
        let fname = format!("{conv_id}{suffix}");
        let src_file = src_dir.join(&fname);
        if valid_regular(&src_file).is_none() {
            continue;
        }
        let dst_file = db_dst_dir.join(&fname);
        if std::fs::copy(&src_file, &dst_file).is_ok() {
            let _ = std::fs::set_permissions(&dst_file, std::fs::Permissions::from_mode(0o600));
        }
    }
}

/// Stage a requested `agy --conversation=<id>` directory into the session `agent_home`
/// so resuming conversations works across isolated homes on macOS Seatbelt without copying
/// bulk brain histories into unrelated sessions.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn stage_agy_conversation_for_resume(
    runtime_dir: &Path,
    host_home: &Path,
    agent_home: &Path,
    command: &[String],
) {
    let Some(conv_id) = extract_agy_conversation_id(command) else {
        return;
    };
    let session_dirs = sorted_agy_session_dirs(runtime_dir);
    stage_agy_conversation_db(&session_dirs, host_home, agent_home, &conv_id);

    let dst = agent_home.join(".gemini/antigravity-cli/brain").join(&conv_id);
    if dst.symlink_metadata().is_ok() {
        return;
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    let brain_rel = Path::new("agent_home/.gemini/antigravity-cli/brain").join(&conv_id);
    for dir in &session_dirs {
        if let Some(valid_dir) = resolve_symlink_free_dir(dir, &brain_rel) {
            candidates.push(valid_dir);
        }
    }

    for host_root in [
        ".gemini/antigravity-cli/brain",
        ".gemini/antigravity/brain",
        ".gemini/antigravity-ide/brain",
    ] {
        let rel = Path::new(host_root).join(&conv_id);
        if let Some(valid_dir) = resolve_symlink_free_dir(host_home, &rel) {
            candidates.push(valid_dir);
        }
    }

    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for cand in candidates {
        let mtime = conversation_candidate_mtime(&cand);
        if best.as_ref().is_none_or(|(best_mtime, _)| mtime > *best_mtime) {
            best = Some((mtime, cand));
        }
    }

    if let Some((_, src)) = best {
        if !agent_home_chain_has_no_symlink(agent_home, &[".gemini", "antigravity-cli", "brain"]) {
            return;
        }
        let mut remaining = MAX_CONVERSATION_TOTAL_BYTES;
        if let Err(err) = copy_conversation_tree_no_symlink(&src, &dst, &mut remaining) {
            eprintln!(
                "aos run: warning: failed staging agy conversation `{conv_id}` from {}: {err}",
                src.display()
            );
            let _ = std::fs::remove_dir_all(&dst);
        }
    }
}

pub(crate) fn restore_native_oauth_store_for_agent(
    host_home: &Path,
    agent_home: &Path,
    command: &[String],
    harvested_secrets: &std::collections::HashMap<String, String>,
) {
    use std::os::unix::fs::PermissionsExt;
    let write_bytes_0600 = |dst: &Path, bytes: &[u8]| {
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(dst, bytes).is_ok() {
            let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o600));
        }
    };
    let write_0600 = |dst: &Path, obj: &serde_json::Map<String, Value>| {
        if let Ok(bytes) = serde_json::to_vec_pretty(&Value::Object(obj.clone())) {
            write_bytes_0600(dst, &bytes);
        }
    };
    if is_claude_command(command) && !harvested_secrets.contains_key("CLAUDE_CODE_OAUTH_TOKEN") {
        if let Some((_, map)) =
            read_sandbox_json_object_no_symlink(host_home, ".claude/.credentials.json", false)
        {
            write_0600(&agent_home.join(".claude/.credentials.json"), &map);
        }
    }
    if is_codex_command(command) && !harvested_secrets.contains_key("OPENAI_API_KEY") {
        if let Some((_, map)) =
            read_sandbox_json_object_no_symlink(host_home, ".codex/auth.json", false)
        {
            write_0600(&agent_home.join(".codex/auth.json"), &map);
        }
    }
    if is_hermes_command(command) {
        if let Some((_, map)) =
            read_sandbox_json_object_no_symlink(host_home, ".hermes/auth.json", false)
        {
            write_0600(&agent_home.join(".hermes/auth.json"), &map);
        }
    }
    if is_agy_or_gemini_command(command) {
        for rel in AGY_AND_GEMINI_OAUTH_STORE_FILES {
            if let Some((_, map)) = read_sandbox_json_object_no_symlink(host_home, rel, false) {
                write_0600(&agent_home.join(rel), &map);
            }
        }
        for rel_settings in [
            ".gemini/antigravity-cli/settings.json",
            ".gemini/settings.json",
        ] {
            if let Some((_, host_map)) = read_sandbox_json_object_with_limit_no_symlink(
                host_home,
                rel_settings,
                false,
                MAX_SETTINGS_SYNC_BYTES,
            ) {
                if let Some(gcreds) = host_map.get("google_credentials") {
                    if let Some(mut dst_map) = load_or_init_host_json_for_merge(
                        agent_home,
                        rel_settings,
                        MAX_SETTINGS_SYNC_BYTES,
                    ) {
                        let dst = agent_home.join(rel_settings);
                        dst_map.insert("google_credentials".to_string(), gcreds.clone());
                        write_0600(&dst, &dst_map);
                    }
                }
            }
        }
    }
    if is_agy_command(command) {
        for rel in AGY_PLUGIN_SECRET_FILES {
            if let Some((_, map)) = read_sandbox_json_object_no_symlink(host_home, rel, false) {
                write_0600(&agent_home.join(rel), &map);
            }
        }
        for rel in AGY_USER_SCOPE_FILES {
            if let Some(scope) = read_sandbox_scope_id_no_symlink(host_home, rel) {
                write_bytes_0600(&agent_home.join(rel), scope.as_bytes());
            }
        }
    }
    if is_opencode_command(command) {
        if let Some((_, host_map)) = read_sandbox_json_object_no_symlink(
            host_home,
            ".local/share/opencode/auth.json",
            false,
        ) {
            if let Some(mut dst_map) = load_or_init_host_json_for_merge(
                agent_home,
                ".local/share/opencode/auth.json",
                MAX_CREDENTIAL_SYNC_BYTES,
            ) {
                let dst = agent_home.join(".local/share/opencode/auth.json");
                let mut changed = false;
                for (prov, entry) in host_map {
                    let is_oauth = entry
                        .get("type")
                        .and_then(|v| v.as_str())
                        .is_some_and(|t| t != "api");
                    if is_oauth || opencode_provider_secret_spec(&prov).is_none() {
                        dst_map.insert(prov, entry);
                        changed = true;
                    }
                }
                if changed {
                    write_0600(&dst, &dst_map);
                }
            }
        }
    }
}
