use super::*;

pub(crate) fn memory_db_path(db: Option<&Path>) -> PathBuf {
    db.map(Path::to_path_buf).unwrap_or_else(|| {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".uomp").join("memory.db")
    })
}

pub(crate) fn open_memory_store(db: Option<&Path>) -> anyhow::Result<SqliteMemoryStore> {
    let path = memory_db_path(db);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    SqliteMemoryStore::open(&path)
}

pub(crate) fn native_memory_import(path: &Path, tag: &str, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let result = store.import_markdown_dir(path, tag)?;
    println!("Imported {} note(s), skipped {}, errors {}", result.imported, result.skipped, result.errors.len());
    for error in &result.errors {
        eprintln!("  {error}");
    }
    println!("Store: {}", memory_db_path(db).display());
    Ok(())
}

pub(crate) fn native_memory_read(key: &str, json: bool, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let Some(item) = store.get(key)? else {
        anyhow::bail!("memory item '{key}' not found");
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&item.value)?);
    } else if let Some(title) = item.value.get("title").and_then(|value| value.as_str()) {
        println!("{title}");
        if let Some(body) = item.value.get("body").and_then(|value| value.as_str()) {
            println!();
            println!("{body}");
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&item.value)?);
    }
    Ok(())
}

pub(crate) fn native_memory_list(tag: Option<&str>, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let items = match tag {
        Some(tag) => store.get_by_tag(tag)?,
        None => store.all()?,
    };
    if items.is_empty() {
        println!("No memory items.");
        return Ok(());
    }
    for item in items {
        println!(
            "{}  [{}]  {}  {}",
            item.key,
            item.tags.join(", "),
            sensitivity_label(item.sensitivity),
            item.description.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

pub(crate) fn native_memory_search(query: &str, tag: Option<&str>, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let items = match tag {
        Some(tag) => store.get_by_tag(tag)?,
        None => store.all()?,
    };
    let needle = query.to_lowercase();
    let mut found = 0;
    for item in items {
        let haystack = format!(
            "{} {} {} {}",
            item.key,
            item.tags.join(" "),
            item.description.as_deref().unwrap_or(""),
            item.value
        )
        .to_lowercase();
        if haystack.contains(&needle) {
            println!("{}  [{}]", item.key, item.tags.join(", "));
            found += 1;
        }
    }
    if found == 0 {
        println!("No matches.");
    }
    Ok(())
}

pub(crate) fn native_memory_status(db: Option<&Path>) -> anyhow::Result<()> {
    let path = memory_db_path(db);
    println!("Aegis memory");
    println!("  Store  {}", path.display());
    println!("  Exists {}", path.exists());
    if path.exists() {
        let store = open_memory_store(db)?;
        println!("  Items  {}", store.count()?);
        let tags = store.list_tags()?;
        println!("  Tags   {}", if tags.is_empty() { "-".to_string() } else { tags.join(", ") });
    }
    Ok(())
}

pub(crate) fn default_data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".uomp")
}

pub(crate) fn default_secrets_dir() -> PathBuf {
    default_data_dir().join(".secrets")
}

pub(crate) fn default_auth_db_path() -> PathBuf {
    default_data_dir().join("auth.db")
}

pub(crate) fn default_pid_file() -> PathBuf {
    default_data_dir().join("server.pid")
}

pub(crate) fn default_ui_pid_file() -> PathBuf {
    default_data_dir().join("ui.pid")
}

pub(crate) fn default_ui_url_file() -> PathBuf {
    default_secrets_dir().join("ui.url")
}

pub(crate) fn ensure_memory_ui(memory_url: &str) -> anyhow::Result<()> {
    if memory_ui_healthy() {
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    let _ = std::process::Command::new(exe)
        .args(["memory", "ui", "--no-open", "--url", memory_url])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    for _ in 0..20 {
        if memory_ui_healthy() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Ok(())
}

pub(crate) fn memory_ui_healthy() -> bool {
    let Ok(response) = ureq::get("http://127.0.0.1:9375/health").call() else {
        return false;
    };
    response
        .into_json::<serde_json::Value>()
        .map(|value| value["service"] == "aegis-memory-ui")
        .unwrap_or(false)
}

pub(crate) fn load_or_create_secret(path: &Path) -> anyhow::Result<String> {
    if path.exists() {
        return Ok(std::fs::read_to_string(path)?.trim().to_string());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let secret = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    std::fs::write(path, &secret)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(secret)
}

pub(crate) fn read_admin_token(explicit: Option<&str>) -> anyhow::Result<String> {
    if let Some(token) = explicit {
        return Ok(token.to_string());
    }
    let path = default_secrets_dir().join("admin-token");
    Ok(std::fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?
        .trim()
        .to_string())
}

pub(crate) fn http_json_with_headers(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> anyhow::Result<Value> {
    let mut request = ureq::request(method, url);
    for (name, value) in headers {
        request = request.set(name, value);
    }
    let response = match body {
        Some(body) => request.send_json(body),
        None => request.call(),
    };
    match response {
        Ok(response) => Ok(response.into_json::<Value>()?),
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_string().unwrap_or_default();
            anyhow::bail!("HTTP {status}: {body}")
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn http_json(
    method: &str,
    url: &str,
    admin_token: Option<&str>,
    body: Option<Value>,
) -> anyhow::Result<Value> {
    let headers: Vec<(&str, &str)> = admin_token
        .map(|token| vec![("x-uomp-admin-token", token)])
        .unwrap_or_default();
    http_json_with_headers(method, url, &headers, body)
}

pub(crate) fn wait_health(url: &str) -> anyhow::Result<()> {
    for _ in 0..50 {
        if ureq::get(&format!("{url}/health")).call().is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    anyhow::bail!("memory server did not become healthy at {url}")
}

pub(crate) fn ensure_memory_server(listen: &str, no_server: bool) -> anyhow::Result<String> {
    let base_url = format!("http://{listen}");
    if no_server || ureq::get(&format!("{base_url}/health")).call().is_ok() {
        return Ok(base_url);
    }
    let exe = std::env::current_exe()?;
    let child = std::process::Command::new(exe)
        .args(["memory", "serve", "--listen", listen])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| anyhow::anyhow!("failed to start memory server: {error}"))?;
    std::fs::create_dir_all(default_data_dir())?;
    std::fs::write(default_pid_file(), child.id().to_string())?;
    wait_health(&base_url)?;
    Ok(base_url)
}

pub(crate) fn write_mcp_config(
    client: &str,
    config_path: Option<&Path>,
    store_path: &Path,
    env_path: &Path,
    env_key: &str,
) -> anyhow::Result<PathBuf> {
    let public_key = default_secrets_dir().join("ed25519-public.jwk");
    let args = vec![
        "memory".to_string(),
        "mcp".to_string(),
        "--store".to_string(),
        store_path.to_string_lossy().to_string(),
        "--public-key".to_string(),
        public_key.to_string_lossy().to_string(),
    ];
    let env = json!({ env_key: env_path.to_string_lossy() });
    let config_path = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_client_config(client));
    let mut config = if config_path.exists() {
        serde_json::from_str::<Value>(&std::fs::read_to_string(&config_path)?)?
    } else {
        json!({})
    };
    if client == "opencode" {
        let mut command = vec!["aegis-os".to_string()];
        command.extend(args.iter().cloned());
        config["mcp"] = json!({
            "uomp": {
                "type": "local",
                "command": command,
                "environment": env
            }
        });
    } else {
        config["mcpServers"] = config
            .get("mcpServers")
            .cloned()
            .unwrap_or_else(|| json!({}));
        config["mcpServers"]["uomp"] = json!({
            "command": "aegis-os",
            "args": args,
            "env": env
        });
    }
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
    Ok(config_path)
}

pub(crate) fn memory_connect(
    client: &str,
    scope: &[String],
    config_path: Option<&Path>,
    listen: Option<&str>,
    no_server: bool,
) -> anyhow::Result<()> {
    let store_path = memory_db_path(None);
    let listen = listen.unwrap_or("127.0.0.1:9374");
    let base_url = ensure_memory_server(listen, no_server)?;
    let admin_token = load_or_create_secret(&default_secrets_dir().join("admin-token"))?;
    let read_tags: Vec<String> = scope
        .iter()
        .filter(|tag| !tag.trim().is_empty())
        .cloned()
        .collect();
    let scopes = json!({
        "read": { "tags": read_tags, "keys": [], "denyTags": [], "denyKeys": [] },
        "write": { "tags": [], "keys": [], "denyTags": [], "denyKeys": [] }
    });
    let session = http_json(
        "POST",
        &format!("{base_url}/v1/sessions"),
        Some(&admin_token),
        Some(json!({
            "agent_id": client,
            "agent_name": client,
            "requested_scopes": scopes,
            "duration_minutes": 30
        })),
    )?;
    let session_id = session["session_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("session response missing session_id"))?
        .to_string();
    let grant = http_json(
        "POST",
        &format!("{base_url}/v1/sessions/{session_id}/grant"),
        Some(&admin_token),
        Some(json!({ "granted_scopes": scopes })),
    )?;
    let token = grant["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("grant response missing token"))?;

    let env_path = default_data_dir()
        .join("sessions")
        .join(format!("{client}.env"));
    std::fs::create_dir_all(env_path.parent().unwrap_or(Path::new(".")))?;
    std::fs::write(
        &env_path,
        format!(
            "UOMP_TOKEN={token}\nUOMP_BASE_URL={base_url}\nUOMP_SESSION_ID={session_id}\nUOMP_STORE={}\nUOMP_PUBLIC_KEY={}\n",
            store_path.display(),
            default_secrets_dir().join("ed25519-public.jwk").display()
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600));
    }
    let config_path = write_mcp_config(client, config_path, &store_path, &env_path, "UOMP_TOKEN_FILE")?;

    println!("UOMP is connected for {client} (pre-authorized).");
    println!("  Server  {base_url}");
    println!("  Env     {}", env_path.display());
    println!("  Config  {}", config_path.display());
    println!("  Store   {}", store_path.display());
    Ok(())
}

pub(crate) fn memory_setup(
    client: &str,
    vault: Option<&Path>,
    tag: &str,
    config_path: Option<&Path>,
    listen: Option<&str>,
    no_server: bool,
) -> anyhow::Result<()> {
    let store_path = memory_db_path(None);
    if let Some(vault) = vault {
        let store = open_memory_store(None)?;
        let result = store.import_markdown_dir(vault, tag)?;
        println!("Imported {} note(s), skipped {}, errors {}", result.imported, result.skipped, result.errors.len());
    }

    let listen = listen.unwrap_or("127.0.0.1:9374");
    let base_url = ensure_memory_server(listen, no_server)?;

    let bridge_token = load_or_create_secret(&default_secrets_dir().join("bridge-token"))?;
    let env_path = default_data_dir().join("sessions").join(format!("{client}.env"));
    std::fs::create_dir_all(env_path.parent().unwrap_or(Path::new(".")))?;
    std::fs::write(
        &env_path,
        format!(
            "UOMP_BRIDGE_URL={base_url}\nUOMP_BRIDGE_TOKEN={bridge_token}\nUOMP_AGENT_ID={client}\nUOMP_STORE={}\nUOMP_PUBLIC_KEY={}\n",
            store_path.display(),
            default_secrets_dir().join("ed25519-public.jwk").display()
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600));
    }

    let config_path = write_mcp_config(
        client,
        config_path,
        &store_path,
        &env_path,
        "UOMP_BRIDGE_FILE",
    )?;

    println!("UOMP is set up for {client}.");
    println!("  Server  {base_url}");
    println!("  Env     {}", env_path.display());
    println!("  Config  {}", config_path.display());
    println!("  Store   {}", store_path.display());
    Ok(())
}

pub(crate) fn default_client_config(client: &str) -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    match client {
        "cursor" => home.join(".cursor").join("mcp.json"),
        "opencode" => home.join(".config").join("opencode").join("opencode.json"),
        _ => {
            #[cfg(target_os = "macos")]
            {
                home.join("Library").join("Application Support").join("Claude").join("claude_desktop_config.json")
            }
            #[cfg(not(target_os = "macos"))]
            {
                home.join(".config").join("Claude").join("claude_desktop_config.json")
            }
        }
    }
}

pub(crate) fn memory_sessions(
    url: &str,
    admin_token: Option<&str>,
    task_id: Option<&str>,
) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json("GET", &format!("{url}/v1/sessions"), Some(&token), None)?;
    let response = if let Some(task_id) = task_id {
        let sessions: Vec<Value> = response["sessions"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|session| session["task_id"].as_str() == Some(task_id))
            .collect();
        json!({ "sessions": sessions })
    } else {
        response
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub(crate) async fn memory_revoke(
    id: &str,
    url: &str,
    admin_token: Option<&str>,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json(
        "POST",
        &format!("{url}/v1/sessions/{id}/revoke"),
        Some(&token),
        Some(json!({})),
    )?;
    if let Some(task_id) = response["task_id"].as_str() {
        let bus = AegisIpcBus::with_state_file(Some(runtime_dir.join("ipc_state.json")));
        let _ = bus
            .request_task_input(task_id, "memory session revoked")
            .await;
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub(crate) fn memory_audit(url: &str, admin_token: Option<&str>, limit: usize) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json(
        "GET",
        &format!("{url}/v1/audit?limit={limit}"),
        Some(&token),
        None,
    )?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub(crate) fn memory_disconnect(client: &str, config_path: Option<&Path>) -> anyhow::Result<()> {
    let env_path = default_data_dir().join("sessions").join(format!("{client}.env"));
    if env_path.exists() {
        let contents = std::fs::read_to_string(&env_path)?;
        let session_id = contents.lines().find_map(|line| line.strip_prefix("UOMP_SESSION_ID="));
        let base_url = contents
            .lines()
            .find_map(|line| line.strip_prefix("UOMP_BASE_URL="))
            .unwrap_or("http://127.0.0.1:9374");
        if let Some(session_id) = session_id {
            let token = read_admin_token(None)?;
            let _ = http_json(
                "POST",
                &format!("{base_url}/v1/sessions/{session_id}/revoke"),
                Some(&token),
                Some(serde_json::json!({})),
            );
        }
        std::fs::remove_file(&env_path)?;
    }

    let config_path = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_client_config(client));
    if config_path.exists() {
        let mut config: Value = serde_json::from_str(&std::fs::read_to_string(&config_path)?)?;
        if client == "opencode" {
            if let Some(mcp) = config.get_mut("mcp").and_then(|value| value.as_object_mut()) {
                mcp.remove("uomp");
            }
        } else if let Some(servers) = config.get_mut("mcpServers").and_then(|value| value.as_object_mut()) {
            servers.remove("uomp");
        }
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
    }
    println!("Disconnected {client}.");
    Ok(())
}

pub(crate) fn memory_pending(url: &str, admin_token: Option<&str>) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json("GET", &format!("{url}/v1/consent/requests?status=pending"), Some(&token), None)?;
    let requests = response["requests"].as_array().cloned().unwrap_or_default();
    if requests.is_empty() {
        println!("No pending consent requests.");
        return Ok(());
    }
    for request in requests {
        println!(
            "{}  {}  {}  {}  {}",
            request["request_id"].as_str().unwrap_or("-"),
            request["agent_id"].as_str().unwrap_or("-"),
            request["task_id"].as_str().unwrap_or("-"),
            request["session_id"].as_str().unwrap_or("-"),
            request["expires_at"].as_str().unwrap_or("-")
        );
    }
    Ok(())
}

pub(crate) fn memory_approve(id: &str, url: &str, admin_token: Option<&str>) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json(
        "POST",
        &format!("{url}/v1/consent/requests/{id}/approve"),
        Some(&token),
        Some(serde_json::json!({})),
    )?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub(crate) fn memory_deny(id: &str, url: &str, admin_token: Option<&str>) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json(
        "POST",
        &format!("{url}/v1/consent/requests/{id}/deny"),
        Some(&token),
        Some(serde_json::json!({})),
    )?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub(crate) fn memory_stop(pid_file: Option<&Path>) -> anyhow::Result<()> {
    let pid_file = pid_file.map(Path::to_path_buf).unwrap_or_else(default_pid_file);
    let pid = std::fs::read_to_string(&pid_file)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", pid_file.display()))?;
    let status = std::process::Command::new("kill")
        .arg(pid.trim())
        .status()
        .map_err(|error| anyhow::anyhow!("failed to stop memory server: {error}"))?;
    if !status.success() {
        anyhow::bail!("failed to stop memory server pid {}", pid.trim());
    }
    let _ = std::fs::remove_file(&pid_file);
    let ui_pid_file = default_ui_pid_file();
    if let Ok(ui_pid) = std::fs::read_to_string(&ui_pid_file) {
        let _ = std::process::Command::new("kill").arg(ui_pid.trim()).status();
        let _ = std::fs::remove_file(&ui_pid_file);
    }
    let _ = std::fs::remove_file(default_ui_url_file());
    println!("Stopped memory server.");
    Ok(())
}

pub(crate) struct BridgeSettings {
    url: String,
    token: String,
    agent_id: String,
    task_id: Option<String>,
    store: Option<PathBuf>,
    public_key: Option<PathBuf>,
}

pub(crate) struct McpAuth {
    bridge: Option<BridgeSettings>,
    base_url: Option<String>,
    jwk: String,
    token: Option<String>,
    claims: Option<RemoteTokenClaims>,
}

pub(crate) fn parse_env_file(path: &Path) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
    Ok(contents
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect())
}

pub(crate) fn bridge_settings() -> anyhow::Result<Option<BridgeSettings>> {
    let from_file = std::env::var_os("UOMP_BRIDGE_FILE").map(PathBuf::from);
    if let Some(path) = from_file {
        let env = parse_env_file(&path)?;
        let url = env
            .get("UOMP_BRIDGE_URL")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{} is missing UOMP_BRIDGE_URL", path.display()))?;
        let token = env
            .get("UOMP_BRIDGE_TOKEN")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{} is missing UOMP_BRIDGE_TOKEN", path.display()))?;
        return Ok(Some(BridgeSettings {
            url,
            token,
            agent_id: env
                .get("UOMP_AGENT_ID")
                .cloned()
                .unwrap_or_else(|| "agent".to_string()),
            task_id: std::env::var("UOMP_TASK_ID")
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| env.get("UOMP_TASK_ID").cloned()),
            store: env.get("UOMP_STORE").map(PathBuf::from),
            public_key: env.get("UOMP_PUBLIC_KEY").map(PathBuf::from),
        }));
    }

    if let (Ok(url), Ok(token)) = (
        std::env::var("UOMP_BRIDGE_URL"),
        std::env::var("UOMP_BRIDGE_TOKEN"),
    ) {
        return Ok(Some(BridgeSettings {
            url,
            token,
            agent_id: std::env::var("UOMP_AGENT_ID").unwrap_or_else(|_| "agent".to_string()),
            task_id: std::env::var("UOMP_TASK_ID")
                .ok()
                .filter(|value| !value.is_empty()),
            store: std::env::var_os("UOMP_STORE").map(PathBuf::from),
            public_key: std::env::var_os("UOMP_PUBLIC_KEY").map(PathBuf::from),
        }));
    }
    Ok(None)
}

pub(crate) fn verify_mcp_token(token: &str, jwk: &str) -> anyhow::Result<RemoteTokenClaims> {
    let config = GatewayConfig::from_jwk(
        RemoteProfile {
            gateway_id: "local-mcp".to_string(),
            audience: "local".to_string(),
            allowed_endpoints: vec![],
            max_token_ttl_secs: 86_400,
        },
        jwk,
    )?;
    Ok(verify_token(token, &config)?)
}

pub(crate) fn scopes_for_tool(name: &str, args: &Value) -> Option<MemoryScopes> {
    let mut read = MemoryScope::default();
    match name {
        "list_memory" | "search_memory" => {
            let tag = args.get("tag").and_then(|value| value.as_str())?;
            if tag.is_empty() {
                return None;
            }
            read.tags.push(tag.to_string());
        }
        "read_memory" => {
            let key = args.get("key").and_then(|value| value.as_str())?;
            if key.is_empty() {
                return None;
            }
            read.keys.push(key.to_string());
        }
        _ => return None,
    }
    Some(MemoryScopes {
        read,
        write: MemoryScope::default(),
    })
}

pub(crate) fn token_covers(granted: &MemoryScopes, requested: &MemoryScopes) -> bool {
    let tags_cover = requested.read.tags.iter().all(|tag| {
        granted
            .read
            .tags
            .iter()
            .any(|allowed| tag == allowed || tag.starts_with(allowed))
    });
    let keys_cover = requested.read.keys.iter().all(|key| {
        granted.read.keys.iter().any(|allowed| allowed == key) || !granted.read.tags.is_empty()
    });
    tags_cover && keys_cover
}

pub(crate) fn request_bridge_consent(
    bridge: &BridgeSettings,
    scopes: &MemoryScopes,
) -> anyhow::Result<String> {
    let body = json!({
        "agent_id": bridge.agent_id,
        "agent_name": bridge.agent_id,
        "task_id": bridge.task_id,
        "requested_scopes": scopes,
        "duration_minutes": 30
    });
    let response = http_json_with_headers(
        "POST",
        &format!("{}/v1/consent/requests", bridge.url),
        &[("x-uomp-bridge-token", bridge.token.as_str())],
        Some(body),
    )?;
    let request_id = response["request_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("consent response missing request_id"))?
        .to_string();
    eprintln!("Aegis memory: consent required for {}", bridge.agent_id);
    eprintln!("  Approve in the local consent UI (opened automatically)");
    eprintln!("  Or run: aegis-os memory approve {request_id}");
    eprintln!("  Review with:  aegis-os memory pending");

    for _ in 0..120 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let status = http_json_with_headers(
            "GET",
            &format!("{}/v1/consent/requests/{request_id}/status", bridge.url),
            &[("x-uomp-bridge-token", bridge.token.as_str())],
            None,
        )?;
        match status["status"].as_str() {
            Some("approved") => {
                if let Some(token) = status["token"].as_str() {
                    return Ok(token.to_string());
                }
                anyhow::bail!("consent {request_id} was approved but no token was issued");
            }
            Some("denied") => anyhow::bail!("consent {request_id} was denied"),
            Some("expired") => anyhow::bail!("consent {request_id} expired"),
            _ => {}
        }
    }
    anyhow::bail!("timed out waiting for consent {request_id}")
}

pub(crate) fn ensure_mcp_claims(
    auth: &mut McpAuth,
    requested: Option<&MemoryScopes>,
) -> anyhow::Result<RemoteTokenClaims> {
    if let (Some(_token), Some(claims)) = (&auth.token, &auth.claims) {
        let fresh = claims.expires_at_ms > chrono::Utc::now().timestamp_millis() + 5_000;
        let covers = requested
            .map(|requested| token_covers(&claims.scopes, requested))
            .unwrap_or(true);
        if fresh && covers {
            return Ok(claims.clone());
        }
    }

    let bridge = auth
        .bridge
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no memory token and no bridge configured"))?;
    let scopes = requested
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("cannot request consent without a memory scope"))?;
    let token = request_bridge_consent(bridge, &scopes)?;
    let claims = verify_mcp_token(&token, &auth.jwk)?;
    auth.token = Some(token);
    auth.claims = Some(claims.clone());
    Ok(claims)
}

pub(crate) fn audit_target(name: &str, args: &Value) -> (&'static str, String) {
    match name {
        "read_memory" => (
            "read",
            format!(
                "memory:key:{}",
                args.get("key").and_then(|value| value.as_str()).unwrap_or("")
            ),
        ),
        "list_memory" | "search_memory" => (
            "read",
            format!(
                "memory:tag:{}",
                args.get("tag").and_then(|value| value.as_str()).unwrap_or("")
            ),
        ),
        other => ("access", format!("tool:{other}")),
    }
}

pub(crate) fn log_mcp_audit(auth: &McpAuth, action: &str, resource: &str, decision: &str, reason: &str) {
    let (Some(base_url), Some(token)) = (auth.base_url.as_deref(), auth.token.as_deref()) else {
        return;
    };
    let body = json!({
        "action": action,
        "resource": resource,
        "decision": decision,
        "reason": reason
    });
    let authorization = format!("Bearer {token}");
    let _ = http_json_with_headers(
        "POST",
        &format!("{base_url}/v1/audit"),
        &[("authorization", authorization.as_str())],
        Some(body),
    );
}

pub(crate) fn run_memory_mcp(
    store_path: Option<&Path>,
    public_key_path: Option<&Path>,
    token: Option<String>,
) -> anyhow::Result<()> {
    use std::io::{BufRead, Write};

    let bridge = bridge_settings()?;
    if let Some(bridge) = &bridge {
        let _ = ensure_memory_ui(&bridge.url);
    }
    let token_file = std::env::var_os("UOMP_TOKEN_FILE").map(PathBuf::from);
    let token_file_env = token_file
        .as_ref()
        .and_then(|path| parse_env_file(path).ok());
    let base_url = bridge
        .as_ref()
        .map(|bridge| bridge.url.clone())
        .or_else(|| std::env::var("UOMP_BASE_URL").ok())
        .or_else(|| {
            token_file_env
                .as_ref()
                .and_then(|env| env.get("UOMP_BASE_URL").cloned())
        });
    let store_path = store_path
        .map(Path::to_path_buf)
        .or_else(|| bridge.as_ref().and_then(|bridge| bridge.store.clone()));
    let key_path = public_key_path
        .map(Path::to_path_buf)
        .or_else(|| bridge.as_ref().and_then(|bridge| bridge.public_key.clone()))
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            home.join(".uomp").join(".secrets").join("ed25519-public.jwk")
        });
    let jwk = std::fs::read_to_string(&key_path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", key_path.display()))?;

    let static_token = token
        .or_else(|| std::env::var("UOMP_TOKEN").ok())
        .or_else(|| {
            token_file_env
                .as_ref()
                .and_then(|env| env.get("UOMP_TOKEN").cloned())
        });
    let claims = match &static_token {
        Some(token) => Some(verify_mcp_token(token, &jwk)?),
        None => None,
    };
    if static_token.is_none() && bridge.is_none() {
        anyhow::bail!(
            "set UOMP_BRIDGE_FILE (recommended), UOMP_TOKEN, UOMP_TOKEN_FILE, or pass --token"
        );
    }

    let mut auth = McpAuth {
        bridge,
        base_url,
        jwk,
        token: static_token,
        claims,
    };
    let store = open_memory_store(store_path.as_deref())?;

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": error.to_string() }
                });
                writeln!(stdout, "{response}")?;
                stdout.flush()?;
                continue;
            }
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(|value| value.as_str()).unwrap_or("");
        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": { "name": "aegis-memory", "version": env!("CARGO_PKG_VERSION") },
                    "capabilities": { "tools": {} }
                }
            }),
            "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
            "tools/list" => json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": memory_mcp_tools() } }),
            "tools/call" => {
                let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
                let name = params.get("name").and_then(|value| value.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                let requested = scopes_for_tool(name, &args);
                let result = ensure_mcp_claims(&mut auth, requested.as_ref()).and_then(|claims| {
                    match memory_mcp_call(&store, &claims, &params) {
                        Ok(value) => Ok(value),
                        Err(error) if error.to_string().contains("ACCESS_DENIED") => {
                            let Some(scopes) = scopes_for_tool(name, &args) else {
                                return Err(error);
                            };
                            // A tag session may not cover a high-sensitivity key. Ask for a
                            // fresh key-scoped consent instead of retrying the same token.
                            if auth.bridge.is_none() {
                                return Err(error);
                            }
                            auth.token = None;
                            auth.claims = None;
                            let claims = ensure_mcp_claims(&mut auth, Some(&scopes))?;
                            memory_mcp_call(&store, &claims, &params)
                        }
                        Err(error) => Err(error),
                    }
                });
                let (action, resource) = audit_target(name, &args);
                match &result {
                    Ok(_) => log_mcp_audit(&auth, action, &resource, "allow", "tool call allowed"),
                    Err(error) => {
                        log_mcp_audit(&auth, action, &resource, "deny", &error.to_string())
                    }
                }
                match result {
                    Ok(value) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "content": [{ "type": "text", "text": value.to_string() }] }
                    }),
                    Err(error) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "isError": true,
                            "content": [{ "type": "text", "text": error.to_string() }]
                        }
                    }),
                }
            }
            other => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("Method not found: {other}") }
            }),
        };
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
    Ok(())
}

pub(crate) fn memory_mcp_tools() -> Value {
    json!([
        {
            "name": "list_memory",
            "description": "List memory items under a tag.",
            "inputSchema": {
                "type": "object",
                "properties": { "tag": { "type": "string" } },
                "required": ["tag"]
            }
        },
        {
            "name": "search_memory",
            "description": "Search memory items under a tag.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tag": { "type": "string" },
                    "query": { "type": "string" }
                },
                "required": ["tag", "query"]
            }
        },
        {
            "name": "read_memory",
            "description": "Read one memory item by key.",
            "inputSchema": {
                "type": "object",
                "properties": { "key": { "type": "string" } },
                "required": ["key"]
            }
        }
    ])
}

pub(crate) fn memory_mcp_call(
    store: &SqliteMemoryStore,
    claims: &aos_memory::RemoteTokenClaims,
    params: &Value,
) -> anyhow::Result<Value> {
    let name = params.get("name").and_then(|value| value.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
    match name {
        "list_memory" => {
            let tag = args.get("tag").and_then(|value| value.as_str()).unwrap_or("");
            if tag.is_empty() {
                anyhow::bail!("tag is required");
            }
            let items = store.get_by_tag(tag)?;
            let visible: Vec<Value> = items
                .into_iter()
                .filter(|item| mcp_item_allowed(&claims.scopes.read, item))
                .map(|item| json!({
                    "key": item.key,
                    "tags": item.tags,
                    "sensitivity": sensitivity_label(item.sensitivity),
                    "description": item.description
                }))
                .collect();
            Ok(json!({ "items": visible }))
        }
        "search_memory" => {
            let tag = args.get("tag").and_then(|value| value.as_str()).unwrap_or("");
            let query = args.get("query").and_then(|value| value.as_str()).unwrap_or("");
            if tag.is_empty() || query.is_empty() {
                anyhow::bail!("tag and query are required");
            }
            let needle = query.to_lowercase();
            let items = store.get_by_tag(tag)?;
            let visible: Vec<Value> = items
                .into_iter()
                .filter(|item| mcp_item_allowed(&claims.scopes.read, item))
                .filter(|item| {
                    format!("{} {} {}", item.key, item.description.as_deref().unwrap_or(""), item.value)
                        .to_lowercase()
                        .contains(&needle)
                })
                .map(|item| json!({
                    "key": item.key,
                    "tags": item.tags,
                    "sensitivity": sensitivity_label(item.sensitivity),
                    "description": item.description
                }))
                .collect();
            Ok(json!({ "items": visible }))
        }
        "read_memory" => {
            let key = args.get("key").and_then(|value| value.as_str()).unwrap_or("");
            if key.is_empty() {
                anyhow::bail!("key is required");
            }
            let Some(item) = store.get(key)? else {
                anyhow::bail!("memory item '{key}' not found");
            };
            if !mcp_item_allowed(&claims.scopes.read, &item) {
                anyhow::bail!("ACCESS_DENIED: key is outside the token scope");
            }
            Ok(json!({
                "key": item.key,
                "value": item.value,
                "tags": item.tags,
                "sensitivity": sensitivity_label(item.sensitivity),
                "description": item.description
            }))
        }
        other => anyhow::bail!("unknown memory tool '{other}'"),
    }
}

pub(crate) fn mcp_item_allowed(scope: &aos_memory::MemoryScope, item: &aos_memory_store::MemoryItem) -> bool {
    if scope.deny_keys.iter().any(|key| key == &item.key) {
        return false;
    }
    if item
        .tags
        .iter()
        .any(|tag| scope.deny_tags.iter().any(|denied| denied == tag))
    {
        return false;
    }
    if scope.keys.iter().any(|key| key == &item.key) {
        return true;
    }
    if item.sensitivity == aos_memory::Sensitivity::High {
        return false;
    }
    item.tags.iter().any(|tag| scope.tags.iter().any(|granted| granted == tag))
}

pub(crate) fn native_memory_payload_list(db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let payloads = store.list_payloads()?;
    if payloads.is_empty() {
        println!("No payloads.");
        return Ok(());
    }
    for payload in payloads {
        println!(
            "{}  {}  {} bytes  agent={}  session={}",
            payload.payload_id,
            payload.format.as_deref().unwrap_or("-"),
            payload.size.unwrap_or(0),
            payload.agent_id,
            payload.session_id
        );
    }
    Ok(())
}

pub(crate) fn native_memory_payload_get(id: &str, output: Option<&Path>, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let Some(envelope) = store.get_payload(id)? else {
        anyhow::bail!("payload '{id}' not found");
    };
    let json = serde_json::to_string_pretty(&envelope)?;
    if let Some(output) = output {
        std::fs::write(output, format!("{json}\n"))?;
        println!("Wrote {id} to {}", output.display());
    } else {
        println!("{json}");
    }
    Ok(())
}

pub(crate) fn native_memory_payload_delete(id: &str, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    if store.delete_payload(id)? {
        println!("Deleted payload {id}.");
        Ok(())
    } else {
        anyhow::bail!("payload '{id}' not found")
    }
}

pub(crate) fn native_memory_staged_list(status: Option<&str>, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let writes = store.list_staged_writes(status)?;
    if writes.is_empty() {
        println!("No staged writes.");
        return Ok(());
    }
    for write in writes {
        println!(
            "{}  {}  [{}]  {}  {}  {}",
            write.id,
            write.key,
            write.tags.join(", "),
            sensitivity_label(write.sensitivity),
            write.status,
            write.agent_id
        );
    }
    Ok(())
}

pub(crate) fn native_memory_staged_approve(id: &str, reviewed_by: &str, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    match store.approve_staged_write(id, reviewed_by)? {
        Some(item) => {
            println!("Approved {} -> {}", id, item.key);
            Ok(())
        }
        None => anyhow::bail!("staged write '{id}' not found or not pending"),
    }
}

pub(crate) fn native_memory_staged_deny(id: &str, reviewed_by: &str, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    match store.deny_staged_write(id, reviewed_by)? {
        Some(write) => {
            println!("Denied {} -> {}", id, write.key);
            Ok(())
        }
        None => anyhow::bail!("staged write '{id}' not found or not pending"),
    }
}

pub(crate) fn sensitivity_label(value: aos_memory::Sensitivity) -> &'static str {
    match value {
        aos_memory::Sensitivity::Low => "low",
        aos_memory::Sensitivity::Medium => "medium",
        aos_memory::Sensitivity::High => "high",
    }
}
