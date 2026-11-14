//! Per-client-session identity resolution shared by hook processes and the MCP server.
//!
//! Problem: with `--agent auto`, every `agy` window used to resolve to the same constant principal
//! (`agy-agent`). Two sessions in the same repository therefore shared one mailbox and one CoW shadow,
//! and topic broadcasts (which exclude the sender) reached nobody.
//!
//! Solution: both the MCP server (`aegis-os mcp-stdio`, spawned directly by the client) and lifecycle
//! hooks (`sh -c "aegis-os agy-hook ..."`, spawned by the same client) walk their parent chain, skip
//! shells/wrappers, and arrive at the same client process. Its `(pid, start_time)` is the [`SessionKey`].
//! Hooks additionally bind the client's `conversationId` to the derived agent id so that a resumed
//! conversation (new client process) keeps its previous principal.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Stable key for "this agent client process". `start_time` defeats PID reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionKey {
    pub pid: u32,
    pub start_time: u64,
}

impl SessionKey {
    pub fn file_stem(&self) -> String {
        format!("{}-{}", self.pid, self.start_time)
    }
}

/// Minimal process table entry used for ancestry walks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub start_time: u64,
}

/// Process names that are never "the client": shells, launch wrappers, and Aegis itself.
pub const WRAPPER_COMMS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "env",
    "timeout",
    "nice",
    "nohup",
    "login",
    "sandbox-exec",
    "aegis-os",
];

fn is_wrapper(comm: &str) -> bool {
    let base = comm.rsplit('/').next().unwrap_or(comm).trim_start_matches('-');
    WRAPPER_COMMS.contains(&base)
}

/// Walks up from `start_pid` (inclusive) and returns the first non-wrapper process.
/// Pure function over a `lookup` so it can be unit-tested without a real process table.
pub fn find_client_ancestor(
    start_pid: u32,
    lookup: impl Fn(u32) -> Option<ProcInfo>,
) -> Option<ProcInfo> {
    let mut pid = start_pid;
    for _ in 0..32 {
        if pid <= 1 {
            return None;
        }
        let info = lookup(pid)?;
        if !is_wrapper(&info.comm) {
            return Some(info);
        }
        if info.ppid == pid {
            return None;
        }
        pid = info.ppid;
    }
    None
}

#[cfg(target_os = "macos")]
pub fn proc_info(pid: u32) -> Option<ProcInfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if n != size {
        return None;
    }
    let comm_bytes: Vec<u8> = info
        .pbi_comm
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    Some(ProcInfo {
        pid,
        ppid: info.pbi_ppid,
        comm: String::from_utf8_lossy(&comm_bytes).to_string(),
        start_time: info.pbi_start_tvsec,
    })
}

#[cfg(target_os = "linux")]
pub fn proc_info(pid: u32) -> Option<ProcInfo> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Format: pid (comm) state ppid ... field 22 = starttime. `comm` may contain spaces/parens.
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat[open + 1..close].to_string();
    let rest: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    let ppid = rest.get(1)?.parse().ok()?;
    let start_time = rest.get(19)?.parse().ok()?;
    Some(ProcInfo {
        pid,
        ppid,
        comm,
        start_time,
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn proc_info(_pid: u32) -> Option<ProcInfo> {
    None
}

/// Session key of the client process that (transitively) launched the current process.
pub fn client_session_key() -> Option<SessionKey> {
    let ppid = std::os::unix::process::parent_id();
    find_client_ancestor(ppid, proc_info).map(|p| SessionKey {
        pid: p.pid,
        start_time: p.start_time,
    })
}

/// Checks whether a client process `pid` (and optional `expected_start_time` to guard against PID
/// reuse) is still alive in the OS process table. Used to auto-prune zombie peers when a client
/// window is closed.
pub fn is_pid_alive(pid: u32, expected_start_time: Option<u64>) -> bool {
    if pid <= 1 {
        return false;
    }
    match proc_info(pid) {
        Some(info) => expected_start_time.is_none_or(|st| st == 0 || info.start_time == st),
        None => false,
    }
}

/// `agy` -> `agy`, `claude` -> `claude`, `codex` -> `codex`, anything else verbatim.
pub fn client_prefix(client: &str) -> &str {
    match client {
        "" => "agent",
        other => other,
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Deterministic, human-readable principal for a client session, e.g. `agy-3f2a9c`.
pub fn derive_agent_id(client: &str, key: &SessionKey) -> String {
    let h = fnv1a64(format!("{}:{}:{}", client, key.pid, key.start_time).as_bytes());
    format!("{}-{:06x}", client_prefix(client), h & 0xff_ffff)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBinding {
    pub client: String,
    pub agent_id: String,
    pub key: SessionKey,
    #[serde(default)]
    pub conversation_id: Option<String>,
    pub bound_at_ms: i64,
}

fn sessions_dir(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("sessions")
}

fn by_key_path(runtime_dir: &Path, key: &SessionKey) -> PathBuf {
    sessions_dir(runtime_dir)
        .join("by-key")
        .join(format!("{}.json", key.file_stem()))
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(128)
        .collect()
}

fn by_conversation_path(runtime_dir: &Path, conversation_id: &str) -> PathBuf {
    sessions_dir(runtime_dir)
        .join("by-conversation")
        .join(format!("{}.json", sanitize(conversation_id)))
}

fn read_binding(path: &Path) -> Option<SessionBinding> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_bytes_atomic_with_mode(
    path: &Path,
    bytes: &[u8],
    mode_override: Option<u32>,
) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    #[cfg(unix)]
    let preserved_mode = if mode_override.is_none() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o7777)
    } else {
        None
    };

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("file");
    let tmp = path.with_file_name(format!(
        ".{}.aegis-tmp-{}-{}",
        file_name,
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));

    let write_res = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        #[cfg(unix)]
        if let Some(mode) = mode_override.or(preserved_mode) {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        f.sync_all()?;
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }

    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let dir_path = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(dir) = std::fs::File::open(dir_path) {
            if let Err(err) = dir.sync_all() {
                if !matches!(
                    err.raw_os_error(),
                    Some(libc::EINVAL) | Some(libc::EPERM) | Some(libc::EROFS)
                ) && err.kind() != std::io::ErrorKind::Unsupported
                {
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}

/// Atomically writes `bytes` to `path` via a sibling temporary file, calling `sync_all()`
/// on the temporary file before renaming and syncing the parent directory afterwards.
/// Preserves existing file mode bits on Unix when overwriting an existing file.
pub fn write_bytes_atomic_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_bytes_atomic_with_mode(path, bytes, None)
}

/// Async variant of [`write_bytes_atomic_synced`].
pub async fn write_bytes_atomic_synced_async(path: &Path, bytes: Vec<u8>) -> anyhow::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || write_bytes_atomic_synced(&path, &bytes)).await??;
    Ok(())
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).unwrap_or_default();
    write_bytes_atomic_with_mode(path, &bytes, Some(0o600))
}

/// Acquires an exclusive cross-process `flock` synchronously for a persisted JSON state file (`<path>.lock`).
pub fn acquire_file_lock_sync(path: &Path) -> anyhow::Result<std::fs::File> {
    let lock_path = path.with_extension("lock");
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(15));
                continue;
            }
            anyhow::bail!(
                "timed out waiting for state lock '{}': {}",
                lock_path.display(),
                error
            );
        }
    }
    Ok(file)
}

/// Acquires an exclusive cross-process `flock` for a persisted JSON state file (`<path>.lock`).
pub async fn acquire_file_lock(path: &Path) -> anyhow::Result<std::fs::File> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || acquire_file_lock_sync(&path)).await?
}

/// Synchronously writes `value` as pretty-printed JSON (owner-only `0o600` on Unix) to a unique
/// sibling temporary file, fsyncs it, and atomically renames it onto `path` when the caller ALREADY
/// holds `acquire_file_lock_sync(path)`.
pub fn write_json_pretty_unlocked_sync<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_bytes_atomic_with_mode(path, &bytes, Some(0o600))?;
    Ok(())
}

/// Synchronously writes `value` as pretty-printed JSON (owner-only `0o600` on Unix) to a unique
/// sibling temporary file and atomically renames it onto `path` while holding a cross-process file lock.
pub fn write_json_pretty_atomic_sync<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let _lock = acquire_file_lock_sync(path)?;
    write_json_pretty_unlocked_sync(path, value)
}

/// Writes `value` as pretty-printed JSON to a unique sibling temporary file, fsyncs it, and
/// atomically renames it onto `path` when the caller ALREADY holds `acquire_file_lock(path)`.
pub async fn write_json_pretty_unlocked<T: Serialize + Sync>(
    path: &Path,
    value: &T,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || write_bytes_atomic_with_mode(&path, &bytes, Some(0o600)))
        .await??;
    Ok(())
}

/// Writes `value` as pretty-printed JSON to a unique sibling temporary file and atomically
/// renames it onto `path` while holding a cross-process file lock.
pub async fn write_json_pretty_atomic<T: Serialize + Sync>(
    path: &Path,
    value: &T,
) -> anyhow::Result<()> {
    let _lock = acquire_file_lock(path).await?;
    write_json_pretty_unlocked(path, value).await
}

/// Resolve the agent id for `key` without side effects: hook-written binding first, else derived.
pub fn resolve_agent_id_for_key(runtime_dir: &Path, client: &str, key: &SessionKey) -> String {
    read_binding(&by_key_path(runtime_dir, key))
        .map(|b| b.agent_id)
        .unwrap_or_else(|| derive_agent_id(client, key))
}

/// Resolution used for `--agent auto` (MCP server and CLI). Returns `None` when no client ancestor
/// can be found (e.g. launched directly from a terminal), in which case callers keep their legacy id.
pub fn resolve_session_agent_id(runtime_dir: &Path, client: &str) -> Option<String> {
    let key = client_session_key()?;
    Some(resolve_agent_id_for_key(runtime_dir, client, &key))
}

/// Hook side: bind `conversation_id` <-> session key <-> agent id. A resumed conversation (new client
/// process) keeps the agent id it had before, so its CoW shadow and mailbox survive restarts.
pub fn bind_conversation_for_key(
    runtime_dir: &Path,
    client: &str,
    key: &SessionKey,
    conversation_id: Option<&str>,
) -> String {
    let previous_for_conversation = conversation_id
        .filter(|c| !c.is_empty())
        .and_then(|c| read_binding(&by_conversation_path(runtime_dir, c)));
    let existing_for_key = read_binding(&by_key_path(runtime_dir, key));

    let agent_id = previous_for_conversation
        .as_ref()
        .map(|b| b.agent_id.clone())
        .or_else(|| existing_for_key.as_ref().map(|b| b.agent_id.clone()))
        .unwrap_or_else(|| derive_agent_id(client, key));

    let unchanged = existing_for_key.as_ref().is_some_and(|b| {
        b.agent_id == agent_id && b.conversation_id.as_deref() == conversation_id
    });
    if !unchanged {
        let binding = SessionBinding {
            client: client.to_string(),
            agent_id: agent_id.clone(),
            key: *key,
            conversation_id: conversation_id.map(|s| s.to_string()),
            bound_at_ms: chrono::Utc::now().timestamp_millis(),
        };
        let _ = write_json_atomic(&by_key_path(runtime_dir, key), &binding);
        if let Some(c) = conversation_id.filter(|c| !c.is_empty()) {
            let _ = write_json_atomic(&by_conversation_path(runtime_dir, c), &binding);
        }
    }
    agent_id
}

/// Convenience wrapper using the real process table.
pub fn bind_conversation(
    runtime_dir: &Path,
    client: &str,
    conversation_id: Option<&str>,
) -> Option<String> {
    let key = client_session_key()?;
    Some(bind_conversation_for_key(runtime_dir, client, &key, conversation_id))
}

/// Returns `true` exactly once per `key` across processes. Used to de-duplicate hooks that are
/// registered both globally (`~/.gemini/config/hooks.json`) and per-repo (`.agents/hooks.json`).
pub fn once_guard(runtime_dir: &Path, key: &str) -> bool {
    let dir = sessions_dir(runtime_dir).join("once");
    if std::fs::create_dir_all(&dir).is_err() {
        return true;
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(sanitize(key)))
    {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn table(entries: &[(u32, u32, &str, u64)]) -> HashMap<u32, ProcInfo> {
        entries
            .iter()
            .map(|(pid, ppid, comm, st)| {
                (
                    *pid,
                    ProcInfo {
                        pid: *pid,
                        ppid: *ppid,
                        comm: comm.to_string(),
                        start_time: *st,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn hook_and_mcp_server_resolve_same_client() {
        // zsh(59720) -> agy(92429) -> aegis-os mcp-stdio(92477)
        //                          -> sh(93000) -> aegis-os agy-hook(93001)
        let t = table(&[
            (59720, 59715, "zsh", 100),
            (92429, 59720, "agy", 200),
            (92477, 92429, "aegis-os", 201),
            (93000, 92429, "sh", 300),
            (93001, 93000, "aegis-os", 301),
        ]);
        let look = |p: u32| t.get(&p).cloned();
        // MCP server starts from its parent pid; hook starts from its parent (sh).
        let from_mcp = find_client_ancestor(92429, look).unwrap();
        let from_hook = find_client_ancestor(93000, look).unwrap();
        assert_eq!(from_mcp.pid, 92429);
        assert_eq!(from_hook.pid, 92429);
        assert_eq!(from_mcp.start_time, from_hook.start_time);
    }

    #[test]
    fn two_windows_get_distinct_ids() {
        let a = SessionKey { pid: 92429, start_time: 200 };
        let b = SessionKey { pid: 88001, start_time: 150 };
        let ia = derive_agent_id("agy", &a);
        let ib = derive_agent_id("agy", &b);
        assert!(ia.starts_with("agy-") && ia.len() == 10, "{ia}");
        assert_ne!(ia, ib);
        assert_eq!(ia, derive_agent_id("agy", &a), "deterministic");
    }

    #[test]
    fn wrapper_detection_handles_login_shells_and_paths() {
        assert!(is_wrapper("-zsh"));
        assert!(is_wrapper("/bin/sh"));
        assert!(!is_wrapper("agy"));
        assert!(!is_wrapper("node"));
    }

    #[test]
    fn resumed_conversation_keeps_agent_id_and_mcp_side_sees_binding() {
        let dir = tempfile::tempdir().unwrap();
        let rt = dir.path();
        let first = SessionKey { pid: 1000, start_time: 1 };
        let id1 = bind_conversation_for_key(rt, "agy", &first, Some("conv-abc"));
        assert_eq!(id1, derive_agent_id("agy", &first));

        // Client restarted (new pid) but resumed the same conversation.
        let second = SessionKey { pid: 2000, start_time: 9 };
        let id2 = bind_conversation_for_key(rt, "agy", &second, Some("conv-abc"));
        assert_eq!(id2, id1);
        // MCP server of the new process resolves through the hook-written binding.
        assert_eq!(resolve_agent_id_for_key(rt, "agy", &second), id1);

        // A different conversation in a third window gets its own id.
        let third = SessionKey { pid: 3000, start_time: 5 };
        let id3 = bind_conversation_for_key(rt, "agy", &third, Some("conv-xyz"));
        assert_ne!(id3, id1);
    }

    #[test]
    fn once_guard_fires_once() {
        let dir = tempfile::tempdir().unwrap();
        assert!(once_guard(dir.path(), "conv-1:PreInvocation:3"));
        assert!(!once_guard(dir.path(), "conv-1:PreInvocation:3"));
        assert!(once_guard(dir.path(), "conv-1:PreInvocation:4"));
    }
}
