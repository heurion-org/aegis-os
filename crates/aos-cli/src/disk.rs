use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use aos_core::IpcBus;
use aos_ipc::AegisIpcBus;
use aos_vfs::vault::{OrgVaultManager, VaultBackendKind, VaultStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEFAULT_GC_OLDER_THAN_DAYS: u64 = 7;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskEntry {
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub path: PathBuf,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_days: Option<u64>,
    pub live: bool,
    pub dirty: bool,
    pub reclaimable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultDiskEntry {
    pub org_id: String,
    pub backend: String,
    pub encrypted: bool,
    pub mounted: bool,
    pub mount_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backing_path: Option<PathBuf>,
    pub backing_bytes: u64,
    pub mounted_logical_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskReport {
    pub runtime_dir: PathBuf,
    pub host_ssd_bytes: u64,
    pub mounted_vault_logical_bytes: u64,
    pub reclaimable_safe_bytes: u64,
    pub vault_backing_bytes: u64,
    pub agent_cache_bytes: u64,
    pub agent_tmp_bytes: u64,
    pub agent_bg_jobs_bytes: u64,
    pub cow_shadow_bytes: u64,
    pub cow_snapshot_bytes: u64,
    pub session_bytes: u64,
    pub protected_bytes: u64,
    pub other_bytes: u64,
    pub live_agents: Vec<String>,
    pub vaults: Vec<VaultDiskEntry>,
    pub entries: Vec<DiskEntry>,
}

#[derive(Debug, Clone)]
pub struct GcOptions {
    pub runtime_dir: PathBuf,
    pub older_than_days: u64,
    pub include_shadows: bool,
    pub force_dirty: bool,
    pub compact_vaults: bool,
    pub apply: bool,
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcAction {
    pub kind: String,
    pub category: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub applied: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcReport {
    pub dry_run: bool,
    pub older_than_days: u64,
    pub include_shadows: bool,
    pub force_dirty: bool,
    pub compact_vaults: bool,
    pub reclaimable_bytes: u64,
    pub reclaimed_bytes: u64,
    pub actions: Vec<GcAction>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
struct DirStats {
    bytes: u64,
    max_mtime: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TreeNodeKind {
    Dir,
    File(u64),
    Symlink(Option<PathBuf>),
}

pub fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    const TIB: f64 = GIB * 1024.0;
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if b < MIB {
        format!("{:.1} KB", b / KIB)
    } else if b < GIB {
        format!("{:.1} MB", b / MIB)
    } else if b < TIB {
        format!("{:.2} GB", b / GIB)
    } else {
        format!("{:.2} TB", b / TIB)
    }
}

fn dir_stats_no_symlinks(path: &Path) -> DirStats {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return DirStats::default();
    };
    if meta.file_type().is_symlink() {
        return DirStats::default();
    }
    let mut stats = DirStats {
        bytes: 0,
        max_mtime: meta.modified().ok(),
    };
    if meta.is_file() {
        stats.bytes = meta.len();
        return stats;
    }
    if !meta.is_dir() {
        return stats;
    }

    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let child = entry.path();
            let Ok(child_meta) = std::fs::symlink_metadata(&child) else {
                continue;
            };
            if child_meta.file_type().is_symlink() {
                continue;
            }
            if let Ok(mtime) = child_meta.modified() {
                stats.max_mtime = Some(match stats.max_mtime {
                    Some(prev) => prev.max(mtime),
                    None => mtime,
                });
            }
            if child_meta.is_file() {
                stats.bytes = stats.bytes.saturating_add(child_meta.len());
            } else if child_meta.is_dir() {
                stack.push(child);
            }
        }
    }
    stats
}

fn file_len_no_symlink(path: &Path) -> u64 {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(|m| !m.file_type().is_symlink() && m.is_file())
        .map(|m| m.len())
        .unwrap_or(0)
}

fn mtime_age_days(mtime: Option<SystemTime>, now: SystemTime) -> Option<u64> {
    mtime.map(|ts| now.duration_since(ts).unwrap_or_default().as_secs() / 86_400)
}

fn session_status_and_age(ses_dir: &Path, dir_mtime: Option<SystemTime>, now: SystemTime) -> (String, Option<u64>, Option<(String, String)>) {
    let raw = std::fs::symlink_metadata(ses_dir.join("session.json"))
        .ok()
        .filter(|m| !m.file_type().is_symlink() && m.is_file())
        .and_then(|_| std::fs::read_to_string(ses_dir.join("session.json")).ok());

    let Some(val) = raw.and_then(|r| serde_json::from_str::<Value>(&r).ok()) else {
        return ("unknown".to_string(), mtime_age_days(dir_mtime, now), None);
    };

    let status = val
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_ascii_lowercase();

    let age_days = val
        .get("updated_at_ms")
        .or_else(|| val.get("created_at_ms"))
        .and_then(|v| v.as_i64())
        .and_then(|ts_ms| {
            let now_ms = now
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|d| i64::try_from(d.as_millis()).ok())?;
            if now_ms >= ts_ms {
                Some(((now_ms - ts_ms) as u64) / 86_400_000)
            } else {
                Some(0)
            }
        })
        .or_else(|| mtime_age_days(dir_mtime, now));

    let agent_ref = match (
        val.get("org_id").and_then(|v| v.as_str()),
        val.get("agent_id").and_then(|v| v.as_str()),
    ) {
        (Some(org), Some(agent)) if !org.is_empty() && !agent.is_empty() => {
            Some((org.to_string(), agent.to_string()))
        }
        _ => None,
    };

    (status, age_days, agent_ref)
}

fn has_non_dotfile_entries_no_symlinks(dir: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return false;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&cur) else {
            continue;
        };
        for entry in rd.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            let child = entry.path();
            let Ok(child_meta) = std::fs::symlink_metadata(&child) else {
                continue;
            };
            if child_meta.file_type().is_symlink() {
                return true;
            }
            if child_meta.is_file() {
                return true;
            }
            if child_meta.is_dir() {
                // Non-empty non-dotfile directory or files inside count as uncommitted work.
                return true;
            }
        }
    }
    false
}

fn collect_tree_no_symlinks(root: &Path) -> Option<BTreeMap<PathBuf, TreeNodeKind>> {
    let meta = std::fs::symlink_metadata(root).ok()?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return None;
    }
    let mut tree = BTreeMap::new();
    let mut stack = vec![(root.to_path_buf(), PathBuf::new())];
    while let Some((abs_dir, rel_dir)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&abs_dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();
            if fname_str == ".DS_Store" || fname_str == ".initialized" {
                continue;
            }
            let abs = entry.path();
            let rel = rel_dir.join(&fname);
            let Ok(m) = std::fs::symlink_metadata(&abs) else {
                continue;
            };
            if m.file_type().is_symlink() {
                tree.insert(rel, TreeNodeKind::Symlink(std::fs::read_link(&abs).ok()));
            } else if m.is_dir() {
                tree.insert(rel.clone(), TreeNodeKind::Dir);
                stack.push((abs, rel));
            } else if m.is_file() {
                tree.insert(rel, TreeNodeKind::File(m.len()));
            }
        }
    }
    Some(tree)
}

fn open_file_no_symlink(path: &Path) -> std::io::Result<std::fs::File> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing non-regular file or symlink",
        ));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

fn files_equal_no_symlinks(a: &Path, b: &Path) -> bool {
    let (Ok(mut fa), Ok(mut fb)) = (open_file_no_symlink(a), open_file_no_symlink(b)) else {
        return false;
    };
    let mut buf_a = [0u8; 8192];
    let mut buf_b = [0u8; 8192];
    loop {
        let Ok(na) = fa.read(&mut buf_a) else {
            return false;
        };
        let Ok(nb) = fb.read(&mut buf_b) else {
            return false;
        };
        if na != nb || buf_a[..na] != buf_b[..nb] {
            return false;
        }
        if na == 0 {
            return true;
        }
    }
}

pub fn shadow_has_uncommitted_diffs(cow_dir: &Path) -> bool {
    let upper = cow_dir.join("upper_workspace");
    let Ok(upper_meta) = std::fs::symlink_metadata(&upper) else {
        return false;
    };
    if upper_meta.file_type().is_symlink() || !upper_meta.is_dir() {
        return false;
    }

    let baseline = cow_dir.join("baseline_snapshot");
    let baseline_meta = std::fs::symlink_metadata(&baseline).ok();
    let Some(base_meta) = baseline_meta else {
        return has_non_dotfile_entries_no_symlinks(&upper);
    };
    if base_meta.file_type().is_symlink() || !base_meta.is_dir() {
        return has_non_dotfile_entries_no_symlinks(&upper);
    }

    let Some(base_tree) = collect_tree_no_symlinks(&baseline) else {
        return has_non_dotfile_entries_no_symlinks(&upper);
    };
    let Some(upper_tree) = collect_tree_no_symlinks(&upper) else {
        return false;
    };

    if base_tree.len() != upper_tree.len() {
        return true;
    }
    for (rel, upper_kind) in &upper_tree {
        let Some(base_kind) = base_tree.get(rel) else {
            return true;
        };
        if base_kind != upper_kind {
            return true;
        }
        if matches!(upper_kind, TreeNodeKind::File(_))
            && !files_equal_no_symlinks(&baseline.join(rel), &upper.join(rel))
        {
            return true;
        }
    }
    false
}

async fn load_live_agents(runtime_dir: &Path) -> BTreeSet<(String, String)> {
    let mut live = BTreeSet::new();
    let ipc_path = runtime_dir.join("ipc_state.json");
    if std::fs::symlink_metadata(&ipc_path)
        .is_ok_and(|m| !m.file_type().is_symlink() && m.is_file())
    {
        let bus = AegisIpcBus::with_state_file(Some(ipc_path));
        if let Ok(peers) = bus.list_all_peers().await {
            for peer in peers {
                let alive = if let Some(pid) = peer.pid {
                    aos_core::session::is_pid_alive(pid, peer.start_time)
                } else {
                    peer.online
                };
                if alive {
                    live.insert((peer.org_id, peer.agent_id));
                }
            }
        }
    }

    let now = SystemTime::now();
    let sessions_dir = runtime_dir.join("sessions");
    if let Ok(rd) = std::fs::read_dir(&sessions_dir) {
        for entry in rd.flatten() {
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with("ses_") {
                continue;
            }
            let dir = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&dir) else {
                continue;
            };
            if meta.file_type().is_symlink() || !meta.is_dir() {
                continue;
            }
            let (status, _, agent_ref) = session_status_and_age(&dir, meta.modified().ok(), now);
            if status == "running" {
                if let Some((org_id, agent_id)) = agent_ref {
                    live.insert((org_id, agent_id));
                }
            }
        }
    }

    live
}

fn collect_agent_slot_dirs(agent_dir: &Path) -> Vec<PathBuf> {
    let mut slots = vec![agent_dir.to_path_buf()];
    let workspaces_dir = agent_dir.join("workspaces");
    if std::fs::symlink_metadata(&workspaces_dir)
        .is_ok_and(|m| !m.file_type().is_symlink() && m.is_dir())
    {
        if let Ok(rd) = std::fs::read_dir(&workspaces_dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if std::fs::symlink_metadata(&p)
                    .is_ok_and(|m| !m.file_type().is_symlink() && m.is_dir())
                {
                    slots.push(p);
                }
            }
        }
    }
    slots
}

fn cache_targets_for_slot(slot_dir: &Path) -> Vec<(&'static str, PathBuf)> {
    let mut targets = Vec::new();
    for base in [slot_dir.join("home"), slot_dir.to_path_buf()] {
        targets.push(("agent_cache", base.join("cargo_target")));
        targets.push(("agent_cache", base.join("deps").join("cache")));
        targets.push(("agent_tmp", base.join("tmp")));
        targets.push(("agent_bg_jobs", base.join("bg_jobs")));
    }
    let mut seen = BTreeSet::new();
    targets.retain(|(_, p)| seen.insert(p.clone()));
    targets
}

fn shared_cache_targets_for_org(org_path: &Path) -> Vec<PathBuf> {
    let shared_root = org_path.join("shared_cache");
    if !is_real_dir(&shared_root) {
        return Vec::new();
    }
    let mut targets = Vec::new();
    let cargo_target = shared_root.join("cargo_target");
    if is_real_dir(&cargo_target) {
        targets.push(cargo_target);
    }
    let deps_dir = shared_root.join("deps");
    if is_real_dir(&deps_dir) {
        let deps_cache = deps_dir.join("cache");
        if is_real_dir(&deps_cache) {
            targets.push(deps_cache);
        }
    }
    targets
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_symlink() && m.is_dir())
}

fn is_protected_root_name(name: &str) -> bool {
    matches!(
        name,
        "keys"
            | "bin"
            | "policy_state.json"
            | "paas_state.json"
            | "ipc_state.json"
            | "ipc_state.json.lock"
            | "telemetry"
            | "audit"
            | ".version"
    )
}

fn canonical_or_self(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn vault_entries_and_backing_map(
    runtime_dir: &Path,
    statuses: &[VaultStatus],
) -> (Vec<VaultDiskEntry>, HashMap<String, VaultStatus>) {
    let _ = runtime_dir;
    let mut out = Vec::with_capacity(statuses.len());
    let mut by_org = HashMap::with_capacity(statuses.len());
    for st in statuses {
        let backing_bytes = st
            .backing_path
            .as_ref()
            .map(|p| dir_stats_no_symlinks(p).bytes)
            .unwrap_or(0);
        let mounted_logical_bytes =
            if st.mounted && st.backend != VaultBackendKind::PlainDir0700 {
                dir_stats_no_symlinks(&st.mount_dir).bytes
            } else {
                0
            };
        out.push(VaultDiskEntry {
            org_id: st.org_id.clone(),
            backend: st.backend.as_str().to_string(),
            encrypted: st.encrypted,
            mounted: st.mounted,
            mount_dir: st.mount_dir.clone(),
            backing_path: st.backing_path.clone(),
            backing_bytes,
            mounted_logical_bytes,
        });
        by_org.insert(st.org_id.clone(), st.clone());
    }
    (out, by_org)
}

pub async fn analyze_runtime_disk(runtime_dir: &Path) -> anyhow::Result<DiskReport> {
    let now = SystemTime::now();
    let live_agents = load_live_agents(runtime_dir).await;
    let statuses = OrgVaultManager::new(runtime_dir)
        .list_org_statuses()
        .unwrap_or_default();
    let (vaults, vault_by_org) = vault_entries_and_backing_map(runtime_dir, &statuses);

    let mut report = DiskReport {
        runtime_dir: runtime_dir.to_path_buf(),
        host_ssd_bytes: 0,
        mounted_vault_logical_bytes: 0,
        reclaimable_safe_bytes: 0,
        vault_backing_bytes: 0,
        agent_cache_bytes: 0,
        agent_tmp_bytes: 0,
        agent_bg_jobs_bytes: 0,
        cow_shadow_bytes: 0,
        cow_snapshot_bytes: 0,
        session_bytes: 0,
        protected_bytes: 0,
        other_bytes: 0,
        live_agents: live_agents
            .iter()
            .map(|(org, agent)| format!("{org}/{agent}"))
            .collect(),
        vaults,
        entries: Vec::new(),
    };

    let Ok(root_rd) = std::fs::read_dir(runtime_dir) else {
        return Ok(report);
    };

    for entry in root_rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }

        match name.as_str() {
            "vaults" if meta.is_dir() => {
                let stats = dir_stats_no_symlinks(&path);
                report.vault_backing_bytes = report.vault_backing_bytes.saturating_add(stats.bytes);
                report.host_ssd_bytes = report.host_ssd_bytes.saturating_add(stats.bytes);
                if stats.bytes > 0 {
                    report.entries.push(DiskEntry {
                        category: "vault".to_string(),
                        org_id: None,
                        agent_id: None,
                        path,
                        bytes: stats.bytes,
                        age_days: mtime_age_days(stats.max_mtime, now),
                        live: false,
                        dirty: false,
                        reclaimable: false,
                        note: Some("encrypted vault storage (protected; use --compact-vaults when locked)".to_string()),
                    });
                }
            }
            "sessions" if meta.is_dir() => {
                if let Ok(ses_rd) = std::fs::read_dir(&path) {
                    for ses_entry in ses_rd.flatten() {
                        let ses_name = ses_entry.file_name().to_string_lossy().to_string();
                        let ses_path = ses_entry.path();
                        let Ok(ses_meta) = std::fs::symlink_metadata(&ses_path) else {
                            continue;
                        };
                        if ses_meta.file_type().is_symlink() {
                            continue;
                        }
                        let stats = dir_stats_no_symlinks(&ses_path);
                        report.host_ssd_bytes = report.host_ssd_bytes.saturating_add(stats.bytes);
                        if !ses_name.starts_with("ses_") || !ses_meta.is_dir() {
                            report.protected_bytes = report.protected_bytes.saturating_add(stats.bytes);
                            continue;
                        }
                        report.session_bytes = report.session_bytes.saturating_add(stats.bytes);
                        let (status, age_days, agent_ref) =
                            session_status_and_age(&ses_path, stats.max_mtime.or_else(|| ses_meta.modified().ok()), now);
                        let running = status == "running";
                        let exited_prunable = matches!(status.as_str(), "exited" | "committed" | "discarded");
                        let reclaimable = !running
                            && exited_prunable
                            && age_days.is_some_and(|d| d >= DEFAULT_GC_OLDER_THAN_DAYS);
                        if reclaimable {
                            report.reclaimable_safe_bytes =
                                report.reclaimable_safe_bytes.saturating_add(stats.bytes);
                        }
                        let category = if running {
                            "session_running"
                        } else if exited_prunable {
                            "session_exited"
                        } else {
                            "session_other"
                        };
                        report.entries.push(DiskEntry {
                            category: category.to_string(),
                            org_id: agent_ref.as_ref().map(|(o, _)| o.clone()),
                            agent_id: agent_ref.map(|(_, a)| a),
                            path: ses_path,
                            bytes: stats.bytes,
                            age_days,
                            live: running,
                            dirty: false,
                            reclaimable,
                            note: Some(format!("status={status}")),
                        });
                    }
                }
            }
            "orgs" if meta.is_dir() => {
                if let Ok(org_rd) = std::fs::read_dir(&path) {
                    for org_entry in org_rd.flatten() {
                        let org_id = org_entry.file_name().to_string_lossy().to_string();
                        if org_id.starts_with('.') {
                            continue;
                        }
                        let org_path = org_entry.path();
                        if !is_real_dir(&org_path) {
                            continue;
                        }
                        let is_mounted_image = vault_by_org.get(&org_id).is_some_and(|v| {
                            v.mounted && v.backend != VaultBackendKind::PlainDir0700
                        });
                        let total_org_bytes = dir_stats_no_symlinks(&org_path).bytes;
                        if is_mounted_image {
                            report.mounted_vault_logical_bytes =
                                report.mounted_vault_logical_bytes.saturating_add(total_org_bytes);
                        } else {
                            report.host_ssd_bytes =
                                report.host_ssd_bytes.saturating_add(total_org_bytes);
                        }

                        let mut accounted_org_bytes: u64 = 0;
                        let agents_dir = org_path.join("agents");
                        if is_real_dir(&agents_dir) {
                            if let Ok(ag_rd) = std::fs::read_dir(&agents_dir) {
                                for ag_entry in ag_rd.flatten() {
                                    let agent_id = ag_entry.file_name().to_string_lossy().to_string();
                                    if agent_id.starts_with('.') {
                                        continue;
                                    }
                                    let agent_dir = ag_entry.path();
                                    if !is_real_dir(&agent_dir) {
                                        continue;
                                    }
                                    let live = live_agents
                                        .contains(&(org_id.clone(), agent_id.clone()));

                                    for slot_dir in collect_agent_slot_dirs(&agent_dir) {
                                        for (category, cache_dir) in cache_targets_for_slot(&slot_dir) {
                                            if !is_real_dir(&cache_dir) {
                                                continue;
                                            }
                                            let stats = dir_stats_no_symlinks(&cache_dir);
                                            accounted_org_bytes =
                                                accounted_org_bytes.saturating_add(stats.bytes);
                                            match category {
                                                "agent_cache" => {
                                                    report.agent_cache_bytes = report
                                                        .agent_cache_bytes
                                                        .saturating_add(stats.bytes)
                                                }
                                                "agent_tmp" => {
                                                    report.agent_tmp_bytes = report
                                                        .agent_tmp_bytes
                                                        .saturating_add(stats.bytes)
                                                }
                                                "agent_bg_jobs" => {
                                                    report.agent_bg_jobs_bytes = report
                                                        .agent_bg_jobs_bytes
                                                        .saturating_add(stats.bytes)
                                                }
                                                _ => {}
                                            }
                                            let age_days = mtime_age_days(stats.max_mtime, now);
                                            let reclaimable = !live
                                                && age_days.is_some_and(|d| {
                                                    d >= DEFAULT_GC_OLDER_THAN_DAYS
                                                });
                                            if reclaimable {
                                                report.reclaimable_safe_bytes = report
                                                    .reclaimable_safe_bytes
                                                    .saturating_add(stats.bytes);
                                            }
                                            if stats.bytes > 0 {
                                                report.entries.push(DiskEntry {
                                                    category: category.to_string(),
                                                    org_id: Some(org_id.clone()),
                                                    agent_id: Some(agent_id.clone()),
                                                    path: cache_dir,
                                                    bytes: stats.bytes,
                                                    age_days,
                                                    live,
                                                    dirty: false,
                                                    reclaimable,
                                                    note: None,
                                                });
                                            }
                                        }

                                        let cow_dir = slot_dir.join("cow_workspace");
                                        if is_real_dir(&cow_dir) {
                                            let cow_stats = dir_stats_no_symlinks(&cow_dir);
                                            let snap_bytes = dir_stats_no_symlinks(
                                                &cow_dir.join("snapshots"),
                                            )
                                            .bytes
                                                .saturating_add(file_len_no_symlink(
                                                    &cow_dir.join("snapshots.json"),
                                                ));
                                            let shadow_only =
                                                cow_stats.bytes.saturating_sub(snap_bytes);
                                            accounted_org_bytes =
                                                accounted_org_bytes.saturating_add(cow_stats.bytes);
                                            report.cow_snapshot_bytes =
                                                report.cow_snapshot_bytes.saturating_add(snap_bytes);
                                            report.cow_shadow_bytes =
                                                report.cow_shadow_bytes.saturating_add(shadow_only);
                                            let dirty = shadow_has_uncommitted_diffs(&cow_dir);
                                            let note = if dirty {
                                                Some(format!(
                                                    "uncommitted changes (recover via `aegis-os vault recover --from-agent {agent_id}`)"
                                                ))
                                            } else if !live {
                                                Some("clean offline shadow (prune via `aegis-os gc --include-shadows`)".to_string())
                                            } else {
                                                Some("active shadow workspace".to_string())
                                            };
                                            if cow_stats.bytes > 0 {
                                                report.entries.push(DiskEntry {
                                                    category: "cow_shadow".to_string(),
                                                    org_id: Some(org_id.clone()),
                                                    agent_id: Some(agent_id.clone()),
                                                    path: cow_dir,
                                                    bytes: cow_stats.bytes,
                                                    age_days: mtime_age_days(
                                                        cow_stats.max_mtime,
                                                        now,
                                                    ),
                                                    live,
                                                    dirty,
                                                    reclaimable: false,
                                                    note,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        let any_org_agent_live = live_agents.iter().any(|(o, _)| o == &org_id);
                        for shared_cache_dir in shared_cache_targets_for_org(&org_path) {
                            let stats = dir_stats_no_symlinks(&shared_cache_dir);
                            accounted_org_bytes =
                                accounted_org_bytes.saturating_add(stats.bytes);
                            report.agent_cache_bytes =
                                report.agent_cache_bytes.saturating_add(stats.bytes);
                            let age_days = mtime_age_days(stats.max_mtime, now);
                            let reclaimable = !any_org_agent_live
                                && age_days.is_some_and(|d| d >= DEFAULT_GC_OLDER_THAN_DAYS);
                            if reclaimable {
                                report.reclaimable_safe_bytes =
                                    report.reclaimable_safe_bytes.saturating_add(stats.bytes);
                            }
                            if stats.bytes > 0 {
                                report.entries.push(DiskEntry {
                                    category: "org_shared_cache".to_string(),
                                    org_id: Some(org_id.clone()),
                                    agent_id: None,
                                    path: shared_cache_dir,
                                    bytes: stats.bytes,
                                    age_days,
                                    live: any_org_agent_live,
                                    dirty: false,
                                    reclaimable,
                                    note: None,
                                });
                            }
                        }

                        let remainder = total_org_bytes.saturating_sub(accounted_org_bytes);
                        report.other_bytes = report.other_bytes.saturating_add(remainder);
                    }
                }
            }
            _ => {
                let stats = dir_stats_no_symlinks(&path);
                report.host_ssd_bytes = report.host_ssd_bytes.saturating_add(stats.bytes);
                if is_protected_root_name(&name) {
                    report.protected_bytes = report.protected_bytes.saturating_add(stats.bytes);
                } else {
                    report.other_bytes = report.other_bytes.saturating_add(stats.bytes);
                }
            }
        }
    }

    report.entries.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| a.path.cmp(&b.path))
    });

    Ok(report)
}

pub async fn render_disk_report(runtime_dir: &Path, top: usize, json: bool) -> anyhow::Result<()> {
    let report = analyze_runtime_disk(runtime_dir).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("Aegis OS Runtime Disk Usage");
    println!("  Runtime Dir:      {}", report.runtime_dir.display());
    println!(
        "  Host SSD Usage:   {} (deduplicated physical backing)",
        format_bytes(report.host_ssd_bytes)
    );
    if report.mounted_vault_logical_bytes > 0 {
        println!(
            "  Mounted OrgVault: {} (logical view backed by vaults/; not double-counted above)",
            format_bytes(report.mounted_vault_logical_bytes)
        );
    }
    println!(
        "  Safe Reclaimable: {} (default `aegis-os gc --yes`, >= {}d offline caches/sessions)",
        format_bytes(report.reclaimable_safe_bytes),
        DEFAULT_GC_OLDER_THAN_DAYS
    );
    println!("  Live Agents:      {}", report.live_agents.len());
    println!();
    println!("Category Breakdown:");
    println!(
        "  Vaults (backing): {:>10}  (never deleted by `gc`)",
        format_bytes(report.vault_backing_bytes)
    );
    println!(
        "  Agent Caches:     {:>10}  (cargo_target, deps/cache)",
        format_bytes(report.agent_cache_bytes)
    );
    println!(
        "  Agent Scratch:    {:>10}  (tmp, bg_jobs)",
        format_bytes(report.agent_tmp_bytes.saturating_add(report.agent_bg_jobs_bytes))
    );
    println!(
        "  CoW Shadows:      {:>10}  (upper_workspace + baseline + snapshots: {})",
        format_bytes(report.cow_shadow_bytes.saturating_add(report.cow_snapshot_bytes)),
        format_bytes(report.cow_snapshot_bytes)
    );
    println!(
        "  Sessions (ses_*): {:>10}",
        format_bytes(report.session_bytes)
    );
    println!(
        "  Protected State:  {:>10}  (keys, policy, ipc, telemetry, audit)",
        format_bytes(report.protected_bytes)
    );
    if report.other_bytes > 0 {
        println!(
            "  Other / AgentDB:  {:>10}",
            format_bytes(report.other_bytes)
        );
    }

    if !report.vaults.is_empty() {
        println!();
        println!("OrgVaults:");
        for v in &report.vaults {
            println!(
                "  - {:<14} backend={:<16} mounted={:<5} encrypted={:<5} backing={}",
                v.org_id,
                v.backend,
                v.mounted,
                v.encrypted,
                format_bytes(v.backing_bytes)
            );
        }
    }

    let shown = report.entries.iter().take(top).collect::<Vec<_>>();
    if !shown.is_empty() {
        println!();
        println!("Top Consumers (showing {} of {}):", shown.len(), report.entries.len());
        for item in shown {
            let mut tags = Vec::new();
            if item.live {
                tags.push("LIVE");
            }
            if item.dirty {
                tags.push("DIRTY");
            }
            if item.reclaimable {
                tags.push("RECLAIMABLE");
            }
            let age_str = item
                .age_days
                .map(|d| format!("{d}d"))
                .unwrap_or_else(|| "-".to_string());
            let tag_str = if tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", tags.join(","))
            };
            let note_str = item
                .note
                .as_ref()
                .map(|n| format!(" — {n}"))
                .unwrap_or_default();
            println!(
                "  {:>10}  {:<15} age={:<4} {}{}{}",
                format_bytes(item.bytes),
                item.category,
                age_str,
                item.path.display(),
                tag_str,
                note_str
            );
        }
    }

    println!();
    println!("Next steps:");
    println!("  • Preview cleanup:   aegis-os gc --dry-run");
    println!("  • Reclaim safe items: aegis-os gc --yes");
    println!("  • Include clean CoW:  aegis-os gc --include-shadows --yes");
    Ok(())
}

fn remove_dir_safe(path: &Path) -> anyhow::Result<()> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting '{}'", path.display()))?;
    if meta.file_type().is_symlink() {
        anyhow::bail!("refusing to follow/remove symlink '{}'", path.display());
    }
    if !meta.is_dir() {
        anyhow::bail!("expected directory at '{}'", path.display());
    }
    std::fs::remove_dir_all(path).with_context(|| format!("removing '{}'", path.display()))
}

struct CachePruneTarget<'a> {
    target_dir: PathBuf,
    category: &'a str,
    live: bool,
    live_reason: String,
    remove_reason_prefix: &'a str,
}

fn prune_cache_dir_target(
    target: CachePruneTarget<'_>,
    opts: &GcOptions,
    now: SystemTime,
    report: &mut GcReport,
) {
    let CachePruneTarget {
        target_dir,
        category,
        live,
        live_reason,
        remove_reason_prefix,
    } = target;
    if !is_real_dir(&target_dir) {
        return;
    }
    let stats = dir_stats_no_symlinks(&target_dir);
    let age_days = mtime_age_days(stats.max_mtime, now).unwrap_or(0);
    if live {
        report.actions.push(GcAction {
            kind: "skip_live".to_string(),
            category: category.to_string(),
            path: target_dir,
            bytes: stats.bytes,
            applied: false,
            reason: live_reason,
        });
        return;
    }
    if age_days < opts.older_than_days {
        report.actions.push(GcAction {
            kind: "skip_recent".to_string(),
            category: category.to_string(),
            path: target_dir,
            bytes: stats.bytes,
            applied: false,
            reason: format!(
                "age {age_days}d is newer than --older-than-days {}",
                opts.older_than_days
            ),
        });
        return;
    }

    report.reclaimable_bytes = report.reclaimable_bytes.saturating_add(stats.bytes);
    if opts.apply {
        match remove_dir_safe(&target_dir) {
            Ok(()) => {
                report.reclaimed_bytes = report.reclaimed_bytes.saturating_add(stats.bytes);
                report.actions.push(GcAction {
                    kind: "remove_dir".to_string(),
                    category: category.to_string(),
                    path: target_dir,
                    bytes: stats.bytes,
                    applied: true,
                    reason: format!("{remove_reason_prefix} ({age_days}d old)"),
                });
            }
            Err(err) => {
                report.warnings.push(format!(
                    "Failed to remove '{}': {err}",
                    target_dir.display()
                ));
            }
        }
    } else {
        report.actions.push(GcAction {
            kind: "remove_dir".to_string(),
            category: category.to_string(),
            path: target_dir,
            bytes: stats.bytes,
            applied: false,
            reason: format!("dry-run: {remove_reason_prefix} ({age_days}d old)"),
        });
    }
}

pub async fn run_gc_plan(opts: &GcOptions) -> anyhow::Result<GcReport> {
    let now = SystemTime::now();
    let live_agents = load_live_agents(&opts.runtime_dir).await;
    let mut report = GcReport {
        dry_run: !opts.apply,
        older_than_days: opts.older_than_days,
        include_shadows: opts.include_shadows,
        force_dirty: opts.force_dirty,
        compact_vaults: opts.compact_vaults,
        reclaimable_bytes: 0,
        reclaimed_bytes: 0,
        actions: Vec::new(),
        warnings: Vec::new(),
    };

    if opts.force_dirty && !opts.include_shadows {
        report.warnings.push(
            "`--force-dirty` has no effect without `--include-shadows`; CoW shadow workspaces were left untouched."
                .to_string(),
        );
    }

    // 1. Offline agent caches, tmp, bg_jobs, and (optionally) CoW shadow workspaces.
    let orgs_dir = opts.runtime_dir.join("orgs");
    if is_real_dir(&orgs_dir) {
        let mut org_paths: Vec<PathBuf> = std::fs::read_dir(&orgs_dir)?
            .flatten()
            .map(|e| e.path())
            .collect();
        org_paths.sort();

        for org_path in org_paths {
            let org_id = org_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if org_id.starts_with('.') || !is_real_dir(&org_path) {
                continue;
            }
            let agents_dir = org_path.join("agents");
            if is_real_dir(&agents_dir) {
                let mut agent_paths: Vec<PathBuf> = std::fs::read_dir(&agents_dir)?
                    .flatten()
                    .map(|e| e.path())
                    .collect();
                agent_paths.sort();

                for agent_dir in agent_paths {
                    let agent_id = agent_dir
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if agent_id.starts_with('.') || !is_real_dir(&agent_dir) {
                        continue;
                    }
                    let live = live_agents.contains(&(org_id.clone(), agent_id.clone()));

                    let mut slot_dirs = collect_agent_slot_dirs(&agent_dir);
                    slot_dirs.sort();
                    for slot_dir in slot_dirs {
                        for (category, target_dir) in cache_targets_for_slot(&slot_dir) {
                            prune_cache_dir_target(
                                CachePruneTarget {
                                    target_dir,
                                    category,
                                    live,
                                    live_reason: format!(
                                        "agent '{org_id}/{agent_id}' is currently live"
                                    ),
                                    remove_reason_prefix: "offline agent cache/scratch",
                                },
                                opts,
                                now,
                                &mut report,
                            );
                        }

                        let cow_dir = slot_dir.join("cow_workspace");
                    if is_real_dir(&cow_dir) {
                        let stats = dir_stats_no_symlinks(&cow_dir);
                        let age_days = mtime_age_days(stats.max_mtime, now).unwrap_or(0);
                        let dirty = shadow_has_uncommitted_diffs(&cow_dir);

                        if live {
                            report.actions.push(GcAction {
                                kind: "skip_live".to_string(),
                                category: "cow_shadow".to_string(),
                                path: cow_dir,
                                bytes: stats.bytes,
                                applied: false,
                                reason: format!("agent '{org_id}/{agent_id}' is currently live"),
                            });
                            continue;
                        }

                        if !opts.include_shadows {
                            if dirty && stats.bytes > 0 {
                                report.warnings.push(format!(
                                    "Offline agent '{agent_id}' (org '{org_id}') has dirty CoW shadow edits at '{}'; recover with `aegis-os vault recover --from-agent {agent_id}`.",
                                    cow_dir.display()
                                ));
                            }
                            continue;
                        }

                        if dirty && !opts.force_dirty {
                            let msg = format!(
                                "Skipped dirty CoW shadow for offline agent '{agent_id}' (org '{org_id}'): recover uncommitted edits with `aegis-os vault recover --from-agent {agent_id}` or pass `--force-dirty`."
                            );
                            report.warnings.push(msg.clone());
                            report.actions.push(GcAction {
                                kind: "skip_dirty_shadow".to_string(),
                                category: "cow_shadow".to_string(),
                                path: cow_dir,
                                bytes: stats.bytes,
                                applied: false,
                                reason: msg,
                            });
                            continue;
                        }

                        if age_days < opts.older_than_days {
                            report.actions.push(GcAction {
                                kind: "skip_recent".to_string(),
                                category: "cow_shadow".to_string(),
                                path: cow_dir,
                                bytes: stats.bytes,
                                applied: false,
                                reason: format!(
                                    "age {age_days}d is newer than --older-than-days {}",
                                    opts.older_than_days
                                ),
                            });
                            continue;
                        }

                        report.reclaimable_bytes =
                            report.reclaimable_bytes.saturating_add(stats.bytes);
                        let reason_label = if dirty {
                            format!("offline dirty CoW shadow forced ({age_days}d old)")
                        } else {
                            format!("offline clean CoW shadow ({age_days}d old)")
                        };
                        if opts.apply {
                            match remove_dir_safe(&cow_dir) {
                                Ok(()) => {
                                    report.reclaimed_bytes =
                                        report.reclaimed_bytes.saturating_add(stats.bytes);
                                    report.actions.push(GcAction {
                                        kind: "remove_dir".to_string(),
                                        category: "cow_shadow".to_string(),
                                        path: cow_dir,
                                        bytes: stats.bytes,
                                        applied: true,
                                        reason: reason_label,
                                    });
                                }
                                Err(err) => {
                                    report.warnings.push(format!(
                                        "Failed to remove '{}': {err}",
                                        cow_dir.display()
                                    ));
                                }
                            }
                        } else {
                            report.actions.push(GcAction {
                                kind: "remove_dir".to_string(),
                                category: "cow_shadow".to_string(),
                                path: cow_dir,
                                bytes: stats.bytes,
                                applied: false,
                                reason: format!("dry-run: {reason_label}"),
                            });
                        }
                    }
                }
            }
            }

            let any_org_agent_live = live_agents.iter().any(|(o, _)| o == &org_id);
            for target_dir in shared_cache_targets_for_org(&org_path) {
                prune_cache_dir_target(
                    CachePruneTarget {
                        target_dir,
                        category: "org_shared_cache",
                        live: any_org_agent_live,
                        live_reason: format!(
                            "at least one agent in org '{org_id}' is currently live"
                        ),
                        remove_reason_prefix: "offline org shared cache",
                    },
                    opts,
                    now,
                    &mut report,
                );
            }
        }
    }

    // 2. Old exited sessions under `sessions/ses_*` (preserving `running` sessions and radar/reminders/stop-budget).
    let sessions_dir = opts.runtime_dir.join("sessions");
    if is_real_dir(&sessions_dir) {
        let mut ses_paths: Vec<PathBuf> = std::fs::read_dir(&sessions_dir)?
            .flatten()
            .map(|e| e.path())
            .collect();
        ses_paths.sort();

        for ses_dir in ses_paths {
            let ses_name = ses_dir
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if !ses_name.starts_with("ses_") || !is_real_dir(&ses_dir) {
                continue;
            }
            let stats = dir_stats_no_symlinks(&ses_dir);
            let dir_mtime = stats.max_mtime.or_else(|| {
                std::fs::symlink_metadata(&ses_dir)
                    .ok()
                    .and_then(|m| m.modified().ok())
            });
            let (status, age_opt, _) = session_status_and_age(&ses_dir, dir_mtime, now);
            let age_days = age_opt.unwrap_or(0);

            if status == "running" {
                report.actions.push(GcAction {
                    kind: "skip_live".to_string(),
                    category: "session_running".to_string(),
                    path: ses_dir,
                    bytes: stats.bytes,
                    applied: false,
                    reason: "session is marked `running`".to_string(),
                });
                continue;
            }
            if !matches!(status.as_str(), "exited" | "committed" | "discarded") {
                continue;
            }
            if age_days < opts.older_than_days {
                report.actions.push(GcAction {
                    kind: "skip_recent".to_string(),
                    category: "session_exited".to_string(),
                    path: ses_dir,
                    bytes: stats.bytes,
                    applied: false,
                    reason: format!(
                        "exited session age {age_days}d is newer than --older-than-days {}",
                        opts.older_than_days
                    ),
                });
                continue;
            }

            report.reclaimable_bytes = report.reclaimable_bytes.saturating_add(stats.bytes);
            if opts.apply {
                match remove_dir_safe(&ses_dir) {
                    Ok(()) => {
                        report.reclaimed_bytes = report.reclaimed_bytes.saturating_add(stats.bytes);
                        report.actions.push(GcAction {
                            kind: "remove_dir".to_string(),
                            category: "session_exited".to_string(),
                            path: ses_dir,
                            bytes: stats.bytes,
                            applied: true,
                            reason: format!("exited session ({status}, {age_days}d old)"),
                        });
                    }
                    Err(err) => {
                        report.warnings.push(format!(
                            "Failed to remove session '{}': {err}",
                            ses_dir.display()
                        ));
                    }
                }
            } else {
                report.actions.push(GcAction {
                    kind: "remove_dir".to_string(),
                    category: "session_exited".to_string(),
                    path: ses_dir,
                    bytes: stats.bytes,
                    applied: false,
                    reason: format!("dry-run: exited session ({status}, {age_days}d old)"),
                });
            }
        }
    }

    // 3. Optional macOS unmounted APFS `.sparsebundle` compaction via `OrgVaultManager::compact_org`.
    if opts.compact_vaults {
        let vault_mgr = OrgVaultManager::new(&opts.runtime_dir);
        let statuses = vault_mgr.list_org_statuses().unwrap_or_default();
        for st in statuses {
            if st.backend == VaultBackendKind::PlainDir0700 {
                continue;
            }
            let target_path = st
                .backing_path
                .clone()
                .unwrap_or_else(|| canonical_or_self(&st.mount_dir));
            let backing_bytes = st
                .backing_path
                .as_ref()
                .map(|p| dir_stats_no_symlinks(p).bytes)
                .unwrap_or(0);

            if st.mounted {
                let msg = format!(
                    "OrgVault '{}' is mounted and cannot be compacted live; run `aegis-os --org {} vault lock` first.",
                    st.org_id, st.org_id
                );
                report.warnings.push(msg.clone());
                report.actions.push(GcAction {
                    kind: "skip_mounted_vault".to_string(),
                    category: "vault".to_string(),
                    path: target_path,
                    bytes: backing_bytes,
                    applied: false,
                    reason: msg,
                });
                continue;
            }

            if st.backend != VaultBackendKind::ApfsSparseBundle {
                report.actions.push(GcAction {
                    kind: "skip_unsupported_vault".to_string(),
                    category: "vault".to_string(),
                    path: target_path,
                    bytes: backing_bytes,
                    applied: false,
                    reason: format!(
                        "offline compaction not supported for vault backend '{}'",
                        st.backend.as_str()
                    ),
                });
                continue;
            }

            #[cfg(target_os = "macos")]
            {
                if opts.apply {
                    match vault_mgr.compact_org(&st.org_id) {
                        Ok(res) => {
                            let saved = res.bytes_reclaimed;
                            report.reclaimed_bytes = report.reclaimed_bytes.saturating_add(saved);
                            report.actions.push(GcAction {
                                kind: "compact_vault".to_string(),
                                category: "vault".to_string(),
                                path: res.backing_path,
                                bytes: saved,
                                applied: true,
                                reason: format!(
                                    "compacted unmounted APFS sparsebundle for '{}' (freed {})",
                                    st.org_id,
                                    format_bytes(saved)
                                ),
                            });
                        }
                        Err(err) => {
                            let msg = format!(
                                "Could not compact vault '{}': {err}",
                                st.org_id
                            );
                            report.warnings.push(msg.clone());
                            report.actions.push(GcAction {
                                kind: "compact_vault".to_string(),
                                category: "vault".to_string(),
                                path: target_path,
                                bytes: 0,
                                applied: false,
                                reason: msg,
                            });
                        }
                    }
                } else {
                    report.actions.push(GcAction {
                        kind: "compact_vault".to_string(),
                        category: "vault".to_string(),
                        path: target_path,
                        bytes: backing_bytes,
                        applied: false,
                        reason: format!(
                            "dry-run: would compact unmounted APFS sparsebundle for '{}'",
                            st.org_id
                        ),
                    });
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                report.actions.push(GcAction {
                    kind: "skip_unsupported_vault".to_string(),
                    category: "vault".to_string(),
                    path: target_path,
                    bytes: backing_bytes,
                    applied: false,
                    reason: "sparsebundle compaction is only supported on macOS".to_string(),
                });
            }
        }
    }

    Ok(report)
}

pub async fn render_gc_command(opts: GcOptions) -> anyhow::Result<()> {
    let report = run_gc_plan(&opts).await?;
    if opts.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!(
        "Aegis OS Garbage Collection ({})",
        if report.dry_run { "DRY RUN" } else { "APPLIED" }
    );
    println!(
        "  Policy: older_than_days={}, include_shadows={}, force_dirty={}, compact_vaults={}",
        report.older_than_days,
        report.include_shadows,
        report.force_dirty,
        report.compact_vaults
    );
    if report.dry_run {
        println!(
            "  Reclaimable: {}",
            format_bytes(report.reclaimable_bytes)
        );
    } else {
        println!("  Reclaimed:   {}", format_bytes(report.reclaimed_bytes));
    }

    if !report.actions.is_empty() {
        println!();
        println!("Planned / Executed Actions ({}):", report.actions.len());
        for a in &report.actions {
            println!(
                "  {:<20} {:>10}  {:<15} {} ({})",
                a.kind,
                format_bytes(a.bytes),
                a.category,
                a.path.display(),
                a.reason
            );
        }
    }

    if !report.warnings.is_empty() {
        println!();
        println!("Warnings:");
        for w in &report.warnings {
            println!("  ! {w}");
        }
    }

    if report.dry_run && report.reclaimable_bytes > 0 {
        println!();
        println!("Dry-run complete. Re-run with `--yes` to apply deletions.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::AgentIdentity;

    fn write_bytes(path: &Path, len: usize, fill: u8) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, vec![fill; len]).unwrap();
    }

    #[test]
    fn format_bytes_formats_human_readable_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(3 * 1024 * 1024), "3.0 MB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.00 GB");
    }

    #[tokio::test]
    async fn disk_report_and_gc_preserve_live_agents_dirty_shadows_keys_and_external_symlinks() {
        let root_tmp = tempfile::tempdir().unwrap();
        let runtime_dir = root_tmp.path().join(".aegis");
        let external_dir = root_tmp.path().join("external_host_data");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        write_bytes(&external_dir.join("big.bin"), 65536, b'E');

        // Protected runtime artifacts that `gc` must NEVER touch.
        write_bytes(&runtime_dir.join("keys/master.key"), 64, b'K');
        write_bytes(&runtime_dir.join("policy_state.json"), 32, b'P');
        write_bytes(&runtime_dir.join("vaults/personal.vault.json"), 128, b'V');
        write_bytes(&runtime_dir.join("sessions/radar/state.json"), 48, b'R');

        // Register one LIVE agent via IPC state pointing to our live test PID.
        let bus = AegisIpcBus::with_state_file(Some(runtime_dir.join("ipc_state.json")));
        let live_id = AgentIdentity::new("personal", "agy-live", "worker");
        bus.register_peer(&live_id, vec![]).await.unwrap();
        bus.update_peer_metadata(&live_id, Some("agy".to_string()), Some(std::process::id()), None, None)
            .await
            .unwrap();

        // Populate live agent caches + CoW shadow (must stay untouched).
        let live_agent_dir = runtime_dir.join("orgs/personal/agents/agy-live");
        write_bytes(&live_agent_dir.join("home/cargo_target/live.rlib"), 1024, b'L');
        write_bytes(&live_agent_dir.join("home/tmp/scratch.txt"), 256, b'S');
        write_bytes(&live_agent_dir.join("cow_workspace/upper_workspace/src/lib.rs"), 50, b'U');

        // Offline agent 1: clean shadow + cache + symlink to `external_dir` inside `node_modules`.
        let clean_offline_dir = runtime_dir.join("orgs/personal/agents/agy-clean");
        write_bytes(&clean_offline_dir.join("home/cargo_target/old.rlib"), 2000, b'C');
        write_bytes(&clean_offline_dir.join("home/deps/cache/pnpm-store/pkg.tgz"), 500, b'P');
        write_bytes(&clean_offline_dir.join("home/tmp/tmp.bin"), 300, b'T');
        write_bytes(&clean_offline_dir.join("home/bg_jobs/job1.log"), 200, b'B');
        write_bytes(&clean_offline_dir.join("cow_workspace/baseline_snapshot/src/main.rs"), 100, b'M');
        write_bytes(&clean_offline_dir.join("cow_workspace/upper_workspace/src/main.rs"), 100, b'M');
        write_bytes(&clean_offline_dir.join("cow_workspace/snapshots/snap1/src/main.rs"), 100, b'M');
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            &external_dir,
            clean_offline_dir.join("home/cargo_target/linked_external"),
        )
        .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            &external_dir,
            clean_offline_dir.join("cow_workspace/baseline_snapshot/ext_link"),
        )
        .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            &external_dir,
            clean_offline_dir.join("cow_workspace/upper_workspace/ext_link"),
        )
        .unwrap();

        // Offline agent 2: dirty shadow (baseline vs upper differs), must be protected unless `--include-shadows --force-dirty`.
        let dirty_offline_dir = runtime_dir.join("orgs/personal/agents/agy-dirty");
        write_bytes(&dirty_offline_dir.join("home/deps/cache/npm/a.tgz"), 600, b'D');
        write_bytes(&dirty_offline_dir.join("cow_workspace/baseline_snapshot/README.md"), 20, b'A');
        write_bytes(&dirty_offline_dir.join("cow_workspace/upper_workspace/README.md"), 20, b'Z');

        // Offline agent 3: missing `baseline_snapshot` + non-dotfile entry in `upper_workspace` -> treated as dirty.
        let nobase_dirty_dir = runtime_dir.join("orgs/personal/agents/agy-nobase");
        write_bytes(&nobase_dirty_dir.join("cow_workspace/upper_workspace/unsaved.txt"), 40, b'N');

        // Sessions: one running, one recent exited (0d), one old exited (15d).
        let now_ms = chrono::Utc::now().timestamp_millis();
        let old_ms = now_ms - 15 * 86_400_000;
        let ses_running = runtime_dir.join("sessions/ses_running");
        write_bytes(&ses_running.join("home/data.bin"), 700, b'1');
        std::fs::write(
            ses_running.join("session.json"),
            serde_json::json!({
                "status": "running",
                "org_id": "personal",
                "agent_id": "agy-live",
                "updated_at_ms": old_ms
            })
            .to_string(),
        )
        .unwrap();

        let ses_recent = runtime_dir.join("sessions/ses_recent");
        write_bytes(&ses_recent.join("home/data.bin"), 400, b'2');
        std::fs::write(
            ses_recent.join("session.json"),
            serde_json::json!({
                "status": "exited",
                "org_id": "personal",
                "agent_id": "agy-clean",
                "updated_at_ms": now_ms
            })
            .to_string(),
        )
        .unwrap();

        let ses_old = runtime_dir.join("sessions/ses_old");
        write_bytes(&ses_old.join("home/data.bin"), 900, b'3');
        std::fs::write(
            ses_old.join("session.json"),
            serde_json::json!({
                "status": "exited",
                "org_id": "personal",
                "agent_id": "agy-clean",
                "updated_at_ms": old_ms
            })
            .to_string(),
        )
        .unwrap();

        // 1. Inspect disk report: external symlink 65536B must NOT be counted anywhere!
        let report = analyze_runtime_disk(&runtime_dir).await.unwrap();
        assert!(report.live_agents.contains(&"personal/agy-live".to_string()));
        assert!(
            report.host_ssd_bytes < 32 * 1024,
            "external symlink target was wrongly counted: host_ssd_bytes={}",
            report.host_ssd_bytes
        );
        // Exactly 4980 = 1024+2000+500+600 (cache) + 256+300 (tmp) + 200 (bg_jobs) without 65536 external file!
        assert_eq!(report.agent_cache_bytes, 1024 + 2000 + 500 + 600);
        assert_eq!(report.agent_tmp_bytes, 256 + 300);
        assert_eq!(report.agent_bg_jobs_bytes, 200);
        // Verify dirty flags match shadow state.
        let clean_entry = report
            .entries
            .iter()
            .find(|e| e.category == "cow_shadow" && e.agent_id.as_deref() == Some("agy-clean"))
            .unwrap();
        assert!(!clean_entry.dirty);
        let dirty_entry = report
            .entries
            .iter()
            .find(|e| e.category == "cow_shadow" && e.agent_id.as_deref() == Some("agy-dirty"))
            .unwrap();
        assert!(dirty_entry.dirty);
        let nobase_entry = report
            .entries
            .iter()
            .find(|e| e.category == "cow_shadow" && e.agent_id.as_deref() == Some("agy-nobase"))
            .unwrap();
        assert!(nobase_entry.dirty);

        // 2. Dry-run default (`apply = false`, `older_than_days = 7`): deletes NOTHING, estimates only old exited session.
        let dry = run_gc_plan(&GcOptions {
            runtime_dir: runtime_dir.clone(),
            older_than_days: 7,
            include_shadows: false,
            force_dirty: false,
            compact_vaults: false,
            apply: false,
            json: false,
        })
        .await
        .unwrap();
        assert!(dry.dry_run);
        assert_eq!(dry.reclaimed_bytes, 0);
        assert!(dry.reclaimable_bytes >= 900);
        assert!(ses_old.exists());
        assert!(clean_offline_dir.join("home/cargo_target").exists());

        // 3. Apply with `older_than_days = 7`, `include_shadows = false`: only old exited session deleted.
        let age_gated = run_gc_plan(&GcOptions {
            runtime_dir: runtime_dir.clone(),
            older_than_days: 7,
            include_shadows: false,
            force_dirty: false,
            compact_vaults: false,
            apply: true,
            json: false,
        })
        .await
        .unwrap();
        assert!(!ses_old.exists());
        assert!(ses_recent.exists(), "recent exited session must respect age threshold");
        assert!(ses_running.exists(), "running session must never be pruned");
        assert!(
            clean_offline_dir.join("home/cargo_target").exists(),
            "0d old offline cache must respect --older-than-days 7"
        );
        assert!(age_gated.reclaimed_bytes >= 900);

        // 4. Apply with `older_than_days = 0`, `include_shadows = true`, `force_dirty = false`:
        // Reclaims offline caches + recent exited session + CLEAN shadow, preserves live agent, BOTH dirty shadows, keys, and external target!
        let gc_clean = run_gc_plan(&GcOptions {
            runtime_dir: runtime_dir.clone(),
            older_than_days: 0,
            include_shadows: true,
            force_dirty: false,
            compact_vaults: false,
            apply: true,
            json: false,
        })
        .await
        .unwrap();
        assert!(!clean_offline_dir.join("home/cargo_target").exists());
        assert!(!clean_offline_dir.join("home/deps/cache").exists());
        assert!(!clean_offline_dir.join("home/tmp").exists());
        assert!(!clean_offline_dir.join("home/bg_jobs").exists());
        assert!(!clean_offline_dir.join("cow_workspace").exists());
        assert!(!dirty_offline_dir.join("home/deps/cache").exists());
        assert!(!ses_recent.exists());
        // Preserved items:
        assert!(live_agent_dir.join("home/cargo_target/live.rlib").exists());
        assert!(live_agent_dir.join("home/tmp/scratch.txt").exists());
        assert!(live_agent_dir.join("cow_workspace/upper_workspace/src/lib.rs").exists());
        assert!(dirty_offline_dir.join("cow_workspace/upper_workspace/README.md").exists());
        assert!(nobase_dirty_dir.join("cow_workspace/upper_workspace/unsaved.txt").exists());
        assert!(ses_running.exists());
        assert!(runtime_dir.join("keys/master.key").exists());
        assert!(runtime_dir.join("policy_state.json").exists());
        assert!(runtime_dir.join("vaults/personal.vault.json").exists());
        assert!(runtime_dir.join("sessions/radar/state.json").exists());
        assert!(external_dir.join("big.bin").exists());
        assert!(
            gc_clean
                .warnings
                .iter()
                .any(|w| w.contains("vault recover --from-agent agy-dirty")),
            "expected recovery warning in {:?}",
            gc_clean.warnings
        );

        // 5. Force dirty removes dirty offline shadows too while still preserving live agent and keys.
        let gc_forced = run_gc_plan(&GcOptions {
            runtime_dir: runtime_dir.clone(),
            older_than_days: 0,
            include_shadows: true,
            force_dirty: true,
            compact_vaults: false,
            apply: true,
            json: false,
        })
        .await
        .unwrap();
        assert!(!dirty_offline_dir.join("cow_workspace").exists());
        assert!(!nobase_dirty_dir.join("cow_workspace").exists());
        assert!(live_agent_dir.join("cow_workspace/upper_workspace/src/lib.rs").exists());
        assert!(external_dir.join("big.bin").exists());
        assert!(gc_forced.reclaimed_bytes >= 80);
    }

    #[tokio::test]
    async fn org_shared_cache_preserved_while_org_has_live_agent_and_reclaimed_when_all_offline() {
        let root_tmp = tempfile::tempdir().unwrap();
        let runtime_dir = root_tmp.path().join(".aegis");
        let external_dir = root_tmp.path().join("external_host_data");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        write_bytes(&external_dir.join("big.bin"), 65536, b'E');

        // Org `acme` has one live agent (via running session), one offline agent, and shared_cache.
        let acme_shared_cargo = runtime_dir.join("orgs/acme/shared_cache/cargo_target");
        let acme_shared_deps = runtime_dir.join("orgs/acme/shared_cache/deps/cache");
        write_bytes(&acme_shared_cargo.join("shared.rlib"), 2048, b'S');
        write_bytes(&acme_shared_deps.join("pnpm-store/pkg.tgz"), 512, b'D');
        #[cfg(unix)]
        std::os::unix::fs::symlink(&external_dir, acme_shared_cargo.join("ext_link")).unwrap();

        let acme_offline_cache = runtime_dir.join("orgs/acme/agents/agy-off/home/cargo_target");
        write_bytes(&acme_offline_cache.join("old.rlib"), 1000, b'O');

        // Org `idle-org` has no `agents/` directory at all, only `shared_cache`.
        let idle_shared_cargo = runtime_dir.join("orgs/idle-org/shared_cache/cargo_target");
        write_bytes(&idle_shared_cargo.join("stale.rlib"), 1500, b'I');

        let now_ms = chrono::Utc::now().timestamp_millis();
        let ses_live = runtime_dir.join("sessions/ses_acme_live");
        std::fs::create_dir_all(&ses_live).unwrap();
        std::fs::write(
            ses_live.join("session.json"),
            serde_json::json!({
                "status": "running",
                "org_id": "acme",
                "agent_id": "agy-live",
                "updated_at_ms": now_ms
            })
            .to_string(),
        )
        .unwrap();

        // 1. Analyze disk report: shared caches accounted in `agent_cache_bytes` without double-counting or following symlinks.
        let report = analyze_runtime_disk(&runtime_dir).await.unwrap();
        assert!(report.live_agents.contains(&"acme/agy-live".to_string()));
        assert_eq!(report.agent_cache_bytes, 2048 + 512 + 1000 + 1500);
        assert!(report.host_ssd_bytes < 32 * 1024);
        let acme_shared_entry = report
            .entries
            .iter()
            .find(|e| e.category == "org_shared_cache" && e.path == acme_shared_cargo)
            .unwrap();
        assert_eq!(acme_shared_entry.org_id.as_deref(), Some("acme"));
        assert_eq!(acme_shared_entry.agent_id, None);
        assert!(acme_shared_entry.live);
        assert!(!acme_shared_entry.reclaimable);

        // 2. While `acme/agy-live` is live: offline agent cache and `idle-org` shared cache are reclaimed,
        //    while `acme/shared_cache/{cargo_target,deps/cache}` are preserved via `skip_live`.
        let gc_live = run_gc_plan(&GcOptions {
            runtime_dir: runtime_dir.clone(),
            older_than_days: 0,
            include_shadows: false,
            force_dirty: false,
            compact_vaults: false,
            apply: true,
            json: false,
        })
        .await
        .unwrap();
        assert!(!acme_offline_cache.exists());
        assert!(!idle_shared_cargo.exists());
        assert!(acme_shared_cargo.join("shared.rlib").exists());
        assert!(acme_shared_deps.join("pnpm-store/pkg.tgz").exists());
        assert!(
            gc_live.actions.iter().any(|a| {
                a.kind == "skip_live"
                    && a.category == "org_shared_cache"
                    && a.path == acme_shared_cargo
            }),
            "expected skip_live action for org shared_cache, got: {:?}",
            gc_live.actions
        );

        // 3. Mark `acme/agy-live` offline: recent shared cache respects `older_than_days = 7` (`skip_recent`),
        //    and is reclaimed once `older_than_days = 0`.
        std::fs::write(
            ses_live.join("session.json"),
            serde_json::json!({
                "status": "exited",
                "org_id": "acme",
                "agent_id": "agy-live",
                "updated_at_ms": now_ms
            })
            .to_string(),
        )
        .unwrap();

        let gc_recent = run_gc_plan(&GcOptions {
            runtime_dir: runtime_dir.clone(),
            older_than_days: 7,
            include_shadows: false,
            force_dirty: false,
            compact_vaults: false,
            apply: true,
            json: false,
        })
        .await
        .unwrap();
        assert!(acme_shared_cargo.exists());
        assert!(gc_recent.actions.iter().any(|a| {
            a.kind == "skip_recent"
                && a.category == "org_shared_cache"
                && a.path == acme_shared_cargo
        }));

        let gc_offline = run_gc_plan(&GcOptions {
            runtime_dir: runtime_dir.clone(),
            older_than_days: 0,
            include_shadows: false,
            force_dirty: false,
            compact_vaults: false,
            apply: true,
            json: false,
        })
        .await
        .unwrap();
        assert!(!acme_shared_cargo.exists());
        assert!(!acme_shared_deps.exists());
        assert!(external_dir.join("big.bin").exists());
        assert!(gc_offline.reclaimed_bytes >= 2048 + 512);
        assert!(gc_offline.actions.iter().any(|a| {
            a.kind == "remove_dir"
                && a.category == "org_shared_cache"
                && a.path == acme_shared_cargo
                && a.applied
        }));
    }

    #[tokio::test]
    async fn gc_compact_vaults_error_warns_without_aborting_rest_of_gc() {
        let root_tmp = tempfile::tempdir().unwrap();
        let runtime_dir = root_tmp.path().join(".aegis");
        let sparse = runtime_dir.join("vaults/acme.sparsebundle");
        write_bytes(&sparse.join("Info.plist"), 128, b'P');

        let offline_tmp = runtime_dir.join("orgs/acme/agents/agy-1/home/tmp");
        write_bytes(&offline_tmp.join("junk.bin"), 1024, b'J');

        let report = run_gc_plan(&GcOptions {
            runtime_dir: runtime_dir.clone(),
            older_than_days: 0,
            include_shadows: false,
            force_dirty: false,
            compact_vaults: true,
            apply: true,
            json: false,
        })
        .await
        .unwrap();

        assert!(
            !offline_tmp.exists(),
            "regular GC must proceed even if vault compaction fails"
        );
        assert!(report.reclaimed_bytes >= 1024);
        #[cfg(target_os = "macos")]
        {
            assert!(
                report
                    .warnings
                    .iter()
                    .any(|w| w.contains("Could not compact vault 'acme'")),
                "expected compact warning, got: {:?}",
                report.warnings
            );
            assert!(report.actions.iter().any(|a| {
                a.kind == "compact_vault" && a.category == "vault" && !a.applied
            }));
        }
    }
}
