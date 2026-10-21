//! Aegis OS Transactional Copy-on-Write File System & Organization CAS Storage (`aos-vfs`)
//!
//! Provides:
//! 1. `CoWWorkspace`: A persistent shadow workspace per Agent with:
//!    - macOS APFS `clonefile(2)` zero-copy block cloning (and fallback copy on other filesystems)
//!    - Instant snapshots (`create_snapshot`), diffs (`diff`), and rollbacks (`rollback`)
//!    - Multi-Agent 3-Way Merge Engine (`commit_to_host`) that safely merges concurrent changes
//!      from multiple Agents (`agy`, `claude`, `codex`) or detects overlapping line conflicts.
//! 2. `OrgCasAndKvStore`: Disk-synchronized Organization Content-Addressable Storage
//!    (`artifact://<org>/sha256:<hash>`) and versioned KV store for multi-agent collaboration.

use aos_core::{
    AgentIdentity, ArtifactMeta, DiffChangeType, FileDiffEntry, OrgKvEntry, OrgSharedStorage,
    RefreshReport, SnapshotMeta, TransactionalWorkspace,
};
use anyhow::{bail, Context};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

// ============================================================================
// 1. Copy-on-Write Shadow Workspace Implementation (with APFS clonefile & 3-Way Merge)
// ============================================================================

pub struct CoWWorkspace {
    host_source_root: PathBuf,
    shadow_root: PathBuf,
    baseline_root: PathBuf,
    snapshots_root: PathBuf,
    snapshots_index_file: PathBuf,
    snapshots: Arc<RwLock<Vec<SnapshotMeta>>>,
}

/// Files whose mtime is within this window of the moment they were cloned are compared by content
/// rather than by metadata (see `CoWWorkspace::same_fingerprint`).
const RACY_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// A host mutation computed during Phase 1 of `workspace_commit` and applied in Phase 2.
enum StagedCommitAction {
    CloneFromShadow {
        rel: String,
        shadow_path: PathBuf,
    },
    WriteMerged {
        rel: String,
        shadow_path: PathBuf,
        merged_content: String,
    },
    DeleteFile {
        rel: String,
    },
}

impl CoWWorkspace {
    /// Initialize or resume a Copy-on-Write shadow workspace from `host_source_root` inside `runtime_workspace_base`.
    pub async fn init(
        host_source_root: impl AsRef<Path>,
        runtime_workspace_base: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        let host_source_root = host_source_root.as_ref().to_path_buf();
        let base = runtime_workspace_base.as_ref().to_path_buf();
        let shadow_root = base.join("upper_workspace");
        let baseline_root = base.join("baseline_snapshot");
        let snapshots_root = base.join("snapshots");
        let snapshots_index_file = base.join("snapshots.json");
        let init_marker = base.join(".initialized");

        tokio::fs::create_dir_all(&snapshots_root).await?;

        let is_existing = init_marker.exists() && shadow_root.exists() && baseline_root.exists();
        if !is_existing {
            tokio::fs::create_dir_all(&shadow_root).await?;
            tokio::fs::create_dir_all(&baseline_root).await?;
            Self::cow_sync_dir(&host_source_root, &shadow_root).await?;
            Self::cow_sync_dir(&shadow_root, &baseline_root).await?;
            tokio::fs::write(&init_marker, Utc::now().to_rfc3339()).await?;
        }

        let mut loaded_snapshots = Vec::new();
        if let Ok(bytes) = tokio::fs::read(&snapshots_index_file).await {
            if let Ok(parsed) = serde_json::from_slice::<Vec<SnapshotMeta>>(&bytes) {
                loaded_snapshots = parsed;
            }
        }

        let ws = Self {
            host_source_root,
            shadow_root,
            baseline_root,
            snapshots_root,
            snapshots_index_file,
            snapshots: Arc::new(RwLock::new(loaded_snapshots)),
        };

        if !is_existing {
            ws.create_snapshot("baseline-init").await?;
        }
        Ok(ws)
    }

    /// Applies the actions staged by Phase 1 of a commit to the host tree and the baseline.
    async fn apply_staged_actions(
        &self,
        staged_actions: Vec<StagedCommitAction>,
    ) -> anyhow::Result<Vec<String>> {
        let mut committed = Vec::new();
        for action in staged_actions {
            match action {
                StagedCommitAction::CloneFromShadow { rel, shadow_path } => {
                    let host_dst = self.host_source_root.join(&rel);
                    let base_path = self.baseline_root.join(&rel);
                    if let Some(parent) = host_dst.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    if let Some(parent) = base_path.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    Self::cow_clone_file(&shadow_path, &host_dst).await?;
                    // Ensure host file mtime is bumped to `now` even when APFS `clonefile(2)`
                    // preserves the older shadow edit timestamp, so Cargo/build systems detect changes.
                    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&host_dst) {
                        let _ = f.set_modified(std::time::SystemTime::now());
                    }
                    Self::cow_clone_file(&shadow_path, &base_path).await?;
                    committed.push(rel);
                }
                StagedCommitAction::WriteMerged {
                    rel,
                    shadow_path,
                    merged_content,
                } => {
                    let host_dst = self.host_source_root.join(&rel);
                    let base_path = self.baseline_root.join(&rel);
                    if let Some(parent) = host_dst.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    if let Some(parent) = base_path.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    tokio::fs::write(&host_dst, &merged_content).await?;
                    tokio::fs::write(&base_path, &merged_content).await?;
                    tokio::fs::write(&shadow_path, &merged_content).await?;
                    committed.push(rel);
                }
                StagedCommitAction::DeleteFile { rel } => {
                    let host_dst = self.host_source_root.join(&rel);
                    let base_path = self.baseline_root.join(&rel);
                    if host_dst.exists() {
                        tokio::fs::remove_file(&host_dst).await?;
                    }
                    if base_path.exists() {
                        tokio::fs::remove_file(&base_path).await?;
                    }
                    committed.push(rel);
                }
            }
        }

        Ok(committed)
    }

    /// Aborts a commit whose Phase 1 found a conflict. Normally nothing has touched the host yet;
    /// under the `prevalidate` ablation the actions staged so far are applied first, modelling a
    /// commit that writes as it goes and leaves a half-applied batch behind.
    async fn fail_commit(
        &self,
        staged_actions: Vec<StagedCommitAction>,
        err: anyhow::Error,
    ) -> anyhow::Result<Vec<String>> {
        if aos_core::ablated("prevalidate") {
            let _ = self.apply_staged_actions(staged_actions).await;
        }
        Err(err)
    }

    async fn flush_snapshots(&self) -> anyhow::Result<()> {
        let list = self.snapshots.read().await.clone();
        let bytes = serde_json::to_vec_pretty(&list)?;
        tokio::fs::write(&self.snapshots_index_file, bytes).await?;
        Ok(())
    }

    async fn clone_into(src: &Path, dst: &Path) -> anyhow::Result<()> {
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        Self::cow_clone_file(src, dst).await
    }

    /// True when `a` and `clone_side` are provably unchanged copies of one another, judged from
    /// metadata alone (no content is read).
    ///
    /// Clones preserve the source mtime (see `cow_clone_file`), so a file nobody has edited since
    /// the copy was made keeps an identical size and mtime. `clone_side` must be the file that was
    /// created *by* the clone (baseline, shadow or snapshot copy): its ctime is the moment of the
    /// clone and cannot be set back by an ordinary write.
    ///
    /// Timestamps have a granularity (a kernel tick, or whole seconds on some filesystems), so an
    /// edit that lands in the same tick as the original mtime would leave size and mtime unchanged.
    /// Like git's "racily clean" rule, equality is therefore only trusted when the mtime predates
    /// the clone by more than [`RACY_WINDOW`]; younger files are compared by content instead.
    fn same_fingerprint(a: &Path, clone_side: &Path) -> bool {
        let (Ok(x), Ok(y)) = (std::fs::metadata(a), std::fs::metadata(clone_side)) else {
            return false;
        };
        if x.len() != y.len() {
            return false;
        }
        let (Ok(m1), Ok(m2)) = (x.modified(), y.modified()) else {
            return false;
        };
        if m1 != m2 {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let Ok(mtime) = m2.duration_since(std::time::UNIX_EPOCH) else {
                return false;
            };
            let ctime = std::time::Duration::new(y.ctime().max(0) as u64, y.ctime_nsec() as u32);
            mtime + RACY_WINDOW < ctime
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    fn touch_mtime(path: &Path) {
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) {
            let _ = f.set_modified(std::time::SystemTime::now());
        }
    }

    /// Relative paths whose shadow content differs from this Agent's baseline, i.e. exactly the set a
    /// `workspace_commit` would touch (unlike `diff()`, which compares against the live host tree and
    /// therefore also reports files that *peers* changed on the host).
    pub async fn changed_since_baseline(&self) -> anyhow::Result<Vec<String>> {
        let base: BTreeMap<String, PathBuf> =
            Self::collect_files(&self.baseline_root).await?.into_iter().collect();
        let shadow: BTreeMap<String, PathBuf> =
            Self::collect_files(&self.shadow_root).await?.into_iter().collect();
        let mut out = Vec::new();
        for (rel, sp) in &shadow {
            match base.get(rel) {
                None => out.push(rel.clone()),
                Some(bp) => {
                    if Self::same_fingerprint(sp, bp) {
                        continue;
                    }
                    if tokio::fs::read(sp).await? != tokio::fs::read(bp).await? {
                        out.push(rel.clone());
                    }
                }
            }
        }
        for rel in base.keys() {
            if !shadow.contains_key(rel) {
                out.push(rel.clone());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Rebases this Agent's shadow onto the *current* host tree so long-lived identities never work on
    /// stale code:
    /// - host changed, agent did not touch the file  -> fast-forward shadow + baseline (and bump shadow mtime)
    /// - host changed, agent changed it too          -> 3-way merge host changes into the shadow
    ///   (base = baseline, theirs = host, ours = shadow), then advance baseline to host
    /// - overlapping edits / binary / delete-vs-modify -> left untouched and reported as conflicts
    ///   (the eventual `workspace_commit` will surface them precisely)
    pub async fn refresh_from_host(&self) -> anyhow::Result<RefreshReport> {
        let host: BTreeMap<String, PathBuf> =
            Self::collect_files(&self.host_source_root).await?.into_iter().collect();
        let base: BTreeMap<String, PathBuf> =
            Self::collect_files(&self.baseline_root).await?.into_iter().collect();
        let shadow: BTreeMap<String, PathBuf> =
            Self::collect_files(&self.shadow_root).await?.into_iter().collect();
        let mut report = RefreshReport::default();

        for (rel, host_path) in &host {
            // Host unchanged since our baseline: nothing to rebase, and no need to read anything.
            if let Some(base_path) = base.get(rel) {
                if Self::same_fingerprint(host_path, base_path) {
                    continue;
                }
            }
            let host_bytes = tokio::fs::read(host_path).await?;
            let shadow_dst = self.shadow_root.join(rel);
            let base_dst = self.baseline_root.join(rel);
            let shadow_bytes = match shadow.get(rel) {
                Some(p) => Some(tokio::fs::read(p).await?),
                None => None,
            };
            match base.get(rel) {
                Some(base_path) => {
                    let base_bytes = tokio::fs::read(base_path).await?;
                    if base_bytes == host_bytes {
                        continue; // host unchanged since our baseline
                    }
                    match shadow_bytes {
                        Some(sb) if sb == base_bytes => {
                            Self::clone_into(host_path, &shadow_dst).await?;
                            Self::touch_mtime(&shadow_dst);
                            Self::clone_into(host_path, &base_dst).await?;
                            report.fast_forwarded.push(rel.clone());
                        }
                        Some(sb) if sb == host_bytes => {
                            Self::clone_into(host_path, &base_dst).await?;
                            report.merged.push(rel.clone());
                        }
                        Some(sb) => {
                            let merged = match (
                                std::str::from_utf8(&base_bytes),
                                std::str::from_utf8(&host_bytes),
                                std::str::from_utf8(&sb),
                            ) {
                                (Ok(b), Ok(h), Ok(s)) => match Self::three_way_merge_lines(b, h, s) {
                                    Ok(m) => Ok(m),
                                    Err(err) => Err(format!("{}: {}", rel, err)),
                                },
                                _ => Err(format!(
                                    "{}: Binary file concurrently modified on host and in shadow",
                                    rel
                                )),
                            };
                            match merged {
                                Ok(m) => {
                                    tokio::fs::write(&shadow_dst, m).await?;
                                    Self::touch_mtime(&shadow_dst);
                                    Self::clone_into(host_path, &base_dst).await?;
                                    report.merged.push(rel.clone());
                                }
                                Err(detail) => {
                                    report.conflicts.push(rel.clone());
                                    report.conflict_details.push(detail);
                                }
                            }
                        }
                        None => {
                            report.conflicts.push(rel.clone());
                            report.conflict_details.push(format!(
                                "{}: Deleted in shadow workspace but modified on host",
                                rel
                            ));
                        }
                    }
                }
                None => match shadow_bytes {
                    None => {
                        Self::clone_into(host_path, &shadow_dst).await?;
                        Self::touch_mtime(&shadow_dst);
                        Self::clone_into(host_path, &base_dst).await?;
                        report.added_from_host.push(rel.clone());
                    }
                    Some(sb) if sb == host_bytes => {
                        Self::clone_into(host_path, &base_dst).await?;
                        report.merged.push(rel.clone());
                    }
                    Some(_) => {
                        report.conflicts.push(rel.clone());
                        report.conflict_details.push(format!(
                            "{}: Independently added on host and in shadow with different content",
                            rel
                        ));
                    }
                },
            }
        }

        for (rel, base_path) in &base {
            if host.contains_key(rel) {
                continue;
            }
            // Deleted on host since our baseline.
            match shadow.get(rel) {
                None => {
                    let _ = tokio::fs::remove_file(base_path).await;
                    report.removed_from_host.push(rel.clone());
                }
                Some(sp) => {
                    if tokio::fs::read(sp).await? == tokio::fs::read(base_path).await? {
                        let _ = tokio::fs::remove_file(sp).await;
                        let _ = tokio::fs::remove_file(base_path).await;
                        report.removed_from_host.push(rel.clone());
                    } else {
                        report.conflicts.push(rel.clone());
                        report.conflict_details.push(format!(
                            "{}: Deleted on host but modified in shadow workspace",
                            rel
                        ));
                    }
                }
            }
        }
        Ok(report)
    }

    /// Clones a single file using zero-copy OS copy-on-write syscalls:
    /// - macOS (APFS): `libc::clonefile(src, dst, 0)`
    /// - Linux (Btrfs / XFS / OCFS2): `libc::ioctl(dst_fd, FICLONE, src_fd)` (`0x40049409`)
    /// Falls back transparently to `tokio::fs::copy` if across filesystems or on non-CoW mounts.
    pub async fn cow_clone_file(src: &Path, dst: &Path) -> anyhow::Result<()> {
        if dst.exists() {
            let _ = tokio::fs::remove_file(dst).await;
        }
        #[cfg(target_os = "macos")]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            if let (Ok(c_src), Ok(c_dst)) = (
                CString::new(src.as_os_str().as_bytes()),
                CString::new(dst.as_os_str().as_bytes()),
            ) {
                // `clonefile(src, dst, 0)` performs an instant APFS Copy-on-Write clone
                let rc = unsafe { libc::clonefile(c_src.as_ptr(), c_dst.as_ptr(), 0) };
                if rc == 0 {
                    return Ok(());
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            use std::collections::HashSet;
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::io::AsRawFd;
            use std::sync::{LazyLock, Mutex};
            // Linux `FICLONE` ioctl request code (`_IOW(0x94, 9, int)` = 0x40049409)
            const FICLONE: libc::c_ulong = 0x40049409;
            // Source/destination device pairs on which reflink cloning is known to be unavailable
            // (`EOPNOTSUPP` on ext4/tmpfs, `EXDEV` across filesystems). Remembering them avoids
            // paying a failed open/truncate/ioctl round-trip for every file before falling back to
            // a plain copy, which made non-reflink filesystems up to 3x slower than `cp -R`.
            static NO_REFLINK: LazyLock<Mutex<HashSet<(u64, u64)>>> =
                LazyLock::new(|| Mutex::new(HashSet::new()));

            let dev_pair = match (std::fs::metadata(src), dst.parent().map(std::fs::metadata)) {
                (Ok(s), Some(Ok(d))) => Some((s.dev(), d.dev())),
                _ => None,
            };
            let known_unavailable = dev_pair
                .map(|p| NO_REFLINK.lock().map(|g| g.contains(&p)).unwrap_or(false))
                .unwrap_or(false);

            if !known_unavailable {
                if let Ok(src_file) = std::fs::File::open(src) {
                    if let Ok(dst_file) = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(dst)
                    {
                        if let Ok(meta) = src_file.metadata() {
                            let _ = dst_file.set_permissions(meta.permissions());
                        }
                        let rc = unsafe {
                            libc::ioctl(dst_file.as_raw_fd(), FICLONE, src_file.as_raw_fd())
                        };
                        if rc == 0 {
                            // Unlike APFS `clonefile`, a fresh `FICLONE` target gets mtime = now.
                            // Carry the source's mtime over so unchanged files keep an identical
                            // (size, mtime) fingerprint and `diff` can skip reading them.
                            if let Ok(m) = src_file.metadata().and_then(|m| m.modified()) {
                                let _ = dst_file.set_modified(m);
                            }
                            return Ok(());
                        }
                        let errno = std::io::Error::last_os_error().raw_os_error();
                        if matches!(
                            errno,
                            Some(libc::EOPNOTSUPP) | Some(libc::EXDEV) | Some(libc::ENOTTY)
                        ) {
                            if let (Some(pair), Ok(mut guard)) = (dev_pair, NO_REFLINK.lock()) {
                                if guard.insert(pair) {
                                    eprintln!(
                                        "[aos-vfs] WARNING: reflink (FICLONE) unavailable between {} and {} \
                                         (errno {:?}); falling back to full file copies. Place the runtime \
                                         directory on btrfs/XFS(reflink) to restore copy-on-write cloning.",
                                        src.display(),
                                        dst.display(),
                                        errno
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::fs::copy(src, dst).await?;
        // Plain copies get mtime = now; keep the source's so unchanged files stay fingerprint-equal.
        if let Ok(m) = std::fs::metadata(src).and_then(|m| m.modified()) {
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(dst) {
                let _ = f.set_modified(m);
            }
        }
        Ok(())
    }

    fn is_ignored_dir_name(name: &str) -> bool {
        matches!(
            name,
            ".aegis_os"
                | ".git"
                | "target"
                | "node_modules"
                | ".gemini"
                | ".next"
                | "dist"
                | "build"
                | ".venv"
                | "venv"
                | "__pycache__"
                | ".dart_tool"
                | "Pods"
                | ".gradle"
                | ".cache"
                | ".nexus"
                | ".agents"
                | ".turbo"
                | "coverage"
        )
    }

    fn contains_ignored_subdir(dir: &Path, max_depth: usize) -> bool {
        if max_depth == 0 {
            return false;
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            return false;
        };
        for entry in rd.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if Self::is_ignored_dir_name(&name_str) {
                return true;
            }
            if max_depth > 1
                && entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false)
                && Self::contains_ignored_subdir(&entry.path(), max_depth - 1)
            {
                return true;
            }
        }
        false
    }

    /// Clones an entire directory tree using macOS APFS directory-level `clonefile(2)` in a single
    /// atomic kernel metadata operation (O(1) time & zero disk blocks) while automatically skipping
    /// heavy build/VCS directories (`.git`, `target`, `node_modules`, `.aegis_os`, `.gemini`).
    pub async fn cow_sync_dir(src: &Path, dst: &Path) -> anyhow::Result<()> {
        if dst.exists() {
            tokio::fs::remove_dir_all(dst).await?;
        }
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        #[cfg(target_os = "macos")]
        if !Self::contains_ignored_subdir(src, 1) {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            if let (Ok(c_src), Ok(c_dst)) = (
                CString::new(src.as_os_str().as_bytes()),
                CString::new(dst.as_os_str().as_bytes()),
            ) {
                let rc = unsafe { libc::clonefile(c_src.as_ptr(), c_dst.as_ptr(), 0) };
                if rc == 0 {
                    return Ok(());
                }
            }
        }

        tokio::fs::create_dir_all(dst).await?;
        let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
        while let Some((cur_src, cur_dst)) = stack.pop() {
            let mut rd = tokio::fs::read_dir(&cur_src).await?;
            while let Some(entry) = rd.next_entry().await? {
                let name = entry.file_name().to_string_lossy().to_string();
                if Self::is_ignored_dir_name(&name) {
                    continue;
                }
                let entry_src = entry.path();
                let entry_dst = cur_dst.join(&name);
                let ft = entry.file_type().await?;
                if ft.is_dir() {
                    #[cfg(target_os = "macos")]
                    if !Self::contains_ignored_subdir(&entry_src, 1) {
                        use std::ffi::CString;
                        use std::os::unix::ffi::OsStrExt;
                        if let (Ok(c_src), Ok(c_dst)) = (
                            CString::new(entry_src.as_os_str().as_bytes()),
                            CString::new(entry_dst.as_os_str().as_bytes()),
                        ) {
                            if unsafe { libc::clonefile(c_src.as_ptr(), c_dst.as_ptr(), 0) } == 0 {
                                continue;
                            }
                        }
                    }
                    tokio::fs::create_dir_all(&entry_dst).await?;
                    stack.push((entry_src, entry_dst));
                } else if ft.is_file() {
                    Self::cow_clone_file(&entry_src, &entry_dst).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn collect_files(root: &Path) -> anyhow::Result<Vec<(String, PathBuf)>> {
        // Walk the whole tree in one blocking task. Doing this with `tokio::fs` costs a thread-pool
        // hop per directory entry (~60 us each), which dominated `diff`/`refresh`/`commit` on large
        // trees even though the underlying syscalls take microseconds.
        let root = root.to_path_buf();
        tokio::task::spawn_blocking(move || Self::collect_files_blocking(&root)).await?
    }

    fn collect_files_blocking(root: &Path) -> anyhow::Result<Vec<(String, PathBuf)>> {
        let mut results = Vec::new();
        if !root.exists() {
            return Ok(results);
        }
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if Self::is_ignored_dir_name(&name) {
                    continue;
                }
                let ft = entry.file_type()?;
                if ft.is_dir() {
                    stack.push(path);
                } else if ft.is_file() {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    results.push((rel, path));
                }
            }
        }
        results.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(results)
    }

    fn sha256_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Returns true if `sub` appears in order as a line-by-line subsequence of `sup`.
    fn is_subsequence(sub: &[&str], sup: &[&str]) -> bool {
        if sub.is_empty() {
            return true;
        }
        if sub.len() > sup.len() {
            return false;
        }
        let mut si = 0usize;
        for &line in sup {
            if line == sub[si] {
                si += 1;
                if si == sub.len() {
                    return true;
                }
            }
        }
        false
    }

    /// Computes edit hunks transforming `base` lines into `target` lines via Longest Common Subsequence (LCS).
    /// Each hunk represents replacing `base[base_start..base_end]` with `replacement`.
    fn compute_lcs_diff_hunks<'a>(
        base: &[&'a str],
        target: &[&'a str],
    ) -> Vec<(usize, usize, Vec<&'a str>)> {
        let n = base.len();
        let m = target.len();
        let mut dp = vec![vec![0usize; m + 1]; n + 1];
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                if base[i] == target[j] {
                    dp[i][j] = 1 + dp[i + 1][j + 1];
                } else {
                    dp[i][j] = dp[i + 1][j].max(dp[i][j + 1]);
                }
            }
        }

        let mut anchors = Vec::new();
        let (mut i, mut j) = (0usize, 0usize);
        while i < n && j < m {
            if base[i] == target[j] {
                anchors.push((i, j));
                i += 1;
                j += 1;
            } else if dp[i + 1][j] >= dp[i][j + 1] {
                i += 1;
            } else {
                j += 1;
            }
        }
        anchors.push((n, m));

        let mut hunks = Vec::new();
        let mut prev_b = 0usize;
        let mut prev_t = 0usize;
        for (curr_b, curr_t) in anchors {
            if curr_b > prev_b || curr_t > prev_t {
                hunks.push((prev_b, curr_b, target[prev_t..curr_t].to_vec()));
            }
            prev_b = curr_b + 1;
            prev_t = curr_t + 1;
        }
        hunks
    }

    /// Performs a general LCS/Diff3 3-Way Merge between:
    /// - `base`: The baseline file content when this Agent's CoW workspace was initialized
    /// - `theirs` (`host_current`): The current file content on the host (potentially modified by another Agent!)
    /// - `ours` (`shadow_new`): The modified file content inside this Agent's CoW shadow workspace
    ///
    /// Supports arbitrary non-overlapping line insertions, deletions, and replacements.
    pub fn three_way_merge_lines(
        base: &str,
        theirs: &str,
        ours: &str,
    ) -> Result<String, String> {
        if theirs == base {
            return Ok(ours.to_string());
        }
        if ours == base || ours == theirs {
            return Ok(theirs.to_string());
        }

        let base_lines: Vec<&str> = base.lines().collect();
        let their_lines: Vec<&str> = theirs.lines().collect();
        let our_lines: Vec<&str> = ours.lines().collect();

        let their_hunks = Self::compute_lcs_diff_hunks(&base_lines, &their_lines);
        let our_hunks = Self::compute_lcs_diff_hunks(&base_lines, &our_lines);

        let mut merged: Vec<&str> = Vec::new();
        let mut b_pos = 0usize;
        let mut ti = 0usize;
        let mut oi = 0usize;

        while ti < their_hunks.len() || oi < our_hunks.len() {
            match (their_hunks.get(ti), our_hunks.get(oi)) {
                (Some(th), None) => {
                    merged.extend_from_slice(&base_lines[b_pos..th.0]);
                    merged.extend_from_slice(&th.2);
                    b_pos = th.1;
                    ti += 1;
                }
                (None, Some(oh)) => {
                    merged.extend_from_slice(&base_lines[b_pos..oh.0]);
                    merged.extend_from_slice(&oh.2);
                    b_pos = oh.1;
                    oi += 1;
                }
                (Some(th), Some(oh)) => {
                    // Check if `th` is strictly before `oh` without overlapping
                    let th_before_oh = if th.0 == th.1 && oh.0 == oh.1 {
                        th.0 < oh.0
                    } else {
                        th.1 <= oh.0 && (th.0 < oh.0 || th.1 < oh.1)
                    };
                    let oh_before_th = if th.0 == th.1 && oh.0 == oh.1 {
                        oh.0 < th.0
                    } else {
                        oh.1 <= th.0 && (oh.0 < th.0 || oh.1 < th.1)
                    };

                    if th_before_oh {
                        merged.extend_from_slice(&base_lines[b_pos..th.0]);
                        merged.extend_from_slice(&th.2);
                        b_pos = th.1;
                        ti += 1;
                    } else if oh_before_th {
                        merged.extend_from_slice(&base_lines[b_pos..oh.0]);
                        merged.extend_from_slice(&oh.2);
                        b_pos = oh.1;
                        oi += 1;
                    } else if th.0 == oh.0 && th.1 == oh.1 && th.2 == oh.2 {
                        // Identical change in both `theirs` and `ours` (False conflict)
                        merged.extend_from_slice(&base_lines[b_pos..th.0]);
                        merged.extend_from_slice(&th.2);
                        b_pos = th.1;
                        ti += 1;
                        oi += 1;
                    } else if th.0 == oh.0
                        && th.1 == oh.1
                        && !th.2.is_empty()
                        && Self::is_subsequence(&th.2, &oh.2)
                    {
                        // Superset merge: `ours` already incorporates all lines of `theirs` in order plus additions
                        merged.extend_from_slice(&base_lines[b_pos..oh.0]);
                        merged.extend_from_slice(&oh.2);
                        b_pos = oh.1;
                        ti += 1;
                        oi += 1;
                    } else if th.0 == oh.0
                        && th.1 == oh.1
                        && !oh.2.is_empty()
                        && Self::is_subsequence(&oh.2, &th.2)
                    {
                        // Superset merge: `theirs` already incorporates all lines of `ours` in order plus additions
                        merged.extend_from_slice(&base_lines[b_pos..th.0]);
                        merged.extend_from_slice(&th.2);
                        b_pos = th.1;
                        ti += 1;
                        oi += 1;
                    } else {
                        let conflict_line = th.0.min(oh.0) + 1;
                        return Err(format!(
                            "3-Way Merge Conflict at line {}: Host has `{}`, Agent Shadow has `{}`",
                            conflict_line,
                            th.2.join("\\n"),
                            oh.2.join("\\n")
                        ));
                    }
                }
                (None, None) => break,
            }
        }

        if b_pos < base_lines.len() {
            merged.extend_from_slice(&base_lines[b_pos..]);
        }

        let mut result = merged.join("\n");
        if ours.ends_with('\n') || theirs.ends_with('\n') {
            result.push('\n');
        }
        Ok(result)
    }
}

#[async_trait]
impl TransactionalWorkspace for CoWWorkspace {
    fn shadow_root(&self) -> &Path {
        &self.shadow_root
    }

    fn host_source_root(&self) -> &Path {
        &self.host_source_root
    }

    async fn create_snapshot(&self, label: &str) -> anyhow::Result<SnapshotMeta> {
        let snapshot_id = format!("snap-{}", &Uuid::new_v4().to_string()[..8]);
        let snap_dir = self.snapshots_root.join(&snapshot_id);
        Self::cow_sync_dir(&self.shadow_root, &snap_dir).await?;

        let files = Self::collect_files(&snap_dir).await?;
        let meta = SnapshotMeta {
            snapshot_id: snapshot_id.clone(),
            label: label.to_string(),
            created_at_ms: Utc::now().timestamp_millis(),
            file_count: files.len(),
        };

        self.snapshots.write().await.push(meta.clone());
        self.flush_snapshots().await?;
        Ok(meta)
    }

    async fn list_snapshots(&self) -> anyhow::Result<Vec<SnapshotMeta>> {
        Ok(self.snapshots.read().await.clone())
    }

    async fn diff(&self, snapshot_id: Option<&str>) -> anyhow::Result<Vec<FileDiffEntry>> {
        let base_dir = if let Some(id) = snapshot_id {
            let dir = self.snapshots_root.join(id);
            if !dir.exists() {
                bail!("Snapshot '{}' not found", id);
            }
            dir
        } else {
            self.host_source_root.clone()
        };

        let base_files: BTreeMap<String, PathBuf> =
            Self::collect_files(&base_dir).await?.into_iter().collect();
        let current_files: BTreeMap<String, PathBuf> = Self::collect_files(&self.shadow_root)
            .await?
            .into_iter()
            .collect();

        let mut diffs = Vec::new();

        let fast_meta_skip = current_files.len() > 500;
        for (rel, cur_path) in &current_files {
            if let Some(base_path) = base_files.get(rel) {
                if fast_meta_skip && Self::same_fingerprint(base_path, cur_path) {
                    continue;
                }
            }
            let cur_bytes = tokio::fs::read(cur_path).await?;
            match base_files.get(rel) {
                None => {
                    let preview = String::from_utf8(cur_bytes.clone()).ok().map(|s| {
                        format!(
                            "+++ {}\n{}",
                            rel,
                            s.lines()
                                .take(20)
                                .map(|l| format!("+ {}", l))
                                .collect::<Vec<_>>()
                                .join("\n")
                        )
                    });
                    diffs.push(FileDiffEntry {
                        relative_path: rel.clone(),
                        change_type: DiffChangeType::Added,
                        old_size: None,
                        new_size: Some(cur_bytes.len() as u64),
                        preview_diff: preview,
                    });
                }
                Some(base_path) => {
                    let base_bytes = tokio::fs::read(base_path).await?;
                    if Self::sha256_bytes(&base_bytes) != Self::sha256_bytes(&cur_bytes) {
                        let preview = match (
                            String::from_utf8(base_bytes.clone()),
                            String::from_utf8(cur_bytes.clone()),
                        ) {
                            (Ok(old_str), Ok(new_str)) => Some(format!(
                                "--- a/{rel}\n+++ b/{rel}\n- {}\n+ {}",
                                old_str.lines().next().unwrap_or(""),
                                new_str.lines().next().unwrap_or("")
                            )),
                            _ => None,
                        };
                        diffs.push(FileDiffEntry {
                            relative_path: rel.clone(),
                            change_type: DiffChangeType::Modified,
                            old_size: Some(base_bytes.len() as u64),
                            new_size: Some(cur_bytes.len() as u64),
                            preview_diff: preview,
                        });
                    }
                }
            }
        }

        for (rel, base_path) in &base_files {
            if !current_files.contains_key(rel) {
                let meta = tokio::fs::metadata(base_path).await?;
                diffs.push(FileDiffEntry {
                    relative_path: rel.clone(),
                    change_type: DiffChangeType::Deleted,
                    old_size: Some(meta.len()),
                    new_size: None,
                    preview_diff: Some(format!("--- a/{}\n(deleted)", rel)),
                });
            }
        }

        Ok(diffs)
    }

    async fn rollback(&self, snapshot_id: &str) -> anyhow::Result<()> {
        let snap_dir = self.snapshots_root.join(snapshot_id);
        if !snap_dir.exists() {
            bail!("Snapshot '{}' does not exist", snapshot_id);
        }
        Self::cow_sync_dir(&snap_dir, &self.shadow_root).await?;
        Ok(())
    }

    async fn changed_since_baseline(&self) -> anyhow::Result<Vec<String>> {
        CoWWorkspace::changed_since_baseline(self).await
    }

    async fn refresh_from_host(&self) -> anyhow::Result<RefreshReport> {
        CoWWorkspace::refresh_from_host(self).await
    }

    async fn commit_to_host(&self, filter_paths: Option<Vec<String>>) -> anyhow::Result<Vec<String>> {
        self.commit_to_host_with_options(filter_paths, false).await
    }

    async fn commit_to_host_with_options(
        &self,
        filter_paths: Option<Vec<String>>,
        overwrite_binaries: bool,
    ) -> anyhow::Result<Vec<String>> {
        // First auto-rebase onto the current host tree so any files modified by peers that this
        // Agent did NOT touch (including regenerated binary artifacts) are fast-forwarded automatically.
        let _ = self.refresh_from_host().await?;

        // Compute diff relative to this Agent's own `baseline_root` so we only touch files this Agent actually changed!
        let base_files: BTreeMap<String, PathBuf> = Self::collect_files(&self.baseline_root)
            .await?
            .into_iter()
            .collect();
        let shadow_files: BTreeMap<String, PathBuf> = Self::collect_files(&self.shadow_root)
            .await?
            .into_iter()
            .collect();

        let mut staged_actions = Vec::new();

        // Phase 1: Validate all Added & Modified files and compute 3-Way Merges before mutating any host file
        for (rel, shadow_path) in &shadow_files {
            if let Some(ref allow_list) = filter_paths {
                if !allow_list.iter().any(|p| p == rel) {
                    continue;
                }
            }

            // The agent never touched this file (same fingerprint as its baseline copy).
            if let Some(base_path) = base_files.get(rel) {
                if Self::same_fingerprint(shadow_path, base_path) {
                    continue;
                }
            }
            let shadow_bytes = tokio::fs::read(shadow_path).await?;
            let host_dst = self.host_source_root.join(rel);

            match base_files.get(rel) {
                None => {
                    if host_dst.exists() {
                        let host_bytes = tokio::fs::read(&host_dst).await?;
                        if Self::sha256_bytes(&host_bytes) != Self::sha256_bytes(&shadow_bytes) {
                            let is_binary = std::str::from_utf8(&host_bytes).is_err()
                                || std::str::from_utf8(&shadow_bytes).is_err();
                            if is_binary && overwrite_binaries {
                                staged_actions.push(StagedCommitAction::CloneFromShadow {
                                    rel: rel.clone(),
                                    shadow_path: shadow_path.clone(),
                                });
                                continue;
                            }
                            return self
                                .fail_commit(
                                    staged_actions,
                                    anyhow::anyhow!(
                                        "3-Way Merge Conflict on newly added file '{}': file was also independently created on host{}",
                                        rel,
                                        if is_binary {
                                            " (pass `overwrite_binaries: true` to overwrite binary artifact, or `paths` to commit source files first)"
                                        } else {
                                            ""
                                        }
                                    ),
                                )
                                .await;
                        }
                    }
                    staged_actions.push(StagedCommitAction::CloneFromShadow {
                        rel: rel.clone(),
                        shadow_path: shadow_path.clone(),
                    });
                }
                Some(existing_base_path) => {
                    let base_bytes = tokio::fs::read(existing_base_path).await?;
                    if Self::sha256_bytes(&base_bytes) == Self::sha256_bytes(&shadow_bytes) {
                        continue;
                    }

                    if host_dst.exists() {
                        let host_bytes = tokio::fs::read(&host_dst).await?;
                        if Self::sha256_bytes(&host_bytes) != Self::sha256_bytes(&base_bytes)
                            && Self::sha256_bytes(&host_bytes) != Self::sha256_bytes(&shadow_bytes)
                            && !aos_core::ablated("merge")
                        {
                            match (
                                std::str::from_utf8(&base_bytes),
                                std::str::from_utf8(&host_bytes),
                                std::str::from_utf8(&shadow_bytes),
                            ) {
                                (Ok(base_str), Ok(their_str), Ok(our_str)) => {
                                    match Self::three_way_merge_lines(base_str, their_str, our_str) {
                                        Ok(merged_str) => {
                                            staged_actions.push(StagedCommitAction::WriteMerged {
                                                rel: rel.clone(),
                                                shadow_path: shadow_path.clone(),
                                                merged_content: merged_str,
                                            });
                                            continue;
                                        }
                                        Err(conflict_err) => {
                                            return self
                                                .fail_commit(
                                                    staged_actions,
                                                    anyhow::anyhow!("Conflict on '{}': {}", rel, conflict_err),
                                                )
                                                .await;
                                        }
                                    }
                                }
                                _ => {
                                    if overwrite_binaries {
                                        staged_actions.push(StagedCommitAction::CloneFromShadow {
                                            rel: rel.clone(),
                                            shadow_path: shadow_path.clone(),
                                        });
                                        continue;
                                    }
                                    return self
                                        .fail_commit(
                                            staged_actions,
                                            anyhow::anyhow!(
                                                "Binary file concurrent modification conflict on '{}': modified in both host and shadow workspace (pass `overwrite_binaries: true` to overwrite with shadow binary, or `paths` to commit specific source files first)",
                                                rel
                                            ),
                                        )
                                        .await;
                                }
                            }
                        }
                    }

                    staged_actions.push(StagedCommitAction::CloneFromShadow {
                        rel: rel.clone(),
                        shadow_path: shadow_path.clone(),
                    });
                }
            }
        }

        for (rel, _) in &base_files {
            if !shadow_files.contains_key(rel) {
                if let Some(ref allow_list) = filter_paths {
                    if !allow_list.iter().any(|p| p == rel) {
                        continue;
                    }
                }
                staged_actions.push(StagedCommitAction::DeleteFile { rel: rel.clone() });
            }
        }

        // Phase 2: All conflicts cleared; apply staged actions atomically across the commit batch
        self.apply_staged_actions(staged_actions).await
    }
}

// ============================================================================
// 2. Organization Shared CAS & Versioned KV Store
// ============================================================================

#[derive(Default, Serialize, Deserialize)]
struct PersistedOrgStoreIndex {
    artifacts: HashMap<String, Vec<ArtifactMeta>>,
    kv_store: HashMap<String, OrgKvEntry>,
}

pub struct OrgCasAndKvStore {
    storage_root: PathBuf,
    index_file: PathBuf,
    artifacts: Arc<RwLock<HashMap<String, Vec<ArtifactMeta>>>>,
    kv_store: Arc<RwLock<HashMap<String, OrgKvEntry>>>,
}

impl OrgCasAndKvStore {
    pub async fn new(storage_root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = storage_root.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&root).await?;
        let index_file = root.join("org_store_index.json");

        let mut initial = PersistedOrgStoreIndex::default();
        if let Ok(bytes) = tokio::fs::read(&index_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedOrgStoreIndex>(&bytes) {
                initial = parsed;
            }
        }

        Ok(Self {
            storage_root: root,
            index_file,
            artifacts: Arc::new(RwLock::new(initial.artifacts)),
            kv_store: Arc::new(RwLock::new(initial.kv_store)),
        })
    }

    async fn reload_from_disk(&self) {
        if let Ok(bytes) = tokio::fs::read(&self.index_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedOrgStoreIndex>(&bytes) {
                *self.artifacts.write().await = parsed.artifacts;
                *self.kv_store.write().await = parsed.kv_store;
            }
        }
    }

    async fn flush_to_disk(&self) -> anyhow::Result<()> {
        let state = PersistedOrgStoreIndex {
            artifacts: self.artifacts.read().await.clone(),
            kv_store: self.kv_store.read().await.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&state)?;
        tokio::fs::write(&self.index_file, bytes).await?;
        Ok(())
    }

    fn org_cas_dir(&self, org_id: &str) -> PathBuf {
        self.storage_root.join(org_id).join("cas")
    }
}

#[async_trait]
impl OrgSharedStorage for OrgCasAndKvStore {
    async fn publish_artifact(
        &self,
        identity: &AgentIdentity,
        name: &str,
        content: &[u8],
        content_type: &str,
        metadata: serde_json::Value,
    ) -> anyhow::Result<ArtifactMeta> {
        self.reload_from_disk().await;
        let mut hasher = Sha256::new();
        hasher.update(content);
        let sha256 = hex::encode(hasher.finalize());

        let cas_dir = self.org_cas_dir(&identity.org_id);
        tokio::fs::create_dir_all(&cas_dir).await?;
        let blob_path = cas_dir.join(&sha256);
        if !blob_path.exists() {
            tokio::fs::write(&blob_path, content).await?;
        }

        let uri = format!("artifact://{}/sha256:{}", identity.org_id, sha256);
        let meta = ArtifactMeta {
            uri: uri.clone(),
            sha256,
            name: name.to_string(),
            org_id: identity.org_id.clone(),
            publisher_agent_id: identity.agent_id.clone(),
            size_bytes: content.len() as u64,
            content_type: content_type.to_string(),
            metadata,
            created_at_ms: Utc::now().timestamp_millis(),
        };

        self.artifacts
            .write()
            .await
            .entry(identity.org_id.clone())
            .or_default()
            .push(meta.clone());

        self.flush_to_disk().await?;
        Ok(meta)
    }

    async fn fetch_artifact(
        &self,
        identity: &AgentIdentity,
        uri_or_hash: &str,
    ) -> anyhow::Result<(ArtifactMeta, Vec<u8>)> {
        self.reload_from_disk().await;
        let target_hash = if let Some(rest) = uri_or_hash.strip_prefix("artifact://") {
            let parts: Vec<&str> = rest.splitn(2, '/').collect();
            if parts.len() != 2 {
                bail!("Invalid artifact URI format: {}", uri_or_hash);
            }
            let uri_org = parts[0];
            if uri_org != identity.org_id {
                bail!(
                    "Cross-organization artifact fetch denied: '{}' != '{}'",
                    uri_org,
                    identity.org_id
                );
            }
            parts[1].strip_prefix("sha256:").unwrap_or(parts[1])
        } else {
            uri_or_hash.strip_prefix("sha256:").unwrap_or(uri_or_hash)
        };

        let meta = {
            let org_artifacts = self.artifacts.read().await;
            let list = org_artifacts
                .get(&identity.org_id)
                .context("No artifacts found for organization")?;
            list.iter()
                .find(|a| a.sha256 == target_hash)
                .cloned()
                .with_context(|| {
                    format!(
                        "Artifact '{}' not found in org '{}'",
                        target_hash, identity.org_id
                    )
                })?
        };

        let blob_path = self.org_cas_dir(&identity.org_id).join(&meta.sha256);
        let bytes = tokio::fs::read(&blob_path).await?;
        Ok((meta, bytes))
    }

    async fn list_artifacts(&self, org_id: &str) -> anyhow::Result<Vec<ArtifactMeta>> {
        self.reload_from_disk().await;
        let org_artifacts = self.artifacts.read().await;
        Ok(org_artifacts.get(org_id).cloned().unwrap_or_default())
    }

    async fn kv_put(
        &self,
        identity: &AgentIdentity,
        namespace: &str,
        key: &str,
        value: serde_json::Value,
        expected_version: Option<u64>,
    ) -> anyhow::Result<OrgKvEntry> {
        self.reload_from_disk().await;
        let composite_key = format!("{}::{}::{}", identity.org_id, namespace, key);
        let entry = {
            let mut store = self.kv_store.write().await;
            let next_version = match store.get(&composite_key) {
                Some(existing) => {
                    if let Some(exp) = expected_version {
                        if existing.version != exp {
                            bail!(
                                "CAS version mismatch on key '{}/{}': expected v{}, found v{}",
                                namespace,
                                key,
                                exp,
                                existing.version
                            );
                        }
                    }
                    existing.version + 1
                }
                None => {
                    if let Some(exp) = expected_version {
                        if exp != 0 {
                            bail!(
                                "CAS version mismatch on new key '{}/{}': expected v{}, but key does not exist",
                                namespace,
                                key,
                                exp
                            );
                        }
                    }
                    1
                }
            };

            let entry = OrgKvEntry {
                namespace: namespace.to_string(),
                key: key.to_string(),
                value,
                version: next_version,
                updated_by_agent: identity.agent_id.clone(),
                updated_at_ms: Utc::now().timestamp_millis(),
            };
            store.insert(composite_key, entry.clone());
            entry
        };

        self.flush_to_disk().await?;
        Ok(entry)
    }

    async fn kv_get(
        &self,
        org_id: &str,
        namespace: &str,
        key: &str,
    ) -> anyhow::Result<Option<OrgKvEntry>> {
        self.reload_from_disk().await;
        let composite_key = format!("{}::{}::{}", org_id, namespace, key);
        let store = self.kv_store.read().await;
        Ok(store.get(&composite_key).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Backdates `path`'s mtime so that it counts as "old" for the racy-timestamp rule.
    fn age(path: &Path, secs: u64) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(secs))
            .unwrap();
    }

    /// The metadata fast path must skip genuinely unchanged files but never hide a real edit,
    /// including an edit that keeps the file size identical.
    #[tokio::test]
    async fn test_fingerprint_fast_path_skips_unchanged_but_not_same_size_edits() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("host");
        std::fs::create_dir_all(&host).unwrap();
        for name in ["keep.txt", "edit.txt"] {
            std::fs::write(host.join(name), "AAAA\n").unwrap();
            age(&host.join(name), 3600);
        }
        let ws = CoWWorkspace::init(&host, tmp.path().join("rt")).await.unwrap();

        // Untouched shadow file: same size + mtime as its baseline copy, and old enough to trust.
        assert!(CoWWorkspace::same_fingerprint(
            &ws.shadow_root.join("keep.txt"),
            &ws.baseline_root.join("keep.txt"),
        ));

        // Same-length rewrite (the case a size-only check would miss).
        std::fs::write(ws.shadow_root.join("edit.txt"), "BBBB\n").unwrap();
        assert!(!CoWWorkspace::same_fingerprint(
            &ws.shadow_root.join("edit.txt"),
            &ws.baseline_root.join("edit.txt"),
        ));

        let changed = ws.changed_since_baseline().await.unwrap();
        assert_eq!(changed, vec!["edit.txt".to_string()]);
    }

    /// A file modified within the racy window of its clone is compared by content, not metadata.
    #[tokio::test]
    async fn test_fingerprint_racy_young_files_fall_back_to_content() {
        let tmp = tempfile::tempdir().unwrap();
        let host = tmp.path().join("host");
        std::fs::create_dir_all(&host).unwrap();
        std::fs::write(host.join("young.txt"), "AAAA\n").unwrap(); // mtime = now
        let ws = CoWWorkspace::init(&host, tmp.path().join("rt")).await.unwrap();
        assert!(!CoWWorkspace::same_fingerprint(
            &ws.shadow_root.join("young.txt"),
            &ws.baseline_root.join("young.txt"),
        ));
        std::fs::write(ws.shadow_root.join("young.txt"), "BBBB\n").unwrap();
        assert_eq!(
            ws.changed_since_baseline().await.unwrap(),
            vec!["young.txt".to_string()]
        );
    }

    #[tokio::test]
    async fn test_refresh_from_host_fast_forwards_merges_and_reports_conflicts() {
        let host = tempfile::tempdir().unwrap();
        let rt = tempfile::tempdir().unwrap();
        let h = host.path();
        std::fs::write(h.join("untouched.rs"), "a\nb\nc\n").unwrap();
        std::fs::write(h.join("both.rs"), "l1\nl2\nl3\nl4\nl5\n").unwrap();
        std::fs::write(h.join("clash.rs"), "x = 1\n").unwrap();
        std::fs::write(h.join("gone.rs"), "bye\n").unwrap();
        let ws = CoWWorkspace::init(h, rt.path().join("cow")).await.unwrap();

        // Agent edits (in its shadow).
        std::fs::write(ws.shadow_root().join("both.rs"), "l1\nl2\nl3\nl4\nAGENT\n").unwrap();
        std::fs::write(ws.shadow_root().join("clash.rs"), "x = 2\n").unwrap();
        // Peer commits on the host meanwhile.
        std::fs::write(h.join("untouched.rs"), "a\nB\nc\n").unwrap();
        std::fs::write(h.join("both.rs"), "PEER\nl2\nl3\nl4\nl5\n").unwrap();
        std::fs::write(h.join("clash.rs"), "x = 3\n").unwrap();
        std::fs::write(h.join("new.rs"), "fresh\n").unwrap();
        std::fs::remove_file(h.join("gone.rs")).unwrap();

        assert_eq!(ws.changed_since_baseline().await.unwrap(), vec!["both.rs", "clash.rs"]);
        let r = ws.refresh_from_host().await.unwrap();
        assert_eq!(r.fast_forwarded, vec!["untouched.rs"]);
        assert_eq!(r.merged, vec!["both.rs"]);
        assert_eq!(r.added_from_host, vec!["new.rs"]);
        assert_eq!(r.removed_from_host, vec!["gone.rs"]);
        assert_eq!(r.conflicts, vec!["clash.rs"]);

        let s = |p: &str| std::fs::read_to_string(ws.shadow_root().join(p)).unwrap();
        assert_eq!(s("untouched.rs"), "a\nB\nc\n");
        assert_eq!(s("both.rs"), "PEER\nl2\nl3\nl4\nAGENT\n");
        assert_eq!(s("clash.rs"), "x = 2\n", "conflicting agent edit preserved");
        assert!(!ws.shadow_root().join("gone.rs").exists());
        // After the rebase only the agent's genuine edits remain to be committed.
        assert_eq!(ws.changed_since_baseline().await.unwrap(), vec!["both.rs", "clash.rs"]);
        // Idempotent.
        assert_eq!(ws.refresh_from_host().await.unwrap().total_updates(), 0);
    }

    #[tokio::test]
    async fn test_cow_workspace_snapshot_rollback_and_commit() {
        let temp = tempfile::tempdir().unwrap();
        let host_dir = temp.path().join("host_project");
        let runtime_dir = temp.path().join("runtime_cow");

        tokio::fs::create_dir_all(&host_dir).await.unwrap();
        tokio::fs::write(host_dir.join("README.md"), "v1 original\n")
            .await
            .unwrap();

        let ws = CoWWorkspace::init(&host_dir, &runtime_dir).await.unwrap();

        tokio::fs::write(ws.shadow_root().join("README.md"), "v2 modified by agent\n")
            .await
            .unwrap();
        tokio::fs::write(ws.shadow_root().join("src.rs"), "fn main() {}\n")
            .await
            .unwrap();

        let host_content = tokio::fs::read_to_string(host_dir.join("README.md"))
            .await
            .unwrap();
        assert_eq!(host_content, "v1 original\n");

        let diffs = ws.diff(None).await.unwrap();
        assert_eq!(diffs.len(), 2);

        let snap_v2 = ws.create_snapshot("after-feature").await.unwrap();
        tokio::fs::remove_file(ws.shadow_root().join("src.rs"))
            .await
            .unwrap();
        assert!(!ws.shadow_root().join("src.rs").exists());

        ws.rollback(&snap_v2.snapshot_id).await.unwrap();
        assert!(ws.shadow_root().join("src.rs").exists());

        let committed = ws.commit_to_host(None).await.unwrap();
        assert_eq!(committed.len(), 2);
        let host_after_commit = tokio::fs::read_to_string(host_dir.join("README.md"))
            .await
            .unwrap();
        assert_eq!(host_after_commit, "v2 modified by agent\n");
    }

    #[tokio::test]
    async fn test_apfs_clone_and_three_way_merge() {
        let temp = tempfile::tempdir().unwrap();
        let host_dir = temp.path().join("shared_repo");
        tokio::fs::create_dir_all(&host_dir).await.unwrap();
        tokio::fs::write(
            host_dir.join("config.toml"),
            "port = 8080\nworkers = 4\ntimeout = 30\n",
        )
        .await
        .unwrap();

        // Both Agent A (`agy`) and Agent B (`claude`) initialize CoW workspaces from the same baseline
        let ws_agy = CoWWorkspace::init(&host_dir, temp.path().join("cow_agy"))
            .await
            .unwrap();
        let ws_claude = CoWWorkspace::init(&host_dir, temp.path().join("cow_claude"))
            .await
            .unwrap();

        // Agent A (`agy`) updates line 1 (`port = 9090`) and commits to host
        tokio::fs::write(
            ws_agy.shadow_root().join("config.toml"),
            "port = 9090\nworkers = 4\ntimeout = 30\n",
        )
        .await
        .unwrap();
        ws_agy.commit_to_host(None).await.unwrap();

        // Agent B (`claude`) updates line 3 (`timeout = 120`) in its CoW workspace and commits to host
        // Without 3-way merge, Agent B would overwrite `port = 9090` back to `8080`!
        tokio::fs::write(
            ws_claude.shadow_root().join("config.toml"),
            "port = 8080\nworkers = 4\ntimeout = 120\n",
        )
        .await
        .unwrap();
        ws_claude.commit_to_host(None).await.unwrap();

        // Verify host has BOTH changes cleanly merged!
        let merged_host = tokio::fs::read_to_string(host_dir.join("config.toml"))
            .await
            .unwrap();
        assert_eq!(merged_host, "port = 9090\nworkers = 4\ntimeout = 120\n");

        // Now test overlapping conflict detection: if a third Agent C modified line 1 to `port = 7070` from old baseline
        let ws_codex = CoWWorkspace::init(&host_dir, temp.path().join("cow_codex"))
            .await
            .unwrap();
        // Simulate concurrent host modification on line 1 while codex also changes line 1
        tokio::fs::write(
            host_dir.join("config.toml"),
            "port = 9999\nworkers = 4\ntimeout = 120\n",
        )
        .await
        .unwrap();
        tokio::fs::write(
            ws_codex.shadow_root().join("config.toml"),
            "port = 7070\nworkers = 4\ntimeout = 120\n",
        )
        .await
        .unwrap();

        let conflict_res = ws_codex.commit_to_host(None).await;
        assert!(conflict_res.is_err());
        assert!(conflict_res
            .unwrap_err()
            .to_string()
            .contains("3-Way Merge Conflict at line 1"));

        // Verify LCS Diff3 multi-line insertion + deletion + modification across unequal line counts!
        let base_src = "fn a() {\n    let x = 1;\n}\nfn b() {\n    let y = 2;\n}\n";
        let their_src = "fn a() {\n    // inserted comment 1\n    // inserted comment 2\n    let x = 10;\n}\nfn b() {\n    let y = 2;\n}\n";
        let our_src = "fn a() {\n    let x = 1;\n}\nfn b() {\n    let y = 20;\n    let z = 30;\n}\n";
        let merged_src = CoWWorkspace::three_way_merge_lines(base_src, their_src, our_src).unwrap();
        assert_eq!(
            merged_src,
            "fn a() {\n    // inserted comment 1\n    // inserted comment 2\n    let x = 10;\n}\nfn b() {\n    let y = 20;\n    let z = 30;\n}\n"
        );
    }

    #[tokio::test]
    async fn test_org_cas_artifact_sharing_and_tenant_isolation() {
        let temp = tempfile::tempdir().unwrap();
        let store = OrgCasAndKvStore::new(temp.path()).await.unwrap();

        let researcher = AgentIdentity::new("org-alpha", "researcher-1", "Data Researcher");
        let coder = AgentIdentity::new("org-alpha", "coder-1", "Rust Developer");
        let outsider = AgentIdentity::new("org-beta", "spy-1", "Outsider");

        let meta = store
            .publish_artifact(
                &researcher,
                "market_report.json",
                b"{\"signal\": \"bullish\"}",
                "application/json",
                json!({"confidence": 0.95}),
            )
            .await
            .unwrap();

        let (fetched_meta, bytes) = store.fetch_artifact(&coder, &meta.uri).await.unwrap();
        assert_eq!(fetched_meta.name, "market_report.json");
        assert_eq!(bytes, b"{\"signal\": \"bullish\"}");

        assert!(store.fetch_artifact(&outsider, &meta.uri).await.is_err());
    }

    #[tokio::test]
    async fn test_binary_fast_forward_and_overwrite_binaries_option() {
        let temp = tempfile::tempdir().unwrap();
        let host_dir = temp.path().join("shared_repo");
        tokio::fs::create_dir_all(&host_dir).await.unwrap();
        tokio::fs::write(host_dir.join("main.tex"), "line1\nline2\n")
            .await
            .unwrap();
        // Simulated binary PDF artifact (invalid UTF-8 bytes)
        tokio::fs::write(host_dir.join("main.pdf"), &[0xffu8, 0xd8, 0x00, 0x01])
            .await
            .unwrap();

        let ws_a = CoWWorkspace::init(&host_dir, temp.path().join("cow_a"))
            .await
            .unwrap();
        let ws_b = CoWWorkspace::init(&host_dir, temp.path().join("cow_b"))
            .await
            .unwrap();

        // Agent A modifies main.tex AND regenerates main.pdf, then commits to host
        tokio::fs::write(ws_a.shadow_root().join("main.tex"), "PEER_A\nline2\n")
            .await
            .unwrap();
        tokio::fs::write(ws_a.shadow_root().join("main.pdf"), &[0xffu8, 0xd8, 0x00, 0x02])
            .await
            .unwrap();
        ws_a.commit_to_host(None).await.unwrap();

        // Case 1: Agent B ONLY modifies line 2 of main.tex (did NOT touch main.pdf).
        // When Agent B commits, main.pdf is automatically fast-forwarded from host without conflict!
        tokio::fs::write(ws_b.shadow_root().join("main.tex"), "line1\nPEER_B\n")
            .await
            .unwrap();
        let committed_b = ws_b.commit_to_host(None).await.unwrap();
        assert_eq!(committed_b, vec!["main.tex"]);
        assert_eq!(
            tokio::fs::read_to_string(host_dir.join("main.tex"))
                .await
                .unwrap(),
            "PEER_A\nPEER_B\n"
        );
        assert_eq!(
            tokio::fs::read(ws_b.shadow_root().join("main.pdf"))
                .await
                .unwrap(),
            vec![0xffu8, 0xd8, 0x00, 0x02]
        );

        // Case 2: Both Host and Agent B modify main.pdf concurrently
        tokio::fs::write(host_dir.join("main.pdf"), &[0xffu8, 0xd8, 0x00, 0x03])
            .await
            .unwrap();
        tokio::fs::write(ws_b.shadow_root().join("main.pdf"), &[0xffu8, 0xd8, 0x00, 0x04])
            .await
            .unwrap();

        let err = ws_b
            .commit_to_host_with_options(None, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("main.pdf"));
        assert!(err.contains("overwrite_binaries: true"));

        let ok_committed = ws_b
            .commit_to_host_with_options(None, true)
            .await
            .unwrap();
        assert_eq!(ok_committed, vec!["main.pdf"]);
        assert_eq!(
            tokio::fs::read(host_dir.join("main.pdf")).await.unwrap(),
            vec![0xffu8, 0xd8, 0x00, 0x04]
        );
    }
}
