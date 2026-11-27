//! Shared security primitives for Aegis OS (Single Source of Truth).
//!
//! Centralizes constant-time comparisons, outbound SSRF IP filtering, `.env*` & `.git/` red-line
//! path checks, atomic private `0o700` directory creation, and test-only nested sandbox path
//! stripping so security guards across crates cannot drift.

use std::ffi::OsStr;
use std::io::{self, Read as _, Write as _};
use std::net::IpAddr;
use std::path::Path;

/// Constant-time exact byte slice comparison. Rejects empty or unequal-length slices.
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.is_empty() || a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Constant-time exact string comparison. Rejects empty or unequal-length strings.
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    ct_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// Constant-time ASCII case-insensitive comparison for hexadecimal HMAC/SHA-256 digests.
/// Rejects empty or unequal-length strings.
pub fn ct_eq_hex(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.is_empty() || a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b)
        .fold(0u8, |acc, (x, y)| {
            acc | (x.to_ascii_lowercase() ^ y.to_ascii_lowercase())
        })
        == 0
}

/// Returns `true` for loopback, private RFC1918, CGNAT, link-local / cloud metadata, ULA,
/// unspecified, multicast, or IPv4-mapped equivalents that untrusted outbound traffic
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

/// Returns `true` when `file_name` names a dotenv secret file (case-insensitive), allowing
/// non-secret templates (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.schema`).
pub fn is_dotenv_secret_filename(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    (lower == ".env" || lower.starts_with(".env."))
        && !matches!(
            lower.as_str(),
            ".env.example" | ".env.sample" | ".env.template" | ".env.dist" | ".env.schema"
        )
}

/// Returns `true` when `path` targets a dotenv secret file (case-insensitive across separators).
pub fn is_dotenv_secret_path(path: &str) -> bool {
    let norm = path.trim().replace('\\', "/");
    let trimmed = norm.trim_end_matches('/');
    let file_name = trimmed.rsplit('/').next().unwrap_or("");
    is_dotenv_secret_filename(file_name)
}

/// Returns `true` when any path segment equals `.git` (case-insensitive, e.g. `.git`,
/// `.git/config`, `sub/.GIT/hooks/pre-commit`).
pub fn is_git_internal_path(path: &str) -> bool {
    let norm = path.trim().replace('\\', "/").to_ascii_lowercase();
    norm.split('/').any(|seg| seg == ".git")
}

/// Creates a private directory with mode `0o700` atomically on Unix (refusing to follow a symlink
/// at `path`).
pub fn create_private_dir_0700(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("refusing symlink at private directory '{}'", path.display()),
                ));
            }
            if !meta.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "non-directory exists at private directory '{}'",
                        path.display()
                    ),
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            }
            return Ok(());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("unsafe entry created at '{}'", path.display()),
                ));
            }
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

fn extract_normal_segments(rel: &Path) -> io::Result<Vec<&OsStr>> {
    let mut segs = Vec::new();
    for comp in rel.components() {
        match comp {
            std::path::Component::Normal(seg) => segs.push(seg),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "relative path '{}' must contain only normal path segments",
                        rel.display()
                    ),
                ));
            }
        }
    }
    if segs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative path must not be empty",
        ));
    }
    Ok(segs)
}

#[cfg(unix)]
mod unix_anchored {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn to_cstring(s: &OsStr) -> io::Result<CString> {
        CString::new(s.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "path segment contains interior NUL byte",
            )
        })
    }

    fn open_dir_anchored(
        root: &Path,
        dir_segments: &[&OsStr],
        create_missing: bool,
    ) -> io::Result<OwnedFd> {
        let c_root = to_cstring(root.as_os_str())?;
        // SAFETY: `c_root` is a NUL-terminated path and flags open an existing directory FD.
        let root_raw = unsafe {
            libc::open(
                c_root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `root_raw` is a newly opened valid file descriptor.
        let mut cur_fd = unsafe { OwnedFd::from_raw_fd(root_raw) };

        for seg in dir_segments {
            let c_seg = to_cstring(seg)?;
            let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            // SAFETY: `cur_fd` is a valid directory FD and `c_seg` is a NUL-terminated segment.
            let mut next_raw = unsafe { libc::openat(cur_fd.as_raw_fd(), c_seg.as_ptr(), flags) };
            if next_raw < 0 {
                let err = io::Error::last_os_error();
                if create_missing && err.raw_os_error() == Some(libc::ENOENT) {
                    // SAFETY: `cur_fd` is a valid directory FD and `c_seg` is a NUL-terminated segment.
                    let mk = unsafe { libc::mkdirat(cur_fd.as_raw_fd(), c_seg.as_ptr(), 0o755) };
                    if mk < 0 {
                        let mk_err = io::Error::last_os_error();
                        if mk_err.raw_os_error() != Some(libc::EEXIST) {
                            return Err(mk_err);
                        }
                    }
                    // SAFETY: retry opening the newly created directory segment with O_NOFOLLOW.
                    next_raw = unsafe { libc::openat(cur_fd.as_raw_fd(), c_seg.as_ptr(), flags) };
                }
            }
            if next_raw < 0 {
                let err = io::Error::last_os_error();
                if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "refusing symlink or non-directory segment '{}' under '{}'",
                            seg.to_string_lossy(),
                            root.display()
                        ),
                    ));
                }
                return Err(err);
            }
            // SAFETY: `next_raw` is a newly opened valid directory FD.
            cur_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
        }

        Ok(cur_fd)
    }

    pub(super) fn write_file(root: &Path, segs: &[&OsStr], bytes: &[u8]) -> io::Result<()> {
        let (dir_segments, leaf) = segs.split_at(segs.len() - 1);
        let parent_fd = open_dir_anchored(root, dir_segments, true)?;
        let c_leaf = to_cstring(leaf[0])?;

        // SAFETY: `st` is initialized before inspection on success.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `parent_fd` is a valid directory FD and `c_leaf` is NUL-terminated.
        let stat_rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                c_leaf.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        let mode: libc::c_uint = if stat_rc == 0 {
            if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing to overwrite symlink or non-regular file",
                ));
            }
            libc::c_uint::from(st.st_mode & 0o777)
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                0o644
            } else {
                return Err(err);
            }
        };

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!(".aegis-tmp-{}-{}-{}", std::process::id(), seq, nanos);
        let c_tmp = to_cstring(OsStr::new(&tmp_name))?;

        // SAFETY: `parent_fd` is a valid directory FD, `c_tmp` is NUL-terminated, and `mode`
        // is passed as `libc::c_uint` for C variadic promotion soundness on ARM64 macOS.
        let tmp_raw = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                c_tmp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if tmp_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `tmp_raw` is a newly created valid file descriptor.
        let mut file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(tmp_raw) });

        if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            drop(file);
            // SAFETY: best-effort cleanup of temp sibling inside `parent_fd`.
            unsafe {
                libc::unlinkat(parent_fd.as_raw_fd(), c_tmp.as_ptr(), 0);
            }
            return Err(err);
        }
        drop(file);

        // Re-check destination before rename so a concurrent swap to a symlink is refused.
        // SAFETY: `parent_fd` is valid and `c_leaf` is NUL-terminated.
        let mut st_after: libc::stat = unsafe { std::mem::zeroed() };
        let after_rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                c_leaf.as_ptr(),
                &mut st_after,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if after_rc == 0 {
            if (st_after.st_mode & libc::S_IFMT) != libc::S_IFREG {
                // SAFETY: cleanup staged temp sibling inside `parent_fd`.
                unsafe {
                    libc::unlinkat(parent_fd.as_raw_fd(), c_tmp.as_ptr(), 0);
                }
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing to overwrite symlink or non-regular file",
                ));
            }
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                // SAFETY: cleanup staged temp sibling inside `parent_fd`.
                unsafe {
                    libc::unlinkat(parent_fd.as_raw_fd(), c_tmp.as_ptr(), 0);
                }
                return Err(err);
            }
        }

        // SAFETY: both `c_tmp` and `c_leaf` reside inside the anchored `parent_fd`.
        if unsafe {
            libc::renameat(
                parent_fd.as_raw_fd(),
                c_tmp.as_ptr(),
                parent_fd.as_raw_fd(),
                c_leaf.as_ptr(),
            )
        } < 0
        {
            let err = io::Error::last_os_error();
            // SAFETY: cleanup staged temp sibling on rename failure.
            unsafe {
                libc::unlinkat(parent_fd.as_raw_fd(), c_tmp.as_ptr(), 0);
            }
            return Err(err);
        }

        Ok(())
    }

    pub(super) fn read_file(root: &Path, segs: &[&OsStr]) -> io::Result<Vec<u8>> {
        let (dir_segments, leaf) = segs.split_at(segs.len() - 1);
        let parent_fd = open_dir_anchored(root, dir_segments, false)?;
        let c_leaf = to_cstring(leaf[0])?;

        // SAFETY: `parent_fd` is a valid directory FD and `c_leaf` is NUL-terminated.
        let raw = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                c_leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ELOOP) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("refusing to read symlink '{}'", leaf[0].to_string_lossy()),
                ));
            }
            return Err(err);
        }
        // SAFETY: `raw` is a newly opened valid file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: `fd` is valid.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing to read non-regular file",
            ));
        }
        let mut file = std::fs::File::from(fd);
        let mut out = Vec::new();
        file.read_to_end(&mut out)?;
        Ok(out)
    }

    pub(super) fn remove_file(root: &Path, segs: &[&OsStr]) -> io::Result<bool> {
        let (dir_segments, leaf) = segs.split_at(segs.len() - 1);
        let parent_fd = match open_dir_anchored(root, dir_segments, false) {
            Ok(fd) => fd,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(err),
        };
        let c_leaf = to_cstring(leaf[0])?;

        // SAFETY: `parent_fd` is valid and `c_leaf` is NUL-terminated.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                c_leaf.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
            return Err(err);
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing to delete symlink or non-regular file",
            ));
        }

        // SAFETY: `parent_fd` is valid and `c_leaf` was verified as a regular file.
        if unsafe { libc::unlinkat(parent_fd.as_raw_fd(), c_leaf.as_ptr(), 0) } < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
            return Err(err);
        }
        Ok(true)
    }
}

#[cfg(not(unix))]
mod non_unix_anchored {
    use super::*;

    fn reject_symlink_ancestors(root: &Path, dir_segments: &[&OsStr]) -> io::Result<std::path::PathBuf> {
        let mut cur = root.to_path_buf();
        for seg in dir_segments {
            cur.push(seg);
            if let Ok(meta) = std::fs::symlink_metadata(&cur) {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("refusing symlink or non-directory '{}'", cur.display()),
                    ));
                }
            }
        }
        Ok(cur)
    }

    pub(super) fn write_file(root: &Path, segs: &[&OsStr], bytes: &[u8]) -> io::Result<()> {
        let (dir_segments, leaf) = segs.split_at(segs.len() - 1);
        let parent = reject_symlink_ancestors(root, dir_segments)?;
        std::fs::create_dir_all(&parent)?;
        let dst = parent.join(leaf[0]);
        if let Ok(meta) = std::fs::symlink_metadata(&dst) {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing to overwrite symlink or non-regular file",
                ));
            }
        }
        std::fs::write(dst, bytes)
    }

    pub(super) fn read_file(root: &Path, segs: &[&OsStr]) -> io::Result<Vec<u8>> {
        let (dir_segments, leaf) = segs.split_at(segs.len() - 1);
        let parent = reject_symlink_ancestors(root, dir_segments)?;
        let dst = parent.join(leaf[0]);
        let meta = std::fs::symlink_metadata(&dst)?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing to read symlink or non-regular file",
            ));
        }
        std::fs::read(dst)
    }

    pub(super) fn remove_file(root: &Path, segs: &[&OsStr]) -> io::Result<bool> {
        let (dir_segments, leaf) = segs.split_at(segs.len() - 1);
        let parent = reject_symlink_ancestors(root, dir_segments)?;
        let dst = parent.join(leaf[0]);
        match std::fs::symlink_metadata(&dst) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "refusing to delete symlink or non-regular file",
                    ));
                }
                std::fs::remove_file(dst)?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Atomically writes `bytes` to `rel` strictly anchored under `root`, traversing every directory
/// component via `openat(..., O_DIRECTORY | O_NOFOLLOW)` on Unix so a concurrent symlink swap
/// in `proc_exec` cannot redirect writes outside `root`. Preserves existing regular file mode.
pub fn write_file_no_symlink_under_root(root: &Path, rel: &Path, bytes: &[u8]) -> io::Result<()> {
    let segs = extract_normal_segments(rel)?;
    #[cfg(unix)]
    {
        unix_anchored::write_file(root, &segs, bytes)
    }
    #[cfg(not(unix))]
    {
        non_unix_anchored::write_file(root, &segs, bytes)
    }
}

/// Reads `rel` strictly anchored under `root` without following any intermediate or leaf symlink.
pub fn read_file_no_symlink_under_root(root: &Path, rel: &Path) -> io::Result<Vec<u8>> {
    let segs = extract_normal_segments(rel)?;
    #[cfg(unix)]
    {
        unix_anchored::read_file(root, &segs)
    }
    #[cfg(not(unix))]
    {
        non_unix_anchored::read_file(root, &segs)
    }
}

/// Removes `rel` strictly anchored under `root` without following any intermediate or leaf symlink.
/// Returns `Ok(true)` if removed or `Ok(false)` if an intermediate directory or leaf did not exist.
pub fn remove_file_no_symlink_under_root(root: &Path, rel: &Path) -> io::Result<bool> {
    let segs = extract_normal_segments(rel)?;
    #[cfg(unix)]
    {
        unix_anchored::remove_file(root, &segs)
    }
    #[cfg(not(unix))]
    {
        non_unix_anchored::remove_file(root, &segs)
    }
}

/// Strips outer nested test harness temp prefixes so red-line path checks inside nested test
/// sandboxes inspect the inner relative/logical path rather than the outer `/agent_home/.tmp...`
/// wrapper. Compiled out to an identity function in release builds without `nested-test-sandbox`.
#[cfg(not(any(test, feature = "nested-test-sandbox")))]
#[inline(always)]
pub const fn strip_nested_test_tmpdir(s: &str) -> &str {
    s
}

/// Strips outer nested test harness temp prefixes when running unit/integration tests inside an
/// Aegis sandbox (`AEGIS_ALLOW_NESTED_TEST_SANDBOX=1` or `AOS_SANDBOX_ID`).
#[cfg(any(test, feature = "nested-test-sandbox"))]
pub fn strip_nested_test_tmpdir(s: &str) -> &str {
    if std::env::var("AEGIS_ALLOW_NESTED_TEST_SANDBOX").as_deref() != Ok("1")
        && std::env::var_os("AOS_SANDBOX_ID").is_none()
    {
        return s;
    }

    let temp_dir_str = std::env::temp_dir().to_string_lossy().into_owned();
    let temp_norm = temp_dir_str.trim_end_matches('/');

    let needles = [
        "/agent_home/tmp/.tmp",
        "/agent_home/.tmp",
        "/home/tmp/.tmp",
        "/home/.tmp",
    ];

    for needle in needles {
        let Some(idx) = s.find(needle) else {
            continue;
        };
        let prefix = &s[..idx];
        if prefix.contains("/../") || prefix.ends_with("/..") {
            return s;
        }
        if needle.starts_with("/home/") {
            if !(prefix.contains("/.aegis/orgs/") && prefix.contains("/agents/")) {
                continue;
            }
            let dir_end = if needle.starts_with("/home/tmp/") {
                idx + "/home/tmp/".len()
            } else {
                idx + "/home/".len()
            };
            let rest = &s[dir_end..];
            return match rest.find('/') {
                Some(slash) => &rest[slash..],
                None => "",
            };
        }

        let has_allowed_prefix = s.starts_with("/tmp/")
            || s.starts_with("/private/tmp/")
            || s.starts_with("/var/folders/")
            || s.starts_with("/private/var/folders/")
            || s.contains("/.aegis/")
            || (!temp_norm.is_empty() && s.starts_with(&format!("{temp_norm}/")));
        if !has_allowed_prefix {
            continue;
        }
        let dir_end = if needle.starts_with("/agent_home/tmp/") {
            idx + "/agent_home/tmp/".len()
        } else {
            idx + "/agent_home/".len()
        };
        let rest = &s[dir_end..];
        return match rest.find('/') {
            Some(slash) => &rest[slash..],
            None => "",
        };
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ct_eq_str_is_exact_and_rejects_empty() {
        assert!(ct_eq_str("secret-123", "secret-123"));
        assert!(!ct_eq_str("Secret-123", "secret-123"));
        assert!(!ct_eq_str("secret-12", "secret-123"));
        assert!(!ct_eq_str("", ""));
        assert!(!ct_eq_bytes(&[], b"a"));
    }

    #[test]
    fn ct_eq_hex_is_case_insensitive_and_rejects_empty() {
        assert!(ct_eq_hex("deadBEEF", "DEADbeef"));
        assert!(!ct_eq_hex("deadbeef", "deadbeee"));
        assert!(!ct_eq_hex("", ""));
    }

    #[test]
    fn forbidden_outbound_ips_cover_v4_v6_and_cgnat() {
        assert!(is_forbidden_outbound_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_forbidden_outbound_ip(IpAddr::V4(Ipv4Addr::new(
            100, 64, 0, 1
        ))));
        assert!(is_forbidden_outbound_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(is_forbidden_outbound_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_forbidden_outbound_ip(
            "::ffff:127.0.0.1".parse().unwrap()
        ));
        assert!(is_forbidden_outbound_ip("fd00:ec2::254".parse().unwrap()));
        assert!(!is_forbidden_outbound_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn dotenv_and_git_internal_paths_detected_case_insensitively() {
        assert!(is_dotenv_secret_path(".env"));
        assert!(is_dotenv_secret_path("apps/api/.ENV.production"));
        assert!(!is_dotenv_secret_path(".env.example"));
        assert!(!is_dotenv_secret_path("config/.ENV.SAMPLE"));
        assert!(is_git_internal_path(".git"));
        assert!(is_git_internal_path(".GIT/config"));
        assert!(is_git_internal_path("sub/.git/hooks/pre-commit"));
        assert!(!is_git_internal_path("src/github.rs"));
    }

    #[cfg(unix)]
    #[test]
    fn create_private_dir_0700_sets_mode_and_rejects_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let tmp = tempfile::tempdir().unwrap();
        let priv_dir = tmp.path().join("private");
        create_private_dir_0700(&priv_dir).unwrap();
        let mode = std::fs::metadata(&priv_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        let target = tmp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = tmp.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(create_private_dir_0700(&link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn anchored_no_symlink_fs_ops_work_and_block_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let outside_file = outside.join("victim.txt");
        std::fs::write(&outside_file, b"keep-me").unwrap();

        // Nested create + mode preservation + read + remove
        let rel = Path::new("nested/dir/app.txt");
        write_file_no_symlink_under_root(&root, rel, b"v1").unwrap();
        std::fs::set_permissions(root.join(rel), std::fs::Permissions::from_mode(0o755)).unwrap();
        write_file_no_symlink_under_root(&root, rel, b"v2").unwrap();
        let mode = std::fs::metadata(root.join(rel)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        assert_eq!(read_file_no_symlink_under_root(&root, rel).unwrap(), b"v2");
        assert!(remove_file_no_symlink_under_root(&root, rel).unwrap());
        assert!(!remove_file_no_symlink_under_root(&root, rel).unwrap());

        // Intermediate directory symlink is rejected across write/read/remove
        symlink(&outside, root.join("esc_dir")).unwrap();
        let via_dir = Path::new("esc_dir/victim.txt");
        assert_eq!(
            write_file_no_symlink_under_root(&root, via_dir, b"pwn")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            read_file_no_symlink_under_root(&root, via_dir)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            remove_file_no_symlink_under_root(&root, via_dir)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"keep-me");

        // Leaf symlink is rejected across write/read/remove
        let real_sub = root.join("sub");
        std::fs::create_dir_all(&real_sub).unwrap();
        symlink(&outside_file, real_sub.join("leaf_link")).unwrap();
        let via_leaf = Path::new("sub/leaf_link");
        assert_eq!(
            write_file_no_symlink_under_root(&root, via_leaf, b"pwn")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            read_file_no_symlink_under_root(&root, via_leaf)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            remove_file_no_symlink_under_root(&root, via_leaf)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"keep-me");

        // Parent traversal and absolute path are rejected
        assert!(write_file_no_symlink_under_root(&root, Path::new("../x"), b"a").is_err());
        assert!(write_file_no_symlink_under_root(&root, Path::new("/etc/passwd"), b"a").is_err());
    }
}
