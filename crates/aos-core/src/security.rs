//! Shared security primitives for Aegis OS (Single Source of Truth).
//!
//! Centralizes constant-time comparisons, outbound SSRF IP filtering, `.env*` & `.git/` red-line
//! path checks, atomic private `0o700` directory creation, and test-only nested sandbox path
//! stripping so security guards across crates cannot drift.

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
}
