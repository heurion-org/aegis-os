use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallMethod {
    Homebrew { exe: PathBuf },
    Source { repo_dir: PathBuf, exe: PathBuf },
    CargoGit { exe: PathBuf },
    SignedRelease { exe: PathBuf },
}

impl InstallMethod {
    fn label(&self) -> &'static str {
        match self {
            Self::Homebrew { .. } => "Homebrew",
            Self::Source { .. } => "Local Cargo Source Build",
            Self::CargoGit { .. } => "Cargo Git Install",
            Self::SignedRelease { .. } => "Signed Release Binary",
        }
    }
}

pub(crate) struct UpgradeOptions<'a> {
    pub home_dir: &'a Path,
    pub runtime_dir: &'a Path,
    pub workspace: &'a Path,
    pub check: bool,
    pub method: &'a str,
    pub tag: Option<&'a str>,
    pub source_dir: Option<&'a Path>,
    pub offline: bool,
    pub refresh_only: bool,
    pub no_refresh: bool,
    pub dry_run: bool,
    pub verbose: bool,
}

pub(super) fn find_aegis_repo_root(start: &Path) -> Option<PathBuf> {
    for ancestor in start.ancestors() {
        let cli_manifest = ancestor.join("crates").join("aos-cli").join("Cargo.toml");
        if cli_manifest.is_file() {
            if let Ok(text) = std::fs::read_to_string(&cli_manifest) {
                if text.contains("name = \"aos-cli\"") {
                    return Some(
                        std::fs::canonicalize(ancestor).unwrap_or_else(|_| ancestor.to_path_buf()),
                    );
                }
            }
        }
    }
    None
}

pub(crate) fn detect_install_method(
    current_exe: &Path,
    workspace: &Path,
    method_arg: &str,
    explicit_source_dir: Option<&Path>,
) -> anyhow::Result<InstallMethod> {
    let canon = std::fs::canonicalize(current_exe).unwrap_or_else(|_| current_exe.to_path_buf());
    let canon_str = canon.to_string_lossy();
    let resolve_source = || -> anyhow::Result<InstallMethod> {
        let repo = explicit_source_dir
            .and_then(find_aegis_repo_root)
            .or_else(|| find_aegis_repo_root(workspace))
            .or_else(|| find_aegis_repo_root(&canon))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "could not locate an Aegis OS source repository (`crates/aos-cli/Cargo.toml`); pass `--source-dir <path/to/aegis-os>`"
                )
            })?;
        Ok(InstallMethod::Source {
            repo_dir: repo,
            exe: canon.clone(),
        })
    };

    match method_arg.trim().to_ascii_lowercase().as_str() {
        "brew" | "homebrew" => Ok(InstallMethod::Homebrew { exe: canon }),
        "cargo" => Ok(InstallMethod::CargoGit { exe: canon }),
        "release" => Ok(InstallMethod::SignedRelease { exe: canon }),
        "source" => resolve_source(),
        "" | "auto" => {
            if explicit_source_dir.is_some() {
                return resolve_source();
            }
            if canon_str.contains("/Cellar/aegis-os/")
                || canon_str.contains("/opt/homebrew/opt/aegis-os")
                || canon_str.contains("/linuxbrew/.linuxbrew/Cellar/aegis-os/")
            {
                return Ok(InstallMethod::Homebrew { exe: canon });
            }
            if canon_str.contains("/target/release/") || canon_str.contains("/target/debug/") {
                if let Some(repo) = find_aegis_repo_root(&canon) {
                    return Ok(InstallMethod::Source {
                        repo_dir: repo,
                        exe: canon,
                    });
                }
            }
            if let Some(repo) = find_aegis_repo_root(workspace) {
                return Ok(InstallMethod::Source {
                    repo_dir: std::fs::canonicalize(&repo).unwrap_or(repo),
                    exe: canon,
                });
            }
            Ok(InstallMethod::SignedRelease { exe: canon })
        }
        other => anyhow::bail!(
            "unknown --method '{}'; expected auto, release, brew, source, or cargo",
            other
        ),
    }
}

pub(crate) fn validate_release_tag(tag: &str) -> anyhow::Result<()> {
    let Some(rest) = tag.strip_prefix('v') else {
        anyhow::bail!(
            "invalid release tag '{}': must start with 'v' (e.g. v0.4.6)",
            tag
        );
    };
    let bytes = rest.as_bytes();
    if rest.is_empty()
        || !bytes[0].is_ascii_digit()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || rest.contains("..")
        || rest.matches('.').count() < 2
        || !rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        anyhow::bail!(
            "invalid release tag '{}': expected semantic tag like v0.4.6 or v0.5.0-rc.1",
            tag
        );
    }
    Ok(())
}

pub(super) fn parse_semver_key(v: &str) -> Option<(u64, u64, u64, bool, String)> {
    let trimmed = v.trim();
    let trimmed = trimmed.strip_prefix('v').unwrap_or(trimmed);
    let (core, pre) = match trimmed.split_once('-') {
        Some((c, p)) => (c, p.to_string()),
        None => (trimmed, String::new()),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch_raw = parts.next()?;
    let patch = patch_raw.split('+').next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch, pre.is_empty(), pre))
}

pub(super) fn read_local_repo_version(repo_dir: &Path) -> Option<String> {
    let cargo_toml = std::fs::read_to_string(repo_dir.join("Cargo.toml")).ok()?;
    let mut in_workspace_pkg = false;
    for raw_line in cargo_toml.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_workspace_pkg = line == "[workspace.package]";
            continue;
        }
        if in_workspace_pkg {
            if let Some(rest) = line.strip_prefix("version") {
                let rest = rest.trim_start();
                if let Some(val) = rest.strip_prefix('=') {
                    let val = val.trim().trim_matches('"');
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

pub(super) async fn fetch_latest_github_release_tag() -> anyhow::Result<String> {
    let api_base = std::env::var("AEGIS_GITHUB_API_BASE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "https://api.github.com".to_string());
    let url = format!(
        "{}/repos/heurion-org/aegis-os/releases/latest",
        api_base.trim_end_matches('/')
    );
    tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(6))
            .build();
        let resp = agent
            .get(&url)
            .set("User-Agent", concat!("aegis-os/", env!("CARGO_PKG_VERSION")))
            .set("Accept", "application/vnd.github+json")
            .call()
            .with_context(|| format!("querying {}", url))?;
        let json_val: Value = resp.into_json()?;
        let tag = json_val
            .get("tag_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("GitHub release payload missing `tag_name`"))?
            .to_string();
        validate_release_tag(&tag)?;
        Ok(tag)
    })
    .await?
}

pub(super) fn contains_exact_tmp_runtime(text: &str) -> bool {
    for needle in ["/tmp/aegis-os-runtime", "/private/tmp/aegis-os-runtime"] {
        let mut rest = text;
        while let Some(pos) = rest.find(needle) {
            let after = &rest[pos + needle.len()..];
            if matches!(
                after.chars().next(),
                None | Some('"') | Some('\'') | Some(' ') | Some('\\')
            ) {
                return true;
            }
            rest = after;
        }
    }
    false
}

pub(super) fn client_configs_have_stale_tmp_runtime(home_dir: &Path) -> Vec<PathBuf> {
    let candidates = [
        home_dir.join(".gemini/config/mcp_config.json"),
        home_dir.join(".gemini/config/hooks.json"),
        home_dir.join(".claude.json"),
        home_dir.join(".claude/settings.json"),
        home_dir.join(".codex/config.toml"),
        home_dir.join(".config/opencode/opencode.json"),
    ];
    candidates
        .into_iter()
        .filter(|path| {
            std::fs::read_to_string(path)
                .map(|text| contains_exact_tmp_runtime(&text))
                .unwrap_or(false)
        })
        .collect()
}

pub(super) fn has_enforced_shims(home_dir: &Path) -> bool {
    let shim_dir = home_dir.join(".aegis").join("bin");
    SUPPORTED_SHIM_AGENTS
        .iter()
        .any(|agent| shim_dir.join(agent).is_file())
}

pub(super) fn release_asset_name() -> anyhow::Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aegis-os-darwin-arm64"),
        ("macos", "x86_64") => Ok("aegis-os-darwin-x86_64"),
        ("linux", "aarch64") => Ok("aegis-os-linux-aarch64"),
        ("linux", "x86_64") => Ok("aegis-os-linux-x86_64"),
        (os, arch) => anyhow::bail!(
            "unsupported platform {}/{} for prebuilt release binaries (try `--method source`)",
            os,
            arch
        ),
    }
}

pub(super) fn atomic_install_binary(src: &Path, dst: &Path) -> anyhow::Result<()> {
    let parent = dst.parent().ok_or_else(|| {
        anyhow::anyhow!("destination binary path has no parent: {}", dst.display())
    })?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".aegis-os.upgrade.{}.tmp", std::process::id()));
    std::fs::copy(src, &tmp).with_context(|| {
        format!(
            "copying upgraded binary to {} (ensure {} is writable)",
            tmp.display(),
            parent.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    if let Ok(file) = std::fs::File::open(&tmp) {
        let _ = file.sync_all();
    }
    if let Err(err) = std::fs::rename(&tmp, dst) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err).with_context(|| {
            format!("replacing binary {} via {}", dst.display(), tmp.display())
        });
    }
    Ok(())
}

pub(super) fn find_on_path(bin_name: &str) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let cand = dir.join(bin_name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

pub(super) fn download_to_file(agent: &ureq::Agent, url: &str, dest: &Path) -> anyhow::Result<()> {
    let resp = agent
        .get(url)
        .set("User-Agent", concat!("aegis-os/", env!("CARGO_PKG_VERSION")))
        .call()
        .with_context(|| format!("HTTP GET {}", url))?;
    let mut reader = resp.into_reader();
    let mut out = std::fs::File::create(dest)?;
    std::io::copy(&mut reader, &mut out)?;
    out.sync_all()?;
    Ok(())
}

pub(crate) fn verify_openssh_signature(bin_path: &Path, sig_path: &Path, work_dir: &Path) -> anyhow::Result<()> {
    let allowed_signers = work_dir.join("allowed_signers");
    std::fs::write(&allowed_signers, format!("{}\n", RELEASE_SIGNER))?;
    let bin_file = std::fs::File::open(bin_path)?;
    let output = std::process::Command::new("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(&allowed_signers)
        .arg("-I")
        .arg(RELEASE_PRINCIPAL)
        .arg("-n")
        .arg(RELEASE_NAMESPACE)
        .arg("-s")
        .arg(sig_path)
        .stdin(std::process::Stdio::from(bin_file))
        .output()
        .context("running `ssh-keygen -Y verify` (OpenSSH 8.1+ is required)")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Ed25519 release signature verification FAILED for {}: {}",
            bin_path.display(),
            stderr.trim()
        );
    }
    Ok(())
}

pub(super) fn signed_release_base_candidates(tag: Option<&str>) -> Vec<String> {
    if let Some(t) = tag {
        if let Ok(override_base) = std::env::var("AEGIS_RELEASE_BASE_URL") {
            let trimmed = override_base.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                return vec![format!("{}/{}", trimmed, t)];
            }
        }
        return vec![format!(
            "https://github.com/heurion-org/aegis-os/releases/download/{}",
            t
        )];
    }
    let endpoint = std::env::var("AEGIS_CLOUD_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "https://heurion.org".to_string());
    vec![
        format!("{}/aegis-cloud/releases", endpoint.trim_end_matches('/')),
        "https://github.com/heurion-org/aegis-os/releases/latest/download".to_string(),
    ]
}

pub(super) fn is_volatile_tmp_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.starts_with("/tmp/") || s.starts_with("/private/tmp/")
}

pub(super) fn resolve_signed_target_exe(current_exe: &Path) -> PathBuf {
    if !is_volatile_tmp_path(current_exe) {
        return current_exe.to_path_buf();
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        return home.join(".local/bin/aegis-os");
    }
    current_exe.to_path_buf()
}

pub(crate) fn probe_binary_version(bin: &Path) -> Option<String> {
    let out = std::process::Command::new(bin).arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for tok in text.split_whitespace() {
        let cleaned =
            tok.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
        if parse_semver_key(cleaned).is_some() {
            return Some(cleaned.strip_prefix('v').unwrap_or(cleaned).to_string());
        }
    }
    None
}

pub(super) fn binary_install_help_contains(bin: &Path, flag: &str) -> bool {
    let Ok(out) = std::process::Command::new(bin)
        .args(["install", "--help"])
        .output()
    else {
        return false;
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    stdout.contains(flag) || stderr.contains(flag)
}

pub(crate) fn binary_supports_install_enforce(bin: &Path) -> bool {
    binary_install_help_contains(bin, "--enforce")
}

pub(crate) fn binary_supports_install_quiet(bin: &Path) -> bool {
    binary_install_help_contains(bin, "--quiet")
}

pub(crate) fn is_candidate_binary_regression(
    cand_bin: &Path,
    current_version: &str,
    current_supports_enforce: bool,
) -> Option<String> {
    let cur_key = parse_semver_key(current_version);
    let cand_ver = probe_binary_version(cand_bin);
    let cand_key = cand_ver.as_deref().and_then(parse_semver_key);
    let cand_enforce = binary_supports_install_enforce(cand_bin);

    match (cur_key, cand_key) {
        (Some(cur), Some(cand)) if cand < cur => Some(format!(
            "candidate binary v{} is older than current v{}",
            cand_ver.as_deref().unwrap_or("unknown"),
            current_version
        )),
        (Some(cur), Some(cand)) if cand == cur && current_supports_enforce && !cand_enforce => {
            Some(format!(
                "candidate binary v{} lacks `install --enforce` support present in current build",
                cand_ver.as_deref().unwrap_or(current_version)
            ))
        }
        (_, None) if current_supports_enforce && !cand_enforce => Some(
            "candidate binary version could not be probed and lacks `install --enforce` support"
                .to_string(),
        ),
        _ => None,
    }
}

pub(super) fn sync_secondary_path_binaries(source_bin: &Path, primary_target: &Path) {
    let mut search_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    search_dirs.push(PathBuf::from("/opt/homebrew/bin"));
    search_dirs.push(PathBuf::from("/usr/local/bin"));
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        search_dirs.push(home.join(".local/bin"));
        search_dirs.push(home.join(".cargo/bin"));
    }
    let target_canon = std::fs::canonicalize(primary_target).ok();
    let mut seen = std::collections::BTreeSet::new();
    for dir in search_dirs {
        let cand = dir.join("aegis-os");
        let cand_s = cand.to_string_lossy();
        if cand == primary_target
            || is_volatile_tmp_path(&cand)
            || cand_s.contains("/target/release/")
            || cand_s.contains("/target/debug/")
            || !seen.insert(cand.clone())
        {
            continue;
        }
        if target_canon.is_some()
            && std::fs::canonicalize(&cand).ok().as_ref() == target_canon.as_ref()
        {
            continue;
        }
        if cand.is_file() {
            let _ = atomic_install_binary(source_bin, &cand);
        }
    }
}

pub(super) enum SignedDownloadOutcome {
    Installed {
        bin_tmp: PathBuf,
        downloaded_from: String,
        version: Option<String>,
    },
    KeptNewerLocal {
        mirror_version: Option<String>,
    },
}

pub(super) async fn perform_signed_release_upgrade(
    exe: &Path,
    tag: Option<&str>,
    dry_run: bool,
    verbose: bool,
) -> anyhow::Result<(PathBuf, Option<String>, bool)> {
    let asset = release_asset_name()?;
    let target_exe = resolve_signed_target_exe(exe);
    let bases = signed_release_base_candidates(tag);

    if dry_run {
        println!(
            "==> [dry-run] Would download `{}` + `{}.sig` from {} (fallback: {:?})",
            asset,
            asset,
            bases[0],
            bases.get(1)
        );
        println!(
            "==> [dry-run] Would verify OpenSSH signature with `{}` (namespace `{}`)",
            RELEASE_PRINCIPAL, RELEASE_NAMESPACE
        );
        println!("==> [dry-run] Would atomically replace {}", target_exe.display());
        let planned_ver = tag.map(|t| t.strip_prefix('v').unwrap_or(t).to_string());
        return Ok((target_exe, planned_ver, false));
    }

    match std::process::Command::new("ssh-keygen").arg("-V").output() {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "`ssh-keygen` (OpenSSH 8.1+) is required to verify release signatures; install openssh-client or upgrade via `brew upgrade aegis-os`"
            );
        }
        Err(err) => return Err(err.into()),
    }

    let bases_owned = bases.clone();
    let work = tempfile::tempdir()?;
    let work_path = work.path().to_path_buf();
    let asset_owned = asset.to_string();
    let enforce_expected = tag.is_none();

    if !verbose {
        println!("==> Downloading Aegis OS release ...");
    }

    let outcome = tokio::task::spawn_blocking(
        move || -> anyhow::Result<SignedDownloadOutcome> {
            let agent = ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(45))
                .build();
            let bin_tmp = work_path.join(&asset_owned);
            let sig_tmp = work_path.join(format!("{}.sig", asset_owned));
            let mut last_err = None;
            let mut skipped_regression: Option<String> = None;
            let mut skipped_mirror_version: Option<String> = None;
            let mut printed_verifying = false;

            for base in &bases_owned {
                let bin_url = format!("{}/{}", base, asset_owned);
                let sig_url = format!("{}/{}.sig", base, asset_owned);
                if verbose {
                    println!("==> Downloading `{}` from {} ...", asset_owned, base);
                }
                if let Err(err) = download_to_file(&agent, &bin_url, &bin_tmp)
                    .and_then(|_| download_to_file(&agent, &sig_url, &sig_tmp))
                {
                    let _ = std::fs::remove_file(&bin_tmp);
                    let _ = std::fs::remove_file(&sig_tmp);
                    last_err = Some(err);
                    continue;
                }
                if verbose || !printed_verifying {
                    println!("==> Verifying Ed25519 release signature ...");
                    printed_verifying = true;
                }
                verify_openssh_signature(&bin_tmp, &sig_tmp, &work_path)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&bin_tmp, std::fs::Permissions::from_mode(0o755));
                }
                let cand_ver = probe_binary_version(&bin_tmp);
                if enforce_expected {
                    if let Some(reason) =
                        is_candidate_binary_regression(&bin_tmp, CURRENT_VERSION, true)
                    {
                        if verbose {
                            println!("  ! skipping {}: {} (trying next mirror)", base, reason);
                        }
                        let _ = std::fs::remove_file(&bin_tmp);
                        let _ = std::fs::remove_file(&sig_tmp);
                        skipped_regression = Some(reason);
                        if let Some(ver) = cand_ver {
                            let is_newer = skipped_mirror_version
                                .as_deref()
                                .map(|prev| parse_semver_key(&ver) > parse_semver_key(prev))
                                .unwrap_or(true);
                            if is_newer {
                                skipped_mirror_version = Some(ver);
                            }
                        }
                        continue;
                    }
                }
                return Ok(SignedDownloadOutcome::Installed {
                    bin_tmp,
                    downloaded_from: base.clone(),
                    version: cand_ver,
                });
            }
            if skipped_regression.is_some() && last_err.is_none() {
                return Ok(SignedDownloadOutcome::KeptNewerLocal {
                    mirror_version: skipped_mirror_version,
                });
            }
            Err(last_err.unwrap_or_else(|| {
                anyhow::anyhow!(
                    "{}",
                    skipped_regression
                        .unwrap_or_else(|| "no release download sources configured".to_string())
                )
            }))
        },
    )
    .await??;

    let (verified_bin, downloaded_from, probed_version) = match outcome {
        SignedDownloadOutcome::KeptNewerLocal { mirror_version } => {
            if verbose {
                println!(
                    "==> Installed binary (v{}) is already newer than published release mirrors; keeping {} intact.",
                    CURRENT_VERSION,
                    target_exe.display()
                );
            }
            return Ok((target_exe, mirror_version, true));
        }
        SignedDownloadOutcome::Installed {
            bin_tmp,
            downloaded_from,
            version,
        } => (bin_tmp, downloaded_from, version),
    };

    atomic_install_binary(&verified_bin, &target_exe)?;
    if verbose {
        println!(
            "==> Installed verified binary from {} -> {}",
            downloaded_from,
            target_exe.display()
        );
    }

    sync_secondary_path_binaries(&verified_bin, &target_exe);
    let resolved_ver = probed_version
        .or_else(|| probe_binary_version(&target_exe))
        .or_else(|| tag.map(|t| t.strip_prefix('v').unwrap_or(t).to_string()));

    Ok((target_exe, resolved_ver, false))
}

pub(super) fn cargo_bin_aegis_path() -> Option<PathBuf> {
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME").filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(cargo_home).join("bin").join("aegis-os"));
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".cargo/bin/aegis-os"))
}

pub(super) fn which_aegis_os_after_upgrade(method: &InstallMethod) -> PathBuf {
    match method {
        InstallMethod::SignedRelease { exe } => resolve_signed_target_exe(exe),
        InstallMethod::Homebrew { exe } => {
            for cand in [
                "/opt/homebrew/bin/aegis-os",
                "/usr/local/bin/aegis-os",
                "/home/linuxbrew/.linuxbrew/bin/aegis-os",
            ] {
                let p = Path::new(cand);
                if p.is_file() {
                    return p.to_path_buf();
                }
            }
            find_on_path("aegis-os").unwrap_or_else(|| exe.clone())
        }
        InstallMethod::CargoGit { exe } | InstallMethod::Source { exe, .. } => {
            if let Some(cargo_bin) = cargo_bin_aegis_path() {
                if cargo_bin.is_file() {
                    return cargo_bin;
                }
            }
            find_on_path("aegis-os").unwrap_or_else(|| exe.clone())
        }
    }
}

pub(super) fn perform_homebrew_upgrade(
    exe: &Path,
    tag: Option<&str>,
    dry_run: bool,
    verbose: bool,
) -> anyhow::Result<(PathBuf, Option<String>)> {
    if tag.is_some() {
        println!("  ! note: Homebrew upgrades track the tap formula version; ignoring `--tag`");
    }
    if dry_run {
        println!("==> [dry-run] Would run: brew update && brew upgrade aegis-os");
        return Ok((exe.to_path_buf(), None));
    }
    if verbose {
        println!("==> Updating Homebrew tap ...");
        let _ = std::process::Command::new("brew").arg("update").status();
        println!("==> Upgrading `aegis-os` via Homebrew ...");
    } else {
        println!("==> Upgrading Aegis OS via Homebrew ...");
        let _ = std::process::Command::new("brew").arg("update").output();
    }
    let status = std::process::Command::new("brew")
        .args(["upgrade", "aegis-os"])
        .status()
        .context("running `brew upgrade aegis-os`")?;
    if !status.success() {
        let tap_status = std::process::Command::new("brew")
            .args(["upgrade", "heurion-org/aegis-os/aegis-os"])
            .status()?;
        if !tap_status.success() {
            anyhow::bail!("`brew upgrade aegis-os` exited with status {}", status);
        }
    }
    let new_exe = which_aegis_os_after_upgrade(&InstallMethod::Homebrew {
        exe: exe.to_path_buf(),
    });
    let new_ver = probe_binary_version(&new_exe);
    Ok((new_exe, new_ver))
}

pub(super) fn perform_source_upgrade(
    repo_dir: &Path,
    exe: &Path,
    offline: bool,
    dry_run: bool,
    verbose: bool,
) -> anyhow::Result<(PathBuf, Option<String>)> {
    let crate_dir = repo_dir.join("crates").join("aos-cli");
    if dry_run {
        println!(
            "==> [dry-run] Would run: cargo install --path {} --locked --force{}",
            crate_dir.display(),
            if offline { " --offline" } else { "" }
        );
        return Ok((
            cargo_bin_aegis_path().unwrap_or_else(|| exe.to_path_buf()),
            read_local_repo_version(repo_dir),
        ));
    }
    if verbose {
        println!(
            "==> Building & installing `aos-cli` from source ({}) ...",
            repo_dir.display()
        );
    } else {
        println!("==> Building & installing Aegis OS from local source ...");
    }
    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("install")
        .arg("--path")
        .arg(&crate_dir)
        .arg("--locked")
        .arg("--force");
    if offline {
        cmd.arg("--offline");
    }
    let status = cmd.status().context("running `cargo install --path`")?;
    if !status.success() {
        anyhow::bail!("`cargo install` failed with status {}", status);
    }
    let cargo_bin = cargo_bin_aegis_path().unwrap_or_else(|| exe.to_path_buf());
    if cargo_bin.is_file() {
        let exe_s = exe.to_string_lossy();
        if exe != cargo_bin
            && !is_volatile_tmp_path(exe)
            && !exe_s.contains("/target/release/")
            && !exe_s.contains("/target/debug/")
            && exe.is_file()
        {
            let _ = atomic_install_binary(&cargo_bin, exe);
        }
        sync_secondary_path_binaries(&cargo_bin, &cargo_bin);
    }
    let new_ver =
        probe_binary_version(&cargo_bin).or_else(|| read_local_repo_version(repo_dir));
    Ok((cargo_bin, new_ver))
}

pub(super) fn perform_cargo_git_upgrade(
    exe: &Path,
    tag: Option<&str>,
    dry_run: bool,
    verbose: bool,
) -> anyhow::Result<(PathBuf, Option<String>)> {
    if dry_run {
        let tag_arg = tag.map(|t| format!(" --tag {}", t)).unwrap_or_default();
        println!(
            "==> [dry-run] Would run: cargo install --git https://github.com/heurion-org/aegis-os{} aos-cli --locked --force",
            tag_arg
        );
        return Ok((
            cargo_bin_aegis_path().unwrap_or_else(|| exe.to_path_buf()),
            tag.map(|t| t.strip_prefix('v').unwrap_or(t).to_string()),
        ));
    }
    if verbose {
        println!("==> Installing `aos-cli` via `cargo install --git` ...");
    } else {
        println!("==> Building & installing Aegis OS via Cargo ...");
    }
    let mut cmd = std::process::Command::new("cargo");
    cmd.args(["install", "--git", "https://github.com/heurion-org/aegis-os"]);
    if let Some(t) = tag {
        cmd.arg("--tag").arg(t);
    }
    cmd.args(["aos-cli", "--locked", "--force"]);
    let status = cmd.status().context("running `cargo install --git`")?;
    if !status.success() {
        anyhow::bail!("`cargo install --git` failed with status {}", status);
    }
    let cargo_bin = cargo_bin_aegis_path().unwrap_or_else(|| exe.to_path_buf());
    let new_ver = probe_binary_version(&cargo_bin)
        .or_else(|| tag.map(|t| t.strip_prefix('v').unwrap_or(t).to_string()));
    Ok((cargo_bin, new_ver))
}

pub(super) async fn run_upgrade_check(method: &InstallMethod, opts: &UpgradeOptions<'_>) -> anyhow::Result<()> {
    let exe = match method {
        InstallMethod::Homebrew { exe }
        | InstallMethod::Source { exe, .. }
        | InstallMethod::CargoGit { exe }
        | InstallMethod::SignedRelease { exe } => exe,
    };
    println!("Aegis OS Upgrade Check (`aegis-os upgrade --check`):");
    println!("  Current Version: v{}", CURRENT_VERSION);
    println!("  Binary Path:     {}", exe.display());
    println!("  Install Method:  {}", method.label());

    if let InstallMethod::Source { repo_dir, .. } = method {
        if let Some(repo_ver) = read_local_repo_version(repo_dir) {
            let cmp_note = match (parse_semver_key(CURRENT_VERSION), parse_semver_key(&repo_ver)) {
                (Some(cur), Some(rep)) if rep > cur => "source update available",
                _ => "up to date with source tree",
            };
            println!(
                "  Source Version:  v{} ({}; {})",
                repo_ver,
                repo_dir.display(),
                cmp_note
            );
        }
    }

    if opts.offline {
        println!("  Latest Release:  skipped (--offline)");
    } else {
        match fetch_latest_github_release_tag().await {
            Ok(latest_tag) => {
                let status = match (parse_semver_key(CURRENT_VERSION), parse_semver_key(&latest_tag)) {
                    (Some(cur), Some(lat)) if lat > cur => "UPGRADE AVAILABLE",
                    (Some(cur), Some(lat)) if lat == cur => "up to date",
                    _ => "compare manually",
                };
                println!("  Latest Release:  {} ({})", latest_tag, status);
            }
            Err(err) => {
                println!("  Latest Release:  unavailable ({})", err);
            }
        }
    }

    let stale = client_configs_have_stale_tmp_runtime(opts.home_dir);
    if !stale.is_empty() {
        println!("\n  ! Client config drift detected (legacy `/tmp/aegis-os-runtime` references):");
        for path in stale {
            println!("    - {}", path.display());
        }
        println!("    Run `aegis-os upgrade --refresh-only` (or full `aegis-os upgrade`) to migrate to `{}`.", opts.runtime_dir.display());
    } else {
        println!("  Client Configs:  no legacy `/tmp/aegis-os-runtime` drift detected");
    }
    Ok(())
}

pub(crate) fn format_upgrade_outcome(
    old_version: &str,
    new_version: Option<&str>,
    kept_newer_local: bool,
) -> String {
    let old_norm = old_version.strip_prefix('v').unwrap_or(old_version);
    if kept_newer_local {
        return match new_version {
            Some(latest) => {
                let latest_norm = latest.strip_prefix('v').unwrap_or(latest);
                format!(
                    "Aegis OS is already up to date (local v{} is newer than latest release v{}).",
                    old_norm, latest_norm
                )
            }
            None => format!(
                "Aegis OS is already up to date (local v{} is newer than published releases).",
                old_norm
            ),
        };
    }

    let Some(new_ver) = new_version else {
        return format!(
            "Aegis OS upgrade complete (previous: v{}; installed version unavailable).",
            old_norm
        );
    };
    let new_norm = new_ver.strip_prefix('v').unwrap_or(new_ver);
    match (parse_semver_key(old_norm), parse_semver_key(new_norm)) {
        (Some(old_k), Some(new_k)) if new_k > old_k => {
            format!("Upgraded Aegis OS: v{} -> v{}", old_norm, new_norm)
        }
        (Some(old_k), Some(new_k)) if new_k == old_k => {
            format!("Aegis OS is already up to date (latest: v{}).", new_norm)
        }
        (Some(old_k), Some(new_k)) if new_k < old_k => {
            format!("Installed Aegis OS v{} (was v{}).", new_norm, old_norm)
        }
        _ if old_norm == new_norm => {
            format!("Aegis OS is already up to date (latest: v{}).", new_norm)
        }
        _ => format!("Upgraded Aegis OS: v{} -> v{}", old_norm, new_norm),
    }
}

#[allow(dead_code)]
pub(crate) fn refresh_via_upgraded_binary(
    new_exe: &Path,
    runtime_dir: &Path,
    home_dir: &Path,
    had_shims: bool,
) -> anyhow::Result<()> {
    refresh_via_upgraded_binary_with_options(
        new_exe,
        runtime_dir,
        home_dir,
        had_shims,
        None,
        false,
    )
}

#[cfg(test)]
pub(crate) fn refresh_via_upgraded_binary_with_path(
    new_exe: &Path,
    runtime_dir: &Path,
    home_dir: &Path,
    had_shims: bool,
    path_override: Option<&std::ffi::OsStr>,
) -> anyhow::Result<()> {
    refresh_via_upgraded_binary_with_options(
        new_exe,
        runtime_dir,
        home_dir,
        had_shims,
        path_override,
        false,
    )
}

pub(crate) fn refresh_via_upgraded_binary_with_options(
    new_exe: &Path,
    runtime_dir: &Path,
    home_dir: &Path,
    had_shims: bool,
    path_override: Option<&std::ffi::OsStr>,
    quiet: bool,
) -> anyhow::Result<()> {
    let pass_enforce = had_shims && binary_supports_install_enforce(new_exe);
    let pass_quiet = quiet && binary_supports_install_quiet(new_exe);
    let mut cmd = std::process::Command::new(new_exe);
    cmd.arg("--runtime-dir")
        .arg(runtime_dir)
        .arg("install")
        .arg("--home-dir")
        .arg(home_dir);
    if pass_enforce {
        cmd.arg("--enforce");
    }
    if pass_quiet {
        cmd.arg("--quiet");
    }
    let status = if quiet {
        let out = cmd.output().with_context(|| {
            format!(
                "invoking upgraded binary `{}` to refresh client integrations",
                new_exe.display()
            )
        })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let detail = if !stderr.trim().is_empty() {
                stderr.trim().to_string()
            } else {
                stdout.trim().to_string()
            };
            anyhow::bail!(
                "`{} install` exited with status {} after upgrade{}",
                new_exe.display(),
                out.status,
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {}", detail)
                }
            );
        }
        out.status
    } else {
        cmd.status().with_context(|| {
            format!(
                "invoking upgraded binary `{}` to refresh client integrations",
                new_exe.display()
            )
        })?
    };
    if !status.success() {
        anyhow::bail!(
            "`{} install` exited with status {} after upgrade",
            new_exe.display(),
            status
        );
    }
    if had_shims && !pass_enforce {
        install_enforced_shims_with_options(home_dir, false, path_override, quiet)?;
    }
    Ok(())
}

/// Upgrade `aegis-os` (Homebrew, Source, Cargo, or Ed25519-signed release) and refresh client integrations.
pub(crate) async fn run_upgrade(opts: UpgradeOptions<'_>) -> anyhow::Result<()> {
    if let Some(tag) = opts.tag {
        validate_release_tag(tag)?;
    }

    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
    let exe_str = current_exe.to_string_lossy();
    let effective_method = if opts.method.trim().eq_ignore_ascii_case("auto")
        && opts.tag.is_some()
        && opts.source_dir.is_none()
        && !exe_str.contains("/Cellar/aegis-os/")
        && !exe_str.contains("/opt/homebrew/opt/aegis-os")
    {
        "release"
    } else {
        opts.method
    };
    let method =
        detect_install_method(&current_exe, opts.workspace, effective_method, opts.source_dir)?;

    if opts.check {
        return run_upgrade_check(&method, &opts).await;
    }

    let verbose = opts.verbose;

    if verbose || opts.dry_run {
        println!("=========================================================================");
        println!(
            "  Aegis OS Upgrader{}",
            if opts.dry_run { " (dry-run)" } else { "" }
        );
        println!("  Current Version: v{}", CURRENT_VERSION);
        println!("  Install Method:  {}", method.label());
        println!("  Runtime Dir:     {}", opts.runtime_dir.display());
        println!("=========================================================================\n");
    } else {
        println!(
            "==> Checking Aegis OS updates (current: v{}) ...",
            CURRENT_VERSION
        );
    }

    let had_shims = has_enforced_shims(opts.home_dir);

    let upgraded: Option<(PathBuf, Option<String>, bool)> = if opts.refresh_only {
        if verbose || opts.dry_run {
            println!("==> Skipping binary download/build (--refresh-only)");
        }
        None
    } else {
        let res = match &method {
            InstallMethod::Homebrew { exe } => {
                let (p, v) = perform_homebrew_upgrade(exe, opts.tag, opts.dry_run, verbose)?;
                (p, v, false)
            }
            InstallMethod::Source { repo_dir, exe } => {
                let (p, v) =
                    perform_source_upgrade(repo_dir, exe, opts.offline, opts.dry_run, verbose)?;
                (p, v, false)
            }
            InstallMethod::CargoGit { exe } => {
                let (p, v) = perform_cargo_git_upgrade(exe, opts.tag, opts.dry_run, verbose)?;
                (p, v, false)
            }
            InstallMethod::SignedRelease { exe } => {
                perform_signed_release_upgrade(exe, opts.tag, opts.dry_run, verbose).await?
            }
        };
        Some(res)
    };

    if !opts.no_refresh {
        if opts.refresh_only || opts.dry_run {
            let quiet_refresh = !verbose && !opts.dry_run;
            if verbose || opts.dry_run {
                println!("\n==> Refreshing global client integrations ...");
            } else {
                println!("==> Refreshing client integrations ...");
            }
            install_global_clients_with_options(
                opts.home_dir,
                opts.runtime_dir,
                opts.dry_run,
                quiet_refresh,
            )
            .await?;
            if had_shims {
                install_enforced_shims_with_options(
                    opts.home_dir,
                    opts.dry_run,
                    None,
                    quiet_refresh,
                )?;
            }
        } else if let Some((new_exe, _, _)) = &upgraded {
            if verbose {
                println!(
                    "\n==> Refreshing client integrations via upgraded binary ({}) ...",
                    new_exe.display()
                );
            } else {
                println!("==> Refreshing client integrations ...");
            }
            refresh_via_upgraded_binary_with_options(
                new_exe,
                opts.runtime_dir,
                opts.home_dir,
                had_shims,
                None,
                !verbose,
            )?;
        }
    } else if verbose || opts.dry_run {
        println!("\n==> Skipping client integration refresh (--no-refresh)");
    }

    if opts.dry_run {
        if let Some((_, Some(planned_ver), _)) = &upgraded {
            println!(
                "==> [dry-run] Target version: v{} (current: v{})",
                planned_ver.strip_prefix('v').unwrap_or(planned_ver),
                CURRENT_VERSION
            );
        }
    } else if let Some((_, installed_ver, kept_newer_local)) = upgraded {
        println!(
            "==> {}",
            format_upgrade_outcome(CURRENT_VERSION, installed_ver.as_deref(), kept_newer_local)
        );
    } else if opts.refresh_only {
        println!(
            "==> Refreshed client integrations (Aegis OS v{}).",
            CURRENT_VERSION
        );
    }

    Ok(())
}
