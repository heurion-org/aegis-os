use super::*;

/// Prefer the stable Homebrew symlink when `current_exe()` resolves into a versioned Cellar
/// path so `~/.aegis/bin/*` shims do not break after `brew upgrade aegis-os`.
pub(super) fn stable_aegis_exe_for_shim() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
    if exe.to_string_lossy().contains("/Cellar/aegis-os/") {
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
    }
    exe
}

#[allow(dead_code)]
pub(crate) fn install_enforced_shims_with_path(
    home_dir: &Path,
    dry_run: bool,
    path_override: Option<&std::ffi::OsStr>,
) -> anyhow::Result<()> {
    install_enforced_shims_with_options(home_dir, dry_run, path_override, false)
}

pub(crate) fn install_enforced_shims_with_options(
    home_dir: &Path,
    dry_run: bool,
    path_override: Option<&std::ffi::OsStr>,
    quiet: bool,
) -> anyhow::Result<()> {
    let shim_dir = home_dir.join(".aegis").join("bin");
    let aegis = stable_aegis_exe_for_shim();
    let path_val = path_override
        .map(|p| p.to_os_string())
        .or_else(|| std::env::var_os("PATH"));
    let mut agents = Vec::new();
    for agent in ["claude", "codex", "agy", "opencode", "hermes"] {
        let mut real = None;
        if let Some(ref path_env) = path_val {
            for dir in std::env::split_paths(path_env) {
                if dir == shim_dir || dir.ends_with(".aegis/bin") {
                    continue;
                }
                let candidate = dir.join(agent);
                if candidate.is_file() {
                    real = Some(candidate);
                    break;
                }
            }
        }
        let Some(real) = real else {
            continue;
        };
        let script = format!(
            "#!/bin/sh\n\
             if [ \"${{AOS_ENFORCEMENT:-}}\" = \"advisory\" ]; then\n\
               exec \"{}\" \"$@\"\n\
             fi\n\
             exec \"{}\" --workspace \"$PWD\" run -- \"{}\" \"$@\"\n",
            real.display(),
            aegis.display(),
            real.display()
        );
        let path = shim_dir.join(agent);
        if dry_run {
            if !quiet {
                println!("  - would write {} -> {}", path.display(), real.display());
            }
        } else {
            std::fs::create_dir_all(&shim_dir)?;
            std::fs::write(&path, script)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
            }
        }
        agents.push(agent);
    }
    if agents.is_empty() {
        if !quiet {
            println!("\n[enforce] Aegis launcher shims:");
            println!("  - no supported agents found on PATH");
        }
    } else {
        let path_block_present =
            install_shell_path_block_with_options(home_dir, &shim_dir, dry_run, quiet)?;
        if !quiet {
            println!("\n[enforce] Aegis launcher shims:");
            for agent in &agents {
                println!("  - {}", shim_dir.join(agent).display());
            }
            if path_block_present {
                if !dry_run {
                    println!(
                        "  PATH block present; new shells will prefer {}",
                        shim_dir.display()
                    );
                }
            } else {
                println!(
                    "  Add this to your shell profile: export PATH=\"{}:$PATH\"",
                    shim_dir.display()
                );
            }
        }
    }
    Ok(())
}

pub(super) fn file_mentions_aegis(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|text| text.contains("aegis-os") || text.contains("Aegis OS"))
        .unwrap_or(false)
}

pub(super) fn format_doctor_disk_status(avail_bytes: u64, total_bytes: u64) -> String {
    let avail_gb = avail_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    let pct = if total_bytes > 0 {
        (avail_bytes as f64 / total_bytes as f64) * 100.0
    } else {
        0.0
    };
    if crate::hooks::is_low_disk(avail_bytes, total_bytes) {
        format!(
            "WARN ({:.2} GB free, {:.1}% — run `aegis-os disk` or `aegis-os gc --dry-run`)",
            avail_gb, pct
        )
    } else {
        format!("OK ({:.2} GB free, {:.1}%)", avail_gb, pct)
    }
}

pub(super) fn find_executable_on_path(bin: &str, path_env: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let path_env = path_env?;
    for dir in std::env::split_paths(path_env) {
        let cand = dir.join(bin);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

pub(super) fn probe_rust_toolchain_status(path_env: Option<&std::ffi::OsStr>) -> String {
    if find_executable_on_path("cargo", path_env).is_none() {
        return "not on PATH (skipped)".to_string();
    }
    let Some(rustc_bin) = find_executable_on_path("rustc", path_env) else {
        return "WARN (`rustc` not found on PATH; run `rustup toolchain install stable --force`)"
            .to_string();
    };
    match std::process::Command::new(&rustc_bin).arg("-vV").output() {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let release = stdout
                .lines()
                .find_map(|line| line.strip_prefix("release:").map(str::trim))
                .filter(|s| !s.is_empty());
            match release {
                Some(ver) => format!("ok (rustc {ver})"),
                None => "ok".to_string(),
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = stderr
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("non-zero exit");
            format!(
                "WARN (`rustc -vV` failed: {detail}; run `rustup toolchain install stable --force`)"
            )
        }
        Err(err) => {
            format!(
                "WARN (`rustc -vV` failed: {err}; run `rustup toolchain install stable --force`)"
            )
        }
    }
}

pub(crate) async fn run_doctor(home_dir: &Path) -> anyhow::Result<()> {
    let checks = vec![
        ("AGY MCP Config", home_dir.join(".gemini/config/mcp_config.json")),
        ("AGY Lifecycle Hooks", home_dir.join(".gemini/config/hooks.json")),
        ("AGY Auto-Allow Rules", home_dir.join(".gemini/antigravity-cli/settings.json")),
        ("AGY Global Rules", home_dir.join(".gemini/config/GEMINI.md")),
        ("Claude Code MCP Config", home_dir.join(".claude.json")),
        ("Claude Code Permissions", home_dir.join(".claude/settings.json")),
        ("Codex CLI Config", home_dir.join(".codex/config.toml")),
        ("OpenCode Config", home_dir.join(".config/opencode/opencode.json")),
        ("OpenCode Rules", home_dir.join(".config/opencode/AGENTS.md")),
        (
            "OpenCode Aegis Plugin",
            home_dir.join(".config/opencode/plugins/aegis-os.js"),
        ),
        (
            "AGY Runtime Skill",
            home_dir.join(".gemini/config/skills/aegis-os-runtime/SKILL.md"),
        ),
        (
            "Claude Runtime Skill",
            home_dir.join(".claude/skills/aegis-os-runtime/SKILL.md"),
        ),
        (
            "Codex Runtime Skill",
            home_dir.join(".codex/skills/aegis-os-runtime/SKILL.md"),
        ),
        (
            "OpenCode Runtime Skill",
            home_dir.join(".config/opencode/skills/aegis-os-runtime/SKILL.md"),
        ),
    ];

    println!("Aegis OS Integration Health Check (`aegis-os doctor`):");
    for (name, path) in checks {
        let status = if !path.exists() {
            "MISSING (Run `aegis-os install`)".to_string()
        } else if file_mentions_aegis(&path) {
            "OK (Aegis entry found)".to_string()
        } else {
            "PRESENT (no Aegis entry found)".to_string()
        };
        println!("  - {:<26} [{}] -> {}", name, status, path.display());
    }

    let shim_dir = home_dir.join(".aegis").join("bin");
    let shims: Vec<String> = ["claude", "codex", "agy", "opencode", "hermes"]
        .into_iter()
        .filter(|agent| shim_dir.join(agent).is_file())
        .map(str::to_string)
        .collect();
    let shim_first = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).next() == Some(shim_dir.clone()))
        .unwrap_or(false);
    println!("\nEnforcement:");
    if shims.is_empty() {
        println!("  - mode: advisory (no PATH shims; run `aegis-os install --enforce`)");
    } else if shim_first {
        println!(
            "  - mode: enforced available via PATH shim ({})",
            shims.join(", ")
        );
    } else {
        println!(
            "  - mode: shims installed ({}) but {} is not first in PATH",
            shims.join(", "),
            shim_dir.display()
        );
    }
    println!("  - broker: per-session Unix/TCP control socket is started by `aos run`");
    println!(
        "  - l7: base-url routes available for Anthropic / OpenAI / Gemini / DeepSeek / Mistral / Groq / xAI / OpenRouter"
    );
    println!("  - generic https: CONNECT-only domain allowlist (no L7 without opt-in MITM)");

    if let Ok(path_env) = std::env::var("PATH") {
        let mut seen = std::collections::BTreeSet::new();
        println!("\nBinary Resolution on PATH:");
        for dir in std::env::split_paths(&path_env) {
            let cand = dir.join("aegis-os");
            if cand.is_file() && seen.insert(cand.clone()) {
                let ver = std::process::Command::new(&cand)
                    .arg("--version")
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                println!("  - {} ({})", cand.display(), ver);
            }
        }
    }

    println!("\nHost Environment:");
    match crate::hooks::fs_disk_space_bytes(home_dir) {
        Some((avail, total)) => {
            println!(
                "  - disk ({}): {}",
                home_dir.display(),
                format_doctor_disk_status(avail, total)
            );
        }
        None => {
            println!("  - disk ({}): unavailable", home_dir.display());
        }
    }
    println!(
        "  - rust toolchain: {}",
        probe_rust_toolchain_status(std::env::var_os("PATH").as_deref())
    );

    println!("\nEnforced Runtime (Phase 1):");
    #[cfg(target_os = "linux")]
    {
        match aos_sandbox::linux_bwrap_path() {
            Some(bwrap) => {
                let help = std::process::Command::new(bwrap)
                    .arg("--help")
                    .output()
                    .map(|o| {
                        format!(
                            "{}{}",
                            String::from_utf8_lossy(&o.stdout),
                            String::from_utf8_lossy(&o.stderr)
                        )
                    })
                    .unwrap_or_default();
                if help.contains("--bind-fd") && help.contains("--ro-bind-fd") {
                    println!("  - status: READY (`{bwrap}` supports --bind-fd)");
                    println!("  - launch: `aegis-os --workspace . run -- claude`");
                } else {
                    println!("  - status: BLOCKED (`{bwrap}` is too old; need >= 0.10 with --bind-fd)");
                }
            }
            None => println!("  - status: BLOCKED (install bubblewrap >= 0.10)"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if Path::new("/usr/bin/sandbox-exec").exists() {
            println!("  - status: READY (macOS Seatbelt MVP; shadow cwd, no path remap)");
            println!("  - launch: `aegis-os --workspace . run -- claude`");
        } else {
            println!("  - status: BLOCKED (/usr/bin/sandbox-exec is missing)");
        }
    }

    println!("Hardware-Isolated Runtime (--isolated MicroVM):");
    let vm_runtime = aos_sandbox::microvm::default_runtime_dir_for_vm();
    let probe = aos_sandbox::microvm::probe_microvm_host(&vm_runtime);
    println!("  - platform: {} ({})", probe.os, probe.arch);
    println!("  - hypervisor: {}", probe.hypervisor_detail);
    match (&probe.vmm_backend, &probe.vmm_path) {
        (Some(kind), Some(path)) => println!("  - vmm: {} ({})", kind.as_str(), path.display()),
        _ => println!("  - vmm: MISSING (install vfkit/krunkit on macOS or cloud-hypervisor on Linux)"),
    }
    if cfg!(target_os = "linux") {
        match &probe.virtiofsd_path {
            Some(p) => println!("  - virtiofsd: {}", p.display()),
            None => println!("  - virtiofsd: MISSING (required on Linux for virtio-fs mounts)"),
        }
    }
    println!(
        "  - vm images ({}): {} ({})",
        probe.images_dir.display(),
        if probe.images_ready { "READY" } else { "MISSING" },
        probe.images_detail
    );
    if probe.ready {
        println!("  - status: READY (hardware-isolated Zero-NIC MicroVM)");
        println!("  - launch: `aegis-os --workspace . run --isolated -- claude`");
    } else {
        println!("  - status: NOT READY (fail-closed; run `aegis-os vm pull` after installing VMM)");
    }
    Ok(())
}
