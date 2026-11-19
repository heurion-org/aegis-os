//! Aegis OS MicroVM Guest PID-1 / Unix Harness Entrypoint (`aegis-guest-init`).

use anyhow::{bail, Context};
use aos_guest_init::{GuestBootConfig, DEFAULT_GUEST_PROXY_PORT};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--pid1") || std::process::id() == 1 {
        #[cfg(target_os = "linux")]
        {
            async fn run_pid1() -> anyhow::Result<()> {
                aos_guest_init::bootstrap_linux_early()?;
                let cmdline = std::fs::read_to_string("/proc/cmdline")
                    .context("reading /proc/cmdline in MicroVM guest")?;
                let cfg = GuestBootConfig::from_kernel_cmdline(&cmdline)?;
                aos_guest_init::mount_linux_virtiofs_shares(&cfg)?;
                aos_guest_init::serve_guest_vsock(cfg).await?;
                Ok(())
            }
            if let Err(err) = run_pid1().await {
                eprintln!("aegis-guest-init PID 1 fatal: {err:#}");
            }
            unsafe {
                libc::sync();
                libc::reboot(libc::RB_POWER_OFF);
            }
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            bail!("--pid1 is only supported inside a Linux MicroVM guest");
        }
    }

    let mut exec_sock: Option<PathBuf> = None;
    let mut egress_sock: Option<PathBuf> = None;
    let mut auth_token: Option<String> = None;
    let mut bridge_token: Option<String> = None;
    let mut ws_dest = PathBuf::from(".");
    let mut home_dest = PathBuf::from("/tmp/aegis-guest-home");
    let mut ro_dest = PathBuf::from("/tmp/aegis-guest-ro");
    let mut pub_dest = PathBuf::from("/tmp/aegis-guest-pub");
    let mut proxy_bind = format!("127.0.0.1:{DEFAULT_GUEST_PROXY_PORT}");

    let mut idx = 1usize;
    while idx < args.len() {
        let take_next = |i: &mut usize, flag: &str| -> anyhow::Result<String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .with_context(|| format!("{flag} requires a value"))
        };
        match args[idx].as_str() {
            "--unix-exec" => exec_sock = Some(PathBuf::from(take_next(&mut idx, "--unix-exec")?)),
            "--unix-egress" => {
                egress_sock = Some(PathBuf::from(take_next(&mut idx, "--unix-egress")?))
            }
            "--auth-token" => auth_token = Some(take_next(&mut idx, "--auth-token")?),
            "--bridge-token" => bridge_token = Some(take_next(&mut idx, "--bridge-token")?),
            "--ws-dest" => ws_dest = PathBuf::from(take_next(&mut idx, "--ws-dest")?),
            "--home-dest" => home_dest = PathBuf::from(take_next(&mut idx, "--home-dest")?),
            "--ro-dest" => ro_dest = PathBuf::from(take_next(&mut idx, "--ro-dest")?),
            "--pub-dest" => pub_dest = PathBuf::from(take_next(&mut idx, "--pub-dest")?),
            "--proxy-bind" => proxy_bind = take_next(&mut idx, "--proxy-bind")?,
            "--help" | "-h" => {
                println!(
                    "aegis-guest-init (--pid1 | --unix-exec <sock> --auth-token <tok> [--unix-egress <sock>] [--bridge-token <tok>] [--ws-dest <dir>] [--home-dest <dir>])"
                );
                return Ok(());
            }
            other => bail!("unknown argument '{other}'"),
        }
        idx += 1;
    }

    let exec_sock = exec_sock.context("pass --pid1 or --unix-exec <sock>")?;
    let auth_token = auth_token.context("--auth-token is required with --unix-exec")?;
    let cfg = GuestBootConfig {
        ws_dest,
        home_dest,
        ro_dest,
        pub_dest,
        host_ro_dest: None,
        auth_token,
        bridge_token,
        proxy_port: DEFAULT_GUEST_PROXY_PORT,
    };
    let (_addr, handle) =
        aos_guest_init::serve_guest_unix(&exec_sock, egress_sock, &proxy_bind, cfg).await?;
    handle.await?;
    Ok(())
}
