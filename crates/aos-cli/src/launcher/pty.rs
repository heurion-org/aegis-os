use super::*;
use super::pty_hub::{DetachEscapeFilter, PtyHub};
use crate::cloud::client::load_cloud_auth;
use crate::relay::host::RelayHostHandle;
use aos_mcp_gateway::relay::SessionMode;

#[derive(Debug, Clone)]
pub(super) struct PtyShareOptions {
    pub runtime_dir: PathBuf,
    pub session_id: String,
    pub project_name: String,
    pub agent_kind: String,
    pub share: bool,
    pub local_only: bool,
    pub headless_detached: bool,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_plain_command(
    program: &str,
    args: &[String],
    cwd: &Path,
    envs: &[(String, String)],
    session_dir: &Path,
    agent_home: &Path,
    host_home: &Path,
    orig_command: &[String],
    project: &Path,
    telemetry: Option<&ExitTelemetryContext>,
) -> anyhow::Result<i32> {
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(cwd).env_clear().kill_on_drop(true);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn()?;
    let pid = child.id().unwrap_or(0);
    let mut wait = Box::pin(child.wait());
    loop {
        tokio::select! {
            status = &mut wait => {
                let code = exit_code(status?);
                sync_credentials(agent_home, host_home, orig_command);
                let pending = print_exit_summary(session_dir, project, cwd, telemetry).await;
                let effective = if code == 0 && pending > 0 { 10 } else { code };
                update_session_state(session_dir, "exited", Some(effective));
                return Ok(effective);
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_err() {
                    break;
                }
                if pid > 0 {
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT); }
                }
            }
        }
    }
    let status = wait.await?;
    let code = exit_code(status);
    sync_credentials(agent_home, host_home, orig_command);
    let pending = print_exit_summary(session_dir, project, cwd, telemetry).await;
    let effective = if code == 0 && pending > 0 { 10 } else { code };
    update_session_state(session_dir, "exited", Some(effective));
    Ok(effective)
}

pub(crate) struct RawTerminalGuard {
    pub(crate) fd: libc::c_int,
    pub(crate) orig: Option<libc::termios>,
}

impl RawTerminalGuard {
    pub(crate) fn enter(fd: libc::c_int) -> Self {
        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
            return Self { fd, orig: None };
        }
        let mut raw = orig;
        unsafe {
            libc::cfmakeraw(&mut raw);
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &raw);
        }
        Self {
            fd,
            orig: Some(orig),
        }
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if let Some(ref orig) = self.orig.take() {
            unsafe {
                let _ = libc::tcsetattr(self.fd, libc::TCSADRAIN, orig);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_pty_command(
    program: &str,
    args: &[String],
    cwd: &Path,
    envs: &[(String, String)],
    session_dir: &Path,
    agent_home: &Path,
    host_home: &Path,
    orig_command: &[String],
    host_project: &Path,
    shadow: &Path,
    telemetry: Option<&ExitTelemetryContext>,
    share_opts: &PtyShareOptions,
) -> anyhow::Result<i32> {
    let winsize = terminal_size();
    let (hub, mut wait_handle) = PtyHub::spawn(
        program,
        args,
        cwd,
        envs,
        winsize,
        Some(session_dir),
    )?;

    let relay_handle: Option<RelayHostHandle> = if share_opts.local_only {
        None
    } else if let Some(auth) = load_cloud_auth(&share_opts.runtime_dir) {
        match RelayHostHandle::start(
            &share_opts.runtime_dir,
            auth,
            hub.clone(),
            share_opts.session_id.clone(),
            share_opts.agent_kind.clone(),
            share_opts.project_name.clone(),
            None,
            SessionMode::Pty,
        )
        .await
        {
            Ok(h) => {
                let web_app_url = load_cloud_auth(&share_opts.runtime_dir)
                    .map(|a| format!("{}/app", crate::cloud::client::api_base(&a.endpoint)));
                eprintln!(
                    "  relay:   E2EE shared session ready (`aegis-os attach {}`)",
                    share_opts.session_id
                );
                if let Some(url) = web_app_url {
                    let has_paired_client = crate::relay::device::load_local_device_store(&share_opts.runtime_dir)
                        .is_some_and(|s| s.trusted_peers.iter().any(|p| !p.is_root && !p.revoked));
                    if has_paired_client {
                        eprintln!("  console: {url}");
                    } else {
                        eprintln!("  console: {url} (run `aegis-os devices pair` for a 1-click phone/browser QR link)");
                    }
                }
                Some(h)
            }
            Err(err) if share_opts.share => {
                hub.shutdown();
                return Err(err).context("starting E2EE cloud relay for --share");
            }
            Err(err) => {
                eprintln!("  relay:   disabled ({})", err);
                None
            }
        }
    } else if share_opts.share {
        hub.shutdown();
        anyhow::bail!(
            "aos run --share requires cloud login (`aegis-os cloud login` or `aegis-os cloud subscribe`)"
        );
    } else {
        None
    };

    let mut local_attached = !share_opts.headless_detached;
    let mut raw_guard = if local_attached {
        Some(RawTerminalGuard::enter(libc::STDIN_FILENO))
    } else {
        None
    };

    let mut out_rx = hub.subscribe_output();
    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(128);
    let (detach_tx, mut detach_rx) = tokio::sync::oneshot::channel::<()>();

    if local_attached {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut input = std::io::stdin();
            let mut buf = [0u8; 1024];
            let mut filter = DetachEscapeFilter::new();
            loop {
                match input.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let (forward, detached) = filter.feed(&buf[..n]);
                        if !forward.is_empty() && in_tx.blocking_send(forward).is_err() {
                            break;
                        }
                        if detached {
                            let _ = detach_tx.send(());
                            break;
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        });
    } else {
        drop(detach_tx);
    }

    let mut first_interrupt = true;
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut stdout = std::io::stdout();

    let status = loop {
        tokio::select! {
            res = &mut wait_handle => {
                break res??;
            }
            _ = &mut detach_rx, if local_attached => {
                local_attached = false;
                drop(raw_guard.take());
                eprintln!(
                    "\r\n[Aegis local terminal detached; session '{}' continues running — reattach with `aegis-os attach {}`]",
                    share_opts.session_id, share_opts.session_id
                );
            }
            chunk = out_rx.recv(), if local_attached => {
                match chunk {
                    Ok(bytes) => {
                        use std::io::Write;
                        if stdout.write_all(&bytes).is_err() {
                            local_attached = false;
                            drop(raw_guard.take());
                        }
                        let _ = stdout.flush();
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        local_attached = false;
                    }
                }
            }
            Some(bytes) = in_rx.recv(), if local_attached => {
                let _ = hub.send_input(bytes).await;
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_err() {
                    break wait_handle.await??;
                }
                let sig = if first_interrupt { libc::SIGINT } else { libc::SIGKILL };
                first_interrupt = false;
                hub.signal_sync(sig);
            }
            _ = sigwinch.recv(), if local_attached => {
                hub.resize_sync(terminal_size());
            }
            _ = sigterm.recv() => {
                hub.signal_sync(libc::SIGTERM);
            }
        }
    };

    drop(raw_guard.take());
    if let Some(rh) = relay_handle {
        rh.shutdown().await;
    }
    hub.shutdown();

    let code = exit_code(status);
    sync_credentials(agent_home, host_home, orig_command);
    let pending = print_exit_summary(session_dir, host_project, shadow, telemetry).await;
    let effective = if code == 0 && pending > 0 { 10 } else { code };
    update_session_state(session_dir, "exited", Some(effective));
    Ok(effective)
}

pub(super) fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}
