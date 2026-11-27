use super::*;

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

pub(super) struct RawTerminalGuard {
    pub(super) fd: libc::c_int,
    pub(super) orig: Option<libc::termios>,
}

impl RawTerminalGuard {
    pub(super) fn enter(fd: libc::c_int) -> Self {
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
) -> anyhow::Result<i32> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    #[cfg(target_os = "macos")]
    let mut winsize = terminal_size();
    #[cfg(not(target_os = "macos"))]
    let winsize = terminal_size();
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            #[cfg(target_os = "macos")]
            &mut winsize,
            #[cfg(not(target_os = "macos"))]
            &winsize,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("allocating a PTY");
    }
    set_fd_cloexec(master);
    set_fd_cloexec(slave);

    // Seed the slave PTY with the caller's initial termios before switching the host terminal
    // into raw passthrough mode (`cfmakeraw`), so arrow keys, Esc, and terminal capability
    // replies are forwarded byte-by-byte to the sandbox PTY without local canonical buffering or
    // echo on the host tty.
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut term) } == 0 {
        let _ = unsafe { libc::tcsetattr(slave, libc::TCSANOW, &term) };
    }
    let raw_guard = RawTerminalGuard::enter(libc::STDIN_FILENO);

    let master_file = unsafe { File::from_raw_fd(master) };
    let slave_file = unsafe { File::from_raw_fd(slave) };
    let stdin = slave_file.try_clone()?;
    let stdout = slave_file.try_clone()?;
    let stderr = slave_file.try_clone()?;

    let mut cmd = std::process::Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    for (key, value) in envs {
        cmd.env(key, value);
    }
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            for sig in [
                libc::SIGCHLD,
                libc::SIGHUP,
                libc::SIGINT,
                libc::SIGQUIT,
                libc::SIGTERM,
                libc::SIGALRM,
            ] {
                libc::signal(sig, libc::SIG_DFL);
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("spawning bwrap under a PTY")?;
    drop(slave_file);

    let mut reader = master_file.try_clone()?;
    let mut writer = master_file.try_clone()?;
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut buf = [0u8; 8192];
        let mut out = std::io::stdout();
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = out.flush();
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut buf = [0u8; 1024];
        let mut input = std::io::stdin();
        loop {
            match input.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = writer.flush();
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    let pid = child.id();
    let mut wait = tokio::task::spawn_blocking(move || child.wait());
    let mut first_interrupt = true;
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            status = &mut wait => {
                let status = status??;
                drop(raw_guard);
                let code = exit_code(status);
                sync_credentials(agent_home, host_home, orig_command);
                let pending = print_exit_summary(session_dir, host_project, shadow, telemetry).await;
                let effective = if code == 0 && pending > 0 { 10 } else { code };
                update_session_state(session_dir, "exited", Some(effective));
                return Ok(effective);
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_err() {
                    let status = wait.await??;
                    drop(raw_guard);
                    let code = exit_code(status);
                    sync_credentials(agent_home, host_home, orig_command);
                    let pending = print_exit_summary(session_dir, host_project, shadow, telemetry).await;
                    let effective = if code == 0 && pending > 0 { 10 } else { code };
                    update_session_state(session_dir, "exited", Some(effective));
                    return Ok(effective);
                }
                if pid > 0 {
                    let sig = if first_interrupt { libc::SIGINT } else { libc::SIGKILL };
                    first_interrupt = false;
                    unsafe {
                        libc::kill(pid as libc::pid_t, sig);
                    }
                }
            }
            _ = sigwinch.recv() => {
                let ws = terminal_size();
                let _ = unsafe {
                    libc::ioctl(
                        master_file.as_raw_fd(),
                        libc::TIOCSWINSZ as libc::c_ulong,
                        &ws,
                    )
                };
                if pid > 0 {
                    unsafe {
                        libc::kill(pid as libc::pid_t, libc::SIGWINCH);
                    }
                }
            }
            _ = sigterm.recv() => {
                if pid > 0 {
                    unsafe {
                        libc::kill(pid as libc::pid_t, libc::SIGTERM);
                    }
                }
            }
        }
    }
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
