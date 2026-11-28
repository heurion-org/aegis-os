use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, watch};

pub const PTY_RING_CAPACITY: usize = 256 * 1024;
const BROADCAST_CAPACITY: usize = 512;

#[derive(Debug, Clone)]
pub enum PtyAction {
    WriteInput(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Signal(libc::c_int),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalPtyServerMsg {
    Replay {
        cols: u16,
        rows: u16,
        data_b64: String,
    },
    Out {
        data_b64: String,
    },
    Exited {
        code: i32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalPtyClientMsg {
    Input { data_b64: String },
    Resize { cols: u16, rows: u16 },
    Signal { signal: i32 },
    Detach,
}

/// Filters stdin bytes for the `Ctrl-] d` (`0x1d`, `b'd'`) detach escape sequence.
#[derive(Debug, Default)]
pub struct DetachEscapeFilter {
    pending_ctrl_bracket: bool,
}

impl DetachEscapeFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Scans `input`, returning forwarded bytes and whether `Ctrl-] d` was triggered.
    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        let mut out = Vec::with_capacity(input.len() + 1);
        for &b in input {
            if self.pending_ctrl_bracket {
                self.pending_ctrl_bracket = false;
                if b == b'd' || b == 0x04 {
                    return (out, true);
                }
                out.push(0x1d);
                if b == 0x1d {
                    self.pending_ctrl_bracket = true;
                } else {
                    out.push(b);
                }
            } else if b == 0x1d {
                self.pending_ctrl_bracket = true;
            } else {
                out.push(b);
            }
        }
        (out, false)
    }

    /// Flushes any trailing buffered `0x1d` byte (e.g. if a lone `Ctrl-]` was sent before timeout).
    #[allow(dead_code)]
    pub fn flush_pending(&mut self) -> Option<u8> {
        if self.pending_ctrl_bracket {
            self.pending_ctrl_bracket = false;
            Some(0x1d)
        } else {
            None
        }
    }
}

pub struct PtyHub {
    pid: libc::pid_t,
    master_file: Option<Arc<File>>,
    ring: Arc<Mutex<VecDeque<u8>>>,
    winsize: Arc<Mutex<(u16, u16)>>,
    out_tx: broadcast::Sender<Vec<u8>>,
    action_tx: mpsc::Sender<PtyAction>,
    alive: Arc<AtomicBool>,
    exit_rx: watch::Receiver<Option<i32>>,
    exit_tx: watch::Sender<Option<i32>>,
    sock_path: Option<PathBuf>,
}

impl PtyHub {
    pub fn spawn(
        program: &str,
        args: &[String],
        cwd: &Path,
        envs: &[(String, String)],
        initial_winsize: libc::winsize,
        session_dir: Option<&Path>,
    ) -> Result<(Arc<Self>, tokio::task::JoinHandle<std::io::Result<ExitStatus>>)> {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        #[cfg(target_os = "macos")]
        let mut ws = initial_winsize;
        #[cfg(not(target_os = "macos"))]
        let ws = initial_winsize;
        if unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                #[cfg(target_os = "macos")]
                &mut ws,
                #[cfg(not(target_os = "macos"))]
                &ws,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error()).context("allocating a PTY");
        }
        super::set_fd_cloexec(master);
        super::set_fd_cloexec(slave);

        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut term) } == 0 {
            let _ = unsafe { libc::tcsetattr(slave, libc::TCSANOW, &term) };
        }

        let master_file = Arc::new(unsafe { File::from_raw_fd(master) });
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
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawning '{}' under a PTY", program))?;
        drop(slave_file);

        let pid = child.id() as libc::pid_t;
        let ring = Arc::new(Mutex::new(VecDeque::with_capacity(8192)));
        let (out_tx, _) = broadcast::channel::<Vec<u8>>(BROADCAST_CAPACITY);
        let (action_tx, mut action_rx) = mpsc::channel::<PtyAction>(256);
        let alive = Arc::new(AtomicBool::new(true));
        let (exit_tx, exit_rx) = watch::channel(None);
        let cols = if initial_winsize.ws_col == 0 {
            80
        } else {
            initial_winsize.ws_col
        };
        let rows = if initial_winsize.ws_row == 0 {
            24
        } else {
            initial_winsize.ws_row
        };
        let winsize = Arc::new(Mutex::new((cols, rows)));
        let sock_path = session_dir.map(|d| d.join("pty.sock"));

        let hub = Arc::new(Self {
            pid,
            master_file: Some(master_file.clone()),
            ring: ring.clone(),
            winsize: winsize.clone(),
            out_tx: out_tx.clone(),
            action_tx,
            alive: alive.clone(),
            exit_rx,
            exit_tx,
            sock_path: sock_path.clone(),
        });

        // Reader thread: reads master PTY output -> ring buffer + broadcast channel.
        let mut reader = master_file.try_clone()?;
        let ring_reader = ring;
        let out_tx_reader = out_tx;
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = buf[..n].to_vec();
                        if let Ok(mut guard) = ring_reader.lock() {
                            for &b in &chunk {
                                if guard.len() >= PTY_RING_CAPACITY {
                                    guard.pop_front();
                                }
                                guard.push_back(b);
                            }
                        }
                        let _ = out_tx_reader.send(chunk);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        });

        // Action task: serializes PTY input writes, resizes, and signal delivery.
        let mut writer = master_file.try_clone()?;
        let master_for_resize = master_file;
        let alive_for_act = alive.clone();
        let winsize_for_act = winsize;
        tokio::spawn(async move {
            while let Some(action) = action_rx.recv().await {
                if !alive_for_act.load(Ordering::Acquire) {
                    break;
                }
                match action {
                    PtyAction::WriteInput(data) => {
                        let _ = writer.write_all(&data);
                        let _ = writer.flush();
                    }
                    PtyAction::Resize { cols, rows } => {
                        if let Ok(mut guard) = winsize_for_act.lock() {
                            *guard = (cols, rows);
                        }
                        let ws = libc::winsize {
                            ws_row: rows,
                            ws_col: cols,
                            ws_xpixel: 0,
                            ws_ypixel: 0,
                        };
                        unsafe {
                            libc::ioctl(
                                master_for_resize.as_raw_fd(),
                                libc::TIOCSWINSZ as libc::c_ulong,
                                &ws,
                            );
                        }
                        if pid > 0 {
                            unsafe {
                                libc::kill(pid, libc::SIGWINCH);
                            }
                        }
                    }
                    PtyAction::Signal(sig) => {
                        if pid > 0 {
                            unsafe {
                                libc::kill(pid, sig);
                            }
                        }
                    }
                }
            }
        });

        // Child wait task marks hub exited once the child terminates.
        let hub_for_wait = hub.clone();
        let wait_handle = tokio::task::spawn_blocking(move || {
            let res = child.wait();
            hub_for_wait.alive.store(false, Ordering::Release);
            let code = match &res {
                Ok(st) => super::pty::exit_code(*st),
                Err(_) => 1,
            };
            let _ = hub_for_wait.exit_tx.send(Some(code));
            res
        });

        if let Some(ref sp) = sock_path {
            if sp.as_os_str().len() < 103 {
                hub.clone().spawn_unix_socket_server(sp.clone())?;
            }
        }

        Ok((hub, wait_handle))
    }

    /// Pipe-backed [`PtyHub`] constructor for headless environments where `/dev/ptmx` (`openpty`)
    /// is restricted (e.g., inside Seatbelt sandboxes during tests).
    #[cfg(test)]
    pub fn spawn_piped(
        program: &str,
        args: &[String],
        cwd: &Path,
        envs: &[(String, String)],
        initial_winsize: libc::winsize,
        session_dir: Option<&Path>,
    ) -> Result<(Arc<Self>, tokio::task::JoinHandle<std::io::Result<ExitStatus>>)> {
        let mut cmd = std::process::Command::new(program);
        cmd.args(args)
            .current_dir(cwd)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in envs {
            cmd.env(key, value);
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawning '{}' piped", program))?;
        let mut stdin = child.stdin.take().context("missing piped stdin")?;
        let stdout = child.stdout.take().context("missing piped stdout")?;
        let stderr = child.stderr.take().context("missing piped stderr")?;

        let pid = child.id() as libc::pid_t;
        let ring = Arc::new(Mutex::new(VecDeque::with_capacity(8192)));
        let (out_tx, _) = broadcast::channel::<Vec<u8>>(BROADCAST_CAPACITY);
        let (action_tx, mut action_rx) = mpsc::channel::<PtyAction>(256);
        let alive = Arc::new(AtomicBool::new(true));
        let (exit_tx, exit_rx) = watch::channel(None);
        let cols = if initial_winsize.ws_col == 0 {
            80
        } else {
            initial_winsize.ws_col
        };
        let rows = if initial_winsize.ws_row == 0 {
            24
        } else {
            initial_winsize.ws_row
        };
        let winsize = Arc::new(Mutex::new((cols, rows)));
        let sock_path = session_dir.map(|d| d.join("pty.sock"));

        let hub = Arc::new(Self {
            pid,
            master_file: None,
            ring: ring.clone(),
            winsize: winsize.clone(),
            out_tx: out_tx.clone(),
            action_tx,
            alive: alive.clone(),
            exit_rx,
            exit_tx,
            sock_path: sock_path.clone(),
        });

        let spawn_pipe_reader = |mut reader: Box<dyn Read + Send>,
                                 ring_r: Arc<Mutex<VecDeque<u8>>>,
                                 tx_r: broadcast::Sender<Vec<u8>>| {
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let chunk = buf[..n].to_vec();
                            if let Ok(mut guard) = ring_r.lock() {
                                for &b in &chunk {
                                    if guard.len() >= PTY_RING_CAPACITY {
                                        guard.pop_front();
                                    }
                                    guard.push_back(b);
                                }
                            }
                            let _ = tx_r.send(chunk);
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            });
        };
        spawn_pipe_reader(Box::new(stdout), ring.clone(), out_tx.clone());
        spawn_pipe_reader(Box::new(stderr), ring, out_tx);

        let alive_for_act = alive.clone();
        let winsize_for_act = winsize;
        tokio::spawn(async move {
            while let Some(action) = action_rx.recv().await {
                if !alive_for_act.load(Ordering::Acquire) {
                    break;
                }
                match action {
                    PtyAction::WriteInput(data) => {
                        let _ = stdin.write_all(&data);
                        let _ = stdin.flush();
                    }
                    PtyAction::Resize { cols, rows } => {
                        if let Ok(mut guard) = winsize_for_act.lock() {
                            *guard = (cols, rows);
                        }
                    }
                    PtyAction::Signal(sig) => {
                        if pid > 0 {
                            unsafe {
                                libc::kill(pid, sig);
                            }
                        }
                    }
                }
            }
        });

        let hub_for_wait = hub.clone();
        let wait_handle = tokio::task::spawn_blocking(move || {
            let res = child.wait();
            hub_for_wait.alive.store(false, Ordering::Release);
            let code = match &res {
                Ok(st) => super::pty::exit_code(*st),
                Err(_) => 1,
            };
            let _ = hub_for_wait.exit_tx.send(Some(code));
            res
        });

        if let Some(ref sp) = sock_path {
            if sp.as_os_str().len() < 103 {
                hub.clone().spawn_unix_socket_server(sp.clone())?;
            }
        }

        Ok((hub, wait_handle))
    }

    #[allow(dead_code)]
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    pub fn snapshot_ring(&self) -> (u16, u16, Vec<u8>) {
        let (cols, rows) = self.winsize.lock().map(|g| *g).unwrap_or((80, 24));
        let bytes = self
            .ring
            .lock()
            .map(|g| g.iter().copied().collect())
            .unwrap_or_default();
        (cols, rows, bytes)
    }

    pub fn subscribe_output(&self) -> broadcast::Receiver<Vec<u8>> {
        self.out_tx.subscribe()
    }

    pub fn subscribe_exit(&self) -> watch::Receiver<Option<i32>> {
        self.exit_rx.clone()
    }

    pub async fn send_input(&self, data: Vec<u8>) -> Result<()> {
        if !self.alive.load(Ordering::Acquire) {
            bail!("PTY session has exited");
        }
        self.action_tx
            .send(PtyAction::WriteInput(data))
            .await
            .map_err(|_| anyhow::anyhow!("PTY writer closed"))
    }

    pub async fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        if !self.alive.load(Ordering::Acquire) {
            return Ok(());
        }
        self.action_tx
            .send(PtyAction::Resize { cols, rows })
            .await
            .map_err(|_| anyhow::anyhow!("PTY control closed"))
    }

    pub async fn signal(&self, sig: libc::c_int) -> Result<()> {
        if !self.alive.load(Ordering::Acquire) {
            return Ok(());
        }
        self.action_tx
            .send(PtyAction::Signal(sig))
            .await
            .map_err(|_| anyhow::anyhow!("PTY control closed"))
    }

    pub fn signal_sync(&self, sig: libc::c_int) {
        if self.alive.load(Ordering::Acquire) && self.pid > 0 {
            unsafe {
                libc::kill(self.pid, sig);
            }
        }
    }

    pub fn resize_sync(&self, ws: libc::winsize) {
        if let Ok(mut guard) = self.winsize.lock() {
            *guard = (ws.ws_col, ws.ws_row);
        }
        if let Some(ref master) = self.master_file {
            unsafe {
                libc::ioctl(
                    master.as_raw_fd(),
                    libc::TIOCSWINSZ as libc::c_ulong,
                    &ws,
                );
            }
        }
        self.signal_sync(libc::SIGWINCH);
    }

    pub fn shutdown(&self) {
        self.alive.store(false, Ordering::Release);
        if let Some(ref sp) = self.sock_path {
            let _ = std::fs::remove_file(sp);
        }
    }

    fn spawn_unix_socket_server(self: Arc<Self>, sock_path: PathBuf) -> Result<()> {
        let _ = std::fs::remove_file(&sock_path);
        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(&sock_path).with_context(|| {
            format!("binding local PTY attach socket at {}", sock_path.display())
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));
        }

        let mut exit_rx = self.subscribe_exit();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = exit_rx.changed() => {
                        if exit_rx.borrow().is_some() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                let hub = self.clone();
                                tokio::spawn(async move {
                                    let _ = hub.handle_unix_client(stream).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            let _ = std::fs::remove_file(&sock_path);
        });
        Ok(())
    }

    async fn handle_unix_client(self: Arc<Self>, stream: UnixStream) -> Result<()> {
        let (read_half, mut write_half) = stream.into_split();
        let (cols, rows, replay) = self.snapshot_ring();
        let mut out_rx = self.subscribe_output();
        let mut exit_rx = self.subscribe_exit();

        let replay_line = serde_json::to_string(&LocalPtyServerMsg::Replay {
            cols,
            rows,
            data_b64: B64.encode(&replay),
        })? + "\n";
        write_half.write_all(replay_line.as_bytes()).await?;
        write_half.flush().await?;

        let (writer_tx, mut writer_rx) = mpsc::channel::<String>(256);
        let write_task = tokio::spawn(async move {
            while let Some(line) = writer_rx.recv().await {
                if write_half.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                let _ = write_half.flush().await;
            }
        });

        let mut reader = BufReader::new(read_half).lines();
        loop {
            tokio::select! {
                chunk = out_rx.recv() => {
                    match chunk {
                        Ok(bytes) => {
                            let line = serde_json::to_string(&LocalPtyServerMsg::Out {
                                data_b64: B64.encode(bytes),
                            })? + "\n";
                            let _ = writer_tx.try_send(line);
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = exit_rx.changed() => {
                    let exited_code = *exit_rx.borrow();
                    if let Some(code) = exited_code {
                        let line = serde_json::to_string(&LocalPtyServerMsg::Exited { code })? + "\n";
                        let _ = writer_tx.send(line).await;
                        break;
                    }
                }
                line_res = reader.next_line() => {
                    match line_res {
                        Ok(Some(line)) => {
                            let Ok(msg) = serde_json::from_str::<LocalPtyClientMsg>(&line) else {
                                continue;
                            };
                            match msg {
                                LocalPtyClientMsg::Input { data_b64 } => {
                                    if let Ok(bytes) = B64.decode(data_b64.trim()) {
                                        let _ = self.send_input(bytes).await;
                                    }
                                }
                                LocalPtyClientMsg::Resize { cols, rows } => {
                                    let _ = self.resize(cols, rows).await;
                                }
                                LocalPtyClientMsg::Signal { signal } => {
                                    let _ = self.signal(signal).await;
                                }
                                LocalPtyClientMsg::Detach => break,
                            }
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
            }
        }
        drop(writer_tx);
        let _ = write_task.await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn test_detach_escape_filter() {
        let mut f = DetachEscapeFilter::new();

        // Ctrl-] x passes both through
        let (out, det) = f.feed(&[0x1d, b'x', b'a']);
        assert!(!det);
        assert_eq!(out, vec![0x1d, b'x', b'a']);

        // Split across two reads: [0x1d] then [b'd'] triggers detach
        let (out1, det1) = f.feed(&[b'h', b'i', 0x1d]);
        assert!(!det1);
        assert_eq!(out1, b"hi");

        let (out2, det2) = f.feed(b"dz");
        assert!(det2);
        assert!(out2.is_empty());
    }

    #[tokio::test]
    async fn test_pty_hub_ring_replay_and_unix_socket() {
        // Keep path short enough for macOS 104-byte sockaddr_un limit inside Seatbelt TMPDIR.
        let dir = tempfile::Builder::new().prefix("p").tempdir().unwrap();
        let sock_len = dir.path().join("pty.sock").to_string_lossy().len();
        let ws = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let session_dir = if sock_len < 103 {
            Some(dir.path())
        } else {
            None
        };
        let (hub, wait_handle) = PtyHub::spawn_piped(
            "/bin/sh",
            &[],
            dir.path(),
            &[("PATH".to_string(), "/bin:/usr/bin".to_string())],
            ws,
            session_dir,
        )
        .unwrap();

        hub.send_input(b"echo RING_REPLAY_CHECK\n".to_vec())
            .await
            .unwrap();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut saw_ring = false;
        while tokio::time::Instant::now() < deadline {
            let (_, _, snap) = hub.snapshot_ring();
            if String::from_utf8_lossy(&snap).contains("RING_REPLAY_CHECK") {
                saw_ring = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(saw_ring, "ring buffer did not capture early PTY output");

        if let Some(sdir) = session_dir {
            let sock = sdir.join("pty.sock");
            let stream = UnixStream::connect(&sock).await.unwrap();
            let (rx, mut tx) = stream.into_split();
            let mut lines = BufReader::new(rx).lines();

            let first = lines.next_line().await.unwrap().unwrap();
            let replay_msg: LocalPtyServerMsg = serde_json::from_str(&first).unwrap();
            match replay_msg {
                LocalPtyServerMsg::Replay { data_b64, .. } => {
                    let bytes = B64.decode(data_b64).unwrap();
                    assert!(String::from_utf8_lossy(&bytes).contains("RING_REPLAY_CHECK"));
                }
                other => panic!("expected Replay first, got {:?}", other),
            }

            let cmd_line = serde_json::to_string(&LocalPtyClientMsg::Input {
                data_b64: B64.encode(b"echo UNIX_SOCK_OK\nexit\n"),
            })
            .unwrap()
                + "\n";
            tx.write_all(cmd_line.as_bytes()).await.unwrap();

            let mut saw_unix_ok = false;
            let read_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
            while tokio::time::Instant::now() < read_deadline {
                match tokio::time::timeout(std::time::Duration::from_secs(1), lines.next_line())
                    .await
                {
                    Ok(Ok(Some(line))) => {
                        if let Ok(LocalPtyServerMsg::Out { data_b64 }) =
                            serde_json::from_str(&line)
                        {
                            let bytes = B64.decode(data_b64).unwrap_or_default();
                            if String::from_utf8_lossy(&bytes).contains("UNIX_SOCK_OK") {
                                saw_unix_ok = true;
                                break;
                            }
                        }
                    }
                    _ => break,
                }
            }
            assert!(saw_unix_ok, "unix socket client did not receive echoed output");
        } else {
            hub.send_input(b"exit\n".to_vec()).await.unwrap();
        }

        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), wait_handle).await;
        hub.shutdown();
    }

    #[tokio::test]
    async fn test_pty_hub_real_openpty_when_permitted() {
        let dir = tempfile::Builder::new().prefix("p").tempdir().unwrap();
        let ws = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let spawned = PtyHub::spawn(
            "/bin/sh",
            &["-c".to_string(), "echo REAL_PTY_OK".to_string()],
            dir.path(),
            &[("PATH".to_string(), "/bin:/usr/bin".to_string())],
            ws,
            None,
        );
        let (hub, wait_handle) = match spawned {
            Ok(pair) => pair,
            Err(err) => {
                // Inside macOS Seatbelt sandboxes `/dev/ptmx` returns EPERM (`Operation not permitted`).
                let is_perm = err.chain().any(|e| {
                    e.downcast_ref::<std::io::Error>().is_some_and(|ioe| {
                        ioe.kind() == std::io::ErrorKind::PermissionDenied
                            || ioe.raw_os_error() == Some(libc::EPERM)
                    })
                });
                if is_perm {
                    return;
                }
                panic!("unexpected PtyHub::spawn failure: {:?}", err);
            }
        };
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), wait_handle).await;
        let (_, _, snap) = hub.snapshot_ring();
        assert!(String::from_utf8_lossy(&snap).contains("REAL_PTY_OK"));
        hub.shutdown();
    }
}
