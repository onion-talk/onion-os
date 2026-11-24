//! Interactive Amnesic Shell over WebSocket (`/api/pty/ws`):
//! - Unix/Alpine Linux: real pseudo-terminal (`libc::openpty` + `TIOCSWINSZ` resize + `AsyncFd`)
//! - Windows (dev/CI): `cmd.exe` async pipes with identical JSON framing
//!
//! Enforces `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY=socks5h://<TOR_SOCKS_ADDR>` and `HISTFILE=/dev/null`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
#[cfg(not(unix))]
use tokio::sync::mpsc;
use tokio::sync::{oneshot, Mutex};

#[derive(Debug, Default)]
pub struct PtyRegistry {
    next_id: AtomicU64,
    active_count: AtomicUsize,
    killers: Mutex<HashMap<u64, oneshot::Sender<()>>>,
}

impl PtyRegistry {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            active_count: AtomicUsize::new(0),
            killers: Mutex::new(HashMap::new()),
        }
    }

    pub fn active_count(&self) -> usize {
        self.active_count.load(Ordering::Relaxed)
    }

    pub async fn register(self: &Arc<Self>) -> (PtySessionGuard, oneshot::Receiver<()>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.active_count.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.killers.lock().await.insert(id, tx);
        (
            PtySessionGuard {
                id,
                registry: Arc::clone(self),
            },
            rx,
        )
    }

    pub async fn kill_all(&self) -> usize {
        let mut map = self.killers.lock().await;
        let count = map.len();
        for (_, tx) in map.drain() {
            let _ = tx.send(());
        }
        count
    }
}

pub struct PtySessionGuard {
    id: u64,
    registry: Arc<PtyRegistry>,
}

impl Drop for PtySessionGuard {
    fn drop(&mut self) {
        self.registry.active_count.fetch_sub(1, Ordering::Relaxed);
        let reg = Arc::clone(&self.registry);
        let id = self.id;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                reg.killers.lock().await.remove(&id);
            });
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ClientPtyFrame {
    Input {
        data: String,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    Ping,
}

#[derive(Debug, Serialize)]
struct ServerPtyFrame<'a> {
    #[serde(rename = "type")]
    frame_type: &'a str,
    data: &'a str,
}

pub async fn run_pty_websocket(
    socket: WebSocket,
    registry: Arc<PtyRegistry>,
    home_dir: PathBuf,
    tor_socks_addr: String,
) {
    let _ = fs::create_dir_all(&home_dir);
    let (_guard, kill_rx) = registry.register().await;

    #[cfg(unix)]
    {
        run_unix_pty_session(socket, kill_rx, &home_dir, &tor_socks_addr).await;
    }

    #[cfg(windows)]
    {
        run_windows_pipe_session(socket, kill_rx, &home_dir, &tor_socks_addr).await;
    }
}

fn serialize_output_frame(text: &str) -> Option<Message> {
    let frame = ServerPtyFrame {
        frame_type: "output",
        data: text,
    };
    serde_json::to_string(&frame)
        .ok()
        .map(|s| Message::Text(s.into()))
}

#[cfg(unix)]
async fn run_unix_pty_session(
    socket: WebSocket,
    mut kill_rx: oneshot::Receiver<()>,
    home_dir: &Path,
    tor_socks_addr: &str,
) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use tokio::io::unix::AsyncFd;

    let mut master_raw: libc::c_int = -1;
    let mut slave_raw: libc::c_int = -1;
    let initial_ws = libc::winsize {
        ws_row: 28,
        ws_col: 100,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    // SAFETY: master_raw, slave_raw and initial_ws are valid stack pointers; name/termios are null.
    let rc = unsafe {
        libc::openpty(
            &mut master_raw,
            &mut slave_raw,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &initial_ws,
        )
    };
    if rc != 0 || master_raw < 0 || slave_raw < 0 {
        let (mut tx, _) = socket.split();
        if let Some(msg) = serialize_output_frame("\r\n[onion-os] Failed to allocate PTY.\r\n") {
            let _ = tx.send(msg).await;
        }
        return;
    }

    // SAFETY: master_raw and slave_raw are freshly allocated file descriptors returned by openpty.
    let master_owned = unsafe { OwnedFd::from_raw_fd(master_raw) };
    // SAFETY: slave_raw is a uniquely owned file descriptor returned by openpty.
    let slave_owned = unsafe { OwnedFd::from_raw_fd(slave_raw) };

    let Ok(slave_out) = slave_owned.try_clone() else {
        return;
    };
    let Ok(slave_err) = slave_owned.try_clone() else {
        return;
    };

    // Set O_NONBLOCK on master_owned before registering with Tokio AsyncFd
    // SAFETY: master_owned.as_raw_fd() is a valid open PTY master file descriptor.
    unsafe {
        let flags = libc::fcntl(master_owned.as_raw_fd(), libc::F_GETFL);
        if flags >= 0 {
            let _ = libc::fcntl(
                master_owned.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            );
        }
    }

    let socks_uri = format!("socks5h://{tor_socks_addr}");
    let shell_bin = if Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else if Path::new("/bin/sh").exists() {
        "/bin/sh"
    } else {
        "sh"
    };

    let mut cmd = Command::new(shell_bin);
    cmd.arg("-i")
        .current_dir(home_dir)
        .env_clear()
        .env("HOME", home_dir)
        .env("USER", "onion")
        .env("LOGNAME", "onion")
        .env("TERM", "xterm-256color")
        .env("PS1", "onion@amnesic:\\w$ ")
        .env("HISTFILE", "/dev/null")
        .env("HISTSIZE", "0")
        .env("PATH", "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HTTP_PROXY", &socks_uri)
        .env("HTTPS_PROXY", &socks_uri)
        .env("ALL_PROXY", &socks_uri)
        .env("http_proxy", &socks_uri)
        .env("https_proxy", &socks_uri)
        .env("all_proxy", &socks_uri)
        .stdin(Stdio::from(slave_owned))
        .stdout(Stdio::from(slave_out))
        .stderr(Stdio::from(slave_err));

    // SAFETY: setsid and ioctl(TIOCSCTTY) are async-signal-safe POSIX calls before execve.
    unsafe {
        cmd.pre_exec(|| {
            let _ = libc::setsid();
            let _ = libc::ioctl(0, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let (mut tx, _) = socket.split();
            let err_line = format!("\r\n[onion-os] Shell spawn error: {e}\r\n");
            if let Some(msg) = serialize_output_frame(&err_line) {
                let _ = tx.send(msg).await;
            }
            return;
        }
    };

    #[allow(deprecated)]
    let Ok(async_master) = AsyncFd::new(master_owned) else {
        let _ = child.kill();
        let _ = child.wait();
        return;
    };

    let (mut ws_tx, mut ws_rx) = socket.split();
    let banner = "\x1b[38;5;48mOnionOS v1.0.0 Amnesic Tor Shell\x1b[0m (tmpfs RAM | HISTFILE=/dev/null | SOCKS5h enforced)\r\n";
    if let Some(msg) = serialize_output_frame(banner) {
        let _ = ws_tx.send(msg).await;
    }

    let mut read_buf = [0u8; 4096];

    loop {
        tokio::select! {
            _ = &mut kill_rx => {
                if let Some(msg) = serialize_output_frame("\r\n[PANIC BURN / LOCK] Session terminated.\r\n") {
                    let _ = ws_tx.send(msg).await;
                }
                break;
            }
            readable = async_master.readable() => {
                let Ok(mut guard) = readable else {
                    break;
                };
                let read_res = guard.try_io(|inner| {
                    // SAFETY: inner.as_raw_fd() is valid and read_buf is a valid mutable byte slice.
                    let n = unsafe {
                        libc::read(
                            inner.as_raw_fd(),
                            read_buf.as_mut_ptr().cast::<libc::c_void>(),
                            read_buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                });
                match read_res {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        let text = String::from_utf8_lossy(&read_buf[..n]);
                        if let Some(msg) = serialize_output_frame(&text) {
                            if ws_tx.send(msg).await.is_err() {
                                break;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        // On Linux PTY master, EIO indicates the slave side closed (shell exited)
                        if e.raw_os_error() == Some(libc::EIO) {
                            break;
                        }
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            break;
                        }
                    }
                    Err(_would_block) => continue,
                }
            }
            ws_msg = ws_rx.next() => {
                let Some(Ok(msg)) = ws_msg else {
                    break;
                };
                match msg {
                    Message::Text(txt) => {
                        match serde_json::from_str::<ClientPtyFrame>(&txt) {
                            Ok(ClientPtyFrame::Input { data }) => {
                                if write_all_nonblocking_pty(&async_master, data.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                            Ok(ClientPtyFrame::Resize { cols, rows }) => {
                                let ws = libc::winsize {
                                    ws_row: rows.clamp(5, 200),
                                    ws_col: cols.clamp(20, 500),
                                    ws_xpixel: 0,
                                    ws_ypixel: 0,
                                };
                                // SAFETY: async_master.as_raw_fd() is an open PTY master fd and ws is valid.
                                unsafe {
                                    let _ = libc::ioctl(async_master.as_raw_fd(), libc::TIOCSWINSZ, &ws);
                                }
                            }
                            Ok(ClientPtyFrame::Ping) => {
                                let pong = ServerPtyFrame { frame_type: "pong", data: "" };
                                if let Ok(s) = serde_json::to_string(&pong) {
                                    let _ = ws_tx.send(Message::Text(s.into())).await;
                                }
                            }
                            Err(_) => {
                                if write_all_nonblocking_pty(&async_master, txt.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Message::Binary(bin) => {
                        if write_all_nonblocking_pty(&async_master, &bin).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
async fn write_all_nonblocking_pty(
    async_master: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    mut data: &[u8],
) -> Result<(), std::io::Error> {
    use std::os::fd::AsRawFd;

    while !data.is_empty() {
        let mut guard = async_master.writable().await?;
        match guard.try_io(|inner| {
            // SAFETY: inner.as_raw_fd() is valid and data points to valid immutable slice.
            let written = unsafe {
                libc::write(
                    inner.as_raw_fd(),
                    data.as_ptr().cast::<libc::c_void>(),
                    data.len(),
                )
            };
            if written < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(written as usize)
            }
        }) {
            Ok(Ok(0)) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "PTY write 0")),
            Ok(Ok(n)) => data = &data[n..],
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

#[cfg(windows)]
async fn run_windows_pipe_session(
    socket: WebSocket,
    mut kill_rx: oneshot::Receiver<()>,
    home_dir: &Path,
    tor_socks_addr: &str,
) {
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command;

    let socks_uri = format!("socks5h://{tor_socks_addr}");
    let mut cmd = Command::new("cmd.exe");
    cmd.arg("/Q")
        .current_dir(home_dir)
        .env("HOME", home_dir)
        .env("HTTP_PROXY", &socks_uri)
        .env("HTTPS_PROXY", &socks_uri)
        .env("ALL_PROXY", &socks_uri)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let (mut tx, _) = socket.split();
            let err_line = format!("\r\n[onion-os] Shell spawn error: {e}\r\n");
            if let Some(msg) = serialize_output_frame(&err_line) {
                let _ = tx.send(msg).await;
            }
            return;
        }
    };

    let Some(mut child_stdin) = child.stdin.take() else {
        let _ = child.kill().await;
        return;
    };
    let Some(mut child_stdout) = child.stdout.take() else {
        let _ = child.kill().await;
        return;
    };
    let Some(mut child_stderr) = child.stderr.take() else {
        let _ = child.kill().await;
        return;
    };

    let (out_tx, mut out_rx) = mpsc::channel::<String>(64);
    let out_tx_err = out_tx.clone();

    let stdout_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match child_stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let s = String::from_utf8_lossy(&buf[..n]).into_owned();
                    if out_tx.send(s).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let stderr_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match child_stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let s = String::from_utf8_lossy(&buf[..n]).into_owned();
                    if out_tx_err.send(s).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let (mut ws_tx, mut ws_rx) = socket.split();
    let banner = "\x1b[38;5;48mOnionOS v1.0.0 Amnesic Shell (Windows Host Dev Mode)\x1b[0m\r\n";
    if let Some(msg) = serialize_output_frame(banner) {
        let _ = ws_tx.send(msg).await;
    }

    loop {
        tokio::select! {
            _ = &mut kill_rx => {
                if let Some(msg) = serialize_output_frame("\r\n[PANIC BURN / LOCK] Session terminated.\r\n") {
                    let _ = ws_tx.send(msg).await;
                }
                break;
            }
            maybe_chunk = out_rx.recv() => {
                let Some(chunk) = maybe_chunk else {
                    break;
                };
                if let Some(msg) = serialize_output_frame(&chunk) {
                    if ws_tx.send(msg).await.is_err() {
                        break;
                    }
                }
            }
            ws_msg = ws_rx.next() => {
                let Some(Ok(msg)) = ws_msg else {
                    break;
                };
                match msg {
                    Message::Text(txt) => {
                        match serde_json::from_str::<ClientPtyFrame>(&txt) {
                            Ok(ClientPtyFrame::Input { data }) => {
                                if child_stdin.write_all(data.as_bytes()).await.is_err() {
                                    break;
                                }
                                let _ = child_stdin.flush().await;
                            }
                            Ok(ClientPtyFrame::Resize { cols, rows }) => {
                                let _ = (cols, rows);
                            }
                            Ok(ClientPtyFrame::Ping) => {
                                let pong = ServerPtyFrame { frame_type: "pong", data: "" };
                                if let Ok(s) = serde_json::to_string(&pong) {
                                    let _ = ws_tx.send(Message::Text(s.into())).await;
                                }
                            }
                            Err(_) => {
                                if child_stdin.write_all(txt.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Message::Binary(bin) => {
                        if child_stdin.write_all(&bin).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    let _ = child.kill().await;
    stdout_task.abort();
    stderr_task.abort();
}
