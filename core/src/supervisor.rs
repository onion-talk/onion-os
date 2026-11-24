//! Single-Container Process Supervisor, Isolated `browser-agent` (`UID 10015`) & Kernel System Monitor
//! - Supervises optional `/usr/local/bin/oniontalk-node` (`127.0.0.1:8420`)
//! - Isolates Xvfb/Firefox/x11vnc/websockify inside `onion-os browser-agent` (`127.0.0.1:6902`, `HOME=/sandbox-home`,
//!   MIT-MAGIC-COOKIE-1 `.Xauthority` `0600`, zero `-ac`) authenticated via constant-time `X-Browser-Agent-Token`
//! - Strict Netfilter flag verification (`/run/onionos/netfilter.active` starting with `"active"`)

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use zeroize::Zeroize;

use crate::proxy::SandboxResetResponse;
use crate::vault::constant_time_eq;

pub const BROWSER_LAUNCH_URL: &str =
    "/sandbox/vnc.html?autoconnect=true&resize=scale&reconnect=true&path=sandbox/websockify";
pub const DEFAULT_NETFILTER_FLAG_PATH: &str = "/run/onionos/netfilter.active";
pub const DEFAULT_BROWSER_TOKEN_FILE: &str = "/run/onionos/browser.token";
pub const BROWSER_AGENT_HEADER: &str = "x-browser-agent-token";

pub const FIREFOX_HARDENED_USER_JS: &str = r#"// OnionOS v1.0.0 Hardened Amnesic Tor Profile (Auto-generated in tmpfs)
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", 9050);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.predictor.enabled", false);
user_pref("media.peerconnection.enabled", false);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.firstparty.isolate", true);
user_pref("webgl.disabled", true);
user_pref("gfx.webrender.software", true);
user_pref("layers.acceleration.disabled", true);
user_pref("security.sandbox.content.level", 0);
user_pref("security.sandbox.gpu.level", 0);
user_pref("dom.ipc.processCount", 2);
user_pref("browser.tabs.closeWindowWithLastTab", false);
user_pref("browser.tabs.warnOnClose", false);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("toolkit.cosmeticAnimations.enabled", false);
user_pref("accessibility.force_disabled", 1);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("places.history.enabled", false);
user_pref("browser.privatebrowsing.autostart", true);
"#;

pub const OPENBOX_MAXIMIZED_RC_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<openbox_config xmlns="http://openbox.org/3.4/rc" xmlns:xi="http://www.w3.org/2001/XInclude">
  <applications>
    <application class="*">
      <decor>no</decor>
      <maximized>yes</maximized>
      <focus>yes</focus>
    </application>
  </applications>
</openbox_config>
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatusResponse {
    pub state: String,
    pub pid: Option<u32>,
    pub ws_ready: bool,
    pub memory_kib: u64,
    pub launch_url: String,
}

impl BrowserStatusResponse {
    pub fn stopped_default() -> Self {
        Self {
            state: "stopped".to_owned(),
            pid: None,
            ws_ready: false,
            memory_kib: 0,
            launch_url: BROWSER_LAUNCH_URL.to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStopResponse {
    pub stopped: bool,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfoView {
    pub name: String,
    pub state: String,
    pub pid: u32,
    pub mem_kib: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemMonitorResponse {
    pub os_pretty_name: String,
    pub uid: u32,
    pub cap_eff_hex: String,
    pub cap_bnd_hex: String,
    pub no_new_privs: bool,
    pub netfilter_active: bool,
    pub mem_rss_kib: u64,
    pub tmpfs_bytes: u64,
    pub tmpfs_files: usize,
    pub uptime_secs: u64,
    pub browser_state: String,
    pub relay_state: String,
    pub onion_share_active: bool,
    pub active_ptys: usize,
    pub processes: Vec<ProcessInfoView>,
}

#[derive(Debug, Clone)]
pub struct ProcSecurityCaps {
    pub cap_eff_hex: String,
    pub cap_bnd_hex: String,
    pub cap_bnd_zero: bool,
    pub no_new_privs: bool,
    pub vm_rss_kib: u64,
}

#[derive(Clone)]
struct RemoteAgentClient {
    base_url: String,
    token_file: PathBuf,
    http: reqwest::Client,
}

struct BrowserInner {
    state: &'static str,
    children: Vec<(&'static str, Child)>,
    oniontalk_child: Option<Child>,
}

pub struct ProcessSupervisor {
    sandbox_home: PathBuf,
    tor_socks_port: u16,
    browser_ws_addr: String,
    remote_agent: Option<RemoteAgentClient>,
    inner: Mutex<BrowserInner>,
}

impl ProcessSupervisor {
    pub fn new(home_dir: PathBuf, tor_socks_addr: &str, sandbox_browser_url: &str) -> Self {
        let agent_url = env::var("ONIONOS_BROWSER_AGENT_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_owned())
            .filter(|s| !s.is_empty());

        let token_file = env::var("ONIONOS_BROWSER_TOKEN_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_BROWSER_TOKEN_FILE));

        Self::new_with_agent(
            home_dir,
            tor_socks_addr,
            sandbox_browser_url,
            agent_url,
            token_file,
        )
    }

    pub fn new_with_agent(
        sandbox_home: PathBuf,
        tor_socks_addr: &str,
        sandbox_browser_url: &str,
        agent_url: Option<String>,
        token_file: PathBuf,
    ) -> Self {
        let tor_socks_port = tor_socks_addr
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(9050);

        let browser_ws_addr = extract_host_port(sandbox_browser_url, "127.0.0.1:6901");

        let remote_agent = agent_url.and_then(|base_url| {
            let http = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(6))
                .connect_timeout(Duration::from_millis(800))
                .build()
                .ok()?;
            Some(RemoteAgentClient {
                base_url,
                token_file,
                http,
            })
        });

        Self {
            sandbox_home,
            tor_socks_port,
            browser_ws_addr,
            remote_agent,
            inner: Mutex::new(BrowserInner {
                state: "stopped",
                children: Vec::new(),
                oniontalk_child: None,
            }),
        }
    }

    pub fn new_local_agent(
        sandbox_home: PathBuf,
        tor_socks_addr: &str,
        sandbox_browser_url: &str,
    ) -> Self {
        Self::new_with_agent(
            sandbox_home,
            tor_socks_addr,
            sandbox_browser_url,
            None,
            PathBuf::new(),
        )
    }

    /// Starts `/usr/local/bin/oniontalk-node` on `127.0.0.1:8420` if the binary exists and `:8420` is free.
    pub async fn ensure_oniontalk_node(&self, oniontalk_url: &str) {
        let bin_path = Path::new("/usr/local/bin/oniontalk-node");
        if !bin_path.is_file() {
            return;
        }
        let target_addr = extract_host_port(oniontalk_url, "127.0.0.1:8420");
        if tcp_probe(&target_addr, 120).await {
            return;
        }

        let mut guard = self.inner.lock().await;
        if let Some(child) = &mut guard.oniontalk_child {
            if matches!(child.try_wait(), Ok(None)) {
                return;
            }
        }

        let data_dir = if Path::new("/data").is_dir() {
            PathBuf::from("/data")
        } else {
            let fallback = self.sandbox_home.join(".oniontalk-data");
            let _ = fs::create_dir_all(&fallback);
            fallback
        };

        let hostname_file = data_dir.join("hostname");
        let socks_addr = format!("127.0.0.1:{}", self.tor_socks_port);

        let mut cmd = Command::new(bin_path);
        cmd.env_clear();
        #[cfg(windows)]
        {
            for var in ["SystemRoot", "SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"] {
                if let Ok(val) = env::var(var) {
                    cmd.env(var, val);
                }
            }
        }
        #[cfg(unix)]
        {
            cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin")
                .env("USER", "onion");
        }
        cmd.env("HOME", &data_dir)
            .env("EXTERNAL_TOR", "1")
            .env("PORT", "8420")
            .env("ONIONTALK_WEB_PORT", "8420")
            .env("ONIONTALK_RELAY_PORT", "8080")
            .env("TOR_SOCKS_ADDR", &socks_addr)
            .env("TOR_SOCKS_PORT", self.tor_socks_port.to_string())
            .env("ONIONTALK_DATA_DIR", &data_dir)
            .env("LOCAL_ONION_HOSTNAME_FILE", &hostname_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        if let Ok(child) = cmd.spawn() {
            tracing::info!("Supervised oniontalk-node started on 127.0.0.1:8420");
            guard.oniontalk_child = Some(child);
        }
    }

    pub async fn browser_state_label(&self) -> String {
        if self.remote_agent.is_some() {
            return self.browser_status().await.state;
        }
        let mut guard = self.inner.lock().await;
        reap_exited_browser_children(&mut guard);
        if guard.state != "stopped" && !has_healthy_browser_core(&guard) {
            stop_children_locked(&mut guard, &self.sandbox_home).await;
        }
        guard.state.to_owned()
    }

    pub async fn browser_status(&self) -> BrowserStatusResponse {
        if let Some(agent) = &self.remote_agent {
            return remote_agent_status(agent).await;
        }
        self.local_browser_status().await
    }

    pub async fn start_browser(&self) -> Result<BrowserStatusResponse, String> {
        if let Some(agent) = &self.remote_agent {
            return remote_agent_start(agent).await;
        }
        self.local_start_browser().await
    }

    pub async fn stop_browser(&self) -> BrowserStopResponse {
        if let Some(agent) = &self.remote_agent {
            return remote_agent_stop(agent, Duration::from_millis(1500)).await;
        }
        self.local_stop_browser().await
    }

    pub async fn stop_browser_fast(&self, timeout: Duration) -> BrowserStopResponse {
        if let Some(agent) = &self.remote_agent {
            return remote_agent_stop(agent, timeout).await;
        }
        self.local_stop_browser().await
    }

    pub async fn reset_browser(&self) -> (bool, String) {
        if let Some(agent) = &self.remote_agent {
            return remote_agent_reset(agent).await;
        }
        self.local_reset_browser().await
    }

    async fn local_browser_status(&self) -> BrowserStatusResponse {
        let (state_str, primary_pid, has_core, pids) = {
            let mut guard = self.inner.lock().await;
            reap_exited_browser_children(&mut guard);
            if guard.state != "stopped" && !has_healthy_browser_core(&guard) {
                stop_children_locked(&mut guard, &self.sandbox_home).await;
            }
            let firefox_pid = guard
                .children
                .iter()
                .find(|(role, _)| *role == "firefox")
                .and_then(|(_, c)| c.id());
            let core_ok = has_healthy_browser_core(&guard);
            let p_pid = firefox_pid.or_else(|| guard.children.first().and_then(|(_, c)| c.id()));
            let all_pids: Vec<u32> = guard.children.iter().filter_map(|(_, c)| c.id()).collect();
            (guard.state, p_pid, core_ok, all_pids)
        };

        let ws_ready = if state_str == "stopped" || !has_core {
            false
        } else {
            tcp_probe("127.0.0.1:5900", 120).await && http_head_probe(&self.browser_ws_addr, 250).await
        };

        let effective_state = if state_str == "starting" && ws_ready {
            let mut guard = self.inner.lock().await;
            if guard.state == "starting" {
                guard.state = "running";
            }
            "running"
        } else {
            state_str
        };

        let memory_kib: u64 = pids.iter().copied().map(read_pid_rss_kib).sum();

        BrowserStatusResponse {
            state: effective_state.to_owned(),
            pid: primary_pid,
            ws_ready,
            memory_kib,
            launch_url: BROWSER_LAUNCH_URL.to_owned(),
        }
    }

    async fn local_start_browser(&self) -> Result<BrowserStatusResponse, String> {
        {
            let mut guard = self.inner.lock().await;
            reap_exited_browser_children(&mut guard);
            if guard.state == "running"
                && has_healthy_browser_core(&guard)
                && tcp_probe("127.0.0.1:5900", 120).await
                && http_head_probe(&self.browser_ws_addr, 250).await
            {
                drop(guard);
                return Ok(self.local_browser_status().await);
            }
            stop_children_locked(&mut guard, &self.sandbox_home).await;
            guard.state = "starting";
        }

        #[cfg(not(unix))]
        {
            let mut guard = self.inner.lock().await;
            guard.state = "stopped";
            Err("On-demand Xvfb/Firefox sandbox requires Linux container runtime".into())
        }

        #[cfg(unix)]
        {
            let spawn_res = self.spawn_unix_browser_stack().await;
            if let Err(err) = spawn_res {
                let mut guard = self.inner.lock().await;
                stop_children_locked(&mut guard, &self.sandbox_home).await;
                return Err(err);
            }

            let mut ready = false;
            for _ in 0..30 {
                if tcp_probe("127.0.0.1:5900", 120).await
                    && http_head_probe(&self.browser_ws_addr, 250).await
                {
                    ready = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }

            {
                let mut guard = self.inner.lock().await;
                reap_exited_browser_children(&mut guard);
                let has_firefox = guard.children.iter().any(|(r, _)| *r == "firefox");
                let has_vnc = guard.children.iter().any(|(r, _)| *r == "x11vnc");
                if guard.children.is_empty() || !has_firefox || !has_vnc {
                    stop_children_locked(&mut guard, &self.sandbox_home).await;
                    return Err("Browser stack (Firefox/x11vnc) exited prematurely during X11 handshake".into());
                }
                guard.state = if ready { "running" } else { "starting" };
            }

            Ok(self.local_browser_status().await)
        }
    }

    #[cfg(unix)]
    async fn spawn_unix_browser_stack(&self) -> Result<(), String> {
        let _ = fs::remove_file("/tmp/.X99-lock");
        let _ = fs::remove_file("/tmp/.X11-unix/X99");

        fs::create_dir_all(&self.sandbox_home)
            .map_err(|e| format!("Failed creating sandbox home: {e}"))?;

        // Generate 0600 MIT-MAGIC-COOKIE-1 .Xauthority (NEVER pass `-ac` to Xvfb!)
        let xauth_path = self.sandbox_home.join(".Xauthority");
        write_xauthority_cookie(&xauth_path, b"99")?;
        let xauth_str = xauth_path.to_string_lossy().into_owned();

        let profile_dir = self.sandbox_home.join(".browser-profile");
        fs::create_dir_all(&profile_dir)
            .map_err(|e| format!("Failed creating volatile browser profile: {e}"))?;
        fs::write(profile_dir.join("user.js"), FIREFOX_HARDENED_USER_JS.as_bytes())
            .map_err(|e| format!("Failed writing hardened user.js: {e}"))?;

        let openbox_cfg_dir = self.sandbox_home.join(".config").join("openbox");
        let _ = fs::create_dir_all(&openbox_cfg_dir);
        let _ = fs::write(
            openbox_cfg_dir.join("rc.xml"),
            OPENBOX_MAXIMIZED_RC_XML.as_bytes(),
        );

        let socks_env = format!("socks5h://127.0.0.1:{}", self.tor_socks_port);

        // 1. Xvfb :99 with strict -auth .Xauthority and -nolisten tcp (NO `-ac`!)
        let xvfb = Command::new("Xvfb")
            .args([
                ":99",
                "-screen",
                "0",
                "1366x768x24",
                "-nolisten",
                "tcp",
                "-auth",
                &xauth_str,
            ])
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", &self.sandbox_home)
            .env("USER", "sandbox")
            .env("XAUTHORITY", &xauth_str)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("Failed to spawn Xvfb: {e}"))?;

        {
            let mut guard = self.inner.lock().await;
            guard.children.push(("xvfb", xvfb));
        }

        tokio::time::sleep(Duration::from_millis(250)).await;

        // 2. Window manager (openbox) with maximized undecorated rc.xml
        if let Ok(ob) = Command::new("openbox")
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("DISPLAY", ":99")
            .env("HOME", &self.sandbox_home)
            .env("USER", "sandbox")
            .env("XAUTHORITY", &xauth_str)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
        {
            let mut guard = self.inner.lock().await;
            guard.children.push(("openbox", ob));
        }

        // 3. Hardened Firefox ESR in isolated /sandbox-home/.browser-profile
        let ff_bin = if Path::new("/usr/bin/firefox-esr").exists() {
            "firefox-esr"
        } else {
            "firefox"
        };
        let profile_str = profile_dir.to_string_lossy().into_owned();
        let ff_stderr_stdio = {
            use std::os::unix::fs::OpenOptionsExt;
            let log_path = self.sandbox_home.join("firefox-last.log");
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(log_path)
                .map(Stdio::from)
                .unwrap_or_else(|_| Stdio::null())
        };
        let firefox = Command::new(ff_bin)
            .args([
                "--no-remote",
                "--width",
                "1366",
                "--height",
                "768",
                "--profile",
                &profile_str,
                "about:blank",
            ])
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("DISPLAY", ":99")
            .env("HOME", &self.sandbox_home)
            .env("USER", "sandbox")
            .env("XAUTHORITY", &xauth_str)
            .env("NO_AT_BRIDGE", "1")
            .env("GDK_BACKEND", "x11")
            .env("MOZ_ENABLE_WAYLAND", "0")
            .env("LIBGL_ALWAYS_SOFTWARE", "1")
            .env("MOZ_CRASHREPORTER_DISABLE", "1")
            .env("MOZ_DISABLE_CONTENT_SANDBOX", "1")
            .env("MOZ_DISABLE_GMP_SANDBOX", "1")
            .env("MOZ_DISABLE_RDD_SANDBOX", "1")
            .env("MOZ_DISABLE_SOCKET_PROCESS_SANDBOX", "1")
            .env("MOZ_DISABLE_UTILITY_SANDBOX", "1")
            .env("ALL_PROXY", &socks_env)
            .env("HTTP_PROXY", &socks_env)
            .env("HTTPS_PROXY", &socks_env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(ff_stderr_stdio)
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("Failed to spawn {ff_bin}: {e}"))?;

        {
            let mut guard = self.inner.lock().await;
            guard.children.push(("firefox", firefox));
        }

        // 4. x11vnc on localhost:5900 authenticated with -auth .Xauthority + -noxdamage
        let x11vnc = Command::new("x11vnc")
            .args([
                "-display",
                ":99",
                "-auth",
                &xauth_str,
                "-forever",
                "-shared",
                "-nopw",
                "-noxdamage",
                "-rfbport",
                "5900",
                "-localhost",
                "-quiet",
            ])
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", &self.sandbox_home)
            .env("USER", "sandbox")
            .env("XAUTHORITY", &xauth_str)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("Failed to spawn x11vnc: {e}"))?;

        {
            let mut guard = self.inner.lock().await;
            guard.children.push(("x11vnc", x11vnc));
        }

        // 5. websockify --web=/usr/share/novnc 127.0.0.1:6901 127.0.0.1:5900
        let websockify = Command::new("websockify")
            .args([
                "--web=/usr/share/novnc",
                &self.browser_ws_addr,
                "127.0.0.1:5900",
            ])
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", &self.sandbox_home)
            .env("USER", "sandbox")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("Failed to spawn websockify: {e}"))?;

        {
            let mut guard = self.inner.lock().await;
            guard.children.push(("websockify", websockify));
        }

        Ok(())
    }

    async fn local_stop_browser(&self) -> BrowserStopResponse {
        let mut guard = self.inner.lock().await;
        stop_children_locked(&mut guard, &self.sandbox_home).await;
        BrowserStopResponse {
            stopped: true,
            state: "stopped".to_owned(),
        }
    }

    async fn local_reset_browser(&self) -> (bool, String) {
        let was_running = self.local_browser_status().await.state != "stopped";
        let _ = self.local_stop_browser().await;
        if was_running {
            match self.local_start_browser().await {
                Ok(_) => (
                    true,
                    "Volatile Tor Browser profile wiped and restarted cleanly".into(),
                ),
                Err(e) => (
                    true,
                    format!("Volatile Tor Browser profile wiped (restart skipped: {e})"),
                ),
            }
        } else {
            (true, "Volatile Tor Browser profile wiped (engine stopped)".into())
        }
    }
}

/// Writes valid `libXau` binary `.Xauthority` entries (`FamilyLocal` `0x0100` with kernel hostname + `FamilyWild` `0xFFFF`, `MIT-MAGIC-COOKIE-1`, 16B CSPRNG) with mode `0600`.
pub fn write_xauthority_cookie(xauth_path: &Path, display_num: &[u8]) -> Result<(), String> {
    let _ = fs::remove_file(xauth_path);
    let mut cookie = [0u8; 16];
    OsRng.fill_bytes(&mut cookie);

    const FAMILY_LOCAL: u16 = 0x0100; // <X11/Xauth.h> FamilyLocal (256)
    const FAMILY_WILD: u16 = 0xFFFF; // <X11/Xauth.h> FamilyWild (65535)
    const AUTH_NAME: &[u8] = b"MIT-MAGIC-COOKIE-1";

    let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "localhost".to_owned());
    let host_bytes = hostname.as_bytes();

    let mut record = Vec::with_capacity(112);
    // Entry 1: FamilyLocal (0x0100) + container hostname (matched by Xlib / libxcb over unix socket)
    record.extend_from_slice(&FAMILY_LOCAL.to_be_bytes());
    record.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    record.extend_from_slice(host_bytes);
    record.extend_from_slice(&(display_num.len() as u16).to_be_bytes());
    record.extend_from_slice(display_num);
    record.extend_from_slice(&(AUTH_NAME.len() as u16).to_be_bytes());
    record.extend_from_slice(AUTH_NAME);
    record.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
    record.extend_from_slice(&cookie);

    // Entry 2: FamilyWild (0xFFFF) + empty address (universal fallback)
    record.extend_from_slice(&FAMILY_WILD.to_be_bytes());
    record.extend_from_slice(&0u16.to_be_bytes());
    record.extend_from_slice(&(display_num.len() as u16).to_be_bytes());
    record.extend_from_slice(display_num);
    record.extend_from_slice(&(AUTH_NAME.len() as u16).to_be_bytes());
    record.extend_from_slice(AUTH_NAME);
    record.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
    record.extend_from_slice(&cookie);
    cookie.zeroize();

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts
        .open(xauth_path)
        .map_err(|e| format!("Failed opening {}: {e}", xauth_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    file.write_all(&record)
        .map_err(|e| format!("Failed writing Xauthority cookie: {e}"))?;
    let _ = file.sync_all();
    record.zeroize();
    Ok(())
}

// ============================================================================
// Remote HTTP Delegation (`onion-os serve` UID 10014 -> `browser-agent` UID 10015)
// ============================================================================

fn read_agent_token(token_file: &Path) -> Option<String> {
    fs::read_to_string(token_file)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

async fn remote_agent_status(agent: &RemoteAgentClient) -> BrowserStatusResponse {
    let Some(tok) = read_agent_token(&agent.token_file) else {
        return BrowserStatusResponse::stopped_default();
    };
    let url = format!("{}/status", agent.base_url);
    let res = agent
        .http
        .get(&url)
        .header(BROWSER_AGENT_HEADER, tok)
        .timeout(Duration::from_millis(1200))
        .send()
        .await;

    match res {
        Ok(r) if r.status().is_success() => r
            .json::<BrowserStatusResponse>()
            .await
            .unwrap_or_else(|_| BrowserStatusResponse::stopped_default()),
        _ => BrowserStatusResponse::stopped_default(),
    }
}

async fn remote_agent_start(agent: &RemoteAgentClient) -> Result<BrowserStatusResponse, String> {
    let tok = read_agent_token(&agent.token_file)
        .ok_or_else(|| "Browser agent token file unavailable".to_owned())?;
    let url = format!("{}/start", agent.base_url);
    let resp = agent
        .http
        .post(&url)
        .header(BROWSER_AGENT_HEADER, tok)
        .timeout(Duration::from_secs(6))
        .send()
        .await
        .map_err(|e| format!("Browser agent unreachable ({url}): {e}"))?;

    if !resp.status().is_success() {
        let code = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        return Err(format!("Browser agent returned {code}: {txt}"));
    }

    resp.json::<BrowserStatusResponse>()
        .await
        .map_err(|e| format!("Invalid browser agent response: {e}"))
}

async fn remote_agent_stop(agent: &RemoteAgentClient, timeout: Duration) -> BrowserStopResponse {
    let Some(tok) = read_agent_token(&agent.token_file) else {
        return BrowserStopResponse {
            stopped: false,
            state: "stopped".to_owned(),
        };
    };
    let url = format!("{}/stop", agent.base_url);
    let res = agent
        .http
        .post(&url)
        .header(BROWSER_AGENT_HEADER, tok)
        .timeout(timeout)
        .send()
        .await;

    match res {
        Ok(r) if r.status().is_success() => r.json::<BrowserStopResponse>().await.unwrap_or(
            BrowserStopResponse {
                stopped: true,
                state: "stopped".to_owned(),
            },
        ),
        _ => BrowserStopResponse {
            stopped: true,
            state: "stopped".to_owned(),
        },
    }
}

async fn remote_agent_reset(agent: &RemoteAgentClient) -> (bool, String) {
    let Some(tok) = read_agent_token(&agent.token_file) else {
        return (false, "Browser agent token file unavailable".to_owned());
    };
    let url = format!("{}/reset", agent.base_url);
    match agent
        .http
        .post(&url)
        .header(BROWSER_AGENT_HEADER, tok)
        .timeout(Duration::from_secs(6))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => match r.json::<SandboxResetResponse>().await {
            Ok(sr) => (sr.ok, sr.message),
            Err(_) => (true, "Sandbox reset completed".to_owned()),
        },
        Ok(r) => (false, format!("Browser agent reset returned {}", r.status())),
        Err(e) => (false, format!("Browser agent unreachable: {e}")),
    }
}

// ============================================================================
// Standalone `onion-os browser-agent` Daemon (`UID 10015`, `127.0.0.1:6902`)
// ============================================================================

struct BrowserAgentDaemonState {
    supervisor: ProcessSupervisor,
    token_file: PathBuf,
}

pub fn build_browser_agent_router(
    supervisor: ProcessSupervisor,
    token_file: PathBuf,
) -> Router {
    let state = Arc::new(BrowserAgentDaemonState {
        supervisor,
        token_file,
    });
    Router::new()
        .route("/status", get(agent_http_status))
        .route("/start", post(agent_http_start))
        .route("/stop", post(agent_http_stop))
        .route("/reset", post(agent_http_reset))
        .with_state(state)
}

pub async fn run_browser_agent_cli() -> Result<(), String> {
    let port = env::var("ONIONOS_BROWSER_AGENT_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(6902);

    let token_file = env::var("ONIONOS_BROWSER_TOKEN_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_BROWSER_TOKEN_FILE));

    let sandbox_home = env::var("ONIONOS_SANDBOX_HOME")
        .or_else(|_| env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/sandbox-home"));

    let tor_socks = env::var("TOR_SOCKS_ADDR").unwrap_or_else(|_| "127.0.0.1:9050".into());
    let sandbox_ws_url =
        env::var("SANDBOX_BROWSER_URL").unwrap_or_else(|_| "http://127.0.0.1:6901".into());

    let _ = fs::create_dir_all(&sandbox_home);
    let supervisor =
        ProcessSupervisor::new_local_agent(sandbox_home, &tor_socks, &sandbox_ws_url);
    let router = build_browser_agent_router(supervisor, token_file);

    let bind_addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| format!("Failed binding browser-agent on {bind_addr}: {e}"))?;

    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| format!("browser-agent runtime error: {e}"))
}

fn verify_agent_request(headers: &HeaderMap, token_file: &Path) -> Result<(), &'static str> {
    let Some(expected) = read_agent_token(token_file) else {
        return Err("Agent token unconfigured");
    };
    let Some(provided) = headers
        .get(BROWSER_AGENT_HEADER)
        .and_then(|v| v.to_str().ok())
    else {
        return Err("Missing X-Browser-Agent-Token");
    };

    if constant_time_eq(provided.trim().as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err("Invalid X-Browser-Agent-Token")
    }
}

fn agent_unauthorized(msg: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

async fn agent_http_status(
    State(state): State<Arc<BrowserAgentDaemonState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(msg) = verify_agent_request(&headers, &state.token_file) {
        return agent_unauthorized(msg);
    }
    Json(state.supervisor.local_browser_status().await).into_response()
}

async fn agent_http_start(
    State(state): State<Arc<BrowserAgentDaemonState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(msg) = verify_agent_request(&headers, &state.token_file) {
        return agent_unauthorized(msg);
    }
    match state.supervisor.local_start_browser().await {
        Ok(st) => Json(st).into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

async fn agent_http_stop(
    State(state): State<Arc<BrowserAgentDaemonState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(msg) = verify_agent_request(&headers, &state.token_file) {
        return agent_unauthorized(msg);
    }
    Json(state.supervisor.local_stop_browser().await).into_response()
}

async fn agent_http_reset(
    State(state): State<Arc<BrowserAgentDaemonState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(msg) = verify_agent_request(&headers, &state.token_file) {
        return agent_unauthorized(msg);
    }
    let (ok, msg) = state.supervisor.local_reset_browser().await;
    Json(SandboxResetResponse {
        ok,
        reset: ok,
        status: 200,
        message: msg,
    })
    .into_response()
}

// ============================================================================
// Process Reaping & Kernel /proc Telemetry
// ============================================================================

fn has_healthy_browser_core(inner: &BrowserInner) -> bool {
    let has_xvfb = inner.children.iter().any(|(r, _)| *r == "xvfb");
    let has_ff = inner.children.iter().any(|(r, _)| *r == "firefox");
    let has_vnc = inner.children.iter().any(|(r, _)| *r == "x11vnc");
    let has_ws = inner.children.iter().any(|(r, _)| *r == "websockify");
    has_xvfb && has_ff && has_vnc && has_ws
}

fn reap_exited_browser_children(inner: &mut BrowserInner) {
    inner
        .children
        .retain_mut(|(_, child)| matches!(child.try_wait(), Ok(None)));
    if inner.children.is_empty() {
        inner.state = "stopped";
    }
}

async fn stop_children_locked(inner: &mut BrowserInner, sandbox_home: &Path) {
    for (_, mut child) in inner.children.drain(..) {
        #[cfg(unix)]
        if let Some(pid) = child.id() {
            if pid > 1 {
                unsafe {
                    let _ = libc::kill(-(pid as i32), libc::SIGKILL);
                }
            }
        }
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    inner.state = "stopped";

    let profile_dir = sandbox_home.join(".browser-profile");
    if profile_dir.exists() {
        let _ = fs::remove_dir_all(&profile_dir);
    }
    let _ = fs::remove_file(sandbox_home.join("firefox-last.log"));
    let xauth = sandbox_home.join(".Xauthority");
    let _ = fs::remove_file(xauth);
    let _ = fs::remove_file("/tmp/.X99-lock");
    let _ = fs::remove_file("/tmp/.X11-unix/X99");
    let _ = (FIREFOX_HARDENED_USER_JS, OPENBOX_MAXIMIZED_RC_XML);
}

pub fn read_proc_security_caps() -> ProcSecurityCaps {
    let mut cap_eff_hex = "0000000000000000".to_owned();
    let mut cap_bnd_hex = "0000000000000000".to_owned();
    let mut no_new_privs = false;
    let mut vm_rss_kib = 0u64;

    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("CapEff:") {
                cap_eff_hex = rest.trim().to_owned();
            } else if let Some(rest) = line.strip_prefix("CapBnd:") {
                cap_bnd_hex = rest.trim().to_owned();
            } else if let Some(rest) = line.strip_prefix("NoNewPrivs:") {
                no_new_privs = rest.trim() == "1";
            } else if let Some(rest) = line.strip_prefix("VmRSS:") {
                vm_rss_kib = parse_kib_field(rest);
            }
        }
    }

    let cap_bnd_zero = !cap_bnd_hex.is_empty() && cap_bnd_hex.bytes().all(|b| b == b'0');

    ProcSecurityCaps {
        cap_eff_hex,
        cap_bnd_hex,
        cap_bnd_zero,
        no_new_privs,
        vm_rss_kib,
    }
}

/// Strictly checks that `ONIONOS_NETFILTER_FLAG` (`/run/onionos/netfilter.active`) exists and starts with `"active"`.
pub fn is_netfilter_active() -> bool {
    let flag_path = env::var("ONIONOS_NETFILTER_FLAG")
        .unwrap_or_else(|_| DEFAULT_NETFILTER_FLAG_PATH.to_owned());
    is_netfilter_flag_file_valid(Path::new(&flag_path))
}

pub fn is_netfilter_flag_file_valid(path: &Path) -> bool {
    fs::read_to_string(path)
        .ok()
        .is_some_and(|content| content.trim().starts_with("active"))
}

pub fn list_container_processes() -> Vec<ProcessInfoView> {
    let Ok(rd) = fs::read_dir("/proc") else {
        return vec![ProcessInfoView {
            name: "onion-os".to_owned(),
            state: "R".to_owned(),
            pid: std::process::id(),
            mem_kib: 0,
        }];
    };

    let mut procs = Vec::new();
    for entry in rd.flatten() {
        let fname = entry.file_name();
        let Some(pid_str) = fname.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let status_path = entry.path().join("status");
        let Ok(text) = fs::read_to_string(status_path) else {
            continue;
        };

        let mut name = String::new();
        let mut state = "S".to_owned();
        let mut mem_kib = 0u64;

        for line in text.lines() {
            if let Some(v) = line.strip_prefix("Name:") {
                name = v.trim().to_owned();
            } else if let Some(v) = line.strip_prefix("State:") {
                state = v.split_whitespace().next().unwrap_or("S").to_owned();
            } else if let Some(v) = line.strip_prefix("VmRSS:") {
                mem_kib = parse_kib_field(v);
            }
        }

        if !name.is_empty() {
            procs.push(ProcessInfoView {
                name,
                state,
                pid,
                mem_kib,
            });
        }
    }

    procs.sort_by(|a, b| b.mem_kib.cmp(&a.mem_kib).then_with(|| a.pid.cmp(&b.pid)));
    procs.truncate(64);
    procs
}

fn read_pid_rss_kib(pid: u32) -> u64 {
    let path = format!("/proc/{pid}/status");
    let Ok(text) = fs::read_to_string(path) else {
        return 0;
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            return parse_kib_field(v);
        }
    }
    0
}

fn parse_kib_field(raw: &str) -> u64 {
    raw.split_whitespace()
        .next()
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0)
}

fn extract_host_port(url_str: &str, fallback: &str) -> String {
    let Ok(parsed) = reqwest::Url::parse(url_str) else {
        return fallback.to_owned();
    };
    let Some(host) = parsed.host_str() else {
        return fallback.to_owned();
    };
    let port = parsed.port_or_known_default().unwrap_or(80);
    format!("{host}:{port}")
}

async fn tcp_probe(addr: &str, timeout_ms: u64) -> bool {
    tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .is_ok_and(|r| r.is_ok())
}

async fn http_head_probe(addr: &str, timeout_ms: u64) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fut = async {
        let mut stream = TcpStream::connect(addr).await.ok()?;
        stream
            .write_all(b"HEAD /vnc.html HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .ok()?;
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.ok()?;
        Some(n >= 7 && buf.starts_with(b"HTTP/1."))
    };
    tokio::time::timeout(Duration::from_millis(timeout_ms), fut)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}
