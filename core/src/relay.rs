//! Sovereign P2P Mesh Relay Controller (`oniontalk-relay-rs:1.8.2` On-Demand on `127.0.0.1:8088`)
//! - Ephemeral (`ADD_ONION NEW:ED25519-V3`) or PQC-Persistent (`/vault/relay.otpqcv2` `ADD_ONION ED25519-V3:<keyblob>`)
//! - Strict Base64 keyblob sanitizer preventing Tor ControlPort CRLF/command injection
//! - CSPRNG RAM-only `RELAY_ADMIN_TOKEN` (`Zeroizing<String>`) & process-group teardown (`kill(-pgid, SIGKILL)`)

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::{
    shred_and_remove_file, PersistedRelayIdentity, VaultError, VaultManager,
};

pub const DEFAULT_RELAY_BIN: &str = "/usr/local/bin/oniontalk-relay-rs";
pub const DEFAULT_RELAY_BIND_ADDR: &str = "127.0.0.1:8088";

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("Relay binary unavailable at '{0}'")]
    BinaryUnavailable(String),
    #[error("Relay node is not running")]
    NotRunning,
    #[error("Vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("Invalid or unsafe Tor ED25519-V3 keyblob: {0}")]
    InvalidKeyblob(String),
    #[error("Tor ControlPort error: {0}")]
    TorControl(String),
    #[error("Relay startup or healthcheck failed: {0}")]
    StartupFailed(String),
    #[error("Relay voucher request failed: {0}")]
    VoucherFailed(String),
    #[error("Relay I/O error: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayStatusResponse {
    pub state: String,
    pub binary_available: bool,
    pub persistent: bool,
    pub onion_address: Option<String>,
    pub onion_url: Option<String>,
    pub node_pubkey: Option<String>,
    pub peers_count: u64,
    pub online_nodes: u64,
    pub hibernating_nodes: u64,
    pub avg_peer_rtt_ms: f64,
    pub invalid_peers_blocked: u64,
    pub spoofed_acks_blocked: u64,
    pub engine: Option<String>,
    pub routing_engine: Option<String>,
    pub zero_trust_mode: Option<String>,
    pub memory_kib: u64,
    pub uptime_secs: u64,
}

impl RelayStatusResponse {
    pub fn stopped_with_binary(binary_available: bool) -> Self {
        Self {
            state: "stopped".to_owned(),
            binary_available,
            persistent: false,
            onion_address: None,
            onion_url: None,
            node_pubkey: None,
            peers_count: 0,
            online_nodes: 0,
            hibernating_nodes: 0,
            avg_peer_rtt_ms: 0.0,
            invalid_peers_blocked: 0,
            spoofed_acks_blocked: 0,
            engine: None,
            routing_engine: None,
            zero_trust_mode: None,
            memory_kib: 0,
            uptime_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayStopResponse {
    pub stopped: bool,
    pub del_onion_ok: bool,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayVoucherResponse {
    pub ok: bool,
    pub voucher: String,
    pub node_onion: Option<String>,
    pub node_pubkey: Option<String>,
}

struct ActiveRelayInstance {
    child: Child,
    service_id: String,
    onion_address: String,
    onion_url: String,
    persistent: bool,
    admin_token: Zeroizing<String>,
    relay_dir: PathBuf,
    started_at: Instant,
}

pub struct RelayNodeManager {
    home_dir: PathBuf,
    tor_socks_addr: String,
    tor_control_addr: String,
    tor_cookie_file: Option<PathBuf>,
    relay_bin: PathBuf,
    relay_args: Vec<String>,
    relay_data_dir_override: Option<PathBuf>,
    relay_bind_addr: String,
    http: reqwest::Client,
    active: Mutex<Option<ActiveRelayInstance>>,
}

impl RelayNodeManager {
    pub fn new(
        home_dir: PathBuf,
        tor_socks_addr: String,
        tor_control_addr: String,
        tor_cookie_file: Option<PathBuf>,
    ) -> Result<Arc<Self>, String> {
        let relay_bin = env::var("ONIONOS_RELAY_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_RELAY_BIN));

        let relay_data_dir_override = env::var("ONIONOS_RELAY_DATA_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from);

        let relay_bind_addr = env::var("ONIONOS_RELAY_BIND_ADDR")
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                env::var("ONIONOS_RELAY_BIND_PORT")
                    .ok()
                    .map(|p| p.trim().to_owned())
                    .filter(|p| !p.is_empty())
                    .map(|p| format!("127.0.0.1:{p}"))
            })
            .unwrap_or_else(|| DEFAULT_RELAY_BIND_ADDR.to_owned());

        Self::new_with_overrides(
            home_dir,
            tor_socks_addr,
            tor_control_addr,
            tor_cookie_file,
            relay_bin,
            Vec::new(),
            relay_data_dir_override,
            relay_bind_addr,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_overrides(
        home_dir: PathBuf,
        tor_socks_addr: String,
        tor_control_addr: String,
        tor_cookie_file: Option<PathBuf>,
        relay_bin: PathBuf,
        relay_args: Vec<String>,
        relay_data_dir_override: Option<PathBuf>,
        relay_bind_addr: String,
    ) -> Result<Arc<Self>, String> {
        let relay_bind_addr = validate_loopback_bind_addr(&relay_bind_addr)?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(3))
            .connect_timeout(Duration::from_millis(500))
            .build()
            .map_err(|e| format!("Failed building relay local HTTP client: {e}"))?;

        Ok(Arc::new(Self {
            home_dir,
            tor_socks_addr,
            tor_control_addr,
            tor_cookie_file,
            relay_bin,
            relay_args,
            relay_data_dir_override,
            relay_bind_addr,
            http,
            active: Mutex::new(None),
        }))
    }

    pub fn is_binary_available(&self) -> bool {
        self.relay_bin.is_file()
    }

    pub async fn state_label(&self) -> String {
        let mut guard = self.active.lock().await;
        if let Some(inst) = &mut *guard {
            if matches!(inst.child.try_wait(), Ok(None)) {
                return "running".to_owned();
            }
            let dead_dir = inst.relay_dir.clone();
            *guard = None;
            wipe_relay_runtime_dir(&dead_dir);
        }
        "stopped".to_owned()
    }

    pub async fn status(&self) -> RelayStatusResponse {
        let bin_ok = self.is_binary_available();

        let (onion_address, onion_url, persistent, pid, uptime_secs) = {
            let mut guard = self.active.lock().await;
            let Some(inst) = &mut *guard else {
                return RelayStatusResponse::stopped_with_binary(bin_ok);
            };
            if !matches!(inst.child.try_wait(), Ok(None)) {
                let dead_dir = inst.relay_dir.clone();
                *guard = None;
                wipe_relay_runtime_dir(&dead_dir);
                return RelayStatusResponse::stopped_with_binary(bin_ok);
            }
            (
                inst.onion_address.clone(),
                inst.onion_url.clone(),
                inst.persistent,
                inst.child.id(),
                inst.started_at.elapsed().as_secs(),
            )
        };

        let memory_kib = pid.map(read_pid_rss_kib).unwrap_or(0);
        let health_url = format!("http://{}/health", self.relay_bind_addr);
        let health_res = self
            .http
            .get(&health_url)
            .timeout(Duration::from_millis(400))
            .send()
            .await;

        let mut resp = RelayStatusResponse {
            state: "starting".to_owned(),
            binary_available: bin_ok,
            persistent,
            onion_address: Some(onion_address),
            onion_url: Some(onion_url),
            node_pubkey: None,
            peers_count: 0,
            online_nodes: 0,
            hibernating_nodes: 0,
            avg_peer_rtt_ms: 0.0,
            invalid_peers_blocked: 0,
            spoofed_acks_blocked: 0,
            engine: None,
            routing_engine: None,
            zero_trust_mode: None,
            memory_kib,
            uptime_secs,
        };

        if let Ok(hr) = health_res {
            if hr.status().is_success() {
                resp.state = "running".to_owned();
                if let Ok(val) = hr.json::<serde_json::Value>().await {
                    populate_health_metrics(&mut resp, &val);
                }
            }
        }

        resp
    }

    pub async fn start(
        &self,
        persistent: bool,
        vault: &VaultManager,
    ) -> Result<RelayStatusResponse, RelayError> {
        let existing_identity = if persistent {
            vault.load_relay_identity().await?
        } else {
            None
        };

        if !self.is_binary_available() {
            return Err(RelayError::BinaryUnavailable(
                self.relay_bin.display().to_string(),
            ));
        }

        // Tear down any previous relay instance cleanly before starting a new one
        let _ = self.stop_with_timeout(Duration::from_millis(800)).await;

        let relay_dir = self.resolve_relay_runtime_dir();
        fs::create_dir_all(&relay_dir).map_err(|e| RelayError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&relay_dir, fs::Permissions::from_mode(0o700));
        }
        wipe_relay_runtime_dir(&relay_dir);
        fs::create_dir_all(&relay_dir).map_err(|e| RelayError::Io(e.to_string()))?;

        let (service_id, keyblob_for_save, created_at_str, restored_node_key) =
            match existing_identity {
                Some(persisted) => {
                    validate_ed25519_v3_keyblob(&persisted.tor_ed25519_v3_keyblob)?;
                    let sid = tor_add_onion_relay(
                        &self.tor_control_addr,
                        self.tor_cookie_file.as_deref(),
                        Some(&persisted.tor_ed25519_v3_keyblob),
                        &self.relay_bind_addr,
                        Duration::from_secs(4),
                    )
                    .await?
                    .0;
                    (
                        sid,
                        Zeroizing::new(persisted.tor_ed25519_v3_keyblob.clone()),
                        persisted.created_at.clone(),
                        persisted.relay_node_key_b64.clone(),
                    )
                }
                None => {
                    let (sid, fresh_keyblob) = tor_add_onion_relay(
                        &self.tor_control_addr,
                        self.tor_cookie_file.as_deref(),
                        None,
                        &self.relay_bind_addr,
                        Duration::from_secs(4),
                    )
                    .await?;
                    if persistent {
                        validate_ed25519_v3_keyblob(&fresh_keyblob)?;
                    }
                    (sid, fresh_keyblob, Utc::now().to_rfc3339(), None)
                }
            };

        let onion_address = format!("{service_id}.onion");
        let onion_url = format!("http://{onion_address}");

        let hostname_path = relay_dir.join("hostname");
        let node_key_path = relay_dir.join("oniontalk_node_ed25519.key");

        if let Err(e) = write_restricted_file(&hostname_path, format!("{onion_address}\n").as_bytes())
        {
            let _ = tor_del_onion_relay(
                &self.tor_control_addr,
                self.tor_cookie_file.as_deref(),
                &service_id,
                Duration::from_millis(800),
            )
            .await;
            return Err(RelayError::Io(e));
        }

        if persistent {
            if let Some(ref b64_key) = restored_node_key {
                if let Ok(raw_key) = B64.decode(b64_key.trim().as_bytes()) {
                    let key_zero = Zeroizing::new(raw_key);
                    let _ = write_restricted_file(&node_key_path, &key_zero);
                }
            }
        }

        let mut admin_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut admin_bytes);
        let admin_token = Zeroizing::new(hex::encode(admin_bytes));
        admin_bytes.zeroize();

        let socks_uri = format!("socks5h://{}", self.tor_socks_addr);

        let mut cmd = Command::new(&self.relay_bin);
        if !self.relay_args.is_empty() {
            cmd.args(&self.relay_args);
        }
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
                .env("HOME", &relay_dir)
                .env("USER", "onion");
        }
        cmd.env("EXTERNAL_TOR", "1")
            .env("RELAY_BIND_ADDR", &self.relay_bind_addr)
            .env("DATA_DIR", &relay_dir)
            .env("TOR_HOSTNAME_FILE", &hostname_path)
            .env("TOR_SOCKS_PROXY", &socks_uri)
            .env("RELAY_ADMIN_TOKEN", admin_token.as_str())
            .env("RELAY_NODE_KEY_FILE", &node_key_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        #[cfg(unix)]
        {
            cmd.process_group(0);
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = tor_del_onion_relay(
                    &self.tor_control_addr,
                    self.tor_cookie_file.as_deref(),
                    &service_id,
                    Duration::from_millis(800),
                )
                .await;
                wipe_relay_runtime_dir(&relay_dir);
                return Err(RelayError::StartupFailed(format!(
                    "Failed spawning {}: {e}",
                    self.relay_bin.display()
                )));
            }
        };

        // Poll up to 3.5s (24 * 150ms) for `GET http://127.0.0.1:8088/health` -> 200 OK
        let health_url = format!("http://{}/health", self.relay_bind_addr);
        let mut healthy = false;
        for _ in 0..24 {
            if !matches!(child.try_wait(), Ok(None)) {
                break;
            }
            if let Ok(r) = self
                .http
                .get(&health_url)
                .timeout(Duration::from_millis(300))
                .send()
                .await
            {
                if r.status().is_success() {
                    healthy = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        if !healthy {
            kill_child_process_group(&mut child).await;
            let _ = tor_del_onion_relay(
                &self.tor_control_addr,
                self.tor_cookie_file.as_deref(),
                &service_id,
                Duration::from_millis(800),
            )
            .await;
            wipe_relay_runtime_dir(&relay_dir);
            return Err(RelayError::StartupFailed(format!(
                "Relay failed healthcheck on {health_url} within 3.5s"
            )));
        }

        if persistent {
            let relay_node_key_b64 = fs::read(&node_key_path)
                .ok()
                .filter(|b| !b.is_empty())
                .map(|raw| {
                    let z = Zeroizing::new(raw);
                    B64.encode(&*z)
                })
                .or(restored_node_key);

            let to_save = PersistedRelayIdentity {
                tor_ed25519_v3_keyblob: keyblob_for_save.as_str().to_owned(),
                onion_address: onion_address.clone(),
                relay_node_key_b64,
                created_at: created_at_str,
            };
            if let Err(e) = vault.save_relay_identity(&to_save).await {
                kill_child_process_group(&mut child).await;
                let _ = tor_del_onion_relay(
                    &self.tor_control_addr,
                    self.tor_cookie_file.as_deref(),
                    &service_id,
                    Duration::from_millis(800),
                )
                .await;
                wipe_relay_runtime_dir(&relay_dir);
                return Err(RelayError::Vault(e));
            }
        }

        {
            let mut guard = self.active.lock().await;
            *guard = Some(ActiveRelayInstance {
                child,
                service_id,
                onion_address,
                onion_url,
                persistent,
                admin_token,
                relay_dir,
                started_at: Instant::now(),
            });
        }

        Ok(self.status().await)
    }

    pub async fn issue_voucher(&self) -> Result<RelayVoucherResponse, RelayError> {
        let (admin_tok, onion_addr) = {
            let mut guard = self.active.lock().await;
            let Some(inst) = &mut *guard else {
                return Err(RelayError::NotRunning);
            };
            if !matches!(inst.child.try_wait(), Ok(None)) {
                let dead_dir = inst.relay_dir.clone();
                *guard = None;
                wipe_relay_runtime_dir(&dead_dir);
                return Err(RelayError::NotRunning);
            }
            (inst.admin_token.clone(), inst.onion_address.clone())
        };

        let url = format!("http://{}/api/v1/node/claim-token", self.relay_bind_addr);
        let resp = self
            .http
            .get(&url)
            .header("X-Admin-Token", admin_tok.as_str())
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|e| RelayError::VoucherFailed(e.to_string()))?;

        if !resp.status().is_success() {
            let code = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(RelayError::VoucherFailed(format!("HTTP {code}: {detail}")));
        }

        let val = resp
            .json::<serde_json::Value>()
            .await
            .map_err(|e| RelayError::VoucherFailed(format!("Invalid voucher JSON: {e}")))?;

        let voucher = val
            .get("voucher")
            .or_else(|| val.get("claim_token"))
            .or_else(|| val.get("claimToken"))
            .or_else(|| val.get("token"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| {
                RelayError::VoucherFailed("Missing voucher field in relay response".into())
            })?;

        let node_onion = val
            .get("nodeOnion")
            .or_else(|| val.get("node_onion"))
            .or_else(|| val.get("onion"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or(Some(onion_addr));

        let node_pubkey = val
            .get("nodePubkey")
            .or_else(|| val.get("node_pubkey"))
            .or_else(|| val.get("pubkey"))
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        Ok(RelayVoucherResponse {
            ok: true,
            voucher,
            node_onion,
            node_pubkey,
        })
    }

    pub async fn stop_with_timeout(&self, timeout: Duration) -> RelayStopResponse {
        let taken = {
            let mut guard = self.active.lock().await;
            guard.take()
        };

        let Some(mut inst) = taken else {
            return RelayStopResponse {
                stopped: true,
                del_onion_ok: true,
                state: "stopped".to_owned(),
            };
        };

        let (_, del_ok) = tokio::join!(
            kill_child_process_group(&mut inst.child),
            tor_del_onion_relay(
                &self.tor_control_addr,
                self.tor_cookie_file.as_deref(),
                &inst.service_id,
                timeout,
            ),
        );

        inst.service_id.zeroize();
        wipe_relay_runtime_dir(&inst.relay_dir);

        RelayStopResponse {
            stopped: true,
            del_onion_ok: del_ok,
            state: "stopped".to_owned(),
        }
    }

    fn resolve_relay_runtime_dir(&self) -> PathBuf {
        if let Some(custom) = &self.relay_data_dir_override {
            return custom.clone();
        }
        let data_root = Path::new("/data");
        if data_root.is_dir() && crate::forensics::check_dir_writable(data_root) {
            return data_root.join("relay");
        }
        self.home_dir.join(".relay-runtime")
    }
}

/// Strict Base64 validator: allows ONLY ASCII `[A-Za-z0-9+/=]` of length `80..=128`,
/// blocking CRLF, spaces, quotes or Tor ControlPort command injection.
pub fn validate_ed25519_v3_keyblob(keyblob: &str) -> Result<(), RelayError> {
    let len = keyblob.len();
    if !(80..=128).contains(&len) {
        return Err(RelayError::InvalidKeyblob(format!(
            "Expected Base64 length 80..=128, got {len}"
        )));
    }
    if !keyblob
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    {
        return Err(RelayError::InvalidKeyblob(
            "Keyblob contains non-Base64 or control characters".into(),
        ));
    }
    Ok(())
}

fn populate_health_metrics(target: &mut RelayStatusResponse, v: &serde_json::Value) {
    let str_field = |keys: &[&str]| -> Option<String> {
        for &k in keys {
            if let Some(s) = v.get(k).and_then(|x| x.as_str()) {
                if !s.is_empty() {
                    return Some(s.to_owned());
                }
            }
        }
        None
    };
    let u64_field = |keys: &[&str]| -> u64 {
        for &k in keys {
            if let Some(n) = v.get(k).and_then(|x| x.as_u64()) {
                return n;
            }
        }
        0
    };
    let f64_field = |keys: &[&str]| -> f64 {
        for &k in keys {
            if let Some(n) = v.get(k).and_then(|x| x.as_f64()) {
                return n;
            }
        }
        0.0
    };

    target.node_pubkey = str_field(&["node_pubkey", "nodePubkey", "pubkey"]);
    target.peers_count = u64_field(&["peers_count", "peersCount", "known_peers", "peers"]);
    target.online_nodes = u64_field(&["online_nodes", "onlineNodes"]);
    target.hibernating_nodes = u64_field(&["hibernating_nodes", "hibernatingNodes"]);
    target.avg_peer_rtt_ms = f64_field(&["avg_peer_rtt_ms", "avgPeerRttMs"]);
    target.invalid_peers_blocked =
        u64_field(&["invalid_peers_blocked", "invalidPeersBlocked"]);
    target.spoofed_acks_blocked =
        u64_field(&["spoofed_acks_blocked", "spoofedAcksBlocked"]);
    target.engine = str_field(&["engine", "version"]);
    target.routing_engine = str_field(&["routing_engine", "routingEngine"]);
    target.zero_trust_mode = str_field(&["zero_trust_mode", "zeroTrustMode"]);
}

async fn kill_child_process_group(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        if pid > 1 {
            // SAFETY: child was spawned with `.process_group(0)`, so `-pid` targets its isolated PGID.
            unsafe {
                let _ = libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

fn write_restricted_file(path: &Path, content: &[u8]) -> Result<(), String> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| format!("Failed opening {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    file.write_all(content)
        .map_err(|e| format!("Failed writing {}: {e}", path.display()))?;
    let _ = file.sync_all();
    Ok(())
}

fn wipe_relay_runtime_dir(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if let Ok(meta) = fs::symlink_metadata(&p) {
            if meta.file_type().is_dir() {
                wipe_relay_runtime_dir(&p);
                let _ = fs::remove_dir(&p);
            } else {
                let _ = shred_and_remove_file(&p);
            }
        }
    }
    let _ = fs::remove_dir(dir);
}

fn read_pid_rss_kib(pid: u32) -> u64 {
    let path = format!("/proc/{pid}/status");
    let Ok(text) = fs::read_to_string(path) else {
        return 0;
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            return v
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }
    0
}

fn load_control_cookie_hex(cookie_file: Option<&Path>) -> Option<String> {
    if let Some(p) = cookie_file {
        if let Ok(bytes) = fs::read(p) {
            if !bytes.is_empty() {
                return Some(hex::encode(bytes));
            }
        }
    }
    for candidate in ["/run/tor/control.authcookie", "/var/lib/tor/control_auth_cookie"] {
        if let Ok(bytes) = fs::read(candidate) {
            if !bytes.is_empty() {
                return Some(hex::encode(bytes));
            }
        }
    }
    None
}

pub fn validate_loopback_bind_addr(raw: &str) -> Result<String, String> {
    let sock: SocketAddrV4 = raw.trim().parse().map_err(|_| {
        format!("Invalid relay bind address '{raw}': expected strict 127.0.0.1:<port>")
    })?;
    if sock.ip() != &Ipv4Addr::LOCALHOST || sock.port() == 0 {
        return Err(format!(
            "Relay bind address '{raw}' must bind strictly to 127.0.0.1 with port > 0"
        ));
    }
    Ok(sock.to_string())
}

async fn tor_add_onion_relay(
    control_addr: &str,
    cookie_file: Option<&Path>,
    restored_keyblob: Option<&str>,
    relay_bind_addr: &str,
    timeout: Duration,
) -> Result<(String, Zeroizing<String>), RelayError> {
    if let Some(kb) = restored_keyblob {
        validate_ed25519_v3_keyblob(kb)?;
    }
    let clean_bind =
        validate_loopback_bind_addr(relay_bind_addr).map_err(RelayError::TorControl)?;
    let cookie_hex = load_control_cookie_hex(cookie_file);

    let fut = async {
        let stream = TcpStream::connect(control_addr)
            .await
            .map_err(|e| RelayError::TorControl(format!("connect {control_addr}: {e}")))?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let auth_cmd = match &cookie_hex {
            Some(h) => format!("AUTHENTICATE {h}\r\n"),
            None => "AUTHENTICATE \"\"\r\n".to_owned(),
        };
        write_half
            .write_all(auth_cmd.as_bytes())
            .await
            .map_err(|e| RelayError::TorControl(e.to_string()))?;

        let mut auth_line = String::new();
        reader
            .read_line(&mut auth_line)
            .await
            .map_err(|e| RelayError::TorControl(e.to_string()))?;
        if !auth_line.starts_with("250") {
            return Err(RelayError::TorControl(format!(
                "AUTHENTICATE rejected: {}",
                auth_line.trim()
            )));
        }

        let cmd = Zeroizing::new(match restored_keyblob {
            Some(kb) => {
                format!("ADD_ONION ED25519-V3:{kb} Flags=Detach Port=80,{clean_bind}\r\n")
            }
            None => {
                format!("ADD_ONION NEW:ED25519-V3 Flags=Detach Port=80,{clean_bind}\r\n")
            }
        });
        write_half
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| RelayError::TorControl(e.to_string()))?;

        let mut service_id: Option<String> = None;
        let mut captured_keyblob = Zeroizing::new(
            restored_keyblob.unwrap_or_default().to_owned(),
        );

        loop {
            let mut line = String::new();
            let n = reader
                .read_line(&mut line)
                .await
                .map_err(|e| RelayError::TorControl(e.to_string()))?;
            if n == 0 {
                break;
            }
            let trimmed = line.trim();
            if let Some(rest) = trimmed
                .strip_prefix("250-ServiceID=")
                .or_else(|| trimmed.strip_prefix("250 ServiceID="))
            {
                service_id = Some(rest.trim().to_ascii_lowercase());
            } else if let Some(pk_rest) = trimmed
                .strip_prefix("250-PrivateKey=ED25519-V3:")
                .or_else(|| trimmed.strip_prefix("250 PrivateKey=ED25519-V3:"))
            {
                *captured_keyblob = pk_rest.trim().to_owned();
                line.zeroize();
                continue;
            } else if trimmed.contains("PrivateKey=") {
                line.zeroize();
                continue;
            }

            if trimmed.starts_with("250 ") {
                line.zeroize();
                break;
            }
            if !trimmed.starts_with("250") {
                let err_copy = trimmed.to_owned();
                line.zeroize();
                return Err(RelayError::TorControl(format!(
                    "ADD_ONION rejected: {err_copy}"
                )));
            }
            line.zeroize();
        }

        let _ = write_half.write_all(b"QUIT\r\n").await;
        let sid = service_id
            .ok_or_else(|| RelayError::TorControl("Missing ServiceID in ADD_ONION reply".into()))?;
        Ok((sid, captured_keyblob))
    };

    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| RelayError::TorControl(format!("Timeout talking to {control_addr}")))?
}

async fn tor_del_onion_relay(
    control_addr: &str,
    cookie_file: Option<&Path>,
    service_id: &str,
    timeout: Duration,
) -> bool {
    let cookie_hex = load_control_cookie_hex(cookie_file);
    let fut = async {
        let Ok(stream) = TcpStream::connect(control_addr).await else {
            return false;
        };
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let auth_cmd = match &cookie_hex {
            Some(h) => format!("AUTHENTICATE {h}\r\n"),
            None => "AUTHENTICATE \"\"\r\n".to_owned(),
        };
        if write_half.write_all(auth_cmd.as_bytes()).await.is_err() {
            return false;
        }
        let mut line = String::new();
        if reader.read_line(&mut line).await.is_err() || !line.starts_with("250") {
            return false;
        }

        let del_cmd = format!("DEL_ONION {service_id}\r\n");
        if write_half.write_all(del_cmd.as_bytes()).await.is_err() {
            return false;
        }
        line.clear();
        let ok = reader.read_line(&mut line).await.is_ok() && line.starts_with("250");
        let _ = write_half.write_all(b"QUIT\r\n").await;
        ok
    };

    tokio::time::timeout(timeout, fut).await.unwrap_or(false)
}
