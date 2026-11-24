//! OnionOS v1.0.0 Core Library — Consolidated Sovereign Container & Onion Mesh Web Compositor

pub mod files;
pub mod forensics;
pub mod mlkem768;
pub mod onionshare;
pub mod osint;
pub mod proxy;
pub mod pty_shell;
pub mod qr;
pub mod relay;
pub mod supervisor;
pub mod totp;
pub mod vault;

use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, Request, State, WebSocketUpgrade};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, HOST, ORIGIN, REFERRER_POLICY,
    SET_COOKIE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

use crate::files::{
    DualRootFileManager, FileActionResponse, FileDeleteResponse, FileListResponse,
    FileMkdirResponse, FileReadResponse, FileWriteResponse, FilesError,
};
use crate::forensics::{ForensicsError, ScrubReport};
use crate::onionshare::{
    OnionShareController, OnionShareError, OnionShareStartRequest, OnionShareStatusResponse,
    OnionShareStopResponse,
};
use crate::osint::{
    OnionValidationResult, OsintError, OsintProbeResult, TorCircuitsResponse, TorNewnymResult,
};
use crate::proxy::SandboxResetResponse;
use crate::pty_shell::PtyRegistry;
use crate::qr::QrSvgResponse;
use crate::relay::{
    RelayError, RelayNodeManager, RelayStatusResponse, RelayStopResponse, RelayVoucherResponse,
};
use crate::supervisor::{
    BrowserStatusResponse, BrowserStopResponse, ProcessSupervisor, SystemMonitorResponse,
};
use crate::totp::{
    GeneratedSecretResponse, TotpCodesResponse, TotpError, TotpPreviewResponse,
};
use crate::vault::{
    AuthStatusView, DesktopSettings, NewVaultItemInput, OpenResponse, SealResponse, VaultError,
    VaultItemView, VaultManager,
};

pub const ONIONOS_VERSION: &str = "1.0.0";
pub const DEFAULT_OS_PRETTY_NAME: &str = "OnionOS (Onion Mesh Amnesic Tor PQC Linux)";
pub const STRICT_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob: data:; connect-src 'self'; frame-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'";
pub const PROXY_EMBED_CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob: data:; connect-src 'self' ws: wss:; frame-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'";
pub const PERMISSIONS_POLICY_VAL: &str =
    "camera=(), microphone=(self), geolocation=(), payment=(), usb=()";

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub bind_addr: String,
    pub bind_port: u16,
    pub static_dir: PathBuf,
    pub vault_dir: PathBuf,
    pub home_dir: PathBuf,
    pub tor_socks_addr: String,
    pub tor_control_addr: String,
    pub tor_control_cookie_file: Option<PathBuf>,
    pub oniontalk_internal_url: String,
    pub sandbox_browser_url: String,
    pub sandbox_reset_url: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let bind_addr = env::var("ONIONOS_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".into());
        let bind_port = env::var("ONIONOS_BIND_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(8430);

        let static_dir = resolve_static_dir();

        let vault_dir = env::var("ONIONOS_VAULT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_vault_dir());

        let home_dir = env::var("ONIONOS_HOME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_home_dir());

        let tor_socks_addr =
            env::var("TOR_SOCKS_ADDR").unwrap_or_else(|_| "127.0.0.1:9050".into());
        let tor_control_addr =
            env::var("TOR_CONTROL_ADDR").unwrap_or_else(|_| "127.0.0.1:9051".into());
        let tor_control_cookie_file = env::var("TOR_CONTROL_COOKIE_FILE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from);

        let oniontalk_internal_url = env::var("ONIONTALK_INTERNAL_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8420".into());
        let sandbox_browser_url = env::var("SANDBOX_BROWSER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:6901".into());
        let sandbox_reset_url = env::var("SANDBOX_RESET_URL")
            .unwrap_or_else(|_| derive_default_sandbox_reset_url(&sandbox_browser_url));

        Self {
            bind_addr,
            bind_port,
            static_dir,
            vault_dir,
            home_dir,
            tor_socks_addr,
            tor_control_addr,
            tor_control_cookie_file,
            oniontalk_internal_url,
            sandbox_browser_url,
            sandbox_reset_url,
        }
    }
}

fn resolve_static_dir() -> PathBuf {
    if let Ok(custom) = env::var("ONIONOS_STATIC_DIR") {
        return PathBuf::from(custom);
    }
    for candidate in ["./static", "../static", "/usr/share/onionos/static"] {
        let p = PathBuf::from(candidate);
        if p.is_dir() {
            return p;
        }
    }
    PathBuf::from("./static")
}

#[cfg(unix)]
fn default_vault_dir() -> PathBuf {
    PathBuf::from("/vault")
}

#[cfg(windows)]
fn default_vault_dir() -> PathBuf {
    env::temp_dir().join("onionos_vault")
}

#[cfg(unix)]
fn default_home_dir() -> PathBuf {
    PathBuf::from("/home/onion")
}

#[cfg(windows)]
fn default_home_dir() -> PathBuf {
    env::temp_dir().join("onionos_home")
}

fn derive_default_sandbox_reset_url(sandbox_url: &str) -> String {
    let base = sandbox_url.trim_end_matches('/');
    if let Some(prefix) = base.strip_suffix(":6901") {
        format!("{prefix}:6902/reset")
    } else {
        "http://127.0.0.1:6902/reset".into()
    }
}

pub struct AppState {
    pub config: AppConfig,
    pub vault: VaultManager,
    pub files: DualRootFileManager,
    pub supervisor: ProcessSupervisor,
    pub onionshare: Arc<OnionShareController>,
    pub relay: Arc<RelayNodeManager>,
    pub pty_registry: Arc<PtyRegistry>,
    pub internal_http_client: reqwest::Client,
    pub started_at: Instant,
    pub os_pretty_name: String,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Arc<Self>, String> {
        let internal_http_client = reqwest::Client::builder()
            .no_proxy()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("Failed to build internal HTTP client: {e}"))?;

        let os_pretty_name = read_os_pretty_name();
        let files = DualRootFileManager::new(config.home_dir.clone());
        let supervisor = ProcessSupervisor::new(
            config.home_dir.clone(),
            &config.tor_socks_addr,
            &config.sandbox_browser_url,
        );
        let onionshare = OnionShareController::new(
            config.home_dir.clone(),
            config.tor_control_addr.clone(),
            config.tor_control_cookie_file.clone(),
        );
        let relay = RelayNodeManager::new(
            config.home_dir.clone(),
            config.tor_socks_addr.clone(),
            config.tor_control_addr.clone(),
            config.tor_control_cookie_file.clone(),
        )?;

        Ok(Arc::new(Self {
            vault: VaultManager::new(config.vault_dir.clone()),
            files,
            supervisor,
            onionshare,
            relay,
            config,
            pty_registry: Arc::new(PtyRegistry::new()),
            internal_http_client,
            started_at: Instant::now(),
            os_pretty_name,
        }))
    }

    pub async fn teardown_ephemeral_services(&self) {
        let _ = self.pty_registry.kill_all().await;
        let _ = tokio::join!(
            self.onionshare
                .stop_with_timeout(Duration::from_millis(600)),
            self.relay.stop_with_timeout(Duration::from_millis(250)),
            self.supervisor.stop_browser(),
        );
    }

    pub async fn enforce_idle_autolock(&self) -> bool {
        if self.vault.reap_expired_idle_session().await {
            self.teardown_ephemeral_services().await;
            return true;
        }
        false
    }

    pub fn new_for_tests(config: AppConfig) -> Result<Arc<Self>, String> {
        let internal_http_client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| format!("Failed to build test HTTP client: {e}"))?;

        let _ = fs::create_dir_all(&config.vault_dir);
        let files = DualRootFileManager::new(config.home_dir.clone());
        let supervisor = ProcessSupervisor::new(
            config.home_dir.clone(),
            &config.tor_socks_addr,
            &config.sandbox_browser_url,
        );
        let onionshare = OnionShareController::new(
            config.home_dir.clone(),
            config.tor_control_addr.clone(),
            config.tor_control_cookie_file.clone(),
        );
        let relay = RelayNodeManager::new(
            config.home_dir.clone(),
            config.tor_socks_addr.clone(),
            config.tor_control_addr.clone(),
            config.tor_control_cookie_file.clone(),
        )?;

        Ok(Arc::new(Self {
            vault: VaultManager::new_without_backoff(config.vault_dir.clone()),
            files,
            supervisor,
            onionshare,
            relay,
            config,
            pty_registry: Arc::new(PtyRegistry::new()),
            internal_http_client,
            started_at: Instant::now(),
            os_pretty_name: DEFAULT_OS_PRETTY_NAME.to_owned(),
        }))
    }
}

fn read_os_pretty_name() -> String {
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
                let unquoted = val.trim().trim_matches('"');
                if unquoted.contains("OnionOS") {
                    return unquoted.to_owned();
                }
            }
        }
    }
    DEFAULT_OS_PRETTY_NAME.to_owned()
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    NotFound(String),
    Unprocessable(String),
    ServiceUnavailable(String),
    Internal(String),
}

impl From<VaultError> for ApiError {
    fn from(err: VaultError) -> Self {
        match err {
            VaultError::PassphraseTooShort => ApiError::BadRequest(err.to_string()),
            VaultError::InvalidPassphrase => ApiError::Unauthorized(err.to_string()),
            VaultError::Locked | VaultError::Unauthorized => {
                ApiError::Unauthorized(err.to_string())
            }
            VaultError::Validation(m) => ApiError::BadRequest(m),
            VaultError::NotFound(m) => ApiError::NotFound(format!("Vault item not found: {m}")),
            VaultError::Crypto(m) => ApiError::Unprocessable(m),
            VaultError::Io(m) => ApiError::Internal(m),
        }
    }
}

impl From<ForensicsError> for ApiError {
    fn from(err: ForensicsError) -> Self {
        match err {
            ForensicsError::InvalidBase64(_)
            | ForensicsError::PayloadTooLarge
            | ForensicsError::UnsupportedFormat
            | ForensicsError::Malformed { .. } => ApiError::Unprocessable(err.to_string()),
            ForensicsError::UnsafeWipeTarget(_) => ApiError::BadRequest(err.to_string()),
            ForensicsError::Io(_) => ApiError::Internal(err.to_string()),
        }
    }
}

impl From<OsintError> for ApiError {
    fn from(err: OsintError) -> Self {
        match err {
            OsintError::InvalidUrl(_) | OsintError::BlockedTarget(_) => {
                ApiError::BadRequest(err.to_string())
            }
            OsintError::ClientBuild(_) => ApiError::Internal(err.to_string()),
        }
    }
}

impl From<TotpError> for ApiError {
    fn from(err: TotpError) -> Self {
        ApiError::BadRequest(err.to_string())
    }
}

impl From<FilesError> for ApiError {
    fn from(err: FilesError) -> Self {
        match err {
            FilesError::InvalidRoot(_)
            | FilesError::InvalidPath(_)
            | FilesError::UnsupportedAction(_) => ApiError::BadRequest(err.to_string()),
            FilesError::NotFound(_) => ApiError::NotFound(err.to_string()),
            FilesError::PayloadTooLarge => ApiError::Unprocessable(err.to_string()),
            FilesError::Vault(ve) => ApiError::from(ve),
            FilesError::Forensics(fe) => ApiError::from(fe),
            FilesError::Io(m) => ApiError::Internal(m),
        }
    }
}

impl From<OnionShareError> for ApiError {
    fn from(err: OnionShareError) -> Self {
        match err {
            OnionShareError::InvalidMode(_) | OnionShareError::Validation(_) => {
                ApiError::BadRequest(err.to_string())
            }
            OnionShareError::Files(fe) => ApiError::from(fe),
            OnionShareError::TorControl(m) => ApiError::ServiceUnavailable(format!(
                "Tor ControlPort ADD_ONION unavailable: {m}"
            )),
            OnionShareError::Io(m) => ApiError::Internal(m),
        }
    }
}

impl From<RelayError> for ApiError {
    fn from(err: RelayError) -> Self {
        match err {
            RelayError::Vault(ve) => ApiError::from(ve),
            RelayError::InvalidKeyblob(_) => ApiError::BadRequest(err.to_string()),
            RelayError::NotRunning => ApiError::BadRequest(err.to_string()),
            RelayError::BinaryUnavailable(_)
            | RelayError::TorControl(_)
            | RelayError::StartupFailed(_)
            | RelayError::VoucherFailed(_) => ApiError::ServiceUnavailable(err.to_string()),
            RelayError::Io(m) => ApiError::Internal(m),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Unprocessable(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            ApiError::ServiceUnavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
            ApiError::Internal(m) => {
                tracing::error!(error = %m, "Internal OnionOS error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".into())
            }
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let weak_state = Arc::downgrade(&state);
        handle.spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(15));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(st) = weak_state.upgrade() else {
                    break;
                };
                st.enforce_idle_autolock().await;
            }
        });
    }

    Router::new()
        // Static UI Assets
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/styles.css", get(serve_styles))
        .route("/app.js", get(serve_app_js))
        .route("/favicon.svg", get(serve_favicon))
        .route("/assets/{*file}", get(serve_static_asset))
        .route("/icons/{*file}", get(serve_icons_asset))
        .route("/{filename}", get(serve_top_level_static_asset))
        // Public Health & Auth Status
        .route("/api/health", get(api_health))
        .route("/api/auth/status", get(api_auth_status))
        .route("/api/auth/unlock", post(api_auth_unlock))
        .route("/api/auth/lock", post(api_auth_lock))
        // System Telemetry, Monitor, Settings & Panic Burn
        .route("/api/system/telemetry", get(api_system_telemetry))
        .route("/api/system/monitor", get(api_system_monitor))
        .route(
            "/api/system/settings",
            get(api_system_settings_get).post(api_system_settings_post),
        )
        .route("/api/system/panic-burn", post(api_system_panic_burn))
        // Post-Quantum Vault Items
        .route("/api/vault/items", get(api_vault_list).post(api_vault_add))
        .route("/api/vault/items/{id}", delete(api_vault_delete))
        // Hybrid PQC Envelope Seal / Open & Secret Generator
        .route("/api/pqc/seal", post(api_pqc_seal))
        .route("/api/pqc/open", post(api_pqc_open))
        .route("/api/pqc/generate-secret", post(api_pqc_generate_secret))
        // RFC 6238 TOTP 2FA & Offline QR SVG
        .route("/api/totp/codes", get(api_totp_codes))
        .route("/api/totp/preview", post(api_totp_preview))
        .route("/api/qr/svg", post(api_qr_svg))
        // GNOME Files Dual-Root (`ram` + `vault`)
        .route("/api/files/list", get(api_files_list))
        .route("/api/files/mkdir", post(api_files_mkdir))
        .route("/api/files/write", post(api_files_write))
        .route("/api/files/read", get(api_files_read))
        .route("/api/files/delete", post(api_files_delete))
        .route("/api/files/action", post(api_files_action))
        // Lazy Browser Supervisor & Sandbox Reset
        .route("/api/browser/status", get(api_browser_status))
        .route("/api/browser/start", post(api_browser_start))
        .route("/api/browser/stop", post(api_browser_stop))
        .route("/api/sandbox/reset", post(api_sandbox_reset))
        // Ephemeral OnionShare (`ADD_ONION` / `DEL_ONION`)
        .route("/api/onionshare/status", get(api_onionshare_status))
        .route("/api/onionshare/start", post(api_onionshare_start))
        .route("/api/onionshare/stop", post(api_onionshare_stop))
        // Sovereign P2P Mesh Relay (`oniontalk-relay-rs:1.8.2` on `127.0.0.1:8088`)
        .route("/api/relay/status", get(api_relay_status))
        .route("/api/relay/start", post(api_relay_start))
        .route("/api/relay/stop", post(api_relay_stop))
        .route("/api/relay/voucher", post(api_relay_voucher))
        // Anti-Forensics Metadata Scrub & Audit
        .route("/api/forensics/scrub", post(api_forensics_scrub))
        .route("/api/forensics/audit", get(api_forensics_audit))
        // Defensive OSINT & Tor Control / Circuits
        .route("/api/osint/validate-onion", post(api_osint_validate_onion))
        .route("/api/osint/probe", post(api_osint_probe))
        .route("/api/tor/newnym", post(api_tor_newnym))
        .route("/api/tor/circuits", get(api_tor_circuits))
        // Interactive Amnesic PTY WebSocket
        .route("/api/pty/ws", get(api_pty_ws))
        // Local Container Reverse Proxies
        .route("/ot", any(proxy_ot_root))
        .route("/ot/", any(proxy_ot_root))
        .route("/ot/{*path}", any(proxy_ot_subpath))
        .route("/sandbox", any(proxy_sandbox_root))
        .route("/sandbox/", any(proxy_sandbox_root))
        .route("/sandbox/{*path}", any(proxy_sandbox_subpath))
        .layer(DefaultBodyLimit::max(30 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            strict_security_headers_middleware,
        ))
        .with_state(state)
}

fn is_proxy_embed_path(path: &str) -> bool {
    path == "/ot"
        || path.starts_with("/ot/")
        || path == "/sandbox"
        || path.starts_with("/sandbox/")
}

fn canonicalize_loopback_host(host_str: &str) -> Option<&'static str> {
    match host_str.trim().to_ascii_lowercase().as_str() {
        "127.0.0.1" => Some("127.0.0.1"),
        "localhost" => Some("localhost"),
        "::1" | "[::1]" => Some("::1"),
        _ => None,
    }
}

fn parse_loopback_host_port(raw_host: &str) -> Option<(&'static str, Option<u16>)> {
    let trimmed = raw_host.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }

    let (host_str, port_opt) = if let Some(bracketed) = trimmed.strip_prefix('[') {
        let (inside, rest) = bracketed.split_once(']')?;
        let port = match rest {
            "" => None,
            r => {
                let p_str = r.strip_prefix(':')?;
                let p = p_str.parse::<u16>().ok().filter(|p| *p > 0)?;
                Some(p)
            }
        };
        (inside, port)
    } else if trimmed == "::1" {
        ("::1", None)
    } else if let Some((h, p_str)) = trimmed.rsplit_once(':') {
        if h.contains(':') {
            return None;
        }
        let p = p_str.parse::<u16>().ok().filter(|p| *p > 0)?;
        (h, Some(p))
    } else {
        (trimmed.as_str(), None)
    };

    let canonical_host = canonicalize_loopback_host(host_str)?;
    Some((canonical_host, port_opt))
}

pub fn is_trusted_host_or_absent(headers: &HeaderMap, _bind_port: u16) -> bool {
    let Some(host_val) = headers.get(HOST).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    parse_loopback_host_port(host_val).is_some()
}

pub fn is_same_origin_check(
    headers: &HeaderMap,
    bind_port: u16,
    require_origin_present: bool,
) -> bool {
    let Some(origin_val) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) else {
        return !require_origin_present;
    };
    let Ok(origin_url) = reqwest::Url::parse(origin_val.trim()) else {
        return false;
    };
    if !matches!(origin_url.scheme(), "http" | "https") {
        return false;
    };
    let Some(origin_host) = origin_url.host_str() else {
        return false;
    };
    let Some(origin_canon) = canonicalize_loopback_host(origin_host) else {
        return false;
    };

    if let Some(host_raw) = headers.get(HOST).and_then(|v| v.to_str().ok()) {
        let Some((host_canon, host_port_opt)) = parse_loopback_host_port(host_raw) else {
            return false;
        };
        if origin_canon != host_canon {
            return false;
        }
        let scheme_default = if origin_url.scheme() == "https" {
            443
        } else {
            80
        };
        let expected_port = host_port_opt.unwrap_or(scheme_default);
        return origin_url.port_or_known_default() == Some(expected_port);
    }

    if bind_port > 0 && origin_url.port_or_known_default() != Some(bind_port) {
        return false;
    }
    true
}

async fn strict_security_headers_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let is_embed = is_proxy_embed_path(req.uri().path());
    let csp_val = if is_embed {
        HeaderValue::from_static(PROXY_EMBED_CSP)
    } else {
        HeaderValue::from_static(STRICT_CSP)
    };

    if !is_trusted_host_or_absent(req.headers(), state.config.bind_port) {
        let mut denied = (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Untrusted Host header blocked (DNS rebinding guard)" })),
        )
            .into_response();
        let h = denied.headers_mut();
        h.insert(CONTENT_SECURITY_POLICY, csp_val);
        h.insert(
            "permissions-policy",
            HeaderValue::from_static(PERMISSIONS_POLICY_VAL),
        );
        h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        h.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
        h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(X_FRAME_OPTIONS, HeaderValue::from_static("SAMEORIGIN"));
        return denied;
    }

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(CONTENT_SECURITY_POLICY, csp_val);
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static(PERMISSIONS_POLICY_VAL),
    );
    headers.insert(
        X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("SAMEORIGIN"));
    resp
}

// ============================================================================
// Authentication Helpers
// ============================================================================

fn extract_cookie_sid(headers: &HeaderMap) -> Option<String> {
    for val in headers.get_all(COOKIE) {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            let trimmed = pair.trim();
            if let Some(sid) = trimmed.strip_prefix("onionos_sid=") {
                if !sid.is_empty() {
                    return Some(sid.to_owned());
                }
            }
        }
    }
    None
}

fn extract_csrf_header(headers: &HeaderMap) -> Option<&str> {
    headers.get("x-onionos-token").and_then(|v| v.to_str().ok())
}

async fn require_api_auth(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    if !is_same_origin_check(headers, state.config.bind_port, false) {
        return Err(ApiError::Unauthorized(
            "Cross-origin request blocked by Origin guard".into(),
        ));
    }
    state.enforce_idle_autolock().await;
    let sid = extract_cookie_sid(headers);
    let csrf = extract_csrf_header(headers);
    state
        .vault
        .verify_api_auth(sid.as_deref(), csrf)
        .await
        .map_err(ApiError::from)
}

async fn require_cookie_auth_with_origin(
    state: &AppState,
    headers: &HeaderMap,
    require_origin_present: bool,
) -> Result<(), ApiError> {
    if !is_same_origin_check(headers, state.config.bind_port, require_origin_present) {
        return Err(ApiError::Unauthorized(
            "Cross-origin or missing-Origin WebSocket blocked by CSWSH guard".into(),
        ));
    }
    state.enforce_idle_autolock().await;
    let sid = extract_cookie_sid(headers);
    state
        .vault
        .verify_cookie_auth(sid.as_deref())
        .await
        .map_err(ApiError::from)
}

fn is_ws_upgrade_header(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

// ============================================================================
// Static File Handlers
// ============================================================================

async fn serve_index(State(state): State<Arc<AppState>>) -> Response {
    serve_named_static(&state.config.static_dir, "index.html", "text/html; charset=utf-8").await
}

async fn serve_styles(State(state): State<Arc<AppState>>) -> Response {
    serve_named_static(&state.config.static_dir, "styles.css", "text/css; charset=utf-8").await
}

async fn serve_app_js(State(state): State<Arc<AppState>>) -> Response {
    serve_named_static(
        &state.config.static_dir,
        "app.js",
        "application/javascript; charset=utf-8",
    )
    .await
}

async fn serve_favicon(State(state): State<Arc<AppState>>) -> Response {
    serve_named_static(&state.config.static_dir, "favicon.svg", "image/svg+xml").await
}

async fn serve_static_asset(
    State(state): State<Arc<AppState>>,
    AxumPath(file): AxumPath<String>,
) -> Response {
    serve_subpath_static(&state.config.static_dir.join("assets"), &file).await
}

async fn serve_icons_asset(
    State(state): State<Arc<AppState>>,
    AxumPath(file): AxumPath<String>,
) -> Response {
    serve_subpath_static(&state.config.static_dir.join("icons"), &file).await
}

async fn serve_top_level_static_asset(
    State(state): State<Arc<AppState>>,
    AxumPath(filename): AxumPath<String>,
) -> Response {
    if filename == "ot" || filename == "sandbox" || filename == "api" {
        return ApiError::NotFound("Not found".into()).into_response();
    }
    serve_subpath_static(&state.config.static_dir, &filename).await
}

async fn serve_subpath_static(base_dir: &Path, file: &str) -> Response {
    let rel = Path::new(file);
    if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return ApiError::BadRequest("Invalid static asset path".into()).into_response();
    }
    let mime = match rel.extension().and_then(|e| e.to_str()) {
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("webp") => "image/webp",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("woff2") => "font/woff2",
        Some("json") | Some("webmanifest") => "application/json; charset=utf-8",
        Some("html") => "text/html; charset=utf-8",
        _ => "application/octet-stream",
    };
    serve_named_static(base_dir, file, mime).await
}

async fn serve_named_static(
    base_dir: &Path,
    filename: &str,
    content_type: &'static str,
) -> Response {
    let primary = base_dir.join(filename);
    let fallback = Path::new("/usr/share/onionos/static").join(filename);
    let target = if primary.is_file() {
        primary
    } else if fallback.is_file() {
        fallback
    } else {
        return (
            StatusCode::NOT_FOUND,
            [(CONTENT_TYPE, "application/json; charset=utf-8")],
            r#"{"error":"Static asset not found"}"#,
        )
            .into_response();
    };

    match tokio::fs::read(&target).await {
        Ok(bytes) => (StatusCode::OK, [(CONTENT_TYPE, content_type)], bytes).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            [(CONTENT_TYPE, "application/json; charset=utf-8")],
            r#"{"error":"Failed to read static asset"}"#,
        )
            .into_response(),
    }
}

// ============================================================================
// Health, Auth, System Telemetry, Monitor, Settings & Panic Burn
// ============================================================================

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    os_name: String,
    locked: bool,
    vault_initialized: bool,
    tmpfs_writable: bool,
    tor_socks_reachable: bool,
    browser_state: String,
    relay_state: String,
    uptime_secs: u64,
}

async fn api_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    state.enforce_idle_autolock().await;
    let (locked, vault_initialized, _) = state.vault.telemetry_snapshot().await;
    let tmpfs_writable = forensics::check_dir_writable(&state.config.home_dir);
    let tor_socks_reachable = check_tcp_reachable(&state.config.tor_socks_addr, 200).await;
    let browser_state = state.supervisor.browser_state_label().await;
    let relay_state = state.relay.state_label().await;

    Json(HealthResponse {
        status: "ok",
        version: ONIONOS_VERSION,
        os_name: state.os_pretty_name.clone(),
        locked,
        vault_initialized,
        tmpfs_writable,
        tor_socks_reachable,
        browser_state,
        relay_state,
        uptime_secs: state.started_at.elapsed().as_secs(),
    })
}

async fn api_auth_status(State(state): State<Arc<AppState>>) -> Json<AuthStatusView> {
    state.enforce_idle_autolock().await;
    Json(state.vault.status().await)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlockRequest {
    passphrase: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnlockHttpResponse {
    unlocked: bool,
    vault_initialized: bool,
    csrf_token: String,
    identity_fingerprint: String,
    mlkem_pubkey_hex: String,
    x25519_pubkey_hex: String,
    ed25519_pubkey_hex: String,
}

async fn api_auth_unlock(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnlockRequest>,
) -> Result<Response, ApiError> {
    let out = state.vault.unlock(&req.passphrase).await?;
    files::ensure_gnome_home_skeleton(&state.config.home_dir);

    let cookie_str = format!(
        "onionos_sid={}; HttpOnly; SameSite=Strict; Path=/",
        out.session_id
    );
    let cookie_val = HeaderValue::from_str(&cookie_str)
        .map_err(|_| ApiError::Internal("Invalid session cookie header".into()))?;

    let body = UnlockHttpResponse {
        unlocked: out.unlocked,
        vault_initialized: out.vault_initialized,
        csrf_token: out.csrf_token,
        identity_fingerprint: out.identity_fingerprint,
        mlkem_pubkey_hex: out.mlkem_pubkey_hex,
        x25519_pubkey_hex: out.x25519_pubkey_hex,
        ed25519_pubkey_hex: out.ed25519_pubkey_hex,
    };

    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(SET_COOKIE, cookie_val);
    Ok(resp)
}

async fn api_auth_lock(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_api_auth(&state, &headers).await?;
    state.teardown_ephemeral_services().await;
    state.vault.lock().await;

    let mut resp = Json(serde_json::json!({ "locked": true })).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static("onionos_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    Ok(resp)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TelemetryResponse {
    os_pretty_name: String,
    uid: u32,
    tmpfs_files: usize,
    tmpfs_bytes: u64,
    vault_items: usize,
    active_ptys: usize,
    tor_socks_ok: bool,
    sandbox_ok: bool,
    oniontalk_ok: bool,
    browser_state: String,
    relay_state: String,
    onion_share_active: bool,
    uptime_secs: u64,
}

async fn api_system_telemetry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<TelemetryResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;

    let (_, _, vault_items) = state.vault.telemetry_snapshot().await;
    let (tmpfs_files, tmpfs_bytes) = forensics::count_dir_stats(&state.config.home_dir);
    let audit = forensics::audit_posture(&state.config.home_dir);
    let browser_state = state.supervisor.browser_state_label().await;
    let relay_state = state.relay.state_label().await;
    let onion_share_active = state.onionshare.is_active().await;

    let sandbox_addr = host_port_from_url(&state.config.sandbox_browser_url, "127.0.0.1:6901");
    let oniontalk_addr =
        host_port_from_url(&state.config.oniontalk_internal_url, "127.0.0.1:8420");

    let (tor_socks_ok, sandbox_ok, oniontalk_ok) = tokio::join!(
        check_tcp_reachable(&state.config.tor_socks_addr, 150),
        check_tcp_reachable(&sandbox_addr, 150),
        check_tcp_reachable(&oniontalk_addr, 150),
    );

    Ok(Json(TelemetryResponse {
        os_pretty_name: state.os_pretty_name.clone(),
        uid: audit.uid,
        tmpfs_files,
        tmpfs_bytes,
        vault_items,
        active_ptys: state.pty_registry.active_count(),
        tor_socks_ok,
        sandbox_ok,
        oniontalk_ok,
        browser_state,
        relay_state,
        onion_share_active,
        uptime_secs: state.started_at.elapsed().as_secs(),
    }))
}

async fn api_system_monitor(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SystemMonitorResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;

    let caps = supervisor::read_proc_security_caps();
    let netfilter_active = supervisor::is_netfilter_active();
    let processes = supervisor::list_container_processes();
    let (tmpfs_files, tmpfs_bytes) = forensics::count_dir_stats(&state.config.home_dir);
    let audit = forensics::audit_posture(&state.config.home_dir);
    let browser_state = state.supervisor.browser_state_label().await;
    let relay_state = state.relay.state_label().await;
    let onion_share_active = state.onionshare.is_active().await;

    Ok(Json(SystemMonitorResponse {
        os_pretty_name: state.os_pretty_name.clone(),
        uid: audit.uid,
        cap_eff_hex: caps.cap_eff_hex,
        cap_bnd_hex: caps.cap_bnd_hex,
        no_new_privs: caps.no_new_privs,
        netfilter_active,
        mem_rss_kib: caps.vm_rss_kib,
        tmpfs_bytes,
        tmpfs_files,
        uptime_secs: state.started_at.elapsed().as_secs(),
        browser_state,
        relay_state,
        onion_share_active,
        active_ptys: state.pty_registry.active_count(),
        processes,
    }))
}

async fn api_system_settings_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<DesktopSettings>, ApiError> {
    require_api_auth(&state, &headers).await?;
    Ok(Json(state.vault.get_settings().await?))
}

async fn api_system_settings_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DesktopSettings>,
) -> Result<Json<DesktopSettings>, ApiError> {
    require_api_auth(&state, &headers).await?;
    Ok(Json(state.vault.update_settings(req).await?))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PanicBurnRequest {
    #[serde(default, alias = "burn_vault")]
    burn_vault: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PanicBurnResponse {
    burned_files: usize,
    vault_burned: bool,
    del_onion_ok: bool,
    browser_stopped: bool,
    relay_stopped: bool,
    elapsed_ms: u64,
    tor_newnym_ok: bool,
    locked: bool,
}

async fn api_system_panic_burn(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body_opt: Option<Json<PanicBurnRequest>>,
) -> Result<Response, ApiError> {
    require_api_auth(&state, &headers).await?;
    let burn_vault = body_opt.map(|Json(r)| r.burn_vault).unwrap_or(false);

    let started = Instant::now();
    let _ = state.pty_registry.kill_all().await;
    let (browser_stop, os_stop, relay_stop, newnym) = tokio::join!(
        state.supervisor.stop_browser_fast(Duration::from_millis(350)),
        state.onionshare.stop_with_timeout(Duration::from_millis(120)),
        state.relay.stop_with_timeout(Duration::from_millis(150)),
        osint::send_tor_newnym(
            &state.config.tor_control_addr,
            state.config.tor_control_cookie_file.as_deref(),
            Duration::from_millis(120),
        ),
    );
    let vault_burned = state.vault.panic_lock_and_burn(burn_vault).await;
    let (burned_files, _) = forensics::wipe_home_directory(&state.config.home_dir)?;

    let elapsed_ms = started.elapsed().as_millis() as u64;

    let mut resp = Json(PanicBurnResponse {
        burned_files,
        vault_burned,
        del_onion_ok: os_stop.del_onion_ok && relay_stop.del_onion_ok,
        browser_stopped: browser_stop.stopped,
        relay_stopped: relay_stop.stopped,
        elapsed_ms,
        tor_newnym_ok: newnym.ok,
        locked: true,
    })
    .into_response();

    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static("onionos_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    Ok(resp)
}

// ============================================================================
// Vault Items, PQC Seal/Open, Secret Gen, TOTP 2FA & QR SVG
// ============================================================================

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultListResponse {
    items: Vec<VaultItemView>,
}

async fn api_vault_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<VaultListResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let items = state.vault.list_items().await?;
    Ok(Json(VaultListResponse { items }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateVaultItemRequest {
    title: String,
    #[serde(default)]
    category: String,
    content: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, alias = "totp_secret")]
    totp_secret: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateVaultItemResponse {
    item: VaultItemView,
}

async fn api_vault_add(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateVaultItemRequest>,
) -> Result<Json<CreateVaultItemResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let item = state
        .vault
        .add_item(NewVaultItemInput {
            title: req.title,
            category: req.category,
            content: req.content,
            username: req.username,
            url: req.url,
            totp_secret: req.totp_secret,
        })
        .await?;
    Ok(Json(CreateVaultItemResponse { item }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteVaultItemResponse {
    deleted: bool,
    id: String,
}

async fn api_vault_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<DeleteVaultItemResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    state.vault.delete_item(&id).await?;
    Ok(Json(DeleteVaultItemResponse { deleted: true, id }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PqcSealRequest {
    #[serde(default, alias = "recipient_mlkem_hex")]
    recipient_mlkem_hex: Option<String>,
    #[serde(default, alias = "recipient_x25519_hex")]
    recipient_x25519_hex: Option<String>,
    plaintext: String,
}

async fn api_pqc_seal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PqcSealRequest>,
) -> Result<Json<SealResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let sealed = state
        .vault
        .seal_for_recipient(
            req.recipient_mlkem_hex.as_deref(),
            req.recipient_x25519_hex.as_deref(),
            &req.plaintext,
        )
        .await?;
    Ok(Json(sealed))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PqcOpenRequest {
    envelope: String,
}

async fn api_pqc_open(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PqcOpenRequest>,
) -> Result<Json<OpenResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let opened = state.vault.open_with_session(&req.envelope).await?;
    Ok(Json(opened))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateSecretRequest {
    mode: String,
    #[serde(default)]
    length: Option<usize>,
}

async fn api_pqc_generate_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<GenerateSecretRequest>,
) -> Result<Json<GeneratedSecretResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let gen = totp::generate_secret(&req.mode, req.length)?;
    Ok(Json(gen))
}

async fn api_totp_codes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<TotpCodesResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    Ok(Json(state.vault.compute_totp_codes().await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TotpPreviewRequest {
    secret: String,
}

async fn api_totp_preview(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TotpPreviewRequest>,
) -> Result<Json<TotpPreviewResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    Ok(Json(totp::preview_totp(&req.secret)?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QrSvgRequest {
    text: String,
}

async fn api_qr_svg(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<QrSvgRequest>,
) -> Result<Json<QrSvgResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let svg = qr::render_qr_svg(&req.text).map_err(ApiError::BadRequest)?;
    Ok(Json(QrSvgResponse { svg }))
}

// ============================================================================
// Dual-Root File Manager Endpoints (`ram` + `vault`)
// ============================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileQueryParams {
    #[serde(default = "default_file_root")]
    root: String,
    #[serde(default = "default_file_path")]
    path: String,
}

fn default_file_root() -> String {
    "ram".to_owned()
}

fn default_file_path() -> String {
    "/".to_owned()
}

async fn api_files_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<FileQueryParams>,
) -> Result<Json<FileListResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = state.files.list(&state.vault, &q.root, &q.path).await?;
    Ok(Json(res))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileMkdirRequest {
    root: String,
    path: String,
}

async fn api_files_mkdir(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<FileMkdirRequest>,
) -> Result<Json<FileMkdirResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = state
        .files
        .mkdir(&state.vault, &req.root, &req.path)
        .await?;
    Ok(Json(res))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileWriteRequest {
    root: String,
    path: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default, alias = "data_b64")]
    data_b64: Option<String>,
}

async fn api_files_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<FileWriteRequest>,
) -> Result<Json<FileWriteResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = state
        .files
        .write(
            &state.vault,
            &req.root,
            &req.path,
            req.text.as_deref(),
            req.data_b64.as_deref(),
        )
        .await?;
    Ok(Json(res))
}

async fn api_files_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<FileQueryParams>,
) -> Result<Json<FileReadResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = state.files.read(&state.vault, &q.root, &q.path).await?;
    Ok(Json(res))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileDeleteRequest {
    root: String,
    path: String,
    #[serde(default)]
    shred: Option<bool>,
}

async fn api_files_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<FileDeleteRequest>,
) -> Result<Json<FileDeleteResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = state
        .files
        .delete(&state.vault, &req.root, &req.path, req.shred)
        .await?;
    Ok(Json(res))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileActionRequest {
    root: String,
    path: String,
    action: String,
}

async fn api_files_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<FileActionRequest>,
) -> Result<Json<FileActionResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = state
        .files
        .execute_action(&state.vault, &req.root, &req.path, &req.action)
        .await?;
    Ok(Json(res))
}

// ============================================================================
// Lazy Browser Supervisor & OnionShare Endpoints
// ============================================================================

async fn api_browser_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<BrowserStatusResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    Ok(Json(state.supervisor.browser_status().await))
}

async fn api_browser_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<BrowserStatusResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let status = state
        .supervisor
        .start_browser()
        .await
        .map_err(ApiError::ServiceUnavailable)?;
    Ok(Json(status))
}

async fn api_browser_stop(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<BrowserStopResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    Ok(Json(state.supervisor.stop_browser().await))
}

async fn api_sandbox_reset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SandboxResetResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let (ok, msg) = state.supervisor.reset_browser().await;
    Ok(Json(SandboxResetResponse {
        ok,
        reset: ok,
        status: 200,
        message: msg,
    }))
}

async fn api_onionshare_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<OnionShareStatusResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    Ok(Json(state.onionshare.status().await))
}

async fn api_onionshare_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<OnionShareStartRequest>,
) -> Result<Json<OnionShareStatusResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = state.onionshare.start(req, &state.files).await?;
    Ok(Json(res))
}

async fn api_onionshare_stop(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<OnionShareStopResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = state
        .onionshare
        .stop_with_timeout(Duration::from_millis(1500))
        .await;
    Ok(Json(res))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RelayStartRequest {
    #[serde(default)]
    persistent: bool,
}

async fn api_relay_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RelayStatusResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    Ok(Json(state.relay.status().await))
}

async fn api_relay_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body_opt: Option<Json<RelayStartRequest>>,
) -> Result<Json<RelayStatusResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let persistent = body_opt.map(|Json(r)| r.persistent).unwrap_or(false);
    let status = state.relay.start(persistent, &state.vault).await?;
    Ok(Json(status))
}

async fn api_relay_stop(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RelayStopResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = state
        .relay
        .stop_with_timeout(Duration::from_millis(1500))
        .await;
    Ok(Json(res))
}

async fn api_relay_voucher(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RelayVoucherResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = state.relay.issue_voucher().await?;
    Ok(Json(res))
}

// ============================================================================
// Forensics & OSINT / Tor Endpoints
// ============================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScrubRequest {
    filename: String,
    #[serde(alias = "data_b64")]
    data_b64: String,
}

async fn api_forensics_scrub(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ScrubRequest>,
) -> Result<Json<ScrubReport>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let filename = req.filename;
    let data_b64 = req.data_b64;
    let report = tokio::task::spawn_blocking(move || forensics::scrub_base64(&filename, &data_b64))
        .await
        .map_err(|e| ApiError::Internal(format!("Forensics worker join error: {e}")))??;
    Ok(Json(report))
}

async fn api_forensics_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<forensics::ForensicsAuditReport>, ApiError> {
    require_api_auth(&state, &headers).await?;
    Ok(Json(forensics::audit_posture(&state.config.home_dir)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidateOnionRequest {
    address: String,
}

async fn api_osint_validate_onion(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ValidateOnionRequest>,
) -> Result<Json<OnionValidationResult>, ApiError> {
    require_api_auth(&state, &headers).await?;
    Ok(Json(osint::validate_onion_v3(&req.address)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProbeRequest {
    url: String,
}

async fn api_osint_probe(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ProbeRequest>,
) -> Result<Json<OsintProbeResult>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = osint::probe_via_tor(&req.url, &state.config.tor_socks_addr).await?;
    Ok(Json(res))
}

async fn api_tor_newnym(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<TorNewnymResult>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = osint::send_tor_newnym(
        &state.config.tor_control_addr,
        state.config.tor_control_cookie_file.as_deref(),
        Duration::from_millis(1500),
    )
    .await;
    Ok(Json(res))
}

async fn api_tor_circuits(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<TorCircuitsResponse>, ApiError> {
    require_api_auth(&state, &headers).await?;
    let res = osint::query_tor_circuits(
        &state.config.tor_socks_addr,
        &state.config.tor_control_addr,
        state.config.tor_control_cookie_file.as_deref(),
        Duration::from_millis(1500),
    )
    .await;
    Ok(Json(res))
}

// ============================================================================
// PTY WebSocket & Reverse Proxy Endpoints
// ============================================================================

async fn api_pty_ws(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, ApiError> {
    require_cookie_auth_with_origin(&state, req.headers(), true).await?;
    let (mut parts, _body) = req.into_parts();
    let ws = <WebSocketUpgrade as axum::extract::FromRequestParts<()>>::from_request_parts(
        &mut parts,
        &(),
    )
    .await
    .map_err(|rej| ApiError::BadRequest(rej.to_string()))?;

    let registry = Arc::clone(&state.pty_registry);
    let home_dir = state.config.home_dir.clone();
    let tor_socks = state.config.tor_socks_addr.clone();

    Ok(ws.on_upgrade(move |socket| async move {
        pty_shell::run_pty_websocket(socket, registry, home_dir, tor_socks).await;
    }))
}

async fn proxy_ot_root(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, ApiError> {
    let need_origin = is_ws_upgrade_header(req.headers());
    require_cookie_auth_with_origin(&state, req.headers(), need_origin).await?;
    Ok(proxy::forward_reverse_proxy(
        &state.internal_http_client,
        &state.config.oniontalk_internal_url,
        "",
        Some("/ot"),
        req,
    )
    .await)
}

async fn proxy_ot_subpath(
    State(state): State<Arc<AppState>>,
    AxumPath(path): AxumPath<String>,
    req: Request<Body>,
) -> Result<Response, ApiError> {
    let need_origin = is_ws_upgrade_header(req.headers());
    require_cookie_auth_with_origin(&state, req.headers(), need_origin).await?;
    Ok(proxy::forward_reverse_proxy(
        &state.internal_http_client,
        &state.config.oniontalk_internal_url,
        &path,
        Some("/ot"),
        req,
    )
    .await)
}

async fn proxy_sandbox_root(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, ApiError> {
    let need_origin = is_ws_upgrade_header(req.headers());
    require_cookie_auth_with_origin(&state, req.headers(), need_origin).await?;
    if !is_sandbox_ready(&state).await {
        return Ok(render_lazy_browser_stopped_response());
    }
    Ok(proxy::forward_reverse_proxy(
        &state.internal_http_client,
        &state.config.sandbox_browser_url,
        "",
        None,
        req,
    )
    .await)
}

async fn proxy_sandbox_subpath(
    State(state): State<Arc<AppState>>,
    AxumPath(path): AxumPath<String>,
    req: Request<Body>,
) -> Result<Response, ApiError> {
    let need_origin = is_ws_upgrade_header(req.headers());
    require_cookie_auth_with_origin(&state, req.headers(), need_origin).await?;
    if !is_sandbox_ready(&state).await {
        return Ok(render_lazy_browser_stopped_response());
    }
    Ok(proxy::forward_reverse_proxy(
        &state.internal_http_client,
        &state.config.sandbox_browser_url,
        &path,
        None,
        req,
    )
    .await)
}

async fn is_sandbox_ready(state: &AppState) -> bool {
    if state.supervisor.browser_state_label().await != "stopped" {
        return true;
    }
    let addr = host_port_from_url(&state.config.sandbox_browser_url, "127.0.0.1:6901");
    check_tcp_reachable(&addr, 80).await
}

fn render_lazy_browser_stopped_response() -> Response {
    let html = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Tor Browser Hibernated</title></head>\
        <body style=\"background:#1e1e1e;color:#ffffff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;\">\
        <div style=\"background:#242424;border:1px solid #383838;border-radius:12px;padding:28px 32px;max-width:440px;text-align:center;\">\
        <h3 style=\"margin:0 0 8px;\">Tor Browser Engine Stopped (0 MiB RAM)</h3>\
        <p style=\"color:#9a9996;margin:0;line-height:1.5;\">Click <strong>Start Browser</strong> in the GNOME Tor Browser window header to launch an isolated, amnesic Firefox ESR session over Tor SOCKS5h.</p>\
        </div></body></html>";
    (StatusCode::SERVICE_UNAVAILABLE, Html(html)).into_response()
}

// ============================================================================
// Network & Self-Test Utilities
// ============================================================================

async fn check_tcp_reachable(addr: &str, timeout_ms: u64) -> bool {
    tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .is_ok_and(|r| r.is_ok())
}

fn host_port_from_url(url_str: &str, fallback: &str) -> String {
    let Ok(parsed) = reqwest::Url::parse(url_str) else {
        return fallback.to_owned();
    };
    let Some(host) = parsed.host_str() else {
        return fallback.to_owned();
    };
    let port = parsed.port_or_known_default().unwrap_or(80);
    format!("{host}:{port}")
}

/// Deterministic cryptographic, TOTP, QR, Dual-Root Files & Forensic self-test (`onion-os --self-test`).
pub async fn run_deterministic_self_test() -> Result<serde_json::Value, String> {
    // 1. ML-KEM-768 deterministic roundtrip
    let d = [0x42u8; 32];
    let z = [0x24u8; 32];
    let m = [0x99u8; 32];
    let (ek, dk) = mlkem768::keygen_deterministic(&d, &z);
    let (ss_enc, ct) = mlkem768::encaps_deterministic(&ek, &m).map_err(|e| e.to_owned())?;
    let ss_dec = mlkem768::decaps(&dk, &ct).map_err(|e| e.to_owned())?;
    if ss_enc != ss_dec {
        return Err("ML-KEM-768 shared secret mismatch".into());
    }

    // 2. RFC 6238 TOTP & Offline QR SVG verification
    // RFC 6238 SHA1 test seed "12345678901234567890" = Base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    // At epoch 59s, RFC 6238 8-digit is 94287082 -> 6-digit is 287082.
    let totp_snap = totp::compute_totp_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59)
        .map_err(|e| e.to_string())?;
    if totp_snap.code != "287082" {
        return Err(format!(
            "RFC 6238 TOTP vector mismatch (got {})",
            totp_snap.code
        ));
    }
    let qr_svg = qr::render_qr_svg("http://onionosv2selftest.onion")?;
    if !qr_svg.starts_with("<svg") || !qr_svg.ends_with("</svg>") {
        return Err("QR SVG renderer self-test failed".into());
    }

    // 3. OTPQCV2 vault + Dual-Root Files (ram + vault) roundtrip
    let tmp_dir = env::temp_dir().join(format!("onionos_selftest_{}", uuid::Uuid::new_v4()));
    let vault_sub = tmp_dir.join("vault");
    let home_sub = tmp_dir.join("home");
    fs::create_dir_all(&vault_sub).map_err(|e| e.to_string())?;
    fs::create_dir_all(&home_sub).map_err(|e| e.to_string())?;

    let vm = VaultManager::new_without_backoff(vault_sub);
    let fm = DualRootFileManager::new(home_sub);
    let unlock = vm
        .unlock("self-test-passphrase-2026!")
        .await
        .map_err(|e| e.to_string())?;

    fm.write(
        &vm,
        "vault",
        "/Secrets/brief.txt",
        Some("classified-v2"),
        None,
    )
    .await
    .map_err(|e| e.to_string())?;
    let read_back = fm
        .read(&vm, "vault", "/Secrets/brief.txt")
        .await
        .map_err(|e| e.to_string())?;
    if read_back.text.as_deref() != Some("classified-v2") {
        let _ = fs::remove_dir_all(&tmp_dir);
        return Err("Dual-Root encrypted vault file roundtrip mismatch".into());
    }

    let sealed = vm
        .seal_for_recipient(None, None, "onion-os-pqc-self-test")
        .await
        .map_err(|e| e.to_string())?;
    let opened = vm
        .open_with_session(&sealed.envelope)
        .await
        .map_err(|e| e.to_string())?;
    let _ = vm.panic_lock_and_burn(true).await;
    let _ = fs::remove_dir_all(&tmp_dir);
    if opened.plaintext != "onion-os-pqc-self-test" || !opened.verified {
        return Err("OTSEAL01 hybrid seal/open mismatch".into());
    }

    // 4. JPEG & PNG binary scrub verification
    let sample_jpeg: Vec<u8> = vec![
        0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x0C, b'E', b'x', b'i', b'f', 0, 0, b'G', b'P', b'S', 0,
        0xFF, 0xFE, 0x00, 0x06, b'l', b'e', b'a', b'k', 0xFF, 0xDA, 0x00, 0x04, 0x01, 0x00,
        0xAA, 0x55, 0xFF, 0xD9,
    ];
    let jpeg_clean = forensics::scrub_bytes("test.jpg", &sample_jpeg).map_err(|e| e.to_string())?;
    if jpeg_clean.removed_segments.len() != 2
        || jpeg_clean
            .clean_bytes_vec
            .windows(4)
            .any(|w| w == b"Exif" || w == b"leak")
    {
        return Err("JPEG EXIF/COM scrub self-test failed".into());
    }

    // 5. Tor v3 .onion validation
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
    let onion = osint::encode_onion_v3_from_pubkey(&signing.verifying_key().to_bytes());
    let valid_check = osint::validate_onion_v3(&onion);
    let mut tampered = onion.clone();
    tampered.replace_range(0..1, if onion.starts_with('a') { "b" } else { "a" });
    let invalid_check = osint::validate_onion_v3(&tampered);
    if !valid_check.valid || invalid_check.valid {
        return Err("Tor v3 .onion SHA3-256 validation self-test failed".into());
    }

    Ok(serde_json::json!({
        "selfTest": "ok",
        "version": ONIONOS_VERSION,
        "mlkem768": "verified",
        "otpqcv2Vault": "verified",
        "totpRfc6238": "verified",
        "qrSvgOffline": "verified",
        "dualRootFiles": "verified",
        "identityFingerprint": unlock.identity_fingerprint,
        "forensicsScrub": "verified",
        "onionV3Validator": "verified"
    }))
}

// ============================================================================
// Comprehensive Unit & Integration Test Suite (24 deterministic tests)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use http_body_util::BodyExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    fn make_temp_test_dirs(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = env::temp_dir().join(format!("onionos_v2_test_{tag}_{}", uuid::Uuid::new_v4()));
        let vault_dir = base.join("vault");
        let home_dir = base.join("home_onion");
        let static_dir = base.join("static");
        fs::create_dir_all(&vault_dir).unwrap();
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(&static_dir).unwrap();
        fs::write(
            static_dir.join("index.html"),
            b"<!doctype html><title>OnionOS v2</title>",
        )
        .unwrap();
        (base, vault_dir, home_dir)
    }

    async fn build_unlocked_test_app(
        tag: &str,
        tor_control_override: Option<String>,
    ) -> (PathBuf, Router, String, String) {
        let (base, vault_dir, home_dir) = make_temp_test_dirs(tag);
        let cfg = AppConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: 0,
            static_dir: base.join("static"),
            vault_dir,
            home_dir,
            tor_socks_addr: "127.0.0.1:1".into(),
            tor_control_addr: tor_control_override.unwrap_or_else(|| "127.0.0.1:1".into()),
            tor_control_cookie_file: None,
            oniontalk_internal_url: "http://127.0.0.1:1".into(),
            sandbox_browser_url: "http://127.0.0.1:1".into(),
            sandbox_reset_url: "http://127.0.0.1:1/reset".into(),
        };
        let state = AppState::new_for_tests(cfg).unwrap();
        let app = build_router(state);

        let unlock_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/unlock")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"passphrase":"gnome47-sovereign-pqc-pass"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unlock_res.status(), StatusCode::OK);
        let cookie_pair = unlock_res
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let bytes = unlock_res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let csrf = json["csrfToken"].as_str().unwrap().to_owned();

        (base, app, cookie_pair, csrf)
    }

    #[test]
    fn test_01_mlkem768_roundtrip_and_implicit_rejection() {
        let (ek, dk) = mlkem768::keygen();
        let (ss1, mut ct) = mlkem768::encaps(&ek).unwrap();
        let ss2 = mlkem768::decaps(&dk, &ct).unwrap();
        assert_eq!(ss1, ss2);

        ct[42] ^= 0x01;
        let ss_tampered = mlkem768::decaps(&dk, &ct).unwrap();
        assert_ne!(ss1, ss_tampered);
    }

    #[tokio::test]
    async fn test_02_otpqcv2_vault_v2_fields_totp_never_exposed_in_list() {
        let (base, vault_dir, _) = make_temp_test_dirs("vault_v2");
        let pass = "correct-horse-battery-staple-99";

        let vm = VaultManager::new_without_backoff(vault_dir.clone());
        vm.unlock(pass).await.unwrap();

        let created = vm
            .add_item(NewVaultItemInput {
                title: "Sovereign Forge".into(),
                category: "login".into(),
                content: "super-secret-password".into(),
                username: Some("operator".into()),
                url: Some("https://oniontalk.co".into()),
                totp_secret: Some("otpauth://totp/OnionTalk:operator?secret=JBSWY3DPEHPK3PXP".into()),
            })
            .await
            .unwrap();

        assert!(created.has_totp);
        assert_eq!(created.username.as_deref(), Some("operator"));
        let serialized = serde_json::to_string(&created).unwrap();
        assert!(!serialized.contains("JBSWY3DPEHPK3PXP"));
        assert!(!serialized.contains("totpSecret"));

        let codes = vm.compute_totp_codes().await.unwrap();
        assert_eq!(codes.codes.len(), 1);
        assert_eq!(codes.codes[0].code.len(), 6);
        assert_eq!(codes.codes[0].period_secs, 30);

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_03_otpqcv2_wrong_and_short_passphrase_rejected() {
        let (base, vault_dir, _) = make_temp_test_dirs("vault_wrong");
        let vm = VaultManager::new_without_backoff(vault_dir);
        assert!(matches!(
            vm.unlock("short123").await,
            Err(VaultError::PassphraseTooShort)
        ));
        vm.unlock("sovereign-passphrase-12345").await.unwrap();
        vm.lock().await;
        assert!(matches!(
            vm.unlock("wrong-passphrase-attempt-9999").await,
            Err(VaultError::InvalidPassphrase)
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_04_pqc_hybrid_seal_and_open_roundtrip_and_tamper() {
        let (base, vault_dir, _) = make_temp_test_dirs("pqc_seal");
        let vm = VaultManager::new_without_backoff(vault_dir);
        let u = vm.unlock("post-quantum-seal-pass-2026").await.unwrap();

        let sealed = vm
            .seal_for_recipient(
                Some(&u.mlkem_pubkey_hex),
                Some(&u.x25519_pubkey_hex),
                "Rendezvous v2",
            )
            .await
            .unwrap();
        assert_eq!(sealed.recipient_mlkem_bytes, 1184);

        let opened = vm.open_with_session(&sealed.envelope).await.unwrap();
        assert_eq!(opened.plaintext, "Rendezvous v2");
        assert!(opened.verified);

        let mut lines: Vec<String> = sealed.envelope.lines().map(str::to_owned).collect();
        let idx = lines.len() - 2;
        let mut raw = lines[idx].clone().into_bytes();
        raw[4] = if raw[4] == b'A' { b'B' } else { b'A' };
        lines[idx] = String::from_utf8(raw).unwrap();
        assert!(vm.open_with_session(&lines.join("\n")).await.is_err());

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn test_05_forensics_jpeg_exif_gps_and_com_scrub() {
        let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        jpg.extend_from_slice(b"JFIF\0\x01\x02\x00\x00\x01\x00\x01\x00\x00");
        let exif = b"Exif\0\0GPSLatitude=23.55S";
        jpg.extend_from_slice(&[0xFF, 0xE1]);
        jpg.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
        jpg.extend_from_slice(exif);
        jpg.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x07]);
        jpg.extend_from_slice(b"Alice");
        jpg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x04, 0x01, 0x00, 0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD9]);

        let out = forensics::scrub_bytes("photo.jpg", &jpg).unwrap();
        assert_eq!(out.removed_segments.len(), 2);
        assert!(!out.clean_bytes_vec.windows(4).any(|w| w == b"Exif"));
        assert!(!out.clean_bytes_vec.windows(5).any(|w| w == b"Alice"));
    }

    #[test]
    fn test_06_forensics_png_ancillary_chunks_scrub() {
        let mut png = Vec::from(&b"\x89PNG\r\n\x1a\n"[..]);
        let push = |buf: &mut Vec<u8>, ctype: &[u8; 4], payload: &[u8]| {
            buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            buf.extend_from_slice(ctype);
            buf.extend_from_slice(payload);
            buf.extend_from_slice(&[0, 0, 0, 0]);
        };
        push(&mut png, b"IHDR", &[0; 13]);
        push(&mut png, b"eXIf", b"Serial=999");
        push(&mut png, b"tEXt", b"Author\0Bob");
        push(&mut png, b"IDAT", &[1, 2, 3, 4]);
        push(&mut png, b"IEND", &[]);

        let out = forensics::scrub_bytes("shot.png", &png).unwrap();
        assert_eq!(out.removed_segments.len(), 2);
        assert!(!out.clean_bytes_vec.windows(6).any(|w| w == b"Serial"));
    }

    #[test]
    fn test_07_forensics_pdf_info_and_xmp_redaction_preserves_offsets() {
        let pdf = b"%PDF-1.7\n1 0 obj\n<< /Author (John Doe) /Producer <414243> >>\nendobj\nstream\n<x:xmpmeta>SecretXMP</x:xmpmeta>\nendstream\nxref\n%%EOF\n";
        let out = forensics::scrub_bytes("doc.pdf", pdf).unwrap();
        assert_eq!(out.clean_bytes_vec.len(), pdf.len());
        let s = String::from_utf8_lossy(&out.clean_bytes_vec);
        assert!(!s.contains("John Doe"));
        assert!(!s.contains("SecretXMP"));
    }

    #[test]
    fn test_08_forensics_wav_and_mp3_scrub() {
        let mut wav = Vec::from(&b"RIFF\x00\x00\x00\x00WAVE"[..]);
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&[1, 0, 1, 0, 0x44, 0xAC, 0, 0, 0x88, 0x58, 1, 0, 2, 0, 16, 0]);
        wav.extend_from_slice(b"LIST");
        wav.extend_from_slice(&8u32.to_le_bytes());
        wav.extend_from_slice(b"INFOTest");
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&4u32.to_le_bytes());
        wav.extend_from_slice(&[1, 2, 3, 4]);
        let rlen = (wav.len() - 8) as u32;
        wav[4..8].copy_from_slice(&rlen.to_le_bytes());

        let wout = forensics::scrub_bytes("a.wav", &wav).unwrap();
        assert_eq!(wout.removed_segments.len(), 1);

        let mut mp3 = Vec::from(&b"ID3\x03\x00\x00\x00\x00\x00\x06Artist"[..]);
        mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x64]);
        let mout = forensics::scrub_bytes("a.mp3", &mp3).unwrap();
        assert_eq!(mout.clean_bytes_vec, [0xFF, 0xFB, 0x90, 0x64]);
    }

    #[test]
    fn test_09_totp_rfc6238_test_vectors_and_otpauth_uri() {
        // RFC 6238 Appendix B: ASCII "12345678901234567890" = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        // Epoch 59 -> 94287082 (8-digit) -> 287082 (6-digit)
        // Epoch 1111111109 -> 07081804 (8-digit) -> 081804 (6-digit)
        let s1 = totp::compute_totp_at("gezd-gnbv gy3t qojq gezd gnbv gy3t qojq", 59).unwrap();
        assert_eq!(s1.code, "287082");
        assert_eq!(s1.remaining_secs, 1);

        let uri = "otpauth://totp/OnionOS:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=OnionOS";
        let s2 = totp::compute_totp_at(uri, 1_111_111_109).unwrap();
        assert_eq!(s2.code, "081804");

        assert!(totp::compute_totp_at("INVALID!@#", 100).is_err());
    }

    #[test]
    fn test_10_secret_generator_passphrase_and_password_entropy() {
        let pp = totp::generate_secret("passphrase", Some(6)).unwrap();
        assert_eq!(pp.mode, "passphrase");
        assert!(pp.entropy_bits >= 50);
        assert_eq!(pp.secret.split('-').count(), 7);

        let pw = totp::generate_secret("password", Some(28)).unwrap();
        assert_eq!(pw.mode, "password");
        assert_eq!(pw.secret.len(), 28);
        assert!(pw.entropy_bits >= 150);

        assert!(totp::generate_secret("unknown", None).is_err());
    }

    #[test]
    fn test_11_qr_svg_offline_generation_and_bounds() {
        let svg = qr::render_qr_svg("http://exampleonionaddress.onion").unwrap();
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
        assert!(!svg.contains("exampleonionaddress.onion"));

        assert!(qr::render_qr_svg("   ").is_err());
        let huge = "x".repeat(2100);
        assert!(qr::render_qr_svg(&huge).is_err());
    }

    #[tokio::test]
    async fn test_12_files_dual_root_ram_and_encrypted_vault_crud() {
        let (base, vault_dir, home_dir) = make_temp_test_dirs("files_dual");
        let vm = VaultManager::new_without_backoff(vault_dir.clone());
        vm.unlock("dual-root-files-passphrase").await.unwrap();
        let fm = DualRootFileManager::new(home_dir.clone());

        // Default skeleton exists in RAM
        let ram_root = fm.list(&vm, "ram", "/").await.unwrap();
        assert!(ram_root.entries.iter().any(|e| e.name == "Documents"));
        assert!(ram_root.entries.iter().any(|e| e.name == "Welcome-OnionOS.md"));

        // Write + read in encrypted Vault root
        fm.mkdir(&vm, "vault", "/Operations/2026").await.unwrap();
        fm.write(
            &vm,
            "vault",
            "/Operations/2026/plan.md",
            Some("Operation Nightfall"),
            None,
        )
        .await
        .unwrap();

        // Raw file on disk must NOT contain plaintext!
        let raw_blob = fs::read(vault_dir.join(vault::VAULT_FILES_BLOB_NAME)).unwrap();
        assert_eq!(&raw_blob[0..8], vault::VAULT_PQC_MAGIC);
        assert!(!raw_blob
            .windows(b"Nightfall".len())
            .any(|w| w == b"Nightfall"));

        let read_res = fm
            .read(&vm, "vault", "/Operations/2026/plan.md")
            .await
            .unwrap();
        assert!(read_res.is_utf8);
        assert_eq!(read_res.text.as_deref(), Some("Operation Nightfall"));

        let del_res = fm
            .delete(&vm, "vault", "/Operations/2026/plan.md", Some(true))
            .await
            .unwrap();
        assert!(del_res.deleted);

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_13_files_path_traversal_and_nul_blocked() {
        let (base, vault_dir, home_dir) = make_temp_test_dirs("files_trav");
        let vm = VaultManager::new_without_backoff(vault_dir);
        vm.unlock("traversal-guard-passphrase").await.unwrap();
        let fm = DualRootFileManager::new(home_dir);

        assert!(fm.read(&vm, "ram", "/../../etc/passwd").await.is_err());
        assert!(fm.write(&vm, "ram", "/Documents/..\\evil.txt", Some("x"), None).await.is_err());
        assert!(fm.mkdir(&vm, "vault", "/bad\0name").await.is_err());
        assert!(fm.delete(&vm, "ram", "/", Some(true)).await.is_err());

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_14_files_actions_scrub_and_seal_generate_sibling_artifacts() {
        let (base, vault_dir, home_dir) = make_temp_test_dirs("files_act");
        let vm = VaultManager::new_without_backoff(vault_dir);
        vm.unlock("actions-scrub-seal-pass").await.unwrap();
        let fm = DualRootFileManager::new(home_dir);

        let raw_jpg = vec![
            0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x07, b'G', b'P', b'S', b'1', b'2', 0xFF, 0xDA, 0x00,
            0x04, 0x01, 0x00, 0x99, 0xFF, 0xD9,
        ];
        fm.write(
            &vm,
            "ram",
            "/Pictures/cam.jpg",
            None,
            Some(&B64.encode(&raw_jpg)),
        )
        .await
        .unwrap();

        let scrub_act = fm
            .execute_action(&vm, "ram", "/Pictures/cam.jpg", "scrub")
            .await
            .unwrap();
        assert_eq!(scrub_act.output_path, "/Pictures/cam.clean.jpg");

        fm.write(&vm, "vault", "/Secrets/key.txt", Some("top-secret-seed"), None)
            .await
            .unwrap();
        let seal_act = fm
            .execute_action(&vm, "vault", "/Secrets/key.txt", "seal")
            .await
            .unwrap();
        assert_eq!(seal_act.output_path, "/Secrets/key.txt.otseal");
        let sealed_file = fm
            .read(&vm, "vault", "/Secrets/key.txt.otseal")
            .await
            .unwrap();
        let opened = vm
            .open_with_session(sealed_file.text.as_deref().unwrap())
            .await
            .unwrap();
        assert_eq!(opened.plaintext, "top-secret-seed");

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn test_15_osint_tor_v3_and_circuit_parser() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x55u8; 32]);
        let onion = osint::encode_onion_v3_from_pubkey(&signing.verifying_key().to_bytes());
        let res = osint::validate_onion_v3(&onion);
        assert!(res.valid);
        assert_eq!(res.normalized_address, onion);

        assert_eq!(
            osint::parse_bootstrap_progress(
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done"
            ),
            Some(100)
        );
        let lines = vec![
            "21 BUILT $AAAA~GuardOne,$BBBB~MiddleTwo,$CCCC~ExitThree BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL".to_owned(),
            "22 EXTENDED $DDDD~GuardAlpha PURPOSE=HS_CLIENT_REND".to_owned(),
        ];
        let parsed = osint::parse_circuit_status_lines(&lines);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].hops, vec!["GuardOne", "MiddleTwo", "ExitThree"]);
        assert_eq!(parsed[1].purpose, "HS_CLIENT_REND");
    }

    #[test]
    fn test_16_osint_ssrf_guard_blocks_private_and_loopback() {
        assert!(osint::validate_probe_url("http://127.0.0.1:8430/api/health").is_err());
        assert!(osint::validate_probe_url("http://192.168.1.1/").is_err());
        assert!(osint::validate_probe_url("http://localhost:9050").is_err());
        assert!(osint::validate_probe_url("https://check.torproject.org/").is_ok());
    }

    #[tokio::test]
    async fn test_17_desktop_settings_persistence_and_validation() {
        let (base, app, cookie, csrf) = build_unlocked_test_app("settings", None).await;

        let get_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/system/settings")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);

        let update_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/system/settings")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"wallpaper":"onion-obsidian","autoLockMinutes":5,"dockCompact":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update_res.status(), StatusCode::OK);

        // Invalid wallpaper rejected with 400
        let bad_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/system/settings")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"wallpaper":"evil-external","autoLockMinutes":5,"dockCompact":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_res.status(), StatusCode::BAD_REQUEST);

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_18_lazy_browser_idle_stopped_and_friendly_503_sandbox_gate() {
        let (base, app, cookie, csrf) = build_unlocked_test_app("lazy_browser", None).await;

        let st_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/browser/status")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(st_res.status(), StatusCode::OK);
        let bytes = st_res.into_body().collect().await.unwrap().to_bytes();
        let j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(j["state"], "stopped");
        assert_eq!(j["memoryKib"], 0);

        // Accessing /sandbox/ while stopped returns 503 friendly HTML page
        let sb_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/sandbox/vnc.html")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sb_res.status(), StatusCode::SERVICE_UNAVAILABLE);

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_19_system_monitor_and_forensics_audit_endpoints() {
        let (base, app, cookie, csrf) = build_unlocked_test_app("sysmon", None).await;

        let mon_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/system/monitor")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mon_res.status(), StatusCode::OK);
        let mon_bytes = mon_res.into_body().collect().await.unwrap().to_bytes();
        let mon_json: serde_json::Value = serde_json::from_slice(&mon_bytes).unwrap();
        assert!(mon_json["processes"].is_array());
        assert_eq!(mon_json["browserState"], "stopped");

        let aud_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/forensics/audit")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(aud_res.status(), StatusCode::OK);
        let aud_bytes = aud_res.into_body().collect().await.unwrap().to_bytes();
        let aud_json: serde_json::Value = serde_json::from_slice(&aud_bytes).unwrap();
        assert!(aud_json.get("capBndZero").is_some());
        assert!(aud_json.get("noNewPrivs").is_some());

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_20_http_totp_preview_qr_svg_and_secret_gen_routes() {
        let (base, app, cookie, csrf) = build_unlocked_test_app("totp_qr", None).await;

        let prev_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/totp/preview")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"secret":"JBSWY3DPEHPK3PXP"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(prev_res.status(), StatusCode::OK);

        let qr_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/qr/svg")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"text":"onionos://share/v2"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(qr_res.status(), StatusCode::OK);

        let gen_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/pqc/generate-secret")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"mode":"passphrase","length":5}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(gen_res.status(), StatusCode::OK);

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_21_onionshare_add_onion_and_del_onion_with_mock_tor_controlport() {
        // Spawn a mock Tor ControlPort supporting AUTHENTICATE, ADD_ONION, DEL_ONION, GETINFO
        let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_listener.local_addr().unwrap().to_string();
        let del_received = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let del_clone = Arc::clone(&del_received);

        tokio::spawn(async move {
            while let Ok((stream, _)) = mock_listener.accept().await {
                let del_ref = Arc::clone(&del_clone);
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut reader = BufReader::new(r);
                    let mut line = String::new();
                    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                        let cmd = line.trim();
                        if cmd.starts_with("AUTHENTICATE") {
                            let _ = w.write_all(b"250 OK\r\n").await;
                        } else if cmd.starts_with("ADD_ONION") {
                            let fake_id = "a".repeat(56);
                            let reply = format!(
                                "250-ServiceID={fake_id}\r\n250-PrivateKey=ED25519-V3:secret\r\n250 OK\r\n"
                            );
                            let _ = w.write_all(reply.as_bytes()).await;
                        } else if let Some(sid) = cmd.strip_prefix("DEL_ONION ") {
                            del_ref.lock().await.push(sid.trim().to_owned());
                            let _ = w.write_all(b"250 OK\r\n").await;
                        } else if cmd == "GETINFO status/bootstrap-phase" {
                            let _ = w
                                .write_all(b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n")
                                .await;
                        } else if cmd == "GETINFO circuit-status" {
                            let _ = w
                                .write_all(b"250+circuit-status=\r\n7 BUILT $1111~EntryRelay,$2222~MiddleRelay,$3333~ExitRelay PURPOSE=GENERAL\r\n.\r\n250 OK\r\n")
                                .await;
                        } else if cmd == "QUIT" {
                            let _ = w.write_all(b"250 closing connection\r\n").await;
                            break;
                        }
                        line.clear();
                    }
                });
            }
        });

        let (base, app, cookie, csrf) =
            build_unlocked_test_app("onionshare_mock", Some(mock_addr)).await;

        // Verify GET /api/tor/circuits against mock ControlPort
        let circ_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/tor/circuits")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(circ_res.status(), StatusCode::OK);
        let circ_bytes = circ_res.into_body().collect().await.unwrap().to_bytes();
        let circ_json: serde_json::Value = serde_json::from_slice(&circ_bytes).unwrap();
        assert_eq!(circ_json["controlOk"], true);
        assert_eq!(circ_json["bootstrapPct"], 100);
        assert_eq!(circ_json["circuits"][0]["hops"][0], "EntryRelay");

        // Start OnionShare with note & accessCode
        let start_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/onionshare/start")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"mode":"share","note":"Dead-drop coordinates","accessCode":"amber-99"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start_res.status(), StatusCode::OK);
        let start_bytes = start_res.into_body().collect().await.unwrap().to_bytes();
        let start_json: serde_json::Value = serde_json::from_slice(&start_bytes).unwrap();
        assert_eq!(start_json["active"], true);
        assert!(start_json["onionAddress"]
            .as_str()
            .unwrap()
            .ends_with(".onion"));

        // Stop OnionShare -> must issue DEL_ONION to mock ControlPort
        let stop_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/onionshare/stop")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stop_res.status(), StatusCode::OK);
        assert_eq!(del_received.lock().await.len(), 1);

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_22_http_files_api_roundtrip_and_panic_burn_v2_fields() {
        let (base, app, cookie, csrf) = build_unlocked_test_app("files_http_burn", None).await;

        let write_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/files/write")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"root":"ram","path":"/Documents/memo.txt","text":"ephemeral memo"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(write_res.status(), StatusCode::OK);

        let burn_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/system/panic-burn")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"burnVault":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(burn_res.status(), StatusCode::OK);
        let burn_bytes = burn_res.into_body().collect().await.unwrap().to_bytes();
        let burn_json: serde_json::Value = serde_json::from_slice(&burn_bytes).unwrap();
        assert_eq!(burn_json["locked"], true);
        assert_eq!(burn_json["browserStopped"], true);
        assert!(burn_json["burnedFiles"].as_u64().unwrap() >= 1);

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_23_health_reports_version_and_browser_state() {
        let (base, app, _, _) = build_unlocked_test_app("health_check", None).await;
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let b = res.into_body().collect().await.unwrap().to_bytes();
        let j: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(j["version"], "1.0.0");
        assert_eq!(j["browserState"], "stopped");
        assert_eq!(j["relayState"], "stopped");
        assert_eq!(j["locked"], false);

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_24_deterministic_self_test_passes() {
        let report = run_deterministic_self_test().await.unwrap();
        assert_eq!(report["selfTest"], "ok");
        assert_eq!(report["version"], "1.0.0");
        assert_eq!(report["totpRfc6238"], "verified");
        assert_eq!(report["qrSvgOffline"], "verified");
        assert_eq!(report["dualRootFiles"], "verified");
    }

    #[tokio::test]
    async fn test_25_security_regressions_and_idle_autolock() {
        let (base, vault_dir, home_dir) = make_temp_test_dirs("sec_gate");

        // 1. Unsigned PQC envelope must report verified == false
        let bundle = vault::keygen_hybrid_bundle();
        let ek = hex::decode(&bundle.mlkem_pubkey_hex).unwrap();
        let dk = hex::decode(&bundle.mlkem_secret_hex).unwrap();
        let x_pk: [u8; 32] = hex::decode(&bundle.x25519_pubkey_hex).unwrap().try_into().unwrap();
        let x_sk: [u8; 32] = hex::decode(&bundle.x25519_secret_hex).unwrap().try_into().unwrap();
        let unsigned_seal = vault::seal_pqc_envelope(&ek, &x_pk, None, "anon-payload").unwrap();
        let unsigned_open = vault::open_pqc_envelope(&dk, &x_sk, &unsigned_seal.envelope).unwrap();
        assert!(!unsigned_open.verified);
        assert!(unsigned_open.sender_fingerprint.is_none());

        // 2. IPv4-mapped IPv6 & 0.0.0.0/8 SSRF blocked
        assert!(osint::validate_probe_url("http://[::ffff:127.0.0.1]:8430/").is_err());
        assert!(osint::validate_probe_url("http://[::ffff:10.0.0.1]/").is_err());
        assert!(osint::validate_probe_url("http://0.1.2.3/").is_err());

        // 3. Netfilter marker validation
        let nf_flag = base.join("netfilter.active");
        assert!(!supervisor::is_netfilter_flag_file_valid(&nf_flag));
        fs::write(&nf_flag, b"inactive").unwrap();
        assert!(!supervisor::is_netfilter_flag_file_valid(&nf_flag));
        fs::write(&nf_flag, b"active uid-owner=10016\n").unwrap();
        assert!(supervisor::is_netfilter_flag_file_valid(&nf_flag));

        // 4. browser-agent token authentication & .Xauthority generation
        let xauth_file = base.join(".Xauthority");
        supervisor::write_xauthority_cookie(&xauth_file, b"99").unwrap();
        let xauth_bytes = fs::read(&xauth_file).unwrap();
        assert!(xauth_bytes.len() >= 92);
        assert_eq!(&xauth_bytes[0..2], &[0x01, 0x00]); // FamilyLocal
        assert!(xauth_bytes.windows(2).any(|w| w == [0xFF, 0xFF])); // FamilyWild
        assert!(xauth_bytes.windows(18).any(|w| w == b"MIT-MAGIC-COOKIE-1"));

        let tok_file = base.join("browser.token");
        fs::write(&tok_file, b"secret-agent-token-10015\n").unwrap();
        let agent_sup = supervisor::ProcessSupervisor::new_local_agent(
            base.join("sandbox_home"),
            "127.0.0.1:9050",
            "http://127.0.0.1:6901",
        );
        let agent_app = supervisor::build_browser_agent_router(agent_sup, tok_file);

        let unauth_agent = agent_app
            .clone()
            .oneshot(Request::builder().uri("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(unauth_agent.status(), StatusCode::UNAUTHORIZED);

        let auth_agent = agent_app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .header("X-Browser-Agent-Token", "secret-agent-token-10015")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(auth_agent.status(), StatusCode::OK);

        // 5. Host guard, CSP split, Origin CSWSH & Idle Auto-Lock
        let cfg = AppConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: 8430,
            static_dir: base.join("static"),
            vault_dir,
            home_dir,
            tor_socks_addr: "127.0.0.1:1".into(),
            tor_control_addr: "127.0.0.1:1".into(),
            tor_control_cookie_file: None,
            oniontalk_internal_url: "http://127.0.0.1:1".into(),
            sandbox_browser_url: "http://127.0.0.1:1".into(),
            sandbox_reset_url: "http://127.0.0.1:1/reset".into(),
        };
        let state = AppState::new_for_tests(cfg).unwrap();
        let app = build_router(Arc::clone(&state));

        // Untrusted Host -> 403 Forbidden
        let rebind_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .header(HOST, "evil.rebind.attacker:8430")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rebind_res.status(), StatusCode::FORBIDDEN);

        // Trusted Host -> STRICT_CSP with connect-src 'self' and frame-ancestors 'self'
        let root_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(HOST, "127.0.0.1:8430")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(root_res.status(), StatusCode::OK);
        let root_csp = root_res
            .headers()
            .get(CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(root_csp, STRICT_CSP);
        assert!(root_csp.contains("connect-src 'self';"));
        assert!(root_csp.contains("frame-ancestors 'self'"));

        // Unlock session
        let unlock_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/unlock")
                    .header(HOST, "127.0.0.1:8430")
                    .header(ORIGIN, "http://127.0.0.1:8430")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"passphrase":"security-gate-autolock-pass"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unlock_res.status(), StatusCode::OK);
        let cookie = unlock_res
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let ub = unlock_res.into_body().collect().await.unwrap().to_bytes();
        let uj: serde_json::Value = serde_json::from_slice(&ub).unwrap();
        let csrf = uj["csrfToken"].as_str().unwrap().to_owned();

        // /sandbox/ gets PROXY_EMBED_CSP (allowing ws: wss: for websockify)
        let sb_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/sandbox/vnc.html")
                    .header(HOST, "127.0.0.1:8430")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            sb_res.headers().get(CONTENT_SECURITY_POLICY).unwrap(),
            PROXY_EMBED_CSP
        );

        // /api/pty/ws WITHOUT Origin header must be rejected (401)
        let ws_no_origin = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/pty/ws")
                    .header(HOST, "127.0.0.1:8430")
                    .header(COOKIE, &cookie)
                    .header("Connection", "Upgrade")
                    .header("Upgrade", "websocket")
                    .header("Sec-WebSocket-Version", "13")
                    .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ws_no_origin.status(), StatusCode::UNAUTHORIZED);

        // Set autoLockMinutes = 1, backdate last_activity by 65s -> next request locks & zeroizes!
        let _ = state
            .vault
            .update_settings(DesktopSettings {
                wallpaper: "adwaita-blue".into(),
                auto_lock_minutes: 1,
                dock_compact: false,
            })
            .await
            .unwrap();
        state
            .vault
            .backdate_last_activity_for_test(Duration::from_secs(65))
            .await;

        let expired_call = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/vault/items")
                    .header(HOST, "127.0.0.1:8430")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_call.status(), StatusCode::UNAUTHORIZED);
        assert!(state.vault.status().await.locked);

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn test_26_relay_keyblob_validation_and_injection_blocked() {
        let valid_blob = format!("{}====", "A".repeat(84));
        assert!(relay::validate_ed25519_v3_keyblob(&valid_blob).is_ok());

        // Too short / too long
        assert!(relay::validate_ed25519_v3_keyblob("ABCD").is_err());
        assert!(relay::validate_ed25519_v3_keyblob(&"B".repeat(140)).is_err());

        // CRLF / space / Tor ControlPort injection attempt
        let crlf_inj = format!("{}\r\nSIGNAL SHUTDOWN", "A".repeat(84));
        assert!(relay::validate_ed25519_v3_keyblob(&crlf_inj).is_err());
        let space_inj = format!("{} SETCONF", "A".repeat(80));
        assert!(relay::validate_ed25519_v3_keyblob(&space_inj).is_err());
    }

    #[tokio::test]
    async fn test_27_vault_relay_otpqcv2_persistence_and_panic_burn_wipe() {
        let (base, vault_dir, _) = make_temp_test_dirs("relay_vault_v21");
        let vm = VaultManager::new_without_backoff(vault_dir.clone());

        // Must fail while locked
        assert!(matches!(
            vm.load_relay_identity().await,
            Err(VaultError::Locked)
        ));

        vm.unlock("relay-persistence-passphrase-2026").await.unwrap();
        assert!(vm.load_relay_identity().await.unwrap().is_none());

        let fake_keyblob = format!("{}====", "k".repeat(84));
        let fake_onion = format!("{}.onion", "r".repeat(56));
        let saved_id = vault::PersistedRelayIdentity {
            tor_ed25519_v3_keyblob: fake_keyblob.clone(),
            onion_address: fake_onion.clone(),
            relay_node_key_b64: Some(B64.encode([0x5Au8; 32])),
            created_at: "2026-11-22T20:30:00Z".into(),
        };
        vm.save_relay_identity(&saved_id).await.unwrap();

        let blob_path = vault_dir.join(vault::VAULT_RELAY_BLOB_NAME);
        let raw_cipher = fs::read(&blob_path).unwrap();
        assert_eq!(&raw_cipher[0..8], vault::VAULT_PQC_MAGIC);
        assert!(!raw_cipher
            .windows(fake_keyblob.len())
            .any(|w| w == fake_keyblob.as_bytes()));

        // Lock & reopen: relay identity decrypted intact
        vm.lock().await;
        vm.unlock("relay-persistence-passphrase-2026").await.unwrap();
        let loaded = vm.load_relay_identity().await.unwrap().unwrap();
        assert_eq!(loaded.tor_ed25519_v3_keyblob, fake_keyblob);
        assert_eq!(loaded.onion_address, fake_onion);
        assert_eq!(loaded.relay_node_key_b64, Some(B64.encode([0x5Au8; 32])));

        // panic_lock_and_burn(true) must shred & unlink relay.otpqcv2
        assert!(vm.panic_lock_and_burn(true).await);
        assert!(!blob_path.exists());

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_28_relay_manager_lifecycle_mock_controlport_health_and_voucher() {
        let (base, vault_dir, home_dir) = make_temp_test_dirs("relay_mgr_v21");
        let vm = VaultManager::new_without_backoff(vault_dir.clone());
        vm.unlock("relay-e2e-mock-passphrase-21").await.unwrap();

        // 1. Mock Tor ControlPort capturing ADD_ONION & DEL_ONION
        let tor_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tor_addr = tor_listener.local_addr().unwrap().to_string();
        let add_cmds = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let del_cmds = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let add_ref = Arc::clone(&add_cmds);
        let del_ref = Arc::clone(&del_cmds);

        tokio::spawn(async move {
            while let Ok((stream, _)) = tor_listener.accept().await {
                let add_c = Arc::clone(&add_ref);
                let del_c = Arc::clone(&del_ref);
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut reader = BufReader::new(r);
                    let mut line = String::new();
                    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                        let cmd = line.trim().to_owned();
                        if cmd.starts_with("AUTHENTICATE") {
                            let _ = w.write_all(b"250 OK\r\n").await;
                        } else if cmd.starts_with("ADD_ONION ") {
                            add_c.lock().await.push(cmd.clone());
                            let sid = "m".repeat(56);
                            let kb = format!("{}====", "Q".repeat(84));
                            let reply = if cmd.contains("NEW:ED25519-V3") {
                                format!(
                                    "250-ServiceID={sid}\r\n250-PrivateKey=ED25519-V3:{kb}\r\n250 OK\r\n"
                                )
                            } else {
                                format!("250-ServiceID={sid}\r\n250 OK\r\n")
                            };
                            let _ = w.write_all(reply.as_bytes()).await;
                        } else if let Some(sid) = cmd.strip_prefix("DEL_ONION ") {
                            del_c.lock().await.push(sid.trim().to_owned());
                            let _ = w.write_all(b"250 OK\r\n").await;
                        } else if cmd == "QUIT" {
                            let _ = w.write_all(b"250 closing\r\n").await;
                            break;
                        }
                        line.clear();
                    }
                });
            }
        });

        // 2. Mock Relay HTTP Server (`:0`) serving `/health` and `/api/v1/node/claim-token`
        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap().to_string();
        let seen_admin_header = Arc::new(tokio::sync::Mutex::new(Option::<String>::None));
        let admin_hdr_clone = Arc::clone(&seen_admin_header);

        let mock_relay_app = Router::new()
            .route(
                "/health",
                get(|| async {
                    Json(serde_json::json!({
                        "status": "ok",
                        "node_pubkey": "ed25519_mock_pubkey_v181",
                        "peers_count": 7,
                        "online_nodes": 5,
                        "hibernating_nodes": 2,
                        "avg_peer_rtt_ms": 142.5,
                        "invalid_peers_blocked": 3,
                        "spoofed_acks_blocked": 1,
                        "engine": "oniontalk-relay-rs/1.8.2",
                        "routing_engine": "kademlia-onion-v3",
                        "zero_trust_mode": "strict-ed25519-pow"
                    }))
                }),
            )
            .route(
                "/api/v1/node/claim-token",
                get(move |headers: HeaderMap| {
                    let h_ref = Arc::clone(&admin_hdr_clone);
                    async move {
                        let Some(tok) = headers
                            .get("x-admin-token")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned)
                        else {
                            return (
                                StatusCode::UNAUTHORIZED,
                                Json(serde_json::json!({"error": "missing token"})),
                            )
                                .into_response();
                        };
                        *h_ref.lock().await = Some(tok);
                        Json(serde_json::json!({
                            "voucher": "OT-CLAIM-V1-SOVEREIGN-7788",
                            "node_pubkey": "ed25519_mock_pubkey_v181"
                        }))
                        .into_response()
                    }
                }),
            );

        tokio::spawn(async move {
            let _ = axum::serve(relay_listener, mock_relay_app).await;
        });

        // 3. Cross-platform dummy long-lived binary (`cmd.exe` on Windows, `/bin/sh` on Unix)
        #[cfg(windows)]
        let (dummy_bin, dummy_args) = (
            PathBuf::from(env::var("COMSPEC").unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into())),
            vec!["/C".to_owned(), "ping -n 30 127.0.0.1 >NUL".to_owned()],
        );
        #[cfg(unix)]
        let (dummy_bin, dummy_args) = (
            PathBuf::from("/bin/sh"),
            vec!["-c".to_owned(), "sleep 30".to_owned()],
        );

        let relay_mgr = RelayNodeManager::new_with_overrides(
            home_dir.clone(),
            "127.0.0.1:9050".into(),
            tor_addr,
            None,
            dummy_bin,
            dummy_args,
            Some(base.join("relay_runtime")),
            relay_addr,
        )
        .unwrap();

        // First persistent start -> issues ADD_ONION NEW:ED25519-V3 & saves /vault/relay.otpqcv2
        let st1 = relay_mgr.start(true, &vm).await.unwrap();
        assert_eq!(st1.state, "running");
        assert!(st1.persistent);
        assert_eq!(st1.peers_count, 7);
        assert_eq!(st1.online_nodes, 5);
        assert_eq!(st1.node_pubkey.as_deref(), Some("ed25519_mock_pubkey_v181"));
        assert!(vault_dir.join(vault::VAULT_RELAY_BLOB_NAME).is_file());

        // Issue sovereign claim voucher -> sends 64-hex CSPRNG X-Admin-Token
        let v_res = relay_mgr.issue_voucher().await.unwrap();
        assert!(v_res.ok);
        assert_eq!(v_res.voucher, "OT-CLAIM-V1-SOVEREIGN-7788");
        assert_eq!(seen_admin_header.lock().await.as_ref().unwrap().len(), 64);

        // Stop -> issues DEL_ONION & wipes runtime dir
        let stop_res = relay_mgr
            .stop_with_timeout(Duration::from_millis(800))
            .await;
        assert!(stop_res.stopped);
        assert!(stop_res.del_onion_ok);
        assert_eq!(del_cmds.lock().await.len(), 1);
        assert!(!base.join("relay_runtime").exists());

        // Second persistent start -> restores key from /vault/relay.otpqcv2 using ADD_ONION ED25519-V3:<keyblob>
        let st2 = relay_mgr.start(true, &vm).await.unwrap();
        assert_eq!(st2.state, "running");
        {
            let recorded = add_cmds.lock().await;
            assert_eq!(recorded.len(), 2);
            assert!(recorded[0].contains("ADD_ONION NEW:ED25519-V3"));
            assert!(recorded[1].contains("ADD_ONION ED25519-V3:"));
        }
        let _ = relay_mgr
            .stop_with_timeout(Duration::from_millis(800))
            .await;

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_29_permissions_policy_microphone_self_and_relay_http_routes() {
        let (base, app, cookie, csrf) = build_unlocked_test_app("headers_relay", None).await;

        let root_res = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(root_res.status(), StatusCode::OK);
        let pp = root_res
            .headers()
            .get("permissions-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(pp, PERMISSIONS_POLICY_VAL);
        assert!(pp.contains("microphone=(self)"));

        let r_status = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/relay/status")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r_status.status(), StatusCode::OK);
        let rb = r_status.into_body().collect().await.unwrap().to_bytes();
        let rj: serde_json::Value = serde_json::from_slice(&rb).unwrap();
        assert_eq!(rj["state"], "stopped");

        // Voucher when relay is stopped -> 400 Bad Request
        let v_err = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/relay/voucher")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(v_err.status(), StatusCode::BAD_REQUEST);

        let _ = fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn test_30_security_hardening_loopback_bind_and_idle_autolock_teardown() {
        // 1. Strict loopback SocketAddrV4 bind validator blocks non-loopback, port 0, and CRLF injection
        assert_eq!(
            relay::validate_loopback_bind_addr("127.0.0.1:8088").unwrap(),
            "127.0.0.1:8088"
        );
        assert!(relay::validate_loopback_bind_addr("0.0.0.0:8088").is_err());
        assert!(relay::validate_loopback_bind_addr("198.51.100.10:8088").is_err());
        assert!(relay::validate_loopback_bind_addr("127.0.0.1:0").is_err());
        assert!(relay::validate_loopback_bind_addr("127.0.0.1:8088\r\nSIGNAL SHUTDOWN").is_err());

        // 2. Idle auto-lock tears down active Relay (DEL_ONION + process stop)
        let base = env::temp_dir().join(format!("onionos_test30_{}", uuid::Uuid::new_v4()));
        let home_dir = base.join("home");
        let vault_dir = base.join("vault");
        let static_dir = base.join("static");
        fs::create_dir_all(&home_dir).unwrap();
        fs::create_dir_all(&vault_dir).unwrap();
        fs::create_dir_all(&static_dir).unwrap();

        let tor_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tor_addr = tor_listener.local_addr().unwrap().to_string();
        let del_seen = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let del_clone = Arc::clone(&del_seen);
        let valid_kb = base64::engine::general_purpose::STANDARD.encode([0x44u8; 64]);
        let valid_sid = "b".repeat(56);

        tokio::spawn(async move {
            while let Ok((stream, _)) = tor_listener.accept().await {
                let d_ref = Arc::clone(&del_clone);
                let kb = valid_kb.clone();
                let sid = valid_sid.clone();
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut reader = tokio::io::BufReader::new(r);
                    let mut line = String::new();
                    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                        let t = line.trim().to_owned();
                        if t.starts_with("AUTHENTICATE") {
                            let _ = w.write_all(b"250 OK\r\n").await;
                        } else if t.starts_with("ADD_ONION ") {
                            let reply = format!(
                                "250-ServiceID={sid}\r\n250-PrivateKey=ED25519-V3:{kb}\r\n250 OK\r\n"
                            );
                            let _ = w.write_all(reply.as_bytes()).await;
                        } else if let Some(rest) = t.strip_prefix("DEL_ONION ") {
                            d_ref.lock().await.push(rest.trim().to_owned());
                            let _ = w.write_all(b"250 OK\r\n").await;
                        } else if t == "QUIT" {
                            let _ = w.write_all(b"250 closing\r\n").await;
                            break;
                        }
                        line.clear();
                    }
                });
            }
        });

        let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap().to_string();
        let mock_relay = Router::new().route(
            "/health",
            get(|| async { Json(serde_json::json!({ "status": "ok", "peers_count": 3 })) }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(relay_listener, mock_relay).await;
        });

        #[cfg(windows)]
        let (dummy_bin, dummy_args) = (
            PathBuf::from(
                env::var("COMSPEC").unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into()),
            ),
            vec!["/C".to_owned(), "ping -n 30 127.0.0.1 >NUL".to_owned()],
        );
        #[cfg(unix)]
        let (dummy_bin, dummy_args) = (
            PathBuf::from("/bin/sh"),
            vec!["-c".to_owned(), "sleep 30".to_owned()],
        );

        let cfg = AppConfig {
            bind_addr: "127.0.0.1:0".into(),
            bind_port: 0,
            home_dir: home_dir.clone(),
            vault_dir: vault_dir.clone(),
            static_dir,
            oniontalk_internal_url: "http://127.0.0.1:1".into(),
            sandbox_browser_url: "http://127.0.0.1:1".into(),
            sandbox_reset_url: String::new(),
            tor_socks_addr: "127.0.0.1:9050".into(),
            tor_control_addr: tor_addr.clone(),
            tor_control_cookie_file: None,
        };
        let mut state = Arc::try_unwrap(AppState::new_for_tests(cfg).unwrap())
            .ok()
            .expect("unique Arc");
        state.relay = RelayNodeManager::new_with_overrides(
            home_dir,
            "127.0.0.1:9050".into(),
            tor_addr,
            None,
            dummy_bin,
            dummy_args,
            Some(base.join("relay_rt")),
            relay_addr,
        )
        .unwrap();
        let state = Arc::new(state);
        let app = build_router(Arc::clone(&state));

        let unlock = state
            .vault
            .unlock("sovereign-idle-autolock-passphrase-2026")
            .await
            .unwrap();
        let cookie = format!("onionos_sid={}", unlock.session_id);
        let csrf = unlock.csrf_token;

        let started = state.relay.start(false, &state.vault).await.unwrap();
        assert_eq!(started.state, "running");
        assert_eq!(state.relay.state_label().await, "running");

        // Backdate session beyond default 15-minute auto_lock_minutes -> next API/health touch reaps & stops relay
        state
            .vault
            .backdate_last_activity_for_test(Duration::from_secs(16 * 60))
            .await;

        let locked_resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/relay/status")
                    .header(COOKIE, &cookie)
                    .header("X-OnionOS-Token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(locked_resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.relay.state_label().await, "stopped");
        assert_eq!(del_seen.lock().await.len(), 1);

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn test_31_tor_browser_hardened_prefs_and_openbox_rc() {
        let prefs = supervisor::FIREFOX_HARDENED_USER_JS;
        assert!(prefs.contains("user_pref(\"network.proxy.socks\", \"127.0.0.1\");"));
        assert!(prefs.contains("user_pref(\"network.proxy.socks_port\", 9050);"));
        assert!(prefs.contains("user_pref(\"network.proxy.socks_remote_dns\", true);"));
        assert!(prefs.contains("user_pref(\"gfx.webrender.software\", true);"));
        assert!(prefs.contains("user_pref(\"layers.acceleration.disabled\", true);"));
        assert!(prefs.contains("user_pref(\"dom.ipc.processCount\", 2);"));
        assert!(prefs.contains("user_pref(\"browser.tabs.closeWindowWithLastTab\", false);"));
        assert!(prefs.contains("user_pref(\"browser.sessionstore.resume_from_crash\", false);"));

        let rc = supervisor::OPENBOX_MAXIMIZED_RC_XML;
        assert!(rc.contains("<decor>no</decor>"));
        assert!(rc.contains("<maximized>yes</maximized>"));
    }

    #[test]
    fn test_32_onion_mesh_wallpapers_media_csp_and_docker_port_mapping() {
        assert!(STRICT_CSP.contains("media-src 'self' blob: data:;"));
        assert!(PROXY_EMBED_CSP.contains("media-src 'self' blob: data:;"));

        assert_eq!(vault::normalize_wallpaper_id("onion-mesh"), Some("onion-mesh"));
        assert_eq!(vault::normalize_wallpaper_id("adwaita-blue"), Some("onion-mesh"));
        assert_eq!(vault::normalize_wallpaper_id("cobalt-vault"), Some("cobalt-vault"));
        assert_eq!(vault::normalize_wallpaper_id("pqc-shield"), Some("pqc-shield"));
        assert_eq!(vault::normalize_wallpaper_id("tor-night"), Some("tor-night"));
        assert_eq!(vault::normalize_wallpaper_id("brushed-slate"), Some("brushed-slate"));
        assert_eq!(vault::normalize_wallpaper_id("stealth-oled"), Some("stealth-oled"));
        assert_eq!(vault::normalize_wallpaper_id("unknown-theme"), None);

        let mut ok_headers = HeaderMap::new();
        ok_headers.insert(HOST, HeaderValue::from_static("127.0.0.1:8888"));
        ok_headers.insert(ORIGIN, HeaderValue::from_static("http://127.0.0.1:8888"));
        assert!(is_trusted_host_or_absent(&ok_headers, 8430));
        assert!(is_same_origin_check(&ok_headers, 8430, true));

        let mut default_port_headers = HeaderMap::new();
        default_port_headers.insert(HOST, HeaderValue::from_static("127.0.0.1"));
        default_port_headers.insert(ORIGIN, HeaderValue::from_static("http://127.0.0.1"));
        assert!(is_trusted_host_or_absent(&default_port_headers, 8430));
        assert!(is_same_origin_check(&default_port_headers, 8430, true));

        let mut cross_port = HeaderMap::new();
        cross_port.insert(HOST, HeaderValue::from_static("127.0.0.1:8888"));
        cross_port.insert(ORIGIN, HeaderValue::from_static("http://127.0.0.1:3000"));
        assert!(!is_same_origin_check(&cross_port, 8430, true));

        let mut cross_host = HeaderMap::new();
        cross_host.insert(HOST, HeaderValue::from_static("127.0.0.1:8430"));
        cross_host.insert(ORIGIN, HeaderValue::from_static("http://localhost:8430"));
        assert!(!is_same_origin_check(&cross_host, 8430, true));

        let mut rebind = HeaderMap::new();
        rebind.insert(HOST, HeaderValue::from_static("evil.attacker.com:8430"));
        assert!(!is_trusted_host_or_absent(&rebind, 8430));
    }
}
