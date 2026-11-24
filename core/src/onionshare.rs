//! Ephemeral Tor v3 OnionShare Controller (`ADD_ONION` / `DEL_ONION` on ControlPort `:9051`)
//! Supports `"share"` (file/note distribution with constant-time access code & auto-stop)
//! and `"drop"` (anonymous dead-drop upload into `/home/onion/OnionShare/Dropzone` with 16 MiB/64 MiB quotas).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Multipart, Path as AxumPath, Query, Request, State};
use axum::http::header::{
    CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY,
    X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::files::{guess_mime, DualRootFileManager, FilesError};
use crate::vault::constant_time_eq;

pub const MAX_DROP_UPLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DROPZONE_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_DROPZONE_FILES: usize = 50;

#[derive(Debug, thiserror::Error)]
pub enum OnionShareError {
    #[error("Invalid mode '{0}' (expected 'share' or 'drop')")]
    InvalidMode(String),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("File error: {0}")]
    Files(#[from] FilesError),
    #[error("Tor ControlPort ADD_ONION failed: {0}")]
    TorControl(String),
    #[error("Local OnionShare listener error: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceivedDropFile {
    pub name: String,
    pub size_bytes: u64,
    pub received_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnionShareStatusResponse {
    pub active: bool,
    pub mode: Option<String>,
    pub onion_address: Option<String>,
    pub onion_url: Option<String>,
    pub access_code_enabled: bool,
    pub auto_stop_first_download: bool,
    pub downloads_count: u64,
    pub received_files: Vec<ReceivedDropFile>,
    pub started_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnionShareStopResponse {
    pub stopped: bool,
    pub del_onion_ok: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnionShareStartRequest {
    pub mode: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub access_code: Option<String>,
    #[serde(default)]
    pub auto_stop_first_download: bool,
}

#[derive(Clone)]
struct SharedAsset {
    name: String,
    mime: String,
    bytes: Arc<Vec<u8>>,
}

struct EphemeralSiteState {
    mode: String,
    note: Option<String>,
    access_code: Option<Zeroizing<String>>,
    auto_stop_first_download: bool,
    shared_files: Vec<SharedAsset>,
    dropzone_dir: PathBuf,
    downloads_count: Arc<AtomicU64>,
    received_files: Arc<Mutex<Vec<ReceivedDropFile>>>,
    auto_stop_tx: Mutex<Option<oneshot::Sender<()>>>,
}

struct ActiveOnionShareInstance {
    service_id: String,
    mode: String,
    onion_address: String,
    onion_url: String,
    access_code_enabled: bool,
    auto_stop_first_download: bool,
    downloads_count: Arc<AtomicU64>,
    received_files: Arc<Mutex<Vec<ReceivedDropFile>>>,
    started_at: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

pub struct OnionShareController {
    home_dir: PathBuf,
    tor_control_addr: String,
    tor_cookie_file: Option<PathBuf>,
    active: Arc<Mutex<Option<ActiveOnionShareInstance>>>,
}

impl OnionShareController {
    pub fn new(
        home_dir: PathBuf,
        tor_control_addr: String,
        tor_cookie_file: Option<PathBuf>,
    ) -> Arc<Self> {
        Arc::new(Self {
            home_dir,
            tor_control_addr,
            tor_cookie_file,
            active: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn is_active(&self) -> bool {
        self.active.lock().await.is_some()
    }

    pub async fn status(&self) -> OnionShareStatusResponse {
        let guard = self.active.lock().await;
        let Some(inst) = &*guard else {
            return OnionShareStatusResponse {
                active: false,
                mode: None,
                onion_address: None,
                onion_url: None,
                access_code_enabled: false,
                auto_stop_first_download: false,
                downloads_count: 0,
                received_files: Vec::new(),
                started_at: None,
            };
        };

        let received = inst.received_files.lock().await.clone();
        OnionShareStatusResponse {
            active: true,
            mode: Some(inst.mode.clone()),
            onion_address: Some(inst.onion_address.clone()),
            onion_url: Some(inst.onion_url.clone()),
            access_code_enabled: inst.access_code_enabled,
            auto_stop_first_download: inst.auto_stop_first_download,
            downloads_count: inst.downloads_count.load(Ordering::Relaxed),
            received_files: received,
            started_at: Some(inst.started_at.clone()),
        }
    }

    pub async fn start(
        self: &Arc<Self>,
        req: OnionShareStartRequest,
        file_mgr: &DualRootFileManager,
    ) -> Result<OnionShareStatusResponse, OnionShareError> {
        let mode = req.mode.trim().to_ascii_lowercase();
        if mode != "share" && mode != "drop" {
            return Err(OnionShareError::InvalidMode(req.mode));
        }

        // Tear down any previous active service first
        let _ = self.stop_with_timeout(Duration::from_millis(800)).await;

        let clean_note = req
            .note
            .map(|n| n.trim().to_owned())
            .filter(|n| !n.is_empty());
        if clean_note.as_ref().is_some_and(|n| n.len() > 8192) {
            return Err(OnionShareError::Validation(
                "Note exceeds 8 KiB limit".into(),
            ));
        }

        let clean_code = req
            .access_code
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty())
            .map(Zeroizing::new);

        let mut shared_files = Vec::new();
        if mode == "share" {
            for raw_p in &req.paths {
                let (name, bytes) = file_mgr.read_ram_file_for_share(raw_p)?;
                let mime = guess_mime(&name).to_owned();
                shared_files.push(SharedAsset {
                    name,
                    mime,
                    bytes: Arc::new(bytes),
                });
            }
            if shared_files.is_empty() {
                if let Some(note_txt) = &clean_note {
                    shared_files.push(SharedAsset {
                        name: "note.txt".to_owned(),
                        mime: "text/plain; charset=utf-8".to_owned(),
                        bytes: Arc::new(note_txt.as_bytes().to_vec()),
                    });
                } else {
                    return Err(OnionShareError::Validation(
                        "Share mode requires at least one file path or note".into(),
                    ));
                }
            }
        }

        let dropzone_dir = self.home_dir.join("OnionShare").join("Dropzone");
        if mode == "drop" {
            fs::create_dir_all(&dropzone_dir)
                .map_err(|e| OnionShareError::Io(e.to_string()))?;
        }

        // Bind local ephemeral listener (prefer 127.0.0.1:8445, fallback to OS ephemeral port)
        let listener = match TcpListener::bind("127.0.0.1:8445").await {
            Ok(l) => l,
            Err(_) => TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| OnionShareError::Io(e.to_string()))?,
        };
        let local_port = listener
            .local_addr()
            .map_err(|e| OnionShareError::Io(e.to_string()))?
            .port();

        let service_id = tor_add_onion_v3(
            &self.tor_control_addr,
            self.tor_cookie_file.as_deref(),
            local_port,
            Duration::from_secs(4),
        )
        .await?;

        let onion_address = format!("{service_id}.onion");
        let onion_url = format!("http://{onion_address}");
        let started_at = Utc::now().to_rfc3339();
        let access_code_enabled = clean_code.is_some();

        let downloads_count = Arc::new(AtomicU64::new(0));
        let received_files = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (auto_tx, auto_rx) = oneshot::channel::<()>();

        let site_state = Arc::new(EphemeralSiteState {
            mode: mode.clone(),
            note: clean_note,
            access_code: clean_code,
            auto_stop_first_download: req.auto_stop_first_download,
            shared_files,
            dropzone_dir,
            downloads_count: Arc::clone(&downloads_count),
            received_files: Arc::clone(&received_files),
            auto_stop_tx: Mutex::new(Some(auto_tx)),
        });

        let site_router = Router::new()
            .route("/", get(ephemeral_index_handler))
            .route("/download/{idx}", get(ephemeral_download_handler))
            .route("/upload", post(ephemeral_upload_handler))
            .layer(DefaultBodyLimit::max(MAX_DROP_UPLOAD_BYTES + 65_536))
            .layer(middleware::from_fn(onionshare_security_headers_middleware))
            .with_state(site_state);

        tokio::spawn(async move {
            let _ = axum::serve(listener, site_router)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        if req.auto_stop_first_download {
            let ctl = Arc::clone(self);
            tokio::spawn(async move {
                if auto_rx.await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    let _ = ctl.stop_with_timeout(Duration::from_millis(1000)).await;
                }
            });
        }

        {
            let mut guard = self.active.lock().await;
            *guard = Some(ActiveOnionShareInstance {
                service_id,
                mode,
                onion_address,
                onion_url,
                access_code_enabled,
                auto_stop_first_download: req.auto_stop_first_download,
                downloads_count,
                received_files,
                started_at,
                shutdown_tx: Some(shutdown_tx),
            });
        }

        Ok(self.status().await)
    }

    pub async fn stop_with_timeout(&self, timeout: Duration) -> OnionShareStopResponse {
        let taken = {
            let mut guard = self.active.lock().await;
            guard.take()
        };

        let Some(mut inst) = taken else {
            return OnionShareStopResponse {
                stopped: true,
                del_onion_ok: true,
            };
        };

        if let Some(tx) = inst.shutdown_tx.take() {
            let _ = tx.send(());
        }

        let del_ok = tor_del_onion_v3(
            &self.tor_control_addr,
            self.tor_cookie_file.as_deref(),
            &inst.service_id,
            timeout,
        )
        .await;

        OnionShareStopResponse {
            stopped: true,
            del_onion_ok: del_ok,
        }
    }
}

// ============================================================================
// Ephemeral OnionShare HTTP Handlers (Zero External Assets, Safe for Tor Browser Safest Mode)
// ============================================================================

const ONIONSHARE_SITE_CSP: &str =
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'";

async fn onionshare_security_headers_middleware(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(ONIONSHARE_SITE_CSP),
    );
    headers.insert(
        X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    resp
}

fn check_site_access_code(
    expected: Option<&Zeroizing<String>>,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
) -> bool {
    let Some(secret) = expected else {
        return true;
    };
    if let Some(q_code) = query.get("code") {
        if constant_time_eq(q_code.trim().as_bytes(), secret.as_bytes()) {
            return true;
        }
    }
    if let Some(h_code) = headers.get("x-access-code").and_then(|v| v.to_str().ok()) {
        if constant_time_eq(h_code.trim().as_bytes(), secret.as_bytes()) {
            return true;
        }
    }
    false
}

async fn ephemeral_index_handler(
    State(state): State<Arc<EphemeralSiteState>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if !check_site_access_code(state.access_code.as_ref(), &query, &headers) {
        if query.contains_key("code") || headers.contains_key("x-access-code") {
            tokio::time::sleep(Duration::from_millis(350)).await;
        }
        return Html(render_access_code_gate_html()).into_response();
    }

    let code_suffix = query
        .get("code")
        .map(|c| format!("?code={}", html_escape(c)))
        .unwrap_or_default();

    let note_block = state
        .note
        .as_deref()
        .map(|n| {
            format!(
                "<div style=\"background:#242424;padding:12px 16px;border-radius:10px;margin-bottom:16px;border:1px solid #383838;\"><strong>Operator Note:</strong><pre style=\"white-space:pre-wrap;margin:8px 0 0;font-family:monospace;\">{}</pre></div>",
                html_escape(n)
            )
        })
        .unwrap_or_default();

    if state.mode == "share" {
        let mut items_html = String::new();
        for (idx, f) in state.shared_files.iter().enumerate() {
            items_html.push_str(&format!(
                "<li style=\"display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:#2a2a2a;border-radius:8px;margin-bottom:8px;\"><span>{} <small style=\"color:#9a9996;\">({} B)</small></span><a href=\"/download/{idx}{code_suffix}\" style=\"background:#3584e4;color:#fff;text-decoration:none;padding:6px 14px;border-radius:6px;font-weight:600;\">Download</a></li>",
                html_escape(&f.name),
                f.bytes.len()
            ));
        }

        Html(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>OnionShare v2 — Sovereign Share</title></head>\
             <body style=\"background:#1e1e1e;color:#ffffff;font-family:sans-serif;max-width:680px;margin:40px auto;padding:0 20px;\">\
             <h2 style=\"margin-bottom:6px;\">OnionOS Ephemeral Share (.onion v3)</h2>\
             <p style=\"color:#9a9996;margin-top:0;\">End-to-end Tor v3 circuit • Zero clearnet metadata</p>\
             {note_block}<ul style=\"list-style:none;padding:0;\">{items_html}</ul></body></html>"
        ))
        .into_response()
    } else {
        Html(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>OnionShare v2 — Anonymous Dead-Drop</title></head>\
             <body style=\"background:#1e1e1e;color:#ffffff;font-family:sans-serif;max-width:680px;margin:40px auto;padding:0 20px;\">\
             <h2 style=\"margin-bottom:6px;\">OnionOS Anonymous Dead-Drop</h2>\
             <p style=\"color:#9a9996;margin-top:0;\">Submit files directly into isolated volatile RAM (max 16 MiB).</p>\
             {note_block}\
             <form method=\"post\" action=\"/upload{code_suffix}\" enctype=\"multipart/form-data\" style=\"background:#242424;padding:20px;border-radius:12px;border:1px solid #383838;\">\
             <label style=\"display:block;margin-bottom:12px;\">Select file:<br><input type=\"file\" name=\"file\" required style=\"margin-top:6px;\"></label>\
             <button type=\"submit\" style=\"background:#2ec27e;color:#111;border:none;padding:10px 18px;border-radius:8px;font-weight:700;cursor:pointer;\">Send Securely Over Tor</button>\
             </form></body></html>"
        ))
        .into_response()
    }
}

async fn ephemeral_download_handler(
    State(state): State<Arc<EphemeralSiteState>>,
    AxumPath(idx): AxumPath<usize>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if !check_site_access_code(state.access_code.as_ref(), &query, &headers) {
        tokio::time::sleep(Duration::from_millis(350)).await;
        return (StatusCode::FORBIDDEN, "Access code required").into_response();
    }
    if state.mode != "share" {
        return (StatusCode::NOT_FOUND, "Not in share mode").into_response();
    }
    let Some(asset) = state.shared_files.get(idx) else {
        return (StatusCode::NOT_FOUND, "File not found").into_response();
    };

    state.downloads_count.fetch_add(1, Ordering::Relaxed);
    if state.auto_stop_first_download {
        if let Some(tx) = state.auto_stop_tx.lock().await.take() {
            let _ = tx.send(());
        }
    }

    let cd = format!(
        "attachment; filename=\"{}\"",
        sanitize_drop_filename(&asset.name)
    );
    let mut resp = (StatusCode::OK, asset.bytes.as_ref().clone()).into_response();
    if let Ok(ct) = HeaderValue::from_str(&asset.mime) {
        resp.headers_mut().insert(CONTENT_TYPE, ct);
    }
    if let Ok(cd_val) = HeaderValue::from_str(&cd) {
        resp.headers_mut().insert(CONTENT_DISPOSITION, cd_val);
    }
    resp
}

async fn ephemeral_upload_handler(
    State(state): State<Arc<EphemeralSiteState>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if !check_site_access_code(state.access_code.as_ref(), &query, &headers) {
        tokio::time::sleep(Duration::from_millis(350)).await;
        return (StatusCode::FORBIDDEN, "Invalid access code").into_response();
    }
    if state.mode != "drop" {
        return (StatusCode::METHOD_NOT_ALLOWED, "Dropzone disabled").into_response();
    }

    let (mut running_files, mut running_bytes) =
        crate::forensics::count_dir_stats(&state.dropzone_dir);
    if running_files >= MAX_DROPZONE_FILES || running_bytes >= MAX_DROPZONE_TOTAL_BYTES {
        return (
            StatusCode::INSUFFICIENT_STORAGE,
            "Dropzone volatile RAM quota reached (64 MiB / 50 files)",
        )
            .into_response();
    }

    let mut saved_count = 0usize;
    while let Ok(Some(field)) = multipart.next_field().await {
        if running_files >= MAX_DROPZONE_FILES {
            return (
                StatusCode::INSUFFICIENT_STORAGE,
                "Dropzone file count quota reached (50 files)",
            )
                .into_response();
        }
        let raw_name = field.file_name().unwrap_or("drop.bin").to_owned();
        let clean_name = sanitize_drop_filename(&raw_name);
        let Ok(data) = field.bytes().await else {
            return (StatusCode::BAD_REQUEST, "Upload stream error or exceeded 16 MiB")
                .into_response();
        };
        if data.is_empty() {
            continue;
        }
        if data.len() > MAX_DROP_UPLOAD_BYTES
            || running_bytes.saturating_add(data.len() as u64) > MAX_DROPZONE_TOTAL_BYTES
        {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload exceeds OnionShare Dropzone RAM quota",
            )
                .into_response();
        }

        let _ = fs::create_dir_all(&state.dropzone_dir);
        let final_name = unique_drop_filename(&state.dropzone_dir, &clean_name);
        let dest = state.dropzone_dir.join(&final_name);
        if fs::write(&dest, &data).is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed writing drop file").into_response();
        }

        running_files = running_files.saturating_add(1);
        running_bytes = running_bytes.saturating_add(data.len() as u64);

        state.received_files.lock().await.push(ReceivedDropFile {
            name: final_name,
            size_bytes: data.len() as u64,
            received_at: Utc::now().to_rfc3339(),
        });
        saved_count += 1;
    }

    if saved_count == 0 {
        return (StatusCode::BAD_REQUEST, "No non-empty file provided").into_response();
    }

    Html(
        "<!doctype html><html><body style=\"background:#1e1e1e;color:#2ec27e;font-family:sans-serif;max-width:600px;margin:50px auto;padding:20px;\">\
         <h2>Upload Received in Volatile RAM</h2><p style=\"color:#fff;\">Your submission was delivered anonymously over Tor v3.</p></body></html>",
    )
    .into_response()
}

fn render_access_code_gate_html() -> String {
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>OnionShare Protected</title></head>\
     <body style=\"background:#1e1e1e;color:#fff;font-family:sans-serif;max-width:440px;margin:60px auto;padding:20px;\">\
     <h3>Access Code Required</h3>\
     <form method=\"get\" action=\"/\">\
     <input type=\"password\" name=\"code\" placeholder=\"Enter OnionShare access code\" required style=\"width:100%;padding:10px;border-radius:8px;border:1px solid #444;background:#111;color:#fff;margin-bottom:12px;\">\
     <button type=\"submit\" style=\"background:#3584e4;color:#fff;border:none;padding:10px 16px;border-radius:8px;font-weight:600;\">Unlock</button>\
     </form></body></html>"
        .to_owned()
}

fn sanitize_drop_filename(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("drop.bin");
    let mut out = String::with_capacity(base.len().min(96));
    for ch in base.chars() {
        if out.len() >= 96 {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('.').to_owned();
    if trimmed.is_empty() {
        "drop.bin".to_owned()
    } else {
        trimmed
    }
}

fn unique_drop_filename(dir: &Path, clean: &str) -> String {
    if !dir.join(clean).exists() {
        return clean.to_owned();
    }
    let short = &Uuid::new_v4().to_string()[..8];
    match clean.rfind('.') {
        Some(idx) if idx > 0 => format!("{}-{short}.{}", &clean[..idx], &clean[idx + 1..]),
        _ => format!("{clean}-{short}"),
    }
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

// ============================================================================
// Tor ControlPort ADD_ONION / DEL_ONION Wire Protocol
// ============================================================================

fn load_control_cookie_hex(cookie_file: Option<&Path>) -> Option<String> {
    if let Some(p) = cookie_file {
        if let Ok(bytes) = fs::read(p) {
            if !bytes.is_empty() {
                return Some(hex::encode(bytes));
            }
        }
    }
    for default_cookie in ["/run/tor/control.authcookie", "/var/lib/tor/control_auth_cookie"] {
        if let Ok(bytes) = fs::read(default_cookie) {
            if !bytes.is_empty() {
                return Some(hex::encode(bytes));
            }
        }
    }
    None
}

async fn tor_add_onion_v3(
    control_addr: &str,
    cookie_file: Option<&Path>,
    local_port: u16,
    timeout: Duration,
) -> Result<String, OnionShareError> {
    let cookie_hex = load_control_cookie_hex(cookie_file);

    let fut = async {
        let stream = TcpStream::connect(control_addr)
            .await
            .map_err(|e| OnionShareError::TorControl(format!("connect {control_addr}: {e}")))?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let auth_cmd = match &cookie_hex {
            Some(h) => format!("AUTHENTICATE {h}\r\n"),
            None => "AUTHENTICATE \"\"\r\n".to_owned(),
        };
        write_half
            .write_all(auth_cmd.as_bytes())
            .await
            .map_err(|e| OnionShareError::TorControl(e.to_string()))?;

        let mut auth_line = String::new();
        reader
            .read_line(&mut auth_line)
            .await
            .map_err(|e| OnionShareError::TorControl(e.to_string()))?;
        if !auth_line.starts_with("250") {
            return Err(OnionShareError::TorControl(format!(
                "AUTHENTICATE rejected: {}",
                auth_line.trim()
            )));
        }

        let cmd = format!(
            "ADD_ONION NEW:ED25519-V3 Flags=Detach Port=80,127.0.0.1:{local_port}\r\n"
        );
        write_half
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| OnionShareError::TorControl(e.to_string()))?;

        let mut service_id: Option<String> = None;
        loop {
            let mut line = String::new();
            let n = reader
                .read_line(&mut line)
                .await
                .map_err(|e| OnionShareError::TorControl(e.to_string()))?;
            if n == 0 {
                break;
            }
            let trimmed = line.trim();
            if let Some(rest) = trimmed
                .strip_prefix("250-ServiceID=")
                .or_else(|| trimmed.strip_prefix("250 ServiceID="))
            {
                service_id = Some(rest.trim().to_ascii_lowercase());
            }
            // Zeroize any transient PrivateKey line returned by Tor before dropping buffer
            if trimmed.contains("PrivateKey=") {
                line.zeroize();
                continue;
            }
            if trimmed.starts_with("250 ") {
                break;
            }
            if !trimmed.starts_with("250") {
                return Err(OnionShareError::TorControl(format!(
                    "ADD_ONION rejected: {trimmed}"
                )));
            }
        }

        let _ = write_half.write_all(b"QUIT\r\n").await;
        service_id.ok_or_else(|| {
            OnionShareError::TorControl("Missing ServiceID in ADD_ONION reply".into())
        })
    };

    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| OnionShareError::TorControl(format!("Timeout talking to {control_addr}")))?
}

async fn tor_del_onion_v3(
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
