//! Post-Quantum Amnesic Vault (`OTPQCV2\0`), TOTP Keyring, GNOME Settings & Hybrid `.otseal` Engine
//! KDF: Argon2id (m = 19456 KiB, t = 2, p = 1)
//! KEM: NIST FIPS 203 ML-KEM-768 + X25519 ECDH + Ed25519 Identity Signature
//! Dual AEAD: ChaCha20-Poly1305 (inner) + AES-256-GCM (outer)

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use tokio::sync::Mutex;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::mlkem768::{
    self, MLKEM768_CT_BYTES, MLKEM768_DK_BYTES, MLKEM768_EK_BYTES,
};
use crate::totp::{
    self, TotpCodesResponse, VaultTotpCodeEntry,
};

pub const VAULT_PQC_MAGIC: &[u8; 8] = b"OTPQCV2\0";
pub const VAULT_FORMAT_VERSION: u16 = 2;
pub const VAULT_FILENAME: &str = "vault.otpqcv2";
pub const VAULT_FILES_BLOB_NAME: &str = "files.otpqcv2";
pub const VAULT_RELAY_BLOB_NAME: &str = "relay.otpqcv2";
pub const VAULT_RELAY_DOMAIN: &[u8] = b"OTPQCV2-RELAY-V21";
pub const PQC_SUITE_NAME: &str = "ML-KEM-768+X25519+ChaCha20Poly1305+AES256GCM";

pub const VALID_WALLPAPERS: &[&str] = &[
    "onion-mesh",
    "cobalt-vault",
    "pqc-shield",
    "tor-night",
    "brushed-slate",
    "stealth-oled",
];

pub fn normalize_wallpaper_id(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "onion-mesh" | "default" | "adwaita-blue" => Some("onion-mesh"),
        "cobalt-vault" | "sapphire" | "adwaita-amber" => Some("cobalt-vault"),
        "pqc-shield" | "emerald" | "emerald-grid" => Some("pqc-shield"),
        "tor-night" | "cyber_purple" => Some("tor-night"),
        "brushed-slate" | "slate" | "onion-obsidian" => Some("brushed-slate"),
        "stealth-oled" | "amoled" => Some("stealth-oled"),
        _ => None,
    }
}

const SEAL_MAGIC: &[u8; 8] = b"OTSEAL01";
const SEAL_ARMOR_BEGIN: &str = "-----BEGIN ONIONOS PQC SEAL-----";
const SEAL_ARMOR_END: &str = "-----END ONIONOS PQC SEAL-----";

/// Fixed OTPQCV2 binary header size:
/// 8B magic + 2B version + 32B salt + 32B eph_x25519 + 1088B mlkem_ct + 12B inner_nonce + 12B outer_nonce = 1186B
const VAULT_HEADER_LEN: usize = 8 + 2 + 32 + 32 + MLKEM768_CT_BYTES + 12 + 12;

/// Fixed OTSEAL01 binary header size:
/// 8B magic + 32B eph_x25519 + 1088B mlkem_ct + 12B inner_nonce + 12B outer_nonce = 1152B
const SEAL_HEADER_LEN: usize = 8 + 32 + MLKEM768_CT_BYTES + 12 + 12;

pub const ARGON2_M_COST_KIB: u32 = 19_456;
pub const ARGON2_T_COST: u32 = 2;
pub const ARGON2_P_COST: u32 = 1;
pub const MIN_PASSPHRASE_CHARS: usize = 12;

type DualAeadKeys = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Passphrase must be at least {MIN_PASSPHRASE_CHARS} characters")]
    PassphraseTooShort,
    #[error("Invalid passphrase or corrupted OTPQCV2 vault")]
    InvalidPassphrase,
    #[error("Vault is locked")]
    Locked,
    #[error("Unauthorized session or CSRF token")]
    Unauthorized,
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Item not found: {0}")]
    NotFound(String),
    #[error("Cryptographic failure: {0}")]
    Crypto(String),
    #[error("Vault I/O error: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DesktopSettings {
    #[serde(default = "default_wallpaper")]
    pub wallpaper: String,
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: u32,
    #[serde(default)]
    pub dock_compact: bool,
}

fn default_wallpaper() -> String {
    "onion-mesh".to_owned()
}

fn default_auto_lock_minutes() -> u32 {
    15
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            wallpaper: default_wallpaper(),
            auto_lock_minutes: default_auto_lock_minutes(),
            dock_compact: false,
        }
    }
}

/// Internal persisted record inside OTPQCV2 encrypted JSON (`totp_secret` stays encrypted on disk and zeroized in RAM).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultItemRecord {
    id: String,
    title: String,
    category: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    url: Option<String>,
    content: String,
    #[serde(default)]
    totp_secret: Option<String>,
    created_at: String,
}

impl VaultItemRecord {
    fn to_public_view(&self) -> VaultItemView {
        VaultItemView {
            id: self.id.clone(),
            title: self.title.clone(),
            category: self.category.clone(),
            username: self.username.clone(),
            url: self.url.clone(),
            content: self.content.clone(),
            has_totp: self
                .totp_secret
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty()),
            created_at: self.created_at.clone(),
        }
    }

    fn zeroize_sensitive(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.category.zeroize();
        if let Some(u) = &mut self.username {
            u.zeroize();
        }
        if let Some(u) = &mut self.url {
            u.zeroize();
        }
        self.content.zeroize();
        if let Some(sec) = &mut self.totp_secret {
            sec.zeroize();
        }
    }
}

/// Public API view returned by `GET /api/vault/items` and `POST /api/vault/items` (never leaks `totpSecret`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VaultItemView {
    pub id: String,
    pub title: String,
    pub category: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub content: String,
    pub has_totp: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct NewVaultItemInput {
    pub title: String,
    pub category: String,
    pub content: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub totp_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedRelayIdentity {
    pub tor_ed25519_v3_keyblob: String,
    pub onion_address: String,
    #[serde(default)]
    pub relay_node_key_b64: Option<String>,
    pub created_at: String,
}

impl Drop for PersistedRelayIdentity {
    fn drop(&mut self) {
        self.tor_ed25519_v3_keyblob.zeroize();
        if let Some(k) = &mut self.relay_node_key_b64 {
            k.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultPayload {
    version: u16,
    created_at: String,
    updated_at: String,
    identity_fingerprint: String,
    mlkem_pubkey_hex: String,
    x25519_pubkey_hex: String,
    ed25519_pubkey_hex: String,
    #[serde(default)]
    settings: DesktopSettings,
    items: Vec<VaultItemRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthStatusView {
    pub initialized: bool,
    pub locked: bool,
    pub identity_fingerprint: Option<String>,
    pub mlkem_pubkey_hex: Option<String>,
    pub x25519_pubkey_hex: Option<String>,
    pub ed25519_pubkey_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockOutcome {
    pub session_id: String,
    pub unlocked: bool,
    pub vault_initialized: bool,
    pub csrf_token: String,
    pub identity_fingerprint: String,
    pub mlkem_pubkey_hex: String,
    pub x25519_pubkey_hex: String,
    pub ed25519_pubkey_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealResponse {
    pub envelope: String,
    pub suite: String,
    pub ciphertext_bytes: usize,
    pub recipient_mlkem_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenResponse {
    pub plaintext: String,
    pub verified: bool,
    pub sender_fingerprint: Option<String>,
    pub suite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HybridKeygenBundle {
    pub suite: String,
    pub identity_fingerprint: String,
    pub mlkem_pubkey_hex: String,
    pub mlkem_secret_hex: String,
    pub x25519_pubkey_hex: String,
    pub x25519_secret_hex: String,
    pub ed25519_pubkey_hex: String,
    pub ed25519_secret_hex: String,
}

#[derive(Serialize, Deserialize)]
struct SealedInnerPlaintext {
    sender_ed25519_pk_hex: Option<String>,
    sender_sig_hex: Option<String>,
    plaintext: String,
}

struct DerivedIdentity {
    pw_wrap_key: Zeroizing<[u8; 32]>,
    mlkem_ek: Vec<u8>,
    mlkem_dk: Zeroizing<Vec<u8>>,
    x25519_sk_bytes: Zeroizing<[u8; 32]>,
    x25519_pk_bytes: [u8; 32],
    ed25519_seed: Zeroizing<[u8; 32]>,
    ed25519_pk_bytes: [u8; 32],
    fingerprint: String,
}

struct ActiveVaultSession {
    session_id: Zeroizing<String>,
    csrf_token: Zeroizing<String>,
    vault_salt: [u8; 32],
    pw_wrap_key: Zeroizing<[u8; 32]>,
    mlkem_ek: Vec<u8>,
    mlkem_dk: Zeroizing<Vec<u8>>,
    x25519_sk_bytes: Zeroizing<[u8; 32]>,
    x25519_pk_bytes: [u8; 32],
    ed25519_seed: Zeroizing<[u8; 32]>,
    ed25519_pk_bytes: [u8; 32],
    fingerprint: String,
    created_at: String,
    last_activity: Instant,
    settings: DesktopSettings,
    items: Vec<VaultItemRecord>,
}

impl Drop for ActiveVaultSession {
    fn drop(&mut self) {
        self.vault_salt.zeroize();
        for item in &mut self.items {
            item.zeroize_sensitive();
        }
        self.items.clear();
    }
}

struct VaultInnerState {
    active: Option<ActiveVaultSession>,
    volatile_settings: DesktopSettings,
    failed_attempts: u32,
}

pub struct VaultManager {
    vault_dir: PathBuf,
    enforce_backoff: bool,
    inner: Mutex<VaultInnerState>,
}

impl VaultManager {
    pub fn new(vault_dir: PathBuf) -> Self {
        Self {
            vault_dir,
            enforce_backoff: true,
            inner: Mutex::new(VaultInnerState {
                active: None,
                volatile_settings: DesktopSettings::default(),
                failed_attempts: 0,
            }),
        }
    }

    pub fn new_without_backoff(vault_dir: PathBuf) -> Self {
        Self {
            vault_dir,
            enforce_backoff: false,
            inner: Mutex::new(VaultInnerState {
                active: None,
                volatile_settings: DesktopSettings::default(),
                failed_attempts: 0,
            }),
        }
    }

    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }

    pub fn vault_file_path(&self) -> PathBuf {
        self.vault_dir.join(VAULT_FILENAME)
    }

    pub fn vault_files_blob_path(&self) -> PathBuf {
        self.vault_dir.join(VAULT_FILES_BLOB_NAME)
    }

    pub fn vault_relay_blob_path(&self) -> PathBuf {
        self.vault_dir.join(VAULT_RELAY_BLOB_NAME)
    }

    pub fn is_vault_file_present(&self) -> bool {
        self.vault_file_path().is_file()
    }

    pub async fn status(&self) -> AuthStatusView {
        let guard = self.inner.lock().await;
        let file_exists = self.is_vault_file_present();
        if let Some(session) = &guard.active {
            AuthStatusView {
                initialized: true,
                locked: false,
                identity_fingerprint: Some(session.fingerprint.clone()),
                mlkem_pubkey_hex: Some(hex::encode(&session.mlkem_ek)),
                x25519_pubkey_hex: Some(hex::encode(session.x25519_pk_bytes)),
                ed25519_pubkey_hex: Some(hex::encode(session.ed25519_pk_bytes)),
            }
        } else {
            AuthStatusView {
                initialized: file_exists,
                locked: true,
                identity_fingerprint: None,
                mlkem_pubkey_hex: None,
                x25519_pubkey_hex: None,
                ed25519_pubkey_hex: None,
            }
        }
    }

    pub async fn telemetry_snapshot(&self) -> (bool, bool, usize) {
        let guard = self.inner.lock().await;
        let initialized = guard.active.is_some() || self.is_vault_file_present();
        match &guard.active {
            Some(s) => (false, initialized, s.items.len()),
            None => (true, initialized, 0),
        }
    }

    /// Atomically locks an idle-expired unlocked session in RAM, returning `true`
    /// when a live session transitioned from unlocked to locked so `AppState` can tear down
    /// ephemeral child services (`PTY`, `OnionShare`, `Browser`, `Relay` + `DEL_ONION`).
    pub async fn reap_expired_idle_session(&self) -> bool {
        let mut guard = self.inner.lock().await;
        if is_session_idle_expired(&guard.active) {
            if let Some(mut expired) = guard.active.take() {
                expired.vault_salt.zeroize();
                drop(expired);
            }
            return true;
        }
        false
    }

    pub async fn verify_api_auth(
        &self,
        cookie_sid: Option<&str>,
        csrf_header: Option<&str>,
    ) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().await;
        if is_session_idle_expired(&guard.active) {
            if let Some(mut expired) = guard.active.take() {
                expired.vault_salt.zeroize();
                drop(expired);
            }
            return Err(VaultError::Locked);
        }
        let session = guard.active.as_mut().ok_or(VaultError::Locked)?;
        let sid = cookie_sid.ok_or(VaultError::Unauthorized)?;
        let csrf = csrf_header.ok_or(VaultError::Unauthorized)?;
        let sid_ok = constant_time_eq(sid.as_bytes(), session.session_id.as_bytes());
        let csrf_ok = constant_time_eq(csrf.as_bytes(), session.csrf_token.as_bytes());
        if sid_ok && csrf_ok {
            session.last_activity = Instant::now();
            Ok(())
        } else {
            Err(VaultError::Unauthorized)
        }
    }

    pub async fn verify_cookie_auth(&self, cookie_sid: Option<&str>) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().await;
        if is_session_idle_expired(&guard.active) {
            if let Some(mut expired) = guard.active.take() {
                expired.vault_salt.zeroize();
                drop(expired);
            }
            return Err(VaultError::Locked);
        }
        let session = guard.active.as_mut().ok_or(VaultError::Locked)?;
        let sid = cookie_sid.ok_or(VaultError::Unauthorized)?;
        if constant_time_eq(sid.as_bytes(), session.session_id.as_bytes()) {
            session.last_activity = Instant::now();
            Ok(())
        } else {
            Err(VaultError::Unauthorized)
        }
    }

    #[cfg(test)]
    pub async fn backdate_last_activity_for_test(&self, elapsed: Duration) {
        let mut guard = self.inner.lock().await;
        if let Some(session) = &mut guard.active {
            if let Some(past) = Instant::now().checked_sub(elapsed) {
                session.last_activity = past;
            }
        }
    }

    pub async fn unlock(&self, passphrase: &str) -> Result<UnlockOutcome, VaultError> {
        if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
            return Err(VaultError::PassphraseTooShort);
        }

        let mut guard = self.inner.lock().await;
        if self.enforce_backoff && guard.failed_attempts > 0 {
            let shift = guard.failed_attempts.saturating_sub(1).min(4);
            let delay_ms = 200u64.saturating_mul(1u64 << shift).min(2_500);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        let vault_path = self.vault_file_path();
        let pass_zeroizing = Zeroizing::new(passphrase.as_bytes().to_vec());

        let result = if vault_path.is_file() {
            let raw = fs::read(&vault_path).map_err(|e| VaultError::Io(e.to_string()))?;
            load_existing_vault(&raw, &pass_zeroizing)
        } else {
            fs::create_dir_all(&self.vault_dir).map_err(|e| VaultError::Io(e.to_string()))?;
            let mut salt = [0u8; 32];
            OsRng.fill_bytes(&mut salt);
            let id = derive_identity_from_passphrase(&pass_zeroizing, &salt)?;
            let now = Utc::now().to_rfc3339();
            let session = build_session(
                salt,
                id,
                now,
                guard.volatile_settings.clone(),
                Vec::new(),
            );
            persist_session_to_disk(&vault_path, &session)?;
            Ok(session)
        };

        match result {
            Ok(session) => {
                guard.failed_attempts = 0;
                guard.volatile_settings = session.settings.clone();
                let outcome = UnlockOutcome {
                    session_id: session.session_id.as_str().to_owned(),
                    unlocked: true,
                    vault_initialized: true,
                    csrf_token: session.csrf_token.as_str().to_owned(),
                    identity_fingerprint: session.fingerprint.clone(),
                    mlkem_pubkey_hex: hex::encode(&session.mlkem_ek),
                    x25519_pubkey_hex: hex::encode(session.x25519_pk_bytes),
                    ed25519_pubkey_hex: hex::encode(session.ed25519_pk_bytes),
                };
                guard.active = Some(session);
                Ok(outcome)
            }
            Err(err) => {
                guard.failed_attempts = guard.failed_attempts.saturating_add(1);
                if self.enforce_backoff {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(err)
            }
        }
    }

    pub async fn lock(&self) {
        let mut guard = self.inner.lock().await;
        if let Some(mut session) = guard.active.take() {
            session.vault_salt.zeroize();
            drop(session);
        }
    }

    /// Zeroizes active keys in RAM and optionally overwrites + deletes `/vault/vault.otpqcv2` & `/vault/files.otpqcv2`.
    pub async fn panic_lock_and_burn(&self, burn_vault: bool) -> bool {
        let mut guard = self.inner.lock().await;
        if let Some(mut session) = guard.active.take() {
            session.vault_salt.zeroize();
            drop(session);
        }
        guard.failed_attempts = 0;

        if burn_vault {
            let mut burned_any = false;
            let vault_path = self.vault_file_path();
            if vault_path.is_file() && overwrite_and_delete_file(&vault_path).is_ok() {
                burned_any = true;
            }
            let files_blob = self.vault_files_blob_path();
            if files_blob.is_file() && shred_and_remove_file(&files_blob).is_ok() {
                burned_any = true;
            }
            let relay_blob = self.vault_relay_blob_path();
            if relay_blob.is_file() && shred_and_remove_file(&relay_blob).is_ok() {
                burned_any = true;
            }
            return burned_any;
        }
        false
    }

    pub async fn get_settings(&self) -> Result<DesktopSettings, VaultError> {
        let guard = self.inner.lock().await;
        match &guard.active {
            Some(s) => Ok(s.settings.clone()),
            None => Err(VaultError::Locked),
        }
    }

    pub async fn update_settings(
        &self,
        incoming: DesktopSettings,
    ) -> Result<DesktopSettings, VaultError> {
        let Some(canonical_wp) = normalize_wallpaper_id(&incoming.wallpaper) else {
            return Err(VaultError::Validation(format!(
                "Invalid wallpaper '{}' (allowed: {})",
                incoming.wallpaper,
                VALID_WALLPAPERS.join(", ")
            )));
        };
        let clean = DesktopSettings {
            wallpaper: canonical_wp.to_owned(),
            auto_lock_minutes: incoming.auto_lock_minutes.min(240),
            dock_compact: incoming.dock_compact,
        };

        let mut guard = self.inner.lock().await;
        let session = guard.active.as_mut().ok_or(VaultError::Locked)?;
        let prev = session.settings.clone();
        session.settings = clean.clone();
        let vault_path = self.vault_file_path();
        if let Err(e) = persist_session_to_disk(&vault_path, session) {
            session.settings = prev;
            return Err(e);
        }
        guard.volatile_settings = clean.clone();
        Ok(clean)
    }

    pub async fn list_items(&self) -> Result<Vec<VaultItemView>, VaultError> {
        let guard = self.inner.lock().await;
        let session = guard.active.as_ref().ok_or(VaultError::Locked)?;
        Ok(session.items.iter().map(VaultItemRecord::to_public_view).collect())
    }

    pub async fn add_item(&self, input: NewVaultItemInput) -> Result<VaultItemView, VaultError> {
        let clean_title = input.title.trim().to_owned();
        if clean_title.is_empty() {
            return Err(VaultError::Validation("Item title cannot be empty".into()));
        }
        if clean_title.len() > 256 || input.category.len() > 128 || input.content.len() > 1_048_576
        {
            return Err(VaultError::Validation(
                "Vault item exceeds size limits".into(),
            ));
        }

        let clean_cat = if input.category.trim().is_empty() {
            "general".to_owned()
        } else {
            input.category.trim().to_owned()
        };

        let clean_username = input
            .username
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        if clean_username.as_ref().is_some_and(|u| u.len() > 256) {
            return Err(VaultError::Validation("Username exceeds 256 chars".into()));
        }

        let clean_url = input
            .url
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        if clean_url.as_ref().is_some_and(|u| u.len() > 1024) {
            return Err(VaultError::Validation("URL exceeds 1024 chars".into()));
        }

        let normalized_totp = match input
            .totp_secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(raw_sec) => {
                let norm = totp::normalize_totp_secret(raw_sec)
                    .map_err(|e| VaultError::Validation(e.to_string()))?;
                Some(norm.as_str().to_owned())
            }
            None => None,
        };

        let mut guard = self.inner.lock().await;
        let session = guard.active.as_mut().ok_or(VaultError::Locked)?;
        let record = VaultItemRecord {
            id: Uuid::new_v4().to_string(),
            title: clean_title,
            category: clean_cat,
            username: clean_username,
            url: clean_url,
            content: input.content,
            totp_secret: normalized_totp,
            created_at: Utc::now().to_rfc3339(),
        };
        let view = record.to_public_view();
        session.items.push(record);
        let vault_path = self.vault_file_path();
        if let Err(e) = persist_session_to_disk(&vault_path, session) {
            if let Some(mut popped) = session.items.pop() {
                popped.zeroize_sensitive();
            }
            return Err(e);
        }
        Ok(view)
    }

    pub async fn delete_item(&self, id: &str) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().await;
        let session = guard.active.as_mut().ok_or(VaultError::Locked)?;
        let Some(idx) = session.items.iter().position(|it| it.id == id) else {
            return Err(VaultError::NotFound(id.to_owned()));
        };
        let mut removed = session.items.remove(idx);
        let vault_path = self.vault_file_path();
        if let Err(e) = persist_session_to_disk(&vault_path, session) {
            session.items.insert(idx, removed);
            return Err(e);
        }
        removed.zeroize_sensitive();
        Ok(())
    }

    /// Computes live RFC 6238 6-digit TOTP codes for all vault items with a configured `totp_secret`.
    pub async fn compute_totp_codes(&self) -> Result<TotpCodesResponse, VaultError> {
        let guard = self.inner.lock().await;
        let session = guard.active.as_ref().ok_or(VaultError::Locked)?;
        let epoch_secs = totp::current_unix_epoch_secs();

        let mut codes = Vec::new();
        for item in &session.items {
            let Some(secret) = item
                .totp_secret
                .as_deref()
                .filter(|s| !s.trim().is_empty())
            else {
                continue;
            };
            if let Ok(snap) = totp::compute_totp_at(secret, epoch_secs) {
                codes.push(VaultTotpCodeEntry {
                    id: item.id.clone(),
                    title: item.title.clone(),
                    username: item.username.clone(),
                    code: snap.code,
                    period_secs: snap.period_secs,
                    remaining_secs: snap.remaining_secs,
                });
            }
        }

        Ok(TotpCodesResponse {
            server_epoch_secs: epoch_secs,
            codes,
        })
    }

    /// Encrypts an auxiliary OTPQCV2 blob (such as `/vault/files.otpqcv2`) bound to the unlocked session identity.
    pub async fn encrypt_session_blob(
        &self,
        domain_context: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let guard = self.inner.lock().await;
        let session = guard.active.as_ref().ok_or(VaultError::Locked)?;
        encrypt_otpqcv2_with_session(session, domain_context, plaintext)
    }

    /// Decrypts an auxiliary OTPQCV2 blob (such as `/vault/files.otpqcv2`) bound to the unlocked session identity.
    pub async fn decrypt_session_blob(
        &self,
        domain_context: &[u8],
        raw: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let guard = self.inner.lock().await;
        let session = guard.active.as_ref().ok_or(VaultError::Locked)?;
        decrypt_otpqcv2_with_session(session, domain_context, raw)
    }

    /// Loads optional PQC-sealed relay identity from `/vault/relay.otpqcv2` (`OTPQCV2-RELAY-V21`).
    pub async fn load_relay_identity(&self) -> Result<Option<PersistedRelayIdentity>, VaultError> {
        let blob_path = self.vault_relay_blob_path();
        let guard = self.inner.lock().await;
        let session = guard.active.as_ref().ok_or(VaultError::Locked)?;
        if !blob_path.is_file() {
            return Ok(None);
        }
        let raw = fs::read(&blob_path).map_err(|e| VaultError::Io(e.to_string()))?;
        let plain = decrypt_otpqcv2_with_session(session, VAULT_RELAY_DOMAIN, &raw)?;
        let identity: PersistedRelayIdentity = serde_json::from_slice(&plain)
            .map_err(|e| VaultError::Crypto(format!("Corrupted relay.otpqcv2 JSON: {e}")))?;
        Ok(Some(identity))
    }

    /// Saves PQC-sealed relay identity atomically into `/vault/relay.otpqcv2` (`0600`, `OTPQCV2-RELAY-V21`).
    pub async fn save_relay_identity(
        &self,
        identity: &PersistedRelayIdentity,
    ) -> Result<(), VaultError> {
        let guard = self.inner.lock().await;
        let session = guard.active.as_ref().ok_or(VaultError::Locked)?;
        let json_bytes = Zeroizing::new(
            serde_json::to_vec(identity).map_err(|e| VaultError::Crypto(e.to_string()))?,
        );
        let cipher = encrypt_otpqcv2_with_session(session, VAULT_RELAY_DOMAIN, &json_bytes)?;
        atomic_write_restricted(&self.vault_relay_blob_path(), &cipher)
    }

    pub async fn seal_for_recipient(
        &self,
        recipient_mlkem_hex: Option<&str>,
        recipient_x25519_hex: Option<&str>,
        plaintext: &str,
    ) -> Result<SealResponse, VaultError> {
        let guard = self.inner.lock().await;
        let session = guard.active.as_ref().ok_or(VaultError::Locked)?;

        let recipient_ek = match recipient_mlkem_hex.map(str::trim).filter(|s| !s.is_empty()) {
            Some(hex_str) => {
                let decoded = hex::decode(hex_str).map_err(|_| {
                    VaultError::Validation("Invalid hex in recipientMlkemHex".into())
                })?;
                if decoded.len() != MLKEM768_EK_BYTES {
                    return Err(VaultError::Validation(format!(
                        "recipientMlkemHex must decode to {MLKEM768_EK_BYTES} bytes"
                    )));
                }
                decoded
            }
            None => session.mlkem_ek.clone(),
        };

        let recipient_x_pk = match recipient_x25519_hex.map(str::trim).filter(|s| !s.is_empty()) {
            Some(hex_str) => {
                let decoded = hex::decode(hex_str).map_err(|_| {
                    VaultError::Validation("Invalid hex in recipientX25519Hex".into())
                })?;
                let arr: [u8; 32] = decoded.try_into().map_err(|_| {
                    VaultError::Validation("recipientX25519Hex must decode to 32 bytes".into())
                })?;
                arr
            }
            None => session.x25519_pk_bytes,
        };

        seal_pqc_envelope(
            &recipient_ek,
            &recipient_x_pk,
            Some(&session.ed25519_seed),
            plaintext,
        )
    }

    pub async fn open_with_session(&self, envelope: &str) -> Result<OpenResponse, VaultError> {
        let guard = self.inner.lock().await;
        let session = guard.active.as_ref().ok_or(VaultError::Locked)?;
        open_pqc_envelope(&session.mlkem_dk, &session.x25519_sk_bytes, envelope)
    }
}

pub fn keygen_hybrid_bundle() -> HybridKeygenBundle {
    let mut seed = Zeroizing::new([0u8; 64]);
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut *seed);
    OsRng.fill_bytes(&mut salt);

    let d = expand_shake256(b"ONIONOS-KEYGEN-MLKEM-D", &*seed, &salt);
    let z = expand_shake256(b"ONIONOS-KEYGEN-MLKEM-Z", &*seed, &salt);
    let x_seed = expand_shake256(b"ONIONOS-KEYGEN-X25519", &*seed, &salt);
    let ed_seed = expand_shake256(b"ONIONOS-KEYGEN-ED25519", &*seed, &salt);

    let (mlkem_ek, mlkem_dk) = mlkem768::keygen_deterministic(&d, &z);
    let x_sk = X25519StaticSecret::from(*x_seed);
    let x_pk = X25519PublicKey::from(&x_sk);
    let ed_sk = SigningKey::from_bytes(&ed_seed);
    let ed_vk = ed_sk.verifying_key();
    let fp = compute_identity_fingerprint(&mlkem_ek, x_pk.as_bytes(), ed_vk.as_bytes());

    HybridKeygenBundle {
        suite: PQC_SUITE_NAME.to_owned(),
        identity_fingerprint: fp,
        mlkem_pubkey_hex: hex::encode(&mlkem_ek),
        mlkem_secret_hex: hex::encode(&mlkem_dk),
        x25519_pubkey_hex: hex::encode(x_pk.as_bytes()),
        x25519_secret_hex: hex::encode(x_sk.to_bytes()),
        ed25519_pubkey_hex: hex::encode(ed_vk.as_bytes()),
        ed25519_secret_hex: hex::encode(*ed_seed),
    }
}

pub fn seal_pqc_envelope(
    recipient_mlkem_ek: &[u8],
    recipient_x25519_pk: &[u8; 32],
    sender_ed25519_seed: Option<&[u8; 32]>,
    plaintext: &str,
) -> Result<SealResponse, VaultError> {
    if plaintext.len() > 16 * 1024 * 1024 {
        return Err(VaultError::Validation(
            "Plaintext exceeds 16 MiB envelope limit".into(),
        ));
    }

    let (kem_ss_raw, kem_ct) =
        mlkem768::encaps(recipient_mlkem_ek).map_err(|e| VaultError::Crypto(e.to_owned()))?;
    let kem_ss = Zeroizing::new(kem_ss_raw);

    let mut eph_x_seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *eph_x_seed);
    let eph_x_sk = X25519StaticSecret::from(*eph_x_seed);
    let eph_x_pk = X25519PublicKey::from(&eph_x_sk);
    let recip_pk = X25519PublicKey::from(*recipient_x25519_pk);
    let x_ss = Zeroizing::new(eph_x_sk.diffie_hellman(&recip_pk).to_bytes());

    let mut inner_nonce = [0u8; 12];
    let mut outer_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut inner_nonce);
    OsRng.fill_bytes(&mut outer_nonce);

    let mut header = Vec::with_capacity(SEAL_HEADER_LEN);
    header.extend_from_slice(SEAL_MAGIC);
    header.extend_from_slice(eph_x_pk.as_bytes());
    header.extend_from_slice(&kem_ct);
    header.extend_from_slice(&inner_nonce);
    header.extend_from_slice(&outer_nonce);

    let (sender_ed_pk_hex, sender_sig_hex) = match sender_ed25519_seed {
        Some(seed) => {
            let signing = SigningKey::from_bytes(seed);
            let verifying = signing.verifying_key();
            let sig = sign_seal_transcript(&signing, &header, plaintext.as_bytes());
            (
                Some(hex::encode(verifying.as_bytes())),
                Some(hex::encode(sig.to_bytes())),
            )
        }
        None => (None, None),
    };

    let inner_struct = SealedInnerPlaintext {
        sender_ed25519_pk_hex: sender_ed_pk_hex,
        sender_sig_hex,
        plaintext: plaintext.to_owned(),
    };
    let inner_json = Zeroizing::new(
        serde_json::to_vec(&inner_struct).map_err(|e| VaultError::Crypto(e.to_string()))?,
    );

    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[0..32].copy_from_slice(&*kem_ss);
    ikm[32..64].copy_from_slice(&*x_ss);

    let (inner_key, outer_key) = derive_dual_aead_keys(&*ikm, b"OTSEAL01-SALT", b"OTSEAL01")?;

    let inner_cipher = ChaCha20Poly1305::new((&*inner_key).into());
    let inner_ct = inner_cipher
        .encrypt(
            ChaChaNonce::from_slice(&inner_nonce),
            Payload {
                msg: &inner_json,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Crypto("ChaCha20-Poly1305 seal failed".into()))?;

    let outer_cipher = Aes256Gcm::new((&*outer_key).into());
    let outer_ct = outer_cipher
        .encrypt(
            AesNonce::from_slice(&outer_nonce),
            Payload {
                msg: &inner_ct,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Crypto("AES-256-GCM seal failed".into()))?;

    let mut wire = Vec::with_capacity(header.len() + outer_ct.len());
    wire.extend_from_slice(&header);
    wire.extend_from_slice(&outer_ct);
    let ciphertext_bytes = wire.len();

    let b64 = B64.encode(&wire);
    let mut armored = String::with_capacity(b64.len() + 96);
    armored.push_str(SEAL_ARMOR_BEGIN);
    armored.push('\n');
    for chunk in b64.as_bytes().chunks(72) {
        if let Ok(line) = std::str::from_utf8(chunk) {
            armored.push_str(line);
            armored.push('\n');
        }
    }
    armored.push_str(SEAL_ARMOR_END);

    Ok(SealResponse {
        envelope: armored,
        suite: PQC_SUITE_NAME.to_owned(),
        ciphertext_bytes,
        recipient_mlkem_bytes: recipient_mlkem_ek.len(),
    })
}

pub fn open_pqc_envelope(
    recipient_mlkem_dk: &[u8],
    recipient_x25519_sk: &[u8; 32],
    envelope: &str,
) -> Result<OpenResponse, VaultError> {
    if recipient_mlkem_dk.len() != MLKEM768_DK_BYTES {
        return Err(VaultError::Crypto(
            "Invalid ML-KEM-768 decapsulation key length".into(),
        ));
    }

    let cleaned = strip_envelope_armor(envelope);
    if cleaned.is_empty() {
        return Err(VaultError::Validation("Empty PQC envelope".into()));
    }
    let wire = B64
        .decode(cleaned.as_bytes())
        .map_err(|_| VaultError::Validation("Invalid Base64 in PQC envelope".into()))?;

    if wire.len() <= SEAL_HEADER_LEN + 32 || &wire[0..8] != SEAL_MAGIC {
        return Err(VaultError::Validation(
            "Malformed or unrecognized OTSEAL01 envelope".into(),
        ));
    }

    let header = &wire[0..SEAL_HEADER_LEN];
    let outer_ct = &wire[SEAL_HEADER_LEN..];

    let mut eph_x_bytes = [0u8; 32];
    eph_x_bytes.copy_from_slice(&header[8..40]);
    let kem_ct = &header[40..40 + MLKEM768_CT_BYTES];
    let inner_nonce = &header[40 + MLKEM768_CT_BYTES..52 + MLKEM768_CT_BYTES];
    let outer_nonce = &header[52 + MLKEM768_CT_BYTES..SEAL_HEADER_LEN];

    let kem_ss = Zeroizing::new(
        mlkem768::decaps(recipient_mlkem_dk, kem_ct)
            .map_err(|e| VaultError::Crypto(e.to_owned()))?,
    );
    let x_sk = X25519StaticSecret::from(*recipient_x25519_sk);
    let eph_pk = X25519PublicKey::from(eph_x_bytes);
    let x_ss = Zeroizing::new(x_sk.diffie_hellman(&eph_pk).to_bytes());

    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[0..32].copy_from_slice(&*kem_ss);
    ikm[32..64].copy_from_slice(&*x_ss);

    let (inner_key, outer_key) = derive_dual_aead_keys(&*ikm, b"OTSEAL01-SALT", b"OTSEAL01")?;

    let outer_cipher = Aes256Gcm::new((&*outer_key).into());
    let inner_ct = outer_cipher
        .decrypt(
            AesNonce::from_slice(outer_nonce),
            Payload {
                msg: outer_ct,
                aad: header,
            },
        )
        .map_err(|_| VaultError::Crypto("Outer AES-256-GCM authentication failed".into()))?;

    let inner_cipher = ChaCha20Poly1305::new((&*inner_key).into());
    let inner_plain = Zeroizing::new(
        inner_cipher
            .decrypt(
                ChaChaNonce::from_slice(inner_nonce),
                Payload {
                    msg: &inner_ct,
                    aad: header,
                },
            )
            .map_err(|_| {
                VaultError::Crypto("Inner ChaCha20-Poly1305 authentication failed".into())
            })?,
    );

    let parsed: SealedInnerPlaintext = serde_json::from_slice(&inner_plain)
        .map_err(|_| VaultError::Crypto("Corrupted inner envelope payload".into()))?;

    let mut sender_fingerprint = None;
    let verified = match (&parsed.sender_ed25519_pk_hex, &parsed.sender_sig_hex) {
        (Some(pk_hex), Some(sig_hex)) => {
            let pk_bytes: [u8; 32] = hex::decode(pk_hex)
                .map_err(|_| VaultError::Crypto("Invalid sender Ed25519 key".into()))?
                .try_into()
                .map_err(|_| VaultError::Crypto("Invalid sender Ed25519 length".into()))?;
            let sig_bytes: [u8; 64] = hex::decode(sig_hex)
                .map_err(|_| VaultError::Crypto("Invalid sender signature".into()))?
                .try_into()
                .map_err(|_| VaultError::Crypto("Invalid sender signature length".into()))?;

            let vk = VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|_| VaultError::Crypto("Invalid Ed25519 curve point".into()))?;
            let sig = Signature::from_bytes(&sig_bytes);
            verify_seal_transcript(&vk, &sig, header, parsed.plaintext.as_bytes())?;
            let mut h = Sha256::new();
            Sha2Digest::update(&mut h, b"ONIONOS-SENDER-ED25519");
            Sha2Digest::update(&mut h, pk_bytes);
            let digest = h.finalize();
            sender_fingerprint = Some(hex::encode(&digest[0..16]));
            true
        }
        (None, None) => false,
        (Some(_), None) | (None, Some(_)) => {
            return Err(VaultError::Crypto(
                "Incomplete sender signature metadata".into(),
            ));
        }
    };

    Ok(OpenResponse {
        plaintext: parsed.plaintext,
        verified,
        sender_fingerprint,
        suite: PQC_SUITE_NAME.to_owned(),
    })
}

fn strip_envelope_armor(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_prefix = trimmed.strip_prefix("OTSEAL1.").unwrap_or(trimmed);
    let mut out = String::with_capacity(without_prefix.len());
    for line in without_prefix.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with("-----BEGIN ") || l.starts_with("-----END ") {
            continue;
        }
        for ch in l.chars() {
            if !ch.is_ascii_whitespace() {
                out.push(ch);
            }
        }
    }
    out
}

fn sign_seal_transcript(signing: &SigningKey, header: &[u8], plaintext: &[u8]) -> Signature {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, b"ONIONOS-OTSEAL01-SIG");
    Sha2Digest::update(&mut hasher, header);
    Sha2Digest::update(&mut hasher, plaintext);
    let digest = hasher.finalize();
    signing.sign(&digest)
}

fn verify_seal_transcript(
    verifying: &VerifyingKey,
    sig: &Signature,
    header: &[u8],
    plaintext: &[u8],
) -> Result<(), VaultError> {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, b"ONIONOS-OTSEAL01-SIG");
    Sha2Digest::update(&mut hasher, header);
    Sha2Digest::update(&mut hasher, plaintext);
    let digest = hasher.finalize();
    verifying
        .verify(&digest, sig)
        .map_err(|_| VaultError::Crypto("Sender Ed25519 signature verification failed".into()))
}

fn derive_identity_from_passphrase(
    passphrase: &[u8],
    vault_salt: &[u8; 32],
) -> Result<DerivedIdentity, VaultError> {
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(64),
    )
    .map_err(|e| VaultError::Crypto(format!("Argon2id params error: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master_seed = Zeroizing::new([0u8; 64]);
    argon2
        .hash_password_into(passphrase, vault_salt, &mut *master_seed)
        .map_err(|e| VaultError::Crypto(format!("Argon2id KDF error: {e}")))?;

    let mlkem_d = expand_shake256(b"ONIONOS-OTPQCV2-MLKEM768-D", &*master_seed, vault_salt);
    let mlkem_z = expand_shake256(b"ONIONOS-OTPQCV2-MLKEM768-Z", &*master_seed, vault_salt);
    let x25519_sk_bytes = expand_shake256(b"ONIONOS-OTPQCV2-X25519-SK", &*master_seed, vault_salt);
    let ed25519_seed = expand_shake256(b"ONIONOS-OTPQCV2-ED25519-SK", &*master_seed, vault_salt);
    let pw_wrap_key = expand_shake256(b"ONIONOS-OTPQCV2-PW-WRAP", &*master_seed, vault_salt);

    let (mlkem_ek, mlkem_dk_raw) = mlkem768::keygen_deterministic(&mlkem_d, &mlkem_z);
    let mlkem_dk = Zeroizing::new(mlkem_dk_raw);

    let x_sk = X25519StaticSecret::from(*x25519_sk_bytes);
    let x25519_pk_bytes = *X25519PublicKey::from(&x_sk).as_bytes();

    let ed_sk = SigningKey::from_bytes(&ed25519_seed);
    let ed25519_pk_bytes = ed_sk.verifying_key().to_bytes();

    let fingerprint =
        compute_identity_fingerprint(&mlkem_ek, &x25519_pk_bytes, &ed25519_pk_bytes);

    Ok(DerivedIdentity {
        pw_wrap_key,
        mlkem_ek,
        mlkem_dk,
        x25519_sk_bytes,
        x25519_pk_bytes,
        ed25519_seed,
        ed25519_pk_bytes,
        fingerprint,
    })
}

fn expand_shake256(domain: &[u8], seed: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut xof = Shake256::default();
    xof.update(domain);
    xof.update(&[0x00]);
    xof.update(seed);
    xof.update(salt);
    let mut reader = xof.finalize_xof();
    let mut out = Zeroizing::new([0u8; 32]);
    reader.read(&mut *out);
    out
}

fn compute_identity_fingerprint(
    mlkem_ek: &[u8],
    x25519_pk: &[u8; 32],
    ed25519_pk: &[u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, b"ONIONOS-ID-V1");
    Sha2Digest::update(&mut hasher, mlkem_ek);
    Sha2Digest::update(&mut hasher, x25519_pk);
    Sha2Digest::update(&mut hasher, ed25519_pk);
    let digest = hasher.finalize();
    hex::encode(&digest[0..16])
}

fn derive_dual_aead_keys(
    ikm: &[u8],
    salt: &[u8],
    context: &[u8],
) -> Result<DualAeadKeys, VaultError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut inner_info = Vec::with_capacity(context.len() + 28);
    inner_info.extend_from_slice(context);
    inner_info.extend_from_slice(b"-INNER-CHACHA20POLY1305");

    let mut outer_info = Vec::with_capacity(context.len() + 18);
    outer_info.extend_from_slice(context);
    outer_info.extend_from_slice(b"-OUTER-AES256GCM");

    let mut inner_key = Zeroizing::new([0u8; 32]);
    let mut outer_key = Zeroizing::new([0u8; 32]);

    hk.expand(&inner_info, &mut *inner_key)
        .map_err(|_| VaultError::Crypto("HKDF expand inner failed".into()))?;
    hk.expand(&outer_info, &mut *outer_key)
        .map_err(|_| VaultError::Crypto("HKDF expand outer failed".into()))?;

    Ok((inner_key, outer_key))
}

fn is_session_idle_expired(active: &Option<ActiveVaultSession>) -> bool {
    let Some(session) = active else {
        return false;
    };
    let mins = session.settings.auto_lock_minutes;
    if mins == 0 {
        return false;
    }
    session.last_activity.elapsed() > Duration::from_secs(u64::from(mins).saturating_mul(60))
}

fn build_session(
    vault_salt: [u8; 32],
    id: DerivedIdentity,
    created_at: String,
    mut settings: DesktopSettings,
    items: Vec<VaultItemRecord>,
) -> ActiveVaultSession {
    settings.wallpaper = normalize_wallpaper_id(&settings.wallpaper)
        .unwrap_or("onion-mesh")
        .to_owned();
    let mut sid_bytes = [0u8; 32];
    let mut csrf_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sid_bytes);
    OsRng.fill_bytes(&mut csrf_bytes);
    let sid = Zeroizing::new(hex::encode(sid_bytes));
    let csrf = Zeroizing::new(hex::encode(csrf_bytes));
    sid_bytes.zeroize();
    csrf_bytes.zeroize();

    ActiveVaultSession {
        session_id: sid,
        csrf_token: csrf,
        vault_salt,
        pw_wrap_key: id.pw_wrap_key,
        mlkem_ek: id.mlkem_ek,
        mlkem_dk: id.mlkem_dk,
        x25519_sk_bytes: id.x25519_sk_bytes,
        x25519_pk_bytes: id.x25519_pk_bytes,
        ed25519_seed: id.ed25519_seed,
        ed25519_pk_bytes: id.ed25519_pk_bytes,
        fingerprint: id.fingerprint,
        created_at,
        last_activity: Instant::now(),
        settings,
        items,
    }
}

fn encrypt_otpqcv2_with_session(
    session: &ActiveVaultSession,
    domain_context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let signing = SigningKey::from_bytes(&session.ed25519_seed);
    let sig = signing.sign(plaintext);
    let mut signed_plain = Zeroizing::new(Vec::with_capacity(64 + plaintext.len()));
    signed_plain.extend_from_slice(&sig.to_bytes());
    signed_plain.extend_from_slice(plaintext);

    let (kem_ss_raw, kem_ct) =
        mlkem768::encaps(&session.mlkem_ek).map_err(|e| VaultError::Crypto(e.to_owned()))?;
    let kem_ss = Zeroizing::new(kem_ss_raw);

    let mut eph_x_seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *eph_x_seed);
    let eph_x_sk = X25519StaticSecret::from(*eph_x_seed);
    let eph_x_pk = X25519PublicKey::from(&eph_x_sk);
    let self_x_pk = X25519PublicKey::from(session.x25519_pk_bytes);
    let x_ss = Zeroizing::new(eph_x_sk.diffie_hellman(&self_x_pk).to_bytes());

    let mut inner_nonce = [0u8; 12];
    let mut outer_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut inner_nonce);
    OsRng.fill_bytes(&mut outer_nonce);

    let mut header = Vec::with_capacity(VAULT_HEADER_LEN);
    header.extend_from_slice(VAULT_PQC_MAGIC);
    header.extend_from_slice(&VAULT_FORMAT_VERSION.to_be_bytes());
    header.extend_from_slice(&session.vault_salt);
    header.extend_from_slice(eph_x_pk.as_bytes());
    header.extend_from_slice(&kem_ct);
    header.extend_from_slice(&inner_nonce);
    header.extend_from_slice(&outer_nonce);

    let mut ikm = Zeroizing::new([0u8; 96]);
    ikm[0..32].copy_from_slice(&*session.pw_wrap_key);
    ikm[32..64].copy_from_slice(&*kem_ss);
    ikm[64..96].copy_from_slice(&*x_ss);

    let (inner_key, outer_key) =
        derive_dual_aead_keys(&*ikm, &session.vault_salt, domain_context)?;

    let inner_cipher = ChaCha20Poly1305::new((&*inner_key).into());
    let inner_ct = inner_cipher
        .encrypt(
            ChaChaNonce::from_slice(&inner_nonce),
            Payload {
                msg: &signed_plain,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Crypto("OTPQCV2 inner ChaCha20-Poly1305 failed".into()))?;

    let outer_cipher = Aes256Gcm::new((&*outer_key).into());
    let outer_ct = outer_cipher
        .encrypt(
            AesNonce::from_slice(&outer_nonce),
            Payload {
                msg: &inner_ct,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Crypto("OTPQCV2 outer AES-256-GCM failed".into()))?;

    let mut full_bytes = Vec::with_capacity(header.len() + outer_ct.len());
    full_bytes.extend_from_slice(&header);
    full_bytes.extend_from_slice(&outer_ct);
    Ok(full_bytes)
}

fn decrypt_otpqcv2_with_session(
    session: &ActiveVaultSession,
    domain_context: &[u8],
    raw: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if raw.len() <= VAULT_HEADER_LEN + 32 + 64 || &raw[0..8] != VAULT_PQC_MAGIC {
        return Err(VaultError::InvalidPassphrase);
    }
    let ver = u16::from_be_bytes([raw[8], raw[9]]);
    if ver != VAULT_FORMAT_VERSION {
        return Err(VaultError::InvalidPassphrase);
    }

    let header = &raw[0..VAULT_HEADER_LEN];
    let outer_ct = &raw[VAULT_HEADER_LEN..];

    let mut blob_salt = [0u8; 32];
    blob_salt.copy_from_slice(&header[10..42]);
    if !constant_time_eq(&blob_salt, &session.vault_salt) {
        return Err(VaultError::InvalidPassphrase);
    }

    let mut eph_x_bytes = [0u8; 32];
    eph_x_bytes.copy_from_slice(&header[42..74]);
    let kem_ct = &header[74..74 + MLKEM768_CT_BYTES];
    let inner_nonce = &header[74 + MLKEM768_CT_BYTES..86 + MLKEM768_CT_BYTES];
    let outer_nonce = &header[86 + MLKEM768_CT_BYTES..VAULT_HEADER_LEN];

    let kem_ss = Zeroizing::new(
        mlkem768::decaps(&session.mlkem_dk, kem_ct)
            .map_err(|_| VaultError::InvalidPassphrase)?,
    );
    let x_sk = X25519StaticSecret::from(*session.x25519_sk_bytes);
    let eph_pk = X25519PublicKey::from(eph_x_bytes);
    let x_ss = Zeroizing::new(x_sk.diffie_hellman(&eph_pk).to_bytes());

    let mut ikm = Zeroizing::new([0u8; 96]);
    ikm[0..32].copy_from_slice(&*session.pw_wrap_key);
    ikm[32..64].copy_from_slice(&*kem_ss);
    ikm[64..96].copy_from_slice(&*x_ss);

    let (inner_key, outer_key) = derive_dual_aead_keys(&*ikm, &blob_salt, domain_context)?;

    let outer_cipher = Aes256Gcm::new((&*outer_key).into());
    let inner_ct = outer_cipher
        .decrypt(
            AesNonce::from_slice(outer_nonce),
            Payload {
                msg: outer_ct,
                aad: header,
            },
        )
        .map_err(|_| VaultError::InvalidPassphrase)?;

    let inner_cipher = ChaCha20Poly1305::new((&*inner_key).into());
    let signed_plain = Zeroizing::new(
        inner_cipher
            .decrypt(
                ChaChaNonce::from_slice(inner_nonce),
                Payload {
                    msg: &inner_ct,
                    aad: header,
                },
            )
            .map_err(|_| VaultError::InvalidPassphrase)?,
    );

    if signed_plain.len() < 64 {
        return Err(VaultError::InvalidPassphrase);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signed_plain[0..64]);
    let body_slice = &signed_plain[64..];

    let vk = VerifyingKey::from_bytes(&session.ed25519_pk_bytes)
        .map_err(|_| VaultError::InvalidPassphrase)?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(body_slice, &sig)
        .map_err(|_| VaultError::InvalidPassphrase)?;

    Ok(Zeroizing::new(body_slice.to_vec()))
}

fn persist_session_to_disk(
    vault_path: &Path,
    session: &ActiveVaultSession,
) -> Result<(), VaultError> {
    let payload = VaultPayload {
        version: VAULT_FORMAT_VERSION,
        created_at: session.created_at.clone(),
        updated_at: Utc::now().to_rfc3339(),
        identity_fingerprint: session.fingerprint.clone(),
        mlkem_pubkey_hex: hex::encode(&session.mlkem_ek),
        x25519_pubkey_hex: hex::encode(session.x25519_pk_bytes),
        ed25519_pubkey_hex: hex::encode(session.ed25519_pk_bytes),
        settings: session.settings.clone(),
        items: session.items.clone(),
    };

    let json_bytes = Zeroizing::new(
        serde_json::to_vec(&payload).map_err(|e| VaultError::Crypto(e.to_string()))?,
    );

    let full_bytes = encrypt_otpqcv2_with_session(session, b"OTPQCV2-VAULT", &json_bytes)?;
    atomic_write_restricted(vault_path, &full_bytes)
}

fn load_existing_vault(
    raw: &[u8],
    passphrase: &[u8],
) -> Result<ActiveVaultSession, VaultError> {
    if raw.len() <= VAULT_HEADER_LEN + 32 + 64 || &raw[0..8] != VAULT_PQC_MAGIC {
        return Err(VaultError::InvalidPassphrase);
    }
    let ver = u16::from_be_bytes([raw[8], raw[9]]);
    if ver != VAULT_FORMAT_VERSION {
        return Err(VaultError::InvalidPassphrase);
    }

    let mut vault_salt = [0u8; 32];
    vault_salt.copy_from_slice(&raw[10..42]);

    let id = derive_identity_from_passphrase(passphrase, &vault_salt)?;
    let mut temp_session = build_session(
        vault_salt,
        id,
        Utc::now().to_rfc3339(),
        DesktopSettings::default(),
        Vec::new(),
    );

    let json_bytes = decrypt_otpqcv2_with_session(&temp_session, b"OTPQCV2-VAULT", raw)?;
    let payload: VaultPayload =
        serde_json::from_slice(&json_bytes).map_err(|_| VaultError::InvalidPassphrase)?;

    temp_session.created_at = payload.created_at;
    temp_session.settings = payload.settings;
    temp_session.items = payload.items;
    Ok(temp_session)
}

pub fn atomic_write_restricted(target: &Path, data: &[u8]) -> Result<(), VaultError> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| VaultError::Io(e.to_string()))?;
    }
    let tmp_name = format!(
        ".{}.{}.tmp",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("vault.otpqcv2"),
        Uuid::new_v4()
    );
    let tmp_path = target.with_file_name(tmp_name);

    let write_res = (|| -> Result<(), std::io::Error> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, target)?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(VaultError::Io(e.to_string()));
    }
    Ok(())
}

pub fn shred_and_remove_file(path: &Path) -> Result<(), std::io::Error> {
    overwrite_and_delete_file(path)
}

pub fn overwrite_and_delete_file(path: &Path) -> Result<(), std::io::Error> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_file() {
        let len = meta.len();
        if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
            let mut remaining = len;
            let mut buf = [0u8; 16_384];
            while remaining > 0 {
                let n = (remaining as usize).min(buf.len());
                OsRng.fill_bytes(&mut buf[..n]);
                if f.write_all(&buf[..n]).is_err() {
                    break;
                }
                remaining = remaining.saturating_sub(n as u64);
            }
            buf.zeroize();
            let _ = f.sync_data();
        }
    }
    fs::remove_file(path)
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= std::hint::black_box(x ^ y);
    }
    std::hint::black_box(diff) == 0
}
