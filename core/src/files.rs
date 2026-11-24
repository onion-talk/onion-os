//! Dual-Root File Manager (`"ram"` `/home/onion` + `"vault"` `/vault/files.otpqcv2`)
//! Enforces strict traversal/symlink blocking, CSPRNG shred, metadata scrub & `.otseal` actions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::forensics::{self, ForensicsError};
use crate::vault::{
    atomic_write_restricted, overwrite_and_delete_file, VaultError, VaultManager,
};

pub const MAX_FILE_WRITE_BYTES: usize = 16 * 1024 * 1024;
const VAULT_FILES_DOMAIN: &[u8] = b"OTPQCV2-FILES-V2";

const WELCOME_MD: &str = "# Welcome to OnionOS v1.0.0 (Onion Mesh Sovereign Edition)\n\n\
- **RAM Workspace (`ram:/`)**: Lives exclusively in volatile `tmpfs` (`/home/onion`). Zero bytes hit host disk; `Panic Burn` shreds everything in `< 150 ms`.\n\
- **Encrypted Vault (`vault:/`)**: Sealed at rest in `/vault/files.otpqcv2` using `Argon2id (19 MiB) + ML-KEM-768 + X25519 + ChaCha20-Poly1305 + AES-256-GCM`.\n\
- **Zero-Leak Netfilter**: Kernel `iptables`/`ip6tables` restricts WAN packets exclusively to the local `tor` UID (`127.0.0.1:9050`).\n";

#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    #[error("Invalid file root '{0}' (expected 'ram' or 'vault')")]
    InvalidRoot(String),
    #[error("Invalid or unsafe file path: {0}")]
    InvalidPath(String),
    #[error("File or directory not found: {0}")]
    NotFound(String),
    #[error("File payload exceeds 16 MiB limit")]
    PayloadTooLarge,
    #[error("Unsupported file action '{0}' (expected 'scrub' or 'seal')")]
    UnsupportedAction(String),
    #[error("Vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("Forensics error: {0}")]
    Forensics(#[from] ForensicsError),
    #[error("Filesystem I/O error: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRoot {
    Ram,
    Vault,
}

impl FileRoot {
    pub fn parse(raw: &str) -> Result<Self, FilesError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ram" => Ok(Self::Ram),
            "vault" => Ok(Self::Vault),
            other => Err(FilesError::InvalidRoot(other.to_owned())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ram => "ram",
            Self::Vault => "vault",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntryView {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size_bytes: u64,
    pub modified_at: String,
    pub mime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileListResponse {
    pub root: String,
    pub path: String,
    pub entries: Vec<FileEntryView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMkdirResponse {
    pub created: bool,
    pub root: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileWriteResponse {
    pub written: bool,
    pub root: String,
    pub path: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileReadResponse {
    pub root: String,
    pub path: String,
    pub name: String,
    pub size_bytes: usize,
    pub mime: String,
    pub is_utf8: bool,
    pub text: Option<String>,
    pub data_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDeleteResponse {
    pub deleted: bool,
    pub shredded: bool,
    pub root: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileActionResponse {
    pub ok: bool,
    pub action: String,
    pub source_path: String,
    pub output_path: String,
    pub size_bytes: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VirtualVaultFile {
    modified_at: String,
    data_b64: String,
    size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VirtualVaultFs {
    version: u16,
    dirs: BTreeMap<String, String>,
    files: BTreeMap<String, VirtualVaultFile>,
}

impl Default for VirtualVaultFs {
    fn default() -> Self {
        let now = Utc::now().to_rfc3339();
        let mut dirs = BTreeMap::new();
        dirs.insert("/".to_owned(), now.clone());
        dirs.insert("/Documents".to_owned(), now.clone());
        dirs.insert("/Secrets".to_owned(), now);
        Self {
            version: 2,
            dirs,
            files: BTreeMap::new(),
        }
    }
}

pub struct DualRootFileManager {
    home_dir: PathBuf,
    vault_fs_lock: Mutex<()>,
}

impl DualRootFileManager {
    pub fn new(home_dir: PathBuf) -> Self {
        ensure_gnome_home_skeleton(&home_dir);
        Self {
            home_dir,
            vault_fs_lock: Mutex::new(()),
        }
    }

    pub fn home_dir(&self) -> &Path {
        &self.home_dir
    }

    pub async fn list(
        &self,
        vault: &VaultManager,
        root_str: &str,
        raw_path: &str,
    ) -> Result<FileListResponse, FilesError> {
        let root = FileRoot::parse(root_str)?;
        let (norm_path, segments) = normalize_virtual_path(raw_path)?;

        let mut entries = match root {
            FileRoot::Ram => self.list_ram(&segments, &norm_path)?,
            FileRoot::Vault => {
                let _guard = self.vault_fs_lock.lock().await;
                let vfs = self.load_vault_fs(vault).await?;
                list_virtual_entries(&vfs, &norm_path)?
            }
        };

        entries.sort_by(|a, b| {
            let a_is_dir = a.kind == "dir";
            let b_is_dir = b.kind == "dir";
            b_is_dir
                .cmp(&a_is_dir)
                .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
        });

        Ok(FileListResponse {
            root: root.as_str().to_owned(),
            path: norm_path,
            entries,
        })
    }

    pub async fn mkdir(
        &self,
        vault: &VaultManager,
        root_str: &str,
        raw_path: &str,
    ) -> Result<FileMkdirResponse, FilesError> {
        let root = FileRoot::parse(root_str)?;
        let (norm_path, segments) = normalize_virtual_path(raw_path)?;
        if segments.is_empty() {
            return Err(FilesError::InvalidPath("Cannot recreate root '/'".into()));
        }

        match root {
            FileRoot::Ram => {
                let target = self.resolve_ram_path(&segments, true)?;
                fs::create_dir_all(&target).map_err(|e| FilesError::Io(e.to_string()))?;
            }
            FileRoot::Vault => {
                let _guard = self.vault_fs_lock.lock().await;
                let mut vfs = self.load_vault_fs(vault).await?;
                let now = Utc::now().to_rfc3339();
                let mut cur = String::new();
                for seg in &segments {
                    cur.push('/');
                    cur.push_str(seg);
                    if vfs.files.contains_key(&cur) {
                        return Err(FilesError::InvalidPath(format!(
                            "File already exists at '{cur}'"
                        )));
                    }
                    vfs.dirs.entry(cur.clone()).or_insert_with(|| now.clone());
                }
                self.save_vault_fs(vault, &vfs).await?;
            }
        }

        Ok(FileMkdirResponse {
            created: true,
            root: root.as_str().to_owned(),
            path: norm_path,
        })
    }

    pub async fn write(
        &self,
        vault: &VaultManager,
        root_str: &str,
        raw_path: &str,
        text: Option<&str>,
        data_b64: Option<&str>,
    ) -> Result<FileWriteResponse, FilesError> {
        let root = FileRoot::parse(root_str)?;
        let (norm_path, segments) = normalize_virtual_path(raw_path)?;
        if segments.is_empty() {
            return Err(FilesError::InvalidPath(
                "Target path must be a file, not '/'".into(),
            ));
        }

        let bytes = decode_write_payload(text, data_b64)?;
        if bytes.len() > MAX_FILE_WRITE_BYTES {
            return Err(FilesError::PayloadTooLarge);
        }

        self.write_raw_bytes(vault, root, &norm_path, &segments, &bytes)
            .await?;

        Ok(FileWriteResponse {
            written: true,
            root: root.as_str().to_owned(),
            path: norm_path,
            size_bytes: bytes.len(),
        })
    }

    pub async fn read(
        &self,
        vault: &VaultManager,
        root_str: &str,
        raw_path: &str,
    ) -> Result<FileReadResponse, FilesError> {
        let root = FileRoot::parse(root_str)?;
        let (norm_path, segments) = normalize_virtual_path(raw_path)?;
        if segments.is_empty() {
            return Err(FilesError::InvalidPath("Cannot read directory '/'".into()));
        }
        let file_name = segments
            .last()
            .cloned()
            .unwrap_or_else(|| "file.bin".to_owned());

        let bytes = self.read_raw_bytes(vault, root, &norm_path, &segments).await?;
        let size_bytes = bytes.len();
        let data_b64 = B64.encode(&bytes);
        let mime = guess_mime(&file_name).to_owned();
        let (is_utf8, text) = match std::str::from_utf8(&bytes) {
            Ok(s) => (true, Some(s.to_owned())),
            Err(_) => (false, None),
        };

        Ok(FileReadResponse {
            root: root.as_str().to_owned(),
            path: norm_path,
            name: file_name,
            size_bytes,
            mime,
            is_utf8,
            text,
            data_b64,
        })
    }

    pub async fn delete(
        &self,
        vault: &VaultManager,
        root_str: &str,
        raw_path: &str,
        shred: Option<bool>,
    ) -> Result<FileDeleteResponse, FilesError> {
        let root = FileRoot::parse(root_str)?;
        let (norm_path, segments) = normalize_virtual_path(raw_path)?;
        if segments.is_empty() {
            return Err(FilesError::InvalidPath(
                "Refusing to delete root directory '/'".into(),
            ));
        }

        let do_shred = shred.unwrap_or(true);
        let mut shredded = false;

        match root {
            FileRoot::Ram => {
                let target = self.resolve_ram_path(&segments, false)?;
                let meta = fs::symlink_metadata(&target)
                    .map_err(|_| FilesError::NotFound(norm_path.clone()))?;
                if meta.file_type().is_symlink() {
                    return Err(FilesError::InvalidPath(
                        "Refusing symlink target".into(),
                    ));
                }
                if meta.is_dir() {
                    delete_ram_dir_recursive(&target, do_shred)?;
                    shredded = do_shred;
                } else if do_shred {
                    overwrite_and_delete_file(&target)
                        .map_err(|e| FilesError::Io(e.to_string()))?;
                    shredded = true;
                } else {
                    fs::remove_file(&target).map_err(|e| FilesError::Io(e.to_string()))?;
                }
            }
            FileRoot::Vault => {
                let _guard = self.vault_fs_lock.lock().await;
                let mut vfs = self.load_vault_fs(vault).await?;
                let dir_prefix = format!("{norm_path}/");
                let mut removed = vfs.files.remove(&norm_path).is_some()
                    || vfs.dirs.remove(&norm_path).is_some();

                let child_files: Vec<String> = vfs
                    .files
                    .keys()
                    .filter(|k| k.starts_with(&dir_prefix))
                    .cloned()
                    .collect();
                for k in child_files {
                    if let Some(mut f) = vfs.files.remove(&k) {
                        zeroize::Zeroize::zeroize(&mut f.data_b64);
                        removed = true;
                    }
                }
                let child_dirs: Vec<String> = vfs
                    .dirs
                    .keys()
                    .filter(|k| k.starts_with(&dir_prefix))
                    .cloned()
                    .collect();
                for k in child_dirs {
                    vfs.dirs.remove(&k);
                    removed = true;
                }

                if !removed {
                    return Err(FilesError::NotFound(norm_path));
                }
                self.save_vault_fs(vault, &vfs).await?;
                shredded = true;
            }
        }

        Ok(FileDeleteResponse {
            deleted: true,
            shredded,
            root: root.as_str().to_owned(),
            path: norm_path,
        })
    }

    pub async fn execute_action(
        &self,
        vault: &VaultManager,
        root_str: &str,
        raw_path: &str,
        action: &str,
    ) -> Result<FileActionResponse, FilesError> {
        let root = FileRoot::parse(root_str)?;
        let (norm_path, segments) = normalize_virtual_path(raw_path)?;
        if segments.is_empty() {
            return Err(FilesError::InvalidPath("Action requires a file path".into()));
        }
        let file_name = segments
            .last()
            .cloned()
            .unwrap_or_else(|| "artifact.bin".to_owned());

        let source_bytes = self
            .read_raw_bytes(vault, root, &norm_path, &segments)
            .await?;

        let clean_act = action.trim().to_ascii_lowercase();
        match clean_act.as_str() {
            "scrub" => {
                let outcome = forensics::scrub_bytes(&file_name, &source_bytes)?;
                let out_name = derive_clean_filename(&file_name);
                let mut out_segments = segments.clone();
                if let Some(last) = out_segments.last_mut() {
                    *last = out_name;
                }
                let out_path = format!("/{}", out_segments.join("/"));
                let out_len = outcome.clean_bytes_vec.len();
                let detail = if outcome.removed_segments.is_empty() {
                    format!("Verified {} (0 metadata segments found)", outcome.format)
                } else {
                    format!(
                        "Removed {} segment(s): {}",
                        outcome.removed_segments.len(),
                        outcome.removed_segments.join(", ")
                    )
                };
                self.write_raw_bytes(vault, root, &out_path, &out_segments, &outcome.clean_bytes_vec)
                    .await?;

                Ok(FileActionResponse {
                    ok: true,
                    action: "scrub".to_owned(),
                    source_path: norm_path,
                    output_path: out_path,
                    size_bytes: out_len,
                    detail,
                })
            }
            "seal" => {
                let plain_str = match std::str::from_utf8(&source_bytes) {
                    Ok(s) => s.to_owned(),
                    Err(_) => format!("BASE64:{}", B64.encode(&source_bytes)),
                };
                let sealed = vault.seal_for_recipient(None, None, &plain_str).await?;
                let mut out_segments = segments.clone();
                if let Some(last) = out_segments.last_mut() {
                    *last = format!("{file_name}.otseal");
                }
                let out_path = format!("/{}", out_segments.join("/"));
                let env_bytes = sealed.envelope.as_bytes();
                self.write_raw_bytes(vault, root, &out_path, &out_segments, env_bytes)
                    .await?;

                Ok(FileActionResponse {
                    ok: true,
                    action: "seal".to_owned(),
                    source_path: norm_path,
                    output_path: out_path,
                    size_bytes: env_bytes.len(),
                    detail: format!("Sealed with {}", sealed.suite),
                })
            }
            other => Err(FilesError::UnsupportedAction(other.to_owned())),
        }
    }

    /// Resolves and reads a `"ram"` file safely for OnionShare `"share"` mode.
    pub fn read_ram_file_for_share(&self, raw_path: &str) -> Result<(String, Vec<u8>), FilesError> {
        let (norm_path, segments) = normalize_virtual_path(raw_path)?;
        if segments.is_empty() {
            return Err(FilesError::InvalidPath("Cannot share directory '/'".into()));
        }
        let target = self.resolve_ram_path(&segments, false)?;
        let meta =
            fs::symlink_metadata(&target).map_err(|_| FilesError::NotFound(norm_path.clone()))?;
        if !meta.file_type().is_file() {
            return Err(FilesError::InvalidPath(format!(
                "'{norm_path}' is not a regular file"
            )));
        }
        if meta.len() > (MAX_FILE_WRITE_BYTES as u64) * 2 {
            return Err(FilesError::PayloadTooLarge);
        }
        let data = fs::read(&target).map_err(|e| FilesError::Io(e.to_string()))?;
        let name = segments
            .last()
            .cloned()
            .unwrap_or_else(|| "shared.bin".to_owned());
        Ok((name, data))
    }

    async fn read_raw_bytes(
        &self,
        vault: &VaultManager,
        root: FileRoot,
        norm_path: &str,
        segments: &[String],
    ) -> Result<Vec<u8>, FilesError> {
        match root {
            FileRoot::Ram => {
                let target = self.resolve_ram_path(segments, false)?;
                let meta = fs::symlink_metadata(&target)
                    .map_err(|_| FilesError::NotFound(norm_path.to_owned()))?;
                if !meta.file_type().is_file() {
                    return Err(FilesError::InvalidPath(format!(
                        "'{norm_path}' is not a regular file"
                    )));
                }
                if meta.len() > MAX_FILE_WRITE_BYTES as u64 {
                    return Err(FilesError::PayloadTooLarge);
                }
                fs::read(&target).map_err(|e| FilesError::Io(e.to_string()))
            }
            FileRoot::Vault => {
                let _guard = self.vault_fs_lock.lock().await;
                let vfs = self.load_vault_fs(vault).await?;
                let vf = vfs
                    .files
                    .get(norm_path)
                    .ok_or_else(|| FilesError::NotFound(norm_path.to_owned()))?;
                B64.decode(vf.data_b64.as_bytes())
                    .map_err(|e| FilesError::Io(format!("Vault file decode error: {e}")))
            }
        }
    }

    async fn write_raw_bytes(
        &self,
        vault: &VaultManager,
        root: FileRoot,
        norm_path: &str,
        segments: &[String],
        bytes: &[u8],
    ) -> Result<(), FilesError> {
        match root {
            FileRoot::Ram => {
                let target = self.resolve_ram_path(segments, true)?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| FilesError::Io(e.to_string()))?;
                }
                if let Ok(meta) = fs::symlink_metadata(&target) {
                    if meta.file_type().is_symlink() || meta.is_dir() {
                        return Err(FilesError::InvalidPath(
                            "Target exists as directory or symlink".into(),
                        ));
                    }
                }
                fs::write(&target, bytes).map_err(|e| FilesError::Io(e.to_string()))?;
                Ok(())
            }
            FileRoot::Vault => {
                let _guard = self.vault_fs_lock.lock().await;
                let mut vfs = self.load_vault_fs(vault).await?;
                if vfs.dirs.contains_key(norm_path) {
                    return Err(FilesError::InvalidPath(format!(
                        "Directory already exists at '{norm_path}'"
                    )));
                }
                let now = Utc::now().to_rfc3339();
                if segments.len() > 1 {
                    let mut cur = String::new();
                    for seg in &segments[..segments.len() - 1] {
                        cur.push('/');
                        cur.push_str(seg);
                        vfs.dirs.entry(cur.clone()).or_insert_with(|| now.clone());
                    }
                }
                vfs.files.insert(
                    norm_path.to_owned(),
                    VirtualVaultFile {
                        modified_at: now,
                        data_b64: B64.encode(bytes),
                        size_bytes: bytes.len(),
                    },
                );
                self.save_vault_fs(vault, &vfs).await
            }
        }
    }

    fn list_ram(
        &self,
        segments: &[String],
        norm_dir_path: &str,
    ) -> Result<Vec<FileEntryView>, FilesError> {
        ensure_gnome_home_skeleton(&self.home_dir);
        let dir_path = self.resolve_ram_path(segments, false)?;
        let meta = fs::symlink_metadata(&dir_path)
            .map_err(|_| FilesError::NotFound(norm_dir_path.to_owned()))?;
        if !meta.file_type().is_dir() {
            return Err(FilesError::InvalidPath(format!(
                "'{norm_dir_path}' is not a directory"
            )));
        }

        let rd = fs::read_dir(&dir_path).map_err(|e| FilesError::Io(e.to_string()))?;
        let mut out = Vec::new();
        for entry_res in rd {
            let Ok(entry) = entry_res else { continue };
            let name_os = entry.file_name();
            let Some(name) = name_os.to_str() else {
                continue;
            };
            // Hide internal dot-directories like .browser-profile unless explicitly navigated
            if name.starts_with(".onionos_probe_") || name == ".browser-profile" {
                continue;
            }
            let Ok(emeta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if emeta.file_type().is_symlink() {
                // Never expose symlinks in file manager
                continue;
            }

            let child_vpath = if norm_dir_path == "/" {
                format!("/{name}")
            } else {
                format!("{norm_dir_path}/{name}")
            };

            let modified_at = emeta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .and_then(|d| DateTime::<Utc>::from_timestamp(d.as_secs() as i64, 0))
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| Utc::now().to_rfc3339());

            if emeta.is_dir() {
                out.push(FileEntryView {
                    name: name.to_owned(),
                    path: child_vpath,
                    kind: "dir".to_owned(),
                    size_bytes: 0,
                    modified_at,
                    mime: "inode/directory".to_owned(),
                });
            } else if emeta.is_file() {
                out.push(FileEntryView {
                    name: name.to_owned(),
                    path: child_vpath,
                    kind: "file".to_owned(),
                    size_bytes: emeta.len(),
                    modified_at,
                    mime: guess_mime(name).to_owned(),
                });
            }
        }
        Ok(out)
    }

    fn resolve_ram_path(
        &self,
        segments: &[String],
        allow_missing_leaf: bool,
    ) -> Result<PathBuf, FilesError> {
        fs::create_dir_all(&self.home_dir).map_err(|e| FilesError::Io(e.to_string()))?;
        let canon_home =
            fs::canonicalize(&self.home_dir).map_err(|e| FilesError::Io(e.to_string()))?;

        let mut cur = canon_home.clone();
        for (idx, seg) in segments.iter().enumerate() {
            cur.push(seg);
            match fs::symlink_metadata(&cur) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(FilesError::InvalidPath(
                            "Symlink traversal blocked".into(),
                        ));
                    }
                    let canon_cur =
                        fs::canonicalize(&cur).map_err(|e| FilesError::Io(e.to_string()))?;
                    if !canon_cur.starts_with(&canon_home) {
                        return Err(FilesError::InvalidPath(
                            "Path escaped home_dir boundary".into(),
                        ));
                    }
                }
                Err(_) => {
                    if !allow_missing_leaf && idx == segments.len() - 1 {
                        return Err(FilesError::NotFound(format!("/{}", segments.join("/"))));
                    }
                }
            }
        }
        Ok(cur)
    }

    async fn load_vault_fs(&self, vault: &VaultManager) -> Result<VirtualVaultFs, FilesError> {
        let blob_path = vault.vault_files_blob_path();
        if !blob_path.is_file() {
            // Verify session is unlocked before returning default virtual FS
            let empty = vault.encrypt_session_blob(VAULT_FILES_DOMAIN, b"{}").await?;
            let _ = empty;
            let vfs = VirtualVaultFs::default();
            self.save_vault_fs(vault, &vfs).await?;
            return Ok(vfs);
        }

        let raw = fs::read(&blob_path).map_err(|e| FilesError::Io(e.to_string()))?;
        let plain: Zeroizing<Vec<u8>> =
            vault.decrypt_session_blob(VAULT_FILES_DOMAIN, &raw).await?;
        let vfs: VirtualVaultFs = serde_json::from_slice(&plain)
            .map_err(|e| FilesError::Io(format!("Corrupted vault filesystem JSON: {e}")))?;
        Ok(vfs)
    }

    async fn save_vault_fs(
        &self,
        vault: &VaultManager,
        vfs: &VirtualVaultFs,
    ) -> Result<(), FilesError> {
        let json = Zeroizing::new(
            serde_json::to_vec(vfs).map_err(|e| FilesError::Io(e.to_string()))?,
        );
        let cipher = vault.encrypt_session_blob(VAULT_FILES_DOMAIN, &json).await?;
        atomic_write_restricted(&vault.vault_files_blob_path(), &cipher)?;
        Ok(())
    }
}

pub fn ensure_gnome_home_skeleton(home_dir: &Path) {
    let _ = fs::create_dir_all(home_dir);
    for folder in [
        "Documents",
        "Downloads",
        "Pictures",
        "OnionShare",
        "OnionShare/Dropzone",
    ] {
        let _ = fs::create_dir_all(home_dir.join(folder));
    }
    let welcome = home_dir.join("Welcome-OnionOS.md");
    if !welcome.exists() {
        let _ = fs::write(welcome, WELCOME_MD.as_bytes());
    }
}

pub fn normalize_virtual_path(raw: &str) -> Result<(String, Vec<String>), FilesError> {
    if raw.bytes().any(|b| b == 0 || b == b'\\') {
        return Err(FilesError::InvalidPath(
            "NUL bytes and backslashes are forbidden".into(),
        ));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return Ok(("/".to_owned(), Vec::new()));
    }

    let mut segments = Vec::new();
    for part in trimmed.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." || part.contains(':') || part.chars().any(char::is_control) {
            return Err(FilesError::InvalidPath(format!(
                "Forbidden path component '{part}'"
            )));
        }
        if part.len() > 200 {
            return Err(FilesError::InvalidPath("Path component too long".into()));
        }
        segments.push(part.to_owned());
    }

    if segments.is_empty() {
        Ok(("/".to_owned(), Vec::new()))
    } else {
        Ok((format!("/{}", segments.join("/")), segments))
    }
}

fn list_virtual_entries(
    vfs: &VirtualVaultFs,
    norm_dir_path: &str,
) -> Result<Vec<FileEntryView>, FilesError> {
    if norm_dir_path != "/" && !vfs.dirs.contains_key(norm_dir_path) {
        return Err(FilesError::NotFound(norm_dir_path.to_owned()));
    }

    let prefix = if norm_dir_path == "/" {
        "/".to_owned()
    } else {
        format!("{norm_dir_path}/")
    };

    let mut seen_dirs = BTreeSet::new();
    let mut out = Vec::new();

    for (dpath, mod_at) in &vfs.dirs {
        if dpath == norm_dir_path || !dpath.starts_with(&prefix) {
            continue;
        }
        let rest = &dpath[prefix.len()..];
        let Some(direct_child) = rest.split('/').next().filter(|s| !s.is_empty()) else {
            continue;
        };
        if seen_dirs.insert(direct_child.to_owned()) {
            let full = if norm_dir_path == "/" {
                format!("/{direct_child}")
            } else {
                format!("{norm_dir_path}/{direct_child}")
            };
            out.push(FileEntryView {
                name: direct_child.to_owned(),
                path: full,
                kind: "dir".to_owned(),
                size_bytes: 0,
                modified_at: mod_at.clone(),
                mime: "inode/directory".to_owned(),
            });
        }
    }

    for (fpath, vf) in &vfs.files {
        if !fpath.starts_with(&prefix) {
            continue;
        }
        let rest = &fpath[prefix.len()..];
        if rest.is_empty() || rest.contains('/') {
            continue;
        }
        out.push(FileEntryView {
            name: rest.to_owned(),
            path: fpath.clone(),
            kind: "file".to_owned(),
            size_bytes: vf.size_bytes as u64,
            modified_at: vf.modified_at.clone(),
            mime: guess_mime(rest).to_owned(),
        });
    }

    Ok(out)
}

fn decode_write_payload(
    text: Option<&str>,
    data_b64: Option<&str>,
) -> Result<Vec<u8>, FilesError> {
    if let Some(b64_raw) = data_b64.filter(|s| !s.trim().is_empty()) {
        let trimmed = b64_raw.trim();
        let body = match trimmed.find(";base64,") {
            Some(idx) if trimmed.starts_with("data:") => &trimmed[idx + 8..],
            _ => trimmed,
        };
        let clean: Vec<u8> = body.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        if clean.len() > (MAX_FILE_WRITE_BYTES * 4 / 3) + 1024 {
            return Err(FilesError::PayloadTooLarge);
        }
        return B64
            .decode(&clean)
            .map_err(|e| FilesError::InvalidPath(format!("Invalid Base64 content: {e}")));
    }
    if let Some(txt) = text {
        return Ok(txt.as_bytes().to_vec());
    }
    Ok(Vec::new())
}

fn delete_ram_dir_recursive(dir: &Path, shred: bool) -> Result<(), FilesError> {
    let rd = fs::read_dir(dir).map_err(|e| FilesError::Io(e.to_string()))?;
    for entry_res in rd {
        let entry = entry_res.map_err(|e| FilesError::Io(e.to_string()))?;
        let p = entry.path();
        let meta = fs::symlink_metadata(&p).map_err(|e| FilesError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() {
            let _ = fs::remove_file(&p);
        } else if meta.is_dir() {
            delete_ram_dir_recursive(&p, shred)?;
        } else if shred {
            let _ = overwrite_and_delete_file(&p);
        } else {
            let _ = fs::remove_file(&p);
        }
    }
    fs::remove_dir(dir).map_err(|e| FilesError::Io(e.to_string()))
}

fn derive_clean_filename(name: &str) -> String {
    match name.rfind('.') {
        Some(idx) if idx > 0 && idx + 1 < name.len() => {
            format!("{}.clean.{}", &name[..idx], &name[idx + 1..])
        }
        _ => format!("{name}.clean"),
    }
}

pub fn guess_mime(filename: &str) -> &'static str {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".md") || lower.ends_with(".markdown") {
        "text/markdown"
    } else if lower.ends_with(".txt") || lower.ends_with(".log") {
        "text/plain"
    } else if lower.ends_with(".json") {
        "application/json"
    } else if lower.ends_with(".otseal") {
        "application/x-onionos-pqc-seal"
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".svg") {
        "image/svg+xml"
    } else if lower.ends_with(".pdf") {
        "application/pdf"
    } else if lower.ends_with(".wav") {
        "audio/wav"
    } else if lower.ends_with(".mp3") {
        "audio/mpeg"
    } else {
        "application/octet-stream"
    }
}
