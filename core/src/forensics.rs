//! Anti-Forensics Binary Metadata Sanitizer (`onion-clean`), Posture Auditor & RAM Wipe Engine
//! Pure-Rust binary parsers for JPEG, PNG, PDF, WAV and MP3 without external C libraries.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::vault::overwrite_and_delete_file;

const MAX_SCRUB_BYTES: usize = 20 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ForensicsError {
    #[error("Invalid Base64 payload: {0}")]
    InvalidBase64(String),
    #[error("Payload exceeds maximum forensic scrub size ({MAX_SCRUB_BYTES} bytes)")]
    PayloadTooLarge,
    #[error("Unsupported binary format (supported: JPEG, PNG, PDF, WAV, MP3)")]
    UnsupportedFormat,
    #[error("Malformed {format} binary structure: {reason}")]
    Malformed {
        format: &'static str,
        reason: String,
    },
    #[error("Refusing unsafe wipe target outside dedicated home directory: {0}")]
    UnsafeWipeTarget(String),
    #[error("Forensics I/O error: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScrubReport {
    pub format: String,
    pub original_bytes: usize,
    pub clean_bytes: usize,
    pub removed_segments: Vec<String>,
    pub sha256_before: String,
    pub sha256_after: String,
    pub clean_b64: String,
}

#[derive(Debug, Clone)]
pub struct ScrubBinaryOutcome {
    pub format: &'static str,
    pub original_bytes: usize,
    pub clean_bytes_vec: Vec<u8>,
    pub removed_segments: Vec<String>,
    pub sha256_before: String,
    pub sha256_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForensicsAuditReport {
    pub dumpable_zero: bool,
    pub core_ulimit_zero: bool,
    pub home_dir: String,
    pub home_writable: bool,
    pub home_on_tmpfs: bool,
    pub rootfs_readonly: bool,
    pub non_root_uid: bool,
    pub uid: u32,
    pub cap_bnd_zero: bool,
    pub no_new_privs: bool,
    pub files_in_home: usize,
}

pub fn scrub_base64(filename: &str, data_b64: &str) -> Result<ScrubReport, ForensicsError> {
    let trimmed = data_b64.trim();
    let payload_str = match trimmed.find(";base64,") {
        Some(idx) if trimmed.starts_with("data:") => &trimmed[idx + 8..],
        _ => trimmed,
    };

    let filtered: Vec<u8> = payload_str
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if filtered.is_empty() {
        return Err(ForensicsError::InvalidBase64("Empty input".into()));
    }
    if filtered.len() > (MAX_SCRUB_BYTES * 4 / 3) + 1024 {
        return Err(ForensicsError::PayloadTooLarge);
    }

    let raw = B64
        .decode(&filtered)
        .map_err(|e| ForensicsError::InvalidBase64(e.to_string()))?;

    let outcome = scrub_bytes(filename, &raw)?;
    let clean_len = outcome.clean_bytes_vec.len();
    let clean_b64 = B64.encode(&outcome.clean_bytes_vec);

    Ok(ScrubReport {
        format: outcome.format.to_owned(),
        original_bytes: outcome.original_bytes,
        clean_bytes: clean_len,
        removed_segments: outcome.removed_segments,
        sha256_before: outcome.sha256_before,
        sha256_after: outcome.sha256_after,
        clean_b64,
    })
}

pub fn scrub_bytes(filename: &str, data: &[u8]) -> Result<ScrubBinaryOutcome, ForensicsError> {
    if data.is_empty() {
        return Err(ForensicsError::UnsupportedFormat);
    }
    if data.len() > MAX_SCRUB_BYTES {
        return Err(ForensicsError::PayloadTooLarge);
    }

    let sha256_before = sha256_hex(data);
    let lower_name = filename.to_ascii_lowercase();

    let (format, clean_bytes_vec, removed_segments) =
        if data.len() >= 4 && data[0] == 0xFF && data[1] == 0xD8 {
            let (clean, segs) = scrub_jpeg(data)?;
            ("jpeg", clean, segs)
        } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
            let (clean, segs) = scrub_png(data)?;
            ("png", clean, segs)
        } else if data.starts_with(b"%PDF-") {
            let (clean, segs) = scrub_pdf(data)?;
            ("pdf", clean, segs)
        } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WAVE" {
            let (clean, segs) = scrub_wav(data)?;
            ("wav", clean, segs)
        } else if data.starts_with(b"ID3")
            || (data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0)
            || lower_name.ends_with(".mp3")
        {
            let (clean, segs) = scrub_mp3(data)?;
            ("mp3", clean, segs)
        } else {
            return Err(ForensicsError::UnsupportedFormat);
        };

    let sha256_after = sha256_hex(&clean_bytes_vec);

    Ok(ScrubBinaryOutcome {
        format,
        original_bytes: data.len(),
        clean_bytes_vec,
        removed_segments,
        sha256_before,
        sha256_after,
    })
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Strips APP1..APP15 (EXIF/GPS/XMP/IPTC/ICC), COM comments, JFIF thumbnails and trailing bytes.
fn scrub_jpeg(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), ForensicsError> {
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return Err(ForensicsError::Malformed {
            format: "jpeg",
            reason: "Missing SOI marker 0xFFD8".into(),
        });
    }

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&[0xFF, 0xD8]);
    let mut removed = Vec::new();
    let mut pos = 2usize;
    let mut saw_eoi = false;

    while pos < data.len() {
        if data[pos] != 0xFF {
            return Err(ForensicsError::Malformed {
                format: "jpeg",
                reason: format!("Expected 0xFF marker prefix at offset {pos}"),
            });
        }
        while pos < data.len() && data[pos] == 0xFF {
            pos += 1;
        }
        if pos >= data.len() {
            break;
        }
        let marker = data[pos];
        pos += 1;

        if marker == 0xD9 {
            out.extend_from_slice(&[0xFF, 0xD9]);
            saw_eoi = true;
            if pos < data.len() {
                removed.push(format!("TrailingAfterEOI ({}B)", data.len() - pos));
            }
            break;
        }

        if marker == 0x00 || marker == 0x01 || (0xD0..=0xD8).contains(&marker) {
            out.extend_from_slice(&[0xFF, marker]);
            continue;
        }

        if pos + 2 > data.len() {
            return Err(ForensicsError::Malformed {
                format: "jpeg",
                reason: "Truncated marker segment length".into(),
            });
        }
        let seg_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        if seg_len < 2 || pos.checked_add(seg_len).is_none_or(|end| end > data.len()) {
            return Err(ForensicsError::Malformed {
                format: "jpeg",
                reason: format!("Invalid segment length {seg_len} for marker 0x{marker:02X}"),
            });
        }

        if marker == 0xDA {
            // SOS (Start of Scan): copy SOS header + entropy-coded scan until next marker
            out.extend_from_slice(&[0xFF, 0xDA]);
            out.extend_from_slice(&data[pos..pos + seg_len]);
            pos += seg_len;

            let scan_start = pos;
            while pos < data.len() {
                if data[pos] == 0xFF {
                    let ff_start = pos;
                    let mut look = pos + 1;
                    while look < data.len() && data[look] == 0xFF {
                        look += 1;
                    }
                    if look >= data.len() {
                        pos = data.len();
                        break;
                    }
                    let next_byte = data[look];
                    if next_byte == 0x00 || (0xD0..=0xD7).contains(&next_byte) {
                        pos = look + 1;
                        continue;
                    } else {
                        // Real marker reached (e.g. EOI 0xFFD9 or progressive next scan)
                        pos = ff_start;
                        break;
                    }
                } else {
                    pos += 1;
                }
            }
            out.extend_from_slice(&data[scan_start..pos]);
        } else if marker == 0xE0 {
            // APP0: preserve clean minimal 16-byte JFIF header without embedded thumbnail
            let body = &data[pos + 2..pos + seg_len];
            if body.len() >= 14 && &body[0..5] == b"JFIF\0" {
                out.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
                out.extend_from_slice(&body[0..12]);
                out.extend_from_slice(&[0x00, 0x00]); // x_thumbnail = 0, y_thumbnail = 0
                if seg_len > 16 {
                    removed.push(format!("APP0 (JFIF Thumbnail: {}B)", seg_len - 16));
                }
            } else {
                removed.push(format!("APP0 (JFXX/Custom: {}B)", seg_len));
            }
            pos += seg_len;
        } else if (0xE1..=0xEF).contains(&marker) {
            let app_idx = marker - 0xE0;
            let label = match app_idx {
                1 => format!("APP1 (EXIF/XMP: {seg_len}B)"),
                2 => format!("APP2 (ICC/FPXR: {seg_len}B)"),
                13 => format!("APP13 (IPTC/Photoshop: {seg_len}B)"),
                14 => format!("APP14 (Adobe: {seg_len}B)"),
                _ => format!("APP{app_idx} ({seg_len}B)"),
            };
            removed.push(label);
            pos += seg_len;
        } else if marker == 0xFE {
            removed.push(format!("COM (Comment: {seg_len}B)"));
            pos += seg_len;
        } else {
            out.extend_from_slice(&[0xFF, marker]);
            out.extend_from_slice(&data[pos..pos + seg_len]);
            pos += seg_len;
        }
    }

    if !saw_eoi {
        return Err(ForensicsError::Malformed {
            format: "jpeg",
            reason: "Missing EOI marker 0xFFD9".into(),
        });
    }

    Ok((out, removed))
}

/// Keeps critical/safe PNG chunks (`IHDR`, `PLTE`, `IDAT`, `IEND`, `tRNS`) and strips ancillary metadata.
fn scrub_png(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), ForensicsError> {
    const PNG_SIG: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if !data.starts_with(PNG_SIG) {
        return Err(ForensicsError::Malformed {
            format: "png",
            reason: "Missing PNG signature".into(),
        });
    }

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(PNG_SIG);
    let mut removed = Vec::new();
    let mut pos = 8usize;
    let mut saw_iend = false;

    while pos < data.len() {
        if pos + 12 > data.len() {
            return Err(ForensicsError::Malformed {
                format: "png",
                reason: "Truncated PNG chunk header".into(),
            });
        }
        let chunk_len = u32::from_be_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]) as usize;
        let total_chunk = chunk_len
            .checked_add(12)
            .ok_or_else(|| ForensicsError::Malformed {
                format: "png",
                reason: "PNG chunk length overflow".into(),
            })?;
        if pos.checked_add(total_chunk).is_none_or(|end| end > data.len()) {
            return Err(ForensicsError::Malformed {
                format: "png",
                reason: "PNG chunk exceeds file bounds".into(),
            });
        }

        let chunk_type = &data[pos + 4..pos + 8];
        let keep = matches!(
            chunk_type,
            b"IHDR" | b"PLTE" | b"IDAT" | b"IEND" | b"tRNS"
        );

        if keep {
            out.extend_from_slice(&data[pos..pos + total_chunk]);
        } else {
            let name = String::from_utf8_lossy(chunk_type);
            removed.push(format!("{name} ({total_chunk}B)"));
        }
        pos += total_chunk;

        if chunk_type == b"IEND" {
            saw_iend = true;
            if pos < data.len() {
                removed.push(format!("TrailingAfterIEND ({}B)", data.len() - pos));
            }
            break;
        }
    }

    if !saw_iend {
        return Err(ForensicsError::Malformed {
            format: "png",
            reason: "Missing IEND chunk".into(),
        });
    }

    Ok((out, removed))
}

/// Redacts PDF `/Info` keys and `<x:xmpmeta...</x:xmpmeta>` packets in-place with spaces
/// of identical byte length so PDF `xref` offsets remain 100% intact.
fn scrub_pdf(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), ForensicsError> {
    if !data.starts_with(b"%PDF-") || data.len() < 16 {
        return Err(ForensicsError::Malformed {
            format: "pdf",
            reason: "Invalid PDF header".into(),
        });
    }

    let mut out = data.to_vec();
    let mut removed = Vec::new();

    const PDF_KEYS: &[&str] = &[
        "/Author",
        "/Creator",
        "/Producer",
        "/Title",
        "/Subject",
        "/Keywords",
        "/CreationDate",
        "/ModDate",
    ];

    for &key in PDF_KEYS {
        let kb = key.as_bytes();
        let mut cursor = 0usize;
        while cursor + kb.len() < out.len() {
            let Some(rel) = find_subslice(&out[cursor..], kb) else {
                break;
            };
            let key_pos = cursor + rel;
            let mut val_pos = key_pos + kb.len();

            // Ensure key boundary (not a longer key prefix like /AuthorExtra)
            if val_pos < out.len() && out[val_pos].is_ascii_alphanumeric() {
                cursor = val_pos;
                continue;
            }

            while val_pos < out.len() && matches!(out[val_pos], b' ' | b'\t' | b'\r' | b'\n') {
                val_pos += 1;
            }
            if val_pos >= out.len() {
                break;
            }

            if out[val_pos] == b'(' {
                // Literal string (...) with nested parens and backslash escapes
                let content_start = val_pos + 1;
                let mut depth = 1usize;
                let mut p = content_start;
                while p < out.len() && depth > 0 {
                    if out[p] == b'\\' {
                        p = (p + 2).min(out.len());
                        continue;
                    }
                    if out[p] == b'(' {
                        depth += 1;
                    } else if out[p] == b')' {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    p += 1;
                }
                if depth == 0 && p >= content_start {
                    let span = &mut out[content_start..p];
                    if span.iter().any(|&b| b != b' ') {
                        let len = span.len();
                        span.fill(b' ');
                        removed.push(format!("PDF {key} ({len}B redacted)"));
                    }
                    cursor = p + 1;
                    continue;
                }
            } else if out[val_pos] == b'<'
                && (val_pos + 1 >= out.len() || out[val_pos + 1] != b'<')
            {
                // Hex string <...>
                let content_start = val_pos + 1;
                if let Some(end_rel) = out[content_start..].iter().position(|&b| b == b'>') {
                    let content_end = content_start + end_rel;
                    let span = &mut out[content_start..content_end];
                    if !span.is_empty() {
                        let len = span.len();
                        for (idx, b) in span.iter_mut().enumerate() {
                            *b = if idx % 2 == 0 { b'2' } else { b'0' };
                        }
                        if len % 2 == 1 {
                            span[len - 1] = b'0';
                        }
                        removed.push(format!("PDF {key} hex ({len}B redacted)"));
                    }
                    cursor = content_end + 1;
                    continue;
                }
            }
            cursor = val_pos + 1;
        }
    }

    // Redact XMP packets (<x:xmpmeta ... </x:xmpmeta>) with spaces of identical length
    for (open_tag, close_tag, label) in [
        (&b"<x:xmpmeta"[..], &b"</x:xmpmeta>"[..], "XMP xmpmeta"),
        (&b"<?xpacket begin"[..], &b"<?xpacket end"[..], "XMP xpacket"),
    ] {
        let mut search = 0usize;
        while search + open_tag.len() < out.len() {
            let Some(start_rel) = find_subslice(&out[search..], open_tag) else {
                break;
            };
            let start = search + start_rel;
            let Some(end_rel) = find_subslice(&out[start..], close_tag) else {
                break;
            };
            let mut end = start + end_rel + close_tag.len();
            if label == "XMP xpacket" {
                if let Some(gt_rel) = out[end..].iter().take(64).position(|&b| b == b'>') {
                    end += gt_rel + 1;
                }
            }
            let len = end - start;
            out[start..end].fill(b' ');
            removed.push(format!("{label} ({len}B redacted)"));
            search = end;
        }
    }

    Ok((out, removed))
}

/// Strips `LIST`, `id3 `, `bext`, `iXML`, `DISP`, `JUNK` chunks in WAV and updates RIFF header size.
fn scrub_wav(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), ForensicsError> {
    if data.len() < 12 || &data[0..4] != b"RIFF" || &data[8..12] != b"WAVE" {
        return Err(ForensicsError::Malformed {
            format: "wav",
            reason: "Missing RIFF/WAVE header".into(),
        });
    }

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(b"RIFF\0\0\0\0WAVE");
    let mut removed = Vec::new();
    let mut pos = 12usize;
    let mut saw_fmt = false;

    while pos + 8 <= data.len() {
        let chunk_id = &data[pos..pos + 4];
        let chunk_size = u32::from_le_bytes([
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]) as usize;
        let payload_end = pos
            .checked_add(8)
            .and_then(|v| v.checked_add(chunk_size))
            .ok_or_else(|| ForensicsError::Malformed {
                format: "wav",
                reason: "WAV chunk size overflow".into(),
            })?;
        if payload_end > data.len() {
            return Err(ForensicsError::Malformed {
                format: "wav",
                reason: "WAV subchunk exceeds file size".into(),
            });
        }

        let keep = matches!(chunk_id, b"fmt " | b"data" | b"fact");
        if keep {
            if chunk_id == b"fmt " {
                saw_fmt = true;
            }
            out.extend_from_slice(&data[pos..payload_end]);
            if chunk_size % 2 == 1 {
                out.push(0x00);
            }
        } else {
            let name = String::from_utf8_lossy(chunk_id);
            removed.push(format!("WAV {} ({}B)", name.trim(), chunk_size + 8));
        }

        let pad = chunk_size & 1;
        pos = payload_end.saturating_add(pad).min(data.len());
    }

    if !saw_fmt {
        return Err(ForensicsError::Malformed {
            format: "wav",
            reason: "Missing WAV fmt chunk".into(),
        });
    }

    let riff_len = (out.len().saturating_sub(8)) as u32;
    out[4..8].copy_from_slice(&riff_len.to_le_bytes());

    Ok((out, removed))
}

/// Strips leading ID3v2 header(s) and trailing ID3v1 `TAG` trailer in MP3 streams.
fn scrub_mp3(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), ForensicsError> {
    let mut start = 0usize;
    let mut end = data.len();
    let mut removed = Vec::new();

    while start + 10 <= end && &data[start..start + 3] == b"ID3" {
        let ver_major = data[start + 3];
        let flags = data[start + 5];
        let b6 = data[start + 6];
        let b7 = data[start + 7];
        let b8 = data[start + 8];
        let b9 = data[start + 9];
        if (b6 | b7 | b8 | b9) & 0x80 != 0 {
            return Err(ForensicsError::Malformed {
                format: "mp3",
                reason: "Invalid synchsafe integer in ID3v2 header".into(),
            });
        }
        let tag_body = (((b6 as usize) & 0x7F) << 21)
            | (((b7 as usize) & 0x7F) << 14)
            | (((b8 as usize) & 0x7F) << 7)
            | ((b9 as usize) & 0x7F);
        let footer = if (flags & 0x10) != 0 { 10usize } else { 0usize };
        let total = 10usize.saturating_add(tag_body).saturating_add(footer);
        if start + total > end {
            return Err(ForensicsError::Malformed {
                format: "mp3",
                reason: "Truncated ID3v2 tag".into(),
            });
        }
        removed.push(format!("ID3v2.{ver_major} ({total}B)"));
        start += total;
    }

    if end.saturating_sub(start) >= 128 && &data[end - 128..end - 125] == b"TAG" {
        removed.push("ID3v1 TAG (128B)".to_owned());
        end -= 128;
    }

    if start >= end {
        return Err(ForensicsError::Malformed {
            format: "mp3",
            reason: "No MPEG audio frames remaining after ID3 removal".into(),
        });
    }

    Ok((data[start..end].to_vec(), removed))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn check_dir_writable(dir: &Path) -> bool {
    if fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(".onionos_probe_{}", Uuid::new_v4()));
    match OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(mut f) => {
            let ok = f.write_all(b"ok").is_ok();
            drop(f);
            let _ = fs::remove_file(&probe);
            ok
        }
        Err(_) => false,
    }
}

pub fn count_dir_stats(dir: &Path) -> (usize, u64) {
    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(curr) = stack.pop() {
        let Ok(rd) = fs::read_dir(&curr) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_dir() {
                stack.push(path);
            } else {
                files = files.saturating_add(1);
                bytes = bytes.saturating_add(meta.len());
            }
        }
    }
    (files, bytes)
}

pub fn audit_posture(home_dir: &Path) -> ForensicsAuditReport {
    let home_writable = check_dir_writable(home_dir);
    let (files_in_home, _) = count_dir_stats(home_dir);

    #[cfg(target_os = "linux")]
    let dumpable_zero = {
        // SAFETY: PR_GET_DUMPABLE reads the current process dumpable flag with no pointer args.
        unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0 }
    };
    #[cfg(not(target_os = "linux"))]
    let dumpable_zero = false;

    #[cfg(unix)]
    let (core_ulimit_zero, uid) = {
        let mut rlim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: rlim points to valid stack-allocated libc::rlimit for RLIMIT_CORE query.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) };
        let core_zero = rc == 0 && rlim.rlim_cur == 0;
        // SAFETY: geteuid is thread-safe and takes no arguments.
        let current_uid = unsafe { libc::geteuid() };
        (core_zero, current_uid)
    };
    #[cfg(not(unix))]
    let (core_ulimit_zero, uid) = (false, 10014u32);

    let (rootfs_readonly, home_on_tmpfs) = inspect_linux_mounts(home_dir);
    let caps = crate::supervisor::read_proc_security_caps();

    ForensicsAuditReport {
        dumpable_zero,
        core_ulimit_zero,
        home_dir: home_dir.display().to_string(),
        home_writable,
        home_on_tmpfs,
        rootfs_readonly,
        non_root_uid: uid != 0,
        uid,
        cap_bnd_zero: caps.cap_bnd_zero,
        no_new_privs: caps.no_new_privs,
        files_in_home,
    }
}

fn inspect_linux_mounts(home_dir: &Path) -> (bool, bool) {
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else {
        return (false, false);
    };
    let home_str = home_dir.to_string_lossy();
    let mut root_ro = false;
    let mut home_tmpfs = false;

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let mount_point = parts[1];
        let fstype = parts[2];
        let opts = parts[3];
        if mount_point == "/" {
            root_ro = opts.split(',').any(|o| o == "ro");
        }
        if mount_point == home_str.as_ref() && fstype == "tmpfs" {
            home_tmpfs = true;
        }
    }
    (root_ro, home_tmpfs)
}

/// Overwrites with CSPRNG random bytes & deletes all files inside `home_dir` without touching
/// anything outside `home_dir` or following symlinks.
pub fn wipe_home_directory(home_dir: &Path) -> Result<(usize, u64), ForensicsError> {
    let normal_parts = home_dir
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count();
    if normal_parts < 2 {
        return Err(ForensicsError::UnsafeWipeTarget(
            home_dir.display().to_string(),
        ));
    }

    if !home_dir.exists() {
        return Ok((0, 0));
    }

    let canon_root = fs::canonicalize(home_dir).map_err(|e| ForensicsError::Io(e.to_string()))?;
    let canon_normal = canon_root
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count();
    if canon_normal < 2 {
        return Err(ForensicsError::UnsafeWipeTarget(
            canon_root.display().to_string(),
        ));
    }

    wipe_children_recursive(&canon_root, &canon_root)
}

fn wipe_children_recursive(
    root: &Path,
    current: &Path,
) -> Result<(usize, u64), ForensicsError> {
    if !current.starts_with(root) {
        return Err(ForensicsError::UnsafeWipeTarget(
            current.display().to_string(),
        ));
    }

    let mut burned_files = 0usize;
    let mut burned_bytes = 0u64;

    let rd = fs::read_dir(current).map_err(|e| ForensicsError::Io(e.to_string()))?;
    for entry_res in rd {
        let entry = entry_res.map_err(|e| ForensicsError::Io(e.to_string()))?;
        let path = entry.path();
        if !path.starts_with(root) {
            continue;
        }
        let meta = fs::symlink_metadata(&path).map_err(|e| ForensicsError::Io(e.to_string()))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            let _ = fs::remove_file(&path);
            burned_files = burned_files.saturating_add(1);
        } else if ft.is_dir() {
            let (sub_files, sub_bytes) = wipe_children_recursive(root, &path)?;
            burned_files = burned_files.saturating_add(sub_files);
            burned_bytes = burned_bytes.saturating_add(sub_bytes);
            let _ = fs::remove_dir(&path);
        } else if ft.is_file() {
            let sz = meta.len();
            if overwrite_and_delete_file(&path).is_ok() {
                burned_files = burned_files.saturating_add(1);
                burned_bytes = burned_bytes.saturating_add(sz);
            } else {
                // Fallback direct unlink if read-only permission bit was set on file inside tmpfs
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
                }
                #[cfg(windows)]
                #[allow(clippy::permissions_set_readonly_false)]
                {
                    if let Ok(m) = fs::metadata(&path) {
                        let mut perms = m.permissions();
                        if perms.readonly() {
                            perms.set_readonly(false);
                            let _ = fs::set_permissions(&path, perms);
                        }
                    }
                }
                let mut scratch = [0u8; 64];
                OsRng.fill_bytes(&mut scratch);
                let _ = overwrite_and_delete_file(&path);
                burned_files = burned_files.saturating_add(1);
                burned_bytes = burned_bytes.saturating_add(sz);
            }
        }
    }

    Ok((burned_files, burned_bytes))
}
