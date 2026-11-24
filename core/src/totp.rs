//! RFC 6238 TOTP 2FA Authenticator (HMAC-SHA1, 30s step, 6 digits) & High-Entropy Secret Generator
//! Zeroizes decoded Base32 keys in RAM immediately after HMAC computation.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use zeroize::Zeroizing;

pub const TOTP_PERIOD_SECS: u64 = 30;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("Empty or missing TOTP secret")]
    EmptySecret,
    #[error("Invalid RFC 4648 Base32 character in TOTP secret")]
    InvalidBase32,
    #[error("Invalid otpauth:// URI (missing secret parameter)")]
    InvalidOtpAuthUri,
    #[error("Unsupported secret generator mode (expected 'passphrase' or 'password')")]
    InvalidGeneratorMode,
    #[error("HMAC key initialization error")]
    HmacInit,
}

#[derive(Debug, Clone)]
pub struct TotpSnapshot {
    pub code: String,
    pub period_secs: u64,
    pub remaining_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpPreviewResponse {
    pub valid: bool,
    pub code: String,
    pub period_secs: u64,
    pub remaining_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultTotpCodeEntry {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub code: String,
    pub period_secs: u64,
    pub remaining_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCodesResponse {
    pub server_epoch_secs: u64,
    pub codes: Vec<VaultTotpCodeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedSecretResponse {
    pub mode: String,
    pub secret: String,
    pub entropy_bits: u32,
}

/// Curated 256-word EFF-inspired high-distinctiveness wordlist (exact 8 bits/word, zero modulo bias).
const WORDLIST_256: [&str; 256] = [
    "acorn", "agate", "alder", "alloy", "amber", "anchor", "anvil", "apex",
    "apron", "arbor", "argon", "armor", "arrow", "aspen", "atlas", "atom",
    "aurora", "avalanche", "axiom", "azure", "badge", "basalt", "beacon", "birch",
    "bison", "blade", "blaze", "bloom", "bolt", "bonsai", "boulder", "breeze",
    "bridge", "bronze", "brook", "buckle", "bunker", "butte", "cabin", "cable",
    "cactus", "cairn", "caliber", "canopy", "canyon", "carbon", "cargo", "caribou",
    "cascade", "castle", "cedar", "chalice", "channel", "charcoal", "chisel", "chrome",
    "cipher", "citadel", "citrus", "cliff", "cloak", "clover", "cobalt", "comet",
    "compass", "condor", "copper", "coral", "corona", "cortex", "cosmos", "cougar",
    "cradle", "crane", "crater", "creek", "crest", "crimson", "crystal", "cyclone",
    "cypress", "dagger", "dawn", "delta", "desert", "diamond", "dipole", "dolphin",
    "domain", "dragon", "drift", "dynamo", "eagle", "ebony", "echo", "eclipse",
    "ember", "emerald", "enigma", "epoch", "equinox", "estuary", "ether", "falcon",
    "fathom", "feldspar", "ferry", "fiber", "fjord", "flame", "flint", "flora",
    "flux", "forest", "forge", "fossil", "foundry", "frost", "fusion", "galaxy",
    "galleon", "garnet", "gateway", "gazelle", "gecko", "geyser", "glacier", "glade",
    "granite", "griffin", "grove", "harbor", "harvest", "hawk", "hazel", "hearth",
    "helium", "helix", "heron", "horizon", "husky", "hydra", "ibex", "icicle",
    "indigo", "ingot", "inlet", "iodine", "iron", "island", "ivory", "jacket",
    "jade", "jaguar", "jasper", "javelin", "juniper", "karma", "kayak", "kestrel",
    "kernel", "keystone", "kiln", "kinetic", "kraken", "krypton", "lagoon", "lantern",
    "larch", "laser", "latch", "lattice", "laurel", "lava", "ledger", "legend",
    "lemur", "linen", "lithium", "locus", "lotus", "lynx", "magnet", "magma",
    "mantle", "maple", "marble", "mariner", "matrix", "meadow", "mercury", "mesa",
    "meteor", "mica", "mirage", "mistral", "monolith", "monsoon", "mosaic", "nebula",
    "nectar", "neon", "nexus", "nickel", "nimbus", "nitrogen", "nomad", "nova",
    "nutmeg", "oasis", "obsidian", "ocean", "ochre", "octave", "olive", "omega",
    "onyx", "opal", "orbit", "orchid", "osprey", "otter", "oxide", "ozone",
    "palisade", "panther", "paradox", "pebble", "pelican", "pendulum", "phantom", "phoenix",
    "photon", "pillar", "pine", "pioneer", "pixel", "planet", "plasma", "platinum",
    "plume", "polar", "poppy", "portal", "prism", "proton", "pulsar", "pyrite",
    "python", "quantum", "quartz", "quasar", "quiver", "radon", "raptor", "raven",
];

pub fn current_unix_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Validates and normalizes either an `otpauth://` URI or a Base32 TOTP secret.
pub fn normalize_totp_secret(raw: &str) -> Result<Zeroizing<String>, TotpError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(TotpError::EmptySecret);
    }

    let extracted = if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        let parsed = reqwest::Url::parse(trimmed).map_err(|_| TotpError::InvalidOtpAuthUri)?;
        let mut found: Option<String> = None;
        for (k, v) in parsed.query_pairs() {
            if k.eq_ignore_ascii_case("secret") && !v.trim().is_empty() {
                found = Some(v.into_owned());
                break;
            }
        }
        found.ok_or(TotpError::InvalidOtpAuthUri)?
    } else {
        trimmed.to_owned()
    };

    let mut clean = Zeroizing::new(String::with_capacity(extracted.len()));
    for ch in extracted.chars() {
        if matches!(ch, ' ' | '-' | '\t' | '\r' | '\n' | '=') {
            continue;
        }
        let upper = ch.to_ascii_uppercase();
        if matches!(upper, 'A'..='Z' | '2'..='7') {
            clean.push(upper);
        } else {
            return Err(TotpError::InvalidBase32);
        }
    }

    if clean.is_empty() {
        return Err(TotpError::EmptySecret);
    }

    let decoded = decode_base32_clean(&clean)?;
    if decoded.is_empty() {
        return Err(TotpError::EmptySecret);
    }

    Ok(clean)
}

pub fn decode_base32_rfc4648(raw: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let norm = normalize_totp_secret(raw)?;
    decode_base32_clean(&norm)
}

fn decode_base32_clean(clean_upper: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut out = Zeroizing::new(Vec::with_capacity(clean_upper.len() * 5 / 8 + 1));
    let mut bit_buf: u64 = 0;
    let mut bits_in_buf: u32 = 0;

    for b in clean_upper.bytes() {
        let val: u64 = match b {
            b'A'..=b'Z' => (b - b'A') as u64,
            b'2'..=b'7' => (b - b'2' + 26) as u64,
            _ => return Err(TotpError::InvalidBase32),
        };
        bit_buf = (bit_buf << 5) | val;
        bits_in_buf += 5;
        if bits_in_buf >= 8 {
            bits_in_buf -= 8;
            out.push(((bit_buf >> bits_in_buf) & 0xFF) as u8);
        }
    }

    Ok(out)
}

/// Computes RFC 6238 6-digit HMAC-SHA1 TOTP code for `epoch_secs`.
pub fn compute_totp_at(raw_secret: &str, epoch_secs: u64) -> Result<TotpSnapshot, TotpError> {
    let key_bytes = decode_base32_rfc4648(raw_secret)?;
    let counter = epoch_secs / TOTP_PERIOD_SECS;
    let remaining_secs = TOTP_PERIOD_SECS - (epoch_secs % TOTP_PERIOD_SECS);

    let mut mac = HmacSha1::new_from_slice(&key_bytes).map_err(|_| TotpError::HmacInit)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[19] & 0x0F) as usize;
    let bin_code = (((digest[offset] & 0x7F) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    let otp = bin_code % 1_000_000;

    Ok(TotpSnapshot {
        code: format!("{otp:06}"),
        period_secs: TOTP_PERIOD_SECS,
        remaining_secs,
    })
}

pub fn preview_totp(raw_secret: &str) -> Result<TotpPreviewResponse, TotpError> {
    let now = current_unix_epoch_secs();
    let snap = compute_totp_at(raw_secret, now)?;
    Ok(TotpPreviewResponse {
        valid: true,
        code: snap.code,
        period_secs: snap.period_secs,
        remaining_secs: snap.remaining_secs,
    })
}

pub fn generate_secret(
    mode: &str,
    requested_length: Option<usize>,
) -> Result<GeneratedSecretResponse, TotpError> {
    let clean_mode = mode.trim().to_ascii_lowercase();
    match clean_mode.as_str() {
        "passphrase" => {
            let word_count = requested_length.unwrap_or(6).clamp(4, 12);
            let mut idx_bytes = Zeroizing::new(vec![0u8; word_count]);
            OsRng.fill_bytes(&mut idx_bytes);

            let mut parts: Vec<String> = idx_bytes
                .iter()
                .map(|&idx| WORDLIST_256[idx as usize].to_owned())
                .collect();

            let num_suffix = uniform_below(100);
            parts.push(format!("{num_suffix:02}"));

            let entropy_bits = (word_count as u32) * 8 + 6;
            Ok(GeneratedSecretResponse {
                mode: "passphrase".to_owned(),
                secret: parts.join("-"),
                entropy_bits,
            })
        }
        "password" => {
            const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
            const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
            const DIGITS: &[u8] = b"23456789";
            const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}<>?";
            const ALL: &[u8] =
                b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+[]{}<>?";

            let len = requested_length.unwrap_or(24).clamp(12, 128);
            let mut chars = Vec::with_capacity(len);
            // Guarantee class diversity
            chars.push(LOWER[uniform_below(LOWER.len() as u32) as usize]);
            chars.push(UPPER[uniform_below(UPPER.len() as u32) as usize]);
            chars.push(DIGITS[uniform_below(DIGITS.len() as u32) as usize]);
            chars.push(SYMBOLS[uniform_below(SYMBOLS.len() as u32) as usize]);

            while chars.len() < len {
                let idx = uniform_below(ALL.len() as u32) as usize;
                chars.push(ALL[idx]);
            }

            // Fisher-Yates shuffle with CSPRNG
            for i in (1..chars.len()).rev() {
                let j = uniform_below((i + 1) as u32) as usize;
                chars.swap(i, j);
            }

            let secret = String::from_utf8_lossy(&chars).into_owned();
            // log2(78) ≈ 6.285 bits/char
            let entropy_bits = ((len as u32) * 628) / 100;
            Ok(GeneratedSecretResponse {
                mode: "password".to_owned(),
                secret,
                entropy_bits,
            })
        }
        _ => Err(TotpError::InvalidGeneratorMode),
    }
}

fn uniform_below(bound: u32) -> u32 {
    if bound <= 1 {
        return 0;
    }
    let threshold = u32::MAX - (u32::MAX % bound);
    let mut buf = [0u8; 4];
    loop {
        OsRng.fill_bytes(&mut buf);
        let candidate = u32::from_le_bytes(buf);
        if candidate < threshold {
            return candidate % bound;
        }
    }
}
