//! Defensive OSINT & Tor Network Lab (`onion-osint`):
//! - Mathematical Tor v3 `.onion` validation (RFC 4648 Base32 + Ed25519 + SHA3-256 checksum)
//! - Tor Stream-Isolated (`socks5h://iso-<nonce>:tor@127.0.0.1:9050`) HTTP/TLS header probe with SSRF guard
//! - Tor ControlPort `SIGNAL NEWNYM`, `GETINFO status/bootstrap-phase` & `GETINFO circuit-status`

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[derive(Debug, thiserror::Error)]
pub enum OsintError {
    #[error("Invalid target URL: {0}")]
    InvalidUrl(String),
    #[error("Blocked SSRF target (private, loopback or link-local address): {0}")]
    BlockedTarget(String),
    #[error("Failed to construct isolated Tor SOCKS5h client: {0}")]
    ClientBuild(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnionValidationResult {
    pub valid: bool,
    pub normalized: String,
    pub normalized_address: String,
    pub version: Option<u8>,
    pub ed25519_pubkey_hex: Option<String>,
    pub pubkey_hex: Option<String>,
    pub checksum_hex: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OsintProbeResult {
    pub ok: bool,
    pub status_code: Option<u16>,
    pub latency_ms: u64,
    pub circuit_isolation_id: String,
    pub via_tor_socks: bool,
    pub security_headers: BTreeMap<String, String>,
    pub raw_headers: BTreeMap<String, String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TorNewnymResult {
    pub ok: bool,
    pub message: String,
    pub response_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TorCircuitEntry {
    pub id: String,
    pub status: String,
    pub hops: Vec<String>,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TorCircuitsResponse {
    pub socks_ok: bool,
    pub control_ok: bool,
    pub bootstrap_pct: u8,
    pub circuits: Vec<TorCircuitEntry>,
}

pub fn validate_onion_v3(raw_address: &str) -> OnionValidationResult {
    let mut s = raw_address.trim().to_ascii_lowercase();
    if let Some(rest) = s.strip_prefix("http://") {
        s = rest.to_owned();
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest.to_owned();
    }
    if let Some(slash_idx) = s.find(['/', '?', '#']) {
        s.truncate(slash_idx);
    }
    if let Some(at_idx) = s.rfind('@') {
        s = s[at_idx + 1..].to_owned();
    }
    if let Some(colon_idx) = s.find(':') {
        s.truncate(colon_idx);
    }

    let stem = s.strip_suffix(".onion").unwrap_or(&s).trim_matches('.');
    let normalized = if stem.is_empty() {
        String::new()
    } else {
        format!("{stem}.onion")
    };

    let build_invalid = |version: Option<u8>,
                         ed_hex: Option<String>,
                         cs_hex: Option<String>,
                         reason: String| {
        OnionValidationResult {
            valid: false,
            normalized_address: normalized.clone(),
            normalized: normalized.clone(),
            version,
            pubkey_hex: ed_hex.clone(),
            ed25519_pubkey_hex: ed_hex,
            checksum_hex: cs_hex,
            reason,
        }
    };

    if stem.len() == 16 {
        return build_invalid(
            Some(2),
            None,
            None,
            "Deprecated Tor v2 onion address (16 chars); only Tor v3 (56 chars) is secure".into(),
        );
    }

    if stem.len() != 56 {
        return build_invalid(
            None,
            None,
            None,
            format!(
                "Tor v3 onion stem must be exactly 56 base32 characters (got {})",
                stem.len()
            ),
        );
    }

    let decoded = match base32_decode_56(stem) {
        Ok(bytes) => bytes,
        Err(msg) => return build_invalid(None, None, None, msg),
    };

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&decoded[0..32]);
    let checksum = [decoded[32], decoded[33]];
    let version = decoded[34];

    let ed_hex = hex::encode(pubkey);
    let cs_hex = hex::encode(checksum);

    if version != 0x03 {
        return build_invalid(
            Some(version),
            Some(ed_hex),
            Some(cs_hex),
            format!("Unsupported onion version byte 0x{version:02x} (expected 0x03)"),
        );
    }

    let expected_cs = compute_onion_v3_checksum(&pubkey, version);
    if checksum != expected_cs {
        return build_invalid(
            Some(version),
            Some(ed_hex),
            Some(cs_hex),
            format!(
                "SHA3-256 checksum mismatch (got {}, expected {})",
                hex::encode(checksum),
                hex::encode(expected_cs)
            ),
        );
    }

    match VerifyingKey::from_bytes(&pubkey) {
        Ok(vk) if !vk.is_weak() => OnionValidationResult {
            valid: true,
            normalized_address: normalized.clone(),
            normalized,
            version: Some(3),
            pubkey_hex: Some(ed_hex.clone()),
            ed25519_pubkey_hex: Some(ed_hex),
            checksum_hex: Some(cs_hex),
            reason: "Valid Tor v3 Ed25519 hidden service address".into(),
        },
        Ok(_) => build_invalid(
            Some(3),
            Some(ed_hex),
            Some(cs_hex),
            "Rejected weak/low-order Ed25519 public key".into(),
        ),
        Err(_) => build_invalid(
            Some(3),
            Some(ed_hex),
            Some(cs_hex),
            "Bytes do not represent a valid Ed25519 curve point".into(),
        ),
    }
}

pub fn encode_onion_v3_from_pubkey(pubkey: &[u8; 32]) -> String {
    let cs = compute_onion_v3_checksum(pubkey, 0x03);
    let mut raw = [0u8; 35];
    raw[0..32].copy_from_slice(pubkey);
    raw[32] = cs[0];
    raw[33] = cs[1];
    raw[34] = 0x03;
    let stem = base32_encode_35(&raw);
    format!("{stem}.onion")
}

pub fn compute_onion_v3_checksum(pubkey: &[u8; 32], version: u8) -> [u8; 2] {
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([version]);
    let digest = hasher.finalize();
    [digest[0], digest[1]]
}

fn base32_decode_56(stem: &str) -> Result<[u8; 35], String> {
    let bytes = stem.as_bytes();
    if bytes.len() != 56 {
        return Err("Invalid base32 stem length".into());
    }

    let mut out = [0u8; 35];
    let mut bit_buf: u64 = 0;
    let mut bits_in_buf: u32 = 0;
    let mut out_idx = 0usize;

    for (pos, &ch) in bytes.iter().enumerate() {
        let val: u64 = match ch {
            b'a'..=b'z' => (ch - b'a') as u64,
            b'2'..=b'7' => (ch - b'2' + 26) as u64,
            _ => {
                return Err(format!(
                    "Invalid RFC 4648 base32 character '{}' at index {pos}",
                    ch as char
                ));
            }
        };
        bit_buf = (bit_buf << 5) | val;
        bits_in_buf += 5;
        while bits_in_buf >= 8 {
            bits_in_buf -= 8;
            if out_idx < out.len() {
                out[out_idx] = ((bit_buf >> bits_in_buf) & 0xFF) as u8;
                out_idx += 1;
            }
        }
    }

    Ok(out)
}

fn base32_encode_35(data: &[u8; 35]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(56);
    let mut bit_buf: u64 = 0;
    let mut bits_in_buf: u32 = 0;

    for &b in data {
        bit_buf = (bit_buf << 8) | (b as u64);
        bits_in_buf += 8;
        while bits_in_buf >= 5 {
            bits_in_buf -= 5;
            let idx = ((bit_buf >> bits_in_buf) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    out
}

pub fn validate_probe_url(url_str: &str) -> Result<reqwest::Url, OsintError> {
    let parsed = reqwest::Url::parse(url_str.trim())
        .map_err(|e| OsintError::InvalidUrl(e.to_string()))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(OsintError::InvalidUrl(
            "Only http:// and https:// schemes are permitted".into(),
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| OsintError::InvalidUrl("Missing URL host".into()))?
        .to_ascii_lowercase();

    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return Err(OsintError::BlockedTarget(host));
    }

    let trimmed_ipv6 = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = trimmed_ipv6.parse::<IpAddr>() {
        if is_non_public_ip(&ip) {
            return Err(OsintError::BlockedTarget(ip.to_string()));
        }
    }

    Ok(parsed)
}

fn is_non_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.octets()[0] == 0
                || v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_non_public_ip(&IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xFE00) == 0xFC00
                || (v6.segments()[0] & 0xFFC0) == 0xFE80
        }
    }
}

pub async fn probe_via_tor(
    url_str: &str,
    tor_socks_addr: &str,
) -> Result<OsintProbeResult, OsintError> {
    let target_url = validate_probe_url(url_str)?;

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let circuit_isolation_id = format!("iso-{}", hex::encode(nonce));
    let proxy_url = format!("socks5h://{circuit_isolation_id}:tor@{tor_socks_addr}");

    let proxy = reqwest::Proxy::all(&proxy_url)
        .map_err(|e| OsintError::ClientBuild(e.to_string()))?;

    let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 3 {
            return attempt.stop();
        }
        match validate_probe_url(attempt.url().as_str()) {
            Ok(_) => attempt.follow(),
            Err(e) => attempt.error(e),
        }
    });

    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(15))
        .redirect(redirect_policy)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0")
        .build()
        .map_err(|e| OsintError::ClientBuild(e.to_string()))?;

    let started = Instant::now();
    let send_res = client.get(target_url).send().await;
    let latency_ms = started.elapsed().as_millis() as u64;

    match send_res {
        Ok(resp) => {
            let status_code = resp.status().as_u16();
            let mut raw_headers = BTreeMap::new();
            let mut security_headers = BTreeMap::new();

            const SEC_KEYS: &[&str] = &[
                "content-security-policy",
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
                "onion-location",
                "cross-origin-opener-policy",
                "server",
            ];

            for (name, val) in resp.headers() {
                let key = name.as_str().to_ascii_lowercase();
                let val_str = val.to_str().unwrap_or("<binary>").to_owned();
                if SEC_KEYS.contains(&key.as_str()) {
                    security_headers.insert(key.clone(), val_str.clone());
                }
                raw_headers.insert(key, val_str);
            }
            drop(resp);

            Ok(OsintProbeResult {
                ok: true,
                status_code: Some(status_code),
                latency_ms,
                circuit_isolation_id,
                via_tor_socks: true,
                security_headers,
                raw_headers,
                error: None,
            })
        }
        Err(err) => Ok(OsintProbeResult {
            ok: false,
            status_code: None,
            latency_ms,
            circuit_isolation_id,
            via_tor_socks: true,
            security_headers: BTreeMap::new(),
            raw_headers: BTreeMap::new(),
            error: Some(err.to_string()),
        }),
    }
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

pub async fn send_tor_newnym(
    control_addr: &str,
    cookie_file: Option<&Path>,
    timeout: Duration,
) -> TorNewnymResult {
    let cookie_hex = load_control_cookie_hex(cookie_file);

    let fut = async {
        let stream = TcpStream::connect(control_addr).await?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let auth_cmd = match &cookie_hex {
            Some(hex_tok) => format!("AUTHENTICATE {hex_tok}\r\n"),
            None => "AUTHENTICATE \"\"\r\n".to_owned(),
        };
        write_half.write_all(auth_cmd.as_bytes()).await?;
        write_half.flush().await?;

        let mut auth_line = String::new();
        reader.read_line(&mut auth_line).await?;
        if !auth_line.starts_with("250") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Tor ControlPort AUTHENTICATE rejected: {}", auth_line.trim()),
            ));
        }

        write_half.write_all(b"SIGNAL NEWNYM\r\n").await?;
        write_half.flush().await?;

        let mut sig_line = String::new();
        reader.read_line(&mut sig_line).await?;
        let _ = write_half.write_all(b"QUIT\r\n").await;

        let clean_sig = sig_line.trim().to_owned();
        if clean_sig.starts_with("250") {
            Ok(clean_sig)
        } else {
            Err(std::io::Error::other(format!(
                "Tor SIGNAL NEWNYM failed: {clean_sig}"
            )))
        }
    };

    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(line)) => {
            let msg = format!("{line} — Tor circuits rotated (SIGNAL NEWNYM)");
            TorNewnymResult {
                ok: true,
                message: msg,
                response_line: line,
            }
        }
        Ok(Err(e)) => {
            let msg = format!("Tor ControlPort error: {e}");
            TorNewnymResult {
                ok: false,
                message: msg.clone(),
                response_line: msg,
            }
        }
        Err(_) => {
            let msg = format!("Tor ControlPort timeout connecting to {control_addr}");
            TorNewnymResult {
                ok: false,
                message: msg.clone(),
                response_line: msg,
            }
        }
    }
}

pub async fn query_tor_circuits(
    socks_addr: &str,
    control_addr: &str,
    cookie_file: Option<&Path>,
    timeout: Duration,
) -> TorCircuitsResponse {
    let socks_ok = tokio::time::timeout(
        Duration::from_millis(200),
        TcpStream::connect(socks_addr),
    )
    .await
    .is_ok_and(|r| r.is_ok());

    let cookie_hex = load_control_cookie_hex(cookie_file);

    let control_fut = async {
        let stream = TcpStream::connect(control_addr).await?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let auth_cmd = match &cookie_hex {
            Some(hex_tok) => format!("AUTHENTICATE {hex_tok}\r\n"),
            None => "AUTHENTICATE \"\"\r\n".to_owned(),
        };
        write_half.write_all(auth_cmd.as_bytes()).await?;
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if !line.starts_with("250") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "AUTHENTICATE failed",
            ));
        }

        // 1. Bootstrap phase
        write_half
            .write_all(b"GETINFO status/bootstrap-phase\r\n")
            .await?;
        let mut bootstrap_pct = 0u8;
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                break;
            }
            let t = line.trim();
            if let Some(pct) = parse_bootstrap_progress(t) {
                bootstrap_pct = pct;
            }
            if t == "250 OK" || t.starts_with("250 ") || !t.starts_with("250") {
                break;
            }
        }

        // 2. Circuit status
        write_half.write_all(b"GETINFO circuit-status\r\n").await?;
        let mut raw_circ_lines = Vec::new();
        let mut in_multiline = false;
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                break;
            }
            let t = line.trim();
            if in_multiline {
                if t == "." {
                    in_multiline = false;
                    continue;
                }
                raw_circ_lines.push(t.to_owned());
                continue;
            }
            if t.starts_with("250+circuit-status=") {
                in_multiline = true;
                let inline = t.trim_start_matches("250+circuit-status=").trim();
                if !inline.is_empty() {
                    raw_circ_lines.push(inline.to_owned());
                }
            } else if let Some(rest) = t.strip_prefix("250-circuit-status=") {
                if !rest.trim().is_empty() {
                    raw_circ_lines.push(rest.trim().to_owned());
                }
            } else if t == "250 OK" || t.starts_with("250 ") || !t.starts_with("250") {
                break;
            }
        }

        let _ = write_half.write_all(b"QUIT\r\n").await;
        let circuits = parse_circuit_status_lines(&raw_circ_lines);
        Ok::<(u8, Vec<TorCircuitEntry>), std::io::Error>((bootstrap_pct, circuits))
    };

    match tokio::time::timeout(timeout, control_fut).await {
        Ok(Ok((bootstrap_pct, circuits))) => TorCircuitsResponse {
            socks_ok,
            control_ok: true,
            bootstrap_pct,
            circuits,
        },
        _ => TorCircuitsResponse {
            socks_ok,
            control_ok: false,
            bootstrap_pct: if socks_ok { 100 } else { 0 },
            circuits: Vec::new(),
        },
    }
}

pub fn parse_bootstrap_progress(line: &str) -> Option<u8> {
    for tok in line.split_whitespace() {
        if let Some(num) = tok.strip_prefix("PROGRESS=") {
            if let Ok(pct) = num.parse::<u8>() {
                return Some(pct.min(100));
            }
        }
    }
    None
}

pub fn parse_circuit_status_lines(lines: &[String]) -> Vec<TorCircuitEntry> {
    let mut out = Vec::new();
    for raw in lines {
        let parts: Vec<&str> = raw.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let id = parts[0].to_owned();
        let status = parts[1].to_owned();
        let mut hops = Vec::new();
        let mut purpose = "GENERAL".to_owned();

        for &token in &parts[2..] {
            if let Some(p) = token.strip_prefix("PURPOSE=") {
                purpose = p.to_owned();
            } else if !token.contains('=') && (token.starts_with('$') || token.contains('~')) {
                for hop_raw in token.split(',') {
                    let clean_hop = if let Some((_, nick)) = hop_raw.split_once('~') {
                        nick.to_owned()
                    } else if let Some((_, nick)) = hop_raw.split_once('=') {
                        nick.to_owned()
                    } else {
                        let trimmed = hop_raw.trim_start_matches('$');
                        trimmed[..trimmed.len().min(10)].to_owned()
                    };
                    if !clean_hop.is_empty() {
                        hops.push(clean_hop);
                    }
                }
            }
        }

        out.push(TorCircuitEntry {
            id,
            status,
            hops,
            purpose,
        });
    }
    out
}
