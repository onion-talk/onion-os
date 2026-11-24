//! Pure-Rust NIST FIPS 203 ML-KEM-768 (Kyber-768) Implementation
//! 100% Bit-for-Bit Wire Compatible with Android BouncyCastle 1.78.1 & kyber-py ML_KEM_768
//! Parameters: n = 256, k = 3, q = 3329, eta1 = 2, eta2 = 2, du = 10, dv = 4
//! Public Key (ek): 1184 bytes | Secret Key (dk): 2400 bytes | Ciphertext (ct): 1088 bytes | Shared Secret: 32 bytes

use rand::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};

pub const MLKEM768_EK_BYTES: usize = 1184;
pub const MLKEM768_DK_BYTES: usize = 2400;
pub const MLKEM768_CT_BYTES: usize = 1088;
#[allow(dead_code)]
pub const MLKEM768_SS_BYTES: usize = 32;

const K: usize = 3;
const Q: i32 = 3329;

/// Standard FIPS 203 Appendix A bit-reversed powers of zeta = 17 mod 3329
const ZETAS: [i32; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

type Poly = [i32; 256];

#[inline(always)]
fn mod_q(x: i32) -> i32 {
    let r = x % Q;
    if r < 0 { r + Q } else { r }
}

#[inline(always)]
fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut c = [0i32; 256];
    for i in 0..256 {
        let s = a[i] + b[i];
        c[i] = if s >= Q { s - Q } else { s };
    }
    c
}

#[inline(always)]
fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut c = [0i32; 256];
    for i in 0..256 {
        let d = a[i] - b[i];
        c[i] = if d < 0 { d + Q } else { d };
    }
    c
}

/// FIPS 203 Algorithm 9: Number-Theoretic Transform (NTT)
#[inline(always)]
fn ntt(f: &Poly) -> Poly {
    let mut p = *f;
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..(start + len) {
                let t = mod_q(zeta * p[j + len]);
                p[j + len] = mod_q(p[j] - t);
                p[j] = mod_q(p[j] + t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
    p
}

/// FIPS 203 Algorithm 10: Inverse NTT (NTT^-1)
#[inline(always)]
fn intt(f: &Poly) -> Poly {
    let mut p = *f;
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
            for j in start..(start + len) {
                let t = p[j];
                p[j] = mod_q(t + p[j + len]);
                p[j + len] = mod_q(zeta * (p[j + len] - t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for coeff in &mut p {
        *coeff = mod_q(*coeff * 3303); // 3303 = 128^-1 mod 3329
    }
    p
}

/// FIPS 203 Algorithm 11 & 12: MultiplyNTTs
#[inline(always)]
fn poly_basemul(a: &Poly, b: &Poly) -> Poly {
    let mut h = [0i32; 256];
    for i in 0..64 {
        let a0 = a[4 * i];
        let a1 = a[4 * i + 1];
        let b0 = b[4 * i];
        let b1 = b[4 * i + 1];
        let gamma0 = ZETAS[64 + i];
        h[4 * i] = mod_q(a0 * b0 + mod_q(a1 * b1) * gamma0);
        h[4 * i + 1] = mod_q(a0 * b1 + a1 * b0);

        let a2 = a[4 * i + 2];
        let a3 = a[4 * i + 3];
        let b2 = b[4 * i + 2];
        let b3 = b[4 * i + 3];
        let gamma1 = Q - gamma0;
        h[4 * i + 2] = mod_q(a2 * b2 + mod_q(a3 * b3) * gamma1);
        h[4 * i + 3] = mod_q(a2 * b3 + a3 * b2);
    }
    h
}

/// FIPS 203 Algorithm 7: SampleNTT(B) via SHAKE-128
fn sample_ntt(rho: &[u8; 32], j_idx: u8, i_idx: u8) -> Poly {
    let mut xof = Shake128::default();
    xof.update(rho);
    xof.update(&[j_idx, i_idx]);
    let mut reader = xof.finalize_xof();

    let mut a = [0i32; 256];
    let mut j = 0usize;
    let mut buf = [0u8; 3];
    while j < 256 {
        reader.read(&mut buf);
        let d1 = (buf[0] as i32) | (((buf[1] as i32) & 0x0F) << 8);
        let d2 = ((buf[1] as i32) >> 4) | ((buf[2] as i32) << 4);
        if d1 < Q {
            a[j] = d1;
            j += 1;
        }
        if d2 < Q && j < 256 {
            a[j] = d2;
            j += 1;
        }
    }
    a
}

/// FIPS 203 Algorithm 8: SamplePolyCBD_eta (eta = 2 for ML-KEM-768)
fn sample_cbd_eta2(sigma: &[u8; 32], nonce: u8) -> Poly {
    let mut xof = Shake256::default();
    xof.update(sigma);
    xof.update(&[nonce]);
    let mut reader = xof.finalize_xof();
    let mut bytes = [0u8; 128];
    reader.read(&mut bytes);

    let mut f = [0i32; 256];
    for i in 0..128 {
        let b = bytes[i];
        let x0 = (b & 1) + ((b >> 1) & 1);
        let y0 = ((b >> 2) & 1) + ((b >> 3) & 1);
        f[2 * i] = mod_q((x0 as i32) - (y0 as i32));

        let x1 = ((b >> 4) & 1) + ((b >> 5) & 1);
        let y1 = ((b >> 6) & 1) + ((b >> 7) & 1);
        f[2 * i + 1] = mod_q((x1 as i32) - (y1 as i32));
    }
    f
}

/// FIPS 203 Algorithm 5: ByteEncode_d
fn byte_encode(f: &Poly, d: usize) -> Vec<u8> {
    let mut out = vec![0u8; 32 * d];
    let mut bit_pos = 0usize;
    for &coeff in f.iter() {
        let val = coeff as u32;
        for b in 0..d {
            if ((val >> b) & 1) != 0 {
                out[bit_pos >> 3] |= 1u8 << (bit_pos & 7);
            }
            bit_pos += 1;
        }
    }
    out
}

/// FIPS 203 Algorithm 6: ByteDecode_d
fn byte_decode(bytes: &[u8], d: usize) -> Poly {
    let mut f = [0i32; 256];
    let mut bit_pos = 0usize;
    for coeff in &mut f {
        let mut val = 0u32;
        for b in 0..d {
            let bit = (bytes[bit_pos >> 3] >> (bit_pos & 7)) & 1;
            val |= (bit as u32) << b;
            bit_pos += 1;
        }
        *coeff = if d == 12 { (val % (Q as u32)) as i32 } else { val as i32 };
    }
    f
}

#[inline(always)]
fn compress_poly(f: &Poly, d: usize) -> Poly {
    let mut out = [0i32; 256];
    let mask = (1i64 << d) - 1;
    for i in 0..256 {
        let num = ((f[i] as i64) << d) + (Q as i64) / 2;
        out[i] = ((num / (Q as i64)) & mask) as i32;
    }
    out
}

#[inline(always)]
fn decompress_poly(f: &Poly, d: usize) -> Poly {
    let mut out = [0i32; 256];
    let half = 1i64 << (d - 1);
    for i in 0..256 {
        let num = (f[i] as i64) * (Q as i64) + half;
        out[i] = (num >> d) as i32;
    }
    out
}

fn k_pke_keygen(d_seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut g = Sha3_512::new();
    Digest::update(&mut g, d_seed);
    Digest::update(&mut g, [K as u8]);
    let g_out = g.finalize();
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g_out[0..32]);
    sigma.copy_from_slice(&g_out[32..64]);

    let mut a_hat = [[[0i32; 256]; K]; K];
    for (i, row) in a_hat.iter_mut().enumerate().take(K) {
        for (j, cell) in row.iter_mut().enumerate().take(K) {
            *cell = sample_ntt(&rho, j as u8, i as u8);
        }
    }

    let mut s_hat = [[0i32; 256]; K];
    let mut e_hat = [[0i32; 256]; K];
    for i in 0..K {
        s_hat[i] = ntt(&sample_cbd_eta2(&sigma, i as u8));
        e_hat[i] = ntt(&sample_cbd_eta2(&sigma, (K + i) as u8));
    }

    let mut t_hat = [[0i32; 256]; K];
    for i in 0..K {
        let mut acc = e_hat[i];
        for j in 0..K {
            let prod = poly_basemul(&a_hat[i][j], &s_hat[j]);
            acc = poly_add(&acc, &prod);
        }
        t_hat[i] = acc;
    }

    let mut ek_pke = Vec::with_capacity(MLKEM768_EK_BYTES);
    let mut dk_pke = Vec::with_capacity(384 * K);
    for i in 0..K {
        ek_pke.extend_from_slice(&byte_encode(&t_hat[i], 12));
        dk_pke.extend_from_slice(&byte_encode(&s_hat[i], 12));
    }
    ek_pke.extend_from_slice(&rho);
    (ek_pke, dk_pke)
}

fn k_pke_encrypt(ek_pke: &[u8], m: &[u8; 32], r_coins: &[u8; 32]) -> Vec<u8> {
    let mut t_hat = [[0i32; 256]; K];
    for i in 0..K {
        t_hat[i] = byte_decode(&ek_pke[384 * i..384 * (i + 1)], 12);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek_pke[384 * K..384 * K + 32]);

    let mut a_hat = [[[0i32; 256]; K]; K];
    for (i, row) in a_hat.iter_mut().enumerate().take(K) {
        for (j, cell) in row.iter_mut().enumerate().take(K) {
            *cell = sample_ntt(&rho, j as u8, i as u8);
        }
    }

    let mut r_hat = [[0i32; 256]; K];
    let mut e1 = [[0i32; 256]; K];
    for i in 0..K {
        r_hat[i] = ntt(&sample_cbd_eta2(r_coins, i as u8));
        e1[i] = sample_cbd_eta2(r_coins, (K + i) as u8);
    }
    let e2 = sample_cbd_eta2(r_coins, (2 * K) as u8);

    let mut u = [[0i32; 256]; K];
    for i in 0..K {
        let mut acc = [0i32; 256];
        for j in 0..K {
            // A^T[i][j] = A[j][i]
            let prod = poly_basemul(&a_hat[j][i], &r_hat[j]);
            acc = poly_add(&acc, &prod);
        }
        u[i] = poly_add(&intt(&acc), &e1[i]);
    }

    let mu = decompress_poly(&byte_decode(m, 1), 1);
    let mut v_acc = [0i32; 256];
    for j in 0..K {
        let prod = poly_basemul(&t_hat[j], &r_hat[j]);
        v_acc = poly_add(&v_acc, &prod);
    }
    let v = poly_add(&poly_add(&intt(&v_acc), &e2), &mu);

    let mut c = Vec::with_capacity(MLKEM768_CT_BYTES);
    for poly in u.iter().take(K) {
        c.extend_from_slice(&byte_encode(&compress_poly(poly, 10), 10));
    }
    c.extend_from_slice(&byte_encode(&compress_poly(&v, 4), 4));
    c
}

fn k_pke_decrypt(dk_pke: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut u_prime = [[0i32; 256]; K];
    for i in 0..K {
        let slice = &ct[320 * i..320 * (i + 1)];
        u_prime[i] = decompress_poly(&byte_decode(slice, 10), 10);
    }
    let v_prime = decompress_poly(&byte_decode(&ct[320 * K..320 * K + 128], 4), 4);

    let mut s_hat = [[0i32; 256]; K];
    for i in 0..K {
        s_hat[i] = byte_decode(&dk_pke[384 * i..384 * (i + 1)], 12);
    }

    let mut acc = [0i32; 256];
    for i in 0..K {
        let u_hat = ntt(&u_prime[i]);
        let prod = poly_basemul(&s_hat[i], &u_hat);
        acc = poly_add(&acc, &prod);
    }
    let w = poly_sub(&v_prime, &intt(&acc));
    let m_vec = byte_encode(&compress_poly(&w, 1), 1);
    let mut m = [0u8; 32];
    m.copy_from_slice(&m_vec[0..32]);
    m
}

pub fn keygen_deterministic(d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (ek, dk_pke) = k_pke_keygen(d);
    let mut h_ek = Sha3_256::new();
    Digest::update(&mut h_ek, &ek);
    let h_out = h_ek.finalize();

    let mut dk = Vec::with_capacity(MLKEM768_DK_BYTES);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h_out);
    dk.extend_from_slice(z);
    (ek, dk)
}

pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    rng.fill_bytes(&mut d);
    rng.fill_bytes(&mut z);
    keygen_deterministic(&d, &z)
}

pub fn encaps_deterministic(ek: &[u8], m: &[u8; 32]) -> Result<([u8; 32], Vec<u8>), &'static str> {
    if ek.len() != MLKEM768_EK_BYTES {
        return Err("Invalid ML-KEM-768 encapsulation key length");
    }
    let mut h_ek = Sha3_256::new();
    Digest::update(&mut h_ek, ek);
    let h_out = h_ek.finalize();

    let mut g = Sha3_512::new();
    Digest::update(&mut g, m);
    Digest::update(&mut g, h_out);
    let g_out = g.finalize();

    let mut k_shared = [0u8; 32];
    let mut r_coins = [0u8; 32];
    k_shared.copy_from_slice(&g_out[0..32]);
    r_coins.copy_from_slice(&g_out[32..64]);

    let ct = k_pke_encrypt(ek, m, &r_coins);
    Ok((k_shared, ct))
}

pub fn encaps(ek: &[u8]) -> Result<([u8; 32], Vec<u8>), &'static str> {
    let mut rng = rand::thread_rng();
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);
    encaps_deterministic(ek, &m)
}

pub fn decaps(dk: &[u8], ct: &[u8]) -> Result<[u8; 32], &'static str> {
    if dk.len() != MLKEM768_DK_BYTES || ct.len() != MLKEM768_CT_BYTES {
        return Err("Invalid ML-KEM-768 decapsulation key or ciphertext length");
    }
    let dk_pke = &dk[0..1152];
    let ek_pke = &dk[1152..2336];
    let h = &dk[2336..2368];
    let z = &dk[2368..2400];

    let m_prime = k_pke_decrypt(dk_pke, ct);

    let mut g = Sha3_512::new();
    Digest::update(&mut g, m_prime);
    Digest::update(&mut g, h);
    let g_out = g.finalize();

    let mut k_prime = [0u8; 32];
    let mut r_prime = [0u8; 32];
    k_prime.copy_from_slice(&g_out[0..32]);
    r_prime.copy_from_slice(&g_out[32..64]);

    let mut j_xof = Shake256::default();
    j_xof.update(z);
    j_xof.update(ct);
    let mut j_reader = j_xof.finalize_xof();
    let mut k_bar = [0u8; 32];
    j_reader.read(&mut k_bar);

    let c_prime = k_pke_encrypt(ek_pke, &m_prime, &r_prime);

    // Constant-time comparison of ct and c_prime
    let mut diff = 0u8;
    for i in 0..MLKEM768_CT_BYTES {
        diff |= ct[i] ^ c_prime[i];
    }
    let mask = ((diff as u16).wrapping_sub(1) >> 8) as u8; // 0xFF if diff == 0 else 0x00
    let mut k_out = [0u8; 32];
    for i in 0..32 {
        k_out[i] = (k_prime[i] & mask) | (k_bar[i] & !mask);
    }
    Ok(k_out)
}
