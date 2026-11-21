pub mod cipher;

use argon2::{Algorithm, Argon2, Params, Version};
use cipher::Knox256;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 4] = b"KNOX";
pub const VERSION: u8 = 2;
pub const HEADER_LEN: usize = 40;
pub const TAG_LEN: usize = 32;

const ARGON_MEM_KIB: u32 = 65536;
const ARGON_ITERS: u32 = 3;
const ARGON_LANES: u32 = 1;

type HmacSha256 = Hmac<Sha256>;

pub struct HeaderInfo {
    pub version: u8,
    pub salt: [u8; 16],
    pub nonce: [u8; 16],
    pub payload_len: usize,
    pub tag: [u8; TAG_LEN],
}

fn fill_rand(buf: &mut [u8]) -> Result<(), String> {
    getrandom::getrandom(buf).map_err(|_| "system rng failed".to_string())
}

fn derive_keys(
    pass: &[u8],
    salt: &[u8; 16],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    let params = Params::new(ARGON_MEM_KIB, ARGON_ITERS, ARGON_LANES, Some(32))
        .map_err(|_| "invalid argon2 params".to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pass, salt, &mut *master)
        .map_err(|_| "argon2 derivation failed".to_string())?;

    let hk = Hkdf::<Sha256>::new(Some(salt), &*master);
    let mut enc_key = Zeroizing::new([0u8; 32]);
    let mut mac_key = Zeroizing::new([0u8; 32]);

    hk.expand(b"knox-v2-enc-key", &mut *enc_key)
        .map_err(|_| "hkdf expand failed".to_string())?;
    hk.expand(b"knox-v2-mac-key", &mut *mac_key)
        .map_err(|_| "hkdf expand failed".to_string())?;

    Ok((enc_key, mac_key))
}

fn do_ctr(cipher: &Knox256, nonce: &[u8; 16], data: &mut [u8]) {
    let mut base_lo = [0u8; 8];
    base_lo.copy_from_slice(&nonce[0..8]);
    let nonce_lo = u64::from_le_bytes(base_lo);

    for (idx, chunk) in data.chunks_mut(16).enumerate() {
        let mut ctr = [0u8; 16];
        ctr[0..8].copy_from_slice(&(idx as u64).to_le_bytes());
        ctr[8..16].copy_from_slice(&nonce[8..16]);

        let mut tweak = *nonce;
        let tw_lo = nonce_lo.wrapping_add(idx as u64) ^ 0x0100_0000_0000_0000;
        tweak[0..8].copy_from_slice(&tw_lo.to_le_bytes());

        let ks = cipher.encrypt_block(ctr, tweak);
        for i in 0..chunk.len() {
            chunk[i] ^= ks[i];
        }
    }
}

fn make_tag(mac_key: &[u8; 32], header: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("32-byte key is valid");
    mac.update(header);
    mac.update(ct);
    mac.update(&(header.len() as u64).to_le_bytes());
    mac.update(&(ct.len() as u64).to_le_bytes());

    let bytes = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&bytes);
    tag
}

pub fn seal(plain: &[u8], pass: &str) -> Result<(Vec<u8>, [u8; TAG_LEN]), String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 16];
    fill_rand(&mut salt)?;
    fill_rand(&mut nonce)?;

    let (enc_key, mac_key) = derive_keys(pass.as_bytes(), &salt)?;

    let mut out = Vec::with_capacity(HEADER_LEN + plain.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&[VERSION, 0, 0, 0]);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);

    let ct_start = out.len();
    out.extend_from_slice(plain);

    let cipher = Knox256::new(&enc_key);
    do_ctr(&cipher, &nonce, &mut out[ct_start..]);

    let tag = make_tag(&mac_key, &out[..HEADER_LEN], &out[ct_start..]);
    out.extend_from_slice(&tag);

    Ok((out, tag))
}

pub fn open(blob: &[u8], pass: &str) -> Result<(Zeroizing<Vec<u8>>, [u8; TAG_LEN]), String> {
    let info = inspect(blob)?;
    let header = &blob[..HEADER_LEN];
    let ct = &blob[HEADER_LEN..blob.len() - TAG_LEN];

    let (enc_key, mac_key) = derive_keys(pass.as_bytes(), &info.salt)?;
    let expected = make_tag(&mac_key, header, ct);

    if !bool::from(expected.ct_eq(&info.tag)) {
        return Err("auth failed: wrong passphrase or tampered container".to_string());
    }

    let mut plain = Zeroizing::new(ct.to_vec());
    let cipher = Knox256::new(&enc_key);
    do_ctr(&cipher, &info.nonce, &mut plain);

    Ok((plain, expected))
}

pub fn inspect(blob: &[u8]) -> Result<HeaderInfo, String> {
    if blob.len() < HEADER_LEN + TAG_LEN || &blob[0..4] != MAGIC {
        return Err("invalid or corrupted KNOX container".to_string());
    }
    let version = blob[4];
    if version != VERSION {
        return Err(format!("unsupported container version: v{version}"));
    }

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 16];
    let mut tag = [0u8; TAG_LEN];

    salt.copy_from_slice(&blob[8..24]);
    nonce.copy_from_slice(&blob[24..40]);
    tag.copy_from_slice(&blob[blob.len() - TAG_LEN..]);

    Ok(HeaderInfo {
        version,
        salt,
        nonce,
        payload_len: blob.len() - HEADER_LEN - TAG_LEN,
        tag,
    })
}

pub fn hex_short(bytes: &[u8]) -> String {
    let mut out = String::new();
    if bytes.len() <= 8 {
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        return out;
    }
    for b in &bytes[..4] {
        out.push_str(&format!("{b:02x}"));
    }
    out.push_str("..");
    for b in &bytes[bytes.len() - 3..] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

const B64_CHARS: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(((input.len() + 2) / 3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        out.push(B64_CHARS[(b0 >> 2) as usize] as char);
        out.push(B64_CHARS[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_CHARS[(((b1 & 0xF) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64_CHARS[(b2 & 0x3F) as usize] as char);
        }
    }
    out
}

pub fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for b in input.bytes() {
        if b == b'=' || b.is_ascii_whitespace() {
            continue;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return Err("malformed armored token".to_string()),
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_open_and_tamper() {
        let msg = b"argon2 + hkdf + knox256";
        let (mut sealed, _) = seal(msg, "secret-pass").unwrap();

        let (opened, _) = open(&sealed, "secret-pass").unwrap();
        assert_eq!(&*opened, msg);

        assert!(open(&sealed, "wrong-pass").is_err());

        sealed[HEADER_LEN + 2] ^= 1;
        assert!(open(&sealed, "secret-pass").is_err());
    }

    #[test]
    fn test_b64() {
        for len in 0..32 {
            let mut data = Vec::new();
            for i in 0..len {
                data.push((i * 37) as u8);
            }
            let enc = b64_encode(&data);
            assert_eq!(b64_decode(&enc).unwrap(), data);
        }
    }
}
