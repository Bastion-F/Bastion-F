pub mod cipher;

use argon2::{Algorithm, Argon2, Params, Version};
use cipher::Knox256;
use rayon::prelude::*;
use std::io::{self, Cursor, Read, Write};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 4] = b"KNOX";
pub const VERSION: u8 = 3;
pub const HEADER_LEN: usize = 120;
pub const TAG_LEN: usize = 32;
pub const CHUNK_SIZE: usize = 64 * 1024;
pub const ENC_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_LEN;

const BATCH_CHUNKS: usize = 64;
const BATCH_PLAIN: usize = BATCH_CHUNKS * CHUNK_SIZE;
const BATCH_ENC: usize = BATCH_CHUNKS * ENC_CHUNK_SIZE;

const ARGON_MEM_KIB: u32 = 65536;
const ARGON_ITERS: u32 = 3;
const ARGON_LANES: u32 = 1;

pub struct HeaderInfo {
    pub version: u8,
    pub salt: [u8; 16],
    pub wrap_nonce: [u8; 16],
    pub wrapped_key: [u8; 32],
    pub stream_nonce: [u8; 16],
    pub header_mac: [u8; TAG_LEN],
}

pub struct StreamStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub chunks: u64,
    pub header_mac: [u8; TAG_LEN],
}

pub struct PreparedSeal {
    pub header: [u8; HEADER_LEN],
    pub enc_key: Zeroizing<[u8; 32]>,
    pub mac_key: Zeroizing<[u8; 32]>,
    pub stream_nonce: [u8; 16],
    pub header_mac: [u8; TAG_LEN],
}

pub struct UnlockedStream {
    pub enc_key: Zeroizing<[u8; 32]>,
    pub mac_key: Zeroizing<[u8; 32]>,
    pub stream_nonce: [u8; 16],
    pub header_mac: [u8; TAG_LEN],
}

fn fill_rand(buf: &mut [u8]) -> Result<(), String> {
    getrandom::getrandom(buf).map_err(|_| "system rng failed".to_string())
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

fn derive_kek(
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

    let mut km = Zeroizing::new([0u8; 48]);
    km[0..32].copy_from_slice(&*master);
    km[32..48].copy_from_slice(salt);

    let wrap_key = Zeroizing::new(blake3::derive_key("knox v3 header wrap key", &*km));
    let hdr_mac_key = Zeroizing::new(blake3::derive_key("knox v3 header mac key", &*km));
    Ok((wrap_key, hdr_mac_key))
}

fn derive_payload_keys(
    file_key: &[u8; 32],
    stream_nonce: &[u8; 16],
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut km = Zeroizing::new([0u8; 48]);
    km[0..32].copy_from_slice(file_key);
    km[32..48].copy_from_slice(stream_nonce);

    let enc_key = Zeroizing::new(blake3::derive_key("knox v3 payload enc key", &*km));
    let mac_key = Zeroizing::new(blake3::derive_key("knox v3 payload mac key", &*km));
    (enc_key, mac_key)
}

fn wrap_xor(cipher: &Knox256, wrap_nonce: &[u8; 16], data: &mut [u8; 32]) {
    let mut base_lo = [0u8; 8];
    base_lo.copy_from_slice(&wrap_nonce[0..8]);
    let nonce_lo = u64::from_le_bytes(base_lo);

    for b in 0..2u64 {
        let mut ctr = [0u8; 16];
        ctr[0..8].copy_from_slice(&b.to_le_bytes());
        ctr[8..16].copy_from_slice(&wrap_nonce[8..16]);

        let mut tweak = *wrap_nonce;
        let tw_lo = nonce_lo ^ b ^ 0x5752_4150_0000_0000;
        tweak[0..8].copy_from_slice(&tw_lo.to_le_bytes());

        let ks = cipher.encrypt_block(ctr, tweak);
        let start = (b as usize) * 16;
        for j in 0..16 {
            data[start + j] ^= ks[j];
        }
    }
}

fn ctr_chunk(
    cipher: &Knox256,
    stream_nonce: &[u8; 16],
    chunk_idx: u64,
    is_last: bool,
    data: &mut [u8],
) {
    let mut base_lo_bytes = [0u8; 8];
    base_lo_bytes.copy_from_slice(&stream_nonce[0..8]);
    let base_lo = u64::from_le_bytes(base_lo_bytes);

    let mut base_mid_bytes = [0u8; 4];
    base_mid_bytes.copy_from_slice(&stream_nonce[8..12]);
    let base_mid = u32::from_le_bytes(base_mid_bytes);

    let last_mask = if is_last { 0xFFu8 } else { 0x00u8 };

    for (b, block) in data.chunks_mut(16).enumerate() {
        let b_u32 = b as u32;
        let mut ctr = [0u8; 16];
        ctr[0..8].copy_from_slice(&chunk_idx.to_le_bytes());
        ctr[8..12].copy_from_slice(&b_u32.to_le_bytes());
        ctr[12..15].copy_from_slice(&stream_nonce[12..15]);
        ctr[15] = stream_nonce[15] ^ last_mask;

        let mut tweak = *stream_nonce;
        tweak[0..8].copy_from_slice(&(base_lo ^ chunk_idx).to_le_bytes());
        tweak[8..12].copy_from_slice(&(base_mid ^ b_u32).to_le_bytes());
        tweak[15] ^= last_mask;

        let ks = cipher.encrypt_block(ctr, tweak);
        for j in 0..block.len() {
            block[j] ^= ks[j];
        }
    }
}

fn chunk_mac(
    mac_key: &[u8; 32],
    stream_nonce: &[u8; 16],
    chunk_idx: u64,
    is_last: bool,
    ct: &[u8],
) -> [u8; TAG_LEN] {
    let mut h = blake3::Hasher::new_keyed(mac_key);
    h.update(stream_nonce);
    h.update(&chunk_idx.to_le_bytes());
    h.update(&[if is_last { 1u8 } else { 0u8 }]);
    h.update(ct);
    *h.finalize().as_bytes()
}

fn encrypt_chunk(
    cipher: &Knox256,
    mac_key: &[u8; 32],
    stream_nonce: &[u8; 16],
    chunk_idx: u64,
    is_last: bool,
    plain: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(plain.len() + TAG_LEN);
    out.extend_from_slice(plain);
    ctr_chunk(cipher, stream_nonce, chunk_idx, is_last, &mut out);
    let tag = chunk_mac(mac_key, stream_nonce, chunk_idx, is_last, &out);
    out.extend_from_slice(&tag);
    out
}

fn decrypt_chunk(
    cipher: &Knox256,
    mac_key: &[u8; 32],
    stream_nonce: &[u8; 16],
    chunk_idx: u64,
    is_last: bool,
    enc: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    if enc.len() < TAG_LEN {
        return Err("corrupted or truncated chunk".to_string());
    }
    let split = enc.len() - TAG_LEN;
    let ct = &enc[..split];
    let tag = &enc[split..];

    let expected = chunk_mac(mac_key, stream_nonce, chunk_idx, is_last, ct);
    if !bool::from(expected.ct_eq(tag)) {
        return Err(format!("chunk {chunk_idx} auth failed: tampered or truncated data"));
    }

    let mut plain = Zeroizing::new(ct.to_vec());
    ctr_chunk(cipher, stream_nonce, chunk_idx, is_last, &mut plain);
    Ok(plain)
}

pub fn prepare_seal(pass: &str) -> Result<PreparedSeal, String> {
    let mut salt = [0u8; 16];
    let mut wrap_nonce = [0u8; 16];
    let mut stream_nonce = [0u8; 16];
    let mut file_key = Zeroizing::new([0u8; 32]);

    fill_rand(&mut salt)?;
    fill_rand(&mut wrap_nonce)?;
    fill_rand(&mut stream_nonce)?;
    fill_rand(&mut *file_key)?;

    let (wrap_key, hdr_mac_key) = derive_kek(pass.as_bytes(), &salt)?;
    let wrap_cipher = Knox256::new(&wrap_key);

    let mut wrapped_key = *file_key;
    wrap_xor(&wrap_cipher, &wrap_nonce, &mut wrapped_key);

    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[8..24].copy_from_slice(&salt);
    header[24..40].copy_from_slice(&wrap_nonce);
    header[40..72].copy_from_slice(&wrapped_key);
    header[72..88].copy_from_slice(&stream_nonce);

    let header_mac = *blake3::keyed_hash(&hdr_mac_key, &header[0..88]).as_bytes();
    header[88..120].copy_from_slice(&header_mac);

    let (enc_key, mac_key) = derive_payload_keys(&file_key, &stream_nonce);

    Ok(PreparedSeal {
        header,
        enc_key,
        mac_key,
        stream_nonce,
        header_mac,
    })
}

pub fn seal_payload<R: Read, W: Write, F: FnMut(u64)>(
    reader: &mut R,
    writer: &mut W,
    prepared: &PreparedSeal,
    mut on_progress: F,
) -> Result<StreamStats, String> {
    writer
        .write_all(&prepared.header)
        .map_err(|e| format!("write error: {e}"))?;

    let cipher = Knox256::new(&prepared.enc_key);

    let mut buf = Zeroizing::new(vec![0u8; BATCH_PLAIN + 1]);
    let mut pending: Option<u8> = None;
    let mut chunk_idx = 0u64;
    let mut bytes_in = 0u64;
    let mut bytes_out = HEADER_LEN as u64;

    loop {
        let mut offset = 0;
        if let Some(b) = pending.take() {
            buf[0] = b;
            offset = 1;
        }

        let n = read_full(reader, &mut buf[offset..]).map_err(|e| format!("read error: {e}"))?;
        let total = offset + n;

        if total == 0 {
            if chunk_idx == 0 {
                let enc = encrypt_chunk(
                    &cipher,
                    &prepared.mac_key,
                    &prepared.stream_nonce,
                    0,
                    true,
                    &[],
                );
                writer
                    .write_all(&enc)
                    .map_err(|e| format!("write error: {e}"))?;
                bytes_out += enc.len() as u64;
                chunk_idx = 1;
            }
            break;
        }

        let is_eof = total <= BATCH_PLAIN;
        let batch_len = if is_eof {
            total
        } else {
            pending = Some(buf[BATCH_PLAIN]);
            BATCH_PLAIN
        };

        let slice = &buf[..batch_len];
        let count = (batch_len + CHUNK_SIZE - 1) / CHUNK_SIZE;
        let base_idx = chunk_idx;

        if count == 1 {
            let enc = encrypt_chunk(
                &cipher,
                &prepared.mac_key,
                &prepared.stream_nonce,
                base_idx,
                is_eof,
                slice,
            );
            writer
                .write_all(&enc)
                .map_err(|e| format!("write error: {e}"))?;
            bytes_out += enc.len() as u64;
        } else {
            let encrypted: Vec<Vec<u8>> = (0..count)
                .into_par_iter()
                .map(|i| {
                    let start = i * CHUNK_SIZE;
                    let end = (start + CHUNK_SIZE).min(batch_len);
                    let last = is_eof && (i + 1 == count);
                    encrypt_chunk(
                        &cipher,
                        &prepared.mac_key,
                        &prepared.stream_nonce,
                        base_idx + (i as u64),
                        last,
                        &slice[start..end],
                    )
                })
                .collect();

            for c in &encrypted {
                writer
                    .write_all(c)
                    .map_err(|e| format!("write error: {e}"))?;
                bytes_out += c.len() as u64;
            }
        }

        bytes_in += batch_len as u64;
        chunk_idx += count as u64;
        on_progress(bytes_in);

        if is_eof {
            break;
        }
    }

    Ok(StreamStats {
        bytes_in,
        bytes_out,
        chunks: chunk_idx,
        header_mac: prepared.header_mac,
    })
}

pub fn parse_header(raw: &[u8]) -> Result<HeaderInfo, String> {
    if raw.len() < HEADER_LEN || &raw[0..4] != MAGIC {
        return Err("invalid or corrupted KNOX container".to_string());
    }
    let version = raw[4];
    if version != VERSION {
        return Err(format!("unsupported container version: v{version}"));
    }

    let mut salt = [0u8; 16];
    let mut wrap_nonce = [0u8; 16];
    let mut wrapped_key = [0u8; 32];
    let mut stream_nonce = [0u8; 16];
    let mut header_mac = [0u8; TAG_LEN];

    salt.copy_from_slice(&raw[8..24]);
    wrap_nonce.copy_from_slice(&raw[24..40]);
    wrapped_key.copy_from_slice(&raw[40..72]);
    stream_nonce.copy_from_slice(&raw[72..88]);
    header_mac.copy_from_slice(&raw[88..120]);

    Ok(HeaderInfo {
        version,
        salt,
        wrap_nonce,
        wrapped_key,
        stream_nonce,
        header_mac,
    })
}

pub fn inspect_reader<R: Read>(reader: &mut R) -> Result<HeaderInfo, String> {
    let mut raw = [0u8; HEADER_LEN];
    let n = read_full(reader, &mut raw).map_err(|e| format!("read error: {e}"))?;
    if n < HEADER_LEN {
        return Err("invalid or truncated KNOX header".to_string());
    }
    parse_header(&raw)
}

pub fn unlock_header<R: Read>(reader: &mut R, pass: &str) -> Result<UnlockedStream, String> {
    let mut raw = [0u8; HEADER_LEN];
    let n = read_full(reader, &mut raw).map_err(|e| format!("read error: {e}"))?;
    if n < HEADER_LEN {
        return Err("invalid or truncated KNOX header".to_string());
    }

    let info = parse_header(&raw)?;
    let (wrap_key, hdr_mac_key) = derive_kek(pass.as_bytes(), &info.salt)?;

    let expected_mac = *blake3::keyed_hash(&hdr_mac_key, &raw[0..88]).as_bytes();
    if !bool::from(expected_mac.ct_eq(&info.header_mac)) {
        return Err("auth failed: wrong passphrase or tampered header".to_string());
    }

    let wrap_cipher = Knox256::new(&wrap_key);
    let mut file_key = Zeroizing::new(info.wrapped_key);
    wrap_xor(&wrap_cipher, &info.wrap_nonce, &mut file_key);

    let (enc_key, mac_key) = derive_payload_keys(&file_key, &info.stream_nonce);
    Ok(UnlockedStream {
        enc_key,
        mac_key,
        stream_nonce: info.stream_nonce,
        header_mac: info.header_mac,
    })
}

pub fn open_payload<R: Read, W: Write, F: FnMut(u64)>(
    reader: &mut R,
    writer: &mut W,
    unlocked: &UnlockedStream,
    mut on_progress: F,
) -> Result<StreamStats, String> {
    let cipher = Knox256::new(&unlocked.enc_key);

    let mut buf = vec![0u8; BATCH_ENC + 1];
    let mut pending: Option<u8> = None;
    let mut chunk_idx = 0u64;
    let mut bytes_in = HEADER_LEN as u64;
    let mut bytes_out = 0u64;

    loop {
        let mut offset = 0;
        if let Some(b) = pending.take() {
            buf[0] = b;
            offset = 1;
        }

        let n = read_full(reader, &mut buf[offset..]).map_err(|e| format!("read error: {e}"))?;
        let total = offset + n;

        if total == 0 {
            return Err("truncated container: missing payload chunks".to_string());
        }

        let is_eof = total <= BATCH_ENC;
        let batch_len = if is_eof {
            total
        } else {
            pending = Some(buf[BATCH_ENC]);
            BATCH_ENC
        };

        let slice = &buf[..batch_len];
        let count = (batch_len + ENC_CHUNK_SIZE - 1) / ENC_CHUNK_SIZE;
        let base_idx = chunk_idx;

        if count == 1 {
            let plain = decrypt_chunk(
                &cipher,
                &unlocked.mac_key,
                &unlocked.stream_nonce,
                base_idx,
                is_eof,
                slice,
            )?;
            writer
                .write_all(&plain)
                .map_err(|e| format!("write error: {e}"))?;
            bytes_out += plain.len() as u64;
        } else {
            let results: Vec<Result<Zeroizing<Vec<u8>>, String>> = (0..count)
                .into_par_iter()
                .map(|i| {
                    let start = i * ENC_CHUNK_SIZE;
                    let end = (start + ENC_CHUNK_SIZE).min(batch_len);
                    let last = is_eof && (i + 1 == count);
                    decrypt_chunk(
                        &cipher,
                        &unlocked.mac_key,
                        &unlocked.stream_nonce,
                        base_idx + (i as u64),
                        last,
                        &slice[start..end],
                    )
                })
                .collect();

            for res in results {
                let plain = res?;
                writer
                    .write_all(&plain)
                    .map_err(|e| format!("write error: {e}"))?;
                bytes_out += plain.len() as u64;
            }
        }

        bytes_in += batch_len as u64;
        chunk_idx += count as u64;
        on_progress(bytes_in - (HEADER_LEN as u64));

        if is_eof {
            break;
        }
    }

    Ok(StreamStats {
        bytes_in,
        bytes_out,
        chunks: chunk_idx,
        header_mac: unlocked.header_mac,
    })
}

pub fn seal_bytes(plain: &[u8], pass: &str) -> Result<(Vec<u8>, [u8; TAG_LEN]), String> {
    let prepared = prepare_seal(pass)?;
    let mut reader = Cursor::new(plain);
    let mut out = Vec::with_capacity(HEADER_LEN + plain.len() + TAG_LEN);
    let stats = seal_payload(&mut reader, &mut out, &prepared, |_| {})?;
    Ok((out, stats.header_mac))
}

pub fn open_bytes(blob: &[u8], pass: &str) -> Result<(Zeroizing<Vec<u8>>, [u8; TAG_LEN]), String> {
    let mut reader = Cursor::new(blob);
    let unlocked = unlock_header(&mut reader, pass)?;
    let mut plain = Zeroizing::new(Vec::new());
    let stats = open_payload(&mut reader, &mut *plain, &unlocked, |_| {})?;
    Ok((plain, stats.header_mac))
}

pub fn bench_stream_pipeline(data: &[u8]) -> [u8; TAG_LEN] {
    let cipher = Knox256::new(&[0x4Bu8; 32]);
    let mac_key = [0x7Fu8; 32];
    let nonce = [0x22u8; 16];
    let count = (data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;

    let tags: Vec<[u8; TAG_LEN]> = (0..count)
        .into_par_iter()
        .map(|i| {
            let start = i * CHUNK_SIZE;
            let end = (start + CHUNK_SIZE).min(data.len());
            let enc = encrypt_chunk(
                &cipher,
                &mac_key,
                &nonce,
                i as u64,
                i + 1 == count,
                &data[start..end],
            );
            let mut t = [0u8; TAG_LEN];
            t.copy_from_slice(&enc[enc.len() - TAG_LEN..]);
            t
        })
        .collect();

    *tags.last().unwrap_or(&[0u8; TAG_LEN])
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
    fn test_empty_and_small_stream() {
        let (sealed_empty, _) = seal_bytes(b"", "pass").unwrap();
        let (opened_empty, _) = open_bytes(&sealed_empty, "pass").unwrap();
        assert!(opened_empty.is_empty());

        let msg = b"blake3 + age stream";
        let (sealed, _) = seal_bytes(msg, "pass").unwrap();
        let (opened, _) = open_bytes(&sealed, "pass").unwrap();
        assert_eq!(&*opened, msg);
        assert!(open_bytes(&sealed, "wrong").is_err());
    }

    #[test]
    fn test_multi_chunk_truncation_and_reorder() {
        let mut data = vec![0u8; CHUNK_SIZE * 2 + 17];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        let (sealed, _) = seal_bytes(&data, "stream-pass").unwrap();
        let (opened, _) = open_bytes(&sealed, "stream-pass").unwrap();
        assert_eq!(&*opened, &data);

        let truncated = &sealed[..HEADER_LEN + ENC_CHUNK_SIZE];
        assert!(open_bytes(truncated, "stream-pass").is_err());

        let mut swapped = sealed.clone();
        let c0 = HEADER_LEN..HEADER_LEN + ENC_CHUNK_SIZE;
        let c1 = HEADER_LEN + ENC_CHUNK_SIZE..HEADER_LEN + ENC_CHUNK_SIZE * 2;
        let tmp = swapped[c0.clone()].to_vec();
        let tmp2 = swapped[c1.clone()].to_vec();
        swapped[c0].copy_from_slice(&tmp2);
        swapped[c1].copy_from_slice(&tmp);
        assert!(open_bytes(&swapped, "stream-pass").is_err());
    }

    #[test]
    fn test_exact_chunk_boundary() {
        let data = vec![0x5Au8; CHUNK_SIZE];
        let (sealed, _) = seal_bytes(&data, "edge").unwrap();
        let (opened, _) = open_bytes(&sealed, "edge").unwrap();
        assert_eq!(&*opened, &data);
    }
}
