pub mod cipher;

use argon2::{Algorithm, Argon2, Params, Version};
use cipher::Knox256;
use rayon::prelude::*;
use std::io::{self, Cursor, Read, Write};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 4] = b"KNOX";
pub const VERSION_PASS: u8 = 4;
pub const VERSION_X25519: u8 = 5;
pub const HEADER_LEN_PASS: usize = 120;
pub const HEADER_LEN_X25519: usize = 136;
pub const TAG_LEN: usize = 32;
pub const CHUNK_SIZE: usize = 64 * 1024;
pub const ENC_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_LEN;

const BATCH_CHUNKS: usize = 64;
const BATCH_PLAIN: usize = BATCH_CHUNKS * CHUNK_SIZE;
const BATCH_ENC: usize = BATCH_CHUNKS * ENC_CHUNK_SIZE;

pub const DEFAULT_M_LOG2: u8 = 16;
pub const DEFAULT_T_COST: u8 = 3;
pub const DEFAULT_P_COST: u8 = 4;

#[derive(Clone, Copy)]
pub struct KdfParams {
    pub m_log2: u8,
    pub t_cost: u8,
    pub p_cost: u8,
}

impl KdfParams {
    pub fn default_v4() -> Self {
        Self {
            m_log2: DEFAULT_M_LOG2,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.m_log2 < 12 || self.m_log2 > 22 {
            return Err("invalid argon2 memory parameter in header".to_string());
        }
        if self.t_cost < 1 || self.t_cost > 16 {
            return Err("invalid argon2 time parameter in header".to_string());
        }
        if self.p_cost < 1 || self.p_cost > 16 {
            return Err("invalid argon2 lanes parameter in header".to_string());
        }
        Ok(())
    }

    pub fn mem_kib(&self) -> u32 {
        1u32 << self.m_log2
    }

    pub fn mem_mib(&self) -> u32 {
        self.mem_kib() / 1024
    }
}

pub enum HeaderKind {
    Passphrase { kdf: KdfParams, salt: [u8; 16] },
    X25519 { eph_pub: [u8; 32] },
}

pub struct HeaderInfo {
    pub version: u8,
    pub header_len: usize,
    pub kind: HeaderKind,
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
    pub header: Vec<u8>,
    pub enc_key: Zeroizing<[u8; 32]>,
    pub mac_key: Zeroizing<[u8; 32]>,
    pub stream_nonce: [u8; 16],
    pub header_mac: [u8; TAG_LEN],
}

pub struct UnlockedStream {
    pub header_len: usize,
    pub enc_key: Zeroizing<[u8; 32]>,
    pub mac_key: Zeroizing<[u8; 32]>,
    pub stream_nonce: [u8; 16],
    pub header_mac: [u8; TAG_LEN],
}

fn fill_rand(buf: &mut [u8]) -> Result<(), String> {
    getrandom::getrandom(buf).map_err(|_| "system rng failed".to_string())
}

pub fn random_hex(len: usize) -> Result<String, String> {
    let mut buf = vec![0u8; len];
    fill_rand(&mut buf)?;
    let mut out = String::with_capacity(len * 2);
    for b in buf {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

pub fn generate_keypair() -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), String> {
    let mut sec_bytes = Zeroizing::new([0u8; 32]);
    fill_rand(&mut *sec_bytes)?;
    let sec = StaticSecret::from(*sec_bytes);
    let pub_key = PublicKey::from(&sec);
    Ok((sec_bytes, *pub_key.as_bytes()))
}

pub fn encode_pub(bytes: &[u8; 32]) -> String {
    format!("knxpub:{}", b64_encode(bytes))
}

pub fn encode_sec(bytes: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(format!("knxsec:{}", b64_encode(bytes)))
}

pub fn decode_pub(s: &str) -> Result<[u8; 32], String> {
    let body = match s.trim().strip_prefix("knxpub:") {
        Some(b) => b,
        None => return Err("expected public key starting with 'knxpub:'".to_string()),
    };
    let raw = b64_decode(body)?;
    if raw.len() != 32 {
        return Err("invalid x25519 public key length".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub fn decode_sec(s: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let body = match s.trim().strip_prefix("knxsec:") {
        Some(b) => b,
        None => return Err("expected secret key starting with 'knxsec:'".to_string()),
    };
    let raw = Zeroizing::new(b64_decode(body)?);
    if raw.len() != 32 {
        return Err("invalid x25519 secret key length".to_string());
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&raw);
    Ok(out)
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

fn derive_kek_pass(
    pass: &[u8],
    salt: &[u8; 16],
    kdf: KdfParams,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    kdf.validate()?;
    let params = Params::new(kdf.mem_kib(), kdf.t_cost as u32, kdf.p_cost as u32, Some(32))
    .map_err(|_| "invalid argon2 params".to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master = Zeroizing::new([0u8; 32]);
    argon
    .hash_password_into(pass, salt, &mut *master)
    .map_err(|_| "argon2 derivation failed".to_string())?;

    let mut km = Zeroizing::new([0u8; 48]);
    km[0..32].copy_from_slice(&*master);
    km[32..48].copy_from_slice(salt);

    let wrap_key = Zeroizing::new(blake3::derive_key("knox v4 header wrap key", &*km));
    let hdr_mac_key = Zeroizing::new(blake3::derive_key("knox v4 header mac key", &*km));
    Ok((wrap_key, hdr_mac_key))
}

fn derive_kek_x25519(
    shared: &[u8; 32],
    eph_pub: &[u8; 32],
    rec_pub: &[u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    if bool::from(shared.ct_eq(&[0u8; 32])) {
        return Err("invalid low-order x25519 public key".to_string());
    }

    let mut km = Zeroizing::new([0u8; 96]);
    km[0..32].copy_from_slice(shared);
    km[32..64].copy_from_slice(eph_pub);
    km[64..96].copy_from_slice(rec_pub);

    let wrap_key = Zeroizing::new(blake3::derive_key("knox v5 x25519 wrap key", &*km));
    let hdr_mac_key = Zeroizing::new(blake3::derive_key("knox v5 x25519 header mac key", &*km));
    Ok((wrap_key, hdr_mac_key))
}

fn derive_payload_keys(
    version: u8,
    file_key: &[u8; 32],
    stream_nonce: &[u8; 16],
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut km = Zeroizing::new([0u8; 48]);
    km[0..32].copy_from_slice(file_key);
    km[32..48].copy_from_slice(stream_nonce);

    let (enc_ctx, mac_ctx) = if version == VERSION_X25519 {
        ("knox v5 payload enc key", "knox v5 payload mac key")
    } else {
        ("knox v4 payload enc key", "knox v4 payload mac key")
    };

    let enc_key = Zeroizing::new(blake3::derive_key(enc_ctx, &*km));
    let mac_key = Zeroizing::new(blake3::derive_key(mac_ctx, &*km));
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

fn encrypt_chunk_into(
    cipher: &Knox256,
    mac_key: &[u8; 32],
    stream_nonce: &[u8; 16],
    chunk_idx: u64,
    is_last: bool,
    plain: &[u8],
    dst: &mut [u8],
) {
    let len = plain.len();
    dst[..len].copy_from_slice(plain);
    cipher.ctr_chunk(stream_nonce, chunk_idx, is_last, &mut dst[..len]);
    let tag = chunk_mac(mac_key, stream_nonce, chunk_idx, is_last, &dst[..len]);
    dst[len..len + TAG_LEN].copy_from_slice(&tag);
}

fn decrypt_chunk_into(
    cipher: &Knox256,
    mac_key: &[u8; 32],
    stream_nonce: &[u8; 16],
    chunk_idx: u64,
    is_last: bool,
    enc: &[u8],
    dst: &mut [u8],
) -> Result<(), String> {
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

    dst[..split].copy_from_slice(ct);
    cipher.ctr_chunk(stream_nonce, chunk_idx, is_last, &mut dst[..split]);
    Ok(())
}

pub fn prepare_seal_pass(pass: &str) -> Result<PreparedSeal, String> {
    let kdf = KdfParams::default_v4();
    let mut salt = [0u8; 16];
    let mut wrap_nonce = [0u8; 16];
    let mut stream_nonce = [0u8; 16];
    let mut file_key = Zeroizing::new([0u8; 32]);

    fill_rand(&mut salt)?;
    fill_rand(&mut wrap_nonce)?;
    fill_rand(&mut stream_nonce)?;
    fill_rand(&mut *file_key)?;

    let (wrap_key, hdr_mac_key) = derive_kek_pass(pass.as_bytes(), &salt, kdf)?;
    let wrap_cipher = Knox256::new(&wrap_key);

    let mut wrapped_key = *file_key;
    wrap_xor(&wrap_cipher, &wrap_nonce, &mut wrapped_key);

    let mut header = vec![0u8; HEADER_LEN_PASS];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = VERSION_PASS;
    header[5] = kdf.m_log2;
    header[6] = kdf.t_cost;
    header[7] = kdf.p_cost;
    header[8..24].copy_from_slice(&salt);
    header[24..40].copy_from_slice(&wrap_nonce);
    header[40..72].copy_from_slice(&wrapped_key);
    header[72..88].copy_from_slice(&stream_nonce);

    let header_mac = *blake3::keyed_hash(&hdr_mac_key, &header[0..88]).as_bytes();
    header[88..120].copy_from_slice(&header_mac);

    let (enc_key, mac_key) = derive_payload_keys(VERSION_PASS, &file_key, &stream_nonce);

    Ok(PreparedSeal {
        header,
       enc_key,
       mac_key,
       stream_nonce,
       header_mac,
    })
}

pub fn prepare_seal_x25519(recipient_pub: &[u8; 32]) -> Result<PreparedSeal, String> {
    let mut eph_raw = Zeroizing::new([0u8; 32]);
    let mut wrap_nonce = [0u8; 16];
    let mut stream_nonce = [0u8; 16];
    let mut file_key = Zeroizing::new([0u8; 32]);

    fill_rand(&mut *eph_raw)?;
    fill_rand(&mut wrap_nonce)?;
    fill_rand(&mut stream_nonce)?;
    fill_rand(&mut *file_key)?;

    let eph_sec = StaticSecret::from(*eph_raw);
    let eph_pub = PublicKey::from(&eph_sec);
    let rec_pub = PublicKey::from(*recipient_pub);
    let shared = eph_sec.diffie_hellman(&rec_pub);

    let (wrap_key, hdr_mac_key) =
    derive_kek_x25519(shared.as_bytes(), eph_pub.as_bytes(), recipient_pub)?;
    let wrap_cipher = Knox256::new(&wrap_key);

    let mut wrapped_key = *file_key;
    wrap_xor(&wrap_cipher, &wrap_nonce, &mut wrapped_key);

    let mut header = vec![0u8; HEADER_LEN_X25519];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = VERSION_X25519;
    header[8..40].copy_from_slice(eph_pub.as_bytes());
    header[40..56].copy_from_slice(&wrap_nonce);
    header[56..88].copy_from_slice(&wrapped_key);
    header[88..104].copy_from_slice(&stream_nonce);

    let header_mac = *blake3::keyed_hash(&hdr_mac_key, &header[0..104]).as_bytes();
    header[104..136].copy_from_slice(&header_mac);

    let (enc_key, mac_key) = derive_payload_keys(VERSION_X25519, &file_key, &stream_nonce);

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
    let mut out_batch = vec![0u8; BATCH_ENC];
    let mut pending: Option<u8> = None;
    let mut chunk_idx = 0u64;
    let mut bytes_in = 0u64;
    let mut bytes_out = prepared.header.len() as u64;

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
                let mut empty_tag = [0u8; TAG_LEN];
                encrypt_chunk_into(
                    &cipher,
                    &prepared.mac_key,
                    &prepared.stream_nonce,
                    0,
                    true,
                    &[],
                    &mut empty_tag,
                );
                writer
                .write_all(&empty_tag)
                .map_err(|e| format!("write error: {e}"))?;
                bytes_out += TAG_LEN as u64;
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
        let enc_len = batch_len + count * TAG_LEN;
        let out_slice = &mut out_batch[..enc_len];

        if count == 1 {
            encrypt_chunk_into(
                &cipher,
                &prepared.mac_key,
                &prepared.stream_nonce,
                base_idx,
                is_eof,
                slice,
                out_slice,
            );
        } else {
            out_slice
            .par_chunks_mut(ENC_CHUNK_SIZE)
            .enumerate()
            .for_each(|(i, dst)| {
                let start = i * CHUNK_SIZE;
                let end = (start + CHUNK_SIZE).min(batch_len);
                let last = is_eof && (i + 1 == count);
                encrypt_chunk_into(
                    &cipher,
                    &prepared.mac_key,
                    &prepared.stream_nonce,
                    base_idx + (i as u64),
                                   last,
                                   &slice[start..end],
                                   dst,
                );
            });
        }

        writer
        .write_all(out_slice)
        .map_err(|e| format!("write error: {e}"))?;
        bytes_out += enc_len as u64;
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
    if raw.len() < 8 || &raw[0..4] != MAGIC {
        return Err("invalid or corrupted KNOX container".to_string());
    }

    match raw[4] {
        VERSION_PASS => {
            if raw.len() < HEADER_LEN_PASS {
                return Err("truncated KNOX v4 header".to_string());
            }
            let kdf = KdfParams {
                m_log2: raw[5],
                t_cost: raw[6],
                p_cost: raw[7],
            };
            kdf.validate()?;

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
                version: VERSION_PASS,
                header_len: HEADER_LEN_PASS,
                kind: HeaderKind::Passphrase { kdf, salt },
                wrap_nonce,
                wrapped_key,
                stream_nonce,
                header_mac,
            })
        }
        VERSION_X25519 => {
            if raw.len() < HEADER_LEN_X25519 {
                return Err("truncated KNOX v5 header".to_string());
            }
            let mut eph_pub = [0u8; 32];
            let mut wrap_nonce = [0u8; 16];
            let mut wrapped_key = [0u8; 32];
            let mut stream_nonce = [0u8; 16];
            let mut header_mac = [0u8; TAG_LEN];

            eph_pub.copy_from_slice(&raw[8..40]);
            wrap_nonce.copy_from_slice(&raw[40..56]);
            wrapped_key.copy_from_slice(&raw[56..88]);
            stream_nonce.copy_from_slice(&raw[88..104]);
            header_mac.copy_from_slice(&raw[104..136]);

            Ok(HeaderInfo {
                version: VERSION_X25519,
                header_len: HEADER_LEN_X25519,
                kind: HeaderKind::X25519 { eph_pub },
                wrap_nonce,
                wrapped_key,
                stream_nonce,
                header_mac,
            })
        }
        v => Err(format!("unsupported container version: v{v}")),
    }
}

pub fn read_header_raw<R: Read>(reader: &mut R) -> Result<(Vec<u8>, HeaderInfo), String> {
    let mut prefix = [0u8; 8];
    let n = read_full(reader, &mut prefix).map_err(|e| format!("read error: {e}"))?;
    if n < 8 || &prefix[0..4] != MAGIC {
        return Err("invalid or corrupted KNOX container".to_string());
    }

    let total = match prefix[4] {
        VERSION_PASS => HEADER_LEN_PASS,
        VERSION_X25519 => HEADER_LEN_X25519,
        v => return Err(format!("unsupported container version: v{v}")),
    };

    let mut raw = vec![0u8; total];
    raw[0..8].copy_from_slice(&prefix);
    let rest = read_full(reader, &mut raw[8..]).map_err(|e| format!("read error: {e}"))?;
    if rest < total - 8 {
        return Err("invalid or truncated KNOX header".to_string());
    }

    let info = parse_header(&raw)?;
    Ok((raw, info))
}

pub fn unlock_passphrase(
    raw: &[u8],
    info: &HeaderInfo,
    pass: &str,
) -> Result<UnlockedStream, String> {
    let (kdf, salt) = match info.kind {
        HeaderKind::Passphrase { kdf, salt } => (kdf, salt),
        _ => return Err("container requires an X25519 secret key, not a passphrase".to_string()),
    };

    let (wrap_key, hdr_mac_key) = derive_kek_pass(pass.as_bytes(), &salt, kdf)?;
    let expected_mac = *blake3::keyed_hash(&hdr_mac_key, &raw[0..88]).as_bytes();
    if !bool::from(expected_mac.ct_eq(&info.header_mac)) {
        return Err("auth failed: wrong passphrase or tampered header".to_string());
    }

    let wrap_cipher = Knox256::new(&wrap_key);
    let mut file_key = Zeroizing::new(info.wrapped_key);
    wrap_xor(&wrap_cipher, &info.wrap_nonce, &mut file_key);

    let (enc_key, mac_key) = derive_payload_keys(VERSION_PASS, &file_key, &info.stream_nonce);
    Ok(UnlockedStream {
        header_len: info.header_len,
       enc_key,
       mac_key,
       stream_nonce: info.stream_nonce,
       header_mac: info.header_mac,
    })
}

pub fn unlock_x25519(
    raw: &[u8],
    info: &HeaderInfo,
    secret: &[u8; 32],
) -> Result<UnlockedStream, String> {
    let eph_pub = match info.kind {
        HeaderKind::X25519 { eph_pub } => eph_pub,
        _ => return Err("container requires a passphrase, not an X25519 key".to_string()),
    };

    let sec = StaticSecret::from(*secret);
    let rec_pub = PublicKey::from(&sec);
    let shared = sec.diffie_hellman(&PublicKey::from(eph_pub));

    let (wrap_key, hdr_mac_key) =
    derive_kek_x25519(shared.as_bytes(), &eph_pub, rec_pub.as_bytes())?;
    let expected_mac = *blake3::keyed_hash(&hdr_mac_key, &raw[0..104]).as_bytes();
    if !bool::from(expected_mac.ct_eq(&info.header_mac)) {
        return Err("auth failed: wrong X25519 key or tampered header".to_string());
    }

    let wrap_cipher = Knox256::new(&wrap_key);
    let mut file_key = Zeroizing::new(info.wrapped_key);
    wrap_xor(&wrap_cipher, &info.wrap_nonce, &mut file_key);

    let (enc_key, mac_key) = derive_payload_keys(VERSION_X25519, &file_key, &info.stream_nonce);
    Ok(UnlockedStream {
        header_len: info.header_len,
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
    let mut plain_batch = Zeroizing::new(vec![0u8; BATCH_PLAIN]);
    let mut pending: Option<u8> = None;
    let mut chunk_idx = 0u64;
    let mut bytes_in = unlocked.header_len as u64;
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
        let last_chunk_len = batch_len - (count - 1) * ENC_CHUNK_SIZE;

        if last_chunk_len < TAG_LEN || (count > 1 && last_chunk_len == TAG_LEN) {
            return Err("corrupted or truncated chunk".to_string());
        }

        let plain_len = batch_len - count * TAG_LEN;
        let out_slice = &mut plain_batch[..plain_len];

        let res = if count == 1 {
            decrypt_chunk_into(
                &cipher,
                &unlocked.mac_key,
                &unlocked.stream_nonce,
                base_idx,
                is_eof,
                slice,
                out_slice,
            )
        } else {
            out_slice
            .par_chunks_mut(CHUNK_SIZE)
            .enumerate()
            .try_for_each(|(i, dst)| {
                let start = i * ENC_CHUNK_SIZE;
                let end = (start + ENC_CHUNK_SIZE).min(batch_len);
                let last = is_eof && (i + 1 == count);
                decrypt_chunk_into(
                    &cipher,
                    &unlocked.mac_key,
                    &unlocked.stream_nonce,
                    base_idx + (i as u64),
                                   last,
                                   &slice[start..end],
                                   dst,
                )
            })
        };

        if let Err(e) = res {
            out_slice.zeroize();
            return Err(e);
        }

        if plain_len > 0 {
            writer
            .write_all(out_slice)
            .map_err(|e| format!("write error: {e}"))?;
            bytes_out += plain_len as u64;
            out_slice.zeroize();
        }

        bytes_in += batch_len as u64;
        chunk_idx += count as u64;
        on_progress(bytes_in - (unlocked.header_len as u64));

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

pub fn seal_bytes_pass(plain: &[u8], pass: &str) -> Result<(Vec<u8>, [u8; TAG_LEN]), String> {
    let prepared = prepare_seal_pass(pass)?;
    let mut reader = Cursor::new(plain);
    let mut out = Vec::with_capacity(HEADER_LEN_PASS + plain.len() + TAG_LEN);
    let stats = seal_payload(&mut reader, &mut out, &prepared, |_| {})?;
    Ok((out, stats.header_mac))
}

pub fn seal_bytes_x25519(
    plain: &[u8],
    recipient_pub: &[u8; 32],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), String> {
    let prepared = prepare_seal_x25519(recipient_pub)?;
    let mut reader = Cursor::new(plain);
    let mut out = Vec::with_capacity(HEADER_LEN_X25519 + plain.len() + TAG_LEN);
    let stats = seal_payload(&mut reader, &mut out, &prepared, |_| {})?;
    Ok((out, stats.header_mac))
}

pub fn open_bytes_pass(
    blob: &[u8],
    pass: &str,
) -> Result<(Zeroizing<Vec<u8>>, [u8; TAG_LEN]), String> {
    let mut reader = Cursor::new(blob);
    let (raw, info) = read_header_raw(&mut reader)?;
    let unlocked = unlock_passphrase(&raw, &info, pass)?;
    let mut plain = Zeroizing::new(Vec::new());
    let stats = open_payload(&mut reader, &mut *plain, &unlocked, |_| {})?;
    Ok((plain, stats.header_mac))
}

pub fn open_bytes_x25519(
    blob: &[u8],
    secret: &[u8; 32],
) -> Result<(Zeroizing<Vec<u8>>, [u8; TAG_LEN]), String> {
    let mut reader = Cursor::new(blob);
    let (raw, info) = read_header_raw(&mut reader)?;
    let unlocked = unlock_x25519(&raw, &info, secret)?;
    let mut plain = Zeroizing::new(Vec::new());
    let stats = open_payload(&mut reader, &mut *plain, &unlocked, |_| {})?;
    Ok((plain, stats.header_mac))
}

pub fn bench_stream_pipeline(data: &[u8], out: &mut [u8]) -> [u8; TAG_LEN] {
    let cipher = Knox256::new(&[0x4Bu8; 32]);
    let mac_key = [0x7Fu8; 32];
    let nonce = [0x22u8; 16];
    let count = (data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
    let enc_len = data.len() + count * TAG_LEN;

    out[..enc_len]
    .par_chunks_mut(ENC_CHUNK_SIZE)
    .enumerate()
    .for_each(|(i, dst)| {
        let start = i * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(data.len());
        encrypt_chunk_into(
            &cipher,
            &mac_key,
            &nonce,
            i as u64,
            i + 1 == count,
            &data[start..end],
            dst,
        );
    });

    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&out[enc_len - TAG_LEN..enc_len]);
    tag
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
            if input.len() % 4 == 1 {
                return Err("malformed armored token".to_string());
            }

            let mut out = Vec::with_capacity((input.len() * 3) / 4);
            let mut buf = 0u32;
            let mut bits = 0u32;

            for b in input.bytes() {
                let val = match b {
                    b'A'..=b'Z' => b - b'A',
                    b'a'..=b'z' => b - b'a' + 26,
                    b'0'..=b'9' => b - b'0' + 52,
                    b'-' => 62,
                    b'_' => 63,
                    _ => return Err("malformed armored token".to_string()),
                };
                buf = (buf << 6) | (val as u32);
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push(((buf >> bits) & 0xFF) as u8);
                }
            }

            if bits > 0 && (buf & ((1u32 << bits) - 1)) != 0 {
                return Err("non-canonical armored token".to_string());
            }

            Ok(out)
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn test_empty_and_small_stream() {
                let (sealed_empty, _) = seal_bytes_pass(b"", "pass").unwrap();
                let (opened_empty, _) = open_bytes_pass(&sealed_empty, "pass").unwrap();
                assert!(opened_empty.is_empty());

                let msg = b"avx2 + aes-ni + blake3 stream";
                let (sealed, _) = seal_bytes_pass(msg, "pass").unwrap();
                let (opened, _) = open_bytes_pass(&sealed, "pass").unwrap();
                assert_eq!(&*opened, msg);
                assert!(open_bytes_pass(&sealed, "wrong").is_err());
            }

            #[test]
            fn test_x25519_roundtrip_and_tamper() {
                let (sec1, pub1) = generate_keypair().unwrap();
                let (sec2, _) = generate_keypair().unwrap();

                let pub_str = encode_pub(&pub1);
                let sec_str = encode_sec(&sec1);
                assert_eq!(decode_pub(&pub_str).unwrap(), pub1);
                assert_eq!(*decode_sec(&sec_str).unwrap(), *sec1);

                let msg = b"x25519 public-key wrapped file_key";
                let (mut sealed, _) = seal_bytes_x25519(msg, &pub1).unwrap();
                let (opened, _) = open_bytes_x25519(&sealed, &sec1).unwrap();
                assert_eq!(&*opened, msg);

                assert!(open_bytes_x25519(&sealed, &sec2).is_err());
                assert!(open_bytes_pass(&sealed, "pass").is_err());

                sealed[HEADER_LEN_X25519 + 3] ^= 1;
                assert!(open_bytes_x25519(&sealed, &sec1).is_err());
            }

            #[test]
            fn test_multi_chunk_truncation_and_reorder() {
                let mut data = vec![0u8; CHUNK_SIZE * 2 + 17];
                for (i, b) in data.iter_mut().enumerate() {
                    *b = (i % 251) as u8;
                }

                let (sealed, _) = seal_bytes_pass(&data, "stream-pass").unwrap();
                let (opened, _) = open_bytes_pass(&sealed, "stream-pass").unwrap();
                assert_eq!(&*opened, &data);

                let truncated = &sealed[..HEADER_LEN_PASS + ENC_CHUNK_SIZE];
                assert!(open_bytes_pass(truncated, "stream-pass").is_err());

                let mut swapped = sealed.clone();
                let c0 = HEADER_LEN_PASS..HEADER_LEN_PASS + ENC_CHUNK_SIZE;
                let c1 = HEADER_LEN_PASS + ENC_CHUNK_SIZE..HEADER_LEN_PASS + ENC_CHUNK_SIZE * 2;
                let tmp = swapped[c0.clone()].to_vec();
                let tmp2 = swapped[c1.clone()].to_vec();
                swapped[c0].copy_from_slice(&tmp2);
                swapped[c1].copy_from_slice(&tmp);
                assert!(open_bytes_pass(&swapped, "stream-pass").is_err());
            }

            #[test]
            fn test_canonical_base64() {
                for len in 0..32 {
                    let mut data = Vec::new();
                    for i in 0..len {
                        data.push((i * 37) as u8);
                    }
                    let enc = b64_encode(&data);
                    assert_eq!(b64_decode(&enc).unwrap(), data);
                }
                assert!(b64_decode("AB").is_err());
                assert!(b64_decode("A").is_err());
                assert!(b64_decode("AA+A").is_err());
            }
        }
