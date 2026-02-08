use anyhow::{anyhow, Context, Result};
use argon2::Argon2;
use clap::Parser;
use console::{Key, Term};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use hmac::{Hmac, Mac};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use rand::{rngs::OsRng, RngCore};
use rayon::prelude::*;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HkdfSha256 = Hmac<Sha256>;
const MAGIC_BYTES: &[u8; 8] = b"BASTION1"; // Watermark

fn read_password_masked(prompt: &str) -> Result<String> {
    let term = Term::stdout();
    term.write_str(prompt)?;
    let mut password = String::new();
    loop {
        match term.read_key()? {
            Key::Char(c) => {
                password.push(c);
                term.write_str("*")?;
            }
            Key::Enter => {
                term.write_line("")?;
                break;
            }
            Key::Backspace => {
                if !password.is_empty() {
                    password.pop();
                    term.clear_chars(1)?;
                }
            }
            _ => {}
        }
    }
    Ok(password)
}
-
fn style_spinner(pb: ProgressBar, msg: &'static str) -> ProgressBar {
    pb.set_style(ProgressStyle::default_spinner()
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
        .template("{spinner:.cyan} {msg} [{elapsed_precise}]")
        .unwrap());
    pb.set_message(msg);
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

fn style_bar(pb: ProgressBar, msg: &'static str) -> ProgressBar {
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} {msg} [{bar:40.cyan/blue}] {percent}% ({eta})")
        .unwrap()
        .progress_chars("#>-"));
    pb.set_message(msg);
    pb
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Identity {
    cipher_key: [u8; 32],
    signing_key: [u8; 32],
}

struct Bastion256 {
    round_keys: [[u32; 8]; 72],
}

impl Bastion256 {
    const GOLDEN_RATIO: u32 = 0x9E3779B9;

    fn new(key: &[u8; 32]) -> Self {
        let mut k = [0u32; 8];
        for i in 0..8 { k[i] = u32::from_le_bytes(key[i*4..(i+1)*4].try_into().unwrap()); }
        let mut round_keys = [[0u32; 8]; 72];
        for r in 0..72 {
            for i in 0..8 {
                round_keys[r][i] = k[(r + i) % 8].wrapping_add(r as u32 ^ Self::GOLDEN_RATIO);
            }
        }
        Self { round_keys }
    }

    fn encrypt_block(&self, block: &mut [u8; 32]) {
        let mut v = [0u32; 8];
        for i in 0..8 { v[i] = u32::from_le_bytes(block[i*4..(i+1)*4].try_into().unwrap()); }
        for r in 0..72 {
            for i in 0..8 { v[i] = v[i].wrapping_add(self.round_keys[r][i]); }
            let mix = |x: u32, y: u32, rot: u32| {
                let a = x.wrapping_add(y);
                (a, y.rotate_left(rot) ^ a)
            };
            (v[0], v[1]) = mix(v[0], v[1], 11); (v[2], v[3]) = mix(v[2], v[3], 15);
            (v[4], v[5]) = mix(v[4], v[5], 21); (v[6], v[7]) = mix(v[6], v[7], 27);
            v.swap(0, 3); v.swap(2, 5); v.swap(4, 7); v.swap(6, 1);
        }
        for i in 0..8 { block[i*4..(i+1)*4].copy_from_slice(&v[i].to_le_bytes()); }
    }
}

fn derive_subkeys(master_key: &[u8; 64], nonce: &[u8]) -> Identity {
    let hk = Hkdf::<Sha256>::new(Some(nonce), master_key);
    
    let mut okm_cipher = [0u8; 32];
    let mut okm_sign = [0u8; 32];
    
    hk.expand(b"bastion-v4-encryption-key", &mut okm_cipher)
        .expect("32 bytes is valid for HKDF-SHA256");
    hk.expand(b"bastion-v4-ed25519-signing-key", &mut okm_sign)
        .expect("32 bytes is valid for HKDF-SHA256");

    Identity {
        cipher_key: okm_cipher,
        signing_key: okm_sign,
    }
}

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)] encrypt: bool,
    #[arg(short, long)] decrypt: bool,
    #[arg(short, long)] path: String,
    #[arg(short, long, default_value_t = false)] shred: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    println!("🛡️  Bastion-F v0.0.2 | Terminal");

    let mut password = read_password_masked("🔑 Enter a master-key: ")?;
    if password.is_empty() { return Err(anyhow!("Password cannot be empty")); }

    let m = MultiProgress::new();

    if args.encrypt {
        encrypt_flow(&args.path, &mut password, &m, args.shred)?;
    } else if args.decrypt {
        decrypt_flow(&args.path, &mut password, &m)?;
    }

    password.zeroize();
    Ok(())
}

fn encrypt_flow(path: &str, password: &mut String, m: &MultiProgress, shred: bool) -> Result<()> {
    let sp = m.add(style_spinner(ProgressBar::new_spinner(), "Reading & Compressing..."));
    let mut data = fs::read(path).context("File not found")?;
    data = compress_prepend_size(&data);
    sp.finish_with_message("🗜️  Compression finished.");

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let kdf_sp = m.add(style_spinner(ProgressBar::new_spinner(), "Deriving keys (Argon2id + HKDF)..."));
    let mut master_seed = [0u8; 64];
    Argon2::default().hash_password_into(password.as_bytes(), &salt, &mut master_seed).unwrap();
    let id = derive_subkeys(&master_seed, &nonce);
    master_seed.zeroize();
    kdf_sp.finish_with_message("🔑 Keys derived safely.");

    let pb = m.add(style_bar(ProgressBar::new(data.len() as u64), "Encrypting blocks..."));
    let cipher = Bastion256::new(&id.cipher_key);
    
    data.par_chunks_mut(32).enumerate().for_each(|(i, chunk)| {
        let mut ks = [0u8; 32];
        ks[0..16].copy_from_slice(&nonce);
        ks[16..32].copy_from_slice(&(i as u128).to_be_bytes());
        cipher.encrypt_block(&mut ks);
        for j in 0..chunk.len() { chunk[j] ^= ks[j]; }
        pb.inc(chunk.len() as u64);
    });
    pb.finish_with_message("⚙️  Encryption complete.");

    let sig_sp = m.add(style_spinner(ProgressBar::new_spinner(), "Signing container..."));
    let signing_key = SigningKey::from_bytes(&id.signing_key);
    let mut sig_ctx = Vec::from(nonce);
    sig_ctx.extend_from_slice(&data);
    let signature = signing_key.sign(&sig_ctx);
    sig_sp.finish_with_message("✍️  Digital signature added.");

    let mut out = File::create(format!("{}.bastion", path))?;
    out.write_all(MAGIC_BYTES)?;
    out.write_all(&salt)?; out.write_all(&nonce)?;
    out.write_all(&signature.to_bytes())?; out.write_all(&data)?;

    println!("✅ DONE: {}.bastion", path);
    if shred { secure_shred(path)?; }
    Ok(())
}

fn decrypt_flow(path: &str, password: &mut String, m: &MultiProgress) -> Result<()> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC_BYTES { return Err(anyhow!("Not a Bastion-F file!")); }

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 16];
    let mut sig_bytes = [0u8; 64];
    file.read_exact(&mut salt)?;
    file.read_exact(&mut nonce)?;
    file.read_exact(&mut sig_bytes)?;

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    let kdf_sp = m.add(style_spinner(ProgressBar::new_spinner(), "Reconstructing keys..."));
    let mut master_seed = [0u8; 64];
    Argon2::default().hash_password_into(password.as_bytes(), &salt, &mut master_seed).unwrap();
    let id = derive_subkeys(&master_seed, &nonce);
    master_seed.zeroize();
    kdf_sp.finish_with_message("🔑 Keys reconstructed.");

    let sig_sp = m.add(style_spinner(ProgressBar::new_spinner(), "Verifying Ed25519 signature..."));
    let mut sig_ctx = Vec::from(nonce);
    sig_ctx.extend_from_slice(&ciphertext);
    let sig = Signature::from_bytes(&sig_bytes);
    SigningKey::from_bytes(&id.signing_key).verifying_key().verify(&sig_ctx, &sig)
        .map_err(|_| anyhow!("🛑 CRITICAL: SIGNATURE INVALID!"))?;
    sig_sp.finish_with_message("🛡️  Signature valid.");

    let pb = m.add(style_bar(ProgressBar::new(ciphertext.len() as u64), "Decrypting blocks..."));
    let cipher = Bastion256::new(&id.cipher_key);
    ciphertext.par_chunks_mut(32).enumerate().for_each(|(i, chunk)| {
        let mut ks = [0u8; 32];
        ks[0..16].copy_from_slice(&nonce);
        ks[16..32].copy_from_slice(&(i as u128).to_be_bytes());
        cipher.encrypt_block(&mut ks);
        for j in 0..chunk.len() { chunk[j] ^= ks[j]; }
        pb.inc(chunk.len() as u64);
    });
    pb.finish_with_message("⚙️  Decryption complete.");

    let dec_sp = m.add(style_spinner(ProgressBar::new_spinner(), "Decompressing..."));
    let final_data = decompress_size_prepended(&ciphertext).map_err(|_| anyhow!("LZ4 Error"))?;
    fs::write(path.replace(".bastion", ".dec"), final_data)?;
    dec_sp.finish_with_message("🔓 File restored.");

    Ok(())
}

// Shredder does not guarantee 100% security, but it makes recovery much harder. It overwrites the file 3 times with different patterns (zeros and random data) before deleting it.
fn secure_shred(path: &str) -> Result<()> {
    println!("🧹 Shredding original...");
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    let len = file.metadata()?.len();
    
    for pass in 1..=3 {
        file.seek(std::io::SeekFrom::Start(0))?;
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut written = 0;
        while written < len {
            if pass % 2 == 0 { OsRng.fill_bytes(&mut buffer); } else { buffer.fill(0); }
            let chunk = std::cmp::min(buffer.len() as u64, len - written) as usize;
            file.write_all(&buffer[..chunk])?;
            written += chunk as u64;
        }
        file.sync_all()?;
    }
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}
