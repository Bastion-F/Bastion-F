use anyhow::{anyhow, Context, Result};
use argon2::Argon2;
use clap::Parser;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use hkdf::Hkdf;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rand::{rngs::OsRng, RngCore};
use rayon::prelude::*;
use sha2::{Digest, Sha256, Sha512};
use std::fs::{self, File};
use std::io::{Read, Write, Seek, BufReader, BufWriter};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC_BYTES: &[u8; 8] = b"BASTION1"; // Watermark
const CHUNK_SIZE: usize = 16 * 1024 * 1024;
const ARX_ROUNDS: usize = 72;

fn read_password_masked(prompt: &str) -> Result<String> {
    use std::io::{self, Write};
    if !atty::is(atty::Stream::Stdin) {
        let mut password = String::new();
        io::stdin().read_line(&mut password)?;
        return Ok(password.trim().to_string());
    }
    print!("{}", prompt);
    io::stdout().flush()?;
    Ok(rpassword::read_password()?)
}

fn style_bar(pb: ProgressBar, msg: &'static str) -> ProgressBar {
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} {msg} [{bar:40.cyan/blue}] {percent}% ({bytes_per_sec})")
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
    round_keys: [[u32; 8]; ARX_ROUNDS],
}

impl Bastion256 {
    const GOLDEN_RATIO: u32 = 0x9E3779B9;

    fn new(key: &[u8; 32]) -> Self {
        let mut k = [0u32; 8];
        for i in 0..8 {
            k[i] = u32::from_le_bytes(key[i*4..(i+1)*4].try_into().unwrap());
        }
        let mut round_keys = [[0u32; 8]; ARX_ROUNDS];
        for r in 0..ARX_ROUNDS {
            for i in 0..8 {
                round_keys[r][i] = k[(r + i) % 8].wrapping_add((r as u32).wrapping_mul(Self::GOLDEN_RATIO));
            }
        }
        Self { round_keys }
    }

    #[inline(always)]
    fn encrypt_block(&self, block: &mut [u8; 32]) {
        let mut v = [0u32; 8];
        for i in 0..8 {
            v[i] = u32::from_le_bytes(block[i*4..(i+1)*4].try_into().unwrap());
        }

        #[inline(always)]
        fn mix(x: u32, y: u32, rot: u32) -> (u32, u32) {
            let a = x.wrapping_add(y);
            (a, y.rotate_left(rot) ^ a)
        }

        for r in 0..ARX_ROUNDS {
            for i in 0..8 {
                v[i] = v[i].wrapping_add(self.round_keys[r][i]);
            }
            
            (v[0], v[1]) = mix(v[0], v[1], 11);
            (v[2], v[3]) = mix(v[2], v[3], 15);
            (v[4], v[5]) = mix(v[4], v[5], 21);
            (v[6], v[7]) = mix(v[6], v[7], 27);
            
            v.swap(0, 3); v.swap(2, 5); v.swap(4, 7); v.swap(6, 1);
        }

        for i in 0..8 {
            block[i*4..(i+1)*4].copy_from_slice(&v[i].to_le_bytes());
        }
    }
}

fn derive_subkeys(master_key: &[u8; 64], nonce: &[u8]) -> Identity {
    let hk = Hkdf::<Sha256>::new(Some(nonce), master_key);
    let mut okm_cipher = [0u8; 32];
    let mut okm_sign = [0u8; 32];
    hk.expand(b"bastion-v4-encryption-key", &mut okm_cipher).unwrap();
    hk.expand(b"bastion-v4-ed25519-signing-key", &mut okm_sign).unwrap();
    Identity { cipher_key: okm_cipher, signing_key: okm_sign }
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
    println!("🛡️  Bastion-F v0.0.4 | Terminal");
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
    let file = File::open(path).context("File not found")?;
    let total_size = file.metadata()?.len();
    
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut master_seed = [0u8; 64];
    Argon2::default().hash_password_into(password.as_bytes(), &salt, &mut master_seed).unwrap();
    let id = derive_subkeys(&master_seed, &nonce);
    master_seed.zeroize();

    let pb = m.add(style_bar(ProgressBar::new(total_size), "Encrypting blocks..."));
    let mut out = BufWriter::with_capacity(CHUNK_SIZE, File::create(format!("{}.bastion", path))?);
    
    out.write_all(MAGIC_BYTES)?;
    out.write_all(&salt)?; 
    out.write_all(&nonce)?;
    out.write_all(&[0u8; 64])?;

    let cipher = Bastion256::new(&id.cipher_key);
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, file);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut hasher = Sha512::new();
    let mut block_idx: u128 = 0;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 { break; }
        let chunk = &mut buffer[..n];
        
        hasher.update(&*chunk); 

        chunk.par_chunks_mut(32).enumerate().for_each(|(i, blk)| {
            let mut ks = [0u8; 32];
            ks[0..16].copy_from_slice(&nonce);
            ks[16..32].copy_from_slice(&(block_idx + i as u128).to_be_bytes());
            cipher.encrypt_block(&mut ks);
            
            for j in 0..blk.len() { blk[j] ^= ks[j]; }
        });
        
        out.write_all(chunk)?;
        block_idx += ((n + 31) / 32) as u128;
        pb.inc(n as u64);
    }
    
    drop(reader); 
    
    out.flush()?;
    let mut final_file = out.into_inner()?;
    
    let signature = SigningKey::from_bytes(&id.signing_key).sign(&hasher.finalize());
    final_file.seek(std::io::SeekFrom::Start(40))?;
    final_file.write_all(&signature.to_bytes())?;

    pb.finish_with_message("⚙️  Encryption complete.");
    if shred { secure_shred(path)?; }
    Ok(())
}

fn decrypt_flow(path: &str, password: &mut String, m: &MultiProgress) -> Result<()> {
    let mut file = File::open(path)?;
    let total_size = file.metadata()?.len();
    let mut header = [0u8; 104];
    file.read_exact(&mut header)?;
    
    if &header[0..8] != MAGIC_BYTES { return Err(anyhow!("Not a Bastion-F file!")); }
    let (salt, nonce, sig_bytes) = (&header[8..24], &header[24..40], &header[40..104]);

    let mut master_seed = [0u8; 64];
    Argon2::default().hash_password_into(password.as_bytes(), salt, &mut master_seed).unwrap();
    let id = derive_subkeys(&master_seed, nonce);
    master_seed.zeroize();

    let out_path = path.replace(".bastion", ".dec");
    let pb = m.add(style_bar(ProgressBar::new(total_size - 104), "Decrypting blocks..."));
    let mut out = BufWriter::with_capacity(CHUNK_SIZE, File::create(&out_path)?);
    
    let cipher = Bastion256::new(&id.cipher_key);
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, file);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut hasher = Sha512::new();
    let mut block_idx: u128 = 0;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 { break; }
        let chunk = &mut buffer[..n];
        
        chunk.par_chunks_mut(32).enumerate().for_each(|(i, blk)| {
            let mut ks = [0u8; 32];
            ks[0..16].copy_from_slice(nonce);
            ks[16..32].copy_from_slice(&(block_idx + i as u128).to_be_bytes());
            cipher.encrypt_block(&mut ks);
            for j in 0..blk.len() { blk[j] ^= ks[j]; }
        });
        
        hasher.update(&*chunk); 
        out.write_all(chunk)?;
        block_idx += ((n + 31) / 32) as u128;
        pb.inc(n as u64);
    }
    
    out.flush()?;
    drop(out);

    let sig = Signature::from_bytes(sig_bytes.try_into()?);
    let verify_result = SigningKey::from_bytes(&id.signing_key)
        .verifying_key()
        .verify(&hasher.finalize(), &sig);

    match verify_result {
        Ok(_) => {
            pb.finish_with_message("⚙️  Decryption complete.");
            Ok(())
        },
        Err(_) => {
            let _ = fs::remove_file(&out_path);
            pb.abandon_with_message("🛑 SIGNATURE FAILED! File deleted.");
            Err(anyhow!("🛑 CRITICAL: SIGNATURE INVALID! Output file deleted for security."))
        }
    }
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
