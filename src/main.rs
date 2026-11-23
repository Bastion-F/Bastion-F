#![deny(unsafe_code)]

mod crypto;
mod ui;

use crypto::cipher::Knox256;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::io::{self, BufRead, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Instant;
use zeroize::Zeroizing;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        run_repl();
        return;
    }

    let cmd = args[0].as_str();
    let rest = &args[1..];

    let res = match cmd {
        "enc" | "encrypt" => run_enc(rest),
        "dec" | "decrypt" => run_dec(rest),
        "info" | "inspect" => run_info(rest),
        "bench" => {
            run_bench();
            Ok(())
        }
        "-h" | "--help" | "help" => {
            ui::print_banner(&get_cwd(), active_backend());
            ui::print_help();
            Ok(())
        }
        other => Err(format!("unknown command '{other}' (try --help)")),
    };

    if let Err(e) = res {
        ui::print_err(&e);
        std::process::exit(1);
    }
}

fn active_backend() -> &'static str {
    let probe = Knox256::new(&[0u8; 32]);
    probe.backend_name()
}

fn run_repl() {
    ui::print_banner(&get_cwd(), active_backend());
    let stdin = io::stdin();

    loop {
        ui::print_prompt();
        let mut line = Zeroizing::new(String::new());
        match stdin.lock().read_line(&mut line) {
            Ok(0) => {
                println!();
                break;
            }
            Ok(_) => {}
            Err(e) => {
                ui::print_err(&format!("read error: {e}"));
                break;
            }
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (cmd, tail) = match trimmed.split_once(char::is_whitespace) {
            Some((c, r)) => (c, r.trim()),
            None => (trimmed, ""),
        };

        let res = match cmd {
            "/quit" | "/exit" | "quit" | "exit" => break,
            "/clear" => {
                print!("\x1b[2J\x1b[H");
                let _ = io::stdout().flush();
                ui::print_banner(&get_cwd(), active_backend());
                Ok(())
            }
            "/help" | "help" => {
                ui::print_help();
                Ok(())
            }
            "/bench" => {
                run_bench();
                Ok(())
            }
            "/enc" => {
                let parts: Vec<String> = tail.split_whitespace().map(|s| s.to_string()).collect();
                run_enc(&parts)
            }
            "/dec" => {
                let parts: Vec<String> = tail.split_whitespace().map(|s| s.to_string()).collect();
                run_dec(&parts)
            }
            "/info" | "/inspect" => {
                let parts: Vec<String> = tail.split_whitespace().map(|s| s.to_string()).collect();
                run_info(&parts)
            }
            "/seal" => run_seal(tail),
            "/open" => run_open(tail),
            _ => Err(format!("unknown command '{cmd}' — type /help")),
        };

        if let Err(e) = res {
            ui::print_err(&e);
        }
        println!();
    }
}

fn ask_pass(confirm: bool) -> Result<Zeroizing<String>, String> {
    let p1 = rpassword::prompt_password(format!("  {}passphrase:{} ", ui::MUTED, ui::RESET))
    .map_err(|e| format!("tty error: {e}"))?;
    let p1 = Zeroizing::new(p1);

    if p1.is_empty() {
        return Err("empty passphrase rejected".to_string());
    }

    if confirm {
        let p2 = rpassword::prompt_password(format!("  {}confirm:   {} ", ui::MUTED, ui::RESET))
        .map_err(|e| format!("tty error: {e}"))?;
        let p2 = Zeroizing::new(p2);

        if p1.as_bytes() != p2.as_bytes() {
            return Err("passphrases do not match".to_string());
        }
    }

    Ok(p1)
}

fn same_path(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(pa), Ok(pb)) => pa == pb,
        _ => false,
    }
}

fn create_temp_file(target: &str) -> Result<(File, PathBuf), String> {
    let parent = match Path::new(target).parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let suffix = crypto::random_hex(8)?;
    let tmp_path = parent.join(format!(".knox-tmp-{suffix}"));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }

    let file = opts
    .open(&tmp_path)
    .map_err(|e| format!("cannot create temp file '{}': {e}", tmp_path.display()))?;
    Ok((file, tmp_path))
}

fn run_enc(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: enc <file> [out]".to_string());
    }
    let input_path = &args[0];
    let output_path = if args.len() > 1 {
        args[1].clone()
    } else {
        format!("{input_path}.knx")
    };

    if same_path(input_path, &output_path) {
        return Err("input and output paths must be different".to_string());
    }

    let mut in_file =
    File::open(input_path).map_err(|e| format!("cannot open '{input_path}': {e}"))?;
    let total_size = in_file.metadata().map(|m| m.len()).unwrap_or(0);
    let pass = ask_pass(true)?;

    let start = Instant::now();
    let spin = ui::Spinner::start("Deriving key (Argon2id)");
    let prepared = crypto::prepare_seal(&pass)?;
    spin.finish();

    let (mut tmp_file, tmp_path) = create_temp_file(&output_path)?;
    let mut bar = ui::Progress::new("enc", total_size);

    let res = crypto::seal_payload(&mut in_file, &mut tmp_file, &prepared, |done| {
        bar.update(done)
    });
    bar.finish();

    let stats = match res {
        Ok(s) => s,
        Err(e) => {
            drop(tmp_file);
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
    };

    if let Err(e) = tmp_file.sync_all() {
        drop(tmp_file);
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("cannot sync output: {e}"));
    }
    drop(tmp_file);

    if let Err(e) = fs::rename(&tmp_path, &output_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("cannot finalize '{output_path}': {e}"));
    }

    ui::print_op("enc", &format!("{input_path} → {output_path}"));
    ui::print_line(
        "cipher",
        &format!("KNOX-256 [{}] + Argon2id + BLAKE3", active_backend()),
                   false,
    );
    ui::print_line(
        "size",
        &format!(
            "{} → {} ({} chunks)",
                 ui::format_bytes(stats.bytes_in),
                 ui::format_bytes(stats.bytes_out),
                 stats.chunks
        ),
        false,
    );
    ui::print_done(
        "hdr-mac",
        &format!("{} (sealed)", crypto::hex_short(&stats.header_mac)),
                   start.elapsed(),
    );
    Ok(())
}

fn run_dec(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: dec <file.knx> [out]".to_string());
    }
    let input_path = &args[0];
    let output_path = if args.len() > 1 {
        args[1].clone()
    } else if let Some(stripped) = input_path.strip_suffix(".knx") {
        stripped.to_string()
    } else {
        format!("{input_path}.dec")
    };

    if same_path(input_path, &output_path) {
        return Err("input and output paths must be different".to_string());
    }

    let mut in_file =
    File::open(input_path).map_err(|e| format!("cannot open '{input_path}': {e}"))?;
    let payload_total = in_file
    .metadata()
    .map(|m| m.len().saturating_sub(crypto::HEADER_LEN as u64))
    .unwrap_or(0);
    let pass = ask_pass(false)?;

    let start = Instant::now();
    let spin = ui::Spinner::start("Unlocking header (Argon2id)");
    let unlocked = crypto::unlock_header(&mut in_file, &pass)?;
    spin.finish();

    let (mut tmp_file, tmp_path) = create_temp_file(&output_path)?;
    let mut bar = ui::Progress::new("dec", payload_total);

    let res = crypto::open_payload(&mut in_file, &mut tmp_file, &unlocked, |done| {
        bar.update(done)
    });
    bar.finish();

    let stats = match res {
        Ok(s) => s,
        Err(e) => {
            drop(tmp_file);
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
    };

    if let Err(e) = tmp_file.sync_all() {
        drop(tmp_file);
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("cannot sync output: {e}"));
    }
    drop(tmp_file);

    if let Err(e) = fs::rename(&tmp_path, &output_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("cannot finalize '{output_path}': {e}"));
    }

    ui::print_op("dec", &format!("{input_path} → {output_path}"));
    ui::print_line(
        "size",
        &format!(
            "{} → {} ({} chunks)",
                 ui::format_bytes(stats.bytes_in),
                 ui::format_bytes(stats.bytes_out),
                 stats.chunks
        ),
        false,
    );
    ui::print_done(
        "hdr-mac",
        &format!("{} (verified)", crypto::hex_short(&stats.header_mac)),
                   start.elapsed(),
    );
    Ok(())
}

fn run_seal(text: &str) -> Result<(), String> {
    if text.is_empty() {
        return Err("usage: /seal <plaintext>".to_string());
    }
    let pass = ask_pass(true)?;
    let start = Instant::now();
    let spin = ui::Spinner::start("Sealing token (Argon2id)");
    let (sealed, mac) = crypto::seal_bytes(text.as_bytes(), &pass)?;
    spin.finish();

    let token = format!("knx4:{}", crypto::b64_encode(&sealed));

    ui::print_op("seal", &format!("{} bytes armored", text.len()));
    ui::print_line("token", &token, false);
    ui::print_done("hdr-mac", &crypto::hex_short(&mac), start.elapsed());
    Ok(())
}

fn run_open(token: &str) -> Result<(), String> {
    let payload = match token.strip_prefix("knx4:") {
        Some(p) => p,
        None => return Err("expected token starting with 'knx4:'".to_string()),
    };
    let raw = crypto::b64_decode(payload)?;
    let pass = ask_pass(false)?;

    let start = Instant::now();
    let spin = ui::Spinner::start("Verifying token (Argon2id)");
    let (plain, mac) = crypto::open_bytes(&raw, &pass)?;
    spin.finish();

    let text = std::str::from_utf8(&plain)
    .map_err(|_| "decrypted data is not valid UTF-8".to_string())?;

    ui::print_op("open", "armored token verified");
    ui::print_line("output", text, false);
    ui::print_done("hdr-mac", &crypto::hex_short(&mac), start.elapsed());
    Ok(())
}

fn run_info(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: info <file.knx>".to_string());
    }
    let path = &args[0];
    let meta = fs::metadata(path).map_err(|e| format!("cannot stat '{path}': {e}"))?;
    let mut file = File::open(path).map_err(|e| format!("cannot open '{path}': {e}"))?;
    let info = crypto::inspect_reader(&mut file)?;

    let body_len = meta.len().saturating_sub(crypto::HEADER_LEN as u64);
    let chunks = (body_len + (crypto::ENC_CHUNK_SIZE as u64) - 1) / (crypto::ENC_CHUNK_SIZE as u64);

    ui::print_op("info", path);
    ui::print_line("format", &format!("KNOX v{} (BLAKE3 STREAM)", info.version), false);
    ui::print_line(
        "kdf",
        &format!(
            "Argon2id ({} MiB · t={} · p={})",
                 info.kdf.mem_mib(),
                 info.kdf.t_cost,
                 info.kdf.p_cost
        ),
        false,
    );
    ui::print_line(
        "file",
        &format!("{} (~{} chunks)", ui::format_bytes(meta.len()), chunks),
                   false,
    );
    ui::print_line("salt", &crypto::hex_short(&info.salt), false);
    ui::print_line("nonce", &crypto::hex_short(&info.stream_nonce), false);
    ui::print_line("hdr-mac", &crypto::hex_short(&info.header_mac), true);
    Ok(())
}

fn run_bench() {
    let spin = ui::Spinner::start("Benchmarking KNOX-256 + BLAKE3 STREAM");

    let blocks = 500_000usize;
    let cipher = Knox256::new(&[0x4Bu8; 32]);
    let tweak = [0x7Fu8; 16];

    let start = Instant::now();
    let block = cipher.encrypt_chain([0x11u8; 16], tweak, blocks);
    let chain_elapsed = start.elapsed();
    let chain_mib = ((blocks * 16) as f64 / (1024.0 * 1024.0)) / chain_elapsed.as_secs_f64();

    let mut ctr_buf = vec![0x42u8; 8 * 1024 * 1024];
    let ctr_start = Instant::now();
    cipher.ctr_chunk(&tweak, 0, false, &mut ctr_buf);
    black_box(&ctr_buf);
    let ctr_elapsed = ctr_start.elapsed();
    let ctr_mib = 8.0 / ctr_elapsed.as_secs_f64();

    let size = 64 * 1024 * 1024;
    let chunks = size / crypto::CHUNK_SIZE;
    let buf = vec![0x42u8; size];
    let mut out = vec![1u8; size + chunks * crypto::TAG_LEN];

    let _ = crypto::bench_stream_pipeline(&buf[..crypto::CHUNK_SIZE * 16], &mut out);

    let stream_start = Instant::now();
    let last_tag = crypto::bench_stream_pipeline(&buf, &mut out);
    let stream_elapsed = stream_start.elapsed();
    let stream_mib = 64.0 / stream_elapsed.as_secs_f64();
    let threads = rayon::current_num_threads();

    let mut flips = 0u64;
    for i in 0..256u16 {
        let mut p1 = [0u8; 16];
        p1[0..2].copy_from_slice(&i.to_le_bytes());
        let mut p2 = p1;
        p2[(i as usize) % 16] ^= 1 << (i & 7);

        let c1 = cipher.encrypt_block(p1, tweak);
        let c2 = cipher.encrypt_block(p2, tweak);
        for j in 0..16 {
            flips += (c1[j] ^ c2[j]).count_ones() as u64;
        }
    }
    let avg = (flips as f64) / (256.0 * 128.0) * 100.0;

    spin.finish();

    let profile = if cfg!(debug_assertions) {
        "DEBUG — rebuild with --release!"
    } else {
        "release"
    };

    ui::print_op(
        "bench",
        &format!("KNOX-256 [{}] + BLAKE3 ({profile})", cipher.backend_name()),
    );
    ui::print_line(
        "1t-chain",
        &format!("{chain_mib:.1} MiB/s (serial latency, {blocks} blocks)"),
                   false,
    );
    ui::print_line("1t-ctr", &format!("{ctr_mib:.1} MiB/s (8 MiB single-core)"), false);
    ui::print_line(
        "stream",
        &format!("{stream_mib:.1} MiB/s (64 MiB enc+MAC on {threads} threads)"),
                   false,
    );
    ui::print_line("avalanche", &format!("{avg:.2}% bit flip per 1-bit delta"), false);
    ui::print_done(
        "checksum",
        &format!("{} · {}", crypto::hex_short(&block), crypto::hex_short(&last_tag)),
                   chain_elapsed + ctr_elapsed + stream_elapsed,
    );
}

fn get_cwd() -> String {
    let dir = match env::current_dir() {
        Ok(p) => p,
        Err(_) => return ".".to_string(),
    };
    let s = dir.display().to_string();
    if let Ok(home) = env::var("HOME") {
        if let Some(rel) = s.strip_prefix(&home) {
            return format!("~{rel}");
        }
    }
    match Path::new(&s).file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => ".".to_string(),
    }
}
