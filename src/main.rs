#![deny(unsafe_code)]

mod crypto;
mod ui;

use crypto::cipher::Knox256;
use crypto::HeaderKind;
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
        "keygen" => run_keygen(rest),
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
            "/keygen" => {
                let parts: Vec<String> = tail.split_whitespace().map(|s| s.to_string()).collect();
                run_keygen(&parts)
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

fn ask_identity() -> Result<Zeroizing<[u8; 32]>, String> {
    let input = rpassword::prompt_password(format!(
        "  {}identity (file or knxsec):{} ",
                                                   ui::MUTED,
                                                   ui::RESET
    ))
    .map_err(|e| format!("tty error: {e}"))?;
    let input = Zeroizing::new(input);
    resolve_sec_key(input.trim())
}

fn resolve_pub_key(spec: &str) -> Result<[u8; 32], String> {
    if spec.starts_with("knxpub:") {
        return crypto::decode_pub(spec);
    }
    let content = fs::read_to_string(spec)
    .map_err(|e| format!("cannot read public key from '{spec}': {e}"))?;
    for line in content.lines() {
        if let Some(pos) = line.find("knxpub:") {
            let token = line[pos..].split_whitespace().next().unwrap_or("");
            return crypto::decode_pub(token);
        }
    }
    Err(format!("no 'knxpub:' key found in '{spec}'"))
}

fn resolve_sec_key(spec: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    if spec.is_empty() {
        return Err("empty identity rejected".to_string());
    }
    if spec.starts_with("knxsec:") {
        return crypto::decode_sec(spec);
    }
    let raw = fs::read_to_string(spec)
    .map_err(|e| format!("cannot read identity file '{spec}': {e}"))?;
    let content = Zeroizing::new(raw);
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with("knxsec:") {
            return crypto::decode_sec(t);
        }
    }
    Err(format!("no 'knxsec:' key found in '{spec}'"))
}

fn parse_flag_args(args: &[String], flag: &str) -> Result<(Option<String>, Vec<String>), String> {
    let mut flag_val: Option<String> = None;
    let mut pos = Vec::new();
    let mut i = 0;

    while i < args.len() {
        if args[i] == flag {
            if i + 1 >= args.len() {
                return Err(format!("missing value after '{flag}'"));
            }
            flag_val = Some(args[i + 1].clone());
            i += 2;
        } else {
            pos.push(args[i].clone());
            i += 1;
        }
    }

    Ok((flag_val, pos))
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

fn run_keygen(args: &[String]) -> Result<(), String> {
    let start = Instant::now();
    let (sec, pub_bytes) = crypto::generate_keypair()?;
    let pub_str = crypto::encode_pub(&pub_bytes);
    let sec_str = crypto::encode_sec(&sec);

    if let Some(path) = args.first() {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            opts.mode(0o600);
        }

        let mut file = opts
        .open(path)
        .map_err(|e| format!("cannot create keyfile '{path}': {e}"))?;

        let body = Zeroizing::new(format!("# public: {pub_str}\n{}\n", &*sec_str));
        if let Err(e) = file.write_all(body.as_bytes()).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(format!("cannot write keyfile '{path}': {e}"));
        }

        ui::print_op("keygen", &format!("X25519 identity → {path}"));
        ui::print_line("public", &pub_str, false);
        ui::print_done("mode", "0600 (saved)", start.elapsed());
    } else {
        ui::print_op("keygen", "X25519 identity");
        ui::print_line("public", &pub_str, false);
        ui::print_line("secret", &sec_str, false);
        ui::print_done("status", "ready (save secret safely)", start.elapsed());
    }

    Ok(())
}

fn run_enc(args: &[String]) -> Result<(), String> {
    let (recipient, pos) = parse_flag_args(args, "-r")?;
    if pos.is_empty() {
        return Err("usage: enc [-r <knxpub|keyfile>] <file> [out]".to_string());
    }
    let input_path = &pos[0];
    let output_path = if pos.len() > 1 {
        pos[1].clone()
    } else {
        format!("{input_path}.knx")
    };

    if same_path(input_path, &output_path) {
        return Err("input and output paths must be different".to_string());
    }

    let mut in_file =
    File::open(input_path).map_err(|e| format!("cannot open '{input_path}': {e}"))?;
    let total_size = in_file.metadata().map(|m| m.len()).unwrap_or(0);

    let (prepared, mode_label, start) = if let Some(ref rec) = recipient {
        let pub_key = resolve_pub_key(rec)?;
        let start = Instant::now();
        let prep = crypto::prepare_seal_x25519(&pub_key)?;
        (prep, "X25519", start)
    } else {
        let pass = ask_pass(true)?;
        let start = Instant::now();
        let spin = ui::Spinner::start("Deriving key (Argon2id)");
        let prep = crypto::prepare_seal_pass(&pass)?;
        spin.finish();
        (prep, "Argon2id", start)
    };

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
        &format!("KNOX-256 [{}] + {mode_label} + BLAKE3", active_backend()),
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
    let (identity, pos) = parse_flag_args(args, "-i")?;
    if pos.is_empty() {
        return Err("usage: dec [-i <keyfile|knxsec>] <file.knx> [out]".to_string());
    }
    let input_path = &pos[0];
    let output_path = if pos.len() > 1 {
        pos[1].clone()
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
    let file_size = in_file.metadata().map(|m| m.len()).unwrap_or(0);
    let (raw_hdr, info) = crypto::read_header_raw(&mut in_file)?;

    let (unlocked, start) = match info.kind {
        HeaderKind::Passphrase { .. } => {
            if identity.is_some() {
                return Err("this container uses a passphrase (remove -i)".to_string());
            }
            let pass = ask_pass(false)?;
            let start = Instant::now();
            let spin = ui::Spinner::start("Unlocking header (Argon2id)");
            let u = crypto::unlock_passphrase(&raw_hdr, &info, &pass)?;
            spin.finish();
            (u, start)
        }
        HeaderKind::X25519 { .. } => {
            let sec = match identity {
                Some(ref spec) => resolve_sec_key(spec)?,
                None => ask_identity()?,
            };
            let start = Instant::now();
            let u = crypto::unlock_x25519(&raw_hdr, &info, &sec)?;
            (u, start)
        }
    };

    let payload_total = file_size.saturating_sub(unlocked.header_len as u64);
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
        return Err("usage: /seal [-r <knxpub|keyfile>] <plaintext>".to_string());
    }

    if let Some(after) = text.strip_prefix("-r ") {
        let (rec, msg) = after
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or("usage: /seal -r <knxpub|keyfile> <plaintext>")?;
        let msg = msg.trim_start();
        if msg.is_empty() {
            return Err("usage: /seal -r <knxpub|keyfile> <plaintext>".to_string());
        }

        let pub_key = resolve_pub_key(rec)?;
        let start = Instant::now();
        let (sealed, mac) = crypto::seal_bytes_x25519(msg.as_bytes(), &pub_key)?;
        let token = format!("knx5:{}", crypto::b64_encode(&sealed));

        ui::print_op("seal", &format!("{} bytes armored (X25519)", msg.len()));
        ui::print_line("token", &token, false);
        ui::print_done("hdr-mac", &crypto::hex_short(&mac), start.elapsed());
        return Ok(());
    }

    let pass = ask_pass(true)?;
    let start = Instant::now();
    let spin = ui::Spinner::start("Sealing token (Argon2id)");
    let (sealed, mac) = crypto::seal_bytes_pass(text.as_bytes(), &pass)?;
    spin.finish();

    let token = format!("knx4:{}", crypto::b64_encode(&sealed));

    ui::print_op("seal", &format!("{} bytes armored", text.len()));
    ui::print_line("token", &token, false);
    ui::print_done("hdr-mac", &crypto::hex_short(&mac), start.elapsed());
    Ok(())
}

fn run_open(text: &str) -> Result<(), String> {
    if text.is_empty() {
        return Err("usage: /open [-i <keyfile|knxsec>] <knx4:...|knx5:...>".to_string());
    }

    let (identity, token) = if let Some(after) = text.strip_prefix("-i ") {
        let (id, tok) = after
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or("usage: /open -i <keyfile|knxsec> <token>")?;
        (Some(id.to_string()), tok.trim())
    } else {
        (None, text.trim())
    };

    if let Some(payload) = token.strip_prefix("knx4:") {
        let raw = crypto::b64_decode(payload)?;
        let pass = ask_pass(false)?;
        let start = Instant::now();
        let spin = ui::Spinner::start("Verifying token (Argon2id)");
        let (plain, mac) = crypto::open_bytes_pass(&raw, &pass)?;
        spin.finish();

        let out = std::str::from_utf8(&plain)
        .map_err(|_| "decrypted data is not valid UTF-8".to_string())?;
        ui::print_op("open", "armored token verified (Argon2id)");
        ui::print_line("output", out, false);
        ui::print_done("hdr-mac", &crypto::hex_short(&mac), start.elapsed());
        return Ok(());
    }

    if let Some(payload) = token.strip_prefix("knx5:") {
        let raw = crypto::b64_decode(payload)?;
        let sec = match identity {
            Some(ref spec) => resolve_sec_key(spec)?,
            None => ask_identity()?,
        };
        let start = Instant::now();
        let (plain, mac) = crypto::open_bytes_x25519(&raw, &sec)?;

        let out = std::str::from_utf8(&plain)
        .map_err(|_| "decrypted data is not valid UTF-8".to_string())?;
        ui::print_op("open", "armored token verified (X25519)");
        ui::print_line("output", out, false);
        ui::print_done("hdr-mac", &crypto::hex_short(&mac), start.elapsed());
        return Ok(());
    }

    Err("expected token starting with 'knx4:' or 'knx5:'".to_string())
}

fn run_info(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: info <file.knx>".to_string());
    }
    let path = &args[0];
    let meta = fs::metadata(path).map_err(|e| format!("cannot stat '{path}': {e}"))?;
    let mut file = File::open(path).map_err(|e| format!("cannot open '{path}': {e}"))?;
    let (_, info) = crypto::read_header_raw(&mut file)?;

    let body_len = meta.len().saturating_sub(info.header_len as u64);
    let chunks = (body_len + (crypto::ENC_CHUNK_SIZE as u64) - 1) / (crypto::ENC_CHUNK_SIZE as u64);

    ui::print_op("info", path);
    match info.kind {
        HeaderKind::Passphrase { kdf, salt } => {
            ui::print_line("format", &format!("KNOX v{} (Passphrase · STREAM)", info.version), false);
            ui::print_line(
                "kdf",
                &format!("Argon2id ({} MiB · t={} · p={})", kdf.mem_mib(), kdf.t_cost, kdf.p_cost),
                           false,
            );
            ui::print_line(
                "file",
                &format!("{} (~{} chunks)", ui::format_bytes(meta.len()), chunks),
                           false,
            );
            ui::print_line("salt", &crypto::hex_short(&salt), false);
        }
        HeaderKind::X25519 { eph_pub } => {
            ui::print_line("format", &format!("KNOX v{} (X25519 · STREAM)", info.version), false);
            ui::print_line(
                "file",
                &format!("{} (~{} chunks)", ui::format_bytes(meta.len()), chunks),
                           false,
            );
            ui::print_line("eph-pub", &crypto::hex_short(&eph_pub), false);
        }
    }
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
