#![forbid(unsafe_code)]

mod crypto;
mod ui;

use crypto::cipher::Knox256;
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
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
            ui::print_banner(&get_cwd());
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

fn run_repl() {
    ui::print_banner(&get_cwd());
    let stdin = io::stdin();

    loop {
        ui::print_prompt();
        let mut line = String::new();
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
                ui::print_banner(&get_cwd());
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

    let raw = fs::read(input_path).map_err(|e| format!("cannot read '{input_path}': {e}"))?;
    let data = Zeroizing::new(raw);
    let pass = ask_pass(true)?;

    let start = Instant::now();
    let (sealed, tag) = crypto::seal(&data, &pass)?;
    fs::write(&output_path, &sealed).map_err(|e| format!("cannot write '{output_path}': {e}"))?;

    ui::print_op("enc", &format!("{input_path} → {output_path}"));
    ui::print_line("cipher", "KNOX-256 + Argon2id + HKDF + HMAC-SHA256", false);
    ui::print_line(
        "size",
        &format!(
            "{} → {} (+{} B overhead)",
            ui::format_bytes(data.len()),
            ui::format_bytes(sealed.len()),
            crypto::HEADER_LEN + crypto::TAG_LEN
        ),
        false,
    );
    ui::print_done("tag", &format!("{} (sealed)", crypto::hex_short(&tag)), start.elapsed());
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

    let blob = fs::read(input_path).map_err(|e| format!("cannot read '{input_path}': {e}"))?;
    let pass = ask_pass(false)?;

    let start = Instant::now();
    let (plain, tag) = crypto::open(&blob, &pass)?;
    fs::write(&output_path, &*plain).map_err(|e| format!("cannot write '{output_path}': {e}"))?;

    ui::print_op("dec", &format!("{input_path} → {output_path}"));
    ui::print_line(
        "size",
        &format!("{} → {}", ui::format_bytes(blob.len()), ui::format_bytes(plain.len())),
        false,
    );
    ui::print_done("tag", &format!("{} (verified)", crypto::hex_short(&tag)), start.elapsed());
    Ok(())
}

fn run_seal(text: &str) -> Result<(), String> {
    if text.is_empty() {
        return Err("usage: /seal <plaintext>".to_string());
    }
    let pass = ask_pass(true)?;
    let start = Instant::now();
    let (sealed, tag) = crypto::seal(text.as_bytes(), &pass)?;
    let token = format!("knx2:{}", crypto::b64_encode(&sealed));

    ui::print_op("seal", &format!("{} bytes armored", text.len()));
    ui::print_line("token", &token, false);
    ui::print_done("tag", &crypto::hex_short(&tag), start.elapsed());
    Ok(())
}

fn run_open(token: &str) -> Result<(), String> {
    let payload = match token.strip_prefix("knx2:") {
        Some(p) => p,
        None => return Err("expected token starting with 'knx2:'".to_string()),
    };
    let raw = crypto::b64_decode(payload)?;
    let pass = ask_pass(false)?;

    let start = Instant::now();
    let (plain, tag) = crypto::open(&raw, &pass)?;
    let text = std::str::from_utf8(&plain).map_err(|_| "decrypted data is not valid UTF-8".to_string())?;

    ui::print_op("open", "armored token verified");
    ui::print_line("output", text, false);
    ui::print_done("tag", &crypto::hex_short(&tag), start.elapsed());
    Ok(())
}

fn run_info(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: info <file.knx>".to_string());
    }
    let path = &args[0];
    let blob = fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    let info = crypto::inspect(&blob)?;

    ui::print_op("info", path);
    ui::print_line("format", &format!("KNOX v{}", info.version), false);
    ui::print_line("payload", &ui::format_bytes(info.payload_len), false);
    ui::print_line("salt", &crypto::hex_short(&info.salt), false);
    ui::print_line("nonce", &crypto::hex_short(&info.nonce), false);
    ui::print_line("tag", &crypto::hex_short(&info.tag), true);
    Ok(())
}

fn run_bench() {
    let blocks = 500_000usize;
    let cipher = Knox256::new(&[0x4Bu8; 32]);
    let tweak = [0x7Fu8; 16];

    let mut block = [0x11u8; 16];
    let start = Instant::now();
    for _ in 0..blocks {
        block = cipher.encrypt_block(block, tweak);
    }
    let elapsed = start.elapsed();
    let mib_s = ((blocks * 16) as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();

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

    ui::print_op("bench", "KNOX-256 raw block core (16 rounds)");
    ui::print_line("throughput", &format!("{mib_s:.1} MiB/s ({blocks} blocks)"), false);
    ui::print_line("avalanche", &format!("{avg:.2}% bit flip per 1-bit delta"), false);
    ui::print_done("checksum", &crypto::hex_short(&block), elapsed);
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
