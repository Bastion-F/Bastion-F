// Yes, I like Claude Code mascot, so I added it here. 
use std::io::{self, Write};
use std::time::Duration;

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const ACCENT: &str = "\x1b[38;5;173m";
pub const TEXT: &str = "\x1b[38;5;254m";
pub const MUTED: &str = "\x1b[38;5;244m";
pub const BORDER: &str = "\x1b[38;5;238m";
pub const GREEN: &str = "\x1b[38;5;108m";
pub const RED: &str = "\x1b[38;5;167m";

pub fn print_banner(cwd: &str) {
    println!();
    println!("  {ACCENT}▐▛███▜▌{RESET}    {BOLD}{TEXT}knox{RESET} {MUTED}v0.5.1{RESET}");
    println!("  {ACCENT}▜█████▛▘{RESET}   {MUTED}KNOX-256 · Argon2id · HKDF-SHA256 · HMAC{RESET}");
    println!("   {ACCENT}▘▘ ▝▝{RESET}     {MUTED}16 rounds · 256-bit key · {cwd}{RESET}");
    println!();
    println!("  {BORDER}──────────────────────────────────────────────────────────{RESET}");
    println!(
        "  {MUTED}Type {TEXT}/help{MUTED} for commands, {TEXT}/seal <text>{MUTED} for quick armor, {TEXT}/quit{MUTED} to exit.{RESET}"
    );
    println!();
}

pub fn print_prompt() {
    print!("{ACCENT}❯{RESET} ");
    let _ = io::stdout().flush();
}

pub fn print_op(verb: &str, subject: &str) {
    println!("{ACCENT}●{RESET} {BOLD}{TEXT}{verb}{RESET}  {TEXT}{subject}{RESET}");
}

pub fn print_line(label: &str, value: &str, last: bool) {
    let glyph = if last { "└" } else { "├" };
    println!("  {BORDER}{glyph}{RESET} {MUTED}{label:<9}{RESET} {TEXT}{value}{RESET}");
}

pub fn print_done(label: &str, value: &str, elapsed: Duration) {
    let ms = elapsed.as_secs_f64() * 1000.0;
    println!(
        "  {BORDER}└{RESET} {MUTED}{label:<9}{RESET} {GREEN}{value}{RESET}  {MUTED}[{ms:.1} ms]{RESET}"
    );
}

pub fn print_err(msg: &str) {
    eprintln!("{RED}✗{RESET} {TEXT}{msg}{RESET}");
}

pub fn print_help() {
    println!("{MUTED}Commands:{RESET}");
    println!("  {ACCENT}/enc{RESET}  {TEXT}<file> [out]{RESET}    {MUTED}Encrypt file to .knx container{RESET}");
    println!("  {ACCENT}/dec{RESET}  {TEXT}<file> [out]{RESET}    {MUTED}Verify HMAC and decrypt .knx container{RESET}");
    println!("  {ACCENT}/seal{RESET} {TEXT}<text>{RESET}          {MUTED}Encrypt text into knx2: armored token{RESET}");
    println!("  {ACCENT}/open{RESET} {TEXT}<knx2:...>{RESET}      {MUTED}Decrypt knx2: armored token{RESET}");
    println!("  {ACCENT}/info{RESET} {TEXT}<file>{RESET}          {MUTED}Inspect .knx header, salt, nonce & tag{RESET}");
    println!("  {ACCENT}/bench{RESET}                {MUTED}Run KNOX-256 throughput & avalanche check{RESET}");
    println!("  {ACCENT}/clear{RESET}                {MUTED}Clear terminal{RESET}");
    println!("  {ACCENT}/quit{RESET}                 {MUTED}Exit session{RESET}");
}

pub fn format_bytes(n: usize) -> String {
    let units = ["B", "KiB", "MiB", "GiB"];
    let mut size = n as f64;
    let mut idx = 0;
    while size >= 1024.0 && idx < units.len() - 1 {
        size /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{n} B")
    } else {
        format!("{size:.2} {}", units[idx])
    }
}
