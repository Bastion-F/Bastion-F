use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const ACCENT: &str = "\x1b[38;5;173m";
pub const TEXT: &str = "\x1b[38;5;254m";
pub const MUTED: &str = "\x1b[38;5;244m";
pub const BORDER: &str = "\x1b[38;5;238m";
pub const GREEN: &str = "\x1b[38;5;108m";
pub const RED: &str = "\x1b[38;5;167m";

const STAR_FRAMES: [&str; 10] = ["·", "✢", "✳", "✶", "✻", "✽", "✻", "✶", "✳", "✢"];

pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    active: bool,
}

impl Spinner {
    pub fn start(label: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        if !io::stderr().is_terminal() {
            return Self {
                stop,
                handle: None,
                active: false,
            };
        }

        let flag = Arc::clone(&stop);
        let text = label.to_string();

        let handle = thread::spawn(move || {
            let started = Instant::now();
            let mut idx = 0usize;
            let mut err = io::stderr();

            while !flag.load(Ordering::Relaxed) {
                let frame = STAR_FRAMES[idx % STAR_FRAMES.len()];
                let secs = started.elapsed().as_secs_f64();
                let _ = write!(
                    err,
                    "\r\x1b[2K  {ACCENT}{frame}{RESET} {MUTED}{text}…  {secs:.1}s{RESET}"
                );
                let _ = err.flush();
                idx += 1;

                for _ in 0..8 {
                    if flag.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        });

        Self {
            stop,
            handle: Some(handle),
            active: true,
        }
    }

    pub fn finish(mut self) {
        self.clear();
    }

    fn clear(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if self.active {
            self.active = false;
            let mut err = io::stderr();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.clear();
    }
}

pub struct Progress {
    verb: String,
    total: u64,
    started: Instant,
    last_draw: Instant,
    frame: usize,
    enabled: bool,
    visible: bool,
}

impl Progress {
    pub fn new(verb: &str, total: u64) -> Self {
        let now = Instant::now();
        Self {
            verb: verb.to_string(),
            total,
            started: now,
            last_draw: now,
            frame: 0,
            enabled: io::stderr().is_terminal(),
            visible: false,
        }
    }

    pub fn update(&mut self, done: u64) {
        if !self.enabled || self.total == 0 {
            return;
        }

        let now = Instant::now();
        if !self.visible {
            let big_enough = self.total >= 2 * 1024 * 1024;
            let took_time = now.duration_since(self.started) >= Duration::from_millis(60);
            if !big_enough && !took_time {
                return;
            }
        } else if done < self.total
            && now.duration_since(self.last_draw) < Duration::from_millis(33)
            {
                return;
            }

            self.visible = true;
        self.last_draw = now;

        let clamped = done.min(self.total);
        let ratio = (clamped as f64) / (self.total as f64);
        let pct = (ratio * 100.0).round() as u32;

        let width = 22usize;
        let filled = ((ratio * (width as f64)).round() as usize).min(width);
        let empty = width - filled;

        let bar_on = "━".repeat(filled);
        let bar_off = "─".repeat(empty);
        let star = STAR_FRAMES[self.frame % STAR_FRAMES.len()];
        self.frame += 1;

        let done_str = format_bytes(clamped);
        let total_str = format_bytes(self.total);
        let rate_str = format_rate(clamped, now.duration_since(self.started));

        let mut err = io::stderr();
        let _ = write!(
            err,
            "\r\x1b[2K  {ACCENT}{star}{RESET} {BOLD}{TEXT}{}{RESET}  {ACCENT}{bar_on}{BORDER}{bar_off}{RESET}  {TEXT}{pct:>3}%{RESET} {MUTED}· {done_str} / {total_str} · {rate_str}{RESET}",
            self.verb
        );
        let _ = err.flush();
    }

    pub fn finish(mut self) {
        self.clear();
    }

    fn clear(&mut self) {
        if self.visible {
            self.visible = false;
            let mut err = io::stderr();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.clear();
    }
}

fn format_rate(bytes: u64, elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64();
    if secs < 0.0005 {
        return "—".to_string();
    }
    let mib_s = (bytes as f64 / (1024.0 * 1024.0)) / secs;
    if mib_s >= 1024.0 {
        format!("{:.2} GiB/s", mib_s / 1024.0)
    } else {
        format!("{mib_s:.1} MiB/s")
    }
}

pub fn print_banner(cwd: &str, backend: &str) {
    println!();
    println!("  {ACCENT}▐▛███▜▌{RESET}    {BOLD}{TEXT}knox{RESET} {MUTED}v0.7.1{RESET}");
    println!("  {ACCENT}▜█████▛▘{RESET}   {MUTED}KNOX-256 [{backend}] · X25519 · Argon2id · BLAKE3{RESET}");
    println!("   {ACCENT}▘▘ ▝▝{RESET}     {MUTED}constant-time · 0600 atomic I/O · {cwd}{RESET}");
    println!();
    println!("  {BORDER}──────────────────────────────────────────────────────────{RESET}");
    println!(
        "  {MUTED}Type {TEXT}/help{MUTED} for commands, {TEXT}/keygen{MUTED} for X25519 keys, {TEXT}/quit{MUTED} to exit.{RESET}"
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
    println!("  {BORDER}{glyph}{RESET} {MUTED}{label:<10}{RESET} {TEXT}{value}{RESET}");
}

pub fn print_done(label: &str, value: &str, elapsed: Duration) {
    let ms = elapsed.as_secs_f64() * 1000.0;
    println!(
        "  {BORDER}└{RESET} {MUTED}{label:<10}{RESET} {GREEN}{value}{RESET}  {MUTED}[{ms:.1} ms]{RESET}"
    );
}

pub fn print_err(msg: &str) {
    eprintln!("{RED}✗{RESET} {TEXT}{msg}{RESET}");
}

pub fn print_help() {
    println!("{MUTED}Commands:{RESET}");
    println!("  {ACCENT}/keygen{RESET} {TEXT}[file]{RESET}                {MUTED}Generate X25519 keypair (0600 if saved){RESET}");
    println!("  {ACCENT}/enc{RESET}    {TEXT}[-r <pub>] <in> [out]{RESET} {MUTED}Encrypt file (passphrase or X25519){RESET}");
    println!("  {ACCENT}/dec{RESET}    {TEXT}[-i <key>] <in> [out]{RESET} {MUTED}Decrypt .knx container (auto-detect){RESET}");
    println!("  {ACCENT}/seal{RESET}   {TEXT}[-r <pub>] <text>{RESET}     {MUTED}Encrypt text into knx4: or knx5: token{RESET}");
    println!("  {ACCENT}/open{RESET}   {TEXT}[-i <key>] <token>{RESET}    {MUTED}Decrypt knx4: or knx5: armored token{RESET}");
    println!("  {ACCENT}/info{RESET}   {TEXT}<file>{RESET}                {MUTED}Inspect .knx header & parameters{RESET}");
    println!("  {ACCENT}/bench{RESET}                        {MUTED}Run KNOX-256 + BLAKE3 STREAM benchmark{RESET}");
    println!("  {ACCENT}/clear{RESET}                        {MUTED}Clear terminal{RESET}");
    println!("  {ACCENT}/quit{RESET}                         {MUTED}Exit session{RESET}");
}

pub fn format_bytes(n: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
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
