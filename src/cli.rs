//! Lớp tiện ích cho CLI: get, eval, bench, devtools.
//!
//! Tách khỏi `main.rs` để `main.rs` chỉ lo parse lệnh.
//!
//! Tất cả chạy trên runtime current_thread duy nhất của `main` — không tự
//! tạo runtime con (lồng runtime là panic ngay).

use crate::config::Config;
use crate::session::{navigate, Session, WaitFor};
use crate::stealth;
use std::time::Instant;

pub async fn get(cfg: &Config, url: &str, js: bool) -> Result<crate::session::NavResult, String> {
    let mut sess = Session::new();
    navigate(url, cfg, &mut sess, &WaitFor::default(), js).await
}

pub async fn eval(cfg: &Config, url: &str, script: &str) -> Result<serde_json::Value, String> {
    let mut sess = Session::new();
    navigate(url, cfg, &mut sess, &WaitFor::default(), true).await?;
    crate::session::eval(&sess, script)
}

pub fn dom_html(r: &crate::session::NavResult) -> Result<String, String> {
    Ok(r.html.clone())
}

/// Đo hiệu năng trên cùng một bộ URL, có thể so với Lightpanda.
pub async fn bench(cfg: &Config, urls_file: Option<&str>, compare: Option<&str>) -> Result<(), String> {
    let urls: Vec<String> = match urls_file {
        Some(f) => std::fs::read_to_string(f)
            .map_err(|e| format!("đọc {f}: {e}"))?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect(),
        None => vec![
            "https://example.com/".into(),
            "https://www.rfc-editor.org/rfc/rfc9110.html".into(),
            "https://news.ycombinator.com/".into(),
        ],
    };
    if urls.is_empty() {
        return Err("không có URL nào để đo".into());
    }

    println!("profile: {}   URL: {}", cfg.profile, urls.len());
    println!("{:.<52} {:>7} {:>9} {:>9}", "URL", "status", "ms", "bytes");
    println!("{}", "-".repeat(80));

    let mut ours = Vec::new();
    for u in &urls {
        let mut sess = Session::new();
        let t = Instant::now();
        match navigate(u, cfg, &mut sess, &WaitFor::default(), true).await {
            Ok(r) => {
                let short: String = u.chars().take(50).collect();
                println!("{short:<52} {:>7} {:>9} {:>9}", r.status, t.elapsed().as_millis(), r.text.len());
                ours.push((u.clone(), t.elapsed().as_millis() as f64, r.text.len() as f64));
            }
            Err(e) => println!("{u:<52} {:>7}   {}", "ERR", e),
        }
    }

    // RSS hiện tại của chính tiến trình.
    let rss = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS")).map(str::to_string))
        .unwrap_or_default();
    println!("\n{rss}");
    if let Ok(exe) = std::env::current_exe().map_err(|e| e.to_string())
        && let Ok(b) = std::fs::metadata(exe) {
        println!("binary: {:.1} MB", b.len() as f64 / 1e6);
    }

    if let Some(bin) = compare {
        println!("\n=== so sánh với {bin} ===");
        println!("{:.<52} {:>9}", "URL", "ms");
        for u in &urls {
            let t = Instant::now();
            let out = std::process::Command::new(bin).arg(u).output();
            match out {
                Ok(_o) => println!("{:<52} {:>9}", u.chars().take(50).collect::<String>(), t.elapsed().as_millis()),
                Err(e) => println!("{u:<52}   ERR {e}"),
            }
        }
    }

    let total: f64 = ours.iter().map(|(_, ms, _)| ms).sum();
    if !ours.is_empty() {
        println!("\ntrung bình: {:.0} ms/URL", total / ours.len() as f64);
    }
    Ok(())
}

/// DevTools trong terminal: vòng lặp REPL trên một tab.
pub async fn devtools(cfg: &Config, url: &str) -> Result<(), String> {
    use std::io::Write;

    let mut sess = Session::new();
    let nav = navigate(url, cfg, &mut sess, &WaitFor::default(), true).await?;
    println!("loaded {} -> {} ({})", nav.final_url, nav.status, nav.elapsed_ms);
    println!("title: {}", nav.title);
    println!("text:  {} ký tự", nav.text.len());
    if !nav.console.is_empty() {
        println!("console: {} dòng", nav.console.len());
        for (k, m) in nav.console.iter().take(20) {
            println!("  [{k}] {m}");
        }
    }
    println!("\ngõ: q thoát · t text · d dom · c console · n network · <expr> eval JS");
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    loop {
        print!("f1> ");
        let _ = std::io::stdout().flush();
        line.clear();
        if std::io::stdin().read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let c = line.trim();
        match c {
            "q" | "quit" | "exit" => break,
            "t" => println!("{}", sess.dom.as_ref().map(|d| d.borrow().text_content(0)).unwrap_or_default()),
            "d" => println!("{}", sess.dom.as_ref().map(|d| d.borrow().inner_html(0)).unwrap_or_default()),
            "c" => {
                if let Some(r) = &sess.realm {
                    let o = r.take();
                    for (k, m) in &o.console { println!("[{k}] {m}"); }
                    for e in &o.errors { println!("[error] {e}"); }
                }
            }
            "n" => {
                for e in &sess.net {
                    println!("{} {:>3} {:>5}b {:>6}ms {}", e.method, e.status, e.body_len, e.elapsed_ms, e.url);
                }
            }
            "" => {}
            expr => match crate::session::eval(&sess, expr) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default()),
                Err(e) => println!("lỗi JS: {e}"),
            },
        }
    }
    Ok(())
}

/// Cài CryptoProvider. Phải gọi trước mọi thứ TLS — xem `net.rs`.
pub fn init_tls() {
    let _ = stealth::names();
}
