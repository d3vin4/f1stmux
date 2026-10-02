//! Utility layer for the CLI: get, eval, bench, devtools.
//!
//! Split out of `main.rs` so `main.rs` only parses commands.
//!
//! Everything runs on the single `current_thread` runtime owned by `main` — it
//! never creates a child runtime (a nested runtime panics immediately).

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

/// Measure performance over the same set of URLs, optionally compared to Lightpanda.
pub async fn bench(cfg: &Config, urls_file: Option<&str>, compare: Option<&str>) -> Result<(), String> {
    let urls: Vec<String> = match urls_file {
        Some(f) => std::fs::read_to_string(f)
            .map_err(|e| format!("read {f}: {e}"))?
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
        return Err("no URLs to measure".into());
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

    // Current RSS of this very process.
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
        println!("\n=== comparison with {bin} ===");
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
        println!("\naverage: {:.0} ms/URL", total / ours.len() as f64);
    }
    Ok(())
}

/// DevTools in the terminal: a REPL loop over one tab.
pub async fn devtools(cfg: &Config, url: &str) -> Result<(), String> {
    use std::io::Write;

    let mut sess = Session::new();
    let nav = navigate(url, cfg, &mut sess, &WaitFor::default(), true).await?;
    println!("loaded {} -> {} ({})", nav.final_url, nav.status, nav.elapsed_ms);
    println!("title: {}", nav.title);
    println!("text:  {} chars", nav.text.len());
    if !nav.console.is_empty() {
        println!("console: {} lines", nav.console.len());
        for (k, m) in nav.console.iter().take(20) {
            println!("  [{k}] {m}");
        }
    }
    println!("\nkeys: q quit · t text · d dom · c console · n network · <expr> eval JS");
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
                Err(e) => println!("JS error: {e}"),
            },
        }
    }
    Ok(())
}

pub async fn audit(cfg: &Config, url: &str) -> Result<(), String> {
    let mut sess = crate::session::Session::new();
    let r = crate::session::navigate(url, cfg, &mut sess, &crate::session::WaitFor::default(), false).await?;
    let cookies: Vec<crate::fetch::Cookie> = sess.cookies.all().iter().cloned().collect();
    let mut a = crate::audit::audit_from(
        &r.final_url,
        r.status,
        &sess.net.last().map(|n| n.resp_headers.clone()).unwrap_or_default(),
        &sess.dom.as_ref().map(|d| d.borrow().inner_html(0)).unwrap_or_default(),
        &cookies,
    );
    a.url = url.into();
    println!("{} -> {} ({})\n", a.url, a.final_url, a.status);
    println!("missing security headers: {}", a.missing_headers.join(", "));
    for f in &a.findings {
        println!("[{:4}] {}\n       {}", f.level, f.title, f.evidence);
    }
    Ok(())
}
