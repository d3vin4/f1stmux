//! F1stmux CLI. One binary: both a client and a daemon.

use clap::{Parser, Subcommand};
use f1stmux::config::Config;

#[derive(Parser)]
#[command(name = "f1stmux", version, about = "Headless browser for AI, built for Termux")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Path to the JSON config file.
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,
    /// Identity profile: chrome, edge, brave.
    #[arg(long, global = true)]
    profile: Option<String>,
    /// Proxy http/https/socks5.
    #[arg(long, global = true)]
    proxy: Option<String>,
    /// Allow the daemon to bind a remote address (defaults to loopback only, since the daemon has no auth).
    #[arg(long, global = true)]
    allow_remote: bool,
    /// Engine: fast | chromium | auto (auto picks chromium when the page needs full layout/API).
    #[arg(long, global = true, default_value = "fast")]
    engine: String,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (JSON-RPC + DevTools).
    Serve,
    /// Open a URL and print it.
    Get {
        url: String,
        /// Print the DOM instead of text.
        #[arg(long)]
        dom: bool,
        /// Print the full JSON (NavResult).
        #[arg(long)]
        json: bool,
        /// Do not run JS.
        #[arg(long)]
        no_js: bool,
    },
    /// Run JS on a URL and print the result.
    Eval {
        url: String,
        script: String,
    },
    /// Print an accessibility/DOM snapshot as a tree.
    Tree { url: String },
    /// List the tools available to AI.
    Tools,
    /// Measure performance.
    Bench {
        /// Path to a URL list (one URL per line).
        #[arg(long)]
        urls: Option<String>,
        #[arg(long)]
        compare: Option<String>,
    },
    /// DevTools in the terminal: a command loop on the current tab.
    Devtools { url: String },
    /// MCP server over stdio for AI clients (opencode, Claude Code...).
    Mcp,
    /// Static security audit of a URL: headers, CSP/CORS, cookies, endpoint/CVE literals in the source.
    Audit { url: String },
    /// PNG screenshot via Chromium CDP (real layout).
    Screenshot { url: String, #[arg(long, short = 'o')] out: String },
    /// PDF via Chromium CDP (real layout).
    Pdf { url: String, #[arg(long, short = 'o')] out: String },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();
    let mut cfg = Config::load(cli.config.as_deref());
    if let Some(p) = cli.profile { cfg.profile = p; }
    if let Some(p) = cli.proxy { cfg.proxy = Some(p); }
    if cli.allow_remote { cfg.allow_remote = true; }

    // --engine chromium/auto: point discovery via env for the lib, full adapter not embedded yet.
    // No faking: a missing binary only reports clearly + falls back to the fast engine.
    let engine = f1stchrome::EngineKind::parse(&cli.engine);
    if engine != f1stchrome::EngineKind::Fast {
        if let Err(e) = probe_chromium().await {
            eprintln!("note: --engine {} requires the chromium backend — {e}. Using the fast engine for this command.", cli.engine);
        }
    }

    // The TLS provider must be installed before anything else. See src/net.rs.
    f1stmux::net::init_tls();

    if let Err(e) = run(&cfg, cli.cmd).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Check whether chrome-headless-shell/Chromium exists on the machine. Returns a clear
/// error instead of faking a browser. Discovery: the F1STCHROME_CDP env var (host:port)
/// or the chrome-headless-shell binary in PATH.
async fn probe_chromium() -> Result<(), String> {
    if std::env::var("F1STCHROME_CDP").is_ok() {
        return Ok(());
    }
    for bin in ["chrome-headless-shell", "chromium", "google-chrome", "chromium-browser"] {
        if which::which(bin).is_ok() {
            return Ok(());
        }
    }
    Err("chrome-headless-shell/chromium not found; set F1STCHROME_CDP=host:port to attach".into())
}

/// Minimal `which` — avoids adding a crate for a single PATH scan.
mod which {
    pub fn which(bin: &str) -> std::io::Result<()> {
        let path = std::env::var("PATH").map_err(|_| std::io::Error::other("no PATH"))?;
        for dir in path.split(':') {
            let p = std::path::Path::new(dir).join(bin);
            if p.is_file() {
                return Ok(());
            }
        }
        Err(std::io::Error::other("not found"))
    }
}

async fn run(cfg: &Config, cmd: Cmd) -> Result<(), String> {
    match cmd {
        Cmd::Serve => f1stmux::rpc::serve(cfg.clone()).await,
        Cmd::Get { url, dom, json, no_js } => {
            let r = f1stmux::cli::get(cfg, &url, !no_js).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
            } else if dom {
                println!("{}", f1stmux::cli::dom_html(&r)?);
            } else {
                println!("{}", r.text);
            }
            if !r.errors.is_empty() {
                eprintln!("\n--- {} JS errors ---", r.errors.len());
                for e in r.errors.iter().take(10) {
                    eprintln!("  {e}");
                }
            }
            Ok(())
        }
        Cmd::Eval { url, script } => {
            let v = f1stmux::cli::eval(cfg, &url, &script).await?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(())
        }
        Cmd::Tree { url } => {
            let r = f1stmux::cli::get(cfg, &url, true).await?;
            println!("{}", f1stmux::cli::dom_html(&r)?);
            Ok(())
        }
        Cmd::Tools => {
            println!("{}", serde_json::to_string_pretty(&f1stmux::tools::catalog()).unwrap_or_default());
            Ok(())
        }
        Cmd::Bench { urls, compare } => f1stmux::cli::bench(cfg, urls.as_deref(), compare.as_deref()).await,
        Cmd::Devtools { url } => f1stmux::cli::devtools(cfg, &url).await,
        Cmd::Mcp => f1stmux::mcp::run(cfg.clone()).await,
        Cmd::Audit { url } => f1stmux::cli::audit(cfg, &url).await,
        Cmd::Screenshot { url, out } => f1stmux::net::screenshot(cfg, &url, &out).await,
        Cmd::Pdf { url, out } => f1stmux::net::pdf(cfg, &url, &out).await,
    }
}

