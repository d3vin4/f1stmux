//! F1stmux CLI. Một binary: vừa làm client, vừa làm daemon.

use clap::{Parser, Subcommand};
use f1stmux::config::Config;

#[derive(Parser)]
#[command(name = "f1stmux", version, about = "Headless browser cho AI, thiết kế Termux")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Đường dẫn file config JSON.
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,
    /// Profile giả danh tính: chrome, edge, brave.
    #[arg(long, global = true)]
    profile: Option<String>,
    /// Proxy http/https/socks5.
    #[arg(long, global = true)]
    proxy: Option<String>,
    /// Cho phép daemon bind địa chỉ remote (mặc định chỉ loopback, vì daemon không auth).
    #[arg(long, global = true)]
    allow_remote: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Chạy daemon (JSON-RPC + DevTools).
    Serve,
    /// Mở một URL và in ra.
    Get {
        url: String,
        /// In DOM thay vì text.
        #[arg(long)]
        dom: bool,
        /// In JSON đầy đủ (NavResult).
        #[arg(long)]
        json: bool,
        /// Không chạy JS.
        #[arg(long)]
        no_js: bool,
    },
    /// Chạy JS trên URL và in kết quả.
    Eval {
        url: String,
        script: String,
    },
    /// In accessibility/DOM snapshot dạng cây.
    Tree { url: String },
    /// Liệt kê tool cho AI.
    Tools,
    /// Đo hiệu năng.
    Bench {
        /// Đường dẫn tới danh sách URL (mỗi dòng một URL).
        #[arg(long)]
        urls: Option<String>,
        #[arg(long)]
        compare: Option<String>,
    },
    /// DevTools trong terminal: vòng lặp lệnh trên tab hiện tại.
    Devtools { url: String },
    /// MCP server qua stdio cho AI client (opencode, Claude Code...).
    Mcp,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();
    let mut cfg = Config::load(cli.config.as_deref());
    if let Some(p) = cli.profile { cfg.profile = p; }
    if let Some(p) = cli.proxy { cfg.proxy = Some(p); }
    if cli.allow_remote { cfg.allow_remote = true; }

    // Provider TLS phải cài trước mọi thứ. Xem src/net.rs.
    f1stmux::net::init_tls();

    if let Err(e) = run(&cfg, cli.cmd).await {
        eprintln!("lỗi: {e}");
        std::process::exit(1);
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
                eprintln!("\n--- {} lỗi JS ---", r.errors.len());
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
    }
}

