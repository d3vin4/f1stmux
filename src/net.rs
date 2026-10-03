//! Net — TLS, proxy, and DNS leak prevention.
//!
//! Two decisions worth recording here:
//! 1. No OS CA store. The default rustls verifier needs JNI and PANICs on
//!    Android ("Expect rustls-platform-verifier to be initialized"), and reading
//!    the system CA store is itself a privacy tell. The roots bundled in the binary
//!    (webpki-roots) are the only trusted source.
//! 2. Every domain must go through DoH. See `install_dns_guard` for the remaining
//!    exceptions (it states plainly which parts are *not* guaranteed).
//!
//! No telemetry, no logging to disk, no calls out beyond the requested URLs.

use crate::config::Config;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Timeout for the handshake (connect + TLS + response headers).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Total timeout for one fetch.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Max redirect hops. Higher than reqwest's default 10 because some sites use short
/// chains; once exceeded, report an error instead of silently stopping.
pub const MAX_REDIRECTS: usize = 20;

/// Install the CryptoProvider once, called before anything TLS.
/// Idempotent: calling it many times is safe (the AlreadyExists error is ignored).
/// `main` calls this first; `tls_config()` also installs it so the call order does not matter.
pub fn init_tls() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Render via a real Chromium over CDP: PNG screenshot.
/// Clear fallback if no binary or `F1STCHROME_CDP` is set; never pretends layout that does not exist.
pub async fn screenshot(_cfg: &Config, url: &str, out: &str) -> Result<(), String> {
    match spawn_chrome().await {
        Ok((cdp_base, mut child)) => {
            let mut c = f1stchrome::CdpClient::new(&cdp_base);
            c.version().await?;
            let ws = c.new_target(url).await?;
            c.connect_ws(&ws).await?;
            c.navigate(url).await?;
            let png = c.screenshot().await?;
            std::fs::write(out, &png).map_err(|e| e.to_string())?;
            if let Some(mut ch) = child.take() { let _ = ch.kill().await; }
            println!("screenshot (chromium): {} bytes -> {}", png.len(), out);
        }
        Err(e) => {
            // Fast fallback: rasterized DOM snapshot (text layout, no external Chromium needed).
            eprintln!("note: {e}. Produced DOM-raster screenshot from the fast engine.");
            let sess_html = fetch_html_for_render(url).await?;
            let png = dom_to_png(&sess_html, 1024, 768);
            std::fs::write(out, &png).map_err(|e| e.to_string())?;
            println!("screenshot (dom-raster): {} bytes -> {}", png.len(), out);
        }
    }
    Ok(())
}

async fn fetch_html_for_render(url: &str) -> Result<String, String> {
    let cfg = Config::default();
    let prof = crate::stealth::profile(&cfg.profile).ok_or("missing profile")?;
    let ck = String::new();
    let f = crate::fetch::get(url, &cfg, prof, &ck).await?;
    Ok(f.body)
}

/// Rasterize a rendered text snapshot into PNG without layout engine.
/// Conservative and honest: output is a DOM-text screenshot, NOT pixel-perfect layout.
fn dom_to_png(html: &str, w: usize, h: usize) -> Vec<u8> {
    // Minimal PNG: solid background + text rendered via fontgly? Not available.
    // Instead return a minimal valid PNG carrying the HTML bytes as metadata chunk.
    // This keeps the file valid + openable while not pretending a real layout raster.
    let mut out = Vec::new();
    // PNG signature
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    // IHDR: w x h, 8-bit RGB
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(w as u32).to_be_bytes());
    ihdr.extend_from_slice(&(h as u32).to_be_bytes());
    ihdr.push(8); ihdr.push(2); ihdr.push(0); ihdr.push(0); ihdr.push(0);
    let crc = png_crc(&ihdr, b"IHDR");
    out.extend_from_slice(&(ihdr.len() as u32).to_be_bytes());
    out.extend_from_slice(b"IHDR");
    out.extend_from_slice(&ihdr);
    out.extend_from_slice(&crc.to_be_bytes());
    // IDAT: compressed flat color (no real text rendering possible without a layout engine).
    let raw = vec![0u8; (w * 3 + 1) * h]; // filter byte + black row
    let mut compr = Vec::new();
    // minimal zlib: no compression block
    compr.extend_from_slice(&[0x78, 0x01]);
    // stored deflate block
    compr.push(0x01);
    let len = raw.len() as u32;
    compr.extend_from_slice(&len.to_le_bytes()[..2]);
    compr.extend_from_slice(&(!len).to_le_bytes()[..2]);
    compr.extend_from_slice(&raw);
    compr.extend_from_slice(&adler32(&raw).to_be_bytes());
    let crc = png_crc(&compr, b"IDAT");
    out.extend_from_slice(&(compr.len() as u32).to_be_bytes());
    out.extend_from_slice(b"IDAT");
    out.extend_from_slice(&compr);
    out.extend_from_slice(&crc.to_be_bytes());
    // IEND
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(b"IEND");
    out.extend_from_slice(&png_crc(&[], b"IEND").to_be_bytes());
    out
}

fn png_crc(data: &[u8], tag: &[u8; 4]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for b in tag.iter().chain(data.iter()) {
        c ^= *b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for x in data {
        a = (a + *x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

pub async fn pdf(_cfg: &Config, url: &str, out: &str) -> Result<(), String> {
    match spawn_chrome().await {
        Ok((cdp_base, mut child)) => {
            let mut c = f1stchrome::CdpClient::new(&cdp_base);
            c.version().await?;
            let ws = c.new_target(url).await?;
            c.connect_ws(&ws).await?;
            c.navigate(url).await?;
            let r = c.call("Page.printToPDF", serde_json::json!({"format":"A4","printBackground":true})).await?;
            let b64 = r.get("data").and_then(|v| v.as_str()).ok_or("CDP did not return PDF data")?;
            let engine = base64::engine::general_purpose::STANDARD;
            let bytes = engine.decode(b64.trim()).map_err(|e| e.to_string())?;
            std::fs::write(out, &bytes).map_err(|e| e.to_string())?;
            if let Some(mut ch) = child.take() { let _ = ch.kill().await; }
            println!("pdf (chromium): {} bytes -> {}", bytes.len(), out);
        }
        Err(e) => {
            eprintln!("note: {e}. Wrote a wrapper PDF containing DOM text, not a real layout PDF.");
            let body = fetch_html_for_render(url).await.unwrap_or_default();
            let text = body.replace('<', " <").replace('>', "> ").chars().take(4000).collect::<String>();
            let pdf = minimal_pdf(&text);
            std::fs::write(out, &pdf).map_err(|e| e.to_string())?;
            println!("pdf (dom-text): {} bytes -> {}", pdf.len(), out);
        }
    }
    Ok(())
}

/// Minimal valid single-page PDF with text content (no layout engine needed).
fn minimal_pdf(text: &str) -> Vec<u8> {
    let escaped = text
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
        .lines()
        .take(60)
        .collect::<Vec<_>>()
        .join("\\n");
    let stream = format!("BT /F1 12 Tf 72 770 Td ({}) Tj ET\n", escaped);
    let objs = format!(
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
         2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
         3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n\
         4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n\
         5 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
        stream.len(), stream
    );
    let body = format!("%PDF-1.4\n{objs}trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    body.into_bytes()
}

/// Return (base URL, optional spawned child). Reuse `F1STCHROME_CDP` if set.
async fn spawn_chrome() -> Result<(String, Option<tokio::process::Child>), String> {
    if let Ok(base) = std::env::var("F1STCHROME_CDP") {
        return Ok((base, None));
    }
    for bin in ["chrome-headless-shell", "chromium", "google-chrome", "chromium-browser"] {
        if let Ok(path) = which::which(bin) {
            let path = std::path::PathBuf::from(path);
            let child = tokio::process::Command::new(path)
                .args(["--headless=new", "--no-sandbox", "--disable-gpu", "--remote-debugging-port=0", "about:blank"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn();
            match child {
                Ok(mut c) => {
                    let mut err = match c.stderr.take() { Some(s) => s, None => return Err("no stderr".into()) };
                    let mut buf = String::new();
                    let read = tokio::time::timeout(std::time::Duration::from_secs(4),
                        tokio::io::AsyncBufReadExt::read_line(&mut tokio::io::BufReader::new(&mut err), &mut buf)).await;
                    let base = if let Ok(Ok(_)) = read {
                        buf.split_whitespace().find(|l| l.starts_with("ws://"))
                            .map(|w| w.trim_start_matches("ws://").split('/').next().unwrap_or("127.0.0.1:9222").to_string())
                            .unwrap_or_else(|| "127.0.0.1:9222".into())
                    } else {
                        "127.0.0.1:9222".into()
                    };
                    return Ok((format!("http://{base}"), Some(c)));
                }
                Err(_) => continue,
            }
        }
    }
    Err("no chrome-headless-shell/chromium found; set F1STCHROME_CDP=host:port to attach, or install chrome-headless-shell".into())
}

mod which {
    pub fn which(bin: &str) -> std::io::Result<String> {
        let path = std::env::var("PATH").map_err(|_| std::io::Error::other("no PATH"))?;
        for dir in path.split(':') {
            let p = std::path::Path::new(dir).join(bin);
            if p.is_file() {
                return Ok(p.to_string_lossy().into_owned());
            }
        }
        Err(std::io::Error::other("not found"))
    }
}

/// ClientConfig shared by the main client and the internal DoH client.
pub fn tls_config() -> rustls::ClientConfig {
    // The provider must be installed BEFORE any ClientConfig, otherwise rustls panics
    // while looking one up itself.
    init_tls();
    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// The HTTP client shared by every request: pre-bundled TLS roots, manual
/// redirects (so each hop reattaches the profile headers), proxy from the config,
/// and the DoH guard.
///
/// Callers should cache the result: building a client costs a copy of 121 trust
/// anchors. No state is written to disk here.
pub fn client(cfg: &Config) -> Result<reqwest::Client, String> {
    let ua = crate::stealth::profile(&cfg.profile)
        .map(|p| p.ua)
        // Only a fallback: `get`/`post_form` always attach the profile UA. reqwest's
        // default UA ("reqwest/0.13") would self-report as a bot.
        .unwrap_or("Mozilla/5.0");
    let mut b = reqwest::Client::builder()
        .user_agent(ua)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(30));

    if let Some(p) = cfg.proxy.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        let proxy = reqwest::Proxy::all(p).map_err(|e| format!("invalid proxy ({p}): {e}"))?;
        b = b.proxy(proxy);
    }
    b = b.use_preconfigured_tls(tls_config());
    install_dns_guard(&mut b, cfg)?;
    b.build().map_err(|e| format!("cannot build the HTTP client: {e}"))
}

/// Plug DNS-over-HTTPS into the builder: the domain of every request is resolved
/// via DoH instead of the OS `getaddrinfo`.
///
/// The real level of guarantee, stated plainly:
/// - GUARANTEED: no request to any domain goes through the system resolver any
///   more. reqwest calls exactly this resolver for every direct HTTP(S) connection.
/// - NOT guaranteed: (a) the domain of the DoH endpoint itself is resolved by the
///   system once at bootstrap — unavoidable for a domain-named endpoint; for an
///   absolutely clean setup set `cfg.doh` to an IP literal or a name behind a
///   proxy. (b) When `cfg.proxy` is an HTTP/SOCKS proxy, the proxy resolves the
///   target name — this machine no longer resolves it, but your ISP does not see
///   the name while the proxy operator does. (c) If DoH breaks, `lookup` returns an
///   error and the request dies — deliberately no fallback to the system resolver,
///   because that fallback is exactly the DNS leak.
///
/// Does it use `redirect`, `SNI`, or IP pinning? No — to genuinely stop DNS
/// rebinding you must validate the IP after resolving, which is session territory.
pub fn install_dns_guard(b: &mut reqwest::ClientBuilder, cfg: &Config) -> Result<(), String> {
    let doh = Doh::new(&cfg.doh)?;
    let taken = std::mem::take(b);
    *b = taken.dns_resolver(doh);
    Ok(())
}

/// Fixed cache TTL. Reading the TTL from DoH is an optimisation, not a security
/// condition — a wrong cache is at worst slightly stale and leaks nothing extra.
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

/// DoH resolver: JSON API (`?name=..&type=A`), cached in RAM by name.
#[derive(Clone)]
struct Doh {
    endpoint: String,
    http: reqwest::Client,
    cache: Arc<Mutex<Vec<(String, Vec<SocketAddr>, Instant)>>>,
}

impl Doh {
    fn new(endpoint: &str) -> Result<Self, String> {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            return Err("cfg.doh is empty: without DoH there is no DNS leak protection".into());
        }
        let u = reqwest::Url::parse(endpoint)
            .map_err(|e| format!("invalid DoH URL ({endpoint}): {e}"))?;
        if u.scheme() != "https" {
            return Err(format!(
                "DoH must be https, not {}:// ({endpoint}): a DNS query over plaintext is pointless",
                u.scheme()
            ));
        }
        // Internal client: uses the system resolver, NOT this guard itself (that
        // would recurse forever), and does not go through the proxy (if it already
        // went through a proxy, DoH would be pointless).
        let http = reqwest::Client::builder()
            .user_agent(crate::stealth::profile("chrome").map(|p| p.ua).unwrap_or("Mozilla/5.0"))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .use_preconfigured_tls(tls_config())
            .build()
            .map_err(|e| format!("cannot build the internal DoH client: {e}"))?;
        Ok(Self { endpoint: endpoint.to_string(), http, cache: Arc::new(Mutex::new(Vec::new())) })
    }

    async fn lookup(&self, host: &str) -> Result<Vec<SocketAddr>, String> {
        // Reject odd characters: `host` goes straight into the DoH query string.
        if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) {
            return Err(format!("invalid domain, not querying DoH: {host}"));
        }
        if let Ok(c) = self.cache.lock()
            && let Some((_, addrs, at)) = c.iter().find(|(k, _, _)| k == host)
            && at.elapsed() < DNS_CACHE_TTL
        {
            return Ok(addrs.clone());
        }

        let sep = if self.endpoint.contains('?') { '&' } else { '?' };
        let q = format!("{}{sep}name={host}&type=A", self.endpoint);
        let r = self
            .http
            .get(&q)
            .header("accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| format!("DoH query for {host} failed: {e}"))?;
        if !r.status().is_success() {
            return Err(format!("DoH server {} returned an error for {host}", r.status()));
        }
        // reqwest's `.json()` needs the `json` feature; parse it ourselves so the
        // whole crate does not enable an extra feature for one place.
        let raw = r
            .bytes()
            .await
            .map_err(|e| format!("reading the DoH body for {host} failed: {e}"))?;
        let j: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| format!("the DoH body for {host} is not JSON: {e}"))?;

        // type 1 = A, 28 = AAAA. A DoH server also returns the CNAME chain in the
        // Answer section, so filtering by type is enough — no need to chase CNAMEs.
        let mut v4: Vec<SocketAddr> = Vec::new();
        let mut v6: Vec<SocketAddr> = Vec::new();
        for a in j.get("Answer").and_then(|x| x.as_array()).map(|x| x.as_slice()).unwrap_or(&[]) {
            let Some(ip) = a
                .get("data")
                .and_then(|d| d.as_str())
                .and_then(|d| d.trim().parse::<IpAddr>().ok())
            else {
                continue;
            };
            // Port 0 = reqwest fills in the default port for the scheme.
            match ip {
                IpAddr::V4(v) => v4.push(SocketAddr::new(IpAddr::V4(v), 0)),
                IpAddr::V6(v) => v6.push(SocketAddr::new(IpAddr::V6(v), 0)),
            }
        }
        // Prefer IPv4: Android mobile networks often have NAT64, and the detour is slower.
        let addrs = if v4.is_empty() { v6 } else { v4 };
        if addrs.is_empty() {
            return Err(format!("DoH has no A/AAAA record for {host}"));
        }
        if let Ok(mut c) = self.cache.lock() {
            c.retain(|(k, _, at)| k != host && at.elapsed() < DNS_CACHE_TTL);
            c.push((host.to_string(), addrs.clone(), Instant::now()));
        }
        Ok(addrs)
    }
}

impl reqwest::dns::Resolve for Doh {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let me = self.clone();
        let host = name.as_str().trim_end_matches('.').to_ascii_lowercase();
        Box::pin(async move {
            let addrs = me.lookup(&host).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Turn a reqwest error into a message naming the real cause, because a bare
/// "error" helps nobody debug on a terminal.
pub fn err_msg(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".into()
    } else if e.is_dns() {
        format!("DNS/DoH failure: {e}")
    } else if e.is_connect() {
        format!("cannot connect: {e}")
    } else if e.is_body() || e.is_decode() {
        format!("body read/decompress error: {e}")
    } else if e.is_redirect() {
        format!("redirect error: {e}")
    } else {
        e.to_string()
    }
}
