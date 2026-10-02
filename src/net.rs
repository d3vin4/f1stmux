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
