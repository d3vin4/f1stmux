//! Page fetching: profile headers → GET → manual redirects → decompress → text.
//!
//! Handling redirects manually (instead of letting reqwest follow them) is
//! deliberate: every hop must reattach the profile headers in the right order,
//! otherwise the UA/Client-Hints fall back to reqwest defaults on the second hop —
//! the most obvious tell. In return we have to watch `Location` ourselves and cap
//! the number of hops.
//!
//! The cookie jar lives in RAM. No telemetry, no logging to disk.

use crate::blocklist::is_blocked_scheme;
use crate::config::Config;
use crate::net;
use crate::stealth::{self, Profile};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Body ceiling. 8 MB covers every ordinary static/SPA page; for larger RSS feeds
/// use `get_bytes` and handle the result yourself.
pub const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fetched {
    /// The requested URL (before redirects).
    pub url: String,
    /// The URL after walking the whole redirect chain.
    pub final_url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub elapsed_ms: u128,
    /// The path taken, hop by hop, in order.
    pub redirects: Vec<String>,
    /// f1stmux has no HTTP cache yet, so this is always false. The field exists so
    /// tools do not have to guess whether the body came from the network or disk;
    /// add a cache when there is one.
    pub from_cache: bool,
}

/// GET, body decompressed into a String. `cookie` is the `Cookie:` header already
/// assembled from the session jar (empty = do not send it).
pub async fn get(
    url: &str,
    cfg: &Config,
    prof: &Profile,
    cookie: &str,
) -> Result<Fetched, String> {
    Ok(run(url, cfg, prof, cookie, None).await?.0)
}

/// Binary GET (images, downloads). `Fetched.body` is still filled with lossy text
/// so the struct shape does not change by kind — the caller reads bytes via `Vec<u8>`.
pub async fn get_bytes(
    url: &str,
    cfg: &Config,
    prof: &Profile,
    cookie: &str,
) -> Result<(Fetched, Vec<u8>), String> {
    run(url, cfg, prof, cookie, None).await
}

/// POST `application/x-www-form-urlencoded` — login, form submit. After 303 (and
/// 302 like a browser) switch to GET and drop the body, exactly like a real browser.
pub async fn post_form(
    url: &str,
    cfg: &Config,
    prof: &Profile,
    cookie: &str,
    body: &str,
) -> Result<(Fetched, Vec<u8>), String> {
    run(url, cfg, prof, cookie, Some(body)).await
}

async fn run(
    url: &str,
    cfg: &Config,
    prof: &Profile,
    cookie: &str,
    post: Option<&str>,
) -> Result<(Fetched, Vec<u8>), String> {
    let mut cur = check_url(url)?;
    let client = net::client(cfg)?;
    let start = Instant::now();
    let mut redirects: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(cur.to_string());
    let mut referer: Option<String> = None;
    let mut method_post = post.is_some();

    loop {
        let verb = if method_post { "POST" } else { "GET" };
        let mut req = client
            .request(if method_post { reqwest::Method::POST } else { reqwest::Method::GET }, cur.as_str())
            .header("accept-encoding", "gzip, deflate, br");
        for (k, v) in stealth::headers(prof, referer.as_deref()) {
            req = req.header(k, v);
        }
        if !cookie.is_empty() {
            req = req.header("cookie", cookie);
        }
        if let Some(b) = post.filter(|_| method_post) {
            req = req.header("content-type", "application/x-www-form-urlencoded").body(b.to_string());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("{verb} {} failed: {}", cur, net::err_msg(&e)))?;

        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if let Some(loc) = location.filter(|_| (300..400).contains(&status)) {
            if redirects.len() >= net::MAX_REDIRECTS {
                return Err(format!(
                    "{} exceeded {} redirects — possibly a loop",
                    url, net::MAX_REDIRECTS
                ));
            }
            let next = reqwest::Url::options()
                .base_url(Some(&cur))
                .parse(&loc)
                .map_err(|e| format!("invalid Location ({loc}): {e}"))?;
            let next = check_url(next.as_str())?;
            if !seen.insert(next.to_string()) {
                return Err(format!("redirect loop at {next}"));
            }
            redirects.push(cur.to_string());
            referer = Some(cur.to_string());
            cur = next;
            // Always for 303, for 302 only when it was a POST: the browser convention is GET.
            if matches!(status, 302 | 303) {
                method_post = false;
            }
            continue;
        }

        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .flat_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_string(), s.to_string())))
            .collect();
        let bytes = read_body(resp).await?;
        return Ok((
            Fetched {
                url: url.to_string(),
                final_url: cur.to_string(),
                status,
                headers: headers.clone(),
                body: decode_text(&bytes, &headers),
                elapsed_ms: start.elapsed().as_millis(),
                redirects,
                from_cache: false,
            },
            bytes,
        ));
    }
}

async fn read_body(mut resp: reqwest::Response) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() && len as usize > MAX_BODY {
        return Err(format!(
            "body of {len} bytes exceeds the {MAX_BODY} byte (8 MB) ceiling — use get_bytes if you really need it"
        ));
    }
    let mut out = Vec::new();
    while let Some(c) = resp.chunk().await.map_err(|e| net::err_msg(&e))? {
        if out.len() + c.len() > MAX_BODY {
            return Err(format!("body exceeded the {MAX_BODY} byte (8 MB) ceiling while reading"));
        }
        out.extend_from_slice(&c);
    }
    Ok(out)
}

/// http/https only. `is_blocked_scheme` is the defence layer for WebRTC/WS — this
/// allowlist is the real fence.
fn check_url(url: &str) -> Result<reqwest::Url, String> {
    let u = reqwest::Url::parse(url).map_err(|e| format!("invalid URL ({url}): {e}"))?;
    let s = u.scheme();
    if s != "http" && s != "https" {
        return Err(format!(
            "scheme {s}: not allowed (http/https only; file:, data:, rtc: are all blocked)"
        ));
    }
    if is_blocked_scheme(s) {
        return Err(format!("scheme {s}: blocked"));
    }
    Ok(u)
}

/// Decode the body with the real charset: the Content-Type header first, then
/// <meta charset> in the first 2 KB. If neither is found, lossy UTF-8. Without this
/// crate whole windows-1251/shift_jis/gbk pages turn into mojibake — rutracker has
/// already proven that.
fn decode_text(b: &[u8], headers: &[(String, String)]) -> String {
    let b = b.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(b);
    if let Some(cs) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .and_then(|(_, v)| v.split(';').find_map(|p| {
            let p = p.trim();
            p.strip_prefix("charset=")
                .or_else(|| p.strip_prefix("charset ="))
                .map(|s| s.trim_matches(['"', '\'']).trim().to_string())
        }))
        .or_else(|| meta_charset(b))
        && !cs.eq_ignore_ascii_case("utf-8")
        && !cs.eq_ignore_ascii_case("utf8")
    {
        if let Some(enc) = encoding_rs::Encoding::for_label(cs.as_bytes()) {
            return enc.decode(b).0.into_owned();
        }
    }
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(b).into_owned(),
    }
}

/// Scan for <meta charset="..."> or <meta ... content="...charset=..."> in the first 2 KB.
/// Walk EVERY meta tag (do not stop at the first one — it may be the viewport).
fn meta_charset(b: &[u8]) -> Option<String> {
    let head = &b[..b.len().min(2048)];
    let lower: Vec<u8> = head.iter().map(|c| c.to_ascii_lowercase()).collect();
    let s = std::str::from_utf8(&lower).ok()?;
    let mut rest = s;
    while let Some(i) = rest.find("<meta") {
        let tag = &rest[i..];
        let end = tag.find('>')?;
        let tag = &tag[..end];
        if let Some(j) = tag.find("charset=") {
            let v = tag[j + 8..].trim_start_matches([' ', '"', '\'']);
            let end = v.find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':')).unwrap_or(v.len());
            if !v[..end].is_empty() {
                return Some(v[..end].to_string());
            }
        }
        rest = &rest[i + 5..];
    }
    None
}

// ───────────────────────── cookie jar ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    /// Matches only the exact host that set the cookie, not subdomains.
    pub host_only: bool,
    pub path: String,
    /// Unix seconds. `None` = a session cookie (dies with the process).
    pub expires: Option<u64>,
    pub secure: bool,
    /// HttpOnly means JS cannot read it — modelled with this flag, because there is
    /// no `document.cookie` here at all, only explicit RPC calls.
    pub visible_to_js: bool,
}

#[derive(Debug, Default, Clone)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_from_headers(&mut self, url: &str, headers: &[(String, String)]) {
        let Ok(base) = reqwest::Url::parse(url) else { return };
        let now = unix_now();
        for (k, v) in headers {
            if !k.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            let Some(c) = parse_set_cookie(&base, v, now) else { continue };
            // Max-Age <= 0 means delete the cookie.
            if c.expires == Some(0) {
                self.cookies.retain(|e| !(e.name == c.name && e.domain == c.domain && e.path == c.path));
                continue;
            }
            self.cookies.retain(|e| !(e.name == c.name && e.domain == c.domain && e.path == c.path));
            self.cookies.push(c);
        }
    }

    /// The `Cookie:` header to send, oldest first (like a browser).
    pub fn header_for(&self, url: &str) -> String {
        join(&self.match_all(url, false))
    }

    /// The part JS is allowed to see (HttpOnly dropped). Called by the session only,
    /// after the scripts have run.
    pub fn visible_for_js(&self, url: &str) -> String {
        join(&self.match_all(url, true))
    }

    /// The session cookies, so the `get_cookies` tool can list them.
    pub fn all(&self) -> &[Cookie] {
        &self.cookies
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    fn match_all(&self, url: &str, js: bool) -> Vec<&Cookie> {
        let Ok(u) = reqwest::Url::parse(url) else { return Vec::new() };
        let Some(host) = u.host_str().map(str::to_ascii_lowercase) else { return Vec::new() };
        let https = u.scheme() == "https";
        let path = u.path();
        let now = unix_now();
        let mut out: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| {
                if js && !c.visible_to_js {
                    return false;
                }
                if c.expires.is_some_and(|e| e <= now) {
                    return false;
                }
                if c.secure && !https {
                    return false;
                }
                if !domain_match(&host, &c.domain, c.host_only) {
                    return false;
                }
                path_matches(path, &c.path)
            })
            .collect();
        // A more specific cookie path is sent first (RFC 6265 §5.4), longest before shortest.
        out.sort_by(|a, b| b.path.len().cmp(&a.path.len()));
        out
    }
}

/// Host-only matches just the domain; otherwise subdomains match too.
fn domain_match(host: &str, domain: &str, host_only: bool) -> bool {
    if host_only {
        return host == domain;
    }
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

/// A shortened RFC 6265 §5.1.4 path match: a prefix, and the character right after
/// the prefix must be `/` (unless the cookie path already ends with `/`).
fn path_matches(path: &str, cookie_path: &str) -> bool {
    if cookie_path == "/" || path == cookie_path {
        return true;
    }
    path.starts_with(cookie_path)
        && (cookie_path.ends_with('/') || path.as_bytes().get(cookie_path.len()) == Some(&b'/'))
}

fn join(cs: &[&Cookie]) -> String {
    cs.iter().map(|c| format!("{}={}", c.name, c.value)).collect::<Vec<_>>().join("; ")
}

fn parse_set_cookie(base: &reqwest::Url, line: &str, now: u64) -> Option<Cookie> {
    let mut parts = line.split(';');
    let (name, value) = parts.next()?.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let host = base.host_str()?.to_ascii_lowercase();
    let mut c = Cookie {
        name: name.to_string(),
        value: value.trim().to_string(),
        domain: host.clone(),
        host_only: true,
        path: default_path(base.path()),
        expires: None,
        secure: false,
        visible_to_js: true,
    };
    for a in parts {
        let a = a.trim();
        let (k, v) = a.split_once('=').unwrap_or((a, ""));
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "domain" => {
                let d = v.trim_start_matches('.').to_ascii_lowercase();
                // RFC 6265 §5.3: an origin may only set cookies for itself or its
                // parent domain. evil.com must not send Domain=victim.com.
                // An IP literal must not use Domain (except for itself).
                if d.is_empty() {
                    continue;
                }
                let host_is_ip = host.parse::<std::net::IpAddr>().is_ok();
                let ok = host == d
                    || (!host_is_ip
                        && d.parse::<std::net::IpAddr>().is_err()
                        && host.len() > d.len()
                        && host.ends_with(d.as_str())
                        && host.as_bytes()[host.len() - d.len() - 1] == b'.');
                if !ok {
                    return None;
                }
                c.domain = d;
                c.host_only = false;
            }
            "path" => {
                if v.starts_with('/') {
                    c.path = v.to_string();
                }
            }
            "max-age" => {
                // Max-Age beats Expires (RFC 6265 §5.3). <= 0 means delete: encoded
                // as Some(0) for set_from_headers to notice.
                c.expires = Some(match v.parse::<i64>() {
                    Ok(n) if n > 0 => now.saturating_add_signed(n),
                    _ => 0,
                });
            }
            "expires" => {
                if c.expires.is_none() {
                    c.expires = parse_http_date(v);
                }
            }
            "secure" => c.secure = true,
            "httponly" => c.visible_to_js = false,
            "samesite" => { /* noted: currently only remembered; full SameSite semantics P2 */ }
            _ => {}
        }
    }
    Some(c)
}

fn default_path(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => path[..i].to_string(),
    }
}

/// The only cookie date format still in use: `Wed, 21 Oct 2015 07:28:00 GMT` (RFC 1123).
/// There is no datetime crate, so dates are computed with the civil-days formula
/// (Howard Hinnant).
fn parse_http_date(s: &str) -> Option<u64> {
    // Drop the weekday if present: "Wed, 21 Oct 2015 07:28:00 GMT"
    let rest = s.trim().split_once(", ").map(|(_, r)| r).unwrap_or(s.trim());
    let f: Vec<&str> = rest.split_whitespace().collect();
    let [d, mon, y, time, ..] = f.as_slice() else { return None };
    let d: i64 = d.parse().ok()?;
    let y: i64 = y.parse().ok()?;
    let mo = mon.to_ascii_lowercase();
    let m: i64 = match mo.get(..3)? {
        "jan" => 1, "feb" => 2, "mar" => 3, "apr" => 4, "may" => 5, "jun" => 6,
        "jul" => 7, "aug" => 8, "sep" => 9, "oct" => 10, "nov" => 11, "dec" => 12,
        _ => return None,
    };
    let (y, m) = if m <= 2 { (y - 1, m + 12) } else { (y, m) };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m - 3) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let t: Vec<&str> = time.split(':').collect();
    let [h, mi, se] = t.as_slice() else { return None };
    let hms: i64 = h.parse::<i64>().ok()? * 3600 + mi.parse::<i64>().ok()? * 60 + se.parse::<i64>().ok()?;
    Some((days * 86_400 + hms).max(0) as u64)
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> reqwest::Url {
        reqwest::Url::parse(s).expect("url")
    }

    #[test]
    fn jar_matches_domain_path_secure_httponly() {
        let mut j = CookieJar::new();
        j.set_from_headers(
            "https://shop.example.com/a/b?x=1",
            &[
                ("Set-Cookie".into(), "sid=1; Domain=example.com; Path=/a; Secure; HttpOnly".into()),
                ("Set-Cookie".into(), "pref=dark; Path=/; Secure".into()),
                ("Set-Cookie".into(), "gone=1; Max-Age=0".into()),
                ("Content-Type".into(), "text/html".into()),
            ],
        );
        assert_eq!(j.len(), 2, "Max-Age=0 must delete, Content-Type is not a cookie");

        // `pref` has no Domain so it is host-only for shop.example.com — exactly
        // like a browser, it does not spread to other subdomains.
        assert_eq!(j.header_for("https://shop.example.com/a/deep"), "pref=dark; sid=1");
        // A Domain= cookie spreads to subdomains; path /a does not match /other
        assert!(j.header_for("https://cdn.example.com/a/deep").contains("sid=1"));
        assert!(!j.header_for("https://cdn.example.com/other").contains("sid=1"));
        // A Secure cookie does not travel over http:
        assert!(!j.header_for("http://shop.example.com/a").contains("sid=1"));
        // HttpOnly is hidden from JS, but still sent:
        assert!(j.visible_for_js("https://shop.example.com/a").contains("pref=dark"));
        assert!(!j.visible_for_js("https://shop.example.com/a").contains("sid=1"));
        j.clear();
        assert!(j.header_for("https://shop.example.com/a").is_empty());
    }

    #[test]
    fn expires_parses_rfc1123() {
        assert_eq!(parse_http_date("Wed, 21 Oct 2015 07:28:00 GMT"), Some(1_445_412_480));
        // A past expiry date -> the cookie must be dropped when building the header.
        let mut j = CookieJar::new();
        let u0 = u("https://a.example/");
        j.cookies.push(parse_set_cookie(&u0, "old=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT", unix_now()).expect("cookie"));
        assert!(j.header_for("https://a.example/").is_empty());
        // Host-only does not spread to subdomains
        j.cookies.clear();
        j.set_from_headers("https://a.example/", &[("set-cookie".into(), "h=1".into())]);
        assert!(j.header_for("https://a.example/").contains("h=1"));
        assert!(!j.header_for("https://b.example/").contains("h=1"));
    }

    #[test]
    fn scheme_allowlist_rejects_everything_else() {
        assert!(check_url("https://ok.example/p").is_ok());
        for bad in ["file:///etc/passwd", "data:text/html,x", "javascript:alert(1)", "ftp://a/b", "stun:a.example:1", "wss://a/b"] {
            assert!(check_url(bad).is_err(), "must block {bad}");
        }
    }
}
