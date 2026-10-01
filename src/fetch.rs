//! Tải trang: header theo profile → GET → redirect tay → giải nén → text.
//!
//! Redirect đi tay (không để reqwest tự điều hướng) là cố ý: mỗi hop phải
//! gắn lại header đúng thứ tự của profile, nếu không UA/Client-Hints sẽ tụt về
//! mặc định của reqwest ở hop thứ hai — dấu vết rõ nhất. Đổi lại phải tự canh
//! `Location` và giới hạn số hop.
//!
//! Cookie jar sống trong RAM. Không telemetry, không log ra đĩa.

use crate::blocklist::is_blocked_scheme;
use crate::config::Config;
use crate::net;
use crate::stealth::{self, Profile};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Trần body. 8 MB là đủ cho mọi trang tĩnh/SPA bình thường; RSS feed lớn hơn thì
/// nên tải bằng `get_bytes` và tự xử lý.
pub const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fetched {
    /// URL đã yêu cầu (trước khi redirect).
    pub url: String,
    /// URL sau khi đi hết chuỗi redirect.
    pub final_url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub elapsed_ms: u128,
    /// Đường đi từng hop, theo thứ tự.
    pub redirects: Vec<String>,
    /// Chưa có HTTP cache trong f1stmux, nên luôn false. Để trường này để tool
    /// không phải đoán body là từ mạng hay từ đĩa; thêm cache khi có.
    pub from_cache: bool,
}

/// GET, body giải nén thành String. `cookie` là header `Cookie:` đã ghép sẵn từ
/// jar của session (rỗng = không gửi).
pub async fn get(
    url: &str,
    cfg: &Config,
    prof: &Profile,
    cookie: &str,
) -> Result<Fetched, String> {
    Ok(run(url, cfg, prof, cookie, None).await?.0)
}

/// GET nhị phân (ảnh, file tải về). `Fetched.body` vẫn được điền bằng lossy text
/// để shape của struct không đổi theo loại — caller đọc byte qua `Vec<u8>`.
pub async fn get_bytes(
    url: &str,
    cfg: &Config,
    prof: &Profile,
    cookie: &str,
) -> Result<(Fetched, Vec<u8>), String> {
    run(url, cfg, prof, cookie, None).await
}

/// POST `application/x-www-form-urlencoded` — đăng nhập, submit form. Sau 303
/// (và 302 như browser) chuyển sang GET và bỏ body, đúng như trình duyệt thật.
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
            .map_err(|e| format!("{verb} {} thất bại: {}", cur, net::err_msg(&e)))?;

        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if let Some(loc) = location.filter(|_| (300..400).contains(&status)) {
            if redirects.len() >= net::MAX_REDIRECTS {
                return Err(format!(
                    "{} vượt quá {} lần redirect — có thể là vòng lặp",
                    url, net::MAX_REDIRECTS
                ));
            }
            let next = reqwest::Url::options()
                .base_url(Some(&cur))
                .parse(&loc)
                .map_err(|e| format!("Location không hợp lệ ({loc}): {e}"))?;
            let next = check_url(next.as_str())?;
            if !seen.insert(next.to_string()) {
                return Err(format!("vòng lặp redirect tại {next}"));
            }
            redirects.push(cur.to_string());
            referer = Some(cur.to_string());
            cur = next;
            // 303 luôn, 302 chỉ khi là POST: browser quy ước thành GET.
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
                headers,
                body: decode_text(&bytes),
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
            "body {len} byte vượt trần {MAX_BODY} byte (8 MB) — tải bằng get_bytes nếu thật sự cần"
        ));
    }
    let mut out = Vec::new();
    while let Some(c) = resp.chunk().await.map_err(|e| net::err_msg(&e))? {
        if out.len() + c.len() > MAX_BODY {
            return Err(format!("body vượt trần {MAX_BODY} byte (8 MB) khi đang đọc"));
        }
        out.extend_from_slice(&c);
    }
    Ok(out)
}

/// Chỉ http/https. `is_blocked_scheme` là lớp phòng thủ cho WebRTC/WS — allowlist
/// này mới là hàng rào thật sự.
fn check_url(url: &str) -> Result<reqwest::Url, String> {
    let u = reqwest::Url::parse(url).map_err(|e| format!("URL không hợp lệ ({url}): {e}"))?;
    let s = u.scheme();
    if s != "http" && s != "https" {
        return Err(format!(
            "scheme {s}: không được phép (chỉ http/https; file:, data:, rtc: đều bị chặn)"
        ));
    }
    if is_blocked_scheme(s) {
        return Err(format!("scheme {s}: bị chặn"));
    }
    Ok(u)
}

/// Không có `encoding_rs` nên không dịch được charset: UTF-8 thì giữ nguyên byte,
/// còn lại thay bằng U+FFFD. Đủ dùng cho HTML tiếng Anh/Việt, và thà không
/// đoán bừa còn hơn giải mã sai.
fn decode_text(b: &[u8]) -> String {
    let b = b.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(b);
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(b).into_owned(),
    }
}

// ───────────────────────── cookie jar ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    /// Chỉ khớp đúng host đặt cookie, không khớp subdomain.
    pub host_only: bool,
    pub path: String,
    /// Unix giây. `None` = session cookie (chết khi process chết).
    pub expires: Option<u64>,
    pub secure: bool,
    /// HttpOnly nghĩa là JS không đọc được — mô hình hoá bằng cờ này, vì ở đây
    /// không có `document.cookie` nào cả, chỉ có lời gọi RPC tường minh.
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
            // Max-Age <= 0 nghĩa là xoá cookie.
            if c.expires == Some(0) {
                self.cookies.retain(|e| !(e.name == c.name && e.domain == c.domain && e.path == c.path));
                continue;
            }
            self.cookies.retain(|e| !(e.name == c.name && e.domain == c.domain && e.path == c.path));
            self.cookies.push(c);
        }
    }

    /// Header `Cookie:` để gửi đi, theo thứ tự cũ hơn trước (giống browser).
    pub fn header_for(&self, url: &str) -> String {
        join(&self.match_all(url, false))
    }

    /// Phần JS được phép thấy (bỏ HttpOnly). Chỉ session gọi, sau khi script
    /// chạy xong.
    pub fn visible_for_js(&self, url: &str) -> String {
        join(&self.match_all(url, true))
    }

    /// Cookie của session, để tool `get_cookies` liệt kê.
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
        // Cookie path cụ thể hơn thì gửi trước, giống browser.
        out.sort_by_key(|c| c.path.len());
        out
    }
}

/// Host-only thì chỉ khớp đúng domain; ngược lại khớp cả subdomain.
fn domain_match(host: &str, domain: &str, host_only: bool) -> bool {
    if host_only {
        return host == domain;
    }
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

/// Path match của RFC 6265 §5.1.4 rút gọn: tiền tố, và ký tự ngay sau tiền tố
/// phải là `/` (trừ khi path cookie đã kết thúc bằng `/`).
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
                if !d.is_empty() {
                    c.domain = d;
                    c.host_only = false;
                }
            }
            "path" => {
                if v.starts_with('/') {
                    c.path = v.to_string();
                }
            }
            "max-age" => {
                // Max-Age thắng Expires (RFC 6265 §5.3). <= 0 nghĩa là xoá: mã hoá
                // thành Some(0) cho set_from_headers nhận ra.
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

/// Định dạng cookie duy nhất còn dùng: `Wed, 21 Oct 2015 07:28:00 GMT` (RFC 1123).
/// Không có crate ngày giờ nên tính ngày bằng công thức civil-days (Howard Hinnant).
fn parse_http_date(s: &str) -> Option<u64> {
    // Bỏ ngày trong tuần nếu có: "Wed, 21 Oct 2015 07:28:00 GMT"
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
        assert_eq!(j.len(), 2, "Max-Age=0 phải xoá, Content-Type không phải cookie");

        // `pref` không có Domain nên host-only cho shop.example.com — đúng như
        // browser, không lan sang subdomain khác.
        assert_eq!(j.header_for("https://shop.example.com/a/deep"), "pref=dark; sid=1");
        // Cookie Domain= lan sang subdomain; path /a không khớp /other
        assert!(j.header_for("https://cdn.example.com/a/deep").contains("sid=1"));
        assert!(!j.header_for("https://cdn.example.com/other").contains("sid=1"));
        // Secure cookie không đi qua http:
        assert!(!j.header_for("http://shop.example.com/a").contains("sid=1"));
        // HttpOnly giấu khỏi JS, nhưng vẫn gửi đi:
        assert!(j.visible_for_js("https://shop.example.com/a").contains("pref=dark"));
        assert!(!j.visible_for_js("https://shop.example.com/a").contains("sid=1"));
        j.clear();
        assert!(j.header_for("https://shop.example.com/a").is_empty());
    }

    #[test]
    fn expires_parses_rfc1123() {
        assert_eq!(parse_http_date("Wed, 21 Oct 2015 07:28:00 GMT"), Some(1_445_412_480));
        // Ngày hết hạn quá khứ -> cookie phải bị bỏ khi ghép header.
        let mut j = CookieJar::new();
        let u0 = u("https://a.example/");
        j.cookies.push(parse_set_cookie(&u0, "old=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT", unix_now()).expect("cookie"));
        assert!(j.header_for("https://a.example/").is_empty());
        // Host-only không lan sang subdomain
        j.cookies.clear();
        j.set_from_headers("https://a.example/", &[("set-cookie".into(), "h=1".into())]);
        assert!(j.header_for("https://a.example/").contains("h=1"));
        assert!(!j.header_for("https://b.example/").contains("h=1"));
    }

    #[test]
    fn scheme_allowlist_rejects_everything_else() {
        assert!(check_url("https://ok.example/p").is_ok());
        for bad in ["file:///etc/passwd", "data:text/html,x", "javascript:alert(1)", "ftp://a/b", "stun:a.example:1", "wss://a/b"] {
            assert!(check_url(bad).is_err(), "phải chặn {bad}");
        }
    }
}
