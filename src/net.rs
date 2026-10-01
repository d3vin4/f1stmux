//! Net — TLS, proxy, và chống rò DNS.
//!
//! Hai quyết định đáng ghi lại ở đây:
//! 1. Không dùng kho CA của hệ điều hành. Verifier mặc định của rustls cần JNI và
//!    PANIC trên Android ("Expect rustls-platform-verifier to be initialized"), và
//!    đọc kho CA hệ thống cũng là một dấu vết riêng tư. Root đi kèm trong binary
//!    (webpki-roots) là nguồn tin duy nhất được tin cậy.
//! 2. Mọi tên miền đều phải đi qua DoH. Xem `install_dns_guard` để biết chỗ nào
//!    vẫn còn ngoại lệ (chính nó cũng nói thẳng phần nào *không* được bảo đảm).
//!
//! Không telemetry, không log ra đĩa, không gọi ra ngoài ngoài các URL được yêu cầu.

use crate::config::Config;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Timeout cho tay cầm (connect + TLS + response headers).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout tổng cho một lần tải.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Số hop redirect tối đa. Cao hơn mặc định 10 của reqwest vì vài site dính chuỗi
/// ngắn; trên đã vượt thì báo lỗi chứ không âm thầm dừng.
pub const MAX_REDIRECTS: usize = 20;

/// Cài CryptoProvider một lần, gọi trước mọi thứ TLS.
/// Idempotent: gọi nhiều lần cũng an toàn (lỗi AlreadyExists bị bỏ qua).
/// `main` gọi hàm này đầu tiên; `tls_config()` cũng tự cài để không phụ thuộc thứ tự gọi.
pub fn init_tls() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// ClientConfig dùng chung cho client chính và client DoH nội bộ.
pub fn tls_config() -> rustls::ClientConfig {
    // Provider phải cài TRƯỚC mọi ClientConfig, nếu không rustls panic khi tự tìm.
    init_tls();
    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Client HTTP dùng chung cho mọi request: TLS roots bundle sẵn, redirect tay
/// (để mỗi hop gắn lại header theo profile), proxy theo config, và DoH guard.
///
/// Caller nên cache kết quả: dựng client tốn công copy 121 trust anchor. Không có
/// state nào được ghi ra đĩa ở đây.
pub fn client(cfg: &Config) -> Result<reqwest::Client, String> {
    let ua = crate::stealth::profile(&cfg.profile)
        .map(|p| p.ua)
        // Chỉ là fallback: `get`/`post_form` luôn gắn UA của profile. UA mặc định
        // của reqwest ("reqwest/0.13") sẽ tự tố giả trình duyệt.
        .unwrap_or("Mozilla/5.0");
    let mut b = reqwest::Client::builder()
        .user_agent(ua)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(30));

    if let Some(p) = cfg.proxy.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        let proxy = reqwest::Proxy::all(p).map_err(|e| format!("proxy không hợp lệ ({p}): {e}"))?;
        b = b.proxy(proxy);
    }
    b = b.use_preconfigured_tls(tls_config());
    install_dns_guard(&mut b, cfg)?;
    b.build().map_err(|e| format!("không dựng được HTTP client: {e}"))
}

/// Cắm DNS-over-HTTPS vào builder: mọi tên miền của mọi request đều được phân
/// giải qua DoH thay vì `getaddrinfo` của hệ điều hành.
///
/// Mức bảo đảm thực tế, nói thẳng:
/// - ĐƯỢC bảo đảm: không còn request nào tới tên miền nào đi qua resolver hệ
///   thống. reqwest gọi đúng resolver này cho mọi kết nối HTTP(S) trực tiếp.
/// - KHÔNG được bảo đảm: (a) tên miền của chính endpoint DoH được hệ thống phân
///   giải một lần lúc bootstrap — đây là điều không tránh được với endpoint ghi
///   bằng tên miền; muốn sạch tuyệt đối thì đặt `cfg.doh` là IP literal hoặc tên
///   sau một proxy. (b) Khi `cfg.proxy` là proxy HTTP/SOCKS, chính proxy sẽ phân
///   giải tên đích — máy này không phân giải nữa, nhưng ISP của bạn không thấy tên
///   đó, và người vận hành proxy thì có. (c) Nếu DoH hỏng, `lookup` trả lỗi và
///   request chết — cố ý không fallback về resolver hệ thống, vì fallback đó chính
///   là rò DNS.
///
/// Có dùng `redirect`, `SNI` hay IP pinning không? Không — nếu muốn chống DNS
/// rebinding thật sự thì phải validate IP sau khi phân giải, chuyện của session.
pub fn install_dns_guard(b: &mut reqwest::ClientBuilder, cfg: &Config) -> Result<(), String> {
    let doh = Doh::new(&cfg.doh)?;
    let taken = std::mem::take(b);
    *b = taken.dns_resolver(doh);
    Ok(())
}

/// TTL cache cố định. Đọc TTL từ DoH là tối ưu, không phải điều kiện bảo mật —
/// nếu cache sai thì tối đa là hơi cũ, không rò gì thêm.
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

/// Resolver DoH: JSON API (`?name=..&type=A`), cache trong RAM theo tên.
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
            return Err("cfg.doh rỗng: không có DoH thì không chống rò DNS được".into());
        }
        let u = reqwest::Url::parse(endpoint)
            .map_err(|e| format!("URL DoH không hợp lệ ({endpoint}): {e}"))?;
        if u.scheme() != "https" {
            return Err(format!(
                "DoH phải là https, không phải {}:// ({endpoint}): bản thân truy vấn DNS mà đi plaintext thì vô nghĩa",
                u.scheme()
            ));
        }
        // Client nội bộ: dùng resolver hệ thống, KHÔNG dùng chính guard này (thế là
        // đệ quy vô hạn), không đi qua proxy (nếu đã qua proxy thì DoH là vô nghĩa).
        let http = reqwest::Client::builder()
            .user_agent(crate::stealth::profile("chrome").map(|p| p.ua).unwrap_or("Mozilla/5.0"))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .use_preconfigured_tls(tls_config())
            .build()
            .map_err(|e| format!("không dựng được client DoH nội bộ: {e}"))?;
        Ok(Self { endpoint: endpoint.to_string(), http, cache: Arc::new(Mutex::new(Vec::new())) })
    }

    async fn lookup(&self, host: &str) -> Result<Vec<SocketAddr>, String> {
        // Chặn ký tự lạ: `host` đi thẳng vào query string của DoH.
        if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')) {
            return Err(format!("tên miền không hợp lệ, không truy vấn DoH: {host}"));
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
            .map_err(|e| format!("truy vấn DoH cho {host} thất bại: {e}"))?;
        if !r.status().is_success() {
            return Err(format!("DoH server {} trả về lỗi cho {host}", r.status()));
        }
        // `.json()` của reqwest cần feature `json`; tự parse để không phải bật
        // thêm feature cho cả crate chỉ vì một chỗ.
        let raw = r
            .bytes()
            .await
            .map_err(|e| format!("đọc body DoH của {host} lỗi: {e}"))?;
        let j: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| format!("body DoH của {host} không phải JSON: {e}"))?;

        // type 1 = A, 28 = AAAA. Server DoH trả cả chuỗi CNAME trong Answer nên
        // lọc theo type là đủ, không cần đuổi CNAME.
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
            // Port 0 = reqwest điền port mặc định theo scheme.
            match ip {
                IpAddr::V4(v) => v4.push(SocketAddr::new(IpAddr::V4(v), 0)),
                IpAddr::V6(v) => v6.push(SocketAddr::new(IpAddr::V6(v), 0)),
            }
        }
        // Ưu tiên IPv4: mạng di động Android hay có NAT64, đường vòng thì chậm hơn.
        let addrs = if v4.is_empty() { v6 } else { v4 };
        if addrs.is_empty() {
            return Err(format!("DoH không có bản ghi A/AAAA cho {host}"));
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

/// Biến lỗi reqwest thành thông điệp nói đúng nguyên nhân, vì "error" trần
/// không giúp được ai debug trên terminal.
pub fn err_msg(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "hết thời gian chờ (timeout)".into()
    } else if e.is_dns() {
        format!("DNS/DoH thất bại: {e}")
    } else if e.is_connect() {
        format!("không kết nối được: {e}")
    } else if e.is_body() || e.is_decode() {
        format!("lỗi đọc/giải nén body: {e}")
    } else if e.is_redirect() {
        format!("lỗi redirect: {e}")
    } else {
        e.to_string()
    }
}
