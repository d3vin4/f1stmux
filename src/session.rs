//! Session và tab: điều phối một lần navigate và giữ trạng thái theo phiên.
//!
//! Mặc định session **RAM-only**: cookie, storage, cache sống trong RAM và biến
//! mất khi process chết. Ghi xuống đĩa là tuỳ chọn tường minh.

use crate::config::Config;
use crate::inspector::NetEntry;
use crate::jsenv::{Env, Realm};
use crate::{dom::SharedDom, htmlparse, inspector, stealth};
use serde::Serialize;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

fn new_id(p: &str) -> String {
    format!("{p}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Điều kiện hoàn tất navigation. Không có layout engine nên phải suy từ tín hiệu.
#[derive(Debug, Clone, Serialize)]
pub struct WaitFor {
    /// Không còn request mới trong khoảng này.
    pub quiet_ms: u64,
    /// Tổng ngân sách thời gian.
    pub budget_ms: u64,
}

impl Default for WaitFor {
    fn default() -> Self {
        Self { quiet_ms: 250, budget_ms: 10_000 }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NavResult {
    pub tab: String,
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub title: String,
    pub text: String,
    pub html: String,
    pub html_len: usize,
    pub elapsed_ms: u128,
    pub console: Vec<(String, String)>,
    pub errors: Vec<String>,
    pub scripts_run: usize,
    /// Có phải nội dung đến từ JS hay từ HTML gốc. Nói rõ để AI không bị đoán mò.
    pub content_from_js: bool,
    pub timed_out: bool,
    pub truncated: bool,
    /// Loại captcha/challenge phát hiện được (None = không thấy).
    /// F1stmux KHÔNG giải captcha — field này để AI biết mà đổi chiến thuật
    /// (đổi profile/proxy, thử lại sau, hoặc báo người dùng).
    pub captcha: Option<String>,
    /// Chuỗi redirect đã đi qua (mỗi hop một URL). Debug shortener/shortlink chain.
    pub redirects: Vec<String>,
}

#[derive(Default)]
pub struct Session {
    pub id: String,
    pub cookies: crate::fetch::CookieJar,
    pub storage: std::collections::HashMap<String, String>,
    pub net: Vec<NetEntry>,
    pub dom: Option<SharedDom>,
    pub realm: Option<Box<Realm>>,
    pub last: Option<NavResult>,
    pub kill_switch: bool,
}

impl Session {
    pub fn new() -> Self {
        Self { id: new_id("s"), ..Default::default() }
    }

    /// Lưu trữ JS vào cookie jar — không vào đĩa.
    pub fn persist_dom(&self) {
        let _ = crate::jsenv::hstorage::all();
    }

    pub fn snapshot(&self) -> serde_json::Value {
        json!({
            "id": self.id,
            "cookies": self.cookies.len(),
            "network": self.net.len(),
            "storage_keys": self.storage.len(),
            "dom_loaded": self.dom.is_some(),
            "last": self.last.as_ref().map(|r| json!({
                "url": r.final_url, "status": r.status, "title": r.title,
                "html_len": r.html_len, "elapsed_ms": r.elapsed_ms
            }))
        })
    }
}

/// Phát hiện trang captcha/challenge bằng dấu hiệu tĩnh (URL, title, marker
/// trong HTML). Nhanh, không JS. Không giải — chỉ gắn nhãn để AI đổi chiến thuật.
pub fn detect_captcha(final_url: &str, title: &str, body: &str) -> Option<String> {
    let u = final_url.to_lowercase();
    for m in ["__cf_chl", "/sorry", "captcha", "validate", "are-you-human", "security-check", "challenge-platform"] {
        if u.contains(m) {
            return Some("challenge-url".into());
        }
    }
    let t = title.to_lowercase();
    for m in ["just a moment", "attention required", "verify you are human", "checking your browser", "please verify", "access denied", "datadome", "perimeterx"] {
        if t.contains(m) {
            return Some("challenge-title".into());
        }
    }
    let b = body.to_lowercase();
    // Thứ tự: loại cụ thể trước, generic sau.
    for (m, k) in [
        ("cf-turnstile", "turnstile"), ("cf-challenge", "cloudflare"),
        ("g-recaptcha", "recaptcha"), ("h-captcha", "hcaptcha"),
        ("data-sitekey", "captcha-form"), ("arkose", "arkose"),
        ("funcaptcha", "arkose"), ("geetest", "geetest"),
    ] {
        if b.contains(m) {
            return Some(k.into());
        }
    }
    None
}
///
/// Đây là chỗ tích hợp chặt nhất của dự án, nên nó là hàm tự do, không phải
/// trait: không có lý do để trừu tượng hoá một pipeline duy nhất.
#[allow(clippy::too_many_arguments)]
/// Điều phối một lần navigate hoàn chỉnh.
pub async fn navigate(
    url: &str,
    cfg: &Config,
    sess: &mut Session,
    _wait: &WaitFor,
    run_js: bool,
) -> Result<NavResult, String> {
    let prof = stealth::profile(&cfg.profile).ok_or_else(|| {
        format!("không có profile `{}` (có: {})", cfg.profile, stealth::names().join(", "))
    })?;

    let t0 = std::time::Instant::now();
    let cookie = sess.cookies.header_for(url);
    let f = crate::fetch::get(url, cfg, prof, &cookie).await?;

    // Nạp Set-Cookie vào jar của session.
    sess.cookies.set_from_headers(&f.final_url, &f.headers);

    let parsed = htmlparse::parse(&f.body);
    let dom = htmlparse::shared(parsed.dom);

    let title0 = parsed.title.clone();
    let text0 = dom.borrow().text_content(0);
    let scripts = parsed.scripts.clone();

    let env = Env {
        ua: prof.ua,
        platform: prof.platform,
        concurrency: prof.hardware_concurrency,
        device_memory: prof.device_memory,
        screen: prof.screen,
        title: Box::leak(title0.clone().into_boxed_str()),
        url: Box::leak(f.final_url.clone().into_boxed_str()),
        cookie: Box::leak(sess.cookies.visible_for_js(&f.final_url).into_boxed_str()),
        timezone: prof.timezone,
    };

    let realm = Realm::new(dom.clone(), &env).map_err(|e| format!("QuickJS: {e}"))?;
    realm.run(crate::jsenv::DOM_JS, "dom.js");

    let mut console = Vec::new();
    let mut errors = Vec::new();
    let mut scripts_run = 0usize;
    let mut timed_out = false;

    if run_js {
        for (i, s) in scripts.iter().enumerate() {
            if std::time::Instant::now() > realm.deadline {
                timed_out = true;
                break;
            }
            match s {
                htmlparse::PageScript::Inline(code) => {
                    realm.run(code, &format!("page:inline#{i}"));
                }
                htmlparse::PageScript::External(src) => {
                    // Tải script ngoài rồi chạy theo đúng thứ tự. Lỗi tải được ghi
                    // như lỗi page (có URL) thay vì làm hỏng cả navigation.
                    let full = reqwest::Url::options()
                        .base_url(reqwest::Url::parse(&f.final_url).ok().as_ref())
                        .parse(src)
                        .map(|u| u.to_string())
                        .unwrap_or_default();
                    if full.is_empty() || !(full.starts_with("http://") || full.starts_with("https://")) {
                        errors.push(format!("page:{src}: URL script không hợp lệ"));
                    } else {
                        let ck = sess.cookies.header_for(&full);
                        match crate::fetch::get(&full, cfg, prof, &ck).await {
                            Ok(sf) => {
                                sess.cookies.set_from_headers(&sf.final_url, &sf.headers);
                                realm.run(&sf.body, &format!("page:{full}"));
                            }
                            Err(e) => errors.push(format!("page:{full}: {e}")),
                        }
                    }
                }
            }
            scripts_run += 1;
        }
    }

    let js = realm.take();
    console.extend(js.console);
    errors.extend(js.errors);
    timed_out |= js.timed_out;

    // Nội dung sau JS. Nếu rỗng mà HTML gốc có nội dung, dùng HTML gốc —
    // nhưng báo rõ điều đó, không giả vờ lấy được nội dung động.
    let text = dom.borrow().text_content(0);
    let is_empty = text.trim().is_empty();
    let has_fallback = !text0.trim().is_empty();
    let from_js = has_fallback && text != text0;
    let (text, content_from_js) = if is_empty && has_fallback {
        (text0, false)
    } else {
        (text, from_js)
    };

    let net = NetEntry {
        url: f.url.clone(),
        method: "GET".into(),
        status: f.status,
        req_headers: stealth::headers(prof, None).into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        resp_headers: f.headers.clone(),
        mime: f.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone()).unwrap_or_default(),
        body_len: f.body.len(),
        req_body: 0,
        elapsed_ms: f.elapsed_ms,
        started_ms: inspector::now_ms() - f.elapsed_ms.min(u128::from(u64::MAX)) as u64,
    };
    sess.net.push(net);
    sess.persist_dom();

    let html = dom.borrow().inner_html(0);
    let captcha = detect_captcha(&f.final_url, &title0, &f.body);
    let res = NavResult {
        tab: sess.id.clone(),
        url: f.url.clone(),
        final_url: f.final_url.clone(),
        status: f.status,
        title: title0,
        text,
        html_len: html.len(),
        html,
        elapsed_ms: t0.elapsed().as_millis(),
        console,
        errors,
        scripts_run,
        content_from_js,
        timed_out,
        truncated: false,
        captcha,
        redirects: f.redirects.clone(),
    };

    sess.dom = Some(dom.clone());
    sess.realm = Some(Box::new(realm));
    sess.last = Some(res.clone());
    Ok(res)
}

/// Chạy JS trên tab đã có, trả về JSON.
pub fn eval(sess: &Session, src: &str) -> Result<serde_json::Value, String> {
    let r = sess.realm.as_ref().ok_or("chưa có tab nào được nạp")?;
    r.eval_json(src)
}