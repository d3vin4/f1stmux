//! Human-solve challenge portal — generic, không gắn với bất kỳ site nào.
//!
//! Khi phát hiện challenge (captcha & co), f1stmux KHÔNG tự giải: challenge
//! nào cũng verify server-side, token giả không bao giờ qua. Thay vào đó:
//! tạo ticket → phục vụ portal loopback cho người dùng giải trên browser thật
//! → nhận token → replay vào session → trả URL đích.
//!
//! Nguyên tắc an toàn:
//! - solve() KHÔNG BAO GIỜ navigate tới đích — chỉ trả URL để agent xử lý
//!   (chặn/log/báo). Không có flag nào bật tự mở cả.
//! - Ticket/token sống trong RAM, hết hạn sau 10 phút, token dùng một lần.
//! - Portal chỉ phục vụ qua daemon loopback (xem gate trong rpc::serve).
//! - Không log token ra bất cứ đâu.

use crate::dom::Dom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const TICKET_TTL_MS: u64 = 600_000;

/// Cách navigate ứng xử khi gặp challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnChallenge {
    /// Mặc định: chỉ gắn flag `captcha`, không làm gì thêm.
    Ignore,
    /// Tự tạo ticket + portal để human giải.
    Portal,
}

impl OnChallenge {
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "portal" | "ticket" | "human" => OnChallenge::Portal,
            _ => OnChallenge::Ignore,
        }
    }
}

/// Đặc tả replay trích từ DOM: POST form nào, field nào, token điền vào đâu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySpec {
    pub post_url: String,
    pub fields: Vec<(String, String)>,
    pub token_field: String,
}

/// Trích replay spec từ DOM: chọn form có hidden input + marker challenge,
/// gom hidden input làm field, action làm post_url. Thuần generic — không biết
/// site nào, chỉ biết cấu trúc form + marker chuẩn (recaptcha/hcaptcha/turnstile).
pub fn auto_extract(dom: &Dom, page_url: &str) -> Option<ReplaySpec> {
    let forms = dom.query("form", 0).ok()?;
    let mut best: Option<(usize, usize)> = None;
    for &id in &forms {
        let html = dom.inner_html(id as usize).to_ascii_lowercase();
        let mut score = 0usize;
        if html.contains("recaptcha") || html.contains("h-captcha") || html.contains("turnstile") || html.contains("captcha") {
            score += 2;
        }
        let hidden = dom.query("input", id as usize).map(|v| {
            v.iter().filter(|i| {
                dom.get(**i as usize).map(|n| {
                    n.attrs.iter().any(|(k, val)| k == "type" && val.eq_ignore_ascii_case("hidden"))
                        && n.attrs.iter().any(|(k, _)| k == "name")
                }).unwrap_or(false)
            }).count()
        }).unwrap_or(0);
        score += hidden;
        if best.map(|(_, s)| score > s).unwrap_or(true) {
            best = Some((id, score));
        }
    }
    let (fid, _) = best?;
    let action = dom.get(fid as usize)
        .and_then(|n| n.attrs.iter().find(|(k, _)| k == "action").map(|(_, v)| v.clone()))
        .unwrap_or_default();
    let post_url = resolve(page_url, &action).unwrap_or_else(|| page_url.to_string());
    let mut fields = Vec::new();
    if let Ok(inputs) = dom.query("input", fid as usize) {
        for i in inputs {
            if let Some(n) = dom.get(i as usize) {
                let g = |k: &str| n.attrs.iter().find(|(a, _)| *a == k).map(|(_, v)| v.clone()).unwrap_or_default();
                let (name, typ, val) = (g("name"), g("type"), g("value"));
                if !name.is_empty() && (typ.eq_ignore_ascii_case("hidden") || typ.is_empty()) {
                    fields.push((name, val));
                }
            }
        }
    }
    let html = dom.inner_html(fid as usize).to_ascii_lowercase();
    let token_field = if html.contains("h-captcha") {
        "h-captcha-response"
    } else if html.contains("turnstile") {
        "cf-turnstile-response"
    } else {
        "g-recaptcha-response"
    };
    Some(ReplaySpec { post_url, fields, token_field: token_field.into() })
}

fn resolve(base: &str, rel: &str) -> Option<String> {
    if rel.is_empty() {
        return None;
    }
    reqwest::Url::options()
        .base_url(reqwest::Url::parse(base).ok().as_ref())
        .parse(rel)
        .map(|u| u.to_string())
        .ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TicketStatus {
    Held,
    Resolved,
    Failed,
    Expired,
}

#[derive(Debug, Clone)]
pub struct Ticket {
    pub id: String,
    pub session: String,
    pub page_url: String,
    pub kind: String,
    pub spec: ReplaySpec,
    pub status: TicketStatus,
    pub url: Option<String>,
    pub note: String,
    pub created_ms: u64,
}

pub type TicketStore = Arc<Mutex<HashMap<String, Ticket>>>;

pub fn new_store() -> TicketStore {
    Arc::new(Mutex::new(HashMap::new()))
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Ref trả cho agent: id ticket + URL portal để đưa human.
#[derive(Debug, Clone, Serialize)]
pub struct ChallengeRef {
    pub id: String,
    pub portal_url: String,
    pub kind: String,
}

pub fn create_ticket(
    store: &TicketStore,
    listen_base: &str,
    session: &str,
    page_url: &str,
    kind: &str,
    spec: ReplaySpec,
) -> ChallengeRef {
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id = format!("ch-{n}");
    store.lock().unwrap().insert(
        id.clone(),
        Ticket {
            id: id.clone(),
            session: session.into(),
            page_url: page_url.into(),
            kind: kind.into(),
            spec,
            status: TicketStatus::Held,
            url: None,
            note: String::new(),
            created_ms: now_ms(),
        },
    );
    ChallengeRef { portal_url: format!("http://{listen_base}/challenge/{id}"), id, kind: kind.into() }
}

pub fn lookup(store: &TicketStore, id: &str) -> Option<Ticket> {
    let mut m = store.lock().unwrap();
    let t = m.get(id)?.clone();
    if t.status == TicketStatus::Held && now_ms().saturating_sub(t.created_ms) > TICKET_TTL_MS {
        if let Some(x) = m.get_mut(id) {
            x.status = TicketStatus::Expired;
        }
        return m.get(id).cloned();
    }
    Some(t)
}

/// Kết quả replay: agent nhận URL đích nhưng solve() KHÔNG navigate tới đó bao giờ.
#[derive(Debug, Clone, Serialize)]
pub struct ResolveOut {
    pub ok: bool,
    pub url: Option<String>,
    pub raw: String,
}

/// Replay token của human vào session: POST form (field trích từ DOM + token)
/// rồi đọc URL đích từ response. Token dùng một lần — xong là ticket đóng.
pub async fn solve(
    store: &TicketStore,
    sess: &mut crate::session::Session,
    cfg: &crate::config::Config,
    prof: &crate::stealth::Profile,
    id: &str,
    token: &str,
) -> Result<ResolveOut, String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("token rỗng".into());
    }
    let t = lookup(store, id).ok_or_else(|| format!("ticket không tồn tại: `{id}`"))?;
    if t.status != TicketStatus::Held {
        return Err(format!("ticket `{id}` đã đóng ({:?})", t.status));
    }
    let mut parts: Vec<(String, String)> = t.spec.fields.clone();
    parts.push((t.spec.token_field.clone(), token.to_string()));
    let body = parts
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                urlenc(k),
                urlenc(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let ck = sess.cookies.header_for(&t.spec.post_url);
    let out = match crate::fetch::post_form(&t.spec.post_url, cfg, prof, &ck, &body).await {
        Ok((f, _)) => {
            sess.cookies.set_from_headers(&f.final_url, &f.headers);
            f.body
        }
        Err(e) => {
            mark(store, id, TicketStatus::Failed, None, format!("replay lỗi mạng: {e}"));
            return Err(format!("replay lỗi mạng: {e}"));
        }
    };
    let raw: String = out.chars().take(2000).collect();
    // Response generic: thử JSON {success, url}, không ép shape của site nào.
    let (ok, url) = match serde_json::from_str::<serde_json::Value>(&out) {
        Ok(v) => {
            let ok = v.get("success").and_then(|x| x.as_bool()).unwrap_or(false);
            let url = v.get("url").and_then(|x| x.as_str()).map(str::to_string);
            (ok && url.is_some(), url)
        }
        Err(_) => (false, None),
    };
    if ok {
        mark(store, id, TicketStatus::Resolved, url.clone(), String::new());
    } else {
        mark(store, id, TicketStatus::Failed, None, format!("server từ chối (raw: {})", &raw[..raw.len().min(200)]));
    }
    Ok(ResolveOut { ok, url, raw })
}

fn mark(store: &TicketStore, id: &str, st: TicketStatus, url: Option<String>, note: String) {
    if let Some(t) = store.lock().unwrap().get_mut(id) {
        t.status = st;
        t.url = url;
        t.note = note;
    }
}

fn urlenc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' | b'_' | b'.' | b'~' => o.push(*b as char),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}
/// Escape HTML khi nhúng giá trị vào portal.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            _ => o.push(c),
        }
    }
    o
}

/// Trang portal cho human: mở trang thật, giải, dán token. Không tên site nào
/// hardcode — mọi thứ lấy từ ticket.
pub fn portal_page(t: &Ticket, ttl_left_s: u64) -> String {
    let host = t.page_url.split('/').nth(2).unwrap_or(&t.page_url);
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Challenge {id} — human solve</title>
<style>:root{{color-scheme:dark}}body{{background:#1e1e1e;color:#d4d4d4;font:14px/1.6 sans-serif;max-width:34em;margin:4em auto;padding:0 1em}}code{{background:#2d2d2d;padding:2px 6px;border-radius:4px}}input{{width:100%;padding:8px;margin:8px 0}}button{{padding:8px 16px;cursor:pointer}}</style>
</head><body>
<h2>Human challenge — ticket <code>{id}</code></h2>
<p>Page: <code>{host}</code> · type: <code>{kind}</code> · expires in {ttl}s</p>
<ol>
<li><a href="{url}" target="_blank" rel="noopener">Open the real page</a> in your browser.</li>
<li>Solve the challenge there, then copy the token with this bookmarklet:<br>
<code>javascript:prompt('token',(typeof grecaptcha!=='undefined'&&grecaptcha.getResponse())||(typeof hcaptcha!=='undefined'&&hcaptcha.getResponse())||'')</code></li>
<li>Paste the token below and submit. The agent never opens the destination itself.</li>
</ol>
<form method="post" action="/challenge/{id}/solution">
<input name="token" placeholder="paste token" autocomplete="off">
<button type="submit">Submit</button>
</form>
</body></html>"#,
        id = esc(&t.id),
        host = esc(host),
        kind = esc(&t.kind),
        ttl = ttl_left_s,
        url = esc(&t.page_url),
    )
}
