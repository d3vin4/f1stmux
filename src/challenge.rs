//! Human-solve challenge portal — generic, tied to no specific site.
//!
//! When a challenge (captcha and friends) is detected, f1stmux does NOT solve it
//! by itself: every challenge verifies server-side, so a fake token never passes.
//! Instead: create a ticket → serve a loopback portal for the user to solve it in a
//! real browser → receive the token → replay it into the session → return the target URL.
//!
//! Safety rules:
//! - solve() NEVER navigates to the target — it only returns the URL for the agent
//!   to handle (block/log/report). No flag turns that auto-open on.
//! - Tickets/tokens live in RAM, expire after 10 minutes, a token is single-use.
//! - The portal is only served over the loopback daemon (see the gate in rpc::serve).
//! - The token is never logged anywhere.

use crate::dom::Dom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const TICKET_TTL_MS: u64 = 600_000;

/// How navigation reacts when it hits a challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnChallenge {
    /// Default: only set the `captcha` flag, do nothing else.
    Ignore,
    /// Automatically create a ticket + portal for a human to solve it.
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

/// Replay spec extracted from the DOM: which form to POST, which fields, where the token goes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySpec {
    pub post_url: String,
    pub fields: Vec<(String, String)>,
    pub token_field: String,
}

/// Extract the replay spec from the DOM: pick the form with hidden inputs + a
/// challenge marker, collect the hidden inputs as fields, use the action as post_url.
/// Purely generic — it knows no site, only form structure + standard markers
/// (recaptcha/hcaptcha/turnstile).
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

/// Extract every named form field on the page so a human solver sees the full
/// form state alongside each captcha: (field name, current value) for all
/// inputs and textareas, plus any challenge sitekeys. Generic DOM truth,
/// no per-site logic. Capped so one page cannot flood the agent context.
pub fn extract_hidden_tokens(dom: &Dom) -> Vec<(String, String)> {
    const CAP: usize = 64;
    let mut out = Vec::new();
    // Sitekeys first — the human needs to know *which* challenge to solve.
    if let Ok(nodes) = dom.query("[data-sitekey]", 0) {
        for id in nodes {
            if let Some(n) = dom.get(id as usize)
                && let Some((_, v)) = n.attrs.iter().find(|(k, _)| k == "data-sitekey")
                && !v.is_empty()
                && !out.iter().any(|(_, x)| x == v)
            {
                out.push(("data-sitekey".to_string(), v.clone()));
            }
            if out.len() >= CAP {
                return out;
            }
        }
    }
    // Every named input, in document order (skip action-only button types).
    if let Ok(inputs) = dom.query("input", 0) {
        for id in inputs {
            if let Some(n) = dom.get(id as usize) {
                let g = |k: &str| {
                    n.attrs.iter().find(|(a, _)| *a == k).map(|(_, v)| v.clone()).unwrap_or_default()
                };
                let (name, typ, val) = (g("name"), g("type"), g("value"));
                if name.is_empty() || out.iter().any(|(n, _)| n == &name) {
                    continue;
                }
                if matches!(
                    typ.to_ascii_lowercase().as_str(),
                    "submit" | "button" | "reset" | "image" | "file"
                ) {
                    continue;
                }
                out.push((name, val));
            }
            if out.len() >= CAP {
                return out;
            }
        }
    }
    // Named textareas carry their text content, not a value attribute.
    if let Ok(areas) = dom.query("textarea", 0) {
        for id in areas {
            if let Some(n) = dom.get(id as usize) {
                if let Some((_, name)) = n.attrs.iter().find(|(k, _)| k == "name").cloned()
                    && !name.is_empty()
                    && !out.iter().any(|(x, _)| x == &name)
                {
                    out.push((name, dom.text_content(id as usize)));
                }
            }
            if out.len() >= CAP {
                return out;
            }
        }
    }
    out
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
    /// Full extracted form state (all named fields + sitekeys) shown to the
    /// human solver alongside the captcha. Generic DOM truth, capped at 64.
    pub context: Vec<(String, String)>,
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

/// Ref returned to the agent: ticket id + portal URL to hand to a human.
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
    context: Vec<(String, String)>,
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
            context,
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

/// Replay result: the agent gets the target URL but solve() NEVER navigates there.
#[derive(Debug, Clone, Serialize)]
pub struct ResolveOut {
    pub ok: bool,
    pub url: Option<String>,
    pub raw: String,
}

/// Replay the human's token into the session: POST the form (fields extracted from
/// the DOM + the token), then read the target URL from the response. The token is
/// single-use — once used, the ticket is closed.
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
        return Err("empty token".into());
    }
    let t = lookup(store, id).ok_or_else(|| format!("ticket does not exist: `{id}`"))?;
    if t.status != TicketStatus::Held {
        return Err(format!("ticket `{id}` is already closed ({:?})", t.status));
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
            mark(store, id, TicketStatus::Failed, None, format!("replay network error: {e}"));
            return Err(format!("replay network error: {e}"));
        }
    };
    let raw: String = out.chars().take(2000).collect();
    // Generic response handling: try JSON {success, url}, never force any site's shape.
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
        mark(store, id, TicketStatus::Failed, None, format!("server rejected it (raw: {})", &raw[..raw.len().min(200)]));
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
/// Escape HTML when embedding a value into the portal.
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

/// The portal page for the human: open the real page, solve it, paste the token.
/// No site name is hardcoded — everything comes from the ticket.
pub fn portal_page(t: &Ticket, ttl_left_s: u64) -> String {
    let host = t.page_url.split('/').nth(2).unwrap_or(&t.page_url);
    let mut rows = String::new();
    for (k, v) in &t.context {
        let vv = if v.len() > 120 { format!("{}…", &v[..120]) } else { v.clone() };
        rows.push_str(&format!("<tr><td><code>{}</code></td><td>{}</td></tr>", esc(k), esc(&vv)));
    }
    let ctx_block = if rows.is_empty() {
        String::new()
    } else {
        format!("<h3>Extracted form state</h3><table><tr><th>field</th><th>value</th></tr>{rows}</table>")
    };
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
{ctx}
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
        ctx = ctx_block,
    )
}
