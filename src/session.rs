//! Sessions and tabs: orchestrate one navigation and keep per-session state.
//!
//! Sessions are **RAM-only** by default: cookies, storage, and cache live in RAM
//! and vanish when the process dies. Writing to disk is an explicit option.

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

/// Navigation completion condition. There is no layout engine, so it must be inferred from signals.
#[derive(Debug, Clone, Serialize)]
pub struct WaitFor {
    /// No new requests within this window.
    pub quiet_ms: u64,
    /// Total time budget.
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
    /// Whether the content came from JS or from the original HTML. Stated explicitly so the AI doesn't have to guess.
    pub content_from_js: bool,
    pub timed_out: bool,
    pub truncated: bool,
    /// Detected captcha/challenge kind (None = none found).
    /// F1stmux does NOT solve captchas — this field lets the AI know and change tactics
    /// (change profile/proxy, retry later, or tell the user).
    pub captcha: Option<String>,
    /// The redirect chain that was walked (one URL per hop). Debug shortener/shortlink chains.
    pub redirects: Vec<String>,
    /// Human-solve ticket when navigating with on_challenge=portal and hitting a challenge.
    pub challenge: Option<crate::challenge::ChallengeRef>,
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
    /// This session's own JS storage — every Realm in the session shares this map.
    pub js_store: crate::jsenv::SessionStore,
}

impl Session {
    pub fn new() -> Self {
        Self { id: new_id("s"), js_store: crate::jsenv::new_store(), ..Default::default() }
    }

    pub fn snapshot(&self) -> serde_json::Value {
        json!({
            "id": self.id,
            "cookies": self.cookies.len(),
            "network": self.net.len(),
            "storage_keys": self.js_store.borrow().len(),
            "dom_loaded": self.dom.is_some(),
            "last": self.last.as_ref().map(|r| json!({
                "url": r.final_url, "status": r.status, "title": r.title,
                "html_len": r.html_len, "elapsed_ms": r.elapsed_ms
            }))
        })
    }
}

/// Detect a captcha/challenge page via static markers (URL, title, marker
/// in the HTML). Fast, no JS. It does not solve — it only labels so the AI can change tactics.
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
    // Order: specific kinds first, generic ones last.
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
/// This is the tightest integration point in the project, so it is a plain function, not a
/// trait: there is no reason to abstract a single pipeline.
#[allow(clippy::too_many_arguments)]
/// Orchestrate one complete navigation.
pub async fn navigate(
    url: &str,
    cfg: &Config,
    sess: &mut Session,
    wait: &WaitFor,
    run_js: bool,
) -> Result<NavResult, String> {
    let prof = stealth::profile(&cfg.profile).ok_or_else(|| {
        format!("no profile `{}` (available: {})", cfg.profile, stealth::names().join(", "))
    })?;

    let t0 = std::time::Instant::now();
    // The blocklist is real policy, not a test button: if the document is blocked, stop immediately;
    // if a subresource is blocked, skip it + note it (the main page stays readable).
    let bl = crate::blocklist::Blocklist::new();
    if let crate::blocklist::Decision::Block { rule } = bl.decide(url, crate::blocklist::ResourceKind::Document) {
        return Err(format!("blocked by blocklist ({rule}): {url}"));
    }
    let cookie = sess.cookies.header_for(url);
    let f = crate::fetch::get(url, cfg, prof, &cookie).await?;

    // Load Set-Cookie into the session's jar.
    sess.cookies.set_from_headers(&f.final_url, &f.headers);

    let parsed = htmlparse::parse(&f.body);
    let dom = htmlparse::shared(parsed.dom);

    let title0 = parsed.title.clone();
    let text0 = dom.borrow().text_content(0);
    let scripts = parsed.scripts.clone();

    let env = Env {
        ua: prof.ua.to_string(),
        platform: prof.platform.to_string(),
        concurrency: prof.hardware_concurrency,
        device_memory: prof.device_memory,
        screen: prof.screen,
        title: title0.clone(),
        url: f.final_url.clone(),
        cookie: sess.cookies.visible_for_js(&f.final_url),
        timezone: prof.timezone.to_string(),
    };

    let mut realm = Realm::new(dom.clone(), &env, sess.js_store.clone()).map_err(|e| format!("QuickJS: {e}"))?;
    // Hook the client budget in instead of a hard deadline — quiet_ms does not apply
    // because JS in the realm runs synchronously, with no background network to be "idle".
    realm.set_deadline_ms(wait.budget_ms);
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
                    // Fetch the external script then run it in order. A fetch failure is recorded
                    // as a page error (with the URL) instead of breaking the whole navigation.
                    let full = reqwest::Url::options()
                        .base_url(reqwest::Url::parse(&f.final_url).ok().as_ref())
                        .parse(src)
                        .map(|u| u.to_string())
                        .unwrap_or_default();
                    if full.is_empty() || !(full.starts_with("http://") || full.starts_with("https://")) {
                        errors.push(format!("page:{src}: invalid script URL"));
                    } else if let crate::blocklist::Decision::Block { rule } =
                        bl.decide(&full, crate::blocklist::ResourceKind::Script)
                    {
                        errors.push(format!("page:{full}: skipped script blocked by blocklist ({rule})"));
                    } else {
                        let ck = sess.cookies.header_for(&full);
                        match crate::fetch::get(&full, cfg, prof, &ck).await {
                            Ok(sf) => {
                                sess.cookies.set_from_headers(&sf.final_url, &sf.headers);
                                sess.net.push(NetEntry {
                                    url: full.clone(),
                                    method: "GET".into(),
                                    status: sf.status,
                                    req_headers: vec![],
                                    resp_headers: sf.headers.clone(),
                                    mime: sf.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone()).unwrap_or_default(),
                                    body_len: sf.body.len(),
                                    req_body: 0,
                                    elapsed_ms: sf.elapsed_ms,
                                    started_ms: inspector::now_ms(),
                                });
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

    // Content after JS. If it is empty while the original HTML has content, use the
    // original HTML — but say so clearly, never pretend the dynamic content was fetched.
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

    let html = dom.borrow().inner_html(0);
    // Final title from the DOM after JS — if a script changed <title>, report it accurately instead of the stale parsed title.
    let title_final = dom.borrow().query("title", 0).ok()
        .and_then(|ids| ids.into_iter().next())
        .map(|id| dom.borrow().text_content(id))
        .filter(|t| !t.trim().is_empty())
        .unwrap_or(title0);
    let captcha = detect_captcha(&f.final_url, &title_final, &f.body);
    let res = NavResult {
        tab: sess.id.clone(),
        url: f.url.clone(),
        final_url: f.final_url.clone(),
        status: f.status,
        title: title_final,
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
        challenge: None,
    };

    sess.dom = Some(dom.clone());
    sess.realm = Some(Box::new(realm));
    sess.last = Some(res.clone());
    Ok(res)
}

/// Run JS on an already-loaded tab, return JSON.
pub fn eval(sess: &Session, src: &str) -> Result<serde_json::Value, String> {
    let r = sess.realm.as_ref().ok_or("no tab has been loaded yet")?;
    r.eval_json(src)
}