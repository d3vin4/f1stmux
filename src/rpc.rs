//! HTTP server: JSON-RPC 2.0 + DevTools endpoints.
//!
//! Deliberately **not** using WebSocket for CDP, even though a real DevTools
//! frontend usually wants one. Reason: the WebSocket handshake requires SHA-1 +
//! binary framing — code we would have to write by hand since we add no
//! dependency. In return, CDP over HTTP POST is entirely sufficient for
//! inspection work, and we avoid a whole failure point. If real-time streaming is
//! ever needed, add it then, backed by numbers.

use crate::config::Config;
use crate::session::Session;
use crate::tools::tool;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct Server {
    /// Config behind a lock so the stealth_profile tool can really switch it at runtime.
    /// Every reader clones and drops the lock immediately; never held across await.
    pub cfg: Mutex<Config>,
    pub sessions: Arc<Mutex<HashMap<String, Session>>>,
    /// Human-solve challenge tickets (RAM, 10-minute expiry).
    pub challenges: crate::challenge::TicketStore,
}

impl Server {
    pub fn new(cfg: Config) -> Self {
        Self { cfg: Mutex::new(cfg), sessions: Arc::new(Mutex::new(HashMap::new())), challenges: crate::challenge::new_store() }
    }

    pub fn config(&self) -> Config {
        self.cfg.lock().unwrap().clone()
    }
}

pub async fn serve(cfg: Config) -> Result<(), String> {
    // The daemon has no auth: binding a remote address without saying so opens the
    // control plane (navigate/plugin/install) to the whole network. Fail-closed unless --allow-remote.
    if cfg.is_remote_bind() && !cfg.allow_remote {
        return Err(format!(
            "refusing to bind {0}: not loopback but allow_remote is missing. \
             The daemon has no auth — only go remote when you understand the risk \
             (--allow-remote or \"allow_remote\": true in the config)",
            cfg.listen
        ));
    }
    let srv = Arc::new(Server::new(cfg));
    let addr = srv.config().listen;
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("cannot bind {addr}: {e}"))?;
    eprintln!("f1stmuxd: listening on http://{addr}  (devtools: http://{addr}/devtools)");

    // ponytail: single-threaded, handles connections one at a time — enough for low-RAM
    // Termux, and it sidesteps every Send/Sync problem in DOM/QuickJS (Rc is not Send).
    loop {
        let Ok((sock, _peer)) = listener.accept().await else { continue };
        let _ = handle(srv.clone(), sock).await;
    }
}

struct Req {
    method: String,
    path: String,
    body: String,
}

async fn handle(srv: Arc<Server>, mut sock: tokio::net::TcpStream) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 64 * 1024];
    let n = sock.read(&mut buf).await.map_err(|e| e.to_string())?;
    let raw = String::from_utf8_lossy(&buf[..n]).to_string();

    let mut lines = raw.split("\r\n");
    let start = lines.next().unwrap_or("");
    let mut parts = start.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut len = 0usize;
    for h in raw.split("\r\n") {
        if let Some(v) = h.strip_prefix("Content-Length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    if len > body.len() && len < 16 * 1024 * 1024 {
        let mut extra = vec![0u8; len - body.len()];
        let _ = sock.read_exact(&mut extra).await;
        body.push_str(&String::from_utf8_lossy(&extra));
    }
    let _ = (method.clone(), &body);

    let req = Req { method, path: path.split('?').next().unwrap_or("/").to_string(), body };
    let (status, ctype, payload) = route(&srv, &req).await;

    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    sock.write_all(resp.as_bytes()).await.map_err(|e| e.to_string())?;
    let _ = sock.shutdown().await;
    Ok(())
}

async fn route(srv: &Arc<Server>, req: &Req) -> (&'static str, &'static str, String) {
/// POST /challenge {session, post_url?, token_field?} → create a human-solve ticket.
/// If post_url is given use it directly, otherwise auto-extract it from the session DOM.
async fn challenge_create_http(srv: &Arc<Server>, body: &str) -> (&'static str, &'static str, String) {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let sid = v.get("session").and_then(Value::as_str).unwrap_or("");
    let m = srv.sessions.lock().unwrap();
    let sess = match m.get(sid) {
        Some(s) => s,
        None => return ("404 Not Found", "text/plain; charset=utf-8", "session does not exist".into()),
    };
    let dom = match sess.dom.as_ref() {
        Some(d) => d.clone(),
        None => return ("422 Unprocessable", "text/plain; charset=utf-8", "session has no page loaded".into()),
    };
    let kind = sess.last.as_ref().and_then(|r| r.captcha.clone()).unwrap_or("manual".into());
    let page_url = sess.last.as_ref().map(|r| r.final_url.clone()).unwrap_or_default();
    let spec = match v.get("post_url").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        Some(u) => crate::challenge::ReplaySpec {
            post_url: u.into(),
            fields: vec![],
            token_field: v.get("token_field").and_then(Value::as_str).unwrap_or("g-recaptcha-response").into(),
        },
        None => match crate::challenge::auto_extract(&dom.borrow(), &page_url) {
            Some(s) => s,
            None => return ("422 Unprocessable", "text/plain; charset=utf-8", "could not auto-extract a replay form from the DOM".into()),
        },
    };
    drop(m);
    let listen = srv.config().listen;
    let t = crate::challenge::create_ticket(&srv.challenges, &listen, sid, &page_url, &kind, spec, crate::challenge::extract_hidden_tokens(&dom.borrow()));
    json(json!({"id": t.id, "portal_url": t.portal_url, "kind": t.kind}))
}

/// POST /challenge/:id/solution {token} (JSON or urlencoded from the portal form)
/// → replay into the session, return {ok, url?, raw?}. Never navigates to the target.
async fn challenge_solution_http(srv: &Arc<Server>, id: &str, body: &str) -> (&'static str, &'static str, String) {
    let token = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("token").and_then(Value::as_str).map(str::to_string))
        .or_else(|| {
            body.split('&').find_map(|p| {
                let (k, v) = p.split_once('=')?;
                (k.trim() == "token").then(|| v.trim().to_string())
            })
        })
        .unwrap_or_default();
    // Minimal URL-decode for the portal form (the token is usually base64url, few special chars).
    let token = percent_decode(&token.replace('+', " "));
    let sess_id = match crate::challenge::lookup(&srv.challenges, id) {
        Some(t) => t.session.clone(),
        None => return ("404 Not Found", "text/plain; charset=utf-8", "ticket does not exist".into()),
    };
    let cfg = srv.config();
    let prof_name = cfg.profile.clone();
    let mut m = srv.sessions.lock().unwrap();
    let sess = match m.get_mut(sess_id.as_str()) {
        Some(s) => s,
        None => return ("410 Gone", "text/plain; charset=utf-8", "the ticket session has been closed".into()),
    };
    let prof = match crate::stealth::profile(&prof_name) {
        Some(p) => p,
        None => return ("500 Internal", "text/plain; charset=utf-8", "the configured profile does not exist".into()),
    };
    match crate::challenge::solve(&srv.challenges, sess, &cfg, prof, id, &token).await {
        Ok(o) => json(serde_json::to_value(&o).unwrap_or(Value::Null)),
        Err(e) => ("422 Unprocessable", "application/json; charset=utf-8", json!({"ok": false, "error": e}).to_string()),
    }
}

fn percent_decode(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() + 1 {
            if let (Some(h), Some(l)) = (hex(b.get(i + 1)), hex(b.get(i + 2))) {
                o.push((h << 4 | l) as char);
                i += 3;
                continue;
            }
        }
        o.push(b[i] as char);
        i += 1;
    }
    o
}

fn hex(c: Option<&u8>) -> Option<u8> {
    let c = *c?;
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
    // ---- DevTools frontend ----
    if req.path == "/devtools" || req.path == "/devtools/" {
        let ws = format!("ws://{}", srv.config().listen);
        return ("200 OK", "text/html; charset=utf-8", crate::inspector::index_html(&ws));
    }
    if req.path == "/devtools/inspector.html" {
        return ("200 OK", "text/html; charset=utf-8", crate::inspector::index_html(""));
    }
    if req.path == "/json/version" {
        return json(crate::inspector::version_json());
    }
    if req.path == "/json/list" {
        let s = srv.sessions.lock().unwrap();
        let last = s.values().find_map(|x| x.last.as_ref());
        return json(crate::inspector::list_json(
            &format!("ws://{}", srv.config().listen),
            last.map(|r| r.title.as_str()).unwrap_or("F1stmux"),
            last.map(|r| r.final_url.as_str()).unwrap_or("about:blank"),
        ));
    }

    // ---- CDP for DevTools ----
    if req.path == "/cdp" && req.method == "POST" {
        let v: Value = serde_json::from_str(&req.body).unwrap_or(Value::Null);
        return json(cdp(srv, &v).await);
    }

    // ---- Human-solve challenge portal (loopback, never logs the token) ----
    if req.path == "/challenge" && req.method == "POST" {
        return challenge_create_http(srv, &req.body).await;
    }
    if let Some(rest) = req.path.strip_prefix("/challenge/") {
        let mut it = rest.splitn(2, '/');
        let (id, tail) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
        if tail.is_empty() && req.method == "GET" {
            return match crate::challenge::lookup(&srv.challenges, id) {
                Some(t) => {
                    let ttl = crate::challenge::TICKET_TTL_MS.saturating_sub(
                        crate::challenge::now_ms().saturating_sub(t.created_ms),
                    ) / 1000;
                    ("200 OK", "text/html; charset=utf-8", crate::challenge::portal_page(&t, ttl))
                }
                None => ("404 Not Found", "text/plain; charset=utf-8", "ticket does not exist".into()),
            };
        }
        if tail == "solution" && req.method == "POST" {
            return challenge_solution_http(srv, id, &req.body).await;
        }
        if tail == "result" && req.method == "GET" {
            return match crate::challenge::lookup(&srv.challenges, id) {
                Some(t) => json(json!({"id": t.id, "status": t.status, "url": t.url, "note": t.note})),
                None => ("404 Not Found", "text/plain; charset=utf-8", "ticket does not exist".into()),
            };
        }
    }

    // ---- JSON-RPC ----
    if req.path == "/rpc" && req.method == "POST" {
        let v: Value = serde_json::from_str(&req.body).unwrap_or(Value::Null);
        let m = v.get("method").and_then(Value::as_str).unwrap_or("").to_string();
        let p = v.get("params").cloned().unwrap_or(json!({}));
        let id = v.get("id").cloned().unwrap_or(Value::Null);
        return match tool(srv, &m, &p).await {
            Ok(r) => json(json!({"jsonrpc":"2.0","id":id,"result":r})),
            Err(e) => json(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":e}})),
        };
    }

    if req.path == "/health" {
        return json(json!({"ok": true, "sessions": srv.sessions.lock().unwrap().len()}));
    }

    if req.path == "/" && req.method == "GET" {
        return json(json!({
            "name": "F1stmux",
            "version": env!("CARGO_PKG_VERSION"),
            "endpoints": ["/rpc", "/cdp", "/devtools", "/json/version", "/json/list", "/health"],
            "note": "no telemetry, no logging by default. /devtools is the real DevTools."
        }));
    }

    ("404 Not Found", "text/plain; charset=utf-8", "no such endpoint".into())
}

fn json(v: Value) -> (&'static str, &'static str, String) {
    ("200 OK", "application/json; charset=utf-8", v.to_string())
}

/// Handle a CDP command. The `F1stmux.*` domains are ours; the remaining DOM/Network
/// domains return compatible data so a real frontend can understand it.
async fn cdp(srv: &Arc<Server>, v: &Value) -> Value {
    let m = v.get("method").and_then(Value::as_str).unwrap_or("");
    let p = v.get("params").cloned().unwrap_or(json!({}));
    let last = srv.sessions.lock().unwrap().values().find_map(|s| s.last.clone());

    let result = match m {
        "DOM.getDocument" => {
            let html = last.as_ref().map(|_| srv.sessions.lock().unwrap().values().find_map(|s| s.dom.as_ref().map(|d| d.borrow().inner_html(0)))).flatten().unwrap_or_default();
            let id = last.as_ref().map(|r| r.final_url.clone()).unwrap_or_default();
            json!({"root": {"nodeId": 1, "nodeName": "#document", "documentURL": id, "localName": "", "nodeValue": "", "childNodeCount": html.matches('<').count()}})
        }
        "DOM.getOuterHTML" => {
            let html = srv.sessions.lock().unwrap().values().find_map(|s| s.dom.as_ref().map(|d| d.borrow().inner_html(0))).unwrap_or_default();
            json!({"outerHTML": html})
        }
        "F1stmux.getText" => json!({"text": last.map(|r| r.text).unwrap_or_default()}),
        "F1stmux.getNav" => match &last {
            Some(r) => serde_json::to_value(r).unwrap_or(Value::Null),
            None => Value::Null,
        },
        "Runtime.consoleAPICalled" | "Log.entryAdded" => {
            json!({"entries": crate::inspector::console_to_cdp(&last.map(|r| r.console.clone()).unwrap_or_default())})
        }
        "Network.getEntries" => {
            let es: Vec<_> = srv.sessions.lock().unwrap().values().flat_map(|s| s.net.clone()).collect();
            json!({"entries": es})
        }
        "Network.getHAR" => {
            let es: Vec<_> = srv.sessions.lock().unwrap().values().flat_map(|s| s.net.clone()).collect();
            json!({"har": crate::inspector::to_har(&es)})
        }
        "Page.getResourceTree" | "Page.getNavigationHistory" => json!({"frameTree": {"frame": {"id": "F1STMUX-TAB-0", "loaderId": "1", "url": last.map(|r| r.final_url.clone()).unwrap_or_default(), "domainAndRegistry": "", "securityOrigin": "", "mimeType": "text/html"}}}),
        "Target.getTargets" => json!({"targetInfos": []}),
        "Target.setDiscoverTargets" => json!({}),
        "Browser.getVersion" => crate::inspector::version_json(),
        _ => {
            let _ = p;
            return json!({"error": {"code": -32601, "message": format!("unsupported CDP method: {m}")}});
        }
    };
    json!({"id": v.get("id").cloned().unwrap_or(Value::Null), "result": result})
}