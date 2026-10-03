//! Tool surface for AI. Every tool is a function; dispatch is one `match`.

use crate::config::Config;
use crate::session::{Session, WaitFor};
use crate::stealth;
use serde_json::{json, Value};
use std::sync::Arc;

fn s(p: &Value, k: &str) -> String {
    p.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Create a new session, or fetch an existing one.
fn get_sess(srv: &Arc<crate::rpc::Server>, p: &Value) -> Result<String, String> {
    let id = s(p, "session");
    let mut m = srv.sessions.lock().unwrap();
    if !id.is_empty() && m.contains_key(&id) {
        return Ok(id);
    }
    let sess = Session::new();
    let id = sess.id.clone();
    m.insert(id.clone(), sess);
    Ok(id)
}

/// Look up an existing session — does NOT create one. A mistyped ID must error
/// out, not silently point at an empty session (previously get_sess created one,
/// making session_close report fake success and operate on the wrong session).
fn need_sess(srv: &Arc<crate::rpc::Server>, p: &Value) -> Result<String, String> {
    let id = s(p, "session");
    if id.is_empty() {
        return get_sess(srv, p);
    }
    let m = srv.sessions.lock().unwrap();
    if m.contains_key(&id) {
        Ok(id)
    } else {
        Err(format!("session does not exist: `{id}` (use session_new to create one)"))
    }
}

pub async fn tool(srv: &Arc<crate::rpc::Server>, name: &str, p: &Value) -> Result<Value, String> {
    match name {
        // ---- orchestration ----
        "session_new" | "session.list" => {
            let id = get_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            Ok(json!(m.get(&id).map(|x| x.snapshot()).unwrap_or(Value::Null)))
        }
        "session_info" => {
            let id = need_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            Ok(m.get(&id).map(|x| x.snapshot()).unwrap_or(Value::Null))
        }
        "session_close" => {
            let id = need_sess(srv, p)?;
            let mut m = srv.sessions.lock().unwrap();
            Ok(json!({ "closed": m.remove(&id).is_some() }))
        }
        "kill_switch" => {
            let mut m = srv.sessions.lock().unwrap();
            let on = p.get("on").and_then(Value::as_bool).unwrap_or(true);
            for x in m.values_mut() { x.kill_switch = on; }
            Ok(json!({ "kill_switch": on, "sessions": m.len() }))
        }

        // ---- navigation ----
        "navigate" => {
            let id = need_sess(srv, p)?;
            let url = s(p, "url");
            if url.is_empty() { return Err("missing `url`".into()); }
            let run_js = p.get("js").and_then(Value::as_bool).unwrap_or(true);
            let wait = WaitFor {
                quiet_ms: p.get("quiet_ms").and_then(Value::as_u64).unwrap_or(250),
                budget_ms: p.get("budget_ms").and_then(Value::as_u64).unwrap_or(10_000),
            };
            let mut m = srv.sessions.lock().unwrap();
            let sess = m.get_mut(&id).ok_or("session does not exist")?;
            let cfg = srv.config();
            let mut r = crate::session::navigate(&url, &cfg, sess, &wait, run_js).await?;
            drop(m);
            // on_challenge=portal: on hitting a challenge, create a human-solve ticket.
            // The default (ignore) only sets the captcha flag and does nothing else.
            if crate::challenge::OnChallenge::from_str(&s(p, "on_challenge")) == crate::challenge::OnChallenge::Portal
                && let Some(kind) = r.captcha.clone()
            {
                let m = srv.sessions.lock().unwrap();
                if let Some(sess) = m.get(&id)
                    && let Some(dom) = sess.dom.as_ref()
                    && let Some(spec) = crate::challenge::auto_extract(&dom.borrow(), &r.final_url)
                {
                    let listen = srv.config().listen;
                    let ctx = crate::challenge::extract_hidden_tokens(&dom.borrow());
                    r.challenge = Some(crate::challenge::create_ticket(
                        &srv.challenges, &listen, &id, &r.final_url, &kind, spec, ctx,
                    ));
                }
            }
            Ok(serde_json::to_value(&r).unwrap_or(Value::Null))
        }
        "extract_text" => {
            let id = need_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session does not exist")?;
            Ok(json!({ "text": sess.dom.as_ref().map(|d| d.borrow().text_content(0)).unwrap_or_default() }))
        }
        "snapshot_dom" => {
            let id = need_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session does not exist")?;
            Ok(json!({ "html": sess.dom.as_ref().map(|d| d.borrow().inner_html(0)).unwrap_or_default() }))
        }
        "query" => {
            let id = need_sess(srv, p)?;
            let sel = s(p, "selector");
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session does not exist")?;
            let d = sess.dom.as_ref().ok_or("no page loaded")?;
            let g = d.borrow();
            let ids = g.query(&sel, 0).map_err(|e| format!("invalid selector: {e:?}"))?;
            let all = p.get("all").and_then(Value::as_bool).unwrap_or(false);
            let out: Vec<Value> = ids.iter().map(|i| json!({
                "id": i,
                "tag": g.get(*i).map(|n| n.name.clone()).unwrap_or_default(),
                "text": g.text_content(*i),
                "html": g.inner_html(*i),
                "attrs": g.get(*i).map(|n| n.attrs.clone()).unwrap_or_default(),
            })).collect();
            if all { Ok(json!({ "count": out.len(), "nodes": out })) }
            else { Ok(out.into_iter().next().map(|v| json!({"count": 1, "nodes": [v]})).unwrap_or(json!({"count":0,"nodes":[]}))) }
        }
        "eval_js" => {
            let id = need_sess(srv, p)?;
            let src = s(p, "script");
            if src.is_empty() { return Err("missing `script`".into()); }
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session does not exist")?;
            crate::session::eval(sess, &src).map_err(|e| format!("JS: {e}"))
        }

        // ---- network ----
        "network_log" => {
            let id = need_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session does not exist")?;
            Ok(json!({ "count": sess.net.len(), "entries": sess.net }))
        }
        "har_export" => {
            // By default export only the calling session — never mix in other sessions' logs.
            // Pass `"all": true` to export everything (admin/debug).
            let only = s(p, "session");
            let all = p.get("all").and_then(Value::as_bool).unwrap_or(false);
            let m = srv.sessions.lock().unwrap();
            let es: Vec<_> = if all {
                m.values().flat_map(|x| x.net.clone()).collect()
            } else {
                let id = if only.is_empty() {
                    m.keys().next().cloned().unwrap_or_default()
                } else { only };
                m.get(&id).map(|x| x.net.clone()).unwrap_or_default()
            };
            Ok(crate::inspector::to_har(&es))
        }
        "blocklist_test" => {
            let url = s(p, "url");
            // By default test as XHR/Script (subresource) — Document is always allowed
            // so the browser never blocks a page the user asked for.
            let kind = match s(p, "kind").to_lowercase().as_str() {
                "document" => crate::blocklist::ResourceKind::Document,
                "image" => crate::blocklist::ResourceKind::Image,
                "script" => crate::blocklist::ResourceKind::Script,
                _ => crate::blocklist::ResourceKind::Xhr,
            };
            let bl = crate::blocklist::Blocklist::new();
            Ok(json!({ "url": url, "decision": serde_json::to_value(bl.decide(&url, kind)).unwrap_or(Value::Null) }))
        }

        // ---- stealth ----
        "stealth_profile" => {
            let name = s(p, "name");
            if !name.is_empty() {
                // Make it real: validate the name and switch the daemon profile used for every
                // later navigation. (Previously it only reported the name without changing
                // anything — the client thought it had changed.)
                if stealth::profile(&name).is_none() {
                    return Err(format!("no profile `{name}` (available: {})", stealth::names().join(", ")));
                }
                srv.cfg.lock().unwrap().profile = name.clone();
                return Ok(json!({ "active": name }));
            }
            Ok(json!({ "active": srv.config().profile, "available": stealth::names() }))
        }

        // ---- plugin ----
        "plugin_list" => {
            let mut r = crate::plugin::Registry::new(crate::plugin::default_root());
            r.scan();
            Ok(json!({ "plugins": r.list().iter().map(|p| p.manifest.id.clone()).collect::<Vec<_>>() }))
        }
        "plugin_info" => {
            let id = s(p, "id");
            if id.is_empty() { return Err("missing `id`".into()); }
            let mut r = crate::plugin::Registry::new(crate::plugin::default_root());
            r.scan();
            match r.get(&id) {
                Some(pl) => Ok(json!({
                    "id": pl.manifest.id, "name": pl.manifest.name,
                    "version": pl.manifest.version, "kind": pl.manifest.kind.as_str(),
                    "entry": pl.manifest.entry, "api": pl.manifest.api,
                    "enabled": pl.enabled(),
                    "permissions": pl.manifest.permissions.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
                    "hooks": pl.manifest.hooks.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
                })),
                None => Err(format!("no plugin `{id}`")),
            }
        }
        "plugin_install" => {
            let dir = s(p, "path");
            let root = crate::plugin::default_root();
            Ok(json!({ "installed": crate::plugin::install_from_dir(std::path::Path::new(&dir), &root)? }))
        }

        // ---- human-solve challenge ----
        "challenge_create" => {
            let sid = s(p, "session");
            let m = srv.sessions.lock().unwrap();
            let sess = match m.get(&sid) {
                Some(s) => s,
                None => return Err(format!("session does not exist: `{sid}`")),
            };
            let dom = sess.dom.as_ref().ok_or("session has no page loaded")?.clone();
            let kind = sess.last.as_ref().and_then(|r| r.captcha.clone()).unwrap_or("manual".into());
            let page_url = sess.last.as_ref().map(|r| r.final_url.clone()).unwrap_or_default();
            let spec = match p.get("post_url").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                Some(u) => crate::challenge::ReplaySpec {
                    post_url: u.into(),
                    fields: vec![],
                    token_field: p.get("token_field").and_then(Value::as_str).unwrap_or("g-recaptcha-response").into(),
                },
                None => crate::challenge::auto_extract(&dom.borrow(), &page_url)
                    .ok_or("could not auto-extract a replay form from the DOM (set post_url manually)")?,
            };
            drop(m);
            let listen = srv.config().listen;
            let ctx = crate::challenge::extract_hidden_tokens(&dom.borrow());
            let t = crate::challenge::create_ticket(&srv.challenges, &listen, &sid, &page_url, &kind, spec, ctx);
            Ok(json!({"id": t.id, "portal_url": t.portal_url, "kind": t.kind}))
        }
        "challenge_result" => {
            let id = s(p, "id");
            match crate::challenge::lookup(&srv.challenges, &id) {
                Some(t) => Ok(json!({"id": t.id, "status": t.status, "url": t.url, "note": t.note})),
                None => Err(format!("ticket does not exist: `{id}`")),
            }
        }

        // ---- bench ----
        "bench" => Ok(json!({ "note": "use the CLI: f1stmux bench --compare <path>" })),

        "version" => Ok(json!({
            "name": "f1stmux",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": "2024-11-05",
            "api": crate::plugin::CURRENT_API_VERSION,
        })),

        _ => Err(format!("unknown tool: {name}")),
    }
}

/// List the tools for MCP / `f1stmux tools`.
pub fn catalog() -> Value {
    json!([
        {"name":"navigate","desc":"Open a URL and return text + console + timing"},
        {"name":"extract_text","desc":"Extract text from the loaded DOM"},
        {"name":"snapshot_dom","desc":"innerHTML of the page"},
        {"name":"query","desc":"querySelector against our DOM"},
        {"name":"eval_js","desc":"Run JS inside the page realm"},
        {"name":"network_log","desc":"List the requests made so far"},
        {"name":"har_export","desc":"Export HAR 1.2"},
        {"name":"blocklist_test","desc":"Check whether a URL is blocked"},
        {"name":"stealth_profile","desc":"View/set the identity profile"},
        {"name":"session_new","desc":"Create a new session"},
        {"name":"session_info","desc":"Session information"},
        {"name":"session_close","desc":"Delete the session and every trace in RAM"},
        {"name":"kill_switch","desc":"Disable every plugin hook immediately"},
        {"name":"plugin_list","desc":"List installed plugins"},
        {"name":"plugin_install","desc":"Install a plugin from a directory"},
        {"name":"plugin_info","desc":"Details of one plugin"},
        {"name":"bench","desc":"Measure performance"},
        {"name":"version","desc":"f1stmux version + protocol"},
        {"name":"challenge_create","desc":"Create a human-solve ticket for the session challenge"},
        {"name":"challenge_result","desc":"Ticket status (poll after a human solves it)"}
    ])
}

fn str_prop(d: &str) -> Value { json!({"type":"string","description":d}) }
fn bool_prop(d: &str) -> Value { json!({"type":"boolean","description":d}) }
fn num_prop(d: &str) -> Value { json!({"type":"number","description":d}) }

/// Tools in the MCP `tools/list` format, with inputSchema so AI clients can validate.
pub fn mcp_tools() -> Value {
    let opt_session = ("session", str_prop("Session ID, leave empty to create one"));
    let defs: Vec<(&str, &str, Vec<(&str, Value)>, Vec<&str>)> = vec![
        ("navigate", "Open a URL, return text/console/network/captcha", vec![
            ("url", str_prop("URL to open")), ("session", str_prop("ID session")),
            ("js", bool_prop("Run the page JS (default true)")),
            ("quiet_ms", num_prop("Network-idle threshold")), ("budget_ms", num_prop("Time budget in ms")),
            ("on_challenge", str_prop("\"portal\" = automatically create a human-solve ticket when a challenge appears")),
        ], vec!["url"]),
        ("extract_text", "Extract text from the loaded page", vec![opt_session.clone()], vec![]),
        ("snapshot_dom", "innerHTML of the loaded page", vec![opt_session.clone()], vec![]),
        ("query", "querySelector against the DOM (tag, #id, .class, [attr])", vec![
            ("selector", str_prop("Simple CSS selector")), ("session", str_prop("ID session")), ("all", bool_prop("Return all matches, default is the first node")),
        ], vec!["selector"]),
        ("eval_js", "Run a JS expression in the page realm, return JSON", vec![
            ("script", str_prop("JS expression")), ("session", str_prop("ID session")),
        ], vec!["script"]),
        ("network_log", "List the requests made by the session", vec![opt_session.clone()], vec![]),
        ("har_export", "Export HAR 1.2 for every session", vec![], vec![]),
        ("blocklist_test", "Check whether a URL is blocked (defaults to testing as XHR)", vec![
            ("url", str_prop("URL to check")), ("kind", str_prop("document|script|xhr|image")),
        ], vec!["url"]),
        ("stealth_profile", "View the identity profile in use", vec![("name", str_prop("Leave empty to view"))], vec![]),
        ("session_new", "Create a new session (RAM-only)", vec![], vec![]),
        ("session_info", "Session information", vec![opt_session.clone()], vec![]),
        ("session_close", "Delete the session and every trace in RAM", vec![opt_session.clone()], vec![]),
        ("kill_switch", "Disable every plugin hook immediately", vec![("on", bool_prop("true=disable hooks"))], vec![]),
        ("plugin_list", "List installed plugins", vec![], vec![]),
        ("plugin_install", "Install a plugin from a directory", vec![("path", str_prop("Path to the plugin directory"))], vec!["path"]),
        ("plugin_info", "Details of one plugin", vec![("id", str_prop("Plugin ID"))], vec!["id"]),
        ("bench", "Note: use the CLI `f1stmux bench`", vec![], vec![]),
        ("version", "f1stmux version + protocol", vec![], vec![]),
        ("challenge_create", "Create a human-solve ticket (returns portal_url for the human)", vec![
            ("session", str_prop("Session ID that has navigated to the challenge page")),
            ("post_url", str_prop("Override the replay URL (default: auto-extract from the form)")),
            ("token_field", str_prop("Token field name (default depends on the challenge kind)")),
        ], vec!["session"]),
        ("challenge_result", "Poll the ticket status", vec![
            ("id", str_prop("Ticket ID")),
        ], vec!["id"]),
    ];
    let tools: Vec<Value> = defs.into_iter().map(|(name, desc, props, req)| {
        let mut map = serde_json::Map::new();
        for (k, v) in props { map.insert(k.into(), v); }
        json!({"name": name, "description": desc,
               "inputSchema": {"type": "object", "properties": Value::Object(map),
                               "required": req, "additionalProperties": true}})
    }).collect();
    Value::Array(tools)
}

pub fn cfg_of(srv: &Arc<crate::rpc::Server>) -> Config { srv.config() }