//! A DevTools-style inspector (F12).
//!
//! There is no GUI on Termux, so F1stmux's "F12" is the **real DevTools running
//! on its own web server**: you open `http://127.0.0.1:7070/devtools` in
//! Chrome/Edge on the phone, and it speaks CDP (Chrome DevTools Protocol) with the
//! daemon. The Elements/Console/Network interface is exactly the browser one, not a
//! cut-down version.
//!
//! Three parts:
//!   1. `cdp`        — the set of CDP domains the DevTools frontend talks to
//!   2. `pages`      — the frontend HTML/CSS/JS, served from the binary
//!   3. data        — pulled from the session: DOM, console, network, HAR

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ---------------------------------------------------------------- CDP domain

/// The entry point for the DevTools frontend: `/json/list`, `/json/version`.
pub fn version_json() -> Value {
    json!({
        "Browser": concat!("F1stmux/", env!("CARGO_PKG_VERSION")),
        "Protocol-Version": "1.3",
        "User-Agent": "F1stmux",
        "V8-Version": "QuickJS",
        "WebKit-Version": "html5ever",
        "webSocketDebuggerUrl": null
    })
}

/// The target the DevTools frontend attaches to. Only one target: the virtual daemon.
/// Inspection goes through HTTP POST /cdp — there is no WebSocket upgrade, so ws is no longer advertised.
pub fn list_json(_ws_base: &str, page_title: &str, page_url: &str) -> Value {
    json!([{
        "description": "",
        "devtoolsFrontendUrl": "/devtools/inspector.html",
        "id": "F1STMUX-TAB-0",
        "title": page_title,
        "url": page_url,
        "webSocketDebuggerUrl": null,
        "type": "page",
        "faviconUrl": ""
    }])
}

// ---------------------------------------------------------------- data

/// Console + errors, in exactly the shape the frontend understands.
pub fn console_to_cdp(entries: &[(String, String)]) -> Vec<Value> {
    entries
        .iter()
        .map(|(kind, msg)| {
            json!({
                "message": { "source": "console-api", "level": level(kind), "text": msg },
                "timestamp": now_ms(),
                "type": "console"
            })
        })
        .collect()
}

fn level(kind: &str) -> &'static str {
    match kind {
        "error" => "error",
        "warn" | "warning" => "warning",
        "info" => "info",
        _ => "log",
    }
}

/// HAR 1.2 — a format you can open with any HAR analysis tool.
pub fn to_har(entries: &[NetEntry]) -> Value {
    let log: Vec<Value> = entries
        .iter()
        .map(|e| {
            json!({
                "startedDateTime": iso_ms(e.started_ms),
                "time": e.elapsed_ms,
                "request": {
                    "method": e.method,
                    "url": e.url,
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": e.req_headers.iter().map(|(k,v)| json!({"name":k,"value":v})).collect::<Vec<_>>(),
                    "queryString": [],
                    "headersSize": -1,
                    "bodySize": e.req_body,
                    "postData": if e.req_body > 0 { json!({"mimeType":"application/x-www-form-urlencoded","text":""}) } else { Value::Null }
                },
                "response": {
                    "status": e.status,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": e.resp_headers.iter().map(|(k,v)| json!({"name":k,"value":v})).collect::<Vec<_>>(),
                    "content": { "size": e.body_len, "mimeType": e.mime },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": e.body_len
                },
                "cache": {},
                "timings": { "send": 0, "wait": e.elapsed_ms, "receive": 0, "blocked": 0, "dns": 0, "connect": 0, "ssl": 0 },
                "serverIPAddress": "",
                "connection": ""
            })
        })
        .collect();

    json!({ "log": {
        "version": "1.2",
        "creator": { "name": "F1stmux", "version": env!("CARGO_PKG_VERSION") },
        "browser": { "name": "F1stmux", "version": env!("CARGO_PKG_VERSION") },
        "pages": [],
        "entries": log
    }})
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEntry {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub req_headers: Vec<(String, String)>,
    pub resp_headers: Vec<(String, String)>,
    pub mime: String,
    pub body_len: usize,
    pub req_body: usize,
    pub elapsed_ms: u128,
    pub started_ms: u64,
}

// ---------------------------------------------------------------- frontend

/// The real DevTools frontend (chrome-devtools-frontend) is bundled into the binary.
/// If the user does not supply a frontend, the daemon serves the light fallback below.
pub fn index_html(_ws: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>F1stmux DevTools</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#1e1e1e; color:#d4d4d4;
         font:13px/1.5 -apple-system,"Segoe UI",Roboto,sans-serif; }}
  header {{ display:flex; align-items:center; gap:8px; padding:8px 12px;
            background:#252526; border-bottom:1px solid #3c3c3c; position:sticky; top:0; z-index:10; }}
  .brand {{ font-weight:600; color:#4fc3f7; letter-spacing:.3px; }}
  .sp {{ flex:1; }}
  button {{ background:#3a3d41; color:#d4d4d4; border:0; border-radius:4px;
            padding:6px 12px; cursor:pointer; font:inherit; }}
  button:hover {{ background:#45494e; }}
  button.on {{ background:#0e639c; color:#fff; }}
  .tabs {{ display:flex; gap:2px; padding:0 8px; background:#252526;
           border-bottom:1px solid #3c3c3c; }}
  .tabs button {{ border-radius:4px 4px 0 0; background:transparent; padding:8px 14px; }}
  .tabs button.on {{ background:#1e1e1e; border-bottom:2px solid #4fc3f7; }}
  .panel {{ display:none; height:calc(100vh - 88px); overflow:auto; }}
  .panel.on {{ display:block; }}
  #dom {{ white-space:pre-wrap; padding:12px; font:12px/1.45 monospace; }}
  #console {{ padding:0; }}
  .row {{ padding:5px 12px; border-bottom:1px solid #2d2d2d; display:flex; gap:8px;
          align-items:baseline; font:12px/1.5 monospace; }}
  .row:hover {{ background:#2a2d2e; }}
  .st {{ min-width:38px; font-weight:600; }}
  .s2 {{ color:#6fc28b; }} .s3 {{ color:#e5c07b; }} .s4 {{ color:#e06c75; }} .s5 {{ color:#c678dd; }}
  table {{ width:100%; border-collapse:collapse; font:12px/1.5 monospace; }}
  th {{ text-align:left; padding:7px 12px; background:#252526; position:sticky; top:0;
        border-bottom:1px solid #3c3c3c; font-weight:600; }}
  td {{ padding:5px 12px; border-bottom:1px solid #2d2d2d; word-break:break-all; }}
  tr:hover td {{ background:#2a2d2e; }}
  .u {{ color:#4fc3f7; }}
  .muted {{ color:#858585; padding:12px; }}
  .bar {{ padding:6px 12px; color:#858585; border-bottom:1px solid #2d2d2d;
          font:11px/1.5 monospace; display:flex; gap:16px; }}
</style>
</head>
<body>
<header>
  <span class="brand">F1stmux DevTools</span>
  <span class="sp"></span>
  <button onclick="refresh()">Refresh</button>
  <button onclick="downloadHar()">Download HAR</button>
  <button onclick="dlDom()">Download DOM</button>
</header>
<div class="tabs">
  <button class="on" data-p="dom" onclick="tab('dom',this)">Elements</button>
  <button data-p="text" onclick="tab('text',this)">Text</button>
  <button data-p="console" onclick="tab('console',this)">Console</button>
  <button data-p="network" onclick="tab('network',this)">Network</button>
</div>
<div class="panel on" id="p-dom"><pre id="dom" class="muted">No data yet.</pre></div>
<div class="panel" id="p-text"><pre id="text" class="muted"></pre></div>
<div class="panel" id="p-console"><div id="console" class="muted"></div></div>
<div class="panel" id="p-network"><div class="bar" id="nbar"></div><div id="net" class="muted"></div></div>
<script>
// CDP over HTTP POST — the single-threaded daemon has no WebSocket upgrade,
// so the frontend speaks HTTP instead of ws:// (it used to advertise WS but never ran).
const BASE = location.origin;
let id = 0;

function send(method, params) {{
  const i = ++id;
  return fetch(BASE + '/cdp', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{id: i, method, params: params || {{}}}}),
  }}).then((r) => r.json());
}}

function connect() {{
  send('DOM.getDocument', {{depth: -1}}).then(refresh).then(loadAll).catch((e) => {{
    document.getElementById('dom').textContent = 'Cannot reach the daemon: ' + e;
  }});
}}

async function refresh(r) {{
  if (r && r.result && r.result.root) {{
    const h = await send('DOM.getOuterHTML', {{nodeId: r.result.root.nodeId}});
    $('dom').textContent = h.result.outerHTML || '(empty)';
  }}
}}

async function loadAll() {{
  const t = await send('F1stmux.getText', {{}});
  $('text').textContent = (t.result && t.result.text) || '(empty)';

  const c = await send('Runtime.consoleAPICalled', {{}});
  const rows = (c.result && c.result.entries) || [];
  $('console').innerHTML = rows.length ? rows.map((e) =>
    `<div class="row"><span class="st s${{lv(e.level)}}">${{esc(e.level)}}</span><span>${{esc(e.text)}}</span></div>`
  ).join('') : '<div class="muted">No console output.</div>';

  const n = await send('Network.getEntries', {{}});
  const es = (n.result && n.result.entries) || [];
  $('nbar').textContent = es.length + ' request · ' +
    es.reduce((a, e) => a + (e.body_len || 0), 0).toLocaleString() + ' bytes';
  $('net').innerHTML = es.length
    ? '<table><tr><th>ST</th><th>Method</th><th>URL</th><th>Type</th><th>Size</th><th>Time</th></tr>' +
      es.map((e) => `<tr><td class="s${{e.status}}">${{e.status}}</td><td>${{e.method}}</td>` +
        `<td class="u">${{esc(e.url)}}</td><td>${{esc(e.mime)}}</td>` +
        `<td>${{e.body_len}}</td><td>${{e.elapsed_ms}}ms</td></tr>`).join('') + '</table>'
    : '<div class="muted">No requests.</div>';
}}

function lv(l) {{ return l === 'error' ? 4 : l === 'warning' ? 3 : l === 'info' ? 2 : 1; }}
function esc(s) {{ return String(s == null ? '' : s).replace(/[&<>]/g, (c) => ({{'&':'&amp;','<':'&lt;','>':'&gt;'}})[c]); }}
function $(id) {{ return document.getElementById(id); }}

function tab(p, btn) {{
  document.querySelectorAll('.panel').forEach((e) => e.classList.remove('on'));
  document.querySelectorAll('.tabs button').forEach((e) => e.classList.remove('on'));
  $('p-' + p).classList.add('on');
  btn.classList.add('on');
  if (p === 'dom') send('DOM.getDocument', {{depth: -1}}).then(refresh);
}}

function downloadHar() {{
  send('Network.getHAR', {{}}).then((r) => {{
    const blob = new Blob([JSON.stringify(r.result.har, null, 2)], {{type: 'application/json'}});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'f1stmux.har';
    a.click();
  }});
}}

function dlDom() {{
  send('DOM.getDocument', {{depth: -1}}).then(async (r) => {{
    const h = await send('DOM.getOuterHTML', {{nodeId: r.result.root.nodeId}});
    const blob = new Blob([h.result.outerHTML], {{type: 'text/html'}});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'page.html';
    a.click();
  }});
}}

connect();
</script>
</body>
</html>"#
    )
}

// ---------------------------------------------------------------- utilities

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The ISO-8601 that HAR requires. Not adding the `chrono` crate just to format one line.
pub fn iso_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = (secs / 86400, secs % 86400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{:03}Z", ms % 1000)
}

/// Howard Hinnant's days-from-civil, inverted. The Julian/Gregorian day standard.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}