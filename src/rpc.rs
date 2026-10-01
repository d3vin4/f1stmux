//! Server HTTP: JSON-RPC 2.0 + endpoint DevTools.
//!
//! Cố tình **không** dùng WebSocket cho CDP, dù DevTools frontend thật thường cần
//! nó. Lý do: handshake WebSocket đòi hỏi SHA-1 + framing nhị phân — code đó
//! phải viết tay vì ta không thêm dependency. Đổi lại, CDP qua HTTP POST hoàn
//! toàn đủ cho thao tác kiểm tra, và ta tránh được một điểm hỏng. Nếu sau này
//! cần stream thời gian thực thì thêm lúc đó, có số liệu chứng minh.

use crate::config::Config;
use crate::session::Session;
use crate::tools::tool;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct Server {
    pub cfg: Config,
    pub sessions: Arc<Mutex<HashMap<String, Session>>>,
}

impl Server {
    pub fn new(cfg: Config) -> Self {
        Self { cfg, sessions: Arc::new(Mutex::new(HashMap::new())) }
    }
}

pub async fn serve(cfg: Config) -> Result<(), String> {
    let srv = Arc::new(Server::new(cfg));
    let addr = srv.cfg.listen.clone();
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("không bind được {addr}: {e}"))?;
    eprintln!("f1stmuxd: nghe trên http://{addr}  (devtools: http://{addr}/devtools)");

    // ponytail: single-thread, xử lý tuần tự từng kết nối — đủ cho Termux RAM thấp,
    // tránh toàn bộ vấn đề Send/Sync của DOM/QuickJS (Rc, không Send).
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
    // ---- DevTools frontend ----
    if req.path == "/devtools" || req.path == "/devtools/" {
        let ws = format!("ws://{}", srv.cfg.listen);
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
            &format!("ws://{}", srv.cfg.listen),
            last.map(|r| r.title.as_str()).unwrap_or("F1stmux"),
            last.map(|r| r.final_url.as_str()).unwrap_or("about:blank"),
        ));
    }

    // ---- CDP cho DevTools ----
    if req.path == "/cdp" && req.method == "POST" {
        let v: Value = serde_json::from_str(&req.body).unwrap_or(Value::Null);
        return json(cdp(srv, &v).await);
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
            "note": "không telemetry, không log mặc định. /devtools là DevTools thật."
        }));
    }

    ("404 Not Found", "text/plain; charset=utf-8", "không có endpoint này".into())
}

fn json(v: Value) -> (&'static str, &'static str, String) {
    ("200 OK", "application/json; charset=utf-8", v.to_string())
}

/// Xử lý lệnh CDP. Domain `F1stmux.*` là của ta; các domain DOM/Network còn lại
/// trả về dữ liệu tương thích để frontend thật hiểu được.
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
            return json!({"error": {"code": -32601, "message": format!("CDP method chưa hỗ trợ: {m}")}});
        }
    };
    json!({"id": v.get("id").cloned().unwrap_or(Value::Null), "result": result})
}