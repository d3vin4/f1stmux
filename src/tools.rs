//! Tool surface cho AI. Mọi tool là một hàm; dispatch là một `match`.

use crate::config::Config;
use crate::session::{Session, WaitFor};
use crate::stealth;
use serde_json::{json, Value};
use std::sync::Arc;

fn s(p: &Value, k: &str) -> String {
    p.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Tạo session mới, hoặc lấy session đã có.
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

/// Lookup session đã tồn tại — KHÔNG tự tạo. Typo ID phải báo lỗi, không lặng
/// lẽ trỏ sang session rỗng (trước đây get_sess tự tạo khiến session_close báo
/// thành công giả và thao tác nhầm session).
fn need_sess(srv: &Arc<crate::rpc::Server>, p: &Value) -> Result<String, String> {
    let id = s(p, "session");
    if id.is_empty() {
        return get_sess(srv, p);
    }
    let m = srv.sessions.lock().unwrap();
    if m.contains_key(&id) {
        Ok(id)
    } else {
        Err(format!("session không tồn tại: `{id}` (dùng session_new để tạo)"))
    }
}

pub async fn tool(srv: &Arc<crate::rpc::Server>, name: &str, p: &Value) -> Result<Value, String> {
    match name {
        // ---- điều phối ----
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

        // ---- điều hướng ----
        "navigate" => {
            let id = need_sess(srv, p)?;
            let url = s(p, "url");
            if url.is_empty() { return Err("thiếu `url`".into()); }
            let run_js = p.get("js").and_then(Value::as_bool).unwrap_or(true);
            let wait = WaitFor {
                quiet_ms: p.get("quiet_ms").and_then(Value::as_u64).unwrap_or(250),
                budget_ms: p.get("budget_ms").and_then(Value::as_u64).unwrap_or(10_000),
            };
            let mut m = srv.sessions.lock().unwrap();
            let sess = m.get_mut(&id).ok_or("session không tồn tại")?;
            let cfg = srv.config();
            let mut r = crate::session::navigate(&url, &cfg, sess, &wait, run_js).await?;
            drop(m);
            // on_challenge=portal: gặp challenge thì tạo ticket human-solve.
            // Mặc định (ignore) chỉ gắn flag captcha, không làm gì thêm.
            if crate::challenge::OnChallenge::from_str(&s(p, "on_challenge")) == crate::challenge::OnChallenge::Portal
                && let Some(kind) = r.captcha.clone()
            {
                let m = srv.sessions.lock().unwrap();
                if let Some(sess) = m.get(&id)
                    && let Some(dom) = sess.dom.as_ref()
                    && let Some(spec) = crate::challenge::auto_extract(&dom.borrow(), &r.final_url)
                {
                    let listen = srv.config().listen;
                    r.challenge = Some(crate::challenge::create_ticket(
                        &srv.challenges, &listen, &id, &r.final_url, &kind, spec,
                    ));
                }
            }
            Ok(serde_json::to_value(&r).unwrap_or(Value::Null))
        }
        "extract_text" => {
            let id = need_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session không tồn tại")?;
            Ok(json!({ "text": sess.dom.as_ref().map(|d| d.borrow().text_content(0)).unwrap_or_default() }))
        }
        "snapshot_dom" => {
            let id = need_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session không tồn tại")?;
            Ok(json!({ "html": sess.dom.as_ref().map(|d| d.borrow().inner_html(0)).unwrap_or_default() }))
        }
        "query" => {
            let id = need_sess(srv, p)?;
            let sel = s(p, "selector");
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session không tồn tại")?;
            let d = sess.dom.as_ref().ok_or("chưa nạp trang")?;
            let g = d.borrow();
            let ids = g.query(&sel, 0).map_err(|e| format!("selector không hợp lệ: {e:?}"))?;
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
            if src.is_empty() { return Err("thiếu `script`".into()); }
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session không tồn tại")?;
            crate::session::eval(sess, &src).map_err(|e| format!("JS: {e}"))
        }

        // ---- mạng ----
        "network_log" => {
            let id = need_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session không tồn tại")?;
            Ok(json!({ "count": sess.net.len(), "entries": sess.net }))
        }
        "har_export" => {
            // Mặc định xuất đúng session đang gọi — không trộn log các session khác.
            // Truyền `"all": true` để xuất toàn bộ (admin/debug).
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
            // Mặc định kiểm tra như XHR/Script (tài nguyên phụ) — Document luôn allow
            // để trình duyệt không tự chặn trang người dùng yêu cầu.
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
                // Đặt thật: validate tên, đổi profile daemon dùng cho mọi navigation sau.
                // (Trước đây chỉ báo tên mà không đổi gì — client tưởng đã đổi.)
                if stealth::profile(&name).is_none() {
                    return Err(format!("không có profile `{name}` (có: {})", stealth::names().join(", ")));
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
            if id.is_empty() { return Err("thiếu `id`".into()); }
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
                None => Err(format!("không có plugin `{id}`")),
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
                None => return Err(format!("session không tồn tại: `{sid}`")),
            };
            let dom = sess.dom.as_ref().ok_or("session chưa nạp trang nào")?.clone();
            let kind = sess.last.as_ref().and_then(|r| r.captcha.clone()).unwrap_or("manual".into());
            let page_url = sess.last.as_ref().map(|r| r.final_url.clone()).unwrap_or_default();
            let spec = match p.get("post_url").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                Some(u) => crate::challenge::ReplaySpec {
                    post_url: u.into(),
                    fields: vec![],
                    token_field: p.get("token_field").and_then(Value::as_str).unwrap_or("g-recaptcha-response").into(),
                },
                None => crate::challenge::auto_extract(&dom.borrow(), &page_url)
                    .ok_or("không trích được form replay từ DOM (dùng post_url thủ công)")?,
            };
            drop(m);
            let listen = srv.config().listen;
            let t = crate::challenge::create_ticket(&srv.challenges, &listen, &sid, &page_url, &kind, spec);
            Ok(json!({"id": t.id, "portal_url": t.portal_url, "kind": t.kind}))
        }
        "challenge_result" => {
            let id = s(p, "id");
            match crate::challenge::lookup(&srv.challenges, &id) {
                Some(t) => Ok(json!({"id": t.id, "status": t.status, "url": t.url, "note": t.note})),
                None => Err(format!("ticket không tồn tại: `{id}`")),
            }
        }

        // ---- bench ----
        "bench" => Ok(json!({ "note": "dùng CLI: f1stmux bench --compare <path>" })),

        "version" => Ok(json!({
            "name": "f1stmux",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": "2024-11-05",
            "api": crate::plugin::CURRENT_API_VERSION,
        })),

        _ => Err(format!("tool chưa có: {name}")),
    }
}

/// Liệt kê tool cho MCP / `f1stmux tools`.
pub fn catalog() -> Value {
    json!([
        {"name":"navigate","desc":"Mở URL và trả về text + console + thời gian"},
        {"name":"extract_text","desc":"Trích text từ DOM đang nạp"},
        {"name":"snapshot_dom","desc":"innerHTML của trang"},
        {"name":"query","desc":"querySelector trên DOM của ta"},
        {"name":"eval_js","desc":"Chạy JS trong realm của trang"},
        {"name":"network_log","desc":"Danh sách request đã đi qua"},
        {"name":"har_export","desc":"Xuất HAR 1.2"},
        {"name":"blocklist_test","desc":"Xem một URL có bị chặn không"},
        {"name":"stealth_profile","desc":"Xem/đặt profile giả danh tính"},
        {"name":"session_new","desc":"Tạo session mới"},
        {"name":"session_info","desc":"Thông tin session"},
        {"name":"session_close","desc":"Xoá session và mọi dấu vết trong RAM"},
        {"name":"kill_switch","desc":"Tắt mọi hook plugin ngay lập tức"},
        {"name":"plugin_list","desc":"Liệt kê plugin đã cài"},
        {"name":"plugin_install","desc":"Cài plugin từ thư mục"},
        {"name":"plugin_info","desc":"Chi tiết một plugin"},
        {"name":"bench","desc":"Đo hiệu năng"},
        {"name":"version","desc":"Phiên bản f1stmux + protocol"},
        {"name":"challenge_create","desc":"Tạo ticket human-solve cho challenge của session"},
        {"name":"challenge_result","desc":"Trạng thái ticket (poll sau khi human giải)"}
    ])
}

fn str_prop(d: &str) -> Value { json!({"type":"string","description":d}) }
fn bool_prop(d: &str) -> Value { json!({"type":"boolean","description":d}) }
fn num_prop(d: &str) -> Value { json!({"type":"number","description":d}) }

/// Tool theo định dạng MCP `tools/list`, kèm inputSchema để AI client validate.
pub fn mcp_tools() -> Value {
    let opt_session = ("session", str_prop("ID session, bỏ trống để tạo mới"));
    let defs: Vec<(&str, &str, Vec<(&str, Value)>, Vec<&str>)> = vec![
        ("navigate", "Mở URL, trả về text/console/network/captcha", vec![
            ("url", str_prop("URL cần mở")), ("session", str_prop("ID session")),
            ("js", bool_prop("Chạy JS của trang (mặc định true)")),
            ("quiet_ms", num_prop("Ngưỡng network-idle")), ("budget_ms", num_prop("Ngân sách ms")),
            ("on_challenge", str_prop("\"portal\" = tự tạo ticket human-solve khi gặp challenge")),
        ], vec!["url"]),
        ("extract_text", "Trích text từ trang đang nạp", vec![opt_session.clone()], vec![]),
        ("snapshot_dom", "innerHTML của trang đang nạp", vec![opt_session.clone()], vec![]),
        ("query", "querySelector trên DOM (tag, #id, .class, [attr])", vec![
            ("selector", str_prop("CSS selector đơn giản")), ("session", str_prop("ID session")), ("all", bool_prop("Trả về tất cả, mặc định node đầu")),
        ], vec!["selector"]),
        ("eval_js", "Chạy JS expression trong realm của trang, trả về JSON", vec![
            ("script", str_prop("JS expression")), ("session", str_prop("ID session")),
        ], vec!["script"]),
        ("network_log", "Danh sách request đã đi qua session", vec![opt_session.clone()], vec![]),
        ("har_export", "Xuất HAR 1.2 của mọi session", vec![], vec![]),
        ("blocklist_test", "Xem URL có bị chặn không (mặc định kiểm như XHR)", vec![
            ("url", str_prop("URL cần kiểm")), ("kind", str_prop("document|script|xhr|image")),
        ], vec!["url"]),
        ("stealth_profile", "Xem profile giả danh tính đang dùng", vec![("name", str_prop("Để trống để xem"))], vec![]),
        ("session_new", "Tạo session mới (RAM-only)", vec![], vec![]),
        ("session_info", "Thông tin session", vec![opt_session.clone()], vec![]),
        ("session_close", "Xoá session và mọi dấu vết trong RAM", vec![opt_session.clone()], vec![]),
        ("kill_switch", "Tắt mọi hook plugin ngay lập tức", vec![("on", bool_prop("true=tắt hook"))], vec![]),
        ("plugin_list", "Liệt kê plugin đã cài", vec![], vec![]),
        ("plugin_install", "Cài plugin từ thư mục", vec![("path", str_prop("Đường dẫn thư mục plugin"))], vec!["path"]),
        ("plugin_info", "Chi tiết một plugin", vec![("id", str_prop("ID plugin"))], vec!["id"]),
        ("bench", "Ghi chú: dùng CLI `f1stmux bench`", vec![], vec![]),
        ("version", "Phiên bản f1stmux + protocol", vec![], vec![]),
        ("challenge_create", "Tạo ticket human-solve (trả portal_url cho human)", vec![
            ("session", str_prop("ID session đã navigate tới trang challenge")),
            ("post_url", str_prop("Ghi đè URL replay (mặc định auto-extract từ form)")),
            ("token_field", str_prop("Tên field token (mặc định theo loại challenge)")),
        ], vec!["session"]),
        ("challenge_result", "Poll trạng thái ticket", vec![
            ("id", str_prop("ID ticket")),
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