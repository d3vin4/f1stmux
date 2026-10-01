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

pub async fn tool(srv: &Arc<crate::rpc::Server>, name: &str, p: &Value) -> Result<Value, String> {
    match name {
        // ---- điều phối ----
        "session_new" | "session.list" => {
            let id = get_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            Ok(json!(m.get(&id).map(|x| x.snapshot()).unwrap_or(Value::Null)))
        }
        "session_info" => {
            let id = get_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            Ok(m.get(&id).map(|x| x.snapshot()).unwrap_or(Value::Null))
        }
        "session_close" => {
            let id = get_sess(srv, p)?;
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
            let id = get_sess(srv, p)?;
            let url = s(p, "url");
            if url.is_empty() { return Err("thiếu `url`".into()); }
            let run_js = p.get("js").and_then(Value::as_bool).unwrap_or(true);
            let wait = WaitFor {
                quiet_ms: p.get("quiet_ms").and_then(Value::as_u64).unwrap_or(250),
                budget_ms: p.get("budget_ms").and_then(Value::as_u64).unwrap_or(10_000),
            };
            let mut m = srv.sessions.lock().unwrap();
            let sess = m.get_mut(&id).ok_or("session không tồn tại")?;
            let r = crate::session::navigate(&url, &srv.cfg, sess, &wait, run_js).await?;
            Ok(serde_json::to_value(&r).unwrap_or(Value::Null))
        }
        "extract_text" => {
            let id = get_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session không tồn tại")?;
            Ok(json!({ "text": sess.dom.as_ref().map(|d| d.borrow().text_content(0)).unwrap_or_default() }))
        }
        "snapshot_dom" => {
            let id = get_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session không tồn tại")?;
            Ok(json!({ "html": sess.dom.as_ref().map(|d| d.borrow().inner_html(0)).unwrap_or_default() }))
        }
        "query" => {
            let id = get_sess(srv, p)?;
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
            let id = get_sess(srv, p)?;
            let src = s(p, "script");
            if src.is_empty() { return Err("thiếu `script`".into()); }
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session không tồn tại")?;
            crate::session::eval(sess, &src).map_err(|e| format!("JS: {e}"))
        }

        // ---- mạng ----
        "network_log" => {
            let id = get_sess(srv, p)?;
            let m = srv.sessions.lock().unwrap();
            let sess = m.get(&id).ok_or("session không tồn tại")?;
            Ok(json!({ "count": sess.net.len(), "entries": sess.net }))
        }
        "har_export" => {
            let m = srv.sessions.lock().unwrap();
            let es: Vec<_> = m.values().flat_map(|x| x.net.clone()).collect();
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
            if !name.is_empty() { return Ok(json!({ "active": name })); }
            Ok(json!({ "active": srv.cfg.profile, "available": stealth::names() }))
        }

        // ---- plugin ----
        "plugin_list" => {
            let r = crate::plugin::Registry::new(crate::plugin::default_root());
            Ok(json!({ "plugins": r.list().iter().map(|p| p.manifest.id.clone()).collect::<Vec<_>>() }))
        }
        "plugin_install" => {
            let dir = s(p, "path");
            let root = crate::plugin::default_root();
            Ok(json!({ "installed": crate::plugin::install_from_dir(std::path::Path::new(&dir), &root)? }))
        }

        // ---- bench ----
        "bench" => Ok(json!({ "note": "dùng CLI: f1stmux bench --compare <path>" })),

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
        {"name":"bench","desc":"Đo hiệu năng"}
    ])
}

pub fn cfg_of(srv: &Arc<crate::rpc::Server>) -> &Config { &srv.cfg }