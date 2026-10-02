//! MCP adapter: JSON-RPC qua stdio cho AI client (opencode, Claude Code...).
//!
//! Thin layer duy nhất: đọc từng dòng JSON từ stdin, dispatch sang
//! [`crate::tools::tool`] trên Server in-process, ghi response ra stdout.
//! Không HTTP, không daemon riêng — `f1stmux mcp` là một MCP server đầy đủ.
//!
//! Hỗ trợ: initialize, notifications/*, tools/list, tools/call. Không hỗ trợ
//! batch (MCP không dùng).

use crate::config::Config;
use crate::rpc::Server;
use serde_json::{json, Value};
use std::sync::Arc;

const PROTOCOL_VERSION: &str = "2024-11-05";

pub async fn run(cfg: Config) -> Result<(), String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let srv = Arc::new(Server::new(cfg));
    let stdin = tokio::io::stdin();
    let mut lines = tokio::io::BufReader::new(stdin).lines();
    let mut out = tokio::io::stdout();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue, // dòng rác: bỏ qua, không chết cả server
        };
        // Notification (không id): không trả lời.
        if v.get("id").is_none() || v.get("id") == Some(&Value::Null) {
            continue;
        }
        let resp = dispatch(&srv, &v).await;
        let mut s = resp.to_string();
        s.push('\n');
        if out.write_all(s.as_bytes()).await.is_err() {
            break; // stdout đóng = client đi rồi, thoát sạch
        }
        let _ = out.flush().await;
    }
    Ok(())
}

async fn dispatch(srv: &Arc<Server>, v: &Value) -> Value {
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let method = v.get("method").and_then(Value::as_str).unwrap_or("");
    let params = v.get("params").cloned().unwrap_or(json!({}));
    let ok = |result: Value| json!({"jsonrpc": "2.0", "id": id, "result": result});
    let err = |code: i64, msg: String| json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}});

    match method {
        "initialize" => ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "f1stmux", "version": env!("CARGO_PKG_VERSION")},
        })),
        "tools/list" => ok(json!({"tools": crate::tools::mcp_tools()})),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            if name.is_empty() {
                return err(-32602, "thiếu `name`".into());
            }
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match crate::tools::tool(srv, name, &args).await {
                // Chuỗi JSON đi thẳng ra text, không stringify thêm lần nữa.
                Ok(Value::String(s)) => ok(json!({"content": [{"type": "text", "text": s}]})),
                Ok(r) => ok(json!({"content": [{"type": "text", "text": r.to_string()}]})),
                Err(e) => ok(json!({"content": [{"type": "text", "text": e}], "isError": true})),
            }
        }
        _ => err(-32601, format!("method chưa hỗ trợ: {method}")),
    }
}
