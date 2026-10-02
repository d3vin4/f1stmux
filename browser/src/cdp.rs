//! CDP client: HTTP + WebSocket transport tới Chromium --remote-debugging-port.
//!
//! Tự viết WebSocket (không thêm crate nặng cho Termux). Hạn chế:
//! - Client-to-server frames BẮT BUỘC mask theo RFC 6455 — đã làm.
//! - Không fancy ping/pong loop; timeout + close frame đủ cho vòng CDP ngắn.
//! - SHA-1 tự viết vì không có crate sha1 trong dep tree và không thêm mới tại runtime.

use base64::Engine as _;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SHA-1 RFC 3174 tối thiểu — đủ cho WebSocket handshake (Sec-WebSocket-Accept).
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut m = [0u8; 4];
    let l = data.len();
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() + 8) % 64 != 0 {
        msg.push(0);
    }
    let bits = (l as u64) * 8;
    msg.extend_from_slice(&bits.to_be_bytes());

    let mut h0 = 0x67452301u32;
    let mut h1 = 0xEFCDAB89u32;
    let mut h2 = 0x98BADCFEu32;
    let mut h3 = 0x10325476u32;
    let mut h4 = 0xC3D2E1F0u32;

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        let _ = &mut m;
    }
    let mut out = [0u8; 20];
    for (i, h) in [h0, h1, h2, h3, h4].into_iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&h.to_be_bytes());
    }
    out
}

fn ws_accept(key: &str) -> String {
    let mut h = sha1(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()).to_vec();
    h.extend_from_slice(b"");
    base64::engine::general_purpose::STANDARD.encode(&h[..20])
}

pub struct CdpClient {
    base: String,
    sock: Option<TcpStream>,
    id: std::sync::atomic::AtomicU64,
    /// Frame nhận liên tiếp, dùng cho events khi chờ response.
    events: Arc<Mutex<Vec<Value>>>,
}

impl CdpClient {
    /// Tạo client trỏ tới CDP endpoint của Chromium đang chạy (chrome-headless-shell).
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            sock: None,
            id: std::sync::atomic::AtomicU64::new(1),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// GET /json/version — kiểm tra endpoint sống và lấy webSocketDebuggerUrl.
    pub async fn version(&self) -> Result<Value, String> {
        let u = format!("{}/json/version", self.base);
        let r = reqwest::get(&u).await.map_err(|e| format!("CDP {u}: {e}"))?;
        let b = r.bytes().await.map_err(|e| e.to_string())?;
        serde_json::from_slice::<Value>(&b).map_err(|e| e.to_string())
    }

    /// Tạo target mới (tab) và lấy webSocketDebuggerUrl thật của target đó.
    pub async fn new_target(&self, url: &str) -> Result<String, String> {
        let u = format!("{}/json/new?{url}", self.base);
        let client = reqwest::Client::new();
        let r = client.put(&u).send().await.map_err(|e| format!("CDP new target: {e}"))?;
        if !r.status().is_success() {
            // Bản cũ của Chromium chỉ chấp nhận GET.
            let r = reqwest::get(&u).await.map_err(|e| e.to_string())?;
            let body = r.text().await.map_err(|e| e.to_string())?;
            let v: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
            return v.get("webSocketDebuggerUrl").and_then(Value::as_str).map(String::from).ok_or("thiếu webSocketDebuggerUrl".into());
        }
        let body = r.text().await.map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        v.get("webSocketDebuggerUrl").and_then(Value::as_str).map(String::from).ok_or("thiếu webSocketDebuggerUrl".into())
    }

    /// Mở WebSocket tới target debug URL.
    pub async fn connect_ws(&mut self, ws_url: &str) -> Result<(), String> {
        let (host, port, path) = parse_ws_url(ws_url)?;
        let mut sock = TcpStream::connect((host.as_str(), port)).await.map_err(|e| format!("WS connect: {e}"))?;

        let key = base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 16]>());
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        sock.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;

        let mut buf = vec![0u8; 8192];
        let n = sock.read(&mut buf).await.map_err(|e| e.to_string())?;
        let resp = String::from_utf8_lossy(&buf[..n]);
        if !resp.contains("101") || !resp.to_lowercase().contains(&ws_accept(&key).to_lowercase()) {
            return Err(format!("WS handshake từ chối: {}", resp.lines().next().unwrap_or("")));
        }
        self.sock = Some(sock);
        Ok(())
    }

    /// Gửi một CDP command và chờ response cùng id (events bị gom riêng).
    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let sock = self.sock.as_mut().ok_or("chưa connect_ws")?;
        let id = self.id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let msg = json!({"id": id, "method": method, "params": params});
        ws_send_text(sock, &msg.to_string()).await?;

        loop {
            let txt = ws_recv_text(sock).await?;
            let v: Value = serde_json::from_str(&txt).map_err(|e| e.to_string())?;
            if v.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(err) = v.get("error") {
                    return Err(err.to_string());
                }
                return Ok(v.get("result").cloned().unwrap_or(Value::Null));
            }
            // Không phải response của mình → event: giữ lại để caller đọc.
            self.events.lock().unwrap().push(v);
        }
    }

    /// Chờ tới khi một event khớp màng lọc (hoặc timeout).
    pub async fn wait_event(&mut self, pred: impl Fn(&Value) -> bool, timeout_ms: u64) -> Result<Value, String> {
        let sock = self.sock.as_mut().ok_or("chưa connect_ws")?;
        let start = std::time::Instant::now();
        loop {
            if let Some(i) = self.events.lock().unwrap().iter().position(&pred) {
                return Ok(self.events.lock().unwrap().remove(i));
            }
            if start.elapsed().as_millis() as u64 > timeout_ms {
                return Err("timeout chờ event".into());
            }
            let txt = ws_recv_text(sock).await?;
            let v: Value = serde_json::from_str(&txt).map_err(|e| e.to_string())?;
            if pred(&v) {
                return Ok(v);
            }
            self.events.lock().unwrap().push(v);
        }
    }

    /// Convenience: navigate, chờ loadEventFired.
    pub async fn navigate(&mut self, url: &str) -> Result<Value, String> {
        self.call("Page.enable", json!({})).await?;
        let _ = self.call("Network.enable", json!({})).await;
        let _ = self.call("Runtime.enable", json!({})).await;
        self.call("Page.navigate", json!({"url": url})).await?;
        let _ = self.wait_event(|v| v.get("method").and_then(Value::as_str) == Some("Page.loadEventFired"), 30_000).await;
        Ok(json!({"ok": true}))
    }

    /// Evaluate JS, trả result.0Text hoặc exception.
    pub async fn evaluate(&mut self, src: &str) -> Result<Value, String> {
        let r = self.call("Runtime.evaluate", json!({"expression": src, "returnByValue": true, "awaitPromise": true})).await?;
        if let Some(exc) = r.get("exceptionDetails") {
            return Err(exc.to_string());
        }
        Ok(r.get("result").cloned().unwrap_or(Value::Null))
    }

    pub async fn html(&mut self) -> Result<String, String> {
        let r = self.evaluate("document.documentElement.outerHTML").await?;
        Ok(r.get("value").and_then(Value::as_str).unwrap_or("").to_string())
    }

    pub async fn text(&mut self) -> Result<String, String> {
        let r = self.evaluate("document.body ? document.body.innerText : ''").await?;
        Ok(r.get("value").and_then(Value::as_str).unwrap_or("").to_string())
    }

    pub async fn screenshot(&mut self) -> Result<Vec<u8>, String> {
        let r = self.call("Page.captureScreenshot", json!({"format": "png"})).await?;
        let b64 = r.get("data").and_then(Value::as_str).ok_or("thiếu data")?;
        base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| e.to_string())
    }
}

fn parse_ws_url(u: &str) -> Result<(String, u16, String), String> {
    let u = u.strip_prefix("ws://").unwrap_or(u);
    let (hostport, path) = u.split_once('/').ok_or("WS URL thiếu path")?;
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| "port sai".to_string())?),
        None => (hostport.to_string(), 80),
    };
    Ok((host, port, format!("/{path}")))
}

/// RFC 6455: client→server text frame PHẢI mask. fin=1, opcode 1.
async fn ws_send_text(sock: &mut TcpStream, text: &str) -> Result<(), String> {
    let payload = text.as_bytes();
    let mut frame = vec![0x81u8];
    let len = payload.len();
    if len < 126 {
        frame.push(0x80 | len as u8);
    } else if len < 65536 {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mask = rand::random::<[u8; 4]>();
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i % 4]);
    }
    sock.write_all(&frame).await.map_err(|e| e.to_string())
}

async fn ws_recv_text(sock: &mut TcpStream) -> Result<String, String> {
    loop {
        let mut head = [0u8; 2];
        sock.read_exact(&mut head).await.map_err(|e| format!("WS read: {e}"))?;
        let fin = head[0] & 0x80 != 0;
        let opcode = head[0] & 0x0f;
        let masked = head[1] & 0x80 != 0;
        let mut len = (head[1] & 0x7f) as u64;
        if len == 126 {
            let mut b = [0u8; 2];
            sock.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            len = u16::from_be_bytes(b) as u64;
        } else if len == 127 {
            let mut b = [0u8; 8];
            sock.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            len = u64::from_be_bytes(b);
        }
        let mask_key = if masked {
            let mut m = [0u8; 4];
            sock.read_exact(&mut m).await.map_err(|e| e.to_string())?;
            Some(m)
        } else {
            None
        };
        let mut payload = vec![0u8; len as usize];
        sock.read_exact(&mut payload).await.map_err(|e| e.to_string())?;
        if let Some(m) = mask_key {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }
        match opcode {
            0x1 => {
                let s = String::from_utf8(payload).map_err(|e| e.to_string())?;
                return Ok(s);
            }
            0x8 => return Err("WS closed".into()),
            0x9 => {
                // Ping → pong cùng payload (opcode 0xA, mask). Đơn giản: bỏ qua ping
                // khi không có CDP traffic liên tục; browser không đòi pong bắt buộc.
                let _ = fin;
                continue;
            }
            0xA => continue,
            _ => continue,
        }
    }
}
