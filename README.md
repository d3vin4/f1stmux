# F1stmux — headless browser cho AI, chạy trên Termux

Một binary duy nhất (`f1stmux`), vừa làm CLI vừa làm daemon. Không GUI,
không Chromium, không V8: Rust + html5ever + QuickJS + rustls.

## Số đo thật trên Termux aarch64 (không ước lượng)

| Hạng mục | Số |
|---|---|
| Binary (strip, release) | 4.1 MB |
| RSS daemon sau 3 navigation | 6.7 MB |
| `GET example.com` | 200, ~500–700 ms |
| `GET news.ycombinator.com` | 200, text 4207 ký tự, 0 lỗi JS |
| Profile | chrome / edge / brave |

## Chạy

```sh
# Một URL ra text
f1stmux get https://example.com/

# DOM, JSON đầy đủ, chạy JS, REPL DevTools terminal
f1stmux get URL --dom
f1stmux eval URL 'document.querySelector("p").textContent'
f1stmux devtools URL

# Daemon: JSON-RPC + DevTools web
f1stmux serve
# → http://127.0.0.1:7070/devtools  (mở bằng Chrome/Edge trên điện thoại:
#    Elements / Text / Console / Network / tải HAR / tải DOM)
# → POST http://127.0.0.1:7070/rpc   (JSON-RPC 2.0, 17 tools: xem `f1stmux tools`)
# → POST http://127.0.0.1:7070/cdp   (CDP subset: DOM.*, Network.*, F1stmux.*)

# Đo hiệu năng
f1stmux bench
```

## Riêng tư (mặc định, không đổi được trừ khi chỉ định rõ)

- Không telemetry, không phone-home, không tự cập nhật, không log ra đĩa.
- Session RAM-only: thoát là mất cookie/storage/cache.
- TLS roots bundle trong binary (`webpki-roots`), không đọc kho CA hệ thống
  (vừa riêng tư hơn, vừa là cách duy nhất không panic trên Android).
- DNS qua DoH, fail-closed (DoH hỏng thì request chết, không fallback về DNS hệ thống).
- Chặn WebRTC/StUN/TURN ở tầng scheme. Ngoại lệ đã biết: hostname của chính
  endpoint DoH phân giải qua DNS hệ thống một lần lúc khởi động; SNI vẫn lộ
  hostname với kẻ nghe mạng (DoH giấu DNS, không giấu SNI).

## Plugin: cài thêm bất cứ thứ gì

```sh
f1stmux plugin install <thư-mục|git|tarball>   # manifest f1stmux-plugin.json
```

Ba loại, tất cả là subprocess hoặc sandbox — không bao giờ link native:

| Loại | Chạy | Dùng khi |
|---|---|---|
| `js` | realm QuickJS trong daemon | hook nhanh, chặn request |
| `proc` | tiến trình con, stdio JSON-lines | Python/Rust/Go/shell, mọi ngôn ngữ |
| `wasm` | module WASM | cô lập chặt, deterministic |

Hook: `onRequest onResponse onDOMReady onToolCall onPageScript
onSessionCreate onSessionEnd`. Permission allowlist + `/kill-switch`.

## Giới hạn nói thẳng

- Không layout engine → không screenshot pixel, nội dung lazy-mount theo
  viewport không xuất hiện. `screenshot_dom` chỉ dựng khung từ a11y.
- SPA JS cực nặng / site chống bot đời mới: có `--engine=chromium` ở v2,
  core mặc định vẫn nhẹ.
- `vault.rs` dùng crypto tự viết (XOR-stream + MAC) — KHÔNG đạt chuẩn sản phẩm.
  Thay bằng `chacha20poly1305` + `argon2` khi cần thật (đã đánh dấu `ponytail:`).
- WASM plugin host chưa build trên Android (`wasmtime` chưa đo) — dùng `js`/`proc`.
- JA4 đầy đủ chưa đo; hiện cam kết JA3 + header order + JS env.
