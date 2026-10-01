# F1stmux — Headless Browser cho AI, thiết kế Termux

Ngày: 2026-10-01 · Trạng thái: **draft, chờ review** · Đối chiếu: Lightpanda

## 0. Phase 0 — kết quả đo thật trên máy đích

Đã build và chạy trên chính máy này (`aarch64-linux-android`, rustc 1.98.1, LLVM 21.1.8). Đây là số thật, không phải ước lượng.

| Hạng mục | Kết quả |
|---|---|
| `libclang` | ✅ Có sẵn ở `$PREFIX/lib/libclang.so` → `rquickjs` build được |
| `rquickjs` 0.14.0 + feature `bindgen` | ✅ Build thành công. QuickJS eval `Promise`/`Proxy`/`Symbol`/`BigInt` đều hoạt động |
| `html5ever` qua `scraper` 0.27 | ✅ Build + parse, `h1` trả về đúng text |
| `rustls` 0.23.45 + `ring` 0.17.14 | ✅ Build được trên Android (không cần NDK) |
| HTTP thật | ✅ `GET https://example.com` → 200, 713 bytes, nội dung đúng, 497 ms |
| HTTP/2 | ✅ `POST https://nghttp2.org/httpbin/post` → 200 |
| SOCKS5 | ✅ Client chấp nhận cấu hình `socks5://` |
| RSS đo được | **6.7 MB** với HTTP stack + roots + 1 realm QuickJS |
| Binary (spike) | 3.3 MB, chưa `strip` |

### 0.1 Ba cái bẫy phải ghi vào thiết kế

Ba lỗi này đều làm build hoặc chạy hỏng, và đều không đoán trước được:

1. **`rustls` mặc định PANIC trên Android.** `rustls-platform-verifier` cần JNI init: `Expect rustls-platform-verifier to be initialized`. Giải pháp: **không dùng system CA store**, dựng `RootCertStore` từ `webpki-roots` (121 root) và `install_default()` thủ công cho `ring`. Với browser riêng tư, cách này **đúng cả về mặt triết lý** — không đọc kho CA của hệ điều hành là một dấu vết.

2. **`aws-lc-rs` cũng có mặt trong cây phụ thuộc.** Nó build được, nhưng kéo theo assembler/C mà ta không dùng. Cấu hình: `rustls` với `default-features = false` + feature `ring`, cài provider bằng tay. Đây là cấu hình bắt buộc trong `Cargo.toml`.

3. **Tên feature của `reqwest` 0.13 đã đổi.** `rustls-tls` không còn tồn tại (tên là `rustls`); muốn tự loại provider thì dùng `rustls-no-provider` và cấu hình TLS thủ công. Ghi vào spec để không ai phải mất 30 phút tìm lại.

### 0.2 Điều này không nói

Số 6.7 MB là RSS của một spike chỉ có HTTP + 1 realm. Daemon thật còn DOM, a11y, plugin host, scheduler. **Mục tiêu idle ≤ 30 MB vẫn là mục tiêu, chưa phải số đo** — Phase 1 sẽ đo lại khi có phần lõi.

---

## 1. Mục tiêu và ràng buộc

F1stmux là headless browser chạy **chỉ trong terminal**, tối ưu cho **Termux trên Android aarch64**, dành cho AI điều khiển.

**Ràng buộc cứng của môi trường đích** (đo trên máy build):

| Hạng mục | Giá trị | Hệ quả thiết kế |
|---|---|---|
| RAM tổng | 3.6 GB (2.8 GB đã dùng) | Mục tiêu daemon idle < 30 MB. Chromium không khả thi. |
| CPU | 8 core aarch64 | Hướng đơn luồng + async, tránh process-per-tab |
| Toolchain | `cargo 1.98`, `node 26`, `python 3.14`, không có Go | Rust là ngôn ngữ chính. Go plugin phải tự cài. |
| Network | Android, không root | DoH bắt buộc để chống DNS leak. |

**Chỉ số thành công** (đo bằng `f1stmux bench`):

- RAM idle daemon ≤ 30 MB; mỗi tab JS ≤ 12 MB
- Cold start < 100 ms
- Navigate+extract, HTML tĩnh: < 300 ms
- Navigate+extract, SPA có JS: < 2 s (chấp nhận hạn chế, xem §7)
- Binary ≤ 15 MB (sau `strip`)
- Không một byte nào ra ngoài ngoài các request do người dùng ra lệnh

## 2. Quyết định kiến trúc

### 2.1 Ngôn ngữ: Rust cho toàn bộ core, C/C++ chỉ khi có bằng chứng

Bạn chọn "C++ + Rust" và "nhanh mạnh tốt nhất nhất". Sau khi cân, kết luận là **Rust cho 100% core**:

- **QuickJS là C, không phải C++.** Nên "C++" thực tế chỉ là tầng FFI tới QuickJS — không phải một ngôn ngữ thứ hai để bảo trì.
- Thêm C++ chỉ để cạnh tranh với Rust trong cùng một việc là tự tạo rào cản build trên nền tảng mà ta còn chưa chắc build được.
- Đường nâng cấp C/C++ vẫn mở: nếu `bench` cho thấy hot path nào (HTML tokenize, buffer xử lý) bị bottleneck, viết một `.cpp` đó, gọi qua `cc` crate, đo lại. **Có bằng chứng mới thêm, không đoán trước.**

Rủi ro của quyết định này: nếu Rust thua ở một hot path, ta phải làm thêm một vòng tối ưu. Chấp nhận, vì vòng đó nhỏ và có đo đạc.

### 2.2 Không có layout engine — đây là quyết định giới hạn, không phải sự lười

Ta **không** dựng pixel. Không có box layout, không rasterize, không screenshot ảnh thật.

Cái ta *có*:

- DOM tree đầy đủ từ HTML5 parser
- Accessibility tree tự dựng (role/name/value)
- `text` trích từ DOM
- Network log đầy đủ, HAR export
- Header order, TLS fingerprint, JS environment

**Hệ quả trung thực:** nội dung mà chỉ hiện sau khi layout tính toán (lazy-mount theo viewport, virtual list, `content-visibility`) sẽ không xuất hiện. Ta không giả vờ không có giới hạn này.

### 2.3 Chống phát hiện: mức đầy đủ, theo 4 lớp

Mỗi lớp chống một loại tín hiệu khác nhau. Bỏ lớp nào là mất lớp đó.

| Lớp | Chống gì | Cơ chế |
|---|---|---|
| **1. Profile danh tính** | Header/UA/Client-Hints không khớp nhau | Bộ profile đóng bóng: `chrome`, `edge`, `brave`, `firefox`, `safari`. Mỗi profile gắn UA + header order + client hints + viewport + timezone + locale + platform, **nhất quán nội bộ**. Tín hiện tệ nhất là profile lộ chỗ trống. |
| **2. TLS** | JA3/JA4 lệch so với browser thật | TLS stack cấu hình được ClientHello: cipher order, extension order (sinh JA4), ALPN, key share, GREASE, signature algos. `--profile` điều khiển, không phải ngẫu nhiên. |
| **3. JS environment** | Canvas/WebGL/Audio/熵 bất thường | Noise *có kiểm soát* trong QuickJS: canvas hash ổn định trong 1 session, khác giữa 2 session. `navigator.hardwareConcurrency`, `deviceMemory`, timezone, platform, `screen` khớp profile. |
| **4. Leak** | DNS leak, WebRTC leak, IP leak | DoH bắt buộc (không có đường tắt), chặn WebRTC peer API, mọi traffic bắt buộc qua proxy/SOCKS5/Tor, chặn request ngoài allowlist. Kill switch tắt tất cả hook khi nghi vấn. |

**Quy tắc bất di bất dịch của lớp 3:** fingerprint phải **ổn định trong suốt session** và **thay đổi giữa các session**. Nhiễu mỗi lần gọi `canvas.toDataURL()` sẽ tệ hơn là không nhiễu — đó là dấu vết của bot.

## 3. Kiến trúc

```
┌─ f1stmux (CLI, Rust) ──┐   ┌─ f1stmux mcp (stdio) ─┐
│  navigate, extract,    │   │  bridge sang HTTP     │
│  bench, plugin, vault  │   │  (chạy ở bất kỳ đâu)  │
└──────────┬─────────────┘   └──────────┬─────────────┘
           │ HTTP/WS JSON-RPC 2.0       │
           └────────────┬───────────────┘
                        ▼
        ┌─────────── f1stmuxd (daemon Rust) ───────────┐
        │                                              │
        │  session mgr ── ephemeral, id-keyed, RAM-only │
        │  tab pool   ── N tab, tách tiến trình khi nặng  │
        │  scheduler  ── queue, cron, retry/backoff      │
        │                                              │
        │  ┌─ pipeline (mỗi navigation) ──────────────┐ │
        │  │ fetch → parse → env → DOM → a11y → text   │ │
        │  └───────────────────────────────────────────┘ │
        │                                              │
        │  ┌─ thư viện ─────────────────────────────┐   │
        │  │ tls   : TLS stack tùy chỉnh (JA3/JA4)   │   │
        │  │ net   : HTTP/2, DoH, proxy chain, block  │   │
        │  │ stealth: profile registry + JS noise     │   │
        │  │ dom   : html5ever → DOM → a11y           │   │
        │  │ js    : QuickJS (nhiều realm, cô lập)    │   │
        │  │ vault : profile mã hoá, key mở trong RAM │   │
        │  │ plugin: host js | wasm | proc            │   │
        │  └─────────────────────────────────────────┘   │
        └──────────────────────────────────────────────┘
```

### 3.1 Đường đi của một lần navigate

```
tool call "navigate"
  → session/tab lookup
  → build headers từ profile (order cố định)
  → TLS handshake với cipher/extension order của profile
  → (nếu có) DNS qua DoH, qua proxy chain
  → GET, theo redirect có kiểm soát, gom cookie vào jar của session
  → [plugin hook: onRequest / onResponse — có thể block/sửa/thêm]
  → HTML5 parse → DOM
  → tạo QuickJS realm, cài DOM bridge + global object khớp profile
  → chạy script tự nhiên, theo dõi mutation + network
  → điều kiện hoàn tất (§7) hoặc hết budget → dừng
  → [plugin hook: onDOMReady]
  → dựng a11y tree, trích text
  → session tự hủy nếu ephemeral
```

Điểm quan trọng: **DOM bridge phải là duy nhất**. Một cây DOM trong Rust, phơi sang JS qua bridge. Không có hai nguồn sự thật — nếu có, mọi bug DOM sẽ là bug khó tìm nhất trong hệ thống.

### 3.2 Cô lập bộ nhớ

Máy có 3.6 GB. Một OOM giết cả phiên làm việc.

- `--max-tabs`, `--max-ram` là giới hạn cứng, không phải gợi ý.
- Realm QuickJS nặng hoặc tab nghi ngờ treo → tách sang tiến trình con, để được kill độc lập.
- Mỗi session mặc định **RAM-only**: cookie, storage, cache sống trong RAM và biến mất khi process chết. Ghi xuống đĩa là tuỳ chọn tường minh (`--persist`), phải có mật khẩu.

## 4. Hệ thống plugin

Mục tiêu: **cài thêm bất cứ thứ gì** — tool, inspector, parser, AI agent, proxy, storage backend, hook, scheduler, adapter OCR — mà không phải sửa core.

### 4.1 Manifest

```json
{
  "id": "acme.blocker",
  "name": "Acme Blocker",
  "version": "1.0.0",
  "kind": "js",
  "entry": "main.js",
  "api": 1,
  "permissions": ["net.intercept", "dom.read", "page.script"],
  "hooks": { "onRequest": 1, "onResponse": 1, "onDOMReady": 1, "onToolCall": 1 }
}
```

`api` là version của host API. Core từ chối plugin khai báo `api` cao hơn nó biết.

### 4.2 Ba loại plugin

| Loại | Chạy | Dùng khi | Chi phí |
|---|---|---|---|
| `js` | Trong realm QuickJS của daemon | Logic nhanh, cần gọi hook, cần chặn request | ~0, hot path |
| `proc` | Tiến trình con, stdio JSON-lines hoặc HTTP localhost | Python (giàu thư viện), Rust/Go/C (nhanh), shell, bọc tool có sẵn | +50–100 ms/call |
| `wasm` | Module WASM trong host | Logic deterministic, cần cô lập chặt hơn `js` | nhỏ |

Cả ba đều là **quy trình con hoặc sandbox**, không phải thư viện native gắn vào. Đây là quyết định cố ý: gắn native nghĩa là phải khớp ABI, đổi phiên bản là vỡ, và một plugin lỗi là sập daemon. `proc` chấp nhận độ trễ và đổi lại **mọi ngôn ngữ đều chạy được**.

### 4.3 Cài đặt và vòng đời

```
f1stmux plugin install <git-url | thư mục | tarball | tên-đăng-ký>
    → tải → đọc manifest → kiểm tra schema + permission → đặt vào ~/.f1stmux/plugins/<id>/
    → daemon hot-load, KHÔNG cần restart
f1stmux plugin list | info <id> | enable | disable | uninstall | grant <perm> | revoke <perm>
```

Registry: thư mục local (`~/.f1stmux/plugins/`) và registry từ xa (opt-in, không mặc định).

### 4.4 Sandbox

- Permission allowlist trên manifest; plugin không khai báo permission thì không có.
- `net.intercept` bị giới hạn theo host/scheme được cấp.
- `js` bị giới hạn thời gian thực thi và quota bộ nhớ.
- `proc` chạy không quyền, không môi trường ngoài, cwd riêng.
- `/kill-switch` tắt mọi hook mà không cần uninstall — dành cho lúc nghi ngờ bị theo dõi.

### 4.5 Điểm can thiệp

| Hook | Plugin được làm gì |
|---|---|
| `onRequest` | Sửa header, chặn, thêm request, đổi URL, ghi HAR |
| `onResponse` | Sửa body/header, chặn, phân tích |
| `onDOMReady` | Đọc DOM, chạy script, trích text |
| `onToolCall` | Thêm tool mới cho AI, chặn tool, ghi log |
| `onPageScript` | Inject script vào realm trước khi page script chạy |
| `onSessionCreate` / `onSessionEnd` | Theo dõi vòng đời session, tự dọn |

Bằng `onToolCall`, plugin có thể **đăng ký tool mới** — đây là đường mở rộng chính cho agent/parser/inspector tuỳ chỉnh mà không đụng core.

## 5. Giao diện

| Bề mặt | Vai trò |
|---|---|
| HTTP + WebSocket JSON-RPC 2.0 | Giao thức gốc. Mọi thứ khác là client của nó. |
| CLI | Cho người và script |
| MCP stdio | Adapter mỏng map sang HTTP. Bắt buộc có, nhưng là *adapter*, không phải kiến trúc. |
| CDP subset | Để Playwright/Puppeteer điều khiển được. Chỉ phần AI thực sự dùng. |

**Quyết định:** HTTP JSON-RPC là nguồn sự thật, MCP là adapter. Lý do: daemon có thể chạy ở máy khác/termux-host, còn MCP client thì luôn nối local. Nếu MCP là gốc thì mọi người dùng non-MCP đều bị ép qua một tầng không cần.

### 5.1 Tool surface (v1)

`navigate` · `extract_text` · `snapshot_dom` · `snapshot_a11y` · `network_log` · `har_export` · `screenshot_dom` · `eval_js` · `click` · `type` · `select` · `scroll` · `wait_for` · `set_cookie` · `get_cookies` · `storage_set/get` · `new_tab` · `close_tab` · `list_tabs` · `download` · `upload` · `pdf` · `plugin_*` · `session_*` · `stealth_profile` · `bench`

## 6. Phân phối

| Kênh | Vai trò |
|---|---|
| `npm install -g f1stmux` | **Kênh chính.** Node đã có. Gói chứa prebuilt binary theo `os`/`arch` (`aarch64-linux-android` là target chính); `postinstall` chọn đúng file. |
| `pkg install f1stmux` | Kế hoạch v1.1, PR vào `termux-packages`. |
| `curl \| sh` | Không làm ở v1. Không cần thiết khi npm đã đủ. |
| `cargo install --git` | Fallback cho người tự build. |

**Không làm `.deb`.** Vô dụng trên Termux, chỉ liên quan desktop Linux. Bỏ hẳn khỏi kế hoạch.

### 6.1 Không phone-home

Không telemetry. Không tự cập nhật. Không gọi registry nếu không `--yes`. Crash report không tự gửi. Lần chạy đầu chỉ hỏi một lần, kết quả lưu cục bộ, và `--telemetry=off` là mặc định **không đổi được trừ khi chỉ định rõ**.

## 7. Điều kiện hoàn tất navigation, và hạn chế đã biết

### 7.1 Không có layout ⇒ phải bù bằng tín hiệu

Ta chấp nhận hạn chế (bạn đã chốt). Cách bù:

1. `network idle` — không còn request nào trong `quiet_ms`.
2. `DOM mutation hết tắt` — không còn mutation trong `quiet_ms`.
3. `readyState === 'complete'`.
4. Ngân sách thời gian theo từng lớp tài nguyên.
5. Nếu vẫn rỗng mà raw HTML có nội dung ⇒ đọc raw HTML. Không để tab trả về rỗng rồi báo thành công.
6. Retry với điều kiện chờ khác khi timeout.

### 7.2 Những gì ta **không** làm được, nói thẳng

| Không làm được | Vì sao | Đường vòng |
|---|---|---|
| Screenshot ảnh thật | Không có layout/raster | `screenshot_dom` dựng khung + vị trí text từ a11y |
| Nội dung chỉ hiện theo layout | Không tính layout | Chấp nhận; ghi rõ giới hạn |
| WebGL thật, WASM trong page đầy đủ | Engine giới hạn | `--engine=chromium` (v2) |
| Google / site JS cực nặng | Tài nguyên 3.6 GB | Dùng bridge Chromium hoặc API chính thức |
| Ẩn dấu hoàn hảo trước công nghệ chống bot đời mới | Bản chất của việc này | Luôn luồn, xoay profile/proxy, retry |

## 8. Rủi ro đã biết

| Rủi ro | Mức | Giảm bằng |
|---|---|---|
| Binding QuickJS không build được trên Termux | ✅ **Đã loại bỏ** | Phase 0 pass, có số đo |
| Crypto backend của TLS không build trên Android | ✅ **Đã loại bỏ** | `ring` build được; phải cấu hình `default-features = false` (§0.1) |
| TLS stack tùy chỉnh không cho JA4 | Trung bình | Tính thứ tự extension thủ công; nếu không được, chỉ cam kết JA3 |
| **Không xác minh được JS→DOM bridge tương tác 2 chiều** | Cao | Phase 1 đầu tiên; đây là phần chưa có bằng chứng nào |
| SPA đọc ra nội dung rỗng | Trung bình | §7.1 + ghi rõ giới hạn trong response |
| Host chậm do hàng đợi nhiều tab | Thấp | Giới hạn tab, tách tiến trình |
| Bị phát hiện ở tầng TLS | Trung bình | Profile nhất quán; không hứa "không bao giờ bị chặn" |
| Người dùng tin rằng nó vô hạn mở rộng | Thấp | Mọi giới hạn đều viết ra, không giấu |

---

## 8.1 Rủi ro *chưa* có bằng chứng

Đọc §0 và dễ tưởng mọi thứ đã an toàn. Không phải. Đây là những thứ **chưa ai build**, kể cả tôi:

- **JS ↔ DOM bridge hai chiều.** Spike chứng minh QuickJS chạy và `html5ever` parse được, nhưng chưa chứng minh chúng nói chuyện được với nhau theo cách mà một trang thật cần. Đây là phần có rủi ro cao nhất còn lại.
- **JA3/JA4 thực tế.** `rustls` build được, nhưng liệu có tùy chỉnh được ClientHello đủ để giả ClientHello của Chrome không — chưa đo.
- **Quy mô thật của RSS.** 6.7 MB là số của spike, không phải của sản phẩm.
- **`wasmtime` trên Android.** Chưa build. Nếu nặng quá, `wasmi` là đường thay thế; plugin `wasm` dời sang sau.
- **DOM bridge có đủ nhanh cho SPA thật** hay không.

## 9. Kế hoạch triển khai

Mỗi phase có một cổng kiểm chứng. **Không qua cổng thì dừng, không làm tiếp.**

| Phase | Nội dung | Cổng |
|---|---|---|
| **0 — Spike** | ✅ **Xong.** Số đo ở §0. Pass. | Đã pass |
| 1 | Core: fetch → parse → DOM → text. HTTP/WS JSON-RPC, CLI. Session ephemeral. | Navigate + đọc text chạy trên site tĩnh thật |
| 2 | Stealth 4 lớp + DoH + proxy + blocklist + vault | Vượt bot-check cơ bản, không rò DNS |
| 3 | Plugin host (`js` + `proc`), registry, hook, permission | Cài plugin tùy ý, hook chạy đúng |
| 4 | MCP, CDP subset, HAR, `screenshot_dom`, PDF | AI điều khiển trực tiếp qua MCP |
| 5 | Queue, crawl, schedule, monitor, diff, notify, supervisor, npm publish | `bench` có số so sánh |
| 6 | `--engine=chromium` bridge | Chỉ khi cần; core vẫn mặc định nhẹ |

### 9.1 Test và đo

- `f1stmux selftest` — correctness cho JS/DOM/stealth/chặn request. Chạy được trên chính máy này, không phụ thuộc CI ngoài.
- `f1stmux bench --compare lightpanda` — cùng bộ URL: RSS, wall-clock, cold start, bytes, JS-heavy subset.
- Golden files cho a11y/text extraction — chạy lại phải ra kết quả giống nhau.
- Test chống leak: sau khi kill daemon, không còn file tạm, không còn cookie, không còn kết nối.

## 10. Ngoài phạm vi

Không làm ở bất kỳ version nào nếu không có yêu cầu mới rõ ràng: `.deb`/rpm, extension Chrome, chế độ có GUI, đồng bộ cloud, tài khoản người dùng, marketplace UI, plugin marketplace trung tâm, tự động cập nhật.
