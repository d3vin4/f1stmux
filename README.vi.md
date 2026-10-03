# F1stmux

[![Release](https://img.shields.io/github/v/release/d3vin4/f1stmux)](https://github.com/d3vin4/f1stmux/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20android%20%7C%20termux-lightgrey.svg)](#cai-dat)

[English](README.md)

Headless browser cho AI agent, chạy được ở nơi Chromium không chạy nổi. Một
binary duy nhất, chỉ terminal, khoảng 7 MB RAM trên Termux/Android (aarch64,
đo thật).

F1stmux tải trang, parse bằng HTML5 parser thật, chạy script của trang trong
QuickJS qua DOM bridge, rồi trả về text, DOM, console output, network log và HAR.
Session sống trong RAM — tắt đi là mọi cookie, cache và dấu vết biến mất.

Trang nào cần layout thật hay JavaScript đầy đủ thì dùng `--engine chromium`
để nối tới Chromium thật qua CDP. Không có backend thì F1stmux báo rõ chứ
không dựng pixel giả.

```
f1stmux get https://example.com/ --json
f1stmux eval URL 'document.querySelector("p").textContent'
f1stmux serve   # JSON-RPC + DevTools web tại 127.0.0.1:7070
f1stmux mcp     # MCP server qua stdio (opencode, Claude Code, ...)
```

## Vì sao dùng F1stmux

| | F1stmux | Trình duyệt đầy đủ | curl + script tay |
|---|---|---|---|
| RAM mỗi session | ~7 MB | hàng trăm MB | ~1 MB |
| JavaScript | QuickJS subset (+ Chromium qua CDP khi cần) | đầy đủ | không có |
| Điều khiển bởi AI (MCP/JSON-RPC/CLI) | native, 20 tools | qua lớp automation | tự viết tay |
| Xử lý captcha | detect + portal cho người giải, không bao giờ tự mở đích | thủ công | thủ công |
| Chạy trên Termux/Android | có, đã verify | không | có |

## Số đo thật

Termux, aarch64. Không ước lượng.

| Chỉ số | Giá trị |
|---|---|
| Binary (stripped release) | 5.4 MB |
| RAM daemon sau nhiều navigation | ~7 MB |
| `GET example.com` | HTTP 200 trong ~0,5–0,7 s |
| Trang chủ Hacker News | HTTP 200, 4200+ ký tự, không lỗi JS |
| Trang chủ GitHub / Google | đọc được nội dung, chịu được lỗi JS của trang |
| Trang Cyrillic (windows-1251) sau Cloudflare | HTTP 200, giải mã đúng |

## Cài đặt

Cần Rust 1.85+ và `libclang` cho QuickJS bindings:

```sh
git clone https://github.com/d3vin4/f1stmux
cd f1stmux
cargo build --release
./target/release/f1stmux --help
```

Hoặc tải binary build sẵn từ
[Releases](https://github.com/d3vin4/f1stmux/releases) rồi bỏ vào `PATH`.

Gói cài sẵn (`npm install -g f1stmux`, `pkg install f1stmux`) đang ở
[roadmap](#roadmap).

## Dùng từ agent

**MCP (khuyên dùng).** Mọi MCP client đều chạy được qua stdio:

```json
{ "mcpServers": { "f1stmux": { "command": "f1stmux", "args": ["mcp"] } } }
```

20 tools: `navigate`, `query`, `eval_js`, `extract_text`, `snapshot_dom`,
`screenshot`, `pdf`, `audit`, `network_log`, `har_export`, `blocklist_test`,
`stealth_profile`, quản lý session, quản lý plugin, challenge tickets.
Xem [`skills/f1stmux/SKILL.md`](skills/f1stmux/SKILL.md) để biết cách dùng chi tiết.

**HTTP.** `f1stmux serve` mở JSON-RPC 2.0 tại `/rpc`, một tập con CDP tại
`/cdp`, và giao diện DevTools web tại `/devtools` — mở bằng trình duyệt trên
điện thoại: Elements, Console, Network, tải HAR/DOM.
Inspection chạy qua HTTP thuần (không upgrade WebSocket); giao diện poll `/cdp`.

> **Chế độ remote.** Daemon không có auth. Mặc định chỉ bind loopback và
> *từ chối* bind địa chỉ khác trừ khi bạn truyền `--allow-remote`
> (hoặc `"allow_remote": true`). Chỉ mở ra mạng mà bạn tin tưởng —
> ai chạm được vào nó đều có thể browse, cài plugin và fetch URL nội bộ.

**CLI.** `get`, `eval`, `tree`, `bench`, `screenshot`, `pdf`, `audit`, và
vòng lặp DevTools trong terminal (`f1stmux devtools URL`).

## Engine Chromium (`--engine`)

```sh
f1stmux --engine chromium get URL --json        # DOM render JS thật qua CDP
f1stmux screenshot URL -o shot.png              # PNG layout thật
f1stmux pdf URL -o page.pdf                     # PDF layout thật
```

Cần một Chromium đang chạy với remote debugging: đặt `F1STCHROME_CDP=host:port`
hoặc để sẵn binary `chrome-headless-shell`/`chromium` trong PATH để tự spawn.
Không có backend thì lệnh báo lỗi rõ ràng — screenshot/pdf lúc đó dùng bản vẽ
tạm từ DOM (ghi rõ trong output), không bao giờ giả vờ là layout thật.

## Riêng tư

Mặc định, không phải tùy chọn.

- Không telemetry, không tự cập nhật, không phone-home, không ghi log ra đĩa.
- Session phù du: cookie, storage và cache chỉ nằm trong RAM.
- CA roots bundle trong binary (không đọc kho của hệ điều hành — mà đây cũng
  là cách duy nhất để TLS chạy được trên Android mà không panic JNI).
- DNS-over-HTTPS, fail-closed. WebRTC/STUN/TURN bị chặn ở tầng scheme.
- Rò rỉ đã biết, ghi ra chứ không giấu: hostname của chính endpoint DoH phân
  giải qua DNS hệ thống một lần lúc khởi động; SNI vẫn lộ hostname với kẻ nghe
  mạng (DoH giấu DNS, không giấu SNI).

## Stealth

Profile danh tính nhất quán (`chrome`, `edge`, `brave`): User-Agent, thứ tự
header, Client Hints, locale, timezone, màn hình, hardware concurrency.
Ổn định trong một session, mới ở session khác — nhiễu theo từng request là
dấu hiệu bot nên không bao giờ làm vậy. Chặn tracker/ad bằng rule gọn
(`||host^`, `|scheme`, `/path/`, ngoại lệ `@@`), thực thi thật trên document
và script con.

## Captcha

Phát hiện và báo, không bao giờ lờ đi: `navigate` trả về field `captcha`
(`cloudflare`, `recaptcha`, `hcaptcha`, `turnstile`, …) kèm toàn bộ field form
trích được (`captcha_tokens`).
F1stmux **không** tự giải challenge — nhưng có portal cho người giải:
`navigate(url, on_challenge="portal")` tạo ticket và phục vụ trang loopback để
người giải trên browser thật, dán token, rồi f1stmux replay vào session. URL
đích được trả về, không bao giờ tự mở. Token giả bị server đích từ chối nên
chỉ lượt giải thật của người mới qua được. Xem `challenge_create` /
`challenge_result`.

## Audit bảo mật

`f1stmux audit URL` kiểm tra response header, CSP/CORS, cookie, và quét source
trang tìm endpoint và chuỗi CVE-ID. Mỗi finding kèm bằng chứng thô. Nó báo
quan sát — không dựng lỗ hổng, không đoán version, không gán severity ngoài
`info`/`warn`/`risk`.

## Plugin

Mọi thứ đều có thể là plugin — tool, parser, proxy, agent — mà không cần đụng
core. Ba loại, đều sandbox hoặc tiến trình con (không bao giờ link native):

| Loại | Chạy | Dùng khi |
|---|---|---|
| `js` | realm QuickJS trong daemon | hook nhanh, chặn request |
| `proc` | tiến trình con, stdio JSON-lines | Python/Rust/Go/shell — mọi ngôn ngữ |
| `wasm` | module WASM | sandbox chặt (host đang làm) |

```sh
f1stmux plugin install <dir|git-url|tarball>   # hot-load, không cần restart
```

Manifest + allowlist quyền + kill switch toàn cục.

## Roadmap

- [ ] `npm install -g f1stmux` với binary build sẵn
- [ ] `pkg install f1stmux` (termux-packages)
- [ ] WASM plugin host trên Android
- [ ] JA4 TLS parroting đầy đủ
- [ ] SSRF IP policy đầy đủ + auth token cho remote mode

## Giấy phép

MIT. Xem [LICENSE](LICENSE).
