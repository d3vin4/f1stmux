# F1stmux

[![Release](https://img.shields.io/github/v/release/d3vin4/f1stmux)](https://github.com/d3vin4/f1stmux/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20android%20%7C%20termux-lightgrey.svg)](#install)

[Tieng Viet](README.vi.md)

A headless browser for AI agents that runs where Chromium cannot. One static
binary, terminal-only, about 7 MB of RAM on Termux/Android (aarch64, measured).

F1stmux fetches a page, parses it with a real HTML5 parser, runs its scripts
in QuickJS against a DOM bridge, and hands you text, DOM, console output,
network log, and HAR. Sessions live in RAM — closing wipes every cookie,
cache entry, and trace.

When a page needs real layout or a full JavaScript engine, `--engine chromium`
attaches to a real Chromium over CDP. Without a backend, F1stmux says so
plainly instead of faking pixels.

```
f1stmux get https://example.com/ --json
f1stmux eval URL 'document.querySelector("p").textContent'
f1stmux serve   # JSON-RPC + web DevTools at 127.0.0.1:7070
f1stmux mcp     # MCP server over stdio (opencode, Claude Code, ...)
```

## Why F1stmux

| | F1stmux | Full browsers | curl + scripts |
|---|---|---|---|
| RAM per session | ~7 MB | hundreds of MB | ~1 MB |
| JavaScript | QuickJS subset (+ Chromium over CDP when needed) | full | none |
| AI control (MCP/JSON-RPC/CLI) | native, 41 tools | via automation layers | hand-rolled |
| Captcha handling | detect + human-solve portal, never auto-opens targets | manual | manual |
| Runs on Termux/Android | yes, verified | no | yes |

## Measured numbers

Termux, aarch64. Not estimates.

| Metric | Value |
|---|---|
| Binary (stripped release) | 5.4 MB |
| Daemon RSS after navigations | ~7 MB |
| `GET example.com` | HTTP 200 in ~0.5–0.7 s |
| Hacker News front page | HTTP 200, 4200+ chars, zero JS errors |
| GitHub / Google homepages | readable content, page JS errors tolerated |
| Cyrillic (windows-1251) page behind Cloudflare | HTTP 200, correct decoding |

## Install

Requires Rust 1.85+ and `libclang` for the QuickJS bindings:

```sh
git clone https://github.com/d3vin4/f1stmux
cd f1stmux
cargo build --release
./target/release/f1stmux --help
```

Or download the static binary from
[Releases](https://github.com/d3vin4/f1stmux/releases) and put it on `PATH`.

Prebuilt packages (`npm install -g f1stmux`, `pkg install f1stmux`) are on the
[roadmap](#roadmap).

## Use it from an agent

**MCP (recommended).** Any MCP client works over stdio:

```json
{ "mcpServers": { "f1stmux": { "command": "f1stmux", "args": ["mcp"] } } }
```

41 tools: `navigate`, `query`, `eval_js`, `extract_text`, `snapshot_dom`,
`screenshot`, `pdf`, `audit`, `network_log`, `har_export`, `blocklist_test`,
`stealth_profile`, tabs (`tabs`, `history`, `back`, `forward`), automation
(`click`, `type_text`, `press`, `select`, `wait_for`), `open` omnibox,
bookmarks, downloads, `cookies`, `settings`, session management,
plugin management, challenge tickets,
recon (`scan`, `cf`, `inject`, `ghclone`).
See [`skills/f1stmux/SKILL.md`](skills/f1stmux/SKILL.md) for the agent guide.

**HTTP.** `f1stmux serve` exposes JSON-RPC 2.0 at `/rpc`, a CDP subset
at `/cdp`, and a web DevTools UI at `/devtools` — open it in your phone's
browser: Elements, Console, Network, HAR/DOM download.
Inspection runs over plain HTTP (no WebSocket upgrade); the UI polls `/cdp`.

> **Remote mode.** The daemon has no authentication. It binds loopback by
> default and *refuses* non-loopback binds unless you pass `--allow-remote`
> (or `"allow_remote": true`). Only expose it to a network you trust —
> anyone who can reach it can browse, install plugins, and fetch internal URLs.

**CLI.** `get`, `eval`, `tree`, `bench`, `screenshot`, `pdf`, `audit`,
`bookmark`, `download`, `open`, and a terminal DevTools REPL
(`f1stmux devtools URL`).

## Browser behavior

Sessions are tabs: each keeps its own history, cookies, storage, and network
log. `back`/`forward` travel history without recording duplicates, `tabs`
lists open tabs, `history` shows the URL trail. Bookmarks persist in
`~/.f1stmux/bookmarks.json`; downloads go to `~/.f1stmux/downloads`.
Automation is real — `click` dispatches to page listeners, `type_text` fires
`input`/`change`, `press` sends keyboard events, `select` fires `change`,
and `wait_for` polls instead of sleeping blind. `open` resolves URLs, bare
domains, bookmarks, and history (there is no search provider — it says so
instead of guessing).

## Chromium engine (`--engine`)

```sh
f1stmux --engine chromium get URL --json        # real JS-rendered DOM over CDP
f1stmux screenshot URL -o shot.png              # real-layout PNG
f1stmux pdf URL -o page.pdf                     # real-layout PDF
```

Needs a running Chromium with remote debugging: set `F1STCHROME_CDP=host:port`
or have `chrome-headless-shell`/`chromium` on `PATH` for auto-spawn.
Without a backend the command fails with a clear message — screenshot/pdf then
use labeled DOM fallbacks, never fake pixel layout.

## Privacy

Defaults, not options.

- No telemetry, no auto-update, no phone-home, no disk logging.
- Ephemeral sessions: RAM-only cookies, storage, and cache.
- Bundled CA roots (never reads the OS store — which is also the only way
  TLS works on Android without a JNI panic).
- DNS-over-HTTPS, fail-closed. WebRTC/STUN/TURN blocked at the scheme layer.
- Known leaks, documented not hidden: the DoH endpoint's own hostname
  resolves via system DNS once at startup; SNI still reveals the hostname
  to a network observer (DoH hides DNS, not SNI).

## Stealth

Consistent identity profiles (`chrome`, `edge`, `brave`): User-Agent,
header order, Client Hints, locale, timezone, screen, hardware concurrency.
Stable within a session, fresh across sessions — per-request noise is a bot
signal, so it is never generated. Tracker/ad blocking uses compact rule
syntax (`||host^`, `|scheme`, `/path/`, `@@` exceptions), enforced on
documents and subresource scripts alike.

## Captchas

Detected and reported, never silently ignored: `navigate` returns a
`captcha` field (`cloudflare`, `recaptcha`, `hcaptcha`, `turnstile`, …) plus
the extracted form state (`captcha_tokens`).
F1stmux does **not** solve challenges — but it offers a human-solve portal:
`navigate(url, on_challenge="portal")` creates a ticket and serves a
loopback page where a person solves the challenge in a real browser, pastes
the token, and f1stmux replays it into the session. The destination URL is
returned, never auto-opened. Fake tokens are rejected by the target server,
so only genuine human solves pass. See `challenge_create` / `challenge_result`.

## Security audit

`f1stmux audit URL` inspects response headers, CSP/CORS, cookies, and scans
page source for endpoint and CVE-ID literals. Every finding carries the raw
evidence it came from. It reports observations — it does not invent
vulnerabilities, guess versions, or assign severity beyond `info`/`warn`/`risk`.

## Plugins

Anything can be a plugin — tools, parsers, proxies, agents — without
touching core. Three kinds, all sandboxed or subprocess-based (never
natively linked):

| Kind | Runs as | For |
|---|---|---|
| `js` | QuickJS realm in-daemon | fast hooks, request blocking |
| `proc` | child process, JSON-lines stdio | Python/Rust/Go/shell — any language |
| `wasm` | WASM module | tight sandboxing (host in progress) |

```sh
f1stmux plugin install <dir|git-url|tarball>   # hot-loaded, no restart
```

Manifest + permission allowlist + global kill switch.

## Roadmap

- [ ] `npm install -g f1stmux` with prebuilt binaries
- [ ] `pkg install f1stmux` (termux-packages)
- [ ] WASM plugin host on Android
- [ ] Full JA4 TLS parroting
- [ ] SSRF IP policy + auth tokens for remote mode

## License

MIT. See [LICENSE](LICENSE).
