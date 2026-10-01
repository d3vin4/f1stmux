# F1stmux — a headless browser for AI agents

One binary. Terminal-only. Built for low-RAM machines (Termux/Android),
where Chromium is not an option.

```
f1stmux get https://example.com/ --json
f1stmux eval URL 'document.querySelector("p").textContent'
f1stmux serve   # JSON-RPC + web DevTools at 127.0.0.1:7070
f1stmux mcp     # MCP server over stdio (opencode, Claude Code, ...)
```

F1stmux fetches a page, parses it with a real HTML5 parser, runs its
scripts in QuickJS against a DOM bridge, and hands you text, DOM,
console output, network log, and HAR. Sessions live in RAM —
close it and every cookie, cache entry, and trace is gone.

## Measured numbers (Termux, aarch64 — not estimates)

| Metric | Value |
|---|---|
| Binary (stripped release) | 4.1 MB |
| Daemon RSS after navigations | ~7 MB |
| `GET example.com` | 200 in ~0.5–0.7 s |
| Hacker News front page | 200, 4200+ chars, zero JS errors |
| GitHub / Google homepages | readable content, JS errors tolerated |
| Rutracker (windows-1251, CF-fronted) | 200, correct Cyrillic decoding |

## Install

Requires Rust (1.85+) and `libclang` for the QuickJS bindings:

```sh
git clone https://github.com/<you>/f1stmux
cd f1stmux
cargo build --release
./target/release/f1stmux --help
```

`npm install -g f1stmux` with prebuilt binaries (including
`aarch64-linux-android`) is planned; see [Roadmap](#roadmap).

## Use it from an agent

**MCP (recommended).** Any MCP client works over stdio:

```json
{ "mcpServers": { "f1stmux": { "command": "f1stmux", "args": ["mcp"] } } }
```

17 tools: `navigate`, `query`, `eval_js`, `extract_text`, `snapshot_dom`,
`network_log`, `har_export`, `blocklist_test`, `stealth_profile`,
session management, plugin management. See
[`skills/f1stmux/SKILL.md`](skills/f1stmux/SKILL.md) for the agent guide.

**HTTP.** `f1stmux serve` exposes JSON-RPC 2.0 at `/rpc`, a CDP subset
at `/cdp`, and a web DevTools UI at `/devtools` — open it in your phone's
Chrome: Elements, Console, Network, HAR/DOM download.

**CLI.** `get`, `eval`, `tree`, `bench`, and a terminal DevTools REPL
(`f1stmux devtools URL`).

## Privacy (defaults, not options)

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
Stable within a session, fresh across sessions — per-call noise is a bot
signal, so we never do it. Tracker/ad blocking via compact rule syntax
(`||host^`, `|scheme`, `/path/`, `@@` exceptions).

## Captchas

Detected and reported, never silently ignored: `navigate` returns a
`captcha` field (`cloudflare`, `recaptcha`, `hcaptcha`, `turnstile`, …).
F1stmux does **not** solve challenges — rotate profile/proxy, retry later,
or use the target's official API.

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

Manifest + permission allowlist + global kill switch. See the manifest
reference in [`docs/`](docs/superpowers/specs/2026-10-01-f1stmux-design.md).

## How it compares

Lightpanda (Servo-based) is the closest project. Honest scorecard:

| | F1stmux | Lightpanda |
|---|---|---|
| RAM idle | ~7 MB measured | ~70–90 MB |
| Binary | 4.1 MB | tens of MB |
| Builds on Termux/Android | yes, verified | x86_64 only |
| JS fidelity | QuickJS subset | V8 (full) |
| Pixel rendering | no (DOM mock only) | partial |
| Plugin system | js/proc/wasm + hooks | — |

We win on footprint and hackability; we lose on JS fidelity and rendering.
If you need pixel screenshots or heavy SPAs, use a real browser engine —
F1stmux plans an optional `--engine=chromium` bridge for exactly that.

## Roadmap

- [ ] `npm install -g f1stmux` with prebuilt binaries
- [ ] `pkg install f1stmux` (termux-packages)
- [ ] WASM plugin host on Android
- [ ] `--engine=chromium` bridge for pixel/JS-heavy pages
- [ ] Full JA4 TLS parroting

## License

MIT. See [LICENSE](LICENSE).
