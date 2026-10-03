# F1stmux — Headless Browser for AI, a Termux-targeted design

> Translated from the original Vietnamese spec; the design intent is unchanged.

Date: 2026-10-01 · Status: **draft, awaiting review** · Compared against: Lightpanda

## 0. Phase 0 — real measurements on the target machine

Built and run on this very machine (`aarch64-linux-android`, rustc 1.98.1, LLVM 21.1.8). These are real numbers, not estimates.

| Item | Result |
|---|---|
| `libclang` | ✅ Already present at `$PREFIX/lib/libclang.so` → `rquickjs` can be built |
| `rquickjs` 0.14.0 + feature `bindgen` | ✅ Builds successfully. QuickJS eval of `Promise`/`Proxy`/`Symbol`/`BigInt` all work |
| `html5ever` via `scraper` 0.27 | ✅ Builds + parses; `h1` returns the correct text |
| `rustls` 0.23.45 + `ring` 0.17.14 | ✅ Builds on Android (no NDK needed) |
| Real HTTP | ✅ `GET https://example.com` → 200, 713 bytes, correct content, 497 ms |
| HTTP/2 | ✅ `POST https://nghttp2.org/httpbin/post` → 200 |
| SOCKS5 | ✅ The client accepts a `socks5://` configuration |
| Measured RSS | **6.7 MB** with the HTTP stack + roots + 1 QuickJS realm |
| Binary (spike) | 3.3 MB, not yet `strip`ped |

### 0.1 Three traps that must be written into the design

Each of these three issues breaks either the build or the runtime, and none of them can be anticipated:

1. **`rustls` PANICs by default on Android.** `rustls-platform-verifier` requires JNI init: `Expect rustls-platform-verifier to be initialized`. Fix: **do not use the system CA store**; build a `RootCertStore` from `webpki-roots` (121 roots) and call `install_default()` manually for `ring`. For a privacy-focused browser this is **also philosophically correct** — not reading the OS certificate authority store is itself a fingerprint.

2. **`aws-lc-rs` is also present in the dependency tree.** It builds, but it drags along assembler/C code that we never use. Configuration: `rustls` with `default-features = false` + the `ring` feature, installing the provider by hand. This configuration is mandatory in `Cargo.toml`.

3. **The feature names of `reqwest` 0.13 have changed.** `rustls-tls` no longer exists (it is now called `rustls`); to exclude the provider yourself, use `rustls-no-provider` and configure TLS manually. Recorded in the spec so nobody has to spend 30 minutes rediscovering it.

### 0.2 What this does not say

The 6.7 MB figure is the RSS of a spike that has only HTTP + 1 realm. The real daemon also has DOM, a11y, a plugin host, and a scheduler. **The idle ≤ 30 MB target is still only a target, not a measurement** — Phase 1 will measure again once the core exists.

---

## 1. Goals and constraints

F1stmux is a headless browser that runs **only inside a terminal**, optimized for **Termux on aarch64 Android**, built for AI control.

**Hard constraints of the target environment** (measured on the build machine):

| Item | Value | Design consequence |
|---|---|---|
| Total RAM | 3.6 GB (2.8 GB already in use) | Daemon idle target < 30 MB. Chromium is not viable. |
| CPU | 8 aarch64 cores | Single-threaded direction + async; avoid process-per-tab |
| Toolchain | `cargo 1.98`, `node 26`, `python 3.14`, no Go | Rust is the primary language. Go plugins must be installed separately. |
| Network | Android, no root | DoH is mandatory to prevent DNS leaks. |

**Success criteria** (measured with `f1stmux bench`):

- Idle daemon RAM ≤ 30 MB; JS per tab ≤ 12 MB
- Cold start < 100 ms
- Navigate+extract, static HTML: < 300 ms
- Navigate+extract, SPA with JS: < 2 s (accepted limitation, see §7)
- Binary ≤ 15 MB (after `strip`)
- Not one byte goes out except through requests the user explicitly commands

## 2. Architecture decisions

### 2.1 Language: Rust for the entire core, C/C++ only with evidence

You originally chose "C++ + Rust" and "as fast as possible at everything". After weighing it, the conclusion is **Rust for 100% of the core**:

- **QuickJS is C, not C++.** So "C++" is in practice only an FFI layer down to QuickJS — not a second language to maintain.
- Adding C++ only to compete with Rust on the same work means creating a build obstacle on a platform we are not even sure can build yet.
- The C/C++ upgrade path stays open: if `bench` shows that some hot path (HTML tokenize, buffer handling) is a bottleneck, write that one `.cpp`, call it through the `cc` crate, and measure again. **Add only with evidence, never on speculation.**

The risk of this decision: if Rust loses on some hot path, we have to run one more optimization round. Accepted, because that round is small and measurable.

### 2.2 No layout engine — this is a limiting decision, not laziness

We **do not** lay out pixels. No box layout, no rasterization, no real-image screenshots.

What we *do* have:

- A full DOM tree from an HTML5 parser
- A self-built accessibility tree (role/name/value)
- `text` extracted from the DOM
- A complete network log, HAR export
- Header order, TLS fingerprint, JS environment

**The honest consequence:** content that only appears after layout is computed (viewport-based lazy mounting, virtual lists, `content-visibility`) will not show up. We do not pretend this limitation does not exist.

### 2.3 Anti-detection: full coverage, in 4 layers

Each layer defends against a different kind of signal. Dropping any layer means losing that layer.

| Layer | What it defends against | Mechanism |
|---|---|---|
| **1. Identity profile** | Mismatched header/UA/Client-Hints | A shadow profile set: `chrome`, `edge`, `brave`, `firefox`, `safari`. Each profile binds a UA + header order + client hints + viewport + timezone + locale + platform, **internally consistent**. The worst signal is a profile that exposes a gap. |
| **2. TLS** | JA3/JA4 that deviate from a real browser | A TLS stack that can configure the ClientHello: cipher order, extension order (which generates JA4), ALPN, key share, GREASE, signature algos. Driven by `--profile`, not random. |
| **3. JS environment** | Anomalous canvas/WebGL/Audio/entropy | *Controlled* noise inside QuickJS: the canvas hash is stable within one session and differs across two sessions. `navigator.hardwareConcurrency`, `deviceMemory`, timezone, platform, `screen` all match the profile. |
| **4. Leaks** | DNS leaks, WebRTC leaks, IP leaks | DoH is mandatory (there is no opt-out), WebRTC peer APIs are blocked, all traffic must go through proxy/SOCKS5/Tor, and requests outside the allowlist are blocked. The kill switch disables every hook when something looks suspicious. |

**The inviolable rule of layer 3:** the fingerprint must be **stable for the whole session** and **different across sessions**. Adding noise on every `canvas.toDataURL()` call is worse than adding none — that is a bot fingerprint.

## 3. Architecture

```
┌─ f1stmux (CLI, Rust) ──┐   ┌─ f1stmux mcp (stdio) ─┐
│  navigate, extract,    │   │  bridge to HTTP       │
│  bench, plugin, vault  │   │  (runs anywhere)      │
└──────────┬─────────────┘   └──────────┬────────────┘
           │ HTTP/WS JSON-RPC 2.0       │
           └─────────────┬──────────────┘
                         ▼
        ┌─────────── f1stmuxd (Rust daemon) ───────────┐
        │                                              │
        │  session mgr ─ ephemeral, id-keyed, RAM-only │
        │  tab pool   ─ N tabs, fork a child process   │
        │  scheduler  ─ queue, cron, retry/backoff     │
        │                                              │
        │  ┌─ pipeline (per navigation) ─────────────┐ │
        │  │ fetch → parse → env → DOM → a11y → text │ │
        │  └─────────────────────────────────────────┘ │
        │                                              │
        │  ┌─ libraries ─────────────────────────────┐ │
        │  │ tls   : custom TLS stack (JA3/JA4)      │ │
        │  │ net   : HTTP/2, DoH, proxy chain, block │ │
        │  │ stealth: profile registry + JS noise    │ │
        │  │ dom   : html5ever → DOM → a11y          │ │
        │  │ js    : QuickJS (multi-realm, isolated) │ │
        │  │ vault : encrypted profiles, keys in RAM │ │
        │  │ plugin: host js | wasm | proc           │ │
        │  └─────────────────────────────────────────┘ │
        │                                              │
        └──────────────────────────────────────────────┘
```

### 3.1 The path of a single navigate

```
tool call "navigate"
  → session/tab lookup
  → build headers from the profile (fixed order)
  → TLS handshake with the profile's cipher/extension order
  → (if any) DNS via DoH, through the proxy chain
  → GET, following redirects under control, collecting cookies into the session jar
  → [plugin hook: onRequest / onResponse — can block/modify/add]
  → HTML5 parse → DOM
  → create a QuickJS realm, install the DOM bridge + a global object matching the profile
  → run page scripts naturally, watching mutations + network
  → completion conditions (§7) or out of budget → stop
  → [plugin hook: onDOMReady]
  → build the a11y tree, extract text
  → the session destroys itself if ephemeral
```

The important point: **the DOM bridge must be the only one**. One DOM tree in Rust, exposed to JS through the bridge. There are no two sources of truth — if there were, every DOM bug would be the hardest bug to find in the whole system.

### 3.2 Memory isolation

The machine has 3.6 GB. A single OOM kills the entire work session.

- `--max-tabs`, `--max-ram` are hard limits, not hints.
- A heavy QuickJS realm or a tab suspected of hanging → move it into a child process so it can be killed independently.
- Each session is **RAM-only** by default: cookies, storage, and cache live in RAM and vanish when the process dies. Writing to disk is an explicit opt-in (`--persist`) and requires a password.

## 4. Plugin system

Goal: **be able to install anything** — tools, inspectors, parsers, AI agents, proxies, storage backends, hooks, schedulers, OCR adapters — without modifying the core.

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

`api` is the version of the host API. The core rejects any plugin that declares an `api` higher than it knows.

### 4.2 Three kinds of plugins

| Kind | Runs in | Use when | Cost |
|---|---|---|---|
| `js` | Inside the daemon's QuickJS realm | Fast logic, needs to call hooks, needs to block requests | ~0, hot path |
| `proc` | Child process, stdio JSON-lines or localhost HTTP | Python (rich libraries), Rust/Go/C (fast), shell, wrapping existing tools | +50–100 ms/call |
| `wasm` | WASM module inside the host | Deterministic logic, needs stricter isolation than `js` | small |

All three are **child processes or sandboxes**, not native libraries linked in. This is a deliberate decision: linking native code means matching the ABI, a version change breaks it, and one buggy plugin brings down the daemon. `proc` accepts the latency and in exchange **every language can run**.

### 4.3 Installation and lifecycle

```
f1stmux plugin install <git-url | directory | tarball | registry-name>
    → download → read manifest → validate schema + permissions → place into ~/.f1stmux/plugins/<id>/
    → daemon hot-loads it, NO restart needed
f1stmux plugin list | info <id> | enable | disable | uninstall | grant <perm> | revoke <perm>
```

Registries: a local directory (`~/.f1stmux/plugins/`) and a remote registry (opt-in, not by default).

### 4.4 Sandbox

- Permissions are an allowlist on the manifest; a plugin that declares no permission has none.
- `net.intercept` is limited to the granted host/scheme.
- `js` is limited in execution time and memory quota.
- `proc` runs unprivileged, with no inherited environment and its own cwd.
- `/kill-switch` disables every hook without needing an uninstall — for when you suspect you are being tracked.

### 4.5 Interception points

| Hook | What the plugin may do |
|---|---|
| `onRequest` | Modify headers, block, add requests, change URLs, record HAR |
| `onResponse` | Modify body/headers, block, analyze |
| `onDOMReady` | Read the DOM, run scripts, extract text |
| `onToolCall` | Register new tools for the AI, block tools, log |
| `onPageScript` | Inject a script into the realm before the page scripts run |
| `onSessionCreate` / `onSessionEnd` | Track the session lifecycle, self-cleanup |

Through `onToolCall` a plugin can **register new tools** — this is the main extension path for custom agents/parsers/inspectors without touching the core.

## 5. Interfaces

| Surface | Role |
|---|---|
| HTTP + WebSocket JSON-RPC 2.0 | The native protocol. Everything else is a client of it. |
| CLI | For humans and scripts |
| MCP stdio | A thin adapter mapping onto HTTP. Mandatory to have, but it is an *adapter*, not the architecture. |
| CDP subset | So Playwright/Puppeteer can drive it. Only the part the AI actually uses. |

**Decision:** HTTP JSON-RPC is the source of truth, MCP is an adapter. The reason: the daemon may run on another machine / a termux host, while MCP clients always connect locally. If MCP were the root, every non-MCP user would be forced through a layer they do not need.

### 5.1 Tool surface (v1)

`navigate` · `extract_text` · `snapshot_dom` · `snapshot_a11y` · `network_log` · `har_export` · `screenshot_dom` · `eval_js` · `click` · `type` · `select` · `scroll` · `wait_for` · `set_cookie` · `get_cookies` · `storage_set/get` · `new_tab` · `close_tab` · `list_tabs` · `download` · `upload` · `pdf` · `plugin_*` · `session_*` · `stealth_profile` · `bench`

## 6. Distribution

| Channel | Role |
|---|---|
| `npm install -g f1stmux` | **The primary channel.** Node is already there. The package contains prebuilt binaries per `os`/`arch` (`aarch64-linux-android` is the primary target); `postinstall` picks the right file. |
| `pkg install f1stmux` | Planned for v1.1, PR into `termux-packages`. |
| `curl \| sh` | Not doing this in v1. Unnecessary while npm is enough. |
| `cargo install --git` | Fallback for people who build it themselves. |

**No `.deb`.** Useless on Termux, only relevant to desktop Linux. Dropped from the plan entirely.

### 6.1 No phone-home

No telemetry. No self-update. No registry call without `--yes`. Crash reports are never sent automatically. The first run asks only once, the result is stored locally, and `--telemetry=off` is the default that **cannot be changed unless explicitly specified**.

## 7. Navigation completion conditions, and known limitations

### 7.1 No layout ⇒ we must compensate with signals

We accept the limitation (you already locked this in). How we compensate:

1. `network idle` — no requests left within `quiet_ms`.
2. `DOM mutations have stopped` — no mutations within `quiet_ms`.
3. `readyState === 'complete'`.
4. A time budget per resource class.
5. If it is still empty but the raw HTML has content ⇒ read the raw HTML. Never let a tab return empty and then report success.
6. Retry with a different wait condition on timeout.

### 7.2 What we **cannot** do, stated plainly

| Cannot do | Why | Workaround |
|---|---|---|
| Real-image screenshots | No layout/raster | `screenshot_dom` builds the frame + text positions from a11y |
| Content that only appears through layout | No layout computation | Accept it; state the limitation clearly |
| Real WebGL, full WASM in the page | Limited engine | `--engine=chromium` (v2) |
| Google / extremely JS-heavy sites | 3.6 GB of resources | Use a Chromium bridge or the official API |
| Perfect stealth against next-generation anti-bot technology | The nature of this work | Always adapt, rotate profiles/proxies, retry |

## 8. Known risks

| Risk | Level | Mitigated by |
|---|---|---|
| QuickJS binding cannot be built on Termux | ✅ **Eliminated** | Phase 0 passed, with measurements |
| The TLS crypto backend does not build on Android | ✅ **Eliminated** | `ring` builds; `default-features = false` is required (§0.1) |
| The custom TLS stack cannot produce JA4 | Medium | Compute the extension order manually; if not possible, only promise JA3 |
| **Cannot verify the bidirectional JS→DOM bridge** | High | First in Phase 1; this is the part with no evidence at all |
| An SPA reads out empty content | Medium | §7.1 + stating the limitation clearly in the response |
| The host slows down from too many tabs in the queue | Low | Tab limits, process separation |
| Getting detected at the TLS layer | Medium | Consistent profiles; do not promise "never blocked" |
| Users believing it scales without limit | Low | Every limitation is written down, nothing hidden |

---

## 8.1 Risks with *no* evidence yet

Reading §0 it is easy to assume everything is safe. It is not. These are the things **nobody has built yet**, including me:

- **The bidirectional JS ↔ DOM bridge.** The spike proved QuickJS runs and `html5ever` parses, but it did not prove the two can talk to each other in the way a real page needs. This is the highest-risk piece left.
- **Real JA3/JA4.** `rustls` builds, but whether the ClientHello can be customized enough to imitate Chrome's ClientHello is not yet measured.
- **The true scale of RSS.** 6.7 MB is the spike's number, not the product's.
- **`wasmtime` on Android.** Not built yet. If it is too heavy, `wasmi` is the fallback; `wasm` plugins move to a later phase.
- Whether the **DOM bridge is fast enough for real SPAs**.

## 9. Implementation plan

Each phase has one verification gate. **If the gate is not passed, stop — do not continue.**

| Phase | Content | Gate |
|---|---|---|
| **0 — Spike** | ✅ **Done.** Measurements in §0. Passed. | Passed |
| 1 | Core: fetch → parse → DOM → text. HTTP/WS JSON-RPC, CLI. Session ephemeral. | Navigate + read text works on a real static site |
| 2 | 4-layer stealth + DoH + proxy + blocklist + vault | Pass basic bot-checks, no DNS leak |
| 3 | Plugin host (`js` + `proc`), registry, hooks, permissions | Install any plugin, hooks run correctly |
| 4 | MCP, CDP subset, HAR, `screenshot_dom`, PDF | AI drives it directly through MCP |
| 5 | Queue, crawl, schedule, monitor, diff, notify, supervisor, npm publish | `bench` has comparable numbers |
| 6 | `--engine=chromium` bridge | Only when needed; core stays lightweight by default |

### 9.1 Tests and measurements

- `f1stmux selftest` — correctness for JS/DOM/stealth/request blocking. Runnable on this very machine, no external CI dependency.
- `f1stmux bench --compare lightpanda` — the same URL set: RSS, wall-clock, cold start, bytes, JS-heavy subset.
- Golden files for a11y/text extraction — re-running must produce identical results.
- Leak tests: after killing the daemon, no temp files remain, no cookies remain, no connections remain.

## 10. Out of scope

Not done in any version without a clear new requirement: `.deb`/rpm, Chrome extension, GUI mode, cloud sync, user accounts, marketplace UI, a central plugin marketplace, automatic updates.