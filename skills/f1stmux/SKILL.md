---
name: f1stmux
description: Drive the F1stmux headless browser — navigate pages, extract text/DOM, run JS, inspect network, export HAR. Use when you need to read, scrape, or automate the web from an agent.
---

# F1stmux skill

F1stmux is a headless browser for AI agents. One binary, terminal-only,
designed for low-RAM machines (Termux/Android). No Chromium needed.

## Two ways to drive it

**1. MCP (preferred inside agents).** Add to your MCP config:

```json
{
  "mcpServers": {
    "f1stmux": { "command": "f1stmux", "args": ["mcp"] }
  }
}
```

For opencode (`opencode.json`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "f1stmux": { "type": "local", "command": ["f1stmux", "mcp"], "enabled": true }
  }
}
```

You get 18 tools. The ones you will use daily:

| Tool | Purpose |
|---|---|
| `navigate` | Open a URL. Returns text, title, status, console, `captcha` flag |
| `query` | CSS selector (`tag`, `#id`, `.class`, `[attr]`) on the live DOM |
| `eval_js` | Run a JS **expression**, get JSON back |
| `extract_text` / `snapshot_dom` | Re-read current tab without re-fetching |
| `network_log` / `har_export` | What the page actually requested |
| `blocklist_test` | Check if a URL would be blocked |

Sessions are RAM-only, isolated per session (cookies, JS storage, network
log). Pass `session` to keep state across calls; omit it to start fresh.
Unknown session IDs are an error, never a silent new session.
`session_close` wipes all traces. `eval_js` throws are tool errors, not nulls.

**2. CLI (scripts, debugging).**

```sh
f1stmux get URL --json          # full NavResult as JSON
f1stmux eval URL 'expr'         # JS expression → JSON
f1stmux devtools URL            # terminal REPL: t/d/c/n/<expr>
f1stmux serve                   # daemon at 127.0.0.1:7070
```

## Reading the result

`navigate` returns (among others):

- `text` — whitespace-collapsed body text, scripts/styles removed
- `content_from_js` — `true` if JS changed the content after parse
- `captcha` — `null` normally; otherwise one of `cloudflare`,
  `recaptcha`, `hcaptcha`, `turnstile`, `challenge-title`, `challenge-url`.
  **F1stmux does not solve captchas.** When set: rotate profile/proxy,
  retry later, escalate to the user — or pass `on_challenge: "portal"` to
  `navigate` so a human can solve it via the loopback portal
  (`challenge_create` / `challenge_result` tools). Solved destinations are
  returned, never auto-opened.
- `errors` — page JS errors (informational; static content still extracted)
- `truncated`/`timed_out` — budgets hit; narrow the selector and re-query

## Practical patterns

- Prefer `query` with a tight selector over re-reading full text.
- `eval_js` takes an **expression**, not statements. Object literals need
  parens: `({a: document.title})`. A statement returns `null`.
- No layout engine: no pixel screenshots, no viewport-lazy content.
  `screenshot_dom` is a DOM-position mock, not a bitmap.
- Non-UTF8 pages (windows-1251, shift_jis, gbk) are decoded automatically.
- Stealth profiles: `chrome` (default), `edge`, `brave` via `--profile`.
  Fingerprint is stable within a session, fresh across sessions.
- Everything except the requested URL stays silent: no telemetry,
  bundled CA roots, DNS-over-HTTPS with fail-closed behavior.

## When NOT to use it

- Pixel-perfect rendering, WebGL, canvas games → needs a real browser engine.
- Active Cloudflare Turnstile/managed challenge → detected and reported,
  not bypassed. Use the official API of the target site instead.
