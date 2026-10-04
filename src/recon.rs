//! Recon helpers for authorized security research: fast downloads, GitHub
//! cloning, Cloudflare footprint analysis, TCP service scan, and payload
//! injection testing.
//!
//! Rules: findings carry raw evidence; nothing is invented. Active tools
//! (scan, inject) only touch the target you name — use them solely on systems
//! you are authorized to test.

use serde::{Deserialize, Serialize};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Fast download: parallel Range requests with single-stream fallback.
// ---------------------------------------------------------------------------

/// Download with up to `parts` parallel Range connections when the server
/// advertises `Accept-Ranges: bytes` and a known length. Otherwise a single
/// stream. Returns (bytes_written, parallel_parts_used).
pub async fn fast_download(url: &str, dest: &std::path::Path, parts: usize) -> Result<(usize, usize), String> {
    fast_download_with(url, dest, parts, &crate::config::Config::default()).await
}

/// Same, honoring the caller's config (proxy, DoH guard, TLS roots).
pub async fn fast_download_with(
    url: &str,
    dest: &std::path::Path,
    parts: usize,
    cfg: &crate::config::Config,
) -> Result<(usize, usize), String> {
    let probe = crate::net::client(cfg)?;
    let head = probe.head(url).send().await.map_err(|e| crate::net::err_msg(&e))?;
    let len = head.content_length().unwrap_or(0) as usize;
    let ranged = head
        .headers()
        .get(reqwest::header::ACCEPT_RANGES)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("bytes"))
        .unwrap_or(false);
    drop(head);

    let n = if ranged && len > 1_048_576 {
        parts.clamp(2, 8)
    } else {
        1
    };
    if n == 1 {
        let cfg2 = cfg.clone();
        let prof = crate::stealth::profile(&cfg2.profile).ok_or("missing profile")?;
        let (_, bytes) = crate::fetch::get_bytes(url, &cfg2, prof, "").await?;
        if let Some(dir) = dest.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        std::fs::write(dest, &bytes).map_err(|e| e.to_string())?;
        return Ok((bytes.len(), 1));
    }

    // Parallel parts into temp files, then concatenate (crash-safe, no sparse seek).
    let tmpdir = dest.with_extension("f1parts");
    std::fs::create_dir_all(&tmpdir).map_err(|e| e.to_string())?;
    let chunk = len.div_ceil(n);
    let pclient = crate::net::client(cfg)?;
    let mut tasks = vec![];
    for i in 0..n {
        let start = i * chunk;
        let end = ((i + 1) * chunk).min(len).saturating_sub(1);
        if start >= len {
            break;
        }
        let url = url.to_string();
        let part_path = tmpdir.join(format!("p{i}"));
        let client = pclient.clone();
        tasks.push(tokio::spawn(async move {
            let r = client
                .get(&url)
                .header("range", format!("bytes={start}-{end}"))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if r.status() != reqwest::StatusCode::PARTIAL_CONTENT {
                return Err(format!("server ignored Range (status {})", r.status()));
            }
            let b = r.bytes().await.map_err(|e| e.to_string())?;
            std::fs::write(&part_path, &b).map_err(|e| e.to_string())?;
            Ok::<usize, String>(b.len())
        }));
    }
    let mut total = 0usize;
    let mut used = 0usize;
    for t in tasks {
        match t.await.map_err(|e| e.to_string())? {
            Ok(n) => {
                total += n;
                used += 1;
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmpdir);
                return Err(e);
            }
        }
    }
    let mut out = std::fs::File::create(dest).map_err(|e| e.to_string())?;
    for i in 0..used {
        let b = std::fs::read(tmpdir.join(format!("p{i}"))).map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut out, &b).map_err(|e| e.to_string())?;
    }
    let _ = std::fs::remove_dir_all(&tmpdir);
    Ok((total, used))
}

// ---------------------------------------------------------------------------
// Fast GitHub clone: tarball-first (codeload), git-shallow fallback.
// ---------------------------------------------------------------------------

/// Parse owner/repo out of `owner/repo`, a github URL, or a URL with .git.
pub fn parse_repo(arg: &str) -> Result<(String, String), String> {
    let t = arg.trim().trim_end_matches('/').trim_end_matches(".git");
    if let Some(rest) = t.strip_prefix("https://github.com/").or_else(|| t.strip_prefix("http://github.com/")) {
        let mut it = rest.split('/');
        match (it.next(), it.next()) {
            (Some(o), Some(r)) if !o.is_empty() && !r.is_empty() => return Ok((o.into(), r.into())),
            _ => {}
        }
    }
    let mut it = t.split('/');
    match (it.next(), it.next()) {
        (Some(o), Some(r)) if !o.is_empty() && !r.is_empty() && it.next().is_none() => Ok((o.into(), r.into())),
        _ => Err(format!("need owner/repo or a github URL, got `{arg}`")),
    }
}

fn run_cmd(prog: &str, args: &[&str], dir: &std::path::Path) -> Result<String, String> {
    let o = std::process::Command::new(prog)
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("spawn {prog}: {e}"))?;
    if !o.status.success() {
        return Err(format!("{prog} failed: {}", String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Clone fast: try the codeload tarball over the parallel downloader first
/// (usually much faster than git), fall back to a shallow blobless git clone.
pub async fn ghclone(repo: &str, dest: Option<&str>, branch: Option<&str>) -> Result<serde_json::Value, String> {
    let (owner, name) = parse_repo(repo)?;
    let target = match dest {
        Some(d) if !d.is_empty() => std::path::PathBuf::from(d),
        _ => std::path::PathBuf::from(&name),
    };
    if target.exists() {
        return Err(format!("destination exists: {}", target.display()));
    }
    let br = match branch {
        Some(b) if !b.is_empty() => b.to_string(),
        _ => default_branch(&owner, &name).await?,
    };
    // Tarball path.
    let tar_url = format!("https://codeload.github.com/{owner}/{name}/tar.gz/refs/heads/{br}");
    let tarball = target.with_extension("tar.gz");
    match fast_download(&tar_url, &tarball, 4).await {
        Ok((bytes, parts)) => {
            let dir = target.parent().unwrap_or(std::path::Path::new("."));
            match run_cmd("tar", &["-xzf", &tarball.to_string_lossy(), "-C", &dir.to_string_lossy()], dir) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&tarball);
                    // codeload unpacks as {name}-{branch}; rename to the requested dir.
                    let unpacked = dir.join(format!("{name}-{br}"));
                    if unpacked != target && unpacked.exists() {
                        let _ = std::fs::rename(&unpacked, &target);
                    }
                    return Ok(serde_json::json!({
                        "method": "tarball", "repo": format!("{owner}/{name}"),
                        "branch": br, "bytes": bytes, "parts": parts,
                        "dir": target.to_string_lossy(),
                    }));
                }
                Err(e) => {
                    // No tar available: keep the archive, report it honestly.
                    return Ok(serde_json::json!({
                        "method": "tarball-kept", "repo": format!("{owner}/{name}"),
                        "branch": br, "bytes": bytes, "note": format!("saved archive (no tar to extract: {e})"),
                        "file": tarball.to_string_lossy(),
                    }));
                }
            }
        }
        Err(_) => {}
    }
    // Git fallback: shallow + blobless.
    let dir = target.parent().unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    run_cmd(
        "git",
        &["clone", "--depth", "1", "--filter=blob:none", "--single-branch", "--branch", &br,
            &format!("https://github.com/{owner}/{name}.git"), &target.to_string_lossy()],
        dir,
    )?;
    Ok(serde_json::json!({
        "method": "git-shallow", "repo": format!("{owner}/{name}"),
        "branch": br, "dir": target.to_string_lossy(),
    }))
}

async fn default_branch(owner: &str, name: &str) -> Result<String, String> {
    let out = tokio::task::spawn_blocking({
        let url = format!("https://github.com/{owner}/{name}.git");
        move || {
            std::process::Command::new("git")
                .args(["ls-remote", "--symref", &url, "HEAD"])
                .output()
                .map_err(|e| e.to_string())
        }
    })
    .await
    .map_err(|e| e.to_string())??;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("ref: refs/heads/") {
            if let Some(b) = rest.split_whitespace().next() {
                return Ok(b.into());
            }
        }
    }
    // Last resort, tried in order.
    Ok("main".into())
}

// ---------------------------------------------------------------------------
// Cloudflare footprint: edge evidence only, nothing inferred.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfReport {
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub behind_cloudflare: bool,
    pub ray: Option<String>,
    pub pop: Option<String>,
    pub cache_status: Option<String>,
    pub mitigated: Option<String>,
    pub has_cf_bm: bool,
    pub has_cf_clearance: bool,
    pub challenge: Option<String>,
    pub server_header: Option<String>,
}

pub async fn cloudflare(url: &str, cfg: &crate::config::Config) -> Result<CfReport, String> {
    let prof = crate::stealth::profile(&cfg.profile).ok_or("missing profile")?;
    let mut sess = crate::session::Session::new();
    let r = crate::session::navigate(url, cfg, &mut sess, &crate::session::WaitFor::default(), false, true).await?;
    let get = |k: &str| {
        sess.net
            .last()
            .and_then(|n| n.resp_headers.iter().find(|(a, _)| a.eq_ignore_ascii_case(k)))
            .map(|(_, v)| v.clone())
    };
    let server = get("server");
    let ray = get("cf-ray");
    let behind = server.as_deref().map(|s| s.eq_ignore_ascii_case("cloudflare")).unwrap_or(false)
        || ray.is_some()
        || get("cf-cache-status").is_some();
    let pop = ray.as_ref().and_then(|r| r.rsplit('-').next().map(str::to_string));
    let cookies: Vec<String> = sess.cookies.all().iter().map(|c| c.name.clone()).collect();
    Ok(CfReport {
        url: url.into(),
        final_url: r.final_url,
        status: r.status,
        behind_cloudflare: behind,
        ray,
        pop,
        cache_status: get("cf-cache-status"),
        mitigated: get("cf-mitigated"),
        has_cf_bm: cookies.iter().any(|c| c == "__cf_bm"),
        has_cf_clearance: cookies.iter().any(|c| c == "cf_clearance"),
        challenge: r.captcha,
        server_header: server,
    })
}

// ---------------------------------------------------------------------------
// TCP service scan (nmap-style connect scan + banner grab, no GUI).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortHit {
    pub port: u16,
    pub state: String,
    pub banner: String,
}

pub const TOP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
    6379, 8080, 8443, 27017, 27018,
];

/// TCP connect scan with banner grab. Sequential is polite but slow; bounded
/// concurrency (default 32) with per-port timeouts. Only scan hosts you are
/// authorized to test — this tool performs no authorization check itself.
pub async fn port_scan(host: &str, ports: &[u16], timeout_ms: u64, concurrency: usize) -> Result<Vec<PortHit>, String> {
    if ports.is_empty() || ports.len() > 200 {
        return Err("give 1–200 ports".into());
    }
    let host = host.to_string();
    let timeout = Duration::from_millis(timeout_ms.clamp(200, 10_000));
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.clamp(1, 64)));
    let mut tasks = vec![];
    for &port in ports {
        let h = host.clone();
        let permit = sem.clone().acquire_owned().await.map_err(|e| e.to_string())?;
        tasks.push(tokio::spawn(async move {
            let _p = permit;
            let addr = format!("{h}:{port}");
            let sock = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                _ => return PortHit { port, state: "closed".into(), banner: String::new() },
            };
            let banner = read_banner(sock).await;
            PortHit {
                port,
                state: "open".into(),
                banner: banner.chars().take(160).collect(),
            }
        }));
    }
    let mut out = vec![];
    for t in tasks {
        out.push(t.await.map_err(|e| e.to_string())?);
    }
    out.sort_by_key(|h: &PortHit| h.port);
    Ok(out)
}

async fn read_banner(mut sock: tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_millis(2000), sock.read(&mut buf))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).trim().to_string()
}

// ---------------------------------------------------------------------------
// Payload injection testing: __PAYLOAD__ marker substitution + reflection evidence.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectHit {
    pub payload: String,
    pub status: u16,
    pub bytes: usize,
    pub reflected: bool,
    pub evidence: String,
}

/// Replace every `__PAYLOAD__` marker in the URL template (and optional body /
/// header templates) with each payload, send, and report reflection evidence.
/// Sequential and non-destructive by construction: it only issues the requests
/// you describe. Use only against systems you are authorized to test.
pub async fn inject(
    cfg: &crate::config::Config,
    url_template: &str,
    method: &str,
    body_template: Option<&str>,
    header_templates: &[(String, String)],
    payloads: &[String],
) -> Result<Vec<InjectHit>, String> {
    if !url_template.contains("__PAYLOAD__")
        && body_template.map(|b| !b.contains("__PAYLOAD__")).unwrap_or(true)
        && !header_templates.iter().any(|(_, v)| v.contains("__PAYLOAD__"))
    {
        return Err("no __PAYLOAD__ marker in url, body, or headers".into());
    }
    if payloads.is_empty() || payloads.len() > 50 {
        return Err("give 1–50 payloads".into());
    }
    let prof = crate::stealth::profile(&cfg.profile).ok_or("missing profile")?;
    let client = crate::net::client(cfg)?;
    let mut out = vec![];
    for p in payloads {
        let url = url_template.replace("__PAYLOAD__", p);
        let req = if method.eq_ignore_ascii_case("POST") {
            let mut r = client.post(&url);
            if let Some(b) = body_template {
                r = r.body(b.replace("__PAYLOAD__", p));
            }
            r
        } else {
            client.get(&url)
        };
        let mut req = req;
        for (k, v) in crate::stealth::headers(prof, None) {
            req = req.header(k, v.replace("__PAYLOAD__", p));
        }
        for (k, v) in header_templates {
            req = req.header(k.as_str(), v.replace("__PAYLOAD__", p));
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let (reflected, evidence) = reflection(&body, p);
                out.push(InjectHit {
                    payload: p.clone(),
                    status,
                    bytes: body.len(),
                    reflected,
                    evidence,
                });
            }
            Err(e) => out.push(InjectHit {
                payload: p.clone(),
                status: 0,
                bytes: 0,
                reflected: false,
                evidence: format!("request failed: {}", crate::net::err_msg(&e)),
            }),
        }
    }
    Ok(out)
}

/// Reflection evidence: the payload (raw or URL-encoded) echoed in the body,
/// with a bounded context window. Reflection alone is not a vulnerability.
fn reflection(body: &str, payload: &str) -> (bool, String) {
    for cand in [payload.to_string(), urlencode(payload)] {
        if cand.len() > 2 && body.contains(&cand) {
            let i = body.find(&cand).unwrap_or(0);
            let s = i.saturating_sub(40);
            let e = (i + cand.len() + 40).min(body.len());
            return (true, body[s..e].replace('\n', " "));
        }
    }
    (false, String::new())
}

fn urlencode(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' | b'_' | b'.' | b'~' => o.push(*b as char),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}
