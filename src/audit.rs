//! Security analyzer — evidence-driven, no fake detectors.
//!
//! Every finding carries RAW evidence taken from the response (header, cookie,
//! body). Every "find CVE/tool" flow only reports: a real pattern match → the
//! source URL → a human checks. It never guesses versions, never constructs
//! vulnerabilities, never fakes severity.
//!
//! Scope: what can be analysed statically or from a single fetch. No destructive
//! scanning, no brute force. Only use it on resources you are allowed to touch.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Audit {
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub findings: Vec<Finding>,
    pub missing_headers: Vec<&'static str>,
    pub cookies: Vec<CookieBrief>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub level: &'static str, // info | warn | risk
    pub title: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieBrief {
    pub name: String,
    pub host_only: bool,
    pub visible_to_js: bool,
    pub path: String,
}

const STRICT_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
];

pub fn audit_from(final_url: &str, status: u16, headers: &[(String, String)], body: &str, cookies: &[crate::fetch::Cookie]) -> Audit {
    let mut findings = Vec::new();
    let h = |k: &str| headers.iter().find(|(a, _)| a.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone());

    for want in STRICT_HEADERS {
        if h(want).is_none() {
            findings.push(Finding { level: "warn", title: format!("missing security header: {want}"), evidence: format!("no `{want}` header") });
        }
    }
    if let Some(csp) = h("content-security-policy") {
        if csp.contains("unsafe-inline") || csp.contains("unsafe-eval") {
            findings.push(Finding { level: "risk", title: "CSP allows unsafe-*".into(), evidence: csp });
        } else if csp.contains("*") {
            findings.push(Finding { level: "info", title: "CSP uses a wildcard".into(), evidence: csp });
        }
    }
    if let Some(acao) = h("access-control-allow-origin")
        && acao == "*" {
            findings.push(Finding { level: "risk", title: "CORS allows every origin".into(), evidence: format!("access-control-allow-origin: {acao}") });
        }
    for c in cookies {
        if !c.host_only {
            findings.push(Finding { level: "info", title: format!("broad cookie domain: {}", c.name), evidence: format!("cookie `{}` covers many subdomains", c.name) });
        }
    }
    // Traces in the body: admin/internal endpoints, sample key/token leaks, debug comments.
    for n in ["/.git", "/admin", "/wp-admin", "/.env", "api_key=", "password=", "console.log("] {
        if body.contains(n) {
            findings.push(Finding { level: "info", title: format!("body contains `{n}`"), evidence: format!("appears in the HTML — verify manually, may be a false positive") });
        }
    }
    // Regex evidence: CVE ids and API endpoints in the source/JS bundle.
    if let Ok(re) = regex::Regex::new(r"CVE-\d{4}-\d{4,7}") {
        for m in re.find_iter(body).take(5) {
            findings.push(Finding { level: "info", title: format!("reference to {} in the source", m.as_str()), evidence: format!("literal `{}` found — does NOT mean this site is affected, check NVD", m.as_str()) });
        }
    }
    if let Ok(re) = regex::Regex::new(r#"/(?:api|v[0-9]+/api)/[A-Za-z0-9_\-./]+"#) {
        let mut seen = std::collections::HashSet::new();
        for m in re.find_iter(body).map(|m| m.as_str()).filter(|s| seen.insert(*s)).take(8) {
            findings.push(Finding { level: "info", title: "endpoint found in the source".into(), evidence: m.into() });
        }
    }

    let missing_headers: Vec<&'static str> = STRICT_HEADERS.iter().copied().filter(|w| h(w).is_none()).collect();
    let cookies = cookies.iter().map(|c| CookieBrief { name: c.name.clone(), host_only: c.host_only, visible_to_js: c.visible_to_js, path: c.path.clone() }).collect();
    Audit { url: String::new(), final_url: final_url.into(), status, findings, missing_headers, cookies }
}
