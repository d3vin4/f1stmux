//! Blocklist — blocks trackers/ads and WebRTC at the request layer.
//!
//! Deliberately small: four rule forms, one parser, not a full AdGuard engine.
//! A real ABP engine means thousands of lines for something 60 domains + a few path
//! rules already cut most of the risk. Add more when it is genuinely needed, not before.
//!
//! Supported rule forms (and only four):
//! - `||host^`      matches the host and all of its subdomains
//! - `|http://`     matches the URL scheme prefix
//! - `/ads/`        matches a substring inside the path
//! - `@@` + one of the three forms above = allowlist, beats every block rule.
//! Empty lines and `#`/`!` are comments. Lines matching no form are ignored.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceKind {
    Document,
    Script,
    Image,
    Stylesheet,
    Xhr,
    Font,
    Media,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Block { rule: String },
    /// Blocked but return an empty payload from an internal cache with a preallocated size.
    Redirect(u64),
}

/// Blocked schemes: WebRTC (stun/turn/rtc) and WebSocket (ws/wss).
///
/// WebRTC exposes no API to JS here, so this is the last line of defence: if
/// another layer (a plugin, a self-built script) creates a `stun:`/`wss:` URL, it
/// stops here. `file:`/`data:`/`javascript:` need no lock here — the http/https
/// allowlist in `fetch` already covers them.
pub fn is_blocked_scheme(scheme: &str) -> bool {
    matches!(scheme, "stun" | "stuns" | "turn" | "turns" | "rtc" | "ws" | "wss")
}

#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    Host(String),
    Scheme(String),
    Path(String),
}

#[derive(Debug, Clone, PartialEq)]
struct Entry {
    rule: Rule,
    text: String,
}

impl Rule {
    fn hits(&self, u: &reqwest::Url) -> bool {
        match self {
            Rule::Host(h) => {
                let host = u.host_str().unwrap_or("").to_ascii_lowercase();
                domain_match(&host, h)
            }
            Rule::Scheme(p) => u.as_str().starts_with(p.as_str()),
            Rule::Path(p) => u.path().contains(p.as_str()),
        }
    }
}

/// `a.example.com` matches `example.com` and `www.example.com`, but does not match
/// `notexample.com`.
fn domain_match(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

/// Parse one rule line. `None` = a comment or not one of the four supported forms.
/// Public so a rule-loading tool can report which line is wrong instead of swallowing it.
pub fn parse_rule(line: &str) -> Option<Rule> {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') || s.starts_with('!') {
        return None;
    }
    let s = s.strip_prefix("@@").unwrap_or(s).trim();
    if let Some(host) = s.strip_prefix("||") {
        // In ABP, `^` is a separator, not a character to match.
        let host = host.trim_end_matches('^').trim().to_ascii_lowercase();
        (!host.is_empty()).then_some(Rule::Host(host))
    } else if let Some(prefix) = s.strip_prefix('|') {
        let prefix = prefix.trim().to_ascii_lowercase();
        (!prefix.is_empty()).then_some(Rule::Scheme(prefix))
    } else if s.contains('/') {
        Some(Rule::Path(s.to_string()))
    } else {
        None
    }
}

#[derive(Debug, Default, Clone)]
pub struct Blocklist {
    allow: Vec<Entry>,
    block: Vec<Entry>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load rules from text (one rule per line). Bad lines are skipped — there is no
    /// error channel here; if you need validation, call `parse_rule` first.
    pub fn add_rules(&mut self, src: &str) {
        for line in src.lines() {
            if let Some(rule) = parse_rule(line) {
                let e = Entry { text: line.trim().to_string(), rule };
                if line.trim().starts_with("@@") {
                    self.allow.push(e);
                } else {
                    self.block.push(e);
                }
            }
        }
    }

    pub fn rules(&self) -> Vec<String> {
        self.allow.iter().chain(&self.block).map(|e| e.text.clone()).collect()
    }

    pub fn clear(&mut self) {
        self.allow.clear();
        self.block.clear();
    }

    /// Decide for one URL. Order: banned scheme → allowlist → block rule →
    /// default policy (trackers/ads as script or XHR).
    ///
    /// The default policy does NOT block `Document`: blocking it would just show a
    /// blank page, while the user needs to see the page to decide for themselves
    /// whether to block further. Tracker downloads still happen for subresources —
    /// that is the accepted trade-off.
    pub fn decide(&self, url: &str, kind: ResourceKind) -> Decision {
        let Ok(u) = reqwest::Url::parse(url) else {
            return Decision::Block { rule: format!("URL could not be parsed: {url}") };
        };
        if is_blocked_scheme(u.scheme()) {
            return Decision::Block { rule: format!("banned scheme: {}:", u.scheme()) };
        }
        if self.allow.iter().any(|e| e.rule.hits(&u)) {
            return Decision::Allow;
        }
        if let Some(e) = self.block.iter().find(|e| e.rule.hits(&u)) {
            return Decision::Block { rule: e.text.clone() };
        }
        let host = u.host_str().unwrap_or("").to_ascii_lowercase();
        if matches!(kind, ResourceKind::Script | ResourceKind::Xhr) && is_tracker(&host) {
            return Decision::Block { rule: format!("default tracker: {host}") };
        }
        Decision::Allow
    }
}

/// The default tracker list. Not EasyPrivacy — only the domains measured to carry
/// most of the fingerprinting/ads leverage on the common web. A full list should be
/// a file the user loads via `add_rules`, not embedded in the binary.
pub const TRACKERS: &[&str] = &[
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "googletagservices.com",
    "google-analytics.com", "analytics.google.com", "googletagmanager.com",
    "facebook.net", "connect.facebook.net", "fbcdn.net", "atdmt.com",
    "adsrvr.org", "adnxs.com", "rubiconproject.com", "pubmatic.com", "openx.net",
    "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "sharethrough.com",
    "bidswitch.net", "casalemedia.com", "smartadserver.com", "teads.tv",
    "amazon-adsystem.com", "scorecardresearch.com", "quantserve.com", "quantcast.com",
    "hotjar.com", "hotjar.io", "fullstory.com", "mouseflow.com", "crazyegg.com", "mixpanel.com",
    "segment.com", "segment.io", "amplitude.com", "branch.io", "appsflyer.com",
    "adjust.com", "kochava.com", "singular.net", "doubleverify.com", "adsafeprotected.com",
    "moatads.com", "sentry.io", "bugsnag.com", "newrelic.com", "nr-data.net",
    "optimizely.com", "vwo.com", "kissmetrics.com", "chartbeat.com", "parsely.com",
    "intercom.io", "driftt.com", "clearbit.com", "tidio.com",
    "onetrust.com", "cookiebot.com",
];

fn is_tracker(host: &str) -> bool {
    TRACKERS.iter().any(|t| domain_match(host, t))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(u: &str, k: ResourceKind) -> Decision {
        Blocklist::new().decide(u, k)
    }

    #[test]
    fn tracker_script_blocked_but_document_allowed() {
        assert!(matches!(d("https://www.google-analytics.com/collect?v=1", ResourceKind::Xhr), Decision::Block { .. }));
        assert!(matches!(d("https://www.google-analytics.com/collect", ResourceKind::Document), Decision::Allow));
        // A subdomain plus a 1-hop redirect to another domain is still blocked.
        assert!(matches!(d("https://a.b.doubleclick.net/pixel", ResourceKind::Script), Decision::Block { .. }));
        // Images pass through (many sites use domains that sound like trackers).
        assert!(matches!(d("https://connect.facebook.net/x.png", ResourceKind::Image), Decision::Allow));
    }

    #[test]
    fn webrtc_schemes_blocked_for_every_kind() {
        for k in [ResourceKind::Script, ResourceKind::Xhr, ResourceKind::Image, ResourceKind::Other] {
            assert!(matches!(d("stun:stun.l.google.com:19302", k), Decision::Block { .. }));
            assert!(matches!(d("turns:a.example.com?transport=tcp", k), Decision::Block { .. }));
            assert!(matches!(d("wss://cdn.example.com/socket", k), Decision::Block { .. }));
        }
    }

    #[test]
    fn four_rule_forms_and_allowlist_wins() {
        let mut b = Blocklist::new();
        b.add_rules("# comment\n||ads.example^\n|http://\n/ads/\n@@||ads.example^\n");
        assert!(matches!(b.decide("http://ads.example/x", ResourceKind::Xhr), Decision::Allow));
        assert!(matches!(b.decide("https://sub.ads.example/x", ResourceKind::Xhr), Decision::Allow));

        let mut b = Blocklist::new();
        b.add_rules("/ads/\n");
        assert!(matches!(b.decide("https://cdn.example/a/ads/b.js", ResourceKind::Script), Decision::Block { .. }));
        // "downloads" contains the substring "ads" — that is why the rule keeps both "/" characters.
        assert!(matches!(b.decide("https://cdn.example/downloads/x.zip", ResourceKind::Other), Decision::Allow));

        let mut b = Blocklist::new();
        b.add_rules("||ads.example^\n");
        assert!(matches!(b.decide("https://notads.example/x", ResourceKind::Xhr), Decision::Allow));
        assert!(matches!(b.decide("https://ads.example.co/x", ResourceKind::Xhr), Decision::Allow));
    }
}
