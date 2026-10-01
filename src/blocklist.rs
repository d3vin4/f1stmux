//! Blocklist — chặn tracker/ad và WebRTC ở tầng request.
//!
//! Cố ý nhỏ: bốn dạng rule, một parser, không phải engine AdGuard đầy đủ.
//! Một engine ABP đúng nghĩa là hàng nghìn dòng cho thứ mà 60 domain + vài rule
//! path đã cắt được phần lớn rủi ro. Thêm khi thật sự cần, không thêm trước.
//!
//! Dạng rule được hỗ trợ (và chỉ bốn):
//! - `||host^`      khớp host và mọi subdomain của nó
//! - `|http://`     khớp tiền tố scheme của URL
//! - `/ads/`        khớp chuỗi con trong path
//! - `@@` + một trong ba dạng trên = allowlist, thắng mọi rule chặn.
//! Dòng rỗng, `#`/`!` là comment. Dòng không khớp dạng nào bị bỏ qua.

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
    /// Chặn nhưng trả về payload rỗng từ cache nội bộ với kích thước cho trước.
    Redirect(u64),
}

/// Scheme bị chặn: WebRTC (stun/turn/rtc) và WebSocket (ws/wss).
///
/// WebRTC không có API nào lộ ra cho JS ở đây, nên đây là lớp phòng thủ cuối: nếu
/// một tầng khác (plugin, script tự dựng) tạo URL `stun:`/`wss:`, nó dừng ở đây.
/// `file:`/`data:`/`javascript:` không cần khoá ở đây — allowlist http/https của
/// `fetch` đã lo rồi.
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

/// `a.example.com` khớp `example.com` và `www.example.com`, nhưng không khớp
/// `notexample.com`.
fn domain_match(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

/// Parse một dòng rule. `None` = comment hoặc không thuộc bốn dạng hỗ trợ.
/// Công khai để tool nạp rule có thể báo dòng nào sai trước khi nuốt im lặng.
pub fn parse_rule(line: &str) -> Option<Rule> {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') || s.starts_with('!') {
        return None;
    }
    let s = s.strip_prefix("@@").unwrap_or(s).trim();
    if let Some(host) = s.strip_prefix("||") {
        // `^` trong ABP là separator, không phải ký tự cần khớp.
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

    /// Nạp rule từ text (mỗi dòng một rule). Dòng lỗi bị bỏ qua — không có kênh
    /// báo lỗi ở đây; nếu cần kiểm tra thì gọi `parse_rule` trước.
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

    /// Quyết định cho một URL. Thứ tự: scheme bị cấm → allowlist → rule chặn →
    /// policy mặc định (tracker/ad ở dạng script hoặc XHR).
    ///
    /// Policy mặc định KHÔNG chặn `Document`: chặn nó thì trình duyệt chỉ ra
    /// trang trắng, mà người dùng cần nhìn trang để tự quyết có chặn tiếp không.
    /// Tải tracker vẫn xảy ra ở tài nguyên phụ — đó là đánh đổi đã chọn.
    pub fn decide(&self, url: &str, kind: ResourceKind) -> Decision {
        let Ok(u) = reqwest::Url::parse(url) else {
            return Decision::Block { rule: format!("URL không phân giải được: {url}") };
        };
        if is_blocked_scheme(u.scheme()) {
            return Decision::Block { rule: format!("scheme bị cấm: {}:", u.scheme()) };
        }
        if self.allow.iter().any(|e| e.rule.hits(&u)) {
            return Decision::Allow;
        }
        if let Some(e) = self.block.iter().find(|e| e.rule.hits(&u)) {
            return Decision::Block { rule: e.text.clone() };
        }
        let host = u.host_str().unwrap_or("").to_ascii_lowercase();
        if matches!(kind, ResourceKind::Script | ResourceKind::Xhr) && is_tracker(&host) {
            return Decision::Block { rule: format!("tracker mặc định: {host}") };
        }
        Decision::Allow
    }
}

/// Danh sách tracker mặc định. Không phải EasyPrivacy — chỉ những domain đo được
/// là phần lớn đòn bẩy fingerprint/ads trên web phổ biến. Danh sách đầy đủ nên
/// là file do người dùng nạp qua `add_rules`, không nhúng trong binary.
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
        // Subdomain + 1-hop redirect sang domain khác vẫn bị chặn.
        assert!(matches!(d("https://a.b.doubleclick.net/pixel", ResourceKind::Script), Decision::Block { .. }));
        // Ảnh thì để qua (nhiều site dùng domain tên trùng tracker).
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
        // "downloads" chứa chuỗi "ads" — đây là lý do giữ cả hai dấu "/" trong rule.
        assert!(matches!(b.decide("https://cdn.example/downloads/x.zip", ResourceKind::Other), Decision::Allow));

        let mut b = Blocklist::new();
        b.add_rules("||ads.example^\n");
        assert!(matches!(b.decide("https://notads.example/x", ResourceKind::Xhr), Decision::Allow));
        assert!(matches!(b.decide("https://ads.example.co/x", ResourceKind::Xhr), Decision::Allow));
    }
}
