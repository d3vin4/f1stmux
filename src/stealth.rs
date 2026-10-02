//! Browser identity profiles.
//!
//! Principle: a profile must be *internally consistent*. The worst signal is not
//! "faked wrong", it is "faked halfway" — Edge UA but Chrome headers, Tokyo
//! timezone but a US locale. Each profile bundles UA + header order + client
//! hints + screen + timezone + locale + concurrency in one place so they cannot drift apart.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Profile {
    pub name: &'static str,
    pub ua: &'static str,
    /// Header order. A real browser sends a fixed order; the wrong order is a tell.
    pub header_order: &'static [&'static str],
    pub sec_ch_ua: &'static str,
    pub platform: &'static str,
    pub accept_language: &'static str,
    pub timezone: &'static str,
    pub screen: (u32, u32),
    pub hardware_concurrency: u32,
    pub device_memory: u32,
    pub webrtc: bool,
}

static CHROME_ORDER: &[&str] = &[
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
    "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
    "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie",
];

static CHROME_131: &str = "\"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\", \"Not_A Brand\";v=\"24\"";

static PROFILES: &[Profile] = &[
    Profile {
        name: "chrome",
        ua: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        header_order: CHROME_ORDER,
        sec_ch_ua: CHROME_131,
        platform: "\"Android\"",
        accept_language: "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
        timezone: "Asia/Ho_Chi_Minh",
        screen: (412, 915),
        hardware_concurrency: 8,
        device_memory: 8,
        webrtc: false,
    },
    Profile {
        name: "edge",
        ua: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 EdgA/131.0.0.0",
        header_order: CHROME_ORDER,
        sec_ch_ua: CHROME_131,
        platform: "\"Android\"",
        accept_language: "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
        timezone: "Asia/Ho_Chi_Minh",
        screen: (412, 915),
        hardware_concurrency: 8,
        device_memory: 8,
        webrtc: false,
    },
    Profile {
        name: "brave",
        ua: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        header_order: CHROME_ORDER,
        sec_ch_ua: CHROME_131,
        platform: "\"Android\"",
        accept_language: "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
        timezone: "Asia/Ho_Chi_Minh",
        screen: (412, 915),
        hardware_concurrency: 8,
        device_memory: 8,
        webrtc: false,
    },
];

pub fn profile(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.name == name)
}

pub fn names() -> Vec<&'static str> {
    PROFILES.iter().map(|p| p.name).collect()
}

/// Headers in the exact profile order. Security: this is the easiest fingerprint to spot.
pub fn headers(p: &Profile, referer: Option<&str>) -> Vec<(&'static str, String)> {
    let mut h: Vec<(&'static str, String)> = vec![
        ("sec-ch-ua", p.sec_ch_ua.into()),
        ("sec-ch-ua-mobile", "?0".into()),
        ("sec-ch-ua-platform", p.platform.into()),
        ("upgrade-insecure-requests", "1".into()),
        ("user-agent", p.ua.into()),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8".into()),
        ("sec-fetch-site", "none".into()),
        ("sec-fetch-mode", "navigate".into()),
        ("sec-fetch-user", "?1".into()),
        ("sec-fetch-dest", "document".into()),
        ("accept-encoding", "gzip, deflate, br".into()),
        ("accept-language", p.accept_language.into()),
    ];
    if let Some(r) = referer {
        h.push(("referer", r.into()));
    }
    let mut out = Vec::new();
    for k in p.header_order {
        if let Some((_, v)) = h.iter().find(|(hk, _)| hk == k) {
            out.push((*k, v.clone()));
        }
    }
    out
}