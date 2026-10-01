//! Cấu hình. Mọi thứ mặc định là riêng tư: không log, không persist, DoH bật.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Cổng JSON-RPC. Mặc định chỉ bind localhost — không ai ngoài máy này gọi được.
    pub listen: String,
    pub profile: String,
    /// Đường dẫn profile mã hoá. None = không lưu gì cả (mặc định).
    pub vault: Option<String>,
    pub proxy: Option<String>,
    pub doh: String,
    pub max_tabs: usize,
    pub max_ram_mb: usize,
    /// Tắt mọi hook plugin mà không cần uninstall.
    pub kill_switch: bool,
    /// Cho phép session ghi cookie/storage xuống đĩa. Mặc định false.
    pub persist: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7070".into(),
            profile: "chrome".into(),
            vault: None,
            proxy: None,
            doh: "https://cloudflare-dns.com/dns-query".into(),
            max_tabs: 8,
            max_ram_mb: 512,
            kill_switch: false,
            persist: false,
        }
    }
}

impl Config {
    /// Đọc config, sau đó cho phép override từ config file.
    /// Không bao giờ tự ghi file — người dùng kiểm soát, không có phone-home.
    pub fn load(path: Option<&std::path::Path>) -> Self {
        let mut cfg = Config::default();
        if let Some(p) = path
            && let Ok(s) = std::fs::read_to_string(p)
            && let Ok(v) = serde_json::from_str::<Config>(&s)
        {
            cfg = v;
        }
        cfg
    }
}