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
    /// Cho phép bind địa chỉ không phải loopback. Mặc định false: daemon không
    /// auth nên bind remote mà không tường minh là tự mở cửa cho cả mạng.
    pub allow_remote: bool,
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
            allow_remote: false,
        }
    }
}

impl Config {
    /// Đọc config, sau đó cho phép override từ config file.
    /// Không bao giờ tự ghi file — người dùng kiểm soát, không có phone-home.
    /// File lỗi thì BÁO ra stderr chứ không lặng lẽ dùng default (trước đây lỗi
    /// parse là rơi về default mà không ai biết — gồm cả lỗi bảo mật).
    pub fn load(path: Option<&std::path::Path>) -> Self {
        let mut cfg = Config::default();
        if let Some(p) = path {
            match std::fs::read_to_string(p) {
                Ok(s) => match serde_json::from_str::<Config>(&s) {
                    Ok(v) => cfg = v,
                    Err(e) => eprintln!("cảnh báo: config {} lỗi parse ({e}), dùng mặc định", p.display()),
                },
                Err(e) => eprintln!("cảnh báo: không đọc được config {} ({e}), dùng mặc định", p.display()),
            }
        }
        cfg
    }

    /// true nếu listen trỏ ra ngoài loopback.
    pub fn is_remote_bind(&self) -> bool {
        let addr = self.listen.trim();
        let host = if let Some(rest) = addr.strip_prefix('[') {
            rest.split(']').next().unwrap_or(rest)
        } else {
            addr.rsplit(':').nth(1).unwrap_or(addr)
        };
        let host = host.to_ascii_lowercase();
        !(host == "127.0.0.1" || host == "localhost" || host == "::1")
    }
}