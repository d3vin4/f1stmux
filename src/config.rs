//! Configuration. Everything defaults to private: no logs, no persistence, DoH on.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// JSON-RPC port. Defaults to localhost only — nothing outside this machine can call it.
    pub listen: String,
    pub profile: String,
    /// Path to the encrypted profile store. None = store nothing (the default).
    pub vault: Option<String>,
    pub proxy: Option<String>,
    pub doh: String,
    pub max_tabs: usize,
    pub max_ram_mb: usize,
    /// Disable every plugin hook without uninstalling.
    pub kill_switch: bool,
    /// Allow the session to write cookies/storage to disk. Defaults to false.
    pub persist: bool,
    /// Allow binding a non-loopback address. Defaults to false: the daemon has no
    /// auth, so binding a remote address without saying so is opening the door to the whole network.
    pub allow_remote: bool,
    /// Engine: fast | chromium | auto. Chromium needs a CDP endpoint
    /// (F1STCHROME_CDP=host:port or a local chrome-headless-shell binary).
    pub engine: String,
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
            engine: "fast".into(),
        }
    }
}

impl Config {
    /// Read the config, then allow overrides from the config file.
    /// Never writes a file on its own — the user stays in control, no phone-home.
    /// A broken file is REPORTED on stderr instead of silently falling back to
    /// defaults (previously a parse error fell back silently — including security errors).
    pub fn load(path: Option<&std::path::Path>) -> Self {
        let mut cfg = Config::default();
        if let Some(p) = path {
            match std::fs::read_to_string(p) {
                Ok(s) => match serde_json::from_str::<Config>(&s) {
                    Ok(v) => cfg = v,
                    Err(e) => eprintln!("warning: config {} failed to parse ({e}), using defaults", p.display()),
                },
                Err(e) => eprintln!("warning: cannot read config {} ({e}), using defaults", p.display()),
            }
        }
        cfg
    }

    /// true if listen points outside loopback.
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