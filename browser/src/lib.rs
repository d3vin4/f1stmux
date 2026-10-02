//! Browser backend abstraction.
//!
//! Fast engine: implementation-native F1stmux engine, no layout, QuickJS subset.
//! Chromium backend: attach a real browser over CDP (chrome-headless-shell or any
//! Chromium accepting --remote-debugging-port). Auto: choose Chromium when the
//! page needs layout/APIs; else Fast. Everything above this crate stays the same.

pub mod cdp;

pub use cdp::CdpClient;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    Fast,
    Chromium,
    Auto,
}

impl EngineKind {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "fast" | "light" | "quick" => EngineKind::Fast,
            "chromium" | "browser" | "chrome" | "full" | "cdp" => EngineKind::Chromium,
            _ => EngineKind::Auto,
        }
    }
}

/// Minimal browser surface. The Fast engine leaves most methods unimplemented
/// rather than faking them; Chromium implements the full set through CDP.
pub trait Browser {
    fn navigate(&mut self, url: &str) -> Result<Page, String>;
    fn evaluate(&mut self, src: &str) -> Result<serde_json::Value, String>;
    fn screenshot(&mut self) -> Result<Vec<u8>, String> {
        Err("Fast engine không có layout; screenshot cần --engine chromium".into())
    }
    fn html(&mut self) -> Result<String, String>;
    fn text(&mut self) -> Result<String, String>;
}

pub struct Page {
    pub url: String,
    pub status: Option<u16>,
    pub title: String,
    pub html: String,
    pub text: String,
}

/// Fast engine: wraps the existing in-memory runtime.
pub struct FastBrowser<F> { inner: F }

impl<F> FastBrowser<F> { pub fn new(inner: F) -> Self { Self { inner } } }

impl<F> Browser for FastBrowser<F>
where
    F: FnMut(&str) -> Result<Page, String>,
{
    fn navigate(&mut self, url: &str) -> Result<Page, String> { (self.inner)(url) }
    fn evaluate(&mut self, _src: &str) -> Result<serde_json::Value, String> {
        Err("Fast engine chưa expose evaluate; dùng eval_js tool của f1stmux".into())
    }
    fn html(&mut self) -> Result<String, String> { Err("không có page".into()) }
    fn text(&mut self) -> Result<String, String> { Err("không có page".into()) }
}
