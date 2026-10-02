//! F1stmux — headless browser cho AI, thiết kế Termux.
//!
//! Binary duy nhất. `f1stmux` vừa là CLI vừa là daemon (subcommand `serve`).
//!
//! Cam kết: không telemetry, không phone-home, không ghi log mặc định. Session
//! mặc định chỉ tồn tại trong RAM — thoát là mất sạch dấu vết.

pub mod blocklist;
pub mod challenge;
pub mod cli;
pub mod config;
pub mod dom;
pub mod fetch;
pub mod htmlparse;
pub mod inspector;
pub mod jsenv;
pub mod mcp;
pub mod net;
pub mod plugin;
pub mod rpc;
pub mod session;
pub mod stealth;
pub mod tools;
pub mod vault;

pub use config::Config;
pub use session::Session;