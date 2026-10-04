//! F1stmux — a headless browser for AI, built for Termux.
//!
//! A single binary. `f1stmux` is both the CLI and the daemon (subcommand `serve`).
//!
//! Commitments: no telemetry, no phone-home, no logging by default. Sessions
//! live in RAM only by default — exit and every trace is gone.

pub mod blocklist;
pub mod audit;
pub mod bookmarks;
pub mod challenge;
pub mod recon;
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