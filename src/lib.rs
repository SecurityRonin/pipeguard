//! PipeGuard — defend against malicious `curl | bash` attacks.
//!
//! Provides multi-layer threat detection using YARA rules, signed rule
//! updates, and shell integration to intercept dangerous piped commands.

pub mod cli;
pub mod config;
pub mod detection;
pub mod logging;
pub mod update;
