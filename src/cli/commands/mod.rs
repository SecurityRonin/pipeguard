//! CLI command implementations.
//!
//! Each submodule implements one top-level CLI command (scan, update,
//! rules, config, install).

pub mod config;
pub mod install;
pub mod rules;
pub mod scan;
pub mod update;

pub use config::cmd_config;
pub use install::cmd_install;
pub use rules::cmd_rules;
pub use scan::cmd_scan;
pub use update::cmd_update;
