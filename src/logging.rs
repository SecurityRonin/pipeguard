//! Centralized structured logging configuration.
//!
//! User-facing output stays on stdout via `println!`. Operational telemetry
//! (what the tool is doing, timing, diagnostics) goes to stderr via tracing.

use thiserror::Error;
use tracing::Level;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LogFormat {
    /// Human-readable colored output
    Pretty,
    /// Structured JSON lines
    Json,
}

/// Errors from logging initialization.
#[derive(Error, Debug)]
pub enum LogInitError {
    #[error("Failed to parse log filter: {0}")]
    FilterError(String),

    #[error("Failed to set global subscriber: {0}")]
    SetGlobalError(String),
}

/// Initialize the global tracing subscriber.
///
/// `RUST_LOG` env var overrides the provided level when set.
/// All output is directed to **stderr** so stdout remains clean for scan results.
pub fn init(level: Level, format: LogFormat) -> Result<(), LogInitError> {
    let filter = build_env_filter(level)?;

    match format {
        LogFormat::Pretty => {
            let subscriber = tracing_subscriber::registry().with(filter).with(
                fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_target(true)
                    .with_thread_ids(false)
                    .with_thread_names(false),
            );
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|e| LogInitError::SetGlobalError(e.to_string()))?;
        }
        LogFormat::Json => {
            let subscriber = tracing_subscriber::registry().with(filter).with(
                fmt::layer()
                    .json()
                    .with_writer(std::io::stderr)
                    .with_target(true)
                    .with_thread_ids(false)
                    .with_thread_names(false),
            );
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|e| LogInitError::SetGlobalError(e.to_string()))?;
        }
    }

    Ok(())
}

fn build_env_filter(level: Level) -> Result<EnvFilter, LogInitError> {
    // RUST_LOG overrides the CLI-provided level when set
    let filter_str = std::env::var("RUST_LOG").unwrap_or_else(|_| level.to_string());
    EnvFilter::try_new(&filter_str).map_err(|e| LogInitError::FilterError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;

    #[test]
    fn build_env_filter_pretty_succeeds() {
        let filter = build_env_filter(Level::DEBUG);
        assert!(filter.is_ok(), "Pretty filter should build successfully");
    }

    #[test]
    fn build_env_filter_for_json_level() {
        let filter = build_env_filter(Level::INFO);
        assert!(filter.is_ok(), "JSON filter should build successfully");
    }

    #[test]
    fn env_filter_respects_level() {
        // Temporarily unset RUST_LOG so the level is used directly
        let prev = std::env::var("RUST_LOG").ok();
        std::env::remove_var("RUST_LOG");

        let filter = build_env_filter(Level::DEBUG).unwrap();
        let filter_str = format!("{}", filter);
        assert!(
            filter_str.contains("debug") || filter_str.contains("DEBUG"),
            "Filter should contain the debug level, got: {}",
            filter_str
        );

        // Restore
        if let Some(val) = prev {
            std::env::set_var("RUST_LOG", val);
        }
    }

    #[test]
    fn log_format_variants() {
        // Ensure both variants exist and are distinct
        assert_ne!(LogFormat::Pretty, LogFormat::Json);
    }
}
