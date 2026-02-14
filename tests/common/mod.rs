//! Shared test utilities for PipeGuard integration tests.
//!
//! Provides common helpers used across detection test files to eliminate
//! boilerplate around building scan commands and asserting results.

use assert_cmd::assert::Assert;
use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

/// Returns a `Command` configured to run the `pipeguard` binary.
#[allow(dead_code, deprecated)]
pub fn pipeguard_cmd() -> Command {
    Command::cargo_bin("pipeguard").unwrap()
}

/// Returns the path to the core YARA rules file.
#[allow(dead_code)]
pub fn core_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/core.yar")
}

/// Builds a scan command that reads from stdin, executes it, and returns the `Assert`.
///
/// This is the base helper that `assert_detects` and `assert_clean` build upon.
#[allow(dead_code)]
pub fn scan_stdin(input: &str) -> Assert {
    pipeguard_cmd()
        .arg("scan")
        .arg("--rules")
        .arg(core_rules_path())
        .write_stdin(input)
        .assert()
}

/// Asserts that the given input is detected as a threat (non-zero exit code).
#[allow(dead_code)]
pub fn assert_detects(input: &str) {
    scan_stdin(input).failure();
}

/// Asserts that the given input is clean (zero exit code, "No threats" in output).
#[allow(dead_code)]
pub fn assert_clean(input: &str) {
    scan_stdin(input)
        .success()
        .stdout(predicate::str::contains("No threats"));
}

/// Asserts that the given input is detected as a High-severity threat.
#[allow(dead_code)]
pub fn assert_detects_high(input: &str) {
    scan_stdin(input)
        .failure()
        .stdout(predicate::str::contains("High"));
}
