# Plan: Centralized Structured Logging with TDD

## Context

PipeGuard has `tracing = "0.1"` and `tracing-subscriber = "0.3"` declared in `Cargo.toml` but **completely unused** — zero tracing macros anywhere in `src/`. All output uses `println!`/`eprintln!` with `colored`. No `--log-level` or `--verbose` CLI flags exist. This plan adds centralized structured logging via the existing tracing dependencies, following TDD (tests first, then implementation).

**Key principle**: User-facing output (scan results, status messages) stays as `println!` on stdout. Operational telemetry (what the tool is doing, timing, diagnostics) goes to stderr via tracing.

---

## Step 1: Enable tracing-subscriber features

**File**: `Cargo.toml` (line 46)

Change `tracing-subscriber = "0.3"` to:
```toml
tracing-subscriber = { version = "0.3", features = ["fmt", "env-filter", "json"] }
```

- `fmt` — formatted output layer
- `env-filter` — `EnvFilter` for level control + `RUST_LOG` override
- `json` — structured JSON log format

---

## Step 2: Create logging module (TDD — tests first)

**New file**: `src/logging.rs`

Public API:
- `LogFormat` enum (`Pretty`, `Json`) — derives `clap::ValueEnum` for CLI reuse
- `LogInitError` — thiserror-based error type
- `init(level: Level, format: LogFormat) -> Result<(), LogInitError>` — sets global subscriber
- `build(level: Level, format: LogFormat) -> Result<impl Subscriber>` — builds without installing (for tests)

Implementation:
- Both formats write to **stderr** via `fmt::layer().with_writer(std::io::stderr)`
- `EnvFilter` constructed from `level` as default, respects `RUST_LOG` env var as override
- `Pretty` format uses colored output; `Json` format emits structured JSON lines

Unit tests (inline `#[cfg(test)]`):
- `build_pretty_subscriber` — returns Ok
- `build_json_subscriber` — returns Ok
- `env_filter_respects_level` — filter string contains the level

Register in `src/lib.rs` (line 4): add `pub mod logging;`

---

## Step 3: Add CLI flags (TDD — tests first)

**File**: `src/cli/args.rs`

Add to `Cli` struct (before `command` field):
```rust
#[arg(long, global = true, default_value = "warn")]
pub log_level: LogLevel,

#[arg(long, global = true, default_value = "pretty")]
pub log_format: crate::logging::LogFormat,
```

New `LogLevel` enum (in same file):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LogLevel { Error, Warn, Info, Debug, Trace }
```

Add `impl From<LogLevel> for tracing::Level`.

Unit tests (inline `#[cfg(test)]`):
- `cli_default_log_level_is_warn`
- `cli_accepts_log_level_debug`
- `cli_accepts_log_format_json`
- `cli_log_level_global_works_after_subcommand`

---

## Step 4: Wire up main.rs

**File**: `src/main.rs`

After `Cli::parse()`, before `run(cli)`:
```rust
if let Err(e) = pipeguard::logging::init(cli.log_level.into(), cli.log_format) {
    eprintln!("{}: Failed to initialize logging: {}", "Error".red().bold(), e);
    return ExitCode::FAILURE;
}
```

At the error handler (line 13), add companion tracing call:
```rust
tracing::error!(error = %e, "Command failed");
```

Update `run()` signature to accept individual fields (log_level/log_format consumed before dispatch).

---

## Step 5: Instrument scan pipeline (highest value)

**File**: `src/cli/commands/scan.rs`

Add structured spans and events alongside existing println! output:
- `info_span!("scan", rules_path, input_source)` wrapping entire function
- `debug!` after rules loaded (rule count)
- `debug!` after content read (content bytes, source)
- `info!` after scan complete (threat_level, match_count, content_hash, scan_duration_ms)

**File**: `src/detection/pipeline.rs`

- Add `pub fn rule_count(&self) -> usize` to `DetectionPipeline` (delegates to `self.scanner.rule_count()`)
- `debug_span!("analyze")` in `analyze()`
- `debug!` in `from_rules_dir()` for each .yar file loaded + total rule count

**File**: `src/detection/scanner.rs`

- `debug_span!("yara_scan", rule_count)` in `scan()`
- `debug!` for scan start/complete with match count

---

## Step 6: Instrument remaining commands (lighter touch)

Add `info!`/`debug!` events alongside existing println! in:
- `src/cli/commands/update.rs` — update check/apply/rollback outcomes
- `src/cli/commands/install.rs` — each shell installed
- `src/cli/commands/rules.rs` — validation outcomes
- `src/cli/commands/config.rs` — config operations

Add `debug!`/`info!`/`warn!` in library layer:
- `src/update/manager.rs` — version activation, rollback
- `src/update/crypto.rs` — signature verification attempts, failures as `warn!`
- `src/update/storage.rs` — symlink creation

---

## Step 7: Integration tests

**File**: `tests/cli_tests.rs` (add to existing)

- `cli_log_level_flag_accepted` — `--log-level debug` succeeds
- `cli_log_level_invalid_rejected` — `--log-level verbose` fails with "possible values"
- `cli_debug_logging_shows_on_stderr_not_stdout` — stdout has scan results only, stderr has debug messages
- `default_log_level_produces_no_stderr_noise` — at default warn, stderr is empty for clean scan

---

## Files Changed

| File | Action |
|------|--------|
| `Cargo.toml` | Modify — add tracing-subscriber features |
| `src/lib.rs` | Modify — add `pub mod logging;` |
| `src/logging.rs` | **Create** — logging module with init/build/LogFormat/LogInitError |
| `src/cli/args.rs` | Modify — add LogLevel enum, log_level/log_format global flags |
| `src/main.rs` | Modify — call logging::init(), add tracing::error at error handler |
| `src/cli/commands/scan.rs` | Modify — add spans + structured events |
| `src/detection/pipeline.rs` | Modify — add rule_count(), debug spans |
| `src/detection/scanner.rs` | Modify — add debug spans |
| `src/cli/commands/update.rs` | Modify — add info/debug events |
| `src/cli/commands/install.rs` | Modify — add info events |
| `src/cli/commands/rules.rs` | Modify — add info events |
| `src/cli/commands/config.rs` | Modify — add debug events |
| `src/update/manager.rs` | Modify — add info/debug events |
| `src/update/crypto.rs` | Modify — add debug/warn events |
| `src/update/storage.rs` | Modify — add debug events |
| `tests/cli_tests.rs` | Modify — add logging integration tests |

## Existing Code to Reuse

- `tests/common/mod.rs` — `pipeguard_cmd()`, `core_rules_path()`, `scan_stdin()` for new integration tests
- `thiserror` pattern from `src/detection/pipeline.rs:29-45` — for `LogInitError`
- `clap::ValueEnum` pattern from `src/cli/args.rs:143-155` — for `LogLevel`/`LogFormat`

## Verification

1. `cargo check` — compiles after each step
2. `cargo test` — all existing tests still pass (stdout unchanged)
3. `pipeguard --log-level debug scan --rules rules/core.yar` with stdin — debug output on stderr, scan results on stdout
4. `pipeguard --log-format json --log-level info scan --rules rules/core.yar` — JSON log lines on stderr
5. `pipeguard scan --rules rules/core.yar` (default) — zero stderr output (warn level, no warnings emitted for clean scan)
