# PipeGuard Development Makefile
# Provides fmt, lint, test, security, and pre-commit targets
SHELL := /bin/bash

# YARA build environment (macOS Homebrew)
export YARA_LIBRARY_PATH ?= /opt/homebrew/lib
export BINDGEN_EXTRA_CLANG_ARGS ?= -I/opt/homebrew/include

# Pre-existing YARA detection gap tests (skip in CI)
SKIP_KNOWN_FAILURES := --skip edge_case_download_exec_multiline \
	--skip real_npm_depconf_exfil \
	--skip real_shell_command_substitution \
	--skip real_pythonw_hidden_execution \
	--skip real_reverseshell_obfuscated_oneliner \
	--skip real_setuptools_custom_install \
	--skip real_reverseshell_tcp_client

.PHONY: all check fmt fmt-check clippy typos toml-check toml-fmt machete \
	test test-all test-lib test-doc deny vet geiger semver-checks \
	build clean pre-commit install-hooks help

## Primary targets

all: fmt-check toml-check clippy typos machete test  ## Run full hygiene suite (default)

check: ## Compile check (fast)
	cargo check

build: ## Build release binary
	cargo build --release

clean: ## Clean build artifacts
	cargo clean

## Formatting

fmt: ## Format all code and TOML
	cargo fmt
	taplo fmt

fmt-check: ## Check Rust formatting (CI-safe)
	cargo fmt --check

toml-fmt: ## Format TOML files
	taplo fmt

toml-check: ## Check TOML formatting (CI-safe)
	taplo fmt --check

## Linting

clippy: ## Run clippy with strict settings
	cargo clippy --all-targets -- -D warnings -D clippy::all

typos: ## Check for typos in source code
	typos

machete: ## Find unused dependencies
	cargo machete

## Testing

test: ## Run tests (skip known YARA detection gaps)
	cargo test -- $(SKIP_KNOWN_FAILURES)

test-all: ## Run ALL tests including known failures
	cargo test

test-lib: ## Run only lib unit tests (fast)
	cargo test --lib

test-doc: ## Run doc tests
	cargo test --doc

## Security & supply chain

deny: ## Run cargo-deny license & advisory checks
	cargo deny check

vet: ## Run cargo-vet dependency audit
	cargo vet

geiger: ## Audit unsafe code in dependency tree
	cargo geiger --all-features

semver-checks: ## Check for semver-breaking API changes
	cargo semver-checks

## Benchmarks

bench: ## Run criterion benchmarks
	cargo bench

## Pre-commit

pre-commit: fmt-check toml-check clippy typos machete test  ## Full pre-commit check

install-hooks: ## Install git pre-commit hook
	@mkdir -p .git/hooks
	@cp .githooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed."

## Help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
