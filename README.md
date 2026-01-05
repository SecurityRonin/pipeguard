# PipeGuard

**Stop malware before it runs. Defend against `curl | bash` attacks.**

---

## The Problem

You've seen this pattern everywhere:

```bash
curl https://example.com/install.sh | bash
```

Homebrew, Rust, countless developer tools—they all use it. Attackers know this.

In 2024-2025, campaigns like **ClickFix** and **AMOS** exploit this trust. Fake CAPTCHAs, AI-generated "installation guides," and poisoned search results trick users into pasting malicious commands. Microsoft reports a [500% increase](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/) in these attacks.

**Your antivirus won't help.** Traditional AV scans *files*—but `curl | bash` streams directly to the interpreter. No file, no scan, no protection.

---

## The Solution

PipeGuard intercepts pipe-to-interpreter patterns and scans content *before* execution:

```bash
# You run this:
curl https://example.com/install.sh | bash

# PipeGuard automatically:
# 1. Intercepts the pipe
# 2. Scans with YARA + Apple XProtect rules + ClamAV
# 3. Shows threat level: Low | Medium | High
# 4. Blocks or prompts before any code runs
```

**Zero configuration.** Install once, stay protected.

---

## Features

- **Pre-execution scanning** — Analyzes scripts before the interpreter sees them
- **Multi-engine detection** — YARA rules + Apple XProtect + ClamAV
- **Three-layer interception** — ZLE keyboard hooks, shell wrappers, audit logging
- **Tiered response** — Warn, prompt, or block based on threat severity
- **macOS native** — Works with your existing shell (bash/zsh)
- **Open source** — MIT licensed, fully auditable

---

## Quick Start

```bash
# Install
cargo install pipeguard

# Enable for your shell
pipeguard init >> ~/.zshrc  # or ~/.bashrc
source ~/.zshrc

# That's it. You're protected.
```

---

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  curl https://... | bash                                    │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  PipeGuard Interception                                     │
│  ├── Stage 1: YARA pattern matching (~5ms)                  │
│  ├── Stage 2: XProtect + ClamAV scan (~50-200ms)            │
│  └── Stage 3: Sandbox analysis (medium threats only)        │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  Threat Assessment                                          │
│  🟢 Clean     → Execute normally                            │
│  🟡 Low       → Warn + prompt                               │
│  🟠 Medium    → Sandbox + require approval                  │
│  🔴 High      → Block execution                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Why PipeGuard?

| What Others Do | What PipeGuard Does |
|----------------|---------------------|
| Scan files on disk | Intercept pipes before execution |
| Detect malware *after* it runs | Block malware *before* it runs |
| Binary-only protection | Script-aware protection |
| Require kernel extensions | Work in userspace |

---

## Enterprise

[**PipeGuard Pro**](https://github.com/SecurityRonin/pipeguard-pro) adds:

- Cloud AI analysis for novel threats
- MDM integration (Jamf, Kandji, Mosyle, Intune)
- Fleet-wide policy enforcement
- Centralized rule distribution
- Audit log aggregation

Contact: enterprise@pipeguard.dev

---

## Technical Details

For threat model, architecture deep-dive, YARA rule categories, academic references, and competitive analysis, see the [research paper](paper/).

---

## Status

**Design complete. Implementation in progress.**

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Research collaboration inquiries: albert@securityronin.com

---

## License

MIT License — Copyright (c) 2026 Security Ronin

Enterprise features available in [PipeGuard Pro](https://github.com/SecurityRonin/pipeguard-pro) (proprietary).
