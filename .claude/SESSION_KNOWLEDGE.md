# PipeGuard Session Knowledge

**Session Date:** 2026-01-05
**Purpose:** Restore context for future Claude sessions

---

## Project Overview

**PipeGuard** is a security tool that protects macOS users from malicious `curl | bash` attacks by intercepting pipe-to-interpreter patterns, scanning content for threats, and blocking known malware.

**Dual-Repo Model:**
- `pipeguard` (this repo) - MIT License, open source core
- `pipeguard-pro` (sibling repo) - Proprietary, enterprise features

---

## Problem Statement

### "Human Prompt Injection"

Users have been systematically trained over years to bypass macOS security controls:

| Trained Behavior | Security Impact |
|-----------------|-----------------|
| Run `curl \| bash` without review | Bypasses Gatekeeper (curl doesn't set quarantine) |
| `xattr -d com.apple.quarantine` reflexively | Disables file quarantine |
| Trust formatted instructions from authoritative sources | Social engineering vector |
| "Just paste this into Terminal" mentality | Enables ClickFix/AMOS attacks |

### Attack Evolution

1. **Legacy (2010s):** `curl | bash` normalized in developer tooling
2. **ClickFix (2024-2025):** Fake CAPTCHAs trick users into pasting commands - 500% increase in attacks
3. **AI Poisoning (Dec 2025):** Shared ChatGPT/Grok conversations deliver AMOS infostealer
4. **Agentic Exploitation (2025):** Comet browser MCP API allows local command execution via prompt injection

### Key Research Sources

- [MITRE ATT&CK T1204.004](https://attack.mitre.org/techniques/T1204/004/) - Malicious Copy and Paste (created March 2025)
- [Malwarebytes AMOS Analysis](https://www.malwarebytes.com/blog/news/2025/12/google-ads-funnel-mac-users-to-poisoned-ai-chats-that-spread-the-amos-infostealer)
- [Microsoft ClickFix Analysis](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- [SquareX Comet MCP Vulnerability](https://labs.sqrx.com/comet-mcp-api-allows-ai-browsers-to-execute-local-commands-dec185fb524b)
- [kicksecure curl|bash analysis](https://www.kicksecure.com/wiki/Dev/curl_bash_pipe)

### macOS Security Gap

| Control | Status for curl\|bash |
|---------|----------------------|
| Gatekeeper | **Bypassed** - curl doesn't set quarantine attribute |
| XProtect | **Bypassed** - no file to scan before execution |
| XProtect API | **None** - no public API for on-demand scanning |
| Apple XProtect YARA rules | Available at `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara` |

---

## Architecture Decisions

### Three-Layer Interception

| Layer | Mechanism | Coverage | Rationale |
|-------|-----------|----------|-----------|
| **ZLE Binding** | Keyboard intercept at Enter key | Interactive shells | Sees full command before execution, can modify `$BUFFER` |
| **Hardened Wrappers** | PATH-shadowed shell functions | Scripts, CI, subshells | Fallback when ZLE not available |
| **Preexec Logging** | Audit trail via preexec hook | All commands | Detection/audit even if bypass occurs |

**Why all three:** Defense in depth - bypassing one layer still triggers another.

### Shell Wrapper Pitfalls (Research Finding)

The simple `command bash "$@"` pattern has issues:
- `$@` context confusion with `-c` flag
- Subshell variable loss in pipes
- Stdin detection (`[ ! -t 0 ]`) insufficient alone

**Solution:** ZLE binding as primary (rewrites before execution), wrappers as fallback with proper stdin capture using `printf '%s'` instead of echo.

Key references:
- [BashPitfalls](https://mywiki.wooledge.org/BashPitfalls)
- [kicksecure bash guide](https://www.kicksecure.com/wiki/Dev/bash)
- [bash-preexec](https://github.com/rcaloras/bash-preexec)

### Detection Pipeline

```
Stage 1: YARA Pattern Matching (~5ms)
    ↓
Stage 2: AV Integration (~50-200ms)
    • Apple XProtect YARA rules (loaded directly, no API)
    • ClamAV (clamd socket)
    ↓
Stage 3: Sandbox Analysis (~1-3s, medium threats only)
    • macOS sandbox-exec dry-run
    • Captures intent: file access, network, processes
    ↓
Stage 4: Cloud AI Analysis (Enterprise only, ~500ms)
    • Encrypted payload transmission (age encryption)
```

### YARA Rule Categories (10)

| Category | Severity | Examples |
|----------|----------|----------|
| Base64 Obfuscation | 5 | `base64 -d`, encoded payloads |
| Staged Downloads | 7 | curl/wget inside downloaded script |
| Reverse Shells | 10 | `/dev/tcp`, `nc -e`, socat |
| Persistence | 8 | LaunchAgents, crontab, rc files |
| Privilege Escalation | 7 | sudo stdin, osascript admin |
| Crypto Wallet Targeting | 9 | Ledger, Trezor, seed phrases |
| Quarantine Bypass | 9 | `xattr -d com.apple.quarantine` |
| AMOS/ClickFix IOCs | 10 | Known campaign indicators |
| Environment Harvesting | 6 | AWS_*, GITHUB_TOKEN, keychain |
| Anti-Analysis | 5 | Sleep delays, VM detection |

### Threat Levels

| Level | Trigger | Action |
|-------|---------|--------|
| 🟡 Low (1-6) | Heuristic matches | Warn + prompt |
| 🟠 Medium (7-8) | Pattern matches | Sandbox + require approval |
| 🔴 High (9-10) | AV hit / known malware | Block, require `--force` |

---

## Network Security Decision

### Problem: TLS Inspection Triggers

Sending malware content to AI analysis endpoint could trigger:
- Enterprise TLS inspection (Zscaler, Netskope)
- EDR on host
- DLP systems
- Network IDS/IPS

### Solution: Encrypt Everything

**All network transmissions use age encryption:**

```rust
pub struct SecurePayload {
    pub ciphertext: Vec<u8>,        // age-encrypted content
    pub ephemeral_public: String,
    pub metadata: PayloadMetadata,  // Safe to inspect (hash, size, URL)
}
```

TLS inspection sees only encrypted blob - no signatures to match.

Response also encrypted (AI explanation might contain malware indicators).

---

## Fleet Policy (Enterprise)

### MDM Integration

- Configuration Profile → `/Library/Managed Preferences/com.pipeguard.plist`
- LaunchDaemon for policy sync (hourly)
- Config precedence: Built-in defaults < User config < MDM (locked)

### Supported MDM Solutions

- Jamf Pro
- Kandji
- Mosyle
- Microsoft Intune
- Fleet

---

## Licensing Decision

### Dual-Repo Model (like chatham)

Researched chatham project structure:
- `chatham/` - MIT licensed packages
- `chatham-pro/` - Proprietary apps importing MIT packages
- Cross-repo workspace via pnpm

**Applied to pipeguard:**

| Repo | License | Contains |
|------|---------|----------|
| `pipeguard` | MIT | Core detection, CLI, config, YARA rules |
| `pipeguard-pro` | Proprietary | AI analysis, license validation, rule sync, fleet policy, MDM, audit |

**Why dual-repo over FSL:**
- True open source (community trust)
- Security tools need full auditability
- Clear contribution target
- Can publish to crates.io

### License Comparison Research

| License | Enterprise Protection | Used By |
|---------|----------------------|---------|
| MIT | ❌ None | Most OSS |
| BSL 1.1 | ✅ Commercial restrictions for X years | HashiCorp, CockroachDB |
| FSL 1.1 | ✅ No competing use, converts in 2 years | Sentry |
| SSPL | ✅ SaaS must open-source everything | MongoDB |

---

## Technology Stack

- **Language:** Rust
- **YARA:** yara-rust bindings
- **Encryption:** age (modern, audited)
- **Config:** TOML
- **Shell Integration:** Zsh ZLE + Bash preexec

---

## Project Structure

```
pipeguard/                    # MIT (open source)
├── Cargo.toml
├── LICENSE                   # MIT - Security Ronin
├── README.md
├── docs/plans/
│   └── 2026-01-05-pipeguard-design.md
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── detection/           # YARA, sandbox, AV
│   ├── interception/        # Shell integration
│   ├── config/              # Settings, allowlist
│   └── logging/             # Audit
├── rules/
│   └── core.yar
└── shell/
    ├── pipeguard.zsh
    └── pipeguard.bash

pipeguard-pro/                # Proprietary
├── Cargo.toml               # Depends on ../pipeguard
├── LICENSE                   # Proprietary - Security Ronin
├── src/
│   ├── lib.rs
│   ├── enterprise/
│   │   ├── ai.rs            # Cloud AI analysis
│   │   ├── license.rs       # License validation
│   │   └── sync.rs          # Central rule sync
│   └── fleet/
│       ├── policy.rs        # Fleet policy
│       ├── mdm.rs           # MDM integration
│       └── audit.rs         # Audit aggregation
```

---

## GitHub Description Options

1. **Concise:** `Defend against curl|bash attacks. Intercepts pipe-to-shell patterns, scans with YARA/AV, blocks malware. Addresses MITRE ATT&CK T1204.004 and AMOS/ClickFix campaigns.`

2. **Technical:** `macOS security tool that intercepts curl|bash patterns with three-layer defense (ZLE + wrappers + audit). Multi-stage detection: YARA rules, Apple XProtect, ClamAV, sandbox analysis. Enterprise fleet policy via MDM.`

---

## Implementation Phases

| Phase | Scope |
|-------|-------|
| 1. Core | Detection engine + CLI (`pipeguard --scan`) |
| 2. Shell | ZLE + wrapper integration |
| 3. UX | Interactive prompts + viewer |
| 4. Config | Settings + allowlist management |
| 5. Sandbox | macOS sandbox-exec analysis |
| 6. Enterprise | AI + central sync + policy (pipeguard-pro) |
| 7. Polish | Installer, docs, testing |

---

## DEF CON / Black Hat Submission Info

- **DEF CON Singapore Demo Labs:** April 28-30, 2026 (deadline Feb 15, 2026)
- **Black Hat Asia Arsenal:** April 23-24, 2026

---

## Commands to Continue

```bash
# Rename repo
mv /Users/4n6h4x0r/src/curls /Users/4n6h4x0r/src/pipeguard

# Continue development
cd /Users/4n6h4x0r/src/pipeguard
claude

# Read this file to restore context:
# /Users/4n6h4x0r/src/pipeguard/.claude/SESSION_KNOWLEDGE.md
```
