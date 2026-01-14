# PipeGuard Design Document

**Date:** 2026-01-05
**Status:** ⚠️ SUPERSEDED - Original design document (historical reference)
**Author:** Security Research Team

> **NOTE:** This document represents the original design plan. The actual implementation differs:
> - **Planned:** 4-stage pipeline (YARA + XProtect + ClamAV + Sandbox)
> - **Implemented:** 2-stage pipeline (Smart Content Filtering + YARA)
> - See `paper/sections/04-architecture.qmd` for current architecture

---

## Overview

PipeGuard is a security tool that protects macOS users from malicious `curl | bash` attacks by intercepting pipe-to-interpreter patterns, scanning content for threats, and blocking known malware.

### Problem Statement

Users have been systematically trained to bypass macOS security controls:
- `curl | bash` bypasses Gatekeeper (curl doesn't set quarantine attribute)
- Power user tutorials normalize `xattr -d com.apple.quarantine`
- AI-generated installation guides (AMOS/ClickFix campaigns) exploit this trained behavior
- MITRE ATT&CK now classifies this as T1204.004 "Malicious Copy and Paste"

### Solution

A three-layer interception system with multi-stage threat detection:
1. **ZLE binding** - Intercept at Enter key (interactive shells)
2. **Hardened wrappers** - Fallback for scripts/non-interactive
3. **Preexec logging** - Audit trail for all pipe-to-interpreter commands

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         User's Shell                            │
│  $ curl https://example.com/install.sh | bash                   │
└─────────────────────────┬───────────────────────────────────────┘
                          │ intercepted
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      pipeguard (Rust binary)                    │
├─────────────────────────────────────────────────────────────────┤
│  1. Download content to temp file                               │
│  2. Run detection pipeline:                                     │
│     ├── YARA pattern matching (10 categories)                   │
│     ├── Apple XProtect rules                                    │
│     ├── ClamAV scan (if available)                              │
│     └── [Enterprise] Cloud AI analysis                          │
│  3. Calculate threat level (low/medium/high)                    │
│  4. Take action based on tier:                                  │
│     ├── 🟡 Low: warn + prompt                                   │
│     ├── 🟠 Medium: sandbox dry-run + intent report + prompt     │
│     └── 🔴 High: block (--force to override)                    │
│  5. If approved: pipe to original interpreter                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Detection Pipeline

### Stage 1: YARA Pattern Matching (~5ms)

10 rule categories covering common attack patterns:

| Category | Severity | Examples |
|----------|----------|----------|
| Base64 Obfuscation | 5 | `base64 -d`, encoded payloads |
| Staged Downloads | 7 | curl/wget inside downloaded script |
| Reverse Shells | 10 | `/dev/tcp`, `nc -e`, socat |
| Persistence Mechanisms | 8 | LaunchAgents, crontab, rc files |
| Privilege Escalation | 7 | sudo stdin, osascript admin |
| Crypto Wallet Targeting | 9 | Ledger, Trezor, seed phrases |
| Quarantine Bypass | 9 | `xattr -d com.apple.quarantine` |
| AMOS/ClickFix IOCs | 10 | Known campaign indicators |
| Environment Harvesting | 6 | AWS_*, GITHUB_TOKEN, keychain |
| Anti-Analysis | 5 | Sleep delays, VM detection |

### Stage 2: AV Integration (~50-200ms)

- **Apple XProtect rules** - Load from `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara`
- **ClamAV** - Connect to clamd socket if available

### Stage 3: Sandbox Analysis (~1-3s, medium threats only)

macOS `sandbox-exec` dry-run to capture intent:
- File access attempts
- Network connection attempts
- Process spawn attempts
- Environment variable access

### Stage 4: Cloud AI Analysis (Enterprise only, ~500ms)

Send encrypted payload to hosted LLM endpoint for behavioral analysis.

---

## Threat Levels

| Level | Trigger | Default Action |
|-------|---------|----------------|
| 🟡 **Low** | Heuristic matches only (severity 1-6) | Warn + prompt to continue |
| 🟠 **Medium** | Pattern matches (severity 7-8) OR suspicious sandbox behavior | Sandbox analysis + require explicit approval |
| 🔴 **High** | AV detection OR known malware patterns (severity 9-10) | Block by default, require `--force` to override |

---

## Shell Interception

### Layer 1: ZLE Binding (Primary)

Intercept at the readline/ZLE level before command execution:

```bash
function pipeguard-accept-line() {
    local cmd="$BUFFER"

    if _pipeguard_is_dangerous "$cmd"; then
        BUFFER="$(_pipeguard_rewrite_command "$cmd")"
    fi

    zle .accept-line
}

zle -N accept-line pipeguard-accept-line
```

### Layer 2: Hardened Wrappers (Fallback)

For non-interactive shells, scripts, CI:

```bash
function _pipeguard_bash_wrapper() {
    set -o errexit -o nounset -o pipefail

    local stdin_content=""
    local has_stdin="false"

    if [[ ! -t 0 ]]; then
        has_stdin="true"
        stdin_content="$(cat)"
    fi

    if [[ "$has_stdin" == "true" ]]; then
        if ! printf '%s' "$stdin_content" | pipeguard --scan; then
            return 1
        fi
        printf '%s' "$stdin_content" | command bash "$@"
    else
        command bash "$@"
    fi
}
```

### Layer 3: Preexec Logging (Audit)

Record all pipe-to-interpreter commands for security review:

```bash
autoload -U add-zsh-hook

function pipeguard_preexec() {
    local cmd="$1"
    if [[ "$cmd" =~ 'curl.*\|.*(bash|sh|zsh)' ]]; then
        pipeguard --audit-log "$cmd"
    fi
}

add-zsh-hook preexec pipeguard_preexec
```

---

## Configuration

### Directory Structure

```
~/.config/pipeguard/
├── config.toml           # Main configuration
├── rules/
│   ├── core.yar          # Shipped default rules
│   └── custom.yar        # User additions
├── allowlist.toml        # Trusted sources
└── logs/
    └── audit.jsonl       # Audit log
```

### config.toml

```toml
[general]
low_action = "warn"
medium_action = "prompt"
high_action = "block"
allow_force_override = true
sandbox_enabled = true

[detection]
yara_enabled = true
clamav_enabled = true
apple_rules_enabled = true
min_severity = 4

[logging]
audit_enabled = true
audit_path = "~/.config/pipeguard/logs/audit.jsonl"

[network]
server_public_key = "age1pipeguard..."

[enterprise]
license_key = ""
ai_analysis_enabled = false
central_rules_enabled = false
```

### allowlist.toml

```toml
[[trusted_domains]]
domain = "raw.githubusercontent.com"
reason = "GitHub raw content"

[[trusted_hashes]]
hash = "sha256:abc123..."
name = "oh-my-zsh installer v1.2.3"

[[blocked_domains]]
domain = "pastebin.com"
reason = "Common malware hosting"
```

---

## Network Security

### All Transmissions Encrypted

To prevent enterprise TLS inspection from flagging malware content:

```rust
pub struct SecurePayload {
    pub ciphertext: Vec<u8>,        // age-encrypted content
    pub ephemeral_public: String,
    pub metadata: PayloadMetadata,  // Safe to inspect
}

#[derive(Serialize)]
pub struct PayloadMetadata {
    pub script_hash: String,
    pub script_size: usize,
    pub source_url: Option<String>,
    pub client_version: String,
}
```

Using **age** encryption - TLS inspection sees only encrypted blob.

---

## Enterprise Features

### Open Source (Free)

- Three-layer interception
- YARA pattern detection (10 categories)
- Apple XProtect rules integration
- ClamAV integration
- Sandbox dry-run analysis
- Local config + custom YARA rules
- Domain/hash allowlisting
- Audit logging (local JSONL)

### Enterprise (Paid License)

- Central rule distribution
- Cloud AI script analysis
- Threat intel feeds integration
- Fleet-wide policy management
- Central audit log aggregation
- MDM integration (Jamf, Kandji, Mosyle, Intune)

---

## Fleet Policy (Enterprise)

### MDM Configuration Profile

Push locked policy via MDM:

```xml
<key>PayloadType</key>
<string>com.pipeguard.policy</string>

<key>high_action</key>
<string>block</string>

<key>allow_force_override</key>
<false/>

<key>enterprise_endpoint</key>
<string>https://pipeguard.company.com/api</string>
```

Lands in `/Library/Managed Preferences/com.pipeguard.plist` - users cannot override.

### LaunchDaemon for Policy Sync

Real-time updates without MDM push delay:

```xml
<key>Label</key>
<string>com.pipeguard.policyd</string>

<key>ProgramArguments</key>
<array>
    <string>/usr/local/bin/pipeguard</string>
    <string>policy-sync</string>
    <string>--daemon</string>
</array>

<key>RunAtLoad</key>
<true/>

<key>StartInterval</key>
<integer>3600</integer>
```

### Config Precedence

1. Built-in defaults (lowest)
2. User config (`~/.config/pipeguard/config.toml`)
3. MDM Managed Preferences (highest, locked)

---

## Project Structure

```
pipeguard/
├── Cargo.toml
├── LICENSE-APACHE
├── LICENSE-MIT
├── README.md
│
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── cli/
│   │   ├── commands.rs
│   │   └── ui.rs
│   ├── detection/
│   │   ├── engine.rs
│   │   ├── yara.rs
│   │   ├── clamav.rs
│   │   └── sandbox.rs
│   ├── interception/
│   │   ├── shell.rs
│   │   └── installer.rs
│   ├── config/
│   │   ├── settings.rs
│   │   └── allowlist.rs
│   ├── logging/
│   │   └── audit.rs
│   └── enterprise/
│       ├── license.rs
│       ├── ai.rs
│       ├── sync.rs
│       └── policy.rs
│
├── rules/
│   └── core.yar
│
├── shell/
│   ├── pipeguard.zsh
│   ├── pipeguard.bash
│   └── install.sh
│
└── tests/
    ├── detection_tests.rs
    └── fixtures/
```

---

## Implementation Phases

| Phase | Scope | Deliverable |
|-------|-------|-------------|
| **1. Core** | Detection engine + CLI | `pipeguard --scan` works |
| **2. Shell** | ZLE + wrapper integration | `curl \| bash` intercepted |
| **3. UX** | Interactive prompts + viewer | Threat-level UI complete |
| **4. Config** | Settings + allowlist management | Full config system |
| **5. Sandbox** | macOS sandbox-exec analysis | Intent reports |
| **6. Enterprise** | AI + central sync + policy | Paid tier functional |
| **7. Polish** | Installer, docs, testing | Release-ready |

---

## References

- [MITRE ATT&CK T1204.004 - Malicious Copy and Paste](https://attack.mitre.org/techniques/T1204/004/)
- [Malwarebytes - AMOS Infostealer via AI Chats](https://www.malwarebytes.com/blog/news/2025/12/google-ads-funnel-mac-users-to-poisoned-ai-chats-that-spread-the-amos-infostealer)
- [Microsoft - ClickFix Social Engineering](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- [Unit42 - Gatekeeper Bypass](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
- [HackTricks - macOS Gatekeeper](https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-gatekeeper.html)
