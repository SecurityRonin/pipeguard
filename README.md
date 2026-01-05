# pipeguard

**Defending against the `curl | bash` attack vector**

---

## TL;DR (Executive Summary)

**Problem:** macOS users have been trained for years to run `curl | bash` and bypass security controls (`xattr -d com.apple.quarantine`). Attackers now exploit this via AI-generated "installation guides" (AMOS/ClickFix campaigns). MITRE classifies this as [T1204.004](https://attack.mitre.org/techniques/T1204/004/).

**Solution:** pipeguard intercepts pipe-to-interpreter patterns, scans content with YARA/AV before execution, and blocks known malware. Three-layer defense: ZLE keyboard interception → hardened shell wrappers → preexec audit logging.

**Status:** Design complete. Implementation in progress.

```bash
# Instead of this (dangerous):
curl https://example.com/install.sh | bash

# pipeguard intercepts automatically:
# → Downloads to temp
# → Scans with YARA (10 rule categories) + Apple XProtect rules + ClamAV
# → Shows threat level: 🟡 Low | 🟠 Medium | 🔴 High
# → Blocks or prompts before execution
```

---

## Key Findings (For Researchers)

### The "Human Prompt Injection" Problem

| AI Prompt Injection | Human "Prompt Injection" |
|---------------------|--------------------------|
| Malicious instructions hidden in data | Malicious commands hidden in "helpful" guides |
| AI can't distinguish user intent from injected commands | User trained to not question Terminal commands |
| Bypasses safety filters via context manipulation | Bypasses Gatekeeper via copy-paste |
| Exploits trust in data sources | Exploits trust in AI/expert sources |

Users have been **pre-conditioned** by years of tutorials to:
- Run arbitrary `curl | bash` commands
- Remove quarantine attributes reflexively
- Trust formatted instructions from authoritative sources

### macOS Security Control Gap

| Control | Status for `curl \| bash` |
|---------|---------------------------|
| Gatekeeper | **Bypassed** - curl doesn't set quarantine |
| XProtect | **Bypassed** - no file to scan before execution |
| TCC | Partially effective - may prompt for folder access |
| SIP | Not applicable - user-initiated |

**Apple's design decision:** Command-line tools don't set quarantine. The security model assumes Terminal users know what they're doing.

### Attack Evolution Timeline

1. **Legacy** (2010s): `curl | bash` normalized in developer tooling
2. **ClickFix** (2024): Fake CAPTCHAs trick users into pasting commands ([500% increase](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/))
3. **AI Poisoning** (2025): Shared ChatGPT/Grok conversations deliver [AMOS infostealer](https://www.malwarebytes.com/blog/news/2025/12/google-ads-funnel-mac-users-to-poisoned-ai-chats-that-spread-the-amos-infostealer)
4. **Agentic Exploitation** (2025): [Comet browser MCP API](https://labs.sqrx.com/comet-mcp-api-allows-ai-browsers-to-execute-local-commands-dec185fb524b) allows local command execution via prompt injection

---

## Technical Architecture

### Detection Pipeline

```
Input (script content)
         │
         ▼
┌─────────────────────────────────────┐
│ Stage 1: YARA Pattern Matching ~5ms │
│ • 10 rule categories                │
│ • Custom rules supported            │
└─────────────────┬───────────────────┘
                  │
         ▼
┌─────────────────────────────────────┐
│ Stage 2: AV Integration    ~50-200ms│
│ • Apple XProtect YARA rules         │
│ • ClamAV (clamd socket)             │
└─────────────────┬───────────────────┘
                  │
         ▼
┌─────────────────────────────────────┐
│ Stage 3: Sandbox Analysis    ~1-3s  │
│ • macOS sandbox-exec dry-run        │
│ • Captures file/network/process     │
│ • Only for medium threats           │
└─────────────────┬───────────────────┘
                  │
         ▼
┌─────────────────────────────────────┐
│ Stage 4: Cloud AI [Enterprise] ~500ms│
│ • Encrypted payload transmission    │
│ • Behavioral analysis + explanation │
└─────────────────┬───────────────────┘
                  │
         ▼
    Threat Level Calculation
    🟡 Low (1-6) → warn + prompt
    🟠 Medium (7-8) → sandbox + approve
    🔴 High (9-10) → block
```

### YARA Rule Categories

| Category | Severity | Rationale |
|----------|----------|-----------|
| Base64 Obfuscation | 5 | Common in staged attacks |
| Staged Downloads | 7 | Script downloads more scripts |
| Reverse Shells | 10 | Immediate compromise indicator |
| Persistence | 8 | LaunchAgents, crontab, rc files |
| Privilege Escalation | 7 | sudo stdin, osascript admin |
| Crypto Wallet Targeting | 9 | AMOS primary objective |
| Quarantine Bypass | 9 | Explicit security control bypass |
| AMOS/ClickFix IOCs | 10 | Known campaign indicators |
| Environment Harvesting | 6 | Credential theft precursor |
| Anti-Analysis | 5 | Sandbox/VM detection |

### Shell Interception Layers

| Layer | Mechanism | Coverage | Bypass Difficulty |
|-------|-----------|----------|-------------------|
| **ZLE Binding** | Keyboard intercept at Enter | Interactive shells | Easy (`\curl`) |
| **Hardened Wrappers** | PATH-shadowed functions | Scripts, CI, subshells | Moderate |
| **Preexec Logging** | Audit trail | All commands | N/A (detection only) |

**Defense in depth:** Bypassing one layer still triggers another.

### Network Security

All cloud transmissions use **age encryption** to prevent enterprise TLS inspection from flagging malware content:

```
Client                          TLS Proxy                    Server
  │                                │                            │
  │ POST encrypted_blob            │                            │
  │ ─────────────────────────────► │                            │
  │                                │  Sees: random bytes        │
  │                                │  No signatures to match    │
  │                                │ ──────────────────────────►│
  │                                │                            │
  │                                │                    Decrypts│
  │                                │                    Analyzes│
```

---

## Threat Model

### In Scope

- `curl | bash` and variants (`wget | sh`, `fetch | zsh`)
- Piped script execution patterns
- Known malware families (AMOS, ClickFix variants)
- Social engineering via AI-generated guides

### Out of Scope

- Downloaded executables (Gatekeeper handles these)
- Kernel exploits / sandbox escapes
- Determined attacker with local access
- Hardware implants

### Limitations

1. **Sandbox evasion:** Malware can detect sandbox and stay dormant
2. **Novel patterns:** Zero-day attacks may not match YARA rules
3. **User override:** `--force` flag exists (can be disabled via MDM)
4. **Shell-specific:** Only protects bash/zsh/sh interpreters

---

## Enterprise Considerations

### Fleet Policy Enforcement

```
MDM (Jamf/Kandji/Mosyle/Intune)
         │
         ▼
┌─────────────────────────────────────┐
│ Configuration Profile               │
│ /Library/Managed Preferences/       │
│ com.pipeguard.plist                 │
│                                     │
│ • high_action = "block"             │
│ • allow_force_override = false      │
│ • ai_analysis_required = true       │
│                                     │
│ [LOCKED - user cannot change]       │
└─────────────────────────────────────┘
```

### Open Source vs Enterprise

| Feature | Open Source | Enterprise |
|---------|-------------|------------|
| YARA detection | ✅ | ✅ |
| Apple XProtect rules | ✅ | ✅ |
| ClamAV integration | ✅ | ✅ |
| Sandbox analysis | ✅ | ✅ |
| Local audit logs | ✅ | ✅ |
| Central rule distribution | ❌ | ✅ |
| Cloud AI analysis | ❌ | ✅ |
| Fleet policy management | ❌ | ✅ |
| Audit log aggregation | ❌ | ✅ |
| Threat intel feeds | ❌ | ✅ |

---

## Implementation

### Technology Stack

- **Language:** Rust (memory safety, single binary, performance)
- **YARA:** yara-rust bindings
- **Encryption:** age (modern, audited)
- **Shell:** Zsh ZLE + Bash preexec

### Project Structure

```
pipeguard/
├── src/
│   ├── detection/     # YARA, ClamAV, sandbox
│   ├── interception/  # Shell integration
│   ├── config/        # Settings, allowlist
│   └── enterprise/    # AI, sync, policy
├── rules/
│   └── core.yar       # Default YARA rules
└── shell/
    ├── pipeguard.zsh  # Zsh integration
    └── pipeguard.bash # Bash integration
```

### Build

```bash
cargo build --release

# With enterprise features
cargo build --release --features enterprise
```

---

## Related Work

### Academic

- Kotzias et al., "Runtime Detection of Software Supply Chain Attacks" (2023)
- Ladisa et al., "Taxonomy of Attacks on Open-Source Supply Chains" (IEEE S&P 2023)

### Industry

- [MITRE ATT&CK T1204.004](https://attack.mitre.org/techniques/T1204/004/) - Malicious Copy and Paste
- [Unit42 Gatekeeper Bypass](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
- [Huntress AMOS Analysis](https://www.huntress.com/blog/amos-stealer-chatgpt-grok-ai-trust)
- [kicksecure curl|bash analysis](https://www.kicksecure.com/wiki/Dev/curl_bash_pipe)

### Tools

- [UXProtect](https://digitasecurity.com/uxprotect/) - XProtect rule visualization
- [bash-preexec](https://github.com/rcaloras/bash-preexec) - Preexec hooks for Bash
- [age](https://age-encryption.org/) - Modern file encryption

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Research Collaboration

Interested in:
- Novel detection patterns for emerging threats
- Sandbox evasion detection techniques
- Behavioral analysis approaches
- User study on security control bypass training

Contact: [TBD]

---

## License

MIT License - Copyright (c) 2026 Security Ronin

Enterprise features are available in [pipeguard-pro](https://github.com/security-ronin/pipeguard-pro) (proprietary license).

---

## Acknowledgments

- Apple Security Research for XProtect rule format documentation
- YARA project maintainers
- bash-preexec contributors
- The security research community documenting AMOS/ClickFix campaigns
