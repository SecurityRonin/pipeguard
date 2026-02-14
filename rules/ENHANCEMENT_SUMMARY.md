# PipeGuard YARA Rules Enhancement Summary

**Date:** 2026-01-13
**Final Rule Count:** 56 rules across 15 threat categories
**Previous Count:** 26 rules across 10 categories

## Enhancement Overview

Enhanced PipeGuard's detection capabilities with 30 new sophisticated YARA rules based on comprehensive research of:
- NSA Cyber's Mitigating-Web-Shells repository
- AMOS stealer campaigns (2024-2025 surge)
- ClickFix social engineering attacks
- Apple XProtect patterns (MACOS_SOMA_E)
- Advanced obfuscation and evasion techniques

## New Rules by Category

### 1. Reverse Shells (3 new rules)
**Total: 7 rules**

- `reverse_shell_bash_obfuscated`: Base64-encoded reverse shell detection
  - Detects: `YmFzaCAtaQ` (base64 for "bash -i")
  - Severity: 10

- `reverse_shell_encrypted`: OpenSSL/Socat encrypted reverse shells
  - Detects: `openssl s_client`, `socat SSL/TLS`
  - Severity: 10

- `reverse_shell_dns_tunneling`: DNS-based C2 communication
  - Detects: DNS queries with base64 encoding and loops
  - Severity: 10

- `reverse_shell_http_tunnel`: HTTP-based reverse shell/C2
  - Detects: curl loops with POST data and custom headers
  - Severity: 10

### 2. Obfuscation (3 new rules)
**Total: 5 rules**

- `hex_encoding_obfuscation`: Hex-encoded command execution
  - Detects: `\x` patterns, `xxd -r -p`
  - Severity: 6

- `string_concatenation_obfuscation`: String splitting obfuscation
  - Detects: `"ba""sh"`, `${VAR:0:1}`, `$((arithmetic))`
  - Severity: 6

- `obfuscation_array_concatenation`: Array/character splitting
  - Detects: `cmd=(c u r l) && "${cmd[@]}"`
  - Severity: 6

- `obfuscation_unicode_encoding`: Unicode escape sequences
  - Detects: `printf '\u0062\u0061\u0073\u0068'` → "bash"
  - Severity: 7

- `obfuscation_variable_indirection`: Variable indirection
  - Detects: `${!var}`, `eval ${VAR}`
  - Severity: 6

### 3. Persistence Mechanisms (3 new rules)
**Total: 7 rules**

- `persistence_at_job`: Scheduled execution via `at` command
  - Detects: `at now +`, heredocs with bash/sh
  - Severity: 8

- `persistence_systemd_unit`: Systemd service persistence
  - Detects: `/etc/systemd/system/*.service`
  - Severity: 8

- `persistence_zsh_plugins`: Zsh plugin directory persistence
  - Detects: `.oh-my-zsh/custom/plugins`, `.zsh/plugins`
  - Severity: 7

### 4. Credential Theft (6 new rules)
**Total: 8 rules**

- `ssh_key_theft_compression`: SSH key theft with compression
  - Detects: `.ssh/id_rsa` + tar/zip + curl/nc exfiltration
  - Severity: 9

- `aws_credentials_exfiltration`: AWS credentials access
  - Detects: `.aws/credentials`, `AWS_ACCESS_KEY_ID` env vars
  - Severity: 9

- `docker_registry_credentials`: Docker registry credentials
  - Detects: `.docker/config.json`, auth tokens
  - Severity: 8

### 5. macOS-Specific Stealers (3 new rules)
**Total: 3 rules**

- `macos_browser_password_theft`: Browser password database access
  - Detects: Chrome/Brave/Firefox/Safari Login Data access
  - Reference: AMOS Stealer technique
  - Severity: 9

- `macos_keychain_export`: Keychain data export
  - Detects: `security export/dump-keychain`
  - Reference: AMOS Stealer technique
  - Severity: 10

- `macos_icloud_keychain_access`: iCloud Keychain access
  - Detects: `Library/Keychains/iCloud`, CloudKit access
  - Severity: 10

### 6. Command Injection (3 rules)
**Total: 3 rules**

- `webshell_like_command_execution`: Webshell patterns for bash
  - Reference: NSA Cyber Mitigating-Web-Shells
  - Detects: `eval ${VAR}`, `$($VAR)`, variable-based execution
  - Severity: 8

- `process_injection_patterns`: Process injection
  - Detects: `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`
  - Severity: 9

- `fileless_execution`: Fileless execution techniques
  - Detects: `memfd_create`, `/dev/shm`, process substitution
  - Severity: 9

### 7. Data Exfiltration (3 rules)
**Total: 3 rules**

- `data_exfiltration_http`: HTTP POST exfiltration
  - Detects: curl POST with file contents
  - Severity: 8

- `data_exfiltration_dns`: DNS tunneling
  - Detects: nslookup/dig with base64 and loops
  - Severity: 9

- `data_exfiltration_icmp`: ICMP covert channels
  - Detects: ping with hexdata patterns
  - Severity: 9

### 8. Reconnaissance (2 new rules)
**Total: 2 rules**

- `system_recon_comprehensive`: System profiling
  - Detects: 4+ of: uname, whoami, ifconfig, ps, netstat, env
  - Severity: 6

- `security_product_detection`: Security product evasion
  - Detects: CrowdStrike/SentinelOne/Carbon Black checks
  - Severity: 7

### 9. Lateral Movement (2 new rules)
**Total: 2 rules**

- `lateral_movement_ssh`: SSH-based pivoting
  - Detects: `ssh -o StrictHostKeyChecking=no` in loops
  - Severity: 8

- `scp_mass_exfiltration`: SCP data exfiltration
  - Detects: `scp -r` with sensitive directories
  - Severity: 9

### 10. AMOS/ClickFix Enhancements (2 enhanced rules)
**Total: 4 rules**

- Enhanced `amos_stealer_indicators`:
  - Added: `/Users/air/work/`, `/tmp/amos` paths
  - Added: Browser credential patterns
  - Reference: XProtect_MACOS_SOMA_E, SentinelOne 2024

- Added `amos_exfiltration`:
  - Detects: Archive creation + curl POST of wallet/keychain data
  - Severity: 10

- Enhanced `clickfix_indicators`:
  - Added: Clipboard manipulation patterns
  - Added: Social engineering lures
  - Reference: Microsoft 2024, Trend Micro 2025

- Added `clickfix_powershell_pattern`:
  - Detects: PowerShell with encoded/hidden execution + DownloadString
  - Severity: 10

## Updated Documentation

All references updated across:
- ✅ paper/sections/04-architecture.qmd
- ✅ paper/sections/05-evaluation.qmd
- ✅ paper/sections/08-conclusion.qmd
- ✅ paper/_quarto.yml (abstract)
- ✅ paper/paperwork/DEFCON_SG_DemoLab_Submission.md
- ✅ README.md
- ✅ Paper PDF rebuilt successfully

## Severity Distribution

- **High (9-10)**: 19 rules - Reverse shells, credential theft, exfiltration
- **Medium (7-8)**: 25 rules - Persistence, privilege escalation, reconnaissance
- **Low (5-6)**: 12 rules - Obfuscation, anti-analysis

## Detection Coverage

The enhanced ruleset now provides comprehensive coverage for:
- ✅ Traditional reverse shells (bash, netcat, Python, Perl)
- ✅ Advanced reverse shells (encrypted, DNS tunneling, HTTP C2)
- ✅ Multiple obfuscation techniques (base64, hex, unicode, concatenation)
- ✅ Persistence mechanisms (cron, LaunchAgents, systemd, zsh plugins, at jobs)
- ✅ Credential theft (SSH keys, AWS, Docker, browser passwords, keychains)
- ✅ macOS-specific attacks (AMOS stealer, keychain access, iCloud)
- ✅ Social engineering (ClickFix campaign patterns)
- ✅ Data exfiltration (HTTP, DNS, ICMP covert channels)
- ✅ Lateral movement (SSH pivoting, SCP mass exfiltration)
- ✅ Anti-analysis and evasion techniques

## Research References

1. **NSA Cyber**: Mitigating-Web-Shells repository
2. **Apple XProtect**: MACOS_SOMA_E signatures (AMOS detection)
3. **SentinelOne 2024**: AMOS stealer analysis
4. **Microsoft 2024**: ClickFix campaign report (500% increase)
5. **Trend Micro 2025**: ClickFix social engineering patterns
6. **Unit42**: Atomic Stealer IOCs
7. **Palo Alto Networks**: Stealer malware analysis
8. **MITRE ATT&CK**: T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer)

## Testing Status

- ✅ YARA syntax validation complete (56 rules compiled)
- ✅ Smart content filter tests passing (15/15)
- 🔄 Real-world malware corpus validation in progress
- 🔄 False positive testing with benign samples ongoing

## Next Steps

1. Collect real-world malware samples from MalwareBazaar
2. Test rules against AMOS/ClickFix samples
3. Validate false positive rates with legitimate installers
4. Community feedback on GitHub
5. Continuous rule updates based on emerging threats
