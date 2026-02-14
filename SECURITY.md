# Security Policy

## Scope

This security policy covers the PipeGuard project, including:

- The `pipeguard` CLI binary and library crate
- YARA rule detection engine (`src/detection/`)
- Cryptographic update verification (`src/update/crypto.rs`) using Ed25519 signatures
- Rule update system (`src/update/`) including versioned storage and signature verification
- Shell integration hooks (bash, zsh)
- Configuration parsing and handling (`src/config/`)

Out of scope:
- Third-party YARA rules not maintained by this project
- Issues in upstream dependencies (report those to the respective projects)

## Security Architecture

PipeGuard employs several layers of security:

- **Ed25519 signature verification** for all rule updates before activation
- **YARA-based detection** for identifying malicious curl|bash patterns
- **Versioned storage with rollback** to recover from bad updates
- **SHA-256 content hashing** for allowlist verification
- **Path traversal prevention** in version string validation

## Reporting a Vulnerability

If you discover a security vulnerability in PipeGuard, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### Reporting Process

1. **Email**: Send a detailed report to the maintainers via GitHub Security Advisories
2. **GitHub Security Advisory**: Use the "Report a vulnerability" button on the repository's Security tab

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact assessment
- Suggested fix (if any)

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix development | Within 30 days (critical), 90 days (non-critical) |
| Public disclosure | After fix is released, coordinated with reporter |

## Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Act in good faith to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts they own or with explicit permission of the account holder
- Report vulnerabilities through the process described above
- Allow reasonable time for remediation before public disclosure

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Hall of Fame

We gratefully acknowledge security researchers who have responsibly disclosed vulnerabilities:

*No reports yet -- be the first!*
