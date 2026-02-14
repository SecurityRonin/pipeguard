# PipeGuard Test Corpus

This directory contains the labeled test corpus used for PipeGuard evaluation.
All samples are provided for reproducibility and independent verification.

## Corpus Structure

```
testdata/
├── malware/           # Malicious shell script patterns
│   ├── reverse_shells/
│   ├── staged_downloads/
│   ├── persistence/
│   ├── credential_theft/
│   ├── crypto_theft/
│   ├── defense_evasion/
│   ├── obfuscation/
│   ├── social_engineering/
│   └── supply_chain/    # DataDog GuardDog patterns
├── benign/            # Legitimate shell scripts
│   ├── development/
│   ├── sysadmin/
│   ├── network/
│   ├── data_processing/
│   └── file_ops/
├── metadata/          # Sample provenance and labels
│   ├── malware_labels.json
│   └── benign_labels.json
└── README.md
```

## Data Provenance

### Malware Samples

Our malware corpus is derived from the following authoritative sources:

#### 1. MITRE ATT&CK Framework (T1059.004)
- **Source**: https://attack.mitre.org/techniques/T1059/004/
- **Techniques**: Command and Scripting Interpreter: Unix Shell
- **Coverage**: Reverse shells, staged execution, persistence mechanisms
- **License**: CC BY-SA 4.0

#### 2. GTFOBins Project
- **Source**: https://gtfobins.github.io/
- **Description**: Curated list of Unix binaries that can be exploited
- **Coverage**: Shell spawning, file exfiltration, privilege escalation
- **License**: GPL-3.0
- **Citation**: Pinna, E. & Cardaci, A. "GTFOBins"

#### 3. AMOS/Atomic Stealer IOCs (2024-2025)
- **Sources**:
  - SentinelOne: "From Amos to Poseidon" (2024)
  - Palo Alto Unit42: "Stealers on the Rise" (2024)
  - Trend Micro MDR: "AMOS Stealer Campaign" (2025)
- **Coverage**: Keychain dumping, crypto wallet theft, browser credential exfiltration
- **IOC Domains**: ekochist[.]com, goatramz[.]com, misshon[.]com

#### 4. ClickFix Campaign Patterns (2024-2025)
- **Source**: Multiple threat intelligence reports
- **Description**: Social engineering attacks using fake CAPTCHA verification
- **Coverage**: "Verify you are human" lures, clipboard-based attacks

#### 5. MalwareBazaar (abuse.ch)
- **Source**: https://bazaar.abuse.ch/
- **Description**: Community-driven malware sample sharing platform
- **Coverage**: Tagged shell script samples (file_type=sh)
- **Access**: Free API with registration
- **License**: CC0 (samples), varies for malware content

#### 6. AutoMalDesc Dataset (November 2025)
- **Source**: arXiv:2511.13333
- **Description**: Large-scale multi-language script analysis dataset
- **Coverage**: Bash, PowerShell, Python, JavaScript malicious scripts
- **License**: Research use

#### 7. DataDog GuardDog (2024-2025)
- **Source**: https://github.com/DataDog/guarddog
- **Dataset**: https://github.com/DataDog/malicious-software-packages-dataset
- **Description**: Supply chain attack detection patterns from DataDog's GuardDog tool
- **Dataset Size**: 17,952 human-vetted malicious PyPI/npm packages
- **Coverage**:
  - `code-execution.yml`: subprocess.Popen, os.system, eval, exec in setup.py
  - `exec-base64.yml`: Base64/marshal/zlib obfuscated execution
  - `exfiltrate-sensitive-data.yml`: Environment variable and credential theft
  - `npm-install-script.yml`: Malicious postinstall/preinstall hooks
  - `download-executable.yml`: Remote binary download and execution
- **MITRE Techniques**: T1195.002 (Supply Chain Compromise), T1059.006 (Python)
- **License**: Apache-2.0
- **Citation**: DataDog Security Research

### Benign Samples

Our benign corpus represents common legitimate use cases:

#### 1. Developer Workflows
- Git operations, package management (npm, cargo, pip)
- Docker/container workflows
- Build systems (make, cmake)
- **Source**: Common patterns from open-source projects

#### 2. System Administration
- Service management (brew, systemctl)
- Log viewing and analysis
- System information gathering
- **Source**: Official documentation and tutorials

#### 3. Legitimate Network Operations
- curl/wget downloads (NOT piped to shell)
- API interactions
- Port testing with nc -zv
- **Source**: Official tool documentation

#### 4. Real-World Installers (Sanitized)
- Homebrew-style installation patterns
- Rustup/NVM-style environment setup
- **Note**: Patterns that modify RC files are correctly flagged as Medium
- **Source**: Official installer scripts (sanitized, no RC modifications)

## Labeling Methodology

### Ground Truth Establishment

1. **Expert Review**: Each sample reviewed by security researchers
2. **Multi-Source Verification**: Cross-referenced with:
   - VirusTotal (60+ AV engines)
   - MalwareBazaar community tags
   - YARA rule matches from established rulesets
3. **MITRE ATT&CK Mapping**: Each malware sample mapped to technique IDs

### Label Schema

```json
{
  "sample_id": "sha256_hash",
  "filename": "sample_001.sh",
  "is_malicious": true,
  "threat_category": "reverse_shell",
  "mitre_technique": "T1059.004",
  "severity": 10,
  "source": "gtfobins",
  "verification": {
    "virustotal_detections": 45,
    "yara_matches": ["revshell_bash_dev_tcp"],
    "expert_reviewed": true
  }
}
```

## How to Obtain Additional Labeled Data

### For Researchers

#### MalwareBazaar API
```bash
# Query for shell script samples
curl -X POST https://mb-api.abuse.ch/api/v1/ \
  -d "query=get_file_type" \
  -d "file_type=sh"

# Download sample by hash (password: infected)
curl -X POST https://mb-api.abuse.ch/api/v1/ \
  -d "query=get_file" \
  -d "sha256_hash=<HASH>" \
  -o sample.zip
```

#### VirusTotal Academic Access
1. Apply at: https://www.virustotal.com/gui/contact-us
2. Select "Academic API access" or "Access to malware folder"
3. Rate limits: ~500 requests/day for academic licenses

#### DataDog Malicious Packages Dataset
- **URL**: https://github.com/DataDog/malicious-software-packages-dataset
- **License**: Apache-2.0
- **Description**: Human-vetted malicious npm/PyPI packages

### For Security Teams

#### Threat Intelligence Feeds
- **Abuse.ch URLhaus**: https://urlhaus.abuse.ch/
- **AMOS IOC GitHub**: Community-maintained IOC lists
- **SentinelOne Research**: Published threat analyses

## Reproduction Instructions

### Running the Benchmark

```bash
# Build release binary
cargo build --release

# Run detection benchmark
cargo bench --bench detection_benchmark

# Run full test suite
cargo test --test malware_detection_tests
cargo test --test false_positive_tests
```

### Verifying Results

```bash
# Calculate TPR/FPR
cargo test --test detection_benchmark -- test_metrics_calculation --nocapture

# Generate HTML report
cargo bench -- --save-baseline main
```

### Expected Results

| Metric | Threshold | Notes |
|--------|-----------|-------|
| TPR (True Positive Rate) | >= 95% | Malware correctly detected |
| FPR (False Positive Rate) | <= 5% | Benign incorrectly flagged |
| P99 Latency | < 100ms | For inputs <= 10KB |

## Citation

If you use this test corpus in your research, please cite:

```bibtex
@software{pipeguard2026,
  title={PipeGuard: Defending Against Curl|Bash Attacks},
  author={Security Ronin},
  year={2026},
  url={https://github.com/SecurityRonin/pipeguard},
  note={Test corpus version 1.2}
}
```

## License

- **Test infrastructure**: MIT License
- **Malware samples**: Research use only (see individual source licenses)
- **Benign samples**: MIT License

## Changelog

### v1.2 (January 2026)
- Added 11 real-world samples extracted from DataDog malicious packages dataset
- Analyzed packages: boogishell, discord-hook, ReverseShell, SpyWare, 0vulns-dependency-confusion-poc
- C2 infrastructure documented: 114.116.119.253, paste.bingner.com, webhook.site
- Total samples: 79 malware, 40+ benign
- New documentation: `supply_chain/datadog_real_samples.md`

### v1.1 (January 2026)
- Added 13 supply chain attack patterns from DataDog GuardDog
- New category: supply_chain/ (PyPI/npm malicious packages)
- Total samples: 68 malware, 40+ benign
- MITRE coverage expanded: T1195.002 (Supply Chain Compromise)

### v1.0 (January 2026)
- Initial release with 55+ malware patterns
- 40+ benign workflow patterns
- Coverage for AMOS, ClickFix, and classic attack vectors
