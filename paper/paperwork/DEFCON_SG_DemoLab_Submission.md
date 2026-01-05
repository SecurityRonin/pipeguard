# DEF CON Singapore 2026 - Demo Labs Submission

**Conference:** April 28-30, 2026 | Marina Bay Sands, Singapore
**Submission Deadline:** February 15, 2026 at Midnight UTC
**Materials Due:** April 1, 2026 at Midnight UTC
**Contact:** demolab@defcon.org

---

## 1. PRESENTER INFORMATION

### Primary Presenter: Albert Hui

| Field | Value |
|-------|-------|
| **a. Full Name** (Required) | Albert, HUI Kwun Tai |
| **b. Pseudonym or Handle** | 4n6h4x0r |
| **c. Email** (Required) | albert@securityronin.com |
| **d. Submit Anonymously?** (Required) | N |
| **e. Program Identification** (Required) | B _(N=Name, H=Handle, B=Both)_ |
| **f. Preferred Pronouns** (Required) | he/him |
| **g. Backup Email** | albert@dc852.org |
| **h. Organization Affiliation** | Security Ronin |
| **i. Phone Number** (Required) | +852 9814 3692 |
| **j. Social Media / Personal Sites** | https://www.linkedin.com/in/alberthui |
| **k. Biography** (Required) | See below |
| **l. Previous DEF CON Speaker?** (Required) | N _(Black Hat 2013, but not DEF CON)_ |
| **m. Which DEF CONs?** | N/A |
| **n. ADA Accommodations?** (Required) | N |
| **o. Accommodation Details** | N/A |
| **p. Visa Required?** (Required) | N |
| **q. Passport Details** | N/A |
| **r. Role in Submission** | Tool architect and builder |

#### Albert's Biography (for submission)

```
Albert Hui is a cybersecurity veteran with 30+ years of experience spanning incident
response, digital forensics, and security architecture. Currently serving as Principal
Consultant at Security Ronin and Incident Response Specialist at Blackpanda, he brings
deep expertise in threat detection and malware analysis.

Albert is a high court-approved forensic expert witness with multiple successful criminal
defense cases. His previous speaking experience includes Black Hat 2013 ("Universal DDoS
Mitigation Bypass") and ACFE keynotes. He holds GCFA, GXPN, and numerous other
certifications. As a Python, Rust, and Linux kernel developer, he contributes to
open-source security tooling.

Previously: HSBC Incident Response Lead, Deloitte Director (Risk Advisory), Morgan Stanley
CERT, IBM Global Security Architect. Consulted by HKMA and MAS on banking security
guidelines.
```

---

### Co-Presenter: Eliza Wan

| Field | Value |
|-------|-------|
| **a. Full Name** (Required) | Eliza Wan |
| **b. Pseudonym or Handle** | `[TODO: Fill in handle if desired]` |
| **c. Email** (Required) | wanyathei@gmail.com |
| **d. Submit Anonymously?** (Required) | N |
| **e. Program Identification** (Required) | B _(N=Name, H=Handle, B=Both)_ |
| **f. Preferred Pronouns** (Required) | she/her |
| **g. Backup Email** | `[TODO: Fill in backup email]` |
| **h. Organization Affiliation** | `[TODO: Fill in affiliation]` |
| **i. Phone Number** (Required) | +852 6990 8014 |
| **j. Social Media / Personal Sites** | LinkedIn: https://www.linkedin.com/in/wyh80000/ |
| **k. Biography** (Required) | See below |
| **l. Previous DEF CON Speaker?** (Required) | N |
| **m. Which DEF CONs?** | N/A |
| **n. ADA Accommodations?** (Required) | N |
| **o. Accommodation Details** | N/A |
| **p. Visa Required?** (Required) | N |
| **q. Passport Details** | N/A |
| **r. Role in Submission** | Detection engineer, malware live demonstration |

#### Eliza's Biography (for submission)

```
Eliza Wan is a DFIR Specialist at Blackpanda with over 4 years of experience in incident
response, threat hunting, and security operations. She has investigated ransomware,
business email compromise, and data exfiltration incidents for Fortune 100 companies,
top-tier banks, and critical infrastructure across the Asia-Pacific region.

Eliza holds SANS GCFA (Certified Forensic Analyst), GREM (Reverse Engineering Malware),
and CRTP (Certified Red Team Professional) certifications. Her expertise spans remote
investigation with commercial EDR tools, security automation development, and threat
intelligence-driven hunting.

Previous experience includes Security Analyst at Bullish HK, Senior Consultant at
Deloitte Advisory (Cyber Incident Response), and Threat Analyst at Ensign Infosecurity.
```

---

## 2. DETAILED OUTLINE (CFP Board Only - Not Published)

### Demo Title
**PipeGuard: Defending Against curl|bash Attacks Through Multi-Layer Shell Interception**

### Problem Statement
The rise of AI-assisted development has created a perfect storm for malicious `curl | bash` attacks. Developers increasingly copy installation commands from ChatGPT, Claude, and similar tools directly into terminals. This content bypasses macOS Gatekeeper (no quarantine attribute on piped content) and executes before traditional AV can detect it.

Recent campaigns (AMOS stealer, ClickFix) show 500% increase in this attack vector. MITRE ATT&CK codified it as T1204.004 "Malicious Copy and Paste."

### Solution Overview
PipeGuard provides defense-in-depth through:

1. **Three-Layer Interception**
   - ZLE keyboard binding (catches paste before shell parsing)
   - Hardened shell wrappers (intercepts curl/wget piped to shells)
   - Preexec audit hooks (final inspection before execution)

2. **Multi-Stage Detection Pipeline**
   - Stage 1: YARA signature matching (~10ms)
   - Stage 2: Apple XProtect integration (~10ms)
   - Stage 3: ClamAV deep scan (~50ms)
   - Stage 4: Behavioral sandbox analysis (~500ms)

3. **Tiered Response**
   - Low threat: Warning banner
   - Medium threat: Interactive prompt
   - High threat: Block execution

### Demo Flow (20 minutes + 10 min Q&A)

| Time | Segment | Content |
|------|---------|---------|
| 0:00 | Intro | Problem statement, real-world attack examples |
| 2:00 | Attack Demo | Show unprotected system executing AMOS-style payload |
| 5:00 | Architecture | Three-layer interception diagram |
| 8:00 | Live Install | `pipeguard install --shell zsh` |
| 10:00 | Detection Demo | Trigger each detection stage with test payloads |
| 15:00 | Bypass Attempts | Show what PipeGuard catches vs. traditional AV |
| 18:00 | Enterprise | Brief mention of PipeGuard Pro features |
| 20:00 | Q&A | Open discussion |

### Supporting Materials

- **Source Code:** https://github.com/SecurityRonin/pipeguard (MIT License)

### Technical Requirements
- MacBook Pro with macOS 14+ (we will bring our own)
- Network connection for live GitHub pulls
- Standard monitor connection (HDMI/USB-C)

---

## 3. PRESENTATION ABSTRACT (Max 1337 characters)

**Copy this exactly into OpenConf Abstract field:**

```
PipeGuard: Defending Against curl|bash Attacks Through Multi-Layer Shell Interception

AI coding assistants have normalized copy-pasting installation commands directly into
terminals. This creates a critical vulnerability: piped content bypasses macOS Gatekeeper
entirely—no quarantine attribute, no signature check, no notarization.

We present PipeGuard, an open-source defense tool that intercepts curl|bash patterns at
three layers: ZLE keyboard bindings, hardened shell wrappers, and preexec audit hooks.
Intercepted content flows through a detection pipeline combining YARA signatures, Apple
XProtect, ClamAV, and behavioral sandbox analysis.

In this demo, we'll show:
- Live attacks using AMOS/ClickFix-style payloads
- PipeGuard's interception catching threats pre-execution
- Side-by-side comparison with traditional AV (which fails)
- Enterprise deployment via MDM

PipeGuard fills a gap that existing tools miss: the pre-execution boundary where scripts
never touch the filesystem. Whether you're a developer protecting your workstation or a
security team defending a fleet, this tool belongs in your arsenal.

Source: https://github.com/SecurityRonin/pipeguard (MIT License)
```

**Character count:** ~1,290 characters

---

## 4. PUBLISHABLE REFERENCES

```
[1] Jayson E. Street

[2] Dragos Ruiu
```

---

## 5. CONFIDENTIAL REFERENCES (CFP Board Only)

```
Nil
```

---

## SUBMISSION CHECKLIST

- [ ] All required fields completed for both presenters
- [ ] Biographies proofread and within length limits
- [ ] Abstract under 1337 characters
- [ ] Demo video recorded and uploaded
- [ ] GitHub repo public and README complete
- [ ] OpenConf account created
- [ ] PDF/TXT attachment prepared
- [ ] Topic selected as "Demo Lab" in OpenConf
- [ ] Submission agreements read and accepted

---

## IMPORTANT DEADLINES

| Date | Milestone |
|------|-----------|
| **Feb 15, 2026** | Submission deadline (Midnight UTC) |
| **Apr 1, 2026** | Final materials due (presentation PDF, code, bibliography) |
| **Apr 1, 2026** | Final abstract and biography due |
| **Apr 28-30, 2026** | DEF CON Singapore |
| **May 7, 2026** | Post-conference updated materials due |

---

## AGREEMENTS TO ACCEPT IN OPENCONF

1. Grant of Copyright Use - Permission to record and redistribute
2. Materials submission by April 1, 2026
3. Complete presentation within allocated time
4. Use DEF CON provided laptops for presentation
5. Responsible for own travel expenses
6. $300 SGD honorarium to primary speaker
7. Code of Conduct compliance

---

## NOTES

- Tool MUST be open source (PipeGuard is MIT licensed)
- This is NOT for sales/vendor pitches (we're showing the open-source tool, Pro is just mentioned)
- 2-hour time slot, repeat demo multiple times (~20 min demo + 10 min Q&A each)
- Provided: table, monitors, network, power
- Bring: Own laptop for demo

---

## TODO ITEMS

- [ ] **Eliza:** Confirm handle for program (or remove if not desired)
- [ ] **Eliza:** Add backup email
- [ ] **Eliza:** Add organization affiliation
- [ ] **Both:** Review and finalize biographies
- [ ] **Both:** Create OpenConf accounts
- [ ] Submit before February 15, 2026 Midnight UTC
