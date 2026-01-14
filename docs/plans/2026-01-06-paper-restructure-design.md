# Paper Restructure Design: Clarity Through Narrative

**Date**: 2026-01-06
**Status**: ✅ Structure implemented (technical details evolved)
**Goal**: Reduce cognitive load, improve clarity and eloquence

> **NOTE:** This document describes the paper structure and narrative approach (which was implemented).
> Technical implementation details evolved from the original 4-stage detection pipeline to a 2-stage
> pipeline (Smart Content Filtering + YARA). See current paper sections for accurate technical content.

## Overview

Restructure the PipeGuard paper around "Human Prompt Injection" as the conceptual spine, with agent prompt injection as the forward-looking generalization. Move from front-loaded exposition to problem-first narrative.

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Central framing | Human Prompt Injection → Agent generalization | Visceral hook + forward-looking relevance |
| Structure | Problem-Solution-Context | Readers understand "why" before "what" |
| Design + Implementation | Merge into "Architecture" | Reduce cognitive switching, practitioner-friendly |
| Tool comparisons | Move to "Why Defenses Fail" | Part of the argument, not scholarly appendix |
| Limitations | Promote to Evaluation subsection | Shows intellectual honesty prominently |
| Related Work | Academic citations only | Scholarly duty, not competitive positioning |

## New Structure

```
1. Introduction              (~25 lines)
2. The Prompt Injection Threat (~80 lines)
3. Why Existing Defenses Fail  (~60 lines)
4. Architecture               (~90 lines)
5. Evaluation                 (~180 lines, includes Limitations)
6. Related Work               (~40 lines)
7. Discussion                 (~50 lines)
8. Conclusion                 (~20 lines)
```

**Total**: ~545 lines (similar to current ~560 lines)

## Content Mapping

### Files

```
OLD                          →  NEW
─────────────────────────────────────────────────────────────
01-introduction.qmd          →  01-introduction.qmd (tightened)
02-background.qmd            →  DELETED (content distributed)
03-threat-model.qmd          →  DELETED (merged into §2)
04-design.qmd                →  DELETED (merged into §4)
05-implementation.qmd        →  DELETED (merged into §4)
06-evaluation.qmd            →  05-evaluation.qmd (+ Limitations)
07-related-work.qmd          →  06-related-work.qmd (academic only)
08-discussion.qmd            →  07-discussion.qmd (trimmed)
09-conclusion.qmd            →  08-conclusion.qmd

NEW FILES:
  02-prompt-injection-threat.qmd
  03-why-defenses-fail.qmd
  04-architecture.qmd
```

### Content Flow

```
02-background.qmd content moves to:
├── curl|bash pattern        → 03-why-defenses-fail.qmd
├── macOS security           → 03-why-defenses-fail.qmd
├── AI shift                 → 01-introduction.qmd
├── Human prompt injection   → 02-prompt-injection-threat.qmd
├── Attack timeline          → 02-prompt-injection-threat.qmd
└── Threat landscape         → 02-prompt-injection-threat.qmd

03-threat-model.qmd content moves to:
├── Adversary capabilities   → 02-prompt-injection-threat.qmd
├── Attack vectors           → 02-prompt-injection-threat.qmd
├── Security goals           → 02-prompt-injection-threat.qmd
└── Non-goals                → 02-prompt-injection-threat.qmd

04-design.qmd + 05-implementation.qmd merge into:
└── 04-architecture.qmd      (interleaved design + implementation)

07-related-work.qmd splits:
├── Tool comparisons         → 03-why-defenses-fail.qmd
└── Academic citations       → 06-related-work.qmd

08-discussion.qmd splits:
├── Limitations              → 05-evaluation.qmd (subsection)
├── Ethics                   → woven into relevant sections
└── Deployment + Future      → 07-discussion.qmd
```

## Section Specifications

### 01-introduction.qmd (~25 lines)

**Purpose**: Hook readers, introduce core concept, state contributions

**Content**:
- Hook: AI-assisted development has weaponized `curl | bash`
- The "human prompt injection" parallel (2-3 sentences)
- Teaser: This generalizes to AI agents
- Gap statement: Pre-execution boundary is undefended
- Contributions: 4 bullets (unchanged)

**Remove**: Attack statistics (→ §2), macOS technical details (→ §3)

**Tone**: Urgent but precise

### 02-prompt-injection-threat.qmd (~80 lines)

**Purpose**: Establish the threat model with visceral clarity

**Content**:
1. **Human Prompt Injection** (~30 lines)
   - The AI/human parallel table
   - Behavioral conditioning (years of tutorials)
   - Why users comply without inspection

2. **Attack Campaigns** (~20 lines)
   - AMOS, ClickFix, AI poisoning
   - Timeline format: Legacy → ClickFix → AI Poisoning → Agentic
   - The 500% increase statistic

3. **Agent Prompt Injection** (~15 lines)
   - MCP/Comet example
   - Why this is the same threat model
   - Shell boundary as unified defense point

4. **Threat Model Formalization** (~15 lines)
   - Adversary capabilities
   - Security goals and non-goals

**Tone**: Visceral, concrete examples, "this is happening now"

### 03-why-defenses-fail.qmd (~60 lines)

**Purpose**: Create inevitability for PipeGuard

**Content**:
1. **macOS Security Architecture** (~20 lines)
   - Gatekeeper + quarantine attribute
   - XProtect scanning triggers
   - Why pipes bypass everything

2. **Traditional Security Gaps** (~15 lines)
   - AV: scans files, not streams
   - EDR: detects post-execution

3. **Existing Tools** (~20 lines)
   - Santa: binaries only
   - Objective-See: post-execution monitoring
   - Falco: behavioral detection
   - osquery: detection not prevention

4. **The Gap** (~5 lines)
   - Pre-execution script scanning at the pipe boundary doesn't exist
   - This is what PipeGuard fills

**Tone**: Systematic, builds inevitability

### 04-architecture.qmd (~90 lines)

**Purpose**: Explain how PipeGuard works (design + implementation unified)

**Content**:
1. **Overview** (~5 lines)
   - Defense-in-depth: interception → detection → response

2. **Interception Layers** (~25 lines)
   - Layer 1: ZLE keyboard binding (with zsh code)
   - Layer 2: Hardened shell wrappers (with wrapper code)
   - Layer 3: Preexec audit hook (with hook code)
   - Why three layers: bypass one, others catch

3. **Detection Pipeline** (~35 lines)
   - Stage 1: YARA (yara-rust, compiled rules, ~5ms)
   - Stage 2: XProtect (XProtectService invocation)
   - Stage 3: ClamAV (clamdscan --fdpass)
   - Stage 4: Sandbox (sandbox-exec profile code)
   - Why staged: fast-fail, each adds unique coverage

4. **Threat Response** (~15 lines)
   - Level table: Low/Medium/High → Warn/Prompt/Block
   - Enterprise MDM config
   - Agent vs human response difference

5. **Performance Design** (~10 lines)
   - Pre-compiled YARA rules
   - ClamAV daemon mode
   - Async sandbox with timeout

**Tone**: Practitioner-friendly, shows actual code

### 05-evaluation.qmd (~180 lines)

**Purpose**: Prove it works, acknowledge limitations

**Content**:
1. **Experimental Setup** (~30 lines)
   - Malware corpus: 156 samples
   - Benign corpus: 234 samples
   - Test environment

2. **Detection Effectiveness** (~50 lines)
   - TPR table by stage
   - FPR table by stage
   - Combined: 96.8% TPR, 1.7% FPR
   - AV comparison table

3. **Performance Overhead** (~40 lines)
   - Latency table
   - Memory table
   - Summary: <100ms static, ~500ms with sandbox

4. **Usability Study** (~30 lines)
   - 12 developers, 2 weeks
   - Friction events table
   - User feedback
   - Enterprise deployment results

5. **Limitations** (~30 lines) — PROMOTED FROM DISCUSSION
   - Bypass techniques: obfuscation, shell alternatives, timing
   - Detection gaps: zero-day, time-bombs
   - Platform scope: macOS only
   - Honest acknowledgment

**Tone**: Rigorous, honest about boundaries

### 06-related-work.qmd (~40 lines)

**Purpose**: Academic positioning (scholarly duty)

**Content**:
- Supply chain security (Ladisa taxonomy, Ohm backstabber)
- Shell security research
- YARA effectiveness studies
- Provenance-based detection
- Script security (pipethis mention)

**Remove**: All tool comparisons (now in §3)

**Tone**: Scholarly, citation-focused

### 07-discussion.qmd (~50 lines)

**Purpose**: Deployment guidance and future vision

**Content**:
1. **Deployment Considerations** (~25 lines)
   - Enterprise vs individual
   - False positive management
   - Maintenance burden

2. **Future Work** (~25 lines)
   - ML integration
   - Cross-platform (Linux, Windows)
   - Browser/IDE integration

**Remove**: Limitations (now in §5), detailed ethics (1-2 sentences woven into Limitations re: user autonomy)

**Tone**: Forward-looking, practical

### 08-conclusion.qmd (~20 lines)

**Purpose**: Summarize and call to action

**Content**: Largely unchanged, slight tightening

- The threat is real and growing
- PipeGuard fills the pre-execution gap
- Results: 96.8% detection, 1.7% FP
- Available open source

## Narrative Flow Check

```
Reader journey:

1. HOOK: "AI + curl|bash = problem" (Introduction)
         ↓
2. FEAR: "I could be prompt-injected, and so could my AI tools" (Threat)
         ↓
3. FRUSTRATION: "Nothing I have protects me" (Why Defenses Fail)
         ↓
4. RELIEF: "Here's how PipeGuard works" (Architecture)
         ↓
5. TRUST: "It actually works, here's proof" (Evaluation)
         ↓
6. CONTEXT: "Where this fits academically" (Related Work)
         ↓
7. VISION: "What's next" (Discussion)
         ↓
8. ACTION: "Use it" (Conclusion)
```

## Implementation Notes

1. **Update index.qmd** to reference new section files
2. **Update _quarto.yml** abstract if needed (current abstract is good)
3. **Preserve all citations** — ensure refs.bib entries move with content
4. **Preserve tables** — LaTeX table code moves unchanged
5. **Test PDF build** after restructure

## Success Criteria

- [ ] Reviewers can state the core contribution after reading §1-2
- [ ] Technical depth appears only after problem is established
- [ ] Limitations are visible and honest
- [ ] Paper reads as argument, not section checklist
- [ ] Total length within 10% of original
