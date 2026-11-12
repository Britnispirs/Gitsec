<div align="center">

# Gitsec (`sec`)

### The Version Control System for Software Security State

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-RFC%20%2F%20Early%20Alpha-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()

**Git tracks how your code changes over time. Gitsec tracks how your security posture changes over time.**

</div>

---

## 1. The Problem

In today's software engineering ecosystem, source code is managed with extreme rigor: content-addressable trees, cryptographically signed commits, branching, merging, and granular line-by-line diffs.

Security, however, is still stuck in the era of disconnected flat files:
- **Stateless Scans:** Security scanners run as transient CI jobs, dump raw JSON/SARIF blobs into logs, and exit.
- **No Lineage:** There is no verifiable link connecting a specific source commit, the exact policies enforced at that moment, the tools executed, and the raw evidence produced.
- **No Security Diff:** You cannot natively ask: *"What exact security drift was introduced between commit `A` and commit `B`?"*
- **SaaS Lock-in:** Security state is routinely offloaded to proprietary third-party platforms rather than living alongside the engineering artifacts.

## 2. The Gitsec Paradigm

Gitsec treats **Security State as a first-class, version-controlled entity**.

```
  Git (Code DAG)                 Gitsec (Security DAG)
─────────────────               ───────────────────────
[ Commit: c8f12a ] ────────────► [ Security Snapshot: s9b41e ]
        │                                   │
        ▼                                   ▼
[ Commit: 3d50bf ] ────────────► [ Security Snapshot: 7e220a ]
                                            │
                                            ├── Inputs Hash (Tree + Lockfiles)
                                            ├── Independent Verifiers Evidence
                                            ├── Policy Evaluation Record
                                            └── Posture Status: CLEAN | DEGRADED | CRITICAL
```

- **Code is one tree.**
- **Security state is a parallel, content-addressable tree.**
- Every security snapshot is cryptographically bound to a specific git commit, tool evidence hash, and policy version.

---

## 3. Core Principles

1. **Local-First & Autonomous:** No mandatory SaaS, no cloud account required. Works 100% offline on a developer's workstation, inside an air-gapped container, or in any CI pipeline.
2. **Reproducible Evidence:** A finding without verifiable evidence is an opinion. Gitsec captures tool versions, environment flags, and raw output hashes so any audit can be reproduced deterministically.
3. **Decoupled Verification & Policy:**
   - **Verifiers (Sensors):** Observe and measure ground truth (dependencies, secrets, AST patterns, integrity). They never decide whether a build fails.
   - **Policies (Judges):** Versioned rules that evaluate verifier outputs against organizational risk appetite.
4. **Git-Native UX:** Predictable mental model designed for engineers. If you know Git, you already know Gitsec.

---

## 4. The CLI Experience

```bash
# Initialize security state tracking in the current repository
$ sec init

# Inspect the security posture of the current working tree
$ sec status

# Run independent parallel verifiers (SCA, SAST, Secrets, Integrity)
$ sec check --all

# Record an immutable security snapshot bound to the current HEAD
$ sec commit -m "chore(sec): baseline security state for v1.4.0 release"

# Compare security posture between two revisions
$ sec diff HEAD~1..HEAD

# Inspect the chronological audit trail of security state changes
$ sec log --oneline
```

### Example: Security Diff (`sec diff`)

Unlike a code diff that shows modified lines, a security diff displays **risk delta**:

```text
$ sec diff main..feature/payments

SECURITY POSTURE DIFF: main (s4a19) -> feature/payments (s8c73)
Base Git Commit: 1a9f04d -> Target Git Commit: 4f18bc2

[+] RESOLVED FINDINGS (2)
  - [SCA] CVE-2026-1049 (requests < 2.32.0) [HIGH] - dependency upgraded to 2.32.4
  - [SECRETS] Stale staging token removed from tests/fixtures.py

[-] INTRODUCED FINDINGS (1)
  + [SAST] Insecure deserialization pattern detected:
    File: src/payments/webhook.py:42
    Rule: python/unsafe-pickle-load
    Severity: CRITICAL
    Policy: enterprise-default (violation: blocks merge)

OVERALL POSTURE: DEGRADED (1 blocking violation)
```

---

## 5. Architecture & Storage

All security state resides inside the `.sec/` metadata directory inside your repository:

```text
.sec/
├── HEAD               # Symbolic ref to active security branch (e.g., refs/heads/main)
├── config             # Repository-specific security configuration and verifiers
├── index              # Staging area for pending verification runs
├── objects/           # Content-addressable object store (SHA-256)
│   ├── [0-9a-f]{2}/   # Blobs: Snapshots, Findings, Evidence, Attestations
│   └── ...
└── refs/              # References
    ├── heads/         # Security branches (e.g., main, audit-q4)
    └── tags/          # Signed security milestones (e.g., v1.0.0-certified)
```

---

## 6. Project Roadmap

- [ ] **Phase 0: Foundations & RFC**
  - [x] Manifesto & Repository Core
  - [ ] CAS & Object Storage RFC (`docs/spec/001-storage-model.md`)
  - [ ] Snapshot & Evidence Schema RFC (`docs/spec/002-snapshot-format.md`)
  - [ ] Verifier Contract RFC (`docs/spec/003-verifier-contract.md`)
- [ ] **Phase 1: Minimal Viable Engine (CLI)**
  - [ ] `sec init` (CAS directory scaffolding)
  - [ ] Basic Verifiers Runner (Parallel execution pool)
  - [ ] `sec check` & `sec status`
  - [ ] `sec commit` (Immutable snapshot generation)
  - [ ] `sec diff` (Tree comparison engine)
- [ ] **Phase 2: Policy-as-Code Engine**
  - [ ] Versioned policy declarations
  - [ ] Exception lifecycle management (time-bound waivers)
- [ ] **Phase 3: Attestations & Cryptographic Provenance**
  - [ ] In-toto / Cosign compatible snapshot signing
- [ ] **Phase 4: Remote Sync & Collaboration**
  - [ ] `sec push` / `sec pull` via git-notes or dedicated security refs

---

## 7. License

Licensed under the Apache License, Version 2.0 (the "License"). You may obtain a copy of the License in the [LICENSE](LICENSE) file.

