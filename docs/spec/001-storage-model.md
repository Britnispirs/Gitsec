# RFC 001: Gitsec Storage Model & Object Graph

- **Status:** Draft / Active
- **Author:** Gitsec Core Architecture Group
- **Created:** 2026-11-13
- **Category:** Architecture & Storage

---

## 1. Abstract

This specification defines the storage layout, content-addressable object store (CAS), and cryptographic object graph for **Gitsec** (Security Version Control System).

Gitsec maintains a dedicated metadata directory, `.sec/`, residing alongside the `.git/` directory in a project repository. All security states are modeled as immutable, cryptographically hashed objects forming a Directed Acyclic Graph (DAG) that is anchored directly to Git commit hashes.

---

## 2. Directory Layout (`.sec/`)

When a repository is initialized (`sec init`), the following structure is created:

```text
.sec/
├── HEAD                   # Symbolic pointer to current security branch (ref: refs/heads/main)
├── config.json            # Repository security configuration and verifier profiles
├── index.json             # Staging area for findings from running verifiers
├── objects/               # Content-addressable object database
│   ├── info/              # Packs and alternate metadata (reserved)
│   └── pack/              # Compressed object packs (for large repos)
│   └── [0-9a-f]{2}/       # Loose objects sharded by the first 2 hex digits of their SHA-256
│       └── [0-9a-f]{62}   # Compressed blob (zlib level 6)
└── refs/
    ├── heads/             # Local security branch heads (e.g., refs/heads/main)
    ├── remotes/           # Remote tracking branches (e.g., refs/remotes/origin/main)
    └── tags/              # Immutable release attestations (e.g., refs/tags/v1.0.0-certified)
```

---

## 3. The Content-Addressable Object Model

Every immutable entity in Gitsec is an **Object**. 

### 3.1 Object Header & Hashing

An object's unique identifier (`ObjectID`) is calculated as:

$$\text{ObjectID} = \text{SHA-256}(\text{Type} \mathbin{\Vert} \text{" "} \mathbin{\Vert} \text{SizeInBytes} \mathbin{\Vert} \text{"\0"} \mathbin{\Vert} \text{Payload})$$

This follows the Git header convention, preventing type-confusion attacks where a serialized `Finding` could have the identical hash of a `Snapshot`.

Payloads are canonicalized JSON (keys sorted alphabetically, no whitespace padding) compressed with `zlib`.

---

## 4. Object Types

Gitsec defines four primitive object types:

```
  ┌────────────────────────────────────────────────────────┐
  │                    Snapshot Object                     │
  │   - git_commit_sha: c8f12ad...                         │
  │   - parent_snapshot: 7e220a1...                        │
  │   - posture: DEGRADED                                  │
  └─────────────┬──────────────────────────┬───────────────┘
                │                          │
                ▼                          ▼
  ┌─────────────────────────┐    ┌─────────────────────────┐
  │     Finding Object      │    │     Evidence Object     │
  │ - rule_id: hardcoded-key│    │ - verifier: secrets-v1  │
  │ - severity: CRITICAL    │    │ - input_hash: a812f...  │
  │ - location: auth.ts:42  │    │ - raw_stdout_hash: e9...│
  └─────────────────────────┘    └─────────────────────────┘
```

### 4.1 `Snapshot` Object (`type: snapshot`)
Represents an immutable, point-in-time security audit of a specific code tree.

```json
{
  "schema_version": "1.0.0",
  "git_commit": "4c910b8e721a3089d1bf249c69d80d2df595b16e",
  "parents": ["s7f21a8d..."],
  "author": {
    "name": "Alex Bahonin",
    "email": "alex@example.com",
    "timestamp": 1794558000
  },
  "summary": {
    "posture": "DEGRADED",
    "critical_count": 1,
    "high_count": 0,
    "medium_count": 2,
    "low_count": 0,
    "suppressed_count": 0
  },
  "tree": {
    "findings": [
      "f18b32940a02ef893a7482b832b8519409893d7c50a266b72a8597395ef0841a",
      "f8329b8401a09849208490a09428094892048902849082904892084920849028"
    ],
    "evidence": [
      "e3810f9208a098d0284092840982049820489028490284902849028490284902"
    ],
    "policy": "p9208409284098204982049820489028490284902849028490284902849028490"
  },
  "message": "Security baseline for payment service refactor"
}
```

### 4.2 `Finding` Object (`type: finding`)
Represents a single detected vulnerability, misconfiguration, or secret.

- **Stable Fingerprint:** To allow `sec diff` to track a vulnerability across commits even if code lines shift up or down, each finding computes a semantic fingerprint (hash of code context, rule ID, and symbol name).

```json
{
  "schema_version": "1.0.0",
  "rule_id": "secrets/stripe-live-secret-key",
  "fingerprint": "fp_8a928e192a00c8f9",
  "category": "SECRET",
  "severity": "CRITICAL",
  "title": "Unencrypted Stripe Secret Key detected in source file",
  "location": {
    "file_path": "src/billing/stripe.ts",
    "start_line": 14,
    "end_line": 14,
    "start_col": 21,
    "end_col": 53
  },
  "context": {
    "snippet": "const stripeKey = \"sk_live_51M0...sample\";"
  },
  "remediation": {
    "guidance": "Move the secret key to an environment variable (.env) and access via process.env.STRIPE_SECRET_KEY.",
    "auto_fixable": false
  }
}
```

### 4.3 `Evidence` Object (`type: evidence`)
Ensures auditability and non-repudiation. Anyone can re-execute the verifier on the same inputs and prove the snapshot was generated truthfully.

```json
{
  "schema_version": "1.0.0",
  "verifier": {
    "name": "builtin/secrets-scanner",
    "version": "0.1.0",
    "binary_hash": "b82049...sha256"
  },
  "execution": {
    "started_at": 1794557998,
    "finished_at": 1794558000,
    "duration_ms": 142,
    "exit_code": 1
  },
  "inputs": {
    "git_tree_hash": "a984028409284092840928409284092840928409284092840928409284092840",
    "target_paths": ["src/"]
  },
  "raw_output_sha256": "d41d8cd98f00b204e9800998ecf8427e...sha256"
}
```

### 4.4 `Policy` Object (`type: policy`)
Defines the rules applied to judge findings into an overall posture (CLEAN, DEGRADED, CRITICAL).

```json
{
  "schema_version": "1.0.0",
  "name": "strict-zero-critical",
  "rules": {
    "fail_on_severity": ["CRITICAL", "HIGH"],
    "allow_unresolved_medium_days": 14,
    "forbidden_categories": ["SECRET"]
  },
  "exceptions": []
}
```

---

## 5. Branching & References

1. **Symbolic `HEAD`:** Points to the active security branch reference.
   ```text
   ref: refs/heads/main
   ```
2. **Branch heads:** Stored under `.sec/refs/heads/<branch-name>`. Contains a 64-character hex string of the tip `Snapshot` ObjectID.
3. **Synchronization with Git:** When switching git branches (`git checkout feature`), Gitsec resolves the corresponding security branch (`.sec/refs/heads/feature`). If it doesn't exist, it branches off the common merge-base snapshot.

---

## 6. Security & Tamper Resistance

1. **Cryptographic Chaining:** Changing any finding or evidence retroactively alters its SHA-256 hash, cascading upward and invalidating the `Snapshot` hash and all descendant commits.
2. **Air-gapped verification:** A `.sec/` folder can be copied or archived; any verifier can re-verify the whole chain of custody offline without calling any external API.

