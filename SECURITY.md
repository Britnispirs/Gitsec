# Security Policy

The Gitsec project takes the security of its codebase and ecosystem seriously.
As an infrastructure tool designed to monitor and attest to software security states, Gitsec must uphold the highest standards of integrity.

## Supported Versions

Only the latest development version on the default branch and the most recent major/minor releases receive active security updates.

| Version | Supported          |
| ------- | ------------------ |
| >= 0.1  | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability within Gitsec, **do not open a public issue.**

Please report security issues directly using one of the following methods:

1. **GitHub Security Advisories:** Use the "Report a vulnerability" tab under the Security section of the Gitsec repository.
2. **Encrypted Security Email:** Alternatively, contact the maintainers with a PGP-encrypted message detailing the vulnerability, reproduction steps, and potential impact.

### What to Include in Your Report

- A descriptive summary of the vulnerability.
- Step-by-step instructions to reproduce the issue (including sample code or configuration files).
- The affected component (e.g., Object Store, Verifier Sandbox, Policy Engine, CLI).
- Assessment of potential impact (e.g., privilege escalation, sandbox escape, state tampering).

### Response SLA

- **Acknowledgment:** Within 24-48 hours of receipt.
- **Triage & Reproduction:** Within 5 business days.
- **Remediation & Patching:** High/Critical severity issues are prioritized for expedited patching and coordinated disclosure.

