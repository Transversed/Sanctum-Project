# Security Policy

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in Sanctum, please report it responsibly:

1. **GitHub Private Advisory** (preferred): use [GitHub Security Advisories](https://github.com/Transversed/Sanctum-Project/security/advisories/new) to report privately
2. **Email**: contact the maintainer through GitHub and ask for an encrypted channel

Include in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

| Action | Timeframe |
|--------|-----------|
| Acknowledgment of report | 48 hours |
| Initial assessment | 7 days |
| Fix development | 14-30 days (severity dependent) |
| Public disclosure | After fix is released |

## Scope

The following are in scope for security reports:

- Cryptographic weaknesses (Noise NK, X3DH, Double Ratchet implementation)
- Authentication or admission bypasses (Ed25519 challenge-response, invitations)
- Any way for the host to read, forge or attribute wrongly a message
- Terminal injection through remote content
- Anti-replay circumvention
- Disk writes in ephemeral mode
- Secret leakage (keys in logs, core dumps, swap)
- Memory safety issues (`unsafe` blocks, use-after-free via `zeroize`)
- Tor de-anonymization caused by Sanctum (traffic patterns, metadata leaks)
- Protocol downgrade attacks
- Dependency vulnerabilities in critical crates

## Out of Scope

- Tor network vulnerabilities (report to [Tor Project](https://www.torproject.org/))
- Social engineering attacks
- Attacks requiring physical access AND a running, unlocked session
- Denial of service via Tor (inherent to hidden services)
- Theoretical side-channel attacks without a practical exploit

## Security Design Principles

Sanctum follows these principles — deviations are considered bugs:

1. **Zero disk in ephemeral mode**: No file creation under any circumstance
2. **Forward secrecy**: Past messages unrecoverable if current keys compromised
3. **Host-blind**: The host never has access to plaintext messages
4. **Zeroize on drop**: All key material is wiped from memory when no longer needed
5. **No fallback**: No clearnet, no protocol downgrade, no weak cipher suites
6. **Minimal trust**: the host never trusts a declared fingerprint; admission requires a proven key and an owner-signed invitation

## Supported Versions

| Version | Supported |
|---------|-----------|
| v0.1.1 (current) | ✅ |
| ≤ v0.1.0 | ❌ (protocol v1: no real E2E, unauthenticated admission) |

## Audit Status

Sanctum has **not yet undergone a formal security audit**. v0.1.1 closes the
findings of an internal review (see CHANGELOG.md); an external audit is planned.
The residual risks are listed in [docs/threat-model.md](docs/threat-model.md).
Use at your own risk.

---

Thank you for helping keep Sanctum secure.
