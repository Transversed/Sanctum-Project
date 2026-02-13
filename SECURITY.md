# Security Policy

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in Sanctum, please report it responsibly:

1. **Email**: Send a PGP-encrypted email to the maintainers (key available on request via a secure channel)
2. **GitHub Private Advisory**: Use [GitHub Security Advisories](https://github.com/sanctum-chat/sanctum/security/advisories/new) to report privately

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
- Authentication bypasses (PGP challenge-response)
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
6. **Minimal trust**: Authentication via PGP fingerprint allowlist, not server authority

## Supported Versions

| Version | Supported |
|---------|-----------|
| v0.1.x (current) | ✅ |
| < v0.1 | ❌ |

## Audit Status

Sanctum has **not yet undergone a formal security audit**. An external audit is planned for the v1.0 milestone. Use at your own risk.

## PGP Key for Encrypted Reports

*(To be added when the project maintainer's dedicated reporting key is generated)*

---

Thank you for helping keep Sanctum secure.
