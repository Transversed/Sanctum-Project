# Sanctum — Threat Model

## Overview

Sanctum is a Tor-only, end-to-end encrypted chat tool. This document describes the threat model: who the adversaries are, what they can do, and how Sanctum mitigates their capabilities.

**Core security property**: The host relays ciphertext and cannot read message content. In ephemeral mode, a seized machine yields nothing.

---

## 1. Adversaries

| Adversary | Capabilities | Motivation |
|-----------|-------------|------------|
| **Network observer (ISP/State)** | Traffic analysis, timing correlation, DPI | Identify participants, map communications |
| **Host compromise** | Root access to VPS running a persistent host | Read messages, identify members, tamper with routing |
| **Malicious member** | Legitimate access to a room | Exfiltrate content, impersonate others, disrupt |
| **Active attacker (MITM)** | Intercept/modify Tor traffic (theoretical) | Inject messages, replay, downgrade protocol |
| **Physical attacker** | Physical access to a participant's machine | Extract keys from disk/RAM, read storage |

---

## 2. Attack Surfaces

| ID | Surface | Component | Risk |
|----|---------|-----------|------|
| S1 | Tor transport | Client ↔ Host link | Traffic correlation, timing attacks |
| S2 | Authentication protocol | PGP challenge-response | Replay, impersonation if key compromised |
| S3 | E2E encryption | Double Ratchet pairwise | Session key compromise |
| S4 | Persistent storage | Encrypted SQLite | Physical access, cold boot attacks |
| S5 | Memory (RAM) | Keys in memory | Memory dump, swap leak |
| S6 | Metadata | Timestamps, message sizes | Pattern analysis |
| S7 | Supply chain | Rust crates | Backdoor, unpatched vulnerability |
| S8 | Tor Control Port | Tor management interface | Unauthorized HS creation/destruction |

---

## 3. Threat Scenarios and Mitigations

### T1 — Host VPS Compromised

**Impact**: Critical. Attacker has root access to the host machine.

**What the attacker gets**:
- List of room members (PGP fingerprints, aliases, X25519 public keys)
- Ciphertext blobs in the backlog (persistent mode)
- Tor hidden service private key (can impersonate the .onion address)

**What the attacker does NOT get**:
- Plaintext messages (E2E encrypted, host never has decryption keys)
- Private PGP keys of members
- X25519 private keys of members
- Double Ratchet session state

**Mitigations**:
- E2E encryption (ADR-003): host is blind to content
- Backlog contains only opaque ciphertexts
- In ephemeral mode: no storage, no HS key on disk — nothing to seize

### T2 — PGP Key Stolen

**Impact**: High. Attacker can impersonate the victim.

**Mitigations**:
- PGP is used for authentication only, not message encryption (ADR-004)
- Forward secrecy via Double Ratchet: past messages remain secure
- Revocation: owner can kick the compromised fingerprint immediately
- Recommended: use a dedicated PGP signing subkey for Sanctum (revocable independently)

### T3 — Message Replay

**Impact**: Medium. Attacker re-sends a captured ciphertext.

**Mitigations**:
- Monotonic sequence counter per sender per room (ADR-006)
- 64-bit sliding bitmap window for out-of-order tolerance
- Unique AEAD nonces derived from counter + salt
- Timestamp tolerance (±120s) for backlog expiration, NOT for anti-replay

### T4 — Traffic Analysis / Correlation

**Impact**: High. Attacker correlates timing patterns to identify participants.

**Mitigations**:
- Tor as sole transport (ADR-001): no clearnet metadata
- Message padding to 256-byte blocks (ADR-010): uniform message sizes
- No user-identifiable data in transport headers
- Limitation: Tor itself is vulnerable to global passive adversaries (out of scope)

### T5 — Disk Read After Seizure

**Impact**: Critical. Attacker has physical access to the machine.

**Mitigations**:
- Ephemeral mode: zero disk writes, verified via `strace` (ADR-007)
- Persistent mode: AES-256-GCM encryption with Argon2id key derivation (m=256MiB, t=4, p=2)
- Per-field encryption with unique nonces
- Master key never stored on disk (derived from passphrase at runtime)

### T6 — Swap / Core Dump Leak

**Impact**: High. Secrets leaking to disk via OS mechanisms.

**Mitigations**:
- `mlock()` on all key material (ADR-008)
- `zeroize` on drop for all secret types
- Core dumps disabled (`ulimit -c 0`)
- Recommended: disable swap entirely in ephemeral mode (`swapoff -a`)

### T7 — Malicious Room Member

**Impact**: Medium. Member can copy/screenshot messages they receive.

**Mitigations**:
- Out of scope for cryptographic protection (inherent to any messaging system)
- Operational mitigation: owner can revoke immediately via `/kick`
- All members rotate SPK and purge sessions with revoked member
- Ephemeral mode: no history to exfiltrate retroactively

### T8 — Protocol Downgrade

**Impact**: Critical. Attacker forces use of weaker protocol version.

**Mitigations**:
- Protocol version in every `HandshakeInit`
- Strict version check: reject if version < minimum supported
- No fallback modes, no optional encryption, no weak cipher suites
- `server_id` = SHA-256(host Noise public key) prevents challenge relaying

---

## 4. Explicit Assumptions

- Tor provides the expected network anonymity
- The user protects their PGP private key with a strong passphrase
- The operating system is not compromised at deployment time
- Rust crates are authentic (mitigated by `cargo-deny` + `cargo-audit` in CI)
- The `crossterm` crate does not create temporary files (verified by AT-07)

## 5. Out of Scope

- CPU side-channel attacks (Spectre, Meltdown, etc.)
- Compromise of the Tor network itself (guard discovery, Sybil attacks)
- Pure social engineering
- Rubber-hose cryptanalysis
- Attacks requiring both physical access AND an active unlocked session

---

## 6. Security Properties Summary

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Confidentiality** | Host cannot read messages | E2E Double Ratchet |
| **Forward secrecy** | Past messages safe if current keys leak | Ratchet key derivation per message |
| **Post-compromise security** | Sessions self-heal after compromise | Double Ratchet advancement |
| **Authentication** | Only allowlisted PGP fingerprints can join | PGP challenge-response |
| **Integrity** | Messages cannot be tampered with | AEAD (AES-256-GCM / ChaChaPoly) |
| **Anti-replay** | Duplicate messages rejected | Monotonic counter + bitmap window |
| **Anonymity** | Network identity hidden | Tor Hidden Services v3 |
| **Ephemerality** | No trace on disk | Zero-write mode, verified by strace |
| **Memory safety** | Secrets wiped after use | `mlock()` + `zeroize` |
