# Sanctum — Threat Model (v0.1.1)

This document states what Sanctum v0.1.1 protects, against whom, and — just as
important — what it does **not** protect. Every "Mitigation" below is implemented
and covered by tests unless marked *(not implemented)*.

## 1. Assets

- Message content and timestamps
- Long-term identities (Ed25519 keys) and session keys (X3DH, Double Ratchet)
- Membership of a room (who talks with whom)
- The network location of members and of the host

## 2. Adversaries

| Adversary | Capabilities |
|-----------|--------------|
| **Network observer** | Watches or tampers with traffic between members and the host (including a malicious Tor relay). |
| **Malicious or compromised host** | Runs the relay: sees every frame after the Noise layer, can drop, delay, reorder, inject or forge frames, can hand out wrong keys, can lie about who is present. |
| **Outsider** | Knows the `.onion` address, tries to join or to disturb the room. |
| **Malicious member** | Holds a valid invitation, speaks the protocol with chosen payloads. |
| **Local attacker** | Reads the disk of a member (stolen laptop, backup), or runs code as another local user. |

## 3. What is protected

### T1 — Host reads or forges messages
**Mitigations.** Messages are end-to-end encrypted with a pairwise Double Ratchet
session per pair of members; the host only relays per-recipient envelopes and holds
no key that decrypts them (`host_is_blind` test on the real binary). Prekey bundles
are signed by each member's Ed25519 identity and bound to its fingerprint, so the
host cannot substitute keys silently. The ratchet authenticates its header and both
identity keys (AD), so forged or modified messages are rejected and never
desynchronize a session. The host stamps the sender of every routed frame from the
authenticated connection, so members cannot impersonate each other either.

**Residual.** A host that controls admission could invite a fake identity of its
own: members detect it by comparing safety numbers out of band (`/verify`).

### T2 — Outsider joins the room
**Mitigations.** Authentication proves possession of an Ed25519 key with a
signature bound to the Noise handshake hash (replays on another connection fail);
the host derives the fingerprint itself. Newcomers need an owner-signed,
single-use, expiring invitation bound to the room, to the host session and to the
invitee's fingerprint. No unconditional admission exists.

### T3 — Disturbing the host (denial of service)
**Mitigations.** Handshake + authentication within 30 s, idle members dropped
after 120 s, at most 64 simultaneous connections, a global budget of 30 failed
authentications per minute, bounded frames (64 KiB), three invalid frames close a
connection, bounded skipped keys, no `unwrap`/`expect` in library code, parsers
fuzzed nightly. **Residual:** an onion service can always be flooded at the Tor
level; a member can exhaust another member's one-time prekeys (X3DH then runs
without OPK, which remains secure).

### T4 — Malicious member attacks other members' terminals
**Mitigations.** Everything received from the network (content, aliases, errors)
is stripped of C0/C1 controls, ESC and BiDi overrides before display; aliases are
restricted to `[A-Za-z0-9_-]{1,20}` by the host. Tested end to end on the binary.

### T5 — Disk seized (member or host)
**Mitigations.** Ephemeral mode writes nothing during a session (enforced in CI
with `strace`). The identity key is encrypted at rest (Argon2id 64 MiB +
ChaCha20-Poly1305) and private files are created with mode 0600 from the start.
**Residual:** a weak passphrase can be brute-forced offline; the public key and
fingerprint are stored in clear.

### T6 — Tor control port impersonation
**Mitigations.** SAFECOOKIE authentication: the control port must prove it knows
the cookie before Sanctum sends its own proof; unauthenticated control ports are
refused. Sanctum never needs to run as root.

### T7 — Protocol downgrade
**Mitigations.** The protocol version is bound by the Noise prologue
(`SANCTUM-NOISE-NK-v2`); there is no plaintext mode and no negotiable cipher suite.

## 4. What is NOT protected (residual risks)

- **Metadata visible to the host.** The host knows the room's members (fingerprints
  and aliases), when each member is connected, and when and to whom each message is
  sent, with its size rounded to 256 bytes. The host is the room's directory.
  Cover traffic and private information retrieval are not implemented.
- **Fan-out cost.** Each message is encrypted and sent once per member (O(n)); rooms
  are limited to 50 members. Sender Keys (v0.2) and MLS (v1.0) are planned.
- **Identity binding.** Trust in another member's identity is
  trust-on-first-introduction by the owner's invitation; only `/verify` compared out
  of band defends against a malicious host-owner pair.
- **Memory.** Secrets are wiped on drop (`zeroize`), but pages are not locked
  (`mlock` is *not implemented*) and may reach swap; disable swap and core dumps on
  sensitive machines. A compromised member device reveals that member's messages.
- **Clock.** Displayed times come from the sender's clock.
- **Persistent mode** is not implemented in v0.1.1 (refused by the CLI).
- **No external audit yet.**

## 5. Explicit assumptions

- Tor provides the expected network anonymity.
- Members protect their identity passphrase and their devices.
- The operating system and the Rust toolchain are not compromised; dependencies are
  checked by `cargo-deny` (advisories, licenses, sources) in CI.

## 6. Out of scope

CPU side channels, compromise of the Tor network itself, social engineering,
coercion, and attacks requiring physical access to an unlocked running session.

## 7. Properties summary

| Property | Mechanism | Verified by |
|----------|-----------|-------------|
| Confidentiality against the host | Pairwise X3DH + Double Ratchet, per-recipient envelopes | `host_is_blind` (real binary), `e2e_room_test` |
| Key authenticity | Ed25519-signed bundles bound to fingerprints, safety numbers | `room_crypto` unit tests |
| Forward secrecy / post-compromise security | Double Ratchet (Signal rev. 4) | KAT vectors from an independent implementation |
| Integrity | ChaCha20-Poly1305 with header + identities as AD | ratchet tampering tests |
| Admission control | Channel-bound Ed25519 auth, owner-signed single-use invitations | `host_auth_test`, `auth_flow_test`, `e2e_negative_test` |
| Sender authenticity | Host-stamped sender + per-pair sessions | `host_relay_test`, `e2e_negative_test` |
| Ephemerality | Zero disk writes | `check-no-disk-writes.sh` (CI, strace) |
| Secrets at rest | Argon2id + ChaCha20-Poly1305, 0600 atomic files | `identity` tests |
| Terminal safety | `sanitize_for_terminal` | exhaustive Unicode test, `e2e_negative_test` |
