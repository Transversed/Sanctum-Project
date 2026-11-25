# Sanctum — Architecture (v0.1.1)

This document describes the code as it is. The original design vision is kept in
[`design/architecture-v0.1-vision.md`](design/architecture-v0.1-vision.md); what is
planned next is in [`ROADMAP.md`](../ROADMAP.md). The wire protocol is specified in
[`protocol.md`](protocol.md) and the security analysis in
[`threat-model.md`](threat-model.md).

## 1. Crates

```
sanctum-cli ──► sanctum-infra ──► sanctum-app ──► sanctum-domain
      │               │                               ▲
      │               └──────► sanctum-crypto ────────┘
      └──────────────────────────────────────────────────►
```

| Crate | Role | Main modules |
|-------|------|--------------|
| `sanctum-domain` | Entities, errors, events and ports (traits). No I/O. | `entities::{member, room, invite, session}`, `ports::{identity, crypto, …}` |
| `sanctum-crypto` | Primitives and protocols, no networking. | `noise` (NK, prologue, handshake hash), `x3dh`, `ratchet`, `aead`, `kdf` (Argon2id, HKDF), `padding`, KAT tests |
| `sanctum-app` | Pure application logic. | `auth_service` (channel-bound auth, invitations, rate limiting), `room_service`, `host_service`, `sanitize` |
| `sanctum-infra` | Adapters: network, Tor, codecs, identity, E2E engine. | `host_listener`, `client_connector`, `noise_transport`, `room_crypto`, `e2e_session`, `identity`, `invite_codec`, `proto_codec`, `codec`, `tor_control`, `socks`, `testkit` (tests only) |
| `sanctum-cli` | The `sanctum` binary. | `commands::{init, host, join, room, identity, status}`, `chat_loop`, `passphrase` |

Rules enforced in CI: `unsafe` is forbidden in every crate and target; library
crates have no `unwrap`/`expect` outside tests and log only through `tracing`,
without metadata.

### Ports actually used

`SignatureVerifier` and `Signer` (Ed25519, implemented by
`infra::identity::{Ed25519Verifier, IdentityAdapter}`) are used by the
authentication service and the E2E engine; `UiPort` and `CryptoPort` have
implementations. `StoragePort`, `TransportPort` and `TorPort` are declared but not
implemented yet: the host and the CLI use the concrete adapters directly. Making
them the real seams is a prerequisite of multi-transport support (see roadmap).

## 2. Runtime view

### Host (`sanctum host create <room> [--local] [--chat]`)

1. Decrypts the owner identity (passphrase), creates the room with the owner as
   member, generates a Noise static key pair in RAM (`Zeroizing`).
2. Binds the relay on `127.0.0.1` and, unless `--local`, creates an ephemeral
   onion service through the control port (SAFECOOKIE).
3. `HostListener` serves each connection in its own task: Noise NK → channel-bound
   authentication (`AuthService`) → `PeerReady` → bundle exchange → relay loop.
   The host routes `RatchetKeyExchange` and `RoomMessage` frames to their single
   recipient with the authenticated sender, and stores bundles (one-time prekeys
   handed out once) in RAM only. Limits: `HostLimits` (timeouts, connection cap).
4. With `--chat`, the owner joins its own room as a regular client and can issue
   invitations with `/invite`.

### Member (`sanctum join <invite>`)

1. Checks the invitation is for its fingerprint and that the address is `.onion`
   (or loopback); connects through Tor SOCKS5.
2. `client_connector`: Noise NK with the host key from the invitation, checks
   `server_id`, signs the challenge.
3. `chat_loop` creates a `RoomCrypto` (fresh X25519 keys for this process),
   publishes its bundle, answers `BundleResponse`/`RatchetKeyExchange`, and
   encrypts every message once per peer. Commands: `/who`, `/verify`, `/help`,
   `/exit` (and `/invite` for the owner).

## 3. State and storage

| Data | Where | Lifetime |
|------|-------|----------|
| Identity key | `~/.sanctum/keys/identity.key`, Argon2id + ChaCha20-Poly1305, mode 0600 | Until deleted |
| Public key, fingerprint, config | `~/.sanctum/` (0600 files, 0700 directory) | Until deleted |
| Noise host key, room, members, bundles, nonces, used invitations | Host RAM | Host process |
| X25519 keys, ratchet sessions, skipped keys | Member RAM (`Zeroizing`) | Member process |

Nothing is written to disk while hosting or chatting (CI check with `strace`).
`storage_sqlite` and `storage_memory` exist for the future persistent mode but are
not used by the binary; `--mode persistent` is refused.

## 4. Invariants

| ID | Invariant | Enforced by |
|----|-----------|-------------|
| I1 | No user content leaves a client without E2E encryption | `RoomCrypto`, no plaintext path; `host_is_blind` |
| I2 | The host never trusts a declared fingerprint | `AuthService::verify_response` |
| I3 | The sender of a routed frame is the authenticated peer | `host_listener::route_to_recipient` |
| I4 | Zero disk writes in ephemeral mode | `scripts/check-no-disk-writes.sh` |
| I5 | Remote text is sanitized before display | `sanctum_app::sanitize` |

## 5. Tests

- Unit tests in every crate (auth rejection paths, ratchet tampering and bounds,
  bundles, invitations, identity storage, sanitization).
- Known-answer vectors for X3DH and the Double Ratchet, generated by an independent
  Python implementation (`crates/sanctum-crypto/tests/kat/`), regenerated in CI.
- Network tests against a real host on loopback (`sanctum-infra/tests`, `testkit`).
- End-to-end tests driving the real `sanctum` binary (`sanctum-cli/tests`), including
  `host_is_blind` and negative scenarios.
- Fuzzing (`fuzz/`, nightly) and deterministic random-input tests (stable).
