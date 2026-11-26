# Changelog

All notable changes to Sanctum. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`/kick <alias|fingerprint>`** (owner): removes a member from the running room.
  The host handles `RoomControl/RevokeMember` (owner only), disconnects the member
  with `ProtocolError{revoked}`, sends `PeerLeft` to the others and echoes the
  command to the owner as acknowledgement.
- **Invitation revocation.** Invitations carry a signed `issued_at`; the host
  refuses every invitation issued for a removed member before the removal
  (pending or replayed), and any invitation issued in the future. A newer
  invitation re-admits the member.
- **`scripts/tor-smoke-test.sh`**: end-to-end test over the real Tor network
  (owner + two members through SOCKS, encrypted sessions, 6/6 messages), with
  timings; runbook §6 adds a two-machine checklist.

- **Persistent rooms, milestone A: a durable room** (`host create --mode
  persistent`, `host start`, `host list`, `host delete`). The room, its members,
  revocations and consumed invitations, the Noise host key and the onion key
  live in one sealed file per room; the same `.onion`, keys and tokens work
  after a restart or a crash. The host is **headless**: it holds the owner's
  public key only (`--owner-key`), and the owner connects from their machine
  with `sanctum join`, where `/invite` and `/kick` work. Admissions and
  revocations are saved before they are confirmed; a failed save stops the
  host. Instance lock per room; the store passphrase comes from a systemd
  credential (`sanctum-host-passphrase`), `SANCTUM_HOST_PASSPHRASE` (tests) or
  a prompt. `host start` does not print the address unless `--show-address`.
- Tor: `create_persistent_hidden_service` (no `DiscardPK`, key never written by
  Tor); onion keys are validated before being sent to the control port.
- `sanctum identity show` prints the public key.
- **Sealed file format `SANCTUMS` v1** (`sanctum_crypto::sealed`), the encrypted
  container of the upcoming persistent mode: random master key wrapped by
  Argon2id, XChaCha20-Poly1305 body bound to the authenticated header, one HKDF
  key per kind, bounded Argon2id parameters. Known-answer vectors from an
  independent Python implementation, checked in CI.
- `AeadCipher::XChaCha20Poly1305` (24-byte random nonces), tested against the
  draft-irtf-cfrg-xchacha vectors.

### Changed

- `sanctum join` accepts an expired token from a member already admitted (it
  only locates the room); the host still refuses expired invitations from
  newcomers.
- `storage.data_dir` now defaults to `~/.sanctum/hosts` (persistent room stores).
- Private files are written with an `fsync` of their directory after the rename.

### Fixed

- A revoked member re-admitted by a new invitation was appended as a duplicate
  entry, and authorisation checks kept hitting the revoked one (`Room::add_member`
  now replaces it).
- A client whose connection ended (host gone, kick) kept running until the next
  key press: the runtime waited for the blocked stdin reader on exit.

### Removed

- `rusqlite` (embedded SQLite), the unused `storage_sqlite` / `storage_memory`
  adapters, the `StoragePort` trait they implemented and their tests. The
  persistent mode will store sealed encrypted files instead (no SQL engine, no
  plaintext structure on disk).
- AES-256-GCM from `sanctum-crypto::aead` (never used: everything is
  ChaCha20-Poly1305). `aes-gcm` remains only as a transitive dependency of `snow`.

### Compatibility

- Invitations now sign `issued_at`: tokens issued by v0.1.1 are refused. They were
  already bound to a host session, so restarting the host to upgrade voids them
  anyway.

## [0.1.1] — 2026-11-25 — "Make it true"

This release makes the binary deliver what the README promised. It closes every
finding of the internal review of v0.1.0 (C1–C5 critical, plus the high and medium
findings). **Protocol v2, not compatible with v0.1.0.**

### Security

- **Real end-to-end encryption (C1, C4).** Members exchange Ed25519-signed prekey
  bundles through the host and establish one X3DH + Double Ratchet session per
  pair; each message is sent as one padded envelope per recipient. The host never
  holds a decryption key (verified by `host_is_blind` on the real binary). There is
  no plaintext mode any more.
- **Proven admission (C2).** Channel-bound Ed25519 challenge-response (signature
  over the Noise handshake hash); the host derives fingerprints from keys; newcomers
  need an owner-signed, single-use, expiring invitation bound to the room, the host
  session and their fingerprint. Unconditional auto-admission is gone.
- **Sender authenticity (C3).** The host stamps the authenticated sender on every
  routed frame.
- **Terminal injection (C5).** All remote text is sanitized (C0/C1 controls, ESC,
  BiDi); the host restricts aliases to `[A-Za-z0-9_-]{1,20}`.
- **Double Ratchet hardened** to the Signal specification: header and identities as
  associated data, transactional decryption, global bound on skipped keys, HMAC
  chain KDF; X3DH with the `0xFF³²` prefix and low-order key rejection.
  Known-answer vectors from an independent Python implementation.
- **Identity key encrypted at rest** (Argon2id + ChaCha20-Poly1305), private files
  created 0600 atomically. `identity import` (which derived a key from public PGP
  bytes) is disabled; `identity protect` migrates old plaintext keys.
- **Tor control port** authenticated with SAFECOOKIE only.
- **Resource limits**: handshake timeout, idle timeout, connection cap, global
  authentication failure budget.
- **No disk writes** while hosting or chatting (the `/tmp` key handoff is gone),
  enforced in CI with `strace`.
- Join refuses any non-`.onion` address (no clearnet).
- Dependencies: `rand` 0.8.8, `tokio` 1.54, `rusqlite` 0.41 (RUSTSEC-2026-0097,
  -0386, -0459).

### Added

- Chat commands `/invite`, `/verify` (safety numbers), `/who`, `/help`.
- Scriptable chat when stdin is not a terminal; keepalive pings.
- `CONTRIBUTING.md` (workflow, invariants I1–I5), `ROADMAP.md`, protocol v2
  specification, rewritten threat model and architecture documents.
- CI: build with `protoc`, fmt, clippy `-D warnings`, MSRV 1.89, tests,
  `cargo-deny`, unsafe ban, metadata-free logging check, zero-disk check, KAT
  reproducibility, fuzz targets (nightly fuzzing).

### Changed

- Identities are Ed25519 (the "PGP" vocabulary is gone).
- Logs go to stderr at `warn` level and never contain fingerprints, aliases,
  addresses or content.
- MSRV is 1.89; `license = "AGPL-3.0-only"`.

### Removed

- `--insecure-plaintext`, the `chat_demo` example, protobuf `HandshakeInit` /
  `HandshakeResp` and `RequestBundle`.
- Commands that only pretended to work (`chat`, `send`, `read`, `host status/stop`,
  `room list/members/revoke`) now fail explicitly; `--mode persistent` is refused
  until v0.2.

## [0.1.0] — 2026-03-28

Initial development snapshot (sprints 1–16): crate structure, Noise NK transport,
Tor onion service, X3DH and Double Ratchet primitives, crossterm chat. End-to-end
encryption and authenticated admission were not wired into the binary.

[0.1.1]: https://github.com/Transversed/Sanctum-Project/releases/tag/v0.1.1
[0.1.0]: https://github.com/Transversed/Sanctum-Project/commit/204eec9
