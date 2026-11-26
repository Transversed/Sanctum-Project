
<div align="center">

```
   █████████    █████████   ██████   █████   █████████  ███████████ █████  █████ ██████   ██████
  ███▒▒▒▒▒███  ███▒▒▒▒▒███ ▒▒██████ ▒▒███   ███▒▒▒▒▒███▒█▒▒▒███▒▒▒█▒▒███  ▒▒███ ▒▒██████ ██████ 
 ▒███    ▒▒▒  ▒███    ▒███  ▒███▒███ ▒███  ███     ▒▒▒ ▒   ▒███  ▒  ▒███   ▒███  ▒███▒█████▒███ 
 ▒▒█████████  ▒███████████  ▒███▒▒███▒███ ▒███             ▒███     ▒███   ▒███  ▒███▒▒███ ▒███ 
  ▒▒▒▒▒▒▒▒███ ▒███▒▒▒▒▒███  ▒███ ▒▒██████ ▒███             ▒███     ▒███   ▒███  ▒███ ▒▒▒  ▒███ 
  ███    ▒███ ▒███    ▒███  ▒███  ▒▒█████ ▒▒███     ███    ▒███     ▒███   ▒███  ▒███      ▒███ 
 ▒▒█████████  █████   █████ █████  ▒▒█████ ▒▒█████████     █████    ▒▒████████   █████     █████
  ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒     ▒▒▒▒▒      ▒▒▒▒▒▒▒▒   ▒▒▒▒▒     ▒▒▒▒▒ 
```

**Tor-only encrypted chat. No clearnet. No compromise.**

[![License: AGPL](https://img.shields.io/badge/license-AGPL-purple.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-pre--alpha-red.svg)]()

</div>

---

Sanctum is a terminal-first, Tor-only group chat written in Rust. Members talk
through a relay that runs as a Tor onion service and **cannot read** what they
say: every message is end-to-end encrypted for each member with its own Double
Ratchet session.

> **Status: v0.1.1, pre-alpha, not audited.** The guarantees below are
> implemented and tested, but no external review has happened yet. Do not rely on
> Sanctum when lives are at stake. Read the [threat model](docs/threat-model.md),
> including what it does *not* protect.

## Why Sanctum?

- **Tor-only.** The relay is a v3 onion service; members connect through Tor.
  Non-onion addresses are refused (loopback only for local tests).
- **Blind host.** Pairwise X3DH + Double Ratchet sessions between members; the host
  relays one padded envelope per recipient and never holds a decryption key. A
  test runs the real binary and checks that nothing the host can read contains a
  message.
- **Proven identities.** Ed25519 identities; the host derives fingerprints from
  keys and admits newcomers only with an owner-signed, single-use invitation.
- **Ephemeral.** RAM only while hosting and chatting: zero disk writes, checked in
  CI with `strace`. The identity key itself is encrypted at rest.
- **Auditable.** Five small crates, no `unsafe`, a [written protocol](docs/protocol.md),
  known-answer vectors from an independent implementation, fuzzing, and a CI that
  enforces all of it.

## What the host can and cannot see

| The host sees | The host never sees |
|---------------|---------------------|
| Members' fingerprints and aliases, who is connected | Message text |
| When each message is sent and to whom, size rounded to 256 bytes | Message timestamps |
| Its own onion address | Members' private keys or session keys |

Compare **safety numbers** (`/verify <alias>`) out of band to detect a host that
would introduce a fake member.

## Quick Start

```bash
# Prerequisites: Tor with ControlPort 9051 and CookieAuthentication 1,
# and your user in Tor's group (Debian/Ubuntu: debian-tor). See docs/runbook.md.
sudo apt install tor protobuf-compiler
./scripts/setup-tor.sh

# Build
git clone https://github.com/Transversed/Sanctum-Project.git
cd Sanctum-Project
cargo build --release
export PATH="$PWD/target/release:$PATH"

# Create your identity (Ed25519, encrypted with a passphrase)
sanctum init --alias alice

# Host a room and open the chat as its owner
sanctum host create my-room --chat
#   then, in the chat:  /invite <their_fingerprint>   → a token to send out of band

# Members join with the token they received
sanctum join <invite_token>
```

Never run `sanctum` with `sudo`. For a local test without Tor, add `--local` to
`host create`: invitations then point to `127.0.0.1`.

## Interactive Chat

```
┌──────────────────────────────────────────────────────────────────────────┐
│ SANCTUM │ #ops-room │ ephemeral │ 3 membre(s) │ Tor: ✓ │ E2E: 🔒          │
├──────────────────────────────────────────────────────────────────────────┤
│ ── bob a rejoint la room ──                                              │
│ 🔒 chiffrement de bout en bout établi avec bob                           │
│ [12:03] alice: rendez-vous à 14h                                         │
│ [12:04] bob: reçu, je serai là                                           │
├──────────────────────────────────────────────────────────────────────────┤
│ > _                                                                      │
└──────────────────────────────────────────────────────────────────────────┘
```

Commands: `/who` (members and encryption state), `/verify <alias>` (safety
number), `/invite <fingerprint> [hours]` (owner), `/kick <alias|fingerprint>`
(owner: removes a member and voids the invitations issued to them before),
`/help`, `/exit`. Without a
terminal, `sanctum join` reads lines from stdin and prints one event per line.

## Modes

| | Ephemeral | Persistent |
|---|---|---|
| Availability | **v0.1.1** | Planned for v0.2 (refused by the CLI) |
| Disk writes | None | Encrypted store |
| `.onion` address | New every session | Stable |

## Architecture

```
CLI (sanctum-cli)        ← binary, chat loop, passphrase prompt
 └─► Infrastructure (sanctum-infra) ← Tor, Noise transport, host relay, E2E engine, codecs
      └─► Application (sanctum-app) ← authentication, invitations, sanitization
           └─► Domain (sanctum-domain) ← entities, ports
      Crypto (sanctum-crypto)        ← Noise NK, X3DH, Double Ratchet, AEAD, KDF, padding
```

See [docs/architecture.md](docs/architecture.md).

## Cryptography

| Layer | Construction |
|-------|--------------|
| Transport | Noise `NK_25519_ChaChaPoly_SHA256`, versioned prologue, host key from the invitation |
| Authentication | Ed25519 signature bound to the Noise handshake hash; owner-signed single-use invitations |
| Key agreement | X3DH with Ed25519-signed prekey bundles, one-time prekeys handed out once |
| Messages | Double Ratchet (Signal rev. 4), ChaCha20-Poly1305, header + identities as associated data |
| Metadata | Timestamp inside the ciphertext, padding to 256 bytes |
| Identity at rest | Argon2id (64 MiB) + ChaCha20-Poly1305 |
| Tor control | SAFECOOKIE |

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/protocol.md`](docs/protocol.md) | Wire protocol v2 |
| [`docs/threat-model.md`](docs/threat-model.md) | What is and is not protected |
| [`docs/architecture.md`](docs/architecture.md) | Crates, runtime view, invariants, tests |
| [`docs/runbook.md`](docs/runbook.md) | Installation and operations (French) |
| [`ROADMAP.md`](ROADMAP.md) | What comes next |
| [`CHANGELOG.md`](CHANGELOG.md) | Release notes |
| [`SECURITY.md`](SECURITY.md) | Reporting vulnerabilities |
| [`docs/design/`](docs/design/) | Original design documents (historical) |

## Building

Prerequisites: Rust ≥ 1.89 and `protoc` (`apt install protobuf-compiler`).

```bash
# Debug build
cargo build --workspace

# Release (static musl binary)
cargo build --release --target x86_64-unknown-linux-musl

# Run tests
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets -- -D warnings
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full list of checks run in CI.

## Contributing

Sanctum is in early development. Read [CONTRIBUTING.md](CONTRIBUTING.md) (workflow and security invariants) and the architecture document first, then open an issue to discuss before submitting PRs.

Priorities for contributions: security review, Tor integration testing, crypto protocol verification.

## License

AGPL-3.0-only — see [LICENSE](LICENSE).

## Disclaimer

Sanctum is experimental software. It has **not been audited**. Do not use it for
life-or-death situations until a formal security audit has been completed. Use at
your own risk.

---

<div align="center">
<i>Privacy is no more a myth</i>
</div>
