
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

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-pre--alpha-red.svg)]()

</div>

---

Sanctum is a terminal-first, Tor-only secure chat tool built in Rust. It provides end-to-end encrypted messaging over Tor Hidden Services with zero reliance on clearnet infrastructure, central servers, or trusted third parties.

## Why Sanctum?

Most "secure" messaging tools still depend on centralized servers, phone numbers, or clearnet connections. Sanctum takes a different approach:

- **Tor-only**: All traffic flows through Tor v3 Hidden Services. No clearnet fallback, ever.
- **End-to-end encrypted**: Messages are encrypted client-to-client using the Double Ratchet protocol (X3DH + Noise NK). The host relays ciphertext and cannot read message content.
- **Ephemeral by default**: In ephemeral mode, nothing touches the disk. Keys, messages, and room state exist only in RAM and vanish when the session ends.
- **PGP identity**: Authentication uses PGP challenge-response. No emails, no phone numbers, no accounts.
- **Self-hosted**: You host your own rooms. No central server, no metadata collection, no single point of failure.

## Threat Model

Sanctum is designed for users who need strong operational security: journalists communicating with sources, activists coordinating in hostile environments, security teams exchanging sensitive information.

The host operator sees **who is in the room** (PGP fingerprints) but **never the message content** (E2E ciphertext only). In ephemeral mode, a seized machine yields nothing — all state was in RAM.

## Modes

| | Ephemeral | Persistent |
|---|---|---|
| Disk writes | **None** | Encrypted SQLite |
| Message history | Lost when session ends | Retained (configurable limits) |
| .onion address | Changes every session | Stable across restarts |
| Use case | One-off sensitive conversations | Always-on team room on a VM |

## Quick Start

> ⚠️ **Pre-alpha** — Sanctum is under active development and not yet ready for production use.

```bash
# Prerequisites: Tor must be running with ControlPort enabled
sudo apt install tor
# Add to /etc/tor/torrc: ControlPort 9051 and CookieAuthentication 1

# Build from source
git clone https://github.com/sanctum-chat/sanctum.git
cd sanctum
cargo build --release

# Initialize your profile
sanctum init
sanctum identity import ~/.gnupg/your-signing-key.gpg

# Host a room
sanctum host create my-room --mode ephemeral --chat

# Join a room (from another machine)
sanctum join <invite_token>
```

## Interactive Chat

Sanctum's primary interface is an interactive terminal chat session:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ SANCTUM │ #ops-room │ {Owner} alice │ ephemeral │ 3 peers │ Tor: ✓      │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ [12:03] {Owner}  alice: rendez-vous à 14h                                │
│ [12:04] {Member} bob: reçu, je serai là                                  │
│ [12:05] ── charlie a rejoint (synchronisation...) ──                     │
│ [12:05] ── charlie synchronisation complète ──                           │
│ [12:06] {Member} charlie: salut tout le monde                            │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│ > _                                                                      │
└──────────────────────────────────────────────────────────────────────────┘
```

Slash commands: `/who`, `/verify`, `/kick`, `/status`, `/me`, `/exit`.

## Architecture

Sanctum follows a **Clean/Hexagonal architecture** with strict separation of concerns:

```
CLI (sanctum-cli)
 └─► Application (sanctum-app)     ← use cases, ChatSession, services
      └─► Domain (sanctum-domain)  ← entities, ports (traits), events
           ▲
      Infrastructure (sanctum-infra) ← Tor, Noise, SQLite, PGP, terminal
      Crypto (sanctum-crypto)        ← AEAD, KDF, X3DH, Double Ratchet
```

Five crates, strict dependency direction, all crypto auditable independently.

## Cryptographic Protocols

| Layer | Protocol | Purpose |
|-------|----------|---------|
| Transport | Noise NK (ChaChaPoly, X25519) | Encrypted tunnel client ↔ host |
| Key exchange | X3DH | Initial session establishment between peers |
| E2E messaging | Double Ratchet | Forward secrecy per message, post-compromise security |
| Authentication | PGP challenge-response | Identity verification via PGP fingerprint allowlist |
| Storage encryption | AES-256-GCM + Argon2id | At-rest encryption for persistent mode |

## Security Properties

- **Forward secrecy**: Compromising current keys does not reveal past messages.
- **Post-compromise security**: Sessions self-heal after a key compromise through ratchet advancement.
- **Zero disk (ephemeral)**: Verified via `strace` — no `open(..., O_WRONLY)` on data directories during a full session.
- **Memory protection**: All keys use `mlock()` + `zeroize` on drop. Panic hook wipes secrets.
- **Anti-replay**: Monotonic sequence counter + 64-bit sliding bitmap window.
- **No metadata on host**: The host stores ciphertext blobs indexed by opaque hashes, never plaintext or cleartext fingerprints.

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/architecture.md`](docs/architecture.md) | Full technical architecture (2100+ lines) |
| [`docs/adrs/`](docs/adrs/) | Architecture Decision Records (16 ADRs) |
| [`docs/threat-model.md`](docs/threat-model.md) | Detailed threat model and mitigations |
| [`docs/protocol.md`](docs/protocol.md) | Wire protocol specification |
| [`docs/runbook.md`](docs/runbook.md) | Operational runbook |
| [`SECURITY.md`](SECURITY.md) | Security policy and reporting |

## Roadmap

| Version | Focus | Status |
|---------|-------|--------|
| **v0.1** | MVP: 2-user E2E chat, PGP auth, ephemeral + persistent, interactive CLI | 🔨 In progress |
| v0.2 | TUI (ratatui), Tor client auth, groups up to 30, auto-reconnect | Planned |
| v0.3 | File transfer (≤10 MiB), auto-destruct messages, .deb/.rpm/AUR packaging | Planned |
| v1.0 | MLS for large groups, integrated `arti`, external security audit | Planned |

## Building

```bash
# Debug build
cargo build --workspace

# Release (static musl binary)
cargo build --release --target x86_64-unknown-linux-musl

# Run tests
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings
```

## Contributing

Sanctum is in early development. If you're interested in contributing, please read the architecture document first, then open an issue to discuss before submitting PRs.

Priorities for contributions: security review, Tor integration testing, crypto protocol verification.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

Sanctum is experimental software in active development. It has **not been audited**. Do not use it for life-or-death situations until a formal security audit has been completed. Use at your own risk.

---

<div align="center">
<i>In the shadows, we communicate.</i>
</div>
