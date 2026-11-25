# Sanctum — Roadmap

Sanctum aims to be a technical reference for anonymous, auditable group chat over
Tor: a small, readable codebase with a documented protocol and verifiable claims.

## v0.1.1 — "Make it true" (released)

The binary now delivers what the README states: real end-to-end encryption with a
blind host, proven identities and owner-signed invitations, protocol v2, encrypted
identity at rest, SAFECOOKIE Tor control, resource limits, sanitized terminal
output, known-answer vectors, fuzzing, and a CI that checks all of it. See the
[CHANGELOG](CHANGELOG.md).

## v0.2 — Usable daily

- **Persistent mode**: encrypted store (keys and backlog), stable `.onion`
  (persisted onion key), strict retention limits, and the corresponding storage
  ports wired into the host.
- **Sender Keys** for group messages (O(1) encryption per message instead of O(n)),
  with key rotation when membership changes.
- Membership management: `/kick`, revocation, admin role semantics.
- TUI with `ratatui`, local time display, auto-reconnect.
- Tor client authorization (restricted discovery) for the onion service.
- `mlock` of key material (via a vetted dependency) and core-dump disabling.

## v0.3 — Distribution

- File transfer (≤ 10 MiB), auto-destructing messages.
- `.deb` / `.rpm` / AUR packages, signed releases.
- **Reproducible builds** and a published dependency transparency report.

## v1.0 — Reference grade

- **MLS** (`openmls`) for large groups.
- Integrated `arti` (Tor in Rust) and multiple transports, through the domain ports.
- **External security audit** (after v0.1.1, not before).

## Research track

- Metadata reduction: cover traffic, padding of timing, and private information
  retrieval to hide who talks to whom from the host.
- Formal model of the authentication and invitation flow.
