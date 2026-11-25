# Contributing to Sanctum

Sanctum is pre-alpha security software. These rules exist so that every
change keeps the binary honest about what it protects.

## Workflow

1. **One branch per phase or task** (`fix/p2-signed-auth`, `feat/…`), merged
   into `main` through a pull request. **CI must be green** before merging.
2. **Conventional commits**, prefixed with the plan task ID when there is one:
   `fix(P2.3): verify channel-bound auth signatures`.
3. **Test-first for every vulnerability.** Write the test that demonstrates
   the flaw (it fails), then the fix (it passes). The test stays as a
   regression guard.

## Non-negotiable invariants

A pull request that violates one of these is rejected.

| ID | Invariant |
|----|-----------|
| **I1** | **No silent plaintext.** No byte of user content leaves a client without end-to-end encryption. |
| **I2** | **Proven identity.** The host never trusts a declared fingerprint: it recomputes it from a public key whose possession is proven by a signature over the current channel. |
| **I3** | **Sender set by the host.** `sender_fingerprint` is always taken from the authenticated connection, never from the client's frame. |
| **I4** | **Zero disk writes in ephemeral mode**, enforced in CI by `scripts/check-no-disk-writes.sh`. |
| **I5** | **No remote content displayed without sanitization** (`sanitize_for_terminal`). |

## Code constraints

- `unsafe` is forbidden everywhere (workspace lint + `#![forbid(unsafe_code)]`,
  checked by `scripts/check-forbid-unsafe.sh`).
- Never split `NoiseTransport`: send and receive share one cipher state.
- In `chat_loop.rs`, prefer free functions over methods (avoids crossterm
  borrow conflicts).
- Member admission happens only in `host_listener`, and only after a valid
  owner-signed invitation.
- Secrets live in `Zeroizing<…>` or types that zeroize on drop. Never log a
  full fingerprint, an alias, an address or key material.
- New dependencies must pass `cargo deny check` and be justified in the PR.

## Local checks

```bash
# prerequisites: Rust >= 1.89, protoc (apt install protobuf-compiler), strace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
./scripts/check-forbid-unsafe.sh
./scripts/check-logging.sh
cargo build -p sanctum-cli && ./scripts/check-no-disk-writes.sh --local
```

## Reporting vulnerabilities

Do not open public issues for security problems — see [SECURITY.md](SECURITY.md).
