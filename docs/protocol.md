# Sanctum — Wire Protocol Specification

**Protocol Version**: 1
**Status**: Draft (v0.1)

---

## 1. Transport

All communication flows over **Tor Hidden Services v3**. The host exposes a `.onion` address on a configurable port (default: 9738). Clients connect via their local Tor SOCKS5 proxy.

No clearnet fallback. No WebSocket. No HTTPS.

---

## 2. Frame Format

All messages use a simple length-prefixed framing:

```
┌──────────────┬──────────┬──────────────────────┐
│ len: u32 BE  │ type: u8 │ payload: [u8; len-1] │
│ (4 bytes)    │ (1 byte) │ (len - 1 bytes)      │
└──────────────┴──────────┴──────────────────────┘
```

- `len`: u32 big-endian. Size of (type + payload). Does NOT include its own 4 bytes.
- Total bytes on wire = `4 + len`
- Payload size = `len - 1`
- Constraints: `1 ≤ len ≤ 65536` (64 KiB max). `len = 0` or `len > 65536` → close connection.
- `payload`: Protobuf-serialized (via `prost`)

---

## 3. Message Types

| Type | Code | Direction | Description |
|------|------|-----------|-------------|
| `HandshakeInit` | 0x01 | C→H | Noise NK initiation |
| `HandshakeResp` | 0x02 | H→C | Noise NK response |
| `AuthChallenge` | 0x03 | H→C | PGP challenge |
| `AuthResponse` | 0x04 | C→H | PGP signed response + alias |
| `AuthResult` | 0x05 | H→C | Success/failure + room state + bundles |
| `RoomMessage` | 0x10 | C→H / H→C | E2E encrypted message (relayed blind) |
| `RoomControl` | 0x11 | C→H / H→C | Room operations (kick, allow member) |
| `PeerReady` | 0x12 | H→all | Member X3DH sync complete |
| `RatchetKeyExchange` | 0x20 | C↔C (via H) | Double Ratchet key exchange |
| `PublishBundle` | 0x21 | C→H | Client publishes PreKey Bundle |
| `RequestBundle` | 0x22 | C→H | Client requests a peer's bundle |
| `BundleResponse` | 0x23 | H→C | Host sends requested bundle |
| `OPKDepleted` | 0x24 | H→C | OPK pool low (< 3) notification |
| `RefreshOPK` | 0x25 | C→H | Client publishes new OPKs |
| `BacklogStart` | 0x30 | H→C | Begin backlog delivery |
| `BacklogEnd` | 0x31 | H→C | End backlog delivery |
| `BacklogAck` | 0x32 | C→H | Client confirms backlog received |
| `Ping` | 0xFE | bidirectional | Keepalive (60s interval) |
| `Pong` | 0xFD | bidirectional | Keepalive response |
| `Error` | 0xFF | bidirectional | Protocol error |

---

## 4. Connection Lifecycle

### 4.1 Handshake (Noise NK)

```
Client                              Host
  │                                   │
  ├── HandshakeInit ────────────────►│
  │   { protocol_version: u16,       │
  │     min_supported_version: u16,  │
  │     noise_ephemeral_key: [u8;32]}│
  │                                   │
  │◄── HandshakeResp ────────────────┤
  │   { noise_payload }              │
  │                                   │
  │   [Noise NK transport established]│
```

Version check: if `protocol_version < min_supported_version` → `Error::VersionMismatch` → close.

### 4.2 Authentication (PGP Challenge-Response)

All messages below are encrypted by the Noise NK transport.

```
Client                              Host
  │                                   │
  │◄── AuthChallenge ────────────────┤
  │   { nonce: [u8;32],             │
  │     timestamp: u64,             │
  │     room_id: [u8;16],           │
  │     server_id: [u8;32] }        │
  │                                   │
  │   [Client verifies:              │
  │    server_id == SHA256(host      │
  │    Noise static pubkey)]         │
  │   [Client signs challenge        │
  │    with PGP private key]         │
  │                                   │
  ├── AuthResponse ─────────────────►│
  │   { pgp_fingerprint,            │
  │     signature,                   │
  │     pgp_public_key,             │
  │     display_alias }              │
  │                                   │
  │   [Host verifies:                │
  │    1. fingerprint in allowlist   │
  │    2. signature valid            │
  │    3. nonce not replayed (120s)  │
  │    4. timestamp ±120s]           │
  │                                   │
  │◄── AuthResult ──────────────────┤
  │   { success: bool,              │
  │     member_role: Role,           │
  │     room_state: RoomState }      │
```

`server_id` = SHA-256 of the host's static Noise public key. Binds authentication to a specific server, preventing challenge relay attacks.

`RoomState` includes member list and all PreKey Bundles, avoiding per-peer round-trips during join.

### 4.3 Session Establishment (X3DH)

After authentication, the joining client establishes pairwise Double Ratchet sessions with all existing members.

```
New Member                          Existing Members (via Host relay)
  │                                   │
  ├── PublishBundle ────────────────►│  (host stores bundle)
  │                                   │  (host broadcasts PeerJoined)
  │                                   │
  │  [For each existing member,       │
  │   in parallel:]                   │
  │                                   │
  │  Compute X3DH:                    │
  │  DH1 = DH(IK_self, SPK_peer)    │
  │  DH2 = DH(EK_self, IK_peer)     │
  │  DH3 = DH(EK_self, SPK_peer)    │
  │  DH4 = DH(EK_self, OPK_peer)    │  (optional)
  │  SK = KDF(DH1 ‖ DH2 ‖ DH3      │
  │       [‖ DH4])                    │
  │                                   │
  ├── RatchetKeyExchange ──────────►│  {IK, EK, OPK_id, initial_ciphertext}
  │                                   │
  │  [All sessions established]       │
  │  → Host broadcasts PeerReady     │
```

### 4.4 Messaging

```
MessageEnvelope {
    sender_fingerprint: Fingerprint,
    sequence_number: u64,          // monotonic per sender per room
    nonce: [u8; 12],               // unique AEAD nonce
    timestamp: u64,                // Unix timestamp (seconds)
    ciphertext: Vec<u8>,           // Double Ratchet encrypted, padded to 256B blocks
    ratchet_header: RatchetHeader, // DH ratchet public key + chain counters
}
```

For a group of N members: the sender encrypts the message N-1 times (once per peer ratchet) and sends N-1 `RoomMessage` frames via the host.

### 4.5 Backlog Delivery (Persistent Mode)

```
Host                               Client
  │                                   │
  ├── BacklogStart { count: N } ────►│
  ├── RoomMessage (backlog #1) ─────►│
  ├── RoomMessage (backlog #2) ─────►│
  ├── ...                            │
  ├── BacklogEnd ───────────────────►│
  │                                   │
  │◄── BacklogAck { last_seq: N } ──┤
  │                                   │
  │   [Host deletes delivered msgs]   │
```

If the client crashes before sending `BacklogAck`, the backlog is preserved and redelivered on the next connection. Idempotence is guaranteed by the sequence number anti-replay window.

### 4.6 Keepalive

Both sides send `Ping` every 60 seconds. The other side responds with `Pong`. If 3 consecutive pings go unanswered (180s timeout), the connection is considered dead.

---

## 5. Anti-Replay

- **Monotonic counter**: per sender, per room. Reject if `seq ≤ last_accepted` (with 32-message reordering window).
- **Bitmap window**: 64-bit sliding window to detect replays within the tolerance window.
- **Nonce**: 12 bytes, derived from counter + salt. Uniqueness guaranteed by Double Ratchet.
- **Timestamp**: ±120s tolerance. Used for backlog expiration only, NOT for anti-replay.

---

## 6. Error Handling

| Error | Action | Response Code |
|-------|--------|---------------|
| Version incompatible | Close immediately | `Error::VersionMismatch` |
| Auth failed (3 attempts) | Close + ban 5 min | `Error::AuthFailed` |
| Malformed message | Ignore, safe log | `Error::MalformedMessage` |
| Invalid sequence number | Ignore | `Error::ReplayDetected` |
| Room full | Reject | `Error::RoomFull` |
| Member revoked | Disconnect | `Error::Revoked` |
| Ratchet desynchronized | Re-keying (max 3×) | `Error::RatchetDesync` |

---

## 7. Message Padding

All `RoomMessage` payloads are padded to multiples of 256 bytes before encryption to prevent message-length metadata leakage. Average overhead: ~128 bytes. Maximum message size: 64 KiB (after padding).

---

## 8. Cryptographic Algorithms

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Transport encryption | Noise NK | ChaChaPoly, X25519, SHA-256 |
| Key agreement | X3DH | X25519 |
| E2E messaging | Double Ratchet | X25519 DH ratchet, HKDF-SHA256, AES-256-GCM |
| Authentication | PGP | Ed25519 signing (recommended subkey) |
| Storage encryption | AES-256-GCM | 12-byte unique nonce per field |
| Key derivation | Argon2id | m=256MiB, t=4, p=2 |
| Subkey derivation | HKDF-SHA256 | Context-specific info strings |
