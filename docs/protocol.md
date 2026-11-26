# Sanctum — Wire Protocol, version 2

Status: implemented in v0.1.1. Version 2 is **not** compatible with version 1.
The normative message definitions are in [`proto/sanctum.proto`](../proto/sanctum.proto);
this document explains the flows and the cryptographic constructions.

## 1. Transport

- Clients reach the host through a **Tor v3 onion service** (SOCKS5 on the client
  side). The only exception is loopback (`127.0.0.0/8`, `localhost`) for local
  testing; any other address is refused by the client (no clearnet).
- The host relay listens on `127.0.0.1` only; Tor maps the onion port to it.

## 2. Framing

```
┌────────────┬─────────┬──────────────────────────┐
│ length u32 │ type u8 │ payload (length−1 bytes) │
└────────────┴─────────┴──────────────────────────┘
```

Big-endian length, maximum 65 536 bytes. After the Noise handshake every
payload is encrypted with the Noise transport keys (the type byte is not).

| Type | Message | Direction |
|------|---------|-----------|
| 0x01 | Noise NK message 1 (raw bytes) | C→H |
| 0x02 | Noise NK message 2 (raw bytes) | H→C |
| 0x03 | `AuthChallenge` | H→C |
| 0x04 | `AuthResponse` | C→H |
| 0x05 | `AuthResult` | H→C |
| 0x10 | `RoomMessage` | C→H→C |
| 0x11 | `RoomControl` (owner only) | C→H, echoed H→C |
| 0x12 | `PeerReady` | H→C |
| 0x13 | `PeerLeft` | H→C |
| 0x20 | `RatchetKeyExchange` | C→H→C |
| 0x21 | `PublishBundle` | C→H |
| 0x23 | `BundleResponse` | H→C |
| 0x24 | `OPKDepleted` | H→C |
| 0x25 | `RefreshOPK` | C→H |
| 0xFE / 0xFD | Ping / Pong (empty) | both |
| 0xFF | `ProtocolError` | both |

Types 0x30–0x32 (backlog) are defined for later versions and are not used yet;
of `RoomControl` only the `RevokeMember` action is implemented (§3.9). 0x22
(`RequestBundle`) is retired.

## 3. Connection lifecycle

### 3.1 Noise NK handshake

Pattern `Noise_NK_25519_ChaChaPoly_SHA256`, prologue `SANCTUM-NOISE-NK-v2`.
The host's static key comes from the invitation, so the client authenticates the
host; a peer speaking another protocol version fails here (different prologue).
Both sides keep the handshake hash `h` (32 bytes): it is unique per connection
and binds the authentication to this channel.

### 3.2 Authentication (Ed25519, channel-bound)

```
H→C  AuthChallenge { nonce[32], timestamp, room_id, server_id = SHA-256(host Noise static key) }
C    checks server_id against the key from the invitation
C    sig = Ed25519(identity_sk, payload)
C→H  AuthResponse { ed25519_public_key, sig, display_alias, invite_token }
H→C  AuthResult { success, error_message, member_role }
```

`payload = "SANCTUM-AUTH-v2" ‖ L(h) ‖ L(nonce) ‖ timestamp_u64_be ‖ L(room_id) ‖ L(server_id)`,
where `L(x) = len(x)_u32_be ‖ x`.

The host:
1. refuses if the global failure budget is exhausted (30 failures per 60 s window);
2. refuses a reused nonce or a challenge older than 120 s;
3. derives the fingerprint from the public key itself:
   `SHA-256("sanctum-fingerprint-v1:" ‖ pk)[..20]` as 40 hex characters
   (weak keys are rejected) — a declared fingerprint is never trusted;
4. verifies the signature strictly (`verify_strict`);
5. admits an **active member**, or a newcomer holding a **valid invitation**
   (§3.3). Anything else is refused and the connection closed.

Each connection gets exactly one attempt; the whole handshake + authentication
must complete within 30 s.

### 3.3 Invitations

An invitation is `base64url(JSON(InviteToken))`, issued by the owner
(`/invite <fingerprint>` in the owner's chat, or `sanctum room invite … --host-key`):

```
InviteToken { room_id, onion_address, port, host_noise_pubkey,
              inviter_fingerprint, invited_fingerprint, role, expires_at, issued_at, signature }
signature = Ed25519(owner_sk, "SANCTUM-INVITE-v2" ‖ L(room_id) ‖ L(onion) ‖ L(port)
                    ‖ L(host_noise_pubkey) ‖ L(inviter) ‖ L(invited) ‖ L(role)
                    ‖ L(expires_at) ‖ L(issued_at))
```

The host accepts it only if: it is for this room and this host session (Noise
key), the inviter is the owner and the signature verifies with the owner's key,
it has not expired, it was not issued in the future (beyond the 120 s clock
tolerance), the invitee is the proven fingerprint, the role is not `Owner`, it
has never been used, and it was issued **after** the last revocation of that
fingerprint (§3.9). The member is then added with its proven
public key. Members reconnect without an invitation.

### 3.4 Prekey bundles

Right after authentication each client sends `PublishBundle`:

```
PreKeyBundle { owner_fingerprint, ed25519_public_key, identity_key (X25519 IK),
               signed_pre_key (X25519 SPK), spk_signature, one_time_pre_keys[] }
spk_signature = Ed25519(identity_sk, "SANCTUM-SPK-v2" ‖ IK ‖ SPK)
```

A bundle is valid only if the signature verifies **and**
`Fingerprint(ed25519_public_key) == owner_fingerprint`. The host stores the bundle
of the authenticated identity only, then sends the publisher a `BundleResponse`
for every member who published before it, each carrying **one** one-time prekey
(OPK) that is never handed out again. Below 5 remaining OPKs the owner receives
`OPKDepleted` and answers with `RefreshOPK`. OPKs are not signed (as in X3DH):
substituting one does not let the host compute the shared secret.

### 3.5 Pairwise sessions (X3DH + Double Ratchet)

The later publisher initiates X3DH towards each earlier one and sends a
`RatchetKeyExchange` (routed to that recipient only, sender stamped by the host)
containing its own signed identity (a bundle without OPKs), its ephemeral key,
the OPK id, and a first ratchet message with an empty plaintext so that the
responder can answer immediately. The responder verifies that the signed identity
belongs to the stamped sender, deletes the OPK, and both have a session. If both
sides ever initiate, the session started by the smaller fingerprint wins on both
sides.

X3DH (X25519): `SK = HKDF-SHA256(salt = 0³², ikm = 0xFF³² ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4],
info = "SANCTUM-X3DH-v2")`; non-contributory (low-order) keys are rejected.

Double Ratchet (Signal specification, revision 4):
- `KDF_RK(rk, dh) = HKDF-SHA256(salt = rk, ikm = dh, info = "SANCTUM-DR-RK-v2")` → (rk′, ck)
- `KDF_CK(ck)`: mk = HMAC-SHA256(ck, 0x01), ck′ = HMAC-SHA256(ck, 0x02)
- mk → HKDF-SHA256(salt = 0³², info = "SANCTUM-DR-MSG-v2") → ChaCha20-Poly1305 key ‖ nonce
- AD = `"SANCTUM-DR-v2" ‖ IK_initiator ‖ IK_responder ‖ dh_public ‖ pn_u32_be ‖ n_u32_be`
- at most 256 skipped keys per chain and 1 000 overall; decryption is
  transactional (a failed message never changes the session).

Known-answer vectors produced by an independent Python implementation live in
`crates/sanctum-crypto/tests/kat/`.

### 3.6 Room messages

A message is encrypted once per member with the pairwise session and sent as one
`RoomMessage` per recipient:

```
RoomMessage { sender_fingerprint, sequence_number, envelope: Envelope { recipient_fingerprint, header, ciphertext } }
plaintext  = pad(timestamp_u64_be ‖ utf8 text, 256)       (text ≤ 4 000 bytes)
pad(m)     = len(m)_u32_be ‖ m ‖ random bytes up to a multiple of 256
```

The host forwards each `RoomMessage` to `envelope.recipient_fingerprint` only, after
overwriting `sender_fingerprint` with the authenticated identity. It never holds a
key that decrypts the envelope. A message for which no member has a session is
not sent; a message that fails to decrypt is shown as
`[message indéchiffrable de X]`, never as raw bytes.

### 3.7 Presence and keepalive

`PeerReady { fingerprint, display_alias }` announces members; `PeerLeft` tells
peers to drop a member's session. The host sanitizes aliases to `[A-Za-z0-9_-]{1,20}`;
clients sanitize everything again before display. Clients send `Ping` every 30 s;
a member silent for 120 s is disconnected. Three invalid frames close the
connection.

### 3.8 Safety numbers

`/verify <alias>` shows 12 groups of 5 digits derived from
`SHA-512("SANCTUM-SAFETY-v2" ‖ L(fp_a) ‖ L(pk_a) ‖ L(fp_b) ‖ L(pk_b))` (pairs sorted by
fingerprint). Both members see the same number; comparing it out of band detects a
host that would have introduced a fake member or keys.

### 3.9 Removing a member (`RoomControl`)

```
owner→H  RoomControl { revoke_member: RevokeMember { fingerprint } }
H→target ProtocolError { code: "revoked" }, then the connection is closed
H→others PeerLeft { fingerprint }
H→owner  the same RoomControl, echoed as acknowledgement
```

Only the authenticated owner may send `RoomControl`; anyone else gets
`ProtocolError { code: "revoke_failed" }`, as does the owner targeting itself.
Actions other than `RevokeMember` get `ProtocolError { code: "unsupported" }`.

The host marks the member revoked and records the revocation time `t` for that
fingerprint: every invitation with `issued_at ≤ t` is refused afterwards, so a
pending or replayed invitation cannot bring the member back. A new invitation
issued later (at least one second after, the resolution of `issued_at`)
re-admits it. Revocations live in the host's memory, like everything else in
ephemeral mode.

## 4. Host-side Tor control

The host creates an ephemeral `ED25519-V3` onion service (`Flags=DiscardPK`) through
the control port, authenticated with **SAFECOOKIE** only (the control port's
`SERVERHASH` is verified before the client proof is sent). Control ports without
authentication are refused.
