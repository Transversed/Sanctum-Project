//! Channel-bound Ed25519 challenge-response authentication (protocol v2).
//!
//! ```text
//! Client                                       Host
//!   │── Noise NK (host key from the invite) ──▶│  h = handshake hash
//!   │◀──── AuthChallenge{nonce, ts, room_id, server_id}
//!   │  sig = Sign(sk, "SANCTUM-AUTH-v2" ‖ h ‖ nonce ‖ ts ‖ room_id ‖ server_id)
//!   │── AuthResponse{public_key, sig, alias, invite?} ──▶│
//!   │        fp := Fingerprint(public_key)    (never a declared fp, I2)
//!   │        verify(sig) ; member? else valid owner-signed invite?
//!   │◀──── AuthResult{role}
//! ```
//!
//! Binding the signature to the Noise handshake hash makes a captured
//! response useless on any other connection.

use sanctum_domain::entities::invite::InviteToken;
use sanctum_domain::entities::member::{Fingerprint, Role};
use sanctum_domain::entities::room::RoomId;
use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::identity::SignatureVerifier;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};

/// Domain separator of the authentication signature.
pub const AUTH_SIGNATURE_DOMAIN: &[u8] = b"SANCTUM-AUTH-v2";

const CHALLENGE_NONCE_LEN: usize = 32;
/// Maximum clock difference accepted between challenge and verification.
pub const TIMESTAMP_TOLERANCE_SECS: u64 = 120;
/// Nonces are remembered for twice the tolerance, then purged.
const NONCE_TTL_SECS: u64 = 2 * TIMESTAMP_TOLERANCE_SECS;
/// Global failure budget: beyond this many failures in the window, every
/// authentication is refused until the window slides (anti brute force).
pub const MAX_FAILURES_PER_WINDOW: usize = 30;
/// Length of the sliding failure window.
pub const FAILURE_WINDOW_SECS: u64 = 60;

/// Authentication challenge sent by the host.
#[derive(Debug, Clone)]
pub struct AuthChallenge {
    /// Random nonce (32 bytes).
    pub nonce: Vec<u8>,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// Target room.
    pub room_id: RoomId,
    /// SHA-256 of the host's Noise static public key.
    pub server_id: [u8; 32],
}

/// Authentication response from the client.
#[derive(Debug, Clone)]
pub struct AuthResponse {
    /// Ed25519 public key; the fingerprint is derived from it by the host.
    pub public_key: Vec<u8>,
    /// Signature over [`auth_signing_payload`].
    pub signature: Vec<u8>,
    /// Alias chosen by the client (untrusted, sanitized by the caller).
    pub display_alias: String,
    /// Owner-signed invitation, required for the first admission.
    pub invite: Option<InviteToken>,
}

/// What the host knows about the room when admitting a client.
pub struct RoomAdmission<'a> {
    /// This room.
    pub room_id: &'a RoomId,
    /// Owner fingerprint (the only accepted inviter).
    pub owner_fingerprint: &'a Fingerprint,
    /// Owner public key, used to verify invitations.
    pub owner_public_key: &'a [u8],
    /// This host's Noise static public key (invites are bound to it).
    pub host_noise_pubkey: &'a [u8],
    /// Active members and their roles.
    pub members: &'a HashMap<Fingerprint, Role>,
}

/// How the client was admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Already an active member of the room.
    Member(Role),
    /// Admitted now through a valid invitation (single use).
    Invited(Role),
}

impl Admission {
    /// Role granted to the client.
    pub fn role(&self) -> Role {
        match self {
            Admission::Member(r) | Admission::Invited(r) => *r,
        }
    }
}

/// A successfully authenticated client.
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// Fingerprint computed by the host from the proven public key.
    pub fingerprint: Fingerprint,
    /// Proven public key.
    pub public_key: Vec<u8>,
    /// How the client was admitted.
    pub admission: Admission,
}

/// Bytes signed by the client: domain ‖ h ‖ nonce ‖ ts ‖ room_id ‖ server_id,
/// each variable-length field prefixed by its length.
pub fn auth_signing_payload(
    handshake_hash: &[u8],
    nonce: &[u8],
    timestamp: u64,
    room_id: &str,
    server_id: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(AUTH_SIGNATURE_DOMAIN.len() + 160);
    data.extend_from_slice(AUTH_SIGNATURE_DOMAIN);
    for field in [handshake_hash, nonce] {
        data.extend_from_slice(&(field.len() as u32).to_be_bytes());
        data.extend_from_slice(field);
    }
    data.extend_from_slice(&timestamp.to_be_bytes());
    for field in [room_id.as_bytes(), server_id] {
        data.extend_from_slice(&(field.len() as u32).to_be_bytes());
        data.extend_from_slice(field);
    }
    data
}

/// Stable identifier of an invitation (for single use).
pub fn invite_id(invite: &InviteToken) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SANCTUM-INVITE-ID");
    hasher.update(invite.signed_data());
    hasher.update(&invite.signature);
    hasher.finalize().into()
}

fn fail(reason: &str) -> SanctumError {
    SanctumError::AuthFailed {
        reason: reason.into(),
    }
}

/// Host-side authentication state (nonces, used invites, revocations,
/// failure window).
pub struct AuthService {
    /// nonce → timestamp of the challenge.
    used_nonces: HashMap<Vec<u8>, u64>,
    /// Consumed invitations (id) → their expiry. Past it, the invitation is
    /// refused as expired anyway, so the entry can be dropped.
    used_invites: HashMap<[u8; 32], u64>,
    /// fingerprint → time of revocation: invitations issued at or before
    /// this time are refused.
    revoked: HashMap<Fingerprint, u64>,
    failures: VecDeque<u64>,
}

impl AuthService {
    /// Create a new auth service.
    pub fn new() -> Self {
        Self {
            used_nonces: HashMap::new(),
            used_invites: HashMap::new(),
            revoked: HashMap::new(),
            failures: VecDeque::new(),
        }
    }

    /// Rebuild the durable part of the state (persistent mode): revocations
    /// and consumed invitations. Nonces and the failure window start empty.
    pub fn restore(
        revocations: Vec<(Fingerprint, u64)>,
        used_invites: Vec<([u8; 32], u64)>,
    ) -> Self {
        Self {
            revoked: revocations.into_iter().collect(),
            used_invites: used_invites.into_iter().collect(),
            ..Self::new()
        }
    }

    /// Durable part of the state, for [`AuthService::restore`]: revocations,
    /// and the consumed invitations that have not expired at `now`. Sorted,
    /// so that saving the same state twice gives the same bytes.
    #[allow(clippy::type_complexity)]
    pub fn durable_state(&self, now: u64) -> (Vec<(Fingerprint, u64)>, Vec<([u8; 32], u64)>) {
        let mut revocations: Vec<_> = self
            .revoked
            .iter()
            .map(|(fp, t)| (fp.clone(), *t))
            .collect();
        revocations.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        let mut used: Vec<_> = self
            .used_invites
            .iter()
            .filter(|(_, exp)| **exp >= now)
            .map(|(id, exp)| (*id, *exp))
            .collect();
        used.sort();
        (revocations, used)
    }

    /// Revoke `fingerprint` at `now`: every invitation issued for it until
    /// then becomes unusable. A later invitation re-admits it.
    pub fn revoke(&mut self, fingerprint: &Fingerprint, now: u64) {
        self.revoked.insert(fingerprint.clone(), now);
    }

    /// Generate a challenge for a connecting client.
    pub fn create_challenge(&self, room_id: &RoomId, host_noise_pubkey: &[u8]) -> AuthChallenge {
        let mut nonce = vec![0u8; CHALLENGE_NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        AuthChallenge {
            nonce,
            timestamp: unix_now(),
            room_id: room_id.clone(),
            server_id: compute_server_id(host_noise_pubkey),
        }
    }

    /// Payload the client must sign for `challenge` on the channel `h`.
    pub fn signing_payload(handshake_hash: &[u8], challenge: &AuthChallenge) -> Vec<u8> {
        auth_signing_payload(
            handshake_hash,
            &challenge.nonce,
            challenge.timestamp,
            &challenge.room_id.as_str(),
            &challenge.server_id,
        )
    }

    /// Verify an authentication response (host side).
    ///
    /// Order: global rate limit, nonce, timestamp, fingerprint derivation,
    /// channel-bound signature, then authorization (member or invitation).
    /// Every failure is counted in the global window.
    pub fn verify_response(
        &mut self,
        challenge: &AuthChallenge,
        handshake_hash: &[u8],
        response: &AuthResponse,
        room: &RoomAdmission<'_>,
        verifier: &dyn SignatureVerifier,
        now: u64,
    ) -> Result<Authenticated, SanctumError> {
        self.purge(now);
        if self.failures.len() >= MAX_FAILURES_PER_WINDOW {
            return Err(fail("too many failed authentications, retry later"));
        }
        let result = self.verify_inner(challenge, handshake_hash, response, room, verifier, now);
        if result.is_err() {
            self.failures.push_back(now);
        }
        result
    }

    fn verify_inner(
        &mut self,
        challenge: &AuthChallenge,
        handshake_hash: &[u8],
        response: &AuthResponse,
        room: &RoomAdmission<'_>,
        verifier: &dyn SignatureVerifier,
        now: u64,
    ) -> Result<Authenticated, SanctumError> {
        if self.used_nonces.contains_key(&challenge.nonce) {
            return Err(fail("challenge already used"));
        }
        if now.abs_diff(challenge.timestamp) > TIMESTAMP_TOLERANCE_SECS {
            return Err(fail("challenge expired"));
        }
        if challenge.room_id != *room.room_id {
            return Err(fail("challenge for another room"));
        }

        // I2: the fingerprint comes from the key, never from the client.
        let fingerprint = verifier.fingerprint(&response.public_key)?;
        let payload = Self::signing_payload(handshake_hash, challenge);
        if !verifier.verify(&response.public_key, &payload, &response.signature) {
            return Err(fail("invalid signature"));
        }

        let admission = match room.members.get(&fingerprint) {
            Some(role) => Admission::Member(*role),
            None => match &response.invite {
                Some(invite) => {
                    let role = self.check_invite(invite, &fingerprint, room, verifier, now)?;
                    Admission::Invited(role)
                }
                None => return Err(fail("not a member of this room and no invitation")),
            },
        };

        self.used_nonces
            .insert(challenge.nonce.clone(), challenge.timestamp);
        if let (Admission::Invited(_), Some(invite)) = (admission, &response.invite) {
            self.used_invites
                .insert(invite_id(invite), invite.expires_at);
        }
        Ok(Authenticated {
            fingerprint,
            public_key: response.public_key.clone(),
            admission,
        })
    }

    /// Validate an owner-signed invitation for `fingerprint`.
    pub fn check_invite(
        &self,
        invite: &InviteToken,
        fingerprint: &Fingerprint,
        room: &RoomAdmission<'_>,
        verifier: &dyn SignatureVerifier,
        now: u64,
    ) -> Result<Role, SanctumError> {
        if invite.room_id != *room.room_id {
            return Err(fail("invitation is for another room"));
        }
        if invite.inviter_fingerprint != *room.owner_fingerprint {
            return Err(fail("invitation not issued by the room owner"));
        }
        if !verifier.verify(
            room.owner_public_key,
            &invite.signed_data(),
            &invite.signature,
        ) {
            return Err(fail("invalid invitation signature"));
        }
        if invite.is_expired(now) {
            return Err(fail("invitation expired"));
        }
        if !invite.is_for(fingerprint) {
            return Err(fail("invitation is for another identity"));
        }
        if invite.host_noise_pubkey != room.host_noise_pubkey {
            return Err(fail("invitation is for another host session"));
        }
        if invite.role == Role::Owner {
            return Err(fail("invitation cannot grant the owner role"));
        }
        if self.used_invites.contains_key(&invite_id(invite)) {
            return Err(fail("invitation already used"));
        }
        if let Some(revoked_at) = self.revoked.get(fingerprint) {
            if invite.issued_at <= *revoked_at {
                return Err(fail("invitation revoked by the owner"));
            }
        }
        if invite.issued_at > now.saturating_add(TIMESTAMP_TOLERANCE_SECS) {
            return Err(fail("invitation issued in the future"));
        }
        Ok(invite.role)
    }

    /// Client-side: check that the challenge comes from the expected host.
    pub fn verify_server_id(
        challenge: &AuthChallenge,
        host_noise_pubkey: &[u8],
    ) -> Result<(), SanctumError> {
        if challenge.server_id != compute_server_id(host_noise_pubkey) {
            return Err(fail("server_id mismatch — possible relay attack"));
        }
        Ok(())
    }

    /// Forget expired nonces and failures outside the window.
    fn purge(&mut self, now: u64) {
        self.used_nonces
            .retain(|_, ts| now.saturating_sub(*ts) <= NONCE_TTL_SECS);
        self.used_invites.retain(|_, expires_at| *expires_at >= now);
        while self
            .failures
            .front()
            .is_some_and(|t| now.saturating_sub(*t) > FAILURE_WINDOW_SECS)
        {
            self.failures.pop_front();
        }
    }
}

impl Default for AuthService {
    fn default() -> Self {
        Self::new()
    }
}

/// Current Unix time in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Compute server_id = SHA-256(host_noise_static_pubkey).
pub fn compute_server_id(noise_pubkey: &[u8]) -> [u8; 32] {
    Sha256::digest(noise_pubkey).into()
}

#[cfg(test)]
mod tests {
    //! Uses a toy signature scheme (sig = SHA-256(pk ‖ msg)) so the
    //! authorization logic is tested independently of Ed25519. The real
    //! scheme is exercised end to end in sanctum-infra's host tests.
    use super::*;

    struct ToyVerifier;

    fn toy_sign(pk: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(pk);
        h.update(msg);
        h.finalize().to_vec()
    }

    fn toy_fp(pk: &[u8]) -> Fingerprint {
        let d = Sha256::digest(pk);
        Fingerprint::new(
            d[..20]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>(),
        )
        .unwrap()
    }

    impl SignatureVerifier for ToyVerifier {
        fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            toy_sign(pk, msg) == sig
        }
        fn fingerprint(&self, pk: &[u8]) -> Result<Fingerprint, SanctumError> {
            if pk.len() != 32 {
                return Err(fail("bad key"));
            }
            Ok(toy_fp(pk))
        }
    }

    const HOST_KEY: [u8; 32] = [9u8; 32];
    const OWNER_PK: [u8; 32] = [1u8; 32];
    const ALICE_PK: [u8; 32] = [2u8; 32];
    const BOB_PK: [u8; 32] = [3u8; 32];
    const H1: [u8; 32] = [0xA1; 32];
    const H2: [u8; 32] = [0xA2; 32];

    struct Fixture {
        room_id: RoomId,
        owner_fp: Fingerprint,
        members: HashMap<Fingerprint, Role>,
    }

    impl Fixture {
        fn new() -> Self {
            let owner_fp = toy_fp(&OWNER_PK);
            let mut members = HashMap::new();
            members.insert(owner_fp.clone(), Role::Owner);
            Self {
                room_id: RoomId::new(),
                owner_fp,
                members,
            }
        }
        fn admission(&self) -> RoomAdmission<'_> {
            RoomAdmission {
                room_id: &self.room_id,
                owner_fingerprint: &self.owner_fp,
                owner_public_key: &OWNER_PK,
                host_noise_pubkey: &HOST_KEY,
                members: &self.members,
            }
        }
        fn invite_for(&self, pk: &[u8], expires_at: u64) -> InviteToken {
            let mut t = InviteToken {
                room_id: self.room_id.clone(),
                onion_address: "x.onion".into(),
                port: 1,
                host_noise_pubkey: HOST_KEY.to_vec(),
                inviter_fingerprint: self.owner_fp.clone(),
                invited_fingerprint: toy_fp(pk),
                role: Role::Member,
                expires_at,
                issued_at: unix_now(),
                signature: vec![],
            };
            t.signature = toy_sign(&OWNER_PK, &t.signed_data());
            t
        }
    }

    fn respond(
        pk: &[u8],
        h: &[u8],
        c: &AuthChallenge,
        invite: Option<InviteToken>,
    ) -> AuthResponse {
        AuthResponse {
            public_key: pk.to_vec(),
            signature: toy_sign(pk, &AuthService::signing_payload(h, c)),
            display_alias: "x".into(),
            invite,
        }
    }

    fn verify(
        svc: &mut AuthService,
        fx: &Fixture,
        c: &AuthChallenge,
        h: &[u8],
        r: &AuthResponse,
    ) -> Result<Authenticated, SanctumError> {
        svc.verify_response(c, h, r, &fx.admission(), &ToyVerifier, c.timestamp)
    }

    #[test]
    fn member_authenticates_with_channel_bound_signature() {
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let auth = verify(&mut svc, &fx, &c, &H1, &respond(&OWNER_PK, &H1, &c, None)).unwrap();
        assert_eq!(auth.fingerprint, fx.owner_fp);
        assert_eq!(auth.admission, Admission::Member(Role::Owner));
    }

    #[test]
    fn missing_signature_is_rejected() {
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let mut r = respond(&OWNER_PK, &H1, &c, None);
        r.signature.clear();
        assert!(verify(&mut svc, &fx, &c, &H1, &r).is_err());
    }

    #[test]
    fn signature_by_another_key_is_rejected() {
        // Mallory presents the owner's public key but signs with her own.
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let mut r = respond(&OWNER_PK, &H1, &c, None);
        r.signature = toy_sign(&[0xEE; 32], &AuthService::signing_payload(&H1, &c));
        assert!(verify(&mut svc, &fx, &c, &H1, &r).is_err());
    }

    #[test]
    fn valid_signature_replayed_on_another_channel_is_rejected() {
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let captured = respond(&OWNER_PK, &H1, &c, None);
        // Same challenge, same response, different connection (h differs).
        assert!(verify(&mut svc, &fx, &c, &H2, &captured).is_err());
    }

    #[test]
    fn unknown_client_without_invite_is_rejected() {
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let err = verify(&mut svc, &fx, &c, &H1, &respond(&ALICE_PK, &H1, &c, None)).unwrap_err();
        assert!(err.to_string().contains("no invitation"));
    }

    #[test]
    fn valid_invite_admits_once() {
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let invite = fx.invite_for(&ALICE_PK, unix_now() + 3600);

        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let r = respond(&ALICE_PK, &H1, &c, Some(invite.clone()));
        let auth = verify(&mut svc, &fx, &c, &H1, &r).unwrap();
        assert_eq!(auth.admission, Admission::Invited(Role::Member));
        assert_eq!(auth.fingerprint, toy_fp(&ALICE_PK));

        // Reusing the same invitation (Alice was removed meanwhile).
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let r = respond(&ALICE_PK, &H2, &c, Some(invite));
        let err = verify(&mut svc, &fx, &c, &H2, &r).unwrap_err();
        assert!(err.to_string().contains("already used"));
    }

    #[test]
    fn invalid_invitations_are_rejected() {
        let fx = Fixture::new();
        let now = unix_now();
        let resign = |mut t: InviteToken, pk: &[u8]| {
            t.signature = toy_sign(pk, &t.signed_data());
            t
        };
        let cases: Vec<(&str, InviteToken)> = vec![
            ("expired", fx.invite_for(&ALICE_PK, now - 1)),
            ("another identity", fx.invite_for(&BOB_PK, now + 3600)),
            ("signature", {
                let mut t = fx.invite_for(&ALICE_PK, now + 3600);
                t.role = Role::Admin; // tampered after signing
                t
            }),
            ("another room", {
                let mut t = fx.invite_for(&ALICE_PK, now + 3600);
                t.room_id = RoomId::new();
                resign(t, &OWNER_PK)
            }),
            ("host session", {
                let mut t = fx.invite_for(&ALICE_PK, now + 3600);
                t.host_noise_pubkey = vec![8u8; 32];
                resign(t, &OWNER_PK)
            }),
            ("room owner", {
                // Signed by a non-owner claiming to be the inviter.
                let mut t = fx.invite_for(&ALICE_PK, now + 3600);
                t.inviter_fingerprint = toy_fp(&BOB_PK);
                resign(t, &BOB_PK)
            }),
            ("owner role", {
                let mut t = fx.invite_for(&ALICE_PK, now + 3600);
                t.role = Role::Owner;
                resign(t, &OWNER_PK)
            }),
        ];
        for (expected, invite) in cases {
            let mut svc = AuthService::new();
            let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
            let r = respond(&ALICE_PK, &H1, &c, Some(invite));
            let err = verify(&mut svc, &fx, &c, &H1, &r).unwrap_err().to_string();
            assert!(err.contains(expected), "case {expected}: got {err}");
        }
    }

    #[test]
    fn revocation_blocks_earlier_invitations_only() {
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let now = unix_now();
        let old = fx.invite_for(&ALICE_PK, now + 3600); // issued_at = now
        svc.revoke(&toy_fp(&ALICE_PK), now);

        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let r = respond(&ALICE_PK, &H1, &c, Some(old));
        let err = verify(&mut svc, &fx, &c, &H1, &r).unwrap_err().to_string();
        assert!(err.contains("revoked"), "{err}");

        // A new invitation issued after the revocation re-admits Alice.
        let mut fresh = fx.invite_for(&ALICE_PK, now + 3600);
        fresh.issued_at = now + 1;
        fresh.signature = toy_sign(&OWNER_PK, &fresh.signed_data());
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let r = respond(&ALICE_PK, &H2, &c, Some(fresh));
        assert!(verify(&mut svc, &fx, &c, &H2, &r).is_ok());
    }

    #[test]
    fn consumed_invitations_and_revocations_survive_a_restore() {
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let now = unix_now();
        let used = fx.invite_for(&ALICE_PK, now + 3600);
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let r = respond(&ALICE_PK, &H1, &c, Some(used.clone()));
        verify(&mut svc, &fx, &c, &H1, &r).unwrap();
        svc.revoke(&toy_fp(&OWNER_PK), now); // any fingerprint will do
        let (revocations, used_invites) = svc.durable_state(now);
        assert_eq!(revocations.len(), 1);
        assert_eq!(used_invites, vec![(invite_id(&used), now + 3600)]);

        let mut restored = AuthService::restore(revocations.clone(), used_invites.clone());
        assert_eq!(restored.durable_state(now), (revocations, used_invites));
        let c = restored.create_challenge(&fx.room_id, &HOST_KEY);
        let r = respond(&ALICE_PK, &H2, &c, Some(used));
        let err = verify(&mut restored, &fx, &c, &H2, &r)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already used"), "{err}");
    }

    #[test]
    fn expired_consumed_invitations_are_not_kept() {
        let id = [7u8; 32];
        let svc = AuthService::restore(vec![], vec![(id, 1_000)]);
        assert_eq!(svc.durable_state(1_000).1, vec![(id, 1_000)]);
        assert!(svc.durable_state(1_001).1.is_empty());
    }

    #[test]
    fn invitation_from_the_future_is_rejected() {
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let mut t = fx.invite_for(&ALICE_PK, unix_now() + 7200);
        t.issued_at = unix_now() + 3600;
        t.signature = toy_sign(&OWNER_PK, &t.signed_data());
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let r = respond(&ALICE_PK, &H1, &c, Some(t));
        assert!(verify(&mut svc, &fx, &c, &H1, &r).is_err());
    }

    #[test]
    fn nonce_cannot_be_reused() {
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let r = respond(&OWNER_PK, &H1, &c, None);
        verify(&mut svc, &fx, &c, &H1, &r).unwrap();
        assert!(verify(&mut svc, &fx, &c, &H1, &r).is_err());
    }

    #[test]
    fn stale_challenge_is_rejected() {
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let r = respond(&OWNER_PK, &H1, &c, None);
        let late = c.timestamp + TIMESTAMP_TOLERANCE_SECS + 1;
        assert!(svc
            .verify_response(&c, &H1, &r, &fx.admission(), &ToyVerifier, late)
            .is_err());
    }

    #[test]
    fn failures_claiming_bobs_key_do_not_lock_bob_out() {
        let mut fx = Fixture::new();
        fx.members.insert(toy_fp(&BOB_PK), Role::Member);
        let mut svc = AuthService::new();
        for _ in 0..3 {
            let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
            let mut forged = respond(&BOB_PK, &H1, &c, None);
            forged.signature = vec![0u8; 32];
            assert!(verify(&mut svc, &fx, &c, &H1, &forged).is_err());
        }
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        assert!(verify(&mut svc, &fx, &c, &H2, &respond(&BOB_PK, &H2, &c, None)).is_ok());
    }

    #[test]
    fn global_failure_budget_then_recovery() {
        let fx = Fixture::new();
        let mut svc = AuthService::new();
        let t0 = unix_now();
        for _ in 0..MAX_FAILURES_PER_WINDOW {
            let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
            let r = respond(&ALICE_PK, &H1, &c, None);
            let _ = svc.verify_response(&c, &H1, &r, &fx.admission(), &ToyVerifier, t0);
        }
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let r = respond(&OWNER_PK, &H1, &c, None);
        let err = svc
            .verify_response(&c, &H1, &r, &fx.admission(), &ToyVerifier, t0)
            .unwrap_err();
        assert!(err.to_string().contains("too many"));

        // After the window, the owner gets in again (fresh challenge).
        let later = t0 + FAILURE_WINDOW_SECS + 1;
        let mut c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        c.timestamp = later;
        let r = respond(&OWNER_PK, &H1, &c, None);
        assert!(svc
            .verify_response(&c, &H1, &r, &fx.admission(), &ToyVerifier, later)
            .is_ok());
    }

    #[test]
    fn signing_payload_is_domain_separated_and_channel_bound() {
        let fx = Fixture::new();
        let svc = AuthService::new();
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        let p1 = AuthService::signing_payload(&H1, &c);
        assert!(p1.starts_with(AUTH_SIGNATURE_DOMAIN));
        assert_ne!(p1, AuthService::signing_payload(&H2, &c));
    }

    #[test]
    fn server_id_verification() {
        let fx = Fixture::new();
        let svc = AuthService::new();
        let c = svc.create_challenge(&fx.room_id, &HOST_KEY);
        assert!(AuthService::verify_server_id(&c, &HOST_KEY).is_ok());
        assert!(AuthService::verify_server_id(&c, &[0u8; 32]).is_err());
    }
}
