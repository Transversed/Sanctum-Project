//! Authentication flow with real Ed25519 identities (protocol v2).
//!
//! The logic is unit-tested in sanctum-app with a toy scheme; here the real
//! adapters (Ed25519Verifier, IdentityAdapter, signed invites) are combined.

use sanctum_app::auth_service::{unix_now, Admission, AuthResponse, AuthService, RoomAdmission};
use sanctum_domain::entities::invite::InviteToken;
use sanctum_domain::entities::member::{Fingerprint, Role};
use sanctum_domain::entities::room::RoomId;
use sanctum_domain::ports::identity::Signer;
use sanctum_infra::identity::{Ed25519Verifier, IdentityAdapter};
use sanctum_infra::invite_codec::{create_signed_invite, InviteTarget};
use std::collections::HashMap;

const HOST_KEY: [u8; 32] = [42u8; 32];

struct Room {
    id: RoomId,
    owner: IdentityAdapter,
    members: HashMap<Fingerprint, Role>,
}

impl Room {
    fn new() -> Self {
        let owner = IdentityAdapter::generate();
        let mut members = HashMap::new();
        members.insert(owner.fingerprint().clone(), Role::Owner);
        Self {
            id: RoomId::new(),
            owner,
            members,
        }
    }

    fn admission(&self) -> (Fingerprint, Vec<u8>) {
        (
            self.owner.fingerprint().clone(),
            self.owner.public_key_bytes(),
        )
    }

    fn invite(&self, who: &IdentityAdapter, signer: &dyn Signer) -> InviteToken {
        let target = InviteTarget {
            room_id: self.id.clone(),
            onion_address: "127.0.0.1".into(),
            port: 9738,
            host_noise_pubkey: HOST_KEY.to_vec(),
        };
        create_signed_invite(
            signer,
            &target,
            who.fingerprint().clone(),
            Role::Member,
            unix_now() + 60,
        )
        .unwrap()
    }

    fn authenticate(
        &self,
        svc: &mut AuthService,
        who: &IdentityAdapter,
        h: &[u8],
        invite: Option<InviteToken>,
    ) -> Result<Admission, String> {
        let (owner_fp, owner_pk) = self.admission();
        let admission = RoomAdmission {
            room_id: &self.id,
            owner_fingerprint: &owner_fp,
            owner_public_key: &owner_pk,
            host_noise_pubkey: &HOST_KEY,
            members: &self.members,
        };
        let challenge = svc.create_challenge(&self.id, &HOST_KEY);
        let response = AuthResponse {
            public_key: who.public_key_bytes(),
            signature: Signer::sign(who, &AuthService::signing_payload(h, &challenge)),
            display_alias: "x".into(),
            invite,
        };
        svc.verify_response(
            &challenge,
            h,
            &response,
            &admission,
            &Ed25519Verifier,
            unix_now(),
        )
        .map(|a| a.admission)
        .map_err(|e| e.to_string())
    }
}

#[test]
fn owner_is_recognized_from_the_proven_key() {
    let room = Room::new();
    let mut svc = AuthService::new();
    let a = room
        .authenticate(&mut svc, &room.owner, &[1u8; 32], None)
        .unwrap();
    assert_eq!(a, Admission::Member(Role::Owner));
}

#[test]
fn stranger_is_rejected_without_invitation() {
    let room = Room::new();
    let mut svc = AuthService::new();
    let mallory = IdentityAdapter::generate();
    assert!(room
        .authenticate(&mut svc, &mallory, &[1u8; 32], None)
        .is_err());
}

#[test]
fn owner_signed_invitation_admits_exactly_once() {
    let room = Room::new();
    let mut svc = AuthService::new();
    let alice = IdentityAdapter::generate();
    let invite = room.invite(&alice, &room.owner);

    let a = room
        .authenticate(&mut svc, &alice, &[1u8; 32], Some(invite.clone()))
        .unwrap();
    assert_eq!(a, Admission::Invited(Role::Member));

    let err = room
        .authenticate(&mut svc, &alice, &[2u8; 32], Some(invite))
        .unwrap_err();
    assert!(err.contains("already used"), "{err}");
}

#[test]
fn self_signed_invitation_is_rejected() {
    let room = Room::new();
    let mut svc = AuthService::new();
    let mallory = IdentityAdapter::generate();
    // Mallory forges an invite claiming the owner as inviter.
    let mut forged = room.invite(&mallory, &mallory);
    forged.inviter_fingerprint = room.owner.fingerprint().clone();
    let err = room
        .authenticate(&mut svc, &mallory, &[1u8; 32], Some(forged))
        .unwrap_err();
    assert!(err.contains("invalid invitation signature"), "{err}");
}

#[test]
fn invitation_cannot_be_used_by_someone_else() {
    let room = Room::new();
    let mut svc = AuthService::new();
    let alice = IdentityAdapter::generate();
    let mallory = IdentityAdapter::generate();
    let invite = room.invite(&alice, &room.owner);
    let err = room
        .authenticate(&mut svc, &mallory, &[1u8; 32], Some(invite))
        .unwrap_err();
    assert!(err.contains("another identity"), "{err}");
}
