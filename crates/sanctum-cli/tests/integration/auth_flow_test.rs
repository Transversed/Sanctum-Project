//! Integration test: full authentication flow.
//!
//! Covers AT-04 (auth), AT-10 (nominative invite), AT-12 (version check).

use sanctum_app::auth_service::{AuthResponse, AuthService};
use sanctum_domain::entities::member::Fingerprint;
use sanctum_infra::identity_pgp::IdentityAdapter;
use sanctum_infra::codec::{self, Frame, message_types};
use std::collections::HashSet;

fn allowed_set(fps: &[&Fingerprint]) -> HashSet<Fingerprint> {
    fps.iter().map(|f| (*f).clone()).collect()
}

#[test]
fn full_auth_challenge_response_with_identity_adapter() {
    let client_identity = IdentityAdapter::generate();
    let host_noise_pubkey = vec![42u8; 32];
    let mut auth_svc = AuthService::new();
    let allowed = allowed_set(&[client_identity.fingerprint()]);

    let challenge = auth_svc.create_challenge(
        &sanctum_domain::entities::room::RoomId::new(),
        &host_noise_pubkey,
    );

    let server_id_ok = AuthService::verify_server_id(&challenge, &host_noise_pubkey);
    assert!(server_id_ok.is_ok());

    let challenge_bytes = AuthService::challenge_to_bytes(&challenge);
    let signature = client_identity.sign(&challenge_bytes).unwrap();

    let response = AuthResponse {
        fingerprint: client_identity.fingerprint().clone(),
        signature,
        pgp_public_key: client_identity.public_key_bytes(),
        display_alias: "client-alice".into(),
    };

    let result = auth_svc.verify_response(&challenge, &response, &allowed);
    assert!(result.is_ok(), "auth should succeed for allowed fingerprint");
}

#[test]
fn auth_rejects_non_invited_fingerprint() {
    let client_identity = IdentityAdapter::generate();
    let intruder_identity = IdentityAdapter::generate();
    let host_noise_pubkey = vec![42u8; 32];
    let mut auth_svc = AuthService::new();
    let allowed = allowed_set(&[client_identity.fingerprint()]);

    let challenge = auth_svc.create_challenge(
        &sanctum_domain::entities::room::RoomId::new(),
        &host_noise_pubkey,
    );

    let challenge_bytes = AuthService::challenge_to_bytes(&challenge);
    let signature = intruder_identity.sign(&challenge_bytes).unwrap();

    let response = AuthResponse {
        fingerprint: intruder_identity.fingerprint().clone(),
        signature,
        pgp_public_key: intruder_identity.public_key_bytes(),
        display_alias: "intruder".into(),
    };

    let result = auth_svc.verify_response(&challenge, &response, &allowed);
    assert!(result.is_err(), "intruder should be rejected");
}

#[test]
fn client_detects_server_id_mismatch() {
    let host_noise_pubkey = vec![42u8; 32];
    let fake_noise_pubkey = vec![99u8; 32];
    let mut auth_svc = AuthService::new();

    let challenge = auth_svc.create_challenge(
        &sanctum_domain::entities::room::RoomId::new(),
        &host_noise_pubkey,
    );

    assert!(AuthService::verify_server_id(&challenge, &host_noise_pubkey).is_ok());
    assert!(AuthService::verify_server_id(&challenge, &fake_noise_pubkey).is_err());
}

#[test]
fn auth_challenge_survives_codec_round_trip() {
    let data = b"nonce:1234|timestamp:1700000000|room:abc|server:xyz";
    let frame = Frame::new(message_types::AUTH_CHALLENGE, data.to_vec());
    let encoded = codec::encode_frame(&frame);
    let mut buf = bytes::BytesMut::from(&encoded[..]);
    let decoded = codec::decode_frame(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.message_type, message_types::AUTH_CHALLENGE);
    assert_eq!(decoded.payload, data);
}

#[test]
fn auth_response_survives_codec_round_trip() {
    let data = b"fp:AABB...|sig:deadbeef|pk:0102|alias:alice";
    let frame = Frame::new(message_types::AUTH_RESPONSE, data.to_vec());
    let encoded = codec::encode_frame(&frame);
    let mut buf = bytes::BytesMut::from(&encoded[..]);
    let decoded = codec::decode_frame(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.message_type, message_types::AUTH_RESPONSE);
    assert_eq!(decoded.payload, data);
}

#[test]
fn auth_rate_limits_per_fingerprint() {
    let mut auth_svc = AuthService::new();
    let host_noise_pubkey = vec![42u8; 32];
    let room_id = sanctum_domain::entities::room::RoomId::new();
    let attacker = IdentityAdapter::generate();

    let empty_allowed: HashSet<Fingerprint> = HashSet::new();
    let real_allowed = allowed_set(&[attacker.fingerprint()]);

    for _ in 0..3 {
        let challenge = auth_svc.create_challenge(&room_id, &host_noise_pubkey);
        let challenge_bytes = AuthService::challenge_to_bytes(&challenge);
        let sig = attacker.sign(&challenge_bytes).unwrap();
        let response = AuthResponse {
            fingerprint: attacker.fingerprint().clone(),
            signature: sig,
            pgp_public_key: attacker.public_key_bytes(),
            display_alias: "attacker".into(),
        };
        let result = auth_svc.verify_response(&challenge, &response, &empty_allowed);
        assert!(result.is_err());
    }

    let challenge = auth_svc.create_challenge(&room_id, &host_noise_pubkey);
    let challenge_bytes = AuthService::challenge_to_bytes(&challenge);
    let sig = attacker.sign(&challenge_bytes).unwrap();
    let response = AuthResponse {
        fingerprint: attacker.fingerprint().clone(),
        signature: sig,
        pgp_public_key: attacker.public_key_bytes(),
        display_alias: "attacker".into(),
    };
    let result = auth_svc.verify_response(&challenge, &response, &real_allowed);
    assert!(result.is_err(), "should be rate-limited after 3 failed attempts");
}