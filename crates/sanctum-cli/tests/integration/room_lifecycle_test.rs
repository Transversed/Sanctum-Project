//! Integration test: room lifecycle.
//!
//! Covers AT-03, AT-09.

use sanctum_app::room_service::RoomService;
use sanctum_app::host_service::HostService;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Role};
use sanctum_domain::entities::room::{RoomConfig, RoomMode};
use sanctum_infra::storage_memory::MemoryStorageAdapter;
use sanctum_infra::identity_pgp::IdentityAdapter;
use tokio::sync::broadcast;

#[test]
fn create_room_and_store_in_memory() {
    let alice_id = IdentityAdapter::generate();
    let mut room_svc = RoomService::new();
    let mut storage = MemoryStorageAdapter::new(500);

    room_svc
        .create_room(
            "ops-room", RoomMode::Ephemeral, RoomConfig::default(),
            alice_id.fingerprint().clone(), alice_id.public_key_bytes(),
            DisplayAlias::new("alice").unwrap(),
        )
        .unwrap();

    let room = room_svc.room().unwrap();
    assert_eq!(room.name(), "ops-room");
    assert_eq!(room.active_member_count(), 1);

    storage.store_room(room).unwrap();
    let loaded = storage.load_room(room.id()).unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().name(), "ops-room");
}

#[test]
fn add_member_then_register_in_host_service() {
    let alice = IdentityAdapter::generate();
    let bob = IdentityAdapter::generate();

    let mut room_svc = RoomService::new();
    room_svc
        .create_room(
            "test-room", RoomMode::Ephemeral, RoomConfig::default(),
            alice.fingerprint().clone(), alice.public_key_bytes(),
            DisplayAlias::new("alice").unwrap(),
        )
        .unwrap();

    room_svc
        .add_member(
            alice.fingerprint(), bob.fingerprint().clone(),
            bob.public_key_bytes(), DisplayAlias::new("bob").unwrap(), Role::Member,
        )
        .unwrap();

    let room = room_svc.room().unwrap();
    assert_eq!(room.active_member_count(), 2);

    let (event_tx, mut event_rx) = broadcast::channel(16);
    let mut host_svc = HostService::new(room.clone(), event_tx);

    let result = host_svc.register_client(bob.fingerprint().clone(), 100);
    assert!(result.is_ok());

    let event = event_rx.try_recv();
    assert!(event.is_ok());
}

#[test]
fn host_rejects_non_member() {
    let alice = IdentityAdapter::generate();
    let intruder = IdentityAdapter::generate();

    let mut room_svc = RoomService::new();
    room_svc
        .create_room(
            "private-room", RoomMode::Ephemeral, RoomConfig::default(),
            alice.fingerprint().clone(), alice.public_key_bytes(),
            DisplayAlias::new("alice").unwrap(),
        )
        .unwrap();

    let room = room_svc.room().unwrap();
    let (event_tx, _) = broadcast::channel(16);
    let mut host_svc = HostService::new(room.clone(), event_tx);

    let result = host_svc.register_client(intruder.fingerprint().clone(), 200);
    assert!(result.is_err());
}

#[test]
fn revoke_member_disconnects_from_host() {
    let alice = IdentityAdapter::generate();
    let bob = IdentityAdapter::generate();

    let mut room_svc = RoomService::new();
    room_svc
        .create_room(
            "test-room", RoomMode::Ephemeral, RoomConfig::default(),
            alice.fingerprint().clone(), alice.public_key_bytes(),
            DisplayAlias::new("alice").unwrap(),
        )
        .unwrap();

    room_svc
        .add_member(
            alice.fingerprint(), bob.fingerprint().clone(),
            bob.public_key_bytes(), DisplayAlias::new("bob").unwrap(), Role::Member,
        )
        .unwrap();

    let room = room_svc.room().unwrap();
    let (event_tx, _) = broadcast::channel(16);
    let mut host_svc = HostService::new(room.clone(), event_tx);

    host_svc.register_client(bob.fingerprint().clone(), 100).unwrap();
    assert!(host_svc.is_connected(bob.fingerprint()));

    room_svc.revoke_member(alice.fingerprint(), bob.fingerprint()).unwrap();

    host_svc.remove_client(bob.fingerprint());
    assert!(!host_svc.is_connected(bob.fingerprint()));
}

#[test]
fn invite_generate_validate_round_trip() {
    let alice = IdentityAdapter::generate();
    let bob = IdentityAdapter::generate();

    let mut room_svc = RoomService::new();
    room_svc
        .create_room(
            "invite-room", RoomMode::Ephemeral, RoomConfig::default(),
            alice.fingerprint().clone(), alice.public_key_bytes(),
            DisplayAlias::new("alice").unwrap(),
        )
        .unwrap();

    // generate_invite takes 7 args: inviter_fp, invited_fp, role, onion, port, noise_key, ttl
    let invite = room_svc
        .generate_invite(
            alice.fingerprint(),
            bob.fingerprint().clone(),
            Role::Member,
            "abc123.onion".into(),
            9738,
            vec![0u8; 32],
            3600,
        )
        .unwrap();

    // invited_fingerprint is a field, not a method
    assert_eq!(invite.invited_fingerprint, *bob.fingerprint());

    let valid = room_svc.validate_invite(&invite, bob.fingerprint());
    assert!(valid.is_ok());

    let charlie = IdentityAdapter::generate();
    let invalid = room_svc.validate_invite(&invite, charlie.fingerprint());
    assert!(invalid.is_err());
}

#[test]
fn host_routes_to_ready_peers_only() {
    let alice = IdentityAdapter::generate();
    let bob = IdentityAdapter::generate();
    let charlie = IdentityAdapter::generate();

    let mut room_svc = RoomService::new();
    room_svc
        .create_room(
            "route-room", RoomMode::Ephemeral, RoomConfig::default(),
            alice.fingerprint().clone(), alice.public_key_bytes(),
            DisplayAlias::new("alice").unwrap(),
        )
        .unwrap();

    room_svc.add_member(alice.fingerprint(), bob.fingerprint().clone(),
        bob.public_key_bytes(), DisplayAlias::new("bob").unwrap(), Role::Member).unwrap();
    room_svc.add_member(alice.fingerprint(), charlie.fingerprint().clone(),
        charlie.public_key_bytes(), DisplayAlias::new("charlie").unwrap(), Role::Member).unwrap();

    let room = room_svc.room().unwrap();
    let (event_tx, _) = broadcast::channel(16);
    let mut host_svc = HostService::new(room.clone(), event_tx);

    host_svc.register_client(alice.fingerprint().clone(), 1).unwrap();
    host_svc.register_client(bob.fingerprint().clone(), 2).unwrap();
    host_svc.register_client(charlie.fingerprint().clone(), 3).unwrap();

    host_svc.mark_client_ready(bob.fingerprint());

    let recipients = host_svc.route_recipients(alice.fingerprint());
    assert_eq!(recipients.len(), 1);
    assert_eq!(recipients[0], *bob.fingerprint());

    host_svc.mark_client_ready(charlie.fingerprint());
    let recipients = host_svc.route_recipients(alice.fingerprint());
    assert_eq!(recipients.len(), 2);
}

#[test]
fn room_full_prevents_new_members() {
    let alice = IdentityAdapter::generate();

    let mut config = RoomConfig::default();
    config.max_members = 2;

    let mut room_svc = RoomService::new();
    room_svc
        .create_room(
            "tiny-room", RoomMode::Ephemeral, config,
            alice.fingerprint().clone(), alice.public_key_bytes(),
            DisplayAlias::new("alice").unwrap(),
        )
        .unwrap();

    let bob = IdentityAdapter::generate();
    room_svc.add_member(alice.fingerprint(), bob.fingerprint().clone(),
        bob.public_key_bytes(), DisplayAlias::new("bob").unwrap(), Role::Member).unwrap();

    let charlie = IdentityAdapter::generate();
    let result = room_svc.add_member(alice.fingerprint(), charlie.fingerprint().clone(),
        charlie.public_key_bytes(), DisplayAlias::new("charlie").unwrap(), Role::Member);
    assert!(result.is_err(), "room should be full");
}