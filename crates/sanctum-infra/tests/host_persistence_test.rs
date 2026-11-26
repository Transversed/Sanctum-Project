//! Persistent host: admissions and revocations are saved before they are
//! confirmed, and a failed save stops the host (fail-stop).

use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::host_state::{HostRoomState, HostStatePort};
use sanctum_infra::identity::IdentityAdapter;
use sanctum_infra::proto_codec::{self, pb, WireMessage};
use sanctum_infra::testkit::TestHost;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};

/// Records every saved state.
#[derive(Default)]
struct Recorder(Mutex<Vec<HostRoomState>>);

impl HostStatePort for Recorder {
    fn save(&self, state: &HostRoomState) -> Result<(), SanctumError> {
        self.0.lock().unwrap().push(state.clone());
        Ok(())
    }
}

impl Recorder {
    fn last(&self) -> HostRoomState {
        self.0.lock().unwrap().last().cloned().expect("a save")
    }
    fn count(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

/// Refuses every save (disk full, I/O error…).
struct Broken;

impl HostStatePort for Broken {
    fn save(&self, _: &HostRoomState) -> Result<(), SanctumError> {
        Err(SanctumError::StorageError("disk full".into()))
    }
}

fn revoke(fp: &str) -> sanctum_infra::codec::Frame {
    let msg = WireMessage::RoomControl(pb::RoomControl {
        action: Some(pb::room_control::Action::RevokeMember(pb::RevokeMember {
            fingerprint: fp.to_string(),
        })),
    });
    proto_codec::proto_encode(&msg).unwrap()
}

#[tokio::test]
async fn admissions_and_revocations_are_saved() {
    let store = Arc::new(Recorder::default());
    let host = TestHost::start_persistent(store.clone()).await;

    // The owner reconnecting is not a change: nothing to save.
    let mut owner = host.connect_owner().await;
    assert_eq!(store.count(), 0);

    let (alice, _alice_s) = host.join("alice").await;
    let saved = store.last();
    let member = saved
        .room
        .find_member(alice.fingerprint())
        .expect("alice saved");
    assert!(member.is_active());
    assert_eq!(member.identity_key(), alice.public_key_bytes().as_slice());
    assert_eq!(saved.used_invites.len(), 1, "her invitation is consumed");

    owner
        .transport
        .send_frame(&revoke(alice.fingerprint().as_str()))
        .await
        .unwrap();
    let mut saved = store.last();
    for _ in 0..40 {
        if !saved.revocations.is_empty() {
            break;
        }
        sleep(Duration::from_millis(50)).await;
        saved = store.last();
    }
    assert_eq!(saved.revocations.len(), 1);
    assert_eq!(&saved.revocations[0].0, alice.fingerprint());
    assert!(!saved
        .room
        .find_member(alice.fingerprint())
        .unwrap()
        .is_active());
    assert!(!host.is_stopped());
}

#[tokio::test]
async fn a_failed_save_refuses_the_admission_and_stops_the_host() {
    let host = TestHost::start_persistent(Arc::new(Broken)).await;
    let alice = IdentityAdapter::generate();
    let token = host.invite(alice.fingerprint());
    let err = host
        .connect(&alice, "alice", Some(&token))
        .await
        .err()
        .expect("admission refused");
    assert!(err.to_string().contains("disk full"), "{err}");
    assert!(host.is_stopped(), "the host must stop after a failed save");
}
