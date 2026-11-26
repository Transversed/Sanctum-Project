//! Persistent host store: the room's state in a sealed file (`SANCTUMS`,
//! kind host-state), one directory per room.
//!
//! ```text
//! <data_dir>/<room_id>/     0700
//!   state.sanctum           0600, sealed protobuf `HostStateV1`
//!   lock                    0600, empty: held (flock) while the host runs
//! ```
//!
//! What is stored: the room, its members (public keys only: the host never
//! holds the owner's private key), revocations, consumed invitations until
//! they expire, the Noise host key and the onion service key. Nothing about
//! connections, nonces or timing. Every save rewrites the whole file
//! atomically and durably ([`write_private_file`]).

use crate::identity::{create_private_dir, write_private_file};
use prost::Message;
use sanctum_crypto::sealed::{self, KdfParams, MasterKey, SealedHeader, SealedKind};
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Member, Role};
use sanctum_domain::entities::room::{Room, RoomConfig, RoomId, RoomMode};
use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::host_state::{HostRoomState, HostStatePort};
use std::fs::File;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Storage schema (`proto/sanctum_store.proto`).
pub mod store_pb {
    include!(concat!(env!("OUT_DIR"), "/sanctum.store.rs"));
}

/// File holding the sealed state.
pub const STATE_FILE: &str = "state.sanctum";
/// Lock file, held while a host serves the room.
pub const LOCK_FILE: &str = "lock";

fn err(msg: impl Into<String>) -> SanctumError {
    SanctumError::StorageError(msg.into())
}

fn corrupted(what: &str) -> SanctumError {
    err(format!("corrupted host state: {what}"))
}

/// Keys a persistent host needs at every start; they never change once the
/// room exists.
pub struct HostKeys {
    /// Noise NK static private key (invitations are bound to its public key).
    pub noise_private: Zeroizing<Vec<u8>>,
    /// Noise NK static public key.
    pub noise_public: Vec<u8>,
    /// Tor onion service key (`ED25519-V3:<base64>`); `None` for `--local` rooms.
    pub onion_key: Option<Zeroizing<String>>,
    /// Virtual port of the onion service.
    pub hidden_service_port: u16,
    /// Loopback port of the relay.
    pub local_port: u16,
}

impl std::fmt::Debug for HostKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostKeys")
            .field("onion_key", &self.onion_key.as_ref().map(|_| "…"))
            .field("hidden_service_port", &self.hidden_service_port)
            .field("local_port", &self.local_port)
            .finish_non_exhaustive()
    }
}

/// An unlocked room store. Holds the instance lock until dropped.
pub struct SealedHostStore {
    path: PathBuf,
    master: MasterKey,
    header: SealedHeader,
    keys: HostKeys,
    _lock: File,
}

impl std::fmt::Debug for SealedHostStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedHostStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Directory of the room `room_id` under `data_dir`.
pub fn room_dir(data_dir: &Path, room_id: &RoomId) -> PathBuf {
    data_dir.join(room_id.as_str())
}

/// Room ids that have a store under `data_dir` (sorted).
pub fn list_rooms(data_dir: &Path) -> Result<Vec<RoomId>, SanctumError> {
    let entries = match std::fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(err(format!("read {}: {e}", data_dir.display()))),
    };
    let mut ids: Vec<RoomId> = entries
        .filter_map(Result::ok)
        .filter(|e| e.path().join(STATE_FILE).is_file())
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    ids.sort_by_key(RoomId::as_str);
    Ok(ids)
}

/// Refuse a directory other users can read: the files are encrypted, but
/// their sizes and dates are metadata.
fn check_private_dir(dir: &Path) -> Result<(), SanctumError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir)
            .map_err(|e| err(format!("{}: {e}", dir.display())))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(err(format!(
                "{} is accessible to other users (mode {:o}): chmod 700 it",
                dir.display(),
                mode & 0o777
            )));
        }
    }
    Ok(())
}

/// Take the instance lock of a room directory.
fn lock(dir: &Path) -> Result<File, SanctumError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(dir.join(LOCK_FILE))
        .map_err(|e| err(format!("lock: {e}")))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            Err(err("this room is already being hosted by another process"))
        }
        Err(std::fs::TryLockError::Error(e)) => Err(err(format!("lock: {e}"))),
    }
}

impl SealedHostStore {
    /// Create the store of a new room under `data_dir` and write its
    /// initial state. Fails if the room already has a store.
    pub fn create(
        data_dir: &Path,
        passphrase: &[u8],
        params: KdfParams,
        keys: HostKeys,
        state: &HostRoomState,
    ) -> Result<Self, SanctumError> {
        create_private_dir(data_dir)?;
        check_private_dir(data_dir)?;
        let dir = room_dir(data_dir, state.room.id());
        if dir.join(STATE_FILE).exists() {
            return Err(err("this room already has a store"));
        }
        create_private_dir(&dir)?;
        check_private_dir(&dir)?;
        let lock = lock(&dir)?;
        let master = MasterKey::generate();
        let header = SealedHeader::new(&master, passphrase, SealedKind::HostState, params)?;
        let store = Self {
            path: dir.join(STATE_FILE),
            master,
            header,
            keys,
            _lock: lock,
        };
        store.save(state)?;
        Ok(store)
    }

    /// Unlock the store of `room_id` (runs Argon2id once).
    pub fn open(
        data_dir: &Path,
        room_id: &RoomId,
        passphrase: &[u8],
    ) -> Result<(Self, HostRoomState), SanctumError> {
        let dir = room_dir(data_dir, room_id);
        check_private_dir(&dir)?;
        let lock = lock(&dir)?;
        let path = dir.join(STATE_FILE);
        let file = std::fs::read(&path).map_err(|e| err(format!("read host state: {e}")))?;
        let (header, master, plaintext) =
            sealed::open_with_passphrase(&file, passphrase, SealedKind::HostState)?;
        let (keys, state) = decode(&plaintext)?;
        if state.room.id() != room_id {
            return Err(corrupted("room id mismatch"));
        }
        Ok((
            Self {
                path,
                master,
                header,
                keys,
                _lock: lock,
            },
            state,
        ))
    }

    /// The room's service keys.
    pub fn keys(&self) -> &HostKeys {
        &self.keys
    }
}

impl HostStatePort for SealedHostStore {
    fn save(&self, state: &HostRoomState) -> Result<(), SanctumError> {
        let plaintext = Zeroizing::new(encode(&self.keys, state).encode_to_vec());
        let file = sealed::seal(&self.master, &self.header, &plaintext)?;
        write_private_file(&self.path, &file)
    }
}

fn role_to_pb(role: Role) -> store_pb::StoredRole {
    match role {
        Role::Member => store_pb::StoredRole::Member,
        Role::Admin => store_pb::StoredRole::Admin,
        Role::Owner => store_pb::StoredRole::Owner,
    }
}

fn encode(keys: &HostKeys, state: &HostRoomState) -> store_pb::HostStateV1 {
    let room = &state.room;
    let config = room.config();
    store_pb::HostStateV1 {
        room_id: room.id().as_str(),
        room_name: room.name().to_string(),
        config: Some(store_pb::StoredRoomConfig {
            max_members: u32::from(config.max_members),
            backlog_max_messages: config.backlog_max_messages,
            backlog_max_age_hours: config.backlog_max_age_hours,
            message_padding_block: u32::from(config.message_padding_block),
        }),
        members: room
            .members()
            .iter()
            .map(|m| store_pb::StoredMember {
                fingerprint: m.fingerprint().as_str().to_string(),
                identity_key: m.identity_key().to_vec(),
                display_alias: m.display_alias().as_str().to_string(),
                role: role_to_pb(m.role()) as i32,
                joined_at: m.joined_at(),
                revoked: !m.is_active(),
            })
            .collect(),
        revocations: state
            .revocations
            .iter()
            .map(|(fp, t)| store_pb::StoredRevocation {
                fingerprint: fp.as_str().to_string(),
                revoked_at: *t,
            })
            .collect(),
        used_invites: state
            .used_invites
            .iter()
            .map(|(id, exp)| store_pb::StoredUsedInvite {
                invite_id: id.to_vec(),
                expires_at: *exp,
            })
            .collect(),
        noise_private_key: keys.noise_private.to_vec(),
        noise_public_key: keys.noise_public.clone(),
        onion_key: keys
            .onion_key
            .as_ref()
            .map(|k| k.to_string())
            .unwrap_or_default(),
        hidden_service_port: u32::from(keys.hidden_service_port),
        local_port: u32::from(keys.local_port),
    }
}

fn fingerprint(s: String) -> Result<Fingerprint, SanctumError> {
    Fingerprint::new(s).map_err(|_| corrupted("invalid fingerprint"))
}

fn port(v: u32) -> Result<u16, SanctumError> {
    u16::try_from(v).map_err(|_| corrupted("invalid port"))
}

fn decode(plaintext: &[u8]) -> Result<(HostKeys, HostRoomState), SanctumError> {
    // Secrets move out of the decoded message into `Zeroizing` buffers; the
    // decoded copies are wiped when the message is dropped.
    let mut s = store_pb::HostStateV1::decode(plaintext).map_err(|_| corrupted("undecodable"))?;
    let noise_private = Zeroizing::new(std::mem::take(&mut s.noise_private_key));
    let onion_key = Zeroizing::new(std::mem::take(&mut s.onion_key));
    if noise_private.len() != 32 || s.noise_public_key.len() != 32 {
        return Err(corrupted("invalid Noise key"));
    }
    let keys = HostKeys {
        noise_private,
        noise_public: std::mem::take(&mut s.noise_public_key),
        onion_key: (!onion_key.is_empty()).then_some(onion_key),
        hidden_service_port: port(s.hidden_service_port)?,
        local_port: port(s.local_port)?,
    };

    let c = s.config.take().ok_or_else(|| corrupted("no room config"))?;
    let mut config = RoomConfig {
        max_members: u16::try_from(c.max_members).map_err(|_| corrupted("max_members"))?,
        backlog_max_messages: c.backlog_max_messages,
        backlog_max_age_hours: c.backlog_max_age_hours,
        message_padding_block: u16::try_from(c.message_padding_block)
            .map_err(|_| corrupted("padding block"))?,
    };
    config.validate();
    let mut members = Vec::with_capacity(s.members.len());
    for m in s.members {
        let role = match store_pb::StoredRole::try_from(m.role) {
            Ok(store_pb::StoredRole::Member) => Role::Member,
            Ok(store_pb::StoredRole::Admin) => Role::Admin,
            Ok(store_pb::StoredRole::Owner) => Role::Owner,
            Err(_) => return Err(corrupted("unknown role")),
        };
        let alias = DisplayAlias::new(m.display_alias).map_err(|_| corrupted("invalid alias"))?;
        let mut member = Member::new(
            fingerprint(m.fingerprint)?,
            m.identity_key,
            alias,
            role,
            m.joined_at,
        );
        if m.revoked {
            member.revoke();
        }
        members.push(member);
    }
    let owners = members
        .iter()
        .filter(|m| m.role() == Role::Owner && m.is_active())
        .count();
    if owners != 1 {
        return Err(corrupted("the room must have exactly one active owner"));
    }
    let room_id: RoomId = s
        .room_id
        .parse()
        .map_err(|_| corrupted("invalid room id"))?;
    let room = Room::with_id(room_id, s.room_name, RoomMode::Persistent, config, members);

    let revocations = s
        .revocations
        .into_iter()
        .map(|r| Ok((fingerprint(r.fingerprint)?, r.revoked_at)))
        .collect::<Result<Vec<_>, SanctumError>>()?;
    let used_invites = s
        .used_invites
        .into_iter()
        .map(|u| {
            let id: [u8; 32] = u
                .invite_id
                .try_into()
                .map_err(|_| corrupted("invalid invitation id"))?;
            Ok((id, u.expires_at))
        })
        .collect::<Result<Vec<_>, SanctumError>>()?;
    Ok((
        keys,
        HostRoomState {
            room,
            revocations,
            used_invites,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAdapter;

    const FAST: KdfParams = KdfParams {
        memory_kib: sealed::MIN_MEMORY_KIB,
        iterations: 1,
        lanes: 1,
    };

    fn data_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        d
    }

    fn keys() -> HostKeys {
        HostKeys {
            noise_private: Zeroizing::new(vec![0x11; 32]),
            noise_public: vec![0x22; 32],
            onion_key: Some(Zeroizing::new("ED25519-V3:c2VjcmV0LW9uaW9uLWtleQ==".into())),
            hidden_service_port: 9738,
            local_port: 41000,
        }
    }

    fn state(name: &str) -> (HostRoomState, IdentityAdapter) {
        let owner = IdentityAdapter::generate();
        let alice = IdentityAdapter::generate();
        let bob = IdentityAdapter::generate();
        let member = |id: &IdentityAdapter, alias: &str, role| {
            Member::new(
                id.fingerprint().clone(),
                id.public_key_bytes(),
                DisplayAlias::new(alias).unwrap(),
                role,
                1_700_000_000,
            )
        };
        let mut revoked = member(&bob, "bob", Role::Member);
        revoked.revoke();
        let room = Room::with_id(
            RoomId::new(),
            name,
            RoomMode::Persistent,
            RoomConfig::default(),
            vec![
                member(&owner, "owner", Role::Owner),
                member(&alice, "alice", Role::Member),
                revoked,
            ],
        );
        (
            HostRoomState {
                room,
                revocations: vec![(bob.fingerprint().clone(), 1_700_000_500)],
                used_invites: vec![([9u8; 32], 1_800_000_000)],
            },
            owner,
        )
    }

    #[test]
    fn create_then_reopen_gives_back_the_same_state_and_keys() {
        let dir = data_dir();
        let (st, _) = state("ops-room");
        let store =
            SealedHostStore::create(dir.path(), b"host passphrase", FAST, keys(), &st).unwrap();
        drop(store); // releases the lock
        let (store, back) =
            SealedHostStore::open(dir.path(), st.room.id(), b"host passphrase").unwrap();
        assert_eq!(back.room.id(), st.room.id());
        assert_eq!(back.room.name(), "ops-room");
        assert_eq!(back.room.mode(), RoomMode::Persistent);
        assert_eq!(back.room.members().len(), 3);
        for (a, b) in back.room.members().iter().zip(st.room.members()) {
            assert_eq!(a.fingerprint(), b.fingerprint());
            assert_eq!(a.identity_key(), b.identity_key());
            assert_eq!(a.role(), b.role());
            assert_eq!(a.is_active(), b.is_active());
            assert_eq!(a.joined_at(), b.joined_at());
        }
        assert_eq!(back.revocations, st.revocations);
        assert_eq!(back.used_invites, st.used_invites);
        let k = store.keys();
        assert_eq!(k.noise_private.as_slice(), &[0x11; 32]);
        assert_eq!(k.noise_public, vec![0x22; 32]);
        assert_eq!(
            k.onion_key.as_deref().map(String::as_str),
            Some("ED25519-V3:c2VjcmV0LW9uaW9uLWtleQ==")
        );
        assert_eq!((k.hidden_service_port, k.local_port), (9738, 41000));
        assert_eq!(list_rooms(dir.path()).unwrap(), vec![st.room.id().clone()]);
    }

    #[test]
    fn saves_replace_the_state() {
        let dir = data_dir();
        let (mut st, _) = state("r");
        let store = SealedHostStore::create(dir.path(), b"p4ssphrase", FAST, keys(), &st).unwrap();
        st.used_invites.clear();
        st.revocations
            .push((st.room.members()[1].fingerprint().clone(), 42));
        store.save(&st).unwrap();
        drop(store);
        let (_, back) = SealedHostStore::open(dir.path(), st.room.id(), b"p4ssphrase").unwrap();
        assert!(back.used_invites.is_empty());
        assert_eq!(back.revocations.len(), 2);
    }

    #[test]
    fn nothing_is_stored_in_clear() {
        let dir = data_dir();
        let (st, owner) = state("room-name-marker-0123456789");
        let _store = SealedHostStore::create(dir.path(), b"p4ssphrase", FAST, keys(), &st).unwrap();
        let file = std::fs::read(room_dir(dir.path(), st.room.id()).join(STATE_FILE)).unwrap();
        let needles: Vec<Vec<u8>> = vec![
            b"room-name-marker-0123456789".to_vec(),
            owner.fingerprint().as_str().as_bytes().to_vec(),
            owner.public_key_bytes(),
            b"alice".to_vec(),
            vec![0x11; 32],
            b"ED25519-V3".to_vec(),
        ];
        for n in needles {
            assert!(
                !file.windows(n.len()).any(|w| w == n.as_slice()),
                "{n:?} in clear"
            );
        }
    }

    #[test]
    fn wrong_passphrase_and_second_instance_are_refused() {
        let dir = data_dir();
        let (st, _) = state("r");
        let store =
            SealedHostStore::create(dir.path(), b"right passphrase", FAST, keys(), &st).unwrap();
        let busy =
            SealedHostStore::open(dir.path(), st.room.id(), b"right passphrase").unwrap_err();
        assert!(busy.to_string().contains("already being hosted"), "{busy}");
        drop(store);
        let wrong =
            SealedHostStore::open(dir.path(), st.room.id(), b"wrong passphrase").unwrap_err();
        assert!(wrong.to_string().contains("wrong passphrase"), "{wrong}");
        assert!(SealedHostStore::open(dir.path(), st.room.id(), b"right passphrase").is_ok());
    }

    #[test]
    fn a_room_cannot_be_created_twice_and_files_are_private() {
        let dir = data_dir();
        let (st, _) = state("r");
        let store = SealedHostStore::create(dir.path(), b"p4ssphrase", FAST, keys(), &st).unwrap();
        drop(store);
        assert!(SealedHostStore::create(dir.path(), b"p4ssphrase", FAST, keys(), &st).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let rd = room_dir(dir.path(), st.room.id());
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&rd), 0o700);
            assert_eq!(mode(&rd.join(STATE_FILE)), 0o600);
            assert_eq!(mode(&rd.join(LOCK_FILE)), 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_data_dir_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = data_dir();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let (st, _) = state("r");
        let e = SealedHostStore::create(dir.path(), b"p4ssphrase", FAST, keys(), &st).unwrap_err();
        assert!(e.to_string().contains("chmod 700"), "{e}");
    }

    #[test]
    fn a_state_without_exactly_one_owner_is_refused() {
        let (mut st, _) = state("r");
        let members: Vec<Member> = st
            .room
            .members()
            .iter()
            .filter(|m| m.role() != Role::Owner)
            .cloned()
            .collect();
        st.room = Room::with_id(
            st.room.id().clone(),
            "r",
            RoomMode::Persistent,
            RoomConfig::default(),
            members,
        );
        let bytes = encode(&keys(), &st).encode_to_vec();
        assert!(decode(&bytes).unwrap_err().to_string().contains("owner"));
    }
}
