//! Sealed files (`SANCTUMS`): the encrypted container of the persistent mode.
//!
//! ```text
//! header (111 bytes, authenticated, never secret)
//!   "SANCTUMS" ‖ version u16 ‖ kind u8 ‖ memory_kib u32 ‖ iterations u32 ‖ lanes u32
//!   ‖ salt[16] ‖ wrap_nonce[24] ‖ wrapped_master[32 + 16]
//! body
//!   body_nonce[24] ‖ XChaCha20-Poly1305(K_kind, body_nonce, plaintext, AD = header)
//!
//! KEK            = Argon2id(passphrase, salt, memory_kib, iterations, lanes)
//! wrapped_master = XChaCha20-Poly1305(KEK, wrap_nonce, master, AD = header[..39])
//! K_kind         = HKDF-SHA256(salt = none, ikm = master, info = "SANCTUM-STORE-<kind>-v1")
//! ```
//! (integers big-endian; `header[..39]` is everything before `wrap_nonce`).
//!
//! The master key is random and only *wrapped* by the passphrase: unlocking
//! runs Argon2id once, after which every save reuses the header and draws a
//! fresh random body nonce (no counter to persist). Changing the passphrase
//! rewrites the header only ([`SealedHeader::rewrap`]). The Argon2id
//! parameters are bounded when parsing, so a crafted header cannot make the
//! host allocate gigabytes.

use sanctum_domain::SanctumError;
use zeroize::Zeroizing;

use crate::aead::{self, AeadCipher, TAG_LEN};
use crate::kdf;

/// File magic.
pub const SEALED_MAGIC: &[u8; 8] = b"SANCTUMS";
/// Format version.
pub const SEALED_VERSION: u16 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const WRAPPED_LEN: usize = 32 + TAG_LEN;
/// Bytes before `wrap_nonce`: magic, version, kind, the three parameters, salt.
const PREFIX_LEN: usize = 8 + 2 + 1 + 4 + 4 + 4 + SALT_LEN;
/// Header length.
pub const HEADER_LEN: usize = PREFIX_LEN + NONCE_LEN + WRAPPED_LEN;
/// Smallest possible sealed file (empty plaintext).
pub const MIN_FILE_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

/// Accepted Argon2id parameter ranges (also enforced on parsing).
pub const MIN_MEMORY_KIB: u32 = 8 * 1024;
/// 1 GiB.
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
/// At most 16 passes.
pub const MAX_ITERATIONS: u32 = 16;
/// At most 16 lanes.
pub const MAX_LANES: u32 = 16;

fn corrupted() -> SanctumError {
    SanctumError::StorageError("wrong passphrase or corrupted sealed file".into())
}

fn malformed(msg: &str) -> SanctumError {
    SanctumError::StorageError(format!("not a valid sealed file: {msg}"))
}

/// What a sealed file holds; each kind has its own body key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SealedKind {
    /// Host state: room, members, revocations, service keys.
    HostState = 1,
    /// Host backlog of pending envelopes (persistent mode, milestone B).
    Backlog = 2,
    /// Client state: X25519 keys, ratchet sessions, pinned peers.
    ClientState = 3,
}

impl SealedKind {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::HostState),
            2 => Some(Self::Backlog),
            3 => Some(Self::ClientState),
            _ => None,
        }
    }

    /// HKDF `info` for this kind's body key.
    fn info(self) -> &'static [u8] {
        match self {
            Self::HostState => b"SANCTUM-STORE-host-state-v1",
            Self::Backlog => b"SANCTUM-STORE-backlog-v1",
            Self::ClientState => b"SANCTUM-STORE-client-state-v1",
        }
    }
}

/// Argon2id parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism.
    pub lanes: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 4 lanes: the identity file's parameters.
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            lanes: 4,
        }
    }
}

impl KdfParams {
    fn check(self) -> Result<Self, SanctumError> {
        let ok = (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (1..=MAX_ITERATIONS).contains(&self.iterations)
            && (1..=MAX_LANES).contains(&self.lanes);
        if ok {
            Ok(self)
        } else {
            Err(malformed("Argon2id parameters out of bounds"))
        }
    }
}

/// The random key every sealed file of a store is encrypted under.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    /// A fresh random master key.
    pub fn generate() -> Self {
        Self(Zeroizing::new(aead::generate_key()))
    }

    fn body_key(&self, kind: SealedKind) -> Result<Zeroizing<Vec<u8>>, SanctumError> {
        Ok(Zeroizing::new(kdf::derive_subkey(
            self.0.as_slice(),
            &[],
            kind.info(),
            32,
        )?))
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(…)")
    }
}

/// The authenticated header of a sealed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedHeader {
    kind: SealedKind,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    wrap_nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_LEN],
}

impl SealedHeader {
    /// Wrap `master` under `passphrase` for a file of `kind` (runs Argon2id).
    pub fn new(
        master: &MasterKey,
        passphrase: &[u8],
        kind: SealedKind,
        params: KdfParams,
    ) -> Result<Self, SanctumError> {
        let mut salt = [0u8; SALT_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        Self::new_with(
            master,
            passphrase,
            kind,
            params,
            salt,
            aead::generate_xnonce(),
        )
    }

    pub(crate) fn new_with(
        master: &MasterKey,
        passphrase: &[u8],
        kind: SealedKind,
        params: KdfParams,
        salt: [u8; SALT_LEN],
        wrap_nonce: [u8; NONCE_LEN],
    ) -> Result<Self, SanctumError> {
        let params = params.check()?;
        let mut header = Self {
            kind,
            params,
            salt,
            wrap_nonce,
            wrapped: [0u8; WRAPPED_LEN],
        };
        let kek = header.kek(passphrase)?;
        let wrapped = aead::encrypt(
            AeadCipher::XChaCha20Poly1305,
            kek.as_slice(),
            &wrap_nonce,
            master.0.as_slice(),
            &header.prefix(),
        )?;
        header.wrapped.copy_from_slice(&wrapped);
        Ok(header)
    }

    /// Recover the master key (runs Argon2id).
    pub fn unlock(&self, passphrase: &[u8]) -> Result<MasterKey, SanctumError> {
        let kek = self.kek(passphrase)?;
        let master = Zeroizing::new(
            aead::decrypt(
                AeadCipher::XChaCha20Poly1305,
                kek.as_slice(),
                &self.wrap_nonce,
                &self.wrapped,
                &self.prefix(),
            )
            .map_err(|_| corrupted())?,
        );
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&master);
        Ok(MasterKey(key))
    }

    /// The same master key wrapped under a new passphrase (new salt and nonce).
    pub fn rewrap(&self, master: &MasterKey, new_passphrase: &[u8]) -> Result<Self, SanctumError> {
        Self::new(master, new_passphrase, self.kind, self.params)
    }

    /// What the file holds.
    pub fn kind(&self) -> SealedKind {
        self.kind
    }

    /// Argon2id parameters.
    pub fn params(&self) -> KdfParams {
        self.params
    }

    fn kek(&self, passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>, SanctumError> {
        Ok(Zeroizing::new(kdf::derive_argon2id(
            passphrase,
            &self.salt,
            self.params.memory_kib,
            self.params.iterations,
            self.params.lanes,
        )?))
    }

    fn prefix(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PREFIX_LEN);
        out.extend_from_slice(SEALED_MAGIC);
        out.extend_from_slice(&SEALED_VERSION.to_be_bytes());
        out.push(self.kind as u8);
        out.extend_from_slice(&self.params.memory_kib.to_be_bytes());
        out.extend_from_slice(&self.params.iterations.to_be_bytes());
        out.extend_from_slice(&self.params.lanes.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out
    }

    /// Serialized header.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.prefix();
        out.extend_from_slice(&self.wrap_nonce);
        out.extend_from_slice(&self.wrapped);
        out
    }

    /// Parse the header at the start of a sealed file.
    pub fn parse(file: &[u8]) -> Result<Self, SanctumError> {
        if file.len() < MIN_FILE_LEN {
            return Err(malformed("too short"));
        }
        if &file[..8] != SEALED_MAGIC {
            return Err(malformed("bad magic"));
        }
        let u32_at =
            |i: usize| u32::from_be_bytes([file[i], file[i + 1], file[i + 2], file[i + 3]]);
        if u16::from_be_bytes([file[8], file[9]]) != SEALED_VERSION {
            return Err(malformed("unsupported version"));
        }
        let kind = SealedKind::from_byte(file[10]).ok_or_else(|| malformed("unknown kind"))?;
        let params = KdfParams {
            memory_kib: u32_at(11),
            iterations: u32_at(15),
            lanes: u32_at(19),
        }
        .check()?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&file[23..PREFIX_LEN]);
        let mut wrap_nonce = [0u8; NONCE_LEN];
        wrap_nonce.copy_from_slice(&file[PREFIX_LEN..PREFIX_LEN + NONCE_LEN]);
        let mut wrapped = [0u8; WRAPPED_LEN];
        wrapped.copy_from_slice(&file[PREFIX_LEN + NONCE_LEN..HEADER_LEN]);
        Ok(Self {
            kind,
            params,
            salt,
            wrap_nonce,
            wrapped,
        })
    }
}

/// Encrypt `plaintext` into a complete sealed file.
pub fn seal(
    master: &MasterKey,
    header: &SealedHeader,
    plaintext: &[u8],
) -> Result<Vec<u8>, SanctumError> {
    seal_with_nonce(master, header, plaintext, aead::generate_xnonce())
}

pub(crate) fn seal_with_nonce(
    master: &MasterKey,
    header: &SealedHeader,
    plaintext: &[u8],
    body_nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, SanctumError> {
    let header_bytes = header.to_bytes();
    let key = master.body_key(header.kind)?;
    let ct = aead::encrypt(
        AeadCipher::XChaCha20Poly1305,
        key.as_slice(),
        &body_nonce,
        plaintext,
        &header_bytes,
    )?;
    let mut out = header_bytes;
    out.reserve(NONCE_LEN + ct.len());
    out.extend_from_slice(&body_nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a sealed file of the `expected` kind with an unlocked master key.
pub fn open(
    master: &MasterKey,
    file: &[u8],
    expected: SealedKind,
) -> Result<Zeroizing<Vec<u8>>, SanctumError> {
    let header = SealedHeader::parse(file)?;
    if header.kind != expected {
        return Err(malformed("unexpected kind"));
    }
    let key = master.body_key(header.kind)?;
    let body = &file[HEADER_LEN..];
    aead::decrypt(
        AeadCipher::XChaCha20Poly1305,
        key.as_slice(),
        &body[..NONCE_LEN],
        &body[NONCE_LEN..],
        &file[..HEADER_LEN],
    )
    .map(Zeroizing::new)
    .map_err(|_| corrupted())
}

/// Unlock a sealed file with its passphrase and decrypt it (runs Argon2id).
pub fn open_with_passphrase(
    file: &[u8],
    passphrase: &[u8],
    expected: SealedKind,
) -> Result<(SealedHeader, MasterKey, Zeroizing<Vec<u8>>), SanctumError> {
    let header = SealedHeader::parse(file)?;
    let master = header.unlock(passphrase)?;
    let plaintext = open(&master, file, expected)?;
    Ok((header, master, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters so the tests stay fast (the minimum accepted).
    const FAST: KdfParams = KdfParams {
        memory_kib: MIN_MEMORY_KIB,
        iterations: 1,
        lanes: 1,
    };

    fn sealed(plaintext: &[u8]) -> (MasterKey, SealedHeader, Vec<u8>) {
        let master = MasterKey::generate();
        let header =
            SealedHeader::new(&master, b"passphrase", SealedKind::HostState, FAST).unwrap();
        let file = seal(&master, &header, plaintext).unwrap();
        (master, header, file)
    }

    #[test]
    fn round_trip_with_the_passphrase_and_with_the_master_key() {
        let (master, header, file) = sealed(b"room state");
        assert_eq!(file.len(), MIN_FILE_LEN + 10);
        assert_eq!(SealedHeader::parse(&file).unwrap(), header);
        let (h, m, pt) = open_with_passphrase(&file, b"passphrase", SealedKind::HostState).unwrap();
        assert_eq!(pt.as_slice(), b"room state");
        assert_eq!(h, header);
        assert_eq!(
            open(&m, &file, SealedKind::HostState).unwrap().as_slice(),
            b"room state"
        );
        assert_eq!(
            open(&master, &file, SealedKind::HostState)
                .unwrap()
                .as_slice(),
            b"room state"
        );
    }

    #[test]
    fn plaintext_does_not_appear_and_each_seal_differs() {
        let marker = b"SANCTUM-PLAINTEXT-MARKER-0123456789";
        let (master, header, a) = sealed(marker);
        let b = seal(&master, &header, marker).unwrap();
        assert_ne!(a, b, "fresh body nonce every time");
        for file in [&a, &b] {
            assert!(!file.windows(marker.len()).any(|w| w == marker));
        }
    }

    #[test]
    fn wrong_passphrase_is_refused() {
        let (_, _, file) = sealed(b"x");
        let err = open_with_passphrase(&file, b"wrong", SealedKind::HostState).unwrap_err();
        assert!(err.to_string().contains("wrong passphrase"), "{err}");
    }

    #[test]
    fn every_flipped_bit_is_detected() {
        let (master, _, file) = sealed(b"members and revocations");
        for i in 0..file.len() {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            assert!(
                open(&master, &bad, SealedKind::HostState).is_err(),
                "byte {i} not authenticated"
            );
        }
    }

    #[test]
    fn a_tampered_wrapping_does_not_unlock() {
        let (_, _, file) = sealed(b"x");
        for i in [
            0usize,
            11,
            23,
            PREFIX_LEN,
            PREFIX_LEN + NONCE_LEN,
            HEADER_LEN - 1,
        ] {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            assert!(
                SealedHeader::parse(&bad)
                    .and_then(|h| h.unlock(b"passphrase"))
                    .is_err(),
                "byte {i}"
            );
        }
    }

    #[test]
    fn truncated_files_are_refused() {
        let (master, _, file) = sealed(b"abc");
        for len in [0, 8, HEADER_LEN, MIN_FILE_LEN - 1, file.len() - 1] {
            assert!(
                open(&master, &file[..len], SealedKind::HostState).is_err(),
                "{len}"
            );
        }
    }

    #[test]
    fn the_kind_is_checked_and_keys_differ_per_kind() {
        let master = MasterKey::generate();
        let header = SealedHeader::new(&master, b"p", SealedKind::ClientState, FAST).unwrap();
        let file = seal(&master, &header, b"sessions").unwrap();
        assert!(open(&master, &file, SealedKind::HostState).is_err());
        assert!(open(&master, &file, SealedKind::ClientState).is_ok());
        // Relabelling the kind byte breaks the authentication.
        let mut relabelled = file.clone();
        relabelled[10] = SealedKind::HostState as u8;
        assert!(open(&master, &relabelled, SealedKind::HostState).is_err());
    }

    #[test]
    fn out_of_bounds_parameters_are_refused_before_any_work() {
        let (_, _, file) = sealed(b"x");
        let patch = |offset: usize, value: u32| {
            let mut f = file.clone();
            f[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            f
        };
        for f in [
            patch(11, MAX_MEMORY_KIB + 1),
            patch(11, MIN_MEMORY_KIB - 1),
            patch(15, 0),
            patch(15, MAX_ITERATIONS + 1),
            patch(19, 0),
            patch(19, MAX_LANES + 1),
        ] {
            assert!(SealedHeader::parse(&f).is_err());
        }
        assert!(SealedHeader::new(
            &MasterKey::generate(),
            b"p",
            SealedKind::HostState,
            KdfParams {
                memory_kib: 4 * 1024 * 1024,
                ..FAST
            }
        )
        .is_err());
    }

    #[test]
    fn bad_magic_version_or_kind_is_refused() {
        let (_, _, file) = sealed(b"x");
        for (i, v) in [(0usize, b'X'), (9, 2), (10, 0), (10, 9)] {
            let mut bad = file.clone();
            bad[i] = v;
            assert!(SealedHeader::parse(&bad).is_err(), "byte {i}");
        }
    }

    #[test]
    fn rewrap_changes_the_passphrase_but_not_the_master_key() {
        let (master, header, file) = sealed(b"state");
        let new_header = header.rewrap(&master, b"new passphrase").unwrap();
        assert!(new_header.unlock(b"passphrase").is_err());
        let m2 = new_header.unlock(b"new passphrase").unwrap();
        assert_eq!(
            open(&m2, &file, SealedKind::HostState).unwrap().as_slice(),
            b"state"
        );
        let refreshed = seal(&m2, &new_header, b"state").unwrap();
        assert!(open_with_passphrase(&refreshed, b"passphrase", SealedKind::HostState).is_err());
        assert!(open_with_passphrase(&refreshed, b"new passphrase", SealedKind::HostState).is_ok());
    }

    #[test]
    fn master_key_debug_does_not_leak() {
        assert_eq!(
            format!("{:?}", MasterKey::from_bytes([7; 32])),
            "MasterKey(…)"
        );
    }
}
