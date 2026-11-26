//! Ed25519 identity adapter.
//!
//! The fingerprint is `SHA-256("sanctum-fingerprint-v1:" ‖ pk)[..20]`, as
//! 40 uppercase hex characters.
//!
//! On disk (`~/.sanctum/keys/`):
//! - `identity.key`: the 32-byte secret, **encrypted** with a key derived
//!   from the user's passphrase (Argon2id, 64 MiB, 3 passes) and sealed with
//!   ChaCha20-Poly1305. Layout:
//!   `"SANCTUMK" ‖ version (1) ‖ salt (32) ‖ nonce (12) ‖ ciphertext (48)`;
//!   the 9-byte header is authenticated as associated data.
//! - `identity.pub`, `identity.fingerprint`: public, in clear.
//!
//! Private files are created with mode 0600 from the start (no window
//! between creation and `chmod`) and replaced atomically through a rename.

use sanctum_crypto::aead::{self, AeadCipher};
use sanctum_crypto::kdf;
use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::identity::{SignatureVerifier, Signer as SignerPort};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const KEY_DIR: &str = "keys";
const PRIV_KEY_FILE: &str = "identity.key";
const PUB_KEY_FILE: &str = "identity.pub";
const FP_FILE: &str = "identity.fingerprint";

/// Magic bytes of an encrypted identity file.
pub const KEY_FILE_MAGIC: &[u8; 8] = b"SANCTUMK";
/// Current encrypted identity file version.
pub const KEY_FILE_VERSION: u8 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = KEY_FILE_MAGIC.len() + 1;
const KEY_FILE_LEN: usize = HEADER_LEN + SALT_LEN + NONCE_LEN + 32 + 16;

fn storage(msg: impl Into<String>) -> SanctumError {
    SanctumError::StorageError(msg.into())
}

/// Seal a 32-byte secret key with a passphrase.
pub fn encrypt_secret_key(secret: &[u8; 32], passphrase: &[u8]) -> Result<Vec<u8>, SanctumError> {
    if passphrase.is_empty() {
        return Err(storage(
            "a passphrase is required to protect the identity key",
        ));
    }
    let salt = kdf::generate_salt();
    let nonce = aead::generate_nonce();
    let key = Zeroizing::new(kdf::derive_master_key(passphrase, &salt)?);
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(KEY_FILE_MAGIC);
    header.push(KEY_FILE_VERSION);
    let ct = aead::encrypt(
        AeadCipher::ChaCha20Poly1305,
        key.as_ref(),
        &nonce,
        secret,
        &header,
    )?;

    let mut out = header;
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open an encrypted identity file. A wrong passphrase and a corrupted file
/// are indistinguishable (authentication failure).
pub fn decrypt_secret_key(
    blob: &[u8],
    passphrase: &[u8],
) -> Result<Zeroizing<[u8; 32]>, SanctumError> {
    if blob.len() != KEY_FILE_LEN || &blob[..KEY_FILE_MAGIC.len()] != KEY_FILE_MAGIC {
        return Err(storage("not an encrypted Sanctum identity file"));
    }
    if blob[KEY_FILE_MAGIC.len()] != KEY_FILE_VERSION {
        return Err(storage("unsupported identity file version"));
    }
    let (header, rest) = blob.split_at(HEADER_LEN);
    let (salt, rest) = rest.split_at(SALT_LEN);
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let key = Zeroizing::new(kdf::derive_master_key(passphrase, salt)?);
    let pt = Zeroizing::new(
        aead::decrypt(
            AeadCipher::ChaCha20Poly1305,
            key.as_ref(),
            nonce,
            ct,
            header,
        )
        .map_err(|_| storage("wrong passphrase or corrupted identity file"))?,
    );
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&pt);
    Ok(secret)
}

/// Write `bytes` to `path` atomically, readable by the owner only.
///
/// The temporary file is created with mode 0600 and `O_EXCL`, synced, then
/// renamed over `path`, and the directory is synced so that the rename
/// survives a crash.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SanctumError> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| storage("private file has no parent directory"))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| storage("invalid private file name"))?;
    let mut suffix = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut suffix);
    let tmp = dir.join(format!(
        ".{name}.tmp-{}",
        suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        // Make the rename itself durable.
        #[cfg(unix)]
        std::fs::File::open(dir)?.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|e| storage(format!("write {}: {e}", path.display())))
}

/// Create `dir` (and parents) with mode 0700 on Unix.
pub fn create_private_dir(dir: &Path) -> Result<(), SanctumError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| storage(format!("create {}: {e}", dir.display())))
}

/// Ed25519 identity for signing and verification.
pub struct IdentityAdapter {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    fingerprint: Fingerprint,
}

impl IdentityAdapter {
    /// Generate a new random Ed25519 identity.
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::generate(&mut rand::rngs::OsRng))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let fingerprint = derive_fingerprint(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            fingerprint,
        }
    }

    /// Create from a raw 32-byte secret key.
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        Self::from_signing_key(SigningKey::from_bytes(secret))
    }

    /// Default key directory: `~/.sanctum/keys`.
    pub fn default_dir() -> PathBuf {
        sanctum_home().join(KEY_DIR)
    }

    /// Load and decrypt the identity from the default directory.
    pub fn load_from_disk(passphrase: &[u8]) -> Result<Self, SanctumError> {
        Self::load_from(&Self::default_dir(), passphrase)
    }

    /// Load and decrypt the identity from `dir`.
    pub fn load_from(dir: &Path, passphrase: &[u8]) -> Result<Self, SanctumError> {
        let path = dir.join(PRIV_KEY_FILE);
        let blob = Zeroizing::new(std::fs::read(&path).map_err(|e| {
            storage(format!(
                "cannot read identity key at {}: {e}\nRun `sanctum init` first.",
                path.display()
            ))
        })?);
        if blob.len() == 32 {
            return Err(storage(
                "this identity key is stored unencrypted (created by an older version).\n\
                 Run `sanctum identity protect` to encrypt it with a passphrase.",
            ));
        }
        let secret = decrypt_secret_key(&blob, passphrase)?;
        Ok(Self::from_secret(&secret))
    }

    /// Load a legacy, unencrypted 32-byte key from `dir` (migration only).
    pub fn load_legacy_from(dir: &Path) -> Result<Self, SanctumError> {
        let blob = Zeroizing::new(
            std::fs::read(dir.join(PRIV_KEY_FILE)).map_err(|e| storage(e.to_string()))?,
        );
        let secret: Zeroizing<[u8; 32]> = Zeroizing::new(
            blob.as_slice()
                .try_into()
                .map_err(|_| storage("not a legacy (unencrypted) identity key"))?,
        );
        Ok(Self::from_secret(&secret))
    }

    /// Encrypt and save the identity to the default directory.
    pub fn save_to_disk(&self, passphrase: &[u8]) -> Result<(), SanctumError> {
        self.save_to(&Self::default_dir(), passphrase)
    }

    /// Encrypt and save the identity to `dir` (created with mode 0700).
    pub fn save_to(&self, dir: &Path, passphrase: &[u8]) -> Result<(), SanctumError> {
        create_private_dir(dir)?;
        let secret = Zeroizing::new(self.signing_key.to_bytes());
        let blob = encrypt_secret_key(&secret, passphrase)?;
        write_private_file(&dir.join(PRIV_KEY_FILE), &blob)?;
        write_private_file(&dir.join(PUB_KEY_FILE), &self.verifying_key.to_bytes())?;
        write_private_file(&dir.join(FP_FILE), self.fingerprint.as_str().as_bytes())?;
        Ok(())
    }

    /// Fingerprint of the identity in `dir`, from the public file only.
    pub fn public_fingerprint_in(dir: &Path) -> Result<Fingerprint, SanctumError> {
        fingerprint_of_public_key(&Self::public_key_in(dir)?)
    }

    /// Public key stored in `dir` (no passphrase needed).
    pub fn public_key_in(dir: &Path) -> Result<Vec<u8>, SanctumError> {
        let pk = std::fs::read(dir.join(PUB_KEY_FILE)).map_err(|e| storage(e.to_string()))?;
        fingerprint_of_public_key(&pk)?;
        Ok(pk)
    }

    /// Our fingerprint.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Public key bytes (32 bytes Ed25519).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
}

/// Fingerprint of raw Ed25519 public key bytes (rejects invalid keys).
pub fn fingerprint_of_public_key(public_key: &[u8]) -> Result<Fingerprint, SanctumError> {
    let bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SanctumError::InvalidSignature)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| SanctumError::InvalidSignature)?;
    if key.is_weak() {
        return Err(SanctumError::InvalidSignature);
    }
    Ok(derive_fingerprint(&key))
}

/// Stateless Ed25519 verifier (strict verification).
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Verifier;

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(pk) = <[u8; 32]>::try_from(public_key) else {
            return false;
        };
        let Ok(sig) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        let Ok(key) = VerifyingKey::from_bytes(&pk) else {
            return false;
        };
        key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig))
            .is_ok()
    }

    fn fingerprint(&self, public_key: &[u8]) -> Result<Fingerprint, SanctumError> {
        fingerprint_of_public_key(public_key)
    }
}

impl SignerPort for IdentityAdapter {
    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }

    fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }
}

/// Also usable through the concrete type.
impl IdentityAdapter {
    /// Sign `message` (64-byte Ed25519 signature).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        SignerPort::sign(self, message)
    }

    /// Verify with the local key (tests, self-checks).
    pub fn verify_own(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(sig) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        self.verifying_key
            .verify(message, &ed25519_dalek::Signature::from_bytes(&sig))
            .is_ok()
    }
}

/// Derive a 40-char hex fingerprint from an Ed25519 public key.
fn derive_fingerprint(verifying_key: &VerifyingKey) -> Fingerprint {
    let mut hasher = Sha256::new();
    hasher.update(b"sanctum-fingerprint-v1:");
    hasher.update(verifying_key.as_bytes());
    let hash = hasher.finalize();
    let hex: String = hash[..20].iter().map(|b| format!("{b:02X}")).collect();
    // 40 uppercase hex characters always form a valid fingerprint.
    Fingerprint::new(hex).unwrap_or_else(|_| unreachable!("40 hex chars"))
}

/// Get the sanctum home directory.
/// `~/.sanctum`: identity, configuration and (persistent mode) host stores.
pub fn sanctum_home() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sanctum")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut r = [0u8; 6];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut r);
        let d = std::env::temp_dir().join(format!(
            "sanctum-id-{tag}-{}",
            r.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        d
    }

    #[test]
    fn generate_and_fingerprint() {
        let id = IdentityAdapter::generate();
        assert_eq!(id.fingerprint().as_str().len(), 40);
        assert_eq!(id.public_key_bytes().len(), 32);
    }

    #[test]
    fn sign_verify_round_trip() {
        let alice = IdentityAdapter::generate();
        let sig = alice.sign(b"challenge data");
        assert_eq!(sig.len(), 64);
        assert!(Ed25519Verifier.verify(&alice.public_key_bytes(), b"challenge data", &sig));
        assert!(alice.verify_own(b"challenge data", &sig));
        assert!(!Ed25519Verifier.verify(&alice.public_key_bytes(), b"fake data", &sig));
        let bob = IdentityAdapter::generate();
        assert!(!Ed25519Verifier.verify(&bob.public_key_bytes(), b"challenge data", &sig));
    }

    #[test]
    fn verifier_rejects_malformed_inputs() {
        let alice = IdentityAdapter::generate();
        let sig = alice.sign(b"msg");
        let v = Ed25519Verifier;
        assert!(!v.verify(&alice.public_key_bytes()[..31], b"msg", &sig));
        assert!(!v.verify(&alice.public_key_bytes(), b"msg", &sig[..63]));
        assert!(!v.verify(&[0u8; 32], b"msg", &[0u8; 64]));
    }

    #[test]
    fn fingerprint_is_derived_from_the_key() {
        let alice = IdentityAdapter::generate();
        let fp = Ed25519Verifier
            .fingerprint(&alice.public_key_bytes())
            .unwrap();
        assert_eq!(&fp, alice.fingerprint());
        assert!(Ed25519Verifier.fingerprint(&[1u8; 31]).is_err());
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;
        assert!(Ed25519Verifier.fingerprint(&identity_point).is_err());
    }

    // P5.1: the private key file never contains the key in clear.
    #[test]
    fn saved_key_is_encrypted_private_and_reloadable() {
        let dir = tmp_dir("save");
        let id = IdentityAdapter::generate();
        id.save_to(&dir, b"correct horse battery").unwrap();

        let blob = std::fs::read(dir.join(PRIV_KEY_FILE)).unwrap();
        assert!(blob.starts_with(KEY_FILE_MAGIC));
        let secret = id.signing_key.to_bytes();
        assert!(
            !blob.windows(32).any(|w| w == secret),
            "secret key stored in clear"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir.join(PRIV_KEY_FILE)), 0o600);
            assert_eq!(mode(&dir), 0o700);
        }

        let loaded = IdentityAdapter::load_from(&dir, b"correct horse battery").unwrap();
        assert_eq!(loaded.fingerprint(), id.fingerprint());
        assert_eq!(
            IdentityAdapter::public_fingerprint_in(&dir).unwrap(),
            *id.fingerprint()
        );
        assert!(IdentityAdapter::load_from(&dir, b"wrong passphrase").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_key_file_is_rejected() {
        let id = IdentityAdapter::generate();
        let mut blob = encrypt_secret_key(&id.signing_key.to_bytes(), b"pw-pw-pw-pw").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(decrypt_secret_key(&blob, b"pw-pw-pw-pw").is_err());
        let mut header = encrypt_secret_key(&id.signing_key.to_bytes(), b"pw-pw-pw-pw").unwrap();
        header[8] = 2; // version
        assert!(decrypt_secret_key(&header, b"pw-pw-pw-pw").is_err());
    }

    #[test]
    fn empty_passphrase_is_refused() {
        assert!(encrypt_secret_key(&[1u8; 32], b"").is_err());
    }

    #[test]
    fn legacy_plaintext_key_is_detected_and_migratable() {
        let dir = tmp_dir("legacy");
        create_private_dir(&dir).unwrap();
        let id = IdentityAdapter::generate();
        write_private_file(&dir.join(PRIV_KEY_FILE), &id.signing_key.to_bytes()).unwrap();
        let err = IdentityAdapter::load_from(&dir, b"whatever").err().unwrap();
        assert!(err.to_string().contains("identity protect"));
        let legacy = IdentityAdapter::load_legacy_from(&dir).unwrap();
        assert_eq!(legacy.fingerprint(), id.fingerprint());
        legacy.save_to(&dir, b"new passphrase").unwrap();
        assert!(IdentityAdapter::load_from(&dir, b"new passphrase").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp_file() {
        let dir = tmp_dir("atomic");
        create_private_dir(&dir).unwrap();
        let p = dir.join("f");
        write_private_file(&p, b"one").unwrap();
        write_private_file(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
