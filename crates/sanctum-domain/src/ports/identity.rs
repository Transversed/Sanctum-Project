//! PGP identity port (sign, verify, import).

use crate::entities::member::Fingerprint;
use crate::errors::SanctumError;

/// PGP identity port.
pub trait IdentityPort: Send + Sync {
    /// Sign data with local PGP key. Returns detached signature.
    fn sign(&self, data: &[u8])
        -> impl std::future::Future<Output = Result<Vec<u8>, SanctumError>> + Send;

    /// Verify a PGP signature.
    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        signer_key: &[u8],
    ) -> impl std::future::Future<Output = Result<bool, SanctumError>> + Send;

    /// Local PGP fingerprint.
    fn local_fingerprint(
        &self,
    ) -> impl std::future::Future<Output = Result<Fingerprint, SanctumError>> + Send;

    /// Local PGP public key bytes.
    fn local_public_key(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, SanctumError>> + Send;

    /// Import a peer's PGP public key.
    fn import_public_key(
        &self,
        key_data: &[u8],
    ) -> impl std::future::Future<Output = Result<Fingerprint, SanctumError>> + Send;
}