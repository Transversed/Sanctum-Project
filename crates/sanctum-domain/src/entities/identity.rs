//! Public cryptographic identity and PreKey Bundle.
//! Private keys NEVER live in domain entities.

use serde::{Deserialize, Serialize};

use super::member::Fingerprint;

/// X3DH PreKey Bundle — public keys only, safe to store on host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// Identity key (IK) — long-term.
    pub identity_key: Vec<u8>,
    /// Signed pre-key (SPK) — rotated every 24-48h.
    pub signed_prekey: Vec<u8>,
    /// SPK signature by IK.
    pub signed_prekey_signature: Vec<u8>,
    /// SPK identifier.
    pub signed_prekey_id: u32,
    /// One-time pre-key (OPK) — single use, optional.
    pub one_time_prekey: Option<Vec<u8>>,
    /// OPK identifier.
    pub one_time_prekey_id: Option<u32>,
}

/// Public identity combining PGP (auth) and X25519 (encryption).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    fingerprint: Fingerprint,
    pgp_public_key: Vec<u8>,
    bundle: PreKeyBundle,
}

impl Identity {
    /// Create a new public identity.
    pub fn new(fingerprint: Fingerprint, pgp_public_key: Vec<u8>, bundle: PreKeyBundle) -> Self {
        Self {
            fingerprint,
            pgp_public_key,
            bundle,
        }
    }

    /// PGP fingerprint.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// PGP public key.
    pub fn pgp_public_key(&self) -> &[u8] {
        &self.pgp_public_key
    }

    /// PreKey Bundle.
    pub fn bundle(&self) -> &PreKeyBundle {
        &self.bundle
    }

    /// Update the bundle (SPK rotation, OPK refresh).
    pub fn update_bundle(&mut self, bundle: PreKeyBundle) {
        self.bundle = bundle;
    }
}