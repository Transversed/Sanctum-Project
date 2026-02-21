//! Tor hidden service port.

use crate::errors::SanctumError;

/// Hidden service configuration.
pub struct HiddenServiceConfig {
    /// Local listen port.
    pub local_port: u16,
    /// Port exposed on .onion.
    pub onion_port: u16,
    /// Transient HS (no key on disk) = ephemeral mode.
    pub transient: bool,
}

/// Tor port.
pub trait TorPort: Send + Sync {
    /// Create a hidden service, return .onion address.
    fn create_hidden_service(
        &self,
        config: &HiddenServiceConfig,
    ) -> impl std::future::Future<Output = Result<String, SanctumError>> + Send;

    /// Destroy a hidden service.
    fn destroy_hidden_service(
        &self,
        onion_address: &str,
    ) -> impl std::future::Future<Output = Result<(), SanctumError>> + Send;

    /// Check if Tor is connected.
    fn check_connectivity(
        &self,
    ) -> impl std::future::Future<Output = Result<bool, SanctumError>> + Send;
}