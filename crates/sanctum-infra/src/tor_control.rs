//! Tor hidden service management.
//!
//! Controls the creation and destruction of Tor v3 onion services.
//! Uses the Tor control port protocol.

use sanctum_domain::errors::SanctumError;

/// Tor configuration.
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// Tor SOCKS5 proxy address (default: 127.0.0.1:9050).
    pub socks_addr: String,
    /// Tor control port address (default: 127.0.0.1:9051).
    pub control_addr: String,
    /// Hidden service port to expose.
    pub hidden_service_port: u16,
    /// Local port to forward to.
    pub local_port: u16,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks_addr: "127.0.0.1:9050".into(),
            control_addr: "127.0.0.1:9051".into(),
            hidden_service_port: 9738,
            local_port: 9738,
        }
    }
}

/// Tor hidden service info.
#[derive(Debug, Clone)]
pub struct HiddenService {
    /// The .onion address (without port).
    pub onion_address: String,
    /// The exposed port.
    pub port: u16,
}

/// Tor controller.
///
/// In production, connects to Tor's control port via `torut`.
/// This implementation provides the interface with mock support.
pub struct TorController {
    config: TorConfig,
    active_service: Option<HiddenService>,
    available: bool,
}

impl TorController {
    /// Create a new Tor controller.
    pub fn new(config: TorConfig) -> Self {
        Self {
            config,
            active_service: None,
            available: false,
        }
    }

    /// Create a mock controller (for testing, always "available").
    pub fn mock() -> Self {
        Self {
            config: TorConfig::default(),
            active_service: None,
            available: true,
        }
    }

    /// Check if Tor is available.
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// Set availability (for testing).
    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    /// Create a new hidden service.
    ///
    /// In production, this sends ADD_ONION to the Tor control port.
    /// Returns the .onion address.
    pub async fn create_hidden_service(&mut self) -> Result<HiddenService, SanctumError> {
        if !self.available {
            return Err(SanctumError::TorUnavailable(
                "Tor is not available".into(),
            ));
        }

        if self.active_service.is_some() {
            return Err(SanctumError::TorUnavailable(
                "hidden service already active".into(),
            ));
        }

        // In production: connect to control port, send ADD_ONION
        // For now, generate a mock .onion address
        let onion = generate_mock_onion();
        let hs = HiddenService {
            onion_address: onion,
            port: self.config.hidden_service_port,
        };
        self.active_service = Some(hs.clone());
        Ok(hs)
    }

    /// Destroy the active hidden service.
    pub async fn destroy_hidden_service(&mut self) -> Result<(), SanctumError> {
        if self.active_service.is_none() {
            return Err(SanctumError::TorUnavailable(
                "no active hidden service".into(),
            ));
        }
        self.active_service = None;
        Ok(())
    }

    /// Get the active hidden service.
    pub fn active_service(&self) -> Option<&HiddenService> {
        self.active_service.as_ref()
    }

    /// Get the SOCKS5 proxy address for client connections.
    pub fn socks_addr(&self) -> &str {
        &self.config.socks_addr
    }
}

/// Generate a mock v3 onion address (56 chars base32 + ".onion").
fn generate_mock_onion() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 35]; // 35 bytes → 56 base32 chars
    rand::rngs::OsRng.fill_bytes(&mut bytes);

    // Simple base32-like encoding (lowercase a-z, 2-7)
    let chars: Vec<char> = bytes
        .iter()
        .flat_map(|b| {
            let hi = (b >> 4) & 0x0F;
            let lo = b & 0x0F;
            vec![
                if hi < 10 { (b'a' + hi) as char } else { (b'2' + hi - 10) as char },
                if lo < 10 { (b'a' + lo) as char } else { (b'2' + lo - 10) as char },
            ]
        })
        .take(56)
        .collect();

    format!("{}.onion", chars.iter().collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_and_destroy_hidden_service() {
        let mut tor = TorController::mock();
        let hs = tor.create_hidden_service().await.unwrap();
        assert!(hs.onion_address.ends_with(".onion"));
        assert_eq!(hs.port, 9738);
        assert!(tor.active_service().is_some());

        tor.destroy_hidden_service().await.unwrap();
        assert!(tor.active_service().is_none());
    }

    #[tokio::test]
    async fn create_fails_when_unavailable() {
        let mut tor = TorController::new(TorConfig::default());
        assert!(!tor.is_available());
        assert!(tor.create_hidden_service().await.is_err());
    }

    #[tokio::test]
    async fn create_fails_when_already_active() {
        let mut tor = TorController::mock();
        tor.create_hidden_service().await.unwrap();
        assert!(tor.create_hidden_service().await.is_err());
    }

    #[tokio::test]
    async fn destroy_fails_when_no_service() {
        let mut tor = TorController::mock();
        assert!(tor.destroy_hidden_service().await.is_err());
    }

    #[test]
    fn mock_onion_address_format() {
        let addr = generate_mock_onion();
        assert!(addr.ends_with(".onion"));
        let name = addr.strip_suffix(".onion").unwrap();
        assert_eq!(name.len(), 56);
    }
}