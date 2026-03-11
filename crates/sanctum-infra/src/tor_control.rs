//! Tor hidden service management via the Control Port protocol.
//!
//! Connects to the local Tor daemon's control port (default 9051),
//! authenticates via cookie file, and creates/destroys ephemeral
//! v3 onion hidden services using ADD_ONION / DEL_ONION.

use sanctum_domain::errors::SanctumError;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{info, warn};

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
    /// The service ID (for DEL_ONION). This is the onion address without ".onion".
    pub service_id: String,
}

/// Tor controller — manages connection to the Tor control port.
pub struct TorController {
    config: TorConfig,
    active_service: Option<HiddenService>,
    control_stream: Option<BufReader<TcpStream>>,
    mock: bool,
}

impl TorController {
    /// Create a new Tor controller.
    pub fn new(config: TorConfig) -> Self {
        Self {
            config,
            active_service: None,
            control_stream: None,
            mock: false,
        }
    }

    /// Create a mock controller (for testing without Tor).
    pub fn mock() -> Self {
        Self {
            config: TorConfig::default(),
            active_service: None,
            control_stream: None,
            mock: true,
        }
    }

    /// Check if Tor is available by connecting to the control port.
    pub async fn check_availability(&mut self) -> bool {
        if self.mock {
            return true;
        }
        match TcpStream::connect(&self.config.control_addr).await {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Connect and authenticate to the Tor control port.
    ///
    /// Tries cookie auth first, then falls back to no-auth.
    pub async fn connect(&mut self) -> Result<(), SanctumError> {
        if self.mock {
            info!("[tor] mock mode — skipping connect");
            return Ok(());
        }

        let stream = TcpStream::connect(&self.config.control_addr)
            .await
            .map_err(|e| SanctumError::TorUnavailable(
                format!("cannot connect to control port {}: {e}", self.config.control_addr),
            ))?;

        let mut reader = BufReader::new(stream);

        // Step 1: Send PROTOCOLINFO to get the cookie path
        write_cmd(&mut reader, "PROTOCOLINFO 1\r\n").await?;

        let mut cookie_path_from_tor: Option<String> = None;
        loop {
            let line = read_response(&mut reader).await?;
            // Parse: 250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/path/to/cookie"
            if line.contains("COOKIEFILE=") {
                if let Some(start) = line.find("COOKIEFILE=\"") {
                    let rest = &line[start + 12..];
                    if let Some(end) = rest.find('"') {
                        cookie_path_from_tor = Some(rest[..end].to_string());
                    }
                }
            }
            if line.starts_with("250 ") {
                break; // End of PROTOCOLINFO response
            }
            if line.starts_with("5") {
                return Err(SanctumError::TorUnavailable(
                    format!("PROTOCOLINFO failed: {line}"),
                ));
            }
        }

        // Step 2: Read cookie and authenticate
        let cookie_paths_to_try: Vec<String> = {
            let mut paths = Vec::new();
            if let Some(p) = cookie_path_from_tor {
                paths.push(p);
            }
            paths.push("/var/lib/tor/control_auth_cookie".into());
            paths.push("/var/run/tor/control.authcookie".into());
            paths.push("/usr/local/var/lib/tor/control_auth_cookie".into());
            paths
        };

        let mut authenticated = false;

        for cookie_path in &cookie_paths_to_try {
            eprintln!("[DEBUG] trying cookie: {cookie_path}");
            match tokio::fs::read(cookie_path).await {
                Ok(cookie) => {
                    eprintln!("[DEBUG] read {} bytes from {cookie_path}", cookie.len());
                    if cookie.len() != 32 {
                        eprintln!("[DEBUG] wrong length, skipping");
                        continue;
                    }
                    let hex_cookie = hex_encode(&cookie);
                    let cmd = format!("AUTHENTICATE {hex_cookie}\r\n");
                    eprintln!("[DEBUG] sending: AUTHENTICATE {}...", &hex_cookie[..16]);
                    write_cmd(&mut reader, &cmd).await?;
                    let response = read_response(&mut reader).await?;
                    eprintln!("[DEBUG] response: {response}");
                    if response.starts_with("250") {
                        info!("[tor] authenticated via cookie ({cookie_path})");
                        authenticated = true;
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("[DEBUG] cannot read {cookie_path}: {e}");
                }
            }
        }

        if !authenticated {
            write_cmd(&mut reader, "AUTHENTICATE\r\n").await?;
            let response = read_response(&mut reader).await?;
            if response.starts_with("250") {
                info!("[tor] authenticated (no password)");
                authenticated = true;
            }
        }

        if !authenticated {
            return Err(SanctumError::TorUnavailable(
                "could not authenticate to Tor control port".into(),
            ));
        }

        self.control_stream = Some(reader);
        Ok(())
    }

    /// Create a new ephemeral v3 hidden service.
    ///
    /// Sends ADD_ONION to Tor. The hidden service forwards
    /// `hidden_service_port` → `127.0.0.1:local_port`.
    pub async fn create_hidden_service(&mut self) -> Result<HiddenService, SanctumError> {
        if self.active_service.is_some() {
            return Err(SanctumError::TorUnavailable(
                "hidden service already active".into(),
            ));
        }

        if self.mock {
            let onion = generate_mock_onion();
            let service_id = onion.strip_suffix(".onion").unwrap().to_string();
            let hs = HiddenService {
                onion_address: onion,
                port: self.config.hidden_service_port,
                service_id,
            };
            self.active_service = Some(hs.clone());
            return Ok(hs);
        }

        let reader = self.control_stream.as_mut().ok_or_else(|| {
            SanctumError::TorUnavailable("not connected to control port".into())
        })?;

        // ADD_ONION NEW:ED25519-V3 Port=HS_PORT,127.0.0.1:LOCAL_PORT Flags=DiscardPK
        let cmd = format!(
            "ADD_ONION NEW:ED25519-V3 Port={},{} Flags=DiscardPK\r\n",
            self.config.hidden_service_port,
            format!("127.0.0.1:{}", self.config.local_port),
        );

        write_cmd(reader, &cmd).await?;

        // Response format:
        // 250-ServiceID=<base32 onion address without .onion>
        // 250 OK
        let mut service_id = String::new();
        loop {
            let line = read_response(reader).await?;
            if line.starts_with("250-ServiceID=") {
                service_id = line
                    .trim_start_matches("250-ServiceID=")
                    .trim()
                    .to_string();
            } else if line.starts_with("250 ") {
                break;
            } else if line.starts_with("5") {
                return Err(SanctumError::TorUnavailable(
                    format!("ADD_ONION failed: {line}"),
                ));
            }
        }

        if service_id.is_empty() {
            return Err(SanctumError::TorUnavailable(
                "ADD_ONION did not return a ServiceID".into(),
            ));
        }

        let onion_address = format!("{service_id}.onion");
        let hs = HiddenService {
            onion_address: onion_address.clone(),
            port: self.config.hidden_service_port,
            service_id: service_id.clone(),
        };

        info!("[tor] hidden service created: {onion_address}:{}", self.config.hidden_service_port);
        self.active_service = Some(hs.clone());
        Ok(hs)
    }

    /// Destroy the active hidden service.
    pub async fn destroy_hidden_service(&mut self) -> Result<(), SanctumError> {
        let hs = self.active_service.take().ok_or_else(|| {
            SanctumError::TorUnavailable("no active hidden service".into())
        })?;

        if self.mock {
            info!("[tor] mock: hidden service destroyed");
            return Ok(());
        }

        if let Some(reader) = self.control_stream.as_mut() {
            let cmd = format!("DEL_ONION {}\r\n", hs.service_id);
            write_cmd(reader, &cmd).await?;
            let response = read_response(reader).await?;
            if !response.starts_with("250") {
                warn!("[tor] DEL_ONION unexpected response: {response}");
            }
            info!("[tor] hidden service destroyed: {}", hs.onion_address);
        }

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

    /// Is this a mock controller?
    pub fn is_mock(&self) -> bool {
        self.mock
    }

    /// Set availability (for testing).
    pub fn set_available(&mut self, _available: bool) {
        // Kept for backward compat with existing tests
    }

    /// Check if Tor is available (backward compat).
    pub fn is_available(&self) -> bool {
        self.mock || self.control_stream.is_some()
    }
}

// ============================================================
// Helpers
// ============================================================

async fn write_cmd(
    reader: &mut BufReader<TcpStream>,
    cmd: &str,
) -> Result<(), SanctumError> {
    reader
        .get_mut()
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e| SanctumError::TorUnavailable(format!("control write: {e}")))?;
    reader
        .get_mut()
        .flush()
        .await
        .map_err(|e| SanctumError::TorUnavailable(format!("control flush: {e}")))?;
    Ok(())
}

async fn read_response(
    reader: &mut BufReader<TcpStream>,
) -> Result<String, SanctumError> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| SanctumError::TorUnavailable(format!("control read: {e}")))?;
    Ok(line.trim_end().to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Generate a mock v3 onion address for testing.
fn generate_mock_onion() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 35];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
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
    async fn mock_create_and_destroy() {
        let mut tor = TorController::mock();
        let hs = tor.create_hidden_service().await.unwrap();
        assert!(hs.onion_address.ends_with(".onion"));
        assert_eq!(hs.port, 9738);
        assert!(!hs.service_id.is_empty());
        assert!(tor.active_service().is_some());

        tor.destroy_hidden_service().await.unwrap();
        assert!(tor.active_service().is_none());
    }

    #[tokio::test]
    async fn mock_double_create_fails() {
        let mut tor = TorController::mock();
        tor.create_hidden_service().await.unwrap();
        assert!(tor.create_hidden_service().await.is_err());
    }

    #[tokio::test]
    async fn mock_destroy_without_create_fails() {
        let mut tor = TorController::mock();
        assert!(tor.destroy_hidden_service().await.is_err());
    }

    #[test]
    fn mock_onion_format() {
        let addr = generate_mock_onion();
        assert!(addr.ends_with(".onion"));
        let name = addr.strip_suffix(".onion").unwrap();
        assert_eq!(name.len(), 56);
    }
}