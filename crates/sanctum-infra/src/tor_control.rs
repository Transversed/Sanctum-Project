//! Tor hidden service management via the Control Port protocol.
//!
//! Connects to the local Tor daemon's control port (default 9051),
//! authenticates via cookie file, and creates/destroys ephemeral
//! v3 onion hidden services using ADD_ONION / DEL_ONION.

use hmac::{Hmac, Mac};
use sanctum_domain::errors::SanctumError;
use sha2::Sha256;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

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
    /// The service ID (for DEL_ONION). Onion address without ".onion".
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
        TcpStream::connect(&self.config.control_addr).await.is_ok()
    }

    /// Connect and authenticate to the Tor control port.
    ///
    /// 1. Connects to the control port
    /// 2. Sends PROTOCOLINFO to discover the cookie file path
    /// 3. Reads the cookie (must be exactly 32 bytes)
    /// 4. Authenticates with the cookie
    pub async fn connect(&mut self) -> Result<(), SanctumError> {
        if self.mock {
            info!("tor mock mode, skipping connect");
            return Ok(());
        }

        // ── Step 1: Connect to control port ──
        let stream = TcpStream::connect(&self.config.control_addr)
            .await
            .map_err(|e| {
                SanctumError::TorUnavailable(format!(
                    "cannot connect to control port {}: {e}",
                    self.config.control_addr
                ))
            })?;

        let mut reader = BufReader::new(stream);

        authenticate_safecookie(&mut reader).await?;
        self.control_stream = Some(reader);
        Ok(())
    }

    /// Create a new ephemeral v3 hidden service.
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
            SanctumError::TorUnavailable(
                "not connected to control port — call connect() first".into(),
            )
        })?;

        let cmd = format!(
            "ADD_ONION NEW:ED25519-V3 Port={},127.0.0.1:{} Flags=DiscardPK\r\n",
            self.config.hidden_service_port, self.config.local_port,
        );

        write_cmd(reader, &cmd).await?;

        let mut service_id = String::new();
        loop {
            let line = read_response(reader).await?;
            if line.starts_with("250-ServiceID=") {
                service_id = line.trim_start_matches("250-ServiceID=").trim().to_string();
            } else if line.starts_with("250 ") {
                break;
            } else if line.starts_with("5") {
                return Err(SanctumError::TorUnavailable(format!(
                    "ADD_ONION failed: {line}"
                )));
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
            service_id,
        };

        // Never log the .onion address (metadata).
        info!("hidden service created");
        self.active_service = Some(hs.clone());
        Ok(hs)
    }

    /// Destroy the active hidden service.
    pub async fn destroy_hidden_service(&mut self) -> Result<(), SanctumError> {
        let hs = self
            .active_service
            .take()
            .ok_or_else(|| SanctumError::TorUnavailable("no active hidden service".into()))?;

        if self.mock {
            info!("[tor] mock: hidden service destroyed");
            return Ok(());
        }

        if let Some(reader) = self.control_stream.as_mut() {
            let cmd = format!("DEL_ONION {}\r\n", hs.service_id);
            write_cmd(reader, &cmd).await?;
            let response = read_response(reader).await?;
            if !response.starts_with("250") {
                warn!(
                    "hidden service removal failed (status {})",
                    response.get(..3).unwrap_or("?")
                );
            }
            info!("hidden service destroyed");
        }

        Ok(())
    }

    /// Get the active hidden service.
    pub fn active_service(&self) -> Option<&HiddenService> {
        self.active_service.as_ref()
    }

    /// Get the SOCKS5 proxy address.
    pub fn socks_addr(&self) -> &str {
        &self.config.socks_addr
    }

    /// Is this a mock controller?
    pub fn is_mock(&self) -> bool {
        self.mock
    }

    /// Check if Tor is available (backward compat).
    pub fn is_available(&self) -> bool {
        self.mock || self.control_stream.is_some()
    }

    /// Set availability (backward compat for tests).
    pub fn set_available(&mut self, _available: bool) {}
}

// ============================================================
// Helpers
// ============================================================

/// HMAC key of the server's proof (control-spec, AUTHCHALLENGE).
pub const SAFECOOKIE_SERVER_KEY: &[u8] =
    b"Tor safe cookie authentication server-to-controller hash";
/// HMAC key of the controller's proof.
pub const SAFECOOKIE_CLIENT_KEY: &[u8] =
    b"Tor safe cookie authentication controller-to-server hash";

fn safecookie_mac(
    key: &[u8],
    cookie: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac
}

/// SERVERHASH = HMAC-SHA256(server key, cookie ‖ client nonce ‖ server nonce).
pub fn safecookie_server_hash(cookie: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> [u8; 32] {
    safecookie_mac(SAFECOOKIE_SERVER_KEY, cookie, client_nonce, server_nonce)
        .finalize()
        .into_bytes()
        .into()
}

/// Controller proof = HMAC-SHA256(client key, cookie ‖ client nonce ‖ server nonce).
pub fn safecookie_client_hash(cookie: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> [u8; 32] {
    safecookie_mac(SAFECOOKIE_CLIENT_KEY, cookie, client_nonce, server_nonce)
        .finalize()
        .into_bytes()
        .into()
}

fn tor_err(msg: impl Into<String>) -> SanctumError {
    SanctumError::TorUnavailable(msg.into())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// SAFECOOKIE authentication (control-spec 3.24): both sides prove they
/// know the cookie without revealing it, so a fake control port cannot
/// steal it. Unauthenticated control ports are refused.
async fn authenticate_safecookie(reader: &mut BufReader<TcpStream>) -> Result<(), SanctumError> {
    write_cmd(reader, "PROTOCOLINFO 1\r\n").await?;
    let mut methods: Vec<String> = Vec::new();
    let mut cookie_file: Option<String> = None;
    loop {
        let line = read_response(reader).await?;
        if let Some(rest) = line.strip_prefix("250-AUTH ") {
            if let Some(m) = rest.split(' ').find_map(|t| t.strip_prefix("METHODS=")) {
                methods = m.split(',').map(str::to_string).collect();
            }
            if let Some(start) = rest.find("COOKIEFILE=\"") {
                let path = &rest[start + 12..];
                cookie_file = path.find('"').map(|end| path[..end].to_string());
            }
        }
        if line.starts_with("250 ") {
            break;
        }
        if line.starts_with('4') || line.starts_with('5') || line.is_empty() {
            return Err(tor_err(format!("PROTOCOLINFO failed: {line}")));
        }
    }

    if !methods.iter().any(|m| m == "SAFECOOKIE") {
        let reason = if methods.iter().any(|m| m == "NULL") {
            "the Tor control port accepts unauthenticated connections: refusing to use it"
        } else {
            "the Tor control port does not offer SAFECOOKIE authentication"
        };
        return Err(tor_err(format!("{reason}.\n{TORRC_HELP}")));
    }
    let cookie_path = cookie_file.ok_or_else(|| tor_err("Tor did not report its cookie file"))?;
    let cookie = Zeroizing::new(
        tokio::fs::read(&cookie_path)
            .await
            .map_err(|e| tor_err(format!("cannot read the Tor cookie ({e}).\n{TORRC_HELP}")))?,
    );
    if cookie.len() != 32 {
        return Err(tor_err("Tor cookie has an unexpected length"));
    }

    let mut client_nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut client_nonce);
    write_cmd(
        reader,
        &format!("AUTHCHALLENGE SAFECOOKIE {}\r\n", hex_encode(&client_nonce)),
    )
    .await?;
    let line = read_response(reader).await?;
    let rest = line
        .strip_prefix("250 AUTHCHALLENGE ")
        .ok_or_else(|| tor_err(format!("AUTHCHALLENGE failed: {line}")))?;
    let field = |name: &str| {
        rest.split(' ')
            .find_map(|t| t.strip_prefix(name))
            .and_then(hex_decode)
            .ok_or_else(|| tor_err("malformed AUTHCHALLENGE reply"))
    };
    let server_hash = field("SERVERHASH=")?;
    let server_nonce = field("SERVERNONCE=")?;

    // Constant-time check that the control port knows the cookie.
    if safecookie_mac(SAFECOOKIE_SERVER_KEY, &cookie, &client_nonce, &server_nonce)
        .verify_slice(&server_hash)
        .is_err()
    {
        return Err(tor_err(
            "the Tor control port could not prove it knows the cookie (fake control port?)",
        ));
    }
    let proof = safecookie_client_hash(&cookie, &client_nonce, &server_nonce);
    write_cmd(reader, &format!("AUTHENTICATE {}\r\n", hex_encode(&proof))).await?;
    let line = read_response(reader).await?;
    if !line.starts_with("250") {
        return Err(tor_err(format!("Tor rejected authentication: {line}")));
    }
    debug!("authenticated to the Tor control port (SAFECOOKIE)");
    Ok(())
}

const TORRC_HELP: &str = "Checklist:\n\
  1. /etc/tor/torrc contains: ControlPort 9051, CookieAuthentication 1, \
CookieAuthFileGroupReadable 1\n\
  2. restart Tor: sudo systemctl restart tor\n\
  3. add your user to Tor's group (Debian/Ubuntu: debian-tor, others: tor):\n\
     sudo usermod -aG debian-tor $USER   then log out and back in\n\
  Never run sanctum itself with sudo.";

async fn write_cmd(reader: &mut BufReader<TcpStream>, cmd: &str) -> Result<(), SanctumError> {
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

async fn read_response(reader: &mut BufReader<TcpStream>) -> Result<String, SanctumError> {
    let mut line = String::new();
    // Bounded: a hostile control port cannot make us buffer forever.
    (&mut *reader)
        .take(4096)
        .read_line(&mut line)
        .await
        .map_err(|e| SanctumError::TorUnavailable(format!("control read: {e}")))?;
    Ok(line.trim_end().to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

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
                if hi < 10 {
                    (b'a' + hi) as char
                } else {
                    (b'2' + hi - 10) as char
                },
                if lo < 10 {
                    (b'a' + lo) as char
                } else {
                    (b'2' + lo - 10) as char
                },
            ]
        })
        .take(56)
        .collect();
    format!("{}.onion", chars.iter().collect::<String>())
}

#[cfg(test)]
mod tests {
    // Reference values computed independently with Python's hmac module:
    // cookie = 00..1f, client nonce = AA*32, server nonce = 55*32.
    #[test]
    fn safecookie_hashes_match_reference() {
        let cookie: Vec<u8> = (0u8..32).collect();
        let cn = [0xAAu8; 32];
        let sn = [0x55u8; 32];
        assert_eq!(
            hex_encode(&safecookie_server_hash(&cookie, &cn, &sn)).to_lowercase(),
            "5f7cb5569957c99373e329258545940f029af175da225f4a3125eebf30c24bba"
        );
        assert_eq!(
            hex_encode(&safecookie_client_hash(&cookie, &cn, &sn)).to_lowercase(),
            "9f99f2c4b75c91123ca5c6c6e3f76a9ef7fbd9471053cbe34454a4269cc39f7c"
        );
    }

    #[test]
    fn hex_decode_round_trip_and_rejects_garbage() {
        assert_eq!(hex_decode("00ffA0"), Some(vec![0x00, 0xff, 0xa0]));
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }

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

    #[test]
    fn hex_encode_correct() {
        assert_eq!(hex_encode(&[0x47, 0xDF, 0x36]), "47DF36");
        assert_eq!(hex_encode(&[0x00, 0xFF]), "00FF");
    }
}
