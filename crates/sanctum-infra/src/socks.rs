//! SOCKS5 client for connecting through Tor to .onion addresses.
//!
//! Implements just enough of the SOCKS5 protocol (RFC 1928) to
//! connect to a Tor hidden service via the local SOCKS5 proxy.
//!
//! SOCKS5 flow:
//! 1. Client → Proxy: greeting (version=5, methods=[NO_AUTH])
//! 2. Proxy → Client: method selection (version=5, method=NO_AUTH)
//! 3. Client → Proxy: connect request (version=5, cmd=CONNECT, addr=.onion, port)
//! 4. Proxy → Client: connect response (version=5, status, bound addr)
//! 5. Connection established — raw TCP to the hidden service

use sanctum_domain::errors::SanctumError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

/// Connect to a .onion address through a Tor SOCKS5 proxy.
///
/// `socks_addr`: the local Tor SOCKS5 proxy (e.g. "127.0.0.1:9050")
/// `target_onion`: the .onion address (e.g. "abc...xyz.onion")
/// `target_port`: the port on the hidden service (e.g. 9738)
///
/// Returns a TcpStream connected to the hidden service.
pub async fn connect_via_tor(
    socks_addr: &str,
    target_onion: &str,
    target_port: u16,
) -> Result<TcpStream, SanctumError> {
    // Connect to the SOCKS5 proxy
    let mut stream = TcpStream::connect(socks_addr)
        .await
        .map_err(|e| SanctumError::TorUnavailable(
            format!("cannot connect to Tor SOCKS5 proxy at {socks_addr}: {e}"),
        ))?;

    // ── Step 1: Greeting ──
    // Version 5, 1 method: NO_AUTH (0x00)
    stream.write_all(&[0x05, 0x01, 0x00]).await
        .map_err(|e| SanctumError::TorUnavailable(format!("SOCKS5 greeting write: {e}")))?;

    // ── Step 2: Method selection ──
    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await
        .map_err(|e| SanctumError::TorUnavailable(format!("SOCKS5 method read: {e}")))?;

    if method_resp[0] != 0x05 {
        return Err(SanctumError::TorUnavailable(
            format!("SOCKS5 version mismatch: expected 5, got {}", method_resp[0]),
        ));
    }
    if method_resp[1] != 0x00 {
        return Err(SanctumError::TorUnavailable(
            format!("SOCKS5 no acceptable auth method (got 0x{:02X})", method_resp[1]),
        ));
    }

    // ── Step 3: Connect request ──
    // Version=5, CMD=CONNECT(0x01), RSV=0x00, ATYP=DOMAINNAME(0x03)
    let domain = target_onion.as_bytes();
    let domain_len = domain.len() as u8;

    let mut request = Vec::with_capacity(4 + 1 + domain.len() + 2);
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]); // ver, cmd, rsv, atyp
    request.push(domain_len);
    request.extend_from_slice(domain);
    request.extend_from_slice(&target_port.to_be_bytes());

    stream.write_all(&request).await
        .map_err(|e| SanctumError::TorUnavailable(format!("SOCKS5 connect write: {e}")))?;

    // ── Step 4: Connect response ──
    // Read first 4 bytes: version, status, rsv, atyp
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await
        .map_err(|e| SanctumError::TorUnavailable(format!("SOCKS5 response read: {e}")))?;

    if resp_header[0] != 0x05 {
        return Err(SanctumError::TorUnavailable(
            format!("SOCKS5 response version mismatch: {}", resp_header[0]),
        ));
    }

    if resp_header[1] != 0x00 {
        let reason = match resp_header[1] {
            0x01 => "general SOCKS server failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(SanctumError::TorUnavailable(
            format!("SOCKS5 connect failed: {reason} (0x{:02X})", resp_header[1]),
        ));
    }

    // Drain the bound address (we don't need it)
    match resp_header[3] {
        0x01 => {
            // IPv4: 4 bytes addr + 2 bytes port
            let mut drain = [0u8; 6];
            stream.read_exact(&mut drain).await
                .map_err(|e| SanctumError::TorUnavailable(format!("SOCKS5 drain: {e}")))?;
        }
        0x03 => {
            // Domain: 1 byte len + N bytes + 2 bytes port
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await
                .map_err(|e| SanctumError::TorUnavailable(format!("SOCKS5 drain: {e}")))?;
            let mut drain = vec![0u8; len_buf[0] as usize + 2];
            stream.read_exact(&mut drain).await
                .map_err(|e| SanctumError::TorUnavailable(format!("SOCKS5 drain: {e}")))?;
        }
        0x04 => {
            // IPv6: 16 bytes addr + 2 bytes port
            let mut drain = [0u8; 18];
            stream.read_exact(&mut drain).await
                .map_err(|e| SanctumError::TorUnavailable(format!("SOCKS5 drain: {e}")))?;
        }
        other => {
            return Err(SanctumError::TorUnavailable(
                format!("SOCKS5 unknown address type: 0x{other:02X}"),
            ));
        }
    }

    info!("[tor] connected to {target_onion}:{target_port} via SOCKS5");
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_fails_without_tor() {
        // No Tor running on a random port
        let result = connect_via_tor("127.0.0.1:19999", "test.onion", 9738).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SOCKS5") || err.contains("connect"));
    }
}