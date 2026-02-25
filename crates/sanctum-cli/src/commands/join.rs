//! `sanctum join` — join a room via invite token.

use crate::config::Config;
use tokio_util::sync::CancellationToken;

/// Run the join command.
pub async fn run(
    token: &str,
    no_chat: bool,
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[sanctum] parsing invite token...");

    // TODO: decode base64url token → InviteToken
    // TODO: validate invite (fingerprint match, not expired)
    // TODO: connect to host via Tor SOCKS5
    // TODO: Noise NK handshake
    // TODO: PGP auth challenge-response
    // TODO: X3DH with peers

    if token.len() < 10 {
        return Err("invalid invite token (too short)".into());
    }

    println!("[sanctum] connecting to room...");
    println!("[sanctum] token: {}...", &token[..10.min(token.len())]);

    // Placeholder: simulate join
    println!("[sanctum] joined room successfully");

    if !no_chat && config.chat.auto_chat_on_join {
        println!("[sanctum] opening interactive chat...");
        // In production: call commands::chat::run(room_id, ...)
        shutdown.cancelled().await;
    }

    Ok(())
}