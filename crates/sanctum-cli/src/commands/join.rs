//! `sanctum join` — join a room via invite token.

use crate::commands::chat_loop;
use crate::config::Config;
use sanctum_infra::client_connector;
use sanctum_infra::e2e_session::PeerPrivateKeys;
use sanctum_infra::invite_codec;
use sanctum_infra::tor_control::TorConfig;
use tokio_util::sync::CancellationToken;

pub async fn run(
    token: &str,
    no_chat: bool,
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    // Decode
    println!("[sanctum] parsing invite token...");
    let invite = invite_codec::decode_invite(token)?;

    println!("[sanctum] room: {}", invite.room_id);
    println!("[sanctum] host: {}:{}", invite.onion_address, invite.port);
    println!("[sanctum] role: {:?}", invite.role);

    // Validate
    let local_fp = invite.invited_fingerprint.clone();
    invite_codec::validate_invite(&invite, &local_fp)?;
    println!("[sanctum] token valid");

    // E2E keys
    let e2e_keys = PeerPrivateKeys::generate(5);

    // Connect
    let is_local = invite.onion_address == "localhost"
        || invite.onion_address.starts_with("127.");

    let alias = config.identity.alias.clone();

    let session = if !is_local && invite.onion_address.ends_with(".onion") {
        println!("[sanctum] connecting via Tor (may take 10-30s)...");
        let tc = TorConfig {
            socks_addr: format!("127.0.0.1:{}", config.tor.socks_port),
            ..TorConfig::default()
        };
        client_connector::connect_via_tor_and_auth(
            &tc.socks_addr, &invite.onion_address, invite.port,
            &local_fp, &alias, &invite.host_noise_pubkey,
        ).await?
    } else {
        let addr = format!("{}:{}", invite.onion_address, invite.port);
        println!("[sanctum] connecting to {addr}...");
        client_connector::connect_and_auth(
            &addr, &local_fp, &alias, &invite.host_noise_pubkey,
        ).await?
    };

    println!("[sanctum] authenticated (Noise OK, role: {})", session.role);

    if no_chat {
        println!("[sanctum] joined (no-chat mode)");
        return Ok(());
    }

    println!("[sanctum] type messages or /exit to quit");
    println!("──────────────────────────────────────────────");

    chat_loop::run(session.transport, local_fp, alias, Some(e2e_keys), false, shutdown).await;

    println!("[sanctum] goodbye.");
    Ok(())
}