//! `sanctum join` — join a room via invite token, using real identity.

use crate::commands::chat_loop;
use crate::config::Config;
use sanctum_app::sanitize::sanitize_for_terminal;
use sanctum_infra::client_connector::{self, ClientCredentials};
use sanctum_infra::identity::IdentityAdapter;
use sanctum_infra::invite_codec;
use tokio_util::sync::CancellationToken;

pub async fn run(
    token: &str,
    no_chat: bool,
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load our real identity
    let identity = IdentityAdapter::load_from_disk(crate::passphrase::read_existing()?.as_bytes())
        .map_err(|e| format!("{e}\nRun `sanctum init --alias <n>` first."))?;
    let local_fp = identity.fingerprint().clone();
    let alias = config.identity.alias.clone();
    println!("[sanctum] identity: {} ({})", alias, local_fp.short());

    // Decode token
    println!("[sanctum] parsing invite token...");
    let invite = invite_codec::decode_invite(token)?;

    println!("[sanctum] room: {}", invite.room_id);
    println!(
        "[sanctum] host: {}:{}",
        sanitize_for_terminal(&invite.onion_address),
        invite.port
    );
    println!("[sanctum] role: {:?}", invite.role);

    // Validate: is this token for us?
    invite_codec::validate_invite(&invite, &local_fp)?;
    println!("[sanctum] token valid (for our fingerprint)");

    // Connect: Tor for .onion, direct TCP only for loopback (local tests).
    // Anything else would be a clearnet connection: refused.
    let creds = ClientCredentials {
        identity: &identity,
        display_alias: &alias,
        invite_token: Some(token),
    };
    let is_loopback = invite.onion_address == "localhost"
        || invite
            .onion_address
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());

    let session = if invite.onion_address.ends_with(".onion") {
        println!("[sanctum] connecting via Tor (may take 10-30s)...");
        let socks_addr = format!("127.0.0.1:{}", config.tor.socks_port);
        client_connector::connect_via_tor_and_auth(
            &socks_addr,
            &invite.onion_address,
            invite.port,
            &creds,
            &invite.host_noise_pubkey,
        )
        .await?
    } else if is_loopback {
        let addr = format!("{}:{}", invite.onion_address, invite.port);
        println!("[sanctum] connecting to {addr} (local, no Tor)...");
        client_connector::connect_and_auth(&addr, &creds, &invite.host_noise_pubkey).await?
    } else {
        return Err(format!(
            "refusing to connect to '{}': not a .onion address (Sanctum never uses clearnet)",
            sanitize_for_terminal(&invite.onion_address)
        )
        .into());
    };

    println!(
        "[sanctum] authenticated (Noise OK, role: {})",
        sanitize_for_terminal(&session.role)
    );

    if no_chat {
        println!("[sanctum] joined (no-chat mode)");
        return Ok(());
    }

    println!("[sanctum] type messages or /exit to quit");
    println!("──────────────────────────────────────────────");

    let chat_cfg = chat_loop::ChatConfig {
        room_name: invite.room_id.as_str().chars().take(8).collect(),
        room_mode: "ephemeral".into(),
        tor_connected: !is_loopback,
        inviter: None,
    };
    chat_loop::run(
        session.transport,
        std::sync::Arc::new(identity),
        alias,
        shutdown,
        chat_cfg,
    )
    .await;

    println!("[sanctum] goodbye.");
    Ok(())
}
