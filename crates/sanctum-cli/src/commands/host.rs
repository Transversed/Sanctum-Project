//! `sanctum host` — host a room with real networking + real identity.

use crate::commands::chat_loop;
use crate::config::Config;
use clap::{Args, Subcommand};
use sanctum_app::host_service::HostService;
use sanctum_app::room_service::RoomService;
use sanctum_domain::entities::member::DisplayAlias;
use sanctum_domain::entities::room::{RoomConfig, RoomMode};
use sanctum_domain::events::SanctumEvent;
use sanctum_infra::client_connector;
use sanctum_infra::e2e_session::PeerPrivateKeys;
use sanctum_infra::host_listener::HostListener;
use sanctum_infra::identity_pgp::IdentityAdapter;
use sanctum_infra::invite_codec;
use sanctum_infra::tor_control::{TorConfig as InfraTorConfig, TorController};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Arguments of `sanctum host create`.
#[derive(Args)]
pub struct CreateArgs {
    /// Room name.
    pub name: String,
    /// Room mode. Only `ephemeral` is available in v0.1.1.
    #[arg(long, default_value = "ephemeral")]
    pub mode: String,
    /// Local relay port (default from config).
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long, default_value = "10")]
    pub max_members: u16,
    #[arg(long, default_value = "500")]
    pub backlog_max: u32,
    #[arg(long, default_value = "72")]
    pub backlog_hours: u32,
    /// Open the interactive chat as the owner.
    #[arg(long)]
    pub chat: bool,
    /// Listen on 127.0.0.1 without creating a Tor hidden service.
    #[arg(long)]
    pub local: bool,
    /// DANGER: allow sending unencrypted messages (the host reads them).
    #[arg(long)]
    pub insecure_plaintext: bool,
}

#[derive(Subcommand)]
pub enum HostAction {
    /// Create and host a room.
    Create(CreateArgs),
    /// Not implemented in v0.1.1.
    Status,
    /// Not implemented in v0.1.1 (stop the host with Ctrl-C).
    Stop,
}

pub async fn run(
    action: HostAction,
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        HostAction::Create(args) => run_create(args, config, shutdown).await,
        HostAction::Status => Err(crate::commands::not_implemented("host status")),
        HostAction::Stop => Err(crate::commands::not_implemented(
            "host stop (stop the host with Ctrl-C)",
        )),
    }
}

/// Only ephemeral rooms exist in v0.1.1 (persistent storage is not wired).
fn parse_mode(mode: &str) -> Result<RoomMode, String> {
    match mode {
        "ephemeral" => Ok(RoomMode::Ephemeral),
        "persistent" => Err(
            "persistent mode is not available in v0.1.1: storage and a stable .onion \
             are not implemented yet. Use --mode ephemeral."
                .into(),
        ),
        other => Err(format!("unknown mode '{other}' (expected: ephemeral)")),
    }
}

async fn run_create(
    args: CreateArgs,
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let CreateArgs {
        name,
        mode,
        port,
        max_members,
        backlog_max,
        backlog_hours,
        chat: open_chat,
        local,
        insecure_plaintext,
    } = args;
    let name = name.as_str();
    let room_mode = parse_mode(&mode)?;

    // Load real identity
    let identity = IdentityAdapter::load_from_disk()
        .map_err(|e| format!("{e}\nRun `sanctum init --alias <name>` first."))?;
    let owner_fp = identity.fingerprint().clone();
    let alias = config.identity.alias.clone();
    println!("[sanctum] identity: {} ({})", alias, owner_fp.short());

    let listen_port = port.unwrap_or(config.host.listen_port);

    let mut room_config = RoomConfig {
        max_members,
        backlog_max_messages: backlog_max,
        backlog_max_age_hours: backlog_hours,
        ..RoomConfig::default()
    };
    room_config.validate();

    // Noise keypair
    let (noise_priv, noise_pub): (Vec<u8>, Vec<u8>) = sanctum_infra::noise_keygen();

    // E2E keys
    let e2e_keys = PeerPrivateKeys::generate(5);

    // Room
    let mut room_svc = RoomService::new();
    let owner_alias =
        DisplayAlias::new(&alias).unwrap_or_else(|_| DisplayAlias::new("host").unwrap());
    room_svc.create_room(
        name,
        room_mode,
        room_config,
        owner_fp.clone(),
        identity.public_key_bytes(),
        owner_alias,
    )?;
    let room = room_svc.room()?.clone();
    println!("[sanctum] room '{}' created ({})", room.name(), room_mode);

    // Tor
    let bind_addr = format!("127.0.0.1:{listen_port}");
    let mut tor = if local {
        println!("[sanctum] local mode (no Tor)");
        TorController::mock()
    } else {
        let tc_config = InfraTorConfig {
            socks_addr: format!("127.0.0.1:{}", config.tor.socks_port),
            control_addr: format!("127.0.0.1:{}", config.tor.control_port),
            hidden_service_port: listen_port,
            local_port: listen_port,
        };
        let mut tc = TorController::new(tc_config);
        if let Err(e) = tc.connect().await {
            eprintln!("[sanctum] Tor: {e}");
            return Err(e.into());
        }
        tc
    };

    let hs = tor.create_hidden_service().await?;
    if !local {
        println!("[sanctum] hidden service: {}:{}", hs.onion_address, hs.port);
    }
    println!("[sanctum] relay on {bind_addr}");

    // Relay
    let (event_tx, _) = broadcast::channel::<SanctumEvent>(256);
    let host_svc = HostService::new(room.clone(), event_tx);
    let listener = HostListener::new(
        bind_addr.clone(),
        host_svc,
        noise_pub.clone(),
        noise_priv.clone(),
        shutdown.clone(),
    );
    let relay_handle = tokio::spawn(async move {
        if let Err(e) = listener.run().await {
            eprintln!("[sanctum] relay: {e}");
        }
    });

    let onion_display = if local {
        "127.0.0.1".to_string()
    } else {
        hs.onion_address.clone()
    };
    println!();
    println!("[sanctum] your fingerprint (share with invitees):");
    println!("  {}", owner_fp.as_str());
    println!();
    println!("[sanctum] to invite someone (run as the owner, in another terminal):");
    println!(
        "  sanctum room invite <their_fingerprint> --room-onion {} --room-port {} --room-id {} --host-key {}",
        onion_display,
        hs.port,
        room.id().as_str(),
        invite_codec::encode_host_key(&noise_pub),
    );
    println!();

    if open_chat {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        let session =
            client_connector::connect_and_auth(&bind_addr, &owner_fp, &alias, &noise_pub).await?;

        println!("[sanctum] connected as owner (Noise OK)");
        println!("[sanctum] type messages or /exit to quit");
        println!("──────────────────────────────────────────────");

        let chat_cfg = chat_loop::ChatConfig {
            room_name: room.name().to_string(),
            room_mode: room_mode.to_string(),
            tor_connected: !local,
            insecure_plaintext,
        };
        chat_loop::run_with_config(
            session.transport,
            owner_fp,
            alias,
            Some(e2e_keys),
            true,
            shutdown.clone(),
            chat_cfg,
        )
        .await;
    } else {
        println!("[sanctum] relay running. Ctrl-C to stop.");
        shutdown.cancelled().await;
    }

    let _ = tor.destroy_hidden_service().await;
    shutdown.cancel();
    let _ = relay_handle.await;
    println!("[sanctum] host stopped.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_mode_is_refused_explicitly() {
        assert!(parse_mode("ephemeral").is_ok());
        let err = parse_mode("persistent").unwrap_err();
        assert!(err.contains("not available"));
        assert!(parse_mode("bogus").is_err());
    }
}
