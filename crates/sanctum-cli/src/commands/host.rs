//! `sanctum host` — host a room with real networking + real identity.

use crate::commands::chat_loop;
use crate::config::Config;
use clap::Subcommand;
use sanctum_app::host_service::HostService;
use sanctum_app::room_service::RoomService;
use sanctum_domain::entities::member::DisplayAlias;
use sanctum_domain::entities::room::{RoomConfig, RoomMode};
use sanctum_domain::events::SanctumEvent;
use sanctum_infra::client_connector;
use sanctum_infra::e2e_session::PeerPrivateKeys;
use sanctum_infra::host_listener::HostListener;
use sanctum_infra::identity_pgp::IdentityAdapter;
use sanctum_infra::tor_control::{TorConfig as InfraTorConfig, TorController};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

#[derive(Subcommand)]
pub enum HostAction {
    Create {
        name: String,
        #[arg(long, default_value = "ephemeral")]
        mode: String,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, default_value = "10")]
        max_members: u16,
        #[arg(long, default_value = "500")]
        backlog_max: u32,
        #[arg(long, default_value = "72")]
        backlog_hours: u32,
        #[arg(long)]
        chat: bool,
        #[arg(long)]
        local: bool,
    },
    Status,
    Stop,
}

pub async fn run(
    action: HostAction, config: &Config, shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        HostAction::Create { name, mode, port, max_members, backlog_max, backlog_hours, chat, local } => {
            run_create(&name, &mode, port, max_members, backlog_max, backlog_hours, chat, local, config, shutdown).await
        }
        HostAction::Status => { println!("[sanctum] not implemented"); Ok(()) }
        HostAction::Stop => { println!("[sanctum] stopping..."); Ok(()) }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_create(
    name: &str, mode: &str, port: Option<u16>, max_members: u16,
    backlog_max: u32, backlog_hours: u32, open_chat: bool, local: bool,
    config: &Config, shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load real identity
    let identity = IdentityAdapter::load_from_disk().map_err(|e| {
        format!("{e}\nRun `sanctum init --alias <name>` first.")
    })?;
    let owner_fp = identity.fingerprint().clone();
    let alias = config.identity.alias.clone();
    println!("[sanctum] identity: {} ({})", alias, owner_fp.short());

    let room_mode = match mode { "persistent" => RoomMode::Persistent, _ => RoomMode::Ephemeral };
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
    let _ = std::fs::write("/tmp/sanctum_noise_pub", &noise_pub);

    // E2E keys
    let e2e_keys = PeerPrivateKeys::generate(5);

    // Room
    let mut room_svc = RoomService::new();
    let owner_alias = DisplayAlias::new(&alias).unwrap_or_else(|_| DisplayAlias::new("host").unwrap());
    room_svc.create_room(
        name, room_mode, room_config,
        owner_fp.clone(), identity.public_key_bytes(), owner_alias,
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
    if !local { println!("[sanctum] hidden service: {}:{}", hs.onion_address, hs.port); }
    println!("[sanctum] relay on {bind_addr}");

    // Relay
    let (event_tx, _) = broadcast::channel::<SanctumEvent>(256);
    let host_svc = HostService::new(room.clone(), event_tx);
    let listener = HostListener::new(
        bind_addr.clone(), host_svc, noise_pub.clone(), noise_priv.clone(), shutdown.clone(),
    );
    let relay_handle = tokio::spawn(async move {
        if let Err(e) = listener.run().await { eprintln!("[sanctum] relay: {e}"); }
    });

    let onion_display = if local { "127.0.0.1".to_string() } else { hs.onion_address.clone() };
    println!();
    println!("[sanctum] your fingerprint (share with invitees):");
    println!("  {}", owner_fp.as_str());
    println!();
    println!("[sanctum] to invite someone:");
    println!("  sanctum room invite <their_fingerprint> --room-onion {} --room-port {} --room-id {}",
        onion_display, hs.port, room.id().as_str());
    println!();

    if open_chat {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        let session = client_connector::connect_and_auth(
            &bind_addr, &owner_fp, &alias, &noise_pub,
        ).await?;

        println!("[sanctum] connected as owner (Noise OK)");
        println!("[sanctum] type messages or /exit to quit");
        println!("──────────────────────────────────────────────");

        chat_loop::run(session.transport, owner_fp, alias, Some(e2e_keys), true, shutdown.clone()).await;
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