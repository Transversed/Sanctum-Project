//! `sanctum host` — host a room.

use crate::config::Config;
use clap::Subcommand;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Member, Role};
use sanctum_domain::entities::room::{RoomConfig, RoomMode};
use sanctum_domain::events::SanctumEvent;
use sanctum_app::room_service::RoomService;
use sanctum_app::host_service::HostService;
use sanctum_infra::tor_control::{TorConfig as InfraTorConfig, TorController};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Host subcommands.
#[derive(Subcommand)]
pub enum HostAction {
    /// Create and host a new room.
    Create {
        /// Room name.
        name: String,

        /// Room mode.
        #[arg(long, default_value = "ephemeral")]
        mode: String,

        /// Listen port.
        #[arg(long)]
        port: Option<u16>,

        /// Max members.
        #[arg(long, default_value = "10")]
        max_members: u16,

        /// Max backlog messages (persistent only).
        #[arg(long, default_value = "500")]
        backlog_max: u32,

        /// Max backlog age in hours (persistent only).
        #[arg(long, default_value = "72")]
        backlog_hours: u32,

        /// Open interactive chat immediately.
        #[arg(long)]
        chat: bool,
    },

    /// Show host status.
    Status,

    /// Stop hosting.
    Stop,
}

/// Run the host command.
pub async fn run(
    action: HostAction,
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        HostAction::Create {
            name, mode, port, max_members,
            backlog_max, backlog_hours, chat,
        } => {
            let room_mode = match mode.as_str() {
                "persistent" => RoomMode::Persistent,
                _ => RoomMode::Ephemeral,
            };

            let listen_port = port.unwrap_or(config.host.listen_port);

            let mut room_config = RoomConfig::default();
            room_config.max_members = max_members;
            room_config.backlog_max_messages = backlog_max;
            room_config.backlog_max_age_hours = backlog_hours;
            room_config.validate();

            // Create room
            let mut room_svc = RoomService::new();
            // TODO: load real identity
            let owner_fp = Fingerprint::new("A".repeat(40)).unwrap();
            let owner_alias = DisplayAlias::new(&config.identity.alias)
                .unwrap_or_else(|_| DisplayAlias::new("host").unwrap());

            room_svc.create_room(
                &name, room_mode, room_config,
                owner_fp.clone(), vec![0u8; 32], owner_alias,
            )?;

            let room = room_svc.room()?.clone();
            println!("[sanctum] room created: {} ({})", room.name(), room.id());
            println!("[sanctum] mode: {room_mode}");

            // Init Tor
            let tor_config = InfraTorConfig {
                socks_addr: format!("127.0.0.1:{}", config.tor.socks_port),
                control_addr: format!("127.0.0.1:{}", config.tor.control_port),
                hidden_service_port: listen_port,
                local_port: listen_port,
            };

            let mut tor = TorController::new(tor_config);
            tor.set_available(true); // TODO: real Tor detection

            match tor.create_hidden_service().await {
                Ok(hs) => {
                    println!("[sanctum] onion: {}", hs.onion_address);
                    println!("[sanctum] port: {}", hs.port);
                }
                Err(e) => {
                    eprintln!("[sanctum] warning: Tor unavailable: {e}");
                    eprintln!("[sanctum] running in local-only mode");
                }
            }

            // Start host service
            let (event_tx, _) = broadcast::channel(256);
            let _host_svc = HostService::new(room, event_tx.clone());

            println!("[sanctum] host running. Ctrl-C to stop.");

            if chat {
                println!("[sanctum] interactive mode — type messages or /help");
            }

            // Wait for shutdown
            shutdown.cancelled().await;
            println!("[sanctum] host stopped.");
            Ok(())
        }
        HostAction::Status => {
            println!("[sanctum] host status: not implemented yet");
            Ok(())
        }
        HostAction::Stop => {
            println!("[sanctum] stopping host...");
            Ok(())
        }
    }
}