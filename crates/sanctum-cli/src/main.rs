//! Sanctum CLI — entry point.

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod banner;
mod config;
mod commands;

/// Sanctum — encrypted group chat over Tor hidden services.
#[derive(Parser)]
#[command(name = "sanctum", version, about, long_about = None)]
struct Cli {
    /// Config file path (default: ~/.sanctum/config.toml).
    #[arg(long, global = true)]
    config: Option<String>,

    /// Verbosity level.
    #[arg(short, long, global = true, default_value = "off")]
    log_level: String,

    /// Disable banner.
    #[arg(long, global = true)]
    no_banner: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Sanctum profile.
    Init {
        /// Display alias.
        #[arg(long)]
        alias: Option<String>,
    },

    /// Manage identity keys.
    Identity {
        #[command(subcommand)]
        action: commands::identity::IdentityAction,
    },

    /// Host a room.
    Host {
        #[command(subcommand)]
        action: commands::host::HostAction,
    },

    /// Join a room via invite token.
    Join {
        /// Invite token (base64url).
        token: String,

        /// Skip interactive chat after joining.
        #[arg(long)]
        no_chat: bool,
    },

    /// Open an interactive chat session.
    Chat {
        /// Room ID.
        room_id: String,

        /// Number of backlog messages to display.
        #[arg(long, default_value = "50")]
        backlog: u32,
    },

    /// Manage rooms.
    Room {
        #[command(subcommand)]
        action: commands::room::RoomAction,
    },

    /// Send a message (non-interactive).
    Send {
        /// Room ID.
        room_id: String,

        /// Message text.
        message: String,
    },

    /// Read messages (non-interactive).
    Read {
        /// Room ID.
        room_id: String,

        /// Follow mode (stream new messages).
        #[arg(long)]
        follow: bool,

        /// Number of last messages to show.
        #[arg(long)]
        last: Option<u32>,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Show system status.
    Status,

    /// Export release manifest.
    ExportManifest,
}

fn main() {
    // Custom panic hook: clean terminal + zeroize hint
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Restore terminal
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::cursor::Show
        );
        eprintln!("\n[sanctum] fatal error — secrets may still be in memory");
        default_hook(info);
    }));

    let cli = Cli::parse();

    // Init logging
    let filter = EnvFilter::try_new(&cli.log_level).unwrap_or_else(|_| EnvFilter::new("off"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Banner
    if !cli.no_banner {
        banner::print_banner();
    }

    // Load config
    let config = config::Config::load(cli.config.as_deref());

    // Runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let result = rt.block_on(async {
        // Signal handler
        let shutdown = tokio_util::sync::CancellationToken::new();
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            eprintln!("\n[sanctum] shutting down...");
            shutdown_clone.cancel();
        });

        run(cli.command, config, shutdown).await
    });

    if let Err(e) = result {
        eprintln!("[sanctum] error: {e}");
        std::process::exit(1);
    }
}

async fn run(
    command: Commands,
    config: config::Config,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Init { alias } => {
            commands::init::run(alias, &config).await
        }
        Commands::Identity { action } => {
            commands::identity::run(action, &config).await
        }
        Commands::Host { action } => {
            commands::host::run(action, &config, shutdown).await
        }
        Commands::Join { token, no_chat } => {
            commands::join::run(&token, no_chat, &config, shutdown).await
        }
        Commands::Chat { room_id, backlog } => {
            commands::chat::run(&room_id, backlog, &config, shutdown).await
        }
        Commands::Room { action } => {
            commands::room::run(action, &config).await
        }
        Commands::Send { room_id, message } => {
            commands::send::run(&room_id, &message, &config).await
        }
        Commands::Read { room_id, follow, last, json } => {
            commands::read::run(&room_id, follow, last, json, &config).await
        }
        Commands::Status => {
            commands::status::run(&config).await
        }
        Commands::ExportManifest => {
            commands::export_manifest::run().await
        }
    }
}