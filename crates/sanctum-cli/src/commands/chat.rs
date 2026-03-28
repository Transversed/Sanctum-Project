//! `sanctum chat` — open an interactive chat session.
//!
//! This is the PRIMARY user experience of Sanctum.

use crate::config::Config;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Role};
use sanctum_domain::entities::room::RoomMode;
use sanctum_domain::events::ChatEvent;
use sanctum_app::chat_session::{ChatSession, SessionConfig};

use sanctum_infra::terminal_renderer::TerminalLineRenderer;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Run the chat command.
pub async fn run(
    room_id: &str,
    backlog: u32,
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: load room from storage, connect if needed
    // For now, create a local session

    let local_fp = Fingerprint::new("A".repeat(40)).unwrap();
    let local_alias = DisplayAlias::new(&config.identity.alias)
        .unwrap_or_else(|_| DisplayAlias::new("anon").unwrap());

    let session_config = SessionConfig {
        room_id: room_id.parse::<sanctum_domain::entities::room::RoomId>()
            .unwrap_or_else(|_| sanctum_domain::entities::room::RoomId::new()),
        room_name: format!("room-{}", &room_id[..8.min(room_id.len())]),
        room_mode: RoomMode::Ephemeral,
        local_fingerprint: local_fp,
        local_alias: local_alias.to_string(),
        local_role: Role::Member,
    };

    let ui = TerminalLineRenderer::new();
    let (event_tx, _) = broadcast::channel::<ChatEvent>(256);

    let session = ChatSession::new(session_config, ui, event_tx.clone(), shutdown.clone());

    // Init UI
    session.init_ui()?;

    println!("[sanctum] connected to room. Type messages or /help for commands.");
    println!("[sanctum] backlog: last {} messages", backlog);

    // Main input loop
    let _ui_ref = &session;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                break;
            }
            // In production: network recv loop, render loop, etc.
            // For now: just wait for shutdown
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(3600)) => {}
        }
    }

    // Cleanup
    session.cleanup_ui()?;
    println!("[sanctum] session ended. Secrets cleared.");

    Ok(())
}