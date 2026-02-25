//! `sanctum send` — send a message non-interactively.

use crate::config::Config;

/// Run the send command.
pub async fn run(
    room_id: &str,
    message: &str,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: connect to room, send message, disconnect
    println!(
        "[sanctum] sending to room {}...",
        &room_id[..8.min(room_id.len())]
    );
    println!("[sanctum] message: {message}");
    println!("[sanctum] sent (not implemented)");
    Ok(())
}