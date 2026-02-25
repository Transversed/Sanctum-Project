//! `sanctum read` — read messages non-interactively.

use crate::config::Config;

/// Run the read command.
pub async fn run(
    room_id: &str,
    follow: bool,
    last: Option<u32>,
    json: bool,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let count = last.unwrap_or(config.chat.backlog_display);

    println!(
        "[sanctum] reading from room {}...",
        &room_id[..8.min(room_id.len())]
    );

    if follow {
        println!("[sanctum] streaming mode (Ctrl-C to stop)");
    } else {
        println!("[sanctum] showing last {count} messages");
    }

    if json {
        println!("[sanctum] output format: JSON");
    }

    // TODO: connect, fetch backlog, optionally stream
    println!("[sanctum] (not implemented)");

    Ok(())
}