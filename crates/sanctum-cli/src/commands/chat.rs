//! `sanctum chat` — reopen a chat session on a known room.
//!
//! Not implemented in v0.1.1: rooms are ephemeral and only reachable through
//! `sanctum host create --chat` (owner) or `sanctum join <token>` (members).

use crate::config::Config;
use tokio_util::sync::CancellationToken;

pub async fn run(
    _room_id: &str,
    _backlog: u32,
    _config: &Config,
    _shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(super::not_implemented(
        "chat (use `sanctum host create --chat` or `sanctum join <token>`)",
    ))
}
