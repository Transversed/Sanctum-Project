//! `sanctum send` — non-interactive send. Not implemented in v0.1.1.

use crate::config::Config;

pub async fn run(
    _room_id: &str,
    _message: &str,
    _config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(super::not_implemented("send"))
}
