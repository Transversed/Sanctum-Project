//! `sanctum read` — non-interactive read. Not implemented in v0.1.1.

use crate::config::Config;

pub async fn run(
    _room_id: &str,
    _follow: bool,
    _last: Option<u32>,
    _json: bool,
    _config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(super::not_implemented("read"))
}
