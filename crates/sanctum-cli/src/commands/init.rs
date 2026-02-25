//! `sanctum init` — initialize a new Sanctum profile.

use crate::config::Config;
use std::fs;
use std::os::unix::fs::PermissionsExt;

/// Run the init command.
pub async fn run(alias: Option<String>, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let home = Config::home_dir();

    if home.exists() {
        eprintln!("[sanctum] profile already exists at {}", home.display());
        eprintln!("[sanctum] use --force to reinitialize (not implemented yet)");
        return Ok(());
    }

    // Create directory structure
    fs::create_dir_all(home.join("keys"))?;
    fs::create_dir_all(home.join("data"))?;

    // Set permissions: 0700
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;

    // Create default config
    let alias = alias.unwrap_or_else(|| config.identity.alias.clone());
    let config_content = format!(
        r#"[identity]
alias = "{alias}"

[tor]
control_port = {control_port}
socks_port = {socks_port}

[host]
default_mode = "ephemeral"
listen_port = {listen_port}

[chat]
auto_chat_on_join = true
backlog_display = 50
"#,
        control_port = config.tor.control_port,
        socks_port = config.tor.socks_port,
        listen_port = config.host.listen_port,
    );

    let config_path = home.join("config.toml");
    fs::write(&config_path, config_content)?;
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;

    println!("[sanctum] profile initialized at {}", home.display());
    println!("[sanctum] alias: {alias}");
    println!("[sanctum] next: import your PGP key with `sanctum identity import <keyfile>`");

    Ok(())
}