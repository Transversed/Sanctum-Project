//! `sanctum init` — initialize a new Sanctum profile.
//!
//! Creates ~/.sanctum/ with:
//! - config.toml (alias, tor, host settings)
//! - keys/identity.key (Ed25519 private key)
//! - keys/identity.pub (Ed25519 public key)
//! - keys/identity.fingerprint (human-readable)
//! - data/ (empty, for persistent mode)

use crate::config::Config;
use sanctum_infra::identity_pgp::IdentityAdapter;
use std::fs;
use std::os::unix::fs::PermissionsExt;

pub async fn run(alias: Option<String>, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let home = Config::home_dir();

    if home.exists() {
        // Check if identity already exists
        let key_path = home.join("keys").join("identity.key");
        if key_path.exists() {
            let id = IdentityAdapter::load_from_disk()?;
            println!("[sanctum] profile already exists");
            println!("[sanctum] fingerprint: {}", id.fingerprint().as_str());
            println!("[sanctum] to reinitialize, delete ~/.sanctum/ first");
            return Ok(());
        }
    }

    // Create directory structure
    fs::create_dir_all(home.join("keys"))?;
    fs::create_dir_all(home.join("data"))?;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;

    // Generate Ed25519 identity
    let identity = IdentityAdapter::generate();
    identity.save_to_disk()?;

    // Write config
    let alias = alias.unwrap_or_else(|| config.identity.alias.clone());
    let config_content = format!(
        r#"[identity]
alias = "{alias}"
pgp_key_id = "{fingerprint}"

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
        fingerprint = identity.fingerprint().as_str(),
        control_port = config.tor.control_port,
        socks_port = config.tor.socks_port,
        listen_port = config.host.listen_port,
    );

    let config_path = home.join("config.toml");
    fs::write(&config_path, config_content)?;
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;

    println!("[sanctum] profile initialized at {}", home.display());
    println!("[sanctum] alias: {alias}");
    println!("[sanctum] fingerprint: {}", identity.fingerprint().as_str());
    println!("[sanctum] Ed25519 keypair saved to ~/.sanctum/keys/");
    println!();
    println!("[sanctum] next: host a room with `sanctum host create <name> --chat --local`");

    Ok(())
}