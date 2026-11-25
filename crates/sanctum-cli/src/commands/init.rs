//! `sanctum init` — initialize a new Sanctum profile.
//!
//! Creates ~/.sanctum/ with:
//! - config.toml (alias, tor, host settings)
//! - keys/identity.key (Ed25519 private key, encrypted with a passphrase)
//! - keys/identity.pub (Ed25519 public key)
//! - keys/identity.fingerprint (human-readable)

use crate::config::Config;
use crate::passphrase;
use sanctum_infra::identity::IdentityAdapter;
use sanctum_infra::identity::{create_private_dir, write_private_file};

pub async fn run(alias: Option<String>, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let home = Config::home_dir();

    if home.exists() {
        // Check if identity already exists
        let key_path = home.join("keys").join("identity.key");
        if key_path.exists() {
            let fp = IdentityAdapter::public_fingerprint_in(&IdentityAdapter::default_dir())?;
            println!("[sanctum] profile already exists");
            println!("[sanctum] fingerprint: {}", fp.as_str());
            println!("[sanctum] to reinitialize, delete ~/.sanctum/ first");
            return Ok(());
        }
    }

    // Directories are created with mode 0700 from the start.
    create_private_dir(&home)?;

    // Generate the Ed25519 identity, encrypted with a passphrase.
    let pass = passphrase::read_new()?;
    let identity = IdentityAdapter::generate();
    identity.save_to_disk(pass.as_bytes())?;

    // Write config
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

    write_private_file(&home.join("config.toml"), config_content.as_bytes())?;

    println!("[sanctum] profile initialized at {}", home.display());
    println!("[sanctum] alias: {alias}");
    println!("[sanctum] fingerprint: {}", identity.fingerprint().as_str());
    println!(
        "[sanctum] Ed25519 key saved encrypted (Argon2id + ChaCha20-Poly1305) in ~/.sanctum/keys/"
    );
    println!();
    println!("[sanctum] next: host a room with `sanctum host create <name> --chat --local`");

    Ok(())
}
