//! `sanctum identity` — manage identity keys.

use crate::config::Config;
use clap::Subcommand;
use sanctum_infra::identity_pgp::IdentityAdapter;

/// Identity subcommands.
#[derive(Subcommand)]
pub enum IdentityAction {
    /// Import a PGP key file.
    Import {
        /// Path to the key file.
        keyfile: String,
    },
    /// Show current identity (fingerprint).
    Show,
    /// Generate a new identity (for testing).
    Generate,
}

/// Run the identity command.
pub async fn run(action: IdentityAction, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        IdentityAction::Import { keyfile } => {
            let key_data = std::fs::read(&keyfile)?;
            if key_data.len() < 32 {
                return Err("key file too small (need at least 32 bytes)".into());
            }

            // Store key (in production: parse PGP, extract signing subkey)
            let key_path = Config::home_dir().join("keys").join("signing.key");
            std::fs::write(&key_path, &key_data)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }

            let identity = IdentityAdapter::from_key(key_data[..32].to_vec())?;
            println!("[sanctum] key imported: {}", identity.fingerprint());
            Ok(())
        }
        IdentityAction::Show => {
            let identity = load_identity()?;
            println!("[sanctum] fingerprint: {}", identity.fingerprint().as_str());
            println!("[sanctum] alias: {}", config.identity.alias);
            Ok(())
        }
        IdentityAction::Generate => {
            let identity = IdentityAdapter::generate();
            let key_dir = Config::home_dir().join("keys");
            std::fs::create_dir_all(&key_dir)?;
            // In production, this would export a PGP key
            println!("[sanctum] generated identity: {}", identity.fingerprint());
            println!("[sanctum] ⚠ this is a test identity, not a real PGP key");
            Ok(())
        }
    }
}

/// Load the current identity from disk.
fn load_identity() -> Result<IdentityAdapter, Box<dyn std::error::Error>> {
    let key_path = Config::home_dir().join("keys").join("signing.key");
    let key_data = std::fs::read(&key_path)
        .map_err(|_| "no identity found — run `sanctum identity import` first")?;
    let identity = IdentityAdapter::from_key(key_data[..32].to_vec())?;
    Ok(identity)
}