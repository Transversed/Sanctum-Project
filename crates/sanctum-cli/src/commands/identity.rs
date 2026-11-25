//! `sanctum identity` — inspect the local Ed25519 identity.
//!
//! The identity is created by `sanctum init` and stored in
//! `~/.sanctum/keys/identity.key`. Sanctum identities are Ed25519 keys;
//! importing OpenPGP keys is not supported.

use crate::config::Config;
use clap::Subcommand;
use sanctum_infra::identity::IdentityAdapter;

/// Identity subcommands.
#[derive(Subcommand)]
pub enum IdentityAction {
    /// Disabled: OpenPGP import is not supported (see `sanctum init`).
    Import {
        /// Path to the key file (ignored).
        keyfile: String,
    },
    /// Show the current identity (fingerprint).
    Show,
}

/// Why `identity import` is refused.
pub const IMPORT_DISABLED: &str = "`sanctum identity import` is disabled.\n\
    It used the first 32 bytes of an OpenPGP file as an Ed25519 secret: those \
    bytes are packet headers and public data, so anyone holding your public \
    key could rebuild that \"secret\". It also copied the whole PGP file to \
    ~/.sanctum in clear text.\n\
    Sanctum identities are native Ed25519 keys created by `sanctum init`.\n\
    If you ran `identity import` before, delete ~/.sanctum/keys/signing.key.";

/// Run the identity command.
pub async fn run(
    action: IdentityAction,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        IdentityAction::Import { .. } => Err(IMPORT_DISABLED.into()),
        IdentityAction::Show => {
            let identity = IdentityAdapter::load_from_disk()?;
            println!("[sanctum] fingerprint: {}", identity.fingerprint().as_str());
            println!("[sanctum] alias: {}", config.identity.alias);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn import_is_refused_and_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("sanctum-import-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("key.gpg");
        std::fs::write(&key, [0x99u8; 64]).unwrap();

        let res = run(
            IdentityAction::Import {
                keyfile: key.display().to_string(),
            },
            &Config::default(),
        )
        .await;
        assert!(res.unwrap_err().to_string().contains("disabled"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
