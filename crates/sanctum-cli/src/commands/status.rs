//! `sanctum status` — show local profile status (no network access).

use crate::config::Config;
use sanctum_infra::identity::IdentityAdapter;

/// Run the status command.
pub async fn run(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let home = Config::home_dir();

    println!("[sanctum] system status");
    println!(
        "  profile:  {}",
        if home.exists() {
            "initialized"
        } else {
            "not initialized (run `sanctum init`)"
        }
    );
    println!("  home:     {}", home.display());
    println!("  alias:    {}", config.identity.alias);

    match IdentityAdapter::load_from_disk() {
        Ok(id) => println!(
            "  identity: Ed25519, fingerprint {}",
            id.fingerprint().short()
        ),
        Err(_) => println!("  identity: none"),
    }

    println!(
        "  tor:      socks=127.0.0.1:{}, control=127.0.0.1:{} (connectivity not checked)",
        config.tor.socks_port, config.tor.control_port
    );
    println!(
        "  host:     port={}, mode=ephemeral",
        config.host.listen_port
    );
    Ok(())
}
