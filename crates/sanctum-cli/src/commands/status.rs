//! `sanctum status` — show system status.

use crate::config::Config;

/// Run the status command.
pub async fn run(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let home = Config::home_dir();
    let profile_exists = home.exists();

    println!("[sanctum] system status");
    println!("  profile:  {}", if profile_exists { "initialized" } else { "not initialized" });
    println!("  home:     {}", home.display());
    println!("  alias:    {}", config.identity.alias);

    // Identity
    let key_path = home.join("keys").join("signing.key");
    if key_path.exists() {
        println!("  identity: imported");
    } else {
        println!("  identity: not imported");
    }

    // Tor
    println!("  tor:      socks=127.0.0.1:{}, control=127.0.0.1:{}",
        config.tor.socks_port, config.tor.control_port);

    // TODO: check actual Tor connectivity
    println!("  tor conn: unknown (not checked)");

    // Host
    println!("  host:     port={}, mode={}", config.host.listen_port, config.host.default_mode);

    Ok(())
}
