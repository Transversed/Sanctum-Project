//! Configuration loading from file, env vars, and defaults.
//!
//! Precedence: CLI flags > env vars (SANCTUM_*) > config.toml > defaults.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Identity settings.
    #[serde(default)]
    pub identity: IdentityConfig,

    /// Tor settings.
    #[serde(default)]
    pub tor: TorConfig,

    /// Network settings.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Host settings.
    #[serde(default)]
    pub host: HostConfig,

    /// Storage settings.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Logging settings.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Chat settings.
    #[serde(default)]
    pub chat: ChatConfig,

    /// UI settings.
    #[serde(default)]
    pub ui: UiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// PGP key ID.
    #[serde(default)]
    pub pgp_key_id: String,
    /// Display alias.
    #[serde(default = "default_alias")]
    pub alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    /// Control port.
    #[serde(default = "default_control_port")]
    pub control_port: u16,
    /// Auth method.
    #[serde(default = "default_control_auth")]
    pub control_auth: String,
    /// SOCKS port.
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Keepalive interval in seconds.
    #[serde(default = "default_ping_interval")]
    pub ping_interval: u64,
    /// Timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    /// Default room mode.
    #[serde(default = "default_mode")]
    pub default_mode: String,
    /// Listen port.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Max connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Data directory.
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    /// Max DB size in MiB.
    #[serde(default = "default_db_max_size")]
    pub db_max_size_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log output.
    #[serde(default = "default_log_output")]
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatConfig {
    /// Auto-open chat after join.
    #[serde(default = "default_true")]
    pub auto_chat_on_join: bool,
    /// Backlog messages to display.
    #[serde(default = "default_backlog_display")]
    pub backlog_display: u32,
    /// Timestamp format.
    #[serde(default = "default_timestamp_format")]
    pub timestamp_format: String,
    /// Show system events.
    #[serde(default = "default_true")]
    pub show_system_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Show banner.
    #[serde(default = "default_true")]
    pub banner: bool,
    /// Use colors.
    #[serde(default = "default_true")]
    pub color: bool,
}

// Defaults
fn default_alias() -> String { "anon".into() }
fn default_control_port() -> u16 { 9051 }
fn default_control_auth() -> String { "cookie".into() }
fn default_socks_port() -> u16 { 9050 }
fn default_ping_interval() -> u64 { 60 }
fn default_timeout() -> u64 { 180 }
fn default_mode() -> String { "ephemeral".into() }
fn default_listen_port() -> u16 { 9738 }
fn default_max_connections() -> u16 { 20 }
fn default_data_dir() -> String { "~/.sanctum/data".into() }
fn default_db_max_size() -> u32 { 256 }
fn default_log_level() -> String { "off".into() }
fn default_log_output() -> String { "stdout".into() }
fn default_true() -> bool { true }
fn default_backlog_display() -> u32 { 50 }
fn default_timestamp_format() -> String { "%H:%M".into() }

impl Default for IdentityConfig {
    fn default() -> Self { Self { pgp_key_id: String::new(), alias: default_alias() } }
}
impl Default for TorConfig {
    fn default() -> Self { Self { control_port: default_control_port(), control_auth: default_control_auth(), socks_port: default_socks_port() } }
}
impl Default for NetworkConfig {
    fn default() -> Self { Self { ping_interval: default_ping_interval(), timeout: default_timeout() } }
}
impl Default for HostConfig {
    fn default() -> Self { Self { default_mode: default_mode(), listen_port: default_listen_port(), max_connections: default_max_connections() } }
}
impl Default for StorageConfig {
    fn default() -> Self { Self { data_dir: default_data_dir(), db_max_size_mb: default_db_max_size() } }
}
impl Default for LoggingConfig {
    fn default() -> Self { Self { level: default_log_level(), output: default_log_output() } }
}
impl Default for ChatConfig {
    fn default() -> Self { Self { auto_chat_on_join: true, backlog_display: default_backlog_display(), timestamp_format: default_timestamp_format(), show_system_events: true } }
}
impl Default for UiConfig {
    fn default() -> Self { Self { banner: true, color: true } }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            identity: IdentityConfig::default(),
            tor: TorConfig::default(),
            network: NetworkConfig::default(),
            host: HostConfig::default(),
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
            chat: ChatConfig::default(),
            ui: UiConfig::default(),
        }
    }
}

impl Config {
    /// Load config from file, falling back to defaults.
    pub fn load(path: Option<&str>) -> Self {
        let config_path = path
            .map(PathBuf::from)
            .unwrap_or_else(default_config_path);

        match std::fs::read_to_string(&config_path) {
            Ok(contents) => {
                toml::from_str(&contents).unwrap_or_else(|e| {
                    eprintln!("[sanctum] warning: failed to parse config: {e}");
                    Config::default()
                })
            }
            Err(_) => Config::default(),
        }
    }

    /// Sanctum home directory (~/.sanctum/).
    pub fn home_dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".sanctum")
    }

    /// Resolve data directory (expand ~).
    pub fn data_dir(&self) -> PathBuf {
        let dir = self.storage.data_dir.replace('~', &dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .to_string_lossy());
        PathBuf::from(dir)
    }
}

/// Default config file path.
fn default_config_path() -> PathBuf {
    Config::home_dir().join("config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = Config::default();
        assert_eq!(config.tor.socks_port, 9050);
        assert_eq!(config.host.listen_port, 9738);
        assert_eq!(config.chat.backlog_display, 50);
        assert!(config.chat.auto_chat_on_join);
    }

    #[test]
    fn parse_toml() {
        let toml_str = r#"
[identity]
alias = "alice"

[tor]
socks_port = 19050

[chat]
backlog_display = 100
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.identity.alias, "alice");
        assert_eq!(config.tor.socks_port, 19050);
        assert_eq!(config.chat.backlog_display, 100);
    }

    #[test]
    fn load_missing_file_returns_defaults() {
        let config = Config::load(Some("/nonexistent/path.toml"));
        assert_eq!(config.tor.socks_port, 9050);
    }

    #[test]
    fn home_dir_exists() {
        let home = Config::home_dir();
        assert!(home.to_string_lossy().contains("sanctum"));
    }
}