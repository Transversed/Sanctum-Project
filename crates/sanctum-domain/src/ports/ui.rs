//! User interface port (terminal, TUI, or mock for tests).

use crate::entities::member::Role;
use crate::errors::SanctumError;

/// Status bar info.
#[derive(Debug, Clone)]
pub struct StatusInfo {
    /// Room name.
    pub room_name: String,
    /// Local user role.
    pub local_role: Role,
    /// Local user alias.
    pub local_alias: String,
    /// Room mode string.
    pub room_mode: String,
    /// Connected peer count.
    pub peer_count: usize,
    /// Tor connected?
    pub tor_connected: bool,
}

/// UI port.
pub trait UiPort: Send + Sync {
    /// Read a line of user input (async blocking).
    fn read_input(&self)
        -> impl std::future::Future<Output = Result<String, SanctumError>> + Send;

    /// Display an incoming message.
    fn print_message(&self, role: &str, sender: &str, content: &str, timestamp: u64);

    /// Display own outgoing message.
    fn print_own_message(&self, role: &str, alias: &str, content: &str, timestamp: u64);

    /// Display a system event (join, leave, etc).
    fn print_system(&self, text: &str);

    /// Display backlog start marker.
    fn print_backlog_start(&self, count: u32);

    /// Display backlog end marker.
    fn print_backlog_end(&self);

    /// Update the status bar.
    fn update_status(&self, status: &StatusInfo);

    /// Initialize terminal (raw mode, etc).
    fn init(&self) -> Result<(), SanctumError>;

    /// Restore terminal to normal state.
    fn cleanup(&self) -> Result<(), SanctumError>;
}