//! Interactive chat session orchestrator.
//!
//! ChatSession coordinates the async loops that make up an interactive
//! chat: reading user input, receiving network messages, rendering
//! events to the UI, and periodic maintenance (backlog GC).

use sanctum_domain::entities::member::{Fingerprint, Role};
use sanctum_domain::entities::room::{RoomId, RoomMode};
use sanctum_domain::errors::SanctumError;
use sanctum_domain::events::ChatEvent;
use sanctum_domain::ports::ui::{StatusInfo, UiPort};

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Chat session configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Room ID.
    pub room_id: RoomId,
    /// Room name.
    pub room_name: String,
    /// Room mode.
    pub room_mode: RoomMode,
    /// Local fingerprint.
    pub local_fingerprint: Fingerprint,
    /// Local alias.
    pub local_alias: String,
    /// Local role.
    pub local_role: Role,
}

/// Interactive chat session.
///
/// Generic over UiPort to allow both real terminal and mock UI in tests.
pub struct ChatSession<U: UiPort> {
    config: SessionConfig,
    ui: U,
    event_tx: broadcast::Sender<ChatEvent>,
    shutdown: CancellationToken,
}

impl<U: UiPort> ChatSession<U> {
    /// Create a new chat session.
    pub fn new(
        config: SessionConfig,
        ui: U,
        event_tx: broadcast::Sender<ChatEvent>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            config,
            ui,
            event_tx,
            shutdown,
        }
    }

    /// Get the event sender (for other tasks to emit events).
    pub fn event_tx(&self) -> broadcast::Sender<ChatEvent> {
        self.event_tx.clone()
    }

    /// Get the cancellation token (for coordinated shutdown).
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Get session config.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Build the initial status info.
    pub fn build_status(&self, peer_count: usize, tor_connected: bool) -> StatusInfo {
        StatusInfo {
            room_name: self.config.room_name.clone(),
            local_role: self.config.local_role,
            local_alias: self.config.local_alias.clone(),
            room_mode: format!("{}", self.config.room_mode),
            peer_count,
            tor_connected,
        }
    }

    /// Initialize the UI.
    pub fn init_ui(&self) -> Result<(), SanctumError> {
        self.ui.init()
    }

    /// Cleanup the UI (restore terminal).
    pub fn cleanup_ui(&self) -> Result<(), SanctumError> {
        self.ui.cleanup()
    }

    /// Emit a ChatEvent.
    pub fn emit(&self, event: ChatEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Request shutdown.
    pub fn request_shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Is shutdown requested?
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown.is_cancelled()
    }

    /// Run the render loop: receive events and display them.
    pub async fn render_loop(&self) {
        let mut rx = self.event_tx.subscribe();

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                event = rx.recv() => {
                    match event {
                        Ok(evt) => self.handle_chat_event(&evt),
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            self.ui.print_system(&format!("⚠ Skipped {n} events"));
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    }

    /// Handle a single chat event by dispatching to the UI.
    fn handle_chat_event(&self, event: &ChatEvent) {
        match event {
            ChatEvent::IncomingMessage {
                sender_display,
                content,
                timestamp,
                ..
            } => {
                self.ui.print_message("", sender_display, content, *timestamp);
            }
            ChatEvent::OutgoingMessage { content, timestamp } => {
                self.ui.print_own_message(
                    "",
                    &self.config.local_alias,
                    content,
                    *timestamp,
                );
            }
            ChatEvent::PeerJoining { display, .. } => {
                self.ui.print_system(&format!("── {display} joining (synchronizing...) ──"));
            }
            ChatEvent::PeerReady { display, .. } => {
                self.ui.print_system(&format!("── {display} ready ──"));
            }
            ChatEvent::PeerLeft { display, .. } => {
                self.ui.print_system(&format!("── {display} left ──"));
            }
            ChatEvent::PeerRevoked { display, .. } => {
                self.ui.print_system(&format!("── {display} was revoked ──"));
            }
            ChatEvent::Connected { peer_count, .. } => {
                self.ui.print_system(&format!(
                    "Connected to {} ({} peers)",
                    self.config.room_name, peer_count
                ));
            }
            ChatEvent::Disconnected { reason } => {
                self.ui.print_system(&format!("Disconnected: {reason}"));
            }
            ChatEvent::BacklogStart { count } => {
                self.ui.print_backlog_start(*count);
            }
            ChatEvent::BacklogEnd => {
                self.ui.print_backlog_end();
            }
            ChatEvent::ProtocolError { message } => {
                self.ui.print_system(&format!("Protocol error: {message}"));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Mock UI that captures all outputs.
    struct MockUi {
        messages: Arc<Mutex<Vec<String>>>,
        system: Arc<Mutex<Vec<String>>>,
    }

    impl MockUi {
        fn new() -> Self {
            Self {
                messages: Arc::new(Mutex::new(Vec::new())),
                system: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl UiPort for MockUi {
        fn read_input(&self) -> impl std::future::Future<Output = Result<String, SanctumError>> + Send {
            async { Ok("/exit".into()) }
        }
        fn print_message(&self, _role: &str, sender: &str, content: &str, _ts: u64) {
            self.messages.lock().unwrap().push(format!("{sender}: {content}"));
        }
        fn print_own_message(&self, _role: &str, alias: &str, content: &str, _ts: u64) {
            self.messages.lock().unwrap().push(format!("{alias}: {content}"));
        }
        fn print_system(&self, text: &str) {
            self.system.lock().unwrap().push(text.to_string());
        }
        fn print_backlog_start(&self, count: u32) {
            self.system.lock().unwrap().push(format!("backlog: {count}"));
        }
        fn print_backlog_end(&self) {
            self.system.lock().unwrap().push("backlog end".into());
        }
        fn update_status(&self, _status: &StatusInfo) {}
        fn init(&self) -> Result<(), SanctumError> { Ok(()) }
        fn cleanup(&self) -> Result<(), SanctumError> { Ok(()) }
    }

    fn test_config() -> SessionConfig {
        SessionConfig {
            room_id: RoomId::new(),
            room_name: "test-room".into(),
            room_mode: RoomMode::Ephemeral,
            local_fingerprint: Fingerprint::new("4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B").unwrap(),
            local_alias: "alice".into(),
            local_role: Role::Owner,
        }
    }

    #[test]
    fn session_creation() {
        let (tx, _rx) = broadcast::channel(16);
        let token = CancellationToken::new();
        let ui = MockUi::new();
        let session = ChatSession::new(test_config(), ui, tx, token);
        assert_eq!(session.config().room_name, "test-room");
        assert!(!session.is_shutdown_requested());
    }

    #[test]
    fn session_shutdown() {
        let (tx, _rx) = broadcast::channel(16);
        let token = CancellationToken::new();
        let ui = MockUi::new();
        let session = ChatSession::new(test_config(), ui, tx, token);
        session.request_shutdown();
        assert!(session.is_shutdown_requested());
    }

    #[test]
    fn handle_incoming_message() {
        let (tx, _rx) = broadcast::channel(16);
        let token = CancellationToken::new();
        let ui = MockUi::new();
        let msgs = ui.messages.clone();
        let session = ChatSession::new(test_config(), ui, tx, token);

        session.handle_chat_event(&ChatEvent::IncomingMessage {
            sender: Fingerprint::new("4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B").unwrap(),
            sender_display: "bob".into(),
            content: "Hello!".into(),
            timestamp: 1700000000,
            seq: 1,
        });

        let captured = msgs.lock().unwrap();
        assert_eq!(captured[0], "bob: Hello!");
    }

    #[test]
    fn handle_peer_events() {
        let (tx, _rx) = broadcast::channel(16);
        let token = CancellationToken::new();
        let ui = MockUi::new();
        let sys = ui.system.clone();
        let session = ChatSession::new(test_config(), ui, tx, token);

        session.handle_chat_event(&ChatEvent::PeerJoining {
            fingerprint: Fingerprint::new("4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B").unwrap(),
            display: "charlie".into(),
        });
        session.handle_chat_event(&ChatEvent::PeerReady {
            fingerprint: Fingerprint::new("4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B").unwrap(),
            display: "charlie".into(),
        });

        let captured = sys.lock().unwrap();
        assert!(captured[0].contains("charlie joining"));
        assert!(captured[1].contains("charlie ready"));
    }

    #[test]
    fn build_status() {
        let (tx, _rx) = broadcast::channel(16);
        let token = CancellationToken::new();
        let ui = MockUi::new();
        let session = ChatSession::new(test_config(), ui, tx, token);

        let status = session.build_status(3, true);
        assert_eq!(status.room_name, "test-room");
        assert_eq!(status.peer_count, 3);
        assert!(status.tor_connected);
    }
}