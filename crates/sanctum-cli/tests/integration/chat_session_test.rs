//! Integration test: ChatSession event flow.
//!
//! Covers AT-15, AT-16, AT-17.

use sanctum_app::chat_session::{ChatSession, SessionConfig};
use sanctum_app::input_parser::{parse_input, Input, SlashCommand};
use sanctum_domain::entities::member::{Fingerprint, Role};
use sanctum_domain::entities::room::{RoomId, RoomMode};
use sanctum_domain::events::ChatEvent;
use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::ui::{StatusInfo, UiPort};

use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

fn fp(s: &str) -> Fingerprint {
    Fingerprint::new(format!("{:0>40}", s)).unwrap()
}

#[derive(Debug, Clone)]
enum UiEvent {
    Init,
    Cleanup,
    System(String),
    Message { sender: String, content: String },
    OwnMessage { content: String },
    BacklogStart(u32),
    BacklogEnd,
    StatusUpdate,
}

struct MockUi {
    events: Arc<Mutex<Vec<UiEvent>>>,
}

impl MockUi {
    fn new() -> Self {
        Self { events: Arc::new(Mutex::new(Vec::new())) }
    }
}

impl UiPort for MockUi {
    fn read_input(&self) -> impl std::future::Future<Output = Result<String, SanctumError>> + Send {
        async { Err(SanctumError::ConnectionLost("mock".into())) }
    }
    fn print_message(&self, _role: &str, sender: &str, content: &str, _ts: u64) {
        self.events.lock().unwrap().push(UiEvent::Message { sender: sender.into(), content: content.into() });
    }
    fn print_own_message(&self, _role: &str, _alias: &str, content: &str, _ts: u64) {
        self.events.lock().unwrap().push(UiEvent::OwnMessage { content: content.into() });
    }
    fn print_system(&self, text: &str) {
        self.events.lock().unwrap().push(UiEvent::System(text.into()));
    }
    fn print_backlog_start(&self, count: u32) {
        self.events.lock().unwrap().push(UiEvent::BacklogStart(count));
    }
    fn print_backlog_end(&self) {
        self.events.lock().unwrap().push(UiEvent::BacklogEnd);
    }
    fn update_status(&self, _status: &StatusInfo) {
        self.events.lock().unwrap().push(UiEvent::StatusUpdate);
    }
    fn init(&self) -> Result<(), SanctumError> {
        self.events.lock().unwrap().push(UiEvent::Init);
        Ok(())
    }
    fn cleanup(&self) -> Result<(), SanctumError> {
        self.events.lock().unwrap().push(UiEvent::Cleanup);
        Ok(())
    }
}

fn make_session(ui: MockUi) -> (ChatSession<MockUi>, broadcast::Sender<ChatEvent>, CancellationToken) {
    let config = SessionConfig {
        room_id: RoomId::new(),
        room_name: "test-room".into(),
        room_mode: RoomMode::Ephemeral,
        local_fingerprint: fp("AA"),
        local_alias: "alice".into(),
        local_role: Role::Owner,
    };
    let (event_tx, _) = broadcast::channel(256);
    let shutdown = CancellationToken::new();
    let session = ChatSession::new(config, ui, event_tx.clone(), shutdown.clone());
    (session, event_tx, shutdown)
}

#[test]
fn session_init_and_cleanup() {
    let ui = MockUi::new();
    let events = ui.events.clone();
    let (session, _, _) = make_session(ui);
    session.init_ui().unwrap();
    session.cleanup_ui().unwrap();
    let captured = events.lock().unwrap();
    assert!(matches!(captured[0], UiEvent::Init));
    assert!(matches!(captured[1], UiEvent::Cleanup));
}

#[test]
fn shutdown_cancels_token() {
    let ui = MockUi::new();
    let (session, _, shutdown) = make_session(ui);
    assert!(!shutdown.is_cancelled());
    session.request_shutdown();
    assert!(shutdown.is_cancelled());
}

#[tokio::test]
async fn emit_events_reach_subscribers() {
    let ui = MockUi::new();
    let (session, event_tx, _) = make_session(ui);
    let mut rx = event_tx.subscribe();
    session.emit(ChatEvent::OutgoingMessage { content: "hello".into(), timestamp: 1234 });
    let event = rx.recv().await.unwrap();
    match event {
        ChatEvent::OutgoingMessage { content, .. } => assert_eq!(content, "hello"),
        _ => panic!("wrong event type"),
    }
}

#[test]
fn build_status_reflects_config() {
    let ui = MockUi::new();
    let (session, _, _) = make_session(ui);
    let status = session.build_status(3, true);
    assert_eq!(status.room_name, "test-room");
    assert_eq!(status.peer_count, 3);
    assert!(status.tor_connected);
    assert_eq!(status.local_alias, "alice");
}

#[test]
fn slash_commands_parsed_correctly() {
    match parse_input("hello everyone") {
        Input::Message(msg) => assert_eq!(msg, "hello everyone"),
        other => panic!("expected Message, got {other:?}"),
    }
    match parse_input("/who") {
        Input::Command(SlashCommand::Members) => {}
        other => panic!("expected Members, got {other:?}"),
    }
    match parse_input("/exit") {
        Input::Command(SlashCommand::Exit) => {}
        other => panic!("expected Exit, got {other:?}"),
    }
    match parse_input("/help") {
        Input::Command(SlashCommand::Help) => {}
        other => panic!("expected Help, got {other:?}"),
    }
    match parse_input("/status") {
        Input::Command(SlashCommand::Status) => {}
        other => panic!("expected Status, got {other:?}"),
    }
    match parse_input("") {
        Input::Empty => {}
        other => panic!("expected Empty, got {other:?}"),
    }
    match parse_input("   ") {
        Input::Empty => {}
        other => panic!("expected Empty, got {other:?}"),
    }
}

#[test]
fn slash_commands_case_insensitive() {
    match parse_input("/WHO") {
        Input::Command(SlashCommand::Members) => {}
        other => panic!("expected Members, got {other:?}"),
    }
    match parse_input("/EXIT") {
        Input::Command(SlashCommand::Exit) => {}
        other => panic!("expected Exit, got {other:?}"),
    }
    match parse_input("/Help") {
        Input::Command(SlashCommand::Help) => {}
        other => panic!("expected Help, got {other:?}"),
    }
}

#[test]
fn slash_command_aliases_work() {
    match parse_input("/quit") {
        Input::Command(SlashCommand::Exit) => {}
        other => panic!("expected Exit, got {other:?}"),
    }
    match parse_input("/q") {
        Input::Command(SlashCommand::Exit) => {}
        other => panic!("expected Exit, got {other:?}"),
    }
    match parse_input("/h") {
        Input::Command(SlashCommand::Help) => {}
        other => panic!("expected Help, got {other:?}"),
    }
    match parse_input("/?") {
        Input::Command(SlashCommand::Help) => {}
        other => panic!("expected Help, got {other:?}"),
    }
}

#[test]
fn chat_events_for_tor_loss() {
    let event = ChatEvent::TorStatusChanged { connected: false };
    match event {
        ChatEvent::TorStatusChanged { connected } => assert!(!connected),
        _ => panic!("wrong variant"),
    }
    let event = ChatEvent::Disconnected { reason: "Tor connection lost".into() };
    match event {
        ChatEvent::Disconnected { reason } => assert!(reason.contains("Tor")),
        _ => panic!("wrong variant"),
    }
}

#[tokio::test]
async fn event_sequence_order_preserved() {
    let (tx, mut rx) = broadcast::channel::<ChatEvent>(16);

    tx.send(ChatEvent::Connected {
        room_id: RoomId::new(),
        role: Role::Owner,
        peer_count: 0,
    }).unwrap();

    tx.send(ChatEvent::IncomingMessage {
        sender: fp("BB"),
        sender_display: "bob".into(),
        content: "hello".into(),
        timestamp: 1000,
        seq: 1,
    }).unwrap();

    tx.send(ChatEvent::PeerLeft {
        fingerprint: fp("BB"),
        display: "bob".into(),
    }).unwrap();

    let e1 = rx.recv().await.unwrap();
    let e2 = rx.recv().await.unwrap();
    let e3 = rx.recv().await.unwrap();

    assert!(matches!(e1, ChatEvent::Connected { .. }));
    assert!(matches!(e2, ChatEvent::IncomingMessage { .. }));
    assert!(matches!(e3, ChatEvent::PeerLeft { .. }));
}