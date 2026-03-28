//! Terminal line renderer — UiPort implementation.
//!
//! MVP renderer using crossterm for line-based interactive chat.
//! Supports colored output, system messages, and a simple status bar.

use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::ui::{StatusInfo, UiPort};

use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetForegroundColor};
use std::io::Write;
use std::sync::Mutex;

/// Terminal line renderer.
pub struct TerminalLineRenderer {
    /// Buffered stdout (Mutex for Send + Sync).
    stdout: Mutex<std::io::Stdout>,
}

impl TerminalLineRenderer {
    /// Create a new terminal renderer.
    pub fn new() -> Self {
        Self {
            stdout: Mutex::new(std::io::stdout()),
        }
    }

    /// Write colored text to stdout.
    #[allow(dead_code)]
    fn write_colored(&self, color: Color, text: &str) {
        if let Ok(mut out) = self.stdout.lock() {
            let _ = write!(out, "{}{}{}", SetForegroundColor(color), text, ResetColor);
            let _ = out.flush();
        }
    }

    /// Format a timestamp to HH:MM.
    fn format_time(timestamp: u64) -> String {
        let secs = timestamp % 86400;
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        format!("{hours:02}:{mins:02}")
    }
}

impl Default for TerminalLineRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl UiPort for TerminalLineRenderer {
    #[allow(clippy::manual_async_fn)]
    fn read_input(&self) -> impl std::future::Future<Output = Result<String, SanctumError>> + Send {
        async {
            let (tx, rx) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                let mut line = String::new();
                match std::io::stdin().read_line(&mut line) {
                    Ok(_) => { let _ = tx.send(Ok(line)); }
                    Err(e) => { let _ = tx.send(Err(SanctumError::ConnectionLost(e.to_string()))); }
                }
            });
            rx.await.unwrap_or_else(|_| Err(SanctumError::ConnectionLost("input cancelled".into())))
        }
    }

    fn print_message(&self, _role: &str, sender: &str, content: &str, timestamp: u64) {
        let time = Self::format_time(timestamp);
        if let Ok(mut out) = self.stdout.lock() {
            let _ = writeln!(
                out,
                "{dim}[{time}]{reset} {cyan}{bold}{sender}{reset}: {content}",
                dim = SetAttribute(Attribute::Dim),
                reset = ResetColor,
                cyan = SetForegroundColor(Color::Cyan),
                bold = SetAttribute(Attribute::Bold),
            );
            let _ = out.flush();
        }
    }

    fn print_own_message(&self, _role: &str, alias: &str, content: &str, timestamp: u64) {
        let time = Self::format_time(timestamp);
        if let Ok(mut out) = self.stdout.lock() {
            let _ = writeln!(
                out,
                "{dim}[{time}]{reset} {green}{bold}{alias}{reset}: {content}",
                dim = SetAttribute(Attribute::Dim),
                reset = ResetColor,
                green = SetForegroundColor(Color::Green),
                bold = SetAttribute(Attribute::Bold),
            );
            let _ = out.flush();
        }
    }

    fn print_system(&self, text: &str) {
        if let Ok(mut out) = self.stdout.lock() {
            let _ = writeln!(
                out,
                "{yellow}{text}{reset}",
                yellow = SetForegroundColor(Color::DarkYellow),
                reset = ResetColor,
            );
            let _ = out.flush();
        }
    }

    fn print_backlog_start(&self, count: u32) {
        self.print_system(&format!("── backlog ({count} messages) ──"));
    }

    fn print_backlog_end(&self) {
        self.print_system("── end of backlog ──");
    }

    fn update_status(&self, status: &StatusInfo) {
        if let Ok(mut out) = self.stdout.lock() {
            let tor_indicator = if status.tor_connected { "🧅" } else { "⚠" };
            let _ = writeln!(
                out,
                "{dim}[{room} | {mode} | {role} | {peers} peers | {tor}]{reset}",
                dim = SetAttribute(Attribute::Dim),
                room = status.room_name,
                mode = status.room_mode,
                role = status.local_role,
                peers = status.peer_count,
                tor = tor_indicator,
                reset = ResetColor,
            );
            let _ = out.flush();
        }
    }

    fn init(&self) -> Result<(), SanctumError> {
        if let Ok(mut out) = self.stdout.lock() {
            let _ = writeln!(out);
            let _ = write!(
                out,
                "{bold}{cyan}Sanctum{reset} — encrypted chat session\n\n",
                bold = SetAttribute(Attribute::Bold),
                cyan = SetForegroundColor(Color::Cyan),
                reset = ResetColor,
            );
            let _ = out.flush();
        }
        Ok(())
    }

    fn cleanup(&self) -> Result<(), SanctumError> {
        if let Ok(mut out) = self.stdout.lock() {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{dim}Session ended. Secrets cleared.{reset}",
                dim = SetAttribute(Attribute::Dim),
                reset = ResetColor,
            );
            let _ = out.flush();
        }
        Ok(())
    }
}

/// Null UI adapter for non-interactive mode (send/read commands).
pub struct NullUiAdapter;

impl UiPort for NullUiAdapter {
    #[allow(clippy::manual_async_fn)]
    fn read_input(&self) -> impl std::future::Future<Output = Result<String, SanctumError>> + Send {
        async { Err(SanctumError::ConnectionLost("non-interactive mode".into())) }
    }
    fn print_message(&self, _: &str, _: &str, _: &str, _: u64) {}
    fn print_own_message(&self, _: &str, _: &str, _: &str, _: u64) {}
    fn print_system(&self, _: &str) {}
    fn print_backlog_start(&self, _: u32) {}
    fn print_backlog_end(&self) {}
    fn update_status(&self, _: &StatusInfo) {}
    fn init(&self) -> Result<(), SanctumError> { Ok(()) }
    fn cleanup(&self) -> Result<(), SanctumError> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sanctum_domain::entities::member::Role;

    #[test]
    fn format_time() {
        assert_eq!(TerminalLineRenderer::format_time(0), "00:00");
        assert_eq!(TerminalLineRenderer::format_time(3661), "01:01");
        assert_eq!(TerminalLineRenderer::format_time(86399), "23:59");
    }

    #[test]
    fn null_adapter_works() {
        let ui = NullUiAdapter;
        ui.print_message("", "alice", "hello", 0);
        ui.print_system("test");
        ui.init().unwrap();
        ui.cleanup().unwrap();
    }

    #[test]
    fn terminal_init_cleanup() {
        // Just verify it doesn't panic (no real terminal in CI)
        let renderer = TerminalLineRenderer::new();
        renderer.init().unwrap();
        renderer.cleanup().unwrap();
    }

    #[test]
    fn status_format() {
        let renderer = TerminalLineRenderer::new();
        let status = StatusInfo {
            room_name: "test-room".into(),
            local_role: Role::Owner,
            local_alias: "alice".into(),
            room_mode: "ephemeral".into(),
            peer_count: 3,
            tor_connected: true,
        };
        // Just verify it doesn't panic
        renderer.update_status(&status);
    }
}