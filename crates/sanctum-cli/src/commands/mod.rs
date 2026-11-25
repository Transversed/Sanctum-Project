//! CLI command implementations.

pub mod chat;
pub mod chat_loop;
pub mod export_manifest;
pub mod host;
pub mod identity;
pub mod init;
pub mod join;
pub mod read;
pub mod room;
pub mod send;
pub mod status;

/// Error returned by commands that exist in the CLI surface but are not
/// implemented yet. Failing loudly beats pretending to succeed.
pub fn not_implemented(what: &str) -> Box<dyn std::error::Error> {
    format!("`sanctum {what}` is not implemented in v0.1.1").into()
}
