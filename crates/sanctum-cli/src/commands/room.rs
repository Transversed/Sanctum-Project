//! `sanctum room` — room management commands.

use crate::config::Config;
use clap::Subcommand;

/// Room subcommands.
#[derive(Subcommand)]
pub enum RoomAction {
    /// List known rooms.
    List,

    /// List members of a room.
    Members {
        /// Room ID.
        room_id: String,
    },

    /// Invite a member to a room.
    Invite {
        /// Room ID.
        room_id: String,
        /// PGP fingerprint of the invitee.
        fingerprint: String,
        /// Role to assign.
        #[arg(long, default_value = "member")]
        role: String,
    },

    /// Revoke a member from a room.
    Revoke {
        /// Room ID.
        room_id: String,
        /// PGP fingerprint to revoke.
        fingerprint: String,
    },
}

/// Run the room command.
pub async fn run(action: RoomAction, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        RoomAction::List => {
            // TODO: load rooms from storage
            println!("[sanctum] known rooms:");
            println!("[sanctum] (none — join or host a room first)");
            Ok(())
        }
        RoomAction::Members { room_id } => {
            // TODO: load room, list members
            println!("[sanctum] members of room {}:", &room_id[..8.min(room_id.len())]);
            println!("[sanctum] (not connected to room)");
            Ok(())
        }
        RoomAction::Invite { room_id, fingerprint, role } => {
            // TODO: validate inputs, generate invite token
            println!("[sanctum] generating invite for {} as {role}...", &fingerprint[..8.min(fingerprint.len())]);
            println!("[sanctum] invite token: <not implemented>");
            println!("[sanctum] share this token with the invitee via a secure channel");
            Ok(())
        }
        RoomAction::Revoke { room_id, fingerprint } => {
            // TODO: validate, revoke member
            println!("[sanctum] revoking {}...", &fingerprint[..8.min(fingerprint.len())]);
            println!("[sanctum] member revoked (not implemented)");
            Ok(())
        }
    }
}