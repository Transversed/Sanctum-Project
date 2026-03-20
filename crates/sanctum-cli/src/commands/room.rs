//! `sanctum room` — room management commands.

use crate::config::Config;
use clap::Subcommand;
use sanctum_domain::entities::invite::InviteToken;
use sanctum_domain::entities::member::{Fingerprint, Role};
use sanctum_domain::entities::room::RoomId;
use sanctum_infra::invite_codec;

#[derive(Subcommand)]
pub enum RoomAction {
    /// List known rooms.
    List,

    /// List members of a room.
    Members {
        /// Room ID.
        room_id: String,
    },

    /// Generate an invite token for a member.
    Invite {
        /// PGP fingerprint of the invitee (40 hex chars).
        fingerprint: String,

        /// .onion address of the host.
        #[arg(long)]
        room_onion: String,

        /// Port of the host.
        #[arg(long, default_value = "9738")]
        room_port: u16,

        /// Room ID.
        #[arg(long)]
        room_id: String,

        /// Host Noise public key (hex, 64 chars).
        #[arg(long, default_value = "")]
        noise_pubkey: String,

        /// Role to assign.
        #[arg(long, default_value = "member")]
        role: String,

        /// Token validity in hours.
        #[arg(long, default_value = "24")]
        ttl_hours: u64,
    },

    /// Revoke a member from a room.
    Revoke {
        room_id: String,
        fingerprint: String,
    },
}

pub async fn run(action: RoomAction, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        RoomAction::List => {
            println!("[sanctum] known rooms:");
            println!("[sanctum] (none — host or join a room first)");
            Ok(())
        }
        RoomAction::Members { room_id } => {
            println!("[sanctum] members of room {}:", short(&room_id));
            println!("[sanctum] (not connected)");
            Ok(())
        }
        RoomAction::Invite {
            fingerprint, room_onion, room_port, room_id,
            noise_pubkey, role, ttl_hours,
        } => {
            run_invite(
                &fingerprint, &room_onion, room_port, &room_id,
                &noise_pubkey, &role, ttl_hours, config,
            )
        }
        RoomAction::Revoke { room_id, fingerprint } => {
            println!("[sanctum] revoking {}...", short(&fingerprint));
            println!("[sanctum] (not implemented)");
            Ok(())
        }
    }
}

fn run_invite(
    fingerprint: &str,
    room_onion: &str,
    room_port: u16,
    room_id: &str,
    noise_pubkey_hex: &str,
    role: &str,
    ttl_hours: u64,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate fingerprint
    let invited_fp = Fingerprint::new(fingerprint)
        .map_err(|e| format!("invalid fingerprint: {e}"))?;

    // Parse role
    let member_role = match role {
        "admin" => Role::Admin,
        _ => Role::Member,
    };

    // Parse room ID
    let rid = RoomId::from_str(room_id)
        .map_err(|e| format!("invalid room ID: {e}"))?;

    let noise_pub = if noise_pubkey_hex.is_empty() {
    std::fs::read("/tmp/sanctum_noise_pub")
    // Read from temp file if available (demo compat)
        .or_else(|_| std::fs::read("/tmp/sanctum_demo_noise_pub"))
        .unwrap_or_else(|_| vec![0u8; 32])
    } else {
        hex_decode(noise_pubkey_hex)?
    };

    // TODO: load real inviter fingerprint from identity
    let inviter_fp = Fingerprint::new("A".repeat(40)).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let token = InviteToken {
        room_id: rid,
        onion_address: room_onion.to_string(),
        port: room_port,
        host_noise_pubkey: noise_pub,
        inviter_fingerprint: inviter_fp,
        invited_fingerprint: invited_fp.clone(),
        role: member_role,
        expires_at: now + (ttl_hours * 3600),
        signature: vec![], // MVP: no PGP signature
    };

    let encoded = invite_codec::encode_invite(&token)?;

    println!("[sanctum] invite generated for {}", invited_fp.short());
    println!("[sanctum] role: {role}");
    println!("[sanctum] expires in: {ttl_hours}h");
    println!();
    println!("[sanctum] ── INVITE TOKEN ──");
    println!("{encoded}");
    println!("[sanctum] ── END TOKEN ──");
    println!();
    println!("[sanctum] share this token with {} via a secure channel", invited_fp.short());
    println!("[sanctum] they join with: sanctum join {}", &encoded[..40.min(encoded.len())]);

    Ok(())
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let clean = hex.trim();
    if clean.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.into()))
        .collect()
}

fn short(s: &str) -> &str {
    if s.len() >= 8 { &s[..8] } else { s }
}