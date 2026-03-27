//! `sanctum room` — room management commands.

use crate::config::Config;
use clap::Subcommand;
use sanctum_domain::entities::invite::InviteToken;
use sanctum_domain::entities::member::{Fingerprint, Role};
use sanctum_domain::entities::room::RoomId;
use sanctum_infra::identity_pgp::IdentityAdapter;
use sanctum_infra::invite_codec;

#[derive(Subcommand)]
pub enum RoomAction {
    List,
    Members { room_id: String },
    /// Generate an invite token for a member.
    Invite {
        /// PGP fingerprint of the invitee (40 hex chars).
        fingerprint: String,
        /// .onion address (or 127.0.0.1 for local).
        #[arg(long)]
        room_onion: String,
        /// Port.
        #[arg(long, default_value = "9738")]
        room_port: u16,
        /// Room ID (UUID).
        #[arg(long)]
        room_id: String,
        /// Role to assign.
        #[arg(long, default_value = "member")]
        role: String,
        /// Token validity in hours.
        #[arg(long, default_value = "24")]
        ttl_hours: u64,
    },
    Revoke { room_id: String, fingerprint: String },
}

pub async fn run(action: RoomAction, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        RoomAction::List => {
            println!("[sanctum] known rooms: (none — host or join a room first)");
            Ok(())
        }
        RoomAction::Members { room_id } => {
            println!("[sanctum] members of {}: (not connected)", &room_id[..8.min(room_id.len())]);
            Ok(())
        }
        RoomAction::Invite { fingerprint, room_onion, room_port, room_id, role, ttl_hours } => {
            run_invite(&fingerprint, &room_onion, room_port, &room_id, &role, ttl_hours, config)
        }
        RoomAction::Revoke { room_id: _, fingerprint } => {
            println!("[sanctum] revoking {}... (not implemented)", &fingerprint[..8.min(fingerprint.len())]);
            Ok(())
        }
    }
}

fn run_invite(
    fingerprint: &str, room_onion: &str, room_port: u16,
    room_id: &str, role: &str, ttl_hours: u64, _config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load our identity (inviter)
    let identity = IdentityAdapter::load_from_disk().map_err(|e| {
        format!("{e}\nRun `sanctum init` first.")
    })?;
    let inviter_fp = identity.fingerprint().clone();

    let invited_fp = Fingerprint::new(fingerprint)
        .map_err(|e| format!("invalid fingerprint: {e}"))?;

    let member_role = match role { "admin" => Role::Admin, _ => Role::Member };

    let rid = RoomId::from_str(room_id)
        .map_err(|e| format!("invalid room ID: {e}"))?;

    // Read host Noise public key
    let noise_pub = std::fs::read("/tmp/sanctum_noise_pub")
        .or_else(|_| std::fs::read("/tmp/sanctum_demo_noise_pub"))
        .unwrap_or_else(|_| {
            eprintln!("[sanctum] warning: could not read host Noise key, using empty");
            vec![0u8; 32]
        });

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let token = InviteToken {
        room_id: rid,
        onion_address: room_onion.to_string(),
        port: room_port,
        host_noise_pubkey: noise_pub,
        inviter_fingerprint: inviter_fp.clone(),
        invited_fingerprint: invited_fp.clone(),
        role: member_role,
        expires_at: now + (ttl_hours * 3600),
        signature: vec![],
    };

    let encoded = invite_codec::encode_invite(&token)?;

    println!("[sanctum] invite generated");
    println!("[sanctum] from: {} ({})", inviter_fp.short(), "you");
    println!("[sanctum] to: {}", invited_fp.short());
    println!("[sanctum] role: {role}");
    println!("[sanctum] expires in: {ttl_hours}h");
    println!();
    println!("── INVITE TOKEN ──");
    println!("{encoded}");
    println!("── END TOKEN ──");
    println!();
    println!("[sanctum] the invitee joins with: sanctum join <token>");

    Ok(())
}