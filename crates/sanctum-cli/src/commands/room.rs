//! `sanctum room` — room management commands.

use crate::config::Config;
use clap::Subcommand;
use sanctum_domain::entities::member::{Fingerprint, Role};
use sanctum_domain::entities::room::RoomId;
use sanctum_infra::identity::IdentityAdapter;
use sanctum_infra::invite_codec;

#[derive(Subcommand)]
pub enum RoomAction {
    List,
    Members {
        room_id: String,
    },
    /// Generate an invite token for a member.
    Invite {
        /// Fingerprint of the invitee (40 hex chars).
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
        /// Host Noise public key, as printed by `sanctum host create`.
        #[arg(long)]
        host_key: String,
    },
    Revoke {
        room_id: String,
        fingerprint: String,
    },
}

pub async fn run(action: RoomAction, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        RoomAction::List => Err(super::not_implemented("room list")),
        RoomAction::Members { .. } => Err(super::not_implemented("room members")),
        RoomAction::Invite {
            fingerprint,
            room_onion,
            room_port,
            room_id,
            role,
            ttl_hours,
            host_key,
        } => run_invite(
            &fingerprint,
            &room_onion,
            room_port,
            &room_id,
            &role,
            ttl_hours,
            &host_key,
            config,
        ),
        RoomAction::Revoke { .. } => Err(super::not_implemented("room revoke")),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_invite(
    fingerprint: &str,
    room_onion: &str,
    room_port: u16,
    room_id: &str,
    role: &str,
    ttl_hours: u64,
    host_key: &str,
    _config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load our identity (inviter)
    let identity =
        IdentityAdapter::load_from_disk().map_err(|e| format!("{e}\nRun `sanctum init` first."))?;
    let inviter_fp = identity.fingerprint().clone();

    let invited_fp =
        Fingerprint::new(fingerprint).map_err(|e| format!("invalid fingerprint: {e}"))?;

    let member_role = match role {
        "admin" => Role::Admin,
        _ => Role::Member,
    };

    let rid = room_id
        .parse::<RoomId>()
        .map_err(|e| format!("invalid room ID: {e}"))?;

    // Host Noise public key: explicit, validated, never a silent fallback.
    let noise_pub = invite_codec::decode_host_key(host_key)?;

    let target = invite_codec::InviteTarget {
        room_id: rid,
        onion_address: room_onion.to_string(),
        port: room_port,
        host_noise_pubkey: noise_pub,
    };
    let expires_at = sanctum_app::auth_service::unix_now() + ttl_hours * 3600;
    let token = invite_codec::create_signed_invite(
        &identity,
        &target,
        invited_fp.clone(),
        member_role,
        expires_at,
    )?;

    let encoded = invite_codec::encode_invite(&token)?;

    println!("[sanctum] invite generated");
    println!("[sanctum] from: {} (you)", inviter_fp.short());
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
