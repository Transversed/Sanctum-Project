//! `sanctum host` — host a room.
//!
//! Ephemeral rooms (default) live in RAM: the owner's identity is loaded and
//! `--chat` opens the owner's chat on the same machine. Persistent rooms are
//! "headless": the host only knows the owner's *public* key, keeps the room
//! in a sealed store (`~/.sanctum/hosts/<room_id>/`), and the owner connects
//! like any member, from their own machine.

use crate::commands::chat_loop;
use crate::config::Config;
use crate::passphrase;
use clap::{Args, Subcommand};
use sanctum_app::auth_service::AuthService;
use sanctum_app::host_service::HostService;
use sanctum_app::room_service::RoomService;
use sanctum_crypto::sealed::KdfParams;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint};
use sanctum_domain::entities::room::{Room, RoomConfig, RoomId, RoomMode};
use sanctum_domain::events::SanctumEvent;
use sanctum_domain::ports::host_state::HostRoomState;
use sanctum_infra::client_connector::{self, ClientCredentials};
use sanctum_infra::host_listener::HostListener;
use sanctum_infra::host_store::{self, HostKeys, SealedHostStore};
use sanctum_infra::identity::{fingerprint_of_public_key, IdentityAdapter};
use sanctum_infra::invite_codec;
use sanctum_infra::invite_codec::InviteTarget;
use sanctum_infra::tor_control::{TorConfig as InfraTorConfig, TorController};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

type BoxError = Box<dyn std::error::Error>;

/// Arguments of `sanctum host create`.
#[derive(Args)]
pub struct CreateArgs {
    /// Room name.
    pub name: String,
    /// Room mode: `ephemeral` (RAM only) or `persistent` (sealed store,
    /// stable .onion, headless host).
    #[arg(long, default_value = "ephemeral")]
    pub mode: String,
    /// Local relay port (default from config).
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long, default_value = "10")]
    pub max_members: u16,
    #[arg(long, default_value = "500")]
    pub backlog_max: u32,
    #[arg(long, default_value = "72")]
    pub backlog_hours: u32,
    /// Ephemeral mode only: open the interactive chat as the owner.
    #[arg(long)]
    pub chat: bool,
    /// Listen on 127.0.0.1 without creating a Tor hidden service (tests).
    #[arg(long)]
    pub local: bool,
    /// Persistent mode: the owner's Ed25519 public key, as 64 hex characters
    /// or the path of an `identity.pub` file (`sanctum identity show`).
    #[arg(long)]
    pub owner_key: Option<String>,
    /// Persistent mode: alias shown for the owner.
    #[arg(long, default_value = "owner")]
    pub owner_alias: String,
    /// Persistent mode: where room stores live (default from config).
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
}

/// Arguments of `sanctum host start`.
#[derive(Args)]
pub struct StartArgs {
    /// Room id (optional when only one room is stored).
    pub room_id: Option<String>,
    /// Listen on 127.0.0.1 without publishing the onion service (tests).
    #[arg(long)]
    pub local: bool,
    /// Print the .onion address and the owner's invitation command. Off by
    /// default: under a service manager, stdout ends up in the journal.
    #[arg(long)]
    pub show_address: bool,
    /// Where room stores live (default from config).
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum HostAction {
    /// Create and host a room.
    Create(CreateArgs),
    /// Host a persistent room again (after a restart).
    Start(StartArgs),
    /// List the persistent rooms stored on this machine (ids only).
    List {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Delete a persistent room's store. Deletion on disk is not secure
    /// (journaling, SSD, snapshots): use full-disk encryption.
    Delete {
        room_id: String,
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Not implemented yet.
    Status,
    /// Not implemented (stop the host with Ctrl-C).
    Stop,
}

pub async fn run(
    action: HostAction,
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(), BoxError> {
    match action {
        HostAction::Create(args) => match parse_mode(&args.mode)? {
            RoomMode::Ephemeral => run_create_ephemeral(args, config, shutdown).await,
            RoomMode::Persistent => run_create_persistent(args, config, shutdown).await,
        },
        HostAction::Start(args) => run_start(args, config, shutdown).await,
        HostAction::List { data_dir } => run_list(&data_dir_of(data_dir, config)),
        HostAction::Delete {
            room_id,
            yes,
            data_dir,
        } => run_delete(&data_dir_of(data_dir, config), &room_id, yes),
        HostAction::Status => Err(crate::commands::not_implemented("host status")),
        HostAction::Stop => Err(crate::commands::not_implemented(
            "host stop (stop the host with Ctrl-C)",
        )),
    }
}

fn parse_mode(mode: &str) -> Result<RoomMode, String> {
    match mode {
        "ephemeral" => Ok(RoomMode::Ephemeral),
        "persistent" => Ok(RoomMode::Persistent),
        other => Err(format!(
            "unknown mode '{other}' (expected: ephemeral or persistent)"
        )),
    }
}

fn room_config(max_members: u16, backlog_max: u32, backlog_hours: u32) -> RoomConfig {
    let mut c = RoomConfig {
        max_members,
        backlog_max_messages: backlog_max,
        backlog_max_age_hours: backlog_hours,
        ..RoomConfig::default()
    };
    c.validate();
    c
}

/// `--data-dir`, else `storage.data_dir` from the config (`~` expanded).
fn data_dir_of(arg: Option<PathBuf>, config: &Config) -> PathBuf {
    arg.unwrap_or_else(|| {
        let raw = &config.storage.data_dir;
        match raw.strip_prefix("~/") {
            Some(rest) => dirs::home_dir().unwrap_or_default().join(rest),
            None => PathBuf::from(raw),
        }
    })
}

fn tor_config(config: &Config, hidden_service_port: u16, local_port: u16) -> InfraTorConfig {
    InfraTorConfig {
        socks_addr: format!("127.0.0.1:{}", config.tor.socks_port),
        control_addr: format!("127.0.0.1:{}", config.tor.control_port),
        hidden_service_port,
        local_port,
    }
}

async fn connect_tor(
    config: &Config,
    hidden_service_port: u16,
    local_port: u16,
) -> Result<TorController, BoxError> {
    let mut tc = TorController::new(tor_config(config, hidden_service_port, local_port));
    if let Err(e) = tc.connect().await {
        eprintln!("[sanctum] Tor: {e}");
        return Err(e.into());
    }
    Ok(tc)
}

/// The command printed for someone (the owner included) to get a token.
fn invite_command(who: &str, target: &InviteTarget) -> String {
    format!(
        // `=`: the base64url host key may start with '-'.
        "sanctum room invite {who} --room-onion {} --room-port {} --room-id {} --host-key={}",
        target.onion_address,
        target.port,
        target.room_id.as_str(),
        invite_codec::encode_host_key(&target.host_noise_pubkey),
    )
}

// ── Ephemeral ──

async fn run_create_ephemeral(
    args: CreateArgs,
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(), BoxError> {
    if args.owner_key.is_some() {
        return Err("--owner-key is for persistent rooms (--mode persistent)".into());
    }
    let name = args.name.as_str();
    let room_mode = RoomMode::Ephemeral;

    // Load real identity
    let identity = IdentityAdapter::load_from_disk(passphrase::read_existing()?.as_bytes())
        .map_err(|e| format!("{e}\nRun `sanctum init --alias <name>` first."))?;
    let identity = Arc::new(identity);
    let owner_fp = identity.fingerprint().clone();
    let alias = config.identity.alias.clone();
    println!("[sanctum] identity: {} ({})", alias, owner_fp.short());

    let listen_port = args.port.unwrap_or(config.host.listen_port);

    // Noise keypair
    let (noise_priv, noise_pub) = sanctum_infra::noise_keygen()?;

    // Room
    let mut room_svc = RoomService::new();
    let owner_alias =
        DisplayAlias::new(&alias).unwrap_or_else(|_| DisplayAlias::new("host").unwrap());
    room_svc.create_room(
        name,
        room_mode,
        room_config(args.max_members, args.backlog_max, args.backlog_hours),
        owner_fp.clone(),
        identity.public_key_bytes(),
        owner_alias,
    )?;
    let room = room_svc.room()?.clone();
    println!("[sanctum] room '{}' created ({})", room.name(), room_mode);

    // Bind first: with --port 0 the OS picks the port, and Tor must map to
    // the real one. The relay only ever listens on loopback.
    let tcp_listener = tokio::net::TcpListener::bind(("127.0.0.1", listen_port)).await?;
    let local_port = tcp_listener.local_addr()?.port();
    let bind_addr = format!("127.0.0.1:{local_port}");
    let mut tor = if args.local {
        println!("[sanctum] local mode (no Tor)");
        TorController::mock()
    } else {
        connect_tor(config, listen_port.max(1), local_port).await?
    };

    let hs = tor.create_hidden_service().await?;
    if !args.local {
        println!("[sanctum] hidden service: {}:{}", hs.onion_address, hs.port);
    }
    println!("[sanctum] relay on {bind_addr}");

    // Relay
    let (event_tx, _) = broadcast::channel::<SanctumEvent>(256);
    let host_svc = HostService::new(room.clone(), event_tx);
    let listener = HostListener::new(
        bind_addr.clone(),
        host_svc,
        noise_pub.clone(),
        noise_priv,
        shutdown.clone(),
    );
    let relay_handle = tokio::spawn(async move {
        if let Err(e) = listener.serve(tcp_listener).await {
            eprintln!("[sanctum] relay: {e}");
        }
    });

    // Port members connect to: the onion virtual port, or the local port.
    let target = InviteTarget {
        room_id: room.id().clone(),
        onion_address: if args.local {
            "127.0.0.1".to_string()
        } else {
            hs.onion_address.clone()
        },
        port: if args.local { local_port } else { hs.port },
        host_noise_pubkey: noise_pub.clone(),
    };
    println!();
    println!("[sanctum] your fingerprint (share with invitees):");
    println!("  {}", owner_fp.as_str());
    println!();
    println!("[sanctum] to invite someone: type `/invite <their_fingerprint>` in the chat,");
    println!("[sanctum] or run as the owner, in another terminal:");
    println!("  {}", invite_command("<their_fingerprint>", &target));
    println!();

    if args.chat {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        let creds = ClientCredentials {
            identity: identity.as_ref(),
            display_alias: &alias,
            invite_token: None,
        };
        let session = client_connector::connect_and_auth(&bind_addr, &creds, &noise_pub).await?;

        println!("[sanctum] connected as owner (Noise OK)");
        println!("[sanctum] type messages or /exit to quit");
        println!("──────────────────────────────────────────────");

        let chat_cfg = chat_loop::ChatConfig {
            room_name: room.name().to_string(),
            room_mode: room_mode.to_string(),
            tor_connected: !args.local,
            inviter: Some(chat_loop::InviteIssuer {
                identity: identity.clone(),
                target,
            }),
        };
        chat_loop::run(
            session.transport,
            identity.clone(),
            alias,
            shutdown.clone(),
            chat_cfg,
        )
        .await;
    } else {
        println!("[sanctum] relay running. Ctrl-C to stop.");
        shutdown.cancelled().await;
    }

    let _ = tor.destroy_hidden_service().await;
    shutdown.cancel();
    let _ = relay_handle.await;
    println!("[sanctum] host stopped.");
    Ok(())
}

// ── Persistent ──

/// `--owner-key`: 64 hex characters, or a file holding the raw 32-byte key
/// (`~/.sanctum/keys/identity.pub`) or its hex form.
fn parse_owner_key(arg: &str) -> Result<(Vec<u8>, Fingerprint), BoxError> {
    let from_hex = |s: &str| -> Option<Vec<u8>> {
        let s = s.trim();
        (s.len() == 64)
            .then(|| {
                (0..64)
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
                    .collect::<Option<Vec<u8>>>()
            })
            .flatten()
    };
    let key = match from_hex(arg) {
        Some(k) => k,
        None => {
            let bytes = std::fs::read(arg).map_err(|e| {
                format!("--owner-key: neither 64 hex characters nor a readable file ({e})")
            })?;
            if bytes.len() == 32 {
                bytes
            } else {
                from_hex(&String::from_utf8_lossy(&bytes))
                    .ok_or("--owner-key: the file holds neither 32 bytes nor 64 hex characters")?
            }
        }
    };
    let fp = fingerprint_of_public_key(&key)
        .map_err(|_| "--owner-key: not a valid Ed25519 public key")?;
    Ok((key, fp))
}

/// Shared by `create` and `start`: serve a persistent room until Ctrl-C.
struct PersistentHost {
    store: SealedHostStore,
    room: Room,
    auth: AuthService,
    tcp_listener: tokio::net::TcpListener,
    tor: Option<TorController>,
}

async fn serve_persistent(
    host: PersistentHost,
    shutdown: CancellationToken,
) -> Result<(), BoxError> {
    let PersistentHost {
        store,
        room,
        auth,
        tcp_listener,
        mut tor,
    } = host;
    let bind_addr = format!("127.0.0.1:{}", tcp_listener.local_addr()?.port());
    let (noise_pub, noise_priv) = {
        let k = store.keys();
        (k.noise_public.clone(), k.noise_private.clone())
    };
    let (event_tx, _) = broadcast::channel::<SanctumEvent>(256);
    let listener = HostListener::new(
        bind_addr.clone(),
        HostService::new(room, event_tx),
        noise_pub,
        noise_priv,
        shutdown.clone(),
    )
    .with_persistence(Arc::new(store), auth);
    let storage_failed = listener.storage_failure();
    let relay = tokio::spawn(async move {
        if let Err(e) = listener.serve(tcp_listener).await {
            eprintln!("[sanctum] relay: {e}");
        }
    });
    println!("[sanctum] relay on {bind_addr}");
    println!("[sanctum] relay running. Ctrl-C to stop.");
    shutdown.cancelled().await;

    if let Some(tor) = tor.as_mut() {
        let _ = tor.destroy_hidden_service().await;
    }
    let _ = relay.await;
    if storage_failed.load(Ordering::SeqCst) {
        return Err("the host state could not be saved: host stopped (check the disk)".into());
    }
    println!("[sanctum] host stopped.");
    Ok(())
}

async fn run_create_persistent(
    args: CreateArgs,
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(), BoxError> {
    if args.chat {
        return Err(
            "--chat is not available for persistent rooms: the host holds no \
                    identity. Connect as the owner from your machine with `sanctum join`."
                .into(),
        );
    }
    let owner_key = args.owner_key.as_deref().ok_or(
        "persistent rooms need --owner-key (the owner's public key, see `sanctum identity show`)",
    )?;
    let (owner_pk, owner_fp) = parse_owner_key(owner_key)?;
    let owner_alias =
        DisplayAlias::new(&args.owner_alias).map_err(|e| format!("--owner-alias: {e}"))?;
    let data_dir = data_dir_of(args.data_dir, config);
    let pass = passphrase::read_host_new()?;

    let mut room_svc = RoomService::new();
    room_svc.create_room(
        &args.name,
        RoomMode::Persistent,
        room_config(args.max_members, args.backlog_max, args.backlog_hours),
        owner_fp.clone(),
        owner_pk,
        owner_alias,
    )?;
    let room = room_svc.room()?.clone();
    let (noise_priv, noise_pub) = sanctum_infra::noise_keygen()?;

    let listen_port = args.port.unwrap_or(config.host.listen_port);
    let tcp_listener = tokio::net::TcpListener::bind(("127.0.0.1", listen_port)).await?;
    let local_port = tcp_listener.local_addr()?.port();
    let hidden_service_port = if listen_port == 0 { 9738 } else { listen_port };
    let (tor, onion) = if args.local {
        println!("[sanctum] local mode (no Tor)");
        (None, None)
    } else {
        let mut tc = connect_tor(config, hidden_service_port, local_port).await?;
        let (hs, key) = tc.create_persistent_hidden_service(None).await?;
        (Some(tc), Some((hs, key)))
    };

    let keys = HostKeys {
        noise_private: noise_priv,
        noise_public: noise_pub.clone(),
        onion_key: onion.as_ref().map(|(_, k)| k.clone()),
        hidden_service_port,
        local_port,
    };
    let state = HostRoomState {
        room: room.clone(),
        revocations: Vec::new(),
        used_invites: Vec::new(),
    };
    println!("[sanctum] sealing the room store (Argon2id)…");
    let store = SealedHostStore::create(
        &data_dir,
        pass.as_bytes(),
        KdfParams::default(),
        keys,
        &state,
    )?;
    drop(pass);

    let target = InviteTarget {
        room_id: room.id().clone(),
        onion_address: match &onion {
            Some((hs, _)) => hs.onion_address.clone(),
            None => "127.0.0.1".into(),
        },
        port: if onion.is_some() {
            hidden_service_port
        } else {
            local_port
        },
        host_noise_pubkey: noise_pub,
    };
    println!("[sanctum] persistent room '{}' created", room.name());
    println!("[sanctum] room id: {}", room.id().as_str());
    if let Some((hs, _)) = &onion {
        println!(
            "[sanctum] hidden service: {}:{} (stable)",
            hs.onion_address, hs.port
        );
    }
    println!(
        "[sanctum] store: {}",
        host_store::room_dir(&data_dir, room.id()).display()
    );
    println!();
    println!(
        "[sanctum] owner {}: on YOUR machine, get your access token with",
        owner_fp.short()
    );
    println!("  {}", invite_command(owner_fp.as_str(), &target));
    println!("[sanctum] then `sanctum join <token>`; invite others from that chat with /invite.");
    println!(
        "[sanctum] after a restart of this machine: sanctum host start {}",
        room.id().as_str()
    );
    println!();

    serve_persistent(
        PersistentHost {
            store,
            room,
            auth: AuthService::new(),
            tcp_listener,
            tor,
        },
        shutdown,
    )
    .await
}

/// The room to start: the one named, or the only one stored.
fn resolve_room(data_dir: &Path, arg: Option<&str>) -> Result<RoomId, BoxError> {
    let rooms = host_store::list_rooms(data_dir)?;
    match arg {
        Some(a) => {
            let matches: Vec<&RoomId> =
                rooms.iter().filter(|r| r.as_str().starts_with(a)).collect();
            match matches.as_slice() {
                [one] => Ok((*one).clone()),
                [] => Err(format!("no stored room matches '{a}' (see `sanctum host list`)").into()),
                _ => Err(format!("'{a}' matches several rooms: give more characters").into()),
            }
        }
        None => match rooms.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err(format!("no persistent room under {}", data_dir.display()).into()),
            _ => Err("several rooms are stored: give the room id (see `sanctum host list`)".into()),
        },
    }
}

async fn run_start(
    args: StartArgs,
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(), BoxError> {
    let data_dir = data_dir_of(args.data_dir, config);
    let room_id = resolve_room(&data_dir, args.room_id.as_deref())?;
    let pass = passphrase::read_host_existing()?;
    println!("[sanctum] unlocking the room store (Argon2id)…");
    let (store, state) = SealedHostStore::open(&data_dir, &room_id, pass.as_bytes())?;
    drop(pass);

    let (local_port, hidden_service_port, onion_key) = {
        let k = store.keys();
        (
            k.local_port,
            k.hidden_service_port,
            k.onion_key.as_ref().map(|k| Zeroizing::new(k.to_string())),
        )
    };
    if onion_key.is_none() && !args.local {
        return Err(
            "this room was created with --local (no onion service): start it with --local".into(),
        );
    }
    let tcp_listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port))
        .await
        .map_err(|e| format!("cannot listen on 127.0.0.1:{local_port} (the room's port): {e}"))?;
    let (tor, onion) = match (&onion_key, args.local) {
        (Some(key), false) => {
            let mut tc = connect_tor(config, hidden_service_port, local_port).await?;
            let (hs, _) = tc.create_persistent_hidden_service(Some(key)).await?;
            (Some(tc), Some(hs))
        }
        _ => {
            println!("[sanctum] local mode (no Tor)");
            (None, None)
        }
    };

    let room = state.room.clone();
    println!(
        "[sanctum] persistent room {} started ({} members, {} revoked)",
        room.id(),
        room.active_member_count(),
        room.members().len() - room.active_member_count(),
    );
    if onion.is_some() {
        println!("[sanctum] hidden service published");
    }
    if args.show_address {
        let owner = room
            .members()
            .iter()
            .find(|m| m.role() == sanctum_domain::entities::member::Role::Owner)
            .map(|m| m.fingerprint().as_str().to_string())
            .unwrap_or_default();
        let target = InviteTarget {
            room_id: room.id().clone(),
            onion_address: onion
                .as_ref()
                .map_or("127.0.0.1".into(), |hs| hs.onion_address.clone()),
            port: if onion.is_some() {
                hidden_service_port
            } else {
                local_port
            },
            host_noise_pubkey: store.keys().noise_public.clone(),
        };
        println!("[sanctum] owner token command:");
        println!("  {}", invite_command(&owner, &target));
    }

    serve_persistent(
        PersistentHost {
            store,
            room,
            auth: AuthService::restore(state.revocations, state.used_invites),
            tcp_listener,
            tor,
        },
        shutdown,
    )
    .await
}

fn run_list(data_dir: &Path) -> Result<(), BoxError> {
    let rooms = host_store::list_rooms(data_dir)?;
    if rooms.is_empty() {
        println!("[sanctum] no persistent room under {}", data_dir.display());
    }
    for r in rooms {
        println!("{}", r.as_str());
    }
    Ok(())
}

fn run_delete(data_dir: &Path, room_id: &str, yes: bool) -> Result<(), BoxError> {
    let id = resolve_room(data_dir, Some(room_id))?;
    let dir = host_store::room_dir(data_dir, &id);
    if !yes {
        println!("[sanctum] this would delete {}", dir.display());
        println!("[sanctum] the room, its members and its .onion address are lost for good.");
        println!(
            "[sanctum] Deletion is not secure on journaling filesystems, SSDs or VM snapshots."
        );
        println!("[sanctum] Run again with --yes to delete.");
        return Ok(());
    }
    // Refuse while a host serves the room.
    let lock = std::fs::File::open(dir.join(host_store::LOCK_FILE))?;
    if lock.try_lock().is_err() {
        return Err("this room is being hosted: stop it first".into());
    }
    std::fs::remove_dir_all(&dir)?;
    println!("[sanctum] room {} deleted", id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_printed_invite_command_survives_a_key_starting_with_a_dash() {
        let mut key = vec![0xF8u8; 32]; // base64url "-…"
        key[1] = 1;
        assert!(invite_codec::encode_host_key(&key).starts_with('-'));
        let target = InviteTarget {
            room_id: RoomId::new(),
            onion_address: "127.0.0.1".into(),
            port: 9738,
            host_noise_pubkey: key,
        };
        let cmd = invite_command("AB", &target);
        assert!(cmd.contains(" --host-key=-"), "{cmd}");
    }

    #[test]
    fn both_modes_parse() {
        assert_eq!(parse_mode("ephemeral").unwrap(), RoomMode::Ephemeral);
        assert_eq!(parse_mode("persistent").unwrap(), RoomMode::Persistent);
        assert!(parse_mode("bogus").is_err());
    }

    #[test]
    fn owner_key_from_hex_or_file() {
        let id = IdentityAdapter::generate();
        let pk = id.public_key_bytes();
        let hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
        let (k, fp) = parse_owner_key(&hex).unwrap();
        assert_eq!(k, pk);
        assert_eq!(&fp, id.fingerprint());

        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("identity.pub");
        std::fs::write(&raw, &pk).unwrap();
        assert_eq!(parse_owner_key(raw.to_str().unwrap()).unwrap().1, fp);
        let txt = dir.path().join("owner.hex");
        std::fs::write(&txt, format!("{}\n", hex.to_uppercase())).unwrap();
        assert_eq!(parse_owner_key(txt.to_str().unwrap()).unwrap().1, fp);

        assert!(parse_owner_key("abcd").is_err());
        assert!(parse_owner_key(&"00".repeat(32)).is_err(), "weak key");
    }

    #[test]
    fn rooms_resolve_by_prefix() {
        let dir = tempfile::tempdir().unwrap();
        assert!(resolve_room(dir.path(), None).is_err());
        let a = RoomId::new();
        std::fs::create_dir(dir.path().join(a.as_str())).unwrap();
        std::fs::write(
            dir.path().join(a.as_str()).join(host_store::STATE_FILE),
            b"x",
        )
        .unwrap();
        assert_eq!(resolve_room(dir.path(), None).unwrap(), a);
        assert_eq!(resolve_room(dir.path(), Some(&a.as_str()[..8])).unwrap(), a);
        assert!(resolve_room(dir.path(), Some("zzzz")).is_err());
    }
}
