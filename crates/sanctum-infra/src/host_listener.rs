//! Host network listener with Noise NK transport encryption.
//!
//! Each client gets its own Noise session. The host decrypts transport
//! for routing but is blind to E2E payloads.
//!
//! When a new client joins:
//! 1. Noise handshake
//! 2. Auth challenge-response
//! 3. Send PeerReady for all existing clients → new client
//! 4. Broadcast PeerReady for new client → all existing clients

use crate::codec::{self, message_types, Frame};
use crate::noise_transport::NoiseTransport;
use crate::proto_codec::{self, pb, WireMessage};
use crate::tcp_transport::TcpTransport;
use sanctum_app::auth_service::{AuthResponse, AuthService};
use sanctum_app::host_service::HostService;
use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::errors::SanctumError;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
struct RoutedMessage {
    sender: Fingerprint,
    frame: Frame,
}

/// Stores fingerprint → display alias for all connected clients.
type AliasMap = Arc<Mutex<HashMap<String, String>>>;

pub struct HostListener {
    bind_addr: String,
    host_service: Arc<Mutex<HostService>>,
    auth_service: Arc<Mutex<AuthService>>,
    host_noise_pubkey: Vec<u8>,
    host_noise_privkey: Vec<u8>,
    clients: Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>>,
    aliases: AliasMap,
    route_tx: broadcast::Sender<RoutedMessage>,
    shutdown: CancellationToken,
}

impl HostListener {
    pub fn new(
        bind_addr: String,
        host_service: HostService,
        host_noise_pubkey: Vec<u8>,
        host_noise_privkey: Vec<u8>,
        shutdown: CancellationToken,
    ) -> Self {
        let (route_tx, _) = broadcast::channel(1024);
        Self {
            bind_addr,
            host_service: Arc::new(Mutex::new(host_service)),
            auth_service: Arc::new(Mutex::new(AuthService::new())),
            host_noise_pubkey,
            host_noise_privkey,
            clients: Arc::new(Mutex::new(HashMap::new())),
            aliases: Arc::new(Mutex::new(HashMap::new())),
            route_tx,
            shutdown,
        }
    }

    pub async fn run(&self) -> Result<(), SanctumError> {
        let listener = TcpListener::bind(&self.bind_addr)
            .await
            .map_err(|e| SanctumError::ConnectionLost(format!("bind {}: {e}", self.bind_addr)))?;

        eprintln!("[sanctum] listening on {}", self.bind_addr);
        let mut conn_counter: u64 = 1;

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    eprintln!("[sanctum] host shutting down");
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, addr)) => {
                            let conn_id = conn_counter;
                            conn_counter += 1;
                            eprintln!("[sanctum] connection #{conn_id} from {addr}");

                            let tcp = TcpTransport::new(stream, conn_id);
                            let host_svc = self.host_service.clone();
                            let auth_svc = self.auth_service.clone();
                            let noise_pub = self.host_noise_pubkey.clone();
                            let noise_priv = self.host_noise_privkey.clone();
                            let clients = self.clients.clone();
                            let aliases = self.aliases.clone();
                            let route_tx = self.route_tx.clone();
                            let shutdown = self.shutdown.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handle_client(
                                    tcp, conn_id, host_svc, auth_svc,
                                    noise_pub, noise_priv, clients, aliases,
                                    route_tx, shutdown,
                                ).await {
                                    eprintln!("[sanctum] client #{conn_id} error: {e}");
                                }
                            });
                        }
                        Err(e) => { let _ = e; }
                    }
                }
            }
        }
        Ok(())
    }
}

async fn handle_client(
    tcp: TcpTransport,
    conn_id: u64,
    host_svc: Arc<Mutex<HostService>>,
    auth_svc: Arc<Mutex<AuthService>>,
    host_noise_pubkey: Vec<u8>,
    host_noise_privkey: Vec<u8>,
    clients: Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>>,
    aliases: AliasMap,
    route_tx: broadcast::Sender<RoutedMessage>,
    shutdown: CancellationToken,
) -> Result<(), SanctumError> {
    // ── Phase 1: Noise NK Handshake ──
    let mut transport = NoiseTransport::host_handshake(tcp, &host_noise_privkey).await?;

    // ── Phase 2: Auth ──
    let (fingerprint, display_alias) = authenticate_client(
        &mut transport, &host_svc, &auth_svc, &host_noise_pubkey, conn_id,
    ).await?;
    eprintln!("[sanctum] client #{conn_id} authenticated: {} ({})", display_alias, fingerprint.short());

    // Register client
    {
        let mut svc = host_svc.lock().await;
        svc.register_client(fingerprint.clone(), conn_id)?;
        svc.mark_client_ready(&fingerprint);
    }

    // Store alias
    {
        aliases.lock().await.insert(fingerprint.as_str().to_string(), display_alias.clone());
    }

    // Create outbound channel
    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(256);
    { clients.lock().await.insert(conn_id, out_tx); }

    let mut route_rx = route_tx.subscribe();

    // ── Phase 3: Send PeerReady for ALL existing clients to the NEW client ──
    {
        let alias_map = aliases.lock().await;
        for (fp_str, alias) in alias_map.iter() {
            if fp_str != fingerprint.as_str() {
                let peer_frame = proto_codec::proto_encode(&WireMessage::PeerReady(pb::PeerReady {
                    fingerprint: fp_str.clone(),
                    display_alias: alias.clone(),
                })).unwrap();
                let _ = transport.send_frame(&peer_frame).await;
            }
        }
    }

    // ── Phase 4: Broadcast PeerReady for NEW client to all EXISTING clients ──
    let join_frame = proto_codec::proto_encode(&WireMessage::PeerReady(pb::PeerReady {
        fingerprint: fingerprint.as_str().to_string(),
        display_alias: display_alias.clone(),
    })).unwrap();
    let _ = route_tx.send(RoutedMessage {
        sender: fingerprint.clone(),
        frame: join_frame,
    });

    // ── Phase 5: Message loop ──
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,

            result = transport.recv_frame() => {
                match result {
                    Ok(frame) => {
                        match frame.message_type {
                            message_types::ROOM_MESSAGE => {
                                let svc = host_svc.lock().await;
                                let recipients = svc.route_recipients(&fingerprint);
                                drop(svc);

                                for recipient_fp in recipients {
                                    let svc = host_svc.lock().await;
                                    if let Some(cid) = svc.connection_id_for(&recipient_fp) {
                                        let cls = clients.lock().await;
                                        if let Some(tx) = cls.get(&cid) {
                                            let _ = tx.send(frame.clone()).await;
                                        }
                                    }
                                }
                            }
                            message_types::PING => {
                                let pong = codec::pong_frame();
                                transport.send_frame(&pong).await?;
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        eprintln!("[sanctum] {} ({}) disconnected: {e}", display_alias, fingerprint.short());
                        break;
                    }
                }
            }

            Some(frame) = out_rx.recv() => {
                if let Err(e) = transport.send_frame(&frame).await {
                    eprintln!("[sanctum] send to {} failed: {e}", display_alias);
                    break;
                }
            }

            Ok(routed) = route_rx.recv() => {
                if routed.sender != fingerprint {
                    if let Err(e) = transport.send_frame(&routed.frame).await {
                        eprintln!("[sanctum] broadcast to {} failed: {e}", display_alias);
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    { host_svc.lock().await.remove_client(&fingerprint); }
    { clients.lock().await.remove(&conn_id); }
    { aliases.lock().await.remove(fingerprint.as_str()); }
    transport.shutdown().await;

    // Notify peers that this client left
    // (In production: broadcast a PeerLeft event)
    eprintln!("[sanctum] {} ({}) left the room", display_alias, fingerprint.short());
    Ok(())
}

async fn authenticate_client(
    transport: &mut NoiseTransport,
    host_svc: &Arc<Mutex<HostService>>,
    auth_svc: &Arc<Mutex<AuthService>>,
    host_noise_pubkey: &[u8],
    conn_id: u64,
) -> Result<(Fingerprint, String), SanctumError> {
    let room_id = {
        let svc = host_svc.lock().await;
        svc.room().id().clone()
    };

    let challenge = {
        let svc = auth_svc.lock().await;
        svc.create_challenge(&room_id, host_noise_pubkey)
    };

    let challenge_msg = WireMessage::AuthChallenge(pb::AuthChallenge {
        nonce: challenge.nonce.clone(),
        timestamp: challenge.timestamp,
        room_id: challenge.room_id.as_str().to_string(),
        server_id: challenge.server_id.to_vec(),
    });
    transport.send_frame(&proto_codec::proto_encode(&challenge_msg)?).await?;

    let resp_frame = transport.recv_frame().await?;
    if resp_frame.message_type != message_types::AUTH_RESPONSE {
        return Err(SanctumError::AuthFailed {
            reason: format!("expected AuthResponse, got 0x{:02X}", resp_frame.message_type),
        });
    }

    let (fingerprint, display_alias) = match proto_codec::proto_decode(&resp_frame)? {
        WireMessage::AuthResponse(r) => {
            let fp = Fingerprint::new(r.fingerprint)
                .map_err(|e| SanctumError::AuthFailed { reason: e.to_string() })?;
            (fp, r.display_alias)
        }
        _ => return Err(SanctumError::AuthFailed { reason: "unexpected message".into() }),
    };

    // Add member dynamically if not already present
    {
        let mut svc = host_svc.lock().await;
        if svc.room().find_member(&fingerprint).is_none() {
            let member = sanctum_domain::entities::member::Member::new(
                fingerprint.clone(),
                vec![0u8; 32],
                sanctum_domain::entities::member::DisplayAlias::new(&display_alias)
                    .unwrap_or_else(|_| sanctum_domain::entities::member::DisplayAlias::new("anon").unwrap()),
                sanctum_domain::entities::member::Role::Member,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            let _ = svc.room_mut().add_member(member);
        }
    }

    let authorized_fps = {
        let svc = host_svc.lock().await;
        svc.room().members().iter()
            .filter(|m| m.is_active())
            .map(|m| m.fingerprint().clone())
            .collect::<std::collections::HashSet<_>>()
    };

    let auth_response = AuthResponse {
        fingerprint: fingerprint.clone(),
        signature: vec![],
        pgp_public_key: vec![],
        display_alias: display_alias.clone(),
    };

    auth_svc.lock().await.verify_response(&challenge, &auth_response, &authorized_fps)?;

    let result_msg = WireMessage::AuthResult(pb::AuthResult {
        success: true,
        error_message: String::new(),
        member_role: "member".into(),
        room_state: None,
    });
    transport.send_frame(&proto_codec::proto_encode(&result_msg)?).await?;

    Ok((fingerprint, display_alias))
}