//! Host network listener with Noise NK transport encryption.
//!
//! Each client connection gets its own Noise session.
//! The host decrypts the Noise layer (transport) to see frame types
//! for routing, but CANNOT read E2E encrypted payloads inside
//! RoomMessage.ciphertext — those are opaque blobs relayed blindly.
//!
//! Layers:
//!   Client A ←[Noise A]→ Host ←[Noise B]→ Client B
//!   Client A ←─────── [E2E] ──────────→ Client B  (host blind)

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
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
struct RoutedMessage {
    sender: Fingerprint,
    frame: Frame,
}

pub struct HostListener {
    bind_addr: String,
    host_service: Arc<Mutex<HostService>>,
    auth_service: Arc<Mutex<AuthService>>,
    host_noise_pubkey: Vec<u8>,
    host_noise_privkey: Vec<u8>,
    clients: Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>>,
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
            route_tx,
            shutdown,
        }
    }

    pub async fn run(&self) -> Result<(), SanctumError> {
        let listener = TcpListener::bind(&self.bind_addr)
            .await
            .map_err(|e| SanctumError::ConnectionLost(format!("bind {}: {e}", self.bind_addr)))?;

        info!("[sanctum] listening on {}", self.bind_addr);
        let mut conn_counter: u64 = 1;

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("[sanctum] host shutting down");
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, addr)) => {
                            let conn_id = conn_counter;
                            conn_counter += 1;
                            info!("[sanctum] connection #{conn_id} from {addr}");

                            let tcp = TcpTransport::new(stream, conn_id);
                            let host_svc = self.host_service.clone();
                            let auth_svc = self.auth_service.clone();
                            let noise_pub = self.host_noise_pubkey.clone();
                            let noise_priv = self.host_noise_privkey.clone();
                            let clients = self.clients.clone();
                            let route_tx = self.route_tx.clone();
                            let shutdown = self.shutdown.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handle_client(
                                    tcp, conn_id, host_svc, auth_svc,
                                    noise_pub, noise_priv, clients, route_tx, shutdown,
                                ).await {
                                    warn!("[sanctum] client #{conn_id} error: {e}");
                                }
                            });
                        }
                        Err(e) => error!("[sanctum] accept error: {e}"),
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
    route_tx: broadcast::Sender<RoutedMessage>,
    shutdown: CancellationToken,
) -> Result<(), SanctumError> {
    // ── Phase 1: Noise NK Handshake ──
    info!("[sanctum] client #{conn_id}: Noise handshake...");
    let mut transport = NoiseTransport::host_handshake(tcp, &host_noise_privkey).await?;
    info!("[sanctum] client #{conn_id}: Noise established");

    // ── Phase 2: PGP Auth (over encrypted transport) ──
    let fingerprint = authenticate_client(
        &mut transport, &host_svc, &auth_svc, &host_noise_pubkey,
    ).await?;
    info!("[sanctum] client #{conn_id} authenticated as {}", fingerprint.short());

    {
        let mut svc = host_svc.lock().await;
        svc.register_client(fingerprint.clone(), conn_id)?;
        svc.mark_client_ready(&fingerprint);
    }

    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(256);
    { clients.lock().await.insert(conn_id, out_tx); }

    let mut route_rx = route_tx.subscribe();

    // Notify peers
    let join_frame = proto_codec::proto_encode(&WireMessage::PeerReady(pb::PeerReady {
        fingerprint: fingerprint.as_str().to_string(),
        display_alias: fingerprint.short().to_string(),
    })).unwrap();
    let _ = route_tx.send(RoutedMessage {
        sender: fingerprint.clone(),
        frame: join_frame,
    });

    info!("[sanctum] client #{conn_id} entering message loop");

    // ── Phase 3: Message loop ──
    // The host sees frame types (for routing) but E2E payloads are opaque.
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,

            result = transport.recv_frame() => {
                match result {
                    Ok(frame) => {
                        match frame.message_type {
                            message_types::ROOM_MESSAGE => {
                                // Route opaque E2E payload to recipients
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
                            _ => {
                                warn!("[sanctum] unhandled 0x{:02X} from #{conn_id}", frame.message_type);
                            }
                        }
                    }
                    Err(e) => {
                        info!("[sanctum] client #{conn_id} disconnected: {e}");
                        break;
                    }
                }
            }

            Some(frame) = out_rx.recv() => {
                if let Err(e) = transport.send_frame(&frame).await {
                    warn!("[sanctum] send to #{conn_id} failed: {e}");
                    break;
                }
            }

            Ok(routed) = route_rx.recv() => {
                if routed.sender != fingerprint {
                    if let Err(e) = transport.send_frame(&routed.frame).await {
                        warn!("[sanctum] broadcast to #{conn_id} failed: {e}");
                        break;
                    }
                }
            }
        }
    }

    { host_svc.lock().await.remove_client(&fingerprint); }
    { clients.lock().await.remove(&conn_id); }
    transport.shutdown().await;
    info!("[sanctum] client #{conn_id} disconnected cleanly");
    Ok(())
}

async fn authenticate_client(
    transport: &mut NoiseTransport,
    host_svc: &Arc<Mutex<HostService>>,
    auth_svc: &Arc<Mutex<AuthService>>,
    host_noise_pubkey: &[u8],
) -> Result<Fingerprint, SanctumError> {
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
    let frame = proto_codec::proto_encode(&challenge_msg)?;
    transport.send_frame(&frame).await?;

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

    { auth_svc.lock().await.verify_response(&challenge, &auth_response, &authorized_fps)?; }

    let result_msg = WireMessage::AuthResult(pb::AuthResult {
        success: true,
        error_message: String::new(),
        member_role: "member".into(),
        room_state: None,
    });
    transport.send_frame(&proto_codec::proto_encode(&result_msg)?).await?;

    Ok(fingerprint)
}