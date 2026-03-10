//! Host network listener: accept TCP connections, authenticate, route messages.
//!
//! This is the "main loop" of the host. It:
//! 1. Binds a TCP listener on the local port
//! 2. Accepts incoming connections (from Tor hidden service)
//! 3. Runs auth handshake (challenge-response) per client
//! 4. Routes messages between authenticated clients
//! 5. Manages backlog for offline peers (persistent mode)

use crate::codec::{self, message_types, Frame};
use crate::proto_codec::{self, pb, WireMessage};
use crate::tcp_transport::TcpTransport;
use sanctum_app::auth_service::{AuthResponse, AuthService};
use sanctum_app::host_service::HostService;
use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::entities::room::RoomId;
use sanctum_domain::errors::SanctumError;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// A message routed from one client to others.
#[derive(Debug, Clone)]
struct RoutedMessage {
    sender: Fingerprint,
    frame: Frame,
}

/// The running host listener.
pub struct HostListener {
    /// Address to bind on (e.g. "127.0.0.1:9738").
    bind_addr: String,
    /// The host service (room state, routing).
    host_service: Arc<Mutex<HostService>>,
    /// The auth service.
    auth_service: Arc<Mutex<AuthService>>,
    /// Noise static public key of the host (for server_id in challenges).
    host_noise_pubkey: Vec<u8>,
    /// Per-client transports indexed by connection_id.
    clients: Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>>,
    /// Channel for routing messages between clients.
    route_tx: broadcast::Sender<RoutedMessage>,
    /// Shutdown token.
    shutdown: CancellationToken,
}

impl HostListener {
    /// Create a new host listener.
    pub fn new(
        bind_addr: String,
        host_service: HostService,
        host_noise_pubkey: Vec<u8>,
        shutdown: CancellationToken,
    ) -> Self {
        let (route_tx, _) = broadcast::channel(1024);
        Self {
            bind_addr,
            host_service: Arc::new(Mutex::new(host_service)),
            auth_service: Arc::new(Mutex::new(AuthService::new())),
            host_noise_pubkey,
            clients: Arc::new(Mutex::new(HashMap::new())),
            route_tx,
            shutdown,
        }
    }

    /// Run the host listener. Blocks until shutdown.
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

                            let transport = TcpTransport::new(stream, conn_id);
                            let host_svc = self.host_service.clone();
                            let auth_svc = self.auth_service.clone();
                            let noise_pk = self.host_noise_pubkey.clone();
                            let clients = self.clients.clone();
                            let route_tx = self.route_tx.clone();
                            let shutdown = self.shutdown.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handle_client(
                                    transport, conn_id, host_svc, auth_svc,
                                    noise_pk, clients, route_tx, shutdown,
                                ).await {
                                    warn!("[sanctum] client #{conn_id} error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            error!("[sanctum] accept error: {e}");
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle a single client connection (auth + message loop).
async fn handle_client(
    mut transport: TcpTransport,
    conn_id: u64,
    host_svc: Arc<Mutex<HostService>>,
    auth_svc: Arc<Mutex<AuthService>>,
    host_noise_pubkey: Vec<u8>,
    clients: Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>>,
    route_tx: broadcast::Sender<RoutedMessage>,
    shutdown: CancellationToken,
) -> Result<(), SanctumError> {
    // ── Phase 1: Authentication ──
    let fingerprint = authenticate_client(
        &mut transport, &host_svc, &auth_svc, &host_noise_pubkey,
    ).await?;

    info!("[sanctum] client #{conn_id} authenticated as {}", fingerprint.short());

    // Register in host service
    {
        let mut svc = host_svc.lock().await;
        svc.register_client(fingerprint.clone(), conn_id)?;
        // For this simplified MVP, mark client as ready immediately
        // (X3DH would happen here in full implementation)
        svc.mark_client_ready(&fingerprint);
    }

    // Create per-client outbound channel
    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(256);
    {
        clients.lock().await.insert(conn_id, out_tx);
    }

    // Subscribe to routed messages
    let mut route_rx = route_tx.subscribe();

    // Notify other clients
    let join_frame = proto_codec::proto_encode(&WireMessage::PeerReady(pb::PeerReady {
        fingerprint: fingerprint.as_str().to_string(),
        display_alias: fingerprint.short().to_string(),
    })).unwrap();
    let _ = route_tx.send(RoutedMessage {
        sender: fingerprint.clone(),
        frame: join_frame,
    });

    info!("[sanctum] client #{conn_id} entering message loop");

    // ── Phase 2: Message loop ──
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                break;
            }

            // Receive from this client
            result = transport.recv_frame() => {
                match result {
                    Ok(frame) => {
                        match frame.message_type {
                            message_types::ROOM_MESSAGE => {
                                // Route to all other ready clients
                                let svc = host_svc.lock().await;
                                let recipients = svc.route_recipients(&fingerprint);
                                drop(svc);

                                for recipient_fp in recipients {
                                    let svc = host_svc.lock().await;
                                    if let Some(their_conn_id) = svc.connection_id_for(&recipient_fp) {
                                        let cls = clients.lock().await;
                                        if let Some(tx) = cls.get(&their_conn_id) {
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
                                warn!("[sanctum] unhandled message type 0x{:02X} from #{conn_id}", frame.message_type);
                            }
                        }
                    }
                    Err(e) => {
                        info!("[sanctum] client #{conn_id} disconnected: {e}");
                        break;
                    }
                }
            }

            // Send queued frames to this client
            Some(frame) = out_rx.recv() => {
                if let Err(e) = transport.send_frame(&frame).await {
                    warn!("[sanctum] send to #{conn_id} failed: {e}");
                    break;
                }
            }

            // Route broadcast messages (e.g. PeerReady notifications)
            Ok(routed) = route_rx.recv() => {
                // Don't echo back to sender
                if routed.sender != fingerprint {
                    if let Err(e) = transport.send_frame(&routed.frame).await {
                        warn!("[sanctum] broadcast to #{conn_id} failed: {e}");
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    {
        let mut svc = host_svc.lock().await;
        svc.remove_client(&fingerprint);
    }
    {
        clients.lock().await.remove(&conn_id);
    }
    transport.shutdown().await;

    info!("[sanctum] client #{conn_id} disconnected cleanly");
    Ok(())
}

/// Run the PGP challenge-response auth over the transport.
async fn authenticate_client(
    transport: &mut TcpTransport,
    host_svc: &Arc<Mutex<HostService>>,
    auth_svc: &Arc<Mutex<AuthService>>,
    host_noise_pubkey: &[u8],
) -> Result<Fingerprint, SanctumError> {
    // Get room ID for the challenge
    let room_id = {
        let svc = host_svc.lock().await;
        svc.room().id().clone()
    };

    // Create and send challenge
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

    // Receive auth response
    let resp_frame = transport.recv_frame().await?;
    if resp_frame.message_type != message_types::AUTH_RESPONSE {
        return Err(SanctumError::AuthFailed {
            reason: format!("expected AuthResponse, got 0x{:02X}", resp_frame.message_type),
        });
    }

    let resp_msg = proto_codec::proto_decode(&resp_frame)?;
    let (fingerprint, display_alias) = match resp_msg {
        WireMessage::AuthResponse(r) => {
            let fp = Fingerprint::new(r.fingerprint.clone())
                .map_err(|e| SanctumError::AuthFailed { reason: e.to_string() })?;
            (fp, r.display_alias)
        }
        _ => {
            return Err(SanctumError::AuthFailed {
                reason: "unexpected message type in auth".into(),
            });
        }
    };

    // Verify: is this fingerprint authorized?
    let authorized_fps = {
        let svc = host_svc.lock().await;
        svc.room()
            .members()
            .iter()
            .filter(|m| m.is_active())
            .map(|m| m.fingerprint().clone())
            .collect::<std::collections::HashSet<_>>()
    };

    let auth_response = AuthResponse {
        fingerprint: fingerprint.clone(),
        signature: vec![], // MVP: skip PGP signature verification
        pgp_public_key: vec![],
        display_alias: display_alias.clone(),
    };

    {
        let mut svc = auth_svc.lock().await;
        svc.verify_response(&challenge, &auth_response, &authorized_fps)?;
    }

    // Send auth result
    let result_msg = WireMessage::AuthResult(pb::AuthResult {
        success: true,
        error_message: String::new(),
        member_role: "member".into(),
        room_state: None, // MVP: simplified
    });
    let result_frame = proto_codec::proto_encode(&result_msg)?;
    transport.send_frame(&result_frame).await?;

    Ok(fingerprint)
}