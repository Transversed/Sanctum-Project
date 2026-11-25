//! Host network listener: Noise NK transport, proven identities, blind relay.
//!
//! Per connection:
//! 1. Noise NK handshake (the host's static key is in the invitations)
//! 2. Authentication: Ed25519 signature bound to the Noise handshake hash;
//!    the fingerprint is derived from the proven key (I2). Unknown identities
//!    need a valid, single-use, owner-signed invitation.
//! 3. PeerReady exchange with the other connected members
//! 4. Relay loop: the host stamps the authenticated sender on every
//!    `RoomMessage` (I3) and never looks inside the ciphertext.

use crate::codec::{self, message_types, Frame};
use crate::identity::Ed25519Verifier;
use crate::invite_codec;
use crate::noise_transport::NoiseTransport;
use crate::proto_codec::{self, pb, WireMessage};
use crate::tcp_transport::TcpTransport;
use sanctum_app::auth_service::{unix_now, Admission, AuthResponse, AuthService, RoomAdmission};
use sanctum_app::host_service::HostService;
use sanctum_app::sanitize::sanitize_alias;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Member, Role};
use sanctum_domain::errors::SanctumError;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use zeroize::Zeroizing;

/// A client sending this many undecodable frames is disconnected.
const MAX_INVALID_FRAMES: u32 = 3;

#[derive(Debug, Clone)]
struct RoutedMessage {
    sender: Fingerprint,
    frame: Frame,
}

/// State shared by every connection task.
struct HostState {
    host_service: Mutex<HostService>,
    auth_service: Mutex<AuthService>,
    host_noise_pubkey: Vec<u8>,
    /// Never cloned: every connection borrows it through the `Arc`.
    host_noise_privkey: Zeroizing<Vec<u8>>,
    clients: Mutex<HashMap<u64, mpsc::Sender<Frame>>>,
    /// fingerprint → sanitized alias of connected members.
    aliases: Mutex<HashMap<String, String>>,
    route_tx: broadcast::Sender<RoutedMessage>,
    verifier: Ed25519Verifier,
}

pub struct HostListener {
    bind_addr: String,
    state: Arc<HostState>,
    shutdown: CancellationToken,
}

impl HostListener {
    pub fn new(
        bind_addr: String,
        host_service: HostService,
        host_noise_pubkey: Vec<u8>,
        host_noise_privkey: Zeroizing<Vec<u8>>,
        shutdown: CancellationToken,
    ) -> Self {
        let (route_tx, _) = broadcast::channel(1024);
        Self {
            bind_addr,
            state: Arc::new(HostState {
                host_service: Mutex::new(host_service),
                auth_service: Mutex::new(AuthService::new()),
                host_noise_pubkey,
                host_noise_privkey,
                clients: Mutex::new(HashMap::new()),
                aliases: Mutex::new(HashMap::new()),
                route_tx,
                verifier: Ed25519Verifier,
            }),
            shutdown,
        }
    }

    /// Bind `bind_addr` and serve until shutdown.
    pub async fn run(&self) -> Result<(), SanctumError> {
        let listener = TcpListener::bind(&self.bind_addr)
            .await
            .map_err(|e| SanctumError::ConnectionLost(format!("bind {}: {e}", self.bind_addr)))?;
        self.serve(listener).await
    }

    /// Serve on an already bound listener until shutdown.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), SanctumError> {
        info!("relay listening");
        let mut conn_counter: u64 = 1;

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                accept = listener.accept() => {
                    let Ok((stream, _addr)) = accept else { continue };
                    let conn_id = conn_counter;
                    conn_counter += 1;
                    let state = self.state.clone();
                    let shutdown = self.shutdown.clone();
                    tokio::spawn(async move {
                        let tcp = TcpTransport::new(stream, conn_id);
                        if let Err(e) = handle_client(tcp, conn_id, state, shutdown).await {
                            debug!(conn_id, "connection closed: {e}");
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

async fn handle_client(
    tcp: TcpTransport,
    conn_id: u64,
    st: Arc<HostState>,
    shutdown: CancellationToken,
) -> Result<(), SanctumError> {
    // ── Phase 1: Noise NK handshake ──
    let mut transport = NoiseTransport::host_handshake(tcp, &st.host_noise_privkey).await?;

    // ── Phase 2: proven identity ──
    let (fingerprint, display_alias) = authenticate_client(&mut transport, &st).await?;
    debug!(conn_id, "client authenticated");

    {
        let mut svc = st.host_service.lock().await;
        svc.register_client(fingerprint.clone(), conn_id)?;
        svc.mark_client_ready(&fingerprint);
    }
    st.aliases
        .lock()
        .await
        .insert(fingerprint.as_str().to_string(), display_alias.clone());
    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(256);
    st.clients.lock().await.insert(conn_id, out_tx);
    let mut route_rx = st.route_tx.subscribe();

    // ── Phase 3: PeerReady for existing members → newcomer, then broadcast ──
    let peers: Vec<(String, String)> = st
        .aliases
        .lock()
        .await
        .iter()
        .filter(|(fp, _)| fp.as_str() != fingerprint.as_str())
        .map(|(fp, a)| (fp.clone(), a.clone()))
        .collect();
    for (fp, alias) in peers {
        let frame = proto_codec::proto_encode(&WireMessage::PeerReady(pb::PeerReady {
            fingerprint: fp,
            display_alias: alias,
        }))?;
        transport.send_frame(&frame).await?;
    }
    let join_frame = proto_codec::proto_encode(&WireMessage::PeerReady(pb::PeerReady {
        fingerprint: fingerprint.as_str().to_string(),
        display_alias: display_alias.clone(),
    }))?;
    let _ = st.route_tx.send(RoutedMessage {
        sender: fingerprint.clone(),
        frame: join_frame,
    });

    // ── Phase 4: relay loop ──
    let mut invalid_frames: u32 = 0;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,

            result = transport.recv_frame() => {
                let frame = match result {
                    Ok(f) => f,
                    Err(e) => {
                        debug!(conn_id, "client disconnected: {e}");
                        break;
                    }
                };
                match frame.message_type {
                    message_types::ROOM_MESSAGE => {
                        // I3: the sender is the authenticated peer, whatever
                        // the frame claims. Undecodable frames are dropped.
                        let Some(frame) = stamp_sender(&frame, &fingerprint) else {
                            invalid_frames += 1;
                            if invalid_frames >= MAX_INVALID_FRAMES {
                                break;
                            }
                            continue;
                        };
                        relay_to_others(&st, &fingerprint, frame).await;
                    }
                    message_types::PING => transport.send_frame(&codec::pong_frame()).await?,
                    _ => {}
                }
            }

            Some(frame) = out_rx.recv() => {
                if transport.send_frame(&frame).await.is_err() {
                    break;
                }
            }

            Ok(routed) = route_rx.recv() => {
                if routed.sender != fingerprint && transport.send_frame(&routed.frame).await.is_err() {
                    break;
                }
            }
        }
    }

    // Cleanup
    st.host_service.lock().await.remove_client(&fingerprint);
    st.clients.lock().await.remove(&conn_id);
    st.aliases.lock().await.remove(fingerprint.as_str());
    transport.shutdown().await;
    debug!(conn_id, "client left");
    Ok(())
}

/// Forward `frame` to every other ready member.
async fn relay_to_others(st: &HostState, sender: &Fingerprint, frame: Frame) {
    let connection_ids: Vec<u64> = {
        let svc = st.host_service.lock().await;
        svc.route_recipients(sender)
            .iter()
            .filter_map(|fp| svc.connection_id_for(fp))
            .collect()
    };
    let clients = st.clients.lock().await;
    for cid in connection_ids {
        if let Some(tx) = clients.get(&cid) {
            let _ = tx.send(frame.clone()).await;
        }
    }
}

/// Re-encode a `RoomMessage` with the authenticated sender fingerprint.
///
/// Returns `None` if the frame is not a decodable `RoomMessage`.
fn stamp_sender(frame: &Frame, sender: &Fingerprint) -> Option<Frame> {
    match proto_codec::proto_decode(frame) {
        Ok(WireMessage::RoomMessage(mut m)) => {
            m.sender_fingerprint = sender.as_str().to_string();
            proto_codec::proto_encode(&WireMessage::RoomMessage(m)).ok()
        }
        _ => None,
    }
}

/// Alias accepted by the domain (≤ 20 bytes), derived from untrusted input.
fn host_side_alias(raw: &str, fingerprint: &Fingerprint) -> String {
    let mut alias = sanitize_alias(raw).unwrap_or_else(|| fingerprint.short());
    while alias.len() > 20 {
        alias.pop();
    }
    alias
}

async fn send_auth_result(
    transport: &mut NoiseTransport,
    result: Result<Role, &SanctumError>,
) -> Result<(), SanctumError> {
    let msg = match result {
        Ok(role) => pb::AuthResult {
            success: true,
            error_message: String::new(),
            member_role: role.to_string(),
            room_state: None,
        },
        Err(e) => pb::AuthResult {
            success: false,
            error_message: e.to_string(),
            member_role: String::new(),
            room_state: None,
        },
    };
    transport
        .send_frame(&proto_codec::proto_encode(&WireMessage::AuthResult(msg))?)
        .await
}

/// Challenge-response authentication; admits invited newcomers.
async fn authenticate_client(
    transport: &mut NoiseTransport,
    st: &HostState,
) -> Result<(Fingerprint, String), SanctumError> {
    // Snapshot of what admission depends on.
    let (room_id, owner_fp, owner_pk, members) = {
        let svc = st.host_service.lock().await;
        let room = svc.room();
        let owner = room
            .members()
            .iter()
            .find(|m| m.role() == Role::Owner)
            .ok_or_else(|| SanctumError::AuthFailed {
                reason: "room has no owner".into(),
            })?;
        let members: HashMap<Fingerprint, Role> = room
            .members()
            .iter()
            .filter(|m| m.is_active())
            .map(|m| (m.fingerprint().clone(), m.role()))
            .collect();
        (
            room.id().clone(),
            owner.fingerprint().clone(),
            owner.identity_key().to_vec(),
            members,
        )
    };

    let challenge = st
        .auth_service
        .lock()
        .await
        .create_challenge(&room_id, &st.host_noise_pubkey);
    let challenge_msg = WireMessage::AuthChallenge(pb::AuthChallenge {
        nonce: challenge.nonce.clone(),
        timestamp: challenge.timestamp,
        room_id: challenge.room_id.as_str().to_string(),
        server_id: challenge.server_id.to_vec(),
    });
    transport
        .send_frame(&proto_codec::proto_encode(&challenge_msg)?)
        .await?;

    let resp_frame = transport.recv_frame().await?;
    let raw = match proto_codec::proto_decode(&resp_frame) {
        Ok(WireMessage::AuthResponse(r)) => r,
        _ => {
            let err = SanctumError::AuthFailed {
                reason: "expected AuthResponse".into(),
            };
            send_auth_result(transport, Err(&err)).await?;
            return Err(err);
        }
    };

    let invite = if raw.invite_token.is_empty() {
        None
    } else {
        match invite_codec::decode_invite(&raw.invite_token) {
            Ok(t) => Some(t),
            Err(e) => {
                send_auth_result(transport, Err(&e)).await?;
                return Err(e);
            }
        }
    };
    let response = AuthResponse {
        public_key: raw.ed25519_public_key,
        signature: raw.signature,
        display_alias: raw.display_alias,
        invite,
    };
    let admission = RoomAdmission {
        room_id: &room_id,
        owner_fingerprint: &owner_fp,
        owner_public_key: &owner_pk,
        host_noise_pubkey: &st.host_noise_pubkey,
        members: &members,
    };
    let now = unix_now();
    let verified = st.auth_service.lock().await.verify_response(
        &challenge,
        transport.handshake_hash(),
        &response,
        &admission,
        &st.verifier,
        now,
    );
    let auth = match verified {
        Ok(a) => a,
        Err(e) => {
            send_auth_result(transport, Err(&e)).await?;
            return Err(e);
        }
    };

    let alias = host_side_alias(&response.display_alias, &auth.fingerprint);
    if let Admission::Invited(role) = auth.admission {
        // Admission happens here and only here, with the proven key.
        let member = Member::new(
            auth.fingerprint.clone(),
            auth.public_key.clone(),
            DisplayAlias::new(&alias).unwrap_or_else(|_| DisplayAlias::new("member").unwrap()),
            role,
            now,
        );
        let added = st.host_service.lock().await.room_mut().add_member(member);
        if let Err(e) = added {
            send_auth_result(transport, Err(&e)).await?;
            return Err(e);
        }
    }
    send_auth_result(transport, Ok(auth.admission.role())).await?;
    Ok((auth.fingerprint, alias))
}
