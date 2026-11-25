//! Host network listener: Noise NK transport, proven identities, blind relay.
//!
//! Per connection:
//! 1. Noise NK handshake (the host's static key is in the invitations)
//! 2. Authentication: Ed25519 signature bound to the Noise handshake hash;
//!    the fingerprint is derived from the proven key (I2). Unknown identities
//!    need a valid, single-use, owner-signed invitation.
//! 3. PeerReady exchange with the other connected members
//! 4. Bundle exchange: the member publishes its signed prekey bundle; the
//!    host sends it the bundles of members who published earlier (handing
//!    out each one-time prekey once), and the member initiates X3DH.
//! 5. Relay loop: key exchanges and room messages are routed to their single
//!    recipient with the authenticated sender stamped (I3). The host never
//!    holds a key that decrypts them.

use crate::codec::{self, message_types, Frame};
use crate::identity::Ed25519Verifier;
use crate::invite_codec;
use crate::noise_transport::NoiseTransport;
use crate::proto_codec::{self, pb, WireMessage};
use crate::room_crypto::{verify_bundle, MAX_BUNDLE_OPKS};
use crate::tcp_transport::TcpTransport;
use sanctum_app::auth_service::{unix_now, Admission, AuthResponse, AuthService, RoomAdmission};
use sanctum_app::host_service::HostService;
use sanctum_app::sanitize::sanitize_alias;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Member, Role};
use sanctum_domain::errors::SanctumError;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Mutex, Semaphore};
use tokio::time::{timeout, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use zeroize::Zeroizing;

/// A client sending this many invalid frames is disconnected.
const MAX_INVALID_FRAMES: u32 = 3;
/// Below this many one-time prekeys, the owner is asked for more.
const OPK_LOW_WATERMARK: usize = 5;

/// Resource limits of the relay (P5.2).
#[derive(Debug, Clone, Copy)]
pub struct HostLimits {
    /// Noise handshake + authentication must complete within this delay.
    pub handshake_timeout: Duration,
    /// An authenticated client silent for this long is disconnected
    /// (clients send PING every 30 s).
    pub idle_timeout: Duration,
    /// Simultaneous connections, authenticated or not.
    pub max_connections: usize,
}

impl Default for HostLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(120),
            max_connections: 64,
        }
    }
}

/// A published bundle: identity part + pool of one-time prekeys.
struct StoredBundle {
    bundle: pb::PreKeyBundle,
    opks: VecDeque<pb::OneTimePreKey>,
}

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
    /// Bundles of connected members, in RAM only.
    bundles: Mutex<HashMap<Fingerprint, StoredBundle>>,
    limits: HostLimits,
}

pub struct HostListener {
    bind_addr: String,
    state: Arc<HostState>,
    shutdown: CancellationToken,
}

fn state_mut(state: &mut Arc<HostState>) -> &mut HostState {
    Arc::get_mut(state).unwrap_or_else(|| unreachable!("HostState is shared only once serving"))
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
                bundles: Mutex::new(HashMap::new()),
                limits: HostLimits::default(),
            }),
            shutdown,
        }
    }

    /// Override the default resource limits (before serving).
    pub fn with_limits(mut self, limits: HostLimits) -> Self {
        state_mut(&mut self.state).limits = limits;
        self
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
        let slots = Arc::new(Semaphore::new(self.state.limits.max_connections));

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                accept = listener.accept() => {
                    let Ok((stream, _addr)) = accept else { continue };
                    // Over the limit: close immediately (stream dropped).
                    let Ok(permit) = slots.clone().try_acquire_owned() else {
                        debug!("connection limit reached");
                        continue;
                    };
                    let conn_id = conn_counter;
                    conn_counter += 1;
                    let state = self.state.clone();
                    let shutdown = self.shutdown.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
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
    // ── Phases 1-2: Noise NK handshake + proven identity, time-boxed ──
    let setup = async {
        let mut transport = NoiseTransport::host_handshake(tcp, &st.host_noise_privkey).await?;
        let (fp, alias) = authenticate_client(&mut transport, &st).await?;
        Ok::<_, SanctumError>((transport, fp, alias))
    };
    let (mut transport, fingerprint, display_alias) = timeout(st.limits.handshake_timeout, setup)
        .await
        .map_err(|_| SanctumError::ConnectionLost("handshake timeout".into()))??;
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
    let idle = tokio::time::sleep(st.limits.idle_timeout);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,

            _ = &mut idle => {
                debug!(conn_id, "idle timeout");
                break;
            }

            result = transport.recv_frame() => {
                idle.as_mut().reset(Instant::now() + st.limits.idle_timeout);
                let frame = match result {
                    Ok(f) => f,
                    Err(e) => {
                        debug!(conn_id, "client disconnected: {e}");
                        break;
                    }
                };
                let handled = match frame.message_type {
                    message_types::PUBLISH_BUNDLE => {
                        on_publish_bundle(&st, &fingerprint, &frame, &mut transport).await?
                    }
                    message_types::REFRESH_OPK => on_refresh_opk(&st, &fingerprint, &frame).await,
                    message_types::RATCHET_KEY_EXCHANGE | message_types::ROOM_MESSAGE => {
                        // I3: stamped with the authenticated sender, routed to
                        // its single recipient. Invalid frames are dropped.
                        match route_to_recipient(&frame, &fingerprint) {
                            Some((to, frame)) => {
                                send_to(&st, &to, frame).await;
                                true
                            }
                            None => false,
                        }
                    }
                    message_types::PING => {
                        transport.send_frame(&codec::pong_frame()).await?;
                        true
                    }
                    _ => false,
                };
                if !handled {
                    invalid_frames += 1;
                    if invalid_frames >= MAX_INVALID_FRAMES {
                        break;
                    }
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
    st.bundles.lock().await.remove(&fingerprint);
    if let Ok(frame) = proto_codec::proto_encode(&WireMessage::PeerLeft(pb::PeerLeft {
        fingerprint: fingerprint.as_str().to_string(),
    })) {
        let _ = st.route_tx.send(RoutedMessage {
            sender: fingerprint.clone(),
            frame,
        });
    }
    transport.shutdown().await;
    debug!(conn_id, "client left");
    Ok(())
}

/// Send `frame` to the connected member `to` (dropped if absent).
async fn send_to(st: &HostState, to: &Fingerprint, frame: Frame) {
    let cid = st.host_service.lock().await.connection_id_for(to);
    let Some(cid) = cid else { return };
    let tx = st.clients.lock().await.get(&cid).cloned();
    if let Some(tx) = tx {
        let _ = tx.send(frame).await;
    }
}

/// Decode a key exchange or room message, stamp the authenticated sender
/// (I3) and return its single recipient. `None` if invalid or self-addressed.
fn route_to_recipient(frame: &Frame, sender: &Fingerprint) -> Option<(Fingerprint, Frame)> {
    let msg = proto_codec::proto_decode(frame).ok()?;
    let (recipient, stamped) = match msg {
        WireMessage::RatchetKeyExchange(mut m) => {
            m.sender_fingerprint = sender.as_str().to_string();
            (
                m.recipient_fingerprint.clone(),
                WireMessage::RatchetKeyExchange(m),
            )
        }
        WireMessage::RoomMessage(mut m) => {
            m.sender_fingerprint = sender.as_str().to_string();
            let to = m.envelope.as_ref()?.recipient_fingerprint.clone();
            (to, WireMessage::RoomMessage(m))
        }
        _ => return None,
    };
    let recipient = Fingerprint::new(recipient).ok()?;
    if &recipient == sender {
        return None;
    }
    Some((recipient, proto_codec::proto_encode(&stamped).ok()?))
}

/// Store a member's bundle, then give it the bundles of members who
/// published before it (one one-time prekey each): it initiates X3DH.
async fn on_publish_bundle(
    st: &HostState,
    me: &Fingerprint,
    frame: &Frame,
    transport: &mut NoiseTransport,
) -> Result<bool, SanctumError> {
    let Ok(WireMessage::PublishBundle(pb::PublishBundle {
        bundle: Some(mut bundle),
    })) = proto_codec::proto_decode(frame)
    else {
        return Ok(false);
    };
    // The bundle must be signed by the authenticated identity.
    match verify_bundle(&bundle, &st.verifier) {
        Ok(v) if &v.fingerprint == me => {}
        _ => return Ok(false),
    }
    let opks: VecDeque<pb::OneTimePreKey> = std::mem::take(&mut bundle.one_time_pre_keys).into();

    let mut to_send = Vec::new();
    let mut depleted = Vec::new();
    {
        let mut bundles = st.bundles.lock().await;
        for (fp, stored) in bundles.iter_mut() {
            if fp == me {
                continue;
            }
            let mut b = stored.bundle.clone();
            b.one_time_pre_keys = stored.opks.pop_front().into_iter().collect();
            if stored.opks.len() < OPK_LOW_WATERMARK {
                depleted.push((fp.clone(), stored.opks.len() as u32));
            }
            to_send.push(b);
        }
        bundles.insert(me.clone(), StoredBundle { bundle, opks });
    }
    for b in to_send {
        let msg = WireMessage::BundleResponse(pb::BundleResponse { bundle: Some(b) });
        transport
            .send_frame(&proto_codec::proto_encode(&msg)?)
            .await?;
    }
    for (fp, remaining) in depleted {
        if let Ok(f) =
            proto_codec::proto_encode(&WireMessage::OPKDepleted(pb::OpkDepleted { remaining }))
        {
            send_to(st, &fp, f).await;
        }
    }
    Ok(true)
}

/// Add fresh one-time prekeys to the sender's pool (bounded).
async fn on_refresh_opk(st: &HostState, me: &Fingerprint, frame: &Frame) -> bool {
    let Ok(WireMessage::RefreshOPK(r)) = proto_codec::proto_decode(frame) else {
        return false;
    };
    if r.new_opks.iter().any(|o| o.public_key.len() != 32) {
        return false;
    }
    let mut bundles = st.bundles.lock().await;
    let Some(stored) = bundles.get_mut(me) else {
        return false;
    };
    for opk in r.new_opks {
        if stored.opks.len() >= MAX_BUNDLE_OPKS {
            break;
        }
        stored.opks.push_back(opk);
    }
    true
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
