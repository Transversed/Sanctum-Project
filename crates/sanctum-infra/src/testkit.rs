//! Test support: a real host on loopback with an owner identity, and
//! helpers to issue invitations and connect members.
//!
//! Compiled only for tests and with the `test-support` feature. Panicking
//! on setup failures is the desired behaviour here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::client_connector::{self, ClientCredentials, ConnectedSession};
use crate::codec::Frame;
use crate::host_listener::{HostLimits, HostListener};
use crate::identity::IdentityAdapter;
use crate::invite_codec::{self, InviteTarget};
use sanctum_app::auth_service::unix_now;
use sanctum_app::host_service::HostService;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Member, Role};
use sanctum_domain::entities::room::{Room, RoomConfig, RoomId, RoomMode};
use sanctum_domain::errors::SanctumError;
use sanctum_domain::events::SanctumEvent;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;

/// A running host bound to 127.0.0.1 on an ephemeral port.
pub struct TestHost {
    pub addr: String,
    pub port: u16,
    pub noise_pub: Vec<u8>,
    pub owner: Arc<IdentityAdapter>,
    pub room_id: RoomId,
    shutdown: CancellationToken,
}

impl TestHost {
    /// Start a host whose room is owned by a fresh identity.
    pub async fn start() -> Self {
        Self::start_with_config(RoomConfig::default()).await
    }

    /// Start a host with a custom room configuration.
    pub async fn start_with_config(config: RoomConfig) -> Self {
        Self::start_with(config, HostLimits::default()).await
    }

    /// Start a host and receive a copy of every frame it decrypts.
    pub async fn start_with_tap() -> (Self, tokio::sync::mpsc::UnboundedReceiver<Frame>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let host = Self::start_inner(RoomConfig::default(), HostLimits::default(), Some(tx)).await;
        (host, rx)
    }

    /// Start a host with custom room configuration and limits.
    pub async fn start_with(config: RoomConfig, limits: HostLimits) -> Self {
        Self::start_inner(config, limits, None).await
    }

    async fn start_inner(
        config: RoomConfig,
        limits: HostLimits,
        tap: Option<tokio::sync::mpsc::UnboundedSender<Frame>>,
    ) -> Self {
        let owner = Arc::new(IdentityAdapter::generate());
        let member = Member::new(
            owner.fingerprint().clone(),
            owner.public_key_bytes(),
            DisplayAlias::new("owner").expect("alias"),
            Role::Owner,
            unix_now(),
        );
        let room = Room::new("test-room", RoomMode::Ephemeral, config, member);
        let room_id = room.id().clone();
        let (event_tx, _) = broadcast::channel::<SanctumEvent>(64);
        let (noise_priv, noise_pub) = crate::noise_keygen().expect("noise keygen");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let shutdown = CancellationToken::new();
        let host = HostListener::new(
            format!("127.0.0.1:{port}"),
            HostService::new(room, event_tx),
            noise_pub.clone(),
            noise_priv,
            shutdown.clone(),
        )
        .with_limits(limits);
        let host = match tap {
            Some(tap) => host.with_tap(tap),
            None => host,
        };
        tokio::spawn(async move {
            let _ = host.serve(listener).await;
        });
        Self {
            addr: format!("127.0.0.1:{port}"),
            port,
            noise_pub,
            owner,
            room_id,
            shutdown,
        }
    }

    /// Where invitations point to.
    pub fn target(&self) -> InviteTarget {
        InviteTarget {
            room_id: self.room_id.clone(),
            onion_address: "127.0.0.1".into(),
            port: self.port,
            host_noise_pubkey: self.noise_pub.clone(),
        }
    }

    /// Encoded owner-signed invitation for `who`, valid one hour.
    pub fn invite(&self, who: &Fingerprint) -> String {
        let token = invite_codec::create_signed_invite(
            self.owner.as_ref(),
            &self.target(),
            who.clone(),
            Role::Member,
            unix_now() + 3600,
        )
        .expect("invite");
        invite_codec::encode_invite(&token).expect("encode")
    }

    /// Connect and authenticate `identity`.
    pub async fn connect(
        &self,
        identity: &IdentityAdapter,
        alias: &str,
        invite: Option<&str>,
    ) -> Result<ConnectedSession, SanctumError> {
        let creds = ClientCredentials {
            identity,
            display_alias: alias,
            invite_token: invite,
        };
        timeout(
            Duration::from_secs(5),
            client_connector::connect_and_auth(&self.addr, &creds, &self.noise_pub),
        )
        .await
        .map_err(|_| SanctumError::ConnectionLost("connect timeout".into()))?
    }

    /// Connect as the room owner.
    pub async fn connect_owner(&self) -> ConnectedSession {
        self.connect(&self.owner, "owner", None)
            .await
            .expect("owner connects")
    }

    /// Create a new identity, invite it and connect it.
    pub async fn join(&self, alias: &str) -> (IdentityAdapter, ConnectedSession) {
        let identity = IdentityAdapter::generate();
        let invite = self.invite(identity.fingerprint());
        let session = self
            .connect(&identity, alias, Some(&invite))
            .await
            .expect("invited member connects");
        (identity, session)
    }
}

impl Drop for TestHost {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}
