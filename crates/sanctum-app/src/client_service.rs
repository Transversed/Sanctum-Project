//! Client-side service: connection, authentication, message exchange.
//!
//! Manages the client's view of a session: connecting to a host,
//! authenticating, and maintaining the local state.

use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Role};
use sanctum_domain::entities::room::RoomId;
use sanctum_domain::errors::SanctumError;

/// Client connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Not connected.
    Disconnected,
    /// Noise handshake in progress.
    Handshaking,
    /// PGP auth in progress.
    Authenticating,
    /// Authenticated, X3DH in progress.
    Synchronizing,
    /// Fully ready, can send/receive messages.
    Ready,
}

/// Information about the local user in the session.
#[derive(Debug, Clone)]
pub struct LocalIdentity {
    /// Our PGP fingerprint.
    pub fingerprint: Fingerprint,
    /// Our display alias.
    pub display_alias: DisplayAlias,
    /// Our role in the room.
    pub role: Role,
}

/// Client service state.
pub struct ClientService {
    state: ClientState,
    local_identity: Option<LocalIdentity>,
    room_id: Option<RoomId>,
    connection_id: Option<u64>,
}

impl ClientService {
    /// Create a new disconnected client service.
    pub fn new() -> Self {
        Self {
            state: ClientState::Disconnected,
            local_identity: None,
            room_id: None,
            connection_id: None,
        }
    }

    /// Current connection state.
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// Transition to handshaking state.
    pub fn begin_handshake(&mut self, connection_id: u64) {
        self.connection_id = Some(connection_id);
        self.state = ClientState::Handshaking;
    }

    /// Transition to authenticating state (Noise handshake complete).
    pub fn handshake_complete(&mut self) {
        self.state = ClientState::Authenticating;
    }

    /// Transition to synchronizing state (PGP auth complete).
    pub fn auth_complete(
        &mut self,
        identity: LocalIdentity,
        room_id: RoomId,
    ) {
        self.local_identity = Some(identity);
        self.room_id = Some(room_id);
        self.state = ClientState::Synchronizing;
    }

    /// Transition to ready state (X3DH complete with all peers).
    pub fn synchronization_complete(&mut self) {
        self.state = ClientState::Ready;
    }

    /// Mark as disconnected.
    pub fn disconnect(&mut self) {
        self.state = ClientState::Disconnected;
        self.connection_id = None;
    }

    /// Can we send messages?
    pub fn is_ready(&self) -> bool {
        self.state == ClientState::Ready
    }

    /// Get local identity (available after auth).
    pub fn local_identity(&self) -> Option<&LocalIdentity> {
        self.local_identity.as_ref()
    }

    /// Get room ID (available after auth).
    pub fn room_id(&self) -> Option<&RoomId> {
        self.room_id.as_ref()
    }

    /// Get connection ID.
    pub fn connection_id(&self) -> Option<u64> {
        self.connection_id
    }
}

impl Default for ClientService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fp() -> Fingerprint {
        Fingerprint::new("4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B").unwrap()
    }

    fn test_identity() -> LocalIdentity {
        LocalIdentity {
            fingerprint: test_fp(),
            display_alias: DisplayAlias::new("alice").unwrap(),
            role: Role::Member,
        }
    }

    #[test]
    fn state_transitions() {
        let mut svc = ClientService::new();
        assert_eq!(svc.state(), ClientState::Disconnected);
        assert!(!svc.is_ready());

        svc.begin_handshake(1);
        assert_eq!(svc.state(), ClientState::Handshaking);

        svc.handshake_complete();
        assert_eq!(svc.state(), ClientState::Authenticating);

        svc.auth_complete(test_identity(), RoomId::new());
        assert_eq!(svc.state(), ClientState::Synchronizing);
        assert!(svc.local_identity().is_some());

        svc.synchronization_complete();
        assert_eq!(svc.state(), ClientState::Ready);
        assert!(svc.is_ready());

        svc.disconnect();
        assert_eq!(svc.state(), ClientState::Disconnected);
    }

    #[test]
    fn identity_available_after_auth() {
        let mut svc = ClientService::new();
        assert!(svc.local_identity().is_none());

        svc.begin_handshake(1);
        svc.handshake_complete();
        svc.auth_complete(test_identity(), RoomId::new());

        let id = svc.local_identity().unwrap();
        assert_eq!(id.fingerprint, test_fp());
        assert_eq!(id.role, Role::Member);
    }
}