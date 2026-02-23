//! Host service: accept connections, route messages, manage backlog.
//!
//! The host is the central relay for a room. It does NOT decrypt E2E
//! messages — it only sees opaque ciphertexts and routes them.

use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::entities::message::MessageEnvelope;
use sanctum_domain::entities::room::{Room, RoomId, RoomMode};
use sanctum_domain::errors::SanctumError;
use sanctum_domain::events::SanctumEvent;

use std::collections::{HashMap, HashSet};
use tokio::sync::broadcast;

/// Connected client metadata.
#[derive(Debug, Clone)]
pub struct ConnectedClient {
    /// Client fingerprint.
    pub fingerprint: Fingerprint,
    /// Connection identifier (opaque, from TransportPort).
    pub connection_id: u64,
    /// Whether X3DH is complete with all peers.
    pub ready: bool,
}

/// Host service state.
pub struct HostService {
    room: Room,
    connected_clients: HashMap<Fingerprint, ConnectedClient>,
    event_tx: broadcast::Sender<SanctumEvent>,
}

impl HostService {
    /// Create a new host service for a room.
    pub fn new(room: Room, event_tx: broadcast::Sender<SanctumEvent>) -> Self {
        Self {
            room,
            connected_clients: HashMap::new(),
            event_tx,
        }
    }

    /// Get the room.
    pub fn room(&self) -> &Room {
        &self.room
    }

    /// Get the room mutably.
    pub fn room_mut(&mut self) -> &mut Room {
        &mut self.room
    }

    /// Get connected clients.
    pub fn connected_clients(&self) -> &HashMap<Fingerprint, ConnectedClient> {
        &self.connected_clients
    }

    /// Register a new authenticated client.
    pub fn register_client(
        &mut self,
        fingerprint: Fingerprint,
        connection_id: u64,
    ) -> Result<(), SanctumError> {
        if !self.room.is_authorized(&fingerprint) {
            return Err(SanctumError::AuthFailed {
                reason: format!("{fingerprint} not authorized in room"),
            });
        }

        let client = ConnectedClient {
            fingerprint: fingerprint.clone(),
            connection_id,
            ready: false,
        };
        self.connected_clients.insert(fingerprint.clone(), client);

        let _ = self.event_tx.send(SanctumEvent::ClientConnected {
            fingerprint,
        });

        Ok(())
    }

    /// Mark a client as ready (X3DH complete with all peers).
    pub fn mark_client_ready(&mut self, fingerprint: &Fingerprint) {
        if let Some(client) = self.connected_clients.get_mut(fingerprint) {
            client.ready = true;
        }
    }

    /// Remove a disconnected client.
    pub fn remove_client(&mut self, fingerprint: &Fingerprint) {
        self.connected_clients.remove(fingerprint);
        let _ = self.event_tx.send(SanctumEvent::ClientDisconnected {
            fingerprint: fingerprint.clone(),
        });
    }

    /// Determine where to route a message. Returns the fingerprints of
    /// all connected, ready clients in the room except the sender.
    pub fn route_recipients(
        &self,
        sender: &Fingerprint,
    ) -> Vec<Fingerprint> {
        self.connected_clients
            .iter()
            .filter(|(fp, client)| *fp != sender && client.ready)
            .map(|(fp, _)| fp.clone())
            .collect()
    }

    /// Get the list of connected fingerprints (for bundle distribution).
    pub fn connected_fingerprints(&self) -> HashSet<Fingerprint> {
        self.connected_clients.keys().cloned().collect()
    }

    /// Check if a fingerprint is currently connected.
    pub fn is_connected(&self, fingerprint: &Fingerprint) -> bool {
        self.connected_clients.contains_key(fingerprint)
    }

    /// Get the connection_id for a fingerprint.
    pub fn connection_id_for(&self, fingerprint: &Fingerprint) -> Option<u64> {
        self.connected_clients.get(fingerprint).map(|c| c.connection_id)
    }

    /// Emit a message received event.
    pub fn emit_message_received(&self, room_id: &RoomId, sender: &Fingerprint, seq: u64) {
        let _ = self.event_tx.send(SanctumEvent::MessageReceived {
            room_id: room_id.clone(),
            sender: sender.clone(),
            seq,
        });
    }

    /// Emit a message delivered event.
    pub fn emit_message_delivered(&self, room_id: &RoomId, recipient: &Fingerprint, seq: u64) {
        let _ = self.event_tx.send(SanctumEvent::MessageDelivered {
            room_id: room_id.clone(),
            recipient: recipient.clone(),
            seq,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sanctum_domain::entities::member::{DisplayAlias, Member, Role};
    use sanctum_domain::entities::room::{RoomConfig, RoomMode};

    fn fp(suffix: &str) -> Fingerprint {
        Fingerprint::new(format!("{:0>40}", suffix)).unwrap()
    }

    fn make_room() -> Room {
        let owner = Member::new(
            fp("AA"),
            vec![0u8; 32],
            DisplayAlias::new("owner").unwrap(),
            Role::Owner,
            1700000000,
        );
        let mut room = Room::new("test", RoomMode::Ephemeral, RoomConfig::default(), owner);
        let bob = Member::new(
            fp("BB"),
            vec![0u8; 32],
            DisplayAlias::new("bob").unwrap(),
            Role::Member,
            1700000000,
        );
        room.add_member(bob).unwrap();
        room
    }

    #[test]
    fn register_authorized_client() {
        let (tx, _rx) = broadcast::channel(16);
        let mut svc = HostService::new(make_room(), tx);
        assert!(svc.register_client(fp("AA"), 1).is_ok());
        assert!(svc.is_connected(&fp("AA")));
    }

    #[test]
    fn register_unauthorized_client_fails() {
        let (tx, _rx) = broadcast::channel(16);
        let mut svc = HostService::new(make_room(), tx);
        assert!(svc.register_client(fp("FF"), 1).is_err());
    }

    #[test]
    fn route_excludes_sender() {
        let (tx, _rx) = broadcast::channel(16);
        let mut svc = HostService::new(make_room(), tx);
        svc.register_client(fp("AA"), 1).unwrap();
        svc.register_client(fp("BB"), 2).unwrap();
        svc.mark_client_ready(&fp("AA"));
        svc.mark_client_ready(&fp("BB"));

        let recipients = svc.route_recipients(&fp("AA"));
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0], fp("BB"));
    }

    #[test]
    fn route_excludes_not_ready() {
        let (tx, _rx) = broadcast::channel(16);
        let mut svc = HostService::new(make_room(), tx);
        svc.register_client(fp("AA"), 1).unwrap();
        svc.register_client(fp("BB"), 2).unwrap();
        svc.mark_client_ready(&fp("AA"));
        // BB not ready

        let recipients = svc.route_recipients(&fp("AA"));
        assert!(recipients.is_empty());
    }

    #[test]
    fn remove_client() {
        let (tx, _rx) = broadcast::channel(16);
        let mut svc = HostService::new(make_room(), tx);
        svc.register_client(fp("AA"), 1).unwrap();
        svc.remove_client(&fp("AA"));
        assert!(!svc.is_connected(&fp("AA")));
    }
}