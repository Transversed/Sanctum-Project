//! Room: discussion space (ephemeral or persistent).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use super::member::{Fingerprint, Member, MemberStatus, Role};
use crate::errors::SanctumError;

/// Room identifier (UUID v4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoomId(Uuid);

impl RoomId {
    /// Generate a new random room ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Full UUID string.
    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl FromStr for RoomId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl Default for RoomId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0.to_string()[..8])
    }
}

/// Room mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoomMode {
    /// RAM only, no disk writes, no backlog.
    Ephemeral,
    /// Encrypted SQLite, backlog, stable .onion.
    Persistent,
}

impl fmt::Display for RoomMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoomMode::Ephemeral => write!(f, "ephemeral"),
            RoomMode::Persistent => write!(f, "persistent"),
        }
    }
}

/// Room configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomConfig {
    /// Max members (default 10, max 50).
    pub max_members: u16,
    /// Max backlog messages per room.
    pub backlog_max_messages: u32,
    /// Max backlog age in hours.
    pub backlog_max_age_hours: u32,
    /// Padding block size in bytes.
    pub message_padding_block: u16,
}

impl Default for RoomConfig {
    fn default() -> Self {
        Self {
            max_members: 10,
            backlog_max_messages: 500,
            backlog_max_age_hours: 72,
            message_padding_block: 256,
        }
    }
}

impl RoomConfig {
    /// Clamp values to valid ranges.
    pub fn validate(&mut self) {
        self.max_members = self.max_members.clamp(2, 50);
        self.backlog_max_messages = self.backlog_max_messages.clamp(0, 5000);
        self.backlog_max_age_hours = self.backlog_max_age_hours.clamp(0, 720);
        if !self.message_padding_block.is_power_of_two()
            || self.message_padding_block < 64
            || self.message_padding_block > 1024
        {
            self.message_padding_block = 256;
        }
    }
}

/// A Sanctum room.
///
/// Invariants: at least one Owner, no duplicate active fingerprints,
/// active count ≤ max_members.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    id: RoomId,
    name: String,
    mode: RoomMode,
    config: RoomConfig,
    members: Vec<Member>,
}

impl Room {
    /// Create a new room with a mandatory owner.
    pub fn new(
        name: impl Into<String>,
        mode: RoomMode,
        config: RoomConfig,
        owner: Member,
    ) -> Self {
        debug_assert_eq!(owner.role(), Role::Owner);
        Self {
            id: RoomId::new(),
            name: name.into(),
            mode,
            config,
            members: vec![owner],
        }
    }

    /// Restore from storage with a known ID.
    pub fn with_id(
        id: RoomId,
        name: impl Into<String>,
        mode: RoomMode,
        config: RoomConfig,
        members: Vec<Member>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            mode,
            config,
            members,
        }
    }

    /// Room ID.
    pub fn id(&self) -> &RoomId {
        &self.id
    }

    /// Room name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Room mode.
    pub fn mode(&self) -> RoomMode {
        self.mode
    }

    /// Room config.
    pub fn config(&self) -> &RoomConfig {
        &self.config
    }

    /// All members (including revoked).
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// Count of active (non-revoked) members.
    pub fn active_member_count(&self) -> usize {
        self.members.iter().filter(|m| m.is_active()).count()
    }

    /// Is the room at capacity?
    pub fn is_full(&self) -> bool {
        self.active_member_count() >= self.config.max_members as usize
    }

    /// Find a member by fingerprint.
    pub fn find_member(&self, fingerprint: &Fingerprint) -> Option<&Member> {
        self.members.iter().find(|m| m.fingerprint() == fingerprint)
    }

    fn find_member_mut(&mut self, fingerprint: &Fingerprint) -> Option<&mut Member> {
        self.members
            .iter_mut()
            .find(|m| m.fingerprint() == fingerprint)
    }

    /// Add a member. Fails if room is full or fingerprint already active.
    pub fn add_member(&mut self, member: Member) -> Result<(), SanctumError> {
        if self.is_full() {
            return Err(SanctumError::RoomFull {
                current: self.active_member_count() as u16,
                max: self.config.max_members,
            });
        }
        if let Some(existing) = self.find_member(member.fingerprint()) {
            if existing.is_active() {
                return Err(SanctumError::MemberAlreadyExists(
                    member.fingerprint().clone(),
                ));
            }
        }
        self.members.push(member);
        Ok(())
    }

    /// Revoke a member. Cannot revoke the owner.
    pub fn revoke_member(&mut self, fingerprint: &Fingerprint) -> Result<(), SanctumError> {
        let member = self
            .find_member_mut(fingerprint)
            .ok_or_else(|| SanctumError::MemberNotFound(fingerprint.clone()))?;

        if member.role() == Role::Owner {
            return Err(SanctumError::CannotRevokeOwner);
        }
        member.revoke();
        Ok(())
    }

    /// Is this fingerprint authorized (active, not revoked)?
    pub fn is_authorized(&self, fingerprint: &Fingerprint) -> bool {
        self.find_member(fingerprint)
            .map(|m| m.status() == MemberStatus::Active)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::member::DisplayAlias;

    fn make_fp(suffix: &str) -> Fingerprint {
        Fingerprint::new(format!("{:0>40}", suffix)).unwrap()
    }

    fn make_member(suffix: &str, role: Role) -> Member {
        let fp = make_fp(suffix);
        let alias = DisplayAlias::new(format!("user{}", suffix)).unwrap();
        Member::new(fp, vec![0u8; 32], alias, role, 1700000000)
    }

    #[test]
    fn room_creation() {
        let room = Room::new(
            "test-room",
            RoomMode::Ephemeral,
            RoomConfig::default(),
            make_member("AA", Role::Owner),
        );
        assert_eq!(room.name(), "test-room");
        assert_eq!(room.active_member_count(), 1);
    }

    #[test]
    fn room_add_and_reject_duplicate() {
        let mut room = Room::new("t", RoomMode::Ephemeral, RoomConfig::default(), make_member("AA", Role::Owner));
        room.add_member(make_member("BB", Role::Member)).unwrap();
        assert_eq!(room.active_member_count(), 2);
        assert!(room.add_member(make_member("BB", Role::Member)).is_err());
    }

    #[test]
    fn room_full() {
        let config = RoomConfig { max_members: 2, ..Default::default() };
        let mut room = Room::new("t", RoomMode::Ephemeral, config, make_member("AA", Role::Owner));
        room.add_member(make_member("BB", Role::Member)).unwrap();
        assert!(room.is_full());
        assert!(room.add_member(make_member("CC", Role::Member)).is_err());
    }

    #[test]
    fn room_revoke() {
        let mut room = Room::new("t", RoomMode::Ephemeral, RoomConfig::default(), make_member("AA", Role::Owner));
        room.add_member(make_member("BB", Role::Member)).unwrap();
        room.revoke_member(&make_fp("BB")).unwrap();
        assert!(!room.is_authorized(&make_fp("BB")));
    }

    #[test]
    fn room_cannot_revoke_owner() {
        let mut room = Room::new("t", RoomMode::Ephemeral, RoomConfig::default(), make_member("AA", Role::Owner));
        assert!(room.revoke_member(&make_fp("AA")).is_err());
    }

    #[test]
    fn config_validation() {
        let mut config = RoomConfig {
            max_members: 100,
            backlog_max_messages: 10000,
            backlog_max_age_hours: 0,
            message_padding_block: 100,
        };
        config.validate();
        assert_eq!(config.max_members, 50);
        assert_eq!(config.backlog_max_messages, 5000);
        assert_eq!(config.message_padding_block, 256);
    }
}
