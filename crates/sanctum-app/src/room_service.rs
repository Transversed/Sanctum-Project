//! Room management: creation, membership, invitations.

use sanctum_domain::entities::invite::InviteToken;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Member, Role};
use sanctum_domain::entities::room::{Room, RoomConfig, RoomId, RoomMode};
use sanctum_domain::errors::SanctumError;

use std::time::{SystemTime, UNIX_EPOCH};

/// Room management service.
pub struct RoomService {
    room: Option<Room>,
}

impl RoomService {
    /// Create a new room service (no room loaded yet).
    pub fn new() -> Self {
        Self { room: None }
    }

    /// Create a new room with the given owner.
    pub fn create_room(
        &mut self,
        name: impl Into<String>,
        mode: RoomMode,
        config: RoomConfig,
        owner_fingerprint: Fingerprint,
        owner_identity_key: Vec<u8>,
        owner_alias: DisplayAlias,
    ) -> Result<&Room, SanctumError> {
        let owner = Member::new(owner_fingerprint, owner_identity_key, owner_alias, Role::Owner, now());
        let mut validated_config = config;
        validated_config.validate();
        let room = Room::new(name, mode, validated_config, owner);
        self.room = Some(room);
        Ok(self.room.as_ref().unwrap())
    }

    /// Load an existing room (from storage or from AuthResult).
    pub fn load_room(&mut self, room: Room) {
        self.room = Some(room);
    }

    /// Get a reference to the current room.
    pub fn room(&self) -> Result<&Room, SanctumError> {
        self.room.as_ref().ok_or_else(|| {
            SanctumError::RoomNotFound(RoomId::new())
        })
    }

    /// Get a mutable reference to the current room.
    pub fn room_mut(&mut self) -> Result<&mut Room, SanctumError> {
        self.room.as_mut().ok_or_else(|| {
            SanctumError::RoomNotFound(RoomId::new())
        })
    }

    /// Add a member to the room. Requires the caller to have invite permissions.
    pub fn add_member(
        &mut self,
        caller_fingerprint: &Fingerprint,
        new_fingerprint: Fingerprint,
        identity_key: Vec<u8>,
        alias: DisplayAlias,
        role: Role,
    ) -> Result<(), SanctumError> {
        let room = self.room_mut()?;

        // Check caller permissions
        let caller = room
            .find_member(caller_fingerprint)
            .ok_or_else(|| SanctumError::MemberNotFound(caller_fingerprint.clone()))?;

        if !caller.role().can_invite() {
            return Err(SanctumError::InsufficientPermissions {
                need: "Admin".into(),
                have: format!("{}", caller.role()),
            });
        }

        let member = Member::new(new_fingerprint, identity_key, alias, role, now());
        room.add_member(member)
    }

    /// Revoke a member. Requires the caller to have kick permissions.
    pub fn revoke_member(
        &mut self,
        caller_fingerprint: &Fingerprint,
        target_fingerprint: &Fingerprint,
    ) -> Result<(), SanctumError> {
        let room = self.room_mut()?;

        let caller = room
            .find_member(caller_fingerprint)
            .ok_or_else(|| SanctumError::MemberNotFound(caller_fingerprint.clone()))?;

        if !caller.role().can_kick() {
            return Err(SanctumError::InsufficientPermissions {
                need: "Admin".into(),
                have: format!("{}", caller.role()),
            });
        }

        room.revoke_member(target_fingerprint)
    }

    /// Generate an invite token.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_invite(
        &self,
        inviter_fingerprint: &Fingerprint,
        invited_fingerprint: Fingerprint,
        role: Role,
        onion_address: String,
        port: u16,
        host_noise_pubkey: Vec<u8>,
        ttl_secs: u64,
    ) -> Result<InviteToken, SanctumError> {
        let room = self.room()?;

        let inviter = room
            .find_member(inviter_fingerprint)
            .ok_or_else(|| SanctumError::MemberNotFound(inviter_fingerprint.clone()))?;

        if !inviter.role().can_invite() {
            return Err(SanctumError::InsufficientPermissions {
                need: "Admin".into(),
                have: format!("{}", inviter.role()),
            });
        }

        let expires_at = now() + ttl_secs;

        Ok(InviteToken {
            room_id: room.id().clone(),
            onion_address,
            port,
            host_noise_pubkey,
            inviter_fingerprint: inviter_fingerprint.clone(),
            invited_fingerprint,
            role,
            expires_at,
            signature: Vec::new(), // Caller signs via IdentityPort
        })
    }

    /// Validate an incoming invite token.
    pub fn validate_invite(
        &self,
        token: &InviteToken,
        local_fingerprint: &Fingerprint,
    ) -> Result<(), SanctumError> {
        if !token.is_for(local_fingerprint) {
            return Err(SanctumError::InvalidInviteToken(
                "token is not for this fingerprint".into(),
            ));
        }

        if token.is_expired(now()) {
            return Err(SanctumError::InviteTokenExpired);
        }

        Ok(())
    }

    /// Check if a fingerprint is authorized in the current room.
    pub fn is_authorized(&self, fingerprint: &Fingerprint) -> bool {
        self.room
            .as_ref()
            .map(|r| r.is_authorized(fingerprint))
            .unwrap_or(false)
    }
}

impl Default for RoomService {
    fn default() -> Self {
        Self::new()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(suffix: &str) -> Fingerprint {
        Fingerprint::new(format!("{:0>40}", suffix)).unwrap()
    }

    fn alias(name: &str) -> DisplayAlias {
        DisplayAlias::new(name).unwrap()
    }

    fn make_svc_with_room() -> (RoomService, Fingerprint) {
        let mut svc = RoomService::new();
        let owner_fp = fp("AA");
        svc.create_room(
            "test",
            RoomMode::Ephemeral,
            RoomConfig::default(),
            owner_fp.clone(),
            vec![0u8; 32],
            alias("owner"),
        )
        .unwrap();
        (svc, owner_fp)
    }

    #[test]
    fn create_room_works() {
        let (svc, _) = make_svc_with_room();
        let room = svc.room().unwrap();
        assert_eq!(room.name(), "test");
        assert_eq!(room.active_member_count(), 1);
    }

    #[test]
    fn add_member_by_owner() {
        let (mut svc, owner_fp) = make_svc_with_room();
        svc.add_member(&owner_fp, fp("BB"), vec![0u8; 32], alias("bob"), Role::Member)
            .unwrap();
        assert_eq!(svc.room().unwrap().active_member_count(), 2);
    }

    #[test]
    fn add_member_by_regular_fails() {
        let (mut svc, owner_fp) = make_svc_with_room();
        svc.add_member(&owner_fp, fp("BB"), vec![0u8; 32], alias("bob"), Role::Member)
            .unwrap();

        // BB (Member) tries to add CC
        let result = svc.add_member(&fp("BB"), fp("CC"), vec![0u8; 32], alias("charlie"), Role::Member);
        assert!(result.is_err());
    }

    #[test]
    fn revoke_member() {
        let (mut svc, owner_fp) = make_svc_with_room();
        svc.add_member(&owner_fp, fp("BB"), vec![0u8; 32], alias("bob"), Role::Member)
            .unwrap();
        svc.revoke_member(&owner_fp, &fp("BB")).unwrap();
        assert!(!svc.is_authorized(&fp("BB")));
    }

    #[test]
    fn revoke_by_member_fails() {
        let (mut svc, owner_fp) = make_svc_with_room();
        svc.add_member(&owner_fp, fp("BB"), vec![0u8; 32], alias("bob"), Role::Member)
            .unwrap();
        svc.add_member(&owner_fp, fp("CC"), vec![0u8; 32], alias("charlie"), Role::Member)
            .unwrap();

        let result = svc.revoke_member(&fp("BB"), &fp("CC"));
        assert!(result.is_err());
    }

    #[test]
    fn generate_invite() {
        let (svc, owner_fp) = make_svc_with_room();
        let token = svc
            .generate_invite(
                &owner_fp,
                fp("BB"),
                Role::Member,
                "abc123.onion".into(),
                9050,
                vec![0u8; 32],
                3600,
            )
            .unwrap();

        assert!(token.is_for(&fp("BB")));
        assert!(!token.is_expired(now()));
    }

    #[test]
    fn validate_invite_wrong_fingerprint() {
        let (svc, owner_fp) = make_svc_with_room();
        let token = svc
            .generate_invite(
                &owner_fp,
                fp("BB"),
                Role::Member,
                "abc.onion".into(),
                9050,
                vec![],
                3600,
            )
            .unwrap();

        // CC tries to use BB's token
        let result = svc.validate_invite(&token, &fp("CC"));
        assert!(result.is_err());
    }

    #[test]
    fn validate_invite_expired() {
        let (svc, owner_fp) = make_svc_with_room();
        let mut token = svc
            .generate_invite(
                &owner_fp,
                fp("BB"),
                Role::Member,
                "abc.onion".into(),
                9050,
                vec![],
                3600,
            )
            .unwrap();

        token.expires_at = 0; // Force expired
        let result = svc.validate_invite(&token, &fp("BB"));
        assert!(result.is_err());
    }
}