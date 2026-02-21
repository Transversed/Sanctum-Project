//! Room member, PGP fingerprint, role, alias.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// PGP fingerprint — primary identity in Sanctum (40 hex chars).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Create from hex string. Must be exactly 40 hex characters.
    pub fn new(hex: impl Into<String>) -> Result<Self, InvalidFingerprint> {
        let hex = hex.into();
        let normalized: String = hex
            .chars()
            .filter(|c| !c.is_whitespace())
            .map(|c| c.to_ascii_uppercase())
            .collect();

        if normalized.len() != 40 {
            return Err(InvalidFingerprint::WrongLength(normalized.len()));
        }
        if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(InvalidFingerprint::InvalidHex);
        }
        Ok(Self(normalized))
    }

    /// Full 40-char fingerprint.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Truncated display: `ABCD..EF01`.
    pub fn short(&self) -> String {
        let len = self.0.len();
        if len >= 8 {
            format!("{}..{}", &self.0[..4], &self.0[len - 4..])
        } else {
            self.0.clone()
        }
    }
}

// Display: truncated to prevent accidental leaks in logs.
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.short())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.short())
    }
}

/// Fingerprint validation error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum InvalidFingerprint {
    /// Wrong length.
    #[error("fingerprint must be 40 hex chars, got {0}")]
    WrongLength(usize),
    /// Non-hex characters.
    #[error("fingerprint contains non-hex characters")]
    InvalidHex,
}

/// Member role. Owner > Admin > Member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Can send/receive messages.
    Member = 0,
    /// Can invite and kick.
    Admin = 1,
    /// Full control. Auto-assigned to host.
    Owner = 2,
}

impl Role {
    /// Can this role invite members?
    pub fn can_invite(&self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }

    /// Can this role kick members?
    pub fn can_kick(&self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }

    /// Can this role promote/demote?
    pub fn can_promote(&self) -> bool {
        matches!(self, Role::Owner)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Owner => write!(f, "Owner"),
            Role::Admin => write!(f, "Admin"),
            Role::Member => write!(f, "Member"),
        }
    }
}

/// Member status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberStatus {
    /// Active member.
    Active,
    /// Revoked — cannot reconnect.
    Revoked,
}

/// Display alias (cosmetic, max 20 chars, `[a-zA-Z0-9_-]`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DisplayAlias(String);

impl DisplayAlias {
    /// Create a validated alias.
    pub fn new(alias: impl Into<String>) -> Result<Self, InvalidAlias> {
        let alias = alias.into();
        if alias.is_empty() || alias.len() > 20 {
            return Err(InvalidAlias::InvalidLength(alias.len()));
        }
        if !alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(InvalidAlias::InvalidCharacters);
        }
        Ok(Self(alias))
    }

    /// Alias as &str.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Alias validation error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum InvalidAlias {
    /// Wrong length.
    #[error("alias must be 1-20 chars, got {0}")]
    InvalidLength(usize),
    /// Forbidden characters.
    #[error("alias must contain only [a-zA-Z0-9_-]")]
    InvalidCharacters,
}

/// A room member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    fingerprint: Fingerprint,
    identity_key: Vec<u8>,
    display_alias: DisplayAlias,
    role: Role,
    joined_at: u64,
    status: MemberStatus,
}

impl Member {
    /// Create an active member.
    pub fn new(
        fingerprint: Fingerprint,
        identity_key: Vec<u8>,
        display_alias: DisplayAlias,
        role: Role,
        joined_at: u64,
    ) -> Self {
        Self {
            fingerprint,
            identity_key,
            display_alias,
            role,
            joined_at,
            status: MemberStatus::Active,
        }
    }

    /// PGP fingerprint.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// X25519 public identity key.
    pub fn identity_key(&self) -> &[u8] {
        &self.identity_key
    }

    /// Display alias.
    pub fn display_alias(&self) -> &DisplayAlias {
        &self.display_alias
    }

    /// Current role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Current status.
    pub fn status(&self) -> MemberStatus {
        self.status
    }

    /// Join timestamp.
    pub fn joined_at(&self) -> u64 {
        self.joined_at
    }

    /// Revoke this member.
    pub fn revoke(&mut self) {
        self.status = MemberStatus::Revoked;
    }

    /// Change role.
    pub fn set_role(&mut self, role: Role) {
        self.role = role;
    }

    /// Is this member active?
    pub fn is_active(&self) -> bool {
        self.status == MemberStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_valid() {
        let fp = Fingerprint::new("4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B").unwrap();
        assert_eq!(fp.as_str(), "4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B");
    }

    #[test]
    fn fingerprint_normalizes_lowercase() {
        let fp = Fingerprint::new("4a7b3c2d8e9f1a0b5c6d7e8f9a0b1c2d3e4f5a6b").unwrap();
        assert_eq!(fp.as_str(), "4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B");
    }

    #[test]
    fn fingerprint_strips_spaces() {
        let fp =
            Fingerprint::new("4A7B 3C2D 8E9F 1A0B 5C6D 7E8F 9A0B 1C2D 3E4F 5A6B").unwrap();
        assert_eq!(fp.as_str().len(), 40);
    }

    #[test]
    fn fingerprint_rejects_short() {
        assert!(Fingerprint::new("4A7B3C2D").is_err());
    }

    #[test]
    fn fingerprint_rejects_non_hex() {
        assert!(Fingerprint::new("ZZZZ3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B").is_err());
    }

    #[test]
    fn fingerprint_display_does_not_leak_full() {
        let fp = Fingerprint::new("4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B").unwrap();
        let display = format!("{}", fp);
        assert!(!display.contains("8E9F1A0B5C6D7E8F"));
        assert!(display.contains("4A7B..5A6B"));
    }

    #[test]
    fn role_ordering() {
        assert!(Role::Owner > Role::Admin);
        assert!(Role::Admin > Role::Member);
    }

    #[test]
    fn role_permissions() {
        assert!(Role::Owner.can_invite());
        assert!(Role::Owner.can_kick());
        assert!(Role::Owner.can_promote());
        assert!(Role::Admin.can_invite());
        assert!(!Role::Admin.can_promote());
        assert!(!Role::Member.can_invite());
    }

    #[test]
    fn alias_valid() {
        assert!(DisplayAlias::new("alice").is_ok());
        assert!(DisplayAlias::new("bob_42").is_ok());
        assert!(DisplayAlias::new("charlie-x").is_ok());
    }

    #[test]
    fn alias_rejects_invalid() {
        assert!(DisplayAlias::new("").is_err());
        assert!(DisplayAlias::new("a".repeat(21)).is_err());
        assert!(DisplayAlias::new("alice@bob").is_err());
    }

    #[test]
    fn member_lifecycle() {
        let fp = Fingerprint::new("4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B").unwrap();
        let alias = DisplayAlias::new("alice").unwrap();
        let mut m = Member::new(fp, vec![0u8; 32], alias, Role::Owner, 1700000000);

        assert!(m.is_active());
        m.revoke();
        assert!(!m.is_active());
    }
}
