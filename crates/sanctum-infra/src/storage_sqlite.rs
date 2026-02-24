//! SQLite encrypted storage adapter for persistent mode.
//!
//! Data is stored as AES-256-GCM encrypted blobs in SQLite.
//! The DB file itself is not encrypted; individual fields are.

use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::entities::room::RoomId;
use sanctum_domain::errors::SanctumError;

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Schema version.
const SCHEMA_VERSION: &str = "1";

/// SQLite storage adapter.
pub struct SqliteStorageAdapter {
    conn: Connection,
}

impl SqliteStorageAdapter {
    /// Open or create a SQLite database at the given path.
    pub fn open(path: &Path) -> Result<Self, SanctumError> {
        let conn = Connection::open(path)
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        let adapter = Self { conn };
        adapter.run_migrations()?;
        Ok(adapter)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, SanctumError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        let adapter = Self { conn };
        adapter.run_migrations()?;
        Ok(adapter)
    }

    /// Run schema migrations.
    fn run_migrations(&self) -> Result<(), SanctumError> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS rooms (
                    id TEXT PRIMARY KEY,
                    data BLOB NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS members (
                    room_id TEXT NOT NULL,
                    fingerprint_hash TEXT NOT NULL,
                    data BLOB NOT NULL,
                    PRIMARY KEY (room_id, fingerprint_hash),
                    FOREIGN KEY (room_id) REFERENCES rooms(id)
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_id TEXT NOT NULL,
                    recipient_hash TEXT NOT NULL,
                    sequence_number INTEGER NOT NULL,
                    data BLOB NOT NULL,
                    stored_at INTEGER NOT NULL,
                    FOREIGN KEY (room_id) REFERENCES rooms(id)
                );

                CREATE INDEX IF NOT EXISTS idx_messages_backlog
                    ON messages(room_id, recipient_hash, sequence_number);
                CREATE INDEX IF NOT EXISTS idx_messages_expiry
                    ON messages(stored_at);

                CREATE TABLE IF NOT EXISTS keys (
                    key_type TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    data BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    PRIMARY KEY (key_type, key_id)
                );

                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );",
            )
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        // Set schema version if not present
        self.conn
            .execute(
                "INSERT OR IGNORE INTO metadata (key, value) VALUES ('schema_version', ?1)",
                params![SCHEMA_VERSION],
            )
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Store a room (data should be encrypted by caller).
    pub fn store_room(
        &self,
        room_id: &RoomId,
        encrypted_data: &[u8],
        created_at: u64,
    ) -> Result<(), SanctumError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO rooms (id, data, created_at) VALUES (?1, ?2, ?3)",
                params![room_id.as_str(), encrypted_data, created_at as i64],
            )
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Load a room's encrypted data.
    pub fn load_room(&self, room_id: &RoomId) -> Result<Option<Vec<u8>>, SanctumError> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM rooms WHERE id = ?1")
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        let result = stmt
            .query_row(params![room_id.as_str()], |row| row.get::<_, Vec<u8>>(0))
            .optional()
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        Ok(result)
    }

    /// Store a member (data encrypted by caller).
    pub fn store_member(
        &self,
        room_id: &RoomId,
        fingerprint: &Fingerprint,
        encrypted_data: &[u8],
    ) -> Result<(), SanctumError> {
        let fp_hash = hash_fingerprint(fingerprint);
        self.conn
            .execute(
                "INSERT OR REPLACE INTO members (room_id, fingerprint_hash, data) VALUES (?1, ?2, ?3)",
                params![room_id.as_str(), fp_hash, encrypted_data],
            )
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Store a backlog message.
    pub fn store_message(
        &self,
        room_id: &RoomId,
        recipient: &Fingerprint,
        sequence_number: u64,
        encrypted_data: &[u8],
        stored_at: u64,
    ) -> Result<(), SanctumError> {
        let recipient_hash = hash_fingerprint(recipient);
        self.conn
            .execute(
                "INSERT INTO messages (room_id, recipient_hash, sequence_number, data, stored_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    room_id.as_str(),
                    recipient_hash,
                    sequence_number as i64,
                    encrypted_data,
                    stored_at as i64,
                ],
            )
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Fetch backlog messages for a recipient.
    pub fn fetch_backlog(
        &self,
        room_id: &RoomId,
        recipient: &Fingerprint,
        since_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, SanctumError> {
        let recipient_hash = hash_fingerprint(recipient);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sequence_number, data FROM messages
                 WHERE room_id = ?1 AND recipient_hash = ?2 AND sequence_number > ?3
                 ORDER BY sequence_number ASC",
            )
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        let rows = stmt
            .query_map(
                params![room_id.as_str(), recipient_hash, since_seq as i64],
                |row| {
                    Ok((row.get::<_, i64>(0)? as u64, row.get::<_, Vec<u8>>(1)?))
                },
            )
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| SanctumError::StorageError(e.to_string()))?);
        }
        Ok(results)
    }

    /// Purge messages older than max_age_secs.
    pub fn purge_expired(&self, max_age_secs: u64) -> Result<u64, SanctumError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(max_age_secs) as i64;

        let deleted = self
            .conn
            .execute("DELETE FROM messages WHERE stored_at < ?1", params![cutoff])
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        Ok(deleted as u64)
    }

    /// Purge excess messages per room (keep newest N).
    pub fn purge_excess(
        &self,
        room_id: &RoomId,
        max_messages: u32,
    ) -> Result<u64, SanctumError> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM messages WHERE room_id = ?1 AND id NOT IN (
                    SELECT id FROM messages WHERE room_id = ?1
                    ORDER BY sequence_number DESC LIMIT ?2
                )",
                params![room_id.as_str(), max_messages as i64],
            )
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        Ok(deleted as u64)
    }

    /// Get schema version.
    pub fn schema_version(&self) -> Result<String, SanctumError> {
        let version: String = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;
        Ok(version)
    }

    /// Store a key (encrypted by caller).
    pub fn store_key(
        &self,
        key_type: &str,
        key_id: &str,
        encrypted_data: &[u8],
        created_at: u64,
        expires_at: Option<u64>,
    ) -> Result<(), SanctumError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO keys (key_type, key_id, data, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    key_type,
                    key_id,
                    encrypted_data,
                    created_at as i64,
                    expires_at.map(|e| e as i64),
                ],
            )
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Load a key.
    pub fn load_key(
        &self,
        key_type: &str,
        key_id: &str,
    ) -> Result<Option<Vec<u8>>, SanctumError> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM keys WHERE key_type = ?1 AND key_id = ?2")
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        let result = stmt
            .query_row(params![key_type, key_id], |row| row.get::<_, Vec<u8>>(0))
            .optional()
            .map_err(|e| SanctumError::StorageError(e.to_string()))?;

        Ok(result)
    }
}

/// Hash a fingerprint for storage (privacy: don't store raw fingerprints).
fn hash_fingerprint(fp: &Fingerprint) -> String {
    let mut hasher = Sha256::new();
    hasher.update(fp.as_str().as_bytes());
    hex::encode(hasher.finalize())
}

/// Tiny hex encoding (no external dep needed).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Extension trait for optional query results.
trait OptionalExt<T> {
    /// Convert a query result to Option, treating NotFound as None.
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(s: &str) -> Fingerprint {
        Fingerprint::new(format!("{:0>40}", s)).unwrap()
    }

    #[test]
    fn open_and_schema_version() {
        let store = SqliteStorageAdapter::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), "1");
    }

    #[test]
    fn store_and_load_room() {
        let store = SqliteStorageAdapter::open_in_memory().unwrap();
        let room_id = RoomId::new();
        let data = b"encrypted room data";
        store.store_room(&room_id, data, 1700000000).unwrap();
        let loaded = store.load_room(&room_id).unwrap().unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn load_nonexistent_room() {
        let store = SqliteStorageAdapter::open_in_memory().unwrap();
        assert!(store.load_room(&RoomId::new()).unwrap().is_none());
    }

    #[test]
    fn store_and_fetch_backlog() {
        let store = SqliteStorageAdapter::open_in_memory().unwrap();
        let room_id = RoomId::new();
        let recipient = fp("BB");

        // Need a room first (FK constraint)
        store.store_room(&room_id, b"room", 0).unwrap();

        store.store_message(&room_id, &recipient, 1, b"msg1", 1000).unwrap();
        store.store_message(&room_id, &recipient, 2, b"msg2", 1001).unwrap();
        store.store_message(&room_id, &recipient, 3, b"msg3", 1002).unwrap();

        let backlog = store.fetch_backlog(&room_id, &recipient, 1).unwrap();
        assert_eq!(backlog.len(), 2); // seq 2, 3
        assert_eq!(backlog[0].0, 2);
        assert_eq!(backlog[1].0, 3);
    }

    #[test]
    fn purge_expired() {
        let store = SqliteStorageAdapter::open_in_memory().unwrap();
        let room_id = RoomId::new();
        let recipient = fp("BB");
        store.store_room(&room_id, b"room", 0).unwrap();

        // Store message with old timestamp
        store.store_message(&room_id, &recipient, 1, b"old", 100).unwrap();
        // Store message with recent timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        store.store_message(&room_id, &recipient, 2, b"new", now).unwrap();

        let purged = store.purge_expired(3600).unwrap(); // 1h max age
        assert_eq!(purged, 1);

        let remaining = store.fetch_backlog(&room_id, &recipient, 0).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, 2);
    }

    #[test]
    fn store_and_load_key() {
        let store = SqliteStorageAdapter::open_in_memory().unwrap();
        store.store_key("identity", "ik_001", b"secret", 1000, None).unwrap();
        let loaded = store.load_key("identity", "ik_001").unwrap().unwrap();
        assert_eq!(loaded, b"secret");
    }

    #[test]
    fn load_nonexistent_key() {
        let store = SqliteStorageAdapter::open_in_memory().unwrap();
        assert!(store.load_key("x", "y").unwrap().is_none());
    }

    #[test]
    fn store_member() {
        let store = SqliteStorageAdapter::open_in_memory().unwrap();
        let room_id = RoomId::new();
        store.store_room(&room_id, b"room", 0).unwrap();
        store.store_member(&room_id, &fp("AA"), b"member_data").unwrap();
        // No error = success (we don't have a load_member yet, just verifying FK works)
    }

    #[test]
    fn fingerprint_hashing_is_deterministic() {
        let h1 = hash_fingerprint(&fp("AA"));
        let h2 = hash_fingerprint(&fp("AA"));
        assert_eq!(h1, h2);

        let h3 = hash_fingerprint(&fp("BB"));
        assert_ne!(h1, h3);
    }
}