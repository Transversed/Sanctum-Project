-- Sanctum Schema v1
-- Applied at first launch or via `sanctum init`

CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
    room_id TEXT NOT NULL,
    fingerprint_hash TEXT NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (room_id, fingerprint_hash),
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL,
    recipient_hash TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    data BLOB NOT NULL,
    stored_at INTEGER NOT NULL,
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
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
);

INSERT OR IGNORE INTO metadata (key, value) VALUES ('schema_version', '1');