# Sanctum — Operational Runbook

## Prerequisites

- Linux (Ubuntu 22.04+ / Debian 12+ recommended)
- Tor daemon installed and running
- Rust toolchain (for building from source)
- A PGP keypair (GPG)

---

## 1. Install Tor

```bash
sudo apt install tor

# Configure Control Port
sudo tee -a /etc/tor/torrc << EOF
ControlPort 9051
CookieAuthentication 1
EOF

sudo systemctl restart tor

# Grant access to the Tor cookie
sudo usermod -aG debian-tor $USER
# Log out and back in for the group change to take effect
```

Verify Tor is running:

```bash
sudo systemctl status tor
# Should show: active (running)
```

---

## 2. Install Sanctum

### Option A: Pre-built Binary

```bash
# Download the latest release
wget https://github.com/sanctum-chat/sanctum/releases/latest/download/sanctum-linux-x86_64

# Verify signature (when available)
# gpg --verify sanctum-linux-x86_64.sig

chmod +x sanctum-linux-x86_64
sudo mv sanctum-linux-x86_64 /usr/local/bin/sanctum
```

### Option B: Build from Source

```bash
git clone https://github.com/sanctum-chat/sanctum.git
cd sanctum
cargo build --release --target x86_64-unknown-linux-musl
sudo cp target/x86_64-unknown-linux-musl/release/sanctum /usr/local/bin/
```

---

## 3. Initial Setup

```bash
# Initialize your Sanctum profile
sanctum init
# → Enter your alias (displayed to others, max 20 characters)
# → Creates ~/.sanctum/ with config.toml

# Import your PGP signing key
# Recommended: use a dedicated signing subkey
gpg --edit-key <YOUR_KEY_ID>
> addkey    # Ed25519, sign only
> save
gpg --export-secret-subkeys <SUBKEY_ID>! > sanctum-signing-key.gpg

sanctum identity import sanctum-signing-key.gpg
sanctum identity show
# → Displays your PGP fingerprint (this is your Sanctum identity)

# Clean up the exported key
shred -u sanctum-signing-key.gpg
```

---

## 4. Host a Room

### Ephemeral Room (nothing on disk)

```bash
sanctum host create "ops-room" --mode ephemeral --chat
# → Creates a Tor Hidden Service
# → Displays .onion address
# → Generates an invite token
# → Opens interactive chat session
```

### Persistent Room (encrypted storage, backlog)

```bash
sanctum host create "base-camp" --mode persistent \
    --backlog-max 500 \
    --backlog-hours 72 \
    --chat
# → Prompts for a storage passphrase (Argon2id key derivation)
# → Creates ~/.sanctum/data/sanctum.db (encrypted)
# → Stable .onion address across restarts
```

### Invite Members

```bash
# Generate an invite token for a specific PGP fingerprint
sanctum room invite <room_id> <bob_pgp_fingerprint>
# → Prints a base64url token

# Send the token to Bob via a secure out-of-band channel
# (Signal, physical meeting, encrypted email, etc.)
```

---

## 5. Join a Room

```bash
# Paste the invite token
sanctum join <invite_token_base64>
# → Connects to the host via Tor
# → Authenticates via PGP challenge-response
# → Establishes E2E sessions with all members
# → Opens interactive chat session

# To rejoin a known room later:
sanctum chat <room_id>
```

---

## 6. Interactive Chat Commands

| Command | Action |
|---------|--------|
| `/help` | Show available commands |
| `/who` | List connected members with roles and fingerprints |
| `/verify <alias>` | Show full PGP fingerprint for out-of-band verification |
| `/status` | Display room mode, Tor health, peer count |
| `/kick <fingerprint>` | Revoke a member (owner/admin only) |
| `/me <action>` | Action message |
| `/clear` | Clear local screen |
| `/exit` or `/quit` | Leave the session (also: Ctrl-C) |

---

## 7. Troubleshooting

| Problem | Diagnosis | Solution |
|---------|-----------|---------|
| `TorUnavailable` | Tor not running or control port inaccessible | `sudo systemctl status tor`, check `torrc` |
| `AuthFailed` | Fingerprint not in allowlist or wrong key | Check `sanctum identity show`, verify the token |
| Slow connection | Normal: Tor adds 1-5s latency | Wait. Verify Tor connectivity: `tor --verify-config` |
| `StorageError` | Wrong passphrase or corrupt DB | Retry passphrase. Backup: `~/.sanctum/data/sanctum.db` |
| `RatchetDesync` | Double Ratchet sessions desynchronized | Automatic re-keying (3 attempts). If failed: `/exit` + `sanctum chat` |
| Ephemeral mode writing to disk | Critical bug | Report immediately. Verify with strace (see below) |
| `Tor: ✗` in status bar | Tor connection lost during session | Session stays open. Wait for reconnect or `/exit` and retry |

---

## 8. Security Hardening

### Ephemeral Mode (Maximum OPSEC)

```bash
# Disable swap (prevents secrets leaking to disk)
sudo swapoff -a

# Disable core dumps
ulimit -c 0

# Allow mlock (prevents keys from being swapped out)
# Option 1: setcap (persistent)
sudo setcap cap_ipc_lock=ep /usr/local/bin/sanctum

# Option 2: ulimit (session only)
ulimit -l unlimited

# Optional: run from a tmpfs (RAM disk)
mkdir -p /tmp/sanctum-session
export HOME=/tmp/sanctum-session
sanctum init
# Everything lives in RAM, vanishes on reboot
```

### Verify Zero Disk Writes (Ephemeral)

```bash
# Run Sanctum under strace to verify no writes to data directory
strace -e trace=open,openat,creat -f \
    sanctum host create test --mode ephemeral \
    2>&1 | grep -v RDONLY

# Should show NO open(..., O_WRONLY) or O_CREAT on ~/.sanctum/data/
```

### File Permissions

```bash
ls -la ~/.sanctum/
# Expected: drwx------ (0700) for directory
# Expected: -rw------- (0600) for all files
```

### Dedicated PGP Subkey

Using a dedicated signing subkey for Sanctum means you can revoke it independently if compromised, without affecting your main PGP key.

---

## 9. Configuration Reference

Configuration file: `~/.sanctum/config.toml`

```toml
[identity]
pgp_key_id = "0xABCD1234"
alias = "alice"                   # Display name (max 20 chars)

[tor]
control_port = 9051
control_auth = "cookie"           # "cookie" | "password"
socks_port = 9050

[network]
ping_interval = 60                # Keepalive interval (seconds)
timeout = 180                     # Disconnect after N seconds without response

[host]
default_mode = "ephemeral"
listen_port = 9738
max_connections = 20

[storage]
data_dir = "~/.sanctum/data"
db_max_size_mb = 256

[logging]
level = "off"
output = "stdout"

[chat]
auto_chat_on_join = true          # Open interactive session after join
backlog_display = 50              # Messages shown from backlog on connect
timestamp_format = "%H:%M"       # Time format in chat
show_system_events = true         # Show join/leave/revoke events

[ui]
banner = true
color = true
```

Precedence: CLI flags > Environment variables (`SANCTUM_*`) > config.toml > defaults.

---

## 10. Persistent Mode Operations

### Backup

```bash
# The database is encrypted — safe to backup as-is
cp ~/.sanctum/data/sanctum.db /secure-backup/sanctum.db.bak

# Keys (also encrypted)
cp -r ~/.sanctum/keys/ /secure-backup/keys.bak/
```

### Restart

```bash
# Stop the host
sanctum host stop

# Restart — room, members, backlog, and .onion address are restored
sanctum host create "base-camp" --mode persistent --chat
# → Prompts for passphrase
# → Restores from existing database
# → Same .onion address
# → Double Ratchet sessions are re-established (members redo X3DH on reconnect)
```

### Garbage Collection

Backlog is automatically cleaned every 15 minutes:

1. Remove messages older than `backlog_max_age_hours` (default: 72h)
2. Remove excess messages beyond `backlog_max_messages` (default: 500/room)
3. `VACUUM` SQLite if database exceeds `db_max_size_mb`
