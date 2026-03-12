#!/usr/bin/env bash
# Sanctum — Tor setup script
# Installs and configures Tor for use with Sanctum.
set -euo pipefail

echo "[sanctum] setting up Tor..."

# ── Step 1: Install Tor ──
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y tor
elif command -v dnf &>/dev/null; then
    sudo dnf install -y tor
elif command -v pacman &>/dev/null; then
    sudo pacman -Sy --noconfirm tor
elif command -v brew &>/dev/null; then
    brew install tor
else
    echo "[sanctum] error: no supported package manager found"
    echo "[sanctum] install Tor manually: https://www.torproject.org/download/"
    exit 1
fi

# ── Step 2: Configure Control Port ──
TOR_RC="/etc/tor/torrc"
NEEDS_RESTART=false

# Remove any existing Sanctum config block to avoid duplicates
if grep -q "# Added by Sanctum" "$TOR_RC" 2>/dev/null; then
    echo "[sanctum] removing old Sanctum config from torrc..."
    sudo sed -i '/# Added by Sanctum/,/^$/d' "$TOR_RC"
fi

# Add clean config block
if ! grep -q "^ControlPort 9051" "$TOR_RC" 2>/dev/null; then
    echo "[sanctum] configuring Tor control port..."
    echo "" | sudo tee -a "$TOR_RC" >/dev/null
    echo "# Added by Sanctum" | sudo tee -a "$TOR_RC" >/dev/null
    echo "ControlPort 9051" | sudo tee -a "$TOR_RC" >/dev/null
    echo "CookieAuthentication 1" | sudo tee -a "$TOR_RC" >/dev/null
    echo "CookieAuthFileGroupReadable 1" | sudo tee -a "$TOR_RC" >/dev/null
    NEEDS_RESTART=true
fi

# Ensure CookieAuthFileGroupReadable is set even if ControlPort already exists
if ! grep -q "^CookieAuthFileGroupReadable 1" "$TOR_RC" 2>/dev/null; then
    echo "CookieAuthFileGroupReadable 1" | sudo tee -a "$TOR_RC" >/dev/null
    NEEDS_RESTART=true
fi

# ── Step 3: Start / restart Tor ──
if [ "$NEEDS_RESTART" = true ]; then
    echo "[sanctum] restarting Tor with new config..."
    sudo systemctl restart tor
    sleep 2
elif ! systemctl is-active --quiet tor 2>/dev/null; then
    sudo systemctl enable tor
    sudo systemctl start tor
    sleep 2
    echo "[sanctum] Tor service started"
else
    echo "[sanctum] Tor already running"
fi

# ── Step 4: Add user to tor group ──
# Detect the Tor group name (debian-tor on Debian/Ubuntu, tor on Arch/Fedora)
if getent group debian-tor &>/dev/null; then
    TOR_GROUP="debian-tor"
elif getent group tor &>/dev/null; then
    TOR_GROUP="tor"
else
    echo "[sanctum] warning: cannot find Tor group (tor or debian-tor)"
    echo "[sanctum] you may need to manually set cookie permissions"
    TOR_GROUP=""
fi

if [ -n "$TOR_GROUP" ]; then
    if ! id -nG "$USER" | grep -qw "$TOR_GROUP"; then
        echo "[sanctum] adding $USER to group $TOR_GROUP..."
        sudo usermod -aG "$TOR_GROUP" "$USER"
        echo ""
        echo "[sanctum] IMPORTANT: you must restart your terminal for the"
        echo "          group change to take effect. IDEs (VSCode, etc.)"
        echo "          must also be fully restarted."
        echo ""
    else
        echo "[sanctum] $USER is already in group $TOR_GROUP"
    fi
fi

# ── Step 5: Verify cookie permissions ──
COOKIE_FILE="/var/lib/tor/control_auth_cookie"

if [ -f "$COOKIE_FILE" ]; then
    COOKIE_PERMS=$(stat -c "%a" "$COOKIE_FILE" 2>/dev/null || stat -f "%Lp" "$COOKIE_FILE" 2>/dev/null)
    COOKIE_SIZE=$(wc -c < "$COOKIE_FILE" 2>/dev/null || echo "0")

    if [ "$COOKIE_SIZE" -eq 32 ]; then
        echo "[sanctum] cookie file: OK ($COOKIE_SIZE bytes)"
    else
        echo "[sanctum] FAIL: cookie has wrong size ($COOKIE_SIZE, expected 32)"
        echo "[sanctum] try: sudo systemctl restart tor"
        exit 1
    fi

    # Check group-readable
    if [ -r "$COOKIE_FILE" ]; then
        echo "[sanctum] cookie readable: OK"
    else
        echo "[sanctum] FAIL: cookie is not readable by current user"
        echo "[sanctum] permissions: $COOKIE_PERMS"
        echo ""
        echo "[sanctum] fixes to try:"
        echo "  1. sudo chmod 640 $COOKIE_FILE"
        echo "  2. Ensure CookieAuthFileGroupReadable 1 is in /etc/tor/torrc"
        echo "  3. sudo systemctl restart tor"
        echo "  4. Restart your terminal (newgrp $TOR_GROUP)"
        exit 1
    fi
else
    echo "[sanctum] warning: cookie file not found at $COOKIE_FILE"
    echo "[sanctum] Tor may not have started correctly"
fi

# ── Step 6: Verify SOCKS5 connectivity ──
SOCKS_PORT=${SANCTUM_TOR_SOCKS_PORT:-9050}
if command -v curl &>/dev/null; then
    if curl -s --max-time 10 --socks5 "127.0.0.1:$SOCKS_PORT" https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
        echo "[sanctum] Tor SOCKS5 proxy: working"
    else
        echo "[sanctum] warning: could not verify Tor SOCKS5 connectivity"
        echo "[sanctum] this may be normal if Tor is still bootstrapping"
    fi
fi

# ── Step 7: Summary ──
echo ""
echo "[sanctum] Tor setup complete"
echo "  SOCKS:   127.0.0.1:$SOCKS_PORT"
echo "  Control: 127.0.0.1:9051"
echo "  Auth:    cookie ($COOKIE_FILE)"
echo "  Group:   ${TOR_GROUP:-unknown}"
echo ""
echo "[sanctum] next: run 'sanctum init' to create your profile"
echo ""
echo "[sanctum] diagnostic command (if auth still fails):"
echo "  cargo build -p sanctum-cli --example chat_demo"
echo "  sudo ./target/debug/examples/chat_demo host"