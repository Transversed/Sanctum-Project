#!/usr/bin/env bash
# Sanctum — Tor setup script
# Installs and configures Tor for use with Sanctum.
set -euo pipefail

echo "[sanctum] setting up Tor..."

# Detect package manager
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

# Ensure Tor is running
if ! systemctl is-active --quiet tor 2>/dev/null; then
    sudo systemctl enable tor
    sudo systemctl start tor
    echo "[sanctum] Tor service started"
else
    echo "[sanctum] Tor already running"
fi

# Verify Control Port access
CONTROL_PORT=${SANCTUM_TOR_CONTROL_PORT:-9051}
SOCKS_PORT=${SANCTUM_TOR_SOCKS_PORT:-9050}

# Enable control port if not already configured
TOR_RC="/etc/tor/torrc"
if ! grep -q "^ControlPort" "$TOR_RC" 2>/dev/null; then
    echo "[sanctum] enabling Tor control port ($CONTROL_PORT)..."
    echo "" | sudo tee -a "$TOR_RC" >/dev/null
    echo "# Added by Sanctum" | sudo tee -a "$TOR_RC" >/dev/null
    echo "ControlPort $CONTROL_PORT" | sudo tee -a "$TOR_RC" >/dev/null
    echo "CookieAuthentication 1" | sudo tee -a "$TOR_RC" >/dev/null
    sudo systemctl reload tor
    echo "[sanctum] Tor reloaded with control port"
fi

# Verify the current user can read the auth cookie
COOKIE_FILE="/var/lib/tor/control_auth_cookie"
if [ -f "$COOKIE_FILE" ]; then
    if [ -r "$COOKIE_FILE" ]; then
        echo "[sanctum] cookie auth: accessible"
    else
        echo "[sanctum] warning: cannot read $COOKIE_FILE"
        echo "[sanctum] fix: sudo usermod -a -G debian-tor $USER && newgrp debian-tor"
    fi
else
    echo "[sanctum] warning: cookie file not found at $COOKIE_FILE"
fi

# Verify connectivity
if curl -s --socks5 "127.0.0.1:$SOCKS_PORT" https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
    echo "[sanctum] Tor SOCKS5 proxy: working"
else
    echo "[sanctum] warning: could not verify Tor SOCKS5 connectivity"
    echo "[sanctum] ensure Tor is running and SOCKS port is $SOCKS_PORT"
fi

echo ""
echo "[sanctum] Tor setup complete"
echo "  SOCKS:   127.0.0.1:$SOCKS_PORT"
echo "  Control: 127.0.0.1:$CONTROL_PORT"
echo "  Auth:    cookie"
echo ""
echo "[sanctum] next: run 'sanctum init' to create your profile"