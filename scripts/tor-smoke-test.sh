#!/usr/bin/env bash
# Sanctum — end-to-end smoke test over the real Tor network.
#
# One owner hosts a room as an onion service; two members join through Tor
# with invitations issued by `/invite`; everybody exchanges one message.
# Checks: SAFECOOKIE auth to the control port, onion service creation,
# SOCKS5 connection, Noise + authentication, bundle exchange, E2E delivery.
#
# Usage:
#   scripts/tor-smoke-test.sh [--local] [--keep] [path/to/sanctum]
#
#   --local   no Tor (loopback), to check the script itself
#   --keep    keep the work directory (logs) even on success
#
# Prerequisites (without --local): Tor running with SocksPort 9050,
# ControlPort 9051, CookieAuthentication 1, CookieAuthFileGroupReadable 1,
# and the current user in Tor's group (debian-tor). Never run with sudo.
set -euo pipefail

LOCAL=""
KEEP=""
BIN="target/release/sanctum"
for arg in "$@"; do
    case "$arg" in
        --local) LOCAL="--local" ;;
        --keep) KEEP=1 ;;
        -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
        *) BIN="$arg" ;;
    esac
done

if [ "$(id -u)" -eq 0 ]; then
    echo "[smoke] refusing to run as root: sanctum must never run with sudo"
    exit 2
fi
if [ ! -x "$BIN" ]; then
    echo "[smoke] binary not found: $BIN (cargo build --release)"
    exit 2
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

# Tor needs time to publish a new onion service descriptor.
if [ -n "$LOCAL" ]; then JOIN_TIMEOUT=20; JOIN_ATTEMPTS=1; else JOIN_TIMEOUT=150; JOIN_ATTEMPTS=3; fi
MSG_TIMEOUT=$(( JOIN_TIMEOUT ))

WORK="$(mktemp -d -t sanctum-tor-smoke-XXXXXX)"
export SANCTUM_PASSPHRASE="smoke-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
declare -A PID FD
STATUS=1

cleanup() {
    for name in "${!PID[@]}"; do kill "${PID[$name]}" 2>/dev/null || true; done
    wait 2>/dev/null || true
    if [ "$STATUS" -eq 0 ] && [ -z "$KEEP" ]; then
        rm -rf "$WORK"
    else
        echo "[smoke] logs kept in $WORK"
    fi
}
trap cleanup EXIT

now() { date +%s; }
log() { echo "[smoke] $*"; }
fail() { log "FAIL: $*"; exit 1; }

init_user() {
    local name="$1"
    mkdir -p "$WORK/$name"
    HOME="$WORK/$name" "$BIN" --no-banner init --alias "$name" \
        | sed -n 's/^\[sanctum\] fingerprint: //p'
}

# start NAME ARGS... — run sanctum with a FIFO as stdin and a log as stdout.
start() {
    local name="$1"; shift
    mkfifo "$WORK/$name.in"
    HOME="$WORK/$name" "$BIN" --no-banner "$@" < "$WORK/$name.in" > "$WORK/$name.log" 2>&1 &
    PID[$name]=$!
    exec {fd}>"$WORK/$name.in"
    FD[$name]=$fd
}

stop() {
    local name="$1"
    kill "${PID[$name]}" 2>/dev/null || true
    wait "${PID[$name]}" 2>/dev/null || true
    eval "exec ${FD[$name]}>&-"
    rm -f "$WORK/$name.in"
    unset 'PID[$name]' 'FD[$name]'
}

say() { echo "$2" >&"${FD[$1]}"; }

# wait_for NAME PATTERN TIMEOUT — wait until NAME's log matches PATTERN.
wait_for() {
    local name="$1" pattern="$2" timeout="$3" start
    start=$(now)
    while [ $(( $(now) - start )) -lt "$timeout" ]; do
        grep -qE "$pattern" "$WORK/$name.log" 2>/dev/null && return 0
        if [ -n "${PID[$name]:-}" ] && ! kill -0 "${PID[$name]}" 2>/dev/null; then
            return 1
        fi
        sleep 1
    done
    return 1
}

T0=$(now)
log "mode: ${LOCAL:-tor}, binary: $BIN"
OWNER_FP=$(init_user owner)
ALICE_FP=$(init_user alice)
BOB_FP=$(init_user bob)
[ -n "$OWNER_FP" ] && [ -n "$ALICE_FP" ] && [ -n "$BOB_FP" ] || fail "init"
log "identities created"

# ── 1. Host: SAFECOOKIE + onion service ──
t=$(now)
start owner host create smoke --chat $LOCAL
wait_for owner "connected as owner" 60 || fail "host did not start:
$(tail -20 "$WORK/owner.log")"
if [ -z "$LOCAL" ]; then
    ONION=$(sed -n 's/^\[sanctum\] hidden service: \(.*\)$/\1/p' "$WORK/owner.log")
    [ -n "$ONION" ] || fail "no onion service reported"
    log "host up in $(( $(now) - t ))s (onion service created, SAFECOOKIE OK)"
else
    log "host up in $(( $(now) - t ))s (local)"
fi

# ── 2. Invitations from the owner's chat ──
invite() {
    local fp="$1" before
    before=$(grep -cE '^[A-Za-z0-9_-]{200,}$' "$WORK/owner.log" || true)
    say owner "/invite $fp 1"
    for _ in $(seq 1 20); do
        local n
        n=$(grep -cE '^[A-Za-z0-9_-]{200,}$' "$WORK/owner.log" || true)
        if [ "$n" -gt "$before" ]; then
            grep -E '^[A-Za-z0-9_-]{200,}$' "$WORK/owner.log" | tail -1
            return 0
        fi
        sleep 0.5
    done
    return 1
}
ALICE_INVITE=$(invite "$ALICE_FP") || fail "no invitation for alice"
BOB_INVITE=$(invite "$BOB_FP") || fail "no invitation for bob"
log "invitations issued"

# ── 3. Members join through Tor (retry while the descriptor propagates) ──
join() {
    local name="$1" token="$2" attempt t
    for attempt in $(seq 1 "$JOIN_ATTEMPTS"); do
        t=$(now)
        start "$name" join "$token"
        if wait_for "$name" "authenticated" "$JOIN_TIMEOUT"; then
            log "$name joined in $(( $(now) - t ))s (attempt $attempt)"
            return 0
        fi
        log "$name: attempt $attempt failed: $(grep -E 'error|refus|timed out' "$WORK/$name.log" | tail -1)"
        cp "$WORK/$name.log" "$WORK/$name.attempt$attempt.log"
        stop "$name"
        sleep 5
    done
    return 1
}
join alice "$ALICE_INVITE" || fail "alice could not join"
join bob "$BOB_INVITE" || fail "bob could not join"

# ── 4. Pairwise E2E sessions ──
wait_encrypted() {
    local name="$1" peers="$2" start lines
    start=$(now)
    while [ $(( $(now) - start )) -lt "$MSG_TIMEOUT" ]; do
        lines=$(wc -l < "$WORK/$name.log")
        say "$name" "/who"
        sleep 2
        if tail -n +"$(( lines + 1 ))" "$WORK/$name.log" | grep -c "🔒 chiffré" \
            | awk -v p="$peers" '{exit !($1 >= p)}'; then
            return 0
        fi
    done
    return 1
}
t=$(now)
for name in owner alice bob; do
    wait_encrypted "$name" 2 || fail "$name has no E2E session with both others"
done
log "E2E sessions established in $(( $(now) - t ))s"

# ── 5. Messages ──
t=$(now)
for name in owner alice bob; do
    say "$name" "hello-from-$name"
done
for reader in owner alice bob; do
    for writer in owner alice bob; do
        [ "$reader" = "$writer" ] && continue
        wait_for "$reader" "\] $writer: hello-from-$writer" "$MSG_TIMEOUT" \
            || fail "$reader did not receive $writer's message"
    done
done
log "6/6 messages delivered and decrypted in $(( $(now) - t ))s"

# ── 6. Exit ──
for name in alice bob owner; do say "$name" "/exit"; done
sleep 2
STATUS=0
log "PASS in $(( $(now) - T0 ))s"
