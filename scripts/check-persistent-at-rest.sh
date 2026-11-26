#!/usr/bin/env bash
# Sanctum — verify invariant I6: a persistent host writes nothing in clear,
# and nothing outside its room store.
#
# Runs a persistent host (headless, --local) under strace while a member is
# admitted (which triggers a save), then checks that:
#   1. every file-system write targets the store directory;
#   2. the store holds only <room_id>/state.sanctum and <room_id>/lock;
#   3. the state file is sealed (SANCTUMS) and contains none of the room
#      name, the fingerprints or the aliases;
#   4. after a restart the admission is still there.
#
# Usage: scripts/check-persistent-at-rest.sh [path/to/sanctum]
set -euo pipefail

SANCTUM_BIN="${1:-target/debug/sanctum}"
if ! command -v strace &>/dev/null; then
    echo "[sanctum] error: strace not found (apt install strace)"
    exit 2
fi
if [ ! -x "$SANCTUM_BIN" ]; then
    echo "[sanctum] error: binary not found at $SANCTUM_BIN (cargo build first)"
    exit 2
fi
SANCTUM_BIN="$(cd "$(dirname "$SANCTUM_BIN")" && pwd)/$(basename "$SANCTUM_BIN")"

WORK="$(mktemp -d)"
trap 'pkill -f -- "host create $ROOM_NAME" 2>/dev/null || true; rm -rf "$WORK"' EXIT
STORE="$WORK/store"
ROOM_NAME="i6-room-name-marker"
export SANCTUM_PASSPHRASE="ci-identity-passphrase"      # test identities only
export SANCTUM_HOST_PASSPHRASE="ci-host-store-passphrase" # test store only

as() { local who="$1"; shift; HOME="$WORK/$who" "$SANCTUM_BIN" --no-banner "$@"; }
field() { sed -n "s/^\[sanctum\] $1: //p" | head -n1; }

echo "[sanctum] persistent at-rest verification (I6)"
mkdir -p "$WORK/owner" "$WORK/member" "$WORK/host"
as owner init --alias i6owner >/dev/null
as member init --alias i6member >/dev/null
OWNER_PK="$(as owner identity show | field 'public key')"
OWNER_FP="$(as owner identity show | field 'fingerprint')"
MEMBER_FP="$(as member identity show | field 'fingerprint')"

# 1. Headless host under strace (writes traced), in the background.
HOME="$WORK/host" strace -f -qq -o "$WORK/trace.log" \
    -e trace=open,openat,openat2,creat,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,truncate,ftruncate,link,linkat,symlink,symlinkat \
    "$SANCTUM_BIN" --no-banner host create "$ROOM_NAME" --mode persistent \
    --owner-key "$OWNER_PK" --local --port 0 --data-dir "$STORE" \
    </dev/null >"$WORK/host.out" 2>&1 &
HOST_PID=$!
for _ in $(seq 1 100); do
    grep -q "relay running" "$WORK/host.out" 2>/dev/null && break
    sleep 0.2
done
grep -q "relay running" "$WORK/host.out" || { cat "$WORK/host.out"; echo "FAIL: host did not start"; exit 1; }
ROOM_ID="$(field 'room id' <"$WORK/host.out")"

# 2. The owner issues an invitation on "their" machine; the member is admitted.
OWNER_CMD="$(grep -m1 'sanctum room invite' "$WORK/host.out" | sed 's/^ *sanctum //')"
# shellcheck disable=SC2086 # the printed command is split on purpose
INVITE_ARGS=(${OWNER_CMD/$OWNER_FP/$MEMBER_FP})
TOKEN="$(as owner "${INVITE_ARGS[@]}" | grep -E '^[A-Za-z0-9_-]{200,}$' | tail -n1)"
as member join "$TOKEN" --no-chat </dev/null >"$WORK/join.out" 2>&1 \
    || { cat "$WORK/join.out"; echo "FAIL: member not admitted"; exit 1; }
sleep 0.5
# SIGINT to the host itself (strace exits with its tracee).
pkill -INT -f -- "host create $ROOM_NAME" || true
wait "$HOST_PID" 2>/dev/null || true
HOST_PID=""

# 3. Every write targets the store (or a pseudo device).
ALLOW="\"$STORE(/|\")|\"/dev/(null|tty|pts/[0-9]+|ptmx|urandom|random)\"|\"/proc/self/"
VIOLATIONS="$(grep -E \
    'open(at2?)?\(.*(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)|creat\(|rename(at2?)?\(|unlink(at)?\(|mkdir(at)?\(|truncate\(|link(at)?\(|symlink(at)?\(' \
    "$WORK/trace.log" | grep -Ev "$ALLOW" | grep -v 'ENOENT' || true)"
if [ -n "$VIOLATIONS" ]; then
    echo "[sanctum] FAIL: writes outside the room store:"
    echo "$VIOLATIONS" | sed 's/^/    /'
    exit 1
fi
if ! grep -qE "rename(at2?)?\(.*\"$STORE/$ROOM_ID/state\.sanctum\"" "$WORK/trace.log"; then
    echo "[sanctum] FAIL: the state was never saved atomically"
    exit 1
fi

# 4. Only the sealed state and the lock remain.
FILES="$(cd "$STORE" && find . -type f | sort | tr '\n' ' ')"
if [ "$FILES" != "./$ROOM_ID/lock ./$ROOM_ID/state.sanctum " ]; then
    echo "[sanctum] FAIL: unexpected files in the store: $FILES"
    exit 1
fi
STATE="$STORE/$ROOM_ID/state.sanctum"
[ "$(head -c 8 "$STATE")" = "SANCTUMS" ] || { echo "FAIL: state file is not sealed"; exit 1; }
for needle in "$ROOM_NAME" "$OWNER_FP" "$MEMBER_FP" i6owner i6member owner; do
    if grep -aqF "$needle" "$STATE"; then
        echo "[sanctum] FAIL: '$needle' is stored in clear"
        exit 1
    fi
done

# 5. The admission survived: the room has two members after a restart.
HOME="$WORK/host" timeout -s INT 15 "$SANCTUM_BIN" --no-banner host start --local \
    --data-dir "$STORE" </dev/null >"$WORK/restart.out" 2>&1 || true
if ! grep -q "(2 members, 0 revoked)" "$WORK/restart.out"; then
    cat "$WORK/restart.out"
    echo "[sanctum] FAIL: the admitted member was not saved"
    exit 1
fi

echo "[sanctum] PASS: persistent host writes only its sealed store, nothing in clear"
