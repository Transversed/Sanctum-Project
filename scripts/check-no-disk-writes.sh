#!/usr/bin/env bash
# Sanctum — verify invariant I4: zero disk writes in ephemeral mode.
#
# Runs an ephemeral host under strace and fails on ANY file-system write
# (open for writing, create, rename, unlink, mkdir, truncate) outside a
# short allowlist of terminal/pseudo devices.
#
# Usage:
#   scripts/check-no-disk-writes.sh [--local] [path/to/sanctum]
#
#   --local   host without Tor (CI mode). Without it, a running Tor daemon
#             with ControlPort enabled is required.
#
# The profile (`sanctum init`) is created in a throw-away HOME *before*
# tracing starts: creating a profile is allowed to write, hosting is not.
set -euo pipefail

LOCAL_FLAG=""
SANCTUM_BIN="target/debug/sanctum"
for arg in "$@"; do
    case "$arg" in
        --local) LOCAL_FLAG="--local" ;;
        *) SANCTUM_BIN="$arg" ;;
    esac
done
RUN_SECS="${SANCTUM_TRACE_SECS:-5}"

if ! command -v strace &>/dev/null; then
    echo "[sanctum] error: strace not found (apt install strace)"
    exit 2
fi
if [ ! -x "$SANCTUM_BIN" ]; then
    echo "[sanctum] error: binary not found at $SANCTUM_BIN (cargo build first)"
    exit 2
fi
SANCTUM_BIN="$(cd "$(dirname "$SANCTUM_BIN")" && pwd)/$(basename "$SANCTUM_BIN")"

WORK_DIR="$(mktemp -d)"
TRACE_FILE="$WORK_DIR/trace.log"
trap 'rm -rf "$WORK_DIR"' EXIT

export HOME="$WORK_DIR/home"
mkdir -p "$HOME"
cd "$WORK_DIR"

echo "[sanctum] ephemeral disk-write verification"
echo "  binary: $SANCTUM_BIN"
echo "  mode:   ${LOCAL_FLAG:-tor}"

# 1. Profile creation (writes allowed, not traced).
"$SANCTUM_BIN" --no-banner init --alias ci-check >/dev/null

# 2. Ephemeral host under strace, stopped with SIGINT after RUN_SECS.
strace -f -qq -o "$TRACE_FILE" \
    -e trace=open,openat,openat2,creat,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,truncate,ftruncate,link,linkat,symlink,symlinkat \
    timeout -s INT "$RUN_SECS" \
    "$SANCTUM_BIN" --no-banner host create ci-room --mode ephemeral --port 0 $LOCAL_FLAG \
    </dev/null >/dev/null 2>&1 || true

if [ ! -s "$TRACE_FILE" ]; then
    echo "[sanctum] FAIL: empty trace (did the host start?)"
    exit 1
fi

# 3. Every write-like syscall is a violation unless it targets a pseudo device.
ALLOW='"/dev/(null|tty|pts/[0-9]+|ptmx|urandom|random)"|"/proc/self/'
VIOLATIONS="$(grep -E \
    'open(at2?)?\(.*(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)|creat\(|rename(at2?)?\(|unlink(at)?\(|mkdir(at)?\(|truncate\(|link(at)?\(|symlink(at)?\(' \
    "$TRACE_FILE" | grep -Ev "$ALLOW" | grep -v 'ENOENT' || true)"

if [ -n "$VIOLATIONS" ]; then
    echo "[sanctum] FAIL: file-system writes detected in ephemeral mode:"
    echo "$VIOLATIONS" | sed 's/^/    /'
    exit 1
fi

echo "[sanctum] PASS: zero disk writes during an ephemeral host session (${RUN_SECS}s)"
