#!/usr/bin/env bash
# Sanctum — Verify zero disk writes in ephemeral mode (AT-07)
#
# Uses strace to monitor file system writes during an ephemeral session.
# Any write to the data directory is a FAILURE.
set -euo pipefail

SANCTUM_BIN="${1:-target/release/sanctum}"
DATA_DIR="${SANCTUM_DATA_DIR:-$HOME/.sanctum/data}"

if ! command -v strace &>/dev/null; then
    echo "[sanctum] error: strace not found — install with: sudo apt install strace"
    exit 1
fi

if [ ! -f "$SANCTUM_BIN" ]; then
    echo "[sanctum] error: binary not found at $SANCTUM_BIN"
    echo "[sanctum] build first: cargo build --release"
    exit 1
fi

echo "[sanctum] ephemeral disk write verification"
echo "  binary:   $SANCTUM_BIN"
echo "  data_dir: $DATA_DIR"
echo ""

# Create a trace of all file operations
TRACE_FILE=$(mktemp /tmp/sanctum-strace-XXXXXX.log)

echo "[sanctum] tracing file operations..."
strace -f -e trace=open,openat,creat,write,rename,unlink \
    -o "$TRACE_FILE" \
    "$SANCTUM_BIN" --no-banner status 2>/dev/null || true

# Check for writes to data directory
VIOLATIONS=$(grep -c "$DATA_DIR" "$TRACE_FILE" 2>/dev/null || echo "0")

if [ "$VIOLATIONS" -eq 0 ]; then
    echo "[sanctum] PASS: zero writes to $DATA_DIR"
else
    echo "[sanctum] FAIL: $VIOLATIONS file operations detected in $DATA_DIR"
    echo ""
    grep "$DATA_DIR" "$TRACE_FILE"
    rm -f "$TRACE_FILE"
    exit 1
fi

# Also check for temp files created by crossterm or other deps
TEMP_VIOLATIONS=$(grep -cE "(O_WRONLY|O_CREAT|O_TRUNC).*(/tmp/sanctum|\.sanctum)" "$TRACE_FILE" 2>/dev/null || echo "0")

if [ "$TEMP_VIOLATIONS" -eq 0 ]; then
    echo "[sanctum] PASS: no temp files from sanctum"
else
    echo "[sanctum] WARN: $TEMP_VIOLATIONS temp file operations detected"
    grep -E "(O_WRONLY|O_CREAT|O_TRUNC).*(/tmp/sanctum|\.sanctum)" "$TRACE_FILE"
fi

rm -f "$TRACE_FILE"
echo ""
echo "[sanctum] ephemeral verification complete"