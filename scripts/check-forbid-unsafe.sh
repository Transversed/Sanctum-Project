#!/usr/bin/env bash
# Sanctum — verify that unsafe code is forbidden everywhere.
#
# Two independent guards, both required:
#   1. workspace lint `unsafe_code = "forbid"`, inherited by every crate
#      (covers lib, bin, tests, examples and build scripts);
#   2. `#![forbid(unsafe_code)]` at the root of every crate target.
set -euo pipefail

cd "$(dirname "$0")/.."
fail=0

if ! grep -Eq '^unsafe_code *= *"forbid"' Cargo.toml; then
    echo "FAIL: [workspace.lints.rust] unsafe_code = \"forbid\" missing in Cargo.toml"
    fail=1
fi

for manifest in crates/*/Cargo.toml; do
    crate_dir=$(dirname "$manifest")
    if ! awk '/^\[lints\]/{f=1;next} /^\[/{f=0} f && /^workspace *= *true/{ok=1} END{exit !ok}' "$manifest"; then
        echo "FAIL: $manifest does not inherit workspace lints ([lints] workspace = true)"
        fail=1
    fi
    for root in "$crate_dir/src/lib.rs" "$crate_dir/src/main.rs"; do
        [ -f "$root" ] || continue
        if ! grep -q '^#!\[forbid(unsafe_code)\]' "$root"; then
            echo "FAIL: $root lacks #![forbid(unsafe_code)]"
            fail=1
        fi
    done
done

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "PASS: unsafe code is forbidden in every crate"
