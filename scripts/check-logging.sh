#!/usr/bin/env bash
# Sanctum — logging hygiene (P5.3).
#
# Library crates (domain, crypto, app, infra) log through `tracing` only:
# no println!/eprintln!/dbg! outside test code. Log statements must not
# interpolate fingerprints, aliases, addresses or content: we flag tracing
# macros mentioning the usual variable names.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0

lib_src() { find crates/sanctum-{domain,crypto,app,infra}/src -name '*.rs'; }

# Strip everything from the first `#[cfg(test)]` (test modules sit at the end).
non_test() { awk '/#\[cfg\(test\)\]/{exit} {print FILENAME":"FNR": "$0}' "$1"; }

for f in $(lib_src); do
    case "$f" in */testkit.rs|*/kat_tests.rs) continue ;; esac
    if non_test "$f" | grep -E '\b(e?println!|dbg!)\(' | grep -v '^\S*: *//'; then
        echo "FAIL: console output in library code ($f)"
        fail=1
    fi
    if non_test "$f" | grep -E '(trace|debug|info|warn|error)!\(' \
        | grep -Ei 'fingerprint|alias|onion|addr|plaintext|content|\bfp\b' ; then
        echo "FAIL: log statement may leak metadata ($f)"
        fail=1
    fi
done

[ "$fail" -eq 0 ] && echo "PASS: library logging is metadata-free"
exit "$fail"
