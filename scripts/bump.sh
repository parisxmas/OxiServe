#!/usr/bin/env bash
#
# Increments the patch version in Cargo.toml: 0.2.3 -> 0.2.4.
#
# The version is what a client sees in the `Server:` header and what
# `oxiserve -v` prints, so every build that ships behaviour should carry a
# distinct one. Run this before committing a change.
#
#   scripts/bump.sh          # 0.2.3 -> 0.2.4
#   scripts/bump.sh --minor  # 0.2.3 -> 0.3.0
#   scripts/bump.sh --show   # print the current version and exit
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

cur=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
IFS=. read -r MAJ MIN PAT <<< "$cur"

case "${1:-}" in
    --show)  echo "$cur"; exit 0 ;;
    --minor) MIN=$((MIN + 1)); PAT=0 ;;
    --major) MAJ=$((MAJ + 1)); MIN=0; PAT=0 ;;
    "")      PAT=$((PAT + 1)) ;;
    *)       echo "usage: $0 [--show|--minor|--major]" >&2; exit 2 ;;
esac

new="$MAJ.$MIN.$PAT"
# Only the package version at the top of the file, never a dependency's.
awk -v new="$new" '
    /^\[/ { in_pkg = ($0 == "[package]") }
    in_pkg && /^version = / && !done { sub(/"[^"]*"/, "\"" new "\""); done = 1 }
    { print }
' Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml

# Keep Cargo.lock in step so the build does not re-resolve.
cargo update -p oxiserve --precise "$new" >/dev/null 2>&1 || cargo check --quiet >/dev/null 2>&1 || true

echo "$cur -> $new"
