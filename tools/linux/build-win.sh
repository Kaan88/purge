#!/usr/bin/env bash
# Build purge-engine.exe and rigtool.exe (x86_64-pc-windows-gnullvm) into an output folder outside the repo.
# usage: build-win.sh [OUT_DIR]   (default ~/purge-out/<branch>-<short sha>[-dirty])
set -euo pipefail
source "$(dirname "$0")/env-win.sh"
REPO=${PURGE_REPO:?set PURGE_REPO to the repo root}
T=x86_64-pc-windows-gnullvm
rev=$(git -C "$REPO" rev-parse --abbrev-ref HEAD)-$(git -C "$REPO" rev-parse --short HEAD)
[ -n "$(git -C "$REPO" status --porcelain -- crates bins tools Cargo.lock)" ] && rev="$rev-dirty"
OUT=${1:-$HOME/purge-out/$rev}
mkdir -p "$OUT"
(cd "$REPO" && CARGO_TARGET_DIR=$HOME/purge-target/gnullvm cargo build --release --locked -p purge-engine --target $T)
(cd "$REPO/vm/rigtool" && CARGO_TARGET_DIR=$HOME/purge-target/rigtool-gnullvm cargo build --release --locked --target $T)
cp "$HOME/purge-target/gnullvm/$T/release/purge-engine.exe" "$OUT/"
cp "$HOME/purge-target/rigtool-gnullvm/$T/release/rigtool.exe" "$OUT/"
(cd "$OUT" && sha256sum purge-engine.exe rigtool.exe > SHA256SUMS && { echo "built $(date -Is) from $rev, target $T, $(rustc --version)"; git -C "$REPO" status --porcelain -- crates bins tools | sha256sum | sed 's/^/dirty-tree-hash /'; } > BUILDINFO.txt)
echo "$OUT"; ls -la "$OUT"
