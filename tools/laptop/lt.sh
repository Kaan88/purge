#!/usr/bin/env bash
# Build on the laptop, run on the PC (user rule 2026-11-28: Rust builds go to the laptop; the app runs here).
#
#   tools/laptop/lt.sh <worktree> <cargo args...>         sync the worktree, run cargo there
#   tools/laptop/lt.sh <worktree> --fetch <exe>...        copy release exes back to E:\purge-target\lt\<name>\
#
# <worktree> is a checkout on this PC (the main checkout or E:\purge-ui-wt\<name>). Its tracked and untracked,
# non-ignored files are sent to the laptop as a tar with their mtimes, into a fresh E:\purge-lt\src\<name>, so
# deleted files don't linger and cargo stays incremental (same path, same mtimes). Every worktree shares one
# target dir, E:\purge-lt\target; cargo's own lock makes parallel builds take turns. Cargo's exit code is
# passed through. Examples:
#   tools/laptop/lt.sh . build --release -p purge-ui
#   tools/laptop/lt.sh E:/purge-ui-wt/m4 test --release -p purge-scan
#   tools/laptop/lt.sh E:/purge-ui-wt/m4 --fetch Purge.exe purge-engine.exe purge-broker.exe
set -euo pipefail
HOST=${PURGE_LAPTOP:-192.168.1.161}
[ $# -ge 2 ] || { sed -n 2,16p "$0"; exit 2; }
WT=$(cd "$1" && pwd); shift
NAME=$(basename "$WT"); [ "$WT" = "$(cd /c/Users/kaank/Desktop/uninstall/purge && pwd)" ] && NAME=main
SRC="E:\\purge-lt\\src\\$NAME"; TGT='E:\purge-lt\target'

if [ "$1" = "--fetch" ]; then
  shift; OUT="/e/purge-target/lt/$NAME"; mkdir -p "$OUT"
  for f in "$@"; do scp -q "$HOST:E:/purge-lt/target/release/$f" "$OUT/$f"; echo "fetched $OUT/$f"; done
  exit 0
fi

# Sync: fresh source dir, files from git (tracked + untracked, not ignored), mtimes kept.
ssh -o BatchMode=yes "$HOST" "powershell -NoProfile -Command \"if (Test-Path '$SRC') { Remove-Item '$SRC' -Recurse -Force }; New-Item -ItemType Directory -Force '$SRC' | Out-Null\""
(cd "$WT" && git ls-files -co --exclude-standard -z | tar --null -T - -cf -) | ssh -o BatchMode=yes "$HOST" "tar -xf - -C $SRC"

# Build: rustup's cargo (not on the ssh PATH), rust-toolchain.toml picks 1.99.1.
ARGS=$(printf ' %q' "$@")
ssh -o BatchMode=yes "$HOST" "powershell -NoProfile -Command \"\$env:Path = \\\"\$env:USERPROFILE\\.cargo\\bin;\$env:Path\\\"; \$env:CARGO_TARGET_DIR = '$TGT'; \$env:CARGO_HOME = 'E:\\cargo-home'; Set-Location '$SRC'; & cargo$ARGS 2>&1 | ForEach-Object { \\\"\$_\\\" }; exit \$LASTEXITCODE\""
