#!/usr/bin/env bash
# Build purge-engine.exe and rigtool.exe for x86_64-pc-windows-msvc with cargo-xwin (repo's +crt-static configs apply).
# usage: build-msvc.sh [--install] [OUT_DIR]
#   OUT_DIR default: ~/purge-out/<branch>-<short sha>[-dirty]-msvc
#   --install also copies both exes into the repo locations the rig uses
#             (target/release/purge-engine.exe, vm/rigtool/target/release/rigtool.exe),
#             first backing up each existing file next to it as <name>.bak-<timestamp>;
#             each exe is written as <name>.new-<timestamp> and renamed over, so readers never see a partial file.
# First run downloads the MSVC CRT + Windows SDK via xwin, which means accepting Microsoft's licence.
set -euo pipefail
INSTALL=0
if [ "${1:-}" = "--install" ]; then INSTALL=1; shift; fi
export PATH="$HOME/.cargo/bin:$PATH"
export XWIN_CACHE_DIR="${XWIN_CACHE_DIR:-$HOME/.cache/cargo-xwin}"
export XWIN_ARCH=x86_64
REPO=${PURGE_REPO:?set PURGE_REPO to the repo root}
T=x86_64-pc-windows-msvc
rev=$(git -C "$REPO" rev-parse --abbrev-ref HEAD)-$(git -C "$REPO" rev-parse --short HEAD)
[ -n "$(git -C "$REPO" status --porcelain -- crates bins tools Cargo.lock)" ] && rev="$rev-dirty"
OUT=${1:-$HOME/purge-out/$rev-msvc}
mkdir -p "$OUT"
start=$(date +%s)
(cd "$REPO" && CARGO_TARGET_DIR=$HOME/purge-target/msvc cargo xwin build --release --locked -p purge-engine --target $T)
(cd "$REPO/vm/rigtool" && CARGO_TARGET_DIR=$HOME/purge-target/rigtool-msvc cargo xwin build --release --locked --target $T)
E="$HOME/purge-target/msvc/$T/release/purge-engine.exe"
R="$HOME/purge-target/rigtool-msvc/$T/release/rigtool.exe"
cp "$E" "$R" "$OUT/"
(cd "$OUT" && sha256sum purge-engine.exe rigtool.exe > SHA256SUMS)
{
  echo "built $(date -Is) from $rev, target $T, $(rustc --version), $(cargo xwin --version), $(($(date +%s)-start)) s"
  echo "xwin cache $XWIN_CACHE_DIR"
  X="$XWIN_CACHE_DIR/xwin"
  crt=$(grep -oE 'Microsoft\.VC\.[0-9.]+\.CRT' "$X/DONE" 2>/dev/null | head -1 | sed 's/^Microsoft\.VC\.//; s/\.CRT$//' || true)
  sdk=$(ls "$X/sdk/include" 2>/dev/null | grep -E '^10\.' | head -1 || true)
  crtbuild=$(grep -hoE '_VC_CRT_(MAJOR|MINOR|BUILD)_VERSION +[0-9]+' "$X/crt/include/crtversion.h" 2>/dev/null | awk '{printf "%s%s", (NR>1?".":""), $2}' || true)
  echo "xwin CRT ${crt:-?} (crtversion.h $crtbuild), SDK ${sdk:-?}, linker $(lld-link --version 2>/dev/null | head -1)"
  echo "reproduce with: XWIN_CRT_VERSION=${crt:-?} XWIN_SDK_VERSION=${sdk:-?} (same cargo-xwin, rustc)"
  # content hash of uncommitted source (tracked diff + untracked files), not just the file list
  { git -C "$REPO" diff HEAD -- crates bins tools Cargo.lock Cargo.toml; (cd "$REPO" && git ls-files -o --exclude-standard -z -- crates bins tools | sort -z | xargs -0 -r sha256sum); } | sha256sum | sed 's/  -$//; s/^/dirty-tree-hash /'
  echo "source-tree-hash $(cd "$REPO" && find crates bins -type f | sort | xargs -d "\n" sha256sum | sha256sum | cut -c1-64)  (find crates bins -type f | sort | xargs -d '\\n' sha256sum | sha256sum)"
} > "$OUT/BUILDINFO.txt"
if [ "$INSTALL" = 1 ]; then
  ts=$(date +%Y%m%d-%H%M%S)
  for pair in "purge-engine.exe:$REPO/target/release" "rigtool.exe:$REPO/vm/rigtool/target/release"; do
    f=${pair%%:*}; d=${pair#*:}; mkdir -p "$d"
    [ -f "$d/$f" ] && cp -p "$d/$f" "$d/$f.bak-$ts"
    # atomic: write next to it, verify, then rename over (also breaks cargo's hard link to deps/<name>.exe)
    cp "$OUT/$f" "$d/$f.new-$ts"
    [ "$(sha256sum < "$d/$f.new-$ts")" = "$(sha256sum < "$OUT/$f")" ] || { echo "copy mismatch for $f" >&2; rm -f "$d/$f.new-$ts"; exit 1; }
    mv -f "$d/$f.new-$ts" "$d/$f"
    echo "installed $d/$f (backup: $f.bak-$ts)"
  done
fi
echo "$OUT"; ls -la "$OUT"
