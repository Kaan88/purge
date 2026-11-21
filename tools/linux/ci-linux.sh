#!/usr/bin/env bash
# Linux stand-in for `cargo xtask ci` (which cannot run here: xtask links purge-win and spawns a Windows cargo).
# Checks, in order (all run; exit 0 only if every one passes):
#   fmt        cargo fmt --all -- --check
#   clippy     cargo xwin clippy --workspace --all-targets  --target msvc -- -D warnings
#   clippy-mcp cargo xwin clippy -p purge-mcp --all-targets --target msvc -- -D warnings
#   features   clippy of the M2 feature sets, each only once its feature exists in the manifests:
#              purge-win --features write; purge-exec --features fault-inject,test-support;
#              purge-engine --features rig-exec
#   test       cargo xwin test --workspace --target msvc --no-fail-fast under wine; exactly the KNOWN wine
#              failures below are tolerated, any other failure, crash or compile error fails the step
#   check-deps native `cargo tree --target msvc`: purge-mcp's own tree reaches only purge-model and purge-rpc
#              (and no purge-win `write`), and under unified workspace features purge-mcp depends on no other
#              Purge crate (same three checks as tools/xtask/src/check_deps.rs)
#   scanner-coverage  xtask.exe (msvc) under wine
#   rigtool    (optional, CI_RIGTOOL=1 or --rigtool) native `cargo test` in vm/rigtool
# Not run: ui-strings (needs PURGE_UT_STRINGS, a file outside the repo; run it on Windows).
#
# Env: CI_TARGET_DIR   cargo target dir (default ~/purge-target/ci-linux); give parallel agents separate ones
#      PURGE_REPO      checkout to check (default the NTFS repo)
#      CI_LOG_DIR      where step logs go (default $CI_TARGET_DIR/ci-logs)
#      CI_SKIP         space-separated step names to skip (e.g. "test features")
#      CI_RIGTOOL=1    also run the rigtool step
#      CI_KNOWN_FILE   extra tolerated wine failures (default ~/purge-target/ci-linux-known.txt, optional)
#      CI_KNOWN_TARGETS extra tolerated "targets failed" entries, ';'-separated, e.g. "-p purge-exec --lib;-p purge-win --lib"
set -uo pipefail

for a in "$@"; do
  case "$a" in
    --rigtool) CI_RIGTOOL=1 ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "ci-linux: unknown argument $a" >&2; exit 2 ;;
  esac
done

REPO=${PURGE_REPO:?set PURGE_REPO to the repo root}
export CARGO_TARGET_DIR=${CI_TARGET_DIR:-$HOME/purge-target/ci-linux}
LOGS=${CI_LOG_DIR:-$CARGO_TARGET_DIR/ci-logs}
SKIP=" ${CI_SKIP:-} "
T=x86_64-pc-windows-msvc
export PATH="$HOME/.cargo/bin:$PATH"
export XWIN_CACHE_DIR=${XWIN_CACHE_DIR:-$HOME/.cache/cargo-xwin}
export XWIN_ARCH=x86_64
export WINEDEBUG=-all
export WINEPREFIX=${WINEPREFIX:-$HOME/purge-target/wineprefix}
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUNNER=wine

# The live-API tests that fail under wine by design (wine's registry/fs/AppX are not Windows).
# Format: <crate_ident>::<test path>. A listed test that passes is reported, not failed.
KNOWN=(
  purge_source::live::tests::links_are_reported_and_only_g1_links_resolved
  purge_source::live::tests::filesystem_agrees_with_direct_purge_win_calls
  purge_win::appx::tests::current_user_listing
  purge_win::env::tests::live_expansion_and_agreement_with_map
  purge_win::reg::tests::user_classes_is_reported_as_link_and_not_followed
  purge_win::reg::tests::value_types_multi_sz_binary_dword_default
  purge_win::sid::tests::admin_only_writable_on_host
  purge_win::sid::tests::profile_list_has_current_user
  purge_win::versioninfo::tests::notepad_has_microsoft_company
  purge_win::shelllink::tests::round_trip_raw_path_and_arguments
)
# Extra known wine failures (one <crate_ident>::<test path> per line, '#' comments), added only after the test was
# shown to pass on real Windows (VM run). Kept outside the repo; default ~/purge-target/ci-linux-known.txt.
KNOWN_FILE=${CI_KNOWN_FILE:-$HOME/purge-target/ci-linux-known.txt}
if [ -f "$KNOWN_FILE" ]; then
  while read -r l; do l=${l%%#*}; l=${l//[[:space:]]/}; [ -n "$l" ] && KNOWN+=("$l"); done <"$KNOWN_FILE"
fi
# cargo's "N targets failed" entries that may appear (only the binaries holding KNOWN tests).
KNOWN_TARGETS=("-p purge-source --lib" "-p purge-win --lib")
if [ -n "${CI_KNOWN_TARGETS:-}" ]; then IFS=';' read -r -a _xt <<<"$CI_KNOWN_TARGETS"; KNOWN_TARGETS+=("${_xt[@]}"); fi

mkdir -p "$LOGS"
cd "$REPO" || { echo "ci-linux: no repo at $REPO" >&2; exit 2; }
declare -a SUMMARY=()
FAIL=0
T0=$(date +%s)

record() { # name status seconds detail
  SUMMARY+=("$(printf '%-17s %-4s %4ss  %s' "$1" "$2" "$3" "$4")")
  [ "$2" = FAIL ] && FAIL=1
}
skipped() { [[ "$SKIP" == *" $1 "* ]]; }
run_step() { # name cmd...   (pass/fail by exit status; log in $LOGS/<name>.log)
  local name=$1; shift
  if skipped "$name"; then record "$name" SKIP 0 "CI_SKIP"; return; fi
  local s=$(date +%s)
  if "$@" >"$LOGS/$name.log" 2>&1; then record "$name" ok $(( $(date +%s)-s )) ""
  else record "$name" FAIL $(( $(date +%s)-s )) "see $LOGS/$name.log: $(grep -m1 -E '^(error|warning)|Diff in' "$LOGS/$name.log" | cut -c1-140)"
  fi
}

# --- fmt / clippy -------------------------------------------------------------------------------------
run_step fmt cargo fmt --all -- --check
run_step clippy cargo xwin clippy --workspace --all-targets --target $T -- -D warnings
run_step clippy-mcp cargo xwin clippy -p purge-mcp --all-targets --target $T -- -D warnings

# --- M2 feature sets (each only once the feature is declared) ------------------------------------------
has_feature() { # manifest feature
  awk '/^\[features\]/{f=1;next} /^\[/{f=0} f' "$1" 2>/dev/null | grep -qE "^[[:space:]]*\"?$2\"?[[:space:]]*="
}
feat_step() {
  local s=$(date +%s) ran=() failed=()
  if has_feature crates/purge-win/Cargo.toml write; then ran+=("purge-win[write]")
    cargo xwin clippy -p purge-win --features write --all-targets --target $T -- -D warnings >>"$LOGS/features.log" 2>&1 || failed+=("purge-win[write]"); fi
  if has_feature crates/purge-exec/Cargo.toml fault-inject && has_feature crates/purge-exec/Cargo.toml test-support; then ran+=("purge-exec[fault-inject,test-support]")
    cargo xwin clippy -p purge-exec --features fault-inject,test-support --all-targets --target $T -- -D warnings >>"$LOGS/features.log" 2>&1 || failed+=("purge-exec[fault-inject,test-support]"); fi
  if has_feature bins/purge-engine/Cargo.toml rig-exec; then ran+=("purge-engine[rig-exec]")
    cargo xwin clippy -p purge-engine --features rig-exec --all-targets --target $T -- -D warnings >>"$LOGS/features.log" 2>&1 || failed+=("purge-engine[rig-exec]"); fi
  if [ ${#ran[@]} -eq 0 ]; then record features SKIP 0 "no M2 features declared yet"
  elif [ ${#failed[@]} -eq 0 ]; then record features ok $(( $(date +%s)-s )) "${ran[*]}"
  else record features FAIL $(( $(date +%s)-s )) "failed: ${failed[*]} (see $LOGS/features.log)"; fi
}
if skipped features; then record features SKIP 0 "CI_SKIP"; else : >"$LOGS/features.log"; feat_step; fi

# --- tests under wine ---------------------------------------------------------------------------------
test_step() {
  local s=$(date +%s) log="$LOGS/test.log"
  cargo xwin test --workspace --target $T --no-fail-fast >"$log" 2>&1
  local rc=$? dt=$(( $(date +%s)-s ))
  # Per-binary failed tests, keyed by crate ident taken from the "Running ... deps/<ident>-<hash>.exe" line.
  local parsed
  parsed=$(awk '
    /^[[:space:]]*Running / { n=split($0, a, "/"); b=a[n]; sub(/-[0-9a-f]+\.exe\)?$/, "", b); cur=b; bins++ }
    /^[[:space:]]*Doc-tests / { cur=$2; gsub(/-/, "_", cur); cur=cur "(doc)"; bins++ }
    /^test .* \.\.\. FAILED$/ { t=$2; print "F " cur "::" t }
    /^test result: / { res++; p+=$4; f+=$6 }
    /could not compile|^error\[E|error: no test target|failed to run custom build/ { cerr++ }
    /^error: [0-9]+ targets? failed:/ { inlist=1; next }
    inlist && /^[[:space:]]+`/ { t=$0; gsub(/^[[:space:]]+`|`$/, "", t); print "T " t; next }
    inlist { inlist=0 }
    END { printf "S %d %d %d %d %d\n", bins+0, res+0, p+0, f+0, cerr+0 }' "$log")
  local stats; stats=$(grep '^S ' <<<"$parsed"); read -r _ bins res passed failed cerr <<<"$stats"
  local unexpected=() targets_bad=() fixed=()
  while read -r _ name; do
    [ -z "$name" ] && continue
    local k=0; for x in "${KNOWN[@]}"; do [ "$x" = "$name" ] && k=1; done
    [ $k = 0 ] && unexpected+=("$name")
  done < <(grep '^F ' <<<"$parsed")
  while read -r _ tgt; do
    [ -z "$tgt" ] && continue
    local k=0; for x in "${KNOWN_TARGETS[@]}"; do [ "$x" = "$tgt" ] && k=1; done
    [ $k = 0 ] && targets_bad+=("$tgt")
  done < <(grep '^T ' <<<"$parsed" | sed 's/^T /T /')
  for x in "${KNOWN[@]}"; do grep -qxF "F $x" <<<"$parsed" || fixed+=("$x"); done
  local why=()
  [ "$cerr" -gt 0 ] && why+=("compile/build errors ($cerr)")
  [ "$bins" -eq 0 ] && why+=("no test binaries ran")
  [ "$res" -ne "$bins" ] && why+=("$((bins-res)) test binaries ended without a result line (crash/abort?)")
  [ ${#unexpected[@]} -gt 0 ] && why+=("unexpected failures: ${unexpected[*]}")
  [ ${#targets_bad[@]} -gt 0 ] && why+=("failing targets outside the known set: ${targets_bad[*]}")
  [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ] && [ ${#why[@]} -eq 0 ] && why+=("cargo exited $rc without test failures")
  local known_seen=$(( ${#KNOWN[@]} - ${#fixed[@]} ))
  local detail="$passed passed, $failed failed ($known_seen known wine failures) in $bins binaries"
  [ ${#fixed[@]} -gt 0 ] && [ "$bins" -gt 0 ] && [ "$cerr" -eq 0 ] && detail="$detail; known-failing now passing: ${fixed[*]}"
  if [ ${#why[@]} -eq 0 ]; then record test ok $dt "$detail"
  else record test FAIL $dt "$detail; ${why[*]} (see $log)"; fi
}
if skipped test; then record test SKIP 0 "CI_SKIP"; else test_step; fi

# --- check-deps (native cargo tree, msvc target) -------------------------------------------------------
check_deps() {
  local tree=(cargo tree --target $T -e normal,build --prefix none)
  local own ws inv v=()
  own=$("${tree[@]}" -p purge-mcp -f '{p} {f}') || { echo "cargo tree -p purge-mcp failed"; return 1; }
  [ "$(head -1 <<<"$own" | cut -d' ' -f1)" = purge-mcp ] || { echo "unexpected tree: first package is not purge-mcp"; return 1; }
  while read -r n; do v+=("$n is in purge-mcp's dependency tree; only purge-model and purge-rpc are allowed"); done < <(
    awk '{print $1}' <<<"$own" | grep '^purge-' | grep -vxE 'purge-(mcp|model|rpc)' | sort -u)
  grep -E '^purge-win ' <<<"$own" | grep -qE '(^| |,)write(,| |$)' && v+=("purge-win is built with feature write for purge-mcp")
  ws=$("${tree[@]}" --workspace -f '{p}') || { echo "cargo tree --workspace failed"; return 1; }
  mapfile -t forb < <(awk '{print $1}' <<<"$ws" | grep '^purge-' | grep -vxE 'purge-(mcp|model|rpc)' | sort -u)
  printf '%s\n' "${forb[@]}" | grep -qx purge-exec && printf '%s\n' "${forb[@]}" | grep -qx purge-win \
    || { echo "unexpected workspace tree: purge-exec or purge-win missing"; return 1; }
  local args=(); for n in "${forb[@]}"; do args+=(-i "$n"); done
  inv=$("${tree[@]}" --workspace -f '{p}' "${args[@]}") || { echo "cargo tree -i failed"; return 1; }
  # one tree per inverted crate, separated by blank lines; purge-mcp inside a tree = it depends on that root
  while read -r root; do v+=("with workspace feature unification, purge-mcp depends on $root"); done < <(
    awk 'BEGIN{RS=""} { split($0, L, "\n"); split(L[1], r, " "); if ($0 ~ /(^|\n)purge-mcp /) print r[1] }' <<<"$inv")
  if [ ${#v[@]} -eq 0 ]; then
    echo "check-deps: ok (purge-mcp tree has $(wc -l <<<"$own") lines, Purge crates only purge-model, purge-rpc; reaches none of ${#forb[@]} other Purge crates: ${forb[*]})"
    return 0
  fi
  printf 'check-deps: %s\n' "${v[@]}"; return 1
}
if skipped check-deps; then record check-deps SKIP 0 "CI_SKIP"; else
  s=$(date +%s)
  if check_deps >"$LOGS/check-deps.log" 2>&1; then record check-deps ok $(( $(date +%s)-s )) "$(sed -n 's/^check-deps: ok (\(.*\))$/\1/p' "$LOGS/check-deps.log" | cut -c1-120)"
  else record check-deps FAIL $(( $(date +%s)-s )) "$(head -1 "$LOGS/check-deps.log" | cut -c1-140)"; fi
fi

# --- scanner-coverage (xtask.exe under wine) -----------------------------------------------------------
sc_step() {
  cargo xwin build -q -p xtask --target $T && wine "$CARGO_TARGET_DIR/$T/debug/xtask.exe" scanner-coverage
}
run_step scanner-coverage sc_step

# --- rigtool (optional, native) ------------------------------------------------------------------------
if [ "${CI_RIGTOOL:-0}" = 1 ]; then
  # Known Linux-only failure: the test builds its output dir with a trailing '\' (Windows path assumption).
  RIGTOOL_KNOWN=(baseline::tests::baseline_drops_rig_and_trims_fields)
  rt_step() {
    local log="$LOGS/rigtool.log" s=$(date +%s)
    (cd vm/rigtool && CARGO_TARGET_DIR=${CI_RIGTOOL_TARGET_DIR:-$HOME/purge-target/rigtool-linux} cargo test) >"$log" 2>&1
    local rc=$? dt=$(( $(date +%s)-s )) bad=()
    mapfile -t fails < <(sed -n 's/^test \(.*\) \.\.\. FAILED$/\1/p' "$log")
    for f in "${fails[@]}"; do [[ " ${RIGTOOL_KNOWN[*]} " == *" $f "* ]] || bad+=("$f"); done
    local nres; nres=$(grep -c '^test result: ' "$log")
    local sum; sum=$(grep '^test result: ' "$log" | awk '{p+=$4; f+=$6} END{print p+0 " passed, " f+0 " failed"}')
    if [ "$nres" -gt 0 ] && [ ${#bad[@]} -eq 0 ] && { [ $rc -eq 0 ] || [ ${#fails[@]} -gt 0 ]; } && ! grep -q 'could not compile' "$log"; then
      record rigtool ok $dt "$sum (${#fails[@]} known Linux-only)"
    else record rigtool FAIL $dt "$sum; unexpected: ${bad[*]:-build error or crash} (see $log)"; fi
  }
  if skipped rigtool; then record rigtool SKIP 0 "CI_SKIP"; else rt_step; fi
fi

echo "ci-linux: $REPO @ $(git rev-parse --short HEAD 2>/dev/null)$( [ -n "$(git status --porcelain -- crates bins tools Cargo.toml Cargo.lock 2>/dev/null | head -1)" ] && echo ' (dirty)'), target dir $CARGO_TARGET_DIR"
printf '  %s\n' "${SUMMARY[@]}"
if [ $FAIL = 0 ]; then echo "ci-linux: PASS in $(( $(date +%s)-T0 ))s"; exit 0
else echo "ci-linux: FAIL in $(( $(date +%s)-T0 ))s (logs in $LOGS)"; exit 1; fi
