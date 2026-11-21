#!/usr/bin/env bash
# baseline-local-r5: gate M run R5, build part (docs/BASELINE_LOCAL_DESIGN.md 8.2, vm/RIG.md 8a), on the Windows HOST
# itself, read-only: run from Git Bash in an ELEVATED session at the repository root (S4 reads every user's packages
# only elevated; unelevated the build is incomplete and the script exits 3 unless --allow-unelevated is given).
# Builds the host's local baseline twice (cold, warm) with target/release/purge-engine.exe into
# target/baseline-local/r5-host/ (never into kb/ or vm/runs/), measures time, peak working set, size and a load, and runs
# `rigtool baseline-diff` against each shipped baseline with the other as neighbour. There is no truth for the host: the
# two reports (vm/truth/baseline-local/r5-host-vs-<baseline>.json) say how much of each neighbouring clean install the
# host's own sources hold, for the budgets (W4) and as context, not as a safety measurement (S2, S3 come from R1, R2).
# The scan-plan part of R5 (ten programs, merged against none) needs the injected view of BL-FRAMEWORK (wave 5).
# Exit code: 0 ok, 2 refused or a build failed to start, 3 a report shows a problem (see bl_check).
set -uo pipefail
ALLOW_UNELEVATED=0
[ "${1:-}" = --allow-unelevated ] && ALLOW_UNELEVATED=1
NAME=r5-host
ENGINE=target/release/purge-engine.exe
RIGTOOL=${RIGTOOL:-vm/rigtool/target/release/rigtool.exe}
BASELINES=(Professional-26340.9882 EnterpriseSEval-26100.1742)
if [ ! -f Cargo.toml ] || [ ! -d vm/rigtool ]; then echo "$NAME: REFUSED: run from the repository root" >&2; exit 2; fi
. tools/linux/campaigns/baseline-local-lib.sh
command -v powershell.exe >/dev/null || { echo "$NAME: REFUSED: no powershell.exe (run on the Windows host)" >&2; exit 2; }
if [ ! -f "$ENGINE" ] || ! LC_ALL=C grep -a -q 'purge-baseline-local' "$ENGINE"; then
  echo "$NAME: REFUSED: $ENGINE missing or without the local baseline builder (cargo build --release -p purge-engine)" >&2; exit 2
fi
bl_check_rigtool "$RIGTOOL" || exit 2
if ! net session >/dev/null 2>&1 && [ "$ALLOW_UNELEVATED" -ne 1 ]; then
  echo "$NAME: REFUSED: not elevated (S4 would be incomplete); run elevated or pass --allow-unelevated" >&2; exit 2
fi
RUN=target/baseline-local/$NAME
R=vm/truth/baseline-local
mkdir -p "$RUN" "$R"
JOB=$RUN/build-job.ps1
bl_build_job "$(cygpath -w "$PWD/$RUN")" "$(cygpath -w "$PWD/$ENGINE")" > "$JOB"
echo "== $NAME start $(date -Is); engine $(sha256sum "$ENGINE" | cut -c1-12)"
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(cygpath -w "$JOB")" || { echo "$NAME: build job failed" >&2; exit 2; }
cp "$RUN/build.json" "$R/$NAME-build.json"
rc=0
for truth in "${BASELINES[@]}"; do
  for nb in "${BASELINES[@]}"; do
    [ "$nb" = "$truth" ] && continue
    out=$R/$NAME-vs-$truth.json
    echo "== baseline-diff: proxy truth $truth, neighbour $nb -> $out"
    bl_diff "$RIGTOOL" "kb/baselines/$truth.tsv.gz" "$RUN/local-cold.tsv.gz" "kb/baselines/$nb.tsv.gz" "$out" || exit 2
    bl_check "$out" "$RUN/build.json" - host || rc=3
  done
done
echo "== $NAME end $(date -Is), exit $rc"
exit "$rc"
