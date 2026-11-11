#!/usr/bin/env bash
# Recomputes truth for the M0 corpus and re-scores every tool's plans (vm/RIG.md §5, §7).
# Run from vm/:  bash truth/recompute.sh
set -euo pipefail
R=rigtool/target/release/rigtool
APPS="npp 7zip vscode git python node vcredist firefox"
python -I truth/mk_labels.py truth/labels
for id in $APPS; do
  d=runs/$id
  $R truth --s0 $d/snap-$id-0.tsv.gz --s1 $d/snap-$id-1.tsv.gz --s2 $d/snap-$id-2.tsv.gz \
    --lists0 $d/lists-$id-0.json --lists2 $d/lists-$id-2.json --run $d/run.json \
    --ambient truth/ambient.json --labels truth/labels/$id.json --deny truth/deny.json -o $d/truth.json
done
sets=""; for id in $APPS; do sets="$sets runs/$id"; done
$R score --set $sets --deny truth/deny.json --json truth/m0-score.json --md truth/m0-score.md
