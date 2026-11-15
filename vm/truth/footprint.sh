#!/usr/bin/env bash
# Sibling footprint score (M-FP, vm/RIG.md §7): a sibling installed AFTER the app (apps.ps1 `post`, e.g.
# x0-ff-tbafter with Thunderbird) is not in the app run's snap0, so offering its keys and folders scores as a hit,
# not danger. Score the same plan a second time with snap0 replaced by the snap1 of a solo run of the sibling
# (x0-thunderbird: same snapshot, same user SID) and lists-0 by that run's lists-1: every offered target that exists
# on a machine with only the sibling installed then scores danger. The items that are danger in the footprint
# score but not in the normal one are the ones the app shares with the sibling: review each of them.
#
#   bash truth/footprint.sh <app run> <sibling solo run> [out dir]
#   bash truth/footprint.sh x0-ff-tbafter x0-thunderbird truth/x0
#
# Run from vm/ after truth/m1a.sh has written <app run>/truth.json and plans/purge.json. Outputs in the out dir
# (default truth/<prefix of the app run without the dash>): fp-<app run>.{json,md} (footprint score) and
# fp-<app run>-diff.md. Exit 2 on missing input.
set -euo pipefail
R=${RIGTOOL:-rigtool/target/release/rigtool}
RUNS=${M1A_RUNS:-runs}
APP=${1:?app run, e.g. x0-ff-tbafter}
REF=${2:?sibling solo run, e.g. x0-thunderbird}
OUT=${3:-truth/${APP%%-*}}
a=$RUNS/$APP; r=$RUNS/$REF
for f in "$a/truth.json" "$a/plans/purge.json" "$a/snap-$APP-0.tsv.gz" "$a/snap-$APP-2.tsv.gz" "$r/snap-$REF-1.tsv.gz" "$r/lists-$REF-1.json" "$a/run.json" "$r/run.json"; do
  if [ ! -f "$f" ]; then echo "footprint: missing $f" >&2; exit 2; fi
done
mkdir -p "$OUT"
sid=$(python -I -c "import json,sys; print(json.load(open(sys.argv[1],encoding='utf-8-sig')).get('sid') or '')" "$a/run.json")
sid_ref=$(python -I -c "import json,sys; print(json.load(open(sys.argv[1],encoding='utf-8-sig')).get('sid') or '')" "$r/run.json")
if [ "$sid" != "$sid_ref" ]; then
  echo "footprint: the runs have different user SIDs ($sid vs $sid_ref): not the same snapshot; user-hive items cannot be compared" >&2
  exit 2
fi
"$R" score --plan "$a/plans/purge.json" --truth "$a/truth.json" --s0 "$a/snap-$APP-0.tsv.gz" --s2 "$a/snap-$APP-2.tsv.gz" \
  --lists0 "$a/lists-$APP-0.json" --deny truth/deny.json --sid "$sid" --classes \
  --json "$OUT/fp-$APP-base.json" --md "$OUT/fp-$APP-base.md"
"$R" score --plan "$a/plans/purge.json" --truth "$a/truth.json" --s0 "$r/snap-$REF-1.tsv.gz" --s2 "$a/snap-$APP-2.tsv.gz" \
  --lists0 "$r/lists-$REF-1.json" --deny truth/deny.json --sid "$sid" --classes \
  --json "$OUT/fp-$APP.json" --md "$OUT/fp-$APP.md"
python -I - "$OUT/fp-$APP-base.json" "$OUT/fp-$APP.json" "$OUT/fp-$APP-diff.md" "$APP" "$REF" <<'EOF'
import json, sys
base_f, fp_f, out, app, ref = sys.argv[1:6]
def items(p):
    with open(p, encoding='utf-8') as f:
        d = json.load(f)
    return {i['target']: i for t in d['apps'][0]['tools'] for i in t['items']}
b, f = items(base_f), items(fp_f)
shared = sorted(k for k, i in f.items() if i['outcome'] == 'danger' and b.get(k, {}).get('outcome') != 'danger')
lines = [f'# Footprint of {ref} in the plan of {app}', '',
         f'Offered items that are danger with snap0 = snap1 of `{ref}` (a machine with only the sibling installed) but not in '
         f'the normal score: the app shares them with the sibling. **{len(shared)}** item(s).', '',
         '| target | band | preselected | action | scanner | normal outcome | footprint reasons |', '|---|---|---|---|---|---|---|']
for k in shared:
    i = f[k]
    lines.append(f"| `{k}` | {i['band']} | {i['preselected']} | {i.get('action') or ''} | {i.get('scanner') or ''} | "
                 f"{b.get(k, {}).get('outcome')} | {'; '.join(i.get('reasons', []))[:300]} |")
with open(out, 'w', encoding='utf-8') as fh:
    fh.write('\n'.join(lines) + '\n')
print(f'footprint: {len(shared)} item(s) shared with {ref} -> {out}', file=sys.stderr)
EOF
