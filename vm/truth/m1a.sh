#!/usr/bin/env bash
# M1a gate, parts C and E (docs/ENGINE_PLAN.md §11.1 M1a; vm/RIG.md §4a): truth for the engine runs
# vm/runs/r0-<id>, a sanity comparison with the frozen M0 truth, scoring Purge against BCU on the same runs,
# and the inventory check. Run from vm/ after the r0 campaign has been pulled:
#
#   bash truth/m1a.sh
#
# Environment: RIGTOOL (default rigtool/target/release/rigtool), M1A_APPS (default the six gate apps),
# M1A_PREFIX (default r0-).
#
# Per run r0-<id>:
#   1. rigtool truth with the app's label file truth/labels/<id>.json (vscode-user.json and firefox-tb.json
#      include the vscode/firefox rules) -> runs/r0-<id>/truth.json.
#   2. Sanity against truth/frozen/<id>/truth.json, when there is one: label counts and the leftover/user_data
#      items found in only one of the two -> truth/m1a-sanity.md. Expected: the same items except random
#      names (temp files, jump-list hashes). Anything else is investigated before scoring; the frozen truth
#      stays the reference for what counts as a leftover.
#   3. plans/purge.json from plan-purge.json (rig.ps1 Copy-RunPlans already does this) and the frozen BCU
#      plan truth/frozen/<id>/plans/bcu.json next to it (vscode-user and firefox-tb have none).
# Then:
#   4. rigtool score over all runs -> truth/m1a-score.json and .md (gate D reads the *_nd columns).
#   5. Cross-check on the frozen sets, when the git-ignored M0 snaps runs/<id>/ are present: the r0 purge plan
#      and the frozen BCU plan scored against the frozen truth -> truth/m1a-frozen-<id>.json and .md (items
#      with run-specific random names score `gone`; used to confirm danger 0 and precision).
#   6. rigtool invdiff for inv-1/inv-2 against lists-1/lists-2 of every run -> runs/r0-<id>/invdiff-<n>.json
#      and .md; the script exits 1 at the end when any difference is unexplained (gate E).
set -euo pipefail
R=${RIGTOOL:-rigtool/target/release/rigtool}
APPS=${M1A_APPS:-"vscode vscode-user git firefox firefox-tb npp"}
PREFIX=${M1A_PREFIX:-r0-}

python -I truth/mk_labels.py truth/labels

sets=""
sanity_runs=""
for id in $APPS; do
  run=$PREFIX$id
  d=runs/$run
  if [ ! -f "$d/run.json" ]; then
    echo "m1a: $d/run.json is missing: run the campaign first (rig.ps1 Invoke-Campaign -RunPrefix $PREFIX -Engine ...)" >&2
    exit 1
  fi
  "$R" truth --s0 "$d/snap-$run-0.tsv.gz" --s1 "$d/snap-$run-1.tsv.gz" --s2 "$d/snap-$run-2.tsv.gz" \
    --lists0 "$d/lists-$run-0.json" --lists2 "$d/lists-$run-2.json" --run "$d/run.json" \
    --ambient truth/ambient.json --labels "truth/labels/$id.json" --deny truth/deny.json -o "$d/truth.json"

  mkdir -p "$d/plans"
  if [ ! -f "$d/plans/purge.json" ]; then
    if [ -f "$d/plan-purge.json" ]; then
      cp "$d/plan-purge.json" "$d/plans/purge.json"
    else
      echo "m1a: warning: $run has no purge plan (engine-scan failed?)" >&2
    fi
  fi
  if [ -f "truth/frozen/$id/plans/bcu.json" ]; then
    cp "truth/frozen/$id/plans/bcu.json" "$d/plans/bcu.json"
  fi
  if [ -f "truth/frozen/$id/truth.json" ]; then
    sanity_runs="$sanity_runs $id"
  fi
  sets="$sets $d"
done

# 2. sanity: r0 truth vs frozen truth
python -I - "$PREFIX" truth/m1a-sanity.md $sanity_runs <<'EOF'
import json
import sys

prefix, out, ids = sys.argv[1], sys.argv[2], sys.argv[3:]


def key(t):
    return '{}:{}|{}'.format(t.get('type'), str(t.get('path', '')).lower(), str(t.get('name', '') or '').lower())


def load(p):
    with open(p, encoding='utf-8') as f:
        return json.load(f)


lines = ['# M1a truth sanity: r0 runs vs frozen M0 truth', '',
         'Expected: the same leftover/user_data items except random names. Anything else is investigated before scoring.', '']
for id in ids:
    new = load(f'runs/{prefix}{id}/truth.json')
    old = load(f'truth/frozen/{id}/truth.json')
    lines.append(f'## {id}')
    lines.append('')
    lines.append('| label | frozen | r0 |')
    lines.append('|---|---|---|')
    for lab in sorted(set(old.get('counts', {})) | set(new.get('counts', {}))):
        lines.append(f"| {lab} | {old.get('counts', {}).get(lab, 0)} | {new.get('counts', {}).get(lab, 0)} |")
    lines.append('')
    want = ('leftover', 'user_data')
    a = {key(i['target']): i for i in old.get('items', []) if i.get('label') in want}
    b = {key(i['target']): i for i in new.get('items', []) if i.get('label') in want}
    for title, only in (('only in frozen', sorted(set(a) - set(b))), ('only in r0', sorted(set(b) - set(a)))):
        lines.append(f'{title}: {len(only)}')
        for k in only[:40]:
            lines.append(f'- `{k}`')
        if len(only) > 40:
            lines.append(f'- ... {len(only) - 40} more')
        lines.append('')
with open(out, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines) + '\n')
print(f'm1a: sanity report {out} ({len(ids)} run(s) with frozen truth)')
EOF

# 4. score Purge and BCU on the r0 runs
# shellcheck disable=SC2086
"$R" score --set $sets --deny truth/deny.json --json truth/m1a-score.json --md truth/m1a-score.md

# 5. cross-check on the frozen sets
for id in $sanity_runs; do
  run=$PREFIX$id
  m0=runs/$id
  plan=runs/$run/plans/purge.json
  if [ ! -f "$plan" ] || [ ! -f "$m0/snap-$id-0.tsv.gz" ] || [ ! -f "$m0/snap-$id-2.tsv.gz" ]; then
    echo "m1a: skip frozen cross-check for $id (no purge plan or no M0 snaps in $m0)" >&2
    continue
  fi
  plans=(--plan "$plan")
  if [ -f "truth/frozen/$id/plans/bcu.json" ]; then plans+=(--plan "truth/frozen/$id/plans/bcu.json"); fi
  "$R" score "${plans[@]}" --truth "truth/frozen/$id/truth.json" --s0 "$m0/snap-$id-0.tsv.gz" --s2 "$m0/snap-$id-2.tsv.gz" \
    --deny truth/deny.json --json "truth/m1a-frozen-$id.json" --md "truth/m1a-frozen-$id.md"
done

# 6. inventory check (gate E)
unexplained=0
for id in $APPS; do
  run=$PREFIX$id
  d=runs/$run
  for n in 1 2; do
    if [ ! -f "$d/inv-$n.json" ]; then
      echo "m1a: $d/inv-$n.json is missing (engine inventory phase failed?)" >&2
      unexplained=1
      continue
    fi
    explain=()
    if [ -f truth/inventory-explain.json ]; then explain=(--explain truth/inventory-explain.json); fi
    if ! "$R" invdiff --inv "$d/inv-$n.json" --lists "$d/lists-$run-$n.json" "${explain[@]}" \
         --json "$d/invdiff-$n.json" --md "$d/invdiff-$n.md"; then
      echo "m1a: $run phase $n: unexplained inventory differences (see $d/invdiff-$n.md)" >&2
      unexplained=1
    fi
  done
done

echo "m1a: truth, sanity (truth/m1a-sanity.md) and score (truth/m1a-score.md) done; inventory check: $([ $unexplained -eq 0 ] && echo ok || echo FAILED)"
exit $unexplained
