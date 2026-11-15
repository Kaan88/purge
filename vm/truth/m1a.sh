#!/usr/bin/env bash
# M1a gate, parts C and E (docs/ENGINE_PLAN.md §11.1 M1a; vm/RIG.md §4a): truth for the engine runs
# vm/runs/r0-<id>, a sanity comparison with the frozen M0 truth, scoring Purge against BCU on the same runs,
# and the inventory check. Run from vm/ after the r0 campaign (with its own null runs) has been pulled:
#
#   bash truth/m1a.sh [--accept-sanity-diff]
#
# Exit codes: 0 ok; 1 inventory check failed (gate E); 2 missing input (runs, null runs, plans);
# 3 stopped before scoring: the sanity check found differences beyond random names (gate step 9 says
# investigate first). --accept-sanity-diff (or M1A_ACCEPT_SANITY_DIFF=1) scores anyway only when every residual
# item is classified in M1A_SANITY_CLASSIFIED (below); an unclassified residual still stops with exit 3.
# Every run's status goes to $OUT/m1a-status.json (sanity residual, override, invdiff exit codes, exit code).
#
# Environment:
#   RIGTOOL      rigtool binary (default rigtool/target/release/rigtool)
#   M1A_APPS     the gate apps (default "vscode vscode-user git firefox firefox-tb npp")
#   M1A_PREFIX   run-name prefix (default r0-)
#   M1A_RUNS     directory holding the <prefix><id> and <prefix>null<n> run dirs (default runs)
#   M1A_M0_RUNS  directory holding the git-ignored M0 snaps runs/<id>/ for the frozen cross-check (default runs)
#   M1A_OUT      directory for the reports (default truth for the r0- gate, truth/<prefix without the dash> for any
#                other prefix, e.g. truth/x0, truth/f0d, so an extra campaign never overwrites the gate files); the
#                ambient set built here goes there as well
#   M1A_CLASSES  1 adds `rigtool score --classes` (reporting classes blocking / unticked / preexisting_value_ref /
#                old_empty_ext_key, RIG.md §7). Default 0 for r0-, 1 for any other prefix.
#   M1A_BCU      1 (default) copies the frozen BCU plan truth/frozen/<id>/plans/bcu.json next to the purge plan (it was
#                recorded on the M0 run; on another machine state it is only a rough reference); 0 scores purge alone.
# Run directories <prefix><id> whose run.json has `extra` (rig.ps1 -ExtraChecks) also get the live-scan and
# determinism checks -> $OUT/m1a-extra.md (RIG.md §4a). A variant id needs its label file truth/labels/<id>.json
# (missing: exit 2).
#   M1A_NULLS    null run names of the same campaign (default "<prefix>null1 <prefix>null2 <prefix>null3")
#   M1A_AMBIENT  an ambient file to use instead of building one from M1A_NULLS. The M0 set truth/ambient.json
#                (null runs of 2026-11-11, half an hour after the rig-base snapshot) is stale for any later
#                campaign: daily Windows tasks fire inside the snap0 -> snap2 window of a snapshot restored a day
#                later and would be labelled leftover. Use it only knowingly (offline rechecks of old runs).
#   M1A_SERVICING 1 (default) adds truth/labels/_os-servicing.json as a second --labels file; 0 leaves it out.
#   M1A_SANITY   run (default) or skip. skip leaves out step 2 and the frozen cross-check (step 5), for campaigns the
#                frozen M0 truth (Inbound rig-base) does not describe: dirty-base, Clean-Pro, no-baseline variants.
#                The status file records `sanity: skipped`.
#   M1A_SANITY_CLASSIFIED  classification of the residual sanity items (default $OUT/m1a-sanity-classified.json):
#                {"items": [{"app": <id>, "side": "frozen"|"run", "key": <key as in m1a-sanity.md>, "class": ...,
#                "evidence": ...}]}, matched on app, side and the key after normalising random names. Required by
#                --accept-sanity-diff; a residual item it does not list keeps the stop (exit 3).
#   M1A_LABELS   label-file overrides "id=label-id ...": run <prefix><id> uses truth/labels/<label-id>.json
#                (dirty-base: "firefox=firefox-dirty vscode-user=vscode-user-dirty").
#
# Per run <prefix><id>:
#   0. The ambient set: `rigtool ambient` over this campaign's null runs -> $OUT/ambient-<prefix>.json (RIG.md §6).
#      The null runs must exist (Invoke-Campaign -Nulls 3 -RunPrefix <prefix>) and have started within 12 h of the
#      app runs, else the script stops (exit 2).
#   1. rigtool truth with the app's label file truth/labels/<id>.json (vscode-user.json and firefox-tb.json
#      include the vscode/firefox rules) plus truth/labels/_os-servicing.json -> <run>/truth.json.
#   2. Sanity against truth/frozen/<id>/truth.json, when there is one: label counts and the leftover/user_data
#      items found in only one of the two, compared after normalising random names (GUIDs, numbers of 6+ digits,
#      the random part of %TEMP% file names) -> $OUT/m1a-sanity.md. Expected: no residual difference. Any
#      residual is investigated before scoring (exit 3 unless --accept-sanity-diff); the frozen truth stays the
#      reference for what counts as a leftover.
#   3. plans/purge.json = plan-purge.json with each item's `action` taken from the engine's sidecar
#      plan-purge.scan.json (the scorer needs it to tell RemoveDirIfEmpty from a delete, RIG.md §7), and the
#      frozen BCU plan truth/frozen/<id>/plans/bcu.json next to it (vscode-user and firefox-tb have none).
# Then:
#   4. rigtool score over all runs -> $OUT/m1a-score.json and .md (gate D reads the *_nd columns, danger and
#      the noop_if_nonempty list).
#   5. Cross-check on the frozen sets, when the git-ignored M0 snaps are present: the r0 purge plan and the
#      frozen BCU plan scored against the frozen truth -> $OUT/m1a-frozen-<id>.json and .md (items with
#      run-specific random names score `gone`; used to confirm danger 0 and precision).
#   6. rigtool invdiff for inv-1/inv-2 against lists-1/lists-2 of every run -> <run>/invdiff-<n>.json and .md;
#      each exit code is printed and recorded in $OUT/m1a-invdiff.md; the script exits 1 at the end when any
#      difference is unexplained (gate E).
set -euo pipefail
R=${RIGTOOL:-rigtool/target/release/rigtool}
APPS=${M1A_APPS:-"vscode vscode-user git firefox firefox-tb npp"}
PREFIX=${M1A_PREFIX:-r0-}
RUNS=${M1A_RUNS:-runs}
M0RUNS=${M1A_M0_RUNS:-runs}
if [ "$PREFIX" = "r0-" ]; then OUT=${M1A_OUT:-truth}; CLASSES=${M1A_CLASSES:-0}
else OUT=${M1A_OUT:-truth/${PREFIX%-}}; CLASSES=${M1A_CLASSES:-1}; fi
BCU=${M1A_BCU:-1}
NULLS=${M1A_NULLS:-"${PREFIX}null1 ${PREFIX}null2 ${PREFIX}null3"}
SERVICING=${M1A_SERVICING:-1}
ACCEPT=${M1A_ACCEPT_SANITY_DIFF:-0}
SANITY=${M1A_SANITY:-run}
case "$SANITY" in run|skip) ;; *) echo "m1a: M1A_SANITY must be run or skip, not $SANITY" >&2; exit 2 ;; esac
for a in "$@"; do
  case "$a" in
    --accept-sanity-diff) ACCEPT=1 ;;
    *) echo "m1a: unknown argument $a (only --accept-sanity-diff)" >&2; exit 2 ;;
  esac
done
mkdir -p "$OUT"
STATUS="$OUT/m1a-status.json"
CLASSIFIED=${M1A_SANITY_CLASSIFIED:-$OUT/m1a-sanity-classified.json}
CLASSIFIED_USED=""
label_of() { # label-file id for app id $1 (M1A_LABELS overrides)
  local m
  for m in ${M1A_LABELS:-}; do
    if [ "${m%%=*}" = "$1" ]; then echo "${m#*=}"; return; fi
  done
  echo "$1"
}

status() { # status <exit> <stage> [sanity_residual] [invdiff_codes]
  python -I - "$STATUS" "$1" "$2" "${3:-}" "${4:-}" "$ACCEPT" "${AMBIENT:-}" "$SERVICING" "$PREFIX" "$CLASSES" "$BCU" "$SANITY" "$CLASSIFIED_USED" "${M1A_LABELS:-}" <<'EOF'
import json, sys, datetime
out, code, stage, residual, inv, accept, ambient, servicing, prefix, classes, bcu, sanity, classified, labels = sys.argv[1:15]
doc = {'schema': 'purge.rig.m1a-status/1', 'time': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
       'prefix': prefix, 'classes': classes == '1', 'bcu': bcu == '1',
       'exit': int(code), 'stage': stage, 'ambient': ambient or None, 'servicing_rules': servicing == '1',
       'sanity': 'skipped' if sanity == 'skip' else 'run', 'label_overrides': labels or None,
       'sanity_residual': int(residual) if residual else None, 'accept_sanity_diff': accept == '1',
       'sanity_classified': classified or None,
       'invdiff': [dict(zip(('run', 'phase', 'exit'), x.split(':'))) for x in inv.split()] if inv else []}
for d in doc['invdiff']:
    d['exit'] = int(d['exit'])
with open(out, 'w', encoding='utf-8') as f:
    json.dump(doc, f, indent=2)
EOF
}

python -I truth/mk_labels.py truth/labels

# 0. ambient set from this campaign's null runs
if [ -n "${M1A_AMBIENT:-}" ]; then
  AMBIENT=$M1A_AMBIENT
  echo "m1a: ambient set given: $AMBIENT (not built from this campaign's null runs)" >&2
else
  null_dirs=()
  for n in $NULLS; do
    if [ -f "$RUNS/$n/run.json" ] && ls "$RUNS/$n"/snap-"$n"-0.tsv.gz "$RUNS/$n"/snap-"$n"-2.tsv.gz >/dev/null 2>&1; then
      null_dirs+=("$RUNS/$n")
    else
      echo "m1a: null run $RUNS/$n is missing or incomplete" >&2
    fi
  done
  if [ ${#null_dirs[@]} -lt 2 ]; then
    echo "m1a: need at least 2 null runs of this campaign ($NULLS) for the ambient set; run the campaign with" >&2
    echo "     Invoke-Campaign ... -Nulls 3 -RunPrefix $PREFIX (RIG.md §6), or set M1A_AMBIENT to a reviewed ambient file" >&2
    status 2 ambient; exit 2
  fi
  # The null runs must come from the same campaign: started within 12 h of the app runs (guest clock).
  null_jsons=(); for nd in "${null_dirs[@]}"; do null_jsons+=("$nd/run.json"); done
  app_jsons=(); for id in $APPS; do if [ -f "$RUNS/$PREFIX$id/run.json" ]; then app_jsons+=("$RUNS/$PREFIX$id/run.json"); fi; done
  if ! python -I - "${#null_jsons[@]}" "${null_jsons[@]}" "${app_jsons[@]}" <<'EOF'
import json, sys, datetime
n = int(sys.argv[1]); nulls, apps = sys.argv[2:2 + n], sys.argv[2 + n:]
def t(p):
    with open(p, encoding='utf-8-sig') as f:
        s = json.load(f)['started']
    return datetime.datetime.fromisoformat(s.split('.')[0][:19])
ts = {p: t(p) for p in nulls + apps}
if not apps:
    sys.exit(0)
lo, hi = min(ts[p] for p in apps), max(ts[p] for p in apps)
bad = [p for p in nulls if ts[p] < lo - datetime.timedelta(hours=12) or ts[p] > hi + datetime.timedelta(hours=12)]
for p in bad:
    print(f'm1a: null run {p} started {ts[p]}, more than 12 h away from the app runs ({lo} .. {hi}): not the same campaign', file=sys.stderr)
sys.exit(1 if bad else 0)
EOF
  then
    status 2 ambient-age; exit 2
  fi
  AMBIENT="$OUT/ambient-${PREFIX%-}.json"
  "$R" ambient --null "${null_dirs[@]}" -o "$AMBIENT"
fi
labels_extra=()
if [ "$SERVICING" = "1" ]; then labels_extra=(--labels truth/labels/_os-servicing.json); fi

sets=""
sanity_runs=""
for id in $APPS; do
  run=$PREFIX$id
  d=$RUNS/$run
  if [ ! -f "$d/run.json" ]; then
    echo "m1a: $d/run.json is missing: run the campaign first (rig.ps1 Invoke-Campaign -RunPrefix $PREFIX -Engine ...)" >&2
    status 2 runs; exit 2
  fi
  lid=$(label_of "$id")
  if [ ! -f "truth/labels/$lid.json" ]; then
    echo "m1a: no label file truth/labels/$lid.json for $run (variants: VARIANTS in truth/mk_labels.py)" >&2
    status 2 labels; exit 2
  fi
  if [ "$lid" != "$id" ]; then echo "m1a: $run: label file truth/labels/$lid.json (M1A_LABELS)" >&2; fi
  "$R" truth --s0 "$d/snap-$run-0.tsv.gz" --s1 "$d/snap-$run-1.tsv.gz" --s2 "$d/snap-$run-2.tsv.gz" \
    --lists0 "$d/lists-$run-0.json" --lists2 "$d/lists-$run-2.json" --run "$d/run.json" \
    --ambient "$AMBIENT" --labels "truth/labels/$lid.json" "${labels_extra[@]}" --deny truth/deny.json -o "$d/truth.json"

  # 3. plans: the purge plan with its actions, the frozen BCU plan
  mkdir -p "$d/plans"
  if [ -f "$d/plan-purge.json" ]; then
    python -I - "$d/plan-purge.json" "$d/plan-purge.scan.json" "$d/plans/purge.json" <<'EOF'
import json, os, sys
plan_f, scan_f, out_f = sys.argv[1:4]
with open(plan_f, encoding='utf-8-sig') as f:
    plan = json.load(f)
key = lambda t: json.dumps({k: (str(v).lower() if k != 'type' else v) for k, v in sorted(t.items())})
if os.path.isfile(scan_f):
    with open(scan_f, encoding='utf-8-sig') as f:
        scan = json.load(f)
    by = {}
    for it in scan.get('items', []):
        by.setdefault(key(it['target']), []).append(it.get('action'))
    missing = 0
    for it in plan.get('items', []):
        acts = by.get(key(it['target'])) or []
        if acts:
            it['action'] = acts.pop(0)
        else:
            missing += 1
    if missing:
        print(f'm1a: warning: {plan_f}: {missing} item(s) without an action in {scan_f}: scored as deletes', file=sys.stderr)
else:
    print(f'm1a: warning: no {scan_f}: every purge item is scored as a delete (delete-if-empty not recognised)', file=sys.stderr)
with open(out_f, 'w', encoding='utf-8') as f:
    json.dump(plan, f, indent=2, ensure_ascii=False)
EOF
  elif [ ! -f "$d/plans/purge.json" ]; then
    echo "m1a: warning: $run has no purge plan (engine-scan failed?)" >&2
  fi
  if [ "$BCU" = "1" ] && [ -f "truth/frozen/$id/plans/bcu.json" ]; then
    cp "truth/frozen/$id/plans/bcu.json" "$d/plans/bcu.json"
  elif [ "$BCU" != "1" ] && [ -f "$d/plans/bcu.json" ]; then
    rm -f "$d/plans/bcu.json"
  fi
  # plan-live.json / plan-purge-b.json (extra checks) stay out of plans/: they are not offers on this run's state.
  if [ "$SANITY" = "run" ] && [ -f "truth/frozen/$id/truth.json" ]; then
    sanity_runs="$sanity_runs $id"
  fi
  sets="$sets $d"
done

# 2. sanity: run truth vs frozen truth, random names normalised
residual=""
if [ "$SANITY" = "skip" ]; then
  echo "m1a: sanity step skipped (M1A_SANITY=skip: the frozen rig-base truth does not describe this campaign)" >&2
  printf '%s\n' "# M1a truth sanity: skipped" "" \
    "M1A_SANITY=skip: the frozen M0 truth (Inbound rig-base) does not describe this campaign (dirty-base, Clean-Pro or no-baseline runs); neither the sanity comparison nor the frozen cross-check ran." \
    > "$OUT/m1a-sanity.md"
  rm -f "$OUT/m1a-sanity-residual.json"
else
residual=$(python -I - "$RUNS" "$PREFIX" "$OUT/m1a-sanity.md" "$AMBIENT" "$OUT/m1a-sanity-residual.json" $sanity_runs <<'EOF'
import collections
import json
import re
import sys

runs, prefix, out, ambient, resfile, ids = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6:]
tag = prefix.rstrip('-') or 'run'
GUID = re.compile(r'\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?')
NUM = re.compile(r'(?<![0-9a-z])[0-9]{6,}(?![0-9a-z])|(?<=-)[0-9]{6,}(?=\.)')
TEMP = re.compile(r'(\\appdata\\local\\temp\\)([^\\|]+)')
RND = re.compile(r'[a-z0-9]{4,}')


def key(t):
    return '{}:{}|{}'.format(t.get('type'), str(t.get('path', '')).lower(), str(t.get('name', '') or '').lower())


def norm(k):
    # Random names only: GUIDs, long numbers (timestamps, session ids), and the random part of a %TEMP% file name
    # (is-XXXX.tmp, iu-XXXX.tmp, temXXXX.tmp: an alphanumeric run with a digit in it).
    k = GUID.sub('<guid>', k)
    k = NUM.sub('<n>', k)
    k = TEMP.sub(lambda m: m.group(1) + RND.sub(lambda r: '<rnd>' if re.search('[0-9]', r.group(0)) else r.group(0), m.group(2)), k)
    return k


def load(p):
    with open(p, encoding='utf-8') as f:
        return json.load(f)


lines = [f'# M1a truth sanity: {tag} runs vs frozen M0 truth', '',
         f'Ambient set: `{ambient}`.', '',
         'Expected: the same leftover/user_data items except random names (GUIDs, numbers of 6+ digits and the random '
         'part of %TEMP% file names are normalised before the comparison). A **residual** difference is investigated '
         'before scoring (m1a.sh stops with exit 3 unless --accept-sanity-diff).', '']
total = 0
resid = []
for id in ids:
    new = load(f'{runs}/{prefix}{id}/truth.json')
    old = load(f'truth/frozen/{id}/truth.json')
    lines.append(f'## {id}')
    lines.append('')
    lines.append(f'| label | frozen | {tag} |')
    lines.append('|---|---|---|')
    for lab in sorted(set(old.get('counts', {})) | set(new.get('counts', {}))):
        lines.append(f"| {lab} | {old.get('counts', {}).get(lab, 0)} | {new.get('counts', {}).get(lab, 0)} |")
    lines.append('')
    want = ('leftover', 'user_data')
    a = {key(i['target']) for i in old.get('items', []) if i.get('label') in want}
    b = {key(i['target']) for i in new.get('items', []) if i.get('label') in want}
    na, nb = collections.Counter(norm(k) for k in a), collections.Counter(norm(k) for k in b)
    res_old, res_new = na - nb, nb - na
    rnd = len(a ^ b) - sum(res_old.values()) - sum(res_new.values())
    n = sum(res_old.values()) + sum(res_new.values())
    total += n
    lines.append(f'random-name differences (normalised away): {rnd}; **residual: {n}**')
    lines.append('')
    newlab = {key(i['target']): i for i in new.get('items', [])}
    oldlab = {key(i['target']): i for i in old.get('items', [])}
    for side, title, res, raw, other in (('frozen', 'residual, only in frozen', res_old, a, newlab), ('run', f'residual, only in {tag}', res_new, b, oldlab)):
        lst = sorted(k for k in raw if res[norm(k)] > 0)
        resid += [{'app': id, 'side': side, 'key': k, 'norm': norm(k)} for k in lst]
        lines.append(f'{title}: {len(lst)}')
        for k in lst[:60]:
            o = other.get(k)
            lines.append(f'- `{k}`' + (f" (other side: {o['label']}, {o['rule'][:80]})" if o else ''))
        if len(lst) > 60:
            lines.append(f'- ... {len(lst) - 60} more')
        lines.append('')
lines.insert(4, f'**Total residual: {total}** over {len(ids)} run(s).')
lines.insert(5, '')
with open(out, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines) + '\n')
with open(resfile, 'w', encoding='utf-8') as f:
    json.dump({'schema': 'purge.rig.m1a-sanity-residual/1', 'prefix': prefix, 'items': resid}, f, indent=2, ensure_ascii=False)
print(f'm1a: sanity report {out} ({len(ids)} run(s) with frozen truth): residual {total}', file=sys.stderr)
print(total)
EOF
)
fi
if [ -n "$residual" ] && [ "$residual" -gt 0 ]; then
  if [ "$ACCEPT" = "1" ]; then
    # Acceptance needs every residual item classified (app, side, key after normalising random names).
    if ! python -I - "$OUT/m1a-sanity-residual.json" "$CLASSIFIED" <<'EOF'
import json, os, re, sys
resf, clf = sys.argv[1:3]
GUID = re.compile(r'\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?')
NUM = re.compile(r'(?<![0-9a-z])[0-9]{6,}(?![0-9a-z])|(?<=-)[0-9]{6,}(?=\.)')
TEMP = re.compile(r'(\\appdata\\local\\temp\\)([^\\|]+)')
RND = re.compile(r'[a-z0-9]{4,}')
def norm(k):  # as in the sanity step above
    k = GUID.sub('<guid>', k.lower())
    k = NUM.sub('<n>', k)
    return TEMP.sub(lambda m: m.group(1) + RND.sub(lambda r: '<rnd>' if re.search('[0-9]', r.group(0)) else r.group(0), m.group(2)), k)
with open(resf, encoding='utf-8') as f:
    res = json.load(f)['items']
if not os.path.isfile(clf):
    print(f'm1a: --accept-sanity-diff needs the classification file {clf} (M1A_SANITY_CLASSIFIED); none found', file=sys.stderr)
    sys.exit(1)
with open(clf, encoding='utf-8-sig') as f:
    cl = json.load(f).get('items', [])
have = {(c.get('app'), c.get('side'), norm(c.get('key', ''))) for c in cl if c.get('class') and c.get('evidence')}
miss = [r for r in res if (r['app'], r['side'], norm(r['key'])) not in have]
for r in miss[:40]:
    print(f"m1a: unclassified residual: {r['app']} ({r['side']}) {r['key']}", file=sys.stderr)
if miss:
    print(f'm1a: {len(miss)} of {len(res)} residual item(s) not classified in {clf}', file=sys.stderr)
    sys.exit(1)
print(f'm1a: all {len(res)} residual item(s) classified in {clf}', file=sys.stderr)
EOF
    then
      echo "m1a: STOP: --accept-sanity-diff given, but not every residual item is classified (see above)." >&2
      status 3 sanity "$residual"; exit 3
    fi
    CLASSIFIED_USED=$CLASSIFIED
    echo "m1a: sanity residual $residual (beyond random names), scoring: every item classified in $CLASSIFIED (recorded in $STATUS)" >&2
  else
    echo "m1a: STOP: the sanity check found $residual difference(s) beyond random names (see $OUT/m1a-sanity.md)." >&2
    echo "     Gate step 9: investigate them, record each in $CLASSIFIED, then rerun with --accept-sanity-diff." >&2
    status 3 sanity "$residual"; exit 3
  fi
fi

# 4. score Purge and BCU on the r0 runs
classes_arg=()
if [ "$CLASSES" = "1" ]; then classes_arg=(--classes); fi
# shellcheck disable=SC2086
"$R" score --set $sets --deny truth/deny.json "${classes_arg[@]}" --json "$OUT/m1a-score.json" --md "$OUT/m1a-score.md"

# 4b. extra checks (rig.ps1 -ExtraChecks): live scan of the still-installed app and the repeat scan
python -I - "$OUT/m1a-extra.md" $sets <<'EOF'
import hashlib, json, os, sys
out, dirs = sys.argv[1], sys.argv[2:]
def load(p):
    with open(p, encoding='utf-8-sig') as f:
        return json.load(f)
rows, n = [], 0
for d in dirs:
    run = load(os.path.join(d, 'run.json'))
    if not run.get('extra'):
        continue
    n += 1
    x = run['extra']
    live_f, a_f, b_f = (os.path.join(d, f) for f in ('plan-live.json', 'plan-purge.json', 'plan-purge-b.json'))
    live = []
    if os.path.isfile(live_f):
        live = load(live_f).get('items', [])
    safe = [i for i in live if str(i.get('band', '')).lower() == 'safe']
    pre = [i for i in live if i.get('preselected')]
    roots = [i for i in live if str(i.get('scanner', '')).upper() == 'FS-INSTALLDIR']
    root_ok = all(str(i.get('band', '')).lower() == 'blocked' for i in roots)
    live_ok = os.path.isfile(live_f) and not safe and not pre and root_ok
    h = lambda p: hashlib.sha256(open(p, 'rb').read()).hexdigest() if os.path.isfile(p) else None
    det_ok = x.get('det_equal') is True
    rows.append(f"| {run.get('run')} | {'ok' if live_ok else 'FAIL'} | {len(live)} | {len(safe)} | {len(pre)} | "
                f"{', '.join(str(i.get('band')) for i in roots) or 'absent'} | {x.get('det_equal')} | "
                f"{x.get('det_how', '')} | {(h(a_f) or '-')[:12]} / {(h(b_f) or '-')[:12]} |")
    for i in (safe + pre)[:20]:
        t = i.get('target', {})
        rows.append(f"|  | live item: `{t.get('type')} {t.get('path', t.get('full_name', t.get('name', '')))}` "
                    f"{i.get('band')}{' preselected' if i.get('preselected') else ''} ({i.get('scanner')}) | | | | | | | |")
if n == 0:
    print('m1a: no run with extra checks (rig.ps1 -ExtraChecks): no m1a-extra.md', file=sys.stderr)
    sys.exit(0)
with open(out, 'w', encoding='utf-8') as f:
    f.write('# Extra checks (M-LIVE, M-DET)\n\n'
            'Live: `scan --mode external` of the still-installed app (after harvest, before the uninstall). Pass = no item Safe, '
            'none preselected, the InstallRoot (FS-INSTALLDIR) absent or Blocked. Determinism: a second identical post scan; '
            'pass = `det_equal` (`plan_hash` of the two scans\' `.scan.json` sidecars, or the file SHA-256).\n\n'
            '| run | live | items | safe | preselected | install root | det_equal | det by | plan a / b sha256 |\n'
            '|---|---|---:|---:|---:|---|---|---|---|\n' + '\n'.join(rows) + '\n')
print(f'm1a: extra checks for {n} run(s) -> {out}', file=sys.stderr)
EOF

# 5. cross-check on the frozen sets
for id in $sanity_runs; do
  run=$PREFIX$id
  m0=$M0RUNS/$id
  plan=$RUNS/$run/plans/purge.json
  if [ ! -f "$plan" ] || [ ! -f "$m0/snap-$id-0.tsv.gz" ] || [ ! -f "$m0/snap-$id-2.tsv.gz" ]; then
    echo "m1a: skip frozen cross-check for $id (no purge plan or no M0 snaps in $m0)" >&2
    continue
  fi
  plans=(--plan "$plan")
  if [ -f "truth/frozen/$id/plans/bcu.json" ]; then plans+=(--plan "truth/frozen/$id/plans/bcu.json"); fi
  "$R" score "${plans[@]}" --truth "truth/frozen/$id/truth.json" --s0 "$m0/snap-$id-0.tsv.gz" --s2 "$m0/snap-$id-2.tsv.gz" \
    --deny truth/deny.json --json "$OUT/m1a-frozen-$id.json" --md "$OUT/m1a-frozen-$id.md"
done

# 6. inventory check (gate E): every exit code printed and recorded
unexplained=0
codes=""
inv_md=("# M1a inventory check (rigtool invdiff)" "" "Exit 0 = every difference explained; 1 = unexplained differences (or an error); 2 = inv-<n>.json missing." "" "| run | phase | exit | report |" "|---|---|---:|---|")
for id in $APPS; do
  run=$PREFIX$id
  d=$RUNS/$run
  for n in 1 2; do
    if [ ! -f "$d/inv-$n.json" ]; then
      echo "m1a: $d/inv-$n.json is missing (engine inventory phase failed?)" >&2
      rc=2
    else
      explain=()
      if [ -f truth/inventory-explain.json ]; then explain=(--explain truth/inventory-explain.json); fi
      set +e
      "$R" invdiff --inv "$d/inv-$n.json" --lists "$d/lists-$run-$n.json" "${explain[@]}" \
        --json "$d/invdiff-$n.json" --md "$d/invdiff-$n.md"
      rc=$?
      set -e
    fi
    echo "m1a: invdiff $run phase $n: exit $rc" >&2
    codes="$codes $run:$n:$rc"
    inv_md+=("| $run | $n | $rc | $d/invdiff-$n.md |")
    if [ "$rc" -ne 0 ]; then unexplained=1; fi
  done
done
printf '%s\n' "${inv_md[@]}" > "$OUT/m1a-invdiff.md"

status "$unexplained" done "$residual" "$codes"
echo "m1a: truth, sanity ($OUT/m1a-sanity.md, $([ "$SANITY" = skip ] && echo skipped || echo "residual $residual")) and score ($OUT/m1a-score.md) done; inventory check: $([ $unexplained -eq 0 ] && echo ok || echo FAILED) ($OUT/m1a-invdiff.md); exit $unexplained (recorded in $STATUS)"
exit $unexplained
