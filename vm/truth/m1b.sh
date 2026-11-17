#!/usr/bin/env bash
# M1b gate, scan side (docs/M1B_DESIGN.json gate_criteria K1-K9, K14, K16 for steps G1-G4, G7, G8; vm/RIG.md
# section 12). Run from vm/ after the campaigns of rig.ps1 -Mode m1b-apps / m1b-traps / m1b-budgets were pulled:
#
#   bash truth/m1b.sh                    collect (truth, plans, scores, traps) into the evidence dir, then evaluate
#   bash truth/m1b.sh --evaluate DIR     evaluate an evidence dir only (no rigtool; the recorded sample uses this)
#   bash truth/m1b.sh freeze <app>       frozen truth of powershell / temurin from the m1b-freeze runs (FROZEN.md)
#   bash truth/m1b.sh --selftest         m1b_sh_fails_on_missing_input, m1b_sh_passes_on_recorded_sample,
#                                        traps_json_every_case_has_expectation, traps_json_matches_guest_functions
#
# Prints one line per criterion and subject: "<K> <step> <subject>: <value> (limit <limit>) PASS|FAIL", writes
# $M1B_OUT/m1b-score.json (purge.rig.m1b-score/1) and exits 1 when any line FAILs (2 on a usage error). A criterion
# whose input is missing is FAIL with "missing ..." as its value, never skipped.
#
# Stage 1, collect (from the runs; rigtool):
#   For each set: clean = Inbound rig-base (runs <M1B_CLEAN>-<id>, G2), dirty = Inbound dirty-base (<M1B_DIRTY>-<id>,
#   G3), cp = Purge-CleanPro (<M1B_CP>-<id>, G8):
#   0. ambient set from that set's null runs <prefix>null1..3 (rigtool ambient; at least 2), as m1a.sh does;
#   1. rigtool truth with truth/labels/<id>.json (+ _os-servicing.json) -> <run>/truth.json;
#   2. plans/purge.json = plan-purge.json with each item's action from its scan sidecar (as m1a.sh step 3);
#   3. rigtool score --classes over the set -> $EVID/score-<set>.json; fp.json and plan-purge.scan.json of the apps
#      K7 / K8 read are copied to $EVID/<set>-<id>-{fp,scan}.json.
#   Traps (G4, G8): rigtool traps --plan <run>/plan-purge.scan.json --traps truth/m1b-traps.json --app 7zip --sid <run
#   sid> -> $EVID/traps-<run>.json, for M1B_TRAP_RUNS.
#   Budgets (G7): $M1B_BUDGETS (rig.ps1 -Mode m1b-budgets: budgets.json and the PURGE_TIMING logs) -> $EVID/budgets/.
#   Replay (G1): $M1B_REPLAY_DIFF (cargo xtask replay diff, M1B-SCAN-INTEG) and $M1B_REPLAY_SCORE (rigtool score of
#   the replayed plans, written by the gate) -> $EVID/.
#   $EVID/manifest.json records what was collected.
# Stage 2, evaluate (python, reads $EVID only): see the K table in RIG.md section 12.
#
# Environment:
#   RIGTOOL          rigtool binary (default rigtool/target/release/rigtool)
#   M1B_RUNS         run directories (default runs)
#   M1B_OUT          reports (default truth); M1B_EVIDENCE the evidence dir (default $M1B_OUT/m1b-evidence)
#   M1B_APPS         G2/G3 apps (default: the 8 of the gate); M1B_CP_APPS G8 apps (default "7zip python vcredist")
#   M1B_CLEAN, M1B_DIRTY, M1B_CP   run prefixes without the dash (default m1b, m1bd, m1bcp)
#   M1B_SETS         sets to collect and evaluate (default "clean dirty cp")
#   M1B_TRAP_RUNS    trap runs (default "m1b-traps-7zip m1bd-traps-7zip m1bcp-traps-7zip")
#   M1B_LABELS       label overrides "id=label-id ..." (as m1a.sh)
#   M1B_BUDGETS      budgets run dir (default runs/m1b-budgets)
#   M1B_REPLAY_DIFF  default truth/m1b-replay-diff.json; M1B_REPLAY_SCORE default truth/m1b-replay-score.json
# Anything but the defaults for M1B_APPS, M1B_CP_APPS, M1B_SETS or M1B_TRAP_RUNS is recorded as gate_config "custom":
# such a score is never the gate's.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PY=${PYTHON:-python}
R=${RIGTOOL:-rigtool/target/release/rigtool}
RUNS=${M1B_RUNS:-runs}
OUT=${M1B_OUT:-truth}
EVID=${M1B_EVIDENCE:-$OUT/m1b-evidence}
DEF_APPS="7zip python python312-with-313 python313-with-312 node vcredist powershell temurin"
DEF_CP_APPS="7zip python vcredist"
DEF_SETS="clean dirty cp"
DEF_TRAPS="m1b-traps-7zip m1bd-traps-7zip m1bcp-traps-7zip"
APPS=${M1B_APPS:-$DEF_APPS}
CP_APPS=${M1B_CP_APPS:-$DEF_CP_APPS}
SETS=${M1B_SETS:-$DEF_SETS}
TRAP_RUNS=${M1B_TRAP_RUNS:-$DEF_TRAPS}
BUDGETS=${M1B_BUDGETS:-$RUNS/m1b-budgets}
REPLAY_DIFF=${M1B_REPLAY_DIFF:-truth/m1b-replay-diff.json}
REPLAY_SCORE=${M1B_REPLAY_SCORE:-truth/m1b-replay-score.json}
CONFIG=default
if [ "$APPS" != "$DEF_APPS" ] || [ "$CP_APPS" != "$DEF_CP_APPS" ] || [ "$SETS" != "$DEF_SETS" ] || [ "$TRAP_RUNS" != "$DEF_TRAPS" ]; then CONFIG=custom; fi

prefix_of() { case "$1" in clean) echo "${M1B_CLEAN:-m1b}" ;; dirty) echo "${M1B_DIRTY:-m1bd}" ;; cp) echo "${M1B_CP:-m1bcp}" ;; esac; }
apps_of() { if [ "$1" = cp ]; then echo "$CP_APPS"; else echo "$APPS"; fi; }
label_of() { local m; for m in ${M1B_LABELS:-}; do if [ "${m%%=*}" = "$1" ]; then echo "${m#*=}"; return; fi; done; echo "$1"; }

# ------------------------------------------------------------------------------------------- stage 2
evaluate() { # evaluate <evidence dir> <score json out>
  "$PY" -I - "$1" "$2" "$APPS" "$CP_APPS" "$SETS" "$TRAP_RUNS" "$CONFIG" <<'EOF'
import datetime, glob, json, os, re, statistics, sys

evid, out, apps, cp_apps, sets, trap_runs, config = sys.argv[1:8]
apps, cp_apps, sets, trap_runs = apps.split(), cp_apps.split(), sets.split(), trap_runs.split()
STEP = {'clean': 'G2', 'dirty': 'G3', 'cp': 'G8'}
rows = []


def row(k, step, subject, value, limit, ok, note=None):
    rows.append({'id': k, 'step': step, 'subject': subject, 'value': value, 'limit': limit, 'pass': bool(ok), 'note': note})


def load(name):
    p = os.path.join(evid, name)
    if not os.path.isfile(p):
        return None
    try:
        with open(p, encoding='utf-8-sig') as f:
            return json.load(f)
    except Exception:
        return None


def miss(what):
    return f'missing {what}'


def set_apps(s):
    return cp_apps if s == 'cp' else apps


manifest = load('manifest.json') or {}
prefix = {s: manifest.get('prefixes', {}).get(s, {'clean': 'm1b', 'dirty': 'm1bd', 'cp': 'm1bcp'}[s]) for s in sets}


def purge_score(s, id):
    """The purge tool's score of app id in set s, or None."""
    sc = load(f'score-{s}.json')
    if not sc:
        return None
    run = f'{prefix[s]}-{id}'
    for a in sc.get('apps', []):
        # rigtool score: id = the run's app id, dir = the run directory (its last segment is the run name)
        if str(a.get('dir', '')).replace('\\', '/').rstrip('/').split('/')[-1] == run:
            for t in a.get('tools', []):
                if t.get('tool') == 'purge':
                    return t
    return None


# K1-K6 per set and app
for s in sets:
    st = STEP[s]
    for id in set_apps(s):
        t = purge_score(s, id)
        subj = f'{s}/{id}'
        if t is None:
            for k in (['K1'] if s != 'dirty' else ['K2']) + ['K3', 'K4', 'K5', 'K6']:
                if k == 'K6' and s == 'cp':
                    continue
                row(k, st, subj, miss(f'score of {prefix[s]}-{id} (score-{s}.json)'), '-', False)
            continue
        if s == 'dirty':
            row('K2', st, subj, t.get('danger_blocking'), 0, t.get('danger_blocking') == 0)
        else:
            row('K1', st, subj, t.get('danger_listed'), 0, t.get('danger_listed') == 0)
        dp, up = t.get('danger_preselected'), t.get('userdata_preselected')
        row('K3', st, subj, f'danger_preselected={dp} userdata_preselected={up}', '0 and 0', dp == 0 and up == 0)
        ps = t.get('precision_safe')
        row('K4', st, subj, ps, 1.0, ps is None or ps == 1.0, 'no Safe item: null, not counted as a pass' if ps is None else None)
        pn, pc, pw = t.get('protected_n', 0) or 0, t.get('protected_correct'), t.get('protected_wrong') or []
        need = 29 if id in ('python312-with-313', 'python313-with-312') else 0
        if pn == 0 and need == 0:
            row('K5', st, subj, 'n/a (no kept_owner/protected truth item)', '100 %', True)
        else:
            ok = pn >= need and pc == 1.0 and not pw
            row('K5', st, subj, f'protected_correct={pc} n={pn} wrong={len(pw)}', f'100 %{f", n >= {need}" if need else ""}', ok)
        if s != 'cp':
            bad = []
            for it in t.get('items', []):
                if it.get('outcome') == 'hit' and not it.get('userdata') and it.get('band') not in ('Safe', 'Likely'):
                    bad.append(f"leftover in {it.get('band')}: {it.get('target')}")
            bad += [f'user data preselected x{up}'] if up else []
            bad += [f"protected below Protected: {w.get('target', w) if isinstance(w, dict) else w}" for w in pw]
            row('K6', st, subj, len(bad), 0, not bad, '; '.join(bad[:5]) or None)

# K7: 7-Zip MSI (G2): fingerprint root with source MsiComponent; plan lists HKU\<sid>\Software\7-Zip
if 'clean' in sets and '7zip' in apps:
    fp = load('clean-7zip-fp.json')
    if fp is None:
        row('K7', 'G2', 'clean/7zip fingerprint', miss('clean-7zip-fp.json'), 'root C:\\Program Files\\7-Zip from MsiComponent', False)
    else:
        found = []

        def walk(v):
            if isinstance(v, dict):
                p, src = str(v.get('path', '')), str(v.get('source', ''))
                if p.rstrip('\\').lower() == 'c:\\program files\\7-zip' and src.lower().replace('_', '') == 'msicomponent':
                    found.append(v)
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)
        walk(fp.get('roots', fp))
        row('K7', 'G2', 'clean/7zip fingerprint', 'root found' if found else 'no MsiComponent root', 'root C:\\Program Files\\7-Zip from MsiComponent', bool(found))
    t = purge_score('clean', '7zip')
    if t is None:
        row('K7', 'G2', 'clean/7zip plan', miss('score of the 7zip run'), 'HKU\\<sid>\\Software\\7-Zip listed', False)
    else:
        hit = [i for i in t.get('items', []) if re.fullmatch(r'K:HKU\\S-1-5-21-[0-9-]+\\Software\\7-Zip', str(i.get('target', '')), re.I) and i.get('band') != 'Blocked']
        row('K7', 'G2', 'clean/7zip plan', f'{len(hit)} listing(s) of HKU\\<sid>\\Software\\7-Zip', '>= 1', bool(hit))
if True:  # G1: the replay of the frozen corpus
    rs = load('replay-score.json')
    if rs is None:
        row('K4', 'G1', 'replay', miss('replay-score.json (rigtool score of the replayed plans)'), 'danger 0, precision_safe 100 %', False)
        row('K7', 'G1', 'replay 7zip', miss('replay-score.json'), 'HKU\\<sid>\\Software\\7-Zip listed', False)
    else:
        for a in rs.get('apps', []):
            for t in a.get('tools', []):
                if t.get('tool') != 'purge':
                    continue
                ps, dl = t.get('precision_safe'), t.get('danger_listed')
                row('K4', 'G1', f"replay/{a.get('id')}", f'danger_listed={dl} precision_safe={ps}', 'danger 0, precision_safe 100 %',
                    dl == 0 and (ps is None or ps == 1.0))
        z = [t for a in rs.get('apps', []) if a.get('id') == '7zip' for t in a.get('tools', []) if t.get('tool') == 'purge']
        hit = [i for t in z for i in t.get('items', []) if re.fullmatch(r'K:HKU\\S-1-5-21-[0-9-]+\\Software\\7-Zip', str(i.get('target', '')), re.I) and i.get('band') != 'Blocked']
        row('K7', 'G1', 'replay 7zip', f'{len(hit)} listing(s)' if z else miss('a 7zip app in replay-score.json'), 'HKU\\<sid>\\Software\\7-Zip listed', bool(hit))


# K8: vcredist nothing preselected, no danger; python alone: the launcher suggestion (report-only); python312-with-313: none
def suggestions(scan):
    out = []
    for it in (scan or {}).get('items', []):
        if 'suggest_uninstall' in json.dumps(it):
            out.append(it)
    return out


for s in [x for x in sets if x in ('clean', 'dirty')]:
    st = STEP[s]
    if 'vcredist' in apps:
        t = purge_score(s, 'vcredist')
        if t is None:
            row('K8', st, f'{s}/vcredist', miss('vcredist score'), '0 preselected, 0 danger', False)
        else:
            pre = sum(1 for i in t.get('items', []) if i.get('preselected'))
            row('K8', st, f'{s}/vcredist', f'preselected={pre} danger_listed={t.get("danger_listed")}', '0 and 0', pre == 0 and t.get('danger_listed') == 0)
    if 'python' in apps:
        scan = load(f'{s}-python-scan.json')
        if scan is None:
            row('K8', st, f'{s}/python suggestion', miss(f'{s}-python-scan.json'), 'launcher suggestion, report-only', False)
        else:
            sg = suggestions(scan)
            ok = bool(sg) and all(str(i.get('action')) == 'ReportOnly' for i in sg)
            row('K8', st, f'{s}/python suggestion', f'{len(sg)} suggestion(s), actions {sorted({str(i.get("action")) for i in sg})}', '>= 1, all ReportOnly', ok)
    if 'python312-with-313' in apps:
        scan = load(f'{s}-python312-with-313-scan.json')
        if scan is None:
            row('K8', st, f'{s}/python312-with-313 suggestion', miss(f'{s}-python312-with-313-scan.json'), 'none', False)
        else:
            sg = suggestions(scan)
            row('K8', st, f'{s}/python312-with-313 suggestion', len(sg), 0, not sg)

# K9: traps
for run in trap_runs:
    st = 'G8' if run.startswith('m1bcp') or '-m1bcp' in run else 'G4'
    tr = load(f'traps-{run}.json')
    if tr is None:
        row('K9', st, run, miss(f'traps-{run}.json'), 'escapes 0, missed_owned 0, 26 cases', False)
        continue
    sm = tr.get('summary', {})
    ok = sm.get('escapes') == 0 and sm.get('missed_owned') == 0 and sm.get('cases') == 26
    row('K9', st, run, f"cases={sm.get('cases')} escapes={sm.get('escapes')} missed_owned={sm.get('missed_owned')}", 'escapes 0, missed_owned 0, 26 cases', ok)

# K14: budgets
STAMP = re.compile(r'^\[\s*([0-9.]+)s\]')
PHASE = re.compile(r'^timing:\s+phase (\S+) ([0-9.]+)s')


def parse_log(p):
    total, phases = None, {}
    try:
        with open(p, encoding='utf-8', errors='replace') as f:
            for line in f:
                m = STAMP.match(line)
                if m:
                    total = float(m.group(1))
                m = PHASE.match(line)
                if m:
                    phases.setdefault(m.group(1), []).append(float(m.group(2)))
    except OSError:
        return None
    return {'total': total, 'phases': phases}


bud = load('budgets/budgets.json')
if bud is None:
    for what in ('reference walks per scan', 'added scan time', 'added harvest time', 'ownership.components', 'ownership.tables'):
        row('K14', 'G7', what, miss('budgets/budgets.json (rig.ps1 -Mode m1b-budgets)'), '-', False)
else:
    logs = {}
    for r in bud.get('runs', []):
        logs[(r['engine'], r['step'], r['kind'], r['round'])] = parse_log(os.path.join(evid, 'budgets', r['log']))

    def times(eng, step, kind):
        v = [x['total'] for (e, s_, k, _), x in logs.items() if e == eng and s_ == step and k == kind and x and x['total'] is not None]
        return v

    walks = [len(x['phases'].get('refscan', [])) for (e, s_, k, _), x in logs.items() if e == 'm1b' and s_ == 'scan' and x]
    row('K14', 'G7', 'reference walks per scan', walks if walks else miss('m1b scan logs'), '1 each', bool(walks) and all(w == 1 for w in walks))
    for step, label in (('scan', 'added scan time'), ('harvest', 'added harvest time')):
        for kind, lim in (('warm', 2.5), ('cold', 6.5)):
            a, b = times('m1b', step, kind), times('m2', step, kind)
            if not a or not b:
                row('K14', 'G7', f'{label} ({kind})', miss(f'{kind} {step} logs of both engines'), f'<= {lim} s', False)
                continue
            d = statistics.median(a) - statistics.median(b)
            row('K14', 'G7', f'{label} ({kind})', round(d, 3), f'<= {lim} s', d <= lim, f'm1b {statistics.median(a):.3f} s vs m2 {statistics.median(b):.3f} s (median)')
    comp = [v for (e, s_, k, _), x in logs.items() if e == 'm1b' and x for v in x['phases'].get('ownership.components', [])]
    row('K14', 'G7', 'ownership.components', max(comp) if comp else miss('ownership.components phase lines'), '<= 1.5 s', bool(comp) and max(comp) <= 1.5)
    for kind, lim in (('cold', 4.0), ('warm', 0.3)):
        tb = [v for (e, s_, k, _), x in logs.items() if e == 'm1b' and k == kind and x for v in x['phases'].get('ownership.tables', [])]
        val = (max(tb) if kind == 'cold' else statistics.median(tb)) if tb else None
        row('K14', 'G7', f'ownership.tables ({kind})', val if tb else miss(f'{kind} ownership.tables lines'), f'<= {lim} s', bool(tb) and val <= lim)

# K16: replay diff
rd = load('replay-diff.json')
if rd is None:
    row('K16', 'G1', 'replay diff', miss('replay-diff.json'), 'unexplained 0', False)
else:
    allowed = set(rd.get('reasons') or [])
    bad = [r for r in rd.get('rows', []) if r.get('reason') not in allowed]
    ok = rd.get('unexplained') == 0 and not bad and allowed <= {'new_scanner', 'msi_blocker_added', 'msi_root_added', 'policy_m1b'}
    row('K16', 'G1', 'replay diff', f"unexplained={rd.get('unexplained')} rows_without_allowed_reason={len(bad)}", 0, ok)

fails = [r for r in rows if not r['pass']]
for r in rows:
    print(f"{r['id']} {r['step']} {r['subject']}: {r['value']} (limit {r['limit']}) {'PASS' if r['pass'] else 'FAIL'}"
          + (f"  [{r['note']}]" if r['note'] else ''))
doc = {'schema': 'purge.rig.m1b-score/1', 'time': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
       'evidence': evid, 'gate_config': config, 'apps': apps, 'cp_apps': cp_apps, 'sets': sets, 'trap_runs': trap_runs,
       'criteria': rows, 'failed': len(fails), 'pass': not fails and bool(rows)}
os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
with open(out, 'w', encoding='utf-8') as f:
    json.dump(doc, f, indent=2, ensure_ascii=False)
print(f"m1b: {len(rows) - len(fails)}/{len(rows)} PASS, {len(fails)} FAIL ({config} config) -> {out}")
sys.exit(0 if doc['pass'] else 1)
EOF
}

# ------------------------------------------------------------------------------------------- stage 1
collect() {
  mkdir -p "$EVID" "$EVID/budgets"
  rm -f "$EVID"/score-*.json "$EVID"/traps-*.json "$EVID"/*-fp.json "$EVID"/*-scan.json "$EVID"/replay-*.json "$EVID"/budgets/*
  local labels_extra=(--labels truth/labels/_os-servicing.json)
  local s id run d lid p n
  for s in $SETS; do
    p=$(prefix_of "$s")
    # 0. ambient from this set's null runs
    local nulls=()
    for n in 1 2 3; do
      d="$RUNS/$p-null$n"
      if [ -f "$d/run.json" ] && ls "$d/snap-$p-null$n-0.tsv.gz" "$d/snap-$p-null$n-2.tsv.gz" >/dev/null 2>&1; then nulls+=("$d"); fi
    done
    local amb="$EVID/ambient-$s.json"
    if [ ${#nulls[@]} -ge 2 ]; then "$R" ambient --null "${nulls[@]}" -o "$amb" >&2 || rm -f "$amb"
    else echo "m1b: set $s: fewer than 2 null runs ($RUNS/$p-null1..3): no ambient set, no truth, its criteria FAIL" >&2; rm -f "$amb"; fi
    local dirs=()
    for id in $(apps_of "$s"); do
      run="$p-$id"; d="$RUNS/$run"
      if [ ! -f "$d/run.json" ] || [ ! -f "$amb" ]; then echo "m1b: $run: no run or no ambient set" >&2; continue; fi
      lid=$(label_of "$id")
      if [ ! -f "truth/labels/$lid.json" ]; then echo "m1b: $run: no label file truth/labels/$lid.json" >&2; continue; fi
      if ! "$R" truth --s0 "$d/snap-$run-0.tsv.gz" --s1 "$d/snap-$run-1.tsv.gz" --s2 "$d/snap-$run-2.tsv.gz" \
          --lists0 "$d/lists-$run-0.json" --lists2 "$d/lists-$run-2.json" --run "$d/run.json" \
          --ambient "$amb" --labels "truth/labels/$lid.json" "${labels_extra[@]}" --deny truth/deny.json -o "$d/truth.json" >&2; then
        echo "m1b: $run: rigtool truth failed" >&2; continue
      fi
      mkdir -p "$d/plans"
      if [ -f "$d/plan-purge.json" ]; then
        "$PY" -I - "$d/plan-purge.json" "$d/plan-purge.scan.json" "$d/plans/purge.json" <<'EOF'
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
    for it in plan.get('items', []):
        acts = by.get(key(it['target'])) or []
        if acts:
            it['action'] = acts.pop(0)
with open(out_f, 'w', encoding='utf-8') as f:
    json.dump(plan, f, indent=2, ensure_ascii=False)
EOF
      else echo "m1b: $run: no plan-purge.json" >&2; fi
      rm -f "$d/plans/bcu.json"   # M1b scores purge alone
      for f in fp scan; do
        local src="$d/fp.json"; [ "$f" = scan ] && src="$d/plan-purge.scan.json"
        if [ -f "$src" ]; then cp "$src" "$EVID/$s-$id-$f.json"; fi
      done
      dirs+=("$d")
    done
    if [ ${#dirs[@]} -gt 0 ]; then
      "$R" score --set "${dirs[@]}" --deny truth/deny.json --classes --json "$EVID/score-$s.json" --md "$EVID/score-$s.md" >&2 \
        || { echo "m1b: rigtool score for set $s failed" >&2; rm -f "$EVID/score-$s.json"; }
    fi
  done
  for run in $TRAP_RUNS; do
    d="$RUNS/$run"
    if [ ! -f "$d/plan-purge.scan.json" ] || [ ! -f "$d/run.json" ]; then echo "m1b: trap run $run: no plan-purge.scan.json" >&2; continue; fi
    local sid; sid=$("$PY" -I -c "import json,sys; print(json.load(open(sys.argv[1], encoding='utf-8-sig')).get('sid') or '')" "$d/run.json")
    "$R" traps --plan "$d/plan-purge.scan.json" --traps truth/m1b-traps.json --app 7zip ${sid:+--sid "$sid"} --out "$EVID/traps-$run.json" >&2
    case $? in 0|1) ;; *) echo "m1b: rigtool traps for $run: input error" >&2; rm -f "$EVID/traps-$run.json" ;; esac
  done
  if [ -f "$BUDGETS/budgets.json" ]; then cp "$BUDGETS/budgets.json" "$BUDGETS"/*.log "$EVID/budgets/" 2>/dev/null; fi
  [ -f "$REPLAY_DIFF" ] && cp "$REPLAY_DIFF" "$EVID/replay-diff.json"
  [ -f "$REPLAY_SCORE" ] && cp "$REPLAY_SCORE" "$EVID/replay-score.json"
  "$PY" -I -c "
import json, sys
sets = sys.argv[2].split()
pre = {s: v for s, v in zip(('clean', 'dirty', 'cp'), sys.argv[3:6])}
json.dump({'schema': 'purge.rig.m1b-evidence/1', 'note': 'collected by vm/truth/m1b.sh from ' + sys.argv[6],
           'prefixes': {s: pre[s] for s in sets}}, open(sys.argv[1], 'w', encoding='utf-8'), indent=2)
" "$EVID/manifest.json" "$SETS" "$(prefix_of clean)" "$(prefix_of dirty)" "$(prefix_of cp)" "$RUNS"
}

# ------------------------------------------------------------------------------------------- selftest
selftest() {
  local fails=0 tmp; tmp=$(mktemp -d)
  # m1b_sh_fails_on_missing_input: an empty evidence dir -> exit 1, every line FAIL, none skipped
  evaluate "$tmp/empty-does-not-exist" "$tmp/empty.json" >"$tmp/empty.txt" 2>&1; local rc=$?
  if [ $rc -eq 1 ] && "$PY" -I -c "
import json, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
rows = d['criteria']
need = {'K1', 'K2', 'K3', 'K4', 'K5', 'K6', 'K7', 'K8', 'K9', 'K14', 'K16'}
assert rows and all(not r['pass'] for r in rows if r['id'] != 'K5' or 'missing' in str(r['value'])), 'a line passed on no input'
assert need <= {r['id'] for r in rows}, need - {r['id'] for r in rows}
assert not d['pass']
" "$tmp/empty.json"; then echo "ok   m1b_sh_fails_on_missing_input"; else echo "FAIL m1b_sh_fails_on_missing_input (exit $rc)"; fails=$((fails + 1)); fi
  # m1b_sh_passes_on_recorded_sample: the committed sample (synthetic evidence, see its manifest) -> exit 0
  # The sample covers 4 of the 8 apps and the cp set's 7zip only (a custom config, recorded as such).
  if (APPS="7zip python python312-with-313 vcredist" CP_APPS="7zip" CONFIG=custom
      evaluate "$HERE/_m1b_sample" "$tmp/sample.json") >"$tmp/sample.txt" 2>&1; then echo "ok   m1b_sh_passes_on_recorded_sample"
  else echo "FAIL m1b_sh_passes_on_recorded_sample"; grep FAIL "$tmp/sample.txt" | head -10; fails=$((fails + 1)); fi
  # the sample must also fail when one input is taken away (the evaluator reads it)
  cp -r "$HERE/_m1b_sample" "$tmp/s2"; rm -f "$tmp/s2/traps-m1bd-traps-7zip.json"
  if (APPS="7zip python python312-with-313 vcredist" CP_APPS="7zip" CONFIG=custom; evaluate "$tmp/s2" "$tmp/s2.json") >/dev/null 2>&1; then
    echo "FAIL m1b_sh_fails_when_a_sample_input_is_removed"; fails=$((fails + 1)); else echo "ok   m1b_sh_fails_when_a_sample_input_is_removed"; fi
  # traps_json_every_case_has_expectation
  if "$PY" -I - "$HERE/m1b-traps.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
assert d['schema'] == 'purge.m1b.traps/1'
want = ['svc-owned', 'svc-owned-running', 'svc-shared', 'svc-dependent', 'svc-svchost', 'task-owned', 'task-similar-name',
        'task-interpreter', 'fw-owned', 'fw-same-display-name', 'fw-no-app', 'com-owned', 'com-shared-class', 'com-isimpledom',
        'shellex-approved', 'shareddlls-count', 'eventlog-shared-source', 'tracing', 'privacy-twins', 'wer-twins',
        'msi-remnants', 'msi-remnants-foreign', 'msi-shared-component', 'burn-shared-package', 'pkgcache-foreign', 'instfolders']
ids = [c['id'] for c in d['cases']]
assert sorted(ids) == sorted(want) and len(ids) == 26, set(ids) ^ set(want)
V = {'absent', 'protected', 'not_preselected', 'listed', 'safe'}
for c in d['cases']:
    assert c['phase'] in ('pre', 'post') and c['plant'].startswith('Plant-'), c['id']
    assert c['expect'], f"{c['id']}: no expectation"
    for e in c['expect']:
        assert e['verdict'] in V and e['target'].get('type'), c['id']
        assert e.get('blocker') is None or e['verdict'] == 'protected', c['id']
# the design's verdicts for the named cases, except where RIG.md section 12.3 (smoke 2026-11-17) says why not:
# svc-owned, task-owned, fw-owned, com-owned 'listed' (the plants leave files in TrapA's root: no program is proven
# gone), msi-remnants 'absent' (Windows Installer reports the re-registered product installed for another user),
# svc-svchost 'protected' (REF-ANY lists the ServiceDll value inside the service key, Blocked)
must = {'svc-owned': 'listed', 'task-owned': 'listed', 'fw-owned': 'listed', 'com-owned': 'listed', 'msi-remnants': 'absent',
        'svc-owned-running': 'listed', 'svc-shared': 'absent', 'svc-svchost': 'protected', 'task-similar-name': 'absent',
        'fw-same-display-name': 'absent', 'fw-no-app': 'absent', 'msi-remnants-foreign': 'absent', 'pkgcache-foreign': 'absent',
        'task-interpreter': 'not_preselected', 'tracing': 'not_preselected'}
by = {c['id']: c for c in d['cases']}
for k, v in must.items():
    assert by[k]['expect'][0]['verdict'] == v, (k, by[k]['expect'][0]['verdict'], v)
for k in ('svc-dependent', 'com-shared-class', 'com-isimpledom', 'shareddlls-count', 'msi-shared-component', 'burn-shared-package'):
    assert any(e['verdict'] in ('protected', 'absent') for e in by[k]['expect']), k
EOF
  then echo "ok   traps_json_every_case_has_expectation"; else echo "FAIL traps_json_every_case_has_expectation"; fails=$((fails + 1)); fi
  # traps_json_matches_guest_functions (the M1B-RIG-GUEST Pester test, Windows only)
  if command -v powershell.exe >/dev/null 2>&1; then
    local pt; pt=$(cygpath -w "$HERE/../guest/tests/m1b-traps.tests.ps1" 2>/dev/null || echo "$HERE/../guest/tests/m1b-traps.tests.ps1")
    if powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "\$r = Invoke-Pester -Script '$pt' -PassThru -Quiet; if (\$r.FailedCount -or -not \$r.PassedCount) { exit 1 }" >/dev/null 2>&1; then
      echo "ok   traps_json_matches_guest_functions"; else echo "FAIL traps_json_matches_guest_functions"; fails=$((fails + 1)); fi
  else echo "FAIL traps_json_matches_guest_functions (no powershell.exe: run it on Windows)"; fails=$((fails + 1)); fi
  rm -rf "$tmp"
  echo "m1b selftest: $fails failure(s)"
  [ $fails -eq 0 ]
}

# ------------------------------------------------------------------------------------------- freeze
# freeze <app>: the frozen truth of an M1b app from its two raw runs (rig.ps1 -Mode m1b-freeze: runs
# m1b-fz1-<app>, m1b-fz2-<app> on Inbound rig-base, vendor uninstall, no engine), M0 method (FROZEN.md):
# ambient = truth/ambient.json (the M0 null runs) + labels/_os.json via the label file; rigtool truth per run; the
# two runs must agree on the item set of every label but ambient (else exit 1: look at the diff, fix the labels,
# re-run); run 1 is copied to truth/frozen/<app>/{truth.json, run.json} and the fz2 truth beside it as truth-fz2.json.
freeze() {
  local app=$1 k d run lid; lid=$(label_of "$app")
  [ -f "truth/labels/$lid.json" ] || { echo "m1b freeze: no truth/labels/$lid.json" >&2; return 2; }
  for k in 1 2; do
    run="m1b-fz$k-$app"; d="$RUNS/$run"
    [ -f "$d/run.json" ] || { echo "m1b freeze: no run $d (rig.ps1 -Mode m1b-freeze)" >&2; return 2; }
    "$R" truth --s0 "$d/snap-$run-0.tsv.gz" --s1 "$d/snap-$run-1.tsv.gz" --s2 "$d/snap-$run-2.tsv.gz" \
      --lists0 "$d/lists-$run-0.json" --lists2 "$d/lists-$run-2.json" --run "$d/run.json" \
      --ambient truth/ambient.json --labels "truth/labels/$lid.json" --labels truth/labels/_os-servicing.json \
      --deny truth/deny.json -o "$d/truth.json" >&2 \
      || { echo "m1b freeze: rigtool truth failed for $run" >&2; return 2; }
  done
  "$PY" -I - "$RUNS/m1b-fz1-$app/truth.json" "$RUNS/m1b-fz2-$app/truth.json" <<'EOF' || return 1
import json, re, sys
def items(p):
    d = json.load(open(p, encoding='utf-8-sig'))
    out = set()
    for it in d.get('items', []):
        if it.get('label') == 'ambient':
            continue
        out.add((it.get('label'), re.sub(r'S-1-5-21-[0-9-]+', '<sid>', json.dumps(it.get('target'), sort_keys=True)).lower()))
    return out
a, b = items(sys.argv[1]), items(sys.argv[2])
for x in sorted(a - b)[:20]: print('only fz1:', *x)
for x in sorted(b - a)[:20]: print('only fz2:', *x)
print(f'freeze: fz1 {len(a)} items, fz2 {len(b)} items, {len(a ^ b)} differ')
sys.exit(1 if a ^ b else 0)
EOF
  mkdir -p "truth/frozen/$app"
  cp "$RUNS/m1b-fz1-$app/truth.json" "$RUNS/m1b-fz1-$app/run.json" "truth/frozen/$app/"
  cp "$RUNS/m1b-fz2-$app/truth.json" "truth/frozen/$app/truth-fz2.json"
  echo "m1b freeze: truth/frozen/$app written; describe it in truth/FROZEN.md (M1b section)"
}

case "${1:-}" in
  --selftest) selftest; exit $? ;;
  freeze) [ -n "${2:-}" ] || { echo "m1b: freeze needs an app id" >&2; exit 2; }; freeze "$2"; exit $? ;;
  --evaluate) [ -n "${2:-}" ] || { echo "m1b: --evaluate needs an evidence dir" >&2; exit 2; }
              evaluate "$2" "$OUT/m1b-score.json"; exit $? ;;
  "") collect; evaluate "$EVID" "$OUT/m1b-score.json"; exit $? ;;
  *) echo "m1b: unknown argument $1 (--selftest, --evaluate DIR, freeze APP, or nothing)" >&2; exit 2 ;;
esac
