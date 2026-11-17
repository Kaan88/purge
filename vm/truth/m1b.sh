#!/usr/bin/env bash
# M1b gate, scan side (docs/M1B_DESIGN.json gate_criteria K1-K9, K14, K16 for steps G1-G4, G7, G8; vm/RIG.md
# section 12). Run from vm/ after the campaigns of rig.ps1 -Mode m1b-apps / m1b-traps / m1b-budgets were pulled:
#
#   bash truth/m1b.sh                    collect (truth, plans, scores, traps) into the evidence dir, then evaluate:
#                                        the gate score (exit 0 only here, and only in the default configuration)
#   bash truth/m1b.sh --evaluate DIR     evaluate an evidence dir only (no rigtool): never a gate score
#   bash truth/m1b.sh freeze <app>       frozen truth of powershell / temurin from the m1b-freeze runs (FROZEN.md)
#   bash truth/m1b.sh --config           print the configuration this environment gives ("default" or "custom VARS")
#   bash truth/m1b.sh --selftest         the scorer against a generated passing evidence dir (truth/m1b-fixture.py)
#                                        and one bad-run control per finding of review R4b (RIG.md section 12.5)
#
# Prints one line per criterion and subject: "<K> <step> <subject>: <value> (limit <limit>) PASS|FAIL", writes
# $M1B_OUT/m1b-score.json (purge.rig.m1b-score/2). Exit codes: 0 the gate passes (default configuration, collected
# by this invocation, every line PASS); 1 a line FAILs; 2 a usage error; 3 every line passes but the score is not
# the gate's (a custom configuration or --evaluate; the last line says "not a gate score"). A criterion whose input
# is missing is FAIL with "missing ..." as its value, never skipped.
#
# Stage 1, collect (from the runs; rigtool):
#   For each set: clean = Inbound rig-base (runs <M1B_CLEAN>-<id>, G2), dirty = Inbound dirty-base (<M1B_DIRTY>-<id>,
#   G3), cp = Purge-CleanPro (<M1B_CP>-<id>, G8):
#   0. ambient set from that set's null runs <prefix>null1..3 (rigtool ambient; at least 2), as m1a.sh does;
#   1. rigtool truth with truth/labels/<id>.json (+ _os-servicing.json) -> <run>/truth.json;
#   2. plans/purge.json = plan-purge.json with each item's action from its scan sidecar (as m1a.sh step 3);
#   3. rigtool score --classes over the set -> $EVID/score-<set>.json; fp.json and plan-purge.scan.json of the apps
#      K7 / K8 read are copied to $EVID/<set>-<id>-{fp,scan}.json.
#   Every app run and trap run: $EVID/runs/<run>.json (purge.rig.m1b-run/1): its run.json phases, the SHA-256 of
#   run.json and the build record m1b-build.json rig.ps1 wrote beside it (review R4b S2).
#   Traps (G4, G8): rigtool traps --plan <run>/plan-purge.scan.json --traps truth/m1b-traps.json --app 7zip --sid <run
#   sid> -> $EVID/traps-<run>.json, and the guest's m1b-traps-planted.json -> $EVID/traps-planted-<run>.json, for
#   M1B_TRAP_RUNS.
#   Budgets (G7): $M1B_BUDGETS (rig.ps1 -Mode m1b-budgets: budgets.json and the PURGE_TIMING logs) -> $EVID/budgets/.
#   Replay (G1): $M1B_REPLAY_DIFF (cargo xtask replay-diff, M1B-SCAN-INTEG) and $M1B_REPLAY_SCORE (rigtool score of
#   the replayed plans, written by the gate) -> $EVID/.
#   $EVID/manifest.json (purge.rig.m1b-evidence/2) records the prefixes, the configuration, the SHA-256 of the trap
#   file, of each run's label files and of the frozen truth of powershell / temurin.
# Stage 2, evaluate (python, reads $EVID and the committed trap / label / frozen files): see RIG.md section 12.5.
#
# Environment:
#   RIGTOOL          rigtool binary (default rigtool/target/release/rigtool)
#   M1B_OUT          reports (default truth); M1B_EVIDENCE the evidence dir (default $M1B_OUT/m1b-evidence)
#   The gate's inputs. Any of them set to a value other than its default makes the configuration custom, and a
#   custom score is never the gate's (review R4b S3):
#   M1B_RUNS         run directories (default runs)
#   M1B_APPS         G2/G3 apps (default: the 8 of the gate); M1B_CP_APPS G8 apps (default "7zip python vcredist")
#   M1B_CLEAN, M1B_DIRTY, M1B_CP   run prefixes without the dash (default m1b, m1bd, m1bcp)
#   M1B_SETS         sets to collect and evaluate (default "clean dirty cp")
#   M1B_TRAP_RUNS    trap runs (default "m1b-traps-7zip m1bd-traps-7zip m1bcp-traps-7zip")
#   M1B_LABELS       label overrides "id=label-id ..." (as m1a.sh; default none)
#   M1B_BUDGETS      budgets run dir (default runs/m1b-budgets)
#   M1B_REPLAY_DIFF  default truth/m1b-replay-diff.json; M1B_REPLAY_SCORE default truth/m1b-replay-score.json
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PY=${PYTHON:-python}
R=${RIGTOOL:-rigtool/target/release/rigtool}
DEF_APPS="7zip python python312-with-313 python313-with-312 node vcredist powershell temurin"
DEF_CP_APPS="7zip python vcredist"
DEF_SETS="clean dirty cp"
DEF_TRAPS="m1b-traps-7zip m1bd-traps-7zip m1bcp-traps-7zip"
RUNS=${M1B_RUNS:-runs}
OUT=${M1B_OUT:-truth}
EVID=${M1B_EVIDENCE:-$OUT/m1b-evidence}
APPS=${M1B_APPS:-$DEF_APPS}
CP_APPS=${M1B_CP_APPS:-$DEF_CP_APPS}
SETS=${M1B_SETS:-$DEF_SETS}
TRAP_RUNS=${M1B_TRAP_RUNS:-$DEF_TRAPS}
BUDGETS=${M1B_BUDGETS:-$RUNS/m1b-budgets}
REPLAY_DIFF=${M1B_REPLAY_DIFF:-truth/m1b-replay-diff.json}
REPLAY_SCORE=${M1B_REPLAY_SCORE:-truth/m1b-replay-score.json}

# The default of each gate input (see the header); an unset variable, or one equal to its default, is the default.
def_of() {
  case "$1" in
    M1B_RUNS) echo runs ;; M1B_APPS) echo "$DEF_APPS" ;; M1B_CP_APPS) echo "$DEF_CP_APPS" ;; M1B_SETS) echo "$DEF_SETS" ;;
    M1B_TRAP_RUNS) echo "$DEF_TRAPS" ;; M1B_LABELS) echo "" ;; M1B_CLEAN) echo m1b ;; M1B_DIRTY) echo m1bd ;; M1B_CP) echo m1bcp ;;
    M1B_BUDGETS) echo runs/m1b-budgets ;; M1B_REPLAY_DIFF) echo truth/m1b-replay-diff.json ;;
    M1B_REPLAY_SCORE) echo truth/m1b-replay-score.json ;;
  esac
}
GATE_VARS="M1B_RUNS M1B_APPS M1B_CP_APPS M1B_SETS M1B_TRAP_RUNS M1B_LABELS M1B_CLEAN M1B_DIRTY M1B_CP M1B_BUDGETS M1B_REPLAY_DIFF M1B_REPLAY_SCORE"
CONFIG_VARS=""
for v in $GATE_VARS; do
  if [ -n "${!v+x}" ] && [ "${!v}" != "$(def_of "$v")" ]; then CONFIG_VARS="$CONFIG_VARS $v"; fi
done
CONFIG_VARS=${CONFIG_VARS# }
CONFIG=default; [ -n "$CONFIG_VARS" ] && CONFIG=custom

prefix_of() { case "$1" in clean) echo "${M1B_CLEAN:-m1b}" ;; dirty) echo "${M1B_DIRTY:-m1bd}" ;; cp) echo "${M1B_CP:-m1bcp}" ;; esac; }
apps_of() { if [ "$1" = cp ]; then echo "$CP_APPS"; else echo "$APPS"; fi; }
label_of() { local m; for m in ${M1B_LABELS:-}; do if [ "${m%%=*}" = "$1" ]; then echo "${m#*=}"; return; fi; done; echo "$1"; }

# ------------------------------------------------------------------------------------------- python part
# pyeval <mode> args...: modes evaluate (stage 2), runsum and manifest (stage 1 helpers).
pyeval() {
  "$PY" -I - "$@" <<'EOF'
import datetime, hashlib, json, os, re, statistics, sys

MODE = sys.argv[1]
A = sys.argv[2:]

# ------------------------------------------------------------------------------------------- gate constants
# docs/M1B_DESIGN.json gate_criteria; changing one changes the gate (design change and review), never an input file.
TRAP_CASES = ['svc-owned', 'svc-owned-running', 'svc-shared', 'svc-dependent', 'svc-svchost', 'task-owned',
              'task-similar-name', 'task-interpreter', 'fw-owned', 'fw-same-display-name', 'fw-no-app', 'com-owned',
              'com-shared-class', 'com-isimpledom', 'shellex-approved', 'shareddlls-count', 'eventlog-shared-source',
              'tracing', 'privacy-twins', 'wer-twins', 'msi-remnants', 'msi-remnants-foreign', 'msi-shared-component',
              'burn-shared-package', 'pkgcache-foreign', 'instfolders']
BETWEEN_CASES = ['com-shared-class']                  # guest/m1b-traps.ps1: the cases with a between step
TRAP_A, TRAP_B = '7zip', 'node'
K5_MIN = {'python312-with-313': 29, 'python313-with-312': 29}
FROZEN_APPS = ['powershell', 'temurin']               # truth from the m1b-freeze runs (FROZEN.md, RIG.md 12.6)
REPLAY_RUNS = ['vscode', 'git', 'firefox', 'npp', '7zip']
REPLAY_SCHEMA = 'purge.replay-diff/3'
REPLAY_REASONS = ['new_scanner', 'msi_blocker_added', 'msi_root_added', 'policy_m1b', 'promotion_justified']
BUDGET_ENGINES, BUDGET_STEPS, BUDGET_ROUNDS = ['m1b', 'm2'], ['harvest', 'scan'], [1, 2, 3]
BANDS = ['Safe', 'Likely', 'Weak', 'Blocked']
STEP = {'clean': 'G2', 'dirty': 'G3', 'cp': 'G8'}


def sha256_file(p):
    try:
        with open(p, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def label_digest(labels_dir, lid):
    """SHA-256 over a label file, every file it includes (recursively) and _os-servicing.json; None if one is missing."""
    seen = {}

    def walk(name, depth):
        if name in seen or depth > 4:
            return
        p = os.path.join(labels_dir, name)
        seen[name] = sha256_file(p)
        if seen[name] is None:
            return
        try:
            with open(p, encoding='utf-8-sig') as f:
                inc = json.load(f).get('include') or []
        except (OSError, ValueError):
            inc = []
        for i in inc:
            walk(i, depth + 1)
    walk(lid + '.json', 0)
    walk('_os-servicing.json', 0)
    if any(h is None for h in seen.values()):
        return None
    return hashlib.sha256(''.join(f'{n} {h}\n' for n, h in sorted(seen.items())).encode()).hexdigest()


def read_json(p):
    try:
        with open(p, encoding='utf-8-sig') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------------------------------------- stage 1 helpers
if MODE == 'runsum':
    # runsum <run dir> <run name> <out>: the run's record for the evaluator
    d, run, out = A
    rj = read_json(os.path.join(d, 'run.json'))
    plan = read_json(os.path.join(d, 'plan-purge.json'))
    doc = {'schema': 'purge.rig.m1b-run/1', 'run': run,
           'run_json_sha256': sha256_file(os.path.join(d, 'run.json')),
           'run_json': None if rj is None else {
               'run': rj.get('run'), 'started': rj.get('started'), 'finished': rj.get('finished'),
               'phases': [{'name': (p or {}).get('name'), 'ok': (p or {}).get('ok'), 'error': (p or {}).get('error')}
                          for p in (rj.get('phases') or [])]},
           'build': read_json(os.path.join(d, 'm1b-build.json')),
           'plan_items': None if plan is None else len(plan.get('items') or [])}
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    sys.exit(0)

if MODE == 'manifest':
    # manifest <out> <runs dir> <sets> <prefix clean> <prefix dirty> <prefix cp> <label map "run=lid ..."> <truth dir>
    #          <config> <config vars> <rigtool>
    out, runs_dir, sets, pc, pd, pcp, lmap, truth_dir, config, config_vars, rigtool = A
    pre = {'clean': pc, 'dirty': pd, 'cp': pcp}
    labels = {}
    for m in lmap.split():
        run, lid = m.split('=', 1)
        labels[run] = {'label_id': lid, 'sha256': label_digest(os.path.join(truth_dir, 'labels'), lid)}
    doc = {'schema': 'purge.rig.m1b-evidence/2', 'note': 'collected by vm/truth/m1b.sh from ' + runs_dir,
           'prefixes': {s: pre[s] for s in sets.split()}, 'gate_config': config, 'config_vars': config_vars.split(),
           'traps_sha256': sha256_file(os.path.join(truth_dir, 'm1b-traps.json')), 'labels': labels,
           'frozen': {a: sha256_file(os.path.join(truth_dir, 'frozen', a, 'truth.json')) for a in FROZEN_APPS},
           'rigtool': {'path': rigtool, 'sha256': sha256_file(rigtool) or sha256_file(rigtool + '.exe')}}
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    sys.exit(0)

# ------------------------------------------------------------------------------------------- stage 2
assert MODE == 'evaluate', MODE
evid, out, apps, cp_apps, sets, trap_runs, config, config_vars, how, truth_dir = A
apps, cp_apps, sets, trap_runs = apps.split(), cp_apps.split(), sets.split(), trap_runs.split()
rows = []


def row(k, step, subject, value, limit, ok, note=None):
    rows.append({'id': k, 'step': step, 'subject': subject, 'value': value, 'limit': limit, 'pass': bool(ok), 'note': note})


def load(name):
    p = os.path.join(evid, name)
    return read_json(p) if os.path.isfile(p) else None


def miss(what):
    return f'missing {what}'


def set_apps(s):
    return cp_apps if s == 'cp' else apps


def is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


manifest = load('manifest.json') or {}
prefix = {s: (manifest.get('prefixes') or {}).get(s, {'clean': 'm1b', 'dirty': 'm1bd', 'cp': 'm1bcp'}[s]) for s in sets}
app_runs = [(s, id, f'{prefix[s]}-{id}') for s in sets for id in set_apps(s)]


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


def trap_step(run):
    return 'G8' if run.startswith('m1bcp') or '-m1bcp' in run else 'G4'


# RUN (review R4b S2): every scored run finished with every phase ok (a failed plant, launch or uninstall phase is
# not scored as if it had worked).
run_docs = {}
for s, id, run in app_runs + [('traps', None, r) for r in trap_runs]:
    st = trap_step(run) if s == 'traps' else STEP[s]
    rd = load(f'runs/{run}.json')
    run_docs[run] = rd
    rj = (rd or {}).get('run_json')
    if rj is None:
        row('RUN', st, run, miss(f'runs/{run}.json with its run.json'), 'finished, every phase ok', False)
        continue
    ph = rj.get('phases') or []
    bad = [str(p.get('name')) for p in ph if p.get('ok') is not True]
    ok = rj.get('run') == run and bool(rj.get('finished')) and bool(ph) and not bad
    note = ('failed: ' + ', '.join(bad)) if bad else (None if rj.get('run') == run else f"run.json names {rj.get('run')}")
    row('RUN', st, run, f"finished={bool(rj.get('finished'))} phases ok {len(ph) - len(bad)}/{len(ph)}",
        'finished, every phase ok', ok, note)

# BIND (review R4b S2, as m1b-exec.sh): one engine build (SHA-256 before and after the campaign equal, one commit,
# clean sources) for every scored run, each build record written for that very run.json; the budgets' M1b engine is
# the same file; the trap file and each run's labels are the committed ones (the app's own label file).
bind_problems, engines, commits = [], set(), set()
for run, rd in run_docs.items():
    if rd is None:
        bind_problems.append(f'{run}: no run record')
        continue
    b = rd.get('build')
    if not isinstance(b, dict):
        bind_problems.append(f'{run}: no m1b-build.json (rig.ps1 m1b modes write it)')
        continue
    if b.get('run') != run:
        bind_problems.append(f"{run}: build record names run {b.get('run')}")
    if not b.get('run_json_sha256') or b.get('run_json_sha256') != rd.get('run_json_sha256'):
        bind_problems.append(f"{run}: build record is for another run.json ({b.get('run_json_sha256')} vs {rd.get('run_json_sha256')})")
    if not b.get('engine_sha256') or b.get('engine_sha256') != b.get('engine_sha256_after'):
        bind_problems.append(f"{run}: engine sha256 {b.get('engine_sha256')} before, {b.get('engine_sha256_after')} after the campaign")
    if not b.get('commit') or b.get('source_dirty') is not False:
        bind_problems.append(f"{run}: commit {b.get('commit')}, source_dirty {b.get('source_dirty')}")
    if b.get('engine_sha256'):
        engines.add(b['engine_sha256'])
    if b.get('commit'):
        commits.add(b['commit'])
if len(engines) > 1:
    bind_problems.append(f'runs ran {len(engines)} different engines: ' + ', '.join(sorted(engines)))
if len(commits) > 1:
    bind_problems.append(f'runs name {len(commits)} different commits: ' + ', '.join(sorted(commits)))
bud = load('budgets/budgets.json')
if bud is not None:
    be = (bud.get('engine_sha256') or {}).get('m1b')
    if not be or (engines and be not in engines):
        bind_problems.append(f'budgets: M1b engine sha256 {be}, scan runs {sorted(engines)}')
traps_now = sha256_file(os.path.join(truth_dir, 'm1b-traps.json'))
if not traps_now or manifest.get('traps_sha256') != traps_now:
    bind_problems.append(f"trap file sha256 {manifest.get('traps_sha256')} at collect, {traps_now} committed")
for s, id, run in app_runs:
    lab = (manifest.get('labels') or {}).get(run) or {}
    now = label_digest(os.path.join(truth_dir, 'labels'), id)
    if lab.get('label_id') != id:
        bind_problems.append(f"{run}: labels {lab.get('label_id')}, not the app's own ({id})")
    elif not now or lab.get('sha256') != now:
        bind_problems.append(f"{run}: label files sha256 {lab.get('sha256')} at collect, {now} committed")
bind_ok = bool(run_docs) and not bind_problems and len(engines) == 1 and len(commits) == 1
row('BIND', 'G2-G4, G7, G8', 'one build, committed traps and labels',
    f'engines={len(engines)} commits={len(commits)} problems={len(bind_problems)}', 'one engine, one commit, clean, 0 problems',
    bind_ok, '; '.join(bind_problems[:6]) or None)

# FROZEN: powershell and temurin are scored only with labels their freeze checked (G2, G3; FROZEN.md M1b section).
for app in [a for a in FROZEN_APPS if a in apps and ({'clean', 'dirty'} & set(sets))]:
    rec = (manifest.get('frozen') or {}).get(app)
    now = sha256_file(os.path.join(truth_dir, 'frozen', app, 'truth.json'))
    val = 'frozen' if rec and rec == now else (f'not frozen (truth/frozen/{app}/truth.json missing)' if not now else 'frozen truth changed since collect')
    row('FROZEN', 'G2, G3', app, val, 'truth/frozen/<app>/truth.json from m1b-freeze', bool(rec) and rec == now)

# K1-K6 per set and app
for s in sets:
    st = STEP[s]
    for id in set_apps(s):
        t = purge_score(s, id)
        subj = f'{s}/{id}'
        ks = (['K1'] if s != 'dirty' else ['K2']) + ['K3', 'K4', 'K5'] + (['K6'] if s != 'cp' else [])
        if t is None:
            for k in ks:
                row(k, st, subj, miss(f'score of {prefix[s]}-{id} (score-{s}.json)'), '-', False)
            continue
        # An empty plan proves nothing (review R4b S2): with truth leftovers and no plan item, K1-K6 all fail.
        tn, on = t.get('truth_n'), t.get('offered_n')
        empty = None
        if not is_int(tn) or not is_int(on):
            empty = f'score has no truth_n / offered_n ({tn}, {on})'
        elif tn > 0 and on == 0:
            empty = f'empty plan: 0 items offered, {tn} leftover/user-data truth item(s)'
        if empty:
            for k in ks:
                row(k, st, subj, empty, 'a plan with items', False)
            continue
        if s == 'dirty':
            row('K2', st, subj, t.get('danger_blocking'), 0, t.get('danger_blocking') == 0)
        else:
            row('K1', st, subj, t.get('danger_listed'), 0, t.get('danger_listed') == 0)
        dp, up = t.get('danger_preselected'), t.get('userdata_preselected')
        row('K3', st, subj, f'danger_preselected={dp} userdata_preselected={up}', '0 and 0', dp == 0 and up == 0)
        ps = t.get('precision_safe')
        if s == 'clean' and id == '7zip':
            # R4b M6: the 7-Zip MSI app must show a Safe item on rig-base (the replay offers its key Safe, K7).
            row('K4', st, subj, ps, 1.0, ps == 1.0, 'no Safe item: 7-Zip needs one on rig-base' if ps is None else None)
        else:
            row('K4', st, subj, ps, 1.0, ps is None or ps == 1.0, 'no Safe item: null, not counted as a pass' if ps is None else None)
        pn, pc, pw = t.get('protected_n', 0) or 0, t.get('protected_correct'), t.get('protected_wrong') or []
        need = K5_MIN.get(id, 0)
        if pn == 0 and need == 0:
            row('K5', st, subj, 'n/a (no kept_owner/protected truth item)', '100 %', True)
        else:
            ok = pn >= need and pc == 1.0 and not pw
            row('K5', st, subj, f'protected_correct={pc} n={pn} wrong={len(pw)}', f'100 %{f", n >= {need}" if need else ""}', ok)
        if s != 'cp':
            # K6 (ruling 2026-11-17, docs/DECISIONS.md M1b, RIG.md 12.5): a mismatch is an item whose band would offer
            # or preselect it wrongly: preselected below Safe, a band the policy does not have, user data preselected,
            # a protected truth item listed below Protected. A true leftover listed Weak or Blocked is a recall miss,
            # as the M1a gate counted it (recall_visible_nd covers Safe and Likely only): reported, not a mismatch.
            bad, low = [], []
            for it in t.get('items', []):
                band = it.get('band')
                if band not in BANDS:
                    bad.append(f"unknown band {band}: {it.get('target')}")
                elif it.get('preselected') and band != 'Safe':
                    bad.append(f"preselected at {band}: {it.get('target')}")
                elif it.get('outcome') == 'hit' and not it.get('userdata') and band in ('Weak', 'Blocked'):
                    low.append(it.get('target'))
            bad += [f'user data preselected x{up}'] if up else []
            bad += [f"protected below Protected: {w.get('target', w) if isinstance(w, dict) else w}" for w in pw]
            note = '; '.join(bad[:5])
            if low:
                note = (note + '; ' if note else '') + f'recall misses (leftover at Weak/Blocked, not a mismatch): {len(low)}'
            row('K6', st, subj, len(bad), 0, not bad, note or None)

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


# K9: traps. rigtool's verdicts count only when every case was planted (review R4b S1): the guest's planted record
# holds all 26 cases (and the between step) ok, with the gate's TrapA / TrapB, and every expectation's target is among
# the objects its case planted or found already there. A verdict on an object that was never there proves nothing.
def norm_reg(k):
    k = str(k).replace('/', '\\').rstrip('\\')
    k = re.sub(r'^HKU\\S-1-5-21-[0-9-]+_Classes(?=\\|$)', lambda m: 'HKCU\\Software\\Classes', k, flags=re.I)
    k = re.sub(r'^HKU\\S-1-5-21-[0-9-]+(?=\\|$)', lambda m: 'HKCU', k, flags=re.I)
    k = re.sub(r'^HKCR(?=\\|$)', lambda m: 'HKLM\\SOFTWARE\\Classes', k, flags=re.I)
    return k.lower()


PLANT_KINDS = ('key', 'value', 'file', 'dir', 'service', 'task', 'firewall')


def planted_objects(rec):
    out = []
    for p in (rec or {}).get('planted') or []:
        if not isinstance(p, dict) or p.get('kind') not in PLANT_KINDS:
            continue
        t = str(p.get('target') or '')
        if t.startswith('K:'):
            out.append(('key', norm_reg(t[2:]), None))
        elif t.startswith('V:'):
            k, _, n = t[2:].partition('|')
            out.append(('value', norm_reg(k), n.lower()))
        elif t.startswith('P:'):
            out.append(('path', t[2:].replace('/', '\\').rstrip('\\').lower(), None))
        elif t.startswith('SVC:'):
            out.append(('svc', t[4:].lower(), None))
        elif t.startswith('TASK:'):
            out.append(('task', t[5:].lower(), None))
        elif t.startswith('FW:'):
            out.append(('fw', t[3:].lower(), None))
    return out


def under(a, b):
    return a == b or a.startswith(b + '\\')


def planted(target, objs):
    ty = target.get('type')
    if ty == 'Service':
        return any(o[0] == 'svc' and o[1] == str(target.get('name', '')).lower() for o in objs)
    if ty == 'Task':
        return any(o[0] == 'task' and o[1] == str(target.get('path', '')).lower() for o in objs)
    if ty == 'FirewallRule':
        return any(o[0] == 'fw' and o[1] == str(target.get('id', '')).lower() for o in objs)
    if ty == 'RegKey':
        k = norm_reg(target.get('path', ''))
        return any(o[0] in ('key', 'value') and under(o[1], k) for o in objs)
    if ty == 'RegValue':
        k, n = norm_reg(target.get('path', '')), str(target.get('name', '')).lower()
        return any(o[0] == 'value' and o[1] == k and o[2] == n for o in objs)
    if ty == 'Path':
        p = str(target.get('path', '')).replace('/', '\\').rstrip('\\').lower()
        return any(o[0] == 'path' and under(o[1], p) for o in objs)
    return False


trap_def = read_json(os.path.join(truth_dir, 'm1b-traps.json')) or {}
expect_by_case = {c.get('id'): c.get('expect') or [] for c in trap_def.get('cases') or []}
for run in trap_runs:
    st = trap_step(run)
    lim = 'escapes 0, missed_owned 0, 26 cases, every case planted'
    tr, pl = load(f'traps-{run}.json'), load(f'traps-planted-{run}.json')
    if tr is None or pl is None:
        row('K9', st, run, miss(f'traps-{run}.json' if tr is None else f'traps-planted-{run}.json (the guest m1b-traps-planted.json)'), lim, False)
        continue
    probs = []
    if sorted(expect_by_case) != sorted(TRAP_CASES):
        probs.append('trap file does not hold the 26 gate cases')
    if pl.get('schema') != 'purge.rig.m1b-traps.planted/1' or pl.get('trap_a') != TRAP_A or pl.get('trap_b') != TRAP_B:
        probs.append(f"planted record {pl.get('schema')} TrapA {pl.get('trap_a')} TrapB {pl.get('trap_b')}")
    cases = pl.get('cases') or {}
    pre_existing, unplanted, failed = 0, 0, 0
    for cid in TRAP_CASES:
        rec = cases.get(cid)
        steps = [rec] + ([cases.get(cid + '#between')] if cid in BETWEEN_CASES else [])
        if any(not isinstance(r, dict) or r.get('ok') is not True or r.get('error') for r in steps):
            failed += 1
            probs.append(f'{cid}: not planted (case record missing or failed)')
            continue
        pre_existing += sum(1 for p in rec.get('planted') or [] if re.search(r'existed|already', str((p or {}).get('note') or ''), re.I))
        objs = [o for r in steps for o in planted_objects(r)]
        for e in expect_by_case.get(cid, []):
            if not planted(e.get('target') or {}, objs):
                unplanted += 1
                probs.append(f"{cid}: expectation target {json.dumps(e.get('target'))} was not planted")
    unknown = sorted(k for k in cases if k.split('#')[0] not in TRAP_CASES)
    if unknown:
        probs.append('unknown cases in the planted record: ' + ', '.join(unknown))
    sm = tr.get('summary', {})
    ok = sm.get('escapes') == 0 and sm.get('missed_owned') == 0 and sm.get('cases') == 26 and not probs
    row('K9', st, run, f"cases={sm.get('cases')} escapes={sm.get('escapes')} missed_owned={sm.get('missed_owned')} "
        f'failed_cases={failed} unplanted_targets={unplanted} pre_existing_objects={pre_existing}', lim, ok, '; '.join(probs[:5]) or None)

# K14: budgets (review R4b S6: every run exit 0, 3 rounds per engine and step, round 1 shown cold)
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


if bud is None:
    for what in ('budget runs', 'reference walks per scan', 'added scan time', 'added harvest time', 'ownership.components', 'ownership.tables'):
        row('K14', 'G7', what, miss('budgets/budgets.json (rig.ps1 -Mode m1b-budgets)'), '-', False)
else:
    probs, seen = [], {}
    for r in bud.get('runs', []):
        key = (r.get('engine'), r.get('step'), r.get('round'))
        if key in seen:
            probs.append(f'{key} twice')
        seen[key] = r
    want = {(e, s_, n) for e in BUDGET_ENGINES for s_ in BUDGET_STEPS for n in BUDGET_ROUNDS}
    probs += [f'{k} missing' for k in sorted(want - set(seen), key=str)] + [f'{k} not a gate run' for k in sorted(set(seen) - want, key=str)]
    logs = {}
    for key in sorted(want & set(seen), key=str):
        r = seen[key]
        if r.get('kind') != ('cold' if key[2] == 1 else 'warm'):
            probs.append(f"{key}: kind {r.get('kind')}")
            continue
        if not is_int(r.get('exit')) or r.get('exit') != 0:
            probs.append(f"{key}: exit {r.get('exit')}")
            continue
        lg = parse_log(os.path.join(evid, 'budgets', str(r.get('log'))))
        if not lg or lg['total'] is None:
            probs.append(f'{key}: no timing in its log')
            continue
        logs[(key[0], key[1], r.get('kind'), key[2])] = lg
    cold = bud.get('cold_cache_state') or ('moved' if bud.get('cold_cache') else None)
    if cold not in ('moved', 'absent'):
        probs.append(f'cold round not shown cold (cold_cache_state {cold})')
    if not bud.get('program'):
        probs.append('no program recorded')
    row('K14', 'G7', 'budget runs', f'{len(seen)} run(s), {len(probs)} problem(s)', '12 runs (2 engines x 2 steps x 3 rounds), all exit 0, round 1 cold',
        not probs, '; '.join(probs[:5]) or None)

    def times(eng, step, kind):
        return [x['total'] for (e, s_, k, _), x in logs.items() if e == eng and s_ == step and k == kind]

    walks = [len(x['phases'].get('refscan', [])) for (e, s_, k, _), x in logs.items() if e == 'm1b' and s_ == 'scan']
    row('K14', 'G7', 'reference walks per scan', walks if walks else miss('m1b scan logs'), '1 each', bool(walks) and all(w == 1 for w in walks))
    for step, label in (('scan', 'added scan time'), ('harvest', 'added harvest time')):
        for kind, lim in (('warm', 2.5), ('cold', 6.5)):
            a, b = times('m1b', step, kind), times('m2', step, kind)
            if not a or not b:
                row('K14', 'G7', f'{label} ({kind})', miss(f'{kind} {step} logs of both engines'), f'<= {lim} s', False)
                continue
            d = statistics.median(a) - statistics.median(b)
            row('K14', 'G7', f'{label} ({kind})', round(d, 3), f'<= {lim} s', d <= lim, f'm1b {statistics.median(a):.3f} s vs m2 {statistics.median(b):.3f} s (median)')
    comp = [v for (e, s_, k, _), x in logs.items() if e == 'm1b' for v in x['phases'].get('ownership.components', [])]
    row('K14', 'G7', 'ownership.components', max(comp) if comp else miss('ownership.components phase lines'), '<= 1.5 s', bool(comp) and max(comp) <= 1.5)
    for kind, lim in (('cold', 4.0), ('warm', 0.3)):
        tb = [v for (e, s_, k, _), x in logs.items() if e == 'm1b' and k == kind for v in x['phases'].get('ownership.tables', [])]
        val = (max(tb) if kind == 'cold' else statistics.median(tb)) if tb else None
        row('K14', 'G7', f'ownership.tables ({kind})', val if tb else miss(f'{kind} ownership.tables lines'), f'<= {lim} s', bool(tb) and val <= lim)


# K16: replay diff (review R4b B1), judged by its rows: every row carries one of the five reasons (DECISIONS
# 2026-11-17: promotion_justified added to the design's four), none is unexplained, the five frozen runs are in it,
# and every promotion (recomputed here: the band rose toward Safe, or the item became preselected) carries
# promotion_justified and is named with a cause under justified_promotions (xtask JUSTIFIED_PROMOTIONS); a row that
# says promotion_justified must be a promotion.
def band_rank(b):
    return {'Blocked': 0, 'Weak': 1, 'Likely': 2, 'Safe': 3}.get(b, 4)


def fold(v):
    if isinstance(v, str):
        return v.lower()
    if isinstance(v, list):
        return [fold(x) for x in v]
    if isinstance(v, dict):
        return {k: fold(x) for k, x in v.items()}
    return v


def tkey(app, target):
    return (app, json.dumps(fold(target), sort_keys=True))


rd = load('replay-diff.json')
if rd is None:
    row('K16', 'G1', 'replay diff', miss('replay-diff.json'), 'unexplained 0', False)
else:
    probs = []
    if rd.get('schema') != REPLAY_SCHEMA:
        probs.append(f"schema {rd.get('schema')}, not {REPLAY_SCHEMA}")
    if sorted(rd.get('reasons') or []) != sorted(REPLAY_REASONS):
        probs.append(f"declared reasons {rd.get('reasons')}")
    if rd.get('unexplained') != 0:
        probs.append(f"unexplained={rd.get('unexplained')}")
    missing_runs = [r for r in REPLAY_RUNS if r not in (rd.get('apps') or {})]
    if missing_runs:
        probs.append('runs not in the diff: ' + ', '.join(missing_runs))
    just = {tkey(j.get('app'), j.get('target')) for j in rd.get('justified_promotions') or []
            if isinstance(j, dict) and str(j.get('cause') or '').strip()}
    rrows, promos = rd.get('rows') or [], 0
    for r in rrows:
        reason, b, a = r.get('reason'), r.get('before'), r.get('after')
        if reason not in REPLAY_REASONS:
            probs.append(f"{r.get('app')} {json.dumps(r.get('target'))}: reason {reason}")
            continue
        promoted = isinstance(b, dict) and isinstance(a, dict) and (
            band_rank(a.get('band')) > band_rank(b.get('band')) or (bool(a.get('preselected')) and not b.get('preselected')))
        promos += promoted
        if promoted and (reason != 'promotion_justified' or tkey(r.get('app'), r.get('target')) not in just):
            probs.append(f"{r.get('app')} {json.dumps(r.get('target'))}: promotion {b.get('band')} -> {a.get('band')} not justified ({reason})")
        elif reason == 'promotion_justified' and not promoted:
            probs.append(f"{r.get('app')} {json.dumps(r.get('target'))}: promotion_justified on a row that is no promotion")
    if rd.get('promotions') != promos:
        probs.append(f"promotions={rd.get('promotions')} declared, {promos} in the rows")
    row('K16', 'G1', 'replay diff', f"rows={len(rrows)} unexplained={rd.get('unexplained')} promotions={promos} problems={len(probs)}",
        'every row an allowed reason, unexplained 0, every promotion justified', not probs, '; '.join(probs[:5]) or None)

fails = [r for r in rows if not r['pass']]
for r in rows:
    print(f"{r['id']} {r['step']} {r['subject']}: {r['value']} (limit {r['limit']}) {'PASS' if r['pass'] else 'FAIL'}"
          + (f"  [{r['note']}]" if r['note'] else ''))
passed = not fails and bool(rows)
why_not = []
if config != 'default':
    why_not.append('custom configuration: ' + (config_vars or 'see gate_config'))
if how != 'gate':
    why_not.append('evaluate-only (--evaluate): the evidence was not collected by this invocation')
gate = passed and not why_not
doc = {'schema': 'purge.rig.m1b-score/2', 'time': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
       'evidence': evid, 'gate_config': config, 'config_vars': config_vars.split(), 'mode': how,
       'apps': apps, 'cp_apps': cp_apps, 'sets': sets, 'trap_runs': trap_runs,
       'inputs': {'traps_sha256': traps_now, 'labels': manifest.get('labels'), 'frozen': manifest.get('frozen'),
                  'rigtool': manifest.get('rigtool'), 'engines': sorted(engines), 'commits': sorted(commits)},
       'criteria': rows, 'failed': len(fails), 'pass': passed, 'gate': gate, 'not_gate_because': why_not}
os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
with open(out, 'w', encoding='utf-8') as f:
    json.dump(doc, f, indent=2, ensure_ascii=False)
print(f"m1b: {len(rows) - len(fails)}/{len(rows)} PASS, {len(fails)} FAIL -> {out}")
if gate:
    print('m1b: gate PASS')
elif passed:
    print('m1b: not a gate score (' + '; '.join(why_not) + ')')
sys.exit(0 if gate else (3 if passed else 1))
EOF
}

# evaluate <evidence dir> <score json out> [gate|evaluate]: stage 2; "gate" only from the no-argument run.
evaluate() {
  pyeval evaluate "$1" "$2" "$APPS" "$CP_APPS" "$SETS" "$TRAP_RUNS" "$CONFIG" "$CONFIG_VARS" "${3:-evaluate}" "$HERE"
}

# ------------------------------------------------------------------------------------------- stage 1
collect() {
  mkdir -p "$EVID" "$EVID/budgets" "$EVID/runs"
  rm -f "$EVID"/score-*.json "$EVID"/traps-*.json "$EVID"/*-fp.json "$EVID"/*-scan.json "$EVID"/replay-*.json "$EVID"/budgets/* \
        "$EVID"/runs/*.json "$EVID"/manifest.json
  local labels_extra=(--labels truth/labels/_os-servicing.json)
  local s id run d lid p n lmap=""
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
      lid=$(label_of "$id"); lmap="$lmap $run=$lid"
      if [ -d "$d" ]; then pyeval runsum "$d" "$run" "$EVID/runs/$run.json"; fi
      if [ ! -f "$d/run.json" ] || [ ! -f "$amb" ]; then echo "m1b: $run: no run or no ambient set" >&2; continue; fi
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
    if [ -d "$d" ]; then pyeval runsum "$d" "$run" "$EVID/runs/$run.json"; fi
    if [ -f "$d/m1b-traps-planted.json" ]; then cp "$d/m1b-traps-planted.json" "$EVID/traps-planted-$run.json"; fi
    if [ ! -f "$d/plan-purge.scan.json" ] || [ ! -f "$d/run.json" ]; then echo "m1b: trap run $run: no plan-purge.scan.json" >&2; continue; fi
    local sid; sid=$("$PY" -I -c "import json,sys; print(json.load(open(sys.argv[1], encoding='utf-8-sig')).get('sid') or '')" "$d/run.json")
    "$R" traps --plan "$d/plan-purge.scan.json" --traps truth/m1b-traps.json --app 7zip ${sid:+--sid "$sid"} --out "$EVID/traps-$run.json" >&2
    case $? in 0|1) ;; *) echo "m1b: rigtool traps for $run: input error" >&2; rm -f "$EVID/traps-$run.json" ;; esac
  done
  if [ -f "$BUDGETS/budgets.json" ]; then cp "$BUDGETS/budgets.json" "$BUDGETS"/*.log "$EVID/budgets/" 2>/dev/null; fi
  [ -f "$REPLAY_DIFF" ] && cp "$REPLAY_DIFF" "$EVID/replay-diff.json"
  [ -f "$REPLAY_SCORE" ] && cp "$REPLAY_SCORE" "$EVID/replay-score.json"
  pyeval manifest "$EVID/manifest.json" "$RUNS" "$SETS" "$(prefix_of clean)" "$(prefix_of dirty)" "$(prefix_of cp)" "${lmap# }" \
    "$HERE" "$CONFIG" "$CONFIG_VARS" "$R"
}

# ------------------------------------------------------------------------------------------- selftest
# The scorer against truth/m1b-fixture.py's evidence: a passing gate-default dir (exit 0), then each bad-run control
# of review R4b (each must exit 1 with its criterion FAIL; the positive controls must still exit 0), the configuration
# rule (S3), the trap file checks and the guest Pester test.
selftest() {
  local fails=0 tmp rc; tmp=$(mktemp -d)
  local fx="$HERE/m1b-fixture.py"
  ok_() { echo "ok   $1"; }
  no_() { echo "FAIL $1${2:+ ($2)}"; fails=$((fails + 1)); }
  # The fixture holds a copy of the committed trap and label files (truth/) and a frozen truth for powershell and
  # temurin; its manifest is written as collect writes it.
  mkfix() {
    "$PY" -I "$fx" write "$1" "$HERE" >/dev/null || return 1
    pyeval manifest "$1/manifest.json" runs "$DEF_SETS" m1b m1bd m1bcp "$("$PY" -I "$fx" labelmap)" "$1/truth" default "" rigtool
  }
  # eval_gate <dir> <out>: evaluate as the gate does, against the dir's own truth/ copy
  eval_gate() { (HERE="$1/truth"; evaluate "$1" "$2" gate); }

  # m1b_sh_fails_on_missing_input: an empty evidence dir -> exit 1, every line FAIL, none skipped
  eval_gate "$tmp/empty-does-not-exist" "$tmp/empty.json" >"$tmp/empty.txt" 2>&1; rc=$?
  if [ $rc -eq 1 ] && "$PY" -I -c "
import json, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
rows = d['criteria']
need = {'RUN', 'BIND', 'FROZEN', 'K1', 'K2', 'K3', 'K4', 'K5', 'K6', 'K7', 'K8', 'K9', 'K14', 'K16'}
assert rows and all(not r['pass'] for r in rows), [r for r in rows if r['pass']]
assert need <= {r['id'] for r in rows}, need - {r['id'] for r in rows}
assert not d['pass'] and not d['gate']
" "$tmp/empty.json"; then ok_ m1b_sh_fails_on_missing_input; else no_ m1b_sh_fails_on_missing_input "exit $rc"; fi

  # m1b_sh_passes_on_recorded_sample (the design's name; since R4b the evidence is generated, not the hand-made
  # _m1b_sample): the gate-default evidence, evaluated as the gate -> exit 0, gate true
  if mkfix "$tmp/fx" && eval_gate "$tmp/fx" "$tmp/fx.json" >"$tmp/fx.txt" 2>&1; then
    ok_ m1b_sh_passes_on_recorded_sample
  else no_ m1b_sh_passes_on_recorded_sample; grep -E 'FAIL|Error|error' "$tmp/fx.txt" | head -10; fi

  # Bad-run controls (review R4b): "<mutation> <criterion that must FAIL>"; positive controls "<mutation> PASS".
  local ctl
  for ctl in \
      "replay_committed_diff PASS" "replay_promotion_unexplained K16" "replay_justified_not_listed K16" \
      "replay_justified_listed PASS" "replay_justified_no_promotion K16" "replay_sixth_reason K16" \
      "replay_run_missing K16" "replay_old_schema K16" \
      "k6_leftover_weak PASS" "k6_preselected_likely K6" "k6_unknown_band K6" \
      "plant_missing_target K9" "plant_note_only K9" "plant_case_failed K9" "plant_between_failed K9" \
      "plant_record_missing K9" "plant_wrong_trap_b K9" "plant_preexisting PASS" \
      "empty_plan K1" "empty_plan_dirty K2" "score_without_counts K3" \
      "run_phase_failed RUN" "run_unfinished RUN" "run_json_missing RUN" \
      "unbound_engine BIND" "engine_rebuilt BIND" "build_missing BIND" "build_stale BIND" "source_dirty BIND" \
      "two_commits BIND" "budget_engine_other BIND" "traps_changed BIND" "labels_override BIND" "labels_changed BIND" \
      "frozen_missing FROZEN" \
      "budget_exit K14" "budget_two_rounds K14" "budget_kept_cache K14" "budget_kind K14" \
      "no_safe_7zip K4"; do
    set -- $ctl
    rm -rf "$tmp/m"; cp -r "$tmp/fx" "$tmp/m"
    if ! "$PY" -I "$fx" mutate "$tmp/m" "$1" >"$tmp/m.txt" 2>&1; then no_ "control $1" "mutation failed: $(head -c 300 "$tmp/m.txt")"; continue; fi
    eval_gate "$tmp/m" "$tmp/m.json" >"$tmp/m.out" 2>&1; rc=$?
    if [ "$2" = PASS ]; then
      if [ $rc -eq 0 ]; then ok_ "control $1 (still passes)"; else no_ "control $1" "exit $rc: $(grep FAIL "$tmp/m.out" | head -2)"; fi
    elif [ $rc -eq 1 ] && "$PY" -I -c "
import json, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
assert any(r['id'] == sys.argv[2] and not r['pass'] for r in d['criteria']), sys.argv[2]
assert not d['gate'] and not d['pass']
" "$tmp/m.json" "$2" 2>/dev/null; then ok_ "control $1 (fails $2)"
    else no_ "control $1" "exit $rc, $2 not failed: $(grep FAIL "$tmp/m.out" | head -2)"; fi
  done

  # S3: the same passing evidence is not a gate score evaluate-only, or with a custom app list.
  (HERE="$tmp/fx/truth"; evaluate "$tmp/fx" "$tmp/e.json" evaluate) >/dev/null 2>&1; rc=$?
  if [ $rc -eq 3 ] && "$PY" -I -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['pass'] and not d['gate']" "$tmp/e.json"; then
    ok_ config_evaluate_only_is_not_a_gate_score; else no_ config_evaluate_only_is_not_a_gate_score "exit $rc"; fi
  (HERE="$tmp/fx/truth"; APPS="7zip python"; CONFIG=custom; CONFIG_VARS=M1B_APPS; evaluate "$tmp/fx" "$tmp/c.json" gate) >/dev/null 2>&1; rc=$?
  if [ $rc -eq 3 ] && "$PY" -I -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['pass'] and not d['gate']" "$tmp/c.json"; then
    ok_ config_custom_app_list_is_not_a_gate_score; else no_ config_custom_app_list_is_not_a_gate_score "exit $rc"; fi
  # every gate input: custom when changed, default when unset or equal to its default
  local v want got
  for v in $GATE_VARS; do
    got=$(env "$v=x-custom" bash "$HERE/m1b.sh" --config 2>/dev/null)
    if [ "$got" != "custom $v" ]; then no_ "config_$v" "changed: got '$got'"; continue; fi
    want=$(def_of "$v"); got=$(env "$v=$want" bash "$HERE/m1b.sh" --config 2>/dev/null)
    if [ "$got" = default ]; then ok_ "config_$v (custom when changed, default when equal)"; else no_ "config_$v" "equal: got '$got'"; fi
  done

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
  then ok_ traps_json_every_case_has_expectation; else no_ traps_json_every_case_has_expectation; fi
  # traps_json_matches_guest_functions (the M1B-RIG-GUEST Pester test, Windows only)
  if command -v powershell.exe >/dev/null 2>&1; then
    local pt; pt=$(cygpath -w "$HERE/../guest/tests/m1b-traps.tests.ps1" 2>/dev/null || echo "$HERE/../guest/tests/m1b-traps.tests.ps1")
    if powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "\$r = Invoke-Pester -Script '$pt' -PassThru -Quiet; if (\$r.FailedCount -or -not \$r.PassedCount) { exit 1 }" >/dev/null 2>&1; then
      ok_ traps_json_matches_guest_functions; else no_ traps_json_matches_guest_functions; fi
  else no_ traps_json_matches_guest_functions "no powershell.exe: run it on Windows"; fi
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
  --config) if [ "$CONFIG" = default ]; then echo default; else echo "custom $CONFIG_VARS"; fi; exit 0 ;;
  freeze) [ -n "${2:-}" ] || { echo "m1b: freeze needs an app id" >&2; exit 2; }; freeze "$2"; exit $? ;;
  --evaluate) [ -n "${2:-}" ] || { echo "m1b: --evaluate needs an evidence dir" >&2; exit 2; }
              evaluate "$2" "$OUT/m1b-score.json" evaluate; exit $? ;;
  "") collect; evaluate "$EVID" "$OUT/m1b-score.json" gate; exit $? ;;
  *) echo "m1b: unknown argument $1 (--selftest, --evaluate DIR, --config, freeze APP, or nothing)" >&2; exit 2 ;;
esac
