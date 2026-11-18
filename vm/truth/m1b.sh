#!/usr/bin/env bash
# M1b gate, scan side (docs/M1B_DESIGN.json gate_criteria K1-K9, K14, K16 for steps G1-G4, G7, G8; vm/RIG.md
# section 12). Run from vm/ after the campaigns of rig.ps1 -Mode m1b-apps / m1b-traps / m1b-budgets were pulled:
#
#   bash truth/m1b.sh                    collect (truth, plans, scores, traps) into the evidence dir, then evaluate:
#                                        the gate score (exit 0 only here, and only in the default configuration)
#   bash truth/m1b.sh --evaluate DIR     evaluate an evidence dir only (no rigtool): never a gate score
#   bash truth/m1b.sh freeze <app>       frozen truth of powershell / temurin from the m1b-freeze runs (FROZEN.md)
#   bash truth/m1b.sh replay             G1 on the host, before collect: the replay diff and truth/m1b-replay-score.json
#                                        (the five frozen runs replayed with this checkout, scored; see replay below)
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
#   the replayed plans, written by `m1b.sh replay`) -> $EVID/.
#   Each rig-base run's truth -> $EVID/truth-<set>-<id>.json (SANITY against truth/frozen/<id>, review R4c S4); each
#   null run used for an ambient set -> $EVID/runs/<null run>.json (RUN).
#   $EVID/manifest.json (purge.rig.m1b-evidence/2) records the prefixes, the configuration, the SHA-256 of the trap
#   file, of each run's label files and of the frozen truth of powershell / temurin, and the null runs per set.
# Stage 2, evaluate (python, reads $EVID and the committed trap / label / frozen files): see RIG.md section 12.5.
#
# Environment:
#   RIGTOOL          rigtool binary (default rigtool/target/release/rigtool)
#   M1B_OUT          reports (default truth); M1B_EVIDENCE the evidence dir (default $M1B_OUT/m1b-evidence)
#   The gate's inputs. Any of them set to a value other than its default makes the configuration custom, and a
#   custom score is never the gate's (review R4b S3):
#   M1B_RUNS         run directories (default runs)
#   M1B_APPS         G2 apps (default: the 8 of the gate); M1B_DIRTY_APPS G3 apps (default: the 8 without node, ruling
#                    2026-11-18: dirty-base already holds Node.js 20.18.0); M1B_CP_APPS G8 apps (default "7zip python vcredist")
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
# G3 (ruling 2026-11-18): dirty-base already has Node.js 20.18.0 (guest/setup-dirty.ps1), so a node run there is a
# no-op install; node is scored on rig-base (G2) only. rig.ps1 Get-M1bGateApps -Base dirty-base gives the same list.
DEF_DIRTY_APPS="7zip python python312-with-313 python313-with-312 vcredist powershell temurin"
DEF_CP_APPS="7zip python vcredist"
DEF_SETS="clean dirty cp"
DEF_TRAPS="m1b-traps-7zip m1bd-traps-7zip m1bcp-traps-7zip"
RUNS=${M1B_RUNS:-runs}
OUT=${M1B_OUT:-truth}
EVID=${M1B_EVIDENCE:-$OUT/m1b-evidence}
APPS=${M1B_APPS:-$DEF_APPS}
DIRTY_APPS=${M1B_DIRTY_APPS:-$DEF_DIRTY_APPS}
CP_APPS=${M1B_CP_APPS:-$DEF_CP_APPS}
SETS=${M1B_SETS:-$DEF_SETS}
TRAP_RUNS=${M1B_TRAP_RUNS:-$DEF_TRAPS}
BUDGETS=${M1B_BUDGETS:-$RUNS/m1b-budgets}
REPLAY_DIFF=${M1B_REPLAY_DIFF:-truth/m1b-replay-diff.json}
REPLAY_SCORE=${M1B_REPLAY_SCORE:-truth/m1b-replay-score.json}
REPLAY_IDS="vscode git firefox npp 7zip"   # G1's frozen runs (xtask replay_diff::DIFF_RUNS, REPLAY_RUNS below)
# Label files every M1b truth adds to the app's own (collect and freeze): the M1a servicing rules and the M1b noise
# list of Windows-owned churn areas (labels/_m1b-noise.json, RIG.md section 12.6). Both only label ambient.
M1B_TRUTH_LABELS=(--labels truth/labels/_os-servicing.json --labels truth/labels/_m1b-noise.json)

# The default of each gate input (see the header); an unset variable, or one equal to its default, is the default.
def_of() {
  case "$1" in
    M1B_RUNS) echo runs ;; M1B_APPS) echo "$DEF_APPS" ;; M1B_DIRTY_APPS) echo "$DEF_DIRTY_APPS" ;; M1B_CP_APPS) echo "$DEF_CP_APPS" ;;
    M1B_SETS) echo "$DEF_SETS" ;;
    M1B_TRAP_RUNS) echo "$DEF_TRAPS" ;; M1B_LABELS) echo "" ;; M1B_CLEAN) echo m1b ;; M1B_DIRTY) echo m1bd ;; M1B_CP) echo m1bcp ;;
    M1B_BUDGETS) echo runs/m1b-budgets ;; M1B_REPLAY_DIFF) echo truth/m1b-replay-diff.json ;;
    M1B_REPLAY_SCORE) echo truth/m1b-replay-score.json ;;
  esac
}
GATE_VARS="M1B_RUNS M1B_APPS M1B_DIRTY_APPS M1B_CP_APPS M1B_SETS M1B_TRAP_RUNS M1B_LABELS M1B_CLEAN M1B_DIRTY M1B_CP M1B_BUDGETS M1B_REPLAY_DIFF M1B_REPLAY_SCORE"
CONFIG_VARS=""
for v in $GATE_VARS; do
  if [ -n "${!v+x}" ] && [ "${!v}" != "$(def_of "$v")" ]; then CONFIG_VARS="$CONFIG_VARS $v"; fi
done
CONFIG_VARS=${CONFIG_VARS# }
CONFIG=default; [ -n "$CONFIG_VARS" ] && CONFIG=custom

prefix_of() { case "$1" in clean) echo "${M1B_CLEAN:-m1b}" ;; dirty) echo "${M1B_DIRTY:-m1bd}" ;; cp) echo "${M1B_CP:-m1bcp}" ;; esac; }
apps_of() { case "$1" in cp) echo "$CP_APPS" ;; dirty) echo "$DIRTY_APPS" ;; *) echo "$APPS" ;; esac; }
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
OWNED_LISTED = ['svc-owned', 'task-owned', 'fw-owned', 'com-owned']   # design `safe`, file `listed` (DECISIONS M1b R4c S1)
TRAP_A, TRAP_B = '7zip', 'node'
K5_MIN = {'python312-with-313': 29, 'python313-with-312': 29}
FROZEN_APPS = ['powershell', 'temurin']               # truth from the m1b-freeze runs (FROZEN.md, RIG.md 12.6)
# the gate apps with a frozen truth (truth/frozen/<id>/truth.json): SANITY fails, never skips, one it cannot read (R4d N2)
SANITY_APPS = ['7zip', 'python', 'node', 'vcredist', 'powershell', 'temurin']
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
    """SHA-256 over a label file, every file it includes (recursively), _os-servicing.json and _m1b-noise.json; None
    if one is missing."""
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
    walk('_m1b-noise.json', 0)
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
def target_entry(rj, lists0):
    """The run's target ARP entry against lists-0 (ruling 2026-11-18, RUN): the main entry run-app found, whether it
    was already in lists-0 (same key, or same MSI product code), and how many entries the install created. A target
    already there means the install was a no-op (G3 node: dirty-base had Node.js 20.18.0).
    The target is run.json's `main` (Find-MainEntry of the app the run installs after snap 0: TrapA, 7zip, in a trap
    run), never a `pre` entry: a pre-app (TrapB node; the other Python of a pair) is installed before lists-0 on
    purpose and is in lists-0 in every run, so it is not judged (coordinator ruling 2026-11-18). `pre_keys` lists the
    pre entries, `main_is_pre` whether main is one of them, `main_created` whether main is among entries_created.
    Review R5 S2: with no pre record (run.json has no `pre`, or no entry in it) `main_is_pre` is None ("cannot
    tell"), never False, so the evaluator's "no pre record" check fires on a trap run whose pre-app phase recorded
    nothing."""
    if not isinstance(rj, dict):
        return None
    m = rj.get('main') if isinstance(rj.get('main'), dict) else None
    created = rj.get('entries_created')
    pre = rj.get('pre') if isinstance(rj.get('pre'), list) else []
    pre_e = [p.get('entry') for p in pre if isinstance(p, dict) and isinstance(p.get('entry'), dict)]
    out = {'main_key': (m or {}).get('key'), 'main_name': (m or {}).get('name'), 'main_msi': (m or {}).get('msi'),
           'entries_created': [str((e or {}).get('key')) for e in created] if isinstance(created, list) else None,
           'pre_keys': [str(e.get('key')) for e in pre_e], 'main_is_pre': None, 'main_created': None,
           'in_lists0': None}

    def same(e):
        key, code = str(m.get('key') or '').lower(), str(m.get('msi') or '').strip('{}').lower()
        return isinstance(e, dict) and bool((key and str(e.get('key') or '').lower() == key)
                                            or (code and str(e.get('msi') or '').strip('{}').lower() == code))
    if m:
        out['main_is_pre'] = any(same(e) for e in pre_e) if pre_e else None
        if isinstance(created, list):
            out['main_created'] = any(same(e) for e in created)
        if isinstance(lists0, dict) and isinstance(lists0.get('uninstall'), list):
            out['in_lists0'] = any(same(e) for e in lists0['uninstall'])
    return out


if MODE == 'runsum':
    # runsum <run dir> <run name> <out>: the run's record for the evaluator
    d, run, out = A
    rj = read_json(os.path.join(d, 'run.json'))
    plan = read_json(os.path.join(d, 'plan-purge.json'))
    doc = {'schema': 'purge.rig.m1b-run/1', 'run': run,
           'target': target_entry(rj, read_json(os.path.join(d, f'lists-{run}-0.json'))),
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

if MODE == 'rigtoolsrc':
    # rigtoolsrc <vm/rigtool dir>: the SHA-256 of rigtool's sources as its build.rs records it (review R5 S1):
    # Cargo.toml, Cargo.lock, build.rs and every file under src/, sorted by relative path ('/'), one line
    # '<sha256 of the bytes, CRLF read as LF>  <path>' each, hashed.
    root = A[0]
    files = [f for f in ('Cargo.toml', 'Cargo.lock', 'build.rs')]
    for dp, _, fs in os.walk(os.path.join(root, 'src')):
        files += [os.path.relpath(os.path.join(dp, f), root).replace(os.sep, '/') for f in fs]
    lines = ''
    try:
        for rel in sorted(files):
            with open(os.path.join(root, rel), 'rb') as f:
                lines += hashlib.sha256(f.read().replace(b'\r\n', b'\n')).hexdigest() + '  ' + rel + '\n'
    except OSError as e:
        print(f'm1b: rigtool sources: {e}', file=sys.stderr)
        sys.exit(1)
    print(hashlib.sha256(lines.encode()).hexdigest())
    sys.exit(0)

if MODE == 'manifest':
    # manifest <out> <runs dir> <sets> <prefix clean> <prefix dirty> <prefix cp> <label map "run=lid ..."> <truth dir>
    #          <config> <config vars> <rigtool> <null runs "run ..."> <rigtool source sha256> <rigtool tree sha256>
    out, runs_dir, sets, pc, pd, pcp, lmap, truth_dir, config, config_vars, rigtool, nulls, rt_src, rt_tree = A
    pre = {'clean': pc, 'dirty': pd, 'cp': pcp}
    labels = {}
    for m in lmap.split():
        run, lid = m.split('=', 1)
        labels[run] = {'label_id': lid, 'sha256': label_digest(os.path.join(truth_dir, 'labels'), lid)}
    doc = {'schema': 'purge.rig.m1b-evidence/2', 'note': 'collected by vm/truth/m1b.sh from ' + runs_dir,
           'prefixes': {s: pre[s] for s in sets.split()}, 'gate_config': config, 'config_vars': config_vars.split(),
           'traps_sha256': sha256_file(os.path.join(truth_dir, 'm1b-traps.json')), 'labels': labels,
           'deny_sha256': sha256_file(os.path.join(truth_dir, 'deny.json')),   # review R4d S1
           'frozen': {a: sha256_file(os.path.join(truth_dir, 'frozen', a, 'truth.json')) for a in FROZEN_APPS},
           'rigtool': {'path': rigtool, 'sha256': sha256_file(rigtool) or sha256_file(rigtool + '.exe'),
                       # review R5 S1: the sources the binary was built from (`rigtool version`) and vm/rigtool's now
                       'source_sha256': rt_src or None, 'tree_sha256': rt_tree or None},
           # the null runs each set's ambient set was built from (review R4c, R4b S2 rest): RUN checks them too
           'nulls': {s: [n for n in nulls.split() if n.startswith(pre[s] + '-null')] for s in sets.split()}}
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    sys.exit(0)

if MODE == 'replaybind':
    # replaybind <replay score> <truth dir> <runs "id ..."> <commit> <source dirty true|false|unknown> <replay diff>
    #            <replay-diff exit code>: review R4c S2; R4d S3 binds the diff this replay wrote (its SHA-256, None
    #            when replay-diff wrote none) and replay-diff's exit code, which BIND checks
    out, truth_dir, runs, commit, dirty, diff, diff_rc = A
    sc = read_json(out)
    if not isinstance(sc, dict):
        print(f'm1b replay: cannot read {out}', file=sys.stderr)
        sys.exit(1)
    sc['replay'] = {'schema': 'purge.rig.m1b-replay/1', 'runs': runs.split(), 'commit': commit or None,
                    'source_dirty': {'true': True, 'false': False}.get(dirty),
                    'diff_sha256': sha256_file(diff), 'diff_exit': int(diff_rc) if diff_rc.lstrip('-').isdigit() else None,
                    'frozen': {r: sha256_file(os.path.join(truth_dir, 'frozen', r, 'truth.json')) for r in runs.split()},
                    'written': datetime.datetime.now().astimezone().isoformat(timespec='seconds')}
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(sc, f, indent=2, ensure_ascii=False)
    sys.exit(0)


# ------------------------------------------------------------------------------------------- pre-state kept_owner
# prestate <truth.json> <snap0> <snap2> <lists0> <lists2> <label file>: review R4b S5, ruling 2026-11-17 (RIG.md
# section 12.4). A product that stays installed and that the removed app shared (the Python Launcher of the two Python
# pairs) was installed before snap 0, so the diff never sees its objects and K5 has nothing to count. The label file's
# `prestate` block names them: every object in snap 0 AND snap 2 that one of its rules matches becomes a kept_owner
# truth item (`prestate: true`), top-most per rule, never one that is or holds a leftover / user_data truth item (such
# a match is opened to its matching children instead, and reported). Product rules ({CODE}, {PACKED},
# {LOCALPACKAGE}, {DEPKEY}) expand per ARP entry named by `products` that is in lists-0 and lists-2 under the same key
# with the same product code. Rewrites truth.json (counts too) and adds a `prestate` summary. Before that, for every
# app: Windows Installer temp packages are relabelled ambient (temp_packages below, RIG.md section 12.6).
def unesc(s):
    if '\\' not in s:
        return s
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            n = s[i + 1]
            out.append({'\\': '\\', 't': '\t', 'n': '\n', 'r': '\r', '0': '\0'}.get(n, n))
            i += 2
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def snap_objects(p, want, values_of=None):
    """{folded canon: canon} of the snapshot's records whose canon string `want` matches; values_of collects
    {folded key: [(name, preview)]} of every V record under keys whose folded name starts with one of its prefixes."""
    import gzip
    out = {}
    with gzip.open(p, 'rt', encoding='utf-8', errors='replace', newline='\n') as f:
        for line in f:
            if not line or line[0] not in 'DFKV':
                continue
            fl = line.rstrip('\n').rstrip('\r').split('\t')
            r = fl[0]
            if r in ('D', 'F'):
                c = 'P:' + unesc(fl[1])
            elif r == 'K':
                c = 'K:' + unesc(fl[1])
            elif r == 'V' and len(fl) >= 3:
                k = unesc(fl[1])
                c = 'V:' + k + '|' + unesc(fl[2])
                if values_of is not None:
                    kl = k.lower()
                    if any(kl.startswith(x) for x in values_of['prefixes']):
                        values_of['vals'].setdefault(kl, []).append((unesc(fl[2]), unesc(fl[6]) if len(fl) > 6 else ''))
            else:
                continue
            if want.search(c):
                out[c.lower()] = c
    return out


def packed_guid(g):
    h = re.sub(r'[^0-9A-Fa-f]', '', g).upper()
    if len(h) != 32:
        return None
    return h[0:8][::-1] + h[8:12][::-1] + h[12:16][::-1] + ''.join(h[i:i + 2][::-1] for i in range(16, 32, 2))


def parent_of(c):
    t, rest = c[:2], c[2:]
    if t == 'v:':
        return 'k:' + rest.rsplit('|', 1)[0]
    return t + rest.rsplit('\\', 1)[0] if '\\' in rest else None


def under_c(x, c):
    """x is c or inside c (folded canon strings; a value is inside its key)."""
    if x == c:
        return True
    tx, tc = x[:2], c[:2]
    if tc == 'p:':
        return tx == 'p:' and x[2:].startswith(c[2:] + '\\')
    if tc == 'k:' and tx in ('k:', 'v:', 'c:'):
        body = x[2:].rsplit('|', 1)[0] if tx != 'k:' else x[2:]
        return body == c[2:] or body.startswith(c[2:] + '\\')
    if tc == 'v:' and tx == 'c:':
        return x[2:] == c[2:]
    return False


def target_of(c):
    t, rest = c[:2], c[2:]
    if t == 'P:':
        return {'type': 'Path', 'path': rest}
    if t == 'K:':
        return {'type': 'RegKey', 'path': rest}
    k, n = rest.rsplit('|', 1)
    return {'type': 'RegValue', 'path': k, 'name': n}


def canon_of(t):
    ty = t.get('type')
    pre = {'Path': 'P:', 'RegKey': 'K:', 'RegValue': 'V:', 'RegValueChanged': 'C:'}.get(ty)
    if not pre:
        return None
    return pre + str(t.get('path', '')) + (('|' + str(t.get('name') or '')) if pre in ('V:', 'C:') else '')


def prestate_blocks(lab_path, depth=0):
    """The `prestate` blocks of a label file and the files it includes."""
    j = read_json(lab_path) or {}
    out = []
    if depth < 5:
        for inc in j.get('include') or []:
            out += prestate_blocks(os.path.join(os.path.dirname(lab_path), inc), depth + 1)
    if isinstance(j.get('prestate'), dict):
        out.append(j['prestate'])
    return out


def kept_products(lists0, lists2, name_re):
    """ARP entries named by name_re that are in lists-0 and lists-2 under the same key with the same product code."""
    def by_key(l):
        return {str(e.get('key') or '').lower(): e for e in ((l or {}).get('uninstall') or []) if isinstance(e, dict)}
    a, b = by_key(lists0), by_key(lists2)
    out = []
    for k, e in a.items():
        f = b.get(k)
        code = str(e.get('msi') or '')
        if f and code and re.search(name_re, str(e.get('name') or ''), re.I) and str(f.get('msi') or '').lower() == code.lower():
            out.append({'key': e.get('key'), 'name': e.get('name'), 'version': e.get('version'), 'code': code.strip('{}').upper()})
    return out


TEMP_PKGS = 'hklm\\software\\microsoft\\windows\\currentversion\\installer\\temppackages'


def temp_packages(truth, s2p):
    """Windows Installer's temp packages (RIG.md section 12.6): a leftover `C:\\Windows\\Installer\\<x>.msi` that snap 2's
    Installer\\TempPackages key names is the package copy msiexec keeps during a transaction and deletes itself later
    (msiexec's own state, present in some runs only): relabelled ambient. So is a kept_owner one that a generic cached-
    package rule labelled (python.json's `[0-9a-f]{4,8}.msi`), unless snap 2 names it as an installed product's
    LocalPackage. Returns the relabelled paths."""
    ud = 'hklm\\software\\microsoft\\windows\\currentversion\\installer\\userdata\\'
    vals = {'prefixes': [TEMP_PKGS, ud], 'vals': {}}
    snap_objects(s2p, re.compile(r'(?!)'), vals)
    listed = {n.lower() for n, _ in vals['vals'].get(TEMP_PKGS, [])}
    live = {v.lower() for k, vs in vals['vals'].items() if k.startswith(ud) and k.endswith('\\installproperties')
            for n, v in vs if n.lower() == 'localpackage'}
    out = []
    for it in truth.get('items') or []:
        t = it.get('target') or {}
        p = str(t.get('path') or '')
        if it.get('label') in ('leftover', 'kept_owner') and not it.get('prestate') and t.get('type') == 'Path' \
                and p.lower() in listed and p.lower() not in live \
                and re.fullmatch(r'c:\\windows\\installer\\[0-9a-f]{1,8}\.msi', p, re.I):
            it['label'], it['rule'] = 'ambient', 'temp package: Windows Installer\\TempPackages names it in snap 2 (msiexec deletes it itself)'
            out.append(p)
    return out


if MODE == 'prestate':
    tpath, s0p, s2p, l0p, l2p, labp = A
    truth = read_json(tpath)
    if truth is None:
        print(f'm1b prestate: cannot read {tpath}', file=sys.stderr)
        sys.exit(2)
    tp = temp_packages(truth, s2p)
    blocks = prestate_blocks(labp)
    if not blocks:
        if tp:
            c = {}
            for i in truth['items']:
                c[i.get('label')] = c.get(i.get('label'), 0) + 1
            truth['counts'] = dict(sorted(c.items()))
            truth['temp_packages'] = tp
            with open(tpath, 'w', encoding='utf-8') as f:
                json.dump(truth, f, indent=2, ensure_ascii=False)
            print(f'm1b prestate: {len(tp)} Windows Installer temp package(s) relabelled ambient', file=sys.stderr)
        sys.exit(0)
    truth['temp_packages'] = tp
    lists0, lists2 = read_json(l0p), read_json(l2p)
    if lists0 is None or lists2 is None:
        print('m1b prestate: lists-0 / lists-2 missing: the kept products cannot be told', file=sys.stderr)
        sys.exit(2)
    UD = 'hklm\\software\\microsoft\\windows\\currentversion\\installer\\userdata\\s-1-5-18\\products\\'
    DEP = 'hklm\\software\\classes\\installer\\dependencies\\'
    vals = {'prefixes': [UD, DEP], 'vals': {}}
    # pass 1 over snap 0: the values that resolve the product placeholders (LocalPackage, dependency provider)
    snap_objects(s0p, re.compile(r'(?!)'), vals)
    rules, products, skipped = [], [], []
    for bi, b in enumerate(blocks):
        prods = kept_products(lists0, lists2, b.get('products') or r'(?!)') if b.get('products') else []
        for pr in prods:
            pk = packed_guid(pr['code'])
            pr['packed'] = pk
            lp = [v for n, v in vals['vals'].get(f'{UD}{pk.lower()}\\installproperties', []) if n.lower() == 'localpackage']
            pr['local_package'] = lp[0].rsplit('\\', 1)[-1] if lp and lp[0] else None
            dep = sorted({k[len(DEP):].split('\\')[0] for k, vs in vals['vals'].items() if k.startswith(DEP) and '\\' not in k[len(DEP):]
                          for n, v in vs if n == '' and v.strip('{}').upper() == pr['code']})
            pr['dependency_keys'] = dep
            products.append(pr)
        for r in b.get('rules') or []:
            if r.get('label') != 'kept_owner':
                print(f"m1b prestate: rule label {r.get('label')} (only kept_owner): {r.get('match')}", file=sys.stderr)
                sys.exit(2)
            m = r['match']
            if not re.search(r'\{(CODE|PACKED|LOCALPACKAGE|DEPKEY)\}', m):
                rules.append((re.compile(m, re.I), r.get('why', ''), None))
                continue
            for pr in prods:
                subs = {'{CODE}': [pr['code']], '{PACKED}': [pr['packed']],
                        '{LOCALPACKAGE}': [pr['local_package']] if pr['local_package'] else [],
                        '{DEPKEY}': pr['dependency_keys']}
                exp = [m]
                for ph, vs in subs.items():
                    if ph in m:
                        exp = [x.replace(ph, re.escape(v)) for x in exp for v in vs]
                if not exp:
                    skipped.append(f"{m} for {pr['name']} (placeholder not resolved)")
                for x in exp:
                    rules.append((re.compile(x, re.I), r.get('why', ''), pr['code']))
            if not prods:
                skipped.append(f'{m} (no kept product in lists-0 and lists-2)')
    if not rules:
        print('m1b prestate: no rule to apply', file=sys.stderr)
    want = re.compile('|'.join(f'(?:{r[0].pattern})' for r in rules) or r'(?!)', re.I)
    s0 = snap_objects(s0p, want) if rules else {}
    s2 = snap_objects(s2p, want) if rules else {}
    cand = {k: c for k, c in s0.items() if k in s2}
    rule_of = {k: [i for i, r in enumerate(rules) if r[0].search(c)] for k, c in cand.items()}
    items = truth.get('items') or []
    folded = [(canon_of(i.get('target') or {}) or '').lower() for i in items]
    blockers = [f for f, i in zip(folded, items) if f and i.get('label') in ('leftover', 'user_data')]
    known = set(folded) | {'v:' + f[2:] for f in folded if f.startswith('c:')}
    # top-most per rule: a match whose parent is matched by the same rule is part of the parent's item
    tops = [k for k in cand if not (parent_of(k) in cand and set(rule_of[k]) & set(rule_of[parent_of(k)]))]
    children = {}
    for k in cand:
        p = parent_of(k)
        if p in cand:
            children.setdefault(p, []).append(k)
    added, opened, dup = [], [], []
    todo = sorted(tops)
    while todo:
        k = todo.pop(0)
        if k in known:
            dup.append(cand[k])
            continue
        inner = [x for x in blockers if under_c(x, k)]
        if inner:
            opened.append({'object': cand[k], 'holds': inner[:5]})
            todo += sorted(c for c in children.get(k, []) if c not in todo)
            continue
        ri = rule_of[k][0]
        added.append({'target': target_of(cand[k]), 'label': 'kept_owner', 'rule': 'prestate: ' + rules[ri][1],
                      'prestate': True, **({'product': '{' + rules[ri][2] + '}'} if rules[ri][2] else {})})
    items += added
    truth['items'] = items
    counts = {}
    for i in items:
        counts[i.get('label')] = counts.get(i.get('label'), 0) + 1
    truth['counts'] = dict(sorted(counts.items()))
    truth['prestate'] = {'note': 'vm/truth/m1b.sh prestate (RIG.md section 12.4)', 'label_file': labp, 'products': products,
                         'rules': len(rules), 'matched_before_and_after': len(cand), 'added': len(added),
                         'opened': opened, 'already_in_truth': dup, 'skipped_rules': skipped}
    with open(tpath, 'w', encoding='utf-8') as f:
        json.dump(truth, f, indent=2, ensure_ascii=False)
    print(f"m1b prestate: {os.path.basename(os.path.dirname(os.path.abspath(tpath)))}: {len(added)} kept_owner item(s) from the "
          f"pre-state ({len(products)} kept product(s), {len(opened)} opened, {len(skipped)} rule(s) skipped)", file=sys.stderr)
    sys.exit(0)


# ------------------------------------------------------------------------------------------- freeze comparison
# freezecmp <app> <fz1 dir> <fz2 dir> <out dir> <ambient sources>: the M1b freeze rule (RIG.md section 12.6, ruling
# 2026-11-17). Both runs must be whole (every phase ok, install and uninstall exit 0 or 3010, the ARP entry gone), and
# an item the two runs both have must carry the same label in both; else exit 1. Items are compared with random
# names normalised (GUIDs, numbers of 6+ digits, the random part of %TEMP% names), as m1a.sh's sanity step does. An
# item present in ONE run only is churn or chance: it is EXCLUDED from the frozen truth and listed under
# freeze.excluded with the label it had, never kept as a leftover. Writes <out>/truth.json (run 1's truth, the items
# of both runs only), <out>/truth-fz2.json and <out>/run.json.
FZ_GUID = re.compile(r'\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?')
FZ_NUM = re.compile(r'(?<![0-9a-z])[0-9]{6,}(?![0-9a-z])|(?<=-)[0-9]{6,}(?=\.)')
FZ_TEMP = re.compile(r'(\\appdata\\local\\temp\\)([^\\|]+)')
FZ_RND = re.compile(r'[a-z0-9]{4,}')


def fz_norm(t):
    k = re.sub(r's-1-5-21-[0-9-]+', '<sid>', (canon_of(t) or json.dumps(t, sort_keys=True)).lower())
    k = FZ_GUID.sub('<guid>', k)
    k = FZ_NUM.sub('<n>', k)
    return FZ_TEMP.sub(lambda m: m.group(1) + FZ_RND.sub(lambda r: '<rnd>' if re.search('[0-9]', r.group(0)) else r.group(0), m.group(2)), k)


def run_whole(rj):
    """Problems that make a raw freeze run unusable (empty list: the run is whole)."""
    if not isinstance(rj, dict):
        return ['no run.json']
    p = [f"phase {x.get('name')} failed: {x.get('error')}" for x in rj.get('phases') or [] if not x.get('ok')]
    if not rj.get('phases'):
        p.append('no phases')
    ins, un = rj.get('install') or {}, rj.get('uninstall') or {}
    if ins.get('exit') not in (0, 3010) or ins.get('timed_out'):
        p.append(f"install exit {ins.get('exit')} timed_out {ins.get('timed_out')}")
    if un.get('exit') not in (0, 3010) or un.get('timed_out') or un.get('entry_gone') is not True:
        p.append(f"uninstall exit {un.get('exit')} timed_out {un.get('timed_out')} entry_gone {un.get('entry_gone')}")
    if not rj.get('main'):
        p.append('no main ARP entry')
    return p


if MODE == 'freezecmp':
    app, d1, d2, outd, amb_src = A
    t1, t2 = read_json(os.path.join(d1, 'truth.json')), read_json(os.path.join(d2, 'truth.json'))
    r1, r2 = read_json(os.path.join(d1, 'run.json')), read_json(os.path.join(d2, 'run.json'))
    bad = [f'fz1: {x}' for x in run_whole(r1)] + [f'fz2: {x}' for x in run_whole(r2)]
    if t1 is None or t2 is None:
        bad.append('no truth.json for both runs')
    if bad:
        for x in bad:
            print('freeze: run not whole:', x)
        print(f'freeze {app}: refused (a run is not whole: re-run m1b-freeze)')
        sys.exit(1)

    def keyed(t):
        out = {}
        for it in t.get('items') or []:
            out.setdefault(fz_norm(it.get('target') or {}), []).append(it)
        return out
    a, b = keyed(t1), keyed(t2)
    mism, excl = [], []
    keep1, keep2 = [], []
    for k in sorted(set(a) | set(b)):
        la = sorted({i.get('label') for i in a.get(k, [])})
        lb = sorted({i.get('label') for i in b.get(k, [])})
        if k in a and k in b:
            if la != lb:
                mism.append({'item': k, 'fz1': la, 'fz2': lb})
            keep1 += a[k]
            keep2 += b[k]
        else:
            run, its = ('fz1', a[k]) if k in a else ('fz2', b[k])
            for i in its:
                if i.get('label') in ('ambient', 'rig'):
                    (keep1 if run == 'fz1' else keep2).append(i)   # ambient either way: kept as reported
                else:
                    excl.append({'run': run, 'target': i.get('target'), 'label_in_run': i.get('label'), 'rule': i.get('rule')})

    def counts(items):
        c = {}
        for i in items:
            c[i.get('label')] = c.get(i.get('label'), 0) + 1
        return dict(sorted(c.items()))
    na = {k for k, v in a.items() if any(i.get('label') not in ('ambient', 'rig') for i in v)}
    nb = {k for k, v in b.items() if any(i.get('label') not in ('ambient', 'rig') for i in v)}
    print(f'freeze {app}: fz1 {len(na)} non-ambient items, fz2 {len(nb)}, in both {len(na & nb)}, '
          f'excluded (one run only) {len(excl)}, label mismatches {len(mism)}')
    for e in excl:
        print(f"freeze:   excluded, only in {e['run']} (was {e['label_in_run']}): {canon_of(e['target']) or e['target']}")
    for m in mism:
        print(f"freeze:   LABEL MISMATCH {m['item']}: fz1 {m['fz1']} fz2 {m['fz2']}")
    if mism:
        print(f'freeze {app}: refused (the same item has different labels in the two runs: fix the labels)')
        sys.exit(1)
    os.makedirs(outd, exist_ok=True)
    rule = 'present in one freeze run only (Windows churn or chance): excluded from the frozen truth, never a leftover'
    for t, keep, other in ((t1, keep1, 'fz2'), (t2, keep2, 'fz1')):
        t['items'] = keep
        t['counts'] = counts(keep)
        t['freeze'] = {'schema': 'purge.rig.m1b-freeze/1', 'app': app, 'runs': [os.path.basename(os.path.normpath(d1)), os.path.basename(os.path.normpath(d2))],
                       'ambient': amb_src, 'rule': rule, 'compared_with': other, 'excluded': excl}
    with open(os.path.join(outd, 'truth.json'), 'w', encoding='utf-8') as f:
        json.dump(t1, f, indent=2, ensure_ascii=False)
    with open(os.path.join(outd, 'truth-fz2.json'), 'w', encoding='utf-8') as f:
        json.dump(t2, f, indent=2, ensure_ascii=False)
    with open(os.path.join(outd, 'run.json'), 'w', encoding='utf-8') as f:
        json.dump(r1, f, indent=2, ensure_ascii=False)
    print(f"freeze {app}: frozen {counts(keep1)} -> {outd}")
    sys.exit(0)

# ------------------------------------------------------------------------------------------- stage 2
assert MODE == 'evaluate', MODE
evid, out, apps, dirty_apps, cp_apps, sets, trap_runs, config, config_vars, how, truth_dir = A
apps, dirty_apps, cp_apps, sets, trap_runs = apps.split(), dirty_apps.split(), cp_apps.split(), sets.split(), trap_runs.split()
rows = []


def row(k, step, subject, value, limit, ok, note=None):
    rows.append({'id': k, 'step': step, 'subject': subject, 'value': value, 'limit': limit, 'pass': bool(ok), 'note': note})


def load(name):
    p = os.path.join(evid, name)
    return read_json(p) if os.path.isfile(p) else None


def miss(what):
    return f'missing {what}'


def set_apps(s):
    return {'cp': cp_apps, 'dirty': dirty_apps}.get(s, apps)


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
    # Ruling 2026-11-18: the install must have created the target. A target ARP entry already in lists-0 (G3 node:
    # dirty-base had Node.js 20.18.0) or no created entry at all is a no-op install: the run is invalid. Unknown
    # (no target record, lists-0 unreadable) fails too.
    tg = (rd or {}).get('target')
    inval = []
    if not isinstance(tg, dict) or not tg.get('main_key'):
        inval.append('no target ARP entry recorded (run.json main)')
    else:
        if tg.get('in_lists0') is not False:
            inval.append('target ARP entry already in lists-0: a no-op install' if tg.get('in_lists0') is True
                         else 'lists-0 unreadable: cannot tell whether the target was installed by this run')
        if not isinstance(tg.get('entries_created'), list) or not tg.get('entries_created'):
            inval.append('the install created no ARP entry (entries_created empty)')
        if s == 'traps':
            # trap runs judge TrapA (main) only; TrapB is a pre-app in lists-0 by design. main must be TrapA's new
            # entry: not a pre entry, and created by this run.
            if tg.get('main_is_pre') is not False:
                inval.append('target is a pre-app (TrapB) entry, not TrapA' if tg.get('main_is_pre')
                             else 'cannot tell whether the target is TrapA (no pre record)')
            if tg.get('main_created') is not True:
                inval.append('TrapA\'s entry is not among the entries this run created')
    ok = rj.get('run') == run and bool(rj.get('finished')) and bool(ph) and not bad and not inval
    note = '; '.join((['failed: ' + ', '.join(bad)] if bad else [])
                     + ([] if rj.get('run') == run else [f"run.json names {rj.get('run')}"])
                     + ([f"INVALID RUN: {', '.join(inval)} ({(tg or {}).get('main_name')} {(tg or {}).get('main_key')})"] if inval else []))
    row('RUN', st, run, f"finished={bool(rj.get('finished'))} phases ok {len(ph) - len(bad)}/{len(ph)}"
        + (' INVALID: target not installed by this run' if inval else ''),
        'finished, every phase ok, target ARP entry new (not in lists-0, entries_created not empty)'
        + ('; trap run: TrapA judged, TrapB (pre) not' if s == 'traps' else ''), ok, note or None)

# RUN for the null runs each set's ambient set came from (review R4c; the rest of R4b S2): at least 2, each finished
# with every phase ok. They run no engine, so BIND has nothing to bind.
for s in sets:
    nl = (manifest.get('nulls') or {}).get(s) or []
    bad = []
    for n in nl:
        rj = ((load(f'runs/{n}.json') or {}).get('run_json')) or {}
        ph = rj.get('phases') or []
        if rj.get('run') != n or not rj.get('finished') or not ph or any(p.get('ok') is not True for p in ph):
            bad.append(f"{n}: run {rj.get('run')}, finished {bool(rj.get('finished'))}, failed "
                       + ','.join(str(p.get('name')) for p in ph if p.get('ok') is not True))
    row('RUN', STEP[s], f'{prefix[s]}-null*', f'{len(nl)} null run(s), {len(bad)} not whole', '>= 2, each finished, every phase ok',
        len(nl) >= 2 and not bad, '; '.join(bad[:3]) or None)

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
# review R4d S1: the deny list (rigtool truth and score read it: one of the four sources of danger), as the trap file
deny_now = sha256_file(os.path.join(truth_dir, 'deny.json'))
if not deny_now or manifest.get('deny_sha256') != deny_now:
    bind_problems.append(f"deny list sha256 {manifest.get('deny_sha256')} at collect, {deny_now} committed")
# review R5 S1: the scores come from a rigtool built from vm/rigtool as collect found it (collect refuses otherwise;
# this catches evidence collected some other way)
rtm = manifest.get('rigtool') if isinstance(manifest.get('rigtool'), dict) else {}
if not rtm.get('source_sha256') or rtm.get('source_sha256') != rtm.get('tree_sha256'):
    bind_problems.append(f"rigtool built from sources {rtm.get('source_sha256')}, vm/rigtool at collect {rtm.get('tree_sha256')}: "
                         'rebuild rigtool and collect again')
for s, id, run in app_runs:
    lab = (manifest.get('labels') or {}).get(run) or {}
    now = label_digest(os.path.join(truth_dir, 'labels'), id)
    if lab.get('label_id') != id:
        bind_problems.append(f"{run}: labels {lab.get('label_id')}, not the app's own ({id})")
    elif not now or lab.get('sha256') != now:
        bind_problems.append(f"{run}: label files sha256 {lab.get('sha256')} at collect, {now} committed")
# Rig inputs (review R4c S3): collect and evaluate follow each other, so the check above cannot see an edit made before
# the campaign. Each build record holds the SHA-256 of the trap file, every label file, the guest scripts and rig.ps1
# as rig.ps1 found them before (`inputs`) and after (`inputs_after`) the campaign, and whether they differed from HEAD
# (`inputs_dirty`). All runs must hold one set, unchanged and clean, and its trap and label files must be the files
# scored with now.
input_sets = set()
for run, rd in run_docs.items():
    b = (rd or {}).get('build')
    if not isinstance(b, dict):
        continue
    inp = b.get('inputs')
    if not isinstance(inp, dict) or not inp:
        bind_problems.append(f'{run}: build record has no rig input hashes (inputs)')
        continue
    if b.get('inputs_after') != inp:
        bind_problems.append(f'{run}: rig inputs changed during the campaign')
    if b.get('inputs_dirty') is not False:
        bind_problems.append(f"{run}: rig inputs differ from HEAD (inputs_dirty {b.get('inputs_dirty')})")
    input_sets.add(json.dumps(inp, sort_keys=True))
if len(input_sets) > 1:
    bind_problems.append(f'runs hold {len(input_sets)} different sets of rig input hashes (trap, label or guest files, rig.ps1)')
elif input_sets:
    inp = json.loads(next(iter(input_sets)))
    LP, FP = 'vm/truth/labels/', 'vm/truth/frozen/'
    ldir, fdir = os.path.join(truth_dir, 'labels'), os.path.join(truth_dir, 'frozen')
    now_in = {'vm/truth/m1b-traps.json': traps_now, 'vm/truth/deny.json': deny_now}
    now_in.update({LP + f: sha256_file(os.path.join(ldir, f)) for f in (os.listdir(ldir) if os.path.isdir(ldir) else []) if f.endswith('.json')})
    # review R4d S1: every file under truth/frozen (rig.ps1 Get-M1bRigInputs hashes them all), as the label files
    for root, _, files in os.walk(fdir):
        for f in files:
            p = os.path.join(root, f)
            now_in[FP + os.path.relpath(p, fdir).replace(os.sep, '/')] = sha256_file(p)
    run_in = {k: v for k, v in inp.items() if k in ('vm/truth/m1b-traps.json', 'vm/truth/deny.json') or k.startswith(LP) or k.startswith(FP)}
    differ = sorted(k for k in set(now_in) | set(run_in) if now_in.get(k) != run_in.get(k))
    if differ:
        bind_problems.append('trap / label / deny / frozen files at run time differ from those scored with: ' + ', '.join(differ[:4]))
    if not any(k.startswith(FP) for k in now_in) or not deny_now:
        bind_problems.append('no deny list or no frozen truth to score with')
    if not any(k.startswith('vm/guest/') for k in inp) or 'vm/rig.ps1' not in inp:
        bind_problems.append('rig input hashes hold no guest script or no rig.ps1')
# The replay score (review R4c S2): written by `m1b.sh replay` for the gate's commit, clean engine sources, the five
# runs, against the committed frozen truths.
rs = load('replay-score.json')
if rs is not None:
    rb = rs.get('replay')
    if not isinstance(rb, dict) or rb.get('schema') != 'purge.rig.m1b-replay/1':
        bind_problems.append('replay score has no replay block (bash truth/m1b.sh replay writes it)')
    else:
        if not rb.get('commit') or len(commits) != 1 or rb.get('commit') not in commits:
            bind_problems.append(f"replay score from commit {rb.get('commit')}, runs from {sorted(commits)}")
        if rb.get('source_dirty') is not False:
            bind_problems.append(f"replay score: source_dirty {rb.get('source_dirty')}")
        if sorted(rb.get('runs') or []) != sorted(REPLAY_RUNS):
            bind_problems.append(f"replay score runs {rb.get('runs')}, not {REPLAY_RUNS}")
        fzd = [r for r in REPLAY_RUNS if not (rb.get('frozen') or {}).get(r)
               or (rb.get('frozen') or {}).get(r) != sha256_file(os.path.join(truth_dir, 'frozen', r, 'truth.json'))]
        if fzd:
            bind_problems.append('replay score: frozen truth changed or missing since the replay: ' + ', '.join(fzd))
        # review R4d S3: K16 judges the diff this replay wrote, and replay-diff exited 0
        dsha = sha256_file(os.path.join(evid, 'replay-diff.json'))
        if not rb.get('diff_sha256') or rb.get('diff_sha256') != dsha:
            bind_problems.append(f"replay diff is not the one the replay wrote (sha256 {dsha}, replay block {rb.get('diff_sha256')})")
        if rb.get('diff_exit') != 0 or isinstance(rb.get('diff_exit'), bool):
            bind_problems.append(f"replay: cargo xtask replay-diff exit {rb.get('diff_exit')}, not 0")
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

# SANITY (review R4c S4; m1a.sh had it): each rig-base run's truth against the app's frozen truth (truth/frozen/<id>,
# Inbound rig-base like G2; the dirty and Clean-Pro sets have no frozen truth), items keyed with random names normalised
# as the freeze compares them. A frozen leftover or user_data item that the run labels otherwise FAILS (the run's
# labels or the frozen truth are wrong). Items on one side only are counted and listed in the note (a launch that did
# nothing, an uninstall that removed more or less): the gate report judges them.
# Review R4d S2: a frozen item is matched by its exact target first; only when the run has no item with that exact
# target (a random name) does the normalised key decide, and then only the run's non-ambient labels count: another
# object of the same normalised name that the run labels ambient (Windows' %TEMP%\<hex>.tmp beside the bundle's
# DEL<hex>.tmp) is not a relabel, and a key holding only ambient items is "frozen only". R4d N2: an app of
# SANITY_APPS whose frozen truth cannot be read FAILS.
if 'clean' in sets:
    def ckey(t):
        return (canon_of(t) or json.dumps(t, sort_keys=True)).lower()

    for id in apps:
        fz = read_json(os.path.join(truth_dir, 'frozen', id, 'truth.json'))
        subj = f'clean/{id}'
        lim = 'no frozen leftover/user_data item labelled otherwise'
        if not isinstance(fz, dict) or not isinstance(fz.get('items'), list):
            if id in SANITY_APPS:
                row('SANITY', 'G2', subj, miss(f'a readable truth/frozen/{id}/truth.json'), lim, False)
            continue
        rt = load(f'truth-clean-{id}.json')
        if not isinstance(rt, dict) or not isinstance(rt.get('items'), list):
            row('SANITY', 'G2', subj, miss(f'truth-clean-{id}.json (the run truth)'), lim, False)
            continue
        REAL, AMB = {'leftover', 'user_data'}, {'ambient', 'rig'}
        r_exact, r_norm = {}, {}
        for it in rt['items']:
            t = it.get('target') or {}
            r_exact.setdefault(ckey(t), set()).add(it.get('label'))
            r_norm.setdefault(fz_norm(t), set()).add(it.get('label'))
        relab, only_f, f_norm = [], [], set()
        for it in fz['items']:
            t, lab = it.get('target') or {}, it.get('label')
            f_norm.add(fz_norm(t))
            if lab not in REAL:
                continue
            ex = r_exact.get(ckey(t))
            if ex is not None:
                if ex != {lab}:
                    relab.append(f'{canon_of(t)} {lab} -> {sorted(ex)}')
                continue
            nl = r_norm.get(fz_norm(t), set()) - AMB
            if not nl:
                only_f.append(canon_of(t) or fz_norm(t))
            elif lab not in nl or nl - REAL:
                relab.append(f'{fz_norm(t)} {lab} -> {sorted(nl)} (by normalised name)')
        nf = sum(1 for it in fz['items'] if it.get('label') in REAL)
        rr = {fz_norm(it.get('target') or {}) for it in rt['items'] if it.get('label') in REAL}
        only_r = sorted(rr - f_norm)
        note = '; '.join([f'relabelled: {x}' for x in relab[:3]]
                         + ([f"frozen only ({len(only_f)}): " + ', '.join(only_f[:3])] if only_f else [])
                         + ([f"run only ({len(only_r)}): " + ', '.join(only_r[:3])] if only_r else []))
        row('SANITY', 'G2', subj, f'leftover+user_data frozen {nf} run {len(rr)}, relabelled {len(relab)}, '
            f'frozen only {len(only_f)}, run only {len(only_r)}', lim, not relab, note or None)

# K1 and K8's vcredist danger (ruling 2026-11-18): danger OFFERED, danger listed in any band but Blocked
# (rigtool score danger_offered). A danger item the engine lists Blocked is a read-only report line (ENGINE_PLAN.md
# 1.2: BAM and the other Windows-managed stores are reported only; REF-ANY lists such a hit Blocked, DenyListed
# reg.hklm.system; deny.json marks bam as danger), so it is kept, not
# offered: counted as danger_kept and named in the note. Fail-closed: the counts must be integers and agree with the
# score's danger list (danger_listed = every danger item, danger_offered = those not Blocked).
# Review R5 S3: the ruling covers a deny-list hit only. Each Blocked danger item's blockers are read from the run's
# scan sidecar (<set>-<id>-scan.json, the engine's own record); it is accepted only when one of them is DenyListed.
# Another blocker (NotGone, TooLarge, ... states that can change between scan and execute), no blocker, or no scan item
# for the target FAILS, and the note names the blockers.
def norm_target(cs):
    """A score target (`V:<key>|<name>`, `K:<key>`, `P:<path>`) folded for matching it with a scan item's: case, the
    hive spellings, HKU\\<sid>[_Classes] as HKCU, HKCR as HKLM\\SOFTWARE\\Classes, CurrentControlSet as ControlSet001."""
    s = str(cs or '').replace('/', '\\').lower()
    for a, b in (('hkey_local_machine', 'hklm'), ('hkey_users', 'hku'), ('hkey_current_user', 'hkcu'), ('hkey_classes_root', 'hkcr')):
        s = re.sub(r'(?<=^.:)' + a + r'(?=\\|$)', b, s)
    s = re.sub(r'(?<=^.:)hku\\s-1-5-21-[0-9-]+_classes(?=\\|$)', 'hkcu\\\\software\\\\classes', s)
    s = re.sub(r'(?<=^.:)hku\\s-1-5-21-[0-9-]+(?=\\|$)', 'hkcu', s)
    s = re.sub(r'(?<=^.:)hkcr(?=\\|$)', 'hklm\\\\software\\\\classes', s)
    return s.replace('\\currentcontrolset\\', '\\controlset001\\')


def scan_blockers(scan):
    """{normalised target: [blocker, ...]} of a scan sidecar's items, or None when there is no readable scan."""
    if not isinstance(scan, dict) or not isinstance(scan.get('items'), list):
        return None
    out = {}
    for it in scan['items']:
        if isinstance(it, dict) and isinstance(it.get('target'), dict) and canon_of(it['target']):
            out.setdefault(norm_target(canon_of(it['target'])), []).extend(b for b in (it.get('blockers') or []) if isinstance(b, dict))
    return out


def blocker_text(b):
    return str(b.get('kind')) + (f" {b.get('rule')}" if b.get('rule') else '')


def danger_offered(t, scan):
    dl, do, dk, items = t.get('danger_listed'), t.get('danger_offered'), t.get('danger_kept'), t.get('danger')
    if not (is_int(dl) and is_int(do) and is_int(dk)) or not isinstance(items, list):
        return {'value': miss(f'danger_listed / danger_offered / danger_kept / danger in the score ({dl}, {do}, {dk})'),
                'ok': False, 'note': None, 'n': None}
    off = [i for i in items if isinstance(i, dict) and i.get('band') != 'Blocked']
    kept = [i for i in items if isinstance(i, dict) and i.get('band') == 'Blocked']
    probs = []
    if len(items) != dl or len(off) != do or len(kept) != dk or dl != do + dk:
        probs.append(f'counts disagree with the danger list: listed {dl} offered {do} kept {dk}, list {len(items)} '
                     f'({len(off)} not Blocked)')
    bl = scan_blockers(scan) if kept else {}
    kept_txt = []
    for i in kept:
        if bl is None:
            probs.append(f"Blocked danger item {i.get('target')}: no scan sidecar to read its blockers from")
            kept_txt.append(f"{i.get('target')} [{i.get('scanner')}; blockers unknown]")
            continue
        b = bl.get(norm_target(i.get('target')))
        names = ', '.join(blocker_text(x) for x in b or []) or 'none'
        kept_txt.append(f"{i.get('target')} [{i.get('scanner')}; {names}]")
        if b is None:
            probs.append(f"Blocked danger item {i.get('target')}: not in the scan sidecar, its blocker is unknown")
        elif not any(x.get('kind') == 'DenyListed' for x in b):
            probs.append(f"Blocked danger item {i.get('target')}: blocked by {names}, not a deny-list hit (ruling 2026-11-18 covers DenyListed only)")
    note = '; '.join(probs + [f"offered at {i.get('band')}: {i.get('target')}" for i in off[:3]]
                     + ([f'danger_kept {len(kept)} (listed Blocked, report only): ' + ', '.join(kept_txt[:3])] if kept else []))
    return {'value': f'danger_offered={do} (danger_kept={dk})', 'ok': do == 0 and not probs, 'note': note or None, 'n': do}


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
            dg = danger_offered(t, load(f'{s}-{id}-scan.json'))
            row('K1', st, subj, dg['value'], 0, dg['ok'], dg['note'])
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
    if rs is None:
        row('K4', 'G1', 'replay', miss('replay-score.json (bash truth/m1b.sh replay)'), 'danger 0, precision_safe 100 %', False)
        row('K7', 'G1', 'replay 7zip', miss('replay-score.json'), 'HKU\\<sid>\\Software\\7-Zip listed', False)
    else:
        # review R4c S2: one row per replay run, all five required (a file with 7-Zip alone does not pass)
        for rid in REPLAY_RUNS:
            ts = [t for a in rs.get('apps', []) if a.get('id') == rid for t in a.get('tools', []) if t.get('tool') == 'purge']
            if len(ts) != 1:
                row('K4', 'G1', f'replay/{rid}', miss(f'one purge score of {rid} in replay-score.json ({len(ts)} found)'),
                    'danger 0, precision_safe 100 %', False)
                continue
            ps, dl = ts[0].get('precision_safe'), ts[0].get('danger_listed')
            # review R4d N1: an empty replayed plan proves nothing, as K1-K6 (truth items, nothing offered, or no counts)
            tn, on = ts[0].get('truth_n'), ts[0].get('offered_n')
            if not is_int(tn) or not is_int(on) or (tn > 0 and on == 0):
                row('K4', 'G1', f'replay/{rid}', f'empty plan or no counts: truth_n={tn} offered_n={on}', 'a plan with items', False)
                continue
            row('K4', 'G1', f'replay/{rid}', f'danger_listed={dl} precision_safe={ps}', 'danger 0, precision_safe 100 %',
                dl == 0 and (ps is None or ps == 1.0))
        extra = sorted({str(a.get('id')) for a in rs.get('apps', [])} - set(REPLAY_RUNS))
        if extra:
            row('K4', 'G1', 'replay apps', 'not a G1 run: ' + ', '.join(extra), f'exactly {REPLAY_RUNS}', False)
        z = [t for a in rs.get('apps', []) if a.get('id') == '7zip' for t in a.get('tools', []) if t.get('tool') == 'purge']
        hit = [i for t in z for i in t.get('items', []) if re.fullmatch(r'K:HKU\\S-1-5-21-[0-9-]+\\Software\\7-Zip', str(i.get('target', '')), re.I) and i.get('band') != 'Blocked']
        row('K7', 'G1', 'replay 7zip', f'{len(hit)} listing(s)' if z else miss('a 7zip app in replay-score.json'), 'HKU\\<sid>\\Software\\7-Zip listed', bool(hit))


# K8: vcredist nothing preselected, no danger; python: the Launcher suggestion where the Launcher is left orphaned
# (rig-base and Clean-Pro: report-only, scored as a notice); dirty-base python (Python 3.11.9 and 3.13.1 stay, the
# Launcher is 3.13.1's): no suggestion and the Launcher not offered; python312-with-313: none.
# Review R5 B1 (user ruling 2026-11-18): rigtool score takes a ReportOnly item carrying suggest_uninstall out of every
# count (danger, precision, protected_correct) and lists it under `notices`; K8 is the only criterion that scores it,
# so it needs each suggestion of the scan sidecar to be a notice in the score (an old rigtool, or a plan without the
# copied fact, FAILS here, and K1/K5/K6 fail on the same item).
# Review R5 B2 (coordinator ruling 2026-11-18, a design fact): on dirty-base the Launcher belongs to the Python 3.13.1
# that stays, so the correct result is no suggestion; any item on the Launcher listed in any band but Blocked with an
# action other than ReportOnly FAILS (Blocked is the design's "stays Protected").
SUGGEST_SETS = ('clean', 'cp')        # the Launcher is orphaned there (python alone)
# The Python Launcher's product codes (kb/shared-components.json python-launcher, 3.12.7 and 3.13.1; 3.13.17 per R5 N5)
# and its files: a dirty-base item naming one of them is "on the Launcher".
LAUNCHER_CODES = ['73831AC2-F0E1-4173-9FDB-D07463D7EB80', '7102CAE5-270C-4E81-AC25-27699156D8AE',
                  '8078A005-EBA5-4E1A-9AAF-EC4693A1D7C3']
LAUNCHER_FILES = ['c:\\windows\\py.exe', 'c:\\windows\\pyw.exe', 'c:\\windows\\pyshellext.amd64.dll']


def suggest_of(it):
    """The product a scan item suggests uninstalling (SYS-BURNDEPS rule (c): its evidence fact suggest_uninstall)."""
    for ev in (it.get('evidence') or []) if isinstance(it, dict) else []:
        v = (ev.get('detail') or {}).get('suggest_uninstall') if isinstance(ev, dict) and isinstance(ev.get('detail'), dict) else None
        if isinstance(v, str) and v.strip():
            return v
    return None


def suggestions(scan):
    return [it for it in (scan or {}).get('items', []) if suggest_of(it)]


def item_band(it):
    return ((it.get('decision') or {}).get('band') if isinstance(it.get('decision'), dict) else None) or it.get('band')


def on_launcher(it):
    t = it.get('target') if isinstance(it.get('target'), dict) else {}
    text = (str(t.get('path') or '') + '|' + str(t.get('name') or '')).lower()
    if any(c.lower() in text for c in LAUNCHER_CODES):
        return True
    p = str(t.get('path') or '').lower() if t.get('type') == 'Path' else ''
    return any(p == f or p.startswith(f + '\\') for f in LAUNCHER_FILES)


for s in [x for x in sets if x in ('clean', 'dirty', 'cp')]:
    st = STEP[s]
    if 'vcredist' in set_apps(s) and s != 'cp':
        t = purge_score(s, 'vcredist')
        if t is None:
            row('K8', st, f'{s}/vcredist', miss('vcredist score'), '0 preselected, 0 danger offered', False)
        else:
            items = t.get('items')
            pre = sum(1 for i in items if isinstance(i, dict) and i.get('preselected')) if isinstance(items, list) else None
            dg = danger_offered(t, load(f'{s}-vcredist-scan.json'))
            row('K8', st, f'{s}/vcredist', f'preselected={pre} {dg["value"]}', '0 preselected, 0 danger offered',
                pre == 0 and dg['ok'], dg['note'])
    if 'python' in set_apps(s):
        scan = load(f'{s}-python-scan.json')
        subj = f'{s}/python suggestion'
        if s in SUGGEST_SETS:
            lim = '>= 1, all ReportOnly, each a notice in the score'
            t = purge_score(s, 'python')
            if scan is None or t is None:
                row('K8', st, subj, miss(f'{s}-python-scan.json' if scan is None else f'score of {prefix[s]}-python'), lim, False)
            else:
                sg = suggestions(scan)
                nt = t.get('notices')
                probs = [] if sg else ['no suggestion']
                probs += [f"{suggest_of(i)} on {canon_of(i.get('target') or {})}: action {i.get('action')}" for i in sg if i.get('action') != 'ReportOnly']
                if not isinstance(nt, list):
                    probs.append('the score has no notices list (rigtool built before review R5)')
                else:
                    want = sorted(suggest_of(i) for i in sg)
                    got = sorted(str(n.get('suggest_uninstall')) for n in nt if isinstance(n, dict))
                    if want != got:
                        probs.append(f'notices in the score {got}, suggestions in the scan {want} (a suggestion scored as an offer or listing?)')
                row('K8', st, subj, f'{len(sg)} suggestion(s), actions {sorted({str(i.get("action")) for i in sg})}, '
                    f'{len(nt) if isinstance(nt, list) else "no"} notice(s)', lim, not probs,
                    '; '.join(probs[:3] + [f"{n.get('suggest_uninstall')} on {n.get('target')} ({n.get('band')}, would be {n.get('would_be')})"
                                           for n in (nt if isinstance(nt, list) else [])[:2] if isinstance(n, dict)]) or None)
        else:
            lim = '0 suggestions, Launcher not offered (kept by Python 3.13.1)'
            if scan is None:
                row('K8', st, subj, miss(f'{s}-python-scan.json'), lim, False)
            else:
                sg = suggestions(scan)
                off = [i for i in scan.get('items', []) if isinstance(i, dict) and on_launcher(i)
                       and i.get('action') != 'ReportOnly' and item_band(i) != 'Blocked']
                row('K8', st, subj, f'{len(sg)} suggestion(s), {len(off)} Launcher item(s) offered', lim, not sg and not off,
                    '; '.join([f'suggests {suggest_of(i)} on {canon_of(i.get("target") or {})}' for i in sg[:2]]
                              + [f"offered {i.get('action')} at {item_band(i)}: {canon_of(i.get('target') or {})}" for i in off[:3]]) or None)
    if 'python312-with-313' in set_apps(s) and s != 'cp':
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
    # Review R4c S1: `listed` passes at Weak too, so the band of the four owned objects is reported (gate report).
    owned = []
    for c in tr.get('cases') or []:
        if c.get('id') in OWNED_LISTED:
            bands = sorted({l.get('band') for e in c.get('expectations') or [] for l in e.get('listings') or []
                            if l.get('relation') == 'equal'})
            owned.append(f"{c.get('id')}={'/'.join(str(b) for b in bands) or 'not listed'}")
    note = '; '.join(probs[:5] + (['owned bands: ' + ', '.join(owned)] if owned else []))
    row('K9', st, run, f"cases={sm.get('cases')} escapes={sm.get('escapes')} missed_owned={sm.get('missed_owned')} "
        f'failed_cases={failed} unplanted_targets={unplanted} pre_existing_objects={pre_existing}', lim, ok, note or None)

# K14: budgets (review R4b S6: every run exit 0, 3 rounds per engine and step, round 1 shown cold)
STAMP = re.compile(r'^\[\s*([0-9.]+)s\]')
PHASE = re.compile(r'^timing:\s+phase (\S+) ([0-9.]+)s')
# Ruling 2026-11-18 (K14 warm cache): the engine's cache line (PURGE_TIMING), `timing: msi_table_cache disk <path>
# hits=N misses=M` or `timing: msi_table_cache memory ...`; the process total line `timing: total: ... sys.msi_tables
# N/rows ...` (no sys.msi_tables in it: none read); the harvest summary `harvest: <name> (<id>); N root(s), R rejected;
# ...; K co-product candidate(s); ...` (G7 like for like).
CACHE = re.compile(r'^timing:\s+msi_table_cache\s+(\S+)(.*)$')
TOTAL = re.compile(r'^timing:\s+total:(.*)$')
MSI_READS = re.compile(r'(?:^|;)\s*sys\.msi_tables (\d+)')
HSUM = re.compile(r'^harvest: .*?(\d+) root\(s\).*?(\d+) co-product candidate\(s\)')


def parse_log(p):
    total, phases, cache, reads, harvest = None, {}, [], None, None
    try:
        with open(p, encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip('\r\n')
                m = STAMP.match(line)
                if m:
                    total = float(m.group(1))
                m = PHASE.match(line)
                if m:
                    phases.setdefault(m.group(1), []).append(float(m.group(2)))
                m = CACHE.match(line)
                if m:
                    h = re.search(r'\bhits=(\d+)', m.group(2))
                    cache.append({'kind': m.group(1), 'hits': int(h.group(1)) if h else None})
                m = TOTAL.match(line)
                if m:
                    r = MSI_READS.search(m.group(1))
                    reads = int(r.group(1)) if r else 0
                m = HSUM.match(line)
                if m:
                    harvest = {'roots': int(m.group(1)), 'coproducts': int(m.group(2))}
    except OSError:
        return None
    return {'total': total, 'phases': phases, 'cache': cache, 'msi_reads': reads, 'harvest': harvest}


K14_ROWS = ('budget runs', 'reference walks per scan', 'added scan time', 'added harvest time', 'ownership.components',
            'ownership.tables', 'warm MSI table cache', 'like for like')
if bud is None:
    for what in K14_ROWS:
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
    # review R5 B3: the cold harvest fills the disk cache, so the cache is moved aside before EACH cold M1b step
    # (rig.ps1 cold_cache_steps); a record without a state for a step (budgets/2) or with 'kept' is not cold
    ccs = bud.get('cold_cache_steps') if isinstance(bud.get('cold_cache_steps'), dict) else {}
    for step in BUDGET_STEPS:
        if ccs.get(step) not in ('moved', 'absent'):
            probs.append(f"m1b {step} cold: cache state {ccs.get(step)} (moved aside before this step, or absent, needed)")
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

    # Ruling 2026-11-18: a warm round must have read the MSI tables from the disk cache. Every warm M1b log shows
    # `msi_table_cache disk` with hits >= 1 and no `memory` line, and reads fewer sys.msi_tables than the cold round of
    # the same step; a missing log, line or count fails.
    wprobs, wnote = [], []
    for step in BUDGET_STEPS:
        cl = logs.get(('m1b', step, 'cold', 1))
        if cl is None or cl['msi_reads'] is None:
            wprobs.append(f'm1b {step} cold: no log or no timing total line')
            continue
        if cl['msi_reads'] <= 0:
            wprobs.append(f'm1b {step} cold: read no sys.msi_tables (nothing to be warm against: the cold round was '
                          'warm, e.g. the cache the cold harvest filled was not moved aside before the cold scan)')
        for n in BUDGET_ROUNDS[1:]:
            wl = logs.get(('m1b', step, 'warm', n))
            if wl is None:
                wprobs.append(f'm1b {step} round {n}: no log')
                continue
            kinds = [c['kind'] for c in wl['cache']]
            disk = [c for c in wl['cache'] if c['kind'] == 'disk']
            if not wl['cache']:
                wprobs.append(f'm1b {step} round {n}: no msi_table_cache line (cache not on disk)')
            elif 'disk' not in kinds or any(k != 'disk' for k in kinds):
                wprobs.append(f"m1b {step} round {n}: msi_table_cache {'/'.join(kinds)}, not disk")
            elif not all(isinstance(c['hits'], int) and c['hits'] >= 1 for c in disk):
                wprobs.append(f"m1b {step} round {n}: disk cache with hits {[c['hits'] for c in disk]}")
            if wl['msi_reads'] is None:
                wprobs.append(f'm1b {step} round {n}: no timing total line')
            elif wl['msi_reads'] >= cl['msi_reads']:
                wprobs.append(f"m1b {step} round {n}: read {wl['msi_reads']} sys.msi_tables, the cold round {cl['msi_reads']}")
            else:
                wnote.append(f"{step} r{n} {wl['msi_reads']}/{cl['msi_reads']}")
    row('K14', 'G7', 'warm MSI table cache', f'{len(wprobs)} problem(s)',
        'every warm m1b log: msi_table_cache disk (hits >= 1), fewer sys.msi_tables than cold', not wprobs,
        '; '.join(wprobs[:4]) or ('sys.msi_tables warm/cold: ' + ', '.join(wnote)))

    # Ruling 2026-11-18 (G7 like for like): both engines' harvest of the program reports an install root, the same
    # root count in every round, and no co-product candidate (PuTTY: no root for the M2 head, which then skipped the
    # anchor pass the M1b engine ran).
    lprobs, roots = [], {}
    for e in BUDGET_ENGINES:
        for n in BUDGET_ROUNDS:
            hl = logs.get((e, 'harvest', 'cold' if n == 1 else 'warm', n))
            hv = (hl or {}).get('harvest')
            if not hv:
                lprobs.append(f'{e} harvest round {n}: no harvest summary line')
                continue
            roots.setdefault(e, set()).add(hv['roots'])
            if hv['coproducts'] != 0:
                lprobs.append(f"{e} harvest round {n}: {hv['coproducts']} co-product candidate(s)")
    allroots = set().union(*roots.values()) if roots else set()
    if len(allroots) != 1 or set(roots) != set(BUDGET_ENGINES) or min(allroots or {0}) < 1:
        lprobs.append('root counts ' + ', '.join(f'{e} {sorted(v)}' for e, v in sorted(roots.items())) + ' (need the same count >= 1)')
    row('K14', 'G7', 'like for like', 'like for like' if not lprobs else 'not like for like',
        'both engines: same install root count >= 1, 0 co-product candidates', not lprobs,
        '; '.join(lprobs[:4]) or f"program {bud.get('program')}: {sorted(allroots)[0]} root(s) for both engines")


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
       'apps': apps, 'dirty_apps': dirty_apps, 'cp_apps': cp_apps, 'sets': sets, 'trap_runs': trap_runs,
       'inputs': {'traps_sha256': traps_now, 'deny_sha256': deny_now, 'labels': manifest.get('labels'), 'frozen': manifest.get('frozen'),
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
  pyeval evaluate "$1" "$2" "$APPS" "$DIRTY_APPS" "$CP_APPS" "$SETS" "$TRAP_RUNS" "$CONFIG" "$CONFIG_VARS" "${3:-evaluate}" "$HERE"
}

# rigtool_check: review R5 S1. collect and replay score with $R only when it was built from vm/rigtool as committed
# at HEAD: `$R version` reports the SHA-256 of the sources it was built from (build.rs), which must equal the tree's
# (pyeval rigtoolsrc), and vm/rigtool must not differ from HEAD (git status, $GIT as in replay). Otherwise it prints
# why and returns 2 (nothing is collected). The two hashes go into the manifest; BIND checks them again.
RT_SRC=$HERE/../rigtool
RT_SRC_SHA=""; RT_TREE_SHA=""
rigtool_check() {
  local gt st
  read -r -a gt <<<"${GIT:-git}"
  RT_TREE_SHA=$(pyeval rigtoolsrc "$RT_SRC") || { echo "m1b: cannot hash the rigtool sources in $RT_SRC" >&2; return 2; }
  RT_SRC_SHA=$("$R" version 2>/dev/null | sed -n 's/.*source-sha256 \([0-9a-f]\{64\}\).*/\1/p')
  local fix="rebuild it: (cd vm/rigtool && cargo build --release)"
  if [ -z "$RT_SRC_SHA" ]; then
    echo "m1b: $R does not report the sources it was built from (built before review R5, or not rigtool): $fix" >&2; return 2
  fi
  if [ "$RT_SRC_SHA" != "$RT_TREE_SHA" ]; then
    echo "m1b: $R was built from other sources than vm/rigtool now (source-sha256 $RT_SRC_SHA, tree $RT_TREE_SHA): $fix" >&2
    return 2
  fi
  if ! st=$("${gt[@]}" -C "$RT_SRC" status --porcelain -- . 2>/dev/null); then
    echo "m1b: cannot tell whether vm/rigtool differs from HEAD (git status failed)" >&2; return 2
  fi
  if [ -n "$st" ]; then
    echo "m1b: vm/rigtool differs from HEAD; score only with a rigtool built from committed sources:" >&2
    echo "$st" | head -5 >&2; return 2
  fi
  return 0
}

# plan_actions <plan> <scan sidecar> <out>: the plan with each item's action from its scan sidecar (as m1a.sh step 3),
# and its `suggest_uninstall` (the evidence fact of SYS-BURNDEPS rule (c)) when it has one: rigtool score counts a
# ReportOnly item with it as a notice, not an offer (user ruling 2026-11-18, review R5 B1).
plan_actions() {
  "$PY" -I - "$1" "$2" "$3" <<'EOF'
import json, os, sys
plan_f, scan_f, out_f = sys.argv[1:4]
with open(plan_f, encoding='utf-8-sig') as f:
    plan = json.load(f)
key = lambda t: json.dumps({k: (str(v).lower() if k != 'type' else v) for k, v in sorted(t.items())})


def suggest_of(it):
    for ev in it.get('evidence') or []:
        v = (ev.get('detail') or {}).get('suggest_uninstall') if isinstance(ev, dict) and isinstance(ev.get('detail'), dict) else None
        if isinstance(v, str) and v.strip():
            return v
    return None


if os.path.isfile(scan_f):
    with open(scan_f, encoding='utf-8-sig') as f:
        scan = json.load(f)
    by = {}
    for it in scan.get('items', []):
        by.setdefault(key(it['target']), []).append((it.get('action'), suggest_of(it)))
    for it in plan.get('items', []):
        acts = by.get(key(it['target'])) or []
        it.pop('suggest_uninstall', None)
        if acts:
            it['action'], sg = acts.pop(0)
            if sg is not None:
                it['suggest_uninstall'] = sg
with open(out_f, 'w', encoding='utf-8') as f:
    json.dump(plan, f, indent=2, ensure_ascii=False)
EOF
}

# ------------------------------------------------------------------------------------------- G1 replay
# replay (review R4c S2): G1 as one command, run from vm/ on the host before collect. It rewrites $REPLAY_DIFF
# (cargo xtask replay-diff; K16 judges it), replays each of the five frozen runs (the M0 runs and 7-Zip, git-ignored:
# $PURGE_RUNS_DIR, else $M1B_RUNS) with this checkout's engine (cargo xtask replay) into $RUNS/m1b-replay/<id>/
# (git-ignored; the run's snaps, lists and run.json copied, the committed frozen truth truth/frozen/<id>/truth.json, the plan with its
# sidecar actions as plans/purge.json; the run directory itself is not touched), scores them with rigtool score
# --classes and writes $REPLAY_SCORE with a `replay` block (purge.rig.m1b-replay/1: the runs, HEAD, whether the engine
# sources differ from HEAD, the frozen truths' SHA-256), which BIND checks against the gate's runs. A run that cannot
# be replayed is left out (exit 1); K4 G1 then fails, as it needs all five. XTASK (default "cargo xtask") and GIT
# (default git) name the commands (the selftest's stubs).
replay() {
  local src=${PURGE_RUNS_DIR:-$RUNS} stage="$RUNS/m1b-replay" id d s rc=0 commit dirty xt gt drc
  read -r -a xt <<<"${XTASK:-cargo xtask}"; read -r -a gt <<<"${GIT:-git}"
  # review R4d S3: the old diff goes first, so a replay-diff that fails before writing leaves none (K16 FAILs on a
  # missing diff), and the replay block binds the diff this run wrote and replay-diff's exit code (BIND)
  rigtool_check || return 2
  rm -rf "$stage"; mkdir -p "$stage"; rm -f "$REPLAY_SCORE" "$REPLAY_DIFF"
  "${xt[@]}" replay-diff --runs "$src" -o "$REPLAY_DIFF" >&2; drc=$?
  if [ $drc -ne 0 ]; then echo "m1b replay: replay-diff exit $drc: failed or has unexplained rows (K16 judges $REPLAY_DIFF)" >&2; rc=1; fi
  local dirs=()
  for id in $REPLAY_IDS; do
    d="$src/$id"; s="$stage/$id"
    if [ ! -f "$d/run.json" ] || [ ! -f "$HERE/frozen/$id/truth.json" ]; then
      echo "m1b replay: $id: no run $d or no truth/frozen/$id/truth.json" >&2; rc=1; continue
    fi
    mkdir -p "$s/plans"
    cp "$HERE/frozen/$id/truth.json" "$s/truth.json"
    if ! cp "$d/run.json" "$d/snap-$id-0.tsv.gz" "$d/snap-$id-2.tsv.gz" "$s/"; then rc=1; continue; fi
    [ -f "$d/lists-$id-0.json" ] && cp "$d/lists-$id-0.json" "$s/"
    if ! "${xt[@]}" replay --run "$d" --app "$id" -o "$s/replay.json" >&2 || [ ! -f "$s/replay.json" ]; then
      echo "m1b replay: $id: cargo xtask replay failed" >&2; rc=1; continue
    fi
    plan_actions "$s/replay.json" "$s/replay.scan.json" "$s/plans/purge.json" || { rc=1; continue; }
    dirs+=("$s")
  done
  if [ ${#dirs[@]} -eq 0 ] || ! "$R" score --set "${dirs[@]}" --deny "$HERE/deny.json" --classes --json "$REPLAY_SCORE" \
      --md "${REPLAY_SCORE%.json}.md" >&2; then
    echo "m1b replay: rigtool score failed: no $REPLAY_SCORE" >&2; rm -f "$REPLAY_SCORE"; return 1
  fi
  commit=$("${gt[@]}" -C "$HERE" rev-parse HEAD 2>/dev/null) || commit=""
  if dirty=$("${gt[@]}" -C "$HERE/../.." status --porcelain --untracked-files=no -- crates bins tools kb Cargo.toml Cargo.lock \
      rust-toolchain.toml 2>/dev/null); then [ -n "$dirty" ] && dirty=true || dirty=false; else dirty=unknown; fi
  pyeval replaybind "$REPLAY_SCORE" "$HERE" "$REPLAY_IDS" "$commit" "$dirty" "$REPLAY_DIFF" "$drc" || return 1
  echo "m1b replay: ${#dirs[@]} of 5 run(s) scored -> $REPLAY_SCORE" >&2
  return $rc
}

# ------------------------------------------------------------------------------------------- stage 1
collect() {
  rigtool_check || return 2
  mkdir -p "$EVID" "$EVID/budgets" "$EVID/runs"
  rm -f "$EVID"/score-*.json "$EVID"/traps-*.json "$EVID"/*-fp.json "$EVID"/*-scan.json "$EVID"/replay-*.json "$EVID"/budgets/* \
        "$EVID"/runs/*.json "$EVID"/truth-*.json "$EVID"/manifest.json
  local s id run d lid p n lmap="" nmap=""
  for s in $SETS; do
    p=$(prefix_of "$s")
    # 0. ambient from this set's null runs
    local nulls=()
    for n in 1 2 3; do
      d="$RUNS/$p-null$n"
      if [ -f "$d/run.json" ] && ls "$d/snap-$p-null$n-0.tsv.gz" "$d/snap-$p-null$n-2.tsv.gz" >/dev/null 2>&1; then
        nulls+=("$d"); nmap="$nmap $p-null$n"; pyeval runsum "$d" "$p-null$n" "$EVID/runs/$p-null$n.json"
      fi
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
          --ambient "$amb" --labels "truth/labels/$lid.json" "${M1B_TRUTH_LABELS[@]}" --deny truth/deny.json -o "$d/truth.json" >&2; then
        echo "m1b: $run: rigtool truth failed" >&2; continue
      fi
      # the kept product's objects from before snap 0 (label file `prestate`; RIG.md section 12.4)
      if ! pyeval prestate "$d/truth.json" "$d/snap-$run-0.tsv.gz" "$d/snap-$run-2.tsv.gz" "$d/lists-$run-0.json" \
          "$d/lists-$run-2.json" "truth/labels/$lid.json"; then
        echo "m1b: $run: prestate failed" >&2; rm -f "$d/truth.json"; continue
      fi
      mkdir -p "$d/plans"
      if [ -f "$d/plan-purge.json" ]; then
        plan_actions "$d/plan-purge.json" "$d/plan-purge.scan.json" "$d/plans/purge.json"
      else echo "m1b: $run: no plan-purge.json" >&2; fi
      cp "$d/truth.json" "$EVID/truth-$s-$id.json"   # SANITY (review R4c S4)
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
    "$HERE" "$CONFIG" "$CONFIG_VARS" "$R" "${nmap# }" "$RT_SRC_SHA" "$RT_TREE_SHA"
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
    pyeval manifest "$1/manifest.json" runs "$DEF_SETS" m1b m1bd m1bcp "$("$PY" -I "$fx" labelmap)" "$1/truth" default "" rigtool \
      "$("$PY" -I "$fx" nullmap)" "$(printf '7%.0s' {1..64})" "$(printf '7%.0s' {1..64})"
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
      "no_safe_7zip K4" \
      "replay_score_run_missing K4" "replay_score_7zip_only K4" "replay_score_no_block BIND" \
      "replay_score_other_commit BIND" "replay_score_dirty BIND" "replay_score_frozen_changed BIND" \
      "inputs_missing BIND" "inputs_dirty BIND" "inputs_two_sets BIND" "inputs_changed_in_campaign BIND" \
      "inputs_traps_edited_before BIND" "inputs_label_edited_before BIND" \
      "sanity_relabelled SANITY" "sanity_truth_missing SANITY" "sanity_run_only PASS" "sanity_frozen_only PASS" \
      "nulls_too_few RUN" "null_phase_failed RUN" \
      "k1_blocked_denylisted PASS" "k1_danger_likely K1" "k1_danger_safe K1" "k1_danger_likely_beside_kept K1" \
      "k1_counts_disagree K1" "k1_counts_missing K1" "k8_vcredist_danger_likely K8" "k8_vcredist_blocked PASS" \
      "run_target_preinstalled RUN" "run_no_entry_created RUN" "run_lists0_unreadable RUN" "run_target_unknown RUN" \
      "trap_main_is_pre RUN" "trap_main_not_created RUN" \
      "sanity_ambient_same_name PASS" "sanity_ambient_only_same_name PASS" "sanity_relabelled_by_name SANITY" \
      "sanity_frozen_unreadable SANITY" \
      "deny_changed BIND" "inputs_deny_edited_before BIND" "inputs_no_deny BIND" "inputs_frozen_edited_before BIND" \
      "replay_diff_unbound BIND" "replay_diff_failed BIND" "replay_diff_missing K16" \
      "replay_score_empty_plan K4" "replay_score_no_counts K4" \
      "budget_cache_memory K14" "budget_cache_line_missing K14" "budget_cache_no_hits K14" "budget_warm_reads_tables K14" \
      "budget_not_like_for_like K14" "budget_coproduct K14" "budget_no_harvest_line K14" \
      "rigtool_unbound BIND" "rigtool_no_source BIND" \
      "k1_blocked_not_denylisted K1" "k1_blocked_no_scan_item K1" "k1_blocked_no_scan K1" "k8_vcredist_blocked_too_large K8" \
      "k8_suggestion_not_a_notice K8" "k8_notices_missing K8" "k8_suggestion_not_report_only K8" "k8_cp_no_suggestion K8" \
      "k8_dirty_python_suggestion K8" "k8_dirty_launcher_offered K8" "k8_dirty_launcher_blocked PASS" \
      "budget_cold_scan_warm K14" "budget_cold_scan_not_moved K14" "budget_cold_steps_missing K14"; do
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

  # Review R4c S2: `m1b.sh replay` (G1) writes the replay score from the five frozen runs, with stub cargo xtask,
  # rigtool and git: the gate passes with that file, the frozen runs' own plans/ stay untouched, and a run that cannot
  # be replayed makes the step exit 1 and K4 G1 fail.
  mkdir -p "$tmp/bin"
  printf '#!/usr/bin/env bash\nexec "%s" -I "%s" xtask "%s" "$@"\n' "$PY" "$fx" "$HERE" >"$tmp/bin/xtask"
  printf '#!/usr/bin/env bash\nexec "%s" -I "%s" rigtool "$@"\n' "$PY" "$fx" >"$tmp/bin/rigtool"
  printf '#!/usr/bin/env bash\nexec "%s" -I "%s" git "$@"\n' "$PY" "$fx" >"$tmp/bin/git"
  chmod +x "$tmp/bin/"*
  local rv want_rc want_gate
  STUB_RIGTOOL_SHA=$(pyeval rigtoolsrc "$RT_SRC"); export STUB_RIGTOOL_SHA
  # Review R4d S3: the replay block binds the diff the step wrote (sha256) and replay-diff's exit code; a replay-diff
  # that fails before writing leaves no diff behind (the stale one is deleted first): K16 and BIND fail.
  for rv in all npp difffail; do
    if [ $rv = all ]; then want_rc=0; want_gate=0; else want_rc=1; want_gate=1; fi
    "$PY" -I "$fx" replayruns "$tmp/rr" "$([ $rv = npp ] && echo npp)"
    rm -rf "$tmp/rp-$rv"; mkdir -p "$tmp/rp-$rv"; echo '{"stale": true}' >"$tmp/rp-$rv/diff.json"
    (OUT="$tmp/rp-$rv"; HERE="$tmp/fx/truth"; RUNS="$tmp/rr"; unset PURGE_RUNS_DIR; R="$tmp/bin/rigtool"; XTASK="$tmp/bin/xtask"
     GIT="$tmp/bin/git"; REPLAY_SCORE="$tmp/rp-$rv/score.json"; REPLAY_DIFF="$tmp/rp-$rv/diff.json"
     if [ $rv = difffail ]; then export STUB_DIFF_FAIL=1; fi; replay) >"$tmp/rp.txt" 2>&1; rc=$?
    rm -rf "$tmp/m"; cp -r "$tmp/fx" "$tmp/m"; rm -f "$tmp/m/replay-score.json" "$tmp/m/replay-diff.json"
    [ -f "$tmp/rp-$rv/score.json" ] && cp "$tmp/rp-$rv/score.json" "$tmp/m/replay-score.json"
    [ -f "$tmp/rp-$rv/diff.json" ] && cp "$tmp/rp-$rv/diff.json" "$tmp/m/replay-diff.json"
    eval_gate "$tmp/m" "$tmp/m.json" >"$tmp/m.out" 2>&1; local grc=$?
    if [ $rc -eq $want_rc ] && [ $grc -eq $want_gate ] && "$PY" -I - "$tmp/rp-$rv/score.json" "$tmp/rr" "$tmp/m.json" "$rv" "$tmp/rp-$rv/diff.json" <<'EOF'
import hashlib, json, os, sys
rv = sys.argv[4]
s = json.load(open(sys.argv[1], encoding='utf-8'))
want = ['vscode', 'git', 'firefox', '7zip'] if rv == 'npp' else ['vscode', 'git', 'firefox', 'npp', '7zip']
assert sorted(a['id'] for a in s['apps']) == sorted(want), [a['id'] for a in s['apps']]
rb = s['replay']
assert rb['schema'] == 'purge.rig.m1b-replay/1' and rb['commit'] == 'c' * 40 and rb['source_dirty'] is False, rb
assert all(not os.listdir(os.path.join(sys.argv[2], a, 'plans')) for a in want), 'the step wrote into a frozen run'
g = json.load(open(sys.argv[3], encoding='utf-8'))
k4 = [r for r in g['criteria'] if r['id'] == 'K4' and r['step'] == 'G1']
assert len(k4) == 5, k4
failed = lambda i: [r for r in g['criteria'] if r['id'] == i and not r['pass']]
if rv == 'difffail':
    assert not os.path.exists(sys.argv[5]), 'the stale diff survived a failed replay-diff'
    assert rb['diff_sha256'] is None and rb['diff_exit'] not in (0, None), rb
    assert failed('K16') and failed('BIND') and not g['gate'], 'a failed replay-diff passed'
else:
    assert rb['diff_exit'] == 0 and rb['diff_sha256'] == hashlib.sha256(open(sys.argv[5], 'rb').read()).hexdigest(), rb
if rv == 'all':
    assert g['gate'] and all(r['pass'] for r in k4)
elif rv == 'npp':
    assert [r['subject'] for r in k4 if not r['pass']] == ['replay/npp'], k4
EOF
    then ok_ "replay_step_writes_score_$rv"; else no_ "replay_step_writes_score_$rv" "step exit $rc, gate exit $grc: $(tail -2 "$tmp/rp.txt")"; fi
  done

  # Ruling 2026-11-18 (RUN): runsum records the target ARP entry against lists-0; the evaluator rejects a run whose
  # target was already there (the dirty-base node run) or that created no entry.
  "$PY" -I "$fx" targetruns "$tmp/tr" && pyeval runsum "$tmp/tr/m1bd-node" m1bd-node "$tmp/tr/node.json" \
    && pyeval runsum "$tmp/tr/m1bd-temurin" m1bd-temurin "$tmp/tr/temurin.json"; rc=$?
  if [ $rc -eq 0 ] && "$PY" -I - "$tmp/tr/node.json" "$tmp/tr/temurin.json" <<'EOF'
import json, sys
n, t = (json.load(open(p, encoding='utf-8'))['target'] for p in sys.argv[1:3])
assert n['in_lists0'] is True and n['entries_created'] == [], n
assert t['in_lists0'] is False and t['entries_created'] == [t['main_key']], t
EOF
  then ok_ runsum_target_against_lists0; else no_ runsum_target_against_lists0 "exit $rc"; fi
  # Review R5 S1: collect and replay refuse (exit 2) a rigtool that is not built from vm/rigtool at HEAD: a binary that
  # reports other sources, none (built before R5), or a vm/rigtool that differs from HEAD; one built from it passes.
  local rk want_k got_k
  for rk in ok other none dirty; do
    case $rk in ok) want_k=0 ;; *) want_k=2 ;; esac
    (R="$tmp/bin/rigtool"; GIT="$tmp/bin/git"
     case $rk in other) export STUB_RIGTOOL_SHA=$(printf '0%.0s' {1..64}) ;; none) export STUB_RIGTOOL_SHA= ;; dirty) export STUB_GIT_DIRTY=1 ;; esac
     rigtool_check) >"$tmp/rk.txt" 2>&1; got_k=$?
    if [ $got_k -eq $want_k ] && { [ $rk = ok ] || grep -q 'rigtool\|vm/rigtool' "$tmp/rk.txt"; }; then ok_ "rigtool_check_$rk"
    else no_ "rigtool_check_$rk" "exit $got_k: $(head -c 300 "$tmp/rk.txt")"; fi
  done
  (R="$tmp/bin/rigtool"; GIT="$tmp/bin/git"; EVID="$tmp/ev-refused"; export STUB_RIGTOOL_SHA=$(printf '0%.0s' {1..64}); collect) >/dev/null 2>&1; rc=$?
  if [ $rc -eq 2 ] && [ ! -e "$tmp/ev-refused" ]; then ok_ collect_refuses_a_stale_rigtool; else no_ collect_refuses_a_stale_rigtool "exit $rc"; fi
  # Review R5 B1: plan_actions copies the action and, only where the scan item's evidence has it, suggest_uninstall
  "$PY" -I "$fx" planactions "$tmp/pa" && plan_actions "$tmp/pa/plan.json" "$tmp/pa/scan.json" "$tmp/pa/out.json"; rc=$?
  if [ $rc -eq 0 ] && "$PY" -I - "$tmp/pa/out.json" <<'EOF'
import json, sys
p = json.load(open(sys.argv[1], encoding='utf-8'))
got = [(i['target']['path'].rsplit('\\', 1)[-1], i.get('action'), i.get('suggest_uninstall')) for i in p['items']]
assert got == [('{73831AC2-F0E1-4173-9FDB-D07463D7EB80}', 'ReportOnly', 'Python Launcher (64-bit)'),
               ('Python312', 'DeleteKey', None), ('STALE', 'ReportOnly', None)], got
EOF
  then ok_ plan_actions_copies_the_suggestion; else no_ plan_actions_copies_the_suggestion "exit $rc"; fi
  # Trap runs judge TrapA only (coordinator ruling 2026-11-18): a dirty trap run whose TrapB (pre-app node) is in
  # lists-0 and TrapA is new passes RUN; TrapA already in lists-0, or a main entry that is TrapB's, is INVALID.
  local tv want_t
  for tv in trapok trapa0 trappre trapnopre trapemptypre; do
    if [ $tv = trapok ]; then want_t=0; else want_t=1; fi
    rm -rf "$tmp/m"; cp -r "$tmp/fx" "$tmp/m"
    if pyeval runsum "$tmp/tr/$tv/m1bd-traps-7zip" m1bd-traps-7zip "$tmp/tr/$tv.json" \
       && "$PY" -I "$fx" settarget "$tmp/m" m1bd-traps-7zip "$tmp/tr/$tv.json"; then
      eval_gate "$tmp/m" "$tmp/m.json" >"$tmp/m.out" 2>&1; rc=$?
    else rc=99; fi
    if [ $rc -eq $want_t ] && "$PY" -I - "$tmp/m.json" "$tv" <<'EOF'
import json, sys
g = json.load(open(sys.argv[1], encoding='utf-8'))
r = [x for x in g['criteria'] if x['id'] == 'RUN' and x['subject'] == 'm1bd-traps-7zip']
assert len(r) == 1, r
if sys.argv[2] == 'trapok':
    assert r[0]['pass'] and g['gate'], r
else:
    assert not r[0]['pass'] and 'INVALID RUN' in (r[0].get('note') or ''), r
    assert [x['subject'] for x in g['criteria'] if not x['pass']] == ['m1bd-traps-7zip'], 'another line failed'
EOF
    then ok_ "trap_run_judges_trapa_$tv"; else no_ "trap_run_judges_trapa_$tv" "exit $rc: $(grep FAIL "$tmp/m.out" | head -2)"; fi
  done

  # Churn rule (RIG.md section 12.6): an item in one freeze run only is excluded from the frozen truth and reported,
  # never frozen as a leftover; a label that differs between the runs and a run that is not whole refuse the freeze.
  "$PY" -I "$fx" churn "$tmp/ch" ok && pyeval freezecmp fx "$tmp/ch/m1b-fz1-fx" "$tmp/ch/m1b-fz2-fx" "$tmp/ch/out" fixture >"$tmp/ch.txt" 2>&1; rc=$?
  if [ $rc -eq 0 ] && "$PY" -I - "$tmp/ch/out/truth.json" "$tmp/ch/out/truth-fz2.json" <<'EOF'
import json, sys
t1, t2 = (json.load(open(p, encoding='utf-8')) for p in sys.argv[1:3])
WU = 'windowsupdate\\orchestrator'
for t in (t1, t2):
    labs = {i['target']['path'].lower(): i['label'] for i in t['items']}
    assert not any(WU in k for k in labs), 'the one-run Windows churn item is still in a frozen truth'
    assert any(k.endswith('software\\fixture') and v == 'leftover' for k, v in labs.items()), 'the leftover of both runs is lost'
    assert any('\\temp\\msi' in k for k in labs), 'the random-named temp leftover (normalised) is lost'
    ex = t['freeze']['excluded']
    assert len(ex) == 1 and WU in ex[0]['target']['path'].lower() and ex[0]['label_in_run'] == 'leftover', ex
    assert t['counts'].get('leftover') == 2, t['counts']
EOF
  then ok_ churn_one_run_item_excluded_not_leftover; else no_ churn_one_run_item_excluded_not_leftover "exit $rc: $(tail -2 "$tmp/ch.txt")"; fi
  local v_
  for v_ in mismatch broken; do
    "$PY" -I "$fx" churn "$tmp/ch" "$v_" && pyeval freezecmp fx "$tmp/ch/m1b-fz1-fx" "$tmp/ch/m1b-fz2-fx" "$tmp/ch/out" fixture >"$tmp/ch.txt" 2>&1; rc=$?
    if [ $rc -eq 1 ] && [ ! -e "$tmp/ch/out" ]; then ok_ "churn_freeze_refuses_$v_"; else no_ "churn_freeze_refuses_$v_" "exit $rc"; fi
  done
  # The noise list labels ambient only, under Windows-owned roots, matches the churn it was written for, and no
  # leftover / user_data / kept_owner item of any frozen truth (M0 and M1b) or a prefetch / jump-list rule of the apps.
  if "$PY" -I - "$HERE/labels/_m1b-noise.json" "$HERE/frozen" <<'EOF'
import glob, json, os, re, sys
noise = json.load(open(sys.argv[1], encoding='utf-8'))
rules = noise['rules']
assert rules and noise.get('samples'), 'no rules or no recorded churn samples'
# the rule body after its kind prefix (^[KVC]: / ^P: ...) must start under one of these Windows-owned roots
ROOTS = (r'HKLM\\SOFTWARE\\Microsoft\\', r'HKLM\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\', r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\',
         r'HKU\\(?:S-1-5-21-[0-9-]+_Classes|\.DEFAULT\\Software\\Classes)\\Local Settings\\MuiCache\\',
         r'HKU\\[^\\]+\\Software\\Microsoft\\Windows\\', r'HKU\\[^\\]+_Classes\\Local Settings\\Software\\Microsoft\\Windows\\',
         r'C:\\ProgramData\\Microsoft\\', r'C:\\Windows\\')
for r in rules:
    assert r['label'] == 'ambient' and not r.get('first') and not r.get('split'), r
    body = re.sub(r'^\^(\[[KVCP]+\]|[KVCP]):', '', r['match'])
    assert body != r['match'] and any(body.startswith(x) for x in ROOTS), f"not under a Windows-owned root: {r['match']}"
rx = [re.compile(r['match'], re.I) for r in rules]
miss = [s for s in noise['samples'] if not any(x.search(s) for x in rx)]
assert not miss, f'churn samples no noise rule matches: {miss[:3]}'
hit = []
for p in glob.glob(os.path.join(sys.argv[2], '*', 'truth.json')):
    t = json.load(open(p, encoding='utf-8-sig'))
    for i in t.get('items', []):
        if i.get('label') in ('leftover', 'user_data', 'kept_owner'):
            ty, tg = i['target'].get('type'), i['target']
            c = {'Path': 'P:', 'RegKey': 'K:', 'RegValue': 'V:', 'RegValueChanged': 'C:'}.get(ty, '?:') + tg.get('path', '') + (('|' + (tg.get('name') or '')) if ty in ('RegValue', 'RegValueChanged') else '')
            if any(x.search(c) for x in rx):
                hit.append(f'{os.path.basename(os.path.dirname(p))}: {c}')
assert not hit, f'noise rules match real truth items: {hit[:3]}'
for c in ('P:C:\\Windows\\Prefetch\\PWSH.EXE-0A1B2C3D.pf', 'P:C:\\Program Files\\PowerShell\\7\\pwsh.exe',
          'K:HKLM\\SOFTWARE\\Microsoft\\PowerShellCore', 'P:C:\\Program Files\\Eclipse Adoptium\\jdk-21.0.13.9-hotspot',
          'K:HKLM\\SOFTWARE\\Eclipse Adoptium', 'P:C:\\Users\\rig\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\9d5f66f86ab736a4.automaticDestinations-ms'):
    assert not any(x.search(c) for x in rx), f'a noise rule matches an app object: {c}'
EOF
  then ok_ churn_noise_list_windows_owned_and_never_an_app_item; else no_ churn_noise_list_windows_owned_and_never_an_app_item; fi

  # K5 pre-state (RIG.md section 12.4): the kept launcher's objects from before snap 0 become kept_owner truth items,
  # top-most, never one that holds a leftover, never one gone by snap 2, product rules only for a launcher in both lists.
  "$PY" -I "$fx" prestate "$tmp/ps" "$HERE" && pyeval prestate "$tmp/ps/m1b-python312-with-313/truth.json" \
    "$tmp/ps/m1b-python312-with-313/snap-m1b-python312-with-313-0.tsv.gz" "$tmp/ps/m1b-python312-with-313/snap-m1b-python312-with-313-2.tsv.gz" \
    "$tmp/ps/m1b-python312-with-313/lists-m1b-python312-with-313-0.json" "$tmp/ps/m1b-python312-with-313/lists-m1b-python312-with-313-2.json" \
    "$tmp/ps/labels.json" >"$tmp/ps.txt" 2>&1; rc=$?
  if [ $rc -eq 0 ] && "$PY" -I - "$tmp/ps/m1b-python312-with-313/truth.json" <<'EOF'
import json, sys
t = json.load(open(sys.argv[1], encoding='utf-8'))
kept = sorted(i['target']['path'].lower() for i in t['items'] if i['label'] == 'kept_owner')
assert t['counts'] == {'ambient': 2, 'kept_owner': 10, 'leftover': 1}, t['counts']
assert sorted(p.lower() for p in t['temp_packages']) == ['c:\\windows\\installer\\7777.msi', 'c:\\windows\\installer\\8888.msi'], t['temp_packages']
assert not any('.pyw' in k or '.pyz' in k or '9999.msi' in k or 'pythoncore' in k for k in kept), kept
assert any(k.endswith('installer\\dependencies\\cpython-3.13_launcher') for k in kept) and any('4f2a.msi' in k for k in kept), kept
assert [o['object'] for o in t['prestate']['opened']] == ['K:HKLM\\SOFTWARE\\Classes\\.pyw'], t['prestate']['opened']
assert [p['code'] for p in t['prestate']['products']] == ['1A2B3C4D-0000-1111-2222-333344445555']
EOF
  then ok_ k5_prestate_counts_kept_launcher; else no_ k5_prestate_counts_kept_launcher "exit $rc: $(tail -2 "$tmp/ps.txt")"; fi

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
# gone), msi-remnants 'not_preselected' (Windows Installer reports the re-registered product installed for another
# user, so REG-ARP-MSI cannot offer it: a recall limit, docs/DECISIONS.md M1b R4c S1; a later correct Likely offer must
# not score an escape), svc-svchost 'protected' (REF-ANY lists the ServiceDll value inside the service key, Blocked)
must = {'svc-owned': 'listed', 'task-owned': 'listed', 'fw-owned': 'listed', 'com-owned': 'listed', 'msi-remnants': 'not_preselected',
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
  local app=$1 k d run lid n amb src; lid=$(label_of "$app")
  [ -f "truth/labels/$lid.json" ] || { echo "m1b freeze: no truth/labels/$lid.json" >&2; return 2; }
  # The freeze's ambient set: the M0 set truth/ambient.json plus the null runs of the freeze itself
  # (m1b-fz<k>-null<n>, rig.ps1 -Mode m1b-freeze), as M0 and M1a built theirs from the null runs of the same campaign.
  local nulls=()
  for d in "$RUNS"/m1b-fz[12]-null*; do
    run=$(basename "$d")
    if [ -f "$d/run.json" ] && ls "$d/snap-$run-0.tsv.gz" "$d/snap-$run-2.tsv.gz" >/dev/null 2>&1; then nulls+=("$d"); fi
  done
  amb="$RUNS/m1b-fz-ambient.json"; src="truth/ambient.json"
  if [ ${#nulls[@]} -gt 0 ]; then
    "$R" ambient --null "${nulls[@]}" -o "$RUNS/m1b-fz-ambient-nulls.json" >&2 || { echo "m1b freeze: rigtool ambient failed" >&2; return 2; }
    "$PY" -I - truth/ambient.json "$RUNS/m1b-fz-ambient-nulls.json" "$amb" <<'EOF' || return 2
import json, sys
a, b, out = sys.argv[1:4]
A, B = (json.load(open(p, encoding='utf-8-sig')) for p in (a, b))
doc = {'schema': A.get('schema'), 'runs': A['runs'] + B['runs'], 'exact': sorted(set(A['exact']) | set(B['exact'])),
       'patterns': sorted(set(A['patterns']) | set(B['patterns']))}
json.dump(doc, open(out, 'w', encoding='utf-8'), indent=1)
EOF
    src="truth/ambient.json + $(for x in "${nulls[@]}"; do printf '%s ' "$(basename "$x")"; done)"; src=${src% }
  else
    echo "m1b freeze: no freeze null runs ($RUNS/m1b-fz<k>-null<n>): ambient = truth/ambient.json only" >&2
    cp truth/ambient.json "$amb"
  fi
  for k in 1 2; do
    run="m1b-fz$k-$app"; d="$RUNS/$run"
    [ -f "$d/run.json" ] || { echo "m1b freeze: no run $d (rig.ps1 -Mode m1b-freeze)" >&2; return 2; }
    "$R" truth --s0 "$d/snap-$run-0.tsv.gz" --s1 "$d/snap-$run-1.tsv.gz" --s2 "$d/snap-$run-2.tsv.gz" \
      --lists0 "$d/lists-$run-0.json" --lists2 "$d/lists-$run-2.json" --run "$d/run.json" \
      --ambient "$amb" --labels "truth/labels/$lid.json" "${M1B_TRUTH_LABELS[@]}" \
      --deny truth/deny.json -o "$d/truth.json" >&2 \
      || { echo "m1b freeze: rigtool truth failed for $run" >&2; return 2; }
    pyeval prestate "$d/truth.json" "$d/snap-$run-0.tsv.gz" "$d/snap-$run-2.tsv.gz" "$d/lists-$run-0.json" \
      "$d/lists-$run-2.json" "truth/labels/$lid.json" || return 2
  done
  pyeval freezecmp "$app" "$RUNS/m1b-fz1-$app" "$RUNS/m1b-fz2-$app" "truth/frozen/$app" "$src" || return 1
  echo "m1b freeze: truth/frozen/$app written; describe it in truth/FROZEN.md (M1b section)"
}

case "${1:-}" in
  --selftest) selftest; exit $? ;;
  --config) if [ "$CONFIG" = default ]; then echo default; else echo "custom $CONFIG_VARS"; fi; exit 0 ;;
  freeze) [ -n "${2:-}" ] || { echo "m1b: freeze needs an app id" >&2; exit 2; }; freeze "$2"; exit $? ;;
  replay) replay; exit $? ;;
  --evaluate) [ -n "${2:-}" ] || { echo "m1b: --evaluate needs an evidence dir" >&2; exit 2; }
              evaluate "$2" "$OUT/m1b-score.json" evaluate; exit $? ;;
  "") collect || exit $?; evaluate "$EVID" "$OUT/m1b-score.json" gate; exit $? ;;
  *) echo "m1b: unknown argument $1 (--selftest, --evaluate DIR, --config, freeze APP, replay, or nothing)" >&2; exit 2 ;;
esac
