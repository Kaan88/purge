#!/usr/bin/env bash
# win-unit: run the workspace's Rust test binaries, cross-built on the Linux host with cargo-xwin
# (x86_64-pc-windows-msvc), inside a real Windows rig VM (vm/RIG.md section 10). For tests that wine cannot
# judge: live Win32 APIs, registry links and ACLs, junctions, locked files, and the M2 executor.
#
#   bash vm/win-unit.sh [options]
#
# Build (bundle):
#   --name N            results/bundle name (default unit-<yyyymmdd-HHMMSS>)
#   -p CRATE            package to build (repeatable; default --workspace)
#   --features F        a feature set, e.g. "write" or "fault-inject,test-support" (repeatable: one build per set;
#                       default one build without --features)
#   --target-dir D      cargo target dir (default ~/purge-target/win-unit-target; never the repo's target/)
#   --bundle-only       build the bundle and stop
#   --bundle DIR        skip the build and run an existing bundle (DIR/manifest.json)
# Run:
#   --vm VM             Inbound-Win11-Test (default) or Purge-CleanPro
#   --snapshot S        snapshot to restore (default rig-base); the VM is restored to it again at the end
#   --threads N         libtest --test-threads (default 4: the rig VMs have 4 vCPUs)
#   --filter F          libtest filter for the unelevated pass (default: all tests)
#   --elevated          a second pass through the elevated rig agent ...
#   --elevated-args A   ... with these libtest arguments (default "--include-ignored"); tests whose #[ignore]
#                       says "needs ..." (PURGE_RUNS_DIR, PURGE_INNO_FIXTURES) are --skip'ped there and listed
#   --timeout-bin S     per test binary timeout in the guest (default 1800 s)
#   --expected FILE     extra "expected to differ from wine" entries (<crate_ident>::<test path> per line);
#                       default: the KNOWN list of ~/purge-target/ci-linux.sh plus ~/purge-target/ci-linux-known.txt
# Output: --out DIR (default ~/purge-target/win-unit/<name>/): bundle/, guest/<pass>/<binary>.txt (libtest output),
#   guest/<pass>/results.json, report.md, report.json, console.log.
# Exit: 0 every binary ran and no test failed; 1 a test failed or a binary crashed/timed out; 2 refused or setup
#   error (build failed, VM busy, lock held, low memory).
#
# Fixtures: test binaries resolve files through env!("CARGO_MANIFEST_DIR"), baked in at build time as
# /mnt/C/.../purge/<crate>. On Windows a path starting with '/' is rooted on the current drive, so the bundle
# mirrors the files tests read (every package's tests/ dir, kb/, vm/truth/deny.json, vm/runs/npp/lists-npp-2.json)
# under C:<repo path> in the guest and runs each binary with that mirrored package dir as working directory (as
# cargo test does). A file missing from the mirror makes its test fail (they unwrap/expect the read); the one test
# that tolerates a missing file (purge-scan fs::appx, vm/runs/npp/lists-npp-2.json) gets its file mirrored.
#
# Lock: the per-VM flock of ~/purge-target/campaigns (.lock-<VM>), so a run never overlaps a campaign on that VM.
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
NAME=unit-$(date +%Y%m%d-%H%M%S)
PKGS=()
FEATS=()
TDIR=$HOME/purge-target/win-unit-target
BUNDLE_ONLY=0
BUNDLE=
VM=Inbound-Win11-Test
SNAP=rig-base
THREADS=4
FILTER=
ELEV=0
ELEV_ARGS=--include-ignored
TBIN=1800
EXPECTED=
OUT=
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift ;;
    -p) PKGS+=("$2"); shift ;;
    --features) FEATS+=("$2"); shift ;;
    --target-dir) TDIR=$2; shift ;;
    --bundle-only) BUNDLE_ONLY=1 ;;
    --bundle) BUNDLE=$2; shift ;;
    --vm) VM=$2; shift ;;
    --snapshot) SNAP=$2; shift ;;
    --threads) THREADS=$2; shift ;;
    --filter) FILTER=$2; shift ;;
    --elevated) ELEV=1 ;;
    --elevated-args) ELEV_ARGS=$2; shift ;;
    --timeout-bin) TBIN=$2; shift ;;
    --expected) EXPECTED=$2; shift ;;
    --out) OUT=$2; shift ;;
    -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
    *) echo "win-unit: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
case "$VM" in Inbound-Win11-Test|Purge-CleanPro) ;; *) echo "win-unit: only the rig VMs Inbound-Win11-Test and Purge-CleanPro" >&2; exit 2 ;; esac
OUT=${OUT:-$HOME/purge-target/win-unit/$NAME}
mkdir -p "$OUT"
exec > >(tee -a "$OUT/console.log") 2>&1
T0=$(date +%s)
log() { echo "[$(date +%H:%M:%S)] win-unit: $*"; }
case "$TDIR" in "$REPO"/*) echo "win-unit: --target-dir must be outside the repo" >&2; exit 2 ;; esac

# ------------------------------------------------------------------------------------------------- bundle
build_bundle() {
  local B=$OUT/bundle
  rm -rf "${B:?}"; mkdir -p "$B/bin"
  export PATH="$HOME/.cargo/bin:$PATH" XWIN_CACHE_DIR=${XWIN_CACHE_DIR:-$HOME/.cache/cargo-xwin} XWIN_ARCH=x86_64
  local sel=(--workspace)
  if [ ${#PKGS[@]} -gt 0 ]; then sel=(); for p in "${PKGS[@]}"; do sel+=(-p "$p"); done; fi
  local sets=("${FEATS[@]}")
  [ ${#sets[@]} -eq 0 ] && sets=("")
  local i=0
  : >"$B/artifacts.jsonl"
  for f in "${sets[@]}"; do
    local fa=()
    [ -n "$f" ] && fa=(--features "$f")
    local ok=0
    for try in 1 2 3 4; do
      log "build: cargo xwin test --no-run ${sel[*]} ${fa[*]} (try $try)"
      if (cd "$REPO" && CARGO_TARGET_DIR=$TDIR nice cargo xwin test "${sel[@]}" "${fa[@]}" --target x86_64-pc-windows-msvc \
            --no-run --message-format=json >"$B/build-$i.json" 2>"$B/build-$i.err"); then ok=1; break; fi
      log "build failed (tail of $B/build-$i.err):"; grep -E '^(error|warning: unused)' "$B/build-$i.err" | head -5
      [ $try -lt 4 ] && sleep 60
    done
    [ $ok = 1 ] || { log "build failed 4 times; see $B/build-$i.err"; return 2; }
    python3 -I - "$B/build-$i.json" "$f" >>"$B/artifacts.jsonl" <<'PY'
import json, sys
src, feats = sys.argv[1:3]
for line in open(src, encoding='utf-8'):
    try:
        j = json.loads(line)
    except ValueError:
        continue
    if j.get('reason') == 'compiler-artifact' and j.get('executable') and j['profile'].get('test'):
        t = j['target']
        print(json.dumps({'package': j['package_id'], 'target': t['name'], 'kind': t['kind'][0], 'features': feats,
                          'exe': j['executable'], 'manifest_path': j['manifest_path']}))
PY
    i=$((i + 1))
  done
  python3 -I - "$B" "$REPO" <<'PY' || return 2
import hashlib, json, os, re, shutil, subprocess, sys, tarfile
B, repo = sys.argv[1:3]
arts, seen = [], set()
for line in open(os.path.join(B, 'artifacts.jsonl'), encoding='utf-8'):
    a = json.loads(line)
    if a['exe'] in seen:          # the same binary from two feature sets (features unused by it): run once
        continue
    seen.add(a['exe'])
    arts.append(a)
if not arts:
    sys.exit('win-unit: the build produced no test executables')
root = os.path.dirname(os.path.dirname(os.path.dirname(arts[0]['manifest_path'])))  # .../purge/<crates|bins|tools>/<pkg>/Cargo.toml
if os.path.realpath(root) != os.path.realpath(repo) or not root.startswith('/'):
    sys.exit(f'win-unit: manifest root {root} is not the repo {repo}')
guest_root = 'C:' + root.replace('/', '\\')
entries = []
for n, a in enumerate(arts):
    pkg = re.sub(r'[^\w.-]', '_', a['package'].split('#')[-1].split('@')[0].split('/')[-1])
    fs = re.sub(r'[^\w-]', '_', a['features']) if a['features'] else ''
    name = f"{n:02d}-{a['target']}-{a['kind']}" + (f'-{fs}' if fs else '')
    dst = os.path.join(B, 'bin', name + '.exe')
    shutil.copy2(a['exe'], dst)
    mdir = os.path.relpath(os.path.dirname(a['manifest_path']), root)
    entries.append({'name': name, 'target': a['target'], 'ident': a['target'].replace('-', '_'), 'kind': a['kind'],
                    'features': a['features'], 'package': a['package'], 'manifest_dir': mdir,
                    'cwd': guest_root + '\\' + mdir.replace('/', '\\'), 'exe': name + '.exe',
                    'sha256': hashlib.sha256(open(dst, 'rb').read()).hexdigest()})
# fixtures read at run time through CARGO_MANIFEST_DIR (see the header of win-unit.sh)
fx = []
for top in ('crates', 'bins', 'tools'):
    for pkg in sorted(os.listdir(os.path.join(root, top))):
        d = os.path.join(top, pkg, 'tests')
        if os.path.isdir(os.path.join(root, d)):
            fx.append(d)
fx += ['kb', 'vm/truth/deny.json', 'vm/runs/npp/lists-npp-2.json']
missing = [p for p in fx if not os.path.exists(os.path.join(root, p))]
fx = [p for p in fx if p not in missing]
with tarfile.open(os.path.join(B, 'fixtures.tgz'), 'w:gz') as tf:
    for p in fx:
        tf.add(os.path.join(root, p), arcname=root.lstrip('/') + '/' + p)
with tarfile.open(os.path.join(B, 'bin.tgz'), 'w:gz') as tf:
    for e in entries:
        tf.add(os.path.join(B, 'bin', e['exe']), arcname=e['exe'])
# #[ignore = "needs ..."] tests (rig snapshots via PURGE_RUNS_DIR, real Inno logs via PURGE_INNO_FIXTURES: data that is
# not in the guest; without it they return early and would pass silently): --skip'ped in an --include-ignored pass
runs_dir = []
for top in ('crates', 'bins', 'tools'):
    for dp, _, fns in os.walk(os.path.join(root, top)):
        if os.sep + 'target' in dp:
            continue
        for fn in fns:
            if fn.endswith('.rs'):
                t = open(os.path.join(dp, fn), encoding='utf-8', errors='replace').read()
                for m in re.finditer(r'#\[ignore\s*=\s*"needs [^"]*"\]\s*(?:#\[[^\]]*\]\s*)*(?:pub\s+)?fn\s+(\w+)', t):
                    runs_dir.append(m.group(1))
rev = subprocess.run(['git', '-C', root, 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip()
dirty = bool(subprocess.run(['git', '-C', root, 'status', '--porcelain', '--', 'crates', 'bins', 'tools', 'Cargo.lock'],
                            capture_output=True, text=True).stdout.strip())
man = {'schema': 'purge.rig.win-unit/1', 'repo_root': root, 'guest_root': guest_root, 'rev': rev + ('-dirty' if dirty else ''),
       'fixtures': fx, 'fixtures_missing': missing, 'skip_needs_runs_dir': sorted(set(runs_dir)), 'binaries': entries}
json.dump(man, open(os.path.join(B, 'manifest.json'), 'w', encoding='utf-8'), indent=2)
mb = lambda f: os.path.getsize(os.path.join(B, f)) / 1e6
print(f"win-unit: bundle {len(entries)} test binaries ({mb('bin.tgz'):.0f} MB packed), fixtures {len(fx)} paths "
      f"({mb('fixtures.tgz'):.1f} MB) under {guest_root}; rev {man['rev']}"
      + (f"; fixture paths missing on the host: {missing}" if missing else ''))
PY
  BUNDLE=$B
}

if [ -z "$BUNDLE" ]; then
  build_bundle || exit 2
  log "bundle ready in $(( $(date +%s) - T0 )) s"
  [ $BUNDLE_ONLY = 1 ] && exit 0
fi
[ -f "$BUNDLE/manifest.json" ] || { echo "win-unit: no $BUNDLE/manifest.json" >&2; exit 2; }

# ------------------------------------------------------------------------------------------------- run
VBOX=/usr/lib/virtualbox/VBoxManage
LOCKDIR=$HOME/purge-target/campaigns
mkdir -p "$LOCKDIR"
exec 9>"$LOCKDIR/.lock-$VM"
if ! flock -n 9; then log "REFUSED: $VM is locked (a campaign or another win-unit run holds $LOCKDIR/.lock-$VM)"; exit 2; fi
state=$("$VBOX" showvminfo "$VM" --machinereadable 2>/dev/null 9>&- | sed -n 's/^VMState="\(.*\)"$/\1/p')
case "$state" in
  running|paused|starting|restoring|saving|stopping|stuck|livesnapshotting|onlinesnapshotting)
    log "REFUSED: $VM is $state"; exit 2 ;;
  "") log "REFUSED: $VM not found"; exit 2 ;;
esac
if pgrep -af 'rig\.ps1' | grep -F -- "$VM" >/dev/null; then log "REFUSED: a rig.ps1 process for $VM is alive"; exit 2; fi
avail=$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)
if [ "$avail" -lt 6144 ]; then log "REFUSED: only $avail MiB RAM available (need 6144 for a 4 GiB VM)"; exit 2; fi
[ -r "${VMPWFILE:-}" ] || { log "REFUSED: set VMPWFILE to the guest password file"; exit 2; }
export RIG_TMP=${RIG_TMP:-$HOME/.cache/purge-rig-tmp} POWERSHELL_TELEMETRY_OPTOUT=1
mkdir -p "$RIG_TMP"; chmod 700 "$RIG_TMP"
log "run on $VM ($SNAP), RAM available $avail MiB, threads $THREADS$( [ $ELEV = 1 ] && echo ", elevated pass: $ELEV_ARGS")"
T1=$(date +%s)
pargs=(-VmName "$VM" -Snapshot "$SNAP" -Bundle "$BUNDLE" -Out "$OUT/guest" -Threads "$THREADS" -ElevatedArgs "$ELEV_ARGS" -TimeoutBin "$TBIN")
[ -n "$FILTER" ] && pargs+=(-Filter "$FILTER")
[ $ELEV = 1 ] && pargs+=(-Elevated)
pwsh -NoProfile -NonInteractive -File "$REPO/vm/win-unit.ps1" "${pargs[@]}" 9>&- 2>&1 \
  | grep --line-buffered -v -E 'vboxdrv kernel module|available for the current kernel|failed to load\. Please|vboxconfig|You will not be able to start VMs'
prc=${PIPESTATUS[0]}
log "VM part: exit $prc, $(( $(date +%s) - T1 )) s"
exec 9>&-   # release the VM lock before the report

# ------------------------------------------------------------------------------------------------- report
if [ -z "$EXPECTED" ]; then
  EXPECTED=$OUT/expected-wine.txt
  { sed -n '/^KNOWN=(/,/^)/p' "$HOME/purge-target/ci-linux.sh" 2>/dev/null | grep -E '^\s+[a-z_]+::' | tr -d ' '
    [ -f "$HOME/purge-target/ci-linux-known.txt" ] && sed 's/#.*//; s/[[:space:]]//g' "$HOME/purge-target/ci-linux-known.txt" | grep .
  } >"$EXPECTED"
fi
python3 -I - "$BUNDLE/manifest.json" "$OUT/guest" "$EXPECTED" "$OUT" "$prc" "$(( $(date +%s) - T0 ))" <<'PY'
import json, os, re, sys
man_f, gdir, exp_f, out, prc, secs = sys.argv[1:7]
man = json.load(open(man_f, encoding='utf-8'))
expected = {l.strip() for l in open(exp_f, encoding='utf-8') if l.strip() and not l.startswith('#')} if os.path.exists(exp_f) else set()
TEST = re.compile(r'^test (\S+) \.\.\. (ok|FAILED|ignored)\b')
RES = re.compile(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out')
rep = {'rev': man['rev'], 'passes': [], 'exit_vm_part': int(prc), 'seconds_total': int(secs)}
lines, bad = [], False
for p in sorted(os.listdir(gdir)) if os.path.isdir(gdir) else []:
    rj = os.path.join(gdir, p, 'results.json')
    if not os.path.isfile(rj):
        continue
    res = json.load(open(rj, encoding='utf-8-sig'))
    ps = {'pass': p, 'env': res.get('env', {}), 'binaries': [], 'failed': [], 'confirmed': [], 'still_failing_expected': [],
          'skipped_needs_runs_dir': res.get('skipped', [])}
    for b in res['binaries']:
        txt = os.path.join(gdir, p, b['name'] + '.txt')
        t = open(txt, encoding='utf-8', errors='replace').read() if os.path.exists(txt) else ''
        tests = {m.group(1): m.group(2) for m in (TEST.match(l) for l in t.splitlines()) if m}
        r = next((m for m in (RES.match(l) for l in t.splitlines()) if m), None)
        row = {'name': b['name'], 'exit': b.get('exit'), 'seconds': b.get('seconds'), 'timed_out': b.get('timed_out', False),
               'passed': sum(v == 'ok' for v in tests.values()), 'failed': sum(v == 'FAILED' for v in tests.values()),
               'ignored': sum(v == 'ignored' for v in tests.values()), 'summary': bool(r)}
        if r:
            row.update(passed=int(r.group(2)), failed=int(r.group(3)), ignored=int(r.group(4)))
        crash = b.get('timed_out') or (b.get('exit') != 0 and row['failed'] == 0) or not r
        row['crash'] = bool(crash)
        ident = b['ident']
        for tname, v in tests.items():
            full = f'{ident}::{tname}'
            if v == 'FAILED':
                ps['failed'].append(full)
                if full in expected:
                    ps['still_failing_expected'].append(full)
            elif v == 'ok' and full in expected:
                ps['confirmed'].append(full)
        if crash:
            ps['failed'].append(f"{b['name']}: CRASH/TIMEOUT (exit {b.get('exit')}, timed_out {b.get('timed_out', False)}, no complete libtest summary)")
        ps['binaries'].append(row)
    ps['expected_not_seen'] = sorted(e for e in expected if e not in ps['confirmed'] and e not in ps['still_failing_expected'])
    bad = bad or bool(ps['failed'])
    rep['passes'].append(ps)
if not rep['passes']:
    bad = True
rep['ok'] = not bad
json.dump(rep, open(os.path.join(out, 'report.json'), 'w', encoding='utf-8'), indent=2)
L = [f"# win-unit report ({os.path.basename(out)})", '', f"rev {man['rev']}, {len(man['binaries'])} test binaries, total {secs} s, VM part exit {prc}", '']
for ps in rep['passes']:
    e = ps['env']
    L += [f"## pass {ps['pass']}", '', f"guest: {e.get('os', '?')}; user {e.get('user', '?')}, integrity {e.get('integrity', '?')}; args `{e.get('args', '')}`; {e.get('seconds', '?')} s", '',
          '| binary | passed | failed | ignored | exit | s | note |', '|---|---:|---:|---:|---:|---:|---|']
    for r in ps['binaries']:
        L.append(f"| {r['name']} | {r['passed']} | {r['failed']} | {r['ignored']} | {r['exit']} | {r['seconds']} | {'CRASH/TIMEOUT' if r['crash'] else ''} |")
    tot = [sum(r[k] for r in ps['binaries']) for k in ('passed', 'failed', 'ignored')]
    L += ['', f"**total: {tot[0]} passed, {tot[1]} failed, {tot[2]} ignored**", '']
    L += [f"Failing on Windows (real findings): {len(ps['failed'])}"] + [f"- `{x}`" for x in ps['failed']] + ['']
    L += [f"Wine-only failures confirmed (pass on Windows): {len(ps['confirmed'])}"] + [f"- `{x}`" for x in ps['confirmed']] + ['']
    if ps['still_failing_expected']:
        L += ['Expected-to-differ tests that FAIL on Windows too:'] + [f"- `{x}`" for x in ps['still_failing_expected']] + ['']
    if ps['expected_not_seen']:
        L += ['Expected-to-differ tests not run in this pass (filtered, ignored or absent):'] + [f"- `{x}`" for x in ps['expected_not_seen']] + ['']
    if ps['skipped_needs_runs_dir']:
        L += ['Skipped (#[ignore = "needs ..."]: rig snapshots or other data not in the guest): ' + ', '.join(f'`{x}`' for x in ps['skipped_needs_runs_dir']), '']
L.append(f"RESULT: {'ok' if rep['ok'] else 'FAILED'}")
open(os.path.join(out, 'report.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
print('\n'.join(L))
sys.exit(0 if rep['ok'] else 1)
PY
rc=$?
[ "$prc" -ne 0 ] && [ $rc -eq 0 ] && rc=1
log "done in $(( $(date +%s) - T0 )) s, exit $rc; report $OUT/report.md"
exit $rc
