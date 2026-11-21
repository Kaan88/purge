#!/usr/bin/env bash
# baseline-local-lib: shared parts of the gate-M measurement scripts baseline-local-r1.sh, -r2.sh (VMs, from the Linux
# host) and -r5.sh (the Windows host, Git Bash), docs/BASELINE_LOCAL_DESIGN.md 8.1-8.4, vm/RIG.md 8a. Sourced, not run.
#
#   bl_tree_sha256 <vm/rigtool>          SHA-256 of rigtool's sources, as build.rs and truth/m1b.sh compute it
#   bl_check_rigtool <rigtool binary>    refuses (return 2) a rigtool not built from the sources in the tree
#   bl_build_job <run dir> <engine>      the PowerShell (5.1) text that builds the local baseline twice (cold, warm)
#                                        into <run dir>\local-<pass>.tsv.gz and writes <run dir>\build.json
#   bl_diff <rigtool> <truth> <local> <neighbour> <out.json>   rigtool baseline-diff with kb/baselines/view.json
#   bl_check <report.json> <build.json> <expect name|-> <cpus budget>   prints the numbers gate M reads; return 3 when the
#                                        seal failed, the passes differ, the local file is not the truth's Windows
#                                        (expect given) or the pass did not exit 0
# Every function expects the current directory to be the repository root.

# Python 3: python3, else python (on Windows python3 may be the Store alias that does not run).
bl_py() { if python3 -c '' >/dev/null 2>&1; then python3 "$@"; else python "$@"; fi; }

bl_tree_sha256() {
  bl_py -I - "$1" <<'PY'
import hashlib, os, sys
root = sys.argv[1]
files = ['Cargo.toml', 'Cargo.lock', 'build.rs']
for dp, _, fs in os.walk(os.path.join(root, 'src')):
    files += [os.path.relpath(os.path.join(dp, f), root).replace(os.sep, '/') for f in fs]
lines = ''
for rel in sorted(files):
    with open(os.path.join(root, rel), 'rb') as f:
        lines += hashlib.sha256(f.read().replace(b'\r\n', b'\n')).hexdigest() + '  ' + rel + '\n'
print(hashlib.sha256(lines.encode()).hexdigest())
PY
}

bl_check_rigtool() {
  local exe=$1 built tree
  if [ ! -x "$exe" ]; then echo "baseline-local: REFUSED: no rigtool at $exe" >&2; return 2; fi
  built=$("$exe" version 2>/dev/null | sed -n 's/.*source-sha256 \([0-9a-f]*\).*/\1/p')
  tree=$(bl_tree_sha256 vm/rigtool)
  if [ -z "$built" ] || [ "$built" != "$tree" ]; then
    echo "baseline-local: REFUSED: $exe was built from sources ${built:-?}, vm/rigtool is $tree (rebuild it)" >&2
    return 2
  fi
  if ! "$exe" help 2>/dev/null | grep -q 'baseline-diff'; then
    echo "baseline-local: REFUSED: $exe has no baseline-diff" >&2; return 2
  fi
}

# $1: the run directory as the builder sees it (guest C:\cr\out\<run>, or a host directory); $2: purge-engine.exe there.
bl_build_job() {
  local dir=${1//\\/\\\\} engine=${2//\\/\\\\}   # sed reads \ in a replacement as an escape
  cat <<'PS1' | sed -e "s|__DIR__|$dir|g" -e "s|__ENGINE__|$engine|g"
$ErrorActionPreference = 'Stop'
$Dir = '__DIR__'
$Engine = '__ENGINE__'
New-Item -ItemType Directory -Force $Dir | Out-Null
$env:PURGE_TIMING = '1'
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$m = [ordered]@{ schema = 'purge.rig.baseline-local-build/1'; computer = $env:COMPUTERNAME; elevated = $admin
    os = "$($cv.EditionID)-$($cv.CurrentBuildNumber).$($cv.UBR)"; cpus = [Environment]::ProcessorCount
    started = (Get-Date).ToString('o'); engine_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Engine).Hash.ToLower()
    passes = @(); info = $null }
foreach ($pass in 'cold', 'warm') {
    $out = Join-Path $Dir "local-$pass.tsv.gz"
    $log = Join-Path $Dir "build-$pass.log"
    Remove-Item -LiteralPath $out, $log, "$log.out" -Force -ErrorAction SilentlyContinue
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $Engine -ArgumentList @('baseline', 'build', '--out', "`"$out`"") -NoNewWindow -PassThru `
                       -RedirectStandardError $log -RedirectStandardOutput "$log.out"
    $null = $p.Handle   # PS 5.1: keep the handle so ExitCode is readable after the exit
    $peak = 0
    while (-not $p.HasExited) {
        try { $p.Refresh(); if ($p.PeakWorkingSet64 -gt $peak) { $peak = $p.PeakWorkingSet64 } } catch { }
        Start-Sleep -Milliseconds 100
    }
    $p.WaitForExit()
    $sw.Stop()
    $len = $null; if (Test-Path -LiteralPath $out) { $len = (Get-Item -LiteralPath $out).Length }
    $m.passes += [ordered]@{ pass = $pass; exit = $p.ExitCode; seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
        peak_working_set_mb = [Math]::Round($peak / 1MB, 1); file_bytes = $len
        total_line = @(Get-Content -LiteralPath $log | Where-Object { $_ -match '^timing: baseline\.local\.total' }) -join ' ' }
}
# A load of the file (baseline info: read, #end check, hashed sets): the warm-load proxy until BL-VIEW exists.
$ErrorActionPreference = 'Continue'   # PS 5.1 turns a native program's stderr line into an error record under Stop
$sw = [Diagnostics.Stopwatch]::StartNew()
$info = & $Engine baseline info (Join-Path $Dir 'local-cold.tsv.gz') 2>&1 | ForEach-Object { "$_" }
$sw.Stop()
$ErrorActionPreference = 'Stop'
[IO.File]::WriteAllLines((Join-Path $Dir 'info.txt'), [string[]]$info)
$m.info = [ordered]@{ exit = $LASTEXITCODE; seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2) }
$m.finished = (Get-Date).ToString('o')
[IO.File]::WriteAllText((Join-Path $Dir 'build.json'), (ConvertTo-Json -InputObject $m -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
"baseline-local build: $(($m.passes | ForEach-Object { '{0} exit {1} {2}s {3} MB peak {4} bytes' -f $_.pass, $_.exit, $_.seconds, $_.peak_working_set_mb, $_.file_bytes }) -join '; ')"
PS1
}

bl_diff() {
  local rigtool=$1 truth=$2 local_file=$3 nb=$4 out=$5
  mkdir -p "$(dirname "$out")"
  "$rigtool" baseline-diff --truth "$truth" --local "$local_file" --neighbour "$nb" --areas kb/baselines/view.json --out "$out"
}

bl_check() {
  bl_py -I - "$@" <<'PY'
import gzip, hashlib, json, os, sys
rep_path, build_path, expect, cpus_budget = sys.argv[1:5]
rep = json.load(open(rep_path, encoding='utf-8-sig'))
build = json.load(open(build_path, encoding='utf-8-sig'))
bad = []
loc = rep['inputs']['local']
if not loc.get('complete'):
    bad.append('local baseline INCOMPLETE: ' + '; '.join(loc.get('incomplete_reasons', [])))
if expect != '-' and loc['name'].lower() != expect.lower():
    bad.append(f"local baseline is of {loc['name']}, the truth is {expect}")
for p in build['passes']:
    if p['exit'] != 0:
        bad.append(f"{p['pass']} build exit {p['exit']}")
# The two passes must give the same #src lines and records: the body is deterministic, only the header (its time)
# and therefore the #end hash differ.
bodies = []
for p in build['passes']:
    f = os.path.join(os.path.dirname(build_path), f"local-{p['pass']}.tsv.gz")
    try:
        with gzip.open(f, 'rb') as g:
            g.readline()
            h = hashlib.sha256()
            for line in g:
                if not line.startswith(b'#end\t'):
                    h.update(line)
            bodies.append(h.hexdigest())
    except OSError as e:
        bad.append(f'{f}: {e}')
if len(bodies) == 2 and bodies[0] != bodies[1]:
    bad.append(f'cold and warm builds differ below the header: {bodies[0]} vs {bodies[1]}')
t = rep['total']
print(f"local {loc['name']} complete={loc.get('complete')}; truth {rep['inputs']['truth']['name']} ({t['truth']} keys in scope); "
      f"neighbours {[n['name'] for n in rep['inputs']['neighbours']]}")
print(f"TOTAL coverage local {t['coverage_local']} merged {t['coverage_merged']}; false absent local {t['false_absent_local']} "
      f"merged {t['false_absent_merged']}; shared-shape false absent local {t['shared_shape_false_absent_local']} "
      f"merged {t['shared_shape_false_absent_merged']}; W1 scope (>= 0.99 merged) {t['checks']['w1_scope']}")
for a in rep['areas']:
    print(f"  {a['id']:<28} truth {a['truth']:>7}  local {a['coverage_local']}  merged {a['coverage_merged']}  "
          f"shared fa {a['shared_shape_false_absent_local']}/{a['shared_shape_false_absent_merged']}  "
          f"S3 local {a['checks']['s3_local']}  S2 merged {a['checks']['s2_merged']}")
cold = build['passes'][0]
budget = 30 if cpus_budget == 'host' else 120
print(f"W4: cold build {cold['seconds']} s (budget {budget} s on {build['cpus']} CPUs), warm {build['passes'][-1]['seconds']} s; "
      f"peak {cold['peak_working_set_mb']} MB (300); file {cold['file_bytes']} bytes (15 MB); load (baseline info) "
      f"{build['info']['seconds']} s (1.5 s for the view)")
for b in bad:
    print('PROBLEM: ' + b)
sys.exit(3 if bad else 0)
PY
}
