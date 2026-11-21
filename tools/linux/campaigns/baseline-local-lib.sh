#!/usr/bin/env bash
# baseline-local-lib: shared parts of the gate-M measurement scripts baseline-local-r1.sh, -r2.sh (VMs, from the Linux
# host) and -r5.sh (the Windows host, Git Bash), docs/BASELINE_LOCAL_DESIGN.md 8.1-8.4, vm/RIG.md 8a. Sourced, not run.
#
#   bl_tree_sha256 <vm/rigtool>          SHA-256 of rigtool's sources, as build.rs and truth/m1b.sh compute it
#   bl_check_rigtool <rigtool binary>    refuses (return 2) a rigtool not built from the sources in the tree
#   bl_build_job <run dir> <engine> <riglib.ps1>   the PowerShell (5.1) text that builds the local baseline three
#                                        times (cold, warm, settled: after the guest settled and the standby list was
#                                        emptied) into <run dir>\local-<pass>.tsv.gz and writes <run dir>\build.json
#   bl_diff <rigtool> <truth> <local> <neighbour> <out.json>   rigtool baseline-diff with kb/baselines/view.json
#   bl_check <report.json> <build.json> <expect name|-> <cpus budget>   prints the numbers gate M reads; return 3 when the
#                                        seal failed, a pass differs from the cold one with the same source id (a
#                                        determinism failure), the run is INVALID (another source id: the source
#                                        changed between the passes; vm: a guest adapter up), the local file is not
#                                        the truth's Windows (expect given) or a pass did not exit 0
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

# $1: the run directory as the builder sees it (guest C:\cr\out\<run>, or a host directory); $2: purge-engine.exe there;
# $3: riglib.ps1 there (guest C:\cr\guest\riglib.ps1, host vm\guest\riglib.ps1).
bl_build_job() {
  local dir=${1//\\/\\\\} engine=${2//\\/\\\\} riglib=${3//\\/\\\\}   # sed reads \ in a replacement as an escape
  cat <<'PS1' | sed -e "s|__DIR__|$dir|g" -e "s|__ENGINE__|$engine|g" -e "s|__RIGLIB__|$riglib|g"
$ErrorActionPreference = 'Stop'
$Dir = '__DIR__'
$Engine = '__ENGINE__'
$RigLib = '__RIGLIB__'
New-Item -ItemType Directory -Force $Dir | Out-Null
$env:PURGE_TIMING = '1'
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# The adapters Windows reports up (the R1/R2 builds run with the VM's NAT cable disconnected).
function Get-BlNetUp { try { @(Get-NetAdapter -ErrorAction Stop | Where-Object { "$($_.Status)" -eq 'Up' } | ForEach-Object { "$($_.Name)" }) } catch { @("? $($_.Exception.Message)") } }
$m = [ordered]@{ schema = 'purge.rig.baseline-local-build/2'; computer = $env:COMPUTERNAME; elevated = $admin
    os = "$($cv.EditionID)-$($cv.CurrentBuildNumber).$($cv.UBR)"; cpus = [Environment]::ProcessorCount
    started = (Get-Date).ToString('o'); engine_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Engine).Hash.ToLower()
    network_up = [ordered]@{ start = @(Get-BlNetUp); settled = $null }; passes = @(); settle = $null; info = $null }
# Before the settled pass: the boot settle of the exec runs (riglib Wait-M2BootSettle: ReadyBoot trace stopped, uptime
# at least 300 s), then the CPU load under 10 % over 30 s (as rig.ps1 Wait-RigHostSettled; at most 600 s), then the
# standby and modified page lists emptied so the build reads from disk again (NtSetSystemInformation
# SystemMemoryListInformation; elevated only, the record says when it failed). Never throws.
function Wait-BlSettle {
    $rec = [ordered]@{ boot = $null; cpu_settled = $false; cpu_percent = $null; cpu_waited_sec = $null; cache_purged = $false; error = $null }
    try {
        $eap = $ErrorActionPreference
        . $RigLib
        $ErrorActionPreference = $eap
        $rec.boot = Wait-M2BootSettle -MaxSec 600 -MinUptimeSec 300
        if (-not ('PurgeRig.BlSettle' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace PurgeRig {
public static class BlSettle {
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetSystemTimes(out long idle, out long kernel, out long user);
    [DllImport("ntdll.dll")] static extern int NtSetSystemInformation(int cls, ref int info, int len);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string system, string name, out long luid);
    [StructLayout(LayoutKind.Sequential, Pack = 4)] struct Privs { public int Count; public long Luid; public int Attr; }
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool none, ref Privs state, int len, IntPtr prev, IntPtr retLen);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    // Empties the modified page list (3) and the standby list (4); "" when both calls returned STATUS_SUCCESS.
    public static string PurgeStandby() {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) return "OpenProcessToken " + Marshal.GetLastWin32Error();
        try {
            Privs p = new Privs(); p.Count = 1; p.Attr = 2;
            if (!LookupPrivilegeValue(null, "SeProfileSingleProcessPrivilege", out p.Luid)) return "LookupPrivilegeValue " + Marshal.GetLastWin32Error();
            if (!AdjustTokenPrivileges(token, false, ref p, Marshal.SizeOf(p), IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0) return "AdjustTokenPrivileges " + Marshal.GetLastWin32Error();
        } finally { CloseHandle(token); }
        foreach (int cmd in new int[] { 3, 4 }) {
            int c = cmd;
            int st = NtSetSystemInformation(80, ref c, 4);
            if (st != 0) return "NtSetSystemInformation(" + cmd + ") 0x" + st.ToString("x8");
        }
        return "";
    }
}
}
"@
        }
        $t0 = Get-Date
        while ($true) {
            $i0 = [long]0; $k0 = [long]0; $u0 = [long]0; $i1 = [long]0; $k1 = [long]0; $u1 = [long]0
            $null = [PurgeRig.BlSettle]::GetSystemTimes([ref]$i0, [ref]$k0, [ref]$u0)
            Start-Sleep -Seconds 30
            $null = [PurgeRig.BlSettle]::GetSystemTimes([ref]$i1, [ref]$k1, [ref]$u1)
            $total = ($k1 - $k0) + ($u1 - $u0)
            if ($total -gt 0) { $rec.cpu_percent = [Math]::Round(100.0 * (1.0 - (($i1 - $i0) / [double]$total)), 1) }
            if ($null -ne $rec.cpu_percent -and $rec.cpu_percent -lt 10) { $rec.cpu_settled = $true; break }
            if (((Get-Date) - $t0).TotalSeconds -ge 600) { break }
        }
        $rec.cpu_waited_sec = [Math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
        $why = [PurgeRig.BlSettle]::PurgeStandby()
        if ($why) { $rec.error = "standby purge: $why" } else { $rec.cache_purged = $true }
    } catch { $rec.error = $_.Exception.Message }
    $rec
}
foreach ($pass in 'cold', 'warm', 'settled') {
    if ($pass -eq 'settled') {
        $m.settle = Wait-BlSettle
        $m.network_up.settled = @(Get-BlNetUp)
    }
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
        uptime_sec = [int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds
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
[IO.File]::WriteAllText((Join-Path $Dir 'build.json'), (ConvertTo-Json -InputObject $m -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
"baseline-local build: $(($m.passes | ForEach-Object { '{0} exit {1} {2}s {3} MB peak {4} bytes' -f $_.pass, $_.exit, $_.seconds, $_.peak_working_set_mb, $_.file_bytes }) -join '; ')"
"settle: $(if ($m.settle.boot) { "boot waited $($m.settle.boot.waited_sec) s, uptime $($m.settle.boot.uptime_sec) s; " })CPU $($m.settle.cpu_percent) % (settled $($m.settle.cpu_settled), waited $($m.settle.cpu_waited_sec) s); cache purged $($m.settle.cache_purged)$(if ($m.settle.error) { '; ' + $m.settle.error }); network up at start: $(@($m.network_up.start) -join ', ')"
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
passes = build['passes']
for p in passes:
    if p['exit'] != 0:
        bad.append(f"{p['pass']} build exit {p['exit']}")
# Every pass must give the cold pass's #src lines and records: the body is deterministic, only the header (its time)
# and therefore the #end hash differ. Another body with another header source id: the source changed between the
# passes (INVALID); with the same source id: a determinism failure.
d = os.path.dirname(build_path)
body = {}
for p in passes:
    f = os.path.join(d, f"local-{p['pass']}.tsv.gz")
    try:
        with gzip.open(f, 'rb') as g:
            head = g.readline().decode('utf-8', 'replace').rstrip('\n').split('\t')
            h = hashlib.sha256()
            src = []
            for line in g:
                if line.startswith(b'#src\t'):
                    src.append(line.decode('utf-8', 'replace').rstrip('\n'))
                if not line.startswith(b'#end\t'):
                    h.update(line)
            body[p['pass']] = (h.hexdigest(), head[6] if len(head) >= 7 else '', src)
    except OSError as e:
        bad.append(f'{f}: {e}')
first = passes[0]['pass']
for p in passes[1:]:
    a, o = body.get(first), body.get(p['pass'])
    if not a or not o or a[0] == o[0]:
        continue
    diff = [s for s in ('S1', 'S2', 'S3', 'S4', 'S5')
            if [x for x in a[2] if x.startswith(f'#src\t{s}\t')] != [x for x in o[2] if x.startswith(f'#src\t{s}\t')]]
    src_text = f"#src lines that differ: {', '.join(diff)}" if diff else 'every #src line equal'
    if a[1] and o[1] and a[1] != o[1]:
        bad.append(f"RUN INVALID: the source changed between the {first} and {p['pass']} passes (source id {a[1]} vs {o[1]}; "
                   f"{src_text}): not a determinism failure; rerun with the source held still")
    elif a[1] and a[1] == o[1]:
        bad.append(f"{first} and {p['pass']} builds differ below the header with the same source id {a[1]} "
                   f"(a determinism failure; {src_text}): {a[0]} vs {o[0]}")
    else:
        bad.append(f"{first} and {p['pass']} builds differ below the header (no source id to compare; {src_text}): {a[0]} vs {o[0]}")
net = build.get('network_up')
lst = lambda v: [v] if isinstance(v, str) else (v or [])
if cpus_budget != 'host' and net:
    for w in ('start', 'settled'):
        up = [x for x in lst(net.get(w)) if x]
        if up:
            bad.append(f"RUN INVALID: the guest had a network adapter up ({w}: {', '.join(up)}); the build must run offline")
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
def named(name, index):
    for p in passes:
        if p['pass'] == name:
            return p
    return passes[index] if index is not None and index < len(passes) else None
cold, warm, settled = named('cold', 0), named('warm', 1), named('settled', None)
budget = 30 if cpus_budget == 'host' else 120
print(f"W4: cold build {cold['seconds']} s (budget {budget} s on {build['cpus']} CPUs), warm {warm['seconds']} s; "
      f"peak {cold['peak_working_set_mb']} MB (300); file {cold['file_bytes']} bytes (15 MB); load (baseline info) "
      f"{build['info']['seconds']} s (1.5 s for the view)")
if settled:
    st = build.get('settle') or {}
    b = st.get('boot')
    boot = (f"boot settle {b.get('waited_sec')} s (ReadyBoot {'bound reached' if b.get('bounded') else 'stopped'}, uptime {b.get('uptime_sec')} s)"
            if b else 'no boot settle')
    print(f"W4 settled: cold build {settled['seconds']} s (budget {budget} s on {build['cpus']} CPUs) at uptime {settled.get('uptime_sec')} s, "
          f"after {boot}, CPU {st.get('cpu_percent')} % over 30 s ({'settled' if st.get('cpu_settled') else 'NOT settled'} after "
          f"{st.get('cpu_waited_sec')} s), standby list purged {st.get('cache_purged')}"
          f"{'' if st.get('cache_purged') else ' (not a cold read)'}{'; ' + st['error'] if st.get('error') else ''}")
if net:
    print(f"network: adapters up at the start [{', '.join(lst(net.get('start')))}], before the settled pass [{', '.join(lst(net.get('settled')))}]")
for p in passes:
    log = os.path.join(d, f"build-{p['pass']}.log")
    if not os.path.exists(log):
        continue
    with open(log, encoding='utf-8', errors='replace') as f:
        ph = [l.rstrip('\n')[len('timing: baseline.local.'):] for l in f
              if any(l.startswith(f'timing: baseline.local.{k} ') for k in ('read', 'expand', 'parse', 's1', 'total'))]
    if ph:
        print(f"  phases {p['pass']}: {'; '.join(ph)}")
for b in bad:
    print('PROBLEM: ' + b)
sys.exit(3 if bad else 0)
PY
}
