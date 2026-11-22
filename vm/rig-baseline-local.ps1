<#
  Purge rig, gate M runs R1, R2 and R5 (docs\BASELINE_LOCAL_DESIGN.md section 8.2, vm\RIG.md section 8a; package
  BL-MEASURE) on the Windows rig host. Host driver, Windows PowerShell 5.1; dot-sources rig.ps1 for the VM helpers and
  leaves it unchanged. It does what tools/linux/campaigns/baseline-local-{vm,r1,r2,r5}.sh do on a Linux host.

    $env:VMPWFILE = 'C:\path\to\pw.txt'
    .\vm\rig-baseline-local.ps1 -Mode R1      # Purge-CleanPro: truth Professional-26340.9882, neighbour EnterpriseSEval-26100.1742
    .\vm\rig-baseline-local.ps1 -Mode R2      # Inbound-Win11-Test, 3D off: truth and neighbour the other way round
    .\vm\rig-baseline-local.ps1 -Mode R5      # this host, elevated, read-only; no VM, no VMPWFILE
    .\vm\rig-baseline-local.ps1 -Mode R1 -FirstRead   # W4 settled first read (BL-GATE A0, review BL-RM S7); R2 too

  R1, R2 (run bl-r1-cleanpro, bl-r2-inbound): refuses unless the per-VM lock (vm\runs\.lock-<vm>) is free, VMPWFILE
  names a readable file, the VM exists and is not running (or paused, starting, ...), no other rig script for that VM
  is alive, the engine holds the local baseline builder, both shipped baselines exist, rigtool was built from the
  tree's sources (`rigtool version` hash = the hash of vm\rigtool, as BIND) and has baseline-diff, and 6 GiB RAM are
  available. Then: vm\runs\<run>\ moved to vm\runs\_old\, restore rig-base (nothing installed), the VM's NAT cable
  disconnected (controlvm setlinkstate<N> off for each NAT adapter showvminfo names; the rig talks to the guest through
  guestcontrol) until the end, Push-Tools -NoBaselines (the exact baseline stays hidden; the checked rigtool and the
  engine are pushed), one guest job that builds the local baseline three times with PURGE_TIMING=1 into
  C:\cr\out\<run>\ (Get-BlBuildJob, the same text as baseline-local-lib.sh bl_build_job): cold right after boot, warm,
  and settled (after Wait-M2BootSettle, a quiet CPU and an emptied standby list), Pull-Run to vm\runs\<run>\, the cable
  connected again and the VM restored to rig-base and left off;
  then on the host `rigtool baseline-diff` (truth = the VM's own shipped baseline, local = the cold build, neighbour =
  the other shipped baseline) into vm\truth\baseline-local\<run>.json, build.json copied beside it as
  <run>-build.json, and the final check (Test-BlReport, as bl_check).

  R5 (run r5-host): refuses unless elevated (S4 reads every user's packages only elevated; -AllowUnelevated builds an
  incomplete file, which the check then reports), the engine and rigtool pass the same checks and no VirtualBox VM
  runs on the host (the build times are the W4 budgets). Builds the host's local baseline three times into
  vm\runs\r5-host\ (the same job, run by a child powershell.exe; the settled pass empties the host's standby list
  too), copies build.json to vm\truth\baseline-local\r5-host-build.json and
  runs baseline-diff against each shipped baseline as a proxy truth with the other as neighbour
  (vm\truth\baseline-local\r5-host-vs-<baseline>.json): context and budgets, not a safety measurement.

  -Engine: default target\release\purge-engine.exe (cargo build --release -p purge-engine). -RigTool: default
  $env:RIG_RIGTOOL, else vm\rigtool\target\release\rigtool.exe (cargo build --release in vm\rigtool).
  Console log: vm\runs\bl-<run>-<stamp>.log (every line also on the console).
  Exit code: 0 ok; 1 the VM part or the diff failed; 2 refused to start (R5: also the build job or a diff failed);
  3 the report shows a problem (seal failed or file incomplete, a pass differs from the cold one below the header with
  the same source id (a determinism failure), the local file is not of the truth's Windows, a build exit code was not
  0) or the run is INVALID (the passes' source ids differ: the source changed between them; or, R1/R2, the guest saw
  a network adapter up).
  -Library: define the functions and return (vm\guest\tests\rig-selftest.ps1).

  -FirstRead (R1, R2 only; run bl-r1-cleanpro-firstread, bl-r2-inbound-firstread): the same checks, restore, offline
  cable and push, but the guest job builds exactly once: after the same settle as the settled pass (Wait-BlSettle:
  boot settle, quiet CPU, standby list emptied), as the first build of that boot (review BL-RM S7: the settled pass of
  the three-pass job is the third read in one boot, after Defender scanned every manifest twice). No baseline-diff.
  Evidence: vm\truth\baseline-local\<run>.json (purge.rig.baseline-local-firstread/1: duration, settle, uptime,
  network, peak, file size, source id and #src lines) and <run>-build.json. Budget: "settled first build at most 60 s
  on the rig VM" (BL-RM S7; design section 5 gives 120 s for the cold build on a 2-vCPU VM). Exit 3 when the build
  failed, the settle did not hold (CPU not settled or standby list not emptied), the guest was online, or the build
  took more than 60 s (the W4 number is still recorded).
#>
[CmdletBinding()]
param(
    [ValidateSet('R1', 'R2', 'R5')] [string] $Mode = 'R5',
    [string] $Engine = '',
    [string] $RigTool = '',
    [switch] $AllowUnelevated,
    [switch] $FirstRead,
    [switch] $Library
)
$ErrorActionPreference = 'Stop'

# rig.ps1 has parameters of its own (Mode, Engine, ...): ours are kept here first.
$B = [ordered]@{ mode = $Mode; engine = $Engine; rigtool = $RigTool; allow_unelevated = [bool]$AllowUnelevated; first_read = [bool]$FirstRead }
# W4 settled first read, seconds on the rig VM (review BL-RM S7: "settled first build at most 60 s on the rig VM").
$BlFirstReadBudgetSec = 60
$BlRigDir = $PSScriptRoot
$BlRepo = Split-Path -Parent $PSScriptRoot

# ------------------------------------------------------------------------------------------ pure helpers

# The run of a mode: VM (none for R5), run name, truth and neighbour baselines (R5: both, each the proxy truth once),
# 3D off.
function Get-BlRunSpec([string]$M) {
    switch -CaseSensitive ($M) {
        'R1' { return [pscustomobject]@{ mode = 'R1'; vm = 'Purge-CleanPro'; run = 'bl-r1-cleanpro'; truth = 'Professional-26340.9882'; neighbour = 'EnterpriseSEval-26100.1742'; no3d = $false } }
        'R2' { return [pscustomobject]@{ mode = 'R2'; vm = 'Inbound-Win11-Test'; run = 'bl-r2-inbound'; truth = 'EnterpriseSEval-26100.1742'; neighbour = 'Professional-26340.9882'; no3d = $true } }
        'R5' { return [pscustomobject]@{ mode = 'R5'; vm = $null; run = 'r5-host'; truth = $null; neighbour = $null; no3d = $false
                                         baselines = @('Professional-26340.9882', 'EnterpriseSEval-26100.1742') } }
    }
    throw "unknown mode '$M' (R1, R2 or R5)"
}

# VBoxManage VMState values in which a VM is in use (baseline-local-vm.sh refuses these).
$BlBusyStates = @('running', 'paused', 'starting', 'restoring', 'saving', 'stopping', 'stuck', 'livesnapshotting', 'onlinesnapshotting')
function Test-BlVmBusyState([string]$State) { $BlBusyStates -contains $State }

# The VM's NAT adapters from showvminfo --machinereadable (ConvertFrom-MachineReadable): the numbers N of nic<N>="nat",
# ascending. R1 and R2 disconnect exactly these for the whole build (coordinator, gate M round 2: in round 1 Store apps
# updated between the cold and warm passes of Clean-Pro).
function Get-BlNatNics([hashtable]$Info) {
    @($Info.Keys | ForEach-Object { $m = [regex]::Match("$_", '^nic(\d+)$'); if ($m.Success -and "$($Info[$_])" -ceq 'nat') { [int]$m.Groups[1].Value } } | Sort-Object)
}

# The VM's other attached adapters ('N=<type>', neither nat nor none), for the log.
function Get-BlOtherNics([hashtable]$Info) {
    @($Info.Keys | ForEach-Object { $m = [regex]::Match("$_", '^nic(\d+)$'); $v = "$($Info[$_])"; if ($m.Success -and $v -and $v -cne 'nat' -and $v -cne 'none') { [int]$m.Groups[1].Value } } |
        Sort-Object | ForEach-Object { "$_=$($Info["nic$_"])" })
}

# Sets the link of the running VM's NAT adapters (Get-BlNatNics on showvminfo) with controlvm setlinkstate<N>: 'off'
# for the whole build (it throws when an adapter cannot be disconnected or still shows connected), 'on' again before
# the VM is powered off and restored (logged, never throws; the restore of rig-base resets the cable anyway). Adapters
# of another kind are logged and left alone. Returns the NAT adapter numbers. Needs rig.ps1 (Invoke-VBox, Write-RigLog);
# defined here, before -Library returns, for baseline-local-vm.sh too.
function Set-BlNatLink([string]$Vm, [ValidateSet('on', 'off')][string]$State) {
    $vi = Invoke-VBox @('showvminfo', $Vm, '--machinereadable')
    if ($vi.code -ne 0) {
        $msg = "showvminfo $Vm failed: $($vi.out -join ' ')"
        if ($State -eq 'off') { throw $msg }
        Write-RigLog "  !! network: $msg"; return @()
    }
    $info = ConvertFrom-MachineReadable $vi.out
    $nics = @(Get-BlNatNics $info)
    if ($State -eq 'off') {
        foreach ($o in @(Get-BlOtherNics $info)) { Write-RigLog "  network: adapter $o is not NAT; left as it is" }
        if (-not $nics.Count) { Write-RigLog '  network: no NAT adapter to disconnect'; return @() }
    }
    foreach ($n in $nics) {
        $r = Invoke-VBox @('controlvm', $Vm, "setlinkstate$n", $State)
        if ($r.code -ne 0) {
            $msg = "controlvm $Vm setlinkstate$n $State failed: $($r.out -join ' ')"
            if ($State -eq 'off') { throw $msg }
            Write-RigLog "  !! network: $msg"
        }
    }
    $after = ConvertFrom-MachineReadable (Invoke-VBox @('showvminfo', $Vm, '--machinereadable')).out
    Write-RigLog "  network: NAT cable set $State on $(@($nics | ForEach-Object { "nic$_ (now cableconnected$_=$($after["cableconnected$_"]))" }) -join ', ')"
    if ($State -eq 'off') {
        $still = @($nics | Where-Object { $after.ContainsKey("cableconnected$_") -and "$($after["cableconnected$_"])" -cne 'off' })
        if ($still.Count) { throw "NAT adapter(s) $($still -join ', ') still connected after setlinkstate off" }
    }
    $nics
}

function Initialize-BlNative {
    if ('PurgeRig.BlHash' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
namespace PurgeRig {
public static class BlHash {
    public static string Hex(byte[] d) { var sb = new StringBuilder(d.Length * 2); foreach (byte b in d) sb.Append(b.ToString("x2")); return sb.ToString(); }
    // SHA-256 of the bytes with every CRLF read as LF (vm\rigtool\build.rs).
    public static string Sha256Lf(byte[] bytes) {
        var lf = new MemoryStream(bytes.Length);
        for (int i = 0; i < bytes.Length; i++) {
            if (bytes[i] == 13 && i + 1 < bytes.Length && bytes[i + 1] == 10) continue;
            lf.WriteByte(bytes[i]);
        }
        using (var h = SHA256.Create()) return Hex(h.ComputeHash(lf.ToArray()));
    }
    // SHA-256 of a gzip file's lines (each with its LF) after the first line, without the lines that start with
    // "#end<TAB>" (baseline-local-lib.sh bl_check: the body of a local baseline, header and seal left out).
    public static string BodySha256(string path) {
        byte[] buf;
        using (var f = File.OpenRead(path)) using (var g = new GZipStream(f, CompressionMode.Decompress)) using (var m = new MemoryStream()) { g.CopyTo(m); buf = m.ToArray(); }
        using (var h = SHA256.Create()) {
            int i = Array.IndexOf(buf, (byte)10);
            i = (i < 0) ? buf.Length : i + 1;
            while (i < buf.Length) {
                int j = Array.IndexOf(buf, (byte)10, i);
                int end = (j < 0) ? buf.Length : j + 1;
                bool isEnd = end - i >= 5 && buf[i] == 35 && buf[i + 1] == 101 && buf[i + 2] == 110 && buf[i + 3] == 100 && buf[i + 4] == 9;
                if (!isEnd) h.TransformBlock(buf, i, end - i, null, 0);
                i = end;
            }
            h.TransformFinalBlock(new byte[0], 0, 0);
            return Hex(h.Hash);
        }
    }
    // The header's source id (its 7th TAB field; "" when the header has fewer fields) and the #src lines of a gzip
    // local baseline: what tells "the source changed between two passes" from "the same source gave other bytes".
    public static string[] HeaderAndSources(string path) {
        var list = new System.Collections.Generic.List<string>();
        using (var f = File.OpenRead(path)) using (var g = new GZipStream(f, CompressionMode.Decompress)) using (var r = new StreamReader(g, new UTF8Encoding(false))) {
            string first = r.ReadLine() ?? "";
            string[] h = first.Split('\t');
            list.Add(h.Length >= 7 ? h[6] : "");
            string line;
            while ((line = r.ReadLine()) != null) {
                if (line.StartsWith("#src\t")) list.Add(line);
                else if (line.Length > 0 && line[0] != '#') break;   // records follow the #src lines
            }
        }
        return list.ToArray();
    }
    // True when the file holds the ASCII text (the engine's builder marker).
    public static bool FileContains(string path, string text) {
        byte[] b = File.ReadAllBytes(path), t = Encoding.ASCII.GetBytes(text);
        for (int i = 0; i + t.Length <= b.Length; i++) {
            if (b[i] != t[0]) continue;
            int k = 1; while (k < t.Length && b[i + k] == t[k]) k++;
            if (k == t.Length) return true;
        }
        return false;
    }
}
}
'@
}

# SHA-256 of rigtool's sources as vm\rigtool\build.rs (and bl_tree_sha256, truth\m1b.sh) compute it: Cargo.toml,
# Cargo.lock, build.rs and every file under src\, sorted by '/'-path (ordinal); per file '<sha256 CRLF-as-LF>  <path>\n';
# the SHA-256 of those lines.
function Get-BlTreeSha256([string]$Root) {
    Initialize-BlNative
    $rels = New-Object System.Collections.Generic.List[string]
    foreach ($f in 'Cargo.toml', 'Cargo.lock', 'build.rs') { $rels.Add($f) }
    $src = Join-Path $Root 'src'
    $full = (Resolve-Path -LiteralPath $Root).ProviderPath.TrimEnd('\')
    foreach ($f in @(Get-ChildItem -LiteralPath $src -Recurse -File -Force)) { $rels.Add($f.FullName.Substring($full.Length + 1).Replace('\', '/')) }
    $rels.Sort([StringComparer]::Ordinal)
    $lines = New-Object System.Text.StringBuilder
    foreach ($rel in $rels) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $Root ($rel.Replace('/', '\'))))
        [void]$lines.Append([PurgeRig.BlHash]::Sha256Lf($bytes) + '  ' + $rel + "`n")
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    [PurgeRig.BlHash]::Hex($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($lines.ToString())))
}

# The source hash a `rigtool version` line names (rigtool <ver> source-sha256 <hex>); $null when none.
function Get-BlVersionHash([string[]]$Lines) {
    foreach ($l in @($Lines)) { $m = [regex]::Match("$l", 'source-sha256 ([0-9a-f]+)'); if ($m.Success) { return $m.Groups[1].Value } }
    $null
}

# The guest (or host) job that builds the local baseline three times: the text of baseline-local-lib.sh bl_build_job with
# __DIR__ = the run directory as the builder sees it, __ENGINE__ = purge-engine.exe there and __RIGLIB__ = riglib.ps1
# there (vm\guest\riglib.ps1, for Wait-M2BootSettle). Passes: cold (right after boot, as the broker may), warm (the
# determinism pair), settled (after the guest settled and the standby list was emptied: W4 without boot-time I/O).
# -Passes first-read (-FirstRead): one build after the same settle as the settled pass, the first build of the boot.
function Get-BlBuildJob([string]$Dir, [string]$EnginePath, [string]$RigLibPath, [string[]]$Passes = @('cold', 'warm', 'settled')) {
    foreach ($v in $Dir, $EnginePath, $RigLibPath) { if (-not $v -or $v.Contains("'") -or $v -match '[\r\n]') { throw "bad path for the build job: '$v'" } }
    if (-not @($Passes).Count) { throw 'no pass for the build job' }
    foreach ($p in $Passes) { if (@('cold', 'warm', 'settled', 'first-read') -cnotcontains $p) { throw "bad pass '$p'" } }
    $t = @'
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
foreach ($pass in __PASSES__) {
    if ($pass -eq 'settled' -or $pass -eq 'first-read') {
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
$info = & $Engine baseline info (Join-Path $Dir "local-$($m.passes[0].pass).tsv.gz") 2>&1 | ForEach-Object { "$_" }
$sw.Stop()
$ErrorActionPreference = 'Stop'
[IO.File]::WriteAllLines((Join-Path $Dir 'info.txt'), [string[]]$info)
$m.info = [ordered]@{ exit = $LASTEXITCODE; seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2) }
$m.finished = (Get-Date).ToString('o')
[IO.File]::WriteAllText((Join-Path $Dir 'build.json'), (ConvertTo-Json -InputObject $m -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
"baseline-local build: $(($m.passes | ForEach-Object { '{0} exit {1} {2}s {3} MB peak {4} bytes' -f $_.pass, $_.exit, $_.seconds, $_.peak_working_set_mb, $_.file_bytes }) -join '; ')"
"settle: $(if ($m.settle.boot) { "boot waited $($m.settle.boot.waited_sec) s, uptime $($m.settle.boot.uptime_sec) s; " })CPU $($m.settle.cpu_percent) % (settled $($m.settle.cpu_settled), waited $($m.settle.cpu_waited_sec) s); cache purged $($m.settle.cache_purged)$(if ($m.settle.error) { '; ' + $m.settle.error }); network up at start: $(@($m.network_up.start) -join ', ')"
'@
    $t.Replace("`r`n", "`n").Replace('__PASSES__', ((@($Passes) | ForEach-Object { "'$_'" }) -join ', ')).Replace('__DIR__', $Dir).Replace('__ENGINE__', $EnginePath).Replace('__RIGLIB__', $RigLibPath)
}

# The rigtool baseline-diff arguments (paths as given; the caller runs it from the repository root).
function Get-BlDiffArgs([string]$Truth, [string]$Local, [string]$Neighbour, [string]$Out) {
    @('baseline-diff', '--truth', $Truth, '--local', $Local, '--neighbour', $Neighbour, '--areas', 'kb\baselines\view.json', '--out', $Out)
}

# Python-like text of a value in the check's lines (None, True, False).
function Format-BlValue($V) {
    if ($null -eq $V) { return 'None' }
    if ($V -is [bool]) { if ($V) { return 'True' } else { return 'False' } }
    "$V"
}

function Read-BlJson([string]$Path) { [IO.File]::ReadAllText($Path).TrimStart([char]0xFEFF) | ConvertFrom-Json }

# The final check of a run (baseline-local-lib.sh bl_check): the numbers gate M reads ({lines}) and the problems
# ({problems}; exit 3 when there is one): the local file incomplete (seal), not of the expected Windows ($Expect, '-'
# none), a pass with an exit code other than 0, a pass whose body (below the header, without #end) is not the cold
# pass's. A body that differs is told apart by the headers' source ids: other ids mean the source changed between the
# passes (Windows serviced or a package updated: the run is INVALID, {invalid}, and says so; not a determinism failure),
# the same id means the same source gave other bytes (a determinism failure). $Budget 'host' (30 s) or 'vm' (120 s) for
# the cold build. The local-<pass>.tsv.gz files and build-<pass>.log are next to $BuildPath. A build.json of two passes
# (schema 1, no settled pass) is read as before.
function Test-BlReport([string]$ReportPath, [string]$BuildPath, [string]$Expect, [string]$Budget) {
    Initialize-BlNative
    $rep = Read-BlJson $ReportPath
    $build = Read-BlJson $BuildPath
    $bad = @()
    $invalid = $false
    $loc = $rep.inputs.local
    if ($loc.complete -ne $true) { $bad += 'local baseline INCOMPLETE: ' + (@($loc.incomplete_reasons) -join '; ') }
    if ($Expect -ne '-' -and "$($loc.name)".ToLowerInvariant() -ne $Expect.ToLowerInvariant()) { $bad += "local baseline is of $($loc.name), the truth is $Expect" }
    $passes = @($build.passes)
    foreach ($p in $passes) { if ($p.exit -ne 0) { $bad += "$($p.pass) build exit $(Format-BlValue $p.exit)" } }
    $dir = Split-Path -Parent $BuildPath
    $body = @{}
    foreach ($p in $passes) {
        $f = Join-Path $dir "local-$($p.pass).tsv.gz"
        try {
            $hs = [PurgeRig.BlHash]::HeaderAndSources($f)
            $body[$p.pass] = [pscustomobject]@{ sha = [PurgeRig.BlHash]::BodySha256($f); id = $hs[0]; src = @($hs | Select-Object -Skip 1) }
        } catch { $bad += "$f`: $($_.Exception.InnerException.Message)$(if (-not $_.Exception.InnerException) { $_.Exception.Message })" }
    }
    $first = $passes[0].pass
    foreach ($p in @($passes | Select-Object -Skip 1)) {
        $a = $body[$first]; $o = $body[$p.pass]
        if (-not $a -or -not $o -or $a.sha -eq $o.sha) { continue }
        # The sources whose #src line differs, for the reader.
        $diff = @(foreach ($s in 'S1', 'S2', 'S3', 'S4', 'S5') {
            $x = @($a.src | Where-Object { $_.StartsWith("#src`t$s`t") }) -join "`n"
            $y = @($o.src | Where-Object { $_.StartsWith("#src`t$s`t") }) -join "`n"
            if ($x -cne $y) { $s }
        })
        $srcText = $(if ($diff.Count) { "#src lines that differ: $($diff -join ', ')" } else { 'every #src line equal' })
        if ($a.id -and $o.id -and $a.id -cne $o.id) {
            $invalid = $true
            $bad += "RUN INVALID: the source changed between the $first and $($p.pass) passes (source id $($a.id) vs $($o.id); $srcText): not a determinism failure; rerun with the source held still"
        } elseif ($a.id -and $a.id -ceq $o.id) {
            $bad += "$first and $($p.pass) builds differ below the header with the same source id $($a.id) (a determinism failure; $srcText): $($a.sha) vs $($o.sha)"
        } else {
            $bad += "$first and $($p.pass) builds differ below the header (no source id to compare; $srcText): $($a.sha) vs $($o.sha)"
        }
    }
    # R1, R2 (budget 'vm') build with the NAT cable disconnected: an adapter the guest reports up means it was not.
    if ($Budget -eq 'vm' -and $build.network_up) {
        foreach ($w in 'start', 'settled') {
            $up = @($build.network_up.$w | Where-Object { $_ })
            if ($up.Count) { $invalid = $true; $bad += "RUN INVALID: the guest had a network adapter up ($w`: $($up -join ', ')); the build must run offline" }
        }
    }
    $t = $rep.total
    $nbs = '[' + ((@($rep.inputs.neighbours) | ForEach-Object { "'$($_.name)'" }) -join ', ') + ']'
    $lines = @()
    $lines += "local $($loc.name) complete=$(Format-BlValue $loc.complete); truth $($rep.inputs.truth.name) ($($t.truth) keys in scope); neighbours $nbs"
    $lines += "TOTAL coverage local $($t.coverage_local) merged $($t.coverage_merged); false absent local $($t.false_absent_local) merged $($t.false_absent_merged); shared-shape false absent local $($t.shared_shape_false_absent_local) merged $($t.shared_shape_false_absent_merged); W1 scope (>= 0.99 merged) $(Format-BlValue $t.checks.w1_scope)"
    foreach ($a in @($rep.areas)) {
        $lines += ('  {0,-28} truth {1,7}  local {2}  merged {3}  shared fa {4}/{5}  S3 local {6}  S2 merged {7}' -f $a.id, $a.truth, $a.coverage_local, $a.coverage_merged,
            $a.shared_shape_false_absent_local, $a.shared_shape_false_absent_merged, (Format-BlValue $a.checks.s3_local), (Format-BlValue $a.checks.s2_merged))
    }
    $named = { param($Name, $Index) $q = @($passes | Where-Object { $_.pass -eq $Name } | Select-Object -First 1); if ($q.Count) { $q[0] } elseif ($null -ne $Index -and $Index -lt $passes.Count) { $passes[$Index] } else { $null } }
    $cold = & $named 'cold' 0
    $warm = & $named 'warm' 1
    $settled = & $named 'settled' $null
    $budgetSec = $(if ($Budget -eq 'host') { 30 } else { 120 })
    $lines += "W4: cold build $($cold.seconds) s (budget $budgetSec s on $($build.cpus) CPUs), warm $($warm.seconds) s; peak $($cold.peak_working_set_mb) MB (300); file $($cold.file_bytes) bytes (15 MB); load (baseline info) $($build.info.seconds) s (1.5 s for the view)"
    if ($settled) {
        $st = $build.settle
        $boot = $(if ($st.boot) { "boot settle $($st.boot.waited_sec) s (ReadyBoot $(if ($st.boot.bounded) { 'bound reached' } else { 'stopped' }), uptime $($st.boot.uptime_sec) s)" } else { 'no boot settle' })
        $lines += "W4 settled: cold build $($settled.seconds) s (budget $budgetSec s on $($build.cpus) CPUs) at uptime $($settled.uptime_sec) s, after $boot, CPU $($st.cpu_percent) % over 30 s ($(if ($st.cpu_settled) { 'settled' } else { 'NOT settled' }) after $($st.cpu_waited_sec) s), standby list purged $(Format-BlValue $st.cache_purged)$(if (-not $st.cache_purged) { ' (not a cold read)' })$(if ($st.error) { '; ' + $st.error })"
    }
    if ($build.network_up) {
        $lines += "network: adapters up at the start [$(@($build.network_up.start) -join ', ')], before the settled pass [$(@($build.network_up.settled) -join ', ')]"
    }
    foreach ($p in $passes) {
        $log = Join-Path $dir "build-$($p.pass).log"
        if (-not (Test-Path -LiteralPath $log)) { continue }
        $ph = @(Get-Content -LiteralPath $log | Where-Object { $_ -match '^timing: baseline\.local\.(read|expand|parse|s1|total) ' } | ForEach-Object { $_.Substring('timing: baseline.local.'.Length) })
        if ($ph.Count) { $lines += "  phases $($p.pass): $($ph -join '; ')" }
    }
    foreach ($b in $bad) { $lines += 'PROBLEM: ' + $b }
    [pscustomobject]@{ lines = $lines; problems = $bad; ok = (-not $bad.Count); invalid = $invalid }
}

# -FirstRead: the evidence of the one build (purge.rig.baseline-local-firstread/1) from its build.json, and the
# problems (exit 3): the build failed, the settle did not hold, the guest was online, or it took over $BudgetSec.
# $Sources: [PurgeRig.BlHash]::HeaderAndSources of the file (source id, then the #src lines), or @().
function Get-BlFirstReadEvidence($Build, $Spec, [int]$BudgetSec, [string[]]$Sources = @()) {
    $p = @($Build.passes | Where-Object { $_.pass -eq 'first-read' } | Select-Object -First 1)
    $bad = @()
    if (@($Build.passes).Count -ne 1 -or -not $p.Count) { $bad += "expected exactly one pass 'first-read', got $(@($Build.passes | ForEach-Object { $_.pass }) -join ', ')" }
    $p = $(if ($p.Count) { $p[0] } else { $null })
    $st = $Build.settle
    if ($p -and $p.exit -ne 0) { $bad += "the build exited $(Format-BlValue $p.exit)" }
    if (-not $st -or -not $st.cpu_settled) { $bad += 'the CPU did not settle before the build (not a settled first read)' }
    if (-not $st -or -not $st.cache_purged) { $bad += "the standby list was not emptied (not a read from disk)$(if ($st.error) { ': ' + $st.error })" }
    foreach ($w in 'start', 'settled') { $up = @($Build.network_up.$w | Where-Object { $_ }); if ($up.Count) { $bad += "the guest had a network adapter up ($w`: $($up -join ', '))" } }
    $sec = $(if ($p) { $p.seconds } else { $null })
    $within = ($null -ne $sec -and [double]$sec -le $BudgetSec)
    if ($null -ne $sec -and -not $within) { $bad += "W4 settled first read $sec s is over the budget of $BudgetSec s" }
    $doc = [ordered]@{ schema = 'purge.rig.baseline-local-firstread/1'; mode = $Spec.mode; vm = $Spec.vm; run = $Spec.run
        os = $Build.os; cpus = $Build.cpus; elevated = $Build.elevated; engine_sha256 = $Build.engine_sha256; started = $Build.started; finished = $Build.finished
        seconds = $sec; exit = $(if ($p) { $p.exit } else { $null }); uptime_sec = $(if ($p) { $p.uptime_sec } else { $null })
        peak_working_set_mb = $(if ($p) { $p.peak_working_set_mb } else { $null }); file_bytes = $(if ($p) { $p.file_bytes } else { $null })
        total_line = $(if ($p) { $p.total_line } else { $null }); load_seconds = $Build.info.seconds
        budget_sec = $BudgetSec; budget_source = 'review BL-RM S7: settled first build at most 60 s on the rig VM (design section 5: cold build at most 120 s on a 2-vCPU VM)'
        within_budget = $within; settle = $st; network_up = $Build.network_up
        source_id = $(if (@($Sources).Count) { $Sources[0] } else { $null }); src = @($Sources | Select-Object -Skip 1)
        problems = $bad; ok = (-not $bad.Count) }
    [pscustomobject]@{ doc = $doc; problems = $bad; ok = (-not $bad.Count) }
}

if ($Library) { return }

# ------------------------------------------------------------------------------------------ host checks

. (Join-Path $BlRigDir 'rig.ps1')
$Spec = Get-BlRunSpec $B.mode
if ($B.first_read) {
    if (-not $Spec.vm) { Write-Host 'REFUSED: -FirstRead is for -Mode R1 or R2 (a rig VM restored and booted for it)'; exit 2 }
    $Spec.run = "$($Spec.run)-firstread"
}
if ($Spec.vm) { $script:VmName = $Spec.vm }

function Write-BlLines([string[]]$Lines) { foreach ($l in @($Lines)) { Write-RigLog $l } }

function Stop-Bl([int]$Code, [string]$Message) {
    if ($Message) { Write-RigLog "$($Spec.run): $Message" }
    if ($script:BlLock) { $script:BlLock.Dispose(); $script:BlLock = $null }
    Remove-PwTemp
    exit $Code
}

# Engine and rigtool checks shared by every mode (exit 2 on a refusal). Returns {engine, rigtool} full paths.
function Assert-BlTools {
    $eng = $(if ($B.engine) { $B.engine } else { Join-Path $BlRepo 'target\release\purge-engine.exe' })
    Initialize-BlNative
    if (-not (Test-Path -LiteralPath $eng -PathType Leaf) -or -not [PurgeRig.BlHash]::FileContains((Resolve-Path -LiteralPath $eng).ProviderPath, 'purge-baseline-local')) {
        Stop-Bl 2 "REFUSED: $eng missing or without the local baseline builder (BL-BUILD; cargo build --release -p purge-engine)"
    }
    $eng = (Resolve-Path -LiteralPath $eng).ProviderPath
    if ((Split-Path -Leaf $eng) -ne 'purge-engine.exe') { Stop-Bl 2 "REFUSED: the engine file must be named purge-engine.exe: $eng" }
    $rt = $B.rigtool
    if (-not $rt -and $env:RIG_RIGTOOL) { $rt = $env:RIG_RIGTOOL }
    if (-not $rt) { $rt = Join-Path $BlRigDir 'rigtool\target\release\rigtool.exe' }
    if (-not (Test-Path -LiteralPath $rt -PathType Leaf)) { Stop-Bl 2 "REFUSED: no rigtool at $rt (cargo build --release in vm\rigtool)" }
    $rt = (Resolve-Path -LiteralPath $rt).ProviderPath
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        $built = Get-BlVersionHash @(& $rt version 2>$null | ForEach-Object { "$_" })
        $help = @(& $rt help 2>&1 | ForEach-Object { "$_" })
    } finally { $ErrorActionPreference = $old }
    $tree = Get-BlTreeSha256 (Join-Path $BlRigDir 'rigtool')
    if (-not $built -or $built -ne $tree) { Stop-Bl 2 "REFUSED: $rt was built from sources $(if ($built) { $built } else { '?' }), vm\rigtool is $tree (rebuild it)" }
    if (-not ($help -match 'baseline-diff')) { Stop-Bl 2 "REFUSED: $rt has no baseline-diff" }
    foreach ($b in @($Spec.truth, $Spec.neighbour) + @($Spec.baselines) | Where-Object { $_ }) {
        if (-not (Test-Path -LiteralPath (Join-Path $BlRepo "kb\baselines\$b.tsv.gz") -PathType Leaf)) { Stop-Bl 2 "REFUSED: no kb\baselines\$b.tsv.gz" }
    }
    [pscustomobject]@{ engine = $eng; rigtool = $rt }
}

# The per-run lock: an exclusive open of vm\runs\.lock-<name>, released when this process ends.
function Lock-Bl([string]$Name) {
    New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
    try { $script:BlLock = [IO.File]::Open((Join-Path $script:RunsDir ".lock-$Name"), 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { Stop-Bl 2 "REFUSED: another campaign script holds the lock for $Name" }
}

# Runs rigtool baseline-diff from the repository root (relative paths in the report); its table goes to the log.
function Invoke-BlDiff([string]$Tool, [string[]]$A) {
    Push-Location -LiteralPath $BlRepo
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        & $Tool @A 2>&1 | ForEach-Object { Write-RigLog "$_" }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $old; Pop-Location }
    $code
}

$script:BlLock = $null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
$script:RigLogFile = Join-Path $script:RunsDir "bl-$($Spec.run)-$stamp.log"
$started = Get-Date
# Not $R: rig.ps1 code in this scope assigns $r (PowerShell names are case-insensitive).
$BlReportDir = Join-Path $BlRigDir 'truth\baseline-local'
$RRel = 'vm\truth\baseline-local'

# ------------------------------------------------------------------------------------------ R5: this host

if ($Spec.mode -eq 'R5') {
    Lock-Bl $Spec.run
    $tools = Assert-BlTools
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin -and -not $B.allow_unelevated) { Stop-Bl 2 'REFUSED: not elevated (S4 would be incomplete); run elevated or pass -AllowUnelevated' }
    $vms = @(Get-RigVmProcesses)
    if ($vms.Count) { Stop-Bl 2 "REFUSED: a VirtualBox VM runs on the host ($($vms -join ', ')); the build times are the W4 budgets" }
    $null = Move-RunToOld -Run $Spec.run
    $run = Join-Path $script:RunsDir $Spec.run
    New-Item -ItemType Directory -Force $run, $BlReportDir | Out-Null
    $job = Join-Path $run 'build-job.ps1'
    [IO.File]::WriteAllText($job, (Get-BlBuildJob $run $tools.engine (Join-Path $BlRigDir 'guest\riglib.ps1')), (New-Object System.Text.UTF8Encoding($true)))
    Write-RigLog "== $($Spec.run) start $($started.ToString('o')); engine $((Get-FileHash -Algorithm SHA256 -LiteralPath $tools.engine).Hash.ToLower().Substring(0, 12)) ($($tools.engine)); elevated $admin"
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $job 2>&1 | ForEach-Object { Write-RigLog "$_" }
    $jc = $LASTEXITCODE
    $ErrorActionPreference = $old
    if ($jc -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $run 'build.json'))) { Stop-Bl 2 "build job failed (exit $jc)" }
    Copy-Item -LiteralPath (Join-Path $run 'build.json') -Destination (Join-Path $BlReportDir "$($Spec.run)-build.json") -Force
    $rc = 0
    foreach ($truth in $Spec.baselines) {
        foreach ($nb in $Spec.baselines) {
            if ($nb -eq $truth) { continue }
            $out = "$RRel\$($Spec.run)-vs-$truth.json"
            Write-RigLog "== baseline-diff: proxy truth $truth, neighbour $nb -> $out"
            $code = Invoke-BlDiff $tools.rigtool (Get-BlDiffArgs "kb\baselines\$truth.tsv.gz" "vm\runs\$($Spec.run)\local-cold.tsv.gz" "kb\baselines\$nb.tsv.gz" $out)
            if ($code -ne 0) { Stop-Bl 2 "baseline-diff exited $code" }
            $chk = Test-BlReport (Join-Path $BlRepo $out) (Join-Path $run 'build.json') '-' 'host'
            Write-BlLines $chk.lines
            if (-not $chk.ok) { $rc = 3 }
        }
    }
    Stop-Bl $rc "== $($Spec.run) end $((Get-Date).ToString('o')), exit $rc"
}

# ------------------------------------------------------------------------------------------ R1, R2: a rig VM

Assert-RigVm $Spec.vm
Lock-Bl $Spec.vm
$f = $env:VMPWFILE
$readable = $false
if ($f -and (Test-Path -LiteralPath $f -PathType Leaf)) { try { [IO.File]::OpenRead($f).Dispose(); $readable = $true } catch { } }
if (-not $readable) { Stop-Bl 2 'REFUSED: VMPWFILE not set or not readable' }
$vi = Invoke-VBox @('showvminfo', $Spec.vm, '--machinereadable')
$state = $(if ($vi.code -eq 0) { (ConvertFrom-MachineReadable $vi.out)['VMState'] } else { $null })
if (-not $state) { Stop-Bl 2 "REFUSED: VM $($Spec.vm) not found by VBoxManage" }
if (Test-BlVmBusyState $state) { Stop-Bl 2 "REFUSED: VM $($Spec.vm) is $state" }
$others = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessId -ne $PID -and "$($_.CommandLine)" -match 'rig[\w-]*\.ps1' -and "$($_.CommandLine)".Contains($Spec.vm) })
if ($others.Count) { Stop-Bl 2 "REFUSED: a rig script process for $($Spec.vm) is alive (pid $(($others | ForEach-Object { $_.ProcessId }) -join ', '))" }
$tools = Assert-BlTools
Add-Type -AssemblyName Microsoft.VisualBasic
$avail = [int]((New-Object Microsoft.VisualBasic.Devices.ComputerInfo).AvailablePhysicalMemory / 1MB)
if ($avail -lt 6144) { Stop-Bl 2 "REFUSED: only $avail MiB RAM available (need 6144 for a 4 GiB VM)" }

$passes = @($(if ($B.first_read) { @('first-read') } else { @('cold', 'warm', 'settled') }))   # @(): one pass stays an array ($passes[0] is its name, not 'f')
$job = Get-BlBuildJob "C:\cr\out\$($Spec.run)" 'C:\cr\bin\purge-engine.exe' 'C:\cr\guest\riglib.ps1' $passes
Write-RigLog "== $($Spec.run) start $($started.ToString('o')) on $($Spec.vm); engine $((Get-FileHash -Algorithm SHA256 -LiteralPath $tools.engine).Hash.ToLower().Substring(0, 12)) ($($tools.engine)); truth $($Spec.truth); neighbour $($Spec.neighbour)"
$rc = 1
$script:BlNat = @()
try {
    $null = Get-PwFile
    $null = Move-RunToOld -Run $Spec.run
    if ($Spec.no3d) { Restore-Base -Snapshot rig-base -No3D } else { Restore-Base -Snapshot rig-base }
    # Offline for the whole build (gate M round 2): the rig reaches the guest through guestcontrol, not the network.
    $script:BlNat = @(Set-BlNatLink $Spec.vm 'off')
    Push-Tools -RigTool $tools.rigtool -Engine $tools.engine -NoBaselines
    # Three passes and the settle wait before the third (Get-BlBuildJob); -FirstRead: the settle, then one build.
    $j = Invoke-GuestJob -Text $job -Name "$($Spec.run)-build" -TimeoutSec 3600
    Write-BlLines @("$($j.log)" -split "`r?`n" | Where-Object { $_ -ne '' })
    if (-not $j.done) { throw 'the build job did not finish' }
    $got = @(Pull-Run -Run $Spec.run)
    foreach ($n in @($passes | ForEach-Object { "local-$_.tsv.gz" }) + @('build.json', "build-$($passes[0]).log", 'info.txt')) {
        if ($got -notcontains $n) { throw "not pulled: $n" }
    }
    $rc = 0
} catch {
    Write-RigLog "!! $($Spec.run) failed: $($_.Exception.Message)"
    $rc = 1
} finally {
    # Leave the VM as the run found it: rig-base, powered off (a live snapshot comes back 'saved').
    try {
        $st = Get-VmState
        if ($script:BlNat.Count -and $st -eq 'running') { $null = Set-BlNatLink $script:VmName 'on' }
        if (Test-BlVmBusyState $st) {
            $r = Invoke-VBox @('controlvm', $script:VmName, 'poweroff')
            if ($r.code -ne 0) { Write-RigLog "  poweroff: $($r.out -join ' ')" }
            $null = Wait-VmState @('poweroff', 'aborted', 'saved') 120
        }
        $ok = $false
        for ($i = 1; $i -le 6 -and -not $ok; $i++) {
            $r = Invoke-VBox @('snapshot', $script:VmName, 'restore', 'rig-base')
            if ($r.code -eq 0) { $ok = $true } else { Start-Sleep -Seconds 3 }
        }
        Write-RigLog "VM $script:VmName restored to rig-base and left off: $ok (state $(Get-VmState))"
        $cfg = ConvertFrom-MachineReadable (Invoke-VBox @('showvminfo', $script:VmName, '--machinereadable')).out
        Write-RigLog "  network after the restore: $(@(Get-BlNatNics $cfg | ForEach-Object { "nic$_ cableconnected$_=$($cfg["cableconnected$_"])" }) -join ', ')"
    } catch { Write-RigLog "!! leaving the VM at rig-base failed: $($_.Exception.Message)" }
    Remove-PwTemp
}
if ($rc -eq 0 -and $B.first_read) {
    # W4 settled first read: the evidence JSON, no baseline-diff (the three-pass run gives the coverage).
    New-Item -ItemType Directory -Force $BlReportDir | Out-Null
    $build = Join-Path $script:RunsDir "$($Spec.run)\build.json"
    Copy-Item -LiteralPath $build -Destination (Join-Path $BlReportDir "$($Spec.run)-build.json") -Force
    Initialize-BlNative
    $srcs = @(); try { $srcs = @([PurgeRig.BlHash]::HeaderAndSources((Join-Path $script:RunsDir "$($Spec.run)\local-first-read.tsv.gz"))) } catch { Write-RigLog "!! reading the #src lines: $($_.Exception.Message)" }
    $ev = Get-BlFirstReadEvidence (Read-BlJson $build) $Spec $BlFirstReadBudgetSec $srcs
    $ev.doc.engine_path = $tools.engine
    [IO.File]::WriteAllText((Join-Path $BlReportDir "$($Spec.run).json"), (ConvertTo-Json -InputObject $ev.doc -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    $sd = $ev.doc.settle
    Write-RigLog ("W4 settled first read: {0} s (budget {1} s, BL-RM S7) at uptime {2} s on {3} CPUs; peak {4} MB; file {5} bytes; CPU {6} % settled {7}; standby purged {8} -> $RRel\$($Spec.run).json" -f `
        $ev.doc.seconds, $BlFirstReadBudgetSec, $ev.doc.uptime_sec, $ev.doc.cpus, $ev.doc.peak_working_set_mb, $ev.doc.file_bytes, $sd.cpu_percent, $sd.cpu_settled, $sd.cache_purged)
    foreach ($b in $ev.problems) { Write-RigLog "PROBLEM: $b" }
    $rc = $(if ($ev.ok) { 0 } else { 3 })
} elseif ($rc -eq 0) {
    New-Item -ItemType Directory -Force $BlReportDir | Out-Null
    $out = "$RRel\$($Spec.run).json"
    Write-RigLog "== baseline-diff (host): truth $($Spec.truth), local vm\runs\$($Spec.run)\local-cold.tsv.gz, neighbour $($Spec.neighbour)"
    $code = Invoke-BlDiff $tools.rigtool (Get-BlDiffArgs "kb\baselines\$($Spec.truth).tsv.gz" "vm\runs\$($Spec.run)\local-cold.tsv.gz" "kb\baselines\$($Spec.neighbour).tsv.gz" $out)
    if ($code -ne 0) {
        Write-RigLog "!! baseline-diff exited $code"
        $rc = 1
    } else {
        $build = Join-Path $script:RunsDir "$($Spec.run)\build.json"
        Copy-Item -LiteralPath $build -Destination (Join-Path $BlReportDir "$($Spec.run)-build.json") -Force
        $chk = Test-BlReport (Join-Path $BlRepo $out) $build $Spec.truth 'vm'
        Write-BlLines $chk.lines
        $rc = $(if ($chk.ok) { 0 } else { 3 })
    }
}
Stop-Bl $rc "== $($Spec.run) end $((Get-Date).ToString('o')), $([int]((Get-Date) - $started).TotalMinutes) min, exit $rc"
