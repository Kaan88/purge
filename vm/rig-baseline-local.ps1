<#
  Purge rig, gate M runs R1, R2 and R5 (docs\BASELINE_LOCAL_DESIGN.md section 8.2, vm\RIG.md section 8a; package
  BL-MEASURE) on the Windows rig host. Host driver, Windows PowerShell 5.1; dot-sources rig.ps1 for the VM helpers and
  leaves it unchanged. It does what tools/linux/campaigns/baseline-local-{vm,r1,r2,r5}.sh do on a Linux host.

    $env:VMPWFILE = 'C:\path\to\pw.txt'
    .\vm\rig-baseline-local.ps1 -Mode R1      # Purge-CleanPro: truth Professional-26340.9882, neighbour EnterpriseSEval-26100.1742
    .\vm\rig-baseline-local.ps1 -Mode R2      # Inbound-Win11-Test, 3D off: truth and neighbour the other way round
    .\vm\rig-baseline-local.ps1 -Mode R5      # this host, elevated, read-only; no VM, no VMPWFILE

  R1, R2 (run bl-r1-cleanpro, bl-r2-inbound): refuses unless the per-VM lock (vm\runs\.lock-<vm>) is free, VMPWFILE
  names a readable file, the VM exists and is not running (or paused, starting, ...), no other rig script for that VM
  is alive, the engine holds the local baseline builder, both shipped baselines exist, rigtool was built from the
  tree's sources (`rigtool version` hash = the hash of vm\rigtool, as BIND) and has baseline-diff, and 6 GiB RAM are
  available. Then: vm\runs\<run>\ moved to vm\runs\_old\, restore rig-base (nothing installed), Push-Tools
  -NoBaselines (the exact baseline stays hidden; the checked rigtool and the engine are pushed), one guest job that
  builds the local baseline twice (cold, warm) with PURGE_TIMING=1 into C:\cr\out\<run>\ (Get-BlBuildJob, the same
  text as baseline-local-lib.sh bl_build_job), Pull-Run to vm\runs\<run>\, the VM restored to rig-base and left off;
  then on the host `rigtool baseline-diff` (truth = the VM's own shipped baseline, local = the cold build, neighbour =
  the other shipped baseline) into vm\truth\baseline-local\<run>.json, build.json copied beside it as
  <run>-build.json, and the final check (Test-BlReport, as bl_check).

  R5 (run r5-host): refuses unless elevated (S4 reads every user's packages only elevated; -AllowUnelevated builds an
  incomplete file, which the check then reports), the engine and rigtool pass the same checks and no VirtualBox VM
  runs on the host (the build times are the W4 budgets). Builds the host's local baseline twice into vm\runs\r5-host\
  (the same job, run by a child powershell.exe), copies build.json to vm\truth\baseline-local\r5-host-build.json and
  runs baseline-diff against each shipped baseline as a proxy truth with the other as neighbour
  (vm\truth\baseline-local\r5-host-vs-<baseline>.json): context and budgets, not a safety measurement.

  -Engine: default target\release\purge-engine.exe (cargo build --release -p purge-engine). -RigTool: default
  $env:RIG_RIGTOOL, else vm\rigtool\target\release\rigtool.exe (cargo build --release in vm\rigtool).
  Console log: vm\runs\bl-<run>-<stamp>.log (every line also on the console).
  Exit code: 0 ok; 1 the VM part or the diff failed; 2 refused to start (R5: also the build job or a diff failed);
  3 the report shows a problem (seal failed or file incomplete, the passes differ below the header, the local file is
  not of the truth's Windows, a build exit code was not 0).
  -Library: define the functions and return (vm\guest\tests\rig-selftest.ps1).
#>
[CmdletBinding()]
param(
    [ValidateSet('R1', 'R2', 'R5')] [string] $Mode = 'R5',
    [string] $Engine = '',
    [string] $RigTool = '',
    [switch] $AllowUnelevated,
    [switch] $Library
)
$ErrorActionPreference = 'Stop'

# rig.ps1 has parameters of its own (Mode, Engine, ...): ours are kept here first.
$B = [ordered]@{ mode = $Mode; engine = $Engine; rigtool = $RigTool; allow_unelevated = [bool]$AllowUnelevated }
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

# The guest (or host) job that builds the local baseline twice: the text of baseline-local-lib.sh bl_build_job with
# __DIR__ = the run directory as the builder sees it and __ENGINE__ = purge-engine.exe there.
function Get-BlBuildJob([string]$Dir, [string]$EnginePath) {
    foreach ($v in $Dir, $EnginePath) { if (-not $v -or $v.Contains("'") -or $v -match '[\r\n]') { throw "bad path for the build job: '$v'" } }
    $t = @'
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
'@
    $t.Replace("`r`n", "`n").Replace('__DIR__', $Dir).Replace('__ENGINE__', $EnginePath)
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
# none), a pass with an exit code other than 0, the cold and warm bodies (below the header, without #end) not equal.
# $Budget 'host' (30 s) or 'vm' (120 s) for the cold build. The local-<pass>.tsv.gz files are next to $BuildPath.
function Test-BlReport([string]$ReportPath, [string]$BuildPath, [string]$Expect, [string]$Budget) {
    Initialize-BlNative
    $rep = Read-BlJson $ReportPath
    $build = Read-BlJson $BuildPath
    $bad = @()
    $loc = $rep.inputs.local
    if ($loc.complete -ne $true) { $bad += 'local baseline INCOMPLETE: ' + (@($loc.incomplete_reasons) -join '; ') }
    if ($Expect -ne '-' -and "$($loc.name)".ToLowerInvariant() -ne $Expect.ToLowerInvariant()) { $bad += "local baseline is of $($loc.name), the truth is $Expect" }
    $passes = @($build.passes)
    foreach ($p in $passes) { if ($p.exit -ne 0) { $bad += "$($p.pass) build exit $(Format-BlValue $p.exit)" } }
    $bodies = @()
    $dir = Split-Path -Parent $BuildPath
    foreach ($p in $passes) {
        $f = Join-Path $dir "local-$($p.pass).tsv.gz"
        try { $bodies += [PurgeRig.BlHash]::BodySha256($f) } catch { $bad += "$f`: $($_.Exception.InnerException.Message)$(if (-not $_.Exception.InnerException) { $_.Exception.Message })" }
    }
    if ($bodies.Count -eq 2 -and $bodies[0] -ne $bodies[1]) { $bad += "cold and warm builds differ below the header: $($bodies[0]) vs $($bodies[1])" }
    $t = $rep.total
    $nbs = '[' + ((@($rep.inputs.neighbours) | ForEach-Object { "'$($_.name)'" }) -join ', ') + ']'
    $lines = @()
    $lines += "local $($loc.name) complete=$(Format-BlValue $loc.complete); truth $($rep.inputs.truth.name) ($($t.truth) keys in scope); neighbours $nbs"
    $lines += "TOTAL coverage local $($t.coverage_local) merged $($t.coverage_merged); false absent local $($t.false_absent_local) merged $($t.false_absent_merged); shared-shape false absent local $($t.shared_shape_false_absent_local) merged $($t.shared_shape_false_absent_merged); W1 scope (>= 0.99 merged) $(Format-BlValue $t.checks.w1_scope)"
    foreach ($a in @($rep.areas)) {
        $lines += ('  {0,-28} truth {1,7}  local {2}  merged {3}  shared fa {4}/{5}  S3 local {6}  S2 merged {7}' -f $a.id, $a.truth, $a.coverage_local, $a.coverage_merged,
            $a.shared_shape_false_absent_local, $a.shared_shape_false_absent_merged, (Format-BlValue $a.checks.s3_local), (Format-BlValue $a.checks.s2_merged))
    }
    $cold = $passes[0]
    $budgetSec = $(if ($Budget -eq 'host') { 30 } else { 120 })
    $lines += "W4: cold build $($cold.seconds) s (budget $budgetSec s on $($build.cpus) CPUs), warm $($passes[-1].seconds) s; peak $($cold.peak_working_set_mb) MB (300); file $($cold.file_bytes) bytes (15 MB); load (baseline info) $($build.info.seconds) s (1.5 s for the view)"
    foreach ($b in $bad) { $lines += 'PROBLEM: ' + $b }
    [pscustomobject]@{ lines = $lines; problems = $bad; ok = (-not $bad.Count) }
}

if ($Library) { return }

# ------------------------------------------------------------------------------------------ host checks

. (Join-Path $BlRigDir 'rig.ps1')
$Spec = Get-BlRunSpec $B.mode
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
    [IO.File]::WriteAllText($job, (Get-BlBuildJob $run $tools.engine), (New-Object System.Text.UTF8Encoding($true)))
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

$job = Get-BlBuildJob "C:\cr\out\$($Spec.run)" 'C:\cr\bin\purge-engine.exe'
Write-RigLog "== $($Spec.run) start $($started.ToString('o')) on $($Spec.vm); engine $((Get-FileHash -Algorithm SHA256 -LiteralPath $tools.engine).Hash.ToLower().Substring(0, 12)) ($($tools.engine)); truth $($Spec.truth); neighbour $($Spec.neighbour)"
$rc = 1
try {
    $null = Get-PwFile
    $null = Move-RunToOld -Run $Spec.run
    if ($Spec.no3d) { Restore-Base -Snapshot rig-base -No3D } else { Restore-Base -Snapshot rig-base }
    Push-Tools -RigTool $tools.rigtool -Engine $tools.engine -NoBaselines
    $j = Invoke-GuestJob -Text $job -Name "$($Spec.run)-build" -TimeoutSec 1800
    Write-BlLines @("$($j.log)" -split "`r?`n" | Where-Object { $_ -ne '' })
    if (-not $j.done) { throw 'the build job did not finish' }
    $got = @(Pull-Run -Run $Spec.run)
    foreach ($n in 'local-cold.tsv.gz', 'local-warm.tsv.gz', 'build.json', 'build-cold.log', 'info.txt') {
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
    } catch { Write-RigLog "!! leaving the VM at rig-base failed: $($_.Exception.Message)" }
    Remove-PwTemp
}
if ($rc -eq 0) {
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
