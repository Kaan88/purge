<#
  Purge rig v2: host driver (vm\RIG.md §1, §4). Windows PowerShell 5.1 compatible.

  Dot-source and call functions, or run a campaign directly:
    $env:VMPWFILE = 'C:\path\to\pw.txt'      # bare guest password, or a line "password=..."
    . .\vm\rig.ps1
    Invoke-Campaign -Ids npp,7zip,firefox -Nulls 3
    .\vm\rig.ps1 -Ids npp,firefox -Nulls 3     # same, without dot-sourcing

  Per run: power off -> snapshot restore rig-base -> start headless -> wait for the agent -> copy fresh
  rigtool.exe, purge-engine.exe (+ kb\baselines) and guest\*.ps1 -> run the job (run-app.ps1 /
  null-run.ps1) -> copy C:\cr\out\<run>\ to vm\runs\<run>\. A failed run is recorded and the campaign goes on.

  Engine runs (M1a R0, vm\RIG.md §4a): the guest uninstalls with purge-engine and writes its plan; the run
  name carries a prefix so the frozen M0 directories vm\runs\<id>\ are never touched:
    Invoke-Campaign -Ids vscode,vscode-user,git,firefox,firefox-tb,npp -Nulls 0 -RunPrefix r0- `
                    -Engine .\target\release\purge-engine.exe

  Before a run starts, an existing vm\runs\<run>\ is moved to vm\runs\_old\<run>-<stamp>\, so a run
  directory never mixes files from two runs.

  Building rig-base (once, from a clean VM with the user logged on and agent.ps1 running; README order):
    Wait-Agent; Push-Tools; Invoke-SetupBase
    Save-BaseSnapshot -Off                      # offline 'rig-base-off' first
    Restore-Base -Snapshot rig-base-off         # proves autologon + PurgeRigAgent; let it settle ~10 min
    Save-BaseSnapshot                           # then the live 'rig-base'
#>
[CmdletBinding()]
param(
    [string[]] $Ids = @(),
    [int] $Nulls = 0,
    [string] $Snapshot = 'rig-base',
    # 'Inbound-Win11-Test' (Enterprise LTSC 26100, the corpus VM) or 'Purge-CleanPro' (Pro Insider, RIG.md §1)
    [string] $VmName = 'Inbound-Win11-Test',
    # App runs only: run name = <prefix><id> (e.g. 'r0-'); required with -Engine.
    [string] $RunPrefix = '',
    # purge-engine.exe to push; turns on engine mode for the app runs.
    [string] $Engine = ''
)

$script:VBox      = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$script:VmName    = $VmName
$script:GuestUser = 'tester'
$script:RigDir    = $PSScriptRoot
$script:RepoRoot  = Split-Path -Parent $PSScriptRoot
$script:RunsDir   = Join-Path $PSScriptRoot 'runs'
$script:FrozenDir = Join-Path $PSScriptRoot 'truth\frozen'   # frozen M0 truth and plans, read only
$script:PwFile    = $null
$script:PwTemp    = $false
$script:RigLogFile = $null

# --------------------------------------------------------------------------------------------- basics

function Write-RigLog([string]$Message) {
    $line = '[{0}] {1}' -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss'), $Message
    Write-Host $line
    if ($script:RigLogFile) { try { Add-Content -LiteralPath $script:RigLogFile -Value $line -Encoding UTF8 } catch { } }
}

# Path of a file holding only the guest password. A "password=..." file is converted to a temporary bare
# file in %TEMP% (deleted by Remove-PwTemp: after each Invoke-Guest call, or at the end of a campaign,
# which holds one copy for all its calls). The password itself is never printed or logged.
function Get-PwFile {
    if ($script:PwFile -and (Test-Path -LiteralPath $script:PwFile)) { return $script:PwFile }
    $f = $env:VMPWFILE
    if (-not $f -or -not (Test-Path -LiteralPath $f)) {
        throw 'Set $env:VMPWFILE to a file that holds the guest password (bare, or a line password=...).'
    }
    $raw = [IO.File]::ReadAllText($f)
    $m = [regex]::Match($raw, '(?m)^\s*password\s*=\s*(.+?)\s*$')
    if ($m.Success) {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('rigpw-' + [guid]::NewGuid().ToString('N') + '.txt')
        [IO.File]::WriteAllText($tmp, $m.Groups[1].Value)
        $script:PwFile = $tmp
        $script:PwTemp = $true
    } else {
        $script:PwFile = $f
        $script:PwTemp = $false
    }
    $script:PwFile
}

function Remove-PwTemp {
    if ($script:PwTemp -and $script:PwFile) { Remove-Item -LiteralPath $script:PwFile -Force -ErrorAction SilentlyContinue }
    $script:PwFile = $null
    $script:PwTemp = $false
}

# Runs VBoxManage with an argument array; never throws on a non-zero exit. Output lines are returned as
# strings; stderr is merged.
function Invoke-VBox([string[]]$A) {
    $ErrorActionPreference = 'Continue'
    $out = & $script:VBox @A 2>&1
    $code = $LASTEXITCODE
    [pscustomobject]@{ code = $code; out = @($out | ForEach-Object { "$_" }) }
}

# guestcontrol as the guest user (password through --passwordfile only). A temporary password copy made
# for this call alone is deleted before returning; one made by an enclosing caller (Invoke-Campaign) is
# left for that caller to delete.
function Invoke-Guest([string[]]$Sub) {
    $own = -not ($script:PwFile -and (Test-Path -LiteralPath $script:PwFile))
    try {
        $pf = Get-PwFile
        Invoke-VBox (@('guestcontrol', $script:VmName, '--username', $script:GuestUser, '--passwordfile', $pf) + $Sub)
    } finally {
        if ($own) { Remove-PwTemp }
    }
}

# Runs a cmd.exe command line in the guest (unelevated guest user) and returns its stdout lines.
function Invoke-GuestCmd([string]$CommandLine, [int]$TimeoutSec = 120) {
    Invoke-Guest @('run', '--exe', 'C:\Windows\System32\cmd.exe', '--timeout', [string]($TimeoutSec * 1000), '--wait-stdout', '--', 'cmd', '/c', $CommandLine)
}

# Pure: 'key="value"' lines of showvminfo --machinereadable -> hashtable.
function ConvertFrom-MachineReadable([string[]]$Lines) {
    $h = @{}
    foreach ($l in $Lines) {
        $m = [regex]::Match("$l", '^"?([^"=]+)"?="?(.*?)"?$')
        if ($m.Success) { $h[$m.Groups[1].Value] = $m.Groups[2].Value }
    }
    $h
}

function Get-VmState {
    $r = Invoke-VBox @('showvminfo', $script:VmName, '--machinereadable')
    if ($r.code -ne 0) { throw "showvminfo failed: $($r.out -join ' ')" }
    (ConvertFrom-MachineReadable $r.out)['VMState']
}

function Wait-VmState([string[]]$States, [int]$TimeoutSec = 120) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        $s = Get-VmState
        if ($States -contains $s) { return $s }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw "VM did not reach state $($States -join '/') within $TimeoutSec s (now '$s')"
}

# ----------------------------------------------------------------------------------------------- VM

# Powers the VM off, restores the snapshot, starts it headless and waits for the agent. A live snapshot
# comes back in state 'saved' with the agent already running; an offline one needs autologon and the
# PurgeRigAgent logon task (up to $AgentTimeoutSec).
function Restore-Base {
    param([string]$Snapshot = 'rig-base', [int]$AgentTimeoutSec = 300)
    $st = Get-VmState
    Write-RigLog "restore $Snapshot (VM state: $st)"
    if (@('running', 'paused', 'stuck', 'starting', 'stopping', 'saving', 'restoring', 'livesnapshotting', 'teleporting') -contains $st) {
        $r = Invoke-VBox @('controlvm', $script:VmName, 'poweroff')
        if ($r.code -ne 0) { Write-RigLog "  poweroff: $($r.out -join ' ')" }
        $st = Wait-VmState @('poweroff', 'aborted', 'saved') 120
    }
    $ok = $false
    for ($i = 1; $i -le 6 -and -not $ok; $i++) {
        # The session lock can linger for a moment after poweroff.
        $r = Invoke-VBox @('snapshot', $script:VmName, 'restore', $Snapshot)
        if ($r.code -eq 0) { $ok = $true } else { Write-RigLog "  restore try $i failed: $($r.out -join ' ')"; Start-Sleep -Seconds 3 }
    }
    if (-not $ok) { throw "snapshot restore $Snapshot failed" }
    $live = ((Get-VmState) -eq 'saved')
    Write-RigLog "  restored ($(if ($live) { 'live snapshot' } else { 'offline snapshot' })); starting headless"
    $r = Invoke-VBox @('startvm', $script:VmName, '--type', 'headless')
    if ($r.code -ne 0) { throw "startvm failed: $($r.out -join ' ')" }
    $null = Wait-VmState @('running') 120
    $t = $AgentTimeoutSec
    if ($live) { $t = [Math]::Min(180, $AgentTimeoutSec) }
    Wait-Agent -TimeoutSec $t
}

# Waits until C:\cr\jobs\agent.alive is visible through guestcontrol (guest additions up, user logged on),
# checks that the agent is elevated, and that a trivial job completes.
function Wait-Agent {
    param([int]$TimeoutSec = 300)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $seen = $false
    while (-not $seen -and (Get-Date) -lt $deadline) {
        $r = Invoke-Guest @('stat', 'C:\cr\jobs\agent.alive')
        if ($r.code -eq 0) { $seen = $true } else { Start-Sleep -Seconds 5 }
    }
    if (-not $seen) { throw "agent.alive not visible within $TimeoutSec s (guest additions, autologon or PurgeRigAgent task?)" }
    $alive = (Invoke-GuestCmd 'type C:\cr\jobs\agent.alive').out -join ' '
    Write-RigLog "  agent.alive: $($alive.Trim())"
    if ($alive -match 'admin=False') { throw 'the agent is running but not elevated' }
    $left = [Math]::Max(60, [int]($deadline - (Get-Date)).TotalSeconds)
    $j = Invoke-GuestJob -Text "'pong'" -Name 'ping' -TimeoutSec $left
    if (-not $j.done -or $j.log -notmatch 'pong') { throw "agent did not run the ping job (done=$($j.done))" }
    Write-RigLog '  agent ready'
}

# vmjob.ps1 protocol: copy the script to C:\cr\stage, move it into C:\cr\jobs (the agent only picks up
# complete files), wait for <job>.done, fetch <job>.log. Returns {name, done, seconds, log, log_file}.
function Invoke-GuestJob {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][string]$Name, [int]$TimeoutSec = 1800, [string]$LogCopy = '')
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $job = "$stamp-$($Name -replace '[^\w.-]', '_').ps1"
    $tmpDir = Join-Path $env:TEMP 'vmjobs'
    New-Item -ItemType Directory -Force $tmpDir | Out-Null
    $local = Join-Path $tmpDir $job
    [IO.File]::WriteAllText($local, $Text, (New-Object System.Text.UTF8Encoding($true)))
    $r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\stage\', $local)
    if ($r.code -ne 0) {
        $null = Invoke-Guest @('mkdir', '--parents', 'C:\cr\stage')
        $r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\stage\', $local)
        if ($r.code -ne 0) { throw "copyto failed: $($r.out -join ' ')" }
    }
    $r = Invoke-Guest @('mv', "C:\cr\stage\$job", "C:\cr\jobs\$job")
    if ($r.code -ne 0) { throw "guest mv failed: $($r.out -join ' ')" }
    $t = Get-Date
    $deadline = $t.AddSeconds($TimeoutSec)
    $done = $false
    while (-not $done -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        $done = ((Invoke-Guest @('stat', "C:\cr\jobs\$job.done")).code -eq 0)
    }
    $secs = [int]((Get-Date) - $t).TotalSeconds
    if (-not $LogCopy) { $LogCopy = Join-Path $tmpDir "$job.log" }
    Remove-Item -LiteralPath $LogCopy -Force -ErrorAction SilentlyContinue
    $null = Invoke-Guest @('copyfrom', "C:\cr\jobs\$job.log", $LogCopy)
    $log = ''
    if (Test-Path -LiteralPath $LogCopy) { $log = Get-Content -LiteralPath $LogCopy -Raw }
    Remove-Item -LiteralPath $local -Force -ErrorAction SilentlyContinue
    [pscustomobject]@{ name = $job; done = $done; seconds = $secs; log = $log; log_file = $LogCopy }
}

# Pure: what Push-Tools sends for the engine. -Engine given: that file, which must exist. Not given: the
# repo's target\release\purge-engine.exe when it is built, else nothing. The baselines kb\baselines\*.tsv.gz
# go with the engine (purge-engine looks for them in <exe dir>\kb\baselines). Returns {engine, baselines}.
function Get-EnginePush {
    param([string]$Engine = '', [string]$RepoRoot = $script:RepoRoot)
    $explicit = [bool]$Engine
    if (-not $Engine) { $Engine = Join-Path $RepoRoot 'target\release\purge-engine.exe' }
    if (-not (Test-Path -LiteralPath $Engine -PathType Leaf)) {
        if ($explicit) { throw "purge-engine not found: $Engine (cargo build --release -p purge-engine)" }
        return [pscustomobject]@{ engine = $null; baselines = @() }
    }
    $bl = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'kb\baselines') -Filter '*.tsv.gz' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    [pscustomobject]@{ engine = (Resolve-Path -LiteralPath $Engine).ProviderPath; baselines = $bl }
}

# Copies a fresh rigtool.exe to C:\cr\bin, purge-engine.exe to C:\cr\bin and kb\baselines\*.tsv.gz to
# C:\cr\bin\kb\baselines (see Get-EnginePush), and vm\guest\*.ps1 to C:\cr\guest (old copies deleted first).
function Push-Tools {
    param([string]$RigTool = '', [string]$Engine = '')
    if (-not $RigTool) { $RigTool = Join-Path $script:RigDir 'rigtool\target\release\rigtool.exe' }
    if (-not (Test-Path -LiteralPath $RigTool)) { throw "rigtool not built: $RigTool (cargo build --release in vm\rigtool)" }
    $ep = Get-EnginePush -Engine $Engine
    $scripts = @(Get-ChildItem -LiteralPath (Join-Path $script:RigDir 'guest') -Filter '*.ps1' | ForEach-Object { $_.FullName })
    foreach ($d in 'C:\cr\bin', 'C:\cr\bin\kb\baselines', 'C:\cr\guest', 'C:\cr\out', 'C:\cr\stage') { $null = Invoke-Guest @('mkdir', '--parents', $d) }
    $null = Invoke-GuestCmd 'del /f /q C:\cr\guest\*.ps1 C:\cr\bin\rigtool.exe C:\cr\bin\purge-engine.exe C:\cr\bin\kb\baselines\*.tsv.gz'
    $r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\bin\', $RigTool)
    if ($r.code -ne 0) { throw "copy rigtool failed: $($r.out -join ' ')" }
    $expect = @('C:\cr\bin\rigtool.exe')
    if ($ep.engine) {
        # copyto keeps the source file name; the guest scripts expect purge-engine.exe.
        if ((Split-Path -Leaf $ep.engine) -ne 'purge-engine.exe') { throw "the engine file must be named purge-engine.exe: $($ep.engine)" }
        $r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\bin\', $ep.engine)
        if ($r.code -ne 0) { throw "copy purge-engine failed: $($r.out -join ' ')" }
        $expect += 'C:\cr\bin\purge-engine.exe'
        if ($ep.baselines.Count) {
            $r = Invoke-Guest (@('copyto', '--target-directory', 'C:\cr\bin\kb\baselines\') + $ep.baselines)
            if ($r.code -ne 0) { throw "copy baselines failed: $($r.out -join ' ')" }
            $expect += @($ep.baselines | ForEach-Object { 'C:\cr\bin\kb\baselines\' + (Split-Path -Leaf $_) })
        }
    }
    $r = Invoke-Guest (@('copyto', '--target-directory', 'C:\cr\guest\') + $scripts)
    if ($r.code -ne 0) { throw "copy guest scripts failed: $($r.out -join ' ')" }
    $missing = @()
    foreach ($f in $expect + @($scripts | ForEach-Object { 'C:\cr\guest\' + (Split-Path -Leaf $_) })) {
        if ((Invoke-Guest @('stat', $f)).code -ne 0) { $missing += $f }
    }
    if ($missing.Count) { throw "not in the guest after copy: $($missing -join ', ')" }
    $what = 'rigtool.exe'
    if ($ep.engine) { $what += " + purge-engine.exe ($($ep.engine)) + $($ep.baselines.Count) baseline(s)" }
    Write-RigLog "  pushed $what + $($scripts.Count) guest scripts"
}

# ---------------------------------------------------------------------------------------------- runs

# Pure: the job text for a run. App runs (run-app.ps1): __ID__ = the app id, __RUN__ = the run name (default
# the id), __ENGINE__ = 1 with -Engine, else 0. Null runs (null-run.ps1): __RUN__ = null<n>.
function New-RunJobText {
    param([string]$Id = '', [int]$NullRun = 0, [string]$Run = '', [switch]$Engine)
    if ($Id) {
        if ($Id -cnotmatch '^[a-z0-9][a-z0-9_-]*$') { throw "bad app id '$Id' (lowercase letters, digits, _ and -)" }
        if (-not $Run) { $Run = $Id }
        if ($Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$Run' (lowercase letters, digits, _, . and -)" }
        $tpl = [IO.File]::ReadAllText((Join-Path $script:RigDir 'guest\run-app.ps1'))
        return $tpl.Replace('__ID__', $Id).Replace('__RUN__', $Run).Replace('__ENGINE__', $(if ($Engine) { '1' } else { '0' }))
    }
    if ($NullRun -lt 1) { throw 'give -Id or -Null n (n >= 1)' }
    $tpl = [IO.File]::ReadAllText((Join-Path $script:RigDir 'guest\null-run.ps1'))
    $tpl.Replace('__RUN__', "null$NullRun")
}

# Runs one app (-Id) or null run (-Null n) in the guest and pulls its outputs to vm\runs\<run>\.
# App runs: the run name is <RunPrefix><id>. -Engine turns on the guest's engine mode (purge-engine must have
# been pushed) and needs a prefix, so the frozen M0 directory vm\runs\<id>\ is never archived; the plan it
# writes is then copied to plans\ (Copy-RunPlans).
function Invoke-Run {
    [CmdletBinding(DefaultParameterSetName = 'app')]
    param(
        [Parameter(ParameterSetName = 'app', Mandatory)][string]$Id,
        [Parameter(ParameterSetName = 'null', Mandatory)][Alias('Null')][int]$NullRun,
        [Parameter(ParameterSetName = 'app')][string]$RunPrefix = '',
        [Parameter(ParameterSetName = 'app')][switch]$Engine,
        [int]$TimeoutSec = 0
    )
    if ($PSCmdlet.ParameterSetName -eq 'app') {
        $run = Get-RunName -Id $Id -RunPrefix $RunPrefix -Engine:$Engine
        $text = New-RunJobText -Id $Id -Run $run -Engine:$Engine; $to = 5400
    } else { $run = "null$NullRun"; $text = New-RunJobText -NullRun $NullRun; $to = 2400 }
    if ($TimeoutSec -gt 0) { $to = $TimeoutSec }
    $null = Move-RunToOld -Run $run
    $dst = Join-Path $script:RunsDir $run
    New-Item -ItemType Directory -Force $dst | Out-Null
    Write-RigLog "run $run (timeout $to s$(if ($Engine) { ', engine mode' }))"
    $j = Invoke-GuestJob -Text $text -Name $run -TimeoutSec $to -LogCopy (Join-Path $dst 'job.log')
    Write-RigLog "  job $($j.name) done=$($j.done) after $($j.seconds) s"
    $pulled = Pull-Run -Run $run
    if ($Engine) { $null = Copy-RunPlans -Run $run -Id $Id }
    [pscustomobject]@{ run = $run; done = $j.done; seconds = $j.seconds; pulled = $pulled }
}

# Pure: the run name of an app run. With -Engine the prefix is required and the name must differ from the id.
function Get-RunName {
    param([Parameter(Mandatory)][string]$Id, [string]$RunPrefix = '', [switch]$Engine)
    $run = "$RunPrefix$Id"
    if ($run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$run' (prefix '$RunPrefix': lowercase letters, digits, _, . and -)" }
    if ($Engine -and $run -eq $Id) { throw "engine runs need -RunPrefix (e.g. r0-) so the frozen vm\runs\$Id\ is not archived" }
    $run
}

# Engine runs: vm\runs\<run>\plan-purge.json -> plans\purge.json, and the frozen BCU plan of the app
# (vm\truth\frozen\<id>\plans\bcu.json, when there is one) next to it, so `rigtool score --set` scores both
# tools on this run. Returns the names copied.
function Copy-RunPlans {
    param([Parameter(Mandatory)][string]$Run, [Parameter(Mandatory)][string]$Id)
    if ($Run -notmatch '^[A-Za-z0-9_.-]+$') { throw "bad run name '$Run'" }
    $dir = Join-Path $script:RunsDir $Run
    $plans = Join-Path $dir 'plans'
    $copied = @()
    $src = Join-Path $dir 'plan-purge.json'
    if (Test-Path -LiteralPath $src) {
        New-Item -ItemType Directory -Force $plans | Out-Null
        Copy-Item -LiteralPath $src -Destination (Join-Path $plans 'purge.json') -Force
        $copied += 'purge.json'
    } else { Write-RigLog "  !! no plan-purge.json in $dir" }
    $bcu = Join-Path $script:FrozenDir "$Id\plans\bcu.json"
    if (Test-Path -LiteralPath $bcu) {
        New-Item -ItemType Directory -Force $plans | Out-Null
        Copy-Item -LiteralPath $bcu -Destination (Join-Path $plans 'bcu.json') -Force
        $copied += 'bcu.json'
    }
    Write-RigLog "  plans for $Run`: $(if ($copied.Count) { $copied -join ', ' } else { 'none' })"
    $copied
}

# Moves vm\runs\<run>\ (if present) to vm\runs\_old\<run>-<stamp>\ so a new run starts from an empty
# directory and rigtool (which finds snap-/lists-/truth.json files by name) never mixes two runs.
# Returns the archive path, or $null when there was nothing to move.
function Move-RunToOld {
    param([Parameter(Mandatory)][string]$Run)
    if ($Run -notmatch '^[A-Za-z0-9_.-]+$') { throw "bad run name '$Run'" }
    $src = Join-Path $script:RunsDir $Run
    if (-not (Test-Path -LiteralPath $src)) { return $null }
    $oldRoot = Join-Path $script:RunsDir '_old'
    New-Item -ItemType Directory -Force $oldRoot | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $arch = Join-Path $oldRoot "$Run-$stamp"
    for ($i = 2; Test-Path -LiteralPath $arch; $i++) { $arch = Join-Path $oldRoot "$Run-$stamp-$i" }
    Move-Item -LiteralPath $src -Destination $arch -ErrorAction Stop
    Write-RigLog "  moved previous $src to $arch"
    $arch
}

# Copies C:\cr\out\<run>\* to vm\runs\<run>\. VBoxManage copyfrom needs a full destination FILE path per
# file (a directory destination fails), so the guest directory is listed first. Top-level files in
# vm\runs\<run>\ that the guest no longer has (except the host's job.log) are moved to vm\runs\_old\, so the
# directory always holds one run's outputs. Subdirectories (plans\) are left alone.
function Pull-Run {
    param([Parameter(Mandatory)][string]$Run)
    if ($Run -notmatch '^[A-Za-z0-9_.-]+$') { throw "bad run name '$Run'" }
    $dst = Join-Path $script:RunsDir $Run
    New-Item -ItemType Directory -Force $dst | Out-Null
    $r = Invoke-GuestCmd "dir /b /a-d C:\cr\out\$Run"
    $files = @($r.out | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -match '^[\w.-]+$' })
    if (-not $files.Count) { Write-RigLog "  !! nothing in C:\cr\out\$Run ($($r.out -join ' '))"; return @() }
    $stale = @(Get-ChildItem -LiteralPath $dst -File | Where-Object { $_.Name -ne 'job.log' -and $files -notcontains $_.Name })
    if ($stale.Count) {
        $arch = Join-Path (Join-Path $script:RunsDir '_old') ("$Run-stale-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
        New-Item -ItemType Directory -Force $arch | Out-Null
        foreach ($s in $stale) { Move-Item -LiteralPath $s.FullName -Destination (Join-Path $arch $s.Name) -Force }
        Write-RigLog "  moved $($stale.Count) file(s) the guest does not have ($(($stale | ForEach-Object { $_.Name }) -join ', ')) to $arch"
    }
    $got = @()
    foreach ($f in $files) {
        $target = Join-Path $dst $f
        Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
        $c = Invoke-Guest @('copyfrom', "C:\cr\out\$Run\$f", $target)
        if ($c.code -eq 0 -and (Test-Path -LiteralPath $target)) { $got += $f }
        else { Write-RigLog "  !! copyfrom $f failed: $($c.out -join ' ')" }
    }
    Write-RigLog "  pulled $($got.Count)/$($files.Count) files to $dst"
    $got
}

# Checks the run.json pulled for $Run: it must exist, name this run, have started no earlier than
# $NotBefore (host clock; $SkewSec allows for guest/host clock drift) and have no failed phase.
# Returns {ok, error, started, failed_phases}.
function Test-RunResult {
    param([Parameter(Mandatory)][string]$Run, [Parameter(Mandatory)][datetime]$NotBefore, [int]$SkewSec = 300)
    $res = [ordered]@{ ok = $false; error = $null; started = $null; failed_phases = @() }
    $f = Join-Path (Join-Path $script:RunsDir $Run) 'run.json'
    if (-not (Test-Path -LiteralPath $f)) { $res.error = 'run.json not pulled'; return [pscustomobject]$res }
    try { $j = [IO.File]::ReadAllText($f) | ConvertFrom-Json } catch { $res.error = "run.json unreadable: $($_.Exception.Message)"; return [pscustomobject]$res }
    if ("$($j.run)" -ne $Run) { $res.error = "run.json is for run '$($j.run)', not '$Run'"; return [pscustomobject]$res }
    $started = [DateTimeOffset]::MinValue
    $sv = $j.started    # pwsh 6+ ConvertFrom-Json already turns ISO strings into DateTime
    if ($sv -is [DateTimeOffset]) { $started = $sv }
    elseif ($sv -is [datetime]) { $started = [DateTimeOffset]$sv }
    elseif (-not [DateTimeOffset]::TryParse("$sv", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$started)) {
        $res.error = "run.json has no valid 'started' ('$($j.started)')"; return [pscustomobject]$res
    }
    $res.started = $started.ToString('o')
    $limit = ([DateTimeOffset]$NotBefore).AddSeconds(-$SkewSec)
    if ($started -lt $limit) { $res.error = "run.json started $($res.started), before this run began ($(([DateTimeOffset]$NotBefore).ToString('o'))): stale"; return [pscustomobject]$res }
    $res.failed_phases = @(@($j.phases) | Where-Object { $_ -and -not $_.ok } | ForEach-Object { "$($_.name)" })
    if (-not $j.finished) { $res.error = 'run.json has no finished time (job cut short)'; return [pscustomobject]$res }
    if ($res.failed_phases.Count) { $res.error = "failed phases: $($res.failed_phases -join ', ')"; return [pscustomobject]$res }
    $res.ok = $true
    [pscustomobject]$res
}

# Runs null runs then apps, each from a fresh restore. Keeps going after a failed run; writes
# vm\runs\campaign-<stamp>.log and .json. A run is ok only when its job finished and the run.json pulled
# for it is from this run (Test-RunResult) with every phase ok. -RunPrefix names the app runs <prefix><id>
# (null runs keep null<n>); -Engine <purge-engine.exe> pushes that engine and runs the apps in engine mode.
function Invoke-Campaign {
    param([string[]]$Ids = @(), [int]$Nulls = 3, [string]$Snapshot = 'rig-base', [switch]$NoRestore,
          [string]$RunPrefix = '', [string]$Engine = '')
    $useEngine = [bool]$Engine
    $plan = @()
    if ($Nulls -gt 0) { foreach ($n in 1..$Nulls) { $plan += @{ run = "null$n"; null = $n } } }
    # Names are checked before anything is moved or restored.
    foreach ($id in $Ids) { if ($id) { $plan += @{ run = (Get-RunName -Id $id -RunPrefix $RunPrefix -Engine:$useEngine); id = $id } } }
    if ($useEngine) { $null = Get-EnginePush -Engine $Engine }
    New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:RigLogFile = Join-Path $script:RunsDir "campaign-$stamp.log"
    $summaryFile = Join-Path $script:RunsDir "campaign-$stamp.json"
    $results = New-Object System.Collections.ArrayList
    Write-RigLog "campaign ${stamp}: $(($plan | ForEach-Object { $_.run }) -join ', ') from snapshot $Snapshot$(if ($useEngine) { "; engine $Engine" })"
    try {
        $null = Get-PwFile
        foreach ($p in $plan) {
            $t = Get-Date
            $rec = [ordered]@{ run = $p.run; id = $p.id; engine = ($useEngine -and [bool]$p.id); ok = $false; error = $null; start = $t.ToString('o'); end = $null; seconds = $null; pulled = 0; started = $null; failed_phases = @() }
            try {
                # Before anything else, so neither Invoke-Run nor the catch's Pull-Run sees an older run's files.
                $null = Move-RunToOld -Run $p.run
                if (-not $NoRestore) { Restore-Base -Snapshot $Snapshot } else { Wait-Agent -TimeoutSec 120 }
                Push-Tools -Engine $Engine
                if ($p.id) { $res = Invoke-Run -Id $p.id -RunPrefix $RunPrefix -Engine:$useEngine } else { $res = Invoke-Run -NullRun $p.null }
                $rec.pulled = @($res.pulled).Count
                $chk = Test-RunResult -Run $p.run -NotBefore $t
                $rec.started = $chk.started; $rec.failed_phases = @($chk.failed_phases)
                $rec.ok = ($res.done -and $chk.ok)
                if (-not $rec.ok) { $rec.error = "job done=$($res.done); $(if ($chk.error) { $chk.error } else { 'run.json ok' })" }
            } catch {
                $rec.error = $_.Exception.Message
                Write-RigLog "!! run $($p.run) failed: $($rec.error)"
                try { $rec.pulled = @(Pull-Run -Run $p.run).Count } catch { }
            }
            $rec.end = (Get-Date).ToString('o')
            $rec.seconds = [int]((Get-Date) - $t).TotalSeconds
            [void]$results.Add($rec)
            [IO.File]::WriteAllText($summaryFile, (ConvertTo-Json -InputObject @($results) -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
            Write-RigLog "run $($p.run): ok=$($rec.ok) in $($rec.seconds) s$(if ($rec.error) { ' - ' + $rec.error })"
        }
    } finally {
        Remove-PwTemp
        Write-RigLog "campaign done: $(@($results | Where-Object { $_.ok }).Count)/$($plan.Count) ok; summary $summaryFile"
        $script:RigLogFile = $null
    }
    @($results)
}

# ------------------------------------------------------------------------------------ building rig-base

# Runs guest\setup-base.ps1 elevated through the agent (after Push-Tools) and prints its log.
function Invoke-SetupBase {
    param([int]$TimeoutSec = 3600)
    $text = [IO.File]::ReadAllText((Join-Path $script:RigDir 'guest\setup-base.ps1'))
    $j = Invoke-GuestJob -Text $text -Name 'setup-base' -TimeoutSec $TimeoutSec
    $j.log
    if (-not $j.done) { throw 'setup-base did not finish' }
}

# Takes rig-base (live, agent running) or, with -Off, shuts the guest down cleanly and takes rig-base-off.
function Save-BaseSnapshot {
    param([switch]$Off, [string]$Name = '')
    if (-not $Name) { $Name = $(if ($Off) { 'rig-base-off' } else { 'rig-base' }) }
    if ($Off) {
        $null = Invoke-VBox @('controlvm', $script:VmName, 'acpipowerbutton')
        $null = Wait-VmState @('poweroff') 300
        $r = Invoke-VBox @('snapshot', $script:VmName, 'take', $Name, '--description', 'Purge rig v2 base, powered off')
    } else {
        $r = Invoke-VBox @('snapshot', $script:VmName, 'take', $Name, '--live', '--description', 'Purge rig v2 base, live, agent running')
    }
    if ($r.code -ne 0) { throw "snapshot take $Name failed: $($r.out -join ' ')" }
    Write-RigLog "snapshot $Name taken"
}

if ($MyInvocation.InvocationName -ne '.' -and ($Ids.Count -gt 0 -or $Nulls -gt 0)) {
    Invoke-Campaign -Ids $Ids -Nulls $Nulls -Snapshot $Snapshot -RunPrefix $RunPrefix -Engine $Engine
}
