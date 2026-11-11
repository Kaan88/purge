<#
  Purge rig v2: host driver (vm\RIG.md §1, §4). Windows PowerShell 5.1 compatible.

  Dot-source and call functions, or run a campaign directly:
    $env:VMPWFILE = 'C:\path\to\pw.txt'      # bare guest password, or a line "password=..."
    . .\vm\rig.ps1
    Invoke-Campaign -Ids npp,7zip,firefox -Nulls 3
    .\vm\rig.ps1 -Ids npp,firefox -Nulls 3     # same, without dot-sourcing

  Per run: power off -> snapshot restore rig-base -> start headless -> wait for the agent -> copy fresh
  rigtool.exe and guest\*.ps1 -> run the job (run-app.ps1 / null-run.ps1) -> copy C:\cr\out\<run>\ to
  vm\runs\<run>\. A failed run is recorded and the campaign goes on.

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
    [string] $VmName = 'Inbound-Win11-Test'
)

$script:VBox      = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$script:VmName    = $VmName
$script:GuestUser = 'tester'
$script:RigDir    = $PSScriptRoot
$script:RunsDir   = Join-Path $PSScriptRoot 'runs'
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

# Copies a fresh rigtool.exe to C:\cr\bin and vm\guest\*.ps1 to C:\cr\guest (old copies deleted first).
function Push-Tools {
    param([string]$RigTool = '')
    if (-not $RigTool) { $RigTool = Join-Path $script:RigDir 'rigtool\target\release\rigtool.exe' }
    if (-not (Test-Path -LiteralPath $RigTool)) { throw "rigtool not built: $RigTool (cargo build --release in vm\rigtool)" }
    $scripts = @(Get-ChildItem -LiteralPath (Join-Path $script:RigDir 'guest') -Filter '*.ps1' | ForEach-Object { $_.FullName })
    foreach ($d in 'C:\cr\bin', 'C:\cr\guest', 'C:\cr\out', 'C:\cr\stage') { $null = Invoke-Guest @('mkdir', '--parents', $d) }
    $null = Invoke-GuestCmd 'del /f /q C:\cr\guest\*.ps1 C:\cr\bin\rigtool.exe'
    $r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\bin\', $RigTool)
    if ($r.code -ne 0) { throw "copy rigtool failed: $($r.out -join ' ')" }
    $r = Invoke-Guest (@('copyto', '--target-directory', 'C:\cr\guest\') + $scripts)
    if ($r.code -ne 0) { throw "copy guest scripts failed: $($r.out -join ' ')" }
    $missing = @()
    foreach ($f in @('C:\cr\bin\rigtool.exe') + @($scripts | ForEach-Object { 'C:\cr\guest\' + (Split-Path -Leaf $_) })) {
        if ((Invoke-Guest @('stat', $f)).code -ne 0) { $missing += $f }
    }
    if ($missing.Count) { throw "not in the guest after copy: $($missing -join ', ')" }
    Write-RigLog "  pushed rigtool.exe + $($scripts.Count) guest scripts"
}

# ---------------------------------------------------------------------------------------------- runs

# Pure: the job text for a run (template with its placeholder replaced).
function New-RunJobText {
    param([string]$Id = '', [int]$NullRun = 0)
    if ($Id) {
        if ($Id -cnotmatch '^[a-z0-9][a-z0-9_-]*$') { throw "bad app id '$Id' (lowercase letters, digits, _ and -)" }
        $tpl = [IO.File]::ReadAllText((Join-Path $script:RigDir 'guest\run-app.ps1'))
        return $tpl.Replace('__ID__', $Id)
    }
    if ($NullRun -lt 1) { throw 'give -Id or -Null n (n >= 1)' }
    $tpl = [IO.File]::ReadAllText((Join-Path $script:RigDir 'guest\null-run.ps1'))
    $tpl.Replace('__RUN__', "null$NullRun")
}

# Runs one app (-Id) or null run (-Null n) in the guest and pulls its outputs to vm\runs\<run>\.
function Invoke-Run {
    [CmdletBinding(DefaultParameterSetName = 'app')]
    param(
        [Parameter(ParameterSetName = 'app', Mandatory)][string]$Id,
        [Parameter(ParameterSetName = 'null', Mandatory)][Alias('Null')][int]$NullRun,
        [int]$TimeoutSec = 0
    )
    if ($PSCmdlet.ParameterSetName -eq 'app') { $run = $Id; $text = New-RunJobText -Id $Id; $to = 5400 }
    else { $run = "null$NullRun"; $text = New-RunJobText -NullRun $NullRun; $to = 2400 }
    if ($TimeoutSec -gt 0) { $to = $TimeoutSec }
    $null = Move-RunToOld -Run $run
    $dst = Join-Path $script:RunsDir $run
    New-Item -ItemType Directory -Force $dst | Out-Null
    Write-RigLog "run $run (timeout $to s)"
    $j = Invoke-GuestJob -Text $text -Name $run -TimeoutSec $to -LogCopy (Join-Path $dst 'job.log')
    Write-RigLog "  job $($j.name) done=$($j.done) after $($j.seconds) s"
    $pulled = Pull-Run -Run $run
    [pscustomobject]@{ run = $run; done = $j.done; seconds = $j.seconds; pulled = $pulled }
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
# for it is from this run (Test-RunResult) with every phase ok.
function Invoke-Campaign {
    param([string[]]$Ids = @(), [int]$Nulls = 3, [string]$Snapshot = 'rig-base', [switch]$NoRestore)
    New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:RigLogFile = Join-Path $script:RunsDir "campaign-$stamp.log"
    $summaryFile = Join-Path $script:RunsDir "campaign-$stamp.json"
    $plan = @()
    if ($Nulls -gt 0) { foreach ($n in 1..$Nulls) { $plan += @{ run = "null$n"; null = $n } } }
    foreach ($id in $Ids) { if ($id) { $plan += @{ run = $id; id = $id } } }
    $results = New-Object System.Collections.ArrayList
    Write-RigLog "campaign ${stamp}: $(($plan | ForEach-Object { $_.run }) -join ', ') from snapshot $Snapshot"
    try {
        $null = Get-PwFile
        foreach ($p in $plan) {
            $t = Get-Date
            $rec = [ordered]@{ run = $p.run; ok = $false; error = $null; start = $t.ToString('o'); end = $null; seconds = $null; pulled = 0; started = $null; failed_phases = @() }
            try {
                # Before anything else, so neither Invoke-Run nor the catch's Pull-Run sees an older run's files.
                $null = Move-RunToOld -Run $p.run
                if (-not $NoRestore) { Restore-Base -Snapshot $Snapshot } else { Wait-Agent -TimeoutSec 120 }
                Push-Tools
                if ($p.id) { $res = Invoke-Run -Id $p.id } else { $res = Invoke-Run -NullRun $p.null }
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
    Invoke-Campaign -Ids $Ids -Nulls $Nulls -Snapshot $Snapshot
}
