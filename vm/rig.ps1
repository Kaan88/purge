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

  Null runs inside such a campaign (M1a gate rerun, RIG.md §6): with -RunPrefix they are named
  <prefix>null<n> (r0-null1 ...), so the M0 null runs vm\runs\null1..3 behind truth\ambient.json stay as they
  are. -NullWaitSec sets their idle time (default 60 s, as in M0) and -NullOrder spread runs them first,
  in the middle and last instead of all first:
    Invoke-Campaign -Ids vscode,vscode-user,git,firefox,firefox-tb,npp -Nulls 3 -NullOrder spread -NullWaitSec 120 `
                    -RunPrefix r0- -Engine .\target\release\purge-engine.exe

  Extended M1a runs (RIG.md §4b): -ExtraChecks adds the live scan and the repeat scan to every engine app run;
  -NoBaselines pushes no (edition, build) baseline, so the engine runs values-only. Installer and plant files of a
  run (apps.ps1 Get-AppFiles) that the host cache vm\cache\inst holds are pushed to C:\cr\inst with the manifest
  vm\cache\inst\cache-sources.json; the guest checks each SHA-256 against it and downloads only what is missing:
    Invoke-Campaign -Ids npp-userfiles,git-toolsdir -Nulls 0 -RunPrefix x0- -ExtraChecks -Engine .\target\release\purge-engine.exe
    Invoke-Campaign -Ids firefox-tb,vscode,git,npp -Nulls 0 -RunPrefix x0-nb- -ExtraChecks -NoBaselines -Engine .\target\release\purge-engine.exe

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
    [string] $Engine = '',
    # Null runs: idle seconds standing in for install and uninstall (RIG.md §6), and their place in the campaign.
    [int] $NullWaitSec = 60,
    [ValidateSet('first', 'spread')] [string] $NullOrder = 'first',
    # Engine app runs: also the live scan and the repeat scan (run.json `extra`, RIG.md §4a).
    [switch] $ExtraChecks,
    # Push no (edition, build) baseline: the engine runs values-only (x0-nb- campaign).
    [switch] $NoBaselines,
    # VirtualBox execution engine set on the powered-off VM after each restore (VBoxManage modifyvm
    # --vm-execution-engine), e.g. 'native-api' to run on top of KVM next to a KVM/QEMU guest (RIG.md §9).
    # Default: $env:RIG_VM_EXECUTION_ENGINE, else empty = leave the VM as it is.
    [string] $ExecutionEngine = $env:RIG_VM_EXECUTION_ENGINE,
    # Turn the VM's 3D acceleration off after each restore of an offline snapshot (modifyvm --accelerate-3d off;
    # the snapshot keeps its own setting, so the next restore brings it back). Works around guest freezes with
    # VMSVGA 3D (DXVK on the host GPU) on the Linux host (RIG.md §9). Default: on when $env:RIG_VM_NO_3D is 1.
    [switch] $No3D = ($env:RIG_VM_NO_3D -eq '1')
)

# Host platform: Windows (PowerShell 5.1 or 7) or Linux (pwsh 7, RIG.md §9). 5.1 has no $IsWindows.
$script:OnWindows = ($PSVersionTable.PSEdition -ne 'Core') -or [bool]$IsWindows
# Host-side relative paths are written with '\' below; on Linux they become '/' (guest paths C:\... are never
# passed through this). On Windows the path is returned unchanged.
function HostPath([string]$P) { if ($script:OnWindows) { $P } else { $P.Replace('\', '/') } }
# Host temp dir for job files and a temporary password copy: %TEMP% on Windows; on Linux $RIG_TMP, $TMPDIR or /tmp.
function Get-HostTemp {
    if ($script:OnWindows) { return $env:TEMP }
    foreach ($t in $env:RIG_TMP, $env:TMPDIR) { if ($t) { return $t } }
    '/tmp'
}

if ($script:OnWindows) {
    $script:VBox  = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
} else {
    # $VBOXMANAGE overrides; else the real binary /usr/lib/virtualbox/VBoxManage (the /usr/bin wrapper VBox.sh
    # prints a "vboxdrv kernel module is not loaded" warning on every call under the KVM-backend build, which would
    # end up in the merged output); else VBoxManage on PATH.
    $script:VBox  = $env:VBOXMANAGE
    if (-not $script:VBox -and (Test-Path -LiteralPath '/usr/lib/virtualbox/VBoxManage' -PathType Leaf)) { $script:VBox = '/usr/lib/virtualbox/VBoxManage' }
    if (-not $script:VBox) { $c = Get-Command VBoxManage -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1; if ($c) { $script:VBox = $c.Source } else { $script:VBox = '/usr/bin/VBoxManage' } }
}
$script:VmName    = $VmName
$script:GuestUser = 'tester'
$script:RigDir    = $PSScriptRoot
$script:RepoRoot  = Split-Path -Parent $PSScriptRoot
$script:RunsDir   = Join-Path $PSScriptRoot 'runs'
$script:FrozenDir = Join-Path $PSScriptRoot (HostPath 'truth\frozen')   # frozen M0 truth and plans, read only
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
        if (-not $script:OnWindows) {
            # Linux: owner-only (0600) before the password is written; /tmp is shared.
            [IO.File]::WriteAllText($tmp, '')
            [IO.File]::SetUnixFileMode($tmp, [IO.UnixFileMode]'UserRead, UserWrite')
        }
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
    param([string]$Snapshot = 'rig-base', [int]$AgentTimeoutSec = 300, [string]$ExecutionEngine = $env:RIG_VM_EXECUTION_ENGINE,
          [switch]$No3D = ($env:RIG_VM_NO_3D -eq '1'))
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
    if ($ExecutionEngine) {
        # Machine-level setting (not stored in snapshots); the VM is powered off here, as modifyvm requires.
        $r = Invoke-VBox @('modifyvm', $script:VmName, '--vm-execution-engine', $ExecutionEngine)
        if ($r.code -ne 0) { throw "modifyvm --vm-execution-engine $ExecutionEngine failed: $($r.out -join ' ')" }
        Write-RigLog "  execution engine: $ExecutionEngine"
    }
    $live = ((Get-VmState) -eq 'saved')
    if ($No3D) {
        if ($live) { Write-RigLog '  -No3D ignored: a live snapshot (saved state) cannot change its graphics settings' }
        else {
            $r = Invoke-VBox @('modifyvm', $script:VmName, '--accelerate-3d', 'off')
            if ($r.code -ne 0) { throw "modifyvm --accelerate-3d off failed: $($r.out -join ' ')" }
            Write-RigLog '  3D acceleration: off (until the next restore)'
        }
    }
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
    $tmpDir = Join-Path (Get-HostTemp) 'vmjobs'
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
    if ($Engine) { $Engine = HostPath $Engine }   # Linux: a Windows-style '.\target\release\...' works too
    if (-not $Engine) { $Engine = Join-Path $RepoRoot (HostPath 'target\release\purge-engine.exe') }
    if (-not (Test-Path -LiteralPath $Engine -PathType Leaf)) {
        if ($explicit) { throw "purge-engine not found: $Engine (cargo build --release -p purge-engine)" }
        return [pscustomobject]@{ engine = $null; baselines = @() }
    }
    $bl = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot (HostPath 'kb\baselines')) -Filter '*.tsv.gz' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    [pscustomobject]@{ engine = (Resolve-Path -LiteralPath $Engine).ProviderPath; baselines = $bl }
}

# Pure: the files of the host installer cache (vm\cache\inst) a run of app $Id uses: its installer, the
# installers of its pre / post / upgrade_from apps and its plant files (apps.ps1 Get-AppFiles), where the cache
# holds them. Returns full paths.
function Get-CachedRunFiles {
    param([Parameter(Mandatory)][string]$Id, [string]$CacheDir = (Join-Path $script:RigDir (HostPath 'cache\inst')))
    if (-not (Test-Path -LiteralPath (Join-Path $CacheDir 'cache-sources.json'))) { return @() }
    $names = & { . (Join-Path $script:RigDir (HostPath 'guest\apps.ps1')); Get-AppFiles $Id }
    @($names | ForEach-Object { Join-Path $CacheDir $_ } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
}

# Copies a fresh rigtool.exe to C:\cr\bin, purge-engine.exe to C:\cr\bin and kb\baselines\*.tsv.gz to
# C:\cr\bin\kb\baselines (see Get-EnginePush; none with -NoBaselines), and vm\guest\*.ps1 to C:\cr\guest (old
# copies deleted first). -Installers: host cache files (Get-CachedRunFiles) to C:\cr\inst, with the manifest.
function Push-Tools {
    param([string]$RigTool = '', [string]$Engine = '', [switch]$NoBaselines, [string[]]$Installers = @())
    # The guest's rigtool is always the Windows build (rigtool.exe), on a Linux host too.
    if (-not $RigTool) { $RigTool = Join-Path $script:RigDir (HostPath 'rigtool\target\release\rigtool.exe') }
    if (-not (Test-Path -LiteralPath $RigTool)) { throw "rigtool not built: $RigTool (cargo build --release in vm\rigtool)" }
    $ep = Get-EnginePush -Engine $Engine
    if ($NoBaselines) { $ep.baselines = @() }
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
    $inst = @($Installers | Where-Object { $_ })
    if ($inst.Count) {
        $man = Join-Path $script:RigDir (HostPath 'cache\inst\cache-sources.json')
        $null = Invoke-Guest @('mkdir', '--parents', 'C:\cr\inst')
        $r = Invoke-Guest (@('copyto', '--target-directory', 'C:\cr\inst\') + @($man) + $inst)
        if ($r.code -ne 0) { throw "copy cached installers failed: $($r.out -join ' ')" }
        $expect += @(@($man) + $inst | ForEach-Object { 'C:\cr\inst\' + (Split-Path -Leaf $_) })
    }
    $missing = @()
    foreach ($f in $expect + @($scripts | ForEach-Object { 'C:\cr\guest\' + (Split-Path -Leaf $_) })) {
        if ((Invoke-Guest @('stat', $f)).code -ne 0) { $missing += $f }
    }
    if ($missing.Count) { throw "not in the guest after copy: $($missing -join ', ')" }
    $what = 'rigtool.exe'
    if ($ep.engine) { $what += " + purge-engine.exe ($($ep.engine)) + $($ep.baselines.Count) baseline(s)$(if ($NoBaselines) { ' (-NoBaselines)' })" }
    if ($inst.Count) { $what += " + cached $(($inst | ForEach-Object { Split-Path -Leaf $_ }) -join ', ')" }
    Write-RigLog "  pushed $what + $($scripts.Count) guest scripts"
}

# ---------------------------------------------------------------------------------------------- runs

# Pure: the job text for a run. App runs (run-app.ps1): __ID__ = the app id, __RUN__ = the run name (default
# the id), __ENGINE__ = 1 with -Engine, else 0, __EXTRA__ = 1 with -Extra (needs -Engine), else 0. Null runs
# (null-run.ps1): __RUN__ = the run name (default null<n>, or <prefix>null<n>), __WAIT__ = the idle seconds per
# wait (default 60).
function New-RunJobText {
    param([string]$Id = '', [int]$NullRun = 0, [string]$Run = '', [switch]$Engine, [switch]$Extra, [int]$NullWaitSec = 60)
    if ($Id) {
        if ($Id -cnotmatch '^[a-z0-9][a-z0-9_-]*$') { throw "bad app id '$Id' (lowercase letters, digits, _ and -)" }
        if (-not $Run) { $Run = $Id }
        if ($Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$Run' (lowercase letters, digits, _, . and -)" }
        if ($Extra -and -not $Engine) { throw '-Extra (extra checks) needs -Engine' }
        $tpl = [IO.File]::ReadAllText((Join-Path $script:RigDir (HostPath 'guest\run-app.ps1')))
        return $tpl.Replace('__ID__', $Id).Replace('__RUN__', $Run).Replace('__ENGINE__', $(if ($Engine) { '1' } else { '0' })).Replace('__EXTRA__', $(if ($Extra) { '1' } else { '0' }))
    }
    if ($NullRun -lt 1) { throw 'give -Id or -Null n (n >= 1)' }
    if (-not $Run) { $Run = "null$NullRun" }
    if ($Run -cnotmatch '^([a-z0-9][a-z0-9_.-]*-)?null\d+$') { throw "bad null run name '$Run' (null<n> or <prefix>null<n>)" }
    if ($NullWaitSec -lt 0 -or $NullWaitSec -gt 3600) { throw "bad -NullWaitSec $NullWaitSec (0..3600)" }
    $tpl = [IO.File]::ReadAllText((Join-Path $script:RigDir (HostPath 'guest\null-run.ps1')))
    $tpl.Replace('__RUN__', $Run).Replace('__WAIT__', "$NullWaitSec")
}

# Pure: the name of null run n. In a prefixed (engine) campaign the null runs carry the prefix too, so the M0
# null runs vm\runs\null<n>\ (the source of truth\ambient.json) are never archived or overwritten.
function Get-NullRunName {
    param([Parameter(Mandatory)][int]$N, [string]$RunPrefix = '')
    $run = "${RunPrefix}null$N"
    if ($run -cnotmatch '^([a-z0-9][a-z0-9_.-]*-)?null\d+$') { throw "bad null run name '$run' (prefix '$RunPrefix' must end with '-')" }
    $run
}

# Pure: the order of a campaign's runs. 'first' = null runs, then apps (M0). 'spread' = the null runs spread over
# the campaign (first, between the apps, last), so the ambient set sees the same stretch of guest time as the apps.
function Get-CampaignOrder {
    param([object[]]$Nulls = @(), [object[]]$Apps = @(), [string]$NullOrder = 'first')
    $Nulls = @($Nulls | Where-Object { $_ }); $Apps = @($Apps | Where-Object { $_ })
    if ($NullOrder -ne 'spread' -or $Nulls.Count -lt 2 -or $Apps.Count -eq 0) { return @($Nulls) + @($Apps) }
    $out = New-Object System.Collections.ArrayList
    $gaps = $Nulls.Count - 1
    $ai = 0
    for ($k = 0; $k -lt $Nulls.Count; $k++) {
        [void]$out.Add($Nulls[$k])
        if ($k -lt $gaps) {
            $upto = [int][Math]::Round(($k + 1) * $Apps.Count / $gaps)
            while ($ai -lt $upto -and $ai -lt $Apps.Count) { [void]$out.Add($Apps[$ai]); $ai++ }
        }
    }
    while ($ai -lt $Apps.Count) { [void]$out.Add($Apps[$ai]); $ai++ }
    @($out)
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
        [string]$RunPrefix = '',
        [Parameter(ParameterSetName = 'null')][int]$NullWaitSec = 60,
        [Parameter(ParameterSetName = 'app')][switch]$Engine,
        [Parameter(ParameterSetName = 'app')][switch]$ExtraChecks,
        [int]$TimeoutSec = 0
    )
    if ($PSCmdlet.ParameterSetName -eq 'app') {
        $run = Get-RunName -Id $Id -RunPrefix $RunPrefix -Engine:$Engine
        $text = New-RunJobText -Id $Id -Run $run -Engine:$Engine -Extra:$ExtraChecks; $to = 5400
    } else {
        $run = Get-NullRunName -N $NullRun -RunPrefix $RunPrefix
        $text = New-RunJobText -NullRun $NullRun -Run $run -NullWaitSec $NullWaitSec; $to = 2400
    }
    if ($TimeoutSec -gt 0) { $to = $TimeoutSec }
    $null = Move-RunToOld -Run $run
    $dst = Join-Path $script:RunsDir $run
    New-Item -ItemType Directory -Force $dst | Out-Null
    Write-RigLog "run $run (timeout $to s$(if ($Engine) { ', engine mode' })$(if ($ExtraChecks) { ', extra checks' }))"
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
    $bcu = Join-Path $script:FrozenDir (HostPath "$Id\plans\bcu.json")
    if (Test-Path -LiteralPath $bcu) {
        New-Item -ItemType Directory -Force $plans | Out-Null
        Copy-Item -LiteralPath $bcu -Destination (Join-Path $plans 'bcu.json') -Force
        $copied += 'bcu.json'
    }
    # The extra-check plans (plan-live.json: scan of the still-installed app; plan-purge-b.json: the repeat scan)
    # stay in the run directory on purpose: in plans\ `rigtool score --set` would score them as offers on this
    # run's post-uninstall state. truth\m1a.sh reads them there (m1a-extra.md).
    $extra = @('plan-live.json', 'plan-purge-b.json' | Where-Object { Test-Path -LiteralPath (Join-Path $dir $_) })
    Write-RigLog "  plans for $Run`: $(if ($copied.Count) { $copied -join ', ' } else { 'none' })$(if ($extra.Count) { "; extra-check plans kept in the run dir: $($extra -join ', ')" })"
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
# and the null runs <prefix>null<n> (without a prefix: null<n>, as in M0); -Engine <purge-engine.exe> pushes
# that engine and runs the apps in engine mode. -NullWaitSec / -NullOrder: see the header.
function Invoke-Campaign {
    param([string[]]$Ids = @(), [int]$Nulls = 3, [string]$Snapshot = 'rig-base', [switch]$NoRestore,
          [string]$RunPrefix = '', [string]$Engine = '', [int]$NullWaitSec = 60,
          [ValidateSet('first', 'spread')][string]$NullOrder = 'first', [switch]$ExtraChecks, [switch]$NoBaselines,
          [string]$ExecutionEngine = $env:RIG_VM_EXECUTION_ENGINE, [switch]$No3D = ($env:RIG_VM_NO_3D -eq '1'))
    $useEngine = [bool]$Engine
    if ($ExtraChecks -and -not $useEngine) { throw '-ExtraChecks needs -Engine' }
    if ($NoBaselines -and -not $useEngine) { throw '-NoBaselines needs -Engine' }
    # Names are checked before anything is moved or restored.
    $nullPlan = @()
    if ($Nulls -gt 0) { foreach ($n in 1..$Nulls) { $nullPlan += @{ run = (Get-NullRunName -N $n -RunPrefix $RunPrefix); null = $n } } }
    $appPlan = @()
    foreach ($id in $Ids) { if ($id) { $appPlan += @{ run = (Get-RunName -Id $id -RunPrefix $RunPrefix -Engine:$useEngine); id = $id } } }
    $plan = @(Get-CampaignOrder -Nulls $nullPlan -Apps $appPlan -NullOrder $NullOrder)
    if ($useEngine) { $null = Get-EnginePush -Engine $Engine }
    New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:RigLogFile = Join-Path $script:RunsDir "campaign-$stamp.log"
    $summaryFile = Join-Path $script:RunsDir "campaign-$stamp.json"
    $results = New-Object System.Collections.ArrayList
    Write-RigLog "campaign ${stamp}: $(($plan | ForEach-Object { $_.run }) -join ', ') from snapshot $Snapshot on $script:VmName$(if ($useEngine) { "; engine $Engine" })$(if ($ExtraChecks) { '; extra checks' })$(if ($NoBaselines) { '; NO baselines' })$(if ($ExecutionEngine) { "; execution engine $ExecutionEngine" })$(if ($No3D) { '; 3D off' })"
    try {
        $null = Get-PwFile
        foreach ($p in $plan) {
            $t = Get-Date
            $rec = [ordered]@{ run = $p.run; id = $p.id; engine = ($useEngine -and [bool]$p.id); ok = $false; error = $null; start = $t.ToString('o'); end = $null; seconds = $null; pulled = 0; started = $null; failed_phases = @() }
            try {
                # Before anything else, so neither Invoke-Run nor the catch's Pull-Run sees an older run's files.
                $null = Move-RunToOld -Run $p.run
                if (-not $NoRestore) { Restore-Base -Snapshot $Snapshot -ExecutionEngine $ExecutionEngine -No3D:$No3D } else { Wait-Agent -TimeoutSec 120 }
                $inst = @(); if ($p.id) { $inst = @(Get-CachedRunFiles -Id $p.id) }
                Push-Tools -Engine $Engine -NoBaselines:$NoBaselines -Installers $inst
                if ($p.id) { $res = Invoke-Run -Id $p.id -RunPrefix $RunPrefix -Engine:$useEngine -ExtraChecks:$ExtraChecks }
                else { $res = Invoke-Run -NullRun $p.null -RunPrefix $RunPrefix -NullWaitSec $NullWaitSec }
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
    $text = [IO.File]::ReadAllText((Join-Path $script:RigDir (HostPath 'guest\setup-base.ps1')))
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
    Invoke-Campaign -Ids $Ids -Nulls $Nulls -Snapshot $Snapshot -RunPrefix $RunPrefix -Engine $Engine -NullWaitSec $NullWaitSec -NullOrder $NullOrder `
                    -ExtraChecks:$ExtraChecks -NoBaselines:$NoBaselines -ExecutionEngine $ExecutionEngine -No3D:$No3D
}
