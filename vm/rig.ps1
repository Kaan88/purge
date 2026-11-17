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

  M2 executor runs (RIG.md §11): one mode per call, from a restore of m2-base, with the rig-exec engine
  (target\rig-exec\release\purge-engine.exe; the release engine is refused) and the reboot-in-job continuations:
    .\vm\rig.ps1 -Mode m2-traps
    .\vm\rig.ps1 -Mode m2-crash -HardPowerOff
    . .\vm\rig.ps1; Invoke-SnapshotJob -Run m2-try -Mode m2-install    # the generic entry

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
    [switch] $No3D = ($env:RIG_VM_NO_3D -eq '1'),
    # M2 executor runs (RIG.md §11): campaign (default, the M0 / M1a behaviour above) or one M2 mode. The M2 modes
    # restore -Snapshot (default m2-base) and push the rig-exec engine (-Engine, default
    # target\rig-exec\release\purge-engine.exe; the release engine target\release\purge-engine.exe is refused).
    # (checked in the footer, not with ValidateSet: a dot-sourcing script may use $Mode for itself). The M2
    # parameters carry an M2 prefix for the same reason (apps.ps1 owns $Apps); their command-line names are the
    # aliases -HardPowerOff, -FaultPoints, -Apps, -BatchSize.
    [string] $Mode = 'campaign',
    # m2-crash: also the power-off rounds (the host powers the VM off hard while the engine sits at a pause point).
    [Alias('HardPowerOff')] [switch] $M2HardPowerOff,
    # m2-crash: only these fault points (default: every point `journal fault-points` lists).
    [Alias('FaultPoints')] [string[]] $M2FaultPoints = @(),
    # m2-fidelity: real-app round trips after the fixture runs (app ids of guest\apps.ps1; 'none' for none).
    [Alias('Apps')] [string[]] $M2Apps = @(),
    # m2-crash: matrix iterations per job (then a reboot continuation); 0 = all in one job.
    [Alias('BatchSize')] [int] $M2BatchSize = -1,
    # m2-traps / m2-fidelity: a null run (exec replaced by an idle wait, nothing after snap B; RIG.md section 11.8).
    [Alias('Null')] [switch] $M2Null,
    # m2-fidelity app stage: the plan bands whose items are selected (default Safe, Likely, Weak; never Blocked).
    [Alias('AppBands')] [string[]] $M2AppBands = @(),
    # M1b scan modes (RIG.md section 12): m1b-app's app id, the base snapshot (rig-base or dirty-base; m1b-apps and
    # m1b-traps too), the trap plants of guest\m1b-traps.ps1 around the run (m1b-app), and for m1b-budgets the M2-head
    # engine and the program id measured. Prefixed for the same reason as the M2 parameters; command-line names are
    # the aliases -App, -Base, -Traps, -BaseEngine, -Program.
    [Alias('App')] [string] $M1bApp = '',
    [Alias('Base')] [string] $M1bBase = 'rig-base',
    [Alias('Traps')] [switch] $M1bTraps,
    [Alias('BaseEngine')] [string] $M1bBaseEngine = '',
    [Alias('Program')] [string] $M1bProgram = ''
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
# Host installer cache (vm\cache\inst and its cache-sources.json, git-ignored). $env:RIG_CACHE_DIR points elsewhere,
# e.g. a worktree without a cache of its own uses the main checkout's.
$script:CacheDir  = $(if ($env:RIG_CACHE_DIR) { $env:RIG_CACHE_DIR } else { Join-Path $PSScriptRoot (HostPath 'cache\inst') })
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
    param([Parameter(Mandatory)][string]$Id, [string]$CacheDir = $script:CacheDir)
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
    # $env:RIG_RIGTOOL overrides the default build (e.g. a CARGO_TARGET_DIR outside the repo).
    if (-not $RigTool -and $env:RIG_RIGTOOL) { $RigTool = $env:RIG_RIGTOOL }
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
        $man = Join-Path $script:CacheDir 'cache-sources.json'
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
    param([string]$Id = '', [int]$NullRun = 0, [string]$Run = '', [switch]$Engine, [switch]$Extra, [int]$NullWaitSec = 60, $M1b = $null)
    if ($Id) {
        if ($Id -cnotmatch '^[a-z0-9][a-z0-9_-]*$') { throw "bad app id '$Id' (lowercase letters, digits, _ and -)" }
        if (-not $Run) { $Run = $Id }
        if ($Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$Run' (lowercase letters, digits, _, . and -)" }
        if ($Extra -and -not $Engine) { throw '-Extra (extra checks) needs -Engine' }
        $tpl = [IO.File]::ReadAllText((Join-Path $script:RigDir (HostPath 'guest\run-app.ps1')))
        # __M1B__ (RIG.md section 12): base64 of the M1b options as UTF-8 JSON (ConvertTo-M1bOpts); empty = none.
        $m1bText = ''
        if ($M1b) { $m1bText = [Convert]::ToBase64String((New-Object System.Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject (ConvertTo-M1bOpts $M1b) -Compress))) }
        return $tpl.Replace('__ID__', $Id).Replace('__RUN__', $Run).Replace('__ENGINE__', $(if ($Engine) { '1' } else { '0' })).Replace('__EXTRA__', $(if ($Extra) { '1' } else { '0' })).Replace('__M1B__', $m1bText)
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
        [Parameter(ParameterSetName = 'app')]$M1b = $null,
        [int]$TimeoutSec = 0
    )
    if ($PSCmdlet.ParameterSetName -eq 'app') {
        $run = Get-RunName -Id $Id -RunPrefix $RunPrefix -Engine:$Engine
        $text = New-RunJobText -Id $Id -Run $run -Engine:$Engine -Extra:$ExtraChecks -M1b $M1b; $to = 5400
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
          [string]$ExecutionEngine = $env:RIG_VM_EXECUTION_ENGINE, [switch]$No3D = ($env:RIG_VM_NO_3D -eq '1'),
          # M1b options of the app runs (ConvertTo-M1bOpts; RIG.md section 12), $null for none.
          $M1b = $null)
    $useEngine = [bool]$Engine
    if ($M1b) { $null = ConvertTo-M1bOpts $M1b }   # checked before anything is moved or restored
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
                if ($p.id) { $res = Invoke-Run -Id $p.id -RunPrefix $RunPrefix -Engine:$useEngine -ExtraChecks:$ExtraChecks -M1b $M1b }
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

# ------------------------------------------------------------------------------ M2 executor runs (§11)
#
# One M2 run = one guest script (exec-run.ps1, m2-crash.ps1 or m2-reboot.ps1) started from a fresh restore of
# -Snapshot (m2-base) with the rig-exec engine pushed. A script may end a stage with a continuation marker
# C:\cr\out\<run>\continue.json (riglib Request-RigContinuation): kind 'reboot' (the guest restarts itself) or
# 'poweroff' (the host powers the VM off hard, m2-crash -HardPowerOff only). The host then waits for the new boot
# and the agent and submits the same script again with __STAGE__ = the marker's `next` (RIG.md §11.2).
#   .\vm\rig.ps1 -Mode m2-traps
#   .\vm\rig.ps1 -Mode m2-crash -HardPowerOff -Engine .\target\rig-exec\release\purge-engine.exe
#   . .\vm\rig.ps1; Invoke-SnapshotJob -Run m2-try -Mode m2-install -Snapshot m2-base

# The only VMs the rig drives.
$script:RigVms = @('Inbound-Win11-Test', 'Purge-CleanPro')

function Assert-RigVm([string]$Name = $script:VmName) {
    if ($script:RigVms -cnotcontains $Name) { throw "VM '$Name' is not a rig VM ($($script:RigVms -join ', '))" }
}

# Pure: the run name of an M2 mode: <prefix><mode> (m2-traps, g1-m2-traps, ...).
function Get-M2RunName {
    param([Parameter(Mandatory)][string]$Mode, [string]$RunPrefix = '')
    if ($Mode -cnotmatch '^m2-[a-z]+$') { throw "bad M2 mode '$Mode'" }
    $run = "$RunPrefix$Mode"
    if ($run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$run' (prefix '$RunPrefix': lowercase letters, digits, _, . and -)" }
    $run
}

# Pure: the engine an M2 run pushes. Default target\rig-exec\release\purge-engine.exe (the build with fault
# injection, kept apart so it never replaces the release engine the M1a runs push). target\release\purge-engine.exe
# itself is refused. The file must exist and be named purge-engine.exe.
function Get-M2Engine {
    param([string]$Engine = '', [string]$RepoRoot = $script:RepoRoot)
    if (-not $Engine) { $Engine = Join-Path $RepoRoot (HostPath 'target\rig-exec\release\purge-engine.exe') } else { $Engine = HostPath $Engine }
    if (-not (Test-Path -LiteralPath $Engine -PathType Leaf)) { throw "rig-exec engine not found: $Engine (build it into target\rig-exec, RIG.md section 11.1)" }
    $full = (Resolve-Path -LiteralPath $Engine).ProviderPath
    if ((Split-Path -Leaf $full) -ne 'purge-engine.exe') { throw "the engine file must be named purge-engine.exe: $full" }
    $release = Join-Path $RepoRoot (HostPath 'target\release\purge-engine.exe')
    $releaseFull = $(if (Test-Path -LiteralPath $release) { (Resolve-Path -LiteralPath $release).ProviderPath } else { [IO.Path]::GetFullPath($release) })
    if ([string]::Equals($full, $releaseFull, [StringComparison]::OrdinalIgnoreCase)) { throw "refusing the release engine $full for an M2 run: give the rig-exec build (-Engine target\rig-exec\release\purge-engine.exe)" }
    $full
}

# Pure: the guest script of a mode.
function Get-M2Template([string]$Mode) {
    switch ($Mode) {
        'm2-crash' { 'm2-crash.ps1' }
        'm2-reboot' { 'm2-reboot.ps1' }
        { @('m2-traps', 'm2-fidelity', 'm2-install') -contains $_ } { 'exec-run.ps1' }
        default { throw "no M2 template for mode '$Mode'" }
    }
}

# Pure: the job text of one stage. __OPTS__ = base64 of the options as UTF-8 JSON.
function New-M2JobText {
    param([Parameter(Mandatory)][string]$Mode, [Parameter(Mandatory)][string]$Run, [string]$Stage = 'start', $Opts = @{}, [string]$Template = '')
    if ($Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$Run'" }
    if ($Stage -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad stage '$Stage'" }
    if (-not $Template) { $Template = Get-M2Template $Mode }
    if ($Template -cnotmatch '^[a-z0-9-]+\.ps1$') { throw "bad template '$Template'" }
    $json = ConvertTo-Json -InputObject $Opts -Depth 6 -Compress
    $b64 = [Convert]::ToBase64String((New-Object System.Text.UTF8Encoding($false)).GetBytes($json))
    $tpl = [IO.File]::ReadAllText((Join-Path $script:RigDir (HostPath "guest\$Template")))
    $tpl.Replace('__RUN__', $Run).Replace('__MODE__', $Mode).Replace('__STAGE__', $Stage).Replace('__OPTS__', $b64)
}

# install\install.ps1 to C:\cr\install (Push-Tools sends vm\guest\*.ps1 only).
function Push-M2Install {
    $src = Join-Path $script:RepoRoot (HostPath 'install\install.ps1')
    if (-not (Test-Path -LiteralPath $src)) { throw "missing $src" }
    $null = Invoke-Guest @('mkdir', '--parents', 'C:\cr\install')
    $null = Invoke-GuestCmd 'del /f /q C:\cr\install\install.ps1'
    $r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\install\', $src)
    if ($r.code -ne 0) { throw "copy install.ps1 failed: $($r.out -join ' ')" }
    if ((Invoke-Guest @('stat', 'C:\cr\install\install.ps1')).code -ne 0) { throw 'install.ps1 not in the guest after copy' }
    Write-RigLog '  pushed install\install.ps1 to C:\cr\install'
}

# Pure: the M2 ambient set of a VM (RIG.md section 11.8). Each VM has its own, derived from its own null runs
# (Windows churn differs per build): Inbound-Win11-Test truth\m2-ambient.json, Purge-CleanPro
# truth\m2-ambient-cleanpro.json. A VM outside the list has none (Assert-RigVm refuses it anyway).
function Get-M2AmbientFile([string]$Name = $script:VmName) {
    $leaf = switch -CaseSensitive ($Name) { 'Inbound-Win11-Test' { 'm2-ambient.json' } 'Purge-CleanPro' { 'm2-ambient-cleanpro.json' } default { $null } }
    if (-not $leaf) { throw "no M2 ambient set for VM '$Name'" }
    Join-Path $script:RigDir (HostPath "truth\$leaf")
}

# The VM's M2 ambient set (Get-M2AmbientFile) to C:\cr\bin\m2-ambient.json, where riglib Invoke-M2Execdiff passes it
# as --ambient. -None (null runs) or no file: the guest copy is deleted, so execdiff runs without one.
function Push-M2Ambient {
    param([switch]$None)
    $src = Get-M2AmbientFile
    $null = Invoke-GuestCmd 'del /f /q C:\cr\bin\m2-ambient.json'
    if ($None -or -not (Test-Path -LiteralPath $src)) { Write-RigLog "  no M2 ambient set pushed$(if (-not $None) { " ($src missing)" })"; return $false }
    # Copied under the guest's fixed name, whatever the host file is called.
    $tmp = Join-Path (Get-HostTemp) ('m2amb-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force $tmp | Out-Null
    try {
        Copy-Item -LiteralPath $src -Destination (Join-Path $tmp 'm2-ambient.json') -Force
        $r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\bin\', (Join-Path $tmp 'm2-ambient.json'))
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    if ($r.code -ne 0) { throw "copy m2-ambient.json failed: $($r.out -join ' ')" }
    Write-RigLog "  pushed truth\$(Split-Path -Leaf $src) to C:\cr\bin\m2-ambient.json"
    $true
}

# The continuation marker a finished stage left (parsed), or $null when the run is complete.
function Get-GuestContinuation {
    param([Parameter(Mandatory)][string]$Run)
    $tmp = Join-Path (Get-HostTemp) ('rigcont-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
        $r = Invoke-Guest @('copyfrom', "C:\cr\out\$Run\continue.json", $tmp)
        if ($r.code -ne 0 -or -not (Test-Path -LiteralPath $tmp)) { return $null }
        [IO.File]::ReadAllText($tmp) | ConvertFrom-Json
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

# After a 'reboot' continuation: waits until the guest reports a boot time other than $BootBefore, then for the
# agent. The guest restarts itself delay_sec after the job ended, so the old boot is seen for a while first.
function Wait-GuestReboot {
    param([string]$BootBefore = '', [int]$TimeoutSec = 900)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $cmd = 'powershell.exe -NoProfile -Command "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString(''o'')"'
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 10
        $r = Invoke-GuestCmd $cmd 60
        $b = @($r.out | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^\d{4}-\d\d-\d\dT' }) | Select-Object -First 1
        if ($r.code -eq 0 -and $b -and $b -ne $BootBefore) {
            Write-RigLog "  guest rebooted (boot $b)"
            Wait-Agent -TimeoutSec ([Math]::Max(120, [int]($deadline - (Get-Date)).TotalSeconds))
            return $b
        }
    }
    throw "the guest did not reboot within $TimeoutSec s"
}

# After a 'poweroff' continuation (-HardPowerOff): VBoxManage controlvm poweroff (no shutdown, no flush), then a
# cold start and the agent.
# Before a hard power-off: a guest job flushes (FlushFileBuffers) every file of the rig's own run directories,
# C:\cr\out\<run> and C:\cr\work\<run>, so the marker, the stage state, run.json and the A snapshots written seconds
# before survive the power cut. Without it the gate run of 2026-11-16 found continue.json filled with blanks after
# the boot (Invalid JSON primitive). Only these directories: the engine's store (C:\ProgramData\Purge) is never
# flushed by the rig, since its own durability is what the power-off rounds test. A failure is logged, not thrown.
function Sync-GuestRunFiles {
    param([Parameter(Mandatory)][string]$Run, [int]$TimeoutSec = 300)
    if ($Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$Run'" }
    $text = @"
`$ErrorActionPreference = 'Continue'
`$n = 0; `$bad = 0
foreach (`$d in @('C:\cr\out\$Run', 'C:\cr\work\$Run')) {
    if (-not (Test-Path -LiteralPath `$d)) { continue }
    foreach (`$f in @(Get-ChildItem -LiteralPath `$d -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        if ((`$f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        try { `$s = [IO.File]::Open(`$f.FullName, 'Open', 'ReadWrite', 'ReadWrite, Delete'); try { `$s.Flush(`$true) } finally { `$s.Dispose() }; `$n++ } catch { `$bad++ }
    }
}
"RIGSYNC|`$n|`$bad"
"@
    $tmpDir = Join-Path (Get-HostTemp) 'vmjobs'
    New-Item -ItemType Directory -Force $tmpDir | Out-Null
    $j = Invoke-GuestJob -Text $text -Name "$Run-sync" -TimeoutSec $TimeoutSec -LogCopy (Join-Path $tmpDir ('{0}-sync-{1}.log' -f $Run, [guid]::NewGuid().ToString('N').Substring(0, 6)))
    $m = @("$($j.log)" -split "`r?`n" | Where-Object { $_ -like 'RIGSYNC|*' }) | Select-Object -Last 1
    if (-not $j.done -or -not $m) { Write-RigLog "  !! sync of the run files before the power-off did not report (done=$($j.done))"; return }
    $p = $m -split '\|'
    Write-RigLog "  synced $($p[1]) run file(s) to disk before the power-off$(if ([int]$p[2]) { "; $($p[2]) could not be opened" })"
}

function Invoke-HardPowerCycle {
    param([int]$AgentTimeoutSec = 600)
    Assert-RigVm
    Write-RigLog "  hard power-off of $script:VmName"
    $r = Invoke-VBox @('controlvm', $script:VmName, 'poweroff')
    if ($r.code -ne 0) { throw "controlvm poweroff failed: $($r.out -join ' ')" }
    $null = Wait-VmState @('poweroff', 'aborted') 120
    $r = Invoke-VBox @('startvm', $script:VmName, '--type', 'headless')
    if ($r.code -ne 0) { throw "startvm failed: $($r.out -join ' ')" }
    $null = Wait-VmState @('running') 120
    Wait-Agent -TimeoutSec $AgentTimeoutSec
}

# Runs the stages of one M2 run in the guest as it is (no restore, no push): stage $Stage, then every stage a
# continuation marker names. Returns {run, stages[{stage, job, done, seconds, continuation}], logs[], done, error}.
function Invoke-M2Job {
    param([Parameter(Mandatory)][string]$Run, [Parameter(Mandatory)][string]$Mode, [string]$Stage = 'start', $Opts = @{}, [string]$Template = '',
          [int]$TimeoutSec = 14400, [switch]$HardPowerOff, [int]$MaxContinuations = 60)
    $res = [ordered]@{ run = $Run; stages = (New-Object System.Collections.ArrayList); logs = (New-Object System.Collections.ArrayList); done = $false; error = $null }
    $lastSeq = 0
    $tmpDir = Join-Path (Get-HostTemp) 'vmjobs'
    New-Item -ItemType Directory -Force $tmpDir | Out-Null
    for ($k = 0; $k -le $MaxContinuations; $k++) {
        $text = New-M2JobText -Mode $Mode -Run $Run -Stage $Stage -Opts $Opts -Template $Template
        $log = Join-Path $tmpDir ('{0}-{1:00}-{2}-{3}.log' -f $Run, ($res.stages.Count + 1), $Stage, [guid]::NewGuid().ToString('N').Substring(0, 6))
        Write-RigLog "  stage $Stage of $Run"
        $j = Invoke-GuestJob -Text $text -Name "$Run-$Stage" -TimeoutSec $TimeoutSec -LogCopy $log
        $st = [ordered]@{ stage = $Stage; job = $j.name; done = $j.done; seconds = $j.seconds; continuation = $null }
        [void]$res.stages.Add($st)
        [void]$res.logs.Add([pscustomobject]@{ stage = $Stage; n = $res.stages.Count; file = $log })
        Write-RigLog "  job $($j.name) done=$($j.done) after $($j.seconds) s"
        if (-not $j.done) { $res.error = "stage $Stage did not finish within $TimeoutSec s"; return [pscustomobject]$res }
        $m = Get-GuestContinuation -Run $Run
        if (-not $m) { $res.done = $true; return [pscustomobject]$res }
        $seq = [int]$m.seq
        if ($seq -le $lastSeq) { $res.error = "continuation marker $seq seen twice (stage $Stage did not take it)"; return [pscustomobject]$res }
        $lastSeq = $seq
        if ("$($m.next)" -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { $res.error = "bad next stage '$($m.next)' in continuation $seq"; return [pscustomobject]$res }
        $st.continuation = [ordered]@{ seq = $seq; kind = "$($m.kind)"; next = "$($m.next)" }
        Write-RigLog "  continuation $seq`: $($m.kind), then stage $($m.next)"
        try {
            if ($m.kind -eq 'reboot') { $null = Wait-GuestReboot -BootBefore "$($m.boot_before)" }
            elseif ($m.kind -eq 'poweroff') {
                if (-not $HardPowerOff) { throw 'the guest asked for a hard power-off but -HardPowerOff is not set' }
                Sync-GuestRunFiles -Run $Run
                Invoke-HardPowerCycle
            } else { throw "unknown continuation kind '$($m.kind)'" }
        } catch { $res.error = "continuation $seq ($($m.kind)): $($_.Exception.Message)"; return [pscustomobject]$res }
        $Stage = "$($m.next)"
    }
    $res.error = "more than $MaxContinuations continuations"
    [pscustomobject]$res
}

# The generic M2 entry: one run from a fresh restore of $Snapshot. Restore, push rigtool + the rig-exec engine +
# guest scripts + install.ps1, run the stages (Invoke-M2Job), then $After (more jobs in the same VM session, given
# the record), pull C:\cr\out\<run>\ and the job logs (job-<n>-<stage>.log) and check run.json. Returns the record.
function Invoke-SnapshotJob {
    param([Parameter(Mandatory)][string]$Run, [Parameter(Mandatory)][string]$Mode, $Opts = @{}, [string]$Template = '', [string]$Snapshot = 'm2-base',
          [string]$Engine = '', [switch]$HardPowerOff, [switch]$NoRestore, [int]$TimeoutSec = 14400, [scriptblock]$After = $null,
          [string]$ExecutionEngine = $env:RIG_VM_EXECUTION_ENGINE, [switch]$No3D = ($env:RIG_VM_NO_3D -eq '1'))
    Assert-RigVm
    $eng = Get-M2Engine -Engine $Engine
    if ($Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$Run'" }
    $t = Get-Date
    $rec = [ordered]@{ run = $Run; mode = $Mode; snapshot = $Snapshot; vm = $script:VmName; engine = $eng; ok = $false; error = $null; start = $t.ToString('o'); end = $null
        seconds = $null; stages = @(); pulled = 0; started = $null; failed_phases = @(); after = $null }
    $logs = @()
    try {
        $null = Move-RunToOld -Run $Run
        if (-not $NoRestore) { Restore-Base -Snapshot $Snapshot -ExecutionEngine $ExecutionEngine -No3D:$No3D } else { Wait-Agent -TimeoutSec 120 }
        Push-Tools -Engine $eng
        Push-M2Install
        $isNull = $(if ($Opts -is [System.Collections.IDictionary]) { [bool]$Opts['null'] } else { [bool]$Opts.null })
        $null = Push-M2Ambient -None:$isNull
        $j = Invoke-M2Job -Run $Run -Mode $Mode -Opts $Opts -Template $Template -TimeoutSec $TimeoutSec -HardPowerOff:$HardPowerOff
        $rec.stages = @($j.stages); $logs = @($j.logs)
        if ($j.error) { $rec.error = $j.error }
        if ($After -and $j.done) { $rec.after = & $After $rec }
    } catch {
        $rec.error = $_.Exception.Message
        Write-RigLog "!! M2 run $Run failed: $($rec.error)"
    }
    try { $rec.pulled = @(Pull-Run -Run $Run).Count } catch { if (-not $rec.error) { $rec.error = "pull: $($_.Exception.Message)" } }
    $dst = Join-Path $script:RunsDir $Run
    foreach ($l in $logs) {
        if (Test-Path -LiteralPath $l.file) { Move-Item -LiteralPath $l.file -Destination (Join-Path $dst ('job-{0:00}-{1}.log' -f $l.n, $l.stage)) -Force }
    }
    $chk = Test-RunResult -Run $Run -NotBefore $t
    $rec.started = $chk.started; $rec.failed_phases = @($chk.failed_phases)
    if (-not $rec.error -and -not $chk.ok) { $rec.error = $chk.error }
    $rec.ok = (-not $rec.error -and $chk.ok)
    $rec.end = (Get-Date).ToString('o'); $rec.seconds = [int]((Get-Date) - $t).TotalSeconds
    Write-RigLog "M2 run $Run`: ok=$($rec.ok) in $($rec.seconds) s$(if ($rec.error) { ' - ' + $rec.error })"
    [pscustomobject]$rec
}

# Pure: the options and job timeout of a mode.
function Get-M2ModeOpts {
    param([Parameter(Mandatory)][string]$Mode, [string]$Snapshot = 'm2-base', [switch]$HardPowerOff, [string[]]$FaultPoints = @(), [int]$BatchSize = -1,
          [Alias('Null')][switch]$NullRun, [int]$NullWaitSec = 3)
    $o = [ordered]@{ mode = $Mode; snapshot = $Snapshot }
    if ($NullRun) {
        if (@('m2-traps', 'm2-fidelity') -notcontains $Mode) { throw "-Null is for m2-traps / m2-fidelity only (got $Mode)" }
        $o.null = $true; $o.null_wait = $NullWaitSec
    }
    $to = 14400
    switch ($Mode) {
        'm2-install' { $to = 3600 }
        'm2-reboot' { $to = 5400 }
        'm2-crash' {
            $o.batch = $(if ($BatchSize -lt 0) { 10 } else { $BatchSize })
            $o.hard_poweroff = [bool]$HardPowerOff
            # powershell.exe -File passes "-FaultPoints a,b" as one string: split it.
            $fps = @($FaultPoints | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($fps.Count) { $o.points = $fps }
        }
    }
    [pscustomobject]@{ opts = $o; timeout = $to }
}

# One M2 mode end to end (rig.ps1 -Mode ...): names and engine checked first, then Invoke-SnapshotJob. m2-fidelity
# adds the real-app round trips (-Apps, default npp, firefox): per app the M1a engine run <run>-<id> (run-app.ps1,
# installs, uninstalls, writes plan-purge.json) and then exec-run stage 'app' on its plan, in the same VM session.
# Writes vm\runs\m2-<run>-<stamp>.log / .json.
function Invoke-M2Mode {
    param([Parameter(Mandatory)][string]$Mode, [string]$Snapshot = 'm2-base', [string]$Engine = '', [string]$RunPrefix = '', [switch]$HardPowerOff,
          [string[]]$FaultPoints = @(), [string[]]$Apps = @(), [int]$BatchSize = -1, [Alias('Null')][switch]$NullRun, [string[]]$AppBands = @(),
          [string]$ExecutionEngine = $env:RIG_VM_EXECUTION_ENGINE, [switch]$No3D = ($env:RIG_VM_NO_3D -eq '1'))
    Assert-RigVm
    $run = Get-M2RunName -Mode $Mode -RunPrefix $RunPrefix
    $eng = Get-M2Engine -Engine $Engine
    if ($HardPowerOff -and $Mode -ne 'm2-crash') { throw '-HardPowerOff is for -Mode m2-crash only' }
    $mo = Get-M2ModeOpts -Mode $Mode -Snapshot $Snapshot -HardPowerOff:$HardPowerOff -FaultPoints $FaultPoints -BatchSize $BatchSize -NullRun:$NullRun
    $appIds = @()
    $bands = @($AppBands | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($Mode -eq 'm2-fidelity' -and -not $NullRun) {
        $appIds = @($Apps | Where-Object { $_ })
        if (-not $appIds.Count) { $appIds = @('npp', 'firefox') }
        if ($appIds -contains 'none') { $appIds = @() }
        foreach ($a in $appIds) { $null = Get-RunName -Id $a -RunPrefix "$run-" -Engine }
    }
    New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:RigLogFile = Join-Path $script:RunsDir "m2-$run-$stamp.log"
    Write-RigLog "M2 $Mode as run $run from snapshot $Snapshot on $script:VmName; engine $eng$(if ($appIds.Count) { "; apps $($appIds -join ', ')" })$(if ($HardPowerOff) { '; hard power-off' })"
    $after = $null
    if ($appIds.Count) {
        $after = {
            param($Rec)
            $out = @()
            foreach ($a in $appIds) {
                $ar = [ordered]@{ app = $a; app_run = "$run-$a"; ok = $false; error = $null }
                try {
                    $x = Invoke-Run -Id $a -RunPrefix "$run-" -Engine
                    $ar.app_run = $x.run
                    $ok = (Test-RunResult -Run $x.run -NotBefore ([datetime]$Rec.start))
                    if (-not $ok.ok) { throw "app run $($x.run): $($ok.error)" }
                    $j = Invoke-M2Job -Run $run -Mode $Mode -Stage 'app' -Opts ($(if ($bands.Count) { [ordered]@{ mode = $Mode; app = $a; app_run = $x.run; app_bands = $bands } } else { [ordered]@{ mode = $Mode; app = $a; app_run = $x.run } })) -TimeoutSec 7200
                    foreach ($l in $j.logs) { Move-Item -LiteralPath $l.file -Destination (Join-Path (Join-Path $script:RunsDir $x.run) "job-m2-app-$($l.n).log") -Force -ErrorAction SilentlyContinue }
                    if ($j.error) { throw $j.error }
                    $ar.ok = $true
                } catch { $ar.error = $_.Exception.Message; Write-RigLog "!! app $a`: $($ar.error)" }
                $out += [pscustomobject]$ar
            }
            $out
        }   # called by Invoke-SnapshotJob below: $appIds, $run and $Mode resolve in this function's scope
    }
    try {
        $null = Get-PwFile
        $rec = Invoke-SnapshotJob -Run $run -Mode $Mode -Opts $mo.opts -Snapshot $Snapshot -Engine $eng -HardPowerOff:$HardPowerOff -TimeoutSec $mo.timeout -After $after `
                                  -ExecutionEngine $ExecutionEngine -No3D:$No3D
        if ($rec.ok -and @($rec.after | Where-Object { $_ -and -not $_.ok }).Count) { $rec.ok = $false; $rec.error = 'an app round trip failed' }
        [IO.File]::WriteAllText((Join-Path $script:RunsDir "m2-$run-$stamp.json"), (ConvertTo-Json -InputObject $rec -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    } finally {
        Remove-PwTemp
        $script:RigLogFile = $null
    }
    $rec
}

# The M2 ambient set (RIG.md section 11.8): -Count null runs of each of -Modes (run names n<k>-<mode>, each from a
# fresh restore of -Snapshot with the same phases as the real mode up to snap A, an idle wait instead of exec, snap
# B), then the host's rigtool `ambient --m2` over them -> the VM's ambient file (Get-M2AmbientFile:
# vm\truth\m2-ambient.json for Inbound, vm\truth\m2-ambient-cleanpro.json for Purge-CleanPro). Returns the run records.
#   . .\vm\rig.ps1; Invoke-M2NullCampaign -Count 6 -Engine <rig-exec purge-engine.exe>
function Invoke-M2NullCampaign {
    param([int]$Count = 6, [string[]]$Modes = @('m2-traps', 'm2-fidelity'), [string]$Snapshot = 'm2-base', [string]$Engine = '',
          [string]$RigTool = $env:RIG_RIGTOOL, [string]$Out = (Get-M2AmbientFile), [string]$RunPrefix = 'n')
    if ($Count -lt 1) { throw '-Count must be at least 1' }
    if (-not $RigTool) { $RigTool = Join-Path $script:RigDir (HostPath 'rigtool\target\release\rigtool.exe') }
    if (-not (Test-Path -LiteralPath $RigTool)) { throw "rigtool not built: $RigTool" }
    $recs = @(); $dirs = @()
    foreach ($k in 1..$Count) {
        foreach ($m in $Modes) {
            $r = Invoke-M2Mode -Mode $m -Snapshot $Snapshot -Engine $Engine -RunPrefix "$RunPrefix$k-" -Null
            $recs += $r
            $d = Join-Path $script:RunsDir $r.run
            if ($r.ok -and (Test-Path -LiteralPath (Join-Path $d "snap-$($r.run)-b.tsv.gz"))) { $dirs += $d } else { Write-RigLog "!! null run $($r.run) failed: $($r.error)" }
        }
    }
    if ($dirs.Count -lt $Count) { throw "only $($dirs.Count) null run(s) usable; not writing $Out" }
    $a = @('ambient', '--m2', '--null') + $dirs + @('-o', $Out)
    & $RigTool @a
    if ($LASTEXITCODE -ne 0) { throw "rigtool ambient --m2 exited $LASTEXITCODE" }
    $recs
}

# Elevated engine tests (RIG.md section 11.9): #[ignore]d cargo tests that need an elevated token (they take or
# restore SYSTEM ownership), run in the guest as admin through the agent. The guest has no Rust toolchain, so the
# host builds the test binaries (`cargo test -p <crate> --features <f> --release --no-run`), finds the binary that
# lists each test (`<exe> --list --ignored`), copies it to C:\cr\tests and the agent runs
# `<exe> --ignored --exact <full name> --test-threads=1 --nocapture`. Writes vm\runs\<run>\elevated-tests.json
# (schema purge.rig.m2elevated/1), which truth\m2.sh reads as gate g7_elevated_tests. Default run name m2-elevated.
#   . .\vm\rig.ps1; Invoke-M2ElevatedTests
function Get-M2ElevatedTestSpecs {
    @(
        [pscustomobject]@{ crate = 'purge-win'; features = 'write'; name = 'elevated_set_security_assigns_system_owner' }
        [pscustomobject]@{ crate = 'purge-exec'; features = 'test-support'; name = 'elevated_restore_puts_back_a_system_owner' }
    )
}
# Pure: the full test path of $Name in `--list --format terse` output ('a::b::name: test'), or $null.
function Find-TestInList([string[]]$Lines, [string]$Name) {
    foreach ($l in $Lines) {
        $m = [regex]::Match("$l", '^(\S+): test$')
        if ($m.Success -and ($m.Groups[1].Value -ceq $Name -or $m.Groups[1].Value.EndsWith("::$Name", [StringComparison]::Ordinal))) { return $m.Groups[1].Value }
    }
    $null
}
function Invoke-M2ElevatedTests {
    param($Tests = (Get-M2ElevatedTestSpecs), [string]$Snapshot = 'm2-base', [string]$RunPrefix = '',
          [string]$CargoTargetDir = $(if ($env:RIG_TEST_TARGET) { $env:RIG_TEST_TARGET } else { Join-Path $script:RepoRoot (HostPath 'target\rig-elevated') }),
          [switch]$NoRestore, [int]$TimeoutSec = 900)
    Assert-RigVm
    $run = "$RunPrefix" + 'm2-elevated'
    if ($run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$run'" }
    New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
    $null = Move-RunToOld -Run $run
    $dst = Join-Path $script:RunsDir $run
    New-Item -ItemType Directory -Force $dst | Out-Null
    $script:RigLogFile = Join-Path $dst 'rig.log'
    $t = Get-Date
    $doc = [ordered]@{ schema = 'purge.rig.m2elevated/1'; run = $run; snapshot = $Snapshot; vm = $script:VmName; start = $t.ToString('o'); end = $null
        method = 'host cargo test --no-run, binaries copied to the guest and run by the elevated agent'; admin = $false; tests = @(); error = $null; pass = $false }
    $rows = @()
    try {
        $null = Get-PwFile
        # Native stderr (cargo's progress, the test binaries' --list) must not turn into a terminating error when the
        # caller runs with $ErrorActionPreference = 'Stop' (Windows PowerShell 5.1 wraps each stderr line in an
        # ErrorRecord even with 2>$null); exit codes are checked below. Function scope only.
        $ErrorActionPreference = 'Continue'
        # Host build, one cargo call per (crate, features).
        $exes = @{}
        foreach ($g in @($Tests | Group-Object { "$($_.crate)|$($_.features)" })) {
            $c, $f = $g.Name -split '\|', 2
            Write-RigLog "build tests of $c (features $f) into $CargoTargetDir"
            $old = $env:CARGO_TARGET_DIR; $env:CARGO_TARGET_DIR = $CargoTargetDir
            Push-Location $script:RepoRoot
            try { $out = @(& cargo test -p $c --features $f --release --no-run --message-format=json 2>$null) } finally { Pop-Location; $env:CARGO_TARGET_DIR = $old }
            if ($LASTEXITCODE -ne 0) { throw "cargo test --no-run -p $c --features $f exited $LASTEXITCODE" }
            $exes[$g.Name] = @($out | Where-Object { $_ -match '"reason":"compiler-artifact"' } | ForEach-Object { $_ | ConvertFrom-Json } |
                Where-Object { $_.profile.test -and $_.executable } | ForEach-Object { "$($_.executable)" } | Select-Object -Unique)
        }
        foreach ($s in $Tests) {
            $row = [ordered]@{ crate = $s.crate; features = $s.features; name = $s.name; full_name = $null; exe = $null; exit = $null; passed = $false; error = $null }
            foreach ($e in $exes["$($s.crate)|$($s.features)"]) {
                $fn = Find-TestInList @(& $e --list --ignored --format terse 2>$null) $s.name
                if ($fn) { $row.full_name = $fn; $row.exe = $e; break }
            }
            if (-not $row.exe) { $row.error = "no test binary of $($s.crate) (features $($s.features)) lists an ignored test $($s.name)" }
            $rows += $row
        }
        # Guest run.
        if ($NoRestore) { Wait-Agent -TimeoutSec 120 } else { Restore-Base -Snapshot $Snapshot }
        $null = Invoke-Guest @('mkdir', '--parents', 'C:\cr\tests')
        $lines = @()
        foreach ($row in @($rows | Where-Object { $_.exe })) {
            $leaf = '{0}-{1}' -f $row.crate, (Split-Path -Leaf $row.exe)
            $tmp = Join-Path (Get-HostTemp) 'm2elevated'
            New-Item -ItemType Directory -Force $tmp | Out-Null
            Copy-Item -LiteralPath $row.exe -Destination (Join-Path $tmp $leaf) -Force
            $r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\tests\', (Join-Path $tmp $leaf))
            if ($r.code -ne 0) { $row.error = "copy to the guest failed: $($r.out -join ' ')"; continue }
            $row.guest_exe = "C:\cr\tests\$leaf"
            $lines += "`$o = & '$($row.guest_exe)' --ignored --exact '$($row.full_name)' --test-threads=1 --nocapture 2>&1; `$x = `$LASTEXITCODE"
            $lines += "`$o | ForEach-Object { 'out|$($row.name)|' + `$_ }"
            $lines += "'RIGTEST|$($row.name)|' + `$x"
        }
        if ($lines.Count) {
            $text = "`$ErrorActionPreference = 'Continue'`r`n'admin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`r`n" + ($lines -join "`r`n")
            $j = Invoke-GuestJob -Text $text -Name "$run-tests" -TimeoutSec $TimeoutSec -LogCopy (Join-Path $dst 'job-tests.log')
            if (-not $j.done) { throw "test job did not finish within $TimeoutSec s" }
            $log = @("$($j.log)" -split "`r?`n")
            $doc.admin = [bool](@($log | Where-Object { $_ -match '^admin=True' }).Count)
            foreach ($row in $rows) {
                $m = @($log | Where-Object { $_ -like "RIGTEST|$($row.name)|*" }) | Select-Object -Last 1
                if (-not $m) { if (-not $row.error) { $row.error = 'no result line in the job log' }; continue }
                $row.exit = [int](($m -split '\|')[2])
                $row.output_tail = @($log | Where-Object { $_ -like "out|$($row.name)|*" } | ForEach-Object { $_.Substring("out|$($row.name)|".Length) } | Select-Object -Last 30)
                # libtest prints 'running 1 test' and 'test result: ok. 1 passed'; exit 0 with 0 tests run is not a pass.
                $row.passed = ($row.exit -eq 0 -and @($row.output_tail | Where-Object { $_ -match 'test result: ok\. 1 passed' }).Count -gt 0)
                if (-not $row.passed -and -not $row.error) { $row.error = "exit $($row.exit)" }
            }
        }
    } catch {
        $doc.error = $_.Exception.Message
        Write-RigLog "!! elevated tests: $($doc.error)"
    } finally {
        $doc.tests = @($rows | ForEach-Object { [pscustomobject]$_ })
        $doc.end = (Get-Date).ToString('o')
        $doc.pass = (-not $doc.error -and $doc.admin -and $rows.Count -gt 0 -and -not @($rows | Where-Object { -not $_.passed }).Count)
        [IO.File]::WriteAllText((Join-Path $dst 'elevated-tests.json'), (ConvertTo-Json -InputObject $doc -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
        Write-RigLog "elevated tests $run`: pass=$($doc.pass)$(if ($doc.error) { ' - ' + $doc.error })"
        Remove-PwTemp
        $script:RigLogFile = $null
    }
    [pscustomobject]$doc
}

# ------------------------------------------------------------------------------ M1b scan runs (§12)
#
# The scan side of the M1b gate (docs\M1B_DESIGN.json M1B-RIG-HOST, gates G2-G4, G7, G8). Every VM mode is an
# Invoke-Campaign of engine app runs (run-app.ps1) with M1b options passed as __M1B__:
#   msi_tables  run-app writes msi-tables-<run>-<phase>.json (guest\m1b-msi-tables.ps1) right after snap 1 and snap 2,
#               so a replay of the snapshots has the MSI tables (purge.rig.msi_tables/1, purge-source snapfixture)
#   traps       run-app installs trap_b (node) as a pre-app and runs guest\m1b-traps.ps1: phase pre after the launch
#               (before lists 1, so the harvest sees the plants), between after the harvest (before the uninstall),
#               post after the uninstall (before lists 2 / snap 2 and the scan)
# Run names: <RunPrefix>m1b[d|cp]-[traps-]<id> (d = dirty-base, cp = any base on Purge-CleanPro); null runs
# <RunPrefix>m1b[d|cp]-null<n>; freeze runs m1b-fz<k>-<id>. Scoring: bash truth/m1b.sh (from vm\).
#   .\vm\rig.ps1 -Mode m1b-app -App 7zip -Base rig-base [-Traps] -Engine <release purge-engine.exe>
#   .\vm\rig.ps1 -Mode m1b-apps -Base dirty-base -Engine ...            (the gate list, 3 null runs spread)
#   .\vm\rig.ps1 -Mode m1b-traps -Base rig-base -Engine ...             (7zip as TrapA, node as TrapB, every plant)
#   .\vm\rig.ps1 -Mode m1b-freeze                                       (2 raw runs each of powershell, temurin)
#   .\vm\rig.ps1 -Mode m1b-budgets -Engine <m1b engine> -BaseEngine <M2-head engine> -Program <program id>   (host only)

# The gate's app list (G2, G3).
function Get-M1bGateApps { @('7zip', 'python', 'python312-with-313', 'python313-with-312', 'node', 'vcredist', 'powershell', 'temurin') }
# The apps whose truth m1b-freeze makes (two raw runs each, M0 method).
function Get-M1bFreezeApps { @('powershell', 'temurin') }

# Pure: the M1b options as the guest reads them: {msi_tables, traps, trap_a, trap_b}. Accepts a hashtable or an object.
function ConvertTo-M1bOpts($In) {
    $get = { param($n) if ($In -is [System.Collections.IDictionary]) { $In[$n] } else { $In.$n } }
    $o = [ordered]@{ msi_tables = [bool](& $get 'msi_tables'); traps = [bool](& $get 'traps'); trap_a = $null; trap_b = $null }
    if ($o.traps) {
        $o.trap_a = "$(& $get 'trap_a')"; $o.trap_b = "$(& $get 'trap_b')"
        if (-not $o.trap_b) { $o.trap_b = 'node' }
        foreach ($t in $o.trap_a, $o.trap_b) { if ($t -cnotmatch '^[a-z0-9][a-z0-9_-]*$') { throw "bad trap app id '$t'" } }
        if ($o.trap_a -eq $o.trap_b) { throw "TrapA and TrapB are the same app ($($o.trap_a))" }
    }
    $o
}

# Pure: the run-name prefix of an M1b mode (see the section header). -Freeze k: m1b-fz<k>-.
function Get-M1bRunPrefix {
    param([string]$Base = 'rig-base', [string]$VmName = $script:VmName, [switch]$Traps, [string]$RunPrefix = '', [int]$Freeze = 0)
    if (@('rig-base', 'dirty-base') -cnotcontains $Base) { throw "-Base must be rig-base or dirty-base (got '$Base')" }
    if ($Freeze -gt 0) { $p = "${RunPrefix}m1b-fz$Freeze-" }
    else {
        $tag = $(if ($VmName -ceq 'Purge-CleanPro') { 'cp' } elseif ($Base -eq 'dirty-base') { 'd' } else { '' })
        $p = "${RunPrefix}m1b$tag-$(if ($Traps) { 'traps-' })"
    }
    if ($p -cnotmatch '^[a-z0-9][a-z0-9_.-]*-$') { throw "bad M1b run prefix '$p' (RunPrefix '$RunPrefix')" }
    $p
}

# Pure: the release engine an M1b scan run pushes: -Engine, else $env:RIG_ENGINE, else target\release\purge-engine.exe.
# The rig-exec build (fault injection) is refused: the scan gate measures the engine that ships.
function Get-M1bEngine {
    param([string]$Engine = '', [string]$RepoRoot = $script:RepoRoot)
    if (-not $Engine) { $Engine = $env:RIG_ENGINE }
    $ep = Get-EnginePush -Engine $Engine -RepoRoot $RepoRoot
    if (-not $ep.engine) { throw 'no purge-engine.exe to push (cargo build --release -p purge-engine, or give -Engine / $env:RIG_ENGINE)' }
    if ($ep.engine -match '[\\/]rig-exec[\\/]') { throw "refusing the rig-exec engine $($ep.engine) for an M1b scan run (it carries fault injection)" }
    $ep.engine
}

# The build an M1b scan run is bound to (review R4b S2, as rig-m1b-exec.ps1 Get-XBuildInfo): the engine file's
# SHA-256 (lower-case hex; $null without a file), the repository's HEAD and whether its sources differ from HEAD
# (crates, bins, tools, kb, Cargo.toml, Cargo.lock, rust-toolchain.toml; kb is compiled into the engine, R4 M11).
# Read-only git calls. truth\m1b.sh (BIND) requires one engine and one commit over all runs, and clean sources.
function Get-M1bBuildInfo {
    param([string]$Path = '', [string]$RepoRoot = $script:RepoRoot)
    $sha = $null
    if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) { $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
    $commit = $null; $dirty = $null
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        $c = @(& git -C $RepoRoot rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $c.Count) { $commit = "$($c[0])".Trim() }
        $d = @(& git -C $RepoRoot status --porcelain --untracked-files=no -- crates bins tools kb Cargo.toml Cargo.lock rust-toolchain.toml 2>$null)
        if ($LASTEXITCODE -eq 0) { $dirty = [bool]($d | Where-Object { "$_".Trim() }) }
    } finally { $ErrorActionPreference = $old }
    [ordered]@{ path = $Path; sha256 = $sha; commit = $commit; source_dirty = $dirty }
}

# Writes <run>\m1b-build.json (purge.rig.m1b-build/1) for each app run of a campaign (review R4b S2): the build
# declared before the campaign, the engine's SHA-256 again after it (a rebuild in between shows) and the SHA-256 of
# the run.json pulled for that run, so a record left beside an older or newer run.json does not bind it.
function Save-M1bBuildRecords {
    param($Records, $Build, [string]$ShaAfter, [string]$Mode, [string]$Base)
    foreach ($rec in @($Records)) {
        if (-not $rec -or -not $rec.id) { continue }    # null runs run no engine
        $dir = Join-Path $script:RunsDir $rec.run
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        $rj = Join-Path $dir 'run.json'
        $rjSha = $null
        if (Test-Path -LiteralPath $rj -PathType Leaf) { $rjSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $rj).Hash.ToLowerInvariant() }
        $doc = [ordered]@{ schema = 'purge.rig.m1b-build/1'; run = $rec.run; mode = $Mode; base = $Base; vm = $script:VmName
            run_json_sha256 = $rjSha; engine = $Build.path; engine_sha256 = $Build.sha256; engine_sha256_after = $ShaAfter
            commit = $Build.commit; source_dirty = $Build.source_dirty; campaign_ok = [bool]$rec.ok; written = (Get-Date).ToString('o') }
        [IO.File]::WriteAllText((Join-Path $dir 'm1b-build.json'), (ConvertTo-Json -InputObject $doc -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
    }
}

# One engine campaign of an M1b mode, with its build records (Save-M1bBuildRecords). Returns the campaign records.
function Invoke-M1bEngineCampaign {
    param([Parameter(Mandatory)][string]$Mode, [Parameter(Mandatory)][string]$Engine, [string]$Base, [hashtable]$Campaign)
    $build = Get-M1bBuildInfo -Path $Engine
    if ($build.source_dirty -ne $false) { Write-RigLog "!! sources differ from HEAD $($build.commit) (or git failed): truth\m1b.sh will not bind these runs" }
    $res = @(Invoke-Campaign @Campaign -Engine $Engine)
    Save-M1bBuildRecords -Records $res -Build $build -ShaAfter (Get-M1bBuildInfo -Path $Engine).sha256 -Mode $Mode -Base $Base
    $res
}

# One M1b scan mode on the VM ($script:VmName): see the section header. Returns the campaign records.
function Invoke-M1bMode {
    param([Parameter(Mandatory)][ValidateSet('m1b-app', 'm1b-apps', 'm1b-traps', 'm1b-freeze')][string]$Mode,
          [string]$App = '', [string]$Base = 'rig-base', [switch]$Traps, [string[]]$Ids = @(), [int]$Nulls = -1,
          [string]$Engine = '', [string]$RunPrefix = '', [int]$NullWaitSec = 60,
          [string]$ExecutionEngine = $env:RIG_VM_EXECUTION_ENGINE, [switch]$No3D = ($env:RIG_VM_NO_3D -eq '1'))
    Assert-RigVm
    $ids = @($Ids | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $common = @{ ExecutionEngine = $ExecutionEngine; No3D = $No3D; NullWaitSec = $NullWaitSec }
    switch ($Mode) {
        'm1b-app' {
            if (-not $App) { throw '-Mode m1b-app needs -App <id>' }
            $opts = @{ msi_tables = $true; traps = [bool]$Traps; trap_a = $App; trap_b = 'node' }
            $pfx = Get-M1bRunPrefix -Base $Base -Traps:$Traps -RunPrefix $RunPrefix
            $c = @{ Ids = @($App); Nulls = [Math]::Max(0, $Nulls); NullOrder = 'spread'; Snapshot = $Base; RunPrefix = $pfx; M1b = $opts } + $common
            return Invoke-M1bEngineCampaign -Mode $Mode -Engine (Get-M1bEngine $Engine) -Base $Base -Campaign $c
        }
        'm1b-apps' {
            if (-not $ids.Count) { $ids = @(Get-M1bGateApps) }
            $pfx = Get-M1bRunPrefix -Base $Base -RunPrefix $RunPrefix
            $c = @{ Ids = $ids; Nulls = $(if ($Nulls -lt 0) { 3 } else { $Nulls }); NullOrder = 'spread'; Snapshot = $Base; RunPrefix = $pfx; M1b = @{ msi_tables = $true } } + $common
            return Invoke-M1bEngineCampaign -Mode $Mode -Engine (Get-M1bEngine $Engine) -Base $Base -Campaign $c
        }
        'm1b-traps' {
            $opts = @{ msi_tables = $true; traps = $true; trap_a = '7zip'; trap_b = 'node' }
            $pfx = Get-M1bRunPrefix -Base $Base -Traps -RunPrefix $RunPrefix
            $c = @{ Ids = @('7zip'); Nulls = [Math]::Max(0, $Nulls); Snapshot = $Base; RunPrefix = $pfx; M1b = $opts } + $common
            return Invoke-M1bEngineCampaign -Mode $Mode -Engine (Get-M1bEngine $Engine) -Base $Base -Campaign $c
        }
        'm1b-freeze' {
            # Frozen truth is Inbound rig-base truth (FROZEN.md): the M0 method, vendor uninstall, no engine.
            if ($script:VmName -cne 'Inbound-Win11-Test' -or $Base -ne 'rig-base') { throw 'm1b-freeze runs on Inbound-Win11-Test, rig-base only (the frozen truth is Inbound rig-base truth)' }
            if (-not $ids.Count) { $ids = @(Get-M1bFreezeApps) }
            # One null run per round (default; -Nulls n for more), m1b-fz<k>-null<n>: truth\m1b.sh freeze builds the
            # ambient set of the freeze from them (with truth\ambient.json), as M0 and M1a built theirs from the null
            # runs of the same campaign (RIG.md section 12.6).
            $nn = $(if ($Nulls -lt 0) { 1 } else { $Nulls })
            $all = @()
            foreach ($k in 1, 2) {
                $all += @(Invoke-Campaign -Ids $ids -Nulls $nn -Snapshot 'rig-base' -RunPrefix (Get-M1bRunPrefix -Freeze $k -RunPrefix $RunPrefix) -M1b @{ msi_tables = $true } @common)
            }
            return $all
        }
    }
}

# G7 (K14), host only and read-only: purge-engine harvest and forced scan of one program with PURGE_TIMING=1, three
# rounds per engine (round 1 cold, rounds 2-3 warm), for the M1b engine (-Engine) and the M2-head engine
# (-BaseEngine, built from 3265797), in the same session. Cold = the M1b engine's MSI table cache
# %ProgramData%\Purge\fp\msitables moved aside to msitables.m1b-budgets-<stamp> before round 1 (Purge's own cache,
# nothing else is touched; the moved folder is left for the operator to delete). Each step's stderr goes to
# vm\runs\<prefix>m1b-budgets\<engine>-<step>-<round>.log; budgets.json lists them (purge.rig.m1b-budgets/2, with
# each run's exit code, the engines' SHA-256 and cold_cache_state) for truth\m1b.sh. Nothing is uninstalled: harvest and scan only read (and write their -o files under the run dir).
function Invoke-M1bBudgets {
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$BaseEngine, [Parameter(Mandatory)][string]$Program,
          [string]$RunPrefix = '', [int]$Rounds = 3, [switch]$KeepCache)
    if ($Program -match '[\s"]') { throw "bad program id '$Program'" }
    $engines = [ordered]@{ m1b = (Resolve-Path -LiteralPath $Engine).ProviderPath; m2 = (Resolve-Path -LiteralPath $BaseEngine).ProviderPath }
    if ($engines.m1b -eq $engines.m2) { throw '-Engine and -BaseEngine are the same file' }
    $run = "${RunPrefix}m1b-budgets"
    $null = Move-RunToOld -Run $run
    $dst = Join-Path $script:RunsDir $run
    New-Item -ItemType Directory -Force $dst | Out-Null
    # Review R4b S6: the engines' SHA-256 (truth\m1b.sh binds the M1b one to the scan runs' engine), the M1b build,
    # and how round 1 was made cold: 'moved' (the cache was moved aside), 'absent' (there was none) or 'kept'
    # (-KeepCache with a cache in place: not cold, K14 fails).
    $doc = [ordered]@{ schema = 'purge.rig.m1b-budgets/2'; program = $Program; host = $env:COMPUTERNAME; start = (Get-Date).ToString('o'); end = $null
        engines = $engines; engine_sha256 = [ordered]@{ m1b = (Get-M1bBuildInfo -Path $engines.m1b).sha256; m2 = (Get-M1bBuildInfo -Path $engines.m2).sha256 }
        build = (Get-M1bBuildInfo -Path $engines.m1b); cold_cache = $null; cold_cache_state = $null; runs = @() }
    $old = $env:PURGE_TIMING
    try {
        $env:PURGE_TIMING = '1'
        $cache = Join-Path $env:ProgramData 'Purge\fp\msitables'
        foreach ($name in $engines.Keys) {
            for ($i = 1; $i -le $Rounds; $i++) {
                $kind = $(if ($i -eq 1) { 'cold' } else { 'warm' })
                if ($kind -eq 'cold' -and $name -eq 'm1b') {
                    if (-not (Test-Path -LiteralPath $cache)) { $doc.cold_cache_state = 'absent' }
                    elseif ($KeepCache) { $doc.cold_cache_state = 'kept'; Write-RigLog '  -KeepCache: round 1 is not cold (K14 fails)' }
                    else {
                        $aside = "$cache.m1b-budgets-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                        Move-Item -LiteralPath $cache -Destination $aside -ErrorAction Stop
                        $doc.cold_cache = $aside; $doc.cold_cache_state = 'moved'
                        Write-RigLog "  moved the MSI table cache aside: $aside"
                    }
                }
                $fp = Join-Path $dst "fp-$name-$i.json"; $plan = Join-Path $dst "plan-$name-$i.json"
                foreach ($step in 'harvest', 'scan') {
                    $log = Join-Path $dst "$name-$step-$i.log"
                    $a = $(if ($step -eq 'harvest') { @('harvest', $Program, '-o', $fp) } else { @('scan', '--fp', $fp, '--mode', 'forced', '-o', $plan) })
                    $t = Get-Date
                    $p = Start-Process -FilePath $engines[$name] -ArgumentList $a -NoNewWindow -Wait -PassThru -RedirectStandardError $log -RedirectStandardOutput (Join-Path $dst "$name-$step-$i.out")
                    $sec = ((Get-Date) - $t).TotalSeconds
                    $doc.runs += [ordered]@{ engine = $name; step = $step; round = $i; kind = $kind; log = (Split-Path -Leaf $log); exit = $p.ExitCode; wall_s = [Math]::Round($sec, 3) }
                    Write-RigLog ("  {0} {1} round {2} ({3}): exit {4}, {5:N1} s" -f $name, $step, $i, $kind, $p.ExitCode, $sec)
                }
            }
        }
    } finally {
        $env:PURGE_TIMING = $old
        $doc.end = (Get-Date).ToString('o')
        [IO.File]::WriteAllText((Join-Path $dst 'budgets.json'), (ConvertTo-Json -InputObject $doc -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    }
    [pscustomobject]$doc
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

$m1bModes = @('m1b-app', 'm1b-apps', 'm1b-traps', 'm1b-freeze', 'm1b-budgets')
if ($MyInvocation.InvocationName -ne '.' -and $m1bModes -ccontains $Mode) {
    if ($Mode -eq 'm1b-budgets') {
        $null = Invoke-M1bBudgets -Engine $(if ($Engine) { $Engine } else { Get-M1bEngine }) -BaseEngine $M1bBaseEngine -Program $M1bProgram -RunPrefix $RunPrefix
        return
    }
    $m1bArgs = @{ Mode = $Mode; App = $M1bApp; Base = $M1bBase; Traps = $M1bTraps; Ids = $Ids; Engine = $Engine; RunPrefix = $RunPrefix
                  NullWaitSec = $NullWaitSec; ExecutionEngine = $ExecutionEngine; No3D = $No3D }
    if ($PSBoundParameters.ContainsKey('Nulls')) { $m1bArgs.Nulls = $Nulls }
    $null = Invoke-M1bMode @m1bArgs
    return
}
if ($MyInvocation.InvocationName -ne '.' -and $Mode -ne 'campaign') {
    $m2Modes = @('m2-traps', 'm2-fidelity', 'm2-crash', 'm2-reboot', 'm2-install', 'm2-elevated')
    if ($m2Modes -cnotcontains $Mode) { throw "-Mode must be campaign, one of $($m1bModes -join ', ') or one of $($m2Modes -join ', ') (got '$Mode')" }
    $m2Snap = $(if ($PSBoundParameters.ContainsKey('Snapshot')) { $Snapshot } else { 'm2-base' })
    if ($Mode -eq 'm2-elevated') { $null = Invoke-M2ElevatedTests -Snapshot $m2Snap -RunPrefix $RunPrefix; return }
    $null = Invoke-M2Mode -Mode $Mode -Snapshot $m2Snap -Engine $Engine -RunPrefix $RunPrefix -HardPowerOff:$M2HardPowerOff -FaultPoints $M2FaultPoints `
                          -Apps $M2Apps -BatchSize $M2BatchSize -Null:$M2Null -AppBands $M2AppBands -ExecutionEngine $ExecutionEngine -No3D:$No3D
} elseif ($MyInvocation.InvocationName -ne '.' -and ($Ids.Count -gt 0 -or $Nulls -gt 0)) {
    Invoke-Campaign -Ids $Ids -Nulls $Nulls -Snapshot $Snapshot -RunPrefix $RunPrefix -Engine $Engine -NullWaitSec $NullWaitSec -NullOrder $NullOrder `
                    -ExtraChecks:$ExtraChecks -NoBaselines:$NoBaselines -ExecutionEngine $ExecutionEngine -No3D:$No3D
}
