<#
  Purge rig, M3-RIG-UAC (docs\M3_DESIGN.json package M3-RIG-UAC; M3_DESIGN.md section 4 T1 and 11.2; vm\RIG.md
  section 13). Host driver, Windows PowerShell 5.1; dot-sources rig.ps1 for the VM helpers and leaves it unchanged.

    $env:VMPWFILE = 'C:\path\to\pw.txt'
    .\vm\rig-m3.ps1                       # -Mode all: build m3-uac-on if it is missing, then the probe
    .\vm\rig-m3.ps1 -Mode snapshot        # only build the snapshot m3-uac-on (-Rebuild deletes an existing one first)
    .\vm\rig-m3.ps1 -Mode probe           # only the probe, from m3-uac-on

  Snapshot m3-uac-on (offline, child of rig-base on Inbound-Win11-Test): restore rig-base (3D off, RIG.md section 9),
  guest phase uac-set (ConsentPromptBehaviorAdmin=5, PromptOnSecureDesktop=1, EnableLUA checked =1: the Windows
  defaults, so a medium process asking for elevation gets the consent prompt on the secure desktop), ACPI shutdown,
  snapshot take. The agent still starts elevated without a prompt: the PurgeRigAgent logon task runs at the highest
  level, which the task scheduler grants without consent.

  Probe (one boot of m3-uac-on): uac-check, build m3probe.exe in the guest, the UIPI matrix (guest phase uipi: a
  high-integrity dummy TaskDialog, drivers at medium and, as the control, at high, each with SendInput key, SendInput
  mouse, PostMessage/SendMessage and UI Automation Invoke/Toggle), one dialog left open for a screenshot, then the
  secure desktop twice: a medium process asks for elevation, the host takes a screenshot of the prompt, answers it with
  `VBoxManage controlvm <vm> keyboardputscancode` (No: Alt+N, then Esc as fallback; Yes: Alt+Y, then Left+Enter as
  fallback), takes a screenshot after, and the guest records the outcome (1223 for No; a high-integrity child for Yes).
  Then the guest tree is zipped and pulled, the VM is powered off and restored to rig-base (left off).

  Evidence: -Evidence (default E:\purge-build\gate-evidence\m3-rig-uac\): rig-m3-<stamp>.log, *.png, jobs\*.log,
  guest\ (the guest's C:\cr\out\m3-rig-uac\), summary.json. Results: vm\truth\m3-rig-uac.md (written by hand).

  Refuses (exit 2) unless VMPWFILE names a readable file, the VM exists, no VirtualBox VM is running (one VM at a time),
  and the per-VM lock vm\runs\.lock-<vm> is free. Only Inbound-Win11-Test is accepted. Exit 0 when every step ran
  (the findings are in summary.json either way), 1 when a step failed.

  M3 security modes (vm\RIG.md section 14; M3_DESIGN.md 4, 11.2, 11.3, gate G3, G4, G5, G10; M3_FINISH_PLAN.md B4-B6).
  Guest side vm\guest\m3-sec.ps1 + the tool vm\guest\m3sec.cs (built in the guest); scorer vm\truth\m3-sec-score.ps1.
  Each pushes a payload of release artifacts (never built here): -Engine and -Broker (default target\release\*.exe of
  this checkout; the rig-exec engine is refused by install.ps1) and -UiPublish (Purge.exe, or a folder holding it;
  default target\release\Purge.exe, the Rust UI of bins\purge-ui; m3-uac's cancelled-bar row needs it), installs them with install\install.ps1 and runs one boot of the snapshot:

    .\vm\rig-m3.ps1 -Mode m3-broker  -Engine <dir>\purge-engine.exe -Broker <dir>\purge-broker.exe            # rig-base
    .\vm\rig-m3.ps1 -Mode m3-consent -Engine ... -Broker ...                                                    # rig-base
    .\vm\rig-m3.ps1 -Mode m3-uac     -Engine ... -Broker ... -UiPublish <dir>\Purge.exe                        # m3-uac-on
    powershell -File vm\truth\m3-sec-score.ps1 -Mode broker|consent|uac -Evidence <dir>

  -Cases limits m3-broker to some case ids of vm\truth\m3-sec-expect.json; -Base overrides the snapshot; -StdUserKeys
  picks what the host types at m3-uac's credential prompt (password, or user-tab-password: "tester", Tab, password).
  Evidence default: E:\purge-build\gate-evidence\<mode>\ (an existing non-empty one is moved aside first, so the
  scorer never reads an older run): rig-m3-<stamp>.log, *.png, jobs\*.log, guest\ (C:\cr\out\m3-sec\), summary.json.

  M3 end to end (vm\RIG.md section 17; M3_DESIGN.md 11.2 row m3-e2e, gate G6, G7, G12; M3_FINISH_PLAN.md B7). Guest
  side vm\guest\m3-e2e.ps1 (phases), m3-e2e-ui.ps1 (the UI Automation driver), m3-e2e-msi.ps1 (the 1603 / 3010 MSI
  fixtures); expectations vm\truth\m3-e2e-expect.json; scorer vm\truth\m3-e2e-score.ps1. One boot of rig-base per app
  (UAC silent in design 11.2; a prompt that comes up is answered by scancode), the real UI installed as C:\Program Files\Purge\Purge.exe, every step driven through the UI:

    .\vm\rig-m3.ps1 -Mode m3-e2e -Engine ... -Broker ... -UiPublish <dir>\Purge.exe [-Apps npp,msi1603] [-UndoApps npp]
                    [-RunName <name>] [-UacOn]
    powershell -File vm\truth\m3-e2e-score.ps1 -Evidence E:\purge-build\gate-evidence\m3-e2e\<run> -Collect

  -UacOn boots m3-uac-on instead and answers each UAC prompt from the host by scancode (Alt+Y, then Left+Enter), with
  screenshots. Evidence: E:\purge-build\gate-evidence\m3-e2e\<run>\ (run = -RunName or e2e-<stamp>): summary.json,
  rig-m3-<stamp>.log, and per app <app>\ (NN-<step>.png, jobs\*.log, host.json, guest\ = C:\cr\out\m3-e2e\<app>\).

  The m3-e2e ambient set (vm\RIG.md section 17.1): the gate pushes its own set, built from null runs of the same flow,
  never the M2 set, and refuses to start without it (-AmbientFile, default the VM's: Inbound truth\m3-e2e-ambient.json,
  Purge-CleanPro truth\m3-e2e-ambient-cleanpro.json):

    .\vm\rig-m3.ps1 -Mode m3-e2e-null -Count 2 -Engine ... -Broker ... -UiPublish ... [-Apps vscode] [-NullWaitSec 10]
    #   -Count rounds per -Apps app (default the gate's executing apps vscode, vscode-user, git, firefox-tb, execapp,
    #   $M3E2eNullDefaultApps: -Count 2 is 10 null runs; the set needs 6 in all), each from a fresh restore: runs <prefix><k>-m3-e2e-<app> (-RunPrefix,
    #   default en), the gate's flow with the plan consent cancelled and -NullWaitSec idle seconds in place of the
    #   execution (the same window, Invoke-M3E2eWindow), then rigtool `ambient --m2 --added --null` over vm\runs\<run>\
    .\vm\rig-m3.ps1 -Mode m3-e2e-ambient -Count 2 [-Apps vscode]    # host only: rebuild the file from those runs
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'snapshot', 'probe', 'm3-broker', 'm3-consent', 'm3-uac', 'm3-e2e', 'm3-e2e-null', 'm3-e2e-ambient')] [string] $Mode = 'all',
    [string] $Evidence = '',
    [switch] $Rebuild,
    [string] $Engine = '',
    [string] $Broker = '',
    [string] $UiPublish = '',
    [string[]] $Cases = @(),
    [string] $Base = '',
    [ValidateSet('password', 'user-tab-password')] [string] $StdUserKeys = 'password',
    [string[]] $Apps = @(),
    [string[]] $UndoApps = @(),
    [string] $RunName = '',
    [switch] $UacOn,
    # m3-e2e-null / m3-e2e-ambient: null rounds per app, the idle seconds in place of the execution, the null runs'
    # name prefix (default en) and the ambient file written; m3-e2e: the ambient set pushed (default the VM's).
    [int] $Count = 6,
    [int] $NullWaitSec = 10,
    [string] $RunPrefix = '',
    [string] $AmbientFile = '',
    # m3-consent: which consent dialog the broker is started with (package BROKER-CONSENT-UI). toolkit: the broker gets
    # "--consent toolkit" and the run is scored with m3-sec-score.ps1 -Mode consent -ConsentUi toolkit.
    [ValidateSet('taskdialog', 'toolkit')] [string] $ConsentUi = 'taskdialog'
)
$ErrorActionPreference = 'Stop'

# rig.ps1 has parameters of its own (Mode, Engine, RunPrefix, NullWaitSec, ...): ours are kept here first.
if (-not $RunName) { $RunName = $(if ($Mode -eq 'm3-e2e-null') { 'null-' } else { 'e2e-' }) + (Get-Date -Format 'yyyyMMdd-HHmmss') }
if ($RunName -notmatch '^[A-Za-z0-9_.-]+$') { throw "bad -RunName '$RunName'" }
if (-not $Evidence) {
    $Evidence = $(if ($Mode -eq 'm3-e2e') { "E:\purge-build\gate-evidence\m3-e2e\$RunName" } elseif ($Mode -eq 'm3-e2e-null') { "E:\purge-build\gate-evidence\m3-e2e-null\$RunName" } elseif ($Mode -like 'm3-*') { "E:\purge-build\gate-evidence\$Mode" } else { 'E:\purge-build\gate-evidence\m3-rig-uac' })
}
$M3 = [ordered]@{ mode = $Mode; evidence = $Evidence; rebuild = [bool]$Rebuild; engine = $Engine; broker = $Broker; ui = $UiPublish
                  cases = @($Cases | Where-Object { $_ }); base = $Base; std_keys = $StdUserKeys
                  apps = @($Apps | ForEach-Object { "$_" -split ',' } | Where-Object { $_ }); undo_apps = @($UndoApps | ForEach-Object { "$_" -split ',' } | Where-Object { $_ })
                  run = $RunName; uac_on = [bool]$UacOn; count = $Count; null_wait = $NullWaitSec; prefix = $RunPrefix; ambient = $AmbientFile }
$M3Vm = 'Inbound-Win11-Test'
$M3Snap = 'm3-uac-on'
. (Join-Path $PSScriptRoot 'rig.ps1') -VmName $M3Vm

# Seconds between consent.exe appearing and the first key: the secure desktop must be the input desktop first.
$M3UacSettleSec = 6

# Set 1 scancodes (make, break) sent with controlvm keyboardputscancode.
$M3Keys = [ordered]@{
    'alt-y'      = @('38', '15', '95', 'b8')
    'alt-n'      = @('38', '31', 'b1', 'b8')
    'esc'        = @('01', '81')
    'left-enter' = @('e0', '4b', 'e0', 'cb', '1c', '9c')
    'enter'      = @('1c', '9c')
    'tab'        = @('0f', '8f')
    'space'      = @('39', 'b9')
}

$script:M3Lock = $null
$script:M3Lines = New-Object System.Collections.ArrayList
$script:M3Fail = $false

function Stop-M3([int]$Code, [string]$Why) {
    Write-RigLog $Why
    if ($script:M3Lock) { $script:M3Lock.Dispose(); $script:M3Lock = $null }
    Remove-PwTemp
    exit $Code
}

function Assert-M3Start {
    if (-not $env:VMPWFILE -or -not (Test-Path -LiteralPath $env:VMPWFILE -PathType Leaf)) { Stop-M3 2 'REFUSED: $env:VMPWFILE does not name a readable file' }
    $vms = (Invoke-VBox @('list', 'vms')).out -join "`n"
    if ($vms -notmatch ('"' + [regex]::Escape($M3Vm) + '"')) { Stop-M3 2 "REFUSED: VM $M3Vm not found" }
    $running = @((Invoke-VBox @('list', 'runningvms')).out | Where-Object { "$_".Trim() })
    if ($running.Count) { Stop-M3 2 "REFUSED: a VM is running ($($running -join '; ')); one VM at a time" }
    New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
    try { $script:M3Lock = [IO.File]::Open((Join-Path $script:RunsDir ".lock-$M3Vm"), 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { Stop-M3 2 "REFUSED: another rig script holds the lock for $M3Vm" }
}

function Test-M3Snapshot { (Invoke-VBox @('snapshot', $M3Vm, 'showvminfo', $M3Snap)).code -eq 0 }

function Push-M3Scripts {
    $null = Invoke-Guest @('mkdir', '--parents', 'C:\cr\guest')
    $files = @('riglib.ps1', 'm3-uipi-probe.ps1') | ForEach-Object { Join-Path $script:RigDir "guest\$_" }
    $r = Invoke-Guest (@('copyto', '--target-directory', 'C:\cr\guest\') + $files)
    if ($r.code -ne 0) { throw "copy guest scripts failed: $($r.out -join ' ')" }
    Write-RigLog '  pushed riglib.ps1, m3-uipi-probe.ps1'
}

# One guest phase as an agent job; keeps the job log in evidence\jobs\ and returns the "M3 ..." result lines.
function Invoke-M3Phase([string]$Phase, [string]$Tag = '', [int]$WaitSec = 15, [int]$TimeoutSec = 600) {
    $text = "& 'C:\cr\guest\m3-uipi-probe.ps1' -Phase '$Phase'"
    if ($Tag) { $text += " -Tag '$Tag'" }
    $text += " -WaitSec $WaitSec"
    $name = "m3-$Phase$(if ($Tag) { "-$Tag" })"
    $jobs = Join-Path $M3.evidence 'jobs'
    New-Item -ItemType Directory -Force $jobs | Out-Null
    $j = Invoke-GuestJob -Text $text -Name $name -TimeoutSec $TimeoutSec -LogCopy (Join-Path $jobs "$name-$(Get-Date -Format 'HHmmss').log")
    $lines = @("$($j.log)" -split "`r?`n" | Where-Object { $_ -match '^M3 ' })
    foreach ($l in $lines) { Write-RigLog "  $l"; [void]$script:M3Lines.Add($l) }
    if (-not $j.done) { Write-RigLog "  !! phase $Phase did not finish within $TimeoutSec s"; $script:M3Fail = $true }
    elseif (-not $lines.Count) { Write-RigLog "  !! phase $Phase wrote no result line; log: $($j.log_file)"; $script:M3Fail = $true }
    $lines
}

function Save-M3Shot([string]$Name) {
    $f = Join-Path $M3.evidence "$Name.png"
    $r = Invoke-VBox @('controlvm', $M3Vm, 'screenshotpng', $f)
    if ($r.code -ne 0 -or -not (Test-Path -LiteralPath $f)) { Write-RigLog "  !! screenshot $Name failed: $($r.out -join ' ')"; return $null }
    Write-RigLog "  screenshot $Name.png ($((Get-Item $f).Length) bytes)"
    $f
}

function Send-M3Keys([string]$Name) {
    $codes = $M3Keys[$Name]
    $r = Invoke-VBox (@('controlvm', $M3Vm, 'keyboardputscancode') + $codes)
    Write-RigLog "  keyboardputscancode $Name ($($codes -join ' ')): exit $($r.code) $($r.out -join ' ')"
    $r.code -eq 0
}

function Get-M3Field([string]$Line, [string]$Key) {
    $m = [regex]::Match($Line, "(?:^|\s)$([regex]::Escape($Key))=(\S*)")
    if ($m.Success) { $m.Groups[1].Value } else { $null }
}

# One answer of the secure desktop: arm (medium runas), screenshot, keys (each fallback only while the prompt is still
# pending), screenshot, outcome. Returns the record kept in summary.json.
function Invoke-M3Uac([string]$Tag, [string[]]$Keys, [string]$Expect) {
    Write-RigLog "secure desktop: $Tag (expect $Expect)"
    $null = Save-M3Shot "uac-$Tag-0-before"
    $arm = @(Invoke-M3Phase 'uac-arm' $Tag) | Select-Object -First 1
    $rec = [ordered]@{ tag = $Tag; expect = $Expect; arm = $arm; prompt_shot = $null; tries = @(); state = 'pending'; answered_by = $null; result = $null }
    if ((Get-M3Field "$arm" 'consent') -in @($null, 'none')) { Write-RigLog '  !! no consent.exe seen; the prompt did not come up'; $script:M3Fail = $true }
    $rec.prompt_shot = Save-M3Shot "uac-$Tag-1-prompt"
    $i = 2
    foreach ($k in $Keys) {
        $sent = Send-M3Keys $k
        Start-Sleep -Seconds 3
        $shot = Save-M3Shot "uac-$Tag-$i-after-$k"; $i++
        $res = @(Invoke-M3Phase 'uac-result' $Tag 20) | Select-Object -First 1
        $state = Get-M3Field "$res" 'state'
        $rec.tries += [ordered]@{ keys = $k; sent = $sent; shot = $shot; result = $res; state = $state }
        $rec.result = $res
        if ($state -and $state -ne 'pending') { $rec.state = $state; $rec.answered_by = $k; break }
    }
    Write-RigLog "  => $Tag state=$($rec.state) answered_by=$($rec.answered_by)"
    $rec
}

function Invoke-M3Snapshot {
    if (Test-M3Snapshot) {
        if (-not $M3.rebuild) { Write-RigLog "snapshot $M3Snap exists; kept (use -Rebuild to build it again)"; return }
        $null = Invoke-VBox @('snapshot', $M3Vm, 'restore', 'rig-base')
        $r = Invoke-VBox @('snapshot', $M3Vm, 'delete', $M3Snap)
        if ($r.code -ne 0) { throw "snapshot delete $M3Snap failed: $($r.out -join ' ')" }
        Write-RigLog "  deleted the old $M3Snap"
    }
    Write-RigLog "build snapshot $M3Snap from rig-base"
    Restore-Base -Snapshot 'rig-base' -No3D
    Push-M3Scripts
    $set = @(Invoke-M3Phase 'uac-set') | Select-Object -First 1
    if ("$set" -notmatch '^M3 UAC-SET OK') { throw "uac-set failed: $set" }
    Write-RigLog '  ACPI shutdown'
    $null = Invoke-VBox @('controlvm', $M3Vm, 'acpipowerbutton')
    $null = Wait-VmState @('poweroff') 300
    $desc = 'M3-RIG-UAC (offline): rig-base + ConsentPromptBehaviorAdmin=5, PromptOnSecureDesktop=1 (EnableLUA=1), 3D off. Built by vm\rig-m3.ps1.'
    $r = Invoke-VBox @('snapshot', $M3Vm, 'take', $M3Snap, '--description', $desc)
    if ($r.code -ne 0) { throw "snapshot take $M3Snap failed: $($r.out -join ' ')" }
    Write-RigLog "snapshot $M3Snap taken"
}

function Invoke-M3Probe {
    if (-not (Test-M3Snapshot)) { throw "snapshot $M3Snap missing (run -Mode snapshot first)" }
    $sum = [ordered]@{ started = (Get-Date).ToString('o'); vm = $M3Vm; snapshot = $M3Snap; uac = @(); lines = $script:M3Lines }
    Write-RigLog "probe from $M3Snap"
    Restore-Base -Snapshot $M3Snap -No3D
    Push-M3Scripts
    $null = Invoke-M3Phase 'uac-check'
    $null = Invoke-M3Phase 'build'
    $null = Invoke-M3Phase 'inputdesk' 'idle'
    $null = Invoke-M3Phase 'uipi' -TimeoutSec 1200
    $null = Invoke-M3Phase 'dialog-show'
    Start-Sleep -Seconds 2
    $null = Save-M3Shot 'uipi-dialog'
    $null = Invoke-M3Phase 'dialog-quit'
    $sum.uac += Invoke-M3Uac 'no' @('alt-n', 'esc') 'cancelled'
    $sum.uac += Invoke-M3Uac 'yes' @('alt-y', 'left-enter') 'approved'
    $null = Invoke-M3Phase 'inputdesk' 'end'
    $null = Invoke-M3Phase 'pack'
    $zip = Join-Path $M3.evidence 'guest.zip'
    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
    $c = Invoke-Guest @('copyfrom', 'C:\cr\out\m3-rig-uac.zip', $zip)
    if ($c.code -eq 0 -and (Test-Path -LiteralPath $zip)) {
        $g = Join-Path $M3.evidence 'guest'
        if (Test-Path -LiteralPath $g) { Remove-Item -LiteralPath $g -Recurse -Force }
        Expand-Archive -LiteralPath $zip -DestinationPath $g
        Remove-Item -LiteralPath $zip -Force
        Write-RigLog "  guest outputs in $g"
    } else { Write-RigLog "  !! copyfrom of the guest zip failed: $($c.out -join ' ')"; $script:M3Fail = $true }
    $sum.ended = (Get-Date).ToString('o')
    $sum.failed_step = $script:M3Fail
    [IO.File]::WriteAllText((Join-Path $M3.evidence 'summary.json'), (ConvertTo-Json $sum -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
    Write-RigLog "summary: $(Join-Path $M3.evidence 'summary.json')"
}

# ------------------------------------------------------------------------------- M3 security modes (section 14)

$script:M3Shots = New-Object System.Collections.ArrayList
$M3SecExpect = Join-Path $script:RigDir 'truth\m3-sec-expect.json'
$M3SecMethods = @('sendinput-key', 'sendinput-mouse', 'postmessage', 'uia')

# Pure: the snapshot a security mode boots (the rig default UAC-silent rig-base, or m3-uac-on).
function Get-M3SecBase([string]$Mode, [string]$Override = '') {
    if ($Override) { return $Override }
    switch ($Mode) { 'm3-uac' { 'm3-uac-on' } 'm3-broker' { 'rig-base' } 'm3-consent' { 'rig-base' } default { throw "not a security mode: $Mode" } }
}

# Pure: the m3-broker case ids, in order, from the expectations file (the one list the guest runs and the scorer checks);
# -Cases keeps only those named (an unknown name throws).
function Get-M3SecCaseIds([string]$ExpectFile = $M3SecExpect, [string[]]$Only = @()) {
    $x = Get-Content -LiteralPath $ExpectFile -Raw | ConvertFrom-Json
    $ids = @($x.broker.cases | ForEach-Object { "$($_.id)" })
    $only = @($Only | Where-Object { $_ })
    foreach ($o in $only) { if ($ids -notcontains $o) { throw "unknown m3-broker case '$o' (known: $($ids -join ', '))" } }
    if ($only.Count) { $ids = @($ids | Where-Object { $only -contains $_ }) }
    $ids
}

# Pure: the job text of one guest phase of m3-sec.ps1.
function New-M3SecPhaseText([string]$Phase, [string]$Tag = '', [string]$Method = '', [int]$WaitSec = 120) {
    foreach ($v in $Phase, $Tag, $Method) { if ("$v" -notmatch '^[A-Za-z0-9_-]*$') { throw "bad phase argument '$v'" } }
    $t = "& 'C:\cr\guest\m3-sec.ps1' -Phase '$Phase'"
    if ($Tag) { $t += " -Tag '$Tag'" }
    if ($Method) { $t += " -Method '$Method'" }
    if ("$ConsentUi" -eq 'toolkit') { $t += " -ConsentUi 'toolkit'" }
    $t + " -WaitSec $WaitSec"
}

# Moves an evidence directory that holds files aside (<dir>-old-<stamp>), so a scorer never reads a mix of two runs.
function Move-M3EvidenceAside([string]$Dir) {
    if (-not (Test-Path -LiteralPath $Dir)) { return $null }
    if (-not @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue).Count) { return $null }
    $to = "$Dir-old-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Move-Item -LiteralPath $Dir -Destination $to
    $to
}

# The UI under test: -UiPublish as Purge.exe itself or a folder holding it, else target\release\Purge.exe (the Rust
# UI, cargo build --release -p purge-ui: one file, no DLLs). Returns the path of Purge.exe, which may not exist.
function Get-M3UiExe {
    $ui = $(if ($M3.ui) { $M3.ui } else { Join-Path $script:RepoRoot 'target\release\Purge.exe' })
    if (Test-Path -LiteralPath $ui -PathType Container) { return (Join-Path $ui 'Purge.exe') }
    $ui
}

# The release artifacts the guest installs (install.ps1 -SkipBuild): purge-engine.exe, purge-broker.exe, kb\ and, when
# there is one, ui\Purge.exe (Get-M3UiExe; the guest passes ui\ as -UiPublishDir). Returns the zip path in the host
# temp directory.
function New-M3SecPayload {
    $engine = $(if ($M3.engine) { $M3.engine } else { Join-Path $script:RepoRoot 'target\release\purge-engine.exe' })
    $broker = $(if ($M3.broker) { $M3.broker } else { Join-Path $script:RepoRoot 'target\release\purge-broker.exe' })
    $ui = Get-M3UiExe
    foreach ($f in @(@($engine, 'purge-engine.exe'), @($broker, 'purge-broker.exe'))) {
        if (-not (Test-Path -LiteralPath $f[0] -PathType Leaf)) { throw "missing $($f[0]) (cargo build --release -p $([IO.Path]::GetFileNameWithoutExtension($f[1])), or pass -Engine / -Broker)" }
        if ((Split-Path -Leaf $f[0]) -ne $f[1]) { throw "the file must be named $($f[1]): $($f[0])" }
    }
    $stage = Join-Path (Get-HostTemp) "m3sec-payload-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    New-Item -ItemType Directory -Force $stage | Out-Null
    Copy-Item -LiteralPath $engine, $broker -Destination $stage
    Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'kb') -Destination (Join-Path $stage 'kb') -Recurse
    $hasUi = Test-Path -LiteralPath $ui -PathType Leaf
    if ($hasUi) {
        New-Item -ItemType Directory -Force (Join-Path $stage 'ui') | Out-Null
        Copy-Item -LiteralPath $ui -Destination (Join-Path $stage 'ui\Purge.exe')
    }
    else { Write-RigLog "  no UI at ${ui}: m3-uac's cancelled-bar row will have no evidence (the scorer fails it)" }
    $zip = "$stage.zip"
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
    Remove-Item -LiteralPath $stage -Recurse -Force
    Write-RigLog "  payload: $engine, $broker, kb\$(if ($hasUi) { ", ui\ from $ui" }) ($([int]((Get-Item $zip).Length / 1MB)) MB)"
    $zip
}

function Push-M3SecFiles {
    foreach ($d in 'C:\cr\guest', 'C:\cr\m3sec', 'C:\cr\out') { $null = Invoke-Guest @('mkdir', '--parents', $d) }
    $files = @('riglib.ps1', 'm3-sec.ps1', 'm3sec.cs') | ForEach-Object { Join-Path $script:RigDir "guest\$_" }
    $r = Invoke-Guest (@('copyto', '--target-directory', 'C:\cr\guest\') + $files)
    if ($r.code -ne 0) { throw "copy guest scripts failed: $($r.out -join ' ')" }
    Push-M2Install
    $zip = New-M3SecPayload
    try {
        $null = Invoke-GuestCmd 'del /f /q C:\cr\m3sec\payload.zip'
        $r = Invoke-Guest @('copyto', $zip, 'C:\cr\m3sec\payload.zip')
        if ($r.code -ne 0) { throw "copy payload failed: $($r.out -join ' ')" }
    } finally { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
    Write-RigLog '  pushed riglib.ps1, m3-sec.ps1, m3sec.cs, install.ps1, payload.zip'
}

# One guest phase of m3-sec.ps1; keeps the job log and returns the "M3S ..." lines (also kept for summary.json).
function Invoke-M3SecPhase([string]$Phase, [string]$Tag = '', [string]$Method = '', [int]$WaitSec = 120, [int]$TimeoutSec = 0) {
    if (-not $TimeoutSec) { $TimeoutSec = $WaitSec + 300 }
    $name = "sec-$Phase$(if ($Tag) { "-$Tag" })$(if ($Method) { "-$Method" })"
    $jobs = Join-Path $M3.evidence 'jobs'
    New-Item -ItemType Directory -Force $jobs | Out-Null
    $j = Invoke-GuestJob -Text (New-M3SecPhaseText $Phase $Tag $Method $WaitSec) -Name $name -TimeoutSec $TimeoutSec -LogCopy (Join-Path $jobs "$name-$(Get-Date -Format 'HHmmss').log")
    $lines = @("$($j.log)" -split "`r?`n" | Where-Object { $_ -match '^M3S ' })
    foreach ($l in $lines) { Write-RigLog "  $l"; [void]$script:M3Lines.Add($l) }
    if (-not $j.done) { Write-RigLog "  !! phase $name did not finish within $TimeoutSec s"; $script:M3Fail = $true }
    elseif (-not $lines.Count) { Write-RigLog "  !! phase $name wrote no result line; log: $($j.log_file)"; $script:M3Fail = $true }
    $lines
}

function Save-M3SecShot([string]$Name) {
    $f = Save-M3Shot $Name
    [void]$script:M3Shots.Add([ordered]@{ name = $Name; file = $(if ($f) { Split-Path -Leaf $f }); bytes = $(if ($f) { (Get-Item $f).Length } else { 0 }); t = (Get-Date).ToString('o') })
}

function Assert-M3SecUac([string]$Line, [int]$Admin) {
    $m = [regex]::Match("$Line", '"ConsentPromptBehaviorAdmin":(\d+)')
    if (-not $m.Success -or [int]$m.Groups[1].Value -ne $Admin) { throw "UAC is not as this mode needs (ConsentPromptBehaviorAdmin=$Admin): $Line" }
}

# Types the guest password (VMPWFILE, never on a command line or in a log) at the credential prompt, then Enter.
function Send-M3Password {
    $pf = Get-PwFile
    $tmp = Join-Path (Get-HostTemp) ('m3pw-' + [guid]::NewGuid().ToString('N') + '.txt')
    try {
        [IO.File]::WriteAllText($tmp, ([IO.File]::ReadAllText($pf)).TrimEnd("`r", "`n"))
        $r = Invoke-VBox @('controlvm', $M3Vm, 'keyboardputfile', $tmp)
        Write-RigLog "  keyboardputfile (password): exit $($r.code)"
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    $null = Send-M3Keys 'enter'
}

function Start-M3Sec([string]$Fixture) {
    $base = Get-M3SecBase $M3.mode $M3.base
    Write-RigLog "$($M3.mode) from $base"
    Restore-Base -Snapshot $base -No3D
    Push-M3SecFiles
    $u = @(Invoke-M3SecPhase 'uac-check' 'start') | Select-Object -First 1
    if ($M3.mode -eq 'm3-uac') { Assert-M3SecUac $u 5 }
    else {
        # rig-base is at the Windows UAC defaults (RIG.md 13; coordinator ruling 2026-11-22): m3-broker and m3-consent
        # make UAC silent themselves (ConsentPromptBehaviorAdmin=0, design 11.2), record before/after (uac-silent.json,
        # summary uac_silent) and check the result; the scorer checks the recorded silent state.
        $s = @(Invoke-M3SecPhase 'uac-silent') | Select-Object -First 1
        if ("$s" -notmatch '^M3S UAC-SILENT OK') { throw "could not make UAC silent: $s" }
        $u = @(Invoke-M3SecPhase 'uac-check' 'silent') | Select-Object -First 1
        Assert-M3SecUac $u 0
    }
    $b = @(Invoke-M3SecPhase 'build') | Select-Object -First 1
    if ("$b" -notmatch '^M3S BUILD OK') { throw "the guest build of m3sec.exe failed: $b" }
    $i = @(Invoke-M3SecPhase 'install' $Fixture -WaitSec 600) | Select-Object -First 1
    if ("$i" -notmatch '^M3S INSTALL OK') { throw "install failed: $i" }
    $base
}

function Complete-M3Sec([string]$Base, [hashtable]$Extra = @{}) {
    $null = Invoke-M3SecPhase 'pack' -WaitSec 300
    $zip = Join-Path $M3.evidence 'guest.zip'
    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
    $c = Invoke-Guest @('copyfrom', 'C:\cr\out\m3-sec.zip', $zip)
    if ($c.code -eq 0 -and (Test-Path -LiteralPath $zip)) {
        $g = Join-Path $M3.evidence 'guest'
        if (Test-Path -LiteralPath $g) { Remove-Item -LiteralPath $g -Recurse -Force }
        Expand-Archive -LiteralPath $zip -DestinationPath $g
        Remove-Item -LiteralPath $zip -Force
        Write-RigLog "  guest outputs in $g"
    } else { Write-RigLog "  !! copyfrom of the guest zip failed: $($c.out -join ' ')"; $script:M3Fail = $true }
    $sum = [ordered]@{ schema = 'purge.rig.m3sec.summary/1'; mode = $M3.mode; consent_ui = $ConsentUi; vm = $M3Vm; snapshot = $Base; started = $script:M3Started
                       ended = (Get-Date).ToString('o'); failed_step = $script:M3Fail; shots = $script:M3Shots; lines = $script:M3Lines }
    foreach ($k in $Extra.Keys) { $sum[$k] = $Extra[$k] }
    [IO.File]::WriteAllText((Join-Path $M3.evidence 'summary.json'), (ConvertTo-Json $sum -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
    Write-RigLog "summary: $(Join-Path $M3.evidence 'summary.json')"
}

function Invoke-M3SecBroker {
    $base = Start-M3Sec ''
    foreach ($id in Get-M3SecCaseIds -Only $M3.cases) { $null = Invoke-M3SecPhase 'broker-case' $id -WaitSec 180 -TimeoutSec 900 }
    Save-M3SecShot 'broker-end'
    $null = Invoke-M3SecPhase 'broker-summary'
    Complete-M3Sec $base
}

# One kind of consent dialog (uninstall.run or plan.execute) starting at instance $K: the medium attacks by every method
# on it, then the high control (Cancel) by every method on the next instances, then the approval. Returns the next k.
function Invoke-M3SecDialogMatrix([int]$K, [string]$Kind, [int]$FirstWaitSec) {
    $null = Invoke-M3SecPhase 'consent-next' "$K" -WaitSec $FirstWaitSec
    Save-M3SecShot ('c{0:D2}-{1}-shown' -f $K, $Kind)
    foreach ($m in $M3SecMethods) {
        $null = Invoke-M3SecPhase 'consent-attack' "$K" $m -WaitSec 300
        Save-M3SecShot ('c{0:D2}-{1}-attack-{2}' -f $K, $Kind, $m)
    }
    foreach ($m in $M3SecMethods) {
        if ($m -ne $M3SecMethods[0]) {
            $null = Invoke-M3SecPhase 'consent-next' "$K" -WaitSec 300
            Save-M3SecShot ('c{0:D2}-{1}-shown' -f $K, $Kind)
        }
        $null = Invoke-M3SecPhase 'consent-control' "$K" $m -WaitSec 120
        Save-M3SecShot ('c{0:D2}-{1}-control-{2}' -f $K, $Kind, $m)
        $K++
    }
    $null = Invoke-M3SecPhase 'consent-next' "$K" -WaitSec 300
    Save-M3SecShot ('c{0:D2}-{1}-shown' -f $K, $Kind)
    $null = Invoke-M3SecPhase 'consent-approve' "$K" -WaitSec 1200
    Save-M3SecShot ('c{0:D2}-{1}-approved' -f $K, $Kind)
    $K + 1
}

function Invoke-M3SecConsent {
    $base = Start-M3Sec 'lookalike3'
    $null = Invoke-M3SecPhase 'consent-start' -WaitSec 120
    Save-M3SecShot 'c00-client'
    $k = Invoke-M3SecDialogMatrix 1 'uninstall' 900
    $null = Invoke-M3SecDialogMatrix $k 'plan' 1800
    $null = Invoke-M3SecPhase 'client-end' 'consent' -WaitSec 300
    Complete-M3Sec $base
}

# A secure-desktop answer from the host: screenshot, keys, screenshot; the next key only when $Pending says the prompt
# is still up. Returns the keys sent.
function Send-M3SecAnswer([string]$Tag, [string[]]$Keys, [scriptblock]$Pending) {
    # Wait for the secure desktop before any key (see Invoke-M3E2eUac).
    $d = (Get-Date).AddSeconds(10)
    while (-not (& $Pending) -and (Get-Date) -lt $d) { Start-Sleep -Seconds 1 }
    Start-Sleep -Seconds $M3UacSettleSec
    Save-M3SecShot "$Tag-1-prompt"
    $sent = @()
    $i = 2
    foreach ($k in $Keys) {
        $null = Send-M3Keys $k; $sent += $k
        Start-Sleep -Seconds 4
        Save-M3SecShot "$Tag-$i-after-$k"; $i++
        if (-not (& $Pending)) { break }
    }
    $sent
}

function Test-M3ConsentUp {
    $r = Invoke-GuestCmd 'tasklist /fi "imagename eq consent.exe" /nh'
    (($r.out -join ' ') -match 'consent\.exe')
}

function Invoke-M3SecUac {
    $base = Start-M3Sec 'lookalike45'
    $keys = [ordered]@{}
    # 1. The real UI: No at the prompt -> the cancelled bar, nothing runs.
    $ui = @(Invoke-M3SecPhase 'ui-start' -WaitSec 180) | Select-Object -First 1
    if ("$ui" -match 'present=True') {
        $keys.ui = Send-M3SecAnswer 'u1-ui' @('alt-n', 'esc') { Test-M3ConsentUp }
        $null = Invoke-M3SecPhase 'ui-result' -WaitSec 120
        Save-M3SecShot 'u1-ui-9-bar'
    }
    # 2. The rig client: No -> 1223, no broker.
    $null = Invoke-M3SecPhase 'flow-start' 'no' -WaitSec 120
    $keys.no = Send-M3SecAnswer 'u2-no' @('alt-n', 'esc') { Test-M3ConsentUp }
    $null = Invoke-M3SecPhase 'flow-launch' 'no' -WaitSec 60
    # 3. The rig client: Yes -> the full flow (uninstall dialog with the arming test, the paged plan dialog).
    $null = Invoke-M3SecPhase 'flow-start' 'yes' -WaitSec 120
    $keys.yes = Send-M3SecAnswer 'u3-yes' @('alt-y', 'left-enter') { Test-M3ConsentUp }
    $null = Invoke-M3SecPhase 'flow-launch' 'yes' -WaitSec 60
    $null = Invoke-M3SecPhase 'arm-next' '1' -WaitSec 900
    Save-M3SecShot 'u3-yes-c01-uninstall-dialog'
    $null = Invoke-M3SecPhase 'consent-approve' '1' -WaitSec 1200
    Save-M3SecShot 'u3-yes-c01-approved'
    $null = Invoke-M3SecPhase 'consent-next' '2' -WaitSec 1800
    Save-M3SecShot 'u3-yes-c02-page01'
    for ($p = 2; $p -le 12; $p++) {
        $l = @(Invoke-M3SecPhase 'page-next' '2' -WaitSec 60) | Select-Object -First 1
        Save-M3SecShot ('u3-yes-c02-page{0:D2}' -f $p)
        if ("$l" -match 'last=True' -or -not $l) { break }
    }
    $null = Invoke-M3SecPhase 'arm-current' '2' -WaitSec 60
    Save-M3SecShot 'u3-yes-c02-armed'
    $null = Invoke-M3SecPhase 'consent-approve' '2' -WaitSec 1200
    Save-M3SecShot 'u3-yes-c02-approved'
    $null = Invoke-M3SecPhase 'client-end' 'yes' -WaitSec 300
    # 4. A standard user: administrator credentials typed at the prompt; the broker must not serve that client.
    $null = Invoke-M3SecPhase 'std-start' -WaitSec 120
    Save-M3SecShot 'u4-std-1-prompt'
    if ($M3.std_keys -eq 'user-tab-password') {
        $r = Invoke-VBox @('controlvm', $M3Vm, 'keyboardputstring', $script:GuestUser)
        Write-RigLog "  keyboardputstring (user name): exit $($r.code)"
        $null = Send-M3Keys 'tab'
    }
    Send-M3Password
    Start-Sleep -Seconds 5
    Save-M3SecShot 'u4-std-2-after'
    $keys.std = @($M3.std_keys, 'enter')
    $null = Invoke-M3SecPhase 'std-result' -WaitSec 180
    $null = Invoke-M3SecPhase 'uac-summary'
    Complete-M3Sec $base @{ keys = $keys }
}

# ----------------------------------------------------------------------------------- m3-e2e (RIG.md section 17)

$M3E2eExpect = Join-Path $script:RigDir 'truth\m3-e2e-expect.json'
$script:E2eDir = $null
$script:E2eShots = $null
$script:E2eLines = $null
$script:E2eNull = $false          # the app being driven is a null run (every guest phase gets -NullRun)

# Pure: the apps of the expectations file, in its order; -Only keeps those named (an unknown name throws).
function Get-M3E2eApps([string]$ExpectFile = $M3E2eExpect, [string[]]$Only = @()) {
    $x = Get-Content -LiteralPath $ExpectFile -Raw | ConvertFrom-Json
    $apps = @($x.apps)
    $ids = @($apps | ForEach-Object { "$($_.id)" })
    $only = @($Only | Where-Object { $_ })
    foreach ($o in $only) { if ($ids -notcontains $o) { throw "unknown m3-e2e app '$o' (known: $($ids -join ', '))" } }
    if ($only.Count) { $apps = @($apps | Where-Object { $only -contains "$($_.id)" }) }
    $apps
}

# Pure: the apps whose result is undone through the UI (-UndoApps, else the expectations' undo_apps); only apps that
# execute (kind app or fixture) can be undone.
function Get-M3E2eUndoApps([string]$ExpectFile = $M3E2eExpect, [string[]]$Override = @()) {
    $x = Get-Content -LiteralPath $ExpectFile -Raw | ConvertFrom-Json
    $list = @($(if (@($Override | Where-Object { $_ }).Count) { $Override } else { @($x.undo_apps) }) | Where-Object { $_ } | ForEach-Object { "$_" })
    foreach ($u in $list) {
        $a = @($x.apps | Where-Object { "$($_.id)" -eq $u })
        if (-not $a.Count) { throw "undo app '$u' is not an m3-e2e app" }
        if ("$($a[0].kind)" -notin 'app', 'fixture') { throw "undo app '$u' executes nothing (kind $($a[0].kind))" }
    }
    $list
}

# Pure: the job text of one guest phase of m3-e2e.ps1. -NullRun: a phase of a null run (every phase of it carries the
# switch; the guest refuses a phase whose null flag differs from its prepare's). -AmbientSha: the SHA-256 of the ambient
# set the host pushed (setup records it beside the guest copy's own hash).
function New-M3E2ePhaseText([string]$Phase, [string]$App, [string]$Step = '', [int]$WaitSec = 0, [switch]$NullRun, [string]$AmbientSha = '') {
    foreach ($v in $Phase, $App, $Step) { if ("$v" -notmatch '^[A-Za-z0-9_-]*$') { throw "bad phase argument '$v'" } }
    if (-not $Phase -or -not $App) { throw 'a phase and an app are needed' }
    $t = "& 'C:\cr\guest\m3-e2e.ps1' -Phase '$Phase' -App '$App'"
    if ($Step) { $t += " -Step '$Step'" }
    if ($WaitSec) { $t += " -WaitSec $WaitSec" }
    if ($AmbientSha) {
        if ($AmbientSha -cnotmatch '\A[0-9a-f]{64}\z') { throw "bad ambient SHA-256 '$AmbientSha'" }
        if ($NullRun) { throw 'a null run pushes no ambient set' }
        $t += " -AmbientSha '$AmbientSha'"
    }
    if ($NullRun) { $t += ' -NullRun' }
    $t
}

# Pure: the screenshot names an app's flow takes, in order (the scorer requires the same list, expectations
# required_shots). Broker route: the uninstall consent; success flows: move, plan consent, result; undo app: undo.
# -Empty: nothing was preselected (Invoke-M3E2eWindow's skip-empty path): the disabled Move only, no consent, result
# or undo.
function Get-M3E2eShotNames($AppDef, [bool]$Undo, [bool]$Empty = $false) {
    $n = @('01-programs-row', '02-uninstall-clicked', '03-confirm')
    if ("$($AppDef.route)" -eq 'broker') { $n += '04-consent-run', '05-run-approved' }
    $n += '06-scan-done'
    if ("$($AppDef.kind)" -like 'fail-*') { return @($n + '07-failure') }
    if ($Empty) { return @($n + '07-move-waiting') }
    $n += '07-move-waiting', '08-consent-plan', '09-result'
    if ($Undo) { $n += '10-undo-waiting', '11-consent-undo', '12-undone' }
    $n
}

function Invoke-M3E2ePhase([string]$Phase, [string]$App, [string]$Step = '', [int]$WaitSec = 0, [int]$TimeoutSec = 900, [string]$AmbientSha = '') {
    $name = "e2e-$Phase$(if ($Step) { "-$Step" })"
    $jobs = Join-Path $script:E2eDir 'jobs'
    New-Item -ItemType Directory -Force $jobs | Out-Null
    $text = New-M3E2ePhaseText $Phase $App $Step $WaitSec -NullRun:([bool]$script:E2eNull) -AmbientSha $AmbientSha
    $j = Invoke-GuestJob -Text $text -Name "$App-$name" -TimeoutSec $TimeoutSec -LogCopy (Join-Path $jobs "$name-$(Get-Date -Format 'HHmmss').log")
    $lines = @("$($j.log)" -split "`r?`n" | Where-Object { $_ -match '^M3E ' })
    foreach ($l in $lines) { Write-RigLog "  $l"; [void]$script:E2eLines.Add($l) }
    if (-not $j.done) { Write-RigLog "  !! phase $name did not finish within $TimeoutSec s"; $script:M3Fail = $true }
    elseif (-not $lines.Count) { Write-RigLog "  !! phase $name wrote no result line; log: $($j.log_file)"; $script:M3Fail = $true }
    "$(@($lines) | Select-Object -First 1)"
}

# Pure: whether the result line of a guest phase reports success (vm\RIG.md section 17, "Fail fast"): consent-wait
# found=True, ui-wait-result state=result (a null run: declined), ui-wait-undone state=undone, every other phase
# ok=True. No line, a line of another tool, or M3E REFUSED: not a success.
function Test-M3E2eStepLine([string]$Phase, [string]$Line, [bool]$IsNull = $false) {
    if (-not $Line -or $Line -cnotmatch '^M3E ' -or $Line -cmatch '^M3E REFUSED') { return $false }
    switch ($Phase) {
        'consent-wait' { return (Get-M3Field $Line 'found') -ceq 'True' }
        'ui-wait-result' { return (Get-M3Field $Line 'state') -ceq $(if ($IsNull) { 'declined' } else { 'result' }) }
        'ui-wait-undone' { return (Get-M3Field $Line 'state') -ceq 'undone' }
        default { return (Get-M3Field $Line 'ok') -ceq 'True' }
    }
}

# One guest phase whose failure ends the app's flow (fail fast): the phase, its screenshot (-Shot, taken either way:
# it shows the failed state), then a throw when the line is not a success. Invoke-M3E2eApp's catch records the error
# and the step (host.json failed_step), and its finally still runs finish and pulls the evidence; no later step that
# depends on this one runs, so a failed step costs no more timeouts.
function Invoke-M3E2eStep([string]$Phase, [string]$App, [string]$Step = '', [int]$WaitSec = 0, [int]$TimeoutSec = 900, [string]$AmbientSha = '', [string]$Shot = '') {
    $l = Invoke-M3E2ePhase $Phase $App $Step $WaitSec $TimeoutSec $AmbientSha
    if ($Shot) { Save-M3E2eShot $Shot }
    if (-not (Test-M3E2eStepLine $Phase $l ([bool]$script:E2eNull))) {
        $script:E2eFailedStep = "$Phase$(if ($Step) { "-$Step" })"
        throw "step $($script:E2eFailedStep) failed: $(if ($l) { $l } else { 'no result line' })"
    }
    $l
}

function Save-M3E2eShot([string]$Name) {
    $f = Join-Path $script:E2eDir "$Name.png"
    # VBoxManage screenshotpng fails with E_FAIL (TakeScreenShotToArray) while the guest display is off; the setup
    # phase turns the display timeout off. Plain retries only: a key here could land while a UAC prompt starts.
    for ($try = 1; $try -le 3; $try++) {
        $r = Invoke-VBox @('controlvm', $M3Vm, 'screenshotpng', $f)
        $ok = ($r.code -eq 0 -and (Test-Path -LiteralPath $f))
        if ($ok) { break }
        Start-Sleep -Seconds 2
    }
    if ($ok) { Write-RigLog "  screenshot $Name.png ($((Get-Item $f).Length) bytes)" } else { Write-RigLog "  !! screenshot $Name failed: $($r.out -join ' ')" }
    [void]$script:E2eShots.Add([ordered]@{ name = $Name; file = $(if ($ok) { "$Name.png" }); bytes = $(if ($ok) { (Get-Item $f).Length } else { 0 }); t = (Get-Date).ToString('o') })
}

# The UAC prompt on the secure desktop, when one is up: screenshot, Alt+Y (Left+Enter only while it is still up),
# screenshot. Returns the keys sent (empty when no prompt was up).
function Invoke-M3E2eUac([string]$Tag, [string]$App = '', [string]$Step = '') {
    $sent = @()
    $d = (Get-Date).AddSeconds(10)
    while (-not (Test-M3ConsentUp) -and (Get-Date) -lt $d) { Start-Sleep -Seconds 1 }
    if (-not (Test-M3ConsentUp)) { return $sent }
    # consent.exe exists before the secure desktop is the input desktop. Keys sent in that window reach the normal
    # desktop, and Windows then shows the prompt only as a flashing taskbar button (e2e-20261123-053530, 02u-uac-3).
    # The spike (vm\truth\m3-rig-uac.md) answered only after the secure desktop was up.
    Start-Sleep -Seconds $M3UacSettleSec
    # Secure desktop up? If the prompt only sits on the taskbar, the guest presses its taskbar button (uac-front).
    if ($App) { $null = Invoke-M3E2ePhase 'uac-front' $App $Step -TimeoutSec 120 }
    Save-M3E2eShot "$Tag-1-prompt"
    $i = 2
    foreach ($k in 'alt-y', 'left-enter') {
        $null = Send-M3Keys $k; $sent += $k
        Start-Sleep -Seconds 4
        Save-M3E2eShot "$Tag-$i-after-$k"; $i++
        if (-not (Test-M3ConsentUp)) { break }
    }
    $sent
}

function Push-M3E2eFiles($AppDef, [bool]$IsNull = $false) {
    $engine = $(if ($M3.engine) { $M3.engine } else { Join-Path $script:RepoRoot 'target\release\purge-engine.exe' })
    $inst = @()
    if ("$($AppDef.kind)" -eq 'app') { $inst = @(Get-CachedRunFiles -Id "$($AppDef.id)") }
    Push-Tools -Engine $engine -Installers $inst
    Push-M2Install
    # The m3-e2e ambient set (Get-M2AmbientFile below returns it), never the M2 set; a null run pushes none.
    if ($IsNull) { $null = Push-M2Ambient -None }
    else {
        if (-not $script:M3PushAmbient -or -not (Test-Path -LiteralPath $script:M3PushAmbient -PathType Leaf)) { throw 'no m3-e2e ambient set to push (RIG.md section 17.1)' }
        if (-not (Push-M2Ambient)) { throw "the ambient set $script:M3PushAmbient was not pushed" }
    }
    foreach ($d in 'C:\cr\m3e2e', 'C:\cr\out') { $null = Invoke-Guest @('mkdir', '--parents', $d) }
    $extra = @((Join-Path $script:RigDir 'guest\m3sec.cs'), (Join-Path $script:RigDir 'truth\m1b-exec-cases.json'))
    $r = Invoke-Guest (@('copyto', '--target-directory', 'C:\cr\guest\') + $extra)
    if ($r.code -ne 0) { throw "copy m3sec.cs / m1b-exec-cases.json failed: $($r.out -join ' ')" }
    $zip = New-M3SecPayload
    try {
        $null = Invoke-GuestCmd 'del /f /q C:\cr\m3e2e\payload.zip'
        $r = Invoke-Guest @('copyto', $zip, 'C:\cr\m3e2e\payload.zip')
        if ($r.code -ne 0) { throw "copy payload failed: $($r.out -join ' ')" }
    } finally { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
    Write-RigLog '  pushed m3sec.cs, m1b-exec-cases.json, payload.zip'
}

function Get-M3E2eField([string]$Line, [string]$Key) { Get-M3Field $Line $Key }

# The exec window of a gate run and of its null run, one function for both (RIG.md section 17.1; as M1b's guest
# Invoke-ExWindow): every step between snap A / deep A (the end of capture-post) and snap B / deep B (the start of
# capture-exec), in the same order and with the same screenshots. The gate approves the plan consent, so the engine
# executes; a null run cancels it (consent-cancel: the dialog's Cancel by the same m3sec press, then -NullWaitSec idle
# seconds, the gate's execution time, as its null-wait step), so nothing is executed. Both then read the result page
# and take snap B.
#
# Nothing preselected (the rig CLI plan ticks nothing; the guest's ui-move then checks that MoveButton is there and not
# enabled and answers state=skip-empty): Move is never pressed, so there is no plan consent and no result page; the
# window goes from ui-move straight to capture-exec, which checks that no session exists and runs execdiff against the
# rig's empty journal (collateral 0 still holds). A null run never takes this path (the guest refuses it: no consent to
# cancel). Every step fails fast (Invoke-M3E2eStep).
function Invoke-M3E2eWindow([string]$Id, $Rec, [bool]$IsNull) {
    $l = Invoke-M3E2eStep 'ui-move' $Id -TimeoutSec 1200 -Shot '07-move-waiting'
    if ((Get-M3E2eField $l 'state') -ceq 'skip-empty') {
        $Rec.empty_plan = $true
        Write-RigLog "  $Id`: nothing preselected (CLI and UI); no Move, no plan consent, no result wait"
        $null = Invoke-M3E2eStep 'capture-exec' $Id -TimeoutSec 5400
        return
    }
    $Rec.uac_keys.plan = @(Invoke-M3E2eUac '07u-uac' $Id 'plan')
    $null = Invoke-M3E2eStep 'consent-wait' $Id 'plan' -WaitSec 300 -TimeoutSec 900 -Shot '08-consent-plan'
    if ($IsNull) { $null = Invoke-M3E2eStep 'consent-cancel' $Id 'plan' -WaitSec (Assert-M3E2eNullWait $M3.null_wait) -TimeoutSec 900 }
    else { $null = Invoke-M3E2eStep 'consent-approve' $Id 'plan' -TimeoutSec 600 }
    $null = Invoke-M3E2eStep 'ui-wait-result' $Id -WaitSec 1800 -TimeoutSec 2400 -Shot '09-result'
    $null = Invoke-M3E2eStep 'capture-exec' $Id -TimeoutSec 5400
}

# One app: one boot of the base snapshot, the whole flow through the UI, the evidence pulled to $Dir (default
# <evidence>\<app>\). -NullRun <name>: a null run of that name (no ambient set, the plan consent cancelled; never undo).
# -Ambient: the host record {file, sha256} of the ambient set a gate run pushes (host.json ambient; setup gets its hash).
function Invoke-M3E2eApp($AppDef, [bool]$Undo, [string]$Base, [string]$Dir = '', [string]$NullRun = '', $Ambient = $null, [string]$SkipReason = '') {
    $id = "$($AppDef.id)"
    $isNull = [bool]$NullRun
    if ($isNull -and $Undo) { throw 'a null run is never undone' }
    if ($isNull -and $Ambient) { throw 'a null run pushes no ambient set' }
    if (-not $isNull -and -not $Ambient) { throw "gate app $id needs the m3-e2e ambient set" }
    $script:E2eNull = $isNull
    $script:E2eDir = $(if ($Dir) { $Dir } else { Join-Path $M3.evidence $id })
    New-Item -ItemType Directory -Force $script:E2eDir | Out-Null
    $script:E2eShots = New-Object System.Collections.ArrayList
    $script:E2eLines = New-Object System.Collections.ArrayList
    $rec = [ordered]@{ app = $id; kind = "$($AppDef.kind)"; undo = $Undo; base = $Base; started = (Get-Date).ToString('o'); ended = $null; error = $null
                       null_run = $(if ($isNull) { $NullRun }); ambient = $Ambient
                       uac_keys = [ordered]@{}; shots = $script:E2eShots; lines = $script:E2eLines; pulled = $false; failed_step = $null; empty_plan = $false }
    Write-RigLog "m3-e2e app $id ($($AppDef.kind), route $($AppDef.route)$(if ($Undo) { ', undo' })$(if ($isNull) { ", null run $NullRun, idle $($M3.null_wait) s" })) from $Base"
    $booted = $false
    $script:E2eFailedStep = $null
    if ($SkipReason) {
        # Not driven (the MSI smoke check failed for this fixture, Invoke-M3E2eMsiSmoke): the reason is the record.
        $rec.error = $SkipReason; $rec.failed_step = 'msi-smoke'; $rec.ended = (Get-Date).ToString('o')
        Write-RigLog "  !! $id not driven: $SkipReason"
        $script:M3Fail = $true
        [IO.File]::WriteAllText((Join-Path $script:E2eDir 'host.json'), (ConvertTo-Json $rec -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
        $script:E2eNull = $false
        return $rec
    }
    try {
        Restore-Base -Snapshot $Base -No3D -DiagDir $script:E2eDir
        $booted = $true
        Push-M3E2eFiles $AppDef $isNull
        $l = Invoke-M3E2ePhase 'setup' $id -TimeoutSec 1200 -AmbientSha $(if ($Ambient) { "$($Ambient.sha256)" } else { '' })
        if ($l -notmatch '^M3E SETUP OK') { $script:E2eFailedStep = 'setup'; throw "setup failed: $l" }
        $l = Invoke-M3E2ePhase 'prepare' $id -TimeoutSec 5400
        if ((Get-M3E2eField $l 'ok') -ne 'True') { $script:E2eFailedStep = 'prepare'; throw "prepare failed: $l" }
        # From here every step fails fast (Invoke-M3E2eStep): a later step that needs it never runs.
        $null = Invoke-M3E2eStep 'ui-start' $id -TimeoutSec 900 -Shot '01-programs-row'
        $l = Invoke-M3E2eStep 'ui-uninstall' $id -TimeoutSec 900 -Shot '02-uninstall-clicked'
        if ((Get-M3E2eField $l 'state') -eq 'continue-focused') {
            # A real key on the focused Continue button, so Windows puts the UAC prompt in front (see m3-e2e.ps1).
            $null = Send-M3Keys 'space'
            $rec.uac_keys.continue = 'space'
        }
        $rec.uac_keys.run = @(Invoke-M3E2eUac '02u-uac' $id 'run')
        $null = Invoke-M3E2eStep 'ui-await-confirm' $id -WaitSec 300 -TimeoutSec 900 -Shot '03-confirm'
        $l = Invoke-M3E2eStep 'ui-confirm' $id -TimeoutSec 600
        if ((Get-M3E2eField $l 'route') -eq 'broker') {
            $null = Invoke-M3E2eStep 'consent-wait' $id 'run' -WaitSec 300 -TimeoutSec 900 -Shot '04-consent-run'
            $null = Invoke-M3E2eStep 'consent-approve' $id 'run' -TimeoutSec 600 -Shot '05-run-approved'
        }
        $l = Invoke-M3E2ePhase 'ui-wait-scan' $id -WaitSec 2400 -TimeoutSec 3300
        Save-M3E2eShot '06-scan-done'
        $state = Get-M3E2eField $l 'state'
        if ("$($AppDef.kind)" -like 'fail-*') {
            if ($isNull) { throw 'a null run is for an executing app' }
            $null = Invoke-M3E2ePhase 'fail-check' $id -TimeoutSec 600
            Save-M3E2eShot '07-failure'
        } elseif ($state -in 'review', 'empty') {
            $null = Invoke-M3E2eStep 'capture-post' $id -TimeoutSec 5400
            if ($state -eq 'review') {
                Invoke-M3E2eWindow $id $rec $isNull
                if ($Undo -and $rec.empty_plan) {
                    # An undo app must have executed something; the scorer fails an undo app with nothing preselected.
                    $rec.undo_skipped = 'nothing preselected: nothing to undo'
                    Write-RigLog "  !! $id is an undo app, but nothing was preselected: no undo (the scorer fails it)"
                    $script:M3Fail = $true
                } elseif ($Undo) {
                    $l = Invoke-M3E2eStep 'ui-undo' $id -TimeoutSec 900 -Shot '10-undo-waiting'
                    # "Put back all" starts a new broker when the move ended the page's one (DECISIONS 2026-11-24): an
                    # admin explanation not yet shown in this UI process gets a real key on its focused Continue (as
                    # ui-uninstall), then its UAC prompt; consent-wait / -approve find the newest purge-broker.
                    if ((Get-M3E2eField $l 'state') -eq 'continue-focused') {
                        $null = Send-M3Keys 'space'
                        $rec.uac_keys.undo_continue = 'space'
                    }
                    $rec.uac_keys.undo = @(Invoke-M3E2eUac '10u-uac' $id 'undo')
                    $null = Invoke-M3E2eStep 'consent-wait' $id 'undo' -WaitSec 300 -TimeoutSec 900 -Shot '11-consent-undo'
                    $null = Invoke-M3E2eStep 'consent-approve' $id 'undo' -TimeoutSec 600
                    $null = Invoke-M3E2eStep 'ui-wait-undone' $id -WaitSec 1800 -TimeoutSec 2400 -Shot '12-undone'
                    $null = Invoke-M3E2eStep 'capture-undo' $id -TimeoutSec 3600
                }
            } elseif ($isNull) { throw "a null run needs the review page (the scan ended '$state')" }
        } else { $script:E2eFailedStep = 'ui-wait-scan'; $rec.failed_step = 'ui-wait-scan'; $rec.error = "the scan ended '$state'"; Write-RigLog "  !! $id`: the scan ended '$state'; nothing more to drive"; $script:M3Fail = $true }
    } catch {
        $rec.error = $_.Exception.Message
        $rec.failed_step = $script:E2eFailedStep
        Write-RigLog "  !! $id`: $($rec.error)"
        $script:M3Fail = $true
    } finally {
        if ($booted -and (Get-VmState) -eq 'running') {
            try {
                $null = Invoke-M3E2ePhase 'finish' $id -TimeoutSec 1800
                $zip = Join-Path $script:E2eDir 'guest.zip'
                Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
                $c = Invoke-Guest @('copyfrom', "C:\cr\out\m3-e2e-$id.zip", $zip)
                if ($c.code -eq 0 -and (Test-Path -LiteralPath $zip)) {
                    $g = Join-Path $script:E2eDir 'guest'
                    if (Test-Path -LiteralPath $g) { Remove-Item -LiteralPath $g -Recurse -Force }
                    Expand-Archive -LiteralPath $zip -DestinationPath $g
                    # e2e-final7 npp: a snapshot came back with a bad gzip CRC (one digit changed). Every .gz must
                    # decompress whole; else the zip is pulled once more, and a second failure is recorded, not hidden.
                    $bad = @(Get-M3BadGzip $g)
                    if ($bad.Count) {
                        Write-RigLog "  !! corrupt after the pull: $($bad -join ', '); pulling the guest zip again"
                        Remove-Item -LiteralPath $zip, $g -Recurse -Force -ErrorAction SilentlyContinue
                        $c = Invoke-Guest @('copyfrom', "C:\cr\out\m3-e2e-$id.zip", $zip)
                        if ($c.code -eq 0) { Expand-Archive -LiteralPath $zip -DestinationPath $g }
                        $bad = @(Get-M3BadGzip $g)
                        $rec.repulled = $true
                        if ($bad.Count) { $rec.corrupt = $bad; Write-RigLog "  !! still corrupt after the second pull: $($bad -join ', ')"; $script:M3Fail = $true }
                    }
                    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
                    $rec.pulled = $true
                    Write-RigLog "  guest outputs in $g"
                } else { Write-RigLog "  !! copyfrom of the guest zip failed: $($c.out -join ' ')"; $script:M3Fail = $true }
            } catch { Write-RigLog "  !! finish of $id`: $($_.Exception.Message)"; $script:M3Fail = $true }
        }
        $rec.ended = (Get-Date).ToString('o')
        [IO.File]::WriteAllText((Join-Path $script:E2eDir 'host.json'), (ConvertTo-Json $rec -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
        $script:E2eNull = $false
    }
    $rec
}

# Pure: the MSI fixtures a run drives (kind fail-*) and, from the smoke line `M3E MSI-SMOKE msi-smoke ok=False
# msi1603=fail:1603 msi3010=ok:0`, the reason each one is not driven (an app the line names as ok, or every app when
# the line says ok=True, gets none; no line, or an app the line does not name, gets a reason too: fail-closed).
function Get-M3E2eMsiSmokeSkips($Apps, [string]$Line) {
    $skips = [ordered]@{}
    foreach ($a in @($Apps | Where-Object { "$($_.kind)" -like 'fail-*' })) {
        $id = "$($a.id)"
        $f = $(if ($Line -cmatch '^M3E MSI-SMOKE ') { Get-M3Field $Line $id } else { $null })
        if ($f -and $f -clike 'ok:*') { continue }
        $code = $(if ($f) { $f -replace '^fail:', '' } else { '' })
        $skips[$id] = $(if (-not $Line -or $Line -cnotmatch '^M3E MSI-SMOKE ') { "msi smoke: no result ($(if ($Line) { $Line } else { 'no line' })); the fixture MSIs were not checked, so $id is not driven" }
                        elseif (-not $f) { "msi smoke: the line names no result for $id ($Line); $id is not driven" }
                        elseif (-not $code) { "msi smoke: the $id fixture could not be built or installed (msi-smoke\guest\step-msi-smoke.json); $id is not driven" }
                        else { "msi smoke: msiexec /i of the $id fixture exited $code (the smoke wants exit 0 and the ARP entry: the package does not install; msi-smoke\guest\msi-smoke-*.log); $id is not driven" })
    }
    $skips
}

# The MSI smoke check (vm\RIG.md section 17, "MSI smoke"): before the chain drives msi1603 / msi3010, one boot of the
# base snapshot builds both fixture packages in the guest and installs each with `msiexec /i` (guest phase msi-smoke).
# Evidence: <evidence>\msi-smoke\ (jobs, guest\ with step-msi-smoke.json and the verbose MSI logs, host.json).
# Returns {line, ok, skips: {app: reason}}; an app with a reason is recorded as not driven instead of booting.
function Invoke-M3E2eMsiSmoke($Apps, [string]$Base) {
    $msi = @($Apps | Where-Object { "$($_.kind)" -like 'fail-*' })
    if (-not $msi.Count) { return $null }
    $script:E2eDir = Join-Path $M3.evidence 'msi-smoke'
    New-Item -ItemType Directory -Force $script:E2eDir | Out-Null
    $script:E2eShots = New-Object System.Collections.ArrayList
    $script:E2eLines = New-Object System.Collections.ArrayList
    $script:E2eNull = $false
    $rec = [ordered]@{ app = 'msi-smoke'; apps = @($msi | ForEach-Object { "$($_.id)" }); base = $Base; started = (Get-Date).ToString('o'); ended = $null; line = $null; error = $null; pulled = $false; skips = $null }
    Write-RigLog "m3-e2e msi smoke ($($rec.apps -join ', ')) from $Base"
    $line = ''
    $booted = $false
    try {
        Restore-Base -Snapshot $Base -No3D -DiagDir $script:E2eDir
        $booted = $true
        $engine = $(if ($M3.engine) { $M3.engine } else { Join-Path $script:RepoRoot 'target\release\purge-engine.exe' })
        Push-Tools -Engine $engine
        $line = Invoke-M3E2ePhase 'msi-smoke' 'msi-smoke' -TimeoutSec 1200
        $rec.line = $line
    } catch { $rec.error = $_.Exception.Message; Write-RigLog "  !! msi smoke: $($rec.error)" }
    finally {
        if ($booted -and (Get-VmState) -eq 'running') {
            $zip = Join-Path $script:E2eDir 'guest.zip'
            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
            $c = Invoke-Guest @('copyfrom', 'C:\cr\out\m3-e2e-msi-smoke.zip', $zip)
            if ($c.code -eq 0 -and (Test-Path -LiteralPath $zip)) {
                $g = Join-Path $script:E2eDir 'guest'
                if (Test-Path -LiteralPath $g) { Remove-Item -LiteralPath $g -Recurse -Force }
                Expand-Archive -LiteralPath $zip -DestinationPath $g
                Remove-Item -LiteralPath $zip -Force
                $rec.pulled = $true
            } else { Write-RigLog "  !! copyfrom of the msi smoke zip failed: $($c.out -join ' ')" }
        }
    }
    $skips = Get-M3E2eMsiSmokeSkips $msi $line
    $rec.skips = $skips
    $rec.ok = ($skips.Count -eq 0)
    $rec.ended = (Get-Date).ToString('o')
    [IO.File]::WriteAllText((Join-Path $script:E2eDir 'host.json'), (ConvertTo-Json $rec -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
    if (-not $rec.ok) { $script:M3Fail = $true; foreach ($k in $skips.Keys) { Write-RigLog "  !! $k`: $($skips[$k])" } } else { Write-RigLog '  msi smoke ok: both fixture packages install' }
    $rec
}

function Invoke-M3E2e {
    Assert-M3E2eGateRunName $M3.run
    $ui = Get-M3UiExe
    if (-not (Test-Path -LiteralPath $ui -PathType Leaf)) { throw "m3-e2e needs the UI (-UiPublish; no $ui)" }
    $base = $(if ($M3.base) { $M3.base } elseif ($M3.uac_on) { 'm3-uac-on' } else { 'rig-base' })
    if ($base -eq 'm3-uac-on' -and -not (Test-M3Snapshot)) { throw "snapshot $M3Snap missing (rig-m3.ps1 -Mode snapshot)" }
    # The gate's ambient set (RIG.md section 17.1): built from this flow's null runs; no fallback to the M2 set.
    $amb = Resolve-M3E2eAmbient
    if (-not (Test-Path -LiteralPath $amb -PathType Leaf)) { throw "no m3-e2e ambient set $amb (run -Mode m3-e2e-null first, RIG.md section 17.1, or pass -AmbientFile)" }
    $script:M3PushAmbient = $amb
    $ambRec = [ordered]@{ file = $amb; sha256 = (Get-M3Sha256File $amb) }
    Write-RigLog "  ambient set $amb (sha256 $($ambRec.sha256))"
    # The binaries under test (the scorer compares them with the set's provenance, RIG.md section 17.1).
    $bins = Get-M3E2eBinaryHashes
    $setProv = $(try { (Read-M3Json $amb).provenance } catch { $null })
    if (-not $setProv) { Write-RigLog '  !! the ambient set records no provenance (the scorer will fail it)' }
    else {
        $diff = @(Compare-M3E2eProvenance $setProv ([ordered]@{ vm = $M3Vm; snapshot = $base; engine_sha256 = $bins.engine_sha256; broker_sha256 = $bins.broker_sha256; ui_sha256 = $bins.ui_sha256 }))
        if ($diff.Count) { Write-RigLog "  !! the ambient set was built from other runs ($($diff -join '; ')); the scorer will fail it" }
    }
    $apps = @(Get-M3E2eApps -Only $M3.apps)
    $undo = @(Get-M3E2eUndoApps -Override $M3.undo_apps)
    $sum = [ordered]@{ schema = 'purge.rig.m3e2e.summary/1'; run = $M3.run; vm = $M3Vm; snapshot = $base; uac_on = $M3.uac_on; started = $script:M3Started
                       engine = $M3.engine; broker = $M3.broker; ui = $ui; binaries = $bins; ambient = $ambRec; apps_asked = @($apps | ForEach-Object { "$($_.id)" }); undo_apps = $undo; apps = @(); msi_smoke = $null }
    # The MSI fixtures install? (one boot first, when the run drives one; a failing package skips its app.)
    $smoke = Invoke-M3E2eMsiSmoke $apps $base
    $sum.msi_smoke = $smoke
    foreach ($a in $apps) {
        $skip = $(if ($smoke -and $smoke.skips -and $smoke.skips.Contains("$($a.id)")) { "$($smoke.skips["$($a.id)"])" } else { '' })
        $sum.apps += Invoke-M3E2eApp $a ($undo -contains "$($a.id)") $base -Ambient $ambRec -SkipReason $skip
        [IO.File]::WriteAllText((Join-Path $M3.evidence 'summary.json'), (ConvertTo-Json $sum -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
    }
    $sum.ended = (Get-Date).ToString('o')
    $sum.failed_step = $script:M3Fail
    [IO.File]::WriteAllText((Join-Path $M3.evidence 'summary.json'), (ConvertTo-Json $sum -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
    Write-RigLog "summary: $(Join-Path $M3.evidence 'summary.json'); score: powershell -File vm\truth\m3-e2e-score.ps1 -Evidence $($M3.evidence) -Collect"
}

# --------------------------------------------------------------- m3-e2e ambient set (RIG.md section 17.1)

# Fixture names an m3-e2e ambient set must never hold: the rig's PurgeExec* objects (execapp), the MSI fixtures'
# PurgeE2eMsi key, the engine's store C:\ProgramData\Purge (rig-m1b-exec.ps1 $XFixtureRx plus PurgeE2eMsi) and the
# per-volume quarantine X:\.purge-q. An entry on one of them would excuse a change Purge made to that very object.
# Case-insensitive; '\\+' (and '(\\)?' before a pattern's escaped '-') also covers a pattern's escapes. The scorer checks
# the committed file with the same expression (m3-e2e-score.ps1 $E2eFixtureRx).
$M3E2eFixtureRx = '(?i)purgeexec|programdata\\+purge|purgee2emsi|\.purge(\\)?-q'
# Distinct null runs a set must come from (m3-e2e-score.ps1 $E2eMinNullRuns is the same number).
$M3E2eMinNullRuns = 6

# The .gz files under $Dir that do not decompress whole (a bad CRC or a truncated stream), relative to $Dir.
function Get-M3BadGzip([string]$Dir) {
    if (-not (Test-Path -LiteralPath $Dir)) { return @('(no guest folder)') }
    foreach ($f in @(Get-ChildItem -LiteralPath $Dir -Recurse -File -Filter '*.gz')) {
        $fs = $null
        try {
            $fs = [IO.File]::OpenRead($f.FullName)
            $gz = New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Decompress)
            $buf = New-Object byte[] 1048576
            while ($gz.Read($buf, 0, $buf.Length) -gt 0) { }
        } catch { $f.FullName.Substring($Dir.Length).TrimStart('\') } finally { if ($fs) { $fs.Dispose() } }
    }
}

function Get-M3Sha256File([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
function Read-M3Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { [IO.File]::ReadAllText($Path).TrimStart([char]0xFEFF) | ConvertFrom-Json } catch { $null }
}

# The m3-e2e ambient set of a VM: Inbound truth\m3-e2e-ambient.json, Purge-CleanPro truth\m3-e2e-ambient-cleanpro.json
# (another Windows build churns differently). Another VM has none.
function Get-M3E2eAmbientFile([string]$Vm) {
    $leaf = switch -CaseSensitive ($Vm) { 'Inbound-Win11-Test' { 'm3-e2e-ambient.json' } 'Purge-CleanPro' { 'm3-e2e-ambient-cleanpro.json' } default { $null } }
    if (-not $leaf) { throw "no m3-e2e ambient set for VM '$Vm'" }
    Join-Path $script:RigDir "truth\$leaf"
}
function Resolve-M3E2eAmbient { if ($M3.ambient) { $M3.ambient } else { Get-M3E2eAmbientFile $M3Vm } }
# The VM an ambient file is for: the VM whose file it is (Get-M3E2eAmbientFile's leaf), else this script's VM.
function Get-M3E2eAmbientVm([string]$Out) {
    switch -CaseSensitive (Split-Path -Leaf $Out) { 'm3-e2e-ambient.json' { 'Inbound-Win11-Test' } 'm3-e2e-ambient-cleanpro.json' { 'Purge-CleanPro' } default { $M3Vm } }
}

# The idle seconds of a null run's window: 1..600 (0 would be no window at all; the gate's execution took about 8 s),
# passed to the guest unchanged.
function Assert-M3E2eNullWait($Sec) {
    if ($null -eq $Sec -or "$Sec" -notmatch '^\d+$' -or [int]$Sec -lt 1 -or [int]$Sec -gt 600) { throw "-NullWaitSec must be 1..600 (got '$Sec')" }
    [int]$Sec
}

# The binaries under test: purge-engine.exe, purge-broker.exe (-Engine / -Broker, else target\release) and the UI's
# Purge.exe (Get-M3UiExe), with their SHA-256. Throws when one is missing.
function Get-M3E2eBinaryHashes {
    $p = [ordered]@{
        engine = $(if ($M3.engine) { $M3.engine } else { Join-Path $script:RepoRoot 'target\release\purge-engine.exe' })
        broker = $(if ($M3.broker) { $M3.broker } else { Join-Path $script:RepoRoot 'target\release\purge-broker.exe' })
        ui     = Get-M3UiExe
    }
    $h = [ordered]@{}
    foreach ($k in $p.Keys) {
        if (-not (Test-Path -LiteralPath $p[$k] -PathType Leaf)) { throw "missing $k binary $($p[$k])" }
        $h["$($k)_sha256"] = Get-M3Sha256File $p[$k]
    }
    $h
}

# A null campaign's provenance (each null run's run.json, then the set): campaign id (-RunName), VM, snapshot, the
# binaries' SHA-256 and the null wait.
function Get-M3E2eProvenance([string]$Base) {
    $b = Get-M3E2eBinaryHashes
    [ordered]@{ campaign = $M3.run; vm = $M3Vm; snapshot = $Base; engine_sha256 = $b.engine_sha256; broker_sha256 = $b.broker_sha256
                ui_sha256 = $b.ui_sha256; null_wait = (Assert-M3E2eNullWait $M3.null_wait) }
}
$M3E2eProvenanceFields = @('campaign', 'vm', 'snapshot', 'engine_sha256', 'broker_sha256', 'ui_sha256', 'null_wait')

# Why provenance $P (parsed) is incomplete; none: every field is there and well-formed.
function Test-M3E2eProvenance($P) {
    if (-not $P) { return @('no provenance') }
    $why = @()
    foreach ($f in $M3E2eProvenanceFields) { if (-not $P.PSObject.Properties[$f] -or "$($P.$f)" -eq '') { $why += "provenance.$f missing" } }
    foreach ($f in 'engine_sha256', 'broker_sha256', 'ui_sha256') { if ($P.PSObject.Properties[$f] -and "$($P.$f)" -and "$($P.$f)" -cnotmatch '\A[0-9a-f]{64}\z') { $why += "provenance.$f is not a SHA-256" } }
    if ($P.PSObject.Properties['null_wait'] -and "$($P.null_wait)" -ne '' -and $(try { $null = Assert-M3E2eNullWait $P.null_wait; $false } catch { $true })) { $why += "provenance.null_wait '$($P.null_wait)' not 1..600" }
    $why
}

# The fields of $Want (a dictionary) whose value differs in provenance $P (case-sensitive).
function Compare-M3E2eProvenance($P, $Want) {
    foreach ($k in @($Want.Keys)) {
        $have = $(if ($P -and $P.PSObject.Properties[$k]) { "$($P.$k)" } else { '' })
        if ($have -cne "$($Want[$k])") { "$k '$have', want '$($Want[$k])'" }
    }
}

# Push-M2Ambient (rig.ps1) pushes what Get-M2AmbientFile names: for this script the m3-e2e set a gate run resolved
# (Invoke-M3E2e), never rig.ps1's M2 set; a null run pushes with -None and never reads it.
$script:M3PushAmbient = $null
$script:M3E2eProv = $null
function Get-M2AmbientFile([string]$Name = '') { $script:M3PushAmbient }

# The run name of null round $K of app $App: <prefix><k>-m3-e2e-<app> (default prefix en: en1-m3-e2e-vscode).
function Get-M3E2eNullRunName([int]$K, [string]$App, [string]$Prefix = '') {
    if ($K -lt 1) { throw "bad null round $K" }
    if (-not $Prefix) { $Prefix = 'en' }
    $r = "$Prefix$K-m3-e2e-$App"
    if ($r -cnotmatch '\A[a-z0-9][a-z0-9_.-]*\z') { throw "bad run name '$r'" }
    $r
}

# True when $Name has the shape of a null run name (any prefix). A gate run's name never has it.
function Test-M3E2eNullRunShape([string]$Name) { $Name -cmatch '[0-9]-m3-e2e-[a-z0-9][a-z0-9-]*\z' }
function Assert-M3E2eGateRunName([string]$Name) {
    if (Test-M3E2eNullRunShape $Name) { throw "run name '$Name' has the shape of a null run (<prefix><k>-m3-e2e-<app>); pick another -RunName" }
}

# The executing apps a null campaign runs (-Apps, default vscode): a failing uninstaller has no exec window.
# The null campaign's default apps (DECISIONS 2026-11-24, D): the gate's executing apps, both routes. vscode-user is
# the medium route (no run consent; the broker starts at Move), whose window holds Windows' MuiCache / bam /
# UserAssist entries for purge-broker.exe that broker-route null runs never see.
$M3E2eNullDefaultApps = @('vscode', 'vscode-user', 'git', 'firefox-tb', 'execapp')

function Get-M3E2eNullApps([string]$ExpectFile = $M3E2eExpect, [string[]]$Only = @()) {
    $only = @($Only | Where-Object { $_ })
    if (-not $only.Count) { $only = $M3E2eNullDefaultApps }
    $apps = @(Get-M3E2eApps -ExpectFile $ExpectFile -Only $only)
    foreach ($a in $apps) { if ("$($a.kind)" -notin 'app', 'fixture') { throw "app '$($a.id)' executes nothing (kind $($a.kind)); no null run" } }
    $apps
}

# The arguments of the host rigtool call that builds the set from null run dirs (added records too, as M1b).
function Get-M3E2eAmbientArgs([string[]]$Dirs, [string]$Out) {
    if (-not @($Dirs).Count) { throw 'no null run dirs' }
    @('ambient', '--m2', '--added', '--null') + @($Dirs) + @('-o', $Out)
}

# Why run dir $Run (the host's run.json $Doc and the guest's e2e.json $E2e) is not a finished null run of app $App;
# none: it is. Refused: a gate run (the plan consent approved, a session, an execdiff, an ambient set in the guest), a
# run of another app or name, an unfinished run, one with a host error, and one whose window steps failed or are missing.
function Test-M3E2eNullRunDoc($Doc, $E2e, [string]$Run, [string]$App) {
    if (-not $Doc) { return @('no readable run.json') }
    $why = @()
    if ("$($Doc.schema)" -cne 'purge.rig.m3e2e.null/1') { $why += "schema '$($Doc.schema)'" }
    if ("$($Doc.run)" -cne $Run) { $why += "run.json names run '$($Doc.run)'" }
    if ("$($Doc.app)" -cne $App) { $why += "app '$($Doc.app)', want '$App'" }
    if (-not ($Doc.PSObject.Properties['null_run'] -and $Doc.null_run -and $Doc.null_run.null -eq $true)) { $why += 'not a null run (null_run.null is not true)' }
    if (-not "$($Doc.finished)") { $why += 'not finished' }
    if ("$($Doc.error)") { $why += "host error: $($Doc.error)" }
    if ($Doc.pulled -ne $true) { $why += 'guest outputs not pulled' }
    if (-not (Test-M3E2eNullRunShape $Run)) { $why += "run name '$Run' is not of the null shape" }
    # Provenance (RIG.md section 17.1): campaign, VM, snapshot, the binaries' hashes and the null wait it ran with.
    $prov = $(if ($Doc.PSObject.Properties['provenance']) { $Doc.provenance } else { $null })
    $why += @(Test-M3E2eProvenance $prov)
    if ($prov -and $Doc.null_run -and "$($prov.null_wait)" -ne "$($Doc.null_run.wait_sec)") { $why += "provenance.null_wait $($prov.null_wait) is not null_run.wait_sec $($Doc.null_run.wait_sec)" }
    if (-not $E2e) { return @($why + 'no readable e2e.json') }
    # Every plan item's key (capture-post cli.plan_keys, not only the preselected ones): the build refuses entries on them.
    $cli = $(if ($E2e.state -and $E2e.state.PSObject.Properties['cli']) { $E2e.state.cli } else { $null })
    if (-not ($cli -and $cli.PSObject.Properties['plan_keys'] -and $cli.PSObject.Properties['items'])) { $why += 'capture-post recorded no plan_keys' }
    elseif (@(@($cli.plan_keys) | Where-Object { $_ }).Count -ne [int]$cli.items) { $why += "plan_keys $(@(@($cli.plan_keys) | Where-Object { $_ }).Count), plan items $($cli.items)" }
    if ("$($E2e.schema)" -cne 'purge.rig.m3e2e.app/1') { $why += "e2e.json schema '$($E2e.schema)'" }
    if ("$($E2e.app)" -cne $App) { $why += "e2e.json names app '$($E2e.app)'" }
    if (-not ($E2e.state -and $E2e.state.PSObject.Properties['null_run'] -and $E2e.state.null_run -eq $true)) { $why += 'the guest did not run it as a null run (state.null_run)' }
    $st = $E2e.steps
    $step = { param($n) if ($st -and $st.PSObject.Properties[$n]) { $st.$n } else { $null } }
    foreach ($n in 'capture-post', 'ui-move', 'consent-wait-plan', 'consent-cancel-plan', 'null-wait', 'capture-exec') {
        $s = & $step $n
        if (-not $s) { $why += "no step $n" } elseif ($s.ok -ne $true) { $why += "step $n not ok" }
    }
    $r = & $step 'ui-wait-result'
    if (-not ($r -and "$($r.state)" -ceq 'declined')) { $why += "ui-wait-result '$(if ($r) { $r.state })', want 'declined'" }
    foreach ($n in 'consent-approve-plan', 'ui-undo', 'consent-approve-undo', 'capture-undo') { if (& $step $n) { $why += "ran $n" } }
    $cx = & $step 'capture-exec'
    if ($cx -and @(@($cx.sessions_new) | Where-Object { $_ }).Count) { $why += "a session was made: $(@($cx.sessions_new) -join ', ')" }
    if ($E2e.files -and $E2e.files.execdiff -eq $true) { $why += 'an execdiff ran' }
    if ($E2e.PSObject.Properties['ambient'] -and $E2e.ambient -and "$($E2e.ambient.guest_sha256)") { $why += 'an ambient set was in the guest' }
    $why
}

# The objects a null run's own CLI plan preselected (capture-post cli.preselected_keys, Get-E2eTargetKey form), folded:
# Path / RegKey -> {path} (a record on it or under it), RegValue -> {path, name} (that value only), Service -> its
# Services key, Task -> its file under System32\Tasks. Firewall rules and packages have no snapshot path.
function Get-M3E2eTargetRoots([string[]]$Keys) {
    foreach ($k in @($Keys | Where-Object { $_ })) {
        $p = "$k" -split '\|'
        switch -CaseSensitive ($p[0]) {
            'Service' { [pscustomobject]@{ path = "hklm\system\currentcontrolset\services\$($p[1])".ToLowerInvariant(); name = '' } }
            'Task' { [pscustomobject]@{ path = ('c:\windows\system32\tasks\' + "$($p[1])".TrimStart('\')).ToLowerInvariant(); name = '' } }
            'FirewallRule' { }
            'AppxPackage' { }
            default {
                if ($p.Count -ge 2 -and $p[1]) {
                    [pscustomobject]@{ path = $p[1].TrimEnd('\').ToLowerInvariant(); name = $(if ($p[0] -ceq 'RegValue' -and $p.Count -ge 3) { $p[2].ToLowerInvariant() } else { '' }) }
                }
            }
        }
    }
}

# Every record and pattern of an ambient set (purge.rig.m2ambient/1, parsed) that names a fixture ($M3E2eFixtureRx) or
# one of $Roots (Get-M3E2eTargetRoots: the null runs' own preselected objects): union and per run. A record names a root
# when its path is the root or lies under it (a RegValue root: that value only); a pattern when its text, backslashes
# dropped, holds the root's path (and value name), backslashes dropped (fail-closed: it may refuse more than needed).
function Get-M3E2eAmbientFixtureHits($Set, $Roots = @()) {
    $recs = @(@($Set.records)); $pats = @(@($Set.patterns))
    foreach ($r in @($Set.runs)) { if ($r) { $recs += @($r.records); $pats += @($r.patterns) } }
    $recs = @($recs | Where-Object { $null -ne $_ } | ForEach-Object { "$_" }); $pats = @($pats | Where-Object { $null -ne $_ } | ForEach-Object { "$_" })
    $hits = @(@($recs + $pats) | Where-Object { $_ -match $M3E2eFixtureRx })
    $flat = { param($s) "$s".ToLowerInvariant().Replace('\', '') }
    foreach ($root in @($Roots | Where-Object { $_ -and $_.path })) {
        foreach ($k in $recs) {
            if ($k.Length -lt 4) { continue }
            $body = $k.Substring(3).ToLowerInvariant(); $path = $body; $val = $null
            if ($k[1] -ceq 'V') { $i = $body.IndexOf('|'); if ($i -ge 0) { $path = $body.Substring(0, $i); $val = $body.Substring($i + 1) } }
            if ($root.name) { if ($k[1] -ceq 'V' -and $path -eq $root.path -and $val -eq $root.name) { $hits += $k } }
            elseif ($path -eq $root.path -or $path.StartsWith($root.path + '\')) { $hits += $k }
        }
        $needle = & $flat ($root.path + $(if ($root.name) { '|' + $root.name }))
        foreach ($p in $pats) { if ((& $flat $p).Contains($needle)) { $hits += $p } }
    }
    @($hits | Select-Object -Unique)
}

# Purge's own store C:\ProgramData\Purge: the broker writes there in both windows, a null run's cancelled plan too
# (first null run tn1-m3-e2e-vscode, 2026-11-23). Exactly these known null-window records are dropped from the built set
# (records only, compared whole, case-insensitive): in a gate run execdiff judges every record under the store by its
# own store rule (authorised as 'store'), never by the ambient set, and dropping entries can only make the set stricter.
# Any other record or pattern under C:\ProgramData\Purge or on an X:\.purge-q refuses the set (Get-M3E2eStoreRefusals:
# a cancelled plan has no business there), as do the other fixture names; the scorer refuses a committed set naming the
# store at all.
$M3E2eStoreAllowed = @('+F:C:\ProgramData\Purge\sessions\writer.lock', '~D:C:\ProgramData\Purge\sessions', '~D:C:\ProgramData\Purge')
$M3E2eStoreRx = '(?i)programdata\\+purge(\\|\$|$)|\.purge(\\)?-q'
function Test-M3E2eStoreAllowed([string]$Entry) { @($M3E2eStoreAllowed | Where-Object { $_ -ieq $Entry }).Count -gt 0 }

# Removes the allowed store records ($M3E2eStoreAllowed) from $Set (union and per run, in place); returns them.
function Remove-M3E2eStoreEntries($Set) {
    $out = @(@($Set.records) | Where-Object { $null -ne $_ -and (Test-M3E2eStoreAllowed "$_") } | ForEach-Object { "$_" })
    $Set.records = @(@($Set.records) | Where-Object { $null -ne $_ -and -not (Test-M3E2eStoreAllowed "$_") })
    foreach ($r in @($Set.runs | Where-Object { $_ })) {
        $out += @(@($r.records) | Where-Object { $null -ne $_ -and (Test-M3E2eStoreAllowed "$_") } | ForEach-Object { "$_" })
        $r.records = @(@($r.records) | Where-Object { $null -ne $_ -and -not (Test-M3E2eStoreAllowed "$_") })
    }
    @($out | Select-Object -Unique)
}

# Every record or pattern of $Set (union and per run) under the store or on an X:\.purge-q that is not an allowed
# record: each one refuses the set.
function Get-M3E2eStoreRefusals($Set) {
    $all = @(@($Set.records) + @($Set.patterns))
    foreach ($r in @($Set.runs | Where-Object { $_ })) { $all += @($r.records) + @($r.patterns) }
    # (A pattern starts with '^', so it never equals an allowed record.)
    @($all | Where-Object { $null -ne $_ -and "$_" -match $M3E2eStoreRx -and -not (Test-M3E2eStoreAllowed "$_") } | ForEach-Object { "$_" } | Select-Object -Unique)
}

# The host rigtool (ambient builds): $env:RIG_RIGTOOL, else vm\rigtool\target\release\rigtool.exe.
function Get-M3E2eHostRigTool {
    $t = $(if ($env:RIG_RIGTOOL) { $env:RIG_RIGTOOL } else { Join-Path $script:RigDir 'rigtool\target\release\rigtool.exe' })
    if (-not (Test-Path -LiteralPath $t -PathType Leaf)) { throw "rigtool not built: $t" }
    $t
}

# After a null run: vm\runs\<run>\ gets the window's snapshot pair (snap-<run>-a / -b.tsv.gz, moved out of the pulled
# guest outputs), the guest's e2e.json and the host's run.json (purge.rig.m3e2e.null/1). An older dir of that name goes
# to vm\runs\_old\ first. Returns why it is not a null run (Test-M3E2eNullRunDoc); none: it is.
function Save-M3E2eNullRun([string]$Run, $AppDef, $Rec, [string]$Dir, $Provenance = $script:M3E2eProv) {
    $d = Join-Path $script:RunsDir $Run
    if (Test-Path -LiteralPath $d) {
        $old = Join-Path $script:RunsDir '_old'
        New-Item -ItemType Directory -Force $old | Out-Null
        Move-Item -LiteralPath $d -Destination (Join-Path $old "$Run-$(Get-Date -Format 'yyyyMMdd-HHmmss')")
    }
    New-Item -ItemType Directory -Force $d | Out-Null
    $g = Join-Path $Dir 'guest'
    foreach ($s in 'a', 'b') {
        $src = Join-Path $g "snap-$s.tsv.gz"
        if (Test-Path -LiteralPath $src) { Move-Item -LiteralPath $src -Destination (Join-Path $d "snap-$Run-$s.tsv.gz") }
    }
    if (Test-Path -LiteralPath (Join-Path $g 'e2e.json')) { Copy-Item -LiteralPath (Join-Path $g 'e2e.json') -Destination (Join-Path $d 'e2e.json') }
    $doc = [ordered]@{ schema = 'purge.rig.m3e2e.null/1'; run = $Run; mode = 'm3-e2e'; app = "$($AppDef.id)"; vm = $M3Vm; snapshot = $Rec.base
                       null_run = [ordered]@{ null = $true; wait_sec = $M3.null_wait }; provenance = $Provenance; evidence = $Dir; started = $Rec.started; finished = $Rec.ended
                       error = $Rec.error; pulled = $Rec.pulled }
    [IO.File]::WriteAllText((Join-Path $d 'run.json'), (ConvertTo-Json $doc -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    $why = @(Test-M3E2eNullRunDoc (Read-M3Json (Join-Path $d 'run.json')) (Read-M3Json (Join-Path $d 'e2e.json')) $Run "$($AppDef.id)")
    foreach ($s in 'a', 'b') { if (-not (Test-Path -LiteralPath (Join-Path $d "snap-$Run-$s.tsv.gz"))) { $why += "no snap-$Run-$s.tsv.gz" } }
    $why
}

# m3-e2e-ambient (host only): the set from the null runs <prefix><k>-m3-e2e-<app>, k = 1..-Count, of each null app ->
# the VM's file (Resolve-M3E2eAmbient). Each run dir must hold its snapshot pair and mark a finished null run
# (Test-M3E2eNullRunDoc); at least $M3E2eMinNullRuns runs; the set is built into a temporary file and must name no
# fixture and none of the null runs' own preselected objects (Get-M3E2eAmbientFixtureHits). Any refusal throws and writes
# no file (an older file stays as it was). Returns the dirs used.
function Invoke-M3E2eBuildAmbient {
    $out = Resolve-M3E2eAmbient
    $dirs = @(); $bad = @(); $roots = @(); $provs = [ordered]@{}
    foreach ($a in @(Get-M3E2eNullApps -Only $M3.apps)) {
        foreach ($k in 1..([Math]::Max(1, $M3.count))) {
            $r = Get-M3E2eNullRunName $k "$($a.id)" $M3.prefix
            $d = Join-Path $script:RunsDir $r
            if (-not (Test-Path -LiteralPath (Join-Path $d "snap-$r-a.tsv.gz")) -or -not (Test-Path -LiteralPath (Join-Path $d "snap-$r-b.tsv.gz"))) { $bad += "$r`: no snapshot pair in $d"; continue }
            $e2e = Read-M3Json (Join-Path $d 'e2e.json')
            $doc = Read-M3Json (Join-Path $d 'run.json')
            $why = @(Test-M3E2eNullRunDoc $doc $e2e $r "$($a.id)")
            if ($why.Count) { $bad += "$r`: $($why -join '; ')"; continue }
            # Every plan item of the run (preselected or not) is a plan object the set must not name.
            $roots += @(Get-M3E2eTargetRoots @(@($e2e.state.cli.plan_keys) + @($e2e.state.cli.preselected_keys)))
            $provs[$r] = $doc.provenance
            $dirs += $d
        }
    }
    if ($bad.Count) { throw "not null runs, no ambient set written:`n  $($bad -join "`n  ")" }
    if ($dirs.Count -lt $M3E2eMinNullRuns) { throw "$($dirs.Count) null run(s); the set needs at least $M3E2eMinNullRuns (-Count); no ambient set written" }
    # One campaign, one VM (the file's), one snapshot, one set of binaries, one null wait for every run.
    $first = @($provs.Values)[0]
    $want = [ordered]@{}; foreach ($f in $M3E2eProvenanceFields) { $want[$f] = "$($first.$f)" }
    $mixed = @(foreach ($r in $provs.Keys) { $diff = @(Compare-M3E2eProvenance $provs[$r] $want); if ($diff.Count) { "$r`: $($diff -join ', ')" } })
    if ($mixed.Count) { throw "the null runs differ in provenance (first: $(@($provs.Keys)[0])), no ambient set written:`n  $($mixed -join "`n  ")" }
    $vm = Get-M3E2eAmbientVm $out
    if ($want.vm -cne $vm) { throw "the null runs ran on VM '$($want.vm)', the set $out is for '$vm'; no ambient set written" }
    $provenance = [ordered]@{}; foreach ($f in $M3E2eProvenanceFields) { $provenance[$f] = $first.$f }
    $tmp = "$out.tmp-" + [guid]::NewGuid().ToString('N').Substring(0, 8)
    try {
        $a = Get-M3E2eAmbientArgs $dirs $tmp
        $tool = Get-M3E2eHostRigTool
        Write-RigLog "$tool $($a -join ' ')"
        # rigtool writes its progress to stderr; under ErrorActionPreference Stop, Windows PowerShell 5.1 turns the
        # first stderr line into a terminating error (chain null-final3 ended "exit 1" on "ambient --m2: en1...: 102
        # records"). Run it with Continue, log its lines, and judge it by the exit code alone.
        $eap = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $tool @a 2>&1 | ForEach-Object { Write-RigLog "  $_" }
            $code = $LASTEXITCODE
        } finally { $ErrorActionPreference = $eap }
        if ($code -ne 0) { throw "rigtool ambient --m2 --added exited $code; no ambient set written" }
        $set = Read-M3Json $tmp
        if (-not $set -or "$($set.schema)" -cne 'purge.rig.m2ambient/1') { throw "the built set has schema '$(if ($set) { $set.schema })'; no ambient set written" }
        $storeBad = @(Get-M3E2eStoreRefusals $set)
        if ($storeBad.Count) { throw "the built set names Purge's store or a .purge-q beyond the known null-window records ($($storeBad.Count)), no ambient set written: $(@($storeBad | Select-Object -First 10) -join ' | ')" }
        $dropped = @(Remove-M3E2eStoreEntries $set)
        if ($dropped.Count) {
            Write-RigLog "  dropped $($dropped.Count) entr$(if ($dropped.Count -eq 1) { 'y' } else { 'ies' }) of Purge's own store (execdiff's store rule judges them in a gate run): $($dropped -join ' | ')"
            $set | Add-Member -Force -NotePropertyName note -NotePropertyValue "$($set.note)$(if ($set.note) { ' ' })m3-e2e: $($dropped.Count) store entries dropped (C:\ProgramData\Purge; the broker's writer.lock and the sessions dir of the cancelled plan)."
        }
        $set | Add-Member -Force -NotePropertyName provenance -NotePropertyValue $provenance
        [IO.File]::WriteAllText($tmp, (ConvertTo-Json $set -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
        $set = Read-M3Json $tmp
        $hits = @(Get-M3E2eAmbientFixtureHits $set $roots)
        if ($hits.Count) { throw "the built set names fixture or plan objects ($($hits.Count)), no ambient set written; rerun the null rounds: $(@($hits | Select-Object -First 10) -join ' | ')" }
        Move-Item -LiteralPath $tmp -Destination $out -Force
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    Write-RigLog "m3-e2e ambient set ($($dirs.Count) null runs, $(@($set.records).Count) records, $(@($set.patterns).Count) patterns) -> $out"
    $dirs
}

# m3-e2e-null: -Count null rounds per null app (Get-M3E2eNullApps), each from a fresh restore, then the set
# (Invoke-M3E2eBuildAmbient). Any failed null run: no ambient file is written (throws).
function Invoke-M3E2eNullCampaign {
    if ($M3.count -lt 1) { throw '-Count must be at least 1' }
    $null = Assert-M3E2eNullWait $M3.null_wait
    if ($M3.undo_apps.Count) { throw 'a null run is never undone (-UndoApps)' }
    $null = Get-M3E2eHostRigTool
    $out = Resolve-M3E2eAmbient                                       # the output file must be known before the rounds
    $ui = Get-M3UiExe
    if (-not (Test-Path -LiteralPath $ui -PathType Leaf)) { throw "m3-e2e-null needs the UI (-UiPublish; no $ui)" }
    $base = $(if ($M3.base) { $M3.base } elseif ($M3.uac_on) { 'm3-uac-on' } else { 'rig-base' })
    if ($base -eq 'm3-uac-on' -and -not (Test-M3Snapshot)) { throw "snapshot $M3Snap missing (rig-m3.ps1 -Mode snapshot)" }
    $apps = @(Get-M3E2eNullApps -Only $M3.apps)
    # The campaign's provenance, written into every null run's run.json (the build requires one for all, RIG.md 17.1).
    $script:M3E2eProv = Get-M3E2eProvenance $base
    $vm = Get-M3E2eAmbientVm $out
    if ($vm -cne $M3Vm) { throw "the null runs run on $M3Vm, but $out is the set of $vm" }
    $sum = [ordered]@{ schema = 'purge.rig.m3e2e.null-summary/1'; run = $M3.run; vm = $M3Vm; snapshot = $base; uac_on = $M3.uac_on; started = $script:M3Started
                       engine = $M3.engine; broker = $M3.broker; ui = $ui; null_wait = $M3.null_wait; provenance = $script:M3E2eProv; out = $out; runs = @() }
    $bad = @()
    foreach ($a in $apps) {
        foreach ($k in 1..$M3.count) {
            $run = Get-M3E2eNullRunName $k "$($a.id)" $M3.prefix
            $dir = Join-Path $M3.evidence "$run\$($a.id)"
            $rec = Invoke-M3E2eApp $a $false $base -Dir $dir -NullRun $run
            $why = @(Save-M3E2eNullRun $run $a $rec $dir)
            if ($why.Count) { $bad += $run; Write-RigLog "  !! null run $run`: $($why -join '; ')" } else { Write-RigLog "  null run $run ok -> $(Join-Path $script:RunsDir $run)" }
            $sum.runs += [ordered]@{ run = $run; app = "$($a.id)"; ok = ($why.Count -eq 0); why = $why; error = $rec.error }
            [IO.File]::WriteAllText((Join-Path $M3.evidence 'summary.json'), (ConvertTo-Json $sum -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
        }
    }
    if ($bad.Count) { throw "null run(s) failed: $($bad -join ', '); no ambient set written" }
    $sum.dirs = @(Invoke-M3E2eBuildAmbient)
    $sum.ended = (Get-Date).ToString('o')
    [IO.File]::WriteAllText((Join-Path $M3.evidence 'summary.json'), (ConvertTo-Json $sum -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
}

# ------------------------------------------------------------------------------------------------- main

# Dot-sourced (the rig self-test): the functions only.
if ($MyInvocation.InvocationName -eq '.') { return }

# m3-e2e-ambient: host only (no VM, no lock, no evidence directory).
if ($M3.mode -eq 'm3-e2e-ambient') {
    try { $null = Invoke-M3E2eBuildAmbient; exit 0 } catch { Write-Host "!! $($_.Exception.Message)"; exit 1 }
}

$aside = $null
if ($M3.mode -like 'm3-*') { $aside = Move-M3EvidenceAside $M3.evidence }
New-Item -ItemType Directory -Force $M3.evidence | Out-Null
$script:RigLogFile = Join-Path $M3.evidence ("rig-m3-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Write-RigLog "rig-m3 mode=$($M3.mode) vm=$M3Vm evidence=$($M3.evidence)"
if ($aside) { Write-RigLog "  the earlier evidence was moved to $aside" }
Assert-M3Start
$script:M3Started = (Get-Date).ToString('o')
$code = 0
try {
    if ($M3.mode -in 'all', 'snapshot') { Invoke-M3Snapshot }
    if ($M3.mode -in 'all', 'probe') { Invoke-M3Probe }
    if ($M3.mode -eq 'm3-broker') { Invoke-M3SecBroker }
    if ($M3.mode -eq 'm3-consent') { Invoke-M3SecConsent }
    if ($M3.mode -eq 'm3-uac') { Invoke-M3SecUac }
    if ($M3.mode -eq 'm3-e2e') { Invoke-M3E2e }
    if ($M3.mode -eq 'm3-e2e-null') { Invoke-M3E2eNullCampaign }
} catch {
    Write-RigLog "!! $($_.Exception.Message)"
    $code = 1
    if ($M3.mode -in 'm3-broker', 'm3-consent', 'm3-uac' -and (Get-VmState) -eq 'running') {
        # Keep what the guest has so far (the scorer fails the missing rows).
        $script:M3Fail = $true
        try { Complete-M3Sec (Get-M3SecBase $M3.mode $M3.base) @{ aborted = $_.Exception.Message } } catch { Write-RigLog "  !! partial evidence: $($_.Exception.Message)" }
    }
} finally {
    try {
        Write-RigLog 'power off and restore rig-base (left off)'
        if ((Get-VmState) -in 'running', 'paused', 'stuck') { $null = Invoke-VBox @('controlvm', $M3Vm, 'poweroff'); $null = Wait-VmState @('poweroff', 'aborted') 120 }
        Start-Sleep -Seconds 3
        $r = Invoke-VBox @('snapshot', $M3Vm, 'restore', 'rig-base')
        if ($r.code -ne 0) { Write-RigLog "  !! restore rig-base: $($r.out -join ' ')" }
    } catch { Write-RigLog "  !! cleanup: $($_.Exception.Message)" }
}
if ($script:M3Fail -and $code -eq 0) { $code = 1 }
Stop-M3 $code "rig-m3 done, exit $code"
