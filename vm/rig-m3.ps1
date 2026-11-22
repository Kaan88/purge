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
  this checkout; the rig-exec engine is refused by install.ps1) and -UiPublish (default target\ui-publish; m3-uac's
  cancelled-bar row needs it), installs them with install\install.ps1 and runs one boot of the snapshot:

    .\vm\rig-m3.ps1 -Mode m3-broker  -Engine <dir>\purge-engine.exe -Broker <dir>\purge-broker.exe            # rig-base
    .\vm\rig-m3.ps1 -Mode m3-consent -Engine ... -Broker ...                                                    # rig-base
    .\vm\rig-m3.ps1 -Mode m3-uac     -Engine ... -Broker ... -UiPublish <dir>\ui-publish                       # m3-uac-on
    powershell -File vm\truth\m3-sec-score.ps1 -Mode broker|consent|uac -Evidence <dir>

  -Cases limits m3-broker to some case ids of vm\truth\m3-sec-expect.json; -Base overrides the snapshot; -StdUserKeys
  picks what the host types at m3-uac's credential prompt (password, or user-tab-password: "tester", Tab, password).
  Evidence default: E:\purge-build\gate-evidence\<mode>\ (an existing non-empty one is moved aside first, so the
  scorer never reads an older run): rig-m3-<stamp>.log, *.png, jobs\*.log, guest\ (C:\cr\out\m3-sec\), summary.json.

  M3 end to end (vm\RIG.md section 17; M3_DESIGN.md 11.2 row m3-e2e, gate G6, G7, G12; M3_FINISH_PLAN.md B7). Guest
  side vm\guest\m3-e2e.ps1 (phases), m3-e2e-ui.ps1 (the UI Automation driver), m3-e2e-msi.ps1 (the 1603 / 3010 MSI
  fixtures); expectations vm\truth\m3-e2e-expect.json; scorer vm\truth\m3-e2e-score.ps1. One boot of rig-base per app
  (UAC silent in design 11.2; a prompt that comes up is answered by scancode), the real UI installed as C:\Program Files\Purge\Purge.exe, every step driven through the UI:

    .\vm\rig-m3.ps1 -Mode m3-e2e -Engine ... -Broker ... -UiPublish <dir>\ui-publish [-Apps npp,msi1603] [-UndoApps npp]
                    [-RunName <name>] [-UacOn]
    powershell -File vm\truth\m3-e2e-score.ps1 -Evidence E:\purge-build\gate-evidence\m3-e2e\<run> -Collect

  -UacOn boots m3-uac-on instead and answers each UAC prompt from the host by scancode (Alt+Y, then Left+Enter), with
  screenshots. Evidence: E:\purge-build\gate-evidence\m3-e2e\<run>\ (run = -RunName or e2e-<stamp>): summary.json,
  rig-m3-<stamp>.log, and per app <app>\ (NN-<step>.png, jobs\*.log, host.json, guest\ = C:\cr\out\m3-e2e\<app>\).
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'snapshot', 'probe', 'm3-broker', 'm3-consent', 'm3-uac', 'm3-e2e')] [string] $Mode = 'all',
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
    [switch] $UacOn
)
$ErrorActionPreference = 'Stop'

# rig.ps1 has parameters of its own (Mode, Engine, ...): ours are kept here first.
if (-not $RunName) { $RunName = 'e2e-' + (Get-Date -Format 'yyyyMMdd-HHmmss') }
if ($RunName -notmatch '^[A-Za-z0-9_.-]+$') { throw "bad -RunName '$RunName'" }
if (-not $Evidence) {
    $Evidence = $(if ($Mode -eq 'm3-e2e') { "E:\purge-build\gate-evidence\m3-e2e\$RunName" } elseif ($Mode -like 'm3-*') { "E:\purge-build\gate-evidence\$Mode" } else { 'E:\purge-build\gate-evidence\m3-rig-uac' })
}
$M3 = [ordered]@{ mode = $Mode; evidence = $Evidence; rebuild = [bool]$Rebuild; engine = $Engine; broker = $Broker; ui = $UiPublish
                  cases = @($Cases | Where-Object { $_ }); base = $Base; std_keys = $StdUserKeys
                  apps = @($Apps | ForEach-Object { "$_" -split ',' } | Where-Object { $_ }); undo_apps = @($UndoApps | ForEach-Object { "$_" -split ',' } | Where-Object { $_ })
                  run = $RunName; uac_on = [bool]$UacOn }
$M3Vm = 'Inbound-Win11-Test'
$M3Snap = 'm3-uac-on'
. (Join-Path $PSScriptRoot 'rig.ps1') -VmName $M3Vm

# Set 1 scancodes (make, break) sent with controlvm keyboardputscancode.
$M3Keys = [ordered]@{
    'alt-y'      = @('38', '15', '95', 'b8')
    'alt-n'      = @('38', '31', 'b1', 'b8')
    'esc'        = @('01', '81')
    'left-enter' = @('e0', '4b', 'e0', 'cb', '1c', '9c')
    'enter'      = @('1c', '9c')
    'tab'        = @('0f', '8f')
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

# The release artifacts the guest installs (install.ps1 -SkipBuild): purge-engine.exe, purge-broker.exe, kb\ and, when
# given, ui\ (the UI publish folder). Returns the zip path in the host temp directory.
function New-M3SecPayload {
    $engine = $(if ($M3.engine) { $M3.engine } else { Join-Path $script:RepoRoot 'target\release\purge-engine.exe' })
    $broker = $(if ($M3.broker) { $M3.broker } else { Join-Path $script:RepoRoot 'target\release\purge-broker.exe' })
    $ui = $(if ($M3.ui) { $M3.ui } else { Join-Path $script:RepoRoot 'target\ui-publish' })
    foreach ($f in @(@($engine, 'purge-engine.exe'), @($broker, 'purge-broker.exe'))) {
        if (-not (Test-Path -LiteralPath $f[0] -PathType Leaf)) { throw "missing $($f[0]) (cargo build --release -p $([IO.Path]::GetFileNameWithoutExtension($f[1])), or pass -Engine / -Broker)" }
        if ((Split-Path -Leaf $f[0]) -ne $f[1]) { throw "the file must be named $($f[1]): $($f[0])" }
    }
    $stage = Join-Path (Get-HostTemp) "m3sec-payload-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    New-Item -ItemType Directory -Force $stage | Out-Null
    Copy-Item -LiteralPath $engine, $broker -Destination $stage
    Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'kb') -Destination (Join-Path $stage 'kb') -Recurse
    $hasUi = Test-Path -LiteralPath (Join-Path $ui 'Purge.exe') -PathType Leaf
    if ($hasUi) { Copy-Item -LiteralPath $ui -Destination (Join-Path $stage 'ui') -Recurse }
    else { Write-RigLog "  no UI publish folder at ${ui}: m3-uac's cancelled-bar row will have no evidence (the scorer fails it)" }
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
    Assert-M3SecUac $u $(if ($M3.mode -eq 'm3-uac') { 5 } else { 0 })
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
    $sum = [ordered]@{ schema = 'purge.rig.m3sec.summary/1'; mode = $M3.mode; vm = $M3Vm; snapshot = $Base; started = $script:M3Started
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

# Pure: the job text of one guest phase of m3-e2e.ps1.
function New-M3E2ePhaseText([string]$Phase, [string]$App, [string]$Step = '', [int]$WaitSec = 0) {
    foreach ($v in $Phase, $App, $Step) { if ("$v" -notmatch '^[A-Za-z0-9_-]*$') { throw "bad phase argument '$v'" } }
    if (-not $Phase -or -not $App) { throw 'a phase and an app are needed' }
    $t = "& 'C:\cr\guest\m3-e2e.ps1' -Phase '$Phase' -App '$App'"
    if ($Step) { $t += " -Step '$Step'" }
    if ($WaitSec) { $t += " -WaitSec $WaitSec" }
    $t
}

# Pure: the screenshot names an app's flow takes, in order (the scorer requires the same list, expectations
# required_shots). Broker route: the uninstall consent; success flows: move, plan consent, result; undo app: undo.
function Get-M3E2eShotNames($AppDef, [bool]$Undo) {
    $n = @('01-programs-row', '02-uninstall-clicked', '03-confirm')
    if ("$($AppDef.route)" -eq 'broker') { $n += '04-consent-run', '05-run-approved' }
    $n += '06-scan-done'
    if ("$($AppDef.kind)" -like 'fail-*') { return @($n + '07-failure') }
    $n += '07-move-waiting', '08-consent-plan', '09-result'
    if ($Undo) { $n += '10-undo-waiting', '11-consent-undo', '12-undone' }
    $n
}

function Invoke-M3E2ePhase([string]$Phase, [string]$App, [string]$Step = '', [int]$WaitSec = 0, [int]$TimeoutSec = 900) {
    $name = "e2e-$Phase$(if ($Step) { "-$Step" })"
    $jobs = Join-Path $script:E2eDir 'jobs'
    New-Item -ItemType Directory -Force $jobs | Out-Null
    $j = Invoke-GuestJob -Text (New-M3E2ePhaseText $Phase $App $Step $WaitSec) -Name "$App-$name" -TimeoutSec $TimeoutSec -LogCopy (Join-Path $jobs "$name-$(Get-Date -Format 'HHmmss').log")
    $lines = @("$($j.log)" -split "`r?`n" | Where-Object { $_ -match '^M3E ' })
    foreach ($l in $lines) { Write-RigLog "  $l"; [void]$script:E2eLines.Add($l) }
    if (-not $j.done) { Write-RigLog "  !! phase $name did not finish within $TimeoutSec s"; $script:M3Fail = $true }
    elseif (-not $lines.Count) { Write-RigLog "  !! phase $name wrote no result line; log: $($j.log_file)"; $script:M3Fail = $true }
    "$(@($lines) | Select-Object -First 1)"
}

function Save-M3E2eShot([string]$Name) {
    $f = Join-Path $script:E2eDir "$Name.png"
    $r = Invoke-VBox @('controlvm', $M3Vm, 'screenshotpng', $f)
    $ok = ($r.code -eq 0 -and (Test-Path -LiteralPath $f))
    if ($ok) { Write-RigLog "  screenshot $Name.png ($((Get-Item $f).Length) bytes)" } else { Write-RigLog "  !! screenshot $Name failed: $($r.out -join ' ')" }
    [void]$script:E2eShots.Add([ordered]@{ name = $Name; file = $(if ($ok) { "$Name.png" }); bytes = $(if ($ok) { (Get-Item $f).Length } else { 0 }); t = (Get-Date).ToString('o') })
}

# The UAC prompt on the secure desktop, when one is up: screenshot, Alt+Y (Left+Enter only while it is still up),
# screenshot. Returns the keys sent (empty when no prompt was up).
function Invoke-M3E2eUac([string]$Tag) {
    $sent = @()
    $d = (Get-Date).AddSeconds(10)
    while (-not (Test-M3ConsentUp) -and (Get-Date) -lt $d) { Start-Sleep -Seconds 1 }
    if (-not (Test-M3ConsentUp)) { return $sent }
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

function Push-M3E2eFiles($AppDef) {
    $engine = $(if ($M3.engine) { $M3.engine } else { Join-Path $script:RepoRoot 'target\release\purge-engine.exe' })
    $inst = @()
    if ("$($AppDef.kind)" -eq 'app') { $inst = @(Get-CachedRunFiles -Id "$($AppDef.id)") }
    Push-Tools -Engine $engine -Installers $inst
    Push-M2Install
    $null = Push-M2Ambient
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

# One app: one boot of the base snapshot, the whole flow through the UI, the evidence pulled to <evidence>\<app>\.
function Invoke-M3E2eApp($AppDef, [bool]$Undo, [string]$Base) {
    $id = "$($AppDef.id)"
    $script:E2eDir = Join-Path $M3.evidence $id
    New-Item -ItemType Directory -Force $script:E2eDir | Out-Null
    $script:E2eShots = New-Object System.Collections.ArrayList
    $script:E2eLines = New-Object System.Collections.ArrayList
    $rec = [ordered]@{ app = $id; kind = "$($AppDef.kind)"; undo = $Undo; base = $Base; started = (Get-Date).ToString('o'); ended = $null; error = $null
                       uac_keys = [ordered]@{}; shots = $script:E2eShots; lines = $script:E2eLines; pulled = $false }
    Write-RigLog "m3-e2e app $id ($($AppDef.kind), route $($AppDef.route)$(if ($Undo) { ', undo' })) from $Base"
    $booted = $false
    try {
        Restore-Base -Snapshot $Base -No3D
        $booted = $true
        Push-M3E2eFiles $AppDef
        $l = Invoke-M3E2ePhase 'setup' $id -TimeoutSec 1200
        if ($l -notmatch '^M3E SETUP OK') { throw "setup failed: $l" }
        $l = Invoke-M3E2ePhase 'prepare' $id -TimeoutSec 5400
        if ((Get-M3E2eField $l 'ok') -ne 'True') { throw "prepare failed: $l" }
        $null = Invoke-M3E2ePhase 'ui-start' $id -TimeoutSec 900
        Save-M3E2eShot '01-programs-row'
        $l = Invoke-M3E2ePhase 'ui-uninstall' $id -TimeoutSec 900
        Save-M3E2eShot '02-uninstall-clicked'
        $rec.uac_keys.run = @(Invoke-M3E2eUac '02u-uac')
        $null = Invoke-M3E2ePhase 'ui-await-confirm' $id -WaitSec 300 -TimeoutSec 900
        Save-M3E2eShot '03-confirm'
        $l = Invoke-M3E2ePhase 'ui-confirm' $id -TimeoutSec 600
        if ((Get-M3E2eField $l 'route') -eq 'broker') {
            $null = Invoke-M3E2ePhase 'consent-wait' $id 'run' -WaitSec 300 -TimeoutSec 900
            Save-M3E2eShot '04-consent-run'
            $null = Invoke-M3E2ePhase 'consent-approve' $id 'run' -TimeoutSec 600
            Save-M3E2eShot '05-run-approved'
        }
        $l = Invoke-M3E2ePhase 'ui-wait-scan' $id -WaitSec 2400 -TimeoutSec 3300
        Save-M3E2eShot '06-scan-done'
        $state = Get-M3E2eField $l 'state'
        if ("$($AppDef.kind)" -like 'fail-*') {
            $null = Invoke-M3E2ePhase 'fail-check' $id -TimeoutSec 600
            Save-M3E2eShot '07-failure'
        } elseif ($state -in 'review', 'empty') {
            $null = Invoke-M3E2ePhase 'capture-post' $id -TimeoutSec 5400
            if ($state -eq 'review') {
                $null = Invoke-M3E2ePhase 'ui-move' $id -TimeoutSec 1200
                Save-M3E2eShot '07-move-waiting'
                $rec.uac_keys.plan = @(Invoke-M3E2eUac '07u-uac')
                $null = Invoke-M3E2ePhase 'consent-wait' $id 'plan' -WaitSec 300 -TimeoutSec 900
                Save-M3E2eShot '08-consent-plan'
                $null = Invoke-M3E2ePhase 'consent-approve' $id 'plan' -TimeoutSec 600
                $null = Invoke-M3E2ePhase 'ui-wait-result' $id -WaitSec 1800 -TimeoutSec 2400
                Save-M3E2eShot '09-result'
                $null = Invoke-M3E2ePhase 'capture-exec' $id -TimeoutSec 5400
                if ($Undo) {
                    $null = Invoke-M3E2ePhase 'ui-undo' $id -TimeoutSec 900
                    Save-M3E2eShot '10-undo-waiting'
                    $rec.uac_keys.undo = @(Invoke-M3E2eUac '10u-uac')
                    $null = Invoke-M3E2ePhase 'consent-wait' $id 'undo' -WaitSec 300 -TimeoutSec 900
                    Save-M3E2eShot '11-consent-undo'
                    $null = Invoke-M3E2ePhase 'consent-approve' $id 'undo' -TimeoutSec 600
                    $null = Invoke-M3E2ePhase 'ui-wait-undone' $id -WaitSec 1800 -TimeoutSec 2400
                    Save-M3E2eShot '12-undone'
                    $null = Invoke-M3E2ePhase 'capture-undo' $id -TimeoutSec 3600
                }
            }
        } else { Write-RigLog "  !! $id`: the scan ended '$state'; nothing more to drive"; $script:M3Fail = $true }
    } catch {
        $rec.error = $_.Exception.Message
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
                    Remove-Item -LiteralPath $zip -Force
                    $rec.pulled = $true
                    Write-RigLog "  guest outputs in $g"
                } else { Write-RigLog "  !! copyfrom of the guest zip failed: $($c.out -join ' ')"; $script:M3Fail = $true }
            } catch { Write-RigLog "  !! finish of $id`: $($_.Exception.Message)"; $script:M3Fail = $true }
        }
        $rec.ended = (Get-Date).ToString('o')
        [IO.File]::WriteAllText((Join-Path $script:E2eDir 'host.json'), (ConvertTo-Json $rec -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
    }
    $rec
}

function Invoke-M3E2e {
    $ui = $(if ($M3.ui) { $M3.ui } else { Join-Path $script:RepoRoot 'target\ui-publish' })
    if (-not (Test-Path -LiteralPath (Join-Path $ui 'Purge.exe') -PathType Leaf)) { throw "m3-e2e needs the UI publish folder (-UiPublish; no Purge.exe in $ui)" }
    $base = $(if ($M3.base) { $M3.base } elseif ($M3.uac_on) { 'm3-uac-on' } else { 'rig-base' })
    if ($base -eq 'm3-uac-on' -and -not (Test-M3Snapshot)) { throw "snapshot $M3Snap missing (rig-m3.ps1 -Mode snapshot)" }
    $apps = @(Get-M3E2eApps -Only $M3.apps)
    $undo = @(Get-M3E2eUndoApps -Override $M3.undo_apps)
    $sum = [ordered]@{ schema = 'purge.rig.m3e2e.summary/1'; run = $M3.run; vm = $M3Vm; snapshot = $base; uac_on = $M3.uac_on; started = $script:M3Started
                       engine = $M3.engine; broker = $M3.broker; ui = $ui; apps_asked = @($apps | ForEach-Object { "$($_.id)" }); undo_apps = $undo; apps = @() }
    foreach ($a in $apps) {
        $sum.apps += Invoke-M3E2eApp $a ($undo -contains "$($a.id)") $base
        [IO.File]::WriteAllText((Join-Path $M3.evidence 'summary.json'), (ConvertTo-Json $sum -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
    }
    $sum.ended = (Get-Date).ToString('o')
    $sum.failed_step = $script:M3Fail
    [IO.File]::WriteAllText((Join-Path $M3.evidence 'summary.json'), (ConvertTo-Json $sum -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
    Write-RigLog "summary: $(Join-Path $M3.evidence 'summary.json'); score: powershell -File vm\truth\m3-e2e-score.ps1 -Evidence $($M3.evidence) -Collect"
}

# ------------------------------------------------------------------------------------------------- main

# Dot-sourced (the rig self-test): the functions only.
if ($MyInvocation.InvocationName -eq '.') { return }

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
