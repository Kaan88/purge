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
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'snapshot', 'probe')] [string] $Mode = 'all',
    [string] $Evidence = 'E:\purge-build\gate-evidence\m3-rig-uac',
    [switch] $Rebuild
)
$ErrorActionPreference = 'Stop'

# rig.ps1 has parameters of its own (Mode, ...): ours are kept here first.
$M3 = [ordered]@{ mode = $Mode; evidence = $Evidence; rebuild = [bool]$Rebuild }
$M3Vm = 'Inbound-Win11-Test'
$M3Snap = 'm3-uac-on'
. (Join-Path $PSScriptRoot 'rig.ps1') -VmName $M3Vm

# Set 1 scancodes (make, break) sent with controlvm keyboardputscancode.
$M3Keys = [ordered]@{
    'alt-y'      = @('38', '15', '95', 'b8')
    'alt-n'      = @('38', '31', 'b1', 'b8')
    'esc'        = @('01', '81')
    'left-enter' = @('e0', '4b', 'e0', 'cb', '1c', '9c')
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

# ------------------------------------------------------------------------------------------------- main

New-Item -ItemType Directory -Force $M3.evidence | Out-Null
$script:RigLogFile = Join-Path $M3.evidence ("rig-m3-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Write-RigLog "rig-m3 mode=$($M3.mode) vm=$M3Vm evidence=$($M3.evidence)"
Assert-M3Start
$code = 0
try {
    if ($M3.mode -in 'all', 'snapshot') { Invoke-M3Snapshot }
    if ($M3.mode -in 'all', 'probe') { Invoke-M3Probe }
} catch {
    Write-RigLog "!! $($_.Exception.Message)"
    $code = 1
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
