<#
  Purge rig, M3 mode m3-clean-start (vm\RIG.md section 15; docs\M3_DESIGN.md 11.2 row m3-clean-start, 12 G11 "Starts on
  clean Windows", 9.1 "VM: functional only; WARP numbers reported"; docs\M3_FINISH_PLAN.md B9). Host driver, Windows
  PowerShell 5.1; dot-sources rig.ps1 (-VmName Purge-CleanPro) for the VM helpers and changes neither rig.ps1 nor
  rig-m3.ps1. Guest side vm\guest\m3-clean.ps1, scorer vm\truth\m3-clean-score.ps1.

    $env:VMPWFILE = 'C:\path\to\pw.txt'
    powershell -NoProfile -ExecutionPolicy Bypass -File install\inno\build-installer.ps1      # on the gate commit
    .\vm\rig-m3-clean.ps1 -Setup target\installer\Purge-Setup-0.1.0.exe [-Run <name>] [-BenchRuns 6] [-NoMotw]
    powershell -NoProfile -File vm\truth\m3-clean-score.ps1 -Evidence E:\purge-build\gate-evidence\m3-clean-start\<run>

  The gate takes a setup built from the gate commit by install\inno\build-installer.ps1 (the script does not build it;
  it records the setup's SHA-256 and this checkout's HEAD in summary.json, and the scorer checks that the guest ran
  that very file).

  One boot of Purge-CleanPro rig-base (never Inbound-Win11-Test: that VM has had runtimes and apps installed for other
  modes; Clean-Pro rig-base is the clean Windows of the design). Phases (guest\m3-clean.ps1): pre (no .NET, no Windows
  App Runtime, no VC++ redistributable; SmartScreen / Smart App Control / Defender / UAC recorded), install 1 (silent,
  elevated; layout, owners, install.ps1 -Check, data root, event source, ARP entry), ui-start (Purge.exe at medium; UI
  Automation finds the list ProgramList with the machine's ARP names; screenshot ui-names), ui-stop, bench (WARP
  numbers, report only), uninstall-no (the Installed-apps entry, silent; data root kept), install 2, uninstall-yes
  (the data-folder question answered Yes by UI Automation; screenshot of the dialog), rollback (a planted junction
  fails the post-install step; the setup must leave nothing). Then the guest tree is zipped and pulled, the VM is
  powered off and rig-base restored (left off).

  Evidence: -Evidence (default E:\purge-build\gate-evidence\m3-clean-start)\<run> (default run name: the start time,
  yyyyMMdd-HHmmss; an existing non-empty run directory is refused): rig-m3-clean-<stamp>.log, *.png, jobs\*.log, guest\
  (the guest's C:\cr\out\m3-clean\), summary.json.

  Refuses (exit 2) unless VMPWFILE names a readable file, -Setup names a Purge-Setup-*.exe, the VM is Purge-CleanPro and
  exists, no VirtualBox VM is running (one VM at a time), and the lock vm\runs\.lock-Purge-CleanPro is free. Exit 0 when
  every step ran (the verdict is the scorer's), 1 when a step failed.
#>
[CmdletBinding()]
param(
    [string] $Setup = '',
    [string] $Evidence = 'E:\purge-build\gate-evidence\m3-clean-start',
    [string] $Run = '',
    [int] $BenchRuns = 6,
    [string] $Base = 'rig-base',
    # Skip the mark of the web (Zone.Identifier ZoneId=3) and the interactive SmartScreen start.
    [switch] $NoMotw
)
$ErrorActionPreference = 'Stop'

# rig.ps1 has parameters of its own (Mode, Engine, Snapshot, ...): ours are kept here first. The VM is fixed.
$MC = [ordered]@{ setup = $Setup; evidence_root = $Evidence; run = $Run; bench = $BenchRuns; base = $Base; vm = 'Purge-CleanPro'; no_motw = [bool]$NoMotw }
# Set 1 scancodes (make, break) for controlvm keyboardputscancode.
$M3CleanKeys = @{ 'esc' = @('01', '81') }
. (Join-Path $PSScriptRoot 'rig.ps1') -VmName $MC.vm

$script:MCLock = $null
$script:MCLines = New-Object System.Collections.ArrayList
$script:MCShots = New-Object System.Collections.ArrayList
$script:MCFail = $false

# ------------------------------------------------------------------------------------------------- pure helpers

# The only VM this mode runs on (the design's clean Windows); anything else throws.
function Assert-M3CleanVm([string]$Name) {
    if ($Name -cne 'Purge-CleanPro') { throw "m3-clean-start runs on Purge-CleanPro only (got '$Name'; never Inbound-Win11-Test)" }
}

# A setup built by install\inno\build-installer.ps1: target\installer\Purge-Setup-<version>.exe. Returns the full path.
function Resolve-M3CleanSetup([string]$Path) {
    if (-not $Path) { throw '-Setup is required: build it from the gate commit with install\inno\build-installer.ps1 and pass target\installer\Purge-Setup-<version>.exe' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "setup not found: $Path" }
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    if ((Split-Path -Leaf $full) -notmatch '^Purge-Setup-\d+(\.\d+){1,3}\.exe$') { throw "not a Purge setup (Purge-Setup-<version>.exe): $full" }
    $full
}

# The run name: given, or the start time; letters, digits, '.', '_' and '-' only.
function Get-M3CleanRunName([string]$Given, [datetime]$Now = (Get-Date)) {
    $n = $(if ($Given) { $Given } else { $Now.ToString('yyyyMMdd-HHmmss') })
    if ($n -notmatch '^[A-Za-z0-9_.-]+$') { throw "bad run name '$n'" }
    $n
}

# The job text of one guest phase of m3-clean.ps1.
function New-M3CleanPhaseText([string]$Phase, [string]$Tag = '', [int]$WaitSec = 120) {
    foreach ($v in $Phase, $Tag) { if ("$v" -notmatch '^[A-Za-z0-9_-]*$') { throw "bad phase argument '$v'" } }
    $t = "& 'C:\cr\guest\m3-clean.ps1' -Phase '$Phase'"
    if ($Tag) { $t += " -Tag '$Tag'" }
    $t + " -WaitSec $WaitSec"
}

# The host's order of guest phases (name, tag, wait, timeout, keys the host types before it, screenshot after it). One
# list: the driver runs it and the self-test checks it against the guest script's phases. Without -NoMotw the setup gets
# a mark of the web and one interactive start (motw-start: screenshot of what SmartScreen shows; Esc twice closes the
# SmartScreen dialog or the UAC prompt; motw-end stops what is left) before the silent install.
function Get-M3CleanSteps([int]$Bench = 6, [switch]$NoMotw) {
    @(
        [ordered]@{ phase = 'pre'; tag = ''; wait = 60; timeout = 600; shot = 'pre' }
        if (-not $NoMotw) {
            [ordered]@{ phase = 'motw-start'; tag = ''; wait = 60; timeout = 600; shot = 'motw-interactive' }
            [ordered]@{ phase = 'motw-end'; tag = ''; wait = 60; timeout = 600; keys = @('esc', 'esc'); shot = 'motw-end' }
        }
        [ordered]@{ phase = 'install'; tag = '1'; wait = 900; timeout = 1800; shot = 'install-1' }
        [ordered]@{ phase = 'ui-start'; tag = ''; wait = 90; timeout = 600; shot = 'ui-names' }
        [ordered]@{ phase = 'ui-stop'; tag = ''; wait = 30; timeout = 300; shot = '' }
        [ordered]@{ phase = 'bench'; tag = "$Bench"; wait = 60; timeout = 300 + 90 * $Bench; shot = '' }
        [ordered]@{ phase = 'uninstall-no'; tag = ''; wait = 600; timeout = 1500; shot = 'uninstall-no' }
        [ordered]@{ phase = 'install'; tag = '2'; wait = 900; timeout = 1800; shot = 'install-2' }
        [ordered]@{ phase = 'uninstall-yes-start'; tag = ''; wait = 90; timeout = 600; shot = 'uninstall-yes-dialog' }
        [ordered]@{ phase = 'uninstall-yes-answer'; tag = ''; wait = 300; timeout = 900; shot = 'uninstall-yes-done' }
        [ordered]@{ phase = 'rollback'; tag = ''; wait = 900; timeout = 1800; shot = 'rollback' }
    )
}

# ------------------------------------------------------------------------------------------------- VM steps

function Stop-M3Clean([int]$Code, [string]$Why) {
    Write-RigLog $Why
    if ($script:MCLock) { $script:MCLock.Dispose(); $script:MCLock = $null }
    Remove-PwTemp
    exit $Code
}

function Assert-M3CleanStart {
    if (-not $env:VMPWFILE -or -not (Test-Path -LiteralPath $env:VMPWFILE -PathType Leaf)) { Stop-M3Clean 2 'REFUSED: $env:VMPWFILE does not name a readable file' }
    try { Assert-M3CleanVm $MC.vm; $MC.setup = Resolve-M3CleanSetup $MC.setup } catch { Stop-M3Clean 2 "REFUSED: $($_.Exception.Message)" }
    $vms = (Invoke-VBox @('list', 'vms')).out -join "`n"
    if ($vms -notmatch ('"' + [regex]::Escape($MC.vm) + '"')) { Stop-M3Clean 2 "REFUSED: VM $($MC.vm) not found" }
    $running = @((Invoke-VBox @('list', 'runningvms')).out | Where-Object { "$_".Trim() })
    if ($running.Count) { Stop-M3Clean 2 "REFUSED: a VM is running ($($running -join '; ')); one VM at a time" }
    New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
    try { $script:MCLock = [IO.File]::Open((Join-Path $script:RunsDir ".lock-$($MC.vm)"), 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { Stop-M3Clean 2 "REFUSED: another rig script holds the lock for $($MC.vm)" }
}

function Push-M3CleanFiles {
    foreach ($d in 'C:\cr\guest', 'C:\cr\m3clean', 'C:\cr\out') { $null = Invoke-Guest @('mkdir', '--parents', $d) }
    $files = @('riglib.ps1', 'm3-clean.ps1') | ForEach-Object { Join-Path $script:RigDir "guest\$_" }
    $r = Invoke-Guest (@('copyto', '--target-directory', 'C:\cr\guest\') + $files)
    if ($r.code -ne 0) { throw "copy guest scripts failed: $($r.out -join ' ')" }
    $null = Invoke-GuestCmd 'del /f /q C:\cr\m3clean\Purge-Setup-*.exe'
    $r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\m3clean\', $MC.setup)
    if ($r.code -ne 0) { throw "copy setup failed: $($r.out -join ' ')" }
    Write-RigLog "  pushed riglib.ps1, m3-clean.ps1, $(Split-Path -Leaf $MC.setup)"
}

function Invoke-M3CleanPhase($Step) {
    $name = "clean-$($Step.phase)$(if ($Step.tag) { "-$($Step.tag)" })"
    $jobs = Join-Path $MC.evidence 'jobs'
    New-Item -ItemType Directory -Force $jobs | Out-Null
    $j = Invoke-GuestJob -Text (New-M3CleanPhaseText $Step.phase $Step.tag $Step.wait) -Name $name -TimeoutSec $Step.timeout -LogCopy (Join-Path $jobs "$name-$(Get-Date -Format 'HHmmss').log")
    $lines = @("$($j.log)" -split "`r?`n" | Where-Object { $_ -match '^M3C ' })
    foreach ($l in $lines) { Write-RigLog "  $l"; [void]$script:MCLines.Add($l) }
    if (-not $j.done) { Write-RigLog "  !! phase $name did not finish within $($Step.timeout) s"; $script:MCFail = $true }
    elseif (-not $lines.Count) { Write-RigLog "  !! phase $name wrote no result line; log: $($j.log_file)"; $script:MCFail = $true }
    $lines
}

function Save-M3CleanShot([string]$Name) {
    $f = Join-Path $MC.evidence "$Name.png"
    # screenshotpng fails (E_FAIL) while the guest display is off: retry after a Shift tap that wakes it.
    for ($try = 1; $try -le 3; $try++) {
        $r = Invoke-VBox @('controlvm', $MC.vm, 'screenshotpng', $f)
        $ok = ($r.code -eq 0 -and (Test-Path -LiteralPath $f))
        if ($ok) { break }
        $null = Invoke-VBox @('controlvm', $MC.vm, 'keyboardputscancode', '2a', 'aa')
        Start-Sleep -Seconds 2
    }
    if ($ok) { Write-RigLog "  screenshot $Name.png ($((Get-Item $f).Length) bytes)" } else { Write-RigLog "  !! screenshot $Name failed: $($r.out -join ' ')" }
    [void]$script:MCShots.Add([ordered]@{ name = $Name; file = $(if ($ok) { "$Name.png" }); bytes = $(if ($ok) { (Get-Item $f).Length } else { 0 }); t = (Get-Date).ToString('o') })
}

function Complete-M3Clean([hashtable]$Extra = @{}) {
    $zip = Join-Path $MC.evidence 'guest.zip'
    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
    $c = Invoke-Guest @('copyfrom', 'C:\cr\out\m3-clean.zip', $zip)
    if ($c.code -eq 0 -and (Test-Path -LiteralPath $zip)) {
        $g = Join-Path $MC.evidence 'guest'
        if (Test-Path -LiteralPath $g) { Remove-Item -LiteralPath $g -Recurse -Force }
        Expand-Archive -LiteralPath $zip -DestinationPath $g
        Remove-Item -LiteralPath $zip -Force
        Write-RigLog "  guest outputs in $g"
    } else { Write-RigLog "  !! copyfrom of the guest zip failed: $($c.out -join ' ')"; $script:MCFail = $true }
    $head = $null
    try { $head = (& git -C $script:RepoRoot rev-parse HEAD 2>$null) } catch { }
    $setupFile = Get-Item -LiteralPath $MC.setup
    $sum = [ordered]@{ schema = 'purge.rig.m3clean.summary/1'; mode = 'm3-clean-start'; vm = $MC.vm; snapshot = $MC.base; run = $MC.run
                       setup = [ordered]@{ path = $MC.setup; name = $setupFile.Name; bytes = $setupFile.Length; sha256 = (Get-FileHash -LiteralPath $MC.setup -Algorithm SHA256).Hash
                                           built = $setupFile.LastWriteTime.ToString('o') }
                       repo_head = "$head"; bench_runs = $MC.bench; motw = (-not $MC.no_motw); started = $script:MCStarted; ended = (Get-Date).ToString('o')
                       failed_step = $script:MCFail; shots = $script:MCShots; lines = $script:MCLines }
    foreach ($k in $Extra.Keys) { $sum[$k] = $Extra[$k] }
    [IO.File]::WriteAllText((Join-Path $MC.evidence 'summary.json'), (ConvertTo-Json $sum -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
    Write-RigLog "summary: $(Join-Path $MC.evidence 'summary.json')"
}

function Invoke-M3CleanStart {
    Write-RigLog "m3-clean-start from $($MC.vm) $($MC.base); setup $($MC.setup)"
    Restore-Base -Snapshot $MC.base
    Push-M3CleanFiles
    foreach ($s in Get-M3CleanSteps $MC.bench -NoMotw:$MC.no_motw) {
        foreach ($k in @($s['keys'] | Where-Object { $_ })) {
            $codes = $M3CleanKeys[$k]
            $r = Invoke-VBox (@('controlvm', $MC.vm, 'keyboardputscancode') + $codes)
            Write-RigLog "  keyboardputscancode $k ($($codes -join ' ')): exit $($r.code)"
            Start-Sleep -Seconds 3
        }
        $null = Invoke-M3CleanPhase $s
        if ($s.shot) { Start-Sleep -Seconds 2; Save-M3CleanShot $s.shot }
    }
    $null = Invoke-M3CleanPhase ([ordered]@{ phase = 'pack'; tag = ''; wait = 60; timeout = 600 })
    Complete-M3Clean
}

# ------------------------------------------------------------------------------------------------- main

# Dot-sourced (the rig self-test): the functions only.
if ($MyInvocation.InvocationName -eq '.') { return }

try { $MC.run = Get-M3CleanRunName $MC.run } catch { Write-Host "REFUSED: $($_.Exception.Message)"; exit 2 }
$MC.evidence = Join-Path $MC.evidence_root $MC.run
if ((Test-Path -LiteralPath $MC.evidence) -and @(Get-ChildItem -LiteralPath $MC.evidence -Force -ErrorAction SilentlyContinue).Count) {
    Write-Host "REFUSED: the evidence directory $($MC.evidence) exists and is not empty (pick another -Run)"; exit 2
}
New-Item -ItemType Directory -Force $MC.evidence | Out-Null
$script:RigLogFile = Join-Path $MC.evidence ("rig-m3-clean-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Write-RigLog "rig-m3-clean vm=$($MC.vm) base=$($MC.base) evidence=$($MC.evidence)"
Assert-M3CleanStart
$script:MCStarted = (Get-Date).ToString('o')
$code = 0
try {
    Invoke-M3CleanStart
} catch {
    $err = $_.Exception.Message
    Write-RigLog "!! $err"
    $code = 1
    $script:MCFail = $true
    if ((Get-VmState) -eq 'running') {
        # Keep what the guest has so far (the scorer fails the missing rows).
        try {
            $null = Invoke-M3CleanPhase ([ordered]@{ phase = 'pack'; tag = ''; wait = 60; timeout = 600 })
            Complete-M3Clean @{ aborted = $err }
        } catch { Write-RigLog "  !! partial evidence: $($_.Exception.Message)" }
    }
} finally {
    try {
        Write-RigLog "power off and restore $($MC.base) (left off)"
        if ((Get-VmState) -in 'running', 'paused', 'stuck') { $null = Invoke-VBox @('controlvm', $MC.vm, 'poweroff'); $null = Wait-VmState @('poweroff', 'aborted') 120 }
        Start-Sleep -Seconds 3
        $r = Invoke-VBox @('snapshot', $MC.vm, 'restore', $MC.base)
        if ($r.code -ne 0) { Write-RigLog "  !! restore $($MC.base): $($r.out -join ' ')" }
    } catch { Write-RigLog "  !! cleanup: $($_.Exception.Message)" }
}
if ($script:MCFail -and $code -eq 0) { $code = 1 }
Stop-M3Clean $code "rig-m3-clean done, exit $code; score: powershell -NoProfile -File vm\truth\m3-clean-score.ps1 -Evidence $($MC.evidence)"
