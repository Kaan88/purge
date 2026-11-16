<#
  Purge rig: builds the offline snapshot 'm2-base' (child of 'rig-base') on the Inbound VM, or verifies it.
  Uses rig.ps1's helpers (Invoke-VBox, Wait-Agent, Invoke-GuestJob, Wait-VmState); the guest side is
  guest\setup-m2.ps1, sent as an agent job (it is not copied to C:\cr\guest, so nothing else enters the snapshot).

    $env:VMPWFILE = 'C:\path\to\pw.txt'
    .\vm\setup-m2-base.ps1                       # build m2-base (refuses when it already exists)
    .\vm\setup-m2-base.ps1 -VerifyOnly           # restore m2-base, check, create a probe restore point, discard

  Build: power off -> restore rig-base -> create the data disk (2 GB dynamic VDI) if absent and attach it on the
  first free SATA port -> start headless -> wait for the agent -> setup-m2.ps1 -> setup-m2.ps1 -Check -> clean
  guest shutdown (ACPI power button; a guest 'shutdown /s' as fallback; never a hard power-off) -> snapshot take
  m2-base -> restore rig-base, so M1a campaigns find the VM as before. On any failure: hard power-off, restore
  rig-base, rethrow.
  Verify: power off -> restore m2-base -> start -> agent -> setup-m2.ps1 -Check -> probe job (D: facts,
  Get-ComputerRestorePoint, Checkpoint-Computer 'purge-rig-probe') -> power off -> restore m2-base (probe
  discarded) -> restore rig-base.
  The VM is left powered off with rig-base restored in both modes. Only $VmName is ever touched.
  -NoDataDisk: no data disk is created or attached and setup-m2.ps1 skips the D: part (System Restore only). For a
  VM whose M2 runs never use D: (Purge-CleanPro runs m2-traps and m2-fidelity; the D: stage is m2-install):
    .\vm\setup-m2-base.ps1 -VmName Purge-CleanPro -NoDataDisk
#>
[CmdletBinding()]
param(
    [string] $VmName = 'Inbound-Win11-Test',
    [switch] $VerifyOnly,
    [switch] $NoDataDisk,
    [string] $Parent = 'rig-base',
    [string] $SnapshotName = 'm2-base',
    [string] $DataDisk = 'E:\purge-vm\inbound-m2-data.vdi',
    [int] $DataDiskMB = 2048,
    [string] $Controller = 'SATA',
    [int] $AgentTimeoutSec = 900
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'rig.ps1') -VmName $VmName

function Get-SnapshotNames {
    $r = Invoke-VBox @('snapshot', $script:VmName, 'list', '--machinereadable')
    @($r.out | ForEach-Object { $m = [regex]::Match($_, '^SnapshotName(-[\d-]+)?="(.*)"$'); if ($m.Success) { $m.Groups[2].Value } })
}

# Hard power-off (only for states that are thrown away right after: failure, or the verify probe).
function Stop-VmHard {
    $st = Get-VmState
    if (@('running', 'paused', 'stuck', 'starting') -contains $st) {
        Write-RigLog "  power off ($st)"
        $null = Invoke-VBox @('controlvm', $script:VmName, 'poweroff')
        $null = Wait-VmState @('poweroff', 'aborted') 120
    }
}

function Restore-Snap([string]$Name) {
    Stop-VmHard
    $ok = $false
    for ($i = 1; $i -le 6 -and -not $ok; $i++) {
        $r = Invoke-VBox @('snapshot', $script:VmName, 'restore', $Name)
        if ($r.code -eq 0) { $ok = $true } else { Write-RigLog "  restore $Name try $i failed: $($r.out -join ' ')"; Start-Sleep -Seconds 3 }
    }
    if (-not $ok) { throw "snapshot restore $Name failed" }
    Write-RigLog "  restored $Name (VM state $(Get-VmState))"
}

function Start-VmAgent {
    $r = Invoke-VBox @('startvm', $script:VmName, '--type', 'headless')
    if ($r.code -ne 0) { throw "startvm failed: $($r.out -join ' ')" }
    $null = Wait-VmState @('running') 120
    Wait-Agent -TimeoutSec $AgentTimeoutSec
}

# Clean shutdown: ACPI power button, then (if the guest ignored it) 'shutdown /s /t 0' from the guest.
function Stop-VmClean {
    Write-RigLog '  clean shutdown (ACPI power button)'
    $null = Invoke-VBox @('controlvm', $script:VmName, 'acpipowerbutton')
    try { $null = Wait-VmState @('poweroff') 300; return } catch { Write-RigLog "  ACPI shutdown not done after 300 s: $($_.Exception.Message)" }
    Write-RigLog '  fallback: shutdown /s /t 0 in the guest'
    $null = Invoke-GuestCmd 'shutdown /s /t 0' 60
    $null = Wait-VmState @('poweroff') 300
}

# Pure: the first SATA port with nothing attached, from showvminfo --machinereadable.
function Get-FreePort {
    $info = ConvertFrom-MachineReadable (Invoke-VBox @('showvminfo', $script:VmName, '--machinereadable')).out
    $n = 0
    for ($i = 0; $i -lt 64; $i++) { if ($info["storagecontrollername$i"] -eq $Controller) { $n = [int]$info["storagecontrollerportcount$i"]; break } }
    if (-not $n) { throw "no storage controller '$Controller'" }
    for ($p = 0; $p -lt $n; $p++) { if ($info["$Controller-$p-0"] -eq 'none' -or -not $info.ContainsKey("$Controller-$p-0")) { return $p } }
    throw "no free port on $Controller"
}

# The data disk's port when it is attached to the current state, else -1.
function Get-DataDiskPort {
    $info = ConvertFrom-MachineReadable (Invoke-VBox @('showvminfo', $script:VmName, '--machinereadable')).out
    $leaf = [IO.Path]::GetFileName($DataDisk)
    foreach ($k in $info.Keys) {
        $m = [regex]::Match($k, "^$Controller-(\d+)-0$")
        if ($m.Success -and $info[$k] -and [IO.Path]::GetFileName($info[$k]) -ieq $leaf) { return [int]$m.Groups[1].Value }
    }
    -1
}

function Add-DataDisk {
    if (-not (Test-Path -LiteralPath $DataDisk)) {
        Write-RigLog "  create $DataDisk ($DataDiskMB MB, dynamic VDI)"
        $r = Invoke-VBox @('createmedium', 'disk', '--filename', $DataDisk, '--size', "$DataDiskMB", '--format', 'VDI', '--variant', 'Standard')
        if ($r.code -ne 0) { throw "createmedium failed: $($r.out -join ' ')" }
    } else {
        $r = Invoke-VBox @('showmediuminfo', 'disk', $DataDisk)
        $use = @($r.out | Where-Object { $_ -match '^In use by VMs:' })
        Write-RigLog "  $DataDisk exists$(if ($use) { ": $($use -join ' ')" })"
        if ($use -and ($use -join ' ') -notmatch [regex]::Escape($script:VmName)) { throw "$DataDisk is used by another VM: $($use -join ' ')" }
    }
    $port = Get-DataDiskPort
    if ($port -ge 0) { Write-RigLog "  data disk already on $Controller port $port"; return $port }
    $port = Get-FreePort
    $r = Invoke-VBox @('storageattach', $script:VmName, '--storagectl', $Controller, '--port', "$port", '--device', '0', '--type', 'hdd', '--medium', $DataDisk)
    if ($r.code -ne 0) { throw "storageattach failed: $($r.out -join ' ')" }
    Write-RigLog "  attached $DataDisk on $Controller port $port"
    $port
}

# Runs guest\setup-m2.ps1 (or -Check) as an agent job. Returns {exit, json, log, done}.
function Invoke-SetupM2([switch]$Check) {
    $text = [IO.File]::ReadAllText((Join-Path $script:RigDir (HostPath 'guest\setup-m2.ps1'))).Replace('__CHECK__', $(if ($Check) { '1' } else { '0' })).Replace('__NODISK__', $(if ($NoDataDisk) { '1' } else { '0' }))
    $name = $(if ($Check) { 'setup-m2-check' } else { 'setup-m2' })
    $j = Invoke-GuestJob -Text $text -Name $name -TimeoutSec 900
    Get-JobResult $j
}

# Pure-ish: the JSON between the markers in a job log, and the job's exit code. The agent appends 'exit=N' with
# Out-File -Encoding utf8 to a log that `*>` wrote as UTF-16LE, so that line reads as mojibake; it is decoded
# back here (re-encode the tail as UTF-16LE, read it as UTF-8). ok = job done, JSON present with ok=true and,
# when the exit code could be read, exit 0.
function Get-JobResult($J) {
    $exit = $null; $json = $null
    $log = "$($J.log)"
    $m = [regex]::Matches($log, '(?m)^exit=(-?\d+)')
    if ($m.Count) { $exit = [int]$m[$m.Count - 1].Groups[1].Value }
    else {
        $tail = $log.Substring([Math]::Max(0, $log.Length - 16))
        $dec = [Text.Encoding]::UTF8.GetString([Text.Encoding]::Unicode.GetBytes($tail))
        $m2 = [regex]::Matches($dec, 'exit=(-?\d+)')
        if ($m2.Count) { $exit = [int]$m2[$m2.Count - 1].Groups[1].Value }
    }
    $b = [regex]::Match($log, '(?s)--- [\w-]+ json ---\s*(.*?)\s*--- end json ---')
    if ($b.Success) { try { $json = $b.Groups[1].Value | ConvertFrom-Json } catch { } }
    $ok = ($J.done -and $json -and $json.ok -and ($null -eq $exit -or $exit -eq 0))
    [pscustomobject]@{ done = $J.done; exit = $exit; ok = [bool]$ok; json = $json; log = $J.log; log_file = $J.log_file }
}

function Write-Result([string]$What, $Res) {
    Write-RigLog "  $What`: done=$($Res.done) exit=$($Res.exit) ok=$($Res.ok) log=$($Res.log_file)"
    if ($Res.json) {
        if ($Res.json.actions) { foreach ($a in @($Res.json.actions)) { Write-RigLog "    did: $a" } }
        if ($Res.json.problems) { foreach ($p in @($Res.json.problems)) { Write-RigLog "    PROBLEM: $p" } }
    }
}

$probeText = @'
$ErrorActionPreference = 'Continue'
$o = [ordered]@{ d = $null; points_before = $null; probe = $null; probe_error = $null; points_after = $null; ok = $false }
$v = Get-Volume -DriveLetter D -ErrorAction SilentlyContinue
if ($v) {
    $o.d = [ordered]@{ fs = "$($v.FileSystem)"; type = "$($v.DriveType)"; label = "$($v.FileSystemLabel)"; size = [int64]$v.Size; free = [int64]$v.SizeRemaining
                       entries = @(Get-ChildItem -LiteralPath 'D:\' -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) }
}
try { $o.points_before = @(Get-ComputerRestorePoint -ErrorAction Stop).Count } catch { $o.probe_error = "Get-ComputerRestorePoint: $($_.Exception.Message)" }
if (-not $o.probe_error) {
    try {
        Checkpoint-Computer -Description 'purge-rig-probe' -RestorePointType APPLICATION_UNINSTALL -ErrorAction Stop
        $all = @(Get-ComputerRestorePoint -ErrorAction Stop)
        $o.points_after = $all.Count
        $p = @($all | Where-Object { $_.Description -eq 'purge-rig-probe' }) | Select-Object -Last 1
        if ($p) { $o.probe = [ordered]@{ seq = $p.SequenceNumber; type = $p.RestorePointType; time = "$($p.CreationTime)" } }
        $o.ok = [bool]$p
    } catch { $o.probe_error = "Checkpoint-Computer: $($_.Exception.Message)" }
}
Write-Host '--- probe json ---'
Write-Host (ConvertTo-Json -InputObject $o -Depth 5)
Write-Host '--- end json ---'
if ($o.ok) { exit 0 } else { exit 1 }
'@

$names = Get-SnapshotNames
if ($names -notcontains $Parent) { throw "snapshot '$Parent' not found on $VmName" }
Write-RigLog "snapshots on ${VmName}: $($names -join ', ')"

if ($VerifyOnly) {
    if ($names -notcontains $SnapshotName) { throw "snapshot '$SnapshotName' does not exist; build it first" }
    $failed = $null
    try {
        Restore-Snap $SnapshotName
        Start-VmAgent
        $chk = Invoke-SetupM2 -Check
        Write-Result 'check' $chk
        if (-not $chk.ok) { $failed = 'setup-m2 -Check failed' }
        $pj = Get-JobResult (Invoke-GuestJob -Text $probeText -Name 'm2-probe' -TimeoutSec 600)
        Write-RigLog "  probe: done=$($pj.done) exit=$($pj.exit) ok=$($pj.ok) log=$($pj.log_file)"
        if ($pj.json) { Write-RigLog "  probe json: $(ConvertTo-Json -InputObject $pj.json -Depth 5 -Compress)" }
        if (-not $pj.ok) { $failed = (@($failed, 'restore point probe failed') | Where-Object { $_ }) -join '; ' }
    } catch { $failed = $_.Exception.Message; Write-RigLog "!! verify: $failed" }
    finally {
        Remove-PwTemp
        Restore-Snap $SnapshotName      # discards the probe restore point
        Restore-Snap $Parent
    }
    if ($failed) { throw "verify $SnapshotName failed: $failed" }
    Write-RigLog "verify $SnapshotName OK; VM powered off, $Parent restored"
    return
}

if ($names -contains $SnapshotName) { throw "snapshot '$SnapshotName' already exists on $VmName; refusing to build it again (delete it by hand first if a rebuild is wanted)" }

$taken = $false
try {
    Write-RigLog "build $SnapshotName from $Parent on $VmName"
    Restore-Snap $Parent
    $port = $(if ($NoDataDisk) { -1 } else { Add-DataDisk })
    Start-VmAgent
    $set = Invoke-SetupM2
    Write-Result 'setup' $set
    if (-not $set.ok) { throw 'setup-m2 failed (see the job log)' }
    $chk = Invoke-SetupM2 -Check
    Write-Result 'check' $chk
    if (-not $chk.ok) { throw 'setup-m2 -Check failed (see the job log)' }
    Stop-VmClean
    $disk = $(if ($NoDataDisk) { 'no data disk (no D:, m2-install not supported)' } else { "2 GB data disk D: (NTFS, label PURGE-D, empty; $DataDisk on $Controller port $port)" })
    $desc = "M2 rig base (offline): $Parent + $disk " +
            "+ System Restore on C: (shadow storage 10%, rig-only SystemRestorePointCreationFrequency=0). " +
            "Built by vm\setup-m2-base.ps1 / guest\setup-m2.ps1 on $(Get-Date -Format 'yyyy-MM-dd')."
    $r = Invoke-VBox @('snapshot', $script:VmName, 'take', $SnapshotName, '--description', $desc)
    if ($r.code -ne 0) { throw "snapshot take $SnapshotName failed: $($r.out -join ' ')" }
    $taken = $true
    Write-RigLog "snapshot $SnapshotName taken"
} catch {
    Write-RigLog "!! build failed: $($_.Exception.Message)"
    throw
} finally {
    Remove-PwTemp
    Restore-Snap $Parent
    Write-RigLog "VM powered off, $Parent restored$(if (-not $taken) { " ($SnapshotName NOT taken)" })"
}
