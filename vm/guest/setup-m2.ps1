# Purge rig: the M2 additions on top of rig-base, for the offline snapshot 'm2-base' (child of rig-base).
# Run elevated through the agent (host: vm\setup-m2-base.ps1). Idempotent: a second run changes nothing.
#   1. the small data disk (2 GB, attached by the host on a free SATA port) as one NTFS volume D:, label
#      PURGE-D, left empty. Whatever else holds D: (a DVD drive, another volume) is moved to a free letter first.
#   2. System Restore on C: (Enable-ComputerRestore), shadow storage for C: on C: (10 %), and the rig-only
#      value HKLM\...\SystemRestore SystemRestorePointCreationFrequency = 0 (DWORD), so restore points can be
#      created back to back in tests. The product never sets this value.
# -Check only verifies that state and exits 1 if anything is missing. When the agent runs this file as a
# job (no arguments), the host replaces __CHECK__ below with 1 or 0.
# Output: C:\cr\out\setup-m2\setup-m2[-check].json and .log; the JSON is also printed between the lines
# '--- setup-m2 json ---' and '--- end json ---' so the host reads it from the job log.
# Self-contained on purpose (no riglib.ps1): rig-base holds the M0 copy of C:\cr\guest, and pushing fresh guest
# scripts would put more into the snapshot than the two additions above.
# -NoDataDisk (host: setup-m2-base.ps1 -NoDataDisk, placeholder __NODISK__): System Restore only, no data disk and no
# D: check. For a VM whose M2 runs never use D: (Purge-CleanPro: m2-traps and m2-fidelity; the D: stage is m2-install).
param([switch]$Check, [switch]$NoDataDisk)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
if ('__CHECK__' -eq '1') { $Check = $true }
if ('__NODISK__' -eq '1') { $NoDataDisk = $true }

$Mode = $(if ($Check) { 'check' } else { 'setup' })
$OutDir = 'C:\cr\out\setup-m2'
New-Item -ItemType Directory -Force $OutDir | Out-Null
$Base = Join-Path $OutDir $(if ($Check) { 'setup-m2-check' } else { 'setup-m2' })
$LogFile = "$Base.log"
$Utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($LogFile, '', $Utf8)

function NowIso { (Get-Date).ToString('o') }
function Log([string]$Message) {
    $line = '[{0}] {1}' -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fff'), $Message
    Write-Host $line
    try { [IO.File]::AppendAllText($LogFile, $line + "`r`n", $Utf8) } catch { }
}

$DataLetter = 'D'
$DataLabel  = 'PURGE-D'
$MinBytes   = 1.8GB
$MaxBytes   = 2.2GB
$SrKey      = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
$SrPolicy   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore'
$FreqName   = 'SystemRestorePointCreationFrequency'
$ShadowPct  = 10

$R = [ordered]@{ schema = 'purge.rig.setup-m2/1'; mode = $Mode; started = (NowIso); finished = $null
                 computer = $env:COMPUTERNAME; user = $env:USERNAME; admin = $false
                 actions = New-Object System.Collections.ArrayList; problems = New-Object System.Collections.ArrayList
                 data_disk = $null; system_restore = $null; ok = $false }
function Act([string]$What) { [void]$R.actions.Add($What); Log "do: $What" }
function Problem([string]$What) { [void]$R.problems.Add($What); Log "!! $What" }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$R.admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "setup-m2 ($Mode) as $($id.Name) admin=$($R.admin) on $env:COMPUTERNAME"

# ------------------------------------------------------------------------------------------- data disk

# The data disk: not the boot/system disk, between 1.8 and 2.2 GB. Exactly one must exist.
function Get-DataDisk {
    $c = @(Get-Disk | Where-Object { -not $_.IsBoot -and -not $_.IsSystem -and $_.Size -ge $MinBytes -and $_.Size -le $MaxBytes })
    if ($c.Count -gt 1) { throw "more than one candidate data disk: $(($c | ForEach-Object { "#$($_.Number) $($_.FriendlyName) $($_.Size)" }) -join ', ')" }
    if ($c.Count -eq 1) { return $c[0] }
    $null
}

function Get-DataPartition($Disk) {
    @(Get-Partition -DiskNumber $Disk.Number -ErrorAction SilentlyContinue | Where-Object { $_.Type -ne 'Reserved' -and $_.Type -ne 'Unknown' })
}

function Get-FreeLetter {
    $used = @(Get-CimInstance Win32_Volume | Where-Object { $_.DriveLetter } | ForEach-Object { $_.DriveLetter.Substring(0, 1).ToUpper() })
    $used += @(Get-CimInstance Win32_LogicalDisk | ForEach-Object { $_.DeviceID.Substring(0, 1).ToUpper() })
    foreach ($l in [char[]]'ZYXWVUTSRQPONMLKJIHGFE') { if ($used -notcontains "$l") { return "$l" } }
    throw 'no free drive letter'
}

function Set-DataDisk {
    $disk = Get-DataDisk
    if (-not $disk) { Problem 'no data disk (2 GB, not the boot disk) found: is it attached on the SATA controller?'; return }
    Log "data disk #$($disk.Number) '$($disk.FriendlyName)' size=$($disk.Size) style=$($disk.PartitionStyle) offline=$($disk.IsOffline) readonly=$($disk.IsReadOnly)"
    if ($disk.IsOffline) { Act "disk #$($disk.Number) online"; Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction Stop }
    if ($disk.IsReadOnly) { Act "disk #$($disk.Number) read-write"; Set-Disk -Number $disk.Number -IsReadOnly $false -ErrorAction Stop }
    $disk = Get-Disk -Number $disk.Number
    if ("$($disk.PartitionStyle)" -eq 'RAW') {
        Act "initialise disk #$($disk.Number) as GPT"
        Initialize-Disk -Number $disk.Number -PartitionStyle GPT -ErrorAction Stop
    }
    $parts = @(Get-DataPartition $disk)   # @(): one MSFT_Partition alone has no usable .Count
    if ($parts.Count -gt 1) { Problem "data disk #$($disk.Number) has $($parts.Count) partitions; expected one (left as it is)"; return }
    $part = $null
    if ($parts.Count -eq 1) { $part = $parts[0] }

    # Who holds D:? If it is not the data partition, move it to a free letter first.
    $holder = Get-CimInstance Win32_Volume -Filter "DriveLetter='${DataLetter}:'"
    if ($holder) {
        $ours = $false
        if ($part) { $v = $part | Get-Volume -ErrorAction SilentlyContinue; if ($v -and $v.Path -eq $holder.DeviceID) { $ours = $true } }
        if (-not $ours) {
            $nl = Get-FreeLetter
            Act "move ${DataLetter}: ($($holder.Label), drive type $($holder.DriveType), $($holder.DeviceID)) to ${nl}:"
            Set-CimInstance -InputObject $holder -Property @{ DriveLetter = "${nl}:" } -ErrorAction Stop
        }
    }

    if (-not $part) {
        Act "create one partition on disk #$($disk.Number) as ${DataLetter}:"
        $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter $DataLetter -ErrorAction Stop
    } elseif ("$($part.DriveLetter)" -ne $DataLetter) {
        if ($part.DriveLetter -and "$($part.DriveLetter)" -match '^[A-Z]$') {
            Act "remove letter $($part.DriveLetter): from the data partition"
            Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -AccessPath "$($part.DriveLetter):\" -ErrorAction Stop
        }
        Act "assign ${DataLetter}: to the data partition"
        Set-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -NewDriveLetter $DataLetter -ErrorAction Stop
    }
    $vol = Get-Volume -DriveLetter $DataLetter -ErrorAction SilentlyContinue
    if (-not $vol -or "$($vol.FileSystem)" -ne 'NTFS') {
        Act "format ${DataLetter}: NTFS, label $DataLabel"
        $null = Format-Volume -DriveLetter $DataLetter -FileSystem NTFS -NewFileSystemLabel $DataLabel -Confirm:$false -Force -ErrorAction Stop
    } elseif ($vol.FileSystemLabel -ne $DataLabel) {
        Act "label ${DataLetter}: $DataLabel"
        Set-Volume -DriveLetter $DataLetter -NewFileSystemLabel $DataLabel -ErrorAction Stop
    }
}

function Get-DataState {
    $s = [ordered]@{ disk = $null; volume = $null }
    $disk = $null
    try { $disk = Get-DataDisk } catch { Problem $_.Exception.Message }
    if (-not $disk) { Problem 'data disk: not found' }
    else {
        $s.disk = [ordered]@{ number = $disk.Number; name = "$($disk.FriendlyName)"; bus = "$($disk.BusType)"; size = [int64]$disk.Size
                             style = "$($disk.PartitionStyle)"; offline = [bool]$disk.IsOffline; readonly = [bool]$disk.IsReadOnly
                             partitions = @(Get-DataPartition $disk).Count }
        if ($disk.IsOffline -or $disk.IsReadOnly) { Problem 'data disk: offline or read-only' }
        if ($s.disk.partitions -ne 1) { Problem "data disk: $($s.disk.partitions) data partitions (want 1)" }
    }
    $vol = Get-Volume -DriveLetter $DataLetter -ErrorAction SilentlyContinue
    if (-not $vol) { Problem "${DataLetter}: does not exist"; return $s }
    $onData = $false
    if ($disk) {
        $p = @(Get-DataPartition $disk | Where-Object { "$($_.DriveLetter)" -eq $DataLetter })
        $onData = ($p.Count -eq 1)
    }
    $entries = @(Get-ChildItem -LiteralPath "${DataLetter}:\" -Force -ErrorAction SilentlyContinue | Where-Object { @('System Volume Information', '$RECYCLE.BIN') -notcontains $_.Name } | ForEach-Object { $_.Name })
    $s.volume = [ordered]@{ letter = $DataLetter; label = "$($vol.FileSystemLabel)"; fs = "$($vol.FileSystem)"; drive_type = "$($vol.DriveType)"
                           size = [int64]$vol.Size; free = [int64]$vol.SizeRemaining; on_data_disk = $onData; entries = $entries; path = "$($vol.Path)" }
    if ("$($vol.FileSystem)" -ne 'NTFS') { Problem "${DataLetter}: file system is '$($vol.FileSystem)', not NTFS" }
    if ($vol.FileSystemLabel -ne $DataLabel) { Problem "${DataLetter}: label is '$($vol.FileSystemLabel)', not $DataLabel" }
    if ("$($vol.DriveType)" -ne 'Fixed') { Problem "${DataLetter}: drive type is $($vol.DriveType), not Fixed" }
    if ($vol.Size -lt 1.5GB -or $vol.Size -gt $MaxBytes) { Problem "${DataLetter}: size $($vol.Size) is not about 2 GB" }
    if (-not $onData) { Problem "${DataLetter}: is not the data disk's partition" }
    if ($entries.Count) { Problem "${DataLetter}: is not empty: $($entries -join ', ')" }
    $s
}

# ------------------------------------------------------------------------------------- system restore

function Get-CVolume { Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'" }

# The shadow storage association for C: on C:, from 'vssadmin list shadowstorage /for=C:' (the CIM references
# of Win32_ShadowStorage did not match Win32_Volume.DeviceID on this image). Returns @() or one record
# {max_space (bytes, 0 = UNBOUNDED), max_pct, text}. Parses the English output of the rig VMs.
function Get-CShadowStorage {
    $o = @(& vssadmin.exe list shadowstorage /for=C: 2>&1 | ForEach-Object { "$_".Trim() })
    if ($LASTEXITCODE -ne 0) { return @() }
    $on = @($o | Where-Object { $_ -match '^Shadow Copy Storage volume:\s*\(C:\)' })
    $max = @($o | Where-Object { $_ -match '^Maximum Shadow Copy Storage space:' }) | Select-Object -First 1
    if (-not $on.Count -or -not $max) { return @() }
    $rec = [ordered]@{ max_space = [uint64]0; max_pct = $null; text = "$max" }
    $m = [regex]::Match($max, ':\s*([\d.,]+)\s*(B|KB|MB|GB|TB)\s*\((\d+)%\)')
    if ($m.Success) {
        $mult = @{ B = 1; KB = 1KB; MB = 1MB; GB = 1GB; TB = 1TB }[$m.Groups[2].Value]
        $rec.max_space = [uint64]([double]::Parse($m.Groups[1].Value.Replace(',', ''), [Globalization.CultureInfo]::InvariantCulture) * $mult)
        $rec.max_pct = [int]$m.Groups[3].Value
    } elseif ($max -match 'UNBOUNDED') { $rec.max_space = [uint64]::MaxValue }
    @([pscustomobject]$rec)
}

function Set-SystemRestore {
    $pol = Get-ItemProperty -Path $SrPolicy -ErrorAction SilentlyContinue
    if ($pol -and ("$($pol.DisableSR)" -eq '1' -or "$($pol.DisableConfig)" -eq '1')) {
        Problem "System Restore is disabled by policy ($SrPolicy DisableSR=$($pol.DisableSR) DisableConfig=$($pol.DisableConfig)); not changed"
        return
    }
    $sr = Get-ItemProperty -Path $SrKey -ErrorAction SilentlyContinue
    if ("$($sr.RPSessionInterval)" -ne '1') {
        Act 'Enable-ComputerRestore -Drive C:\'
        Enable-ComputerRestore -Drive 'C:\' -ErrorAction Stop
    }
    $ss = @(Get-CShadowStorage)   # @(): a lone PSCustomObject has no .Count in PowerShell 5.1
    $cv = Get-CVolume
    $want = [uint64][math]::Floor($cv.Capacity * $ShadowPct / 100)
    $short = (-not $ss.Count)
    if (-not $short) { if ($null -ne $ss[0].max_pct) { $short = ($ss[0].max_pct -lt $ShadowPct) } else { $short = ($ss[0].max_space -lt $want) } }
    if ($short) {
        Act "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=$ShadowPct%"
        $o = & vssadmin.exe resize shadowstorage /for=C: /on=C: "/maxsize=$ShadowPct%" 2>&1
        $code = $LASTEXITCODE
        Log "  vssadmin exit $code`: $((@($o) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) -join ' | ')"
        if ($code -ne 0 -and -not @(Get-CShadowStorage).Count) {
            # No association yet: client SKUs have no 'vssadmin add shadowstorage'; WMI can create it.
            Act "Win32_ShadowStorage.Create C: on C: MaxSpace=$want"
            $r = Invoke-CimMethod -ClassName Win32_ShadowStorage -MethodName Create -Arguments @{ Volume = 'C:\'; DiffVolume = 'C:\'; MaxSpace = $want } -ErrorAction Stop
            Log "  Create ReturnValue=$($r.ReturnValue)"
            if ($r.ReturnValue -ne 0) { throw "Win32_ShadowStorage.Create returned $($r.ReturnValue)" }
        }
    }
    $cur = Get-ItemProperty -Path $SrKey -Name $FreqName -ErrorAction SilentlyContinue
    $kind = $null
    if ($cur) { try { $kind = (Get-Item -Path $SrKey).GetValueKind($FreqName) } catch { } }
    if (-not $cur -or "$($cur.$FreqName)" -ne '0' -or "$kind" -ne 'DWord') {
        Act "$FreqName = 0 (DWORD)"
        New-ItemProperty -Path $SrKey -Name $FreqName -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
    }
}

function Get-SrState {
    $s = [ordered]@{ rp_session_interval = $null; policy_disable_sr = $null; frequency = $null; frequency_kind = $null
                     shadow_storage = $null; c_capacity = $null; restore_points = $null; restore_points_error = $null; srservice = $null }
    $sr = Get-ItemProperty -Path $SrKey -ErrorAction SilentlyContinue
    $s.rp_session_interval = $sr.RPSessionInterval
    $pol = Get-ItemProperty -Path $SrPolicy -ErrorAction SilentlyContinue
    if ($pol) { $s.policy_disable_sr = $pol.DisableSR }
    if ($sr -and $null -ne $sr.$FreqName) {
        $s.frequency = $sr.$FreqName
        try { $s.frequency_kind = "$((Get-Item -Path $SrKey).GetValueKind($FreqName))" } catch { }
    }
    $cv = Get-CVolume
    $s.c_capacity = [int64]$cv.Capacity
    $ss = @(Get-CShadowStorage)   # @(): a lone PSCustomObject has no .Count in PowerShell 5.1
    if ($ss.Count) { $s.shadow_storage = [ordered]@{ max_space = $ss[0].max_space; max_pct = $ss[0].max_pct; text = $ss[0].text } }
    try { $s.restore_points = @(Get-ComputerRestorePoint -ErrorAction Stop | ForEach-Object { [ordered]@{ seq = $_.SequenceNumber; desc = "$($_.Description)"; type = $_.RestorePointType; time = "$($_.CreationTime)" } }) }
    catch { $s.restore_points_error = $_.Exception.Message }
    $svc = Get-Service -Name VSS -ErrorAction SilentlyContinue
    if ($svc) { $s.srservice = "VSS start=$($svc.StartType) status=$($svc.Status)" }

    if ("$($s.rp_session_interval)" -ne '1') { Problem "System Restore is not enabled (RPSessionInterval=$($s.rp_session_interval))" }
    if ("$($s.policy_disable_sr)" -eq '1') { Problem 'System Restore is disabled by policy (DisableSR=1)' }
    if ("$($s.frequency)" -ne '0' -or $s.frequency_kind -ne 'DWord') { Problem "$FreqName is '$($s.frequency)' ($($s.frequency_kind)), want 0 (DWord)" }
    if (-not $s.shadow_storage) { Problem 'no shadow storage association for C: on C:' }
    elseif ($s.shadow_storage.max_space -lt 1GB) { Problem "shadow storage for C: is only $($s.shadow_storage.max_space) bytes" }
    if ($s.restore_points_error) { Problem "Get-ComputerRestorePoint failed: $($s.restore_points_error)" }
    $s
}

# -------------------------------------------------------------------------------------------- main

if (-not $R.admin) { Problem 'not elevated: run this through the agent' }
elseif (-not $Check) {
    if (-not $NoDataDisk) { try { Set-DataDisk } catch { Problem "data disk setup failed: $($_.Exception.Message)" } }
    try { Set-SystemRestore } catch { Problem "System Restore setup failed: $($_.Exception.Message)" }
    if ($R.problems.Count) { Log "setup problems: $($R.problems.Count); the state check follows" }
}
if ($R.admin) {
    # Setup and check both end with the full state check; setup problems are kept.
    $R.data_disk = $(if ($NoDataDisk) { 'skipped (-NoDataDisk)' } else { Get-DataState })
    $R.system_restore = Get-SrState
}
$R.ok = ($R.problems.Count -eq 0)
$R.finished = NowIso
$json = ConvertTo-Json -InputObject $R -Depth 8
[IO.File]::WriteAllText("$Base.json", $json, $Utf8)
Write-Host '--- setup-m2 json ---'
Write-Host $json
Write-Host '--- end json ---'
Log ("setup-m2 ({0}) {1}: {2} action(s), {3} problem(s)" -f $Mode, $(if ($R.ok) { 'OK' } else { 'FAILED' }), $R.actions.Count, $R.problems.Count)
if ($R.ok) { exit 0 } else { exit 1 }
