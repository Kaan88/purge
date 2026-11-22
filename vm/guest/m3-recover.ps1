<#
  Purge rig, M3 recovery modes m3-owner (gate G8), m3-recover (G9) and m3-extras (allow_irreversible, Restart Manager,
  System Restore) (vm\RIG.md section 15; docs\M3_DESIGN.md 11.2, 12; docs\M3_FINISH_PLAN.md B8). Guest side, Windows
  PowerShell 5.1, run elevated by C:\cr\agent.ps1 as one job per phase; the host driver is vm\rig-m3-recover.ps1. The
  tool is C:\cr\m3rec\m3rec.exe, built here from vm\guest\m3sec.cs + vm\guest\m3rec.cs.

    & C:\cr\guest\m3-recover.ps1 -Phase <phase> [-Tag <t>] [-Fix <fixture>] [-Via ui|client] [-WaitSec <n>]

  Every output is under C:\cr\out\m3-recover\ (log rec.log); result lines start with "M3R ".

  Layout (phase install): the payload pushed by the host (C:\cr\m3rec\payload.zip: purge-engine.exe, purge-broker.exe,
  kb\ and, when given, ui\) is installed with install\install.ps1 -SkipBuild: C:\Program Files\Purge with the rig client
  (m3rec.exe as Purge.exe, so the broker's client check accepts it) and, with ui\, C:\Program Files\PurgeUI with the
  real UI (the History & undo page of m3-recover). Fixture programs (phase fixture -Fix <id>): PurgeRig<Id> with an
  ARP key, files in Program Files and ProgramData, HKLM and HKCU keys; uninstaller "uninst.exe rec-uninstall <key>"
  removes only its ARP key and app.exe. own: also the service PurgeRigOwnSvc with Parameters\Guarded, owned by SYSTEM,
  whose DACL grants nobody WRITE_OWNER (review R8b M1). rm: two files held open by running lockers.

  Phases:
    common:     build, install, uac-silent, uac-check, fixture -Fix f, truth -Fix f -Tag label, pack -Tag name, flush
    m3-recover: crash-arm -Tag k (0 = calibration, nothing suspended), after-boot -Tag k, ui-check -Tag k,
                recover-start -Tag k-after -Via ui|client, dialog-focus -Tag name, recover-result -Tag k-after,
                bookkeeping -Tag k
    m3-owner:   own-exec, own-undo-cut, own-resume-start, own-resume-result (dialog-focus between)
    m3-extras:  sr-enable, npp-install, irrev, rm-exec, rm-retry, rm-after-reboot, sr -Tag off|disabled|created|throttled, extras-summary
#>
param(
    [Parameter(Mandatory)]
    [ValidateSet('build', 'install', 'uac-silent', 'uac-check', 'sr-enable', 'fixture', 'truth', 'pack', 'flush',
                 'crash-arm', 'after-boot', 'ui-check', 'recover-start', 'dialog-focus', 'recover-result', 'bookkeeping',
                 'own-exec', 'own-undo-cut', 'own-resume-start', 'own-resume-result',
                 'npp-install', 'irrev', 'rm-exec', 'rm-retry', 'rm-after-reboot', 'sr', 'extras-summary')]
    [string] $Phase,
    [string] $Tag = '',
    [string] $Fix = '',
    [ValidateSet('', 'ui', 'client')] [string] $Via = '',
    [int] $WaitSec = 120
)
. C:\cr\guest\riglib.ps1
$ErrorActionPreference = 'Continue'

$Out = 'C:\cr\out\m3-recover'
$Bin = 'C:\cr\m3rec'
$Exe = Join-Path $Bin 'm3rec.exe'
$Payload = Join-Path $Bin 'payload'
$ClientDir = Join-Path $Bin 'client'
$PF = 'C:\Program Files\Purge'
$PFUI = 'C:\Program Files\PurgeUI'
$Broker = Join-Path $PF 'purge-broker.exe'
$UiBroker = Join-Path $PFUI 'purge-broker.exe'
$ClientImg = Join-Path $PF 'Purge.exe'
$DataRoot = 'C:\ProgramData\Purge'
$Sessions = Join-Path $DataRoot 'sessions'
$Quarantine = Join-Path $DataRoot 'Quarantine'
$SessionPattern = '^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$'
$Tasks = @{ client = 'PurgeRigRecClient'; ui = 'PurgeRigRecUi'; hold1 = 'PurgeRigRecHold1'; hold2 = 'PurgeRigRecHold2' }
# The fixture owner key (review R8b M1): owned by SYSTEM, a protected DACL that grants nobody WRITE_OWNER
# (0x7003F = KEY_ALL_ACCESS without WRITE_OWNER), Users read.
$OwnSvc = 'PurgeRigOwnSvc'
$OwnSvcKey = "HKLM\SYSTEM\CurrentControlSet\Services\$OwnSvc"
$OwnGuarded = "$OwnSvcKey\Parameters\Guarded"
$OwnSddl = 'O:SYG:SYD:P(A;CI;0x7003f;;;SY)(A;CI;0x7003f;;;BA)(A;CI;KR;;;BU)'
New-Item -ItemType Directory -Force $Out, $Bin | Out-Null
Set-RunLog (Join-Path $Out 'rec.log')
foreach ($v in $Tag, $Fix) { if ($v -and $v -notmatch '^[A-Za-z0-9_-]+$') { throw "bad argument '$v'" } }

# ----------------------------------------------------------------------------------------------- helpers

function Grant-UsersModify([string]$Dir) {
    New-Item -ItemType Directory -Force $Dir | Out-Null
    $null = & icacls.exe $Dir /grant '*S-1-5-32-545:(OI)(CI)M' /q
}
function Read-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
}
function Wait-File([string]$Path, [int]$Sec) {
    $d = (Get-Date).AddSeconds($Sec)
    while (-not (Test-Path -LiteralPath $Path) -and (Get-Date) -lt $d) { Start-Sleep -Milliseconds 250 }
    Test-Path -LiteralPath $Path
}
function Write-Spec($Spec, [string]$Path) { Write-JsonFile $Spec $Path 10 }

# m3rec.exe from the (high) agent, waited for.
function Invoke-Rec([string[]]$Arguments, [int]$TimeoutSec = 120) {
    $q = @($Arguments | ForEach-Object { if ("$_" -match '\s') { '"' + $_ + '"' } else { "$_" } })
    $p = Start-Process -FilePath $Exe -ArgumentList $q -PassThru -WindowStyle Hidden
    if (-not $p.WaitForExit($TimeoutSec * 1000)) { Log "  !! m3rec $($Arguments[0]) still running after $TimeoutSec s; killed"; Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; return -1 }
    $p.ExitCode
}
# m3rec.exe at high, detached: shell execute, so it inherits none of the agent job's handles and outlives the job.
function Start-RecDetached([string[]]$Arguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = (@($Arguments | ForEach-Object { if ("$_" -match '\s') { '"' + $_ + '"' } else { "$_" } }) -join ' ')
    $psi.UseShellExecute = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    [System.Diagnostics.Process]::Start($psi)
}
function Start-Medium([string]$ExePath, [string]$Arguments, [string]$TaskName) { $null = LaunchMedium -Exe $ExePath -Arguments $Arguments -TaskName $TaskName -StartTimeoutSec 0 }
function Stop-Task([string]$TaskName) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue }

function Get-PurgeEvents([datetime]$Since) {
    @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Purge'; StartTime = $Since } -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated | ForEach-Object { [ordered]@{ id = $_.Id; level = $_.LevelDisplayName; time = $_.TimeCreated.ToString('o'); message = "$($_.Message)" } })
}
function Get-BootTime { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
function Get-SessionNames { @(Get-ChildItem -LiteralPath $Sessions -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $SessionPattern } | ForEach-Object { $_.Name } | Sort-Object) }
function Get-BrokerProcs([string]$Image) { @(Get-ProcList | Where-Object { $_.name -ieq 'purge-broker.exe' -and (-not $Image -or $_.path -ieq $Image) }) }

# Flushes every file of the rig's output tree (never the Purge store) before the host cuts the power.
function Sync-OutFiles {
    $n = 0; $bad = 0
    foreach ($f in @(Get-ChildItem -LiteralPath $Out -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        try { $s = [IO.File]::Open($f.FullName, 'Open', 'ReadWrite', 'ReadWrite, Delete'); try { $s.Flush($true) } finally { $s.Dispose() }; $n++ } catch { $bad++ }
    }
    "$n/$bad"
}

# ------------------------------------------------------------------------------------------- store truth

# The Purge store as it stands for one session: journal (complete lines, last record, torn tail), report, index entry,
# quarantine op directories with their files, registry backups.
function Get-StoreTruth([string]$Session) {
    $r = [ordered]@{ session = $Session; t = (NowIso); dir = $false; journal_lines = 0; journal_last_rec = $null; journal_recs = @(); torn_tail = 0
                     report = $false; index_listed = $false; index_state = $null; index_counts = $null; quarantine_ops = @(); reg_backups = 0; error = $null }
    if (-not $Session) { return $r }
    try {
        $d = Join-Path $Sessions $Session
        $r.dir = Test-Path -LiteralPath $d
        $j = Join-Path $d 'journal.jsonl'
        if (Test-Path -LiteralPath $j) {
            $bytes = [IO.File]::ReadAllBytes($j)
            $text = (New-Object Text.UTF8Encoding($false)).GetString($bytes)
            $parts = $text -split "`n"
            $r.torn_tail = $parts[-1].Length
            $complete = @($parts | Select-Object -SkipLast 1)
            $r.journal_lines = $complete.Count
            $r.journal_recs = @($complete | ForEach-Object { $m = [regex]::Match($_, '"rec":"([a-z_]+)"'); if ($m.Success) { $m.Groups[1].Value } else { '?' } })
            if ($complete.Count) { $r.journal_last_rec = $r.journal_recs[-1] }
        }
        $r.report = Test-Path -LiteralPath (Join-Path $d 'report.json')
        $idx = Read-Json (Join-Path $Sessions 'index.json')
        $e = @($idx.sessions | Where-Object { $_.id -eq $Session }) | Select-Object -First 1
        if ($e) { $r.index_listed = $true; $r.index_state = "$($e.state)"; $r.index_counts = $e.counts }
        $qd = Join-Path $Quarantine $Session
        if (Test-Path -LiteralPath $qd) {
            $r.quarantine_ops = @(Get-ChildItem -LiteralPath $qd -Directory -Force | Sort-Object Name | ForEach-Object {
                $files = @(Get-ChildItem -LiteralPath $_.FullName -Recurse -File -Force -ErrorAction SilentlyContinue)
                [ordered]@{ op = $_.Name; files = $files.Count; bytes = [long](($files | Measure-Object Length -Sum).Sum) } })
        }
        $r.reg_backups = @(Get-ChildItem -LiteralPath (Join-Path $d 'reg') -File -Force -ErrorAction SilentlyContinue).Count
    } catch { $r.error = $_.Exception.Message }
    $r
}

# ----------------------------------------------------------------------------------------- fixtures

$FixtureDefs = [ordered]@{
    rec = @{ key = 'PurgeRigRec'; name = 'Purge Rig Recover App'; files = @('data\a.dat', 'data\b.dat', 'data\sub\c.dat'); pdata = @('settings.ini') }
    own = @{ key = 'PurgeRigOwn'; name = 'Purge Rig Owner App'; files = @('data\a.dat'); pdata = @('settings.ini'); service = $true }
    rm  = @{ key = 'PurgeRigRm'; name = 'Purge Rig Locked App'; files = @('data\plain.dat', 'bin\locked.dll'); pdata = @('settings.ini', 'locked.dat') }
    sr1 = @{ key = 'PurgeRigSr1'; name = 'Purge Rig Restore App 1'; files = @('data\a.dat'); pdata = @('settings.ini') }
    sr2 = @{ key = 'PurgeRigSr2'; name = 'Purge Rig Restore App 2'; files = @('data\a.dat'); pdata = @('settings.ini') }
    sr3 = @{ key = 'PurgeRigSr3'; name = 'Purge Rig Restore App 3'; files = @('data\a.dat'); pdata = @('settings.ini') }
    sr4 = @{ key = 'PurgeRigSr4'; name = 'Purge Rig Restore App 4'; files = @('data\a.dat'); pdata = @('settings.ini') }
}
function Get-Fixture([string]$Id) {
    $f = $FixtureDefs[$Id]
    if (-not $f) { throw "unknown fixture '$Id' (known: $($FixtureDefs.Keys -join ', '))" }
    $k = $f.key
    [ordered]@{ id = $Id; key = $k; name = $f.name; program = "HKLM|64|$k"; dir = "C:\Program Files\$k"; pdata = "C:\ProgramData\$k"
                hklm = "HKLM\SOFTWARE\$k"; hkcu = "HKCU\Software\$k"; arp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$k"
                files = @($f.files); pdata_files = @($f.pdata); service = [bool]$f.service }
}

function ConvertTo-PsReg([string]$Key) { $Key -replace '^HKLM\\', 'HKLM:\' -replace '^HKCU\\', 'HKCU:\' }

function Install-RecFixture([string]$Id) {
    $f = Get-Fixture $Id
    foreach ($p in $f.dir, $f.pdata) { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force } }
    New-Item -ItemType Directory -Force $f.dir, $f.pdata | Out-Null
    Copy-Item -LiteralPath $Exe -Destination (Join-Path $f.dir 'app.exe') -Force
    Copy-Item -LiteralPath $Exe -Destination (Join-Path $f.dir 'uninst.exe') -Force
    foreach ($rel in $f.files) {
        $p = Join-Path $f.dir $rel
        New-Item -ItemType Directory -Force (Split-Path $p) | Out-Null
        [IO.File]::WriteAllText($p, "fixture $($f.key) $rel`r`n")
    }
    foreach ($rel in $f.pdata_files) { [IO.File]::WriteAllText((Join-Path $f.pdata $rel), "[rig]`r`nfixture=$($f.key) $rel`r`n") }
    $hk = ConvertTo-PsReg $f.hklm
    $null = New-Item -Path "$hk\Sub" -Force
    Set-ItemProperty -LiteralPath $hk -Name 'InstallDir' -Value $f.dir
    Set-ItemProperty -LiteralPath $hk -Name 'Mode' -Value 7 -Type DWord
    Set-ItemProperty -LiteralPath "$hk\Sub" -Name 'V' -Value 'rig'
    $cu = ConvertTo-PsReg $f.hkcu
    $null = New-Item -Path $cu -Force
    Set-ItemProperty -LiteralPath $cu -Name 'LastRun' -Value 'fixture'
    $null = New-Item -Path $f.arp -Force
    $u = '"' + (Join-Path $f.dir 'uninst.exe') + '" rec-uninstall ' + $f.key
    $props = [ordered]@{ DisplayName = $f.name; DisplayVersion = '1.0.0'; Publisher = 'Purge rig'; InstallLocation = $f.dir
                         DisplayIcon = (Join-Path $f.dir 'app.exe'); UninstallString = $u; QuietUninstallString = "$u /S" }
    foreach ($k in $props.Keys) { Set-ItemProperty -LiteralPath $f.arp -Name $k -Value $props[$k] }
    Set-ItemProperty -LiteralPath $f.arp -Name 'NoModify' -Value 1 -Type DWord
    Set-ItemProperty -LiteralPath $f.arp -Name 'NoRepair' -Value 1 -Type DWord
    Remove-Item -LiteralPath (Join-Path $Out "uninstalled-$($f.key).json") -Force -ErrorAction SilentlyContinue
    $rec = [ordered]@{ fixture = $f; t = (NowIso) }
    if ($f.service) { $rec.service = Install-OwnService $f }
    Write-JsonFile $rec (Join-Path $Out "fixture-$Id.json") 8
    Log "fixture $Id installed ($($f.key))"
    $rec
}

# The service of the owner fixture (own process, demand start, LocalSystem; never started). New-Service hands the
# command line to CreateService as it is, so the fixture and the staged first attempt write the same raw ImagePath (the
# resumed undo's own-attempt check compares it). Parameters (inherited descriptor) and Parameters\Guarded with the
# SYSTEM-owned descriptor $OwnSddl.
function New-OwnService([string]$Dir) {
    New-Service -Name $OwnSvc -BinaryPathName ('"' + (Join-Path $Dir 'svc.exe') + '" -rig') -DisplayName 'Purge rig owner service' -StartupType Manual -ErrorAction Stop | Out-Null
    "created $OwnSvc"
}
function Install-OwnService($F) {
    $svcExe = Join-Path $F.dir 'svc.exe'
    Copy-Item -LiteralPath $Exe -Destination $svcExe -Force
    $null = & sc.exe delete $OwnSvc 2>&1
    $o = try { New-OwnService $F.dir } catch { "New-Service failed: $($_.Exception.Message)" }
    $k = ConvertTo-PsReg $OwnSvcKey
    $null = New-Item -Path "$k\Parameters\Guarded" -Force
    Set-ItemProperty -LiteralPath "$k\Parameters" -Name 'Mode' -Value 'rig'
    Set-ItemProperty -LiteralPath "$k\Parameters\Guarded" -Name 'Level' -Value 1 -Type DWord
    $code = Invoke-Rec @('regsd', $OwnGuarded, $OwnSddl, 'ogdp') 60
    [ordered]@{ sc_create = "$o"; regsd_exit = $code; regsd = (Read-Json (Join-Path $Out 'regsd-last.json')); guarded_sddl = (Get-KeySddl $OwnGuarded) }
}

function Get-KeySddl([string]$Key) {
    $sub = $Key -replace '^HKLM\\', ''
    try {
        $hk = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
        $k = $hk.OpenSubKey($sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [Security.AccessControl.RegistryRights]::ReadPermissions)
        if (-not $k) { return $null }
        try { $k.GetAccessControl('Owner, Group, Access').GetSecurityDescriptorSddlForm('Owner, Group, Access') } finally { $k.Dispose() }
    } catch { "error: $($_.Exception.Message)" }
}

# One registry tree, canonical: K|<rel>[|<sddl>] and V|<rel>|<name>|<kind>|<data> lines, sorted.
function Get-RegTreeLines([string]$Key, [switch]$Sddl) {
    $hive = $(if ($Key -like 'HKCU\*') { 'CurrentUser' } else { 'LocalMachine' })
    $sub = $Key -replace '^HK(LM|CU)\\', ''
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, 'Registry64')
    $lines = New-Object System.Collections.ArrayList
    $walk = {
        param($k, [string]$rel)
        [void]$lines.Add("K|$rel$(if ($Sddl) { '|' + (Get-KeySddl "$Key$(if ($rel) { '\' + $rel })") })")
        foreach ($n in @($k.GetValueNames() | Sort-Object)) {
            $kind = $k.GetValueKind($n)
            $v = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
            $data = $(if ($v -is [byte[]]) { [BitConverter]::ToString($v) } elseif ($v -is [string[]]) { $v -join '\0' } else { "$v" })
            [void]$lines.Add("V|$rel|$n|$kind|$data")
        }
        foreach ($c in @($k.GetSubKeyNames() | Sort-Object)) {
            $ck = $k.OpenSubKey($c, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [Security.AccessControl.RegistryRights]'ReadKey')
            if ($ck) { try { & $walk $ck $(if ($rel) { "$rel\$c" } else { $c }) } finally { $ck.Dispose() } }
            else { [void]$lines.Add("K|$(if ($rel) { "$rel\$c" } else { $c })|unreadable") }
        }
    }
    $k = $base.OpenSubKey($sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [Security.AccessControl.RegistryRights]'ReadKey')
    if (-not $k) { return $null }
    try { & $walk $k '' } finally { $k.Dispose() }
    @($lines | Sort-Object)
}

function Get-DirLines([string]$Dir, [string[]]$Exclude = @()) {
    if (-not (Test-Path -LiteralPath $Dir)) { return $null }
    $root = (Get-Item -LiteralPath $Dir -Force).FullName.TrimEnd('\')
    @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $rel = $_.FullName.Substring($root.Length + 1)
        if ($Exclude -contains $rel) { return }
        if ($_.PSIsContainer) { "D|$rel" } else { "F|$rel|$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)" }
    } | Sort-Object)
}

# The fixture's truth: per root, whether it exists and its canonical lines (app.exe is left out: the uninstaller
# removes it and nothing of Purge puts it back). The ARP key is not a root: the uninstaller owns it.
function Get-FixtureTruth([string]$Id, [string]$Label) {
    $f = Get-Fixture $Id
    $roots = New-Object System.Collections.ArrayList
    $add = { param([string]$Root, $Lines) [void]$roots.Add([ordered]@{ root = $Root; exists = ($null -ne $Lines); lines = @($Lines) }) }
    & $add $f.dir (Get-DirLines $f.dir @('app.exe'))
    & $add $f.pdata (Get-DirLines $f.pdata)
    & $add $f.hklm (Get-RegTreeLines $f.hklm)
    & $add $f.hkcu (Get-RegTreeLines $f.hkcu)
    if ($f.service) { & $add $OwnSvcKey (Get-RegTreeLines $OwnSvcKey -Sddl) }
    [ordered]@{ fixture = $Id; label = $Label; t = (NowIso); roots = @($roots) }
}

function Save-Truth([string]$Id, [string]$Label, [string]$Dir = $Out) {
    $t = Get-FixtureTruth $Id $Label
    Write-JsonFile $t (Join-Path $Dir "truth-$Id-$Label.json") 8
    $t
}

# ------------------------------------------------------------------------------------------ client flows

# One rig client run: spec (broker, steps, vars), optional autopress (a high answerer of each dialog in turn), started at
# medium; Complete-Flow waits for its client.json. -Go: each consent request waits for go-<k>. Returns {dir, ...}.
function Start-Flow([string]$Name, [object[]]$Steps, $Vars = @{}, [string[]]$Press = $null, [string]$BrokerExe = $Broker, [switch]$Go, [switch]$Window) {
    $dir = Join-Path $Out "flows\$Name"
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    Grant-UsersModify $dir
    $spec = [ordered]@{ out = $dir; broker = $BrokerExe; launch = 'runas'; window = [bool]$Window; connects = 1; connect_wait_ms = 30000
                        exit_wait_ms = 60000; go = [bool]$Go; go_wait_ms = 1800000; steps = @($Steps); vars = $Vars }
    Write-Spec $spec (Join-Path $dir 'spec.json')
    $ap = $null
    if ($null -ne $Press) {
        $aps = [ordered]@{ out = (Join-Path $dir 'autopress'); broker_image = $BrokerExe; stop_file = (Join-Path $dir 'autopress.stop'); sequence = @($Press); tick = $true; arm_wait_ms = 1800; max = 20 }
        Write-Spec $aps (Join-Path $dir 'autopress-spec.json')
        $ap = Start-RecDetached @('autopress', (Join-Path $dir 'autopress-spec.json'))
    }
    [IO.File]::WriteAllText((Join-Path $dir 'sessions-before.json'), (ConvertTo-Json @(Get-SessionNames) -Compress))
    $img = Join-Path (Split-Path $BrokerExe) 'Purge.exe'
    Start-Medium $img "client `"$(Join-Path $dir 'spec.json')`"" $Tasks.client
    $fw = $null
    if ($Window) {
        # The client's window in front, as a user's click on the UI would leave it: the broker's dialog then comes to
        # the foreground through the client's AllowSetForegroundWindow (design 8.1), where the host's keys reach it.
        $proc = $null; $d = (Get-Date).AddSeconds(30)
        while (-not $proc -and (Get-Date) -lt $d) { Start-Sleep -Milliseconds 500; $proc = Get-ProcList | Where-Object { $_.path -and $_.path -ieq $img -and $_.cmd -like "*$dir*" } | Select-Object -First 1 }
        if ($proc) { $null = Invoke-Rec @('focuswin', "$($proc.pid)", (Join-Path $dir 'focuswin.json')) 60; $fw = Read-Json (Join-Path $dir 'focuswin.json') }
    }
    [ordered]@{ name = $Name; dir = $dir; autopress_pid = $(if ($ap) { $ap.Id }); t = (NowIso); window_foreground = $(if ($fw) { $fw.foreground }) }
}

function Complete-Flow($F, [int]$Sec = 900) {
    $done = Wait-File (Join-Path $F.dir 'client.json') $Sec
    Stop-Task $Tasks.client
    [IO.File]::WriteAllText((Join-Path $F.dir 'autopress.stop'), (NowIso))
    Start-Sleep -Seconds 1
    $col = { param($p) @(Get-ChildItem -LiteralPath $F.dir -Recurse -Filter $p -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { [ordered]@{ file = $_.Name; data = (Read-Json $_.FullName) } }) }
    [ordered]@{ name = $F.name; finished = $done; client = (Read-Json (Join-Path $F.dir 'client.json')); launched = (Read-Json (Join-Path $F.dir 'launched.json'))
                results = (& $col 'consent-result-*.json'); shown = (& $col 'consent-shown-*.json'); ready = (& $col 'ready-*.json')
                autopress = (& $col 'autopress-*.json'); saved = (& $col 'save-*.json') }
}

function Invoke-Flow([string]$Name, [object[]]$Steps, $Vars = @{}, [string[]]$Press = @('approve'), [string]$BrokerExe = $Broker, [int]$Sec = 900) {
    $f = Start-Flow $Name $Steps $Vars $Press $BrokerExe
    $r = Complete-Flow $f $Sec
    Write-JsonFile $r (Join-Path $Out "flow-$Name.json") 16
    $r
}

# The step records of a finished flow, by op (the client's progress record).
function Get-FlowSteps($R, [string]$Op) { @(@($R.client.steps) | Where-Object { $_.op -eq $Op }) }
function Get-StepResult($Step) { $a = @($Step.asks) | Select-Object -Last 1; if ($a -and $a.response) { $a.response } else { $Step.response } }

# The pending list a fresh broker gives (journal.pending), and history.get of a session.
function Get-Pending([string]$Name, [string]$Session = '') {
    $steps = @(@{ op = 'call'; method = 'journal.pending'; params = @{}; save = 'save-pending.json' })
    if ($Session) { $steps += @{ op = 'call'; method = 'history.get'; params = @{ session = '{session}' }; save = 'save-history.json' } }
    $steps += @{ op = 'shutdown' }
    $r = Invoke-Flow $Name $steps @{ session = $Session } -Press $null -Sec 300
    $p = Read-Json (Join-Path $Out "flows\$Name\save-pending.json")
    $h = Read-Json (Join-Path $Out "flows\$Name\save-history.json")
    [ordered]@{ pending = $p; sessions = @(@($p.result.sessions) | ForEach-Object { "$($_.session)" }); history = $h; history_state = $(if ($h -and $h.result) { "$($h.result.state)" }); flow_finished = $r.finished }
}

# ------------------------------------------------------------------------------------- m3-recover parts

$RecFix = 'rec'

function Get-RecSteps([string]$Restore = 'off') {
    $f = Get-Fixture $RecFix
    @(@{ op = 'prepare'; program = $f.program }, @{ op = 'run'; quiet = $true }, @{ op = 'scan_full' },
      @{ op = 'execute'; select = 'all'; restore_point = $Restore })
}

# ------------------------------------------------------------------------------------------------ phases

Log "== phase $Phase$(if ($Tag) { " tag=$Tag" })$(if ($Fix) { " fix=$Fix" })$(if ($Via) { " via=$Via" })"
switch ($Phase) {
    'build' {
        $fw = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
        $wpf = Join-Path $fw 'WPF'
        Remove-Item -LiteralPath $Exe -Force -ErrorAction SilentlyContinue
        $o = & (Join-Path $fw 'csc.exe') /nologo /target:winexe /platform:x64 /optimize "/out:$Exe" "/r:$wpf\UIAutomationClient.dll" "/r:$wpf\UIAutomationTypes.dll" `
            "/r:$wpf\WindowsBase.dll" '/r:System.Web.Extensions.dll' '/r:System.Windows.Forms.dll' '/r:System.Drawing.dll' 'C:\cr\guest\m3sec.cs' 'C:\cr\guest\m3rec.cs' 2>&1
        foreach ($l in @($o)) { Log "  csc: $l" }
        if (-not (Test-Path -LiteralPath $Exe)) { 'M3R BUILD FAIL'; break }
        New-Item -ItemType Directory -Force $ClientDir, (Join-Path $Bin 'lockers') | Out-Null
        Copy-Item -LiteralPath $Exe -Destination (Join-Path $ClientDir 'Purge.exe') -Force
        Copy-Item -LiteralPath $Exe -Destination (Join-Path $Bin 'lockers\PurgeRigLocker.exe') -Force
        Grant-UsersModify $Out
        "M3R BUILD OK $((Get-Item $Exe).Length)"
    }
    'install' {
        $rec = [ordered]@{ t = (NowIso); install = @(); check = @(); ui = $false }
        if (Test-Path -LiteralPath $Payload) { Remove-Item -LiteralPath $Payload -Recurse -Force }
        Expand-Archive -LiteralPath (Join-Path $Bin 'payload.zip') -DestinationPath $Payload -Force
        $common = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\cr\install\install.ps1', '-SkipBuild',
                    '-Engine', (Join-Path $Payload 'purge-engine.exe'), '-Broker', (Join-Path $Payload 'purge-broker.exe'), '-Kb', (Join-Path $Payload 'kb'))
        $runs = @(@{ name = 'Purge'; args = @('-UiPublishDir', $ClientDir); check = @() })
        if (Test-Path -LiteralPath (Join-Path $Payload 'ui\Purge.exe')) {
            $rec.ui = $true
            $sm = Join-Path $Bin 'startmenu-ui'; New-Item -ItemType Directory -Force $sm | Out-Null
            $runs += @{ name = 'PurgeUI'; args = @('-UiPublishDir', (Join-Path $Payload 'ui'), '-ProgramFilesDir', $PFUI, '-StartMenuDir', $sm); check = @('-ProgramFilesDir', $PFUI, '-StartMenuDir', $sm) }
        }
        $ok = $true
        foreach ($r in $runs) {
            $o = @(& powershell.exe @($common + $r.args) 2>&1 | ForEach-Object { "$_" }); $code = $LASTEXITCODE
            foreach ($l in $o) { Log "  install $($r.name): $l" }
            $rec.install += [ordered]@{ name = $r.name; exit = $code; tail = @($o | Select-Object -Last 5) }
            $c = @(& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'C:\cr\install\install.ps1' -Check @($r.check) 2>&1 | ForEach-Object { "$_" }); $cc = $LASTEXITCODE
            $rec.check += [ordered]@{ name = $r.name; exit = $cc; tail = @($c | Select-Object -Last 5) }
            if ($code -ne 0 -or $cc -ne 0) { $ok = $false }
        }
        $rec.broker_sha256 = (Get-FileHash -LiteralPath $Broker -Algorithm SHA256).Hash
        Write-JsonFile $rec (Join-Path $Out 'install.json') 8
        "M3R INSTALL $(if ($ok) { 'OK' } else { 'FAIL' }) ui=$($rec.ui)"
    }
    'uac-silent' {
        # Coordinator ruling 2026-11-22: rig-base is at the Windows UAC defaults (5/1/1), so these modes make UAC silent
        # themselves (ConsentPromptBehaviorAdmin=0, design 11.2; EnableLUA stays 1, PromptOnSecureDesktop is left) and
        # record the values before and after; the summaries carry uac-silent.json as uac_silent.
        $pk = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $get = { $p = Get-ItemProperty -LiteralPath $pk -ErrorAction SilentlyContinue; [ordered]@{ ConsentPromptBehaviorAdmin = $p.ConsentPromptBehaviorAdmin; PromptOnSecureDesktop = $p.PromptOnSecureDesktop; EnableLUA = $p.EnableLUA } }
        $before = & $get
        $err = $null
        try { Set-ItemProperty -LiteralPath $pk -Name 'ConsentPromptBehaviorAdmin' -Value 0 -Type DWord -ErrorAction Stop } catch { $err = $_.Exception.Message }
        $after = & $get
        $ok = (-not $err -and "$($after.ConsentPromptBehaviorAdmin)" -eq '0' -and "$($after.EnableLUA)" -eq '1')
        Write-JsonFile ([ordered]@{ t = (NowIso); set = [ordered]@{ ConsentPromptBehaviorAdmin = 0 }; before = $before; after = $after; error = $err; ok = $ok }) (Join-Path $Out 'uac-silent.json') 8
        "M3R UAC-SILENT $(if ($ok) { 'OK' } else { 'FAIL' }) before=$($before.ConsentPromptBehaviorAdmin)/$($before.PromptOnSecureDesktop)/$($before.EnableLUA) after=$($after.ConsentPromptBehaviorAdmin)/$($after.PromptOnSecureDesktop)/$($after.EnableLUA) error=$err"
    }
    'sr-enable' {
        # m3-extras: rig-base has System Restore off; the restore-point cases need it on C: (the 'disabled' case turns it
        # off again on purpose). RPSessionInterval 1 = System Restore on (setup-m2.ps1 reads it the same way).
        $srk = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $before = (Get-ItemProperty -LiteralPath $srk -ErrorAction SilentlyContinue).RPSessionInterval
        $err = $null
        try { Enable-ComputerRestore -Drive 'C:\' -ErrorAction Stop } catch { $err = $_.Exception.Message }
        $after = (Get-ItemProperty -LiteralPath $srk -ErrorAction SilentlyContinue).RPSessionInterval
        $ok = ("$after" -eq '1')
        Write-JsonFile ([ordered]@{ t = (NowIso); drive = 'C:\'; rp_session_interval_before = $before; rp_session_interval_after = $after; error = $err; ok = $ok }) (Join-Path $Out 'sr-enable.json') 6
        "M3R SR-ENABLE $(if ($ok) { 'OK' } else { 'FAIL' }) before=$before after=$after error=$err"
    }
    'uac-check' {
        $p = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
        $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $v = [ordered]@{ ConsentPromptBehaviorAdmin = $p.ConsentPromptBehaviorAdmin; PromptOnSecureDesktop = $p.PromptOnSecureDesktop; EnableLUA = $p.EnableLUA
                         build = "$($cv.CurrentBuildNumber).$($cv.UBR)"; boot = (Get-BootTime) }
        Write-JsonFile $v (Join-Path $Out "uac-check$(if ($Tag) { "-$Tag" }).json")
        "M3R UAC-CHECK $(ConvertTo-Json $v -Compress)"
    }
    'fixture' {
        $r = Install-RecFixture $Fix
        $null = Save-Truth $Fix 'installed'
        "M3R FIXTURE $Fix key=$($r.fixture.key) service=$([bool]$r.service)$(if ($r.service) { " guarded_sddl=$($r.service.guarded_sddl)" })"
    }
    'truth' {
        $t = Save-Truth $Fix $Tag
        "M3R TRUTH $Fix $Tag roots=$(@($t.roots | Where-Object { $_.exists }).Count)/$(@($t.roots).Count)"
    }
    'pack' {
        $zip = "C:\cr\out\m3-recover-$Tag.zip"
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path (Join-Path $Out '*') -DestinationPath $zip -Force
        "M3R PACK $Tag $((Get-Item $zip).Length)"
    }
    'flush' { "M3R FLUSH $(Sync-OutFiles)" }

    # -------------------------------------------------------------------------------------- m3-recover
    'crash-arm' {
        # k = 0: the calibration run (the watcher only records every line; the run completes). k >= 1: the watcher
        # suspends the broker when the session journal holds k complete lines; the host then cuts the power.
        $k = [int]$Tag
        $rd = Join-Path $Out "round"
        if (Test-Path -LiteralPath $rd) { Remove-Item -LiteralPath $rd -Recurse -Force }
        Grant-UsersModify $rd
        $rec = [ordered]@{ k = $k; t = (NowIso); boot = (Get-BootTime); sessions_before = @(Get-SessionNames) }
        $null = Save-Truth $RecFix 'pre' $rd
        $ws = [ordered]@{ out = (Join-Path $rd 'watch.json'); sessions = $Sessions; existing = $rec.sessions_before; broker_image = $Broker
                          target = $k; action = $(if ($k -eq 0) { 'record' } else { 'suspend' }); timeout_ms = 1200000 }
        Write-Spec $ws (Join-Path $rd 'watch-spec.json')
        $w = Start-RecDetached @('watch', (Join-Path $rd 'watch-spec.json'))
        $rec.watcher_pid = $w.Id
        $f = Start-Flow 'rec-run' (Get-RecSteps) @{} @('approve', 'approve')
        $rec.flow = $f
        # Wait: suspended (the step was reached), or the run ended (the client wrote client.json) before the step.
        $deadline = (Get-Date).AddSeconds([Math]::Max($WaitSec, 600))
        $st = $null
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
            $st = Read-Json $ws.out
            # The watcher writes its file when armed and once more when it is done (suspended, or the run ended first).
            if ($k -gt 0 -and $st -and $st.state -ne 'armed') { break }
            if (Test-Path -LiteralPath (Join-Path $f.dir 'client.json')) { Start-Sleep -Seconds 3; $st = Read-Json $ws.out; break }
        }
        $rec.watch = $st
        if ($k -eq 0) {
            $rec.flow_result = Complete-Flow $f 600
            $null = $w.WaitForExit(30000)
            $rec.watch = Read-Json $ws.out
            $null = Save-Truth $RecFix 'complete' $rd
            $sess = @(Get-SessionNames | Where-Object { $rec.sessions_before -notcontains $_ }) | Select-Object -First 1
            $rec.session = $sess
            $rec.store = Get-StoreTruth $sess
        } else {
            $rec.client_finished_first = (Test-Path -LiteralPath (Join-Path $f.dir 'client.json'))
        }
        $rec.t_end = (NowIso)
        Write-JsonFile $rec (Join-Path $rd 'arm.json') 12
        $flush = Sync-OutFiles
        "M3R ARM k=$k state=$($rec.watch.state) lines_at_hit=$($rec.watch.lines_seen_at_hit) lines_at_suspend=$($rec.watch.lines_at_suspend) lines=$($rec.watch.lines) session=$($rec.watch.session) flushed=$flush"
    }
    'after-boot' {
        $k = [int]$Tag
        $rd = Join-Path $Out 'round'
        $arm = Read-Json (Join-Path $rd 'arm.json')
        $rec = [ordered]@{ k = $k; t = (NowIso); boot_before = $(if ($arm) { $arm.boot }); boot_after = (Get-BootTime); session = $(if ($arm -and $arm.watch) { $arm.watch.session }) }
        $rec.boot_changed = ($rec.boot_before -and $rec.boot_after -ne $rec.boot_before)
        $rec.sessions = @(Get-SessionNames)
        if (-not $rec.session) { $rec.session = @($rec.sessions | Where-Object { @($arm.sessions_before) -notcontains $_ }) | Select-Object -First 1 }
        $rec.store = Get-StoreTruth $rec.session
        $null = Save-Truth $RecFix 'boot' $rd
        $p = Get-Pending 'pending-boot' $rec.session
        $rec.pending = $p
        $rec.listed = (@($p.sessions) -contains "$($rec.session)")
        $rec.class = $(if ($rec.listed) { 'pending' } elseif (-not $rec.session -or $rec.store.journal_lines -eq 0) { 'none' } elseif ($rec.store.index_listed) { 'finished' } else { 'unindexed' })
        Write-JsonFile $rec (Join-Path $rd 'boot.json') 12
        "M3R BOOT k=$k class=$($rec.class) session=$($rec.session) lines=$($rec.store.journal_lines) last=$($rec.store.journal_last_rec) listed=$($rec.listed) boot_changed=$($rec.boot_changed)"
    }
    'ui-check' {
        $rd = Join-Path $Out 'round'
        $rec = [ordered]@{ t = (NowIso); present = (Test-Path -LiteralPath (Join-Path $PFUI 'Purge.exe')) }
        if ($rec.present) {
            Get-ProcList | Where-Object { $_.path -and $_.path -ieq (Join-Path $PFUI 'Purge.exe') } | ForEach-Object { Stop-Process -Id $_.pid -Force -ErrorAction SilentlyContinue }
            $l = LaunchMedium -Exe (Join-Path $PFUI 'Purge.exe') -TaskName $Tasks.ui -StartTimeoutSec 60
            $rec.ui_pid = $l.pid
            Start-Sleep -Seconds 8
            if ($l.pid) { $null = Invoke-Rec @('focuswin', "$($l.pid)", (Join-Path $rd 'ui-focus.json')) 60 }
            $spec = [ordered]@{ out = (Join-Path $rd 'ui-check.json'); pid = $l.pid; action = 'check'; wait_ms = 120000 }
            Write-Spec $spec (Join-Path $rd 'ui-check-spec.json')
            $null = Invoke-Rec @('uihist', (Join-Path $rd 'ui-check-spec.json')) 240
            $u = Read-Json $spec.out
            $rec.check = $u
            # The banner is for the selected interrupted session: its app name and start are shown, not its id; the UI
            # lists it from journal.pending, so the banner and the Resume/Roll back buttons are the evidence.
            $rec.banner = ($u -and $u.banner -eq $true)
            $rec.buttons = ($u -and $u.resume_button -eq $true -and $u.rollback_button -eq $true)
            $rec.app_named = ($u -and @($u.texts | Where-Object { "$_" -like "*$((Get-Fixture $RecFix).name)*" }).Count -gt 0)
        }
        Write-JsonFile $rec (Join-Path $rd 'ui.json') 10
        "M3R UI k=$Tag present=$($rec.present) banner=$($rec.banner) buttons=$($rec.buttons) app_named=$($rec.app_named)"
    }
    'recover-start' {
        # Tag k-after. Via ui: the real UI's Resume or Roll back button; via client: journal.resume / journal.rollback
        # through the rig client. Either way the broker's dialog is answered by the host's keys afterwards.
        $after = ($Tag -split '-')[-1]
        if ($after -notin 'resume', 'rollback') { throw "recover-start needs -Tag <k>-resume|rollback, got $Tag" }
        $rd = Join-Path $Out 'round'
        $boot = Read-Json (Join-Path $rd 'boot.json')
        $rec = [ordered]@{ tag = $Tag; after = $after; via = $Via; t = (NowIso); session = $boot.session; events_since = (Get-Date).AddSeconds(-2).ToString('o') }
        if ($Via -eq 'ui') {
            $ui = Read-Json (Join-Path $rd 'ui.json')
            $spec = [ordered]@{ out = (Join-Path $rd 'ui-recover.json'); pid = $ui.ui_pid; action = $after; wait_ms = 60000 }
            Write-Spec $spec (Join-Path $rd 'ui-recover-spec.json')
            $null = Invoke-Rec @('uihist', (Join-Path $rd 'ui-recover-spec.json')) 120
            $rec.ui = Read-Json $spec.out
        } else {
            $m = $(if ($after -eq 'resume') { 'journal.resume' } else { 'journal.rollback' })
            $f = Start-Flow 'recover' @(@{ op = 'consent'; method = $m; params = @{ session = '{session}' } }) @{ session = "$($boot.session)" } $null $Broker -Go -Window
            $rec.flow = $f
            if (Wait-File (Join-Path $f.dir 'ready-1.json') 120) { [IO.File]::WriteAllText((Join-Path $f.dir 'go-1'), (NowIso)) }
        }
        # The dialog: a broker with a "Purge security prompt" window (the UI's broker of the check may be the one asking).
        $deadline = (Get-Date).AddSeconds(120); $bp = $null; $d = $null
        while (-not $d -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 1
            foreach ($p in Get-BrokerProcs '') {
                $null = Invoke-Rec @('observe', "$($p.pid)", (Join-Path $rd 'dialog.json'), '2000') 30
                $o = Read-Json (Join-Path $rd 'dialog.json')
                if ($o -and $o.found) { $bp = $p; $d = $o; break }
            }
        }
        $rec.broker_pid = $(if ($bp) { $bp.pid }); $rec.broker_image = $(if ($bp) { $bp.path })
        $rec.dialog = $d
        Write-JsonFile $rec (Join-Path $rd 'recover-start.json') 12
        "M3R DIALOG $Tag found=$([bool]$d) broker=$($rec.broker_pid) primary='$(if ($d) { $d.labels.primary })' verify=$(if ($d -and $d.verify) { $d.verify.toggle } else { 'none' }) footer=$(if ($d) { $d.footer_code })"
    }
    'dialog-focus' {
        # What the host's keys did so far: the dialog (or none), the focused element, the box, the primary button.
        $rd = Join-Path $Out 'round'
        $st = Read-Json (Join-Path $rd 'recover-start.json')
        $pid0 = $(if ($st -and $st.broker_pid) { [int]$st.broker_pid } else { 0 })
        $f = Join-Path $rd "focus-$Tag.json"
        $null = Invoke-Rec @('focused', "$pid0", $f) 30
        $o = Read-Json $f
        $refocused = $false
        if ($o -and $o.found -and $o.focused_in_dialog -ne $true) {
            # The keys would go to another window: the dialog is brought to the front (recorded; the scorer reports it).
            $null = Invoke-Rec @('focus', "$pid0", (Join-Path $rd "refocus-$Tag.json")) 30
            $null = Invoke-Rec @('focused', "$pid0", $f) 30
            $o = Read-Json $f
            $refocused = $true
        }
        "M3R FOCUS $Tag refocused=$refocused found=$([bool]($o -and $o.found)) focused='$(if ($o) { $o.focused_name })' type=$(if ($o -and $o.focused_type) { $o.focused_type } else { 'none' }) in_dialog=$(if ($o) { $o.focused_in_dialog }) primary='$(if ($o) { $o.labels.primary })' enabled=$(if ($o) { $o.primary_enabled }) verify=$(if ($o -and $o.verify) { $o.verify.toggle } else { 'none' })"
    }
    'recover-result' {
        $rd = Join-Path $Out 'round'
        $st = Read-Json (Join-Path $rd 'recover-start.json')
        $boot = Read-Json (Join-Path $rd 'boot.json')
        $rec = [ordered]@{ tag = $Tag; t = (NowIso); start = $st }
        # The broker finishes the run, answers and exits (design 3.6); then the UI shows its result.
        if ($st -and $st.broker_pid) { try { $null = (Get-Process -Id ([int]$st.broker_pid) -ErrorAction Stop).WaitForExit(600000) } catch { } }
        Start-Sleep -Seconds 3
        if ($st.via -eq 'ui') {
            $ui = Read-Json (Join-Path $rd 'ui.json')
            $spec = [ordered]@{ out = (Join-Path $rd 'ui-after.json'); pid = $ui.ui_pid; action = 'read'; wait_ms = 30000 }
            Write-Spec $spec (Join-Path $rd 'ui-after-spec.json')
            $null = Invoke-Rec @('uihist', (Join-Path $rd 'ui-after-spec.json')) 90
            $rec.ui_after = Read-Json $spec.out
            Stop-Task $Tasks.ui
            Get-ProcList | Where-Object { $_.path -and $_.path -ieq (Join-Path $PFUI 'Purge.exe') } | ForEach-Object { Stop-Process -Id $_.pid -Force -ErrorAction SilentlyContinue }
        } else {
            $f = [ordered]@{ name = 'recover'; dir = (Join-Path $Out 'flows\recover') }
            $rec.flow = Complete-Flow $f 600
        }
        $rec.broker_gone = $(if ($st -and $st.broker_pid) { -not [bool](Get-Process -Id ([int]$st.broker_pid) -ErrorAction SilentlyContinue) } else { $null })
        $p = Get-Pending 'pending-after' $boot.session
        $rec.pending_after = $p
        $rec.store = Get-StoreTruth $boot.session
        $rec.events = @(Get-PurgeEvents ([datetime]$st.events_since))
        $null = Save-Truth $RecFix 'after' $rd
        Write-JsonFile $rec (Join-Path $rd 'result.json') 14
        "M3R RESULT $Tag pending_after=$(@($p.sessions).Count) history=$($p.history_state) index=$($rec.store.index_state) quarantine_ops=$(@($rec.store.quarantine_ops).Count)"
    }
    'bookkeeping' {
        # A session whose journal is complete but whose index entry or report is missing: journal.resume runs the
        # bookkeeping without a dialog (writer notes undo.md choice 5). No go file: a dialog would wait and fail the row.
        $rd = Join-Path $Out 'round'
        $boot = Read-Json (Join-Path $rd 'boot.json')
        $r = Invoke-Flow 'bookkeeping' @(@{ op = 'consent'; method = 'journal.resume'; params = @{ session = '{session}' } }) @{ session = "$($boot.session)" } $null $Broker 300
        $rec = [ordered]@{ t = (NowIso); flow = $r; dialog_shown = (@($r.shown).Count -gt 0); store = (Get-StoreTruth $boot.session); pending_after = (Get-Pending 'pending-after' $boot.session) }
        $null = Save-Truth $RecFix 'after' $rd
        Write-JsonFile $rec (Join-Path $rd 'bookkeeping.json') 14
        "M3R BOOKKEEPING k=$Tag dialog=$($rec.dialog_shown) index=$($rec.store.index_state) pending_after=$(@($rec.pending_after.sessions).Count)"
    }

    # ---------------------------------------------------------------------------------------- m3-owner
    'own-exec' {
        $f = Get-Fixture 'own'
        $rec = [ordered]@{ t = (NowIso); sddl_recorded = (Get-KeySddl $OwnGuarded); tree_before = (Get-RegTreeLines $OwnSvcKey -Sddl) }
        $null = Save-Truth 'own' 'pre'
        $r = Invoke-Flow 'own-exec' @(@{ op = 'prepare'; program = $f.program }, @{ op = 'run'; quiet = $true }, @{ op = 'scan_full' },
                                      @{ op = 'execute'; select = 'all'; restore_point = 'off' }) @{} @('approve', 'approve')
        $ex = Get-FlowSteps $r 'execute' | Select-Object -Last 1
        $rec.session = $ex.session
        $rec.exec_result = Get-StepResult $ex
        $rec.service_after = [bool](Get-Service -Name $OwnSvc -ErrorAction SilentlyContinue)
        $rec.tree_after = Get-RegTreeLines $OwnSvcKey -Sddl
        $rec.store = Get-StoreTruth $rec.session
        $rows = Read-Json (Join-Path $Out 'flows\own-exec\candidates-full.json')
        $rec.service_candidate = @($rows | Where-Object { $_.kind -eq 'service' -and "$($_.display_name)" -like "*$OwnSvc*" }) | Select-Object -First 1
        $null = Save-Truth 'own' 'executed'
        Write-JsonFile $rec (Join-Path $Out 'own-exec.json') 12
        "M3R OWN-EXEC session=$($rec.session) outcome=$($rec.exec_result.result.outcome) service_after=$($rec.service_after) candidate=$([bool]$rec.service_candidate)"
    }
    'own-undo-cut' {
        # The undo of the session, cut right after the undo_intent of the service op is in the journal: the watcher
        # suspends and ends the broker. Then the rest of the first attempt that R8b M1 describes is put in place: the
        # service exists as the attempt creates it, and Parameters\Guarded exists with the recorded group and DACL but
        # the creator (Administrators) as owner, because creation cannot assign SYSTEM and the process ended before the
        # security write. Every part found or set is recorded.
        $ex = Read-Json (Join-Path $Out 'own-exec.json')
        $s = "$($ex.session)"
        $rec = [ordered]@{ t = (NowIso); session = $s }
        $jl = @(Get-Content -LiteralPath (Join-Path $Sessions "$s\journal.jsonl") -Encoding UTF8 -ErrorAction SilentlyContinue)
        $named = @($jl | Where-Object { $_ -match '"rec":"intent"' -and $_ -match [regex]::Escape($OwnSvc) })
        $intent = @(@($named | Where-Object { $_ -match 'DeleteService' }) + $named) | Select-Object -First 1
        $op = $(if ($intent -and $intent -match '"op":(\d+)') { [int]$Matches[1] })
        $rec.service_op = $op
        if (-not $op) { Write-JsonFile $rec (Join-Path $Out 'own-undo-cut.json') 8; 'M3R OWN-CUT FAIL no service op in the journal'; break }
        $ws = [ordered]@{ out = (Join-Path $Out 'own-watch.json'); sessions = $Sessions; session = $s; broker_image = $Broker
                          match_regex = ('^(?=.*"rec":"undo_intent")(?=.*"op":{0}[,}}])' -f $op); action = 'suspend-kill'; timeout_ms = 900000 }
        Write-Spec $ws (Join-Path $Out 'own-watch-spec.json')
        $w = Start-RecDetached @('watch', (Join-Path $Out 'own-watch-spec.json'))
        $r = Invoke-Flow 'own-undo' @(@{ op = 'consent'; method = 'undo.run'; params = @{ session = '{session}' } }) @{ session = $s } @('approve') $Broker 600
        $null = $w.WaitForExit(60000)
        $rec.watch = Read-Json $ws.out
        $rec.undo_flow_kind = @($r.results | ForEach-Object { $_.data.kind }) -join ','
        $found = [ordered]@{ service = [bool](Get-Service -Name $OwnSvc -ErrorAction SilentlyContinue); parameters = (Test-Path -LiteralPath (ConvertTo-PsReg "$OwnSvcKey\Parameters"))
                             guarded = (Test-Path -LiteralPath (ConvertTo-PsReg $OwnGuarded)); guarded_sddl = (Get-KeySddl $OwnGuarded); tree = (Get-RegTreeLines $OwnSvcKey -Sddl) }
        $rec.found = $found
        $set = @()
        $fx = Get-Fixture 'own'
        if (-not $found.service) {
            $o = try { New-OwnService $fx.dir } catch { "New-Service failed: $($_.Exception.Message)" }
            $set += "service: $o"
        }
        $pk = ConvertTo-PsReg "$OwnSvcKey\Parameters"
        if (-not (Test-Path -LiteralPath $pk)) { $null = New-Item -Path $pk -Force; $set += 'Parameters created (inherited descriptor, no values)' }
        $gk = ConvertTo-PsReg $OwnGuarded
        if (Test-Path -LiteralPath $gk) { $null = Invoke-Rec @('regsd', $OwnGuarded, 'O:BAG:BAD:(A;;KA;;;BA)', 'd') 30; Remove-Item -LiteralPath $gk -Recurse -Force; $set += 'Guarded removed (the attempt had got further)' }
        $null = New-Item -Path $gk -Force
        $code = Invoke-Rec @('regsd', $OwnGuarded, $OwnSddl, 'gdp') 30
        $set += "Guarded created by Administrators, recorded group and DACL set (regsd exit $code), owner left"
        $rec.staged = $set
        $rec.half_sddl = Get-KeySddl $OwnGuarded
        $rec.half_tree = Get-RegTreeLines $OwnSvcKey -Sddl
        $rec.pending = Get-Pending 'own-pending-cut' $s
        $rec.listed = (@($rec.pending.sessions) -contains $s)
        Write-JsonFile $rec (Join-Path $Out 'own-undo-cut.json') 12
        "M3R OWN-CUT op=$op watch=$($rec.watch.state) hit_line=$($rec.watch.hit_line) half_sddl=$($rec.half_sddl) listed=$($rec.listed)"
    }
    'own-resume-start' {
        $cut = Read-Json (Join-Path $Out 'own-undo-cut.json')
        $s = "$($cut.session)"
        $rec = [ordered]@{ t = (NowIso); session = $s; since = (Get-Date).AddSeconds(-2).ToString('o') }
        # Privilege-use auditing (Security log 4673/4674) for this run: which objects SeRestorePrivilege opened.
        $rec.auditpol = "$(& auditpol.exe /set /subcategory:'{0CCE9228-69AE-11D9-BED3-505054503030}' /success:enable 2>&1)"
        $ps = [ordered]@{ out = (Join-Path $Out 'own-privmon.json'); broker_image = $Broker; stop_file = (Join-Path $Out 'own-privmon.stop'); max_ms = 1800000 }
        Remove-Item -LiteralPath $ps.stop_file -Force -ErrorAction SilentlyContinue
        Write-Spec $ps (Join-Path $Out 'own-privmon-spec.json')
        $pm = Start-RecDetached @('privmon', (Join-Path $Out 'own-privmon-spec.json'))
        $rec.privmon_pid = $pm.Id
        Start-Sleep -Seconds 1
        $f = Start-Flow 'own-resume' @(@{ op = 'call'; method = 'journal.pending'; params = @{}; save = 'save-pending.json' },
                                       @{ op = 'consent'; method = 'journal.resume'; params = @{ session = '{session}' } }) @{ session = $s } $null $Broker -Go -Window
        $rec.flow = $f
        if (Wait-File (Join-Path $f.dir 'ready-1.json') 180) { [IO.File]::WriteAllText((Join-Path $f.dir 'go-1'), (NowIso)) }
        $rd = Join-Path $Out 'round'
        New-Item -ItemType Directory -Force $rd | Out-Null
        $deadline = (Get-Date).AddSeconds(120); $bp = $null; $d = $null
        while (-not $d -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 1
            foreach ($p in Get-BrokerProcs $Broker) {
                $null = Invoke-Rec @('observe', "$($p.pid)", (Join-Path $rd 'dialog.json'), '2000') 30
                $o = Read-Json (Join-Path $rd 'dialog.json')
                if ($o -and $o.found) { $bp = $p; $d = $o; break }
            }
        }
        $rec.broker_pid = $(if ($bp) { $bp.pid }); $rec.dialog = $d; $rec.via = 'client'; $rec.events_since = $rec.since
        Write-JsonFile $rec (Join-Path $rd 'recover-start.json') 12
        Write-JsonFile $rec (Join-Path $Out 'own-resume-start.json') 12
        "M3R DIALOG own found=$([bool]$d) broker=$($rec.broker_pid) primary='$(if ($d) { $d.labels.primary })' footer=$(if ($d) { $d.footer_code })"
    }
    'own-resume-result' {
        $st = Read-Json (Join-Path $Out 'own-resume-start.json')
        $cut = Read-Json (Join-Path $Out 'own-undo-cut.json')
        $ex = Read-Json (Join-Path $Out 'own-exec.json')
        $s = "$($st.session)"
        $rec = [ordered]@{ t = (NowIso); session = $s }
        if ($st.broker_pid) { try { $null = (Get-Process -Id ([int]$st.broker_pid) -ErrorAction Stop).WaitForExit(600000) } catch { } }
        $rec.flow = Complete-Flow ([ordered]@{ name = 'own-resume'; dir = (Join-Path $Out 'flows\own-resume') }) 300
        $rec.pending_before = Read-Json (Join-Path $Out 'flows\own-resume\save-pending.json')
        [IO.File]::WriteAllText((Join-Path $Out 'own-privmon.stop'), (NowIso))
        Start-Sleep -Seconds 3
        $rec.privmon = Read-Json (Join-Path $Out 'own-privmon.json')
        $since = [datetime]$st.since
        $rec.audit = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4673, 4674; StartTime = $since } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'SeRestorePrivilege' } | ForEach-Object {
                $x = [xml]$_.ToXml(); $dd = @{}; foreach ($n in $x.Event.EventData.Data) { $dd[$n.Name] = "$($n.'#text')" }
                [ordered]@{ id = $_.Id; time = $_.TimeCreated.ToString('o'); process = $dd['ProcessName']; object = $dd['ObjectName']; privileges = $dd['PrivilegeList'] } })
        $rec.events = @(Get-PurgeEvents $since)
        $rec.sddl_after = Get-KeySddl $OwnGuarded
        $rec.sddl_recorded = $ex.sddl_recorded
        $rec.tree_after = Get-RegTreeLines $OwnSvcKey -Sddl
        $rec.tree_before = $ex.tree_before
        $rec.half_sddl = $cut.half_sddl
        $rec.pending_after = Get-Pending 'own-pending-after' $s
        $rec.store = Get-StoreTruth $s
        $rec.start = $st
        $null = Save-Truth 'own' 'after'
        Write-JsonFile $rec (Join-Path $Out 'own-resume-result.json') 14
        $sum = [ordered]@{ schema = 'purge.rig.m3rec.owner/1'; t = (NowIso); install = (Read-Json (Join-Path $Out 'install.json')); fixture = (Read-Json (Join-Path $Out 'fixture-own.json'))
                           exec = $ex; cut = $cut; resume = $rec; uac = (Read-Json (Join-Path $Out 'uac-check.json')); uac_silent = (Read-Json (Join-Path $Out 'uac-silent.json')) }
        Write-JsonFile $sum (Join-Path $Out 'm3-owner.json') 18
        "M3R OWN-RESULT sddl_after=$($rec.sddl_after) equal=$($rec.sddl_after -ceq $rec.sddl_recorded) pending_after=$(@($rec.pending_after.sessions).Count) audit=$(@($rec.audit).Count) privmon_thread_enabled=$($rec.privmon.thread_restore_enabled_samples)"
    }

    # --------------------------------------------------------------------------------------- m3-extras
    'npp-install' {
        $inst = 'C:\cr\inst\npp.exe'
        $rec = [ordered]@{ t = (NowIso); installer = (Test-Path -LiteralPath $inst) }
        if ($rec.installer) {
            $rec.installer_sha256 = (Get-FileHash -LiteralPath $inst -Algorithm SHA256).Hash
            $p = Start-Process -FilePath $inst -ArgumentList '/S' -PassThru -Wait
            $rec.exit = $p.ExitCode
        }
        $arp = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | Where-Object { "$((Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).DisplayName)" -match '^Notepad\+\+' }) | Select-Object -First 1
        $rec.program = $(if ($arp) { "HKLM|64|$($arp.PSChildName)" })
        $rec.packages = @(Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*NotepadPlusPlus*' -or $_.PackageFamilyName -like 'NotepadPlusPlus*' } | ForEach-Object { [ordered]@{ name = $_.Name; full = $_.PackageFullName; family = $_.PackageFamilyName; location = $_.InstallLocation } })
        Write-JsonFile $rec (Join-Path $Out 'npp.json') 8
        "M3R NPP installer=$($rec.installer) exit=$($rec.exit) program=$($rec.program) packages=$(@($rec.packages).Count)"
    }
    'irrev' {
        # allow_irreversible (M3-EXEC writer notes, contract 2): off -> the package is "Leave alone", no dialog, nothing
        # removed; on -> the dialog names it, gates its button behind the box; Cancel removes nothing; approval removes it,
        # and an undo cannot put it back.
        $npp = Read-Json (Join-Path $Out 'npp.json')
        $rec = [ordered]@{ t = (NowIso); program = $npp.program; packages_before = $npp.packages }
        $pkg = { @(Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { $_.PackageFamilyName -like 'NotepadPlusPlus*' }).Count }
        if (-not $npp.program) { Write-JsonFile $rec (Join-Path $Out 'irrev.json') 8; 'M3R IRREV FAIL no Notepad++ entry'; break }
        $steps = @(@{ op = 'prepare'; program = $npp.program }, @{ op = 'scan_full'; forced = $true; save = 'candidates-off.json' },
                   @{ op = 'execute'; select = 'kind:package'; allow_irreversible = $false; restore_point = 'off' },
                   @{ op = 'scan_full'; forced = $true; save = 'candidates-on.json' },
                   @{ op = 'execute'; select = 'kind:package'; allow_irreversible = $true; restore_point = 'off'; repeat = 2 },
                   @{ op = 'call'; method = 'undo.run'; params = @{ session = '{session}' }; save = 'save-undo.json' })
        $r = Invoke-Flow 'irrev' $steps @{} @('cancel', 'approve') $Broker 1200
        $rec.flow = $r
        $rec.package_rows = @(Read-Json (Join-Path $Out 'flows\irrev\candidates-off.json') | Where-Object { $_.kind -eq 'package' })
        # The second scan ran after the run with the flag off: the package still listed there is what that run left alone.
        $rec.package_rows_on = @(Read-Json (Join-Path $Out 'flows\irrev\candidates-on.json') | Where-Object { $_.kind -eq 'package' })
        $ex = @(Get-FlowSteps $r 'execute')
        $rec.off = $(if ($ex.Count -ge 1) { $ex[0] })
        $rec.on = $(if ($ex.Count -ge 2) { $ex[1] })
        $rec.undo = Read-Json (Join-Path $Out 'flows\irrev\save-undo.json')
        $rec.packages_after = & $pkg
        Write-JsonFile $rec (Join-Path $Out 'irrev.json') 16
        "M3R IRREV package_rows=$(@($rec.package_rows).Count) dialogs=$(@($r.autopress).Count) packages_after=$($rec.packages_after)"
    }
    'rm-exec' {
        # Restart Manager, report-only (M3_DESIGN.md 7 answer 5, 7a delta 1): two files held by a running app. Purge names
        # the lockers and closes nothing; a file whose ancestors a user can write is held for a retry, one in Program
        # Files gets a boot-time move into quarantine (ENGINE_PLAN 7.6).
        $f = Get-Fixture 'rm'
        $rec = [ordered]@{ t = (NowIso) }
        $locker = Join-Path $Bin 'lockers\PurgeRigLocker.exe'
        $holds = [ordered]@{ held = (Join-Path $f.pdata 'locked.dat'); boot = (Join-Path $f.dir 'bin\locked.dll') }
        $rec.lockers = [ordered]@{}
        $i = 1
        foreach ($k in $holds.Keys) {
            $stop = Join-Path $Out "rm-hold-$k.stop"
            Remove-Item -LiteralPath $stop, "$stop.holding.json" -Force -ErrorAction SilentlyContinue
            Start-Medium $locker "hold `"$($holds[$k])`" `"$stop`"" $Tasks["hold$i"]
            $null = Wait-File "$stop.holding.json" 60
            $rec.lockers[$k] = Read-Json "$stop.holding.json"
            $i++
        }
        $null = Save-Truth 'rm' 'pre'
        $rec.pfro_before = @((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
        $r = Invoke-Flow 'rm-exec' @(@{ op = 'prepare'; program = $f.program }, @{ op = 'run'; quiet = $true }, @{ op = 'scan_full' },
                                     @{ op = 'execute'; select = 'all'; restore_point = 'off' }) @{} @('approve', 'approve')
        $ex = Get-FlowSteps $r 'execute' | Select-Object -Last 1
        $rec.session = $ex.session
        $rec.exec_result = Get-StepResult $ex
        $rec.pfro_after = @((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
        $rec.lockers_alive = [ordered]@{}
        foreach ($k in $holds.Keys) { $rec.lockers_alive[$k] = [bool](Get-Process -Id ([int]$rec.lockers[$k].pid) -ErrorAction SilentlyContinue) }
        $rec.sources_present = [ordered]@{}
        foreach ($k in $holds.Keys) { $rec.sources_present[$k] = (Test-Path -LiteralPath $holds[$k]) }
        $rec.holds = $holds
        $rec.history = (Get-Pending 'rm-history' "$($rec.session)").history
        $rec.store = Get-StoreTruth "$($rec.session)"
        Write-JsonFile $rec (Join-Path $Out 'rm-exec.json') 14
        "M3R RM-EXEC session=$($rec.session) outcome=$($rec.exec_result.result.outcome) held=$(@($rec.exec_result.result.held).Count) lockers_alive=$(@($rec.lockers_alive.Values | Where-Object { $_ }).Count)/2"
    }
    'rm-retry' {
        # The user closes the app that held locked.dat (here: the rig ends that locker), then retries the held items
        # through the broker's dialog.
        $ex = Read-Json (Join-Path $Out 'rm-exec.json')
        $rec = [ordered]@{ t = (NowIso); session = $ex.session }
        [IO.File]::WriteAllText((Join-Path $Out 'rm-hold-held.stop'), (NowIso))
        Start-Sleep -Seconds 3
        $rec.held_locker_alive = [bool](Get-Process -Id ([int]$ex.lockers.held.pid) -ErrorAction SilentlyContinue)
        $r = Invoke-Flow 'rm-retry' @(@{ op = 'consent'; method = 'journal.retry_held'; params = @{ session = '{session}' } }) @{ session = "$($ex.session)" } @('approve') $Broker 600
        $rec.flow = $r
        $rec.result = @($r.results | Select-Object -Last 1 | ForEach-Object { $_.data })
        $rec.source_present = Test-Path -LiteralPath $ex.holds.held
        $rec.store = Get-StoreTruth "$($ex.session)"
        $rec.boot_before = Get-BootTime
        Write-JsonFile $rec (Join-Path $Out 'rm-retry.json') 14
        "M3R RM-RETRY kind=$($rec.result.kind) outcome=$($rec.result.response.result.outcome) source_present=$($rec.source_present)"
    }
    'rm-after-reboot' {
        $ex = Read-Json (Join-Path $Out 'rm-exec.json')
        $rt = Read-Json (Join-Path $Out 'rm-retry.json')
        $rec = [ordered]@{ t = (NowIso); boot_before = $rt.boot_before; boot_after = (Get-BootTime); source_present = (Test-Path -LiteralPath $ex.holds.boot) }
        $leaf = Split-Path -Leaf $ex.holds.boot
        $rec.in_quarantine = @(Get-ChildItem -LiteralPath (Join-Path $Quarantine "$($ex.session)") -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq $leaf } | ForEach-Object { $_.FullName })
        $rec.history = (Get-Pending 'rm-history-boot' "$($ex.session)").history
        $null = Save-Truth 'rm' 'after'
        Write-JsonFile $rec (Join-Path $Out 'rm-after-reboot.json') 12
        "M3R RM-BOOT boot_changed=$($rec.boot_before -ne $rec.boot_after) source_present=$($rec.source_present) in_quarantine=$(@($rec.in_quarantine).Count)"
    }
    'sr' {
        # System Restore (ENGINE_PLAN 7.7, 7a delta 4): the dialog says a restore point will be asked for, and the outcome
        # records what Windows did. off: not asked; disabled: System Restore off on C:; created: on, no frequency limit;
        # throttled: right after created, with the default 24-hour limit.
        $map = @{ off = 'sr1'; disabled = 'sr2'; created = 'sr3'; throttled = 'sr4' }
        $fid = $map[$Tag]
        if (-not $fid) { throw "sr needs -Tag off|disabled|created|throttled" }
        $f = Get-Fixture $fid
        $srKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $rec = [ordered]@{ t = (NowIso); case = $Tag; fixture = $fid; setup = @() }
        switch ($Tag) {
            'disabled' { Disable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue; $rec.setup += 'Disable-ComputerRestore C:\' }
            'created' {
                Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
                $null = New-Item -Path $srKey -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -LiteralPath $srKey -Name 'SystemRestorePointCreationFrequency' -Value 0 -Type DWord
                $rec.setup += 'Enable-ComputerRestore C:\', 'SystemRestorePointCreationFrequency=0'
            }
            'throttled' { Remove-ItemProperty -LiteralPath $srKey -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue; $rec.setup += 'SystemRestorePointCreationFrequency removed (default 24 h)' }
        }
        $rec.points_before = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ sequence = $_.SequenceNumber; description = $_.Description; time = "$($_.CreationTime)" } })
        $restore = $(if ($Tag -eq 'off') { 'off' } else { 'always' })
        $r = Invoke-Flow "sr-$Tag" @(@{ op = 'prepare'; program = $f.program }, @{ op = 'run'; quiet = $true }, @{ op = 'scan_full' },
                                    @{ op = 'execute'; select = 'all'; restore_point = $restore }) @{} @('approve', 'approve')
        $ex = Get-FlowSteps $r 'execute' | Select-Object -Last 1
        $rec.restore_point = $restore
        $rec.exec_result = Get-StepResult $ex
        $rec.plan_dialog = @($r.autopress | Select-Object -Last 1 | ForEach-Object { $_.data.pre })
        $rec.points_after = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ sequence = $_.SequenceNumber; description = $_.Description; time = "$($_.CreationTime)" } })
        Write-JsonFile $rec (Join-Path $Out "sr-$Tag.json") 14
        "M3R SR $Tag outcome=$($rec.exec_result.result.outcome) restore_point=$($rec.exec_result.result.restore_point.kind) points=$(@($rec.points_before).Count)->$(@($rec.points_after).Count)"
    }
    'extras-summary' {
        $sum = [ordered]@{ schema = 'purge.rig.m3rec.extras/1'; t = (NowIso); install = (Read-Json (Join-Path $Out 'install.json')); uac = (Read-Json (Join-Path $Out 'uac-check.json'))
                           uac_silent = (Read-Json (Join-Path $Out 'uac-silent.json')); sr_enable = (Read-Json (Join-Path $Out 'sr-enable.json'))
                           npp = (Read-Json (Join-Path $Out 'npp.json')); irrev = (Read-Json (Join-Path $Out 'irrev.json'))
                           rm = [ordered]@{ exec = (Read-Json (Join-Path $Out 'rm-exec.json')); retry = (Read-Json (Join-Path $Out 'rm-retry.json')); boot = (Read-Json (Join-Path $Out 'rm-after-reboot.json')) }
                           sr = [ordered]@{ off = (Read-Json (Join-Path $Out 'sr-off.json')); disabled = (Read-Json (Join-Path $Out 'sr-disabled.json'))
                                            created = (Read-Json (Join-Path $Out 'sr-created.json')); throttled = (Read-Json (Join-Path $Out 'sr-throttled.json')) } }
        Write-JsonFile $sum (Join-Path $Out 'm3-extras.json') 20
        "M3R EXTRAS-SUMMARY irrev=$([bool]$sum.irrev) rm=$([bool]$sum.rm.exec) sr=$(@($sum.sr.Values | Where-Object { $_ }).Count)"
    }
}
