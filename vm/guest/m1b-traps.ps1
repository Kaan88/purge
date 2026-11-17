# Purge rig, M1b: scan-trap plants (docs/M1B_DESIGN.json package M1B-RIG-GUEST, contract C-RIG).
# Windows PowerShell 5.1, 64-bit, elevated, inside a rig VM only (refuses on any other computer name).
#
# Two products take part. TrapA is the app under test (default 7zip, the 7-Zip MSI): it is installed, the pre plants
# go in, harvest runs, it is uninstalled, then the post plants go in and the scan runs. TrapB (default node) stays
# installed the whole time. Every plant writes objects of its own (names starting with PurgeTrap where the name is
# free; where Windows fixes the name, e.g. a MuiCache value named by an exe path or a Tracing key named by the exe,
# the name follows Windows' rule). No plant changes an object of a real product: an existing value or key a plant
# would have to overwrite is left as it is and recorded as 'existed, kept' (the case then counts as skipped).
#
# One function per trap case; the case table ($M1bCases) maps the case ids of vm/truth/m1b-traps.json to the
# function and its phase:
#   pre      after TrapA's install and launch, before harvest (harvest sees them)
#   between  (only com-shared-class) after harvest, before the uninstall: re-points the shared CLSID to TrapB.
#            If the host never runs this phase, -Phase post runs the pending step first.
#   post     after TrapA's uninstall, before the scan.
#
# Usage (from the rig job, after riglib.ps1 is dot-sourced or with riglib next to this script):
#   m1b-traps.ps1 -List                                   every case id with its phase and function (no change)
#   m1b-traps.ps1 -Phase pre -OutDir C:\cr\out\<run>      plants every pre case (-Case id,... for a subset)
#   m1b-traps.ps1 -Phase between -OutDir ...
#   m1b-traps.ps1 -Phase post -OutDir ...
#   . m1b-traps.ps1 -Library                              only define the functions (tests)
# -TrapA / -TrapB take an app id (7zip, node, or any apps.ps1 id with a launch exe).
# Outputs in -OutDir: m1b-traps-state.json (TrapA/TrapB facts captured at the pre phase: folder, exe, product code,
# upgrade code, ARP key; the post phase needs them once TrapA is gone), m1b-traps-planted.json
# (purge.rig.m1b-traps.planted/1: per case ok/skipped/error and every planted object {kind, target, note}), and
# one run-log line per planted object (riglib Log; m1b-traps.log in -OutDir unless -RunLog names the run's log).
# Exit code: 0 when every selected case planted, 1 otherwise.
[CmdletBinding()]
param(
    [switch]$List,
    [ValidateSet('', 'pre', 'between', 'post')]
    [string]$Phase = '',
    [string[]]$Case = @(),
    [string]$TrapA = '7zip',
    [string]$TrapB = 'node',
    [string]$OutDir = '',
    [string]$RunLog = '',
    [switch]$Library
)

# ------------------------------------------------------------------------------------------ constants

# Computer names of the rig VMs (Inbound-Win11-Test, Purge-CleanPro; run.json `computer`). rig.ps1 Assert-RigVm
# checks the VM name on the host; this is the same list seen from inside the guest.
$M1bRigComputers = @('INBOUND-WIN11-T', 'PURGE-CLEANPRO')

$M1bWork = 'C:\cr\work\m1b-traps'        # build output of the helper exe/dll (C:\cr\** is rig-owned)

# Products the traps know without apps.ps1: display short name (used in names), install folder, main exe, ARP match.
$M1bProducts = @{
    '7zip' = @{ short = '7-Zip'; dir = '%ProgramFiles%\7-Zip'; exe = '7zFM.exe'; match = '^7-Zip' }
    'node' = @{ short = 'Node.js'; dir = '%ProgramFiles%\nodejs'; exe = 'node.exe'; match = '^Node\.js' }
}

# Fixed identifiers of planted objects (fabricated, PurgeTrap-only).
$M1bG = @{
    ComClsid      = '{22EAAAE6-9088-44CB-B30F-B8EFCD75B9C4}'   # com-owned
    ComAppId      = '{3369C8BA-2ECE-4D2A-9A30-0F5B1B336D44}'
    ComTypeLib    = '{59A8DA29-DD14-48B7-9BC7-24F169BF80DC}'
    ComIid        = '{5D7280DF-9A4A-41CE-9C99-3F6B7F0FE683}'
    SharedClsid   = '{AA0252AF-8AAD-4AAB-9CF2-50CFE0FD31DF}'   # com-shared-class
    ProxyClsid    = '{7F044EEC-7677-4F68-B63F-E36F074E7E89}'   # com-isimpledom: TrapA's planted proxy CLSID
    ForeignCode   = '{EAA43DE6-884A-4789-98B3-FC27398D3AF1}'   # msi-remnants-foreign: product code not in the fingerprint
    ForeignUpgr   = '{46902FD0-C2E7-418F-AA4B-3A74751452DF}'
    CompA         = '{8E119FF9-1F7E-461D-B983-12CB719287A1}'   # msi-remnants: TrapA component
    CompForeign   = '{75F6D149-93B5-4C65-BDAB-3514383F6D70}'   # msi-remnants-foreign component
    CompShared    = '{BB74418D-517A-44DA-B308-330546B00AC1}'   # msi-shared-component
    OtherBundle   = '{8F55F023-DF9B-4357-8AE7-2C820D0150CA}'   # burn-shared-package: a bundle that is not TrapA
    UpgrFallback  = '{582DFD65-CEAC-43DD-A530-ED7CFA5E37E9}'   # TrapA upgrade code when the pre phase found none
}
# ISimpleDOMNode (Mozilla accessible/interfaces/msaa/ISimpleDOMNode.idl): a well-known IID other products register.
$M1bISimpleDomIid = '{1814CEEB-49E2-407F-AF99-FA755A7D2607}'

$M1bKeySvc      = 'HKLM\SYSTEM\CurrentControlSet\Services'
$M1bKeyClasses  = 'HKLM\SOFTWARE\Classes'
$M1bKeyClasses32 = 'HKLM\SOFTWARE\WOW6432Node\Classes'
$M1bKeyInstUD   = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18'
$M1bKeyUpgrade  = 'HKLM\SOFTWARE\Classes\Installer\UpgradeCodes'
$M1bKeyDeps     = 'HKLM\SOFTWARE\Classes\Installer\Dependencies'
$M1bKeyFolders  = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders'
$M1bKeyShared   = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs'
$M1bKeyTracing  = 'HKLM\SOFTWARE\Microsoft\Tracing'
$M1bKeyEvtApp   = 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application'
$M1bPkgCache    = 'C:\ProgramData\Package Cache'
$M1bWerArchive  = 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'
$M1bSharedSysDll = 'C:\Windows\System32\comctl32.dll'       # shareddlls-count: a System32 dll with count 1

# ------------------------------------------------------------------------------------------ case table

# id = vm/truth/m1b-traps.json case id (M1B-RIG-HOST), phase, plant = function in this file.
$M1bCases = @(
    [ordered]@{ id = 'svc-owned';             phase = 'pre';  plant = 'Plant-OwnedService' }
    [ordered]@{ id = 'svc-owned-running';     phase = 'pre';  plant = 'Plant-OwnedRunningService' }
    [ordered]@{ id = 'svc-shared';            phase = 'pre';  plant = 'Plant-SharedService' }
    [ordered]@{ id = 'svc-dependent';         phase = 'pre';  plant = 'Plant-DependentService' }
    [ordered]@{ id = 'svc-svchost';           phase = 'pre';  plant = 'Plant-SvchostService' }
    [ordered]@{ id = 'task-owned';            phase = 'pre';  plant = 'Plant-OwnedTask' }
    [ordered]@{ id = 'task-similar-name';     phase = 'pre';  plant = 'Plant-SimilarTask' }
    [ordered]@{ id = 'task-interpreter';      phase = 'pre';  plant = 'Plant-InterpreterTask' }
    [ordered]@{ id = 'fw-owned';              phase = 'pre';  plant = 'Plant-OwnedFirewall' }
    [ordered]@{ id = 'fw-same-display-name';  phase = 'pre';  plant = 'Plant-SameNameFirewall' }
    [ordered]@{ id = 'fw-no-app';             phase = 'pre';  plant = 'Plant-PortFirewall' }
    [ordered]@{ id = 'com-owned';             phase = 'pre';  plant = 'Plant-ComClass' }
    [ordered]@{ id = 'shellex-approved';      phase = 'pre';  plant = 'Plant-ShellexApproved' }
    [ordered]@{ id = 'com-shared-class';      phase = 'pre';  plant = 'Plant-SharedComClass'; between = 'Repoint-SharedComClass' }
    [ordered]@{ id = 'shareddlls-count';      phase = 'pre';  plant = 'Plant-SharedDlls' }
    [ordered]@{ id = 'eventlog-shared-source'; phase = 'pre'; plant = 'Plant-EventLogSource' }
    [ordered]@{ id = 'tracing';               phase = 'pre';  plant = 'Plant-Tracing' }
    [ordered]@{ id = 'privacy-twins';         phase = 'pre';  plant = 'Plant-MuiCacheAndFriends' }
    [ordered]@{ id = 'wer-twins';             phase = 'pre';  plant = 'Plant-WerReports' }
    [ordered]@{ id = 'msi-remnants';          phase = 'post'; plant = 'Plant-MsiRemnants' }
    [ordered]@{ id = 'msi-remnants-foreign';  phase = 'post'; plant = 'Plant-MsiRemnantsForeign' }
    [ordered]@{ id = 'msi-shared-component';  phase = 'post'; plant = 'Plant-SharedComponent' }
    [ordered]@{ id = 'com-isimpledom';        phase = 'post'; plant = 'Plant-IsimpleDom' }
    [ordered]@{ id = 'burn-shared-package';   phase = 'post'; plant = 'Plant-BurnShared' }
    [ordered]@{ id = 'pkgcache-foreign';      phase = 'post'; plant = 'Plant-PkgCacheForeign' }
    [ordered]@{ id = 'instfolders';           phase = 'post'; plant = 'Plant-InstFolders' }
)

# Pure: the -List lines ("<id> <phase> <function>[ (between: <function>)]").
function Get-M1bCaseListing {
    foreach ($c in $M1bCases) {
        $l = '{0,-24} {1,-5} {2}' -f $c.id, $c.phase, $c.plant
        if ($c.between) { $l += "  (between: $($c.between))" }
        $l
    }
}

# Pure: the cases of one phase ('between': the cases with a between step), optionally narrowed to ids.
function Get-M1bCases([string]$Phase, [string[]]$Ids = @()) {
    $sel = @($M1bCases | Where-Object { if ($Phase -eq 'between') { $_.between } else { $_.phase -eq $Phase } })
    if (@($Ids | Where-Object { $_ }).Count) {
        $unknown = @($Ids | Where-Object { $_ -and (@($M1bCases | ForEach-Object { $_.id }) -notcontains $_) })
        if ($unknown.Count) { throw "unknown trap case(s): $($unknown -join ', ')" }
        $sel = @($sel | Where-Object { $Ids -contains $_.id })
    }
    $sel
}

# ------------------------------------------------------------------------------------------ guard

function Get-M1bComputerName { "$env:COMPUTERNAME" }

# Throws unless $Name (default: this computer) is one of the rig VMs. Every plant function calls it first.
function Assert-M1bRigVm([string]$Name = (Get-M1bComputerName)) {
    $n = "$Name".ToUpperInvariant()
    if ($M1bRigComputers -notcontains $n) { throw "m1b-traps: computer '$n' is not a rig VM ($($M1bRigComputers -join ', ')); refusing to plant" }
}

# ------------------------------------------------------------------------------------------ helpers

function Add-M1bPlanted($Ctx, [string]$Kind, [string]$Target, [string]$Note = '') {
    [void]$Ctx.Planted.Add([ordered]@{ kind = $Kind; target = $Target; note = $Note })
    if ($Note -like 'existed*') { $Ctx.Skipped = $true }
    Log ("  m1b-trap {0} ({1}): {2} {3}{4}" -f $Ctx.Case, $Ctx.Phase, $Kind, $Target, $(if ($Note) { " [$Note]" } else { '' }))
}

function Open-M1bKeyWrite([string]$Canon) {
    $k = ConvertTo-CanonKey $Canon
    $hiveName, $rest = $k -split '\\', 2
    $hive = switch ($hiveName) {
        'HKLM' { [Microsoft.Win32.RegistryHive]::LocalMachine }
        'HKU'  { [Microsoft.Win32.RegistryHive]::Users }
        default { throw "unsupported hive in '$Canon'" }
    }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
    try { $base.CreateSubKey($rest) } finally { $base.Dispose() }
}

function Set-M1bKey($Ctx, [string]$Key) {
    $existed = Test-RegKey $Key
    $k = Open-M1bKeyWrite $Key; $k.Dispose()
    Add-M1bPlanted $Ctx 'key' ('K:' + (ConvertTo-CanonKey $Key)) $(if ($existed) { 'key existed already' } else { '' })
}

# Writes one value. -KeepExisting: a value already there with other data is left alone ('existed, kept'); the same
# data again is a no-op (idempotent). Without it the value is (re)written; use it only for objects the trap owns.
function Set-M1bValue($Ctx, [string]$Key, [string]$Name, $Value, [Microsoft.Win32.RegistryValueKind]$Kind = 'String', [switch]$KeepExisting) {
    $k = Open-M1bKeyWrite $Key
    $note = ''
    try {
        $has = @($k.GetValueNames()) -contains $Name
        $before = $null
        if ($has) { $before = $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
        $same = $has -and ((ConvertTo-Json -InputObject $before -Compress) -eq (ConvertTo-Json -InputObject $Value -Compress))
        if ($has -and $KeepExisting -and -not $same) { $note = "existed, kept: $before" }
        else { $k.SetValue($Name, $Value, $Kind) }
    } finally { $k.Dispose() }
    $shown = if ($Value -is [byte[]]) { "($($Value.Length) bytes)" } elseif ($Value -is [array]) { $Value -join '|' } else { "$Value" }
    Add-M1bPlanted $Ctx 'value' ('V:' + (ConvertTo-CanonKey $Key) + '|' + $Name) $(if ($note) { $note } else { $shown })
}

function Get-M1bFileHash([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash }

# Copies $Src to $Dst unless an equal file is already there (a running service exe stays in place).
function Copy-M1bFile($Ctx, [string]$Src, [string]$Dst) {
    $d = Split-Path -Parent $Dst
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force $d | Out-Null }
    if ((Test-Path -LiteralPath $Dst -PathType Leaf) -and (Get-M1bFileHash $Dst) -eq (Get-M1bFileHash $Src)) {
        Add-M1bPlanted $Ctx 'file' ('P:' + $Dst) 'same file already there'
        return
    }
    Copy-Item -LiteralPath $Src -Destination $Dst -Force
    Add-M1bPlanted $Ctx 'file' ('P:' + $Dst)
}

function Write-M1bFile($Ctx, [string]$Path, [string]$Text, [Text.Encoding]$Encoding = $RigUtf8) {
    $d = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force $d | Out-Null; Add-M1bPlanted $Ctx 'dir' ('P:' + $d) }
    [IO.File]::WriteAllText($Path, $Text, $Encoding)
    Add-M1bPlanted $Ctx 'file' ('P:' + $Path)
}

function Get-M1bCsc { Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe' }

# The tiny helper binaries, built once with csc of the .NET Framework on the image:
#   PurgeTrapSvc.exe  a do-nothing Windows service (ServiceBase), startable and stoppable
#   PurgeTrapLib.dll  an empty class library (stands in for every planted dll: COM server, ServiceDll, message file)
function Get-M1bHelper([ValidateSet('exe', 'dll')][string]$Which) {
    $out = Join-Path $M1bWork $(if ($Which -eq 'exe') { 'PurgeTrapSvc.exe' } else { 'PurgeTrapLib.dll' })
    if (Test-Path -LiteralPath $out -PathType Leaf) { return $out }
    New-Item -ItemType Directory -Force $M1bWork | Out-Null
    $csc = Get-M1bCsc
    if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) { throw "csc.exe not found at $csc" }
    if ($Which -eq 'exe') {
        $src = Join-Path $M1bWork 'PurgeTrapSvc.cs'
        [IO.File]::WriteAllText($src, @'
using System.ServiceProcess;
public class PurgeTrapSvc : ServiceBase {
    public PurgeTrapSvc() { ServiceName = "PurgeTrapSvc"; CanStop = true; }
    protected override void OnStart(string[] args) { }
    protected override void OnStop() { }
    public static void Main() { ServiceBase.Run(new PurgeTrapSvc()); }
}
'@, $RigUtf8)
        $a = '/nologo /target:exe /optimize /r:System.ServiceProcess.dll /out:"' + $out + '" "' + $src + '"'
    } else {
        $src = Join-Path $M1bWork 'PurgeTrapLib.cs'
        [IO.File]::WriteAllText($src, "namespace PurgeTrap { public static class Lib { public const string Marker = `"PurgeTrap`"; } }`r`n", $RigUtf8)
        $a = '/nologo /target:library /optimize /out:"' + $out + '" "' + $src + '"'
    }
    $r = Invoke-Native -Exe $csc -Arguments $a -TimeoutSec 120
    if ($r.exit -ne 0 -or -not (Test-Path -LiteralPath $out)) { throw "csc failed ($($r.exit)): $($r.stdout) $($r.stderr)" }
    Log "  m1b-traps: built $out with $csc"
    $out
}

function Invoke-M1bSc([string]$Arguments, [switch]$AllowFail) {
    $r = Invoke-Native -Exe (Join-Path $env:SystemRoot 'System32\sc.exe') -Arguments $Arguments -TimeoutSec 60
    if ($r.exit -ne 0 -and -not $AllowFail) { throw "sc.exe $Arguments -> exit $($r.exit): $("$($r.stdout) $($r.stderr)".Trim())" }
    $r
}

# Creates service $Name with the given configuration, or keeps it when it already has exactly that configuration
# (ImagePath, Start, Type, DependOnService); a service of that name with another configuration is deleted and
# created again (it is always a PurgeTrap service: the caller only passes PurgeTrap names).
function Set-M1bService($Ctx, [string]$Name, [string]$ImagePath, [string]$DisplayName, [string]$Description,
                        [string[]]$DependsOn = @(), [switch]$Share) {
    if ($Name -notlike 'PurgeTrap*') { throw "Set-M1bService: '$Name' is not a PurgeTrap service" }
    $key = "$M1bKeySvc\$Name"
    $want = @{ img = $ImagePath; start = 3; type = $(if ($Share) { 0x20 } else { 0x10 }); dep = (@($DependsOn) -join '|') }
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    $note = ''
    if ($svc) {
        $k = Open-RegKey $key
        $have = @{}
        if ($k) {
            try {
                $have.img = "$($k.GetValue('ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))"
                $have.start = [int]$k.GetValue('Start', -1); $have.type = [int]$k.GetValue('Type', -1)
                $have.dep = (@($k.GetValue('DependOnService', @())) -join '|')
            } finally { $k.Dispose() }
        }
        if ($k -and $have.img -eq $want.img -and $have.start -eq $want.start -and $have.type -eq $want.type -and $have.dep -eq $want.dep) {
            $note = 'existed with this configuration'
        } else {
            if ($svc.Status -ne 'Stopped') { $null = Invoke-M1bSc "stop $Name" -AllowFail }
            $null = Invoke-M1bSc "delete $Name"
            $t0 = Get-Date
            while ((Get-Service -Name $Name -ErrorAction SilentlyContinue) -and ((Get-Date) - $t0).TotalSeconds -lt 30) { Start-Sleep -Milliseconds 500 }
            if (Get-Service -Name $Name -ErrorAction SilentlyContinue) { throw "service $Name is marked for deletion and still there after 30 s" }
            $svc = $null
            $note = 're-created (configuration differed)'
        }
    }
    if (-not $svc) {
        $p = @{ Name = $Name; BinaryPathName = $ImagePath; DisplayName = $DisplayName; StartupType = 'Manual'; Description = $Description; ErrorAction = 'Stop' }
        if (@($DependsOn).Count) { $p.DependsOn = $DependsOn }
        $null = New-Service @p
        if ($Share) { $null = Invoke-M1bSc "config $Name type= share" }
    }
    Set-Service -Name $Name -Description $Description -ErrorAction Stop
    # Failure actions: restart after 60 s twice, reset after a day.
    $null = Invoke-M1bSc "failure $Name reset= 86400 actions= restart/60000/restart/60000//"
    Add-M1bPlanted $Ctx 'service' "SVC:$Name" ("ImagePath=$ImagePath" + $(if (@($DependsOn).Count) { "; DependOnService=$($DependsOn -join ',')" } else { '' }) + $(if ($note) { "; $note" } else { '' }))
    Set-M1bValue $Ctx "$key\Parameters" 'PurgeTrapSetting' "planted by m1b-traps ($($Ctx.Case))"
}

function Set-M1bTask($Ctx, [string]$Folder, [string]$Name, [string]$Execute, [string]$Arguments = '', [string]$WorkDir = '') {
    $tp = '\' + $Folder.Trim('\') + '\'
    if ($tp -notlike '\PurgeTrap\*') { throw "Set-M1bTask: folder '$tp' is not a PurgeTrap folder" }
    $ap = @{ Execute = $Execute }
    if ($Arguments) { $ap.Argument = $Arguments }
    if ($WorkDir) { $ap.WorkingDirectory = $WorkDir }
    $act = New-ScheduledTaskAction @ap
    # A one-time trigger far in the future: the task exists and is enabled but never fires during a run.
    $trg = New-ScheduledTaskTrigger -Once -At ([datetime]'2099-01-01T03:00:00')
    $pri = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $null = Register-ScheduledTask -TaskPath $tp -TaskName $Name -Action $act -Trigger $trg -Principal $pri -Settings (New-ScheduledTaskSettingsSet) -Force -ErrorAction Stop
    Add-M1bPlanted $Ctx 'task' "TASK:$tp$Name" ("$Execute $Arguments".Trim())
}

function Set-M1bFirewallRule($Ctx, [string]$Id, [string]$DisplayName, [string]$Program = '', [int]$Port = 0) {
    if ($Id -notlike 'PurgeTrap*') { throw "Set-M1bFirewallRule: '$Id' is not a PurgeTrap rule" }
    $old = Get-NetFirewallRule -Name $Id -ErrorAction SilentlyContinue
    if ($old) { Remove-NetFirewallRule -Name $Id -ErrorAction Stop }
    $p = @{ Name = $Id; DisplayName = $DisplayName; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; Description = "PurgeTrap rule ($($Ctx.Case))"; ErrorAction = 'Stop' }
    if ($Program) { $p.Program = $Program }
    if ($Port) { $p.Protocol = 'TCP'; $p.LocalPort = "$Port" }
    $null = New-NetFirewallRule @p
    Add-M1bPlanted $Ctx 'firewall' "FW:$Id" ("DisplayName=$DisplayName" + $(if ($Program) { "; App=$Program" } else { "; no App, TCP $Port" }) + $(if ($old) { '; re-created' } else { '' }))
}

# COM class: CLSID\{x}\InprocServer32 = $Dll (+ ThreadingModel) and an optional ProgID / AppID / TypeLib link.
function Set-M1bComClass($Ctx, [string]$Clsid, [string]$Dll, [string]$Name, [string]$ProgId = '', [string]$AppId = '', [string]$TypeLib = '') {
    $k = "$M1bKeyClasses\CLSID\$Clsid"
    Set-M1bValue $Ctx $k '' $Name
    Set-M1bValue $Ctx "$k\InprocServer32" '' $Dll
    Set-M1bValue $Ctx "$k\InprocServer32" 'ThreadingModel' 'Apartment'
    if ($ProgId) { Set-M1bValue $Ctx "$k\ProgID" '' $ProgId }
    if ($AppId) { Set-M1bValue $Ctx $k 'AppID' $AppId }
    if ($TypeLib) { Set-M1bValue $Ctx "$k\TypeLib" '' $TypeLib }
}

# ------------------------------------------------------------------------------------------ products

# Packed product code -> packed upgrade code from Classes\Installer\UpgradeCodes, or $null.
function Find-M1bUpgradeCode([string]$PackedProduct) {
    $rk = Open-RegKey $M1bKeyUpgrade
    if (-not $rk) { return $null }
    try {
        foreach ($sub in $rk.GetSubKeyNames()) {
            $k = $null
            try { $k = $rk.OpenSubKey($sub, $false) } catch { }
            if (-not $k) { continue }
            try { if (@($k.GetValueNames()) -contains $PackedProduct) { return ConvertFrom-PackedGuid $sub } } finally { $k.Dispose() }
        }
    } finally { $rk.Dispose() }
    $null
}

# Facts about a trap product now: {id, short, name, version, dir, exe, exe_name, product_code, upgrade_code,
# arp_key, arp_leaf, bundle, installed}. The folder is the ARP InstallLocation when set, else the known default.
function Resolve-M1bProduct([string]$Id) {
    $def = $M1bProducts[$Id]
    if (-not $def) {
        if (-not (Get-Command Get-App -ErrorAction SilentlyContinue)) { throw "unknown trap product '$Id' (known: $($M1bProducts.Keys -join ', '); apps.ps1 not loaded)" }
        $a = Get-App $Id
        if (-not $a.launch -or -not $a.launch.exe -or -not @($a.launch.dirs)[0]) { throw "app '$Id' has no launch exe/dirs to place the traps in" }
        $def = @{ short = ($a.match -replace '^\^', '' -replace '\\', '' -replace '[\$\(\)\|\?\*\+]', '').Trim(); dir = @($a.launch.dirs)[0]; exe = $a.launch.exe; match = $a.match }
    }
    $e = @(UninstallEntries | Where-Object { "$($_.name)" -match $def.match -and -not $_.sys }) | Select-Object -First 1
    $dir = [Environment]::ExpandEnvironmentVariables($def.dir).TrimEnd('\')
    if ($e -and "$($e.loc)".Trim() -and (Test-Path -LiteralPath (Join-Path "$($e.loc)".Trim().Trim('"') $def.exe))) { $dir = "$($e.loc)".Trim().Trim('"').TrimEnd('\') }
    $code = $null; $upgr = $null
    if ($e) {
        $code = $e.msi
        if ($code) { $upgr = Find-M1bUpgradeCode (ConvertTo-PackedGuid $code) }
    }
    [ordered]@{
        id = $Id; short = $def.short; name = $(if ($e) { "$($e.name)" } else { $def.short }); version = $(if ($e) { "$($e.version)" } else { $null })
        publisher = $(if ($e) { "$($e.publisher)" } else { $null })
        dir = $dir; exe = (Join-Path $dir $def.exe); exe_name = $def.exe
        product_code = $code; upgrade_code = $upgr
        arp_key = $(if ($e) { $e.key } else { $null }); arp_leaf = $(if ($e) { Split-Path -Leaf $e.key } else { $null })
        bundle = $(if ($e) { [bool]$e.bundle } else { $false }); installed = [bool]$e
    }
}

# ------------------------------------------------------------------------------------------ pre plants

# svc-owned: PurgeTrapSvcA, stopped, demand start, ImagePath = a copy of the helper exe in TrapA's folder,
# Description, failure actions, a Parameters subkey.
function Plant-OwnedService($Ctx) {
    Assert-M1bRigVm
    $exe = Join-Path $Ctx.A.dir 'PurgeTrapSvcA.exe'
    Copy-M1bFile $Ctx (Get-M1bHelper exe) $exe
    Set-M1bService $Ctx 'PurgeTrapSvcA' ('"' + $exe + '"') 'PurgeTrap Service A' "PurgeTrap: service owned by $($Ctx.A.short)"
}

# svc-owned-running: PurgeTrapSvcRun, as svc-owned, then started (still running at scan time).
function Plant-OwnedRunningService($Ctx) {
    Assert-M1bRigVm
    $exe = Join-Path $Ctx.A.dir 'PurgeTrapSvcRun.exe'
    $s = Get-Service -Name 'PurgeTrapSvcRun' -ErrorAction SilentlyContinue
    if (-not ($s -and $s.Status -eq 'Running')) { Copy-M1bFile $Ctx (Get-M1bHelper exe) $exe }
    Set-M1bService $Ctx 'PurgeTrapSvcRun' ('"' + $exe + '"') 'PurgeTrap Running Service' "PurgeTrap: running service owned by $($Ctx.A.short)"
    $s = Get-Service -Name 'PurgeTrapSvcRun' -ErrorAction Stop
    if ($s.Status -ne 'Running') { Start-Service -Name 'PurgeTrapSvcRun' -ErrorAction Stop }
    $s.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Add-M1bPlanted $Ctx 'service-state' 'SVC:PurgeTrapSvcRun' 'Running'
}

# svc-shared: name and display name carry TrapA's product name, ImagePath in TrapB's folder.
function Plant-SharedService($Ctx) {
    Assert-M1bRigVm
    $exe = Join-Path $Ctx.B.dir 'PurgeTrapSvcShared.exe'
    Copy-M1bFile $Ctx (Get-M1bHelper exe) $exe
    Set-M1bService $Ctx "PurgeTrapSvcShared-$($Ctx.A.short)" ('"' + $exe + '"') "PurgeTrap $($Ctx.A.short) Shared Service" "PurgeTrap: named after $($Ctx.A.short), runs from $($Ctx.B.short)"
}

# svc-dependent: PurgeTrapSvcA2 (TrapA's folder) that PurgeTrapSvcDep (TrapB's folder) depends on.
function Plant-DependentService($Ctx) {
    Assert-M1bRigVm
    $a2 = Join-Path $Ctx.A.dir 'PurgeTrapSvcA2.exe'
    $dep = Join-Path $Ctx.B.dir 'PurgeTrapSvcDep.exe'
    Copy-M1bFile $Ctx (Get-M1bHelper exe) $a2
    Copy-M1bFile $Ctx (Get-M1bHelper exe) $dep
    Set-M1bService $Ctx 'PurgeTrapSvcA2' ('"' + $a2 + '"') 'PurgeTrap Service A2' "PurgeTrap: owned by $($Ctx.A.short), PurgeTrapSvcDep depends on it"
    Set-M1bService $Ctx 'PurgeTrapSvcDep' ('"' + $dep + '"') 'PurgeTrap Dependent Service' "PurgeTrap: $($Ctx.B.short) service depending on PurgeTrapSvcA2" -DependsOn @('PurgeTrapSvcA2')
}

# svc-svchost: PurgeTrapSvcHost in svchost group PurgeTrapGroup, Parameters\ServiceDll = a dll in TrapA's folder.
# Never started.
function Plant-SvchostService($Ctx) {
    Assert-M1bRigVm
    $dll = Join-Path $Ctx.A.dir 'PurgeTrapSvcHost.dll'
    Copy-M1bFile $Ctx (Get-M1bHelper dll) $dll
    Set-M1bService $Ctx 'PurgeTrapSvcHost' '%SystemRoot%\System32\svchost.exe -k PurgeTrapGroup' 'PurgeTrap Svchost Service' "PurgeTrap: svchost service whose dll is in $($Ctx.A.short)'s folder" -Share
    Set-M1bValue $Ctx "$M1bKeySvc\PurgeTrapSvcHost\Parameters" 'ServiceDll' $dll ExpandString
    try { Set-M1bValue $Ctx 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost' 'PurgeTrapGroup' ([string[]]@('PurgeTrapSvcHost')) MultiString -KeepExisting }
    catch { Add-M1bPlanted $Ctx 'note' 'V:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost|PurgeTrapGroup' "not written: $($_.Exception.Message)" }
}

# task-owned: \PurgeTrap\<A> Update, exec action = TrapA's main exe.
function Plant-OwnedTask($Ctx) {
    Assert-M1bRigVm
    Set-M1bTask $Ctx 'PurgeTrap' "$($Ctx.A.short) Update" $Ctx.A.exe '/PurgeTrap' $Ctx.A.dir
}

# task-similar-name: \PurgeTrap\<A> Updater: TrapA's name, action into TrapB's folder.
function Plant-SimilarTask($Ctx) {
    Assert-M1bRigVm
    Set-M1bTask $Ctx 'PurgeTrap' "$($Ctx.A.short) Updater" $Ctx.B.exe '--version' $Ctx.B.dir
}

# task-interpreter: \PurgeTrap\<A> Script: cmd.exe /c with TrapA's exe path as the argument.
function Plant-InterpreterTask($Ctx) {
    Assert-M1bRigVm
    Set-M1bTask $Ctx 'PurgeTrap' "$($Ctx.A.short) Script" '%SystemRoot%\System32\cmd.exe' ('/c "' + $Ctx.A.exe + '"')
}

# fw-owned: display name PurgeTrap, App = TrapA's exe.
function Plant-OwnedFirewall($Ctx) {
    Assert-M1bRigVm
    Set-M1bFirewallRule $Ctx 'PurgeTrapFwA' 'PurgeTrap' -Program $Ctx.A.exe
}

# fw-same-display-name: a second rule with display name PurgeTrap, App = TrapB's exe.
function Plant-SameNameFirewall($Ctx) {
    Assert-M1bRigVm
    Set-M1bFirewallRule $Ctx 'PurgeTrapFwB' 'PurgeTrap' -Program $Ctx.B.exe
}

# fw-no-app: a port rule named after TrapA, no App field.
function Plant-PortFirewall($Ctx) {
    Assert-M1bRigVm
    Set-M1bFirewallRule $Ctx 'PurgeTrapFwPort' "PurgeTrap $($Ctx.A.short)" -Port 50123
}

# com-owned: CLSID -> dll in TrapA's folder, ProgID (+ version-independent), AppID, TypeLib, an Interface whose
# ProxyStubClsid32 is that CLSID.
function Plant-ComClass($Ctx) {
    Assert-M1bRigVm
    $dll = Join-Path $Ctx.A.dir 'PurgeTrapCom.dll'
    Copy-M1bFile $Ctx (Get-M1bHelper dll) $dll
    $g = $M1bG
    Set-M1bComClass $Ctx $g.ComClsid $dll 'PurgeTrap ComA' -ProgId 'PurgeTrap.ComA.1' -AppId $g.ComAppId -TypeLib $g.ComTypeLib
    Set-M1bValue $Ctx "$M1bKeyClasses\CLSID\$($g.ComClsid)\VersionIndependentProgID" '' 'PurgeTrap.ComA'
    Set-M1bValue $Ctx "$M1bKeyClasses\PurgeTrap.ComA.1" '' 'PurgeTrap ComA'
    Set-M1bValue $Ctx "$M1bKeyClasses\PurgeTrap.ComA.1\CLSID" '' $g.ComClsid
    Set-M1bValue $Ctx "$M1bKeyClasses\PurgeTrap.ComA" '' 'PurgeTrap ComA'
    Set-M1bValue $Ctx "$M1bKeyClasses\PurgeTrap.ComA\CLSID" '' $g.ComClsid
    Set-M1bValue $Ctx "$M1bKeyClasses\PurgeTrap.ComA\CurVer" '' 'PurgeTrap.ComA.1'
    Set-M1bValue $Ctx "$M1bKeyClasses\AppID\$($g.ComAppId)" '' 'PurgeTrap ComA'
    Set-M1bValue $Ctx "$M1bKeyClasses\TypeLib\$($g.ComTypeLib)\1.0" '' 'PurgeTrap ComA Library'
    Set-M1bValue $Ctx "$M1bKeyClasses\TypeLib\$($g.ComTypeLib)\1.0\0\win64" '' $dll
    Set-M1bValue $Ctx "$M1bKeyClasses\TypeLib\$($g.ComTypeLib)\1.0\FLAGS" '' '0'
    Set-M1bValue $Ctx "$M1bKeyClasses\Interface\$($g.ComIid)" '' 'IPurgeTrapComA'
    Set-M1bValue $Ctx "$M1bKeyClasses\Interface\$($g.ComIid)\ProxyStubClsid32" '' $g.ComClsid
    Set-M1bValue $Ctx "$M1bKeyClasses\Interface\$($g.ComIid)\TypeLib" '' $g.ComTypeLib
    Set-M1bValue $Ctx "$M1bKeyClasses\Interface\$($g.ComIid)\TypeLib" 'Version' '1.0'
}

# shellex-approved: a context-menu handler for * and the Approved value, both naming com-owned's CLSID (planted
# here too when com-owned has not run, so the case stands alone).
function Plant-ShellexApproved($Ctx) {
    Assert-M1bRigVm
    $dll = Join-Path $Ctx.A.dir 'PurgeTrapCom.dll'
    if (-not (Test-RegKey "$M1bKeyClasses\CLSID\$($M1bG.ComClsid)\InprocServer32")) {
        Copy-M1bFile $Ctx (Get-M1bHelper dll) $dll
        Set-M1bComClass $Ctx $M1bG.ComClsid $dll 'PurgeTrap ComA'
    }
    Set-M1bValue $Ctx "$M1bKeyClasses\*\shellex\ContextMenuHandlers\PurgeTrapA" '' $M1bG.ComClsid
    Set-M1bValue $Ctx 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved' $M1bG.ComClsid 'PurgeTrap A context menu'
}

# com-shared-class: the CLSID first registered to TrapA's dll (pre, harvest sees it), then re-pointed to TrapB's
# dll before the uninstall (between: Repoint-SharedComClass).
function Plant-SharedComClass($Ctx) {
    Assert-M1bRigVm
    $dll = Join-Path $Ctx.A.dir 'PurgeTrapShared.dll'
    Copy-M1bFile $Ctx (Get-M1bHelper dll) $dll
    $k = "$M1bKeyClasses\CLSID\$($M1bG.SharedClsid)\InprocServer32"
    $cur = Get-RegRaw $k ''
    $bdll = Join-Path $Ctx.B.dir 'PurgeTrapShared.dll'
    if ($cur -and $cur -ieq $bdll) { Add-M1bPlanted $Ctx 'value' ('V:' + $k + '|') 'already re-pointed to TrapB (between step done); kept'; return }
    Set-M1bComClass $Ctx $M1bG.SharedClsid $dll 'PurgeTrap Shared Class'
}

function Repoint-SharedComClass($Ctx) {
    Assert-M1bRigVm
    $dll = Join-Path $Ctx.B.dir 'PurgeTrapShared.dll'
    Copy-M1bFile $Ctx (Get-M1bHelper dll) $dll
    Set-M1bValue $Ctx "$M1bKeyClasses\CLSID\$($M1bG.SharedClsid)\InprocServer32" '' $dll
}

# shareddlls-count: SharedDLLs counts: a TrapA dll with 1, a TrapA dll with 2, a System32 dll with 1 (left alone
# when Windows or a product already counts it).
function Plant-SharedDlls($Ctx) {
    Assert-M1bRigVm
    $d1 = Join-Path $Ctx.A.dir 'PurgeTrapShared1.dll'
    $d2 = Join-Path $Ctx.A.dir 'PurgeTrapShared2.dll'
    Copy-M1bFile $Ctx (Get-M1bHelper dll) $d1
    Copy-M1bFile $Ctx (Get-M1bHelper dll) $d2
    Set-M1bValue $Ctx $M1bKeyShared $d1 1 DWord
    Set-M1bValue $Ctx $M1bKeyShared $d2 2 DWord
    Set-M1bValue $Ctx $M1bKeyShared $M1bSharedSysDll 1 DWord -KeepExisting
}

# eventlog-shared-source: Application\PurgeTrapA (message file in TrapA's folder) and Application\PurgeTrapA2
# (the .NET Framework's shared EventLogMessages.dll).
function Plant-EventLogSource($Ctx) {
    Assert-M1bRigVm
    $dll = Join-Path $Ctx.A.dir 'PurgeTrapMsg.dll'
    Copy-M1bFile $Ctx (Get-M1bHelper dll) $dll
    Set-M1bValue $Ctx "$M1bKeyEvtApp\PurgeTrapA" 'EventMessageFile' $dll ExpandString
    Set-M1bValue $Ctx "$M1bKeyEvtApp\PurgeTrapA" 'TypesSupported' 7 DWord
    Set-M1bValue $Ctx "$M1bKeyEvtApp\PurgeTrapA2" 'EventMessageFile' '%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll' ExpandString
    Set-M1bValue $Ctx "$M1bKeyEvtApp\PurgeTrapA2" 'TypesSupported' 7 DWord
}

# tracing: Tracing\<TrapA exe base name>_RASAPI32 and _RASMANCS with the values RAS writes (kept when RAS already
# wrote them).
function Plant-Tracing($Ctx) {
    Assert-M1bRigVm
    $base = [IO.Path]::GetFileNameWithoutExtension($Ctx.A.exe_name)
    foreach ($sfx in 'RASAPI32', 'RASMANCS') {
        $k = "$M1bKeyTracing\${base}_$sfx"
        Set-M1bValue $Ctx $k 'EnableFileTracing' 0 DWord -KeepExisting
        Set-M1bValue $Ctx $k 'EnableAutoFileTracing' 0 DWord -KeepExisting
        Set-M1bValue $Ctx $k 'EnableConsoleTracing' 0 DWord -KeepExisting
        Set-M1bValue $Ctx $k 'FileTracingMask' ([int]-65536) DWord -KeepExisting
        Set-M1bValue $Ctx $k 'ConsoleTracingMask' ([int]-65536) DWord -KeepExisting
        Set-M1bValue $Ctx $k 'MaxFileSize' 0x100000 DWord -KeepExisting
        Set-M1bValue $Ctx $k 'FileDirectory' '%windir%\tracing' ExpandString -KeepExisting
    }
}

# privacy-twins: MuiCache, PCA Store and AppCompat Layers values named by TrapA's exe path, and the same for TrapB
# (TrapB's are the twins that must stay). Values Windows already wrote are kept.
function Plant-MuiCacheAndFriends($Ctx) {
    Assert-M1bRigVm
    $sid = $RigUserSid
    $mui = "HKU\${sid}_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    $pca = "HKU\$sid\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    $lay = "HKU\$sid\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
    $blob = [byte[]](@(0x53, 0x41, 0x43, 0x50, 0x01, 0, 0, 0) + @(0) * 16)   # 'SACP' header, as the PCA writes
    foreach ($p in @($Ctx.A, $Ctx.B)) {
        Set-M1bValue $Ctx $mui "$($p.exe).FriendlyAppName" "$($p.short) (PurgeTrap)" -KeepExisting
        Set-M1bValue $Ctx $mui "$($p.exe).ApplicationCompany" "$($p.short) (PurgeTrap)" -KeepExisting
        Set-M1bValue $Ctx $pca $p.exe $blob Binary -KeepExisting
        Set-M1bValue $Ctx $lay $p.exe '~ HIGHDPIAWARE' -KeepExisting
    }
}

# Pure: the ReportArchive folder name of a planted crash report for $ExeName (deterministic, AppCrash_<exe>_<40
# hex>_<8 hex>_<8 hex> as WER names them).
function Get-M1bWerFolderName([string]$ExeName) {
    $sha = [Security.Cryptography.SHA1]::Create()
    try { $h = -join @($sha.ComputeHash($RigUtf8.GetBytes("PurgeTrap|$ExeName".ToLowerInvariant())) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    'AppCrash_{0}_{1}_{2}_{3}' -f $ExeName, $h, $h.Substring(0, 8), $h.Substring(32, 8)
}

# wer-twins: ReportArchive\AppCrash_<TrapA exe>_... with a Report.wer naming TrapA's path; the same for TrapB.
function Plant-WerReports($Ctx) {
    Assert-M1bRigVm
    foreach ($p in @($Ctx.A, $Ctx.B)) {
        $dir = Join-Path $M1bWerArchive (Get-M1bWerFolderName $p.exe_name)
        $ft = (Get-Date).ToFileTimeUtc()
        $lines = @(
            'Version=1', 'EventType=APPCRASH', "EventTime=$ft", 'ReportType=2', 'Consent=1', 'UploadTime=0',
            "ReportIdentifier=$([guid]::NewGuid())", 'IsFatal=1', "NsAppName=$($p.exe_name)", "AppName=$($p.short)",
            "AppPath=$($p.exe)", "OriginalFilename=$($p.exe_name)", 'Sig[0].Name=Application Name', "Sig[0].Value=$($p.exe_name)",
            'PurgeTrap=1')
        Write-M1bFile $Ctx (Join-Path $dir 'Report.wer') (($lines -join "`r`n") + "`r`n") (New-Object Text.UnicodeEncoding($false, $true))
    }
}

# ------------------------------------------------------------------------------------------ post plants

function Assert-M1bProductCode($P, [string]$Why) {
    if (-not $P.product_code) { throw "$Why needs the product code of $($P.id) (captured at the pre phase; m1b-traps-state.json has none)" }
}

# MSI registration of one product: UserData\S-1-5-18\Products\<packed>\InstallProperties, the UpgradeCodes value,
# one Components value. Keys or values that already exist (the uninstall left them) are kept as they are.
function Set-M1bMsiRegistration($Ctx, [string]$Code, [string]$Upgrade, [string]$Component, [string]$Name, [string]$Version, [string]$Dir, [string]$ComponentPath) {
    $pp = ConvertTo-PackedGuid $Code
    $ip = "$M1bKeyInstUD\Products\$pp\InstallProperties"
    if (Test-RegKey "$M1bKeyInstUD\Products\$pp") {
        Add-M1bPlanted $Ctx 'key' "K:$M1bKeyInstUD\Products\$pp" 'existed, kept (the uninstall left it)'
    } else {
        Set-M1bValue $Ctx $ip 'DisplayName' $Name
        Set-M1bValue $Ctx $ip 'DisplayVersion' $(if ($Version) { $Version } else { '1.0' })
        Set-M1bValue $Ctx $ip 'Publisher' 'PurgeTrap'
        Set-M1bValue $Ctx $ip 'InstallLocation' ($Dir.TrimEnd('\') + '\')
        Set-M1bValue $Ctx $ip 'LocalPackage' ("C:\Windows\Installer\PurgeTrap{0}.msi" -f $pp.Substring(0, 8))
        Set-M1bValue $Ctx $ip 'UninstallString' "MsiExec.exe /X$Code"
        Set-M1bValue $Ctx $ip 'WindowsInstaller' 1 DWord
        Set-M1bValue $Ctx $ip 'PurgeTrap' 1 DWord
    }
    Set-M1bValue $Ctx "$M1bKeyUpgrade\$(ConvertTo-PackedGuid $Upgrade)" $pp '' -KeepExisting
    Set-M1bValue $Ctx "$M1bKeyInstUD\Components\$(ConvertTo-PackedGuid $Component)" $pp $ComponentPath -KeepExisting
}

# msi-remnants: TrapA's own product code re-registered after its uninstall.
function Plant-MsiRemnants($Ctx) {
    Assert-M1bRigVm
    Assert-M1bProductCode $Ctx.A 'msi-remnants'
    $up = $(if ($Ctx.A.upgrade_code) { $Ctx.A.upgrade_code } else { Add-M1bPlanted $Ctx 'note' 'upgrade code' "none found at pre; fabricated $($M1bG.UpgrFallback)"; $M1bG.UpgrFallback })
    Set-M1bMsiRegistration $Ctx $Ctx.A.product_code $up $M1bG.CompA $Ctx.A.name $Ctx.A.version $Ctx.A.dir $Ctx.A.exe
}

# msi-remnants-foreign: the same three for a fabricated product code that is NOT in the fingerprint, named after
# TrapA and pointing into TrapA's former folder (attribution must go by product code, not by name or path).
function Plant-MsiRemnantsForeign($Ctx) {
    Assert-M1bRigVm
    Set-M1bMsiRegistration $Ctx $M1bG.ForeignCode $M1bG.ForeignUpgr $M1bG.CompForeign "$($Ctx.A.short) PurgeTrap Foreign" '1.0' $Ctx.A.dir (Join-Path $Ctx.A.dir 'PurgeTrapForeign.dat')
}

# msi-shared-component: Components\<c2> with TrapA's and TrapB's packed codes, data = a file re-created in TrapA's
# former folder.
function Plant-SharedComponent($Ctx) {
    Assert-M1bRigVm
    Assert-M1bProductCode $Ctx.A 'msi-shared-component'
    Assert-M1bProductCode $Ctx.B 'msi-shared-component'
    $f = Join-Path $Ctx.A.dir 'PurgeTrapComponent.dat'
    Write-M1bFile $Ctx $f "PurgeTrap shared component file`r`n"
    $k = "$M1bKeyInstUD\Components\$(ConvertTo-PackedGuid $M1bG.CompShared)"
    Set-M1bValue $Ctx $k (ConvertTo-PackedGuid $Ctx.A.product_code) $f -KeepExisting
    Set-M1bValue $Ctx $k (ConvertTo-PackedGuid $Ctx.B.product_code) $f -KeepExisting
}

# com-isimpledom: Interface\{ISimpleDOMNode}\ProxyStubClsid32 = TrapA's planted proxy CLSID, in both views. When a
# real product already registered the interface (Firefox, Thunderbird, NVDA on dirty-base) it is left alone and the
# case is recorded as skipped.
function Plant-IsimpleDom($Ctx) {
    Assert-M1bRigVm
    Set-M1bComClass $Ctx $M1bG.ProxyClsid (Join-Path $Ctx.A.dir 'PurgeTrapProxy.dll') 'PurgeTrap A Proxy'
    foreach ($root in $M1bKeyClasses, $M1bKeyClasses32) {
        $k = "$root\Interface\$M1bISimpleDomIid"
        if ((Test-RegKey $k) -and -not ("$(Get-RegRaw "$k\ProxyStubClsid32" '')" -ieq $M1bG.ProxyClsid)) {
            Add-M1bPlanted $Ctx 'key' "K:$k" "existed, kept (registered by another product: $(Get-RegRaw "$k\ProxyStubClsid32" ''))"
            continue
        }
        Set-M1bValue $Ctx $k '' 'ISimpleDOMNode'
        Set-M1bValue $Ctx "$k\ProxyStubClsid32" '' $M1bG.ProxyClsid
        Set-M1bValue $Ctx "$k\NumMethods" '' '18'
    }
}

# burn-shared-package: Installer\Dependencies\PurgeTrapPkg with Dependents\<TrapA's bundle id> and
# Dependents\<another bundle>, plus its Package Cache directory.
function Plant-BurnShared($Ctx) {
    Assert-M1bRigVm
    $aDep = $(if ($Ctx.A.bundle -and $Ctx.A.arp_leaf) { $Ctx.A.arp_leaf } elseif ($Ctx.A.product_code) { $Ctx.A.product_code } else { throw 'burn-shared-package needs TrapA''s bundle id or product code (pre state)' })
    $k = "$M1bKeyDeps\PurgeTrapPkg"
    Set-M1bValue $Ctx $k '' 'PurgeTrapPkg'
    Set-M1bValue $Ctx $k 'DisplayName' 'PurgeTrap Shared Package'
    Set-M1bValue $Ctx $k 'Version' '1.0.0.0'
    Set-M1bKey $Ctx "$k\Dependents\$aDep"
    Set-M1bKey $Ctx "$k\Dependents\$($M1bG.OtherBundle)"
    Write-M1bFile $Ctx (Join-Path $M1bPkgCache 'PurgeTrapPkg\PurgeTrapPkg.msi') "PurgeTrap package cache payload`r`n"
}

# pkgcache-foreign: a Package Cache directory named by TrapB's product code (and version), as Burn names it.
function Plant-PkgCacheForeign($Ctx) {
    Assert-M1bRigVm
    Assert-M1bProductCode $Ctx.B 'pkgcache-foreign'
    $name = $Ctx.B.product_code + $(if ($Ctx.B.version) { "v$($Ctx.B.version)" } else { '' })
    $dir = Join-Path $M1bPkgCache $name
    if ((Test-Path -LiteralPath $dir) -and -not (Test-Path -LiteralPath (Join-Path $dir 'PurgeTrapForeign.msi'))) {
        Add-M1bPlanted $Ctx 'dir' "P:$dir" 'existed, kept (a real cache directory)'
        return
    }
    Write-M1bFile $Ctx (Join-Path $dir 'PurgeTrapForeign.msi') "PurgeTrap foreign package cache payload`r`n"
}

# instfolders: Installer\Folders values for TrapA's former folder and TrapB's folder (TrapB's is usually there
# already, written by its own install, and kept).
function Plant-InstFolders($Ctx) {
    Assert-M1bRigVm
    Set-M1bValue $Ctx $M1bKeyFolders ($Ctx.A.dir.TrimEnd('\') + '\') '' -KeepExisting
    Set-M1bValue $Ctx $M1bKeyFolders ($Ctx.B.dir.TrimEnd('\') + '\') '' -KeepExisting
}

# ------------------------------------------------------------------------------------------ runner

function Read-M1bJson([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    [IO.File]::ReadAllText($Path) | ConvertFrom-Json
}

# PSCustomObject (from JSON) -> ordered hashtable, one level.
function ConvertTo-M1bMap($O) {
    if ($null -eq $O) { return $null }
    $m = [ordered]@{}
    foreach ($p in $O.PSObject.Properties) { $m[$p.Name] = $p.Value }
    $m
}

# Runs one case: guard, plant, record. Returns the case record {id, phase, plant, ok, skipped, error, planted[]}.
function Invoke-M1bCase($CaseDef, [string]$Step, $A, $B) {
    $fn = $(if ($Step -eq 'between') { $CaseDef.between } else { $CaseDef.plant })
    $ctx = [pscustomobject]@{ Case = $CaseDef.id; Phase = $Step; A = $A; B = $B; Planted = (New-Object System.Collections.ArrayList); Skipped = $false }
    $rec = [ordered]@{ id = $CaseDef.id; phase = $Step; plant = $fn; at = (NowIso); ok = $false; skipped = $false; error = $null; planted = $null }
    Log "m1b-trap $($CaseDef.id): $fn ($Step)"
    try {
        Assert-M1bRigVm
        $ErrorActionPreference = 'Stop'
        $null = & $fn $ctx
        $rec.ok = $true
    } catch {
        $rec.error = "$($_.Exception.Message)"
        Log "  !! m1b-trap $($CaseDef.id): $($rec.error)"
    }
    $rec.skipped = [bool]$ctx.Skipped
    $rec.planted = @($ctx.Planted)
    $rec
}

function Invoke-M1bPhase([string]$Step, [string[]]$Ids, [string]$Dir) {
    Assert-M1bRigVm
    $stateF = Join-Path $Dir 'm1b-traps-state.json'
    $plantF = Join-Path $Dir 'm1b-traps-planted.json'
    $state = Read-M1bJson $stateF
    if ($Step -eq 'pre' -or -not $state) {
        if ($Step -ne 'pre') { Log "  !! m1b-traps: no $stateF; resolving TrapA/TrapB now (TrapA's product code is lost when it is already uninstalled)" }
        $state = [ordered]@{ schema = 'purge.rig.m1b-traps.state/1'; at = (NowIso); computer = (Get-M1bComputerName); a = (Resolve-M1bProduct $TrapA); b = (Resolve-M1bProduct $TrapB); between_done = @() }
        if ($Step -eq 'pre' -and -not $state.a.installed) { throw "TrapA '$TrapA' is not installed (no ARP entry matches); the pre plants need it" }
        if (-not $state.b.installed) { Log "  !! m1b-traps: TrapB '$TrapB' is not installed" }
    } else {
        $state = ConvertTo-M1bMap $state
        $state.a = ConvertTo-M1bMap $state.a; $state.b = ConvertTo-M1bMap $state.b
        $state.between_done = @($state.between_done)
    }
    $A = [pscustomobject]$state.a; $B = [pscustomobject]$state.b
    $doc = Read-M1bJson $plantF
    $cases = [ordered]@{}
    if ($doc) { foreach ($p in $doc.cases.PSObject.Properties) { $cases[$p.Name] = $p.Value } }
    $todo = New-Object System.Collections.ArrayList
    if ($Step -eq 'post') {
        # A between step the host did not run goes first.
        foreach ($c in @(Get-M1bCases 'between' $Ids)) {
            if ($state.between_done -notcontains $c.id -and $cases.Contains($c.id)) { [void]$todo.Add(@($c, 'between')) }
        }
    }
    foreach ($c in @(Get-M1bCases $Step $Ids)) { [void]$todo.Add(@($c, $Step)) }
    $failed = 0
    foreach ($t in $todo) {
        $r = Invoke-M1bCase $t[0] $t[1] $A $B
        $key = $(if ($t[1] -eq 'between') { "$($t[0].id)#between" } else { $t[0].id })
        $cases[$key] = $r
        if (-not $r.ok) { $failed++ }
        if ($t[1] -eq 'between' -and $r.ok) { $state.between_done = @($state.between_done) + $t[0].id }
    }
    Write-JsonFile $state $stateF
    $out = [ordered]@{ schema = 'purge.rig.m1b-traps.planted/1'; computer = (Get-M1bComputerName); trap_a = $TrapA; trap_b = $TrapB; updated = (NowIso); cases = $cases }
    Write-JsonFile $out $plantF 12
    Log ("m1b-traps {0}: {1} case step(s), {2} failed -> {3}" -f $Step, $todo.Count, $failed, $plantF)
    $failed
}

if ($Library) { return }

# ------------------------------------------------------------------------------------------ main

if ($List) {
    Get-M1bCaseListing | ForEach-Object { Write-Output $_ }
    exit 0
}
if (-not $Phase) { throw 'give -List or -Phase pre|between|post' }

if (-not (Get-Command Log -ErrorAction SilentlyContinue)) {
    $lib = Join-Path $PSScriptRoot 'riglib.ps1'
    if (-not (Test-Path -LiteralPath $lib)) { $lib = 'C:\cr\guest\riglib.ps1' }
    . $lib
}
$apps = Join-Path $PSScriptRoot 'apps.ps1'
if (-not (Get-Command Get-App -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $apps)) { . $apps }
Assert-M1bRigVm
if (-not [Environment]::Is64BitProcess) { throw 'run in 64-bit PowerShell' }
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run elevated (through the rig agent)' }
if (-not $OutDir) { throw 'give -OutDir (the run directory)' }
New-Item -ItemType Directory -Force $OutDir | Out-Null
if ($RunLog) { Set-RunLog $RunLog } elseif (-not $script:RigLogFile) { Set-RunLog (Join-Path $OutDir 'm1b-traps.log') }
Log "m1b-traps $Phase on $(Get-M1bComputerName) (TrapA $TrapA, TrapB $TrapB, sid $RigUserSid)"
$failed = Invoke-M1bPhase $Phase $Case $OutDir
if ($failed) { exit 1 }
exit 0
