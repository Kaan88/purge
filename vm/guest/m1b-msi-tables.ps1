# Purge rig, M1b: the MSI tables capture beside a snapshot (docs/M1B_DESIGN.json M1B-RIG-HOST; schema
# purge.rig.msi_tables/1, read by crates/purge-source/src/snapfixture.rs). Windows PowerShell 5.1, 64-bit.
#
#   m1b-msi-tables.ps1 -Out C:\cr\out\<run>\msi-tables-<run>-<phase>.json
#
# Written by run-app.ps1 right after snap <phase> when the host asks for it (rig.ps1 m1b-* modes, __M1B__
# msi_tables). For every product Windows Installer lists in any context (UserData\<sid>\Products\*\InstallProperties,
# value LocalPackage) the cached package is opened READ-ONLY (WindowsInstaller.Installer OpenDatabase mode 0) and the
# rows purge-win msi_db::read_tables returns are copied, with the same rules:
#   - Property: the fixed set (ProductCode, UpgradeCode, ProductName, ProductVersion, Manufacturer, ALLUSERS,
#     ARPINSTALLLOCATION) plus every [Name] a Registry / RemoveRegistry Key or Name cell references;
#   - Component, Registry, RemoveRegistry, Class, ProgId, Extension, TypeLib, AppId, ServiceInstall, and the row
#     count of CustomAction; a table the package does not have is an empty list;
#   - a null text cell is null in an optional column and "" in a required one; a null integer is -2147483648;
#   - at most 200000 rows per table (then truncated), a row with a cell over 64 KiB in UTF-8 is dropped (truncated);
#   - a package that cannot be opened, or a table that exists but cannot be read, is written {"truncated": true}
#     (the engine then treats the package as unreadable, as the live source does).
# No installer session is opened, nothing is installed, repaired or written; only C:\cr is written.
[CmdletBinding()]
param([string]$Out = '', [switch]$Library)

$MtFixed = @('ProductCode', 'UpgradeCode', 'ProductName', 'ProductVersion', 'Manufacturer', 'ALLUSERS', 'ARPINSTALLLOCATION')
$MtMaxRows = 200000
$MtMaxCellBytes = 65536
$MtNullInt = -2147483648

# Pure: the property names a Formatted string references ([Name] with an identifier inside; innermost pair).
function Get-MtPropertyRefs([string]$Formatted) {
    $out = @()
    if (-not $Formatted) { return $out }
    $open = -1
    for ($i = 0; $i -lt $Formatted.Length; $i++) {
        $c = $Formatted[$i]
        if ($c -eq '[') { $open = $i + 1 }
        elseif ($c -eq ']') {
            if ($open -ge 0) {
                $inner = $Formatted.Substring($open, $i - $open)
                if ($inner -cmatch '^[A-Za-z_][A-Za-z0-9_.]*$') { $out += $inner }
            }
            $open = -1
        }
    }
    $out
}

function Invoke-MtCom($Obj, [string]$Name, [string]$Kind, [object[]]$Args_ = @()) {
    $Obj.GetType().InvokeMember($Name, [Reflection.BindingFlags]$Kind, $null, $Obj, $Args_)
}

function Test-MtCellFits($Cells) {
    foreach ($c in $Cells) { if ($c -is [string] -and [Text.Encoding]::UTF8.GetByteCount($c) -gt $MtMaxCellBytes) { return $false } }
    $true
}

# Rows of `SELECT cols FROM table` as arrays of cells (string or $null; integer columns as [int]). $IntCols are the
# 1-based numbers of integer columns, $OptCols those of optional text columns. Missing table: empty. Sets
# $Ctx.truncated on a cut or a dropped row; throws when an existing table cannot be read.
function Read-MtTable($Ctx, $Db, [string]$Table, [string[]]$Cols, [int[]]$IntCols = @(), [int[]]$OptCols = @()) {
    $rows = New-Object System.Collections.ArrayList
    $chk = Invoke-MtCom $Db 'OpenView' 'InvokeMethod' @("SELECT ``Name`` FROM ``_Tables`` WHERE ``Name``='$Table'")
    try {
        $null = Invoke-MtCom $chk 'Execute' 'InvokeMethod'
        $hit = Invoke-MtCom $chk 'Fetch' 'InvokeMethod'
    } finally { $null = Invoke-MtCom $chk 'Close' 'InvokeMethod' }
    if (-not $hit) { return }
    $q = 'SELECT ' + (($Cols | ForEach-Object { '`' + $_ + '`' }) -join ', ') + ' FROM `' + $Table + '`'
    $v = Invoke-MtCom $Db 'OpenView' 'InvokeMethod' @($q)
    try {
        $null = Invoke-MtCom $v 'Execute' 'InvokeMethod'
        while ($true) {
            $r = Invoke-MtCom $v 'Fetch' 'InvokeMethod'
            if (-not $r) { break }
            if ($rows.Count -ge $MtMaxRows) { $Ctx.truncated = $true; break }
            $cells = New-Object object[] $Cols.Count
            for ($n = 1; $n -le $Cols.Count; $n++) {
                if ($IntCols -contains $n) {
                    $cells[$n - 1] = [int](Invoke-MtCom $r 'IntegerData' 'GetProperty' @($n))
                } elseif ((Invoke-MtCom $r 'IsNull' 'GetProperty' @($n)) -and $OptCols -contains $n) {
                    $cells[$n - 1] = $null
                } else {
                    $cells[$n - 1] = [string](Invoke-MtCom $r 'StringData' 'GetProperty' @($n))
                }
            }
            if (-not (Test-MtCellFits $cells)) { $Ctx.truncated = $true; continue }
            [void]$rows.Add($cells)
        }
    } finally { $null = Invoke-MtCom $v 'Close' 'InvokeMethod' }
    $rows
}

# The tables of one package in the MsiTables shape, or {truncated = $true} when it cannot be read.
function Read-MtPackage($Installer, [string]$Path) {
    $ctx = [pscustomobject]@{ truncated = $false }
    try {
        $db = Invoke-MtCom $Installer 'OpenDatabase' 'InvokeMethod' @($Path, 0)
        $reg = @(Read-MtTable $ctx $db 'Registry' @('Registry', 'Root', 'Key', 'Name', 'Value', 'Component_') @(2) @(4, 5))
        $rem = @(Read-MtTable $ctx $db 'RemoveRegistry' @('RemoveRegistry', 'Root', 'Key', 'Name', 'Component_') @(2) @(4))
        $want = @{}
        foreach ($p in $MtFixed) { $want[$p] = $true }
        foreach ($r in @($reg) + @($rem)) { foreach ($p in @(Get-MtPropertyRefs $r[2]) + @(Get-MtPropertyRefs $r[3])) { $want[$p] = $true } }
        $props = New-Object System.Collections.ArrayList
        foreach ($r in @(Read-MtTable $ctx $db 'Property' @('Property', 'Value'))) { if ($want.ContainsKey($r[0])) { [void]$props.Add(@($r[0], $r[1])) } }
        $doc = [ordered]@{
            properties = $props
            components = @(Read-MtTable $ctx $db 'Component' @('Component', 'ComponentId', 'Attributes', 'KeyPath') @(3) @(2, 4) |
                ForEach-Object { [ordered]@{ component = $_[0]; component_id = $_[1]; attributes = $_[2]; key_path = $_[3] } })
            registry = @($reg | ForEach-Object { [ordered]@{ row = $_[0]; root = $_[1]; key = $_[2]; name = $_[3]; value = $_[4]; component = $_[5] } })
            remove_registry = @($rem | ForEach-Object { [ordered]@{ row = $_[0]; root = $_[1]; key = $_[2]; name = $_[3]; value = $null; component = $_[4] } })
            classes = @(Read-MtTable $ctx $db 'Class' @('CLSID', 'Context', 'Component_', 'ProgId_Default', 'AppId_') @() @(4, 5) |
                ForEach-Object { [ordered]@{ clsid = $_[0]; context = $_[1]; component = $_[2]; progid = $_[3]; appid = $_[4] } })
            progids = @(Read-MtTable $ctx $db 'ProgId' @('ProgId') | ForEach-Object { $_[0] })
            extensions = @(Read-MtTable $ctx $db 'Extension' @('Extension', 'Component_', 'ProgId_') @() @(3) |
                ForEach-Object { [ordered]@{ extension = $_[0]; component = $_[1]; progid = $_[2] } })
            typelibs = @(Read-MtTable $ctx $db 'TypeLib' @('LibID') | ForEach-Object { $_[0] })
            appids = @(Read-MtTable $ctx $db 'AppId' @('AppId') | ForEach-Object { $_[0] })
            service_install = @(Read-MtTable $ctx $db 'ServiceInstall' @('Name', 'Component_', 'ServiceType', 'StartType') @(3, 4) |
                ForEach-Object { [ordered]@{ name = $_[0]; component = $_[1]; service_type = $_[2]; start_type = $_[3] } })
            custom_action_count = [int](@(Read-MtTable $ctx $db 'CustomAction' @('Action')).Count)
            truncated = $false
        }
        $doc.truncated = [bool]$ctx.truncated
        $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($db)
        return [pscustomobject]@{ doc = $doc; error = $null }
    } catch {
        return [pscustomobject]@{ doc = [ordered]@{ truncated = $true }; error = "$($_.Exception.Message)" }
    }
}

# Every LocalPackage Windows Installer lists (machine and per-user contexts), each once (case-insensitive).
function Get-MtLocalPackages {
    $base = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
    $lm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    $seen = @{}; $out = @()
    try {
        $ud = $lm.OpenSubKey($base, $false)
        if (-not $ud) { return @() }
        foreach ($sid in $ud.GetSubKeyNames()) {
            $pk = $ud.OpenSubKey("$sid\Products", $false)
            if (-not $pk) { continue }
            foreach ($p in $pk.GetSubKeyNames()) {
                $ip = $pk.OpenSubKey("$p\InstallProperties", $false)
                if (-not $ip) { continue }
                $lp = "$($ip.GetValue('LocalPackage', '', 'DoNotExpandEnvironmentNames'))".Trim()
                $ip.Dispose()
                if ($lp -and -not $seen.ContainsKey($lp.ToLowerInvariant().Replace('/', '\'))) { $seen[$lp.ToLowerInvariant().Replace('/', '\')] = $true; $out += $lp }
            }
            $pk.Dispose()
        }
        $ud.Dispose()
    } finally { $lm.Dispose() }
    $out
}

if ($Library) { return }

if (-not $Out) { throw 'give -Out <file>' }
if (-not (Get-Command Log -ErrorAction SilentlyContinue)) { function Log([string]$m) { Write-Host $m } }
$inst = New-Object -ComObject WindowsInstaller.Installer
$pk = [ordered]@{}
$bad = 0
$t0 = Get-Date
foreach ($lp in @(Get-MtLocalPackages)) {
    $r = Read-MtPackage $inst $lp
    $pk[$lp] = $r.doc
    if ($r.error) { $bad++; Log "  !! msi tables: $lp unreadable: $($r.error)" }
}
$null = [Runtime.InteropServices.Marshal]::ReleaseComObject($inst)
$doc = [ordered]@{ schema = 'purge.rig.msi_tables/1'; packages = $pk }
$json = ConvertTo-Json -InputObject $doc -Depth 12
[IO.File]::WriteAllText($Out, $json, (New-Object System.Text.UTF8Encoding($false)))
Log ("msi tables: {0} package(s), {1} unreadable -> {2} ({3:N0} s)" -f $pk.Count, $bad, $Out, ((Get-Date) - $t0).TotalSeconds)
exit 0
