# Purge rig, M3 e2e: the two failing-uninstaller MSI fixtures (vm\RIG.md section 17; docs\M3_FINISH_PLAN.md B7).
# Windows PowerShell 5.1, functions only (dot-sourced by m3-e2e.ps1 in the guest and by the host self-test, which
# builds both packages in %TEMP% and reads them back; building needs no elevation, installing does).
#
# The repo has no WiX and no MSI fixture, so the packages are written directly with the Windows Installer automation
# interface (WindowsInstaller.Installer, OpenDatabase in create mode, SQL CREATE TABLE / INSERT, summary stream). Each is
# a per-machine x64 product with one registry-only component (HKLM\SOFTWARE\PurgeE2eMsi\<variant>, the key path) and the
# standard execute sequence, nothing else (no files, no UI sequence: the rig installs and Purge uninstalls with /qn).
#
#   1603  a type 19 custom action (error message, then failure) runs only when REMOVE="ALL", after InstallInitialize:
#         `msiexec /x` returns 1603 (ERROR_INSTALL_FAILURE), rolls back, and the product stays installed.
#   3010  ScheduleReboot runs only when REMOVE="ALL", before InstallFinalize; REBOOT=ReallySuppress is in the Property
#         table (and in Purge's quiet command): the product is removed, no restart happens, msiexec returns 3010
#         (ERROR_SUCCESS_REBOOT_REQUIRED).
#
# Codes are fixed (the same product on every build), so a rerun on a restored snapshot sees the same ARP key.

$E2eMsiVariants = [ordered]@{
    '1603' = [ordered]@{ name = 'Purge E2E Failing Uninstall'; product = '{6F3E2B1A-7C4D-4E51-9A0B-2D8C1E6F1603}'; upgrade = '{6F3E2B1A-7C4D-4E51-9A0B-2D8C1E6FA603}'
                         component = '{6F3E2B1A-7C4D-4E51-9A0B-2D8C1E6FC603}'; package = '{6F3E2B1A-7C4D-4E51-9A0B-2D8C1E6FD603}'; file = 'purge-e2e-1603.msi' }
    '3010' = [ordered]@{ name = 'Purge E2E Reboot Uninstall'; product = '{6F3E2B1A-7C4D-4E51-9A0B-2D8C1E6F3010}'; upgrade = '{6F3E2B1A-7C4D-4E51-9A0B-2D8C1E6FA010}'
                         component = '{6F3E2B1A-7C4D-4E51-9A0B-2D8C1E6FC010}'; package = '{6F3E2B1A-7C4D-4E51-9A0B-2D8C1E6FD010}'; file = 'purge-e2e-3010.msi' }
}

function Invoke-E2eMsiCom($Object, [string]$Member, [string]$Kind, [object[]]$Arguments = @()) {
    $flags = [Reflection.BindingFlags]::$Kind
    $Object.GetType().InvokeMember($Member, $flags, $null, $Object, $Arguments)
}

function Invoke-E2eMsiSql($Db, [string]$Sql) {
    $v = Invoke-E2eMsiCom $Db 'OpenView' 'InvokeMethod' @($Sql)
    try { $null = Invoke-E2eMsiCom $v 'Execute' 'InvokeMethod' @() }
    finally { $null = Invoke-E2eMsiCom $v 'Close' 'InvokeMethod' @(); $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($v) }
}

# Pure: an SQL string literal for MSI SQL (single quotes; a quote inside is refused, the fixture never needs one).
function ConvertTo-E2eMsiLiteral($Value) {
    if ($null -eq $Value) { return 'NULL' }
    if ($Value -is [int]) { return "$Value" }
    $s = "$Value"
    if ($s.Contains("'")) { throw "MSI fixture: a quote in a value is not supported: $s" }
    "'$s'"
}

# Pure: the table definitions and rows of a variant (also what the self-test reads back).
function Get-E2eMsiTables([string]$Variant) {
    $v = $E2eMsiVariants[$Variant]
    if (-not $v) { throw "unknown MSI fixture variant '$Variant' (1603, 3010)" }
    $create = [ordered]@{
        Property               = '`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE PRIMARY KEY `Property`'
        Directory              = '`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Directory`'
        Component              = '`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`'
        Feature                = '`Feature` CHAR(38) NOT NULL, `Feature_Parent` CHAR(38), `Title` CHAR(64) LOCALIZABLE, `Description` CHAR(255) LOCALIZABLE, `Display` SHORT, `Level` SHORT NOT NULL, `Directory_` CHAR(72), `Attributes` SHORT NOT NULL PRIMARY KEY `Feature`'
        FeatureComponents      = '`Feature_` CHAR(38) NOT NULL, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Feature_`, `Component_`'
        Registry               = '`Registry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL LOCALIZABLE, `Name` CHAR(255) LOCALIZABLE, `Value` LONGCHAR LOCALIZABLE, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Registry`'
        CustomAction           = '`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255) PRIMARY KEY `Action`'
        InstallExecuteSequence = '`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`'
    }
    $rows = [ordered]@{
        Property = @(
            @('ProductCode', $v.product), @('UpgradeCode', $v.upgrade), @('ProductName', $v.name), @('ProductVersion', '1.0.0'),
            @('Manufacturer', 'Purge rig'), @('ProductLanguage', '1033'), @('ALLUSERS', '1'), @('ARPNOMODIFY', '1'), @('ARPNOREPAIR', '1'),
            @('REBOOT', 'ReallySuppress'), @('MSIRESTARTMANAGERCONTROL', 'Disable'))
        Directory = @(@('TARGETDIR', $null, 'SourceDir'), @('ProgramFiles64Folder', 'TARGETDIR', '.'), @('INSTALLDIR', 'ProgramFiles64Folder', "PurgeE2e|PurgeE2eMsi$Variant"))
        # Attributes 260 = msidbComponentAttributesRegistryKeyPath (4) + msidbComponentAttributes64bit (256).
        Component = @(, @('MainReg', $v.component, 'INSTALLDIR', 260, $null, 'RegMain'))
        Feature = @(, @('Main', $null, $v.name, $null, 1, 1, 'INSTALLDIR', 0))
        FeatureComponents = @(, @('Main', 'MainReg'))
        # Root 2 = HKLM.
        Registry = @(@('RegMain', 2, "SOFTWARE\PurgeE2eMsi\$Variant", 'Installed', '1', 'MainReg'), @('RegName', 2, "SOFTWARE\PurgeE2eMsi\$Variant", 'Fixture', $v.name, 'MainReg'))
        CustomAction = @()
        InstallExecuteSequence = @(
            @('CostInitialize', $null, 800), @('CostFinalize', $null, 1000), @('InstallValidate', $null, 1400), @('InstallInitialize', $null, 1500),
            @('ProcessComponents', $null, 1600), @('UnpublishFeatures', $null, 1800), @('RemoveRegistryValues', $null, 2600),
            @('WriteRegistryValues', $null, 5000), @('RegisterUser', $null, 6000), @('RegisterProduct', $null, 6100),
            @('PublishFeatures', $null, 6300), @('PublishProduct', $null, 6400), @('InstallFinalize', $null, 6600))
    }
    if ($Variant -eq '1603') {
        # Type 19: display the formatted Target as an error and end the installation with failure (1603).
        $rows.CustomAction = @(, @('PurgeE2eFail', 19, $null, 'Purge rig fixture: this uninstall fails on purpose (1603).'))
        $rows.InstallExecuteSequence += , @('PurgeE2eFail', 'REMOVE="ALL"', 1550)
    } else {
        $rows.InstallExecuteSequence += , @('ScheduleReboot', 'REMOVE="ALL"', 6590)
    }
    [ordered]@{ variant = $Variant; def = $v; create = $create; rows = $rows }
}

# Builds the package of $Variant at $Path (overwritten). Returns {path, product, name, sha256}.
function New-E2eMsi([string]$Variant, [string]$Path) {
    $ErrorActionPreference = 'Stop'
    $t = Get-E2eMsiTables $Variant
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $dir = Split-Path -Parent $Path
    if ($dir) { New-Item -ItemType Directory -Force $dir | Out-Null }
    $inst = New-Object -ComObject WindowsInstaller.Installer
    $db = $null
    try {
        # 3 = msiOpenDatabaseModeCreate
        $db = Invoke-E2eMsiCom $inst 'OpenDatabase' 'InvokeMethod' @($Path, 3)
        foreach ($table in $t.create.Keys) {
            Invoke-E2eMsiSql $db ("CREATE TABLE ``$table`` ($($t.create[$table]))")
            $cols = @([regex]::Matches($t.create[$table], '^`([^`]+)`|, `([^`]+)` (?:CHAR|LONGCHAR|SHORT|LONG)') | ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value } })
            foreach ($row in @($t.rows[$table])) {
                if ($null -eq $row) { continue }
                $vals = @($row | ForEach-Object { ConvertTo-E2eMsiLiteral $_ })
                if ($vals.Count -ne $cols.Count) { throw "MSI fixture: $table row has $($vals.Count) values for $($cols.Count) columns" }
                Invoke-E2eMsiSql $db ("INSERT INTO ``$table`` (" + (@($cols | ForEach-Object { "``$_``" }) -join ', ') + ') VALUES (' + ($vals -join ', ') + ')')
            }
        }
        $si = Invoke-E2eMsiCom $db 'SummaryInformation' 'GetProperty' @(20)
        try {
            # (pairs, not a dictionary: an [ordered] dictionary indexed with an int key answers by position)
            $props = @(@(1, 1252), @(2, 'Installation Database'), @(3, "$($t.def.name)"), @(4, 'Purge rig'), @(5, 'Installer'), @(7, 'x64;1033'),
                       @(9, "$($t.def.package)"), @(14, 200), @(15, 2), @(19, 2))
            foreach ($p in $props) { $null = Invoke-E2eMsiCom $si 'Property' 'SetProperty' @([int]$p[0], $p[1]) }
            $null = Invoke-E2eMsiCom $si 'Persist' 'InvokeMethod' @()
        } finally { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($si) }
        $null = Invoke-E2eMsiCom $db 'Commit' 'InvokeMethod' @()
    } finally {
        if ($db) { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) }
        $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($inst)
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
    [ordered]@{ path = $Path; variant = $Variant; product = $t.def.product; name = $t.def.name; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
}

# Reads a built package back (read-only): {sequence: {action: [condition, sequence]}, custom: {action: [type, target]},
# property: {name: value}, template}. The self-test checks a built package with it.
function Read-E2eMsi([string]$Path) {
    $ErrorActionPreference = 'Stop'
    $inst = New-Object -ComObject WindowsInstaller.Installer
    $db = $null
    $out = [ordered]@{ sequence = [ordered]@{}; custom = [ordered]@{}; property = [ordered]@{}; template = $null }
    try {
        $db = Invoke-E2eMsiCom $inst 'OpenDatabase' 'InvokeMethod' @($Path, 0)
        $read = {
            param([string]$Sql, [int]$N)
            $rows = @()
            $v = Invoke-E2eMsiCom $db 'OpenView' 'InvokeMethod' @($Sql)
            try {
                $null = Invoke-E2eMsiCom $v 'Execute' 'InvokeMethod' @()
                while ($true) {
                    $r = Invoke-E2eMsiCom $v 'Fetch' 'InvokeMethod' @()
                    if ($null -eq $r) { break }
                    $rows += , @(1..$N | ForEach-Object { Invoke-E2eMsiCom $r 'StringData' 'GetProperty' @([int]$_) })
                    $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($r)
                }
            } finally { $null = Invoke-E2eMsiCom $v 'Close' 'InvokeMethod' @(); $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($v) }
            , $rows
        }
        foreach ($r in (& $read 'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`' 3)) { $out.sequence[$r[0]] = @($r[1], $r[2]) }
        foreach ($r in (& $read 'SELECT `Action`, `Type`, `Target` FROM `CustomAction`' 3)) { $out.custom[$r[0]] = @($r[1], $r[2]) }
        foreach ($r in (& $read 'SELECT `Property`, `Value` FROM `Property`' 2)) { $out.property[$r[0]] = $r[1] }
        $si = Invoke-E2eMsiCom $db 'SummaryInformation' 'GetProperty' @(0)
        try { $out.template = Invoke-E2eMsiCom $si 'Property' 'GetProperty' @(7) } finally { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($si) }
    } finally {
        if ($db) { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) }
        $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($inst)
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
    $out
}
