# The one version of Purge is [workspace.package] version in the root Cargo.toml. This script reads it,
# checks that Cargo.lock agrees (a --locked release build fails otherwise), and checks every exe it is
# given: the ProductVersion string must be the version and the fixed FILEVERSION its X.Y.Z (plus .0).
# Hub (Kaan88/mdhub, docs/COMPLIANCE.md section 5) reads the installed Purge.exe's FILEVERSION.
# Exit 0 and the version on stdout when everything agrees; exit 1 with the differences otherwise.
# Windows PowerShell 5.1 and PowerShell 7.
#
#   check-version.ps1                                    the version, Cargo.lock checked
#   check-version.ps1 -Exe a.exe, b.exe                  and these exes' version resources
#   check-version.ps1 -Setup Purge-Setup-<v>.exe         and the setup's ProductVersion (Inno's
#                                                        VersionInfoProductVersion = AppVersion)
#   check-version.ps1 -Expect 1.2.3                      and the version a tag asks for

[CmdletBinding()]
param(
    [string[]]$Exe = @(),
    [string]$Setup = '',
    [string]$Expect = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$problems = New-Object System.Collections.Generic.List[string]

$cargoToml = [IO.File]::ReadAllText((Join-Path $repo 'Cargo.toml'))
$section = [regex]::Match($cargoToml, '(?ms)^\[workspace\.package\](.*?)(?=^\[|\z)')
if (-not $section.Success) { [Console]::Error.WriteLine('check-version: Cargo.toml has no [workspace.package] section'); exit 1 }
$found = [regex]::Match($section.Groups[1].Value, '(?m)^\s*version\s*=\s*"([^"]+)"')
if (-not $found.Success) { [Console]::Error.WriteLine('check-version: Cargo.toml [workspace.package] has no version'); exit 1 }
$version = $found.Groups[1].Value
if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$') {
    [Console]::Error.WriteLine("check-version: Cargo.toml version '$version' is not X.Y.Z[-pre]"); exit 1
}
$numeric = ($version -split '[-+]')[0]

if ($Expect -ne '' -and $Expect -ne $version) {
    $problems.Add("the release asks for $Expect but Cargo.toml says $version")
}

# Cargo.lock: every package of this workspace carries the workspace version.
$lockPath = Join-Path $repo 'Cargo.lock'
if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
    $lock = [IO.File]::ReadAllText($lockPath)
    foreach ($m in [regex]::Matches($lock, '(?m)^name = "((?:purge-[a-z-]+)|xtask)"\r?\nversion = "([^"]+)"')) {
        if ($m.Groups[2].Value -ne $version) {
            $problems.Add("Cargo.lock has $($m.Groups[1].Value) $($m.Groups[2].Value), Cargo.toml $version (run cargo update -w)")
        }
    }
}

foreach ($path in $Exe) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $problems.Add("missing: $path"); continue }
    $info = (Get-Item -LiteralPath $path).VersionInfo
    $fixed = '{0}.{1}.{2}.{3}' -f $info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart
    $product = if ($info.ProductVersion) { $info.ProductVersion.Trim() } else { '' }
    if ($product -ne $version) { $problems.Add("$path ProductVersion is '$product', not $version") }
    if ($fixed -ne "$numeric.0") { $problems.Add("$path FILEVERSION is $fixed, not $numeric.0") }
}

if ($Setup -ne '') {
    if (-not (Test-Path -LiteralPath $Setup -PathType Leaf)) {
        $problems.Add("missing: $Setup")
    } else {
        $product = [string](Get-Item -LiteralPath $Setup).VersionInfo.ProductVersion
        if ($product.Trim() -ne $version) { $problems.Add("$Setup ProductVersion is '$product', not $version") }
        if ((Split-Path -Leaf $Setup) -ne "Purge-Setup-$version.exe") { $problems.Add("$Setup is not named Purge-Setup-$version.exe") }
    }
}

if ($problems.Count -gt 0) {
    foreach ($p in $problems) { [Console]::Error.WriteLine("check-version: $p") }
    exit 1
}
$version
exit 0
