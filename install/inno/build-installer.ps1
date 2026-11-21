# Builds Purge's Inno Setup installer: the three release artifacts, then target\installer\
# Purge-Setup-<version>.exe (install\README.md, "Inno installer"). Windows PowerShell 5.1, 64-bit. No
# elevation: nothing is installed here, the setup is only compiled.
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\inno\build-installer.ps1
#   ... -SkipBuild                  pack the artifacts that already exist (no cargo, no dotnet)
#   ... -InnoCompiler <ISCC.exe>    when Inno Setup is somewhere unusual
#
# The version comes from the workspace Cargo.toml ([workspace.package] version).

[CmdletBinding()]
param(
    # Pack target\release and target\ui-publish as they are; run neither cargo nor dotnet.
    [switch]$SkipBuild,
    # ISCC.exe (Inno Setup 6). Default: %LOCALAPPDATA%\Programs, then Program Files (x86), then PATH.
    [string]$InnoCompiler = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Write-Step([string]$Message) { Write-Host "build-installer: $Message" }

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$target = Join-Path $repo 'target'
$uiPublish = Join-Path $target 'ui-publish'
$outDir = Join-Path $target 'installer'
$engineExe = Join-Path $target 'release\purge-engine.exe'
$brokerExe = Join-Path $target 'release\purge-broker.exe'
$kbDir = Join-Path $repo 'kb'
$installPs1 = Join-Path $repo 'install\install.ps1'
$iss = Join-Path $PSScriptRoot 'purge.iss'

if (-not (Test-Path -LiteralPath $iss -PathType Leaf)) { throw "the Inno script is missing: $iss" }

# The version: [workspace.package] of the root Cargo.toml (0.1.0 today; Inno takes up to four numeric
# parts).
$cargoToml = Get-Content -LiteralPath (Join-Path $repo 'Cargo.toml') -Raw
$section = [regex]::Match($cargoToml, '(?ms)^\[workspace\.package\](.*?)(?=^\[|\z)')
if (-not $section.Success) { throw 'Cargo.toml has no [workspace.package] section' }
$found = [regex]::Match($section.Groups[1].Value, '(?m)^\s*version\s*=\s*"([^"]+)"')
if (-not $found.Success) { throw 'Cargo.toml [workspace.package] has no version' }
$version = $found.Groups[1].Value
if ($version -notmatch '^\d+(\.\d+){1,3}$') { throw "Cargo.toml version '$version' is not a numeric version Inno Setup accepts" }

function Resolve-Iscc([string]$Given) {
    if ($Given) {
        $p = if (Test-Path -LiteralPath $Given -PathType Leaf) { (Resolve-Path -LiteralPath $Given).ProviderPath } else { '' }
        if (-not $p) { throw "ISCC.exe not found: $Given" }
        return $p
    }
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
    )
    foreach ($c in $candidates) { if (Test-Path -LiteralPath $c -PathType Leaf) { return $c } }
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw 'ISCC.exe (Inno Setup 6) was not found. Install it: winget install --id JRSoftware.InnoSetup -e, or pass -InnoCompiler <path>'
}

# The release build of install\README.md: two separate cargo builds (never one, never --workspace),
# the dependency check, then the Native AOT publish of the UI. No RUSTFLAGS (it would replace the
# crt-static flags of .cargo\config.toml).
if (-not $SkipBuild) {
    if ($env:RUSTFLAGS) { throw 'RUSTFLAGS is set; it replaces .cargo\config.toml (crt-static) and must be unset for a release build' }
    $env:CARGO_INCREMENTAL = '0'
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) { throw 'cargo was not found on PATH' }
    foreach ($cargoArgs in @(@('build', '--release', '-p', 'purge-engine'), @('build', '--release', '-p', 'purge-broker'), @('xtask', 'check-deps'))) {
        $line = 'cargo ' + ($cargoArgs -join ' ')
        Write-Step $line
        & $cargo.Source @cargoArgs
        if ($LASTEXITCODE -ne 0) { throw "$line failed with exit code $LASTEXITCODE" }
    }
    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    $dotnetPath = if ($dotnet) { $dotnet.Source } else { Join-Path $env:ProgramFiles 'dotnet\dotnet.exe' }
    if (-not (Test-Path -LiteralPath $dotnetPath -PathType Leaf)) { throw 'the .NET SDK was not found (PATH, or C:\Program Files\dotnet\dotnet.exe)' }
    Write-Step "dotnet publish ui\Purge.App -c Release -r win-x64 -o $uiPublish"
    & $dotnetPath publish (Join-Path $repo 'ui\Purge.App') -c Release -r win-x64 -o $uiPublish
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }
} else {
    Write-Step 'build skipped (-SkipBuild): target\release and target\ui-publish must already exist'
}

foreach ($file in @($engineExe, $brokerExe, (Join-Path $uiPublish 'Purge.exe'), $installPs1)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "missing artifact: $file (run without -SkipBuild)" }
}
if (-not (Test-Path -LiteralPath $kbDir -PathType Container)) { throw "the kb folder is missing: $kbDir" }

$iscc = Resolve-Iscc $InnoCompiler
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Write-Step "ISCC ($iscc), version $version"
& $iscc "/DAppVersion=$version" "/DRepoRoot=$repo" "/DEngineExe=$engineExe" "/DBrokerExe=$brokerExe" "/DUiPublishDir=$uiPublish" "/DKbDir=$kbDir" "/DInstallPs1=$installPs1" "/DOutDir=$outDir" $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }

$setup = Join-Path $outDir "Purge-Setup-$version.exe"
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) { throw "ISCC reported success but $setup does not exist" }
$size = (Get-Item -LiteralPath $setup).Length
Write-Step ('setup: {0} ({1:N1} MB)' -f $setup, ($size / 1MB))
$setup
