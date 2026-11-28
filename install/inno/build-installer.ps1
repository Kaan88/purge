# Builds Purge's Inno Setup installer: the three release exes, then target\installer\
# Purge-Setup-<version>.exe (install\README.md, "Inno installer"). Windows PowerShell 5.1, 64-bit. No
# elevation: nothing is installed here, the setup is only compiled.
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\inno\build-installer.ps1
#   ... -SkipBuild                  pack the exes that already exist (no cargo)
#   ... -InnoCompiler <ISCC.exe>    when Inno Setup is somewhere unusual
#
# The version comes from the workspace Cargo.toml ([workspace.package] version), the one version of
# Purge: check-version.ps1 reads it, checks Cargo.lock, and checks that purge-engine.exe,
# purge-broker.exe and Purge.exe carry it before ISCC runs and the setup after; purge.iss refuses a
# payload of another version too. Honours CARGO_TARGET_DIR (target\release otherwise).
#
# Purge.exe is the Rust UI (bins\purge-ui, bin name Purge): <cargo target>\release\Purge.exe, one file.
# The WinUI app (ui\Purge.App, dotnet publish) is no longer built or shipped.

[CmdletBinding()]
param(
    # Pack <cargo target>\release as it is; run no cargo.
    [switch]$SkipBuild,
    # ISCC.exe (Inno Setup 6). Default: %LOCALAPPDATA%\Programs, then Program Files (x86), then PATH.
    [string]$InnoCompiler = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Write-Step([string]$Message) { Write-Host "build-installer: $Message" }

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$target = Join-Path $repo 'target'
$outDir = Join-Path $target 'installer'
$cargoTarget = if ($env:CARGO_TARGET_DIR) { [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR) } else { $target }
$engineExe = Join-Path $cargoTarget 'release\purge-engine.exe'
$brokerExe = Join-Path $cargoTarget 'release\purge-broker.exe'
$uiExe = Join-Path $cargoTarget 'release\Purge.exe'
$checkVersion = Join-Path $PSScriptRoot 'check-version.ps1'
$kbDir = Join-Path $repo 'kb'
$installPs1 = Join-Path $repo 'install\install.ps1'
# The licence files installed next to Purge.exe: Purge's own, its NOTICE, and the crates' notices.
$licenseTxt = Join-Path $repo 'LICENSE'
$noticeTxt = Join-Path $repo 'NOTICE'
$noticesTxt = Join-Path $repo 'THIRD-PARTY-NOTICES.txt'
$iss = Join-Path $PSScriptRoot 'purge.iss'

if (-not (Test-Path -LiteralPath $iss -PathType Leaf)) { throw "the Inno script is missing: $iss" }

# The version: [workspace.package] of the root Cargo.toml, Cargo.lock checked against it.
$version = & $checkVersion
if ($LASTEXITCODE -ne 0 -or -not $version) { throw 'check-version.ps1 failed: Cargo.toml and Cargo.lock disagree, or the version is not X.Y.Z[-pre]' }
$version = [string]$version
# The four-number FILEVERSION (0.2.0-alpha.1 -> 0.2.0.1), for purge.iss's checks and VersionInfoVersion.
$fileVersion = [string](& $checkVersion -FileVersion)
if ($LASTEXITCODE -ne 0 -or -not $fileVersion) { throw 'check-version.ps1 -FileVersion failed' }

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

# The release build of install\README.md: three separate cargo builds (never one, never --workspace:
# a joint build would unify features), then the dependency check. No RUSTFLAGS (it would replace the
# crt-static flags of .cargo\config.toml).
if (-not $SkipBuild) {
    if ($env:RUSTFLAGS) { throw 'RUSTFLAGS is set; it replaces .cargo\config.toml (crt-static) and must be unset for a release build' }
    $env:CARGO_INCREMENTAL = '0'
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) { throw 'cargo was not found on PATH' }
    # cargo builds the workspace of the current folder: run it in this script's repository, never the caller's.
    Push-Location -LiteralPath $repo
    try {
        foreach ($cargoArgs in @(@('build', '--release', '--locked', '-p', 'purge-engine'), @('build', '--release', '--locked', '-p', 'purge-broker'), @('build', '--release', '--locked', '-p', 'purge-ui'), @('xtask', 'check-deps'))) {
            $line = 'cargo ' + ($cargoArgs -join ' ')
            Write-Step $line
            & $cargo.Source @cargoArgs
            if ($LASTEXITCODE -ne 0) { throw "$line failed with exit code $LASTEXITCODE" }
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Step "build skipped (-SkipBuild): $cargoTarget\release must already hold the three exes"
}

# THIRD-PARTY-NOTICES.txt, which the setup installs, matches Cargo.lock and the pinned toolchain
# (cargo xtask notices --check), with -SkipBuild too.
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) { throw 'cargo was not found on PATH (needed for cargo xtask notices --check)' }
Push-Location -LiteralPath $repo
try {
    Write-Step 'cargo xtask notices --check'
    & $cargo.Source xtask notices --check
    if ($LASTEXITCODE -ne 0) { throw "cargo xtask notices --check failed with exit code ${LASTEXITCODE}: run cargo xtask notices and commit THIRD-PARTY-NOTICES.txt" }
} finally {
    Pop-Location
}

foreach ($file in @($engineExe, $brokerExe, $uiExe, $installPs1, $licenseTxt, $noticeTxt, $noticesTxt)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "missing artifact: $file (run without -SkipBuild)" }
}
if (-not (Test-Path -LiteralPath $kbDir -PathType Container)) { throw "the kb folder is missing: $kbDir" }

# The staged broker is the release build, never one built with --features toolkit-consent (review
# S-A of BROKER-CONSENT-UI: a rig or preview build writes the same file name, and -SkipBuild packs what
# is there). install.ps1's check, dot-sourced in a child scope so that its parameters do not replace
# this script's.
& { param($Exe, $Script) . $Script; Assert-ReleaseBroker $Exe } $brokerExe $installPs1

# Every shipped exe carries the version (its VERSIONINFO: bins\versioninfo.rs).
& $checkVersion -Exe $engineExe, $brokerExe, $uiExe | Out-Null
if ($LASTEXITCODE -ne 0) { throw "an exe does not carry version $version (check-version.ps1 above)" }

$iscc = Resolve-Iscc $InnoCompiler
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Write-Step "ISCC ($iscc), version $version (FILEVERSION $fileVersion)"
& $iscc "/DAppVersion=$version" "/DAppFileVersion=$fileVersion" "/DRepoRoot=$repo" "/DEngineExe=$engineExe" "/DBrokerExe=$brokerExe" "/DUiExe=$uiExe" "/DKbDir=$kbDir" "/DInstallPs1=$installPs1" "/DLicenseTxt=$licenseTxt" "/DNoticeTxt=$noticeTxt" "/DNoticesTxt=$noticesTxt" "/DOutDir=$outDir" $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }

$setup = Join-Path $outDir "Purge-Setup-$version.exe"
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) { throw "ISCC reported success but $setup does not exist" }
& $checkVersion -Setup $setup | Out-Null
if ($LASTEXITCODE -ne 0) { throw "the setup does not carry version $version (check-version.ps1 above)" }
$size = (Get-Item -LiteralPath $setup).Length
Write-Step ('setup: {0} ({1:N1} MB)' -f $setup, ($size / 1MB))
$setup
