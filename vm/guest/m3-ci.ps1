# Guest side of the rig mode m3-elevated-ci (vm\rig-m3-ci.ps1, vm\RIG.md section 18; docs\M3_DESIGN.md 12 G1). Run by the
# elevated rig agent, one agent job per phase, Windows PowerShell 5.1. Reads <Root>\manifest.json, written by the host.
#
#   unpack      the repository's tracked files (repo.tgz) at the host's absolute path of the checkout, the portable .NET
#               SDK (dotnet.tgz) to <Root>\dotnet, the UI test output (ui.tgz) at its host path, the cargo stand-in to
#               <Root>\fakecargo; records the token (admin, integrity), the OS and the guest's own .NET installs
#   step -Step  one cargo step of `xtask ci`: its archive (test executables and the binaries the tests start, at their host
#               paths, so env!("CARGO_BIN_EXE_*") and env!("CARGO_MANIFEST_DIR") resolve), then every test executable of
#               the step as `cargo test` runs it (working directory = the package directory), one at a time, with a
#               timeout; libtest output -> <Root>\out\<step>\<n>.txt, exit codes and SHA-256 -> <Root>\out\<step>\results.json
#   ui          `dotnet test` of the UI tests' built assembly with the portable SDK; TRX -> <Root>\out\ui\ui.trx
#   pack        <Root>\out -> <Root>\out.tgz
# Every phase prints one line "M3CI <phase> ..." with its result. The host parses the outputs (rig-m3-ci.ps1).
# -Root and -NoUnpack exist for the host dry run (rig-m3-ci.ps1 -HostRun), which runs this same script on the host.
param(
    [Parameter(Mandatory)][ValidateSet('unpack', 'step', 'ui', 'pack')][string]$Phase,
    [string]$Step = '',
    [string]$Root = 'C:\cr\m3ci',
    [switch]$NoUnpack
)
$ErrorActionPreference = 'Stop'
$man = Get-Content -LiteralPath (Join-Path $Root 'manifest.json') -Raw | ConvertFrom-Json
$out = Join-Path $Root 'out'
New-Item -ItemType Directory -Force $out | Out-Null

function Write-JsonUtf8($Object, [string]$Path) {
    [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Object -Depth 8), (New-Object Text.UTF8Encoding($false)))
}

# Extracts <Root>\<archive> into $Dir (created first). bsdtar (System32\tar.exe) keeps the archive's mtimes.
function Expand-M3CiArchive([string]$Archive, [string]$Dir) {
    $a = Join-Path $Root $Archive
    if (-not (Test-Path -LiteralPath $a -PathType Leaf)) { throw "archive missing: $a" }
    New-Item -ItemType Directory -Force $Dir | Out-Null
    & tar.exe -xzf $a -C $Dir
    if ($LASTEXITCODE -ne 0) { throw "tar -x $Archive -> $Dir exited $LASTEXITCODE" }
}

function Get-M3CiToken {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $integ = ((& whoami.exe /groups) | Select-String 'Mandatory Label\\(\S+ \S+ Level)' | ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ','
    [ordered]@{ user = $id.Name; admin = $admin; integrity = $integ }
}

# Runs $Exe with $Arguments in $Cwd, stdout and stderr to files, at most $TimeoutSec; the process tree is ended on timeout.
function Invoke-M3CiProcess([string]$Exe, [string[]]$Arguments, [string]$Cwd, [string]$OutFile, [int]$TimeoutSec) {
    $err = "$OutFile.err"
    $q = { param($a) if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a } }
    $sp = @{ FilePath = $Exe; WorkingDirectory = $Cwd; NoNewWindow = $true; PassThru = $true; RedirectStandardOutput = $OutFile; RedirectStandardError = $err }
    $al = @($Arguments | Where-Object { "$_" -ne '' } | ForEach-Object { & $q "$_" })
    if ($al.Count) { $sp.ArgumentList = $al }
    $t = Get-Date
    $code = $null; $to = $false; $startError = $null
    try {
        $p = Start-Process @sp
        $null = $p.Handle   # keeps the exit code readable after exit
        $to = -not $p.WaitForExit($TimeoutSec * 1000)
        if ($to) { & taskkill.exe /T /F /PID $p.Id 2>&1 | Out-Null; $null = $p.WaitForExit(30000) } else { $code = $p.ExitCode }
    } catch { $startError = "$($_.Exception.Message)"; $code = -1 }
    if (Test-Path -LiteralPath $err) {
        $e = [IO.File]::ReadAllText($err)
        if ($e) { [IO.File]::AppendAllText($OutFile, "`r`n----- stderr -----`r`n$e") }
        Remove-Item -LiteralPath $err -Force
    }
    if ($startError) { [IO.File]::AppendAllText($OutFile, "`r`nm3-ci runner: could not start ${Exe}: $startError`r`n") }
    [ordered]@{ exit = $code; timed_out = $to; seconds = [int]((Get-Date) - $t).TotalSeconds; start_error = $startError }
}

switch ($Phase) {
    'unpack' {
        $tok = Get-M3CiToken
        $os = Get-CimInstance Win32_OperatingSystem
        $free0 = (Get-PSDrive -Name C).Free
        if (-not $NoUnpack) {
            Expand-M3CiArchive $man.repo.archive $man.repo.dir
            Expand-M3CiArchive $man.ui.archive $man.ui.dir
        }
        Expand-M3CiArchive $man.dotnet.archive (Join-Path $Root 'dotnet')
        New-Item -ItemType Directory -Force (Join-Path $Root 'fakecargo') | Out-Null
        Copy-Item -LiteralPath (Join-Path $Root $man.fakecargo) -Destination (Join-Path $Root 'fakecargo\cargo.exe') -Force
        foreach ($d in @($man.make_dirs)) { New-Item -ItemType Directory -Force $d | Out-Null }
        $guestDotnet = @()
        foreach ($k in 'sdk', 'shared\Microsoft.NETCore.App') {
            $p = Join-Path $env:ProgramFiles "dotnet\$k"
            if (Test-Path -LiteralPath $p) { $guestDotnet += @(Get-ChildItem -LiteralPath $p -Directory | ForEach-Object { "$k\$($_.Name)" }) }
        }
        $info = [ordered]@{ token = $tok; os = "$($os.Caption) $($os.Version)"; computer = $env:COMPUTERNAME
                            free_c_before = $free0; free_c_after = (Get-PSDrive -Name C).Free; guest_dotnet = $guestDotnet; t = (Get-Date).ToString('o') }
        Write-JsonUtf8 $info (Join-Path $out 'unpack.json')
        "M3CI unpack ok admin=$($tok.admin) integrity=$($tok.integrity) free_c_after=$($info.free_c_after)"
    }
    'step' {
        $s = @($man.steps | Where-Object { $_.id -ceq $Step })
        if ($s.Count -ne 1) { throw "no step '$Step' in the manifest" }
        $s = $s[0]
        $tok = Get-M3CiToken
        # The step's executables at their host paths. Steps run in xtask ci's order; a later step's archive replaces the
        # binaries an earlier one put there (purge-engine.exe with and without rig-exec), as the host's cargo did.
        Expand-M3CiArchive $s.archive $man.target_dir
        $od = Join-Path $out $s.id
        New-Item -ItemType Directory -Force $od | Out-Null
        $rows = @()
        foreach ($b in @($s.binaries)) {
            $exe = $b.exe
            $row = [ordered]@{ n = $b.n; exe = $exe; sha256 = $null; exit = $null; timed_out = $false; seconds = 0; start_error = $null }
            if (Test-Path -LiteralPath $exe -PathType Leaf) { $row.sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() }
            $a = @()
            if ($man.threads -gt 0) { $a += "--test-threads=$($man.threads)" }
            foreach ($k in @($b.skip)) { if ($k) { $a += @('--skip', $k) } }
            if (@($b.skip | Where-Object { $_ }).Count) { $a += '--exact' }
            # What cargo sets for a test run (the rest of the environment is the agent's).
            $env:CARGO_MANIFEST_DIR = $b.cwd
            $env:CARGO_PKG_NAME = $b.package
            $env:CARGO_PKG_VERSION = $b.version
            $r = Invoke-M3CiProcess $exe $a $b.cwd (Join-Path $od "$($b.n).txt") $man.timeout_bin
            foreach ($k in $r.Keys) { $row[$k] = $r[$k] }
            $rows += $row
            "M3CI bin $($s.id) $($b.n) exit=$($row.exit) timed_out=$($row.timed_out) $($row.seconds)s $($b.label)"
        }
        Write-JsonUtf8 ([ordered]@{ step = $s.id; token = $tok; binaries = $rows; t = (Get-Date).ToString('o') }) (Join-Path $od 'results.json')
        "M3CI step $($s.id) done binaries=$($rows.Count) admin=$($tok.admin)"
    }
    'ui' {
        $tok = Get-M3CiToken
        # The pipe_harness example the UI tests start, built on the host by the same cargo command the tests run.
        Expand-M3CiArchive $man.ui.harness_archive $man.target_dir
        $od = Join-Path $out 'ui'
        New-Item -ItemType Directory -Force $od | Out-Null
        $dn = Join-Path $Root 'dotnet'
        $env:DOTNET_ROOT = $dn
        $env:DOTNET_MULTILEVEL_LOOKUP = '0'
        $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
        $env:DOTNET_NOLOGO = '1'
        $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
        $env:DOTNET_CLI_HOME = Join-Path $Root 'dotnet-home'
        $env:CARGO_TARGET_DIR = $man.target_dir
        # The stand-in answers exactly `cargo build -q -p purge-broker --example pipe_harness` (the harness is in place).
        $env:PATH = (Join-Path $Root 'fakecargo') + ';' + $dn + ';' + $env:PATH
        $a = @('test', $man.ui.dll, '--logger', 'trx;LogFileName=ui.trx', '--results-directory', $od)
        if ($man.ui.filter) { $a += @('--filter', $man.ui.filter) }
        $r = Invoke-M3CiProcess (Join-Path $dn 'dotnet.exe') $a $man.ui.dir (Join-Path $od 'dotnet-test.txt') $man.timeout_ui
        $dll = $man.ui.dll
        $res = [ordered]@{ token = $tok; dll = $dll; dll_sha256 = $(if (Test-Path -LiteralPath $dll) { (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant() })
                           trx = (Test-Path -LiteralPath (Join-Path $od 'ui.trx')); t = (Get-Date).ToString('o') }
        foreach ($k in $r.Keys) { $res[$k] = $r[$k] }
        Write-JsonUtf8 $res (Join-Path $od 'results.json')
        "M3CI ui exit=$($res.exit) timed_out=$($res.timed_out) trx=$($res.trx) $($res.seconds)s"
    }
    'pack' {
        $z = Join-Path $Root 'out.tgz'
        Remove-Item -LiteralPath $z -Force -ErrorAction SilentlyContinue
        & tar.exe -czf $z -C $out .
        if ($LASTEXITCODE -ne 0) { throw "tar -c out exited $LASTEXITCODE" }
        "M3CI pack ok bytes=$((Get-Item -LiteralPath $z).Length)"
    }
}
