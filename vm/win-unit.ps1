<#
  win-unit, VM part (vm/RIG.md section 10). Called by vm/win-unit.sh after it has built the bundle and taken the
  per-VM lock; not meant to be run alone (it takes no lock). Uses the rig's VM helpers (rig.ps1, dot-sourced) and
  leaves the campaign path untouched.

  Restore -Snapshot, start headless, wait for the agent -> copy the bundle (bin.tgz, fixtures.tgz, manifest.json)
  and the runner to C:\cr\wu -> pass "p1-user": the runner as the rig user through guestcontrol (unelevated) ->
  optional pass "p2-elevated" through the elevated rig agent -> pull C:\cr\wu\out to -Out -> power off and
  restore -Snapshot again, so the VM is left at its snapshot.
#>
param(
    [Parameter(Mandatory)][string]$VmName,
    [string]$Snapshot = 'rig-base',
    [Parameter(Mandatory)][string]$Bundle,
    [Parameter(Mandatory)][string]$Out,
    [int]$Threads = 4,
    [string]$Filter = '',
    [switch]$Elevated,
    [string]$ElevatedArgs = '--include-ignored',
    [int]$TimeoutBin = 1800,
    # cold boot + autologon of the offline rig-base can stall for minutes on a loaded Linux host (RIG.md section 9)
    [int]$AgentTimeoutSec = 900,
    [string]$ExecutionEngine = $(if ($env:RIG_VM_EXECUTION_ENGINE) { $env:RIG_VM_EXECUTION_ENGINE } else { 'default' })
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'rig.ps1') -VmName $VmName

# Guest side (Windows PowerShell 5.1). One pass: unpack once, then every binary of the manifest with its mirrored
# package dir as working directory; libtest output -> out\<pass>\<name>.txt, exit codes -> out\<pass>\results.json.
$runner = @'
param([Parameter(Mandatory)][string]$Pass)
$ErrorActionPreference = 'Stop'
$root = 'C:\cr\wu'
$cfg = Get-Content -LiteralPath "$root\$Pass.json" -Raw | ConvertFrom-Json
$man = Get-Content -LiteralPath "$root\manifest.json" -Raw | ConvertFrom-Json
$od = "$root\out\$Pass"
New-Item -ItemType Directory -Force $od | Out-Null
if (-not (Test-Path "$root\unpacked")) {
    New-Item -ItemType Directory -Force "$root\bin" | Out-Null
    & tar.exe -xzf "$root\bin.tgz" -C "$root\bin"
    if ($LASTEXITCODE -ne 0) { throw "tar bin.tgz: $LASTEXITCODE" }
    & tar.exe -xzf "$root\fixtures.tgz" -C 'C:\'
    if ($LASTEXITCODE -ne 0) { throw "tar fixtures.tgz: $LASTEXITCODE" }
    Set-Content -LiteralPath "$root\unpacked" -Value (Get-Date -Format o)
}
$integ = ((& whoami.exe /groups) | Select-String 'Mandatory Label\\(\S+ \S+ Level)' | ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ','
$os = Get-CimInstance Win32_OperatingSystem
$env:RUST_BACKTRACE = '1'
$t0 = Get-Date
$rows = @()
$q = { param($a) if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a } }
foreach ($b in $man.binaries) {
    if (Test-Path "$root\yield") { break }
    $a = @("--test-threads=$($cfg.threads)") + @($cfg.args) + @($cfg.skip | ForEach-Object { '--skip'; $_ })
    $a = @($a | Where-Object { "$_" -ne '' } | ForEach-Object { & $q "$_" })
    $o = "$od\$($b.name).txt"; $e = "$od\$($b.name).err"
    $t = Get-Date
    try {
        $p = Start-Process -FilePath "$root\bin\$($b.exe)" -ArgumentList $a -WorkingDirectory $b.cwd -NoNewWindow -PassThru `
            -RedirectStandardOutput $o -RedirectStandardError $e
        $null = $p.Handle   # keeps the exit code readable
        $to = -not $p.WaitForExit($cfg.timeout_bin * 1000)
        if ($to) { & taskkill.exe /T /F /PID $p.Id | Out-Null; $p.WaitForExit(30000) | Out-Null }
        $code = $(if ($to) { $null } else { $p.ExitCode })
    } catch {
        Set-Content -LiteralPath $o -Value "win-unit runner: could not start $($b.exe): $_"
        $to = $false; $code = -1
    }
    if (Test-Path $e) { Add-Content -LiteralPath $o -Value ("`r`n----- stderr -----`r`n" + (Get-Content -LiteralPath $e -Raw)); Remove-Item $e }
    $rows += [ordered]@{ name = $b.name; ident = $b.ident; exit = $code; timed_out = $to; seconds = [int]((Get-Date) - $t).TotalSeconds }
}
$res = [ordered]@{ pass = $Pass; yielded = (Test-Path "$root\yield"); skipped = @($cfg.skip)
    env = [ordered]@{ os = "$($os.Caption) $($os.Version)"; user = "$env:USERDOMAIN\$env:USERNAME"; integrity = $integ
        args = (@("--test-threads=$($cfg.threads)") + @($cfg.args)) -join ' '; seconds = [int]((Get-Date) - $t0).TotalSeconds }
    binaries = $rows }
[IO.File]::WriteAllText("$od\results.json", (ConvertTo-Json -InputObject $res -Depth 5), (New-Object Text.UTF8Encoding($false)))
Set-Content -LiteralPath "$od\done" -Value 'done'
'win-unit pass {0}: {1} binaries in {2} s, integrity {3}' -f $Pass, $rows.Count, $res.env.seconds, $integ
'@

function Write-PassConfig([string]$Pass, [string[]]$TestArgs, [string[]]$Skip) {
    $f = Join-Path (Get-HostTemp) "$Pass.json"
    $cfg = [ordered]@{ threads = $Threads; timeout_bin = $TimeoutBin; args = @($TestArgs | Where-Object { $_ }); skip = @($Skip | Where-Object { $_ }) }
    [IO.File]::WriteAllText($f, (ConvertTo-Json -InputObject $cfg -Depth 4), (New-Object Text.UTF8Encoding($false)))
    $f
}

function Copy-ToGuest([string[]]$Files) {
    $r = Invoke-Guest (@('copyto', '--target-directory', 'C:\cr\wu\') + $Files)
    if ($r.code -ne 0) { throw "copyto failed: $($r.out -join ' ')" }
}

$man = Get-Content -LiteralPath (Join-Path $Bundle 'manifest.json') -Raw | ConvertFrom-Json
$runnerFile = Join-Path (Get-HostTemp) 'win-unit-runner.ps1'
[IO.File]::WriteAllText($runnerFile, $runner, (New-Object Text.UTF8Encoding($true)))
New-Item -ItemType Directory -Force $Out | Out-Null
$code = 0
$t0 = Get-Date
try {
    Restore-Base -Snapshot $Snapshot -ExecutionEngine $ExecutionEngine -AgentTimeoutSec $AgentTimeoutSec
    Write-RigLog "ready after $([int]((Get-Date) - $t0).TotalSeconds) s; pushing the bundle ($($man.binaries.Count) binaries)"
    $null = Invoke-GuestCmd 'rmdir /s /q C:\cr\wu & mkdir C:\cr\wu\out'
    $p1 = Write-PassConfig 'p1-user' @($Filter) @()
    $files = @((Join-Path $Bundle 'bin.tgz'), (Join-Path $Bundle 'fixtures.tgz'), (Join-Path $Bundle 'manifest.json'), $runnerFile, $p1)
    $tp = Get-Date
    Copy-ToGuest $files
    $null = Invoke-Guest @('mv', 'C:\cr\wu\win-unit-runner.ps1', 'C:\cr\wu\runner.ps1')
    Write-RigLog "pushed in $([int]((Get-Date) - $tp).TotalSeconds) s"
    # unpack through the elevated agent: the fixture mirror C:\mnt\... is created at the drive root, which the
    # unelevated user may not do; everything stays readable for the user
    $gr = $man.guest_root
    $unpack = @"
`$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force 'C:\cr\wu\bin', '$gr' | Out-Null
$(($man.binaries | ForEach-Object { "New-Item -ItemType Directory -Force '$($_.cwd)' | Out-Null" }) -join "`r`n")
& tar.exe -xzf 'C:\cr\wu\bin.tgz' -C 'C:\cr\wu\bin'; if (`$LASTEXITCODE) { throw "tar bin.tgz: `$LASTEXITCODE" }
& tar.exe -xzf 'C:\cr\wu\fixtures.tgz' -C 'C:\'; if (`$LASTEXITCODE) { throw "tar fixtures.tgz: `$LASTEXITCODE" }
& icacls.exe 'C:\cr\wu' /grant '*S-1-5-11:(OI)(CI)M' /T /Q | Out-Null
Set-Content -LiteralPath 'C:\cr\wu\unpacked' -Value (Get-Date -Format o)
'unpacked: ' + @(Get-ChildItem 'C:\cr\wu\bin' -Filter *.exe).Count + ' exe, ' + @(Get-ChildItem '$gr' -Recurse -File).Count + ' fixture files'
"@
    $j = Invoke-GuestJob -Text $unpack -Name 'win-unit-unpack' -TimeoutSec 900
    Write-RigLog "  unpack: done=$($j.done) $(($j.log -split "`r?`n" | Where-Object { $_ -match 'unpacked|tar|rror' }) -join ' ')"
    if (-not $j.done -or $j.log -notmatch 'unpacked: ') { throw 'unpacking the bundle in the guest failed' }

    # pass 1: the rig user through guestcontrol (a LogonUser token: UAC-filtered, medium integrity)
    $budget = [Math]::Max(600, $TimeoutBin * [Math]::Min(4, $man.binaries.Count))
    Write-RigLog "pass p1-user (unelevated, --test-threads=$Threads$(if ($Filter) { ", filter $Filter" }))"
    $tp = Get-Date
    $r = Invoke-Guest @('run', '--exe', 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '--timeout', [string]($budget * 1000),
        '--wait-stdout', '--wait-stderr', '--', 'powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\cr\wu\runner.ps1', '-Pass', 'p1-user')
    $r.out | Where-Object { $_ -and $_ -notmatch 'vboxdrv|vboxconfig|available for the current|You will not' } | ForEach-Object { Write-RigLog "  guest: $_" }
    Write-RigLog "pass p1-user: guestcontrol exit $($r.code), $([int]((Get-Date) - $tp).TotalSeconds) s"
    if ((Invoke-Guest @('stat', 'C:\cr\wu\out\p1-user\done')).code -ne 0) { Write-RigLog 'pass p1-user did not finish'; $code = 1 }

    if ($Elevated) {
        $skip = @($man.skip_needs_runs_dir)
        $p2 = Write-PassConfig 'p2-elevated' @($ElevatedArgs -split '\s+') $(if ($ElevatedArgs -match 'include-ignored') { $skip } else { @() })
        Copy-ToGuest @($p2)
        Write-RigLog "pass p2-elevated (rig agent, $ElevatedArgs)"
        $j = Invoke-GuestJob -Text "& 'C:\cr\wu\runner.ps1' -Pass 'p2-elevated'" -Name 'win-unit-p2' -TimeoutSec $budget
        Write-RigLog "pass p2-elevated: done=$($j.done), $($j.seconds) s"
        if (-not $j.done) { $code = 1 }
    }

    # pull C:\cr\wu\out (one archive: copyfrom wants a file per call)
    $null = Invoke-GuestCmd 'tar.exe -czf C:\cr\wu\out.tgz -C C:\cr\wu\out .' 600
    $tgz = Join-Path $Out 'out.tgz'
    $r = Invoke-Guest @('copyfrom', 'C:\cr\wu\out.tgz', $tgz)
    if ($r.code -ne 0 -or -not (Test-Path -LiteralPath $tgz)) { throw "copyfrom out.tgz failed: $($r.out -join ' ')" }
    & tar -xzf $tgz -C $Out
    if ($LASTEXITCODE -ne 0) { throw 'host tar -x failed' }
    Remove-Item -LiteralPath $tgz
    Write-RigLog "results pulled to $Out"
} catch {
    Write-RigLog "ERROR: $_"
    $code = 2
} finally {
    # leave the VM at its snapshot: power off, restore
    try {
        $null = Invoke-VBox @('controlvm', $script:VmName, 'poweroff')
        $null = Wait-VmState @('poweroff', 'aborted') 120
        $ok = $false
        for ($i = 1; $i -le 6 -and -not $ok; $i++) {
            $ok = ((Invoke-VBox @('snapshot', $script:VmName, 'restore', $Snapshot)).code -eq 0)
            if (-not $ok) { Start-Sleep -Seconds 3 }
        }
        Write-RigLog "VM powered off and restored to $Snapshot (state $(Get-VmState)); VM part $([int]((Get-Date) - $t0).TotalSeconds) s"
    } catch { Write-RigLog "cleanup: $_"; if ($code -eq 0) { $code = 2 } }
    Remove-PwTemp
    Remove-Item -LiteralPath $runnerFile -Force -ErrorAction SilentlyContinue
}
exit $code
