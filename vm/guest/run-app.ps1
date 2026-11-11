# Purge rig v2: one app run (vm\RIG.md §4). Template: the host replaces __ID__ with the app id and
# submits the result as an agent job (elevated, interactive user). Outputs in C:\cr\out\<id>\:
#   run.log, run.json, lists-<id>-0|1|2.json, snap-<id>-0|1|2.tsv.gz, msi-*.log (MSI apps)
# Every phase is wrapped: a failure is recorded in run.json and the remaining captures still run.
$Id = '__ID__'
# Checked before anything is loaded or created. Case-sensitive, and the placeholder is built by
# concatenation so the host's .Replace('__ID__', ...) cannot rewrite it.
if ($Id -cnotmatch '^[a-z0-9][a-z0-9_-]*$' -or $Id -eq ('__' + 'ID__')) {
    Write-Host ("run-app.ps1: the id placeholder was not replaced with an app id ('{0}')" -f $Id); exit 2
}
. C:\cr\guest\riglib.ps1
. C:\cr\guest\apps.ps1

$InstallMaxSec = 15 * 60; $InstallSettleSec = 20
$LaunchRunSec = 25; $LaunchGraceSec = 5; $LaunchSettleSec = 10
$UninstallMaxSec = 30 * 60; $UninstallSettleSec = 30; $UninstallIdleGiveUpSec = 180

$Run = $Id
$Dir = New-RunDir $Run
Set-RunLog (Join-Path $Dir 'run.log')
Log "run-app $Id on $env:COMPUTERNAME as $env:USERDOMAIN\$env:USERNAME (sid $RigUserSid), 64-bit=$([Environment]::Is64BitProcess)"

$S = [ordered]@{
    schema = 'purge.rig.run/1'; id = $Id; run = $Run; kind = 'app'; tech = $null; url = $null; installer = $null
    installer_sha256 = $null; installer_sig = $null; computer = $env:COMPUTERNAME; sid = $RigUserSid; user_sid = $RigUserSid
    os = $null; started = (NowIso); finished = $null
    main = $null
    install = [ordered]@{ cmd = $null; start = $null; end = $null; exit = $null; timed_out = $false; killed = @() }
    launch = [ordered]@{ done = $false; exe = $null; args = $null; start = $null; end = $null; found = $false; closed = @(); killed = @(); reason = $null }
    uninstall = [ordered]@{ cmd = $null; t0 = $null; t1 = $null; exit = $null; timed_out = $false; entry_gone = $null; killed = @() }
    entries_created = @(); entries_left = @()
    phases = New-Object System.Collections.ArrayList
}
$e = @{ e0 = $null; e1 = $null; e2 = $null; app = $null }
$RunJson = Join-Path $Dir 'run.json'
function Save-Run { $S.finished = NowIso; try { Write-JsonFile $S $RunJson } catch { Log "!! cannot write run.json: $($_.Exception.Message)" } }

function Get-OsString {
    $cv = Open-RegKey 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    try { '{0} {1}.{2}' -f $cv.GetValue('EditionID'), $cv.GetValue('CurrentBuildNumber'), $cv.GetValue('UBR') } finally { $cv.Dispose() }
}

function Compare-Entries($Before, $After) {
    $old = @{}
    foreach ($x in @($Before)) { if ($x) { $old[$x.key] = $true } }
    @(@($After) | Where-Object { $_ -and -not $old.ContainsKey($_.key) })
}

Phase 'setup' {
    $S.os = Get-OsString
    $a = Get-App $Id
    $e.app = $a
    $S.tech = $a.tech
    $file = Join-Path $RigInst $a.file
    $src = Join-Path $RigInst 'sources.json'
    if (Test-Path -LiteralPath $src) {
        $j = Get-Content -LiteralPath $src -Raw | ConvertFrom-Json
        if ($j.$Id) { $S.url = $j.$Id.url }
    }
    if (-not (Test-InstallerFile $file)) {
        Log "installer $file missing or invalid; downloading"
        $rec = Fetch (& $a.url) $a.file
        $S.url = $rec.url
    }
    $info = Get-FileInfoRecord $file $S.url
    $S.installer = $file; $S.installer_sha256 = $info.sha256; $S.installer_sig = "$($info.sig) $($info.signer)".Trim()
    Log "installer $file sha256=$($info.sha256) sig=$($S.installer_sig)"
} $S
Save-Run

Phase 'arp0' { $e.e0 = @(UninstallEntries); Log "ARP entries before: $($e.e0.Count)" } $S
Phase 'lists0' { Lists $Run 0 } $S
Phase 'snap0' { Snap $Run 0 } $S
Save-Run

# ----------------------------------------------------------------------------------------------- install
Phase 'install' {
    $a = $e.app
    if (-not $a) { throw 'no app definition (setup failed)' }
    if ($a.install -eq 'msi') {
        $exe = Join-Path $env:SystemRoot 'System32\msiexec.exe'
        $args_ = '/i "' + $S.installer + '" /qn /norestart /L*v "' + (Join-Path $Dir 'msi-install.log') + '"'
    } else {
        $exe = $S.installer; $args_ = $a.install
    }
    $S.install.cmd = "`"$exe`" $args_"
    Log "install: $($S.install.cmd)"
    $t = Get-Date
    $S.install.start = $t.ToString('o')
    $p = Start-Native $exe $args_
    $exited = $p.WaitForExit($InstallMaxSec * 1000)
    if ($exited) { $S.install.exit = $p.ExitCode }
    Log "installer process exited=$exited exit=$($S.install.exit) after $([int]((Get-Date) - $t).TotalSeconds) s; waiting for its process tree"
    $left = [Math]::Max(60, $InstallMaxSec - [int]((Get-Date) - $t).TotalSeconds)
    $w = WaitTree -Since $t -TimeoutSec $left -RootPid @($p.Id)
    $S.install.end = $w.end.ToString('o')
    $S.install.timed_out = ((-not $exited) -or $w.timed_out)
    if ($S.install.timed_out) {
        $still = @(Get-TreeProcs -Procs (Get-ProcList) -Known $w.known)
        $S.install.killed = @($still | ForEach-Object { "$($_.name)[$($_.pid)]" })
        Stop-Procs $still 'install timeout'
    }
    Log "install done: exit=$($S.install.exit) timed_out=$($S.install.timed_out); settle $InstallSettleSec s"
    Start-Sleep -Seconds $InstallSettleSec
} $S
Save-Run

Phase 'detect' {
    $e.e1 = @(UninstallEntries)
    $created = @(Compare-Entries $e.e0 $e.e1)
    $S.entries_created = $created
    Log "new ARP entries: $(@($created).Count)"
    foreach ($x in $created) { Log ("  [{0}] {1} {2} sys={3} msi={4}" -f $x.key, $x.name, $x.version, $x.sys, $x.msi) }
    $m = Find-MainEntry $e.app $e.e0 $e.e1
    if (-not $m) { throw "no ARP entry matches '$($e.app.match)'" }
    $S.main = $m
    Log "main entry: $($m.key) | $($m.name) $($m.version) | msi=$($m.msi)"
} $S
Save-Run

# ------------------------------------------------------------------------------------------------ launch
Phase 'launch' {
    $a = $e.app
    if (-not $a.launch) { $S.launch.reason = 'app defines no launch'; Log 'no launch for this app'; return }
    if (-not $S.main) { $S.launch.reason = 'no main entry'; throw 'no main entry, cannot resolve the launch exe' }
    $exe = Resolve-LaunchExe $a $S.main
    if (-not $exe) { $S.launch.reason = "exe '$($a.launch.exe)' not found"; throw $S.launch.reason }
    $S.launch.exe = $exe; $S.launch.args = $a.launch.args
    # If LaunchMedium throws, the finally still closes whatever started since $t and deletes the task.
    $t = Get-Date
    $L = [pscustomobject]@{ task = 'PurgeRigLaunch'; start = $t; found = $false }
    try {
        $L = LaunchMedium -Exe $exe -Arguments $a.launch.args -TaskName $L.task
        $S.launch.start = $L.start.ToString('o'); $S.launch.found = $L.found
        Log "running for $LaunchRunSec s"
        Start-Sleep -Seconds $LaunchRunSec
    } finally {
        $r = Stop-Launch $L -GraceSec $LaunchGraceSec
        $S.launch.closed = @($r.closed); $S.launch.killed = @($r.killed)
        $S.launch.end = NowIso
    }
    $S.launch.done = $true
    Log "settle $LaunchSettleSec s"
    Start-Sleep -Seconds $LaunchSettleSec
} $S
Save-Run

Phase 'lists1' { Lists $Run 1 } $S
Phase 'snap1' { Snap $Run 1 } $S
Save-Run

# --------------------------------------------------------------------------------------------- uninstall
Phase 'uninstall' {
    if (-not $S.main) { throw 'no main entry, nothing to uninstall' }
    $main = $S.main
    $c = Build-UninstallCommand $e.app $main (Join-Path $Dir 'msi-uninstall.log')
    $S.uninstall.cmd = $c.display
    Log "uninstall: exe=[$($c.exe)] args=[$($c.args)]"
    $t0 = Get-Date
    $S.uninstall.t0 = $t0.ToString('o')
    $p = Start-Native $c.exe $c.args
    $exited = $p.WaitForExit($UninstallMaxSec * 1000)
    if ($exited) { $S.uninstall.exit = $p.ExitCode }
    Log "uninstaller process exited=$exited exit=$($S.uninstall.exit) after $([int]((Get-Date) - $t0).TotalSeconds) s; waiting for ARP entry removal and process tree"
    # NSIS copies its uninstaller to %TEMP% (Au_.exe) and relaunches it, Burn and MSI spawn children: the
    # end is "main entry gone and no process started after t0 still running".
    $key = $main.key
    $left = [Math]::Max(60, $UninstallMaxSec - [int]((Get-Date) - $t0).TotalSeconds)
    $w = WaitTree -Since $t0 -TimeoutSec $left -Until { -not (Test-RegKey $key) } -IdleGiveUpSec $UninstallIdleGiveUpSec -RootPid @($p.Id)
    $S.uninstall.t1 = $w.end.ToString('o')
    $S.uninstall.timed_out = ((-not $exited) -or $w.timed_out)
    $S.uninstall.entry_gone = (-not (Test-RegKey $key))
    if ($S.uninstall.timed_out) {
        $still = @(Get-TreeProcs -Procs (Get-ProcList) -Known $w.known)
        $S.uninstall.killed = @($still | ForEach-Object { "$($_.name)[$($_.pid)]" })
        Stop-Procs $still 'uninstall timeout'
    }
    Log "uninstall done: exit=$($S.uninstall.exit) entry_gone=$($S.uninstall.entry_gone) timed_out=$($S.uninstall.timed_out) in $([int]($w.end - $t0).TotalSeconds) s; settle $UninstallSettleSec s"
    Start-Sleep -Seconds $UninstallSettleSec
} $S
Save-Run

Phase 'lists2' { Lists $Run 2 } $S
Phase 'snap2' { Snap $Run 2 } $S

Phase 'entries' {
    $e.e2 = @(UninstallEntries)
    $now = @{}
    foreach ($x in $e.e2) { $now[$x.key] = $true }
    $S.entries_left = @(@($S.entries_created) | Where-Object { $now.ContainsKey($_.key) })
    foreach ($x in $S.entries_left) { Log "  entry left: [$($x.key)] $($x.name)" }
} $S

Save-Run
$failed = @($S.phases | Where-Object { -not $_.ok } | ForEach-Object { $_.name })
Log ("run-app $Id finished; failed phases: {0}" -f $(if ($failed.Count) { $failed -join ', ' } else { 'none' }))
if ($failed.Count) { exit 1 }
exit 0
