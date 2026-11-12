# Purge rig v2: one app run (vm\RIG.md §4, engine mode §4a). Template: the host (rig.ps1 New-RunJobText)
# replaces __ID__ with the app id, __RUN__ with the run name (the id, or a prefixed name such as r0-<id>)
# and __ENGINE__ with 1 (engine mode) or 0, and submits the result as an agent job (elevated, interactive
# user). Outputs in C:\cr\out\<run>\:
#   run.log, run.json, lists-<run>-0|1|2.json, snap-<run>-0|1|2.tsv.gz, msi-*.log (MSI apps)
#   engine mode also: inv-1.json, fp.json, engine-run.json, plan-purge.json (+ its sidecar), inv-2.json
# Every phase is wrapped: a failure is recorded in run.json and the remaining captures still run.
$Id = '__ID__'
$Run = '__RUN__'
$EngineFlag = '__ENGINE__'
# Checked before anything is loaded or created. Case-sensitive, and the placeholders are built by
# concatenation so the host's .Replace('__ID__', ...) cannot rewrite them.
if ($Id -cnotmatch '^[a-z0-9][a-z0-9_-]*$' -or $Id -eq ('__' + 'ID__')) {
    Write-Host ("run-app.ps1: the id placeholder was not replaced with an app id ('{0}')" -f $Id); exit 2
}
if ($Run -eq ('__' + 'RUN__')) { $Run = $Id }
if ($Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') {
    Write-Host ("run-app.ps1: bad run name '{0}'" -f $Run); exit 2
}
# An unreplaced placeholder means the vendor uninstall path of M0 (no engine).
$Engine = ($EngineFlag -eq '1')
. C:\cr\guest\riglib.ps1
. C:\cr\guest\apps.ps1

$InstallMaxSec = 15 * 60; $InstallSettleSec = 20
$LaunchRunSec = 25; $LaunchGraceSec = 5; $LaunchSettleSec = 10
$UninstallMaxSec = 30 * 60; $UninstallSettleSec = 30; $UninstallIdleGiveUpSec = 180
$EngineMaxSec = 20 * 60

$Dir = New-RunDir $Run
Set-RunLog (Join-Path $Dir 'run.log')
Log "run-app $Id (run $Run, engine=$Engine) on $env:COMPUTERNAME as $env:USERDOMAIN\$env:USERNAME (sid $RigUserSid), 64-bit=$([Environment]::Is64BitProcess)"

$S = [ordered]@{
    schema = 'purge.rig.run/1'; id = $Id; run = $Run; kind = 'app'; tech = $null; url = $null; installer = $null
    installer_sha256 = $null; installer_sig = $null; computer = $env:COMPUTERNAME; sid = $RigUserSid; user_sid = $RigUserSid
    os = $null; started = (NowIso); finished = $null
    main = $null
    install = [ordered]@{ cmd = $null; start = $null; end = $null; exit = $null; timed_out = $false; killed = @(); ran_as = $null }
    launch = [ordered]@{ done = $false; exe = $null; args = $null; start = $null; end = $null; found = $false; closed = @(); killed = @(); reason = $null }
    uninstall = [ordered]@{ cmd = $null; t0 = $null; t1 = $null; exit = $null; timed_out = $false; entry_gone = $null; killed = @() }
    entries_created = @(); entries_left = @()
    phases = New-Object System.Collections.ArrayList
}
$e = @{ e0 = $null; e1 = $null; e2 = $null; app = $null }
$RunJson = Join-Path $Dir 'run.json'
function Save-Run { $S.finished = NowIso; try { Write-JsonFile $S $RunJson } catch { Log "!! cannot write run.json: $($_.Exception.Message)" } }

# Pre-apps (apps.ps1 'pre'): read here so a failed setup phase still leaves them visible in run.json.
$PreIds = @()
try { $PreIds = @(@((Get-App $Id).pre) | Where-Object { $_ }) } catch { }
if ($PreIds.Count) { $S.pre = New-Object System.Collections.ArrayList }

# Engine mode: files in the run directory and the run.json record of every engine call.
$Inv1 = Join-Path $Dir 'inv-1.json'
$FpFile = Join-Path $Dir 'fp.json'
$EngineRun = Join-Path $Dir 'engine-run.json'
$PlanFile = Join-Path $Dir 'plan-purge.json'
$Inv2 = Join-Path $Dir 'inv-2.json'
if ($Engine) {
    $S.engine = [ordered]@{
        exe = $RigEngine; app = $Id; program_id = $null; run = $null
        files = [ordered]@{ inv1 = 'inv-1.json'; fp = 'fp.json'; run = 'engine-run.json'; plan = 'plan-purge.json'; inv2 = 'inv-2.json' }
        calls = New-Object System.Collections.ArrayList
    }
}

function Get-OsString {
    $cv = Open-RegKey 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    try { '{0} {1}.{2}' -f $cv.GetValue('EditionID'), $cv.GetValue('CurrentBuildNumber'), $cv.GetValue('UBR') } finally { $cv.Dispose() }
}

function Compare-Entries($Before, $After) {
    $old = @{}
    foreach ($x in @($Before)) { if ($x) { $old[$x.key] = $true } }
    @(@($After) | Where-Object { $_ -and -not $old.ContainsKey($_.key) })
}

# The installer of $App in C:\cr\inst (downloaded when missing or invalid); fills $Rec's url, installer,
# installer_sha256 and installer_sig. A corpus variant (firefox-tb) shares its base app's installer file,
# so sources.json is also searched by file name.
function Resolve-Installer($App, $Rec) {
    $file = Join-Path $RigInst $App.file
    $src = Join-Path $RigInst 'sources.json'
    if (Test-Path -LiteralPath $src) {
        $j = Get-Content -LiteralPath $src -Raw | ConvertFrom-Json
        if ($j.($App.id)) { $Rec.url = $j.($App.id).url }
        else {
            foreach ($pr in @($j.PSObject.Properties)) {
                if ($pr.Value.file -and (Split-Path -Leaf "$($pr.Value.file)") -ieq $App.file -and $pr.Value.url) { $Rec.url = $pr.Value.url; break }
            }
        }
    }
    if (-not (Test-InstallerFile $file)) {
        Log "installer $file missing or invalid; downloading"
        $rec = Fetch (& $App.url) $App.file
        $Rec.url = $rec.url
    }
    $info = Get-FileInfoRecord $file $Rec.url
    $Rec.installer = $file; $Rec.installer_sha256 = $info.sha256; $Rec.installer_sig = "$($info.sig) $($info.signer)".Trim()
    Log "installer $file sha256=$($info.sha256) sig=$($Rec.installer_sig)"
    $file
}

# Installs $App silently and waits for its process tree (RIG.md §4 step 2); fills $Rec {cmd, start, end,
# exit, timed_out, killed, ran_as}. With install_il = 'medium' the installer runs at medium integrity through
# the one-shot task PurgeRigInstall (deleted afterwards, also on failure); otherwise from this elevated job.
function Install-App($App, [string]$Installer, $Rec, [string]$MsiLog) {
    if ($App.install -eq 'msi') {
        $exe = Join-Path $env:SystemRoot 'System32\msiexec.exe'
        $args_ = '/i "' + $Installer + '" /qn /norestart /L*v "' + $MsiLog + '"'
    } else {
        $exe = $Installer; $args_ = $App.install
    }
    $Rec.cmd = "`"$exe`" $args_"
    $t = Get-Date
    $Rec.start = $t.ToString('o')
    $exited = $true
    if ($App.install_il -eq 'medium') {
        $Rec.ran_as = 'medium'
        $Rec.task = 'PurgeRigInstall'
        Log "install (medium IL, task PurgeRigInstall): $($Rec.cmd)"
        try {
            $L = LaunchMedium -Exe $exe -Arguments $args_ -TaskName 'PurgeRigInstall' -StartTimeoutSec 60
            if (-not $L.found) { throw "installer $exe did not start through task PurgeRigInstall" }
            $proc = $null
            try { $proc = [System.Diagnostics.Process]::GetProcessById([int]$L.pid); $null = $proc.Handle } catch { $proc = $null }
            $w = WaitTree -Since $t -TimeoutSec $InstallMaxSec -RootPid @([int]$L.pid)
            if ($proc) {
                try { if ($proc.HasExited) { $Rec.exit = $proc.ExitCode } else { $exited = $false } } catch { }
            }
        } finally {
            Unregister-ScheduledTask -TaskName 'PurgeRigInstall' -Confirm:$false -ErrorAction SilentlyContinue
        }
    } else {
        $Rec.ran_as = 'elevated'
        Log "install: $($Rec.cmd)"
        $p = Start-Native $exe $args_
        $exited = $p.WaitForExit($InstallMaxSec * 1000)
        if ($exited) { $Rec.exit = $p.ExitCode }
        Log "installer process exited=$exited exit=$($Rec.exit) after $([int]((Get-Date) - $t).TotalSeconds) s; waiting for its process tree"
        $left = [Math]::Max(60, $InstallMaxSec - [int]((Get-Date) - $t).TotalSeconds)
        $w = WaitTree -Since $t -TimeoutSec $left -RootPid @($p.Id)
    }
    $Rec.end = $w.end.ToString('o')
    $Rec.timed_out = ((-not $exited) -or $w.timed_out)
    if ($Rec.timed_out) {
        $still = @(Get-TreeProcs -Procs (Get-ProcList) -Known $w.known)
        $Rec.killed = @($still | ForEach-Object { "$($_.name)[$($_.pid)]" })
        Stop-Procs $still 'install timeout'
    }
    Log "install done: exit=$($Rec.exit) timed_out=$($Rec.timed_out) ran_as=$($Rec.ran_as); settle $InstallSettleSec s"
    Start-Sleep -Seconds $InstallSettleSec
}

Phase 'setup' {
    $S.os = Get-OsString
    $a = Get-App $Id
    $e.app = $a
    $S.tech = $a.tech
    $null = Resolve-Installer $a $S
} $S
Save-Run

# ------------------------------------------------------------------------------------------- pre-apps
# Installed before lists 0 / snap 0, so their footprint is part of the clean state (apps.ps1 'pre').
foreach ($preId in $PreIds) {
    $pre = [ordered]@{
        id = $preId; url = $null; installer = $null; installer_sha256 = $null; installer_sig = $null
        cmd = $null; start = $null; end = $null; exit = $null; timed_out = $false; killed = @(); ran_as = $null; entry = $null
    }
    [void]$S.pre.Add($pre)
    Phase "pre-$preId" {
        $pa = Get-App $pre.id
        $before = @(UninstallEntries)
        $file = Resolve-Installer $pa $pre
        Install-App $pa $file $pre (Join-Path $Dir "msi-pre-$($pre.id).log")
        $m = Find-MainEntry $pa $before @(UninstallEntries)
        if (-not $m) { throw "pre-app $($pre.id): no ARP entry matches '$($pa.match)'" }
        $pre.entry = $m
        Log "pre-app $($pre.id) installed: $($m.key) | $($m.name) $($m.version)"
    } $S
    Save-Run
}

Phase 'arp0' { $e.e0 = @(UninstallEntries); Log "ARP entries before: $($e.e0.Count)" } $S
Phase 'lists0' { Lists $Run 0 } $S
Phase 'snap0' { Snap $Run 0 } $S
Save-Run

# ----------------------------------------------------------------------------------------------- install
Phase 'install' {
    $a = $e.app
    if (-not $a) { throw 'no app definition (setup failed)' }
    Install-App $a $S.installer $S.install (Join-Path $Dir 'msi-install.log')
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

# ------------------------------------------------------------------------------- engine: before uninstall
if ($Engine) {
    Phase 'engine-inventory-1' {
        $null = Invoke-EngineStep -Step 'inventory-1' -Arguments 'inventory --json' -Calls $S.engine.calls -TimeoutSec $EngineMaxSec -StdoutFile $Inv1
        if (-not $S.main) { throw 'no main entry: cannot resolve the program_id' }
        $inv = [IO.File]::ReadAllText($Inv1) | ConvertFrom-Json
        $S.engine.program_id = Find-InventoryProgramId $inv $S.main.key
        Log "program_id of $($S.main.key): $($S.engine.program_id)"
    } $S
    Phase 'engine-harvest' {
        if (-not $S.engine.program_id) { throw 'no program_id (engine-inventory-1 failed)' }
        $a = 'harvest ' + (ConvertTo-EngineArg $S.engine.program_id) + ' -o ' + (ConvertTo-EngineArg $FpFile)
        $null = Invoke-EngineStep -Step 'harvest' -Arguments $a -Calls $S.engine.calls -TimeoutSec $EngineMaxSec
    } $S
    Save-Run
}

# --------------------------------------------------------------------------------------------- uninstall
Phase 'uninstall' {
    if (-not $S.main) { throw 'no main entry, nothing to uninstall' }
    $main = $S.main
    $key = $main.key
    if ($Engine) {
        # purge-engine uninstall (ENGINE_PLAN §3.4) instead of the vendor command; t0/t1/exit come from its
        # purge.run/0 document. The rig's own WaitTree and settle still run afterwards as a safety net.
        $S.uninstall.via = 'purge-engine'
        if (-not $S.engine.program_id) { throw 'no program_id (engine-inventory-1 failed): nothing was uninstalled' }
        $a = 'uninstall ' + (ConvertTo-EngineArg $S.engine.program_id) + ' --quiet'
        if (Test-Path -LiteralPath $FpFile) { $a += ' --fp ' + (ConvertTo-EngineArg $FpFile) }
        else { Log '!! no fp.json (engine-harvest failed): uninstall without --fp' }
        $a += ' -o ' + (ConvertTo-EngineArg $EngineRun)
        $S.uninstall.cmd = "`"$RigEngine`" $a"
        $t0 = Get-Date
        $S.uninstall.rig_t0 = $t0.ToString('o')
        $engineError = $null
        try { $null = Invoke-EngineStep -Step 'uninstall' -Arguments $a -Calls $S.engine.calls -TimeoutSec $UninstallMaxSec }
        catch { $engineError = $_.Exception.Message }
        $call = $null
        if ($S.engine.calls.Count) { $call = $S.engine.calls[$S.engine.calls.Count - 1] }
        if (-not $call -or $call.step -ne 'uninstall') { throw "purge-engine uninstall did not start: $engineError" }
        $S.uninstall.engine_exit = $call.exit
        $S.uninstall.times = 'rig'
        $S.uninstall.t0 = $S.uninstall.rig_t0
        if (Test-Path -LiteralPath $EngineRun) {
            try {
                $doc = [IO.File]::ReadAllText($EngineRun) | ConvertFrom-Json
                $S.engine.run = $doc
                $S.uninstall.t0 = ConvertFrom-EngineFileTime $doc.t_start
                $S.uninstall.t1 = ConvertFrom-EngineFileTime $doc.t_end
                $S.uninstall.exit = $doc.exit_code
                $S.uninstall.outcome = $doc.outcome
                $S.uninstall.verify_gone = $doc.verify_gone
                $S.uninstall.times = 'engine'
                Log "engine run: outcome=$($doc.outcome) exit=$($doc.exit_code) verify_gone.passed=$($doc.verify_gone.passed) cmd=$($doc.cmd)"
            } catch { Log "!! engine-run.json unreadable: $($_.Exception.Message)" }
        } else { Log '!! no engine-run.json' }
        # Safety net: anything the engine left running (by parent PID from the engine process) and the entry.
        $w = WaitTree -Since $t0 -TimeoutSec 600 -Until { -not (Test-RegKey $key) } -IdleGiveUpSec 60 -RootPid @([int]$call.pid)
        $S.uninstall.rig_t1 = $w.end.ToString('o')
        if (-not $S.uninstall.t1) { $S.uninstall.t1 = $S.uninstall.rig_t1 }
        $S.uninstall.timed_out = ([bool]$call.timed_out -or $w.timed_out)
    } else {
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
        $left = [Math]::Max(60, $UninstallMaxSec - [int]((Get-Date) - $t0).TotalSeconds)
        $w = WaitTree -Since $t0 -TimeoutSec $left -Until { -not (Test-RegKey $key) } -IdleGiveUpSec $UninstallIdleGiveUpSec -RootPid @($p.Id)
        $S.uninstall.t1 = $w.end.ToString('o')
        $S.uninstall.timed_out = ((-not $exited) -or $w.timed_out)
    }
    $S.uninstall.entry_gone = (-not (Test-RegKey $key))
    if ($S.uninstall.timed_out) {
        $still = @(Get-TreeProcs -Procs (Get-ProcList) -Known $w.known)
        $S.uninstall.killed = @($still | ForEach-Object { "$($_.name)[$($_.pid)]" })
        Stop-Procs $still 'uninstall timeout'
    }
    Log "uninstall done: exit=$($S.uninstall.exit) entry_gone=$($S.uninstall.entry_gone) timed_out=$($S.uninstall.timed_out) in $([int]($w.end - $t0).TotalSeconds) s; settle $UninstallSettleSec s"
    Start-Sleep -Seconds $UninstallSettleSec
    if ($Engine -and $engineError) { throw $engineError }
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

# -------------------------------------------------------------------------------- engine: after snap 2
# Only after the capture, so the engine's own reads cannot disturb snap 2.
if ($Engine) {
    Save-Run
    Phase 'engine-scan' {
        if (-not (Test-Path -LiteralPath $FpFile)) { throw 'no fp.json (engine-harvest failed): nothing to scan' }
        $a = 'scan --fp ' + (ConvertTo-EngineArg $FpFile) + ' --mode post --app ' + $Id + ' -o ' + (ConvertTo-EngineArg $PlanFile)
        $null = Invoke-EngineStep -Step 'scan' -Arguments $a -Calls $S.engine.calls -TimeoutSec $EngineMaxSec
    } $S
    Phase 'engine-inventory-2' {
        $null = Invoke-EngineStep -Step 'inventory-2' -Arguments 'inventory --json' -Calls $S.engine.calls -TimeoutSec $EngineMaxSec -StdoutFile $Inv2
    } $S
}

Save-Run
$failed = @($S.phases | Where-Object { -not $_.ok } | ForEach-Object { $_.name })
Log ("run-app $Id ($Run) finished; failed phases: {0}" -f $(if ($failed.Count) { $failed -join ', ' } else { 'none' }))
if ($failed.Count) { exit 1 }
exit 0
