# Purge rig v2: one app run (vm\RIG.md §4, engine mode §4a). Template: the host (rig.ps1 New-RunJobText)
# replaces __ID__ with the app id, __RUN__ with the run name (the id, or a prefixed name such as r0-<id>)
# and __ENGINE__ with 1 (engine mode) or 0, and submits the result as an agent job (elevated, interactive
# user). Outputs in C:\cr\out\<run>\:
#   run.log, run.json, lists-<run>-0|1|2.json, snap-<run>-0|1|2.tsv.gz, msi-*.log (MSI apps)
#   engine mode also: inv-1.json, fp.json, engine-run.json, plan-purge.json (+ its sidecar), inv-2.json
#   extra checks (__EXTRA__ = 1, rig.ps1 -ExtraChecks): plan-live.json (scan of the still-installed app, after the
#   harvest) and plan-purge-b.json (a second identical post scan); results in run.json `extra`
# Every phase is wrapped: a failure is recorded in run.json and the remaining captures still run.
# Phase order (RIG.md §4, §4a, §4b): edge-pause, setup, pre-apps (+ pre-launch, pre-uninstall), plant-pre,
# arp0/lists0/snap0, install (upgrade_from first), detect, launch, post-apps, plant-post, lists1,
# [engine-inventory-1], snap1, [engine-harvest, engine-scan-live], uninstall, lists2, [engine-inventory-2], snap2,
# edge-check, entries, [engine-scan, engine-scan-repeat].
# M1b options (__M1B__, RIG.md section 12) add msi-tables-1 / msi-tables-2 right after snap1 / snap2 and, with traps,
# TrapB as the first pre-app plus m1b-traps-pre (before lists1), m1b-traps-between (before uninstall) and
# m1b-traps-post (after uninstall, before lists2).
$Id = '__ID__'
$Run = '__RUN__'
$EngineFlag = '__ENGINE__'
$ExtraFlag = '__EXTRA__'
# M1b options (rig.ps1 ConvertTo-M1bOpts, RIG.md section 12): base64 of {msi_tables, traps, trap_a, trap_b} as UTF-8
# JSON; empty or unreplaced = none (the M0 / M1a behaviour).
$M1bFlag = '__M1B__'
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
# Unreplaced (an older host) = no extra checks; they need engine mode.
$Extra = ($Engine -and $ExtraFlag -eq '1')
$M1b = $null
if ($M1bFlag -and $M1bFlag -ne ('__' + 'M1B__')) {
    try { $M1b = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($M1bFlag)) | ConvertFrom-Json }
    catch { Write-Host ("run-app.ps1: unreadable M1b options: {0}" -f $_.Exception.Message); exit 2 }
}
. C:\cr\guest\riglib.ps1
. C:\cr\guest\apps.ps1
# The plant functions of the x0 variants (apps.ps1 plant_pre / plant_post).
if (Test-Path -LiteralPath 'C:\cr\guest\x0-plants.ps1') { . C:\cr\guest\x0-plants.ps1 }

$InstallMaxSec = 15 * 60; $InstallSettleSec = 20
$LaunchRunSec = 25; $LaunchGraceSec = 5; $LaunchSettleSec = 10
$UninstallMaxSec = 30 * 60; $UninstallSettleSec = 30; $UninstallIdleGiveUpSec = 180
$EngineMaxSec = 20 * 60

$Dir = New-RunDir $Run
Set-RunLog (Join-Path $Dir 'run.log')
Log "run-app $Id (run $Run, engine=$Engine, extra=$Extra) on $env:COMPUTERNAME as $env:USERDOMAIN\$env:USERNAME (sid $RigUserSid), 64-bit=$([Environment]::Is64BitProcess)"

$S = [ordered]@{
    schema = 'purge.rig.run/1'; id = $Id; run = $Run; kind = 'app'; tech = $null; url = $null; installer = $null
    installer_sha256 = $null; installer_sig = $null; computer = $env:COMPUTERNAME; sid = $RigUserSid; user_sid = $RigUserSid
    os = $null; started = (NowIso); finished = $null
    main = $null
    install = [ordered]@{ cmd = $null; start = $null; end = $null; exit = $null; timed_out = $false; killed = @(); ran_as = $null }
    launch = [ordered]@{ done = $false; exe = $null; args = $null; start = $null; end = $null; found = $false; closed = @(); killed = @(); reason = $null }
    uninstall = [ordered]@{ cmd = $null; t0 = $null; t1 = $null; exit = $null; timed_out = $false; entry_gone = $null; killed = @() }
    entries_created = @(); entries_left = @()
    edge_pause = $null
    planted = New-Object System.Collections.ArrayList
    phases = New-Object System.Collections.ArrayList
}
$e = @{ e0 = $null; e1 = $null; e2 = $null; app = $null }
$RunJson = Join-Path $Dir 'run.json'
function Save-Run { $S.finished = NowIso; try { Write-JsonFile $S $RunJson } catch { Log "!! cannot write run.json: $($_.Exception.Message)" } }

# Variant fields (apps.ps1): read here so a failed setup phase still leaves them visible in run.json.
$Def = $null
try { $Def = Get-App $Id } catch { }
$PreIds = @(); $PostIds = @(); $UpgradeFrom = $null; $PlantPre = $null; $PlantPost = $null
if ($Def) {
    $PreIds = @(@($Def.pre) | Where-Object { $_ })
    $PostIds = @(@($Def.post) | Where-Object { $_ })
    $UpgradeFrom = $Def.upgrade_from
    $PlantPre = $Def.plant_pre; $PlantPost = $Def.plant_post
}
# M1b traps (guest\m1b-traps.ps1): TrapB is installed before snap 0 like any pre-app, unless the app already has it.
if ($M1b -and $M1b.traps) {
    $S.m1b = [ordered]@{ msi_tables = [bool]$M1b.msi_tables; traps = $true; trap_a = "$($M1b.trap_a)"; trap_b = "$($M1b.trap_b)"; tables = @() }
    if ($PreIds -notcontains "$($M1b.trap_b)" -and "$($M1b.trap_b)" -ne $Id) { $PreIds = @("$($M1b.trap_b)") + $PreIds }
} elseif ($M1b) {
    $S.m1b = [ordered]@{ msi_tables = [bool]$M1b.msi_tables; traps = $false; tables = @() }
}
$M1bTraps = 'C:\cr\guest\m1b-traps.ps1'
# Runs one phase of guest\m1b-traps.ps1 in this process (its log lines go to run.log); throws when a case failed.
function Invoke-M1bTrapPhase([string]$Step) {
    if (-not (Test-Path -LiteralPath $M1bTraps)) { throw "missing $M1bTraps (Push-Tools copies vm\guest\*.ps1)" }
    $global:LASTEXITCODE = 0
    & $M1bTraps -Phase $Step -OutDir $Dir -TrapA "$($M1b.trap_a)" -TrapB "$($M1b.trap_b)" -RunLog (Join-Path $Dir 'run.log')
    if ($LASTEXITCODE -ne 0) { throw "m1b-traps $Step`: a case failed (exit $LASTEXITCODE, see m1b-traps-planted.json)" }
}
# A failed m1b-traps phase ends the run (review R4b S1): nothing after it (harvest, uninstall, scan) runs, so no plan
# is scored as if every trap had been planted.
function Stop-RunOnFailedM1bTraps([string]$Name) {
    $ph = @($S.phases | Where-Object { $_.name -eq $Name }) | Select-Object -Last 1
    if ($ph -and -not $ph.ok) { Log "!! $Name failed: the run stops here (RIG.md section 12.2)"; Save-Run; exit 1 }
}
# Writes msi-tables-<run>-<phase>.json beside snap <phase> (guest\m1b-msi-tables.ps1).
function Save-M1bMsiTables([string]$Phase) {
    $f = Join-Path $Dir "msi-tables-$Run-$Phase.json"
    & 'C:\cr\guest\m1b-msi-tables.ps1' -Out $f
    if (-not (Test-Path -LiteralPath $f)) { throw "no $f written" }
    $S.m1b.tables += (Split-Path -Leaf $f)
}
if ($PreIds.Count) { $S.pre = New-Object System.Collections.ArrayList }
if ($PostIds.Count) { $S.post = New-Object System.Collections.ArrayList }
if ($UpgradeFrom) {
    $S.upgrade = [ordered]@{
        id = $UpgradeFrom; url = $null; installer = $null; installer_sha256 = $null; installer_sig = $null; installer_source = $null
        cmd = $null; start = $null; end = $null; exit = $null; timed_out = $false; killed = @(); ran_as = $null; entry = $null
    }
}
if ($PlantPre -or $PlantPost) { $S.plant = [ordered]@{ pre = $PlantPre; post = $PlantPost }; $S.plant_files = New-Object System.Collections.ArrayList }
if ($Extra) {
    $S.extra = [ordered]@{
        live_items = $null; live_safe = $null; live_preselected = $null; live_root_band = $null
        det_equal = $null; det_how = $null; plan_a = $null; plan_b = $null
    }
}

# Engine mode: files in the run directory and the run.json record of every engine call.
$Inv1 = Join-Path $Dir 'inv-1.json'
$FpFile = Join-Path $Dir 'fp.json'
$EngineRun = Join-Path $Dir 'engine-run.json'
$PlanFile = Join-Path $Dir 'plan-purge.json'
$Inv2 = Join-Path $Dir 'inv-2.json'
$PlanLive = Join-Path $Dir 'plan-live.json'
$PlanB = Join-Path $Dir 'plan-purge-b.json'
if ($Engine) {
    $S.engine = [ordered]@{
        exe = $RigEngine; app = $Id; program_id = $null; run = $null
        files = [ordered]@{ inv1 = 'inv-1.json'; fp = 'fp.json'; run = 'engine-run.json'; plan = 'plan-purge.json'; inv2 = 'inv-2.json' }
        # The (edition, build) baselines the engine can see (rig.ps1 -NoBaselines leaves none).
        baselines = @(Get-ChildItem -LiteralPath (Join-Path (Split-Path -Parent $RigEngine) 'kb\baselines') -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        calls = New-Object System.Collections.ArrayList
    }
    if ($Extra) { $S.engine.files.plan_live = 'plan-live.json'; $S.engine.files.plan_b = 'plan-purge-b.json' }
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
#
# Host installer cache (vm\cache\inst, pushed by rig.ps1 with its manifest cache-sources.json): a file listed there
# is used only when its SHA-256 matches the manifest; otherwise it is deleted and downloaded again. The record gets
# installer_source ('host cache', 'rig-base' or 'download') and, for manifest files, installer_version.
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
    $Rec.installer_source = 'rig-base'
    $m = $null
    $mf = Join-Path $RigInst 'cache-sources.json'
    if (Test-Path -LiteralPath $mf) {
        $cj = [IO.File]::ReadAllText($mf) | ConvertFrom-Json
        foreach ($pr in @($cj.PSObject.Properties)) { if ($pr.Name -ieq $App.file) { $m = $pr.Value; break } }
    }
    if ($m) {
        $Rec.installer_version = $m.version
        if (Test-Path -LiteralPath $file) {
            $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash
            if ($h -eq "$($m.sha256)".ToUpperInvariant()) { $Rec.url = $m.url; $Rec.installer_source = 'host cache' }
            else { Log "!! $file sha256 $h != cache manifest $($m.sha256): deleting, downloading again"; Remove-Item -LiteralPath $file -Force }
        }
    } elseif ($App.sha256 -and (Test-Path -LiteralPath $file)) {
        # A pinned app (apps.ps1 'sha256') without a cache entry: a same-named file of another version in the
        # snapshot (dirty-base holds setup-dirty's Python 3.13.1 as python313.exe) is deleted and downloaded again.
        $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash
        if ($h -ne "$($App.sha256)".ToUpperInvariant()) { Log "!! $file sha256 $h != pinned $($App.sha256): deleting, downloading again"; Remove-Item -LiteralPath $file -Force }
    }
    if (-not (Test-InstallerFile $file)) {
        Log "installer $file missing or invalid; downloading"
        # (not $rec: PowerShell names are case-insensitive, that would overwrite $Rec)
        $urls = @(& $App.url)
        if ($m -and $m.url -and $urls -notcontains $m.url) { $urls = @($m.url) + $urls }
        $fetched = Fetch $urls $App.file
        $Rec.url = $fetched.url
        $Rec.installer_source = 'download'
    }
    $info = Get-FileInfoRecord $file $Rec.url
    $Rec.installer_sha256 = $info.sha256; $Rec.installer_sig = "$($info.sig) $($info.signer)".Trim()
    if ($m -and $info.sha256 -ne "$($m.sha256)".ToUpperInvariant()) { Log "!! $($App.file): sha256 differs from the cache manifest (version drift?)"; $Rec.installer_version = $null }
    # Review R4d S4: the pin is checked before the record names the file, so a mismatch leaves $Rec.installer empty
    # and the install phase (which refuses an empty installer) never runs a file of another version.
    if ($App.sha256 -and $info.sha256 -ne "$($App.sha256)".ToUpperInvariant()) { throw "$($App.file): sha256 $($info.sha256) != pinned $($App.sha256)" }
    $Rec.installer = $file
    Log "installer $file sha256=$($info.sha256) sig=$($Rec.installer_sig) source=$($Rec.installer_source)"
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
        # (environment variables expanded: x0-git-toolsdir installs into %USERPROFILE%\Tools)
        $exe = $Installer; $args_ = [Environment]::ExpandEnvironmentVariables("$($App.install)")
    }
    $Rec.cmd = "`"$exe`" $args_"
    # PID-reuse guard for the installer's process tree (Get-TreeProcs): everything already running now.
    $pre = New-ProcKeySet
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
            $w = WaitTree -Since $t -TimeoutSec $InstallMaxSec -RootPid @([int]$L.pid) -Preexisting $pre
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
        $w = WaitTree -Since $t -TimeoutSec $left -RootPid @($p.Id) -Preexisting $pre
    }
    $Rec.end = $w.end.ToString('o')
    $Rec.timed_out = ((-not $exited) -or $w.timed_out)
    if ($Rec.timed_out) {
        $still = @(Get-TreeProcs -Procs (Get-ProcList) -Known $w.known -Preexisting $pre)
        $Rec.killed = @($still | ForEach-Object { "$($_.name)[$($_.pid)]" })
        Stop-Procs $still 'install timeout'
    }
    Log "install done: exit=$($Rec.exit) timed_out=$($Rec.timed_out) ran_as=$($Rec.ran_as); settle $InstallSettleSec s"
    Start-Sleep -Seconds $InstallSettleSec
}

function New-LaunchRecord { [ordered]@{ done = $false; exe = $null; args = $null; start = $null; end = $null; found = $false; closed = @(); killed = @(); reason = $null } }

# Starts $App's launch exe once at medium integrity, lets it run $LaunchRunSec s, closes it and settles
# (RIG.md §4 step 4); fills $Rec (New-LaunchRecord). Used for the main app, pre_launch and post apps.
function Invoke-AppLaunch($App, $Main, $Rec) {
    if (-not $App.launch) { $Rec.reason = 'app defines no launch'; Log "no launch for $($App.id)"; return }
    if (-not $Main) { $Rec.reason = 'no main entry'; throw 'no main entry, cannot resolve the launch exe' }
    $exe = Resolve-LaunchExe $App $Main
    if (-not $exe) { $Rec.reason = "exe '$($App.launch.exe)' not found"; throw $Rec.reason }
    $Rec.exe = $exe; $Rec.args = $App.launch.args
    # If LaunchMedium throws, the finally still closes whatever started since $t and deletes the task.
    $t = Get-Date
    $L = [pscustomobject]@{ task = 'PurgeRigLaunch'; start = $t; found = $false }
    try {
        $L = LaunchMedium -Exe $exe -Arguments $App.launch.args -TaskName $L.task
        $Rec.start = $L.start.ToString('o'); $Rec.found = $L.found
        Log "running $($App.id) for $LaunchRunSec s"
        Start-Sleep -Seconds $LaunchRunSec
    } finally {
        $r = Stop-Launch $L -GraceSec $LaunchGraceSec
        $Rec.closed = @($r.closed); $Rec.killed = @($r.killed)
        $Rec.end = NowIso
    }
    $Rec.done = $true
    Log "settle $LaunchSettleSec s"
    Start-Sleep -Seconds $LaunchSettleSec
}

# Vendor uninstall of an installed app (the M0 path, used for apps.ps1 pre_uninstall): runs the quiet uninstall
# command, waits for the entry to go and the process tree to end, kills what is left on timeout; fills $Rec.
function Invoke-VendorUninstall($App, $Main, $Rec, [string]$MsiLog) {
    $c = Build-UninstallCommand $App $Main $MsiLog
    $Rec.cmd = $c.display
    $key = $Main.key
    Log "vendor uninstall of $($App.id): exe=[$($c.exe)] args=[$($c.args)]"
    $pre = New-ProcKeySet
    $t0 = Get-Date
    $Rec.t0 = $t0.ToString('o')
    $p = Start-Native $c.exe $c.args
    $exited = $p.WaitForExit($UninstallMaxSec * 1000)
    if ($exited) { $Rec.exit = $p.ExitCode }
    $left = [Math]::Max(60, $UninstallMaxSec - [int]((Get-Date) - $t0).TotalSeconds)
    $w = WaitTree -Since $t0 -TimeoutSec $left -Until { -not (Test-RegKey $key) } -IdleGiveUpSec $UninstallIdleGiveUpSec -RootPid @($p.Id) -Preexisting $pre
    $Rec.t1 = $w.end.ToString('o')
    $Rec.timed_out = ((-not $exited) -or $w.timed_out)
    $Rec.entry_gone = (-not (Test-RegKey $key))
    if ($Rec.timed_out) {
        $still = @(Get-TreeProcs -Procs (Get-ProcList) -Known $w.known -Preexisting $pre)
        $Rec.killed = @($still | ForEach-Object { "$($_.name)[$($_.pid)]" })
        Stop-Procs $still 'vendor uninstall timeout'
    }
    Log "vendor uninstall of $($App.id) done: exit=$($Rec.exit) entry_gone=$($Rec.entry_gone) timed_out=$($Rec.timed_out); settle $UninstallSettleSec s"
    Start-Sleep -Seconds $UninstallSettleSec
}

# Runs the x0-plants.ps1 function $Name (apps.ps1 plant_pre / plant_post) with the plant context.
function Invoke-Plant([string]$Phase, [string]$Name) {
    if (-not (Get-Command -Name $Name -CommandType Function -ErrorAction SilentlyContinue)) {
        throw "plant function '$Name' is not defined (is C:\cr\guest\x0-plants.ps1 pushed?)"
    }
    $ctx = @{ Phase = $Phase; S = $S; App = $e.app; Main = $S.main; Dir = $Dir }
    $n0 = $S.planted.Count
    & $Name $ctx
    Log "$Phase ${Name}: $($S.planted.Count - $n0) item(s) planted"
}

# Install one extra app (pre, post) into $Rec, find its ARP entry; returns the app definition.
function Install-ExtraApp([string]$AppId, $Rec, [string]$Kind) {
    $pa = Get-App $AppId
    $before = @(UninstallEntries)
    $file = Resolve-Installer $pa $Rec
    Install-App $pa $file $Rec (Join-Path $Dir "msi-$Kind-$AppId.log")
    $m = Find-MainEntry $pa $before @(UninstallEntries)
    if (-not $m) { throw "$Kind-app ${AppId}: no ARP entry matches '$($pa.match)'" }
    $Rec.entry = $m
    Log "$Kind-app $AppId installed: $($m.key) | $($m.name) $($m.version)"
    $pa
}

function New-ExtraAppRecord([string]$AppId) {
    [ordered]@{
        id = $AppId; url = $null; installer = $null; installer_sha256 = $null; installer_sig = $null; installer_source = $null
        cmd = $null; start = $null; end = $null; exit = $null; timed_out = $false; killed = @(); ran_as = $null; entry = $null
    }
}

# Counts of a raw engine plan (purge.scan/0 items: band, preselected, scanner).
function Get-PlanSummary([string]$Path) {
    $p = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    $items = @(@($p.items) | ForEach-Object { $_ } | Where-Object { $_ })
    [ordered]@{
        items = $items.Count
        safe = @($items | Where-Object { "$($_.band)" -eq 'Safe' }).Count
        preselected = @($items | Where-Object { $_.preselected -eq $true }).Count
        root_band = @($items | Where-Object { "$($_.scanner)" -eq 'FS-INSTALLDIR' } | ForEach-Object { "$($_.band)" })
    }
}

# The plan hash of the scan sidecar (<plan>.scan.json, from the same code as `plan show`), else $null.
function Get-PlanHash([string]$Plan) {
    $side = [IO.Path]::ChangeExtension($Plan, '.scan.json')
    if (-not (Test-Path -LiteralPath $side)) { return $null }
    try { "$(([IO.File]::ReadAllText($side) | ConvertFrom-Json).plan_hash)" } catch { $null }
}

# ------------------------------------------------------------------------------------------- edge pause
# First of all (RIG.md §4a): Edge's updater stopped and disabled for the rest of the run, before any capture.
# A transient change of the restored snapshot, identical in null runs; rig-base itself is never changed.
Phase 'edge-pause' { $S.edge_pause = Suspend-EdgeUpdate } $S

Phase 'setup' {
    $S.os = Get-OsString
    $a = Get-App $Id
    $e.app = $a
    $S.tech = $a.tech
    $null = Resolve-Installer $a $S
    # Installers needed after snap 0 are fetched now, so no download happens between the captures.
    if ($UpgradeFrom) { $S.upgrade.installer = Resolve-Installer (Get-App $UpgradeFrom) $S.upgrade }
    foreach ($postId in $PostIds) {
        $r = New-ExtraAppRecord $postId
        [void]$S.post.Add($r)
        $null = Resolve-Installer (Get-App $postId) $r
    }
} $S
Save-Run

# ------------------------------------------------------------------------------------------- pre-apps
# Installed before lists 0 / snap 0, so their footprint is part of the clean state (apps.ps1 'pre'); launched
# once with pre_launch, then removed with their vendor uninstaller with pre_uninstall.
foreach ($preId in $PreIds) {
    $pre = New-ExtraAppRecord $preId
    [void]$S.pre.Add($pre)
    # (a holder the phase scriptblocks fill: they run in a child scope)
    $pa = @{ def = $null }
    Phase "pre-$preId" { $pa.def = Install-ExtraApp $pre.id $pre 'pre' } $S
    if ($Def.pre_launch) {
        $pre.launch = New-LaunchRecord
        Phase "pre-launch-$preId" {
            if (-not $pa.def) { throw "pre-app $($pre.id) was not installed" }
            Invoke-AppLaunch $pa.def $pre.entry $pre.launch
        } $S
    }
    if ($Def.pre_uninstall) {
        $pre.uninstall = [ordered]@{ cmd = $null; t0 = $null; t1 = $null; exit = $null; timed_out = $false; entry_gone = $null; killed = @() }
        Phase "pre-uninstall-$preId" {
            if (-not $pre.entry) { throw "pre-app $($pre.id) has no ARP entry" }
            Invoke-VendorUninstall $pa.def $pre.entry $pre.uninstall (Join-Path $Dir "msi-pre-uninstall-$($pre.id).log")
        } $S
    }
    Save-Run
}

if ($PlantPre) { Phase 'plant-pre' { Invoke-Plant 'plant-pre' $PlantPre } $S; Save-Run }

Phase 'arp0' { $e.e0 = @(UninstallEntries); Log "ARP entries before: $($e.e0.Count)" } $S
Phase 'lists0' { Lists $Run 0 } $S
Phase 'snap0' { Snap $Run 0 } $S
Save-Run

# ----------------------------------------------------------------------------------------------- install
Phase 'install' {
    $a = $e.app
    if (-not $a) { throw 'no app definition (setup failed)' }
    if (-not $S.installer) { throw 'no installer (setup failed: missing, or not the pinned file)' }
    if ($UpgradeFrom) {
        # apps.ps1 upgrade_from: the older build first, then the main installer over it (an in-place upgrade).
        $u = Get-App $UpgradeFrom
        if (-not $S.upgrade.installer) { throw "no installer for upgrade_from '$UpgradeFrom' (setup failed)" }
        $before = @(UninstallEntries)
        Install-App $u $S.upgrade.installer $S.upgrade (Join-Path $Dir "msi-upgrade-$UpgradeFrom.log")
        $m = Find-MainEntry $u $before @(UninstallEntries)
        if (-not $m) { throw "upgrade_from ${UpgradeFrom}: no ARP entry matches '$($u.match)'" }
        $S.upgrade.entry = $m
        Log "upgrade_from $UpgradeFrom installed: $($m.key) | $($m.name) $($m.version); now the main installer"
    }
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
Phase 'launch' { Invoke-AppLaunch $e.app $S.main $S.launch } $S
Save-Run

# ---------------------------------------------------------------------------------- post-apps, plant-post
# A sibling installed (and launched) after the app (apps.ps1 'post'); its ARP entry is new in lists 2, so truth
# anchors it as kept_owner. detect has already run, so the main entry is unaffected.
foreach ($r in @($S.post)) {
    if (-not $r) { continue }
    Phase "post-$($r.id)" {
        if (-not $r.installer) { throw "no installer for post-app $($r.id) (setup failed)" }
        $pa = Install-ExtraApp $r.id $r 'post'
        $r.launch = New-LaunchRecord
        Invoke-AppLaunch $pa $r.entry $r.launch
    } $S
    Save-Run
}
if ($PlantPost) { Phase 'plant-post' { Invoke-Plant 'plant-post' $PlantPost } $S; Save-Run }
# M1b scan traps, pre plants: after the launch, before lists 1 / snap 1 and the harvest (RIG.md section 12).
if ($M1b -and $M1b.traps) { Phase 'm1b-traps-pre' { Invoke-M1bTrapPhase 'pre' } $S; Save-Run; Stop-RunOnFailedM1bTraps 'm1b-traps-pre' }

Phase 'lists1' { Lists $Run 1 } $S
# Engine inventory right after the lists of the same point (RIG.md §4a): it reads the Uninstall keys and the MSI
# API only, so it cannot change the capture; its Prefetch file is labelled rig.
if ($Engine) {
    Phase 'engine-inventory-1' {
        $null = Invoke-EngineStep -Step 'inventory-1' -Arguments 'inventory --json' -Calls $S.engine.calls -TimeoutSec $EngineMaxSec -StdoutFile $Inv1
        if (-not $S.main) { throw 'no main entry: cannot resolve the program_id' }
        $inv = [IO.File]::ReadAllText($Inv1) | ConvertFrom-Json
        $S.engine.program_id = Find-InventoryProgramId $inv $S.main.key
        Log "program_id of $($S.main.key): $($S.engine.program_id)"
    } $S
}
Phase 'snap1' { Snap $Run 1 } $S
if ($M1b -and $M1b.msi_tables) { Phase 'msi-tables-1' { Save-M1bMsiTables 1 } $S }
Save-Run

# Inno Setup apps: copy the real uninstall log(s) at the snap1 point into the run dir as parser fixtures
# (M1A gate step 7). C:\cr is rig-owned and excluded from snapshots; a miss is logged, never fatal.
if ("$($e.app.tech)" -match 'Inno' -and $S.main) {
    try {
        $k = Get-ItemProperty -LiteralPath ('Registry::' + $S.main.key) -ErrorAction Stop
        $loc = "$($k.'Inno Setup: App Path')"; if (-not $loc) { $loc = "$($k.InstallLocation)" }
        $dats = @(); if ($loc -and (Test-Path -LiteralPath $loc)) { $dats = @(Get-ChildItem -LiteralPath $loc -Filter 'unins*.dat' -File) }
        $S.inno_logs = @()
        foreach ($f in $dats) {
            Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $Dir ('inno-' + $f.Name)) -Force
            $S.inno_logs += ('inno-' + $f.Name); Log "inno log copied: $($f.FullName)"
        }
        if (-not $dats.Count) { Log "!! no unins*.dat under '$loc'" }
    } catch { Log "!! inno log copy failed: $($_.Exception.Message)" }
    Save-Run
}

# ------------------------------------------------------------------------------- engine: before uninstall
if ($Engine) {
    Phase 'engine-harvest' {
        if (-not $S.engine.program_id) { throw 'no program_id (engine-inventory-1 failed)' }
        $a = 'harvest ' + (ConvertTo-EngineArg $S.engine.program_id) + ' -o ' + (ConvertTo-EngineArg $FpFile)
        $null = Invoke-EngineStep -Step 'harvest' -Arguments $a -Calls $S.engine.calls -TimeoutSec $EngineMaxSec
    } $S
    Save-Run
    # Extra check M-LIVE (negative control): a scan of the still-installed app. Pass (truth/m1a.sh): no item Safe,
    # none preselected, the install root absent or Blocked. The scan only reads and writes its -o file.
    if ($Extra) {
        Phase 'engine-scan-live' {
            if (-not (Test-Path -LiteralPath $FpFile)) { throw 'no fp.json (engine-harvest failed): nothing to scan' }
            $a = 'scan --fp ' + (ConvertTo-EngineArg $FpFile) + ' --mode external --app ' + $Id + ' -o ' + (ConvertTo-EngineArg $PlanLive)
            $null = Invoke-EngineStep -Step 'scan-live' -Arguments $a -Calls $S.engine.calls -TimeoutSec $EngineMaxSec
            $sum = Get-PlanSummary $PlanLive
            $S.extra.live_items = $sum.items; $S.extra.live_safe = $sum.safe; $S.extra.live_preselected = $sum.preselected
            $S.extra.live_root_band = @($sum.root_band)
            Log "live scan: $($sum.items) item(s), safe=$($sum.safe), preselected=$($sum.preselected), install root=$(@($sum.root_band) -join ',')"
        } $S
        Save-Run
    }
}
# M1b scan traps, between step: after the harvest, before the uninstall (com-shared-class is re-pointed to TrapB).
if ($M1b -and $M1b.traps) { Phase 'm1b-traps-between' { Invoke-M1bTrapPhase 'between' } $S; Save-Run; Stop-RunOnFailedM1bTraps 'm1b-traps-between' }

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
        $pre = New-ProcKeySet    # PID-reuse guard for the engine's process tree (Get-TreeProcs)
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
        $w = WaitTree -Since $t0 -TimeoutSec 600 -Until { -not (Test-RegKey $key) } -IdleGiveUpSec 60 -RootPid @([int]$call.pid) -Preexisting $pre
        $S.uninstall.rig_t1 = $w.end.ToString('o')
        if (-not $S.uninstall.t1) { $S.uninstall.t1 = $S.uninstall.rig_t1 }
        $S.uninstall.timed_out = ([bool]$call.timed_out -or $w.timed_out)
    } else {
        $c = Build-UninstallCommand $e.app $main (Join-Path $Dir 'msi-uninstall.log')
        $S.uninstall.cmd = $c.display
        Log "uninstall: exe=[$($c.exe)] args=[$($c.args)]"
        $pre = New-ProcKeySet    # PID-reuse guard for the uninstaller's process tree (Get-TreeProcs)
        $t0 = Get-Date
        $S.uninstall.t0 = $t0.ToString('o')
        $p = Start-Native $c.exe $c.args
        $exited = $p.WaitForExit($UninstallMaxSec * 1000)
        if ($exited) { $S.uninstall.exit = $p.ExitCode }
        Log "uninstaller process exited=$exited exit=$($S.uninstall.exit) after $([int]((Get-Date) - $t0).TotalSeconds) s; waiting for ARP entry removal and process tree"
        # NSIS copies its uninstaller to %TEMP% (Au_.exe) and relaunches it, Burn and MSI spawn children: the
        # end is "main entry gone and no process started after t0 still running".
        $left = [Math]::Max(60, $UninstallMaxSec - [int]((Get-Date) - $t0).TotalSeconds)
        $w = WaitTree -Since $t0 -TimeoutSec $left -Until { -not (Test-RegKey $key) } -IdleGiveUpSec $UninstallIdleGiveUpSec -RootPid @($p.Id) -Preexisting $pre
        $S.uninstall.t1 = $w.end.ToString('o')
        $S.uninstall.timed_out = ((-not $exited) -or $w.timed_out)
    }
    $S.uninstall.entry_gone = (-not (Test-RegKey $key))
    if ($S.uninstall.timed_out) {
        $still = @(Get-TreeProcs -Procs (Get-ProcList) -Known $w.known -Preexisting $pre)
        $S.uninstall.killed = @($still | ForEach-Object { "$($_.name)[$($_.pid)]" })
        Stop-Procs $still 'uninstall timeout'
    }
    Log "uninstall done: exit=$($S.uninstall.exit) entry_gone=$($S.uninstall.entry_gone) timed_out=$($S.uninstall.timed_out) in $([int]($w.end - $t0).TotalSeconds) s; settle $UninstallSettleSec s"
    Start-Sleep -Seconds $UninstallSettleSec
    if ($Engine -and $engineError) { throw $engineError }
} $S
Save-Run
# M1b scan traps, post plants: after the uninstall, before lists 2 / snap 2 and the scan.
if ($M1b -and $M1b.traps) { Phase 'm1b-traps-post' { Invoke-M1bTrapPhase 'post' } $S; Save-Run; Stop-RunOnFailedM1bTraps 'm1b-traps-post' }

Phase 'lists2' { Lists $Run 2 } $S
if ($Engine) {
    Phase 'engine-inventory-2' {
        $null = Invoke-EngineStep -Step 'inventory-2' -Arguments 'inventory --json' -Calls $S.engine.calls -TimeoutSec $EngineMaxSec -StdoutFile $Inv2
    } $S
}
Phase 'snap2' { Snap $Run 2 } $S
if ($M1b -and $M1b.msi_tables) { Phase 'msi-tables-2' { Save-M1bMsiTables 2 } $S }
# Proof that the Edge pause held (truth/m1a.sh compares versions_before / versions_end).
Phase 'edge-check' {
    if (-not $S.edge_pause) { throw 'no edge_pause record' }
    $S.edge_pause.versions_end = Get-EdgeVersions
    $S.edge_pause.held = ((ConvertTo-Json -InputObject $S.edge_pause.versions_after -Compress) -eq (ConvertTo-Json -InputObject $S.edge_pause.versions_end -Compress))
    Log "edge pause held: $($S.edge_pause.held)"
} $S

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
    # Extra check M-DET: the same scan again; the plan hashes (scan sidecar) must be equal.
    if ($Extra) {
        Phase 'engine-scan-repeat' {
            if (-not (Test-Path -LiteralPath $PlanFile)) { throw 'no plan-purge.json (engine-scan failed): nothing to repeat' }
            $a = 'scan --fp ' + (ConvertTo-EngineArg $FpFile) + ' --mode post --app ' + $Id + ' -o ' + (ConvertTo-EngineArg $PlanB)
            $null = Invoke-EngineStep -Step 'scan-repeat' -Arguments $a -Calls $S.engine.calls -TimeoutSec $EngineMaxSec
            $ha = Get-PlanHash $PlanFile; $hb = Get-PlanHash $PlanB
            if ($ha -and $hb) { $S.extra.det_how = 'plan_hash' }
            else {
                $ha = (Get-FileHash -Algorithm SHA256 -LiteralPath $PlanFile).Hash; $hb = (Get-FileHash -Algorithm SHA256 -LiteralPath $PlanB).Hash
                $S.extra.det_how = 'file sha256'
            }
            $S.extra.plan_a = $ha; $S.extra.plan_b = $hb
            $S.extra.det_equal = ($ha -eq $hb)
            Log "repeat scan: det_equal=$($S.extra.det_equal) ($($S.extra.det_how) $ha / $hb)"
        } $S
    }
}

Save-Run
$failed = @($S.phases | Where-Object { -not $_.ok } | ForEach-Object { $_.name })
Log ("run-app $Id ($Run) finished; failed phases: {0}" -f $(if ($failed.Count) { $failed -join ', ' } else { 'none' }))
if ($failed.Count) { exit 1 }
exit 0
