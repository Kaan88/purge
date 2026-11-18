# Purge rig v2: null run (vm\RIG.md §4, §6). Template: the host replaces the run placeholder with null1..null3
# (or <prefix>null<n>, e.g. r0-null1 in an engine campaign) and the wait placeholder with the idle seconds.
# Same captures as an app run, with no install, launch or uninstall, so diff(snap-0, snap-2) is pure Windows
# churn for the ambient set. Outputs in C:\cr\out\<run>\ as for run-app.ps1.
$Run = '__RUN__'
$WaitArg = '__WAIT__'
. C:\cr\guest\riglib.ps1

# Idle time standing in for the install and the uninstall. 60 s each (the M0 null runs) unless the host set it,
# e.g. so the snap0 -> snap2 window is as long as an app run's (RIG.md §6).
$w = 60
if ($WaitArg -match '^\d{1,4}$') { $w = [int]$WaitArg }
$Waits = [ordered]@{ install = $w; launch = 0; uninstall = $w }

if ($Run -cnotmatch '^([a-z0-9][a-z0-9_.-]*-)?null\d+$') { Write-Host "null-run.ps1: the run placeholder was not replaced ('$Run')"; exit 2 }
$Dir = New-RunDir $Run
Set-RunLog (Join-Path $Dir 'run.log')
Log "null-run $Run on $env:COMPUTERNAME as $env:USERDOMAIN\$env:USERNAME (sid $RigUserSid)"

$S = [ordered]@{
    schema = 'purge.rig.run/1'; id = $null; run = $Run; kind = 'null'; computer = $env:COMPUTERNAME; sid = $RigUserSid; user_sid = $RigUserSid
    started = (NowIso); finished = $null; waits = $Waits
    install = $null; launch = [ordered]@{ done = $false }; uninstall = $null
    defender = [ordered]@{ idle = $null; snap0 = $null; snap2 = $null }
    entries_created = @(); entries_left = @()
    phases = New-Object System.Collections.ArrayList
}
$RunJson = Join-Path $Dir 'run.json'
function Save-Run { $S.finished = NowIso; try { Write-JsonFile $S $RunJson } catch { Log "!! cannot write run.json: $($_.Exception.Message)" } }
$e = @{ e0 = $null }

# Edge/WebView2 updater pause, exactly as in run-app.ps1 (riglib Suspend-EdgeUpdate, RIG.md §4): before anything is
# captured, so the null runs' ambient set and the app runs share the same paused state.
Phase 'edge-pause' { $S.edge_pause = Suspend-EdgeUpdate } $S
# Defender signature idle, exactly as in run-app.ps1 (riglib Wait-DefenderIdle, RIG.md section 12.7, ruling
# 2026-11-18; gate5 fix): MpCmdRun retried until it exits 0, then Defender's state stable and its signatures current
# (bounded), right before arp0 / lists 0 / snap 0; the versions are recorded at snap 0 and snap 2 (run.json
# `defender`; truth/m1b.sh: a null run whose versions differ is INVALID). Never blocks the run.
Phase 'defender-idle' { $S.defender.idle = Wait-DefenderIdle -OutDir $Dir } $S
Phase 'arp0' { $e.e0 = @(UninstallEntries) } $S
Phase 'lists0' { Lists $Run 0 } $S
Phase 'snap0' { $S.defender.snap0 = Get-DefenderVersions; Snap $Run 0 } $S
Save-Run
Phase 'wait-install' { Log "idle $($Waits.install) s"; Start-Sleep -Seconds $Waits.install } $S
Phase 'wait-launch' { Log "idle $($Waits.launch) s"; Start-Sleep -Seconds $Waits.launch } $S
Phase 'lists1' { Lists $Run 1 } $S
Phase 'snap1' { Snap $Run 1 } $S
Save-Run
Phase 'wait-uninstall' { Log "idle $($Waits.uninstall) s"; Start-Sleep -Seconds $Waits.uninstall } $S
Phase 'lists2' { Lists $Run 2 } $S
Phase 'snap2' { Snap $Run 2; $S.defender.snap2 = Get-DefenderVersions } $S
Phase 'edge-check' {
    if (-not $S.edge_pause) { throw 'no edge_pause record' }
    $S.edge_pause.versions_end = Get-EdgeVersions
    $S.edge_pause.held = ((ConvertTo-Json -InputObject $S.edge_pause.versions_after -Compress) -eq (ConvertTo-Json -InputObject $S.edge_pause.versions_end -Compress))
    Log "edge versions at the end: $(@($S.edge_pause.versions_end.Values) -join '; '); pause held: $($S.edge_pause.held)"
} $S
Phase 'entries' {
    $old = @{}
    foreach ($x in @($e.e0)) { $old[$x.key] = $true }
    $S.entries_created = @(@(UninstallEntries) | Where-Object { -not $old.ContainsKey($_.key) })
    $S.entries_left = $S.entries_created
    if ($S.entries_created.Count) { Log "!! ARP entries appeared during a null run: $(($S.entries_created | ForEach-Object { $_.key }) -join ', ')" }
} $S

Save-Run
$failed = @($S.phases | Where-Object { -not $_.ok } | ForEach-Object { $_.name })
Log ("null-run $Run finished; failed phases: {0}" -f $(if ($failed.Count) { $failed -join ', ' } else { 'none' }))
if ($failed.Count) { exit 1 }
exit 0
