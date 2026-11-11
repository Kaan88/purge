# Purge rig v2: null run (vm\RIG.md §4). Template: the host replaces __RUN__ with null1..null3.
# Same captures and waits as an app run, with no install, launch or uninstall, so diff(snap-0, snap-2)
# is pure Windows churn for the ambient set. Outputs in C:\cr\out\<run>\ as for run-app.ps1.
$Run = '__RUN__'
. C:\cr\guest\riglib.ps1

$Waits = [ordered]@{ install = 60; launch = 0; uninstall = 60 }

if ($Run -notmatch '^null\d+$') { Write-Host "null-run.ps1: __RUN__ was not replaced ('$Run')"; exit 2 }
$Dir = New-RunDir $Run
Set-RunLog (Join-Path $Dir 'run.log')
Log "null-run $Run on $env:COMPUTERNAME as $env:USERDOMAIN\$env:USERNAME (sid $RigUserSid)"

$S = [ordered]@{
    schema = 'purge.rig.run/1'; id = $null; run = $Run; kind = 'null'; computer = $env:COMPUTERNAME; sid = $RigUserSid; user_sid = $RigUserSid
    started = (NowIso); finished = $null; waits = $Waits
    install = $null; launch = [ordered]@{ done = $false }; uninstall = $null
    entries_created = @(); entries_left = @()
    phases = New-Object System.Collections.ArrayList
}
$RunJson = Join-Path $Dir 'run.json'
function Save-Run { $S.finished = NowIso; try { Write-JsonFile $S $RunJson } catch { Log "!! cannot write run.json: $($_.Exception.Message)" } }
$e = @{ e0 = $null }

Phase 'arp0' { $e.e0 = @(UninstallEntries) } $S
Phase 'lists0' { Lists $Run 0 } $S
Phase 'snap0' { Snap $Run 0 } $S
Save-Run
Phase 'wait-install' { Log "idle $($Waits.install) s"; Start-Sleep -Seconds $Waits.install } $S
Phase 'wait-launch' { Log "idle $($Waits.launch) s"; Start-Sleep -Seconds $Waits.launch } $S
Phase 'lists1' { Lists $Run 1 } $S
Phase 'snap1' { Snap $Run 1 } $S
Save-Run
Phase 'wait-uninstall' { Log "idle $($Waits.uninstall) s"; Start-Sleep -Seconds $Waits.uninstall } $S
Phase 'lists2' { Lists $Run 2 } $S
Phase 'snap2' { Snap $Run 2 } $S
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
