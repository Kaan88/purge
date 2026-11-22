<#
  Scorer of the M3 recovery modes (vm\RIG.md section 15): m3-owner (gate G8), m3-recover (G9), m3-extras
  (allow_irreversible, Restart Manager, System Restore). Windows PowerShell 5.1 or pwsh 7. Reads the evidence directory
  of one run of vm\rig-m3-recover.ps1 (summary.json, *.png, guest\ or rounds\<round>\guest\) and
  vm\truth\m3-recover-expect.json.

    powershell -NoProfile -File vm\truth\m3-recover-score.ps1 -Mode owner   -Evidence E:\purge-build\gate-evidence\m3-owner\<run>
    powershell -NoProfile -File vm\truth\m3-recover-score.ps1 -Mode recover -Evidence E:\purge-build\gate-evidence\m3-recover\<run>
    powershell -NoProfile -File vm\truth\m3-recover-score.ps1 -Mode extras  -Evidence E:\purge-build\gate-evidence\m3-extras\<run>
    powershell -NoProfile -File vm\truth\m3-recover-score.ps1 --self-test      (or -SelfTest)

  Fail-closed: every row needs its evidence; a missing file, round, record or field is a FAIL of that row, never a pass.
  Prints one line per row, writes <evidence>\score-<mode>.json, exits 0 (PASS), 1 (FAIL) or 2 (usage). The self-test
  builds a passing synthetic evidence directory per mode in %TEMP%, checks that it passes, then that each single defect
  of a list (a half state, a missing consent screenshot, an owner mismatch, ...) and an empty directory fail.
#>
[CmdletBinding()]
param(
    [ValidateSet('', 'owner', 'recover', 'extras')] [string] $Mode = '',
    [string] $Evidence = '',
    [string] $ExpectFile = '',
    [switch] $SelfTest,
    [Parameter(ValueFromRemainingArguments = $true)] $Rest
)
$ErrorActionPreference = 'Stop'
if (@($Rest) -contains '--self-test') { $SelfTest = $true }
if (-not $ExpectFile) { $ExpectFile = Join-Path $PSScriptRoot 'm3-recover-expect.json' }

# ------------------------------------------------------------------------------------------------ helpers

function Read-J([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
}
function Has($O, [string]$Name) { $null -ne $O -and $null -ne $O.PSObject.Properties[$Name] -and $null -ne $O.$Name }
function Arr($X) { @(@($X) | Where-Object { $null -ne $_ }) }

$script:Rows = New-Object System.Collections.ArrayList
function Row([string]$Name, $Ok, [string]$Detail = '') {
    [void]$script:Rows.Add([ordered]@{ row = $Name; ok = ($Ok -eq $true); detail = $Detail })
}
function Add-Row([string]$Name, [string[]]$Why, [string]$Good = '') {
    $w = @($Why | Where-Object { $_ })
    Row $Name ($w.Count -eq 0) $(if ($w.Count) { $w -join '; ' } else { $Good })
}

# Screenshots the summary names whose file exists with bytes.
function Get-Shots([string]$Ev, $Summary) {
    @(Arr $Summary.shots | Where-Object { $_.file -and [long]$_.bytes -gt 0 -and (Test-Path -LiteralPath (Join-Path $Ev $_.file) -PathType Leaf) -and (Get-Item -LiteralPath (Join-Path $Ev $_.file)).Length -gt 0 } | ForEach-Object { "$($_.name)" })
}

# A fixture truth as one comparable string: per root (sorted), whether it exists and its canonical lines.
function Get-TruthKey($T) {
    if (-not $T) { return $null }
    (@(Arr $T.roots | Sort-Object { "$($_.root)" } | ForEach-Object { "$($_.root)|$($_.exists)|" + (@(Arr $_.lines) -join "`n") })) -join "`n#`n"
}
# The roots where two truths differ, for the detail of a row.
function Get-TruthDiff($A, $B) {
    $m = @{}; foreach ($r in Arr $B.roots) { $m["$($r.root)"] = $r }
    @(Arr $A.roots | Where-Object { $o = $m["$($_.root)"]; -not $o -or "$($o.exists)" -ne "$($_.exists)" -or ((@(Arr $o.lines) -join "`n") -cne (@(Arr $_.lines) -join "`n")) } | ForEach-Object { "$($_.root)" })
}

# The owner part of an SDDL string and the rest (group and DACL).
function Get-SddlOwner([string]$S) { $m = [regex]::Match("$S", '^O:([^:]+?)(?=G:|D:|S:|$)'); if ($m.Success) { $m.Groups[1].Value } else { $null } }
function Get-SddlRest([string]$S) { "$S" -replace '^O:[^:]+?(?=G:|D:|S:|$)', '' }
# Whether any ACE of the DACL grants WRITE_OWNER (0x80000, WO, or a generic/all right that holds it).
function Test-DaclWriteOwner([string]$S) {
    $d = [regex]::Match("$S", 'D:[A-Z]*(\(.*)$')
    if (-not $d.Success) { return $true }
    foreach ($ace in [regex]::Matches($d.Groups[1].Value, '\(([^)]*)\)')) {
        $p = $ace.Groups[1].Value -split ';'
        if ($p[0] -ne 'A') { continue }
        $mask = $p[2]
        if ($mask -match '^0x([0-9a-fA-F]+)$') { if (([Convert]::ToInt64($Matches[1], 16) -band 0x80000) -ne 0) { return $true } }
        elseif ($mask -match 'WO|KA|GA|FA') { return $true }
    }
    $false
}

# ------------------------------------------------------------------------------------------------- owner

# The silent UAC each mode sets itself at start (guest phase uac-silent; coordinator ruling 2026-11-22: rig-base is at the
# Windows defaults): the recorded set is ok, silent with LUA on, and uac-check after it saw the same. The snapshot's own
# value (before) is recorded, never asserted.
function Test-UacSilent($S, $Uac, $Want) {
    $ok = ($S -and $S.ok -eq $true -and "$($S.after.ConsentPromptBehaviorAdmin)" -eq "$Want" -and "$($S.after.EnableLUA)" -eq '1')
    Row 'uac made silent by the mode (recorded before/after)' $ok $(if ($S) { "before $($S.before.ConsentPromptBehaviorAdmin)/$($S.before.PromptOnSecureDesktop)/$($S.before.EnableLUA), after $($S.after.ConsentPromptBehaviorAdmin)/$($S.after.PromptOnSecureDesktop)/$($S.after.EnableLUA)" } else { 'no uac_silent record' })
    Row 'uac silent when checked (ConsentPromptBehaviorAdmin)' ($Uac -and "$($Uac.ConsentPromptBehaviorAdmin)" -eq "$Want") "$(if ($Uac) { $Uac.ConsentPromptBehaviorAdmin })"
}

function Test-Owner([string]$Ev, $X) {
    $doc = Read-J (Join-Path $Ev 'guest\m3-owner.json')
    $sum = Read-J (Join-Path $Ev 'summary.json')
    Row 'evidence guest\m3-owner.json' ($null -ne $doc) $(if (-not $doc) { 'missing or unreadable' })
    Row 'evidence summary.json' ($null -ne $sum) $(if (-not $sum) { 'missing or unreadable' })
    if (-not $doc) { return }
    $o = $X.owner
    Test-UacSilent $doc.uac_silent $doc.uac $X.uac_admin

    $rec = "$($doc.exec.sddl_recorded)"
    $why = @()
    if (-not $rec) { $why += 'no recorded descriptor of Parameters\Guarded' }
    else {
        if ((Get-SddlOwner $rec) -ne $o.recorded_owner) { $why += "recorded owner $(Get-SddlOwner $rec), expected $($o.recorded_owner)" }
        if (Test-DaclWriteOwner $rec) { $why += "the recorded DACL grants WRITE_OWNER: $rec" }
        if ($doc.fixture.service.guarded_sddl -and "$($doc.fixture.service.guarded_sddl)" -cne $rec) { $why += 'the descriptor changed between the fixture and the execute' }
    }
    Add-Row 'fixture: Guarded owned by SYSTEM, no WRITE_OWNER in its DACL (R8b M1)' $why $rec

    $e = $doc.exec
    $why = @()
    if (-not $e.session) { $why += 'no session' }
    if (@(Arr $o.exec_outcomes) -notcontains "$($e.exec_result.result.outcome)") { $why += "outcome $($e.exec_result.result.outcome)" }
    if ($e.service_after -ne $false) { $why += 'the service is still there after the execute' }
    if (-not $e.service_candidate) { $why += 'the scan offered no service candidate' }
    Add-Row 'execute through the broker removed the service' $why "session $($e.session)"

    $c = $doc.cut
    $why = @()
    if (-not $c) { $why += 'no record' }
    else {
        if (@('suspended_killed', 'killed') -notcontains "$($c.watch.state)") { $why += "watcher $($c.watch.state)" }
        if ("$($c.watch.hit_text)" -notmatch '"rec":"undo_intent"' -or ($c.service_op -and "$($c.watch.hit_text)" -notmatch ('"op":{0}[,}}]' -f $c.service_op))) { $why += "cut at '$($c.watch.hit_text)', not the service op's undo_intent" }
        if ($c.listed -ne $true) { $why += 'journal.pending did not list the interrupted undo' }
    }
    Add-Row 'undo cut after the service undo_intent; the session is pending' $why "op $($c.service_op), line $($c.watch.hit_line)"

    $half = "$($c.half_sddl)"
    $why = @()
    if (-not $half) { $why += 'no half-state descriptor' }
    elseif ($rec) {
        if ((Get-SddlOwner $half) -eq (Get-SddlOwner $rec)) { $why += "the half state already has the recorded owner ($half): not the R8b M1 case" }
        if ((Get-SddlRest $half) -cne (Get-SddlRest $rec)) { $why += "group or DACL of the half state differ from the recorded ones: $half" }
    }
    Add-Row 'half state: Guarded re-created, recorded group and DACL, creator as owner' $why $half

    $r = $doc.resume
    $st = $r.start
    $why = @()
    if (-not ($st -and $st.dialog -and $st.dialog.found -eq $true)) { $why += 'no resume dialog' }
    else {
        if ($st.dialog.broker_il -ne 'high') { $why += "dialog at $($st.dialog.broker_il)" }
        if ("$($st.dialog.labels.primary)" -ne $o.resume_label) { $why += "button '$($st.dialog.labels.primary)', expected '$($o.resume_label)'" }
    }
    $k = $(if ($sum -and $sum.keys) { $sum.keys.own })
    if (-not ($k -and $k.answered -eq $true)) { $why += 'the dialog was not answered by the host''s keys' }
    elseif (@(Arr $k.turns | Where-Object { $_.key -notin 'done', 'wait' -and $_.sent -ne $true }).Count) { $why += 'a scancode send failed' }
    $res = @(Arr $r.flow.results | ForEach-Object { $_.data }) | Select-Object -Last 1
    if (-not ($res -and $res.kind -eq 'result')) { $why += "answer $($res.kind)" }
    elseif (@(Arr $o.resume_outcomes) -notcontains "$($res.response.result.outcome)") { $why += "outcome $($res.response.result.outcome)" }
    $shots = @(if ($sum) { Get-Shots $Ev $sum })
    foreach ($s in Arr $o.required_shots) { if ($shots -notcontains $s) { $why += "screenshot $s missing" } }
    if (-not @($shots | Where-Object { $_ -like 'own-3-after-*' }).Count) { $why += 'no screenshot after the keys' }
    Add-Row 'journal.resume through the broker dialog, answered by scancode' $why "$($res.response.result.outcome)"

    $why = @()
    if (-not $r.sddl_after) { $why += 'no descriptor after the resume' }
    elseif ("$($r.sddl_after)" -cne $rec) { $why += "after the resume $($r.sddl_after), recorded $rec" }
    Add-Row 'owner restored: Guarded descriptor equals the recorded one (G8)' $why "$($r.sddl_after)"

    $why = @()
    $tb = @(Arr $e.tree_before) -join "`n"; $ta = @(Arr $r.tree_after) -join "`n"
    if (-not $tb) { $why += 'no service tree before' } elseif ($ta -cne $tb) { $why += "the service tree differs: $(@(Compare-Object @(Arr $e.tree_before) @(Arr $r.tree_after) | Select-Object -First 4 | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }) -join ' | ')" }
    Add-Row 'service tree (keys, values, descriptors) as before the execute' $why "$(@(Arr $r.tree_after).Count) lines"

    $why = @()
    if (@(Arr $r.pending_after.sessions).Count) { $why += "still pending: $(@(Arr $r.pending_after.sessions) -join ',')" }
    if (@(Arr $o.history_states) -notcontains "$($r.pending_after.history_state)") { $why += "history state $($r.pending_after.history_state)" }
    Add-Row 'session closed: nothing pending, history Undone' $why "$($r.pending_after.history_state)"

    $p = $r.privmon
    $why = @()
    if (-not ($p -and $p.state -eq 'done' -and [long]$p.samples -gt 0)) { $why += "privilege monitor $($p.state), $($p.samples) samples" }
    else {
        if ([long]$p.process_token_held_samples -le 0) { $why += 'the process token was never read' }
        if ([long]$p.process_token_enabled_samples -ne 0) { $why += "SeRestorePrivilege enabled in the process token in $($p.process_token_enabled_samples) samples" }
        if (@(Arr $p.impersonating_at_last_sample).Count) { $why += "threads still impersonating at the end: $(@(Arr $p.impersonating_at_last_sample | ForEach-Object { $_.tid }) -join ',')" }
        if (@(Arr $p.episodes | Where-Object { $_.restore_enabled_seen -eq $true -and $null -eq $_.t_off }).Count) { $why += 'an impersonation with the privilege on never ended' }
    }
    $brokerAudit = @(Arr $r.audit | Where-Object { "$($_.process)" -match 'purge-broker\.exe$' })
    $outside = @($brokerAudit | Where-Object { $_.id -eq 4674 -and "$($_.object)" -notmatch $o.audit_object_pattern })
    if ($outside.Count) { $why += "SeRestorePrivilege used on other objects: $(@($outside | ForEach-Object { $_.object }) -join ', ')" }
    $seen = ([long]$p.thread_restore_enabled_samples -gt 0) -or (@($brokerAudit | Where-Object { $_.id -eq 4674 }).Count -gt 0)
    if (-not $seen) { $why += 'no evidence that the privilege was used at all (no thread sample, no audit event)' }
    Add-Row 'privilege scope (T10): only on a thread token, only on the service keys, off at the end' $why "thread samples on $($p.thread_restore_enabled_samples), audit $($brokerAudit.Count)"

    $bad = @(Arr $r.events | Where-Object { [int]$_.id -ge 20 -and [int]$_.id -le 27 })
    Add-Row 'no broker start failures in the event log' @($(if ($bad.Count) { "events $(@($bad | ForEach-Object { $_.id }) -join ',')" })) "$(@(Arr $r.events).Count) Purge events"
}

# ----------------------------------------------------------------------------------------------- recover

function Test-Recover([string]$Ev, $X) {
    $sum = Read-J (Join-Path $Ev 'summary.json')
    Row 'evidence summary.json' ($null -ne $sum) $(if (-not $sum) { 'missing or unreadable' })
    if (-not $sum) { return }
    $xr = $X.recover
    $plan = $sum.plan
    $cd = Join-Path $Ev 'rounds\cal\guest\round'
    Test-UacSilent (Read-J (Join-Path $Ev 'rounds\cal\guest\uac-silent.json')) (Read-J (Join-Path $Ev 'rounds\cal\guest\uac-check.json')) $X.uac_admin
    $cal = Read-J (Join-Path $cd 'arm.json')
    $pre = Read-J (Join-Path $cd 'truth-rec-pre.json')
    $complete = Read-J (Join-Path $cd 'truth-rec-complete.json')
    $why = @()
    if (-not $plan) { $why += 'no plan in the summary' }
    if (-not $cal) { $why += 'no calibration record' }
    else {
        if ($cal.watch.state -ne 'recorded') { $why += "calibration watcher $($cal.watch.state)" }
        if ($plan -and [int]$cal.watch.lines -ne [int]$plan.n) { $why += "calibration journal $($cal.watch.lines) lines, plan N $($plan.n)" }
        if (-not $cal.store -or -not $cal.store.index_listed -or $cal.store.index_state -ne 'Committed') { $why += "calibration session $($cal.store.index_state)" }
    }
    if (-not $pre -or -not $complete) { $why += 'calibration truths missing' }
    elseif ((Get-TruthKey $pre) -ceq (Get-TruthKey $complete)) { $why += 'the uninterrupted run changed nothing on disk' }
    Add-Row 'calibration: an uninterrupted run, N journal lines, committed' $why "N=$($plan.n)"
    if (-not $plan -or -not $pre -or -not $complete) { return }
    $preKey = Get-TruthKey $pre; $completeKey = Get-TruthKey $complete
    $calOps = @(Arr $cal.store.quarantine_ops).Count

    $why = @()
    if ($plan.subset -eq $true) { $why += 'a run over -Steps is not gate evidence' }
    $rounds = @(Arr $sum.rounds)
    foreach ($k in 1..([int]$plan.n)) { foreach ($a in Arr $xr.afters) { $nm = 'k{0:D2}-{1}' -f $k, $a; if (-not @($rounds | Where-Object { $_.name -eq $nm }).Count) { $why += "no round $nm" } } }
    if ($xr.require_ui -and $plan.ui -ne $true) { $why += 'the run did not use the real UI' }
    Add-Row "coverage: every journal step 1..$($plan.n) x $(@(Arr $xr.afters) -join '/')" $why "$($rounds.Count) rounds"

    $shots = @(Get-Shots $Ev $sum)
    $pendingPerAfter = @{}
    foreach ($rd in $rounds | Sort-Object { [int]$_.k }, { "$($_.after)" }) {
        $nm = "$($rd.name)"; $k = [int]$rd.k; $a = "$($rd.after)"
        $g = Join-Path $Ev "rounds\$nm\guest\round"
        $arm = Read-J (Join-Path $g 'arm.json'); $boot = Read-J (Join-Path $g 'boot.json')
        $why = @()
        if ($rd.error) { $why += "rig: $($rd.error)" }
        if (-not $arm) { $why += 'no arm record' }
        elseif ($arm.watch.state -ne 'suspended' -or [int]$arm.watch.lines_seen_at_hit -lt $k) { $why += "watcher $($arm.watch.state) at $($arm.watch.lines_seen_at_hit) lines" }
        if (-not $boot) { $why += 'no boot record'; Add-Row "round $nm" $why; continue }
        if ($boot.boot_changed -ne $true) { $why += 'the VM did not restart (boot time unchanged)' }
        $class = "$($boot.class)"
        if (@(Arr $xr.classes) -notcontains $class) { $why += "class $class" }
        $rpre = Read-J (Join-Path $g 'truth-rec-pre.json')
        if ((Get-TruthKey $rpre) -cne $preKey) { $why += "the round started from another state: $((Get-TruthDiff $rpre $pre) -join ', ')" }
        $after = Read-J (Join-Path $g 'truth-rec-after.json')
        if (-not $after -and $class -in 'none', 'finished') { $after = Read-J (Join-Path $g 'truth-rec-boot.json') }
        $want = $(if ($class -eq 'pending' -and $a -eq 'rollback') { 'pre' } elseif ($class -eq 'none') { 'pre' } else { 'complete' })
        $ak = Get-TruthKey $after
        if (-not $after) { $why += 'no disk truth after the recovery' }
        elseif ($ak -cne $preKey -and $ak -cne $completeKey) { $why += "half state on disk: neither the start nor the finished run ($((Get-TruthDiff $after $complete) -join ', ') differ from the finished run)" }
        elseif (($want -eq 'pre' -and $ak -cne $preKey) -or ($want -eq 'complete' -and $ak -cne $completeKey)) { $why += "disk at the $(if ($ak -ceq $preKey) { 'start' } else { 'finished run' }), expected the $(if ($want -eq 'pre') { 'start' } else { 'finished run' })" }
        if ($class -eq 'pending') {
            $pendingPerAfter[$a] = 1 + [int]$pendingPerAfter[$a]
            $ui = Read-J (Join-Path $g 'ui.json'); $rs = Read-J (Join-Path $g 'recover-start.json'); $res = Read-J (Join-Path $g 'result.json')
            if ($xr.require_ui) {
                if (-not ($ui -and $ui.banner -eq $true -and $ui.buttons -eq $true)) { $why += 'the UI''s History page did not show the interrupted session (banner, Resume, Roll back)' }
                if ($shots -notcontains "$nm-1-banner") { $why += 'screenshot of the banner missing' }
                if ($rs -and $rs.via -ne 'ui') { $why += "recovery started via $($rs.via), not the UI" }
            }
            if (-not ($rs -and $rs.dialog -and $rs.dialog.found -eq $true)) { $why += 'no consent dialog' }
            else {
                if ($rs.dialog.broker_il -ne 'high') { $why += "dialog at $($rs.dialog.broker_il)" }
                if ("$($rs.dialog.labels.primary)" -ne "$($xr.labels.$a)") { $why += "button '$($rs.dialog.labels.primary)', expected '$($xr.labels.$a)'" }
                if (-not $rs.dialog.footer_code) { $why += 'no code in the footer' }
            }
            if ($shots -notcontains "$nm-2-dialog") { $why += 'screenshot of the consent dialog missing' }
            $keys = $(if ($sum.keys) { $sum.keys.$nm })
            if (-not ($keys -and $keys.answered -eq $true)) { $why += 'the dialog was not answered by the host''s keys' }
            elseif (@(Arr $keys.turns | Where-Object { $_.key -notin 'done', 'wait' -and $_.sent -ne $true }).Count) { $why += 'a scancode send failed' }
            if (-not $res) { $why += 'no result record' }
            else {
                if (@(Arr $res.pending_after.sessions).Count) { $why += "still pending after: $(@(Arr $res.pending_after.sessions) -join ',')" }
                if (-not $res.store.index_listed) { $why += 'the index does not list the session' }
                elseif (@(Arr $xr.index_states.$a) -notcontains "$($res.store.index_state)") { $why += "index state $($res.store.index_state)" }
                if (@(Arr $xr.index_states.$a) -notcontains "$($res.pending_after.history_state)") { $why += "history state $($res.pending_after.history_state)" }
                $qops = @(Arr $res.store.quarantine_ops)
                if ($a -eq 'resume') {
                    if ($qops.Count -ne $calOps) { $why += "quarantine holds $($qops.Count) op folders, the finished run $calOps" }
                    if (@($qops | Where-Object { [int]$_.files -lt 1 }).Count) { $why += 'an op folder of the quarantine is empty' }
                } elseif (@($qops | Where-Object { [int]$_.files -gt 0 }).Count) { $why += "rollback left files in quarantine: $(@($qops | Where-Object { [int]$_.files -gt 0 } | ForEach-Object { $_.op }) -join ',')" }
                $bad = @(Arr $res.events | Where-Object { @(Arr $xr.start_failure_events) -contains [int]$_.id })
                if ($bad.Count) { $why += "broker start failures $(@($bad | ForEach-Object { $_.id }) -join ',')" }
            }
        } elseif ($class -eq 'unindexed') {
            $bk = Read-J (Join-Path $g 'bookkeeping.json')
            if (-not $bk) { $why += 'no bookkeeping record' }
            else {
                if ($bk.dialog_shown -ne $false) { $why += 'the bookkeeping opened a dialog' }
                if (-not $bk.store.index_listed -or $bk.store.index_state -ne 'Committed') { $why += "index after the bookkeeping $($bk.store.index_state)" }
                if (@(Arr $bk.pending_after.sessions).Count) { $why += 'still pending' }
            }
        } else {
            if (@(Arr $boot.pending.sessions).Count) { $why += "class $class, but pending lists $(@(Arr $boot.pending.sessions) -join ',')" }
        }
        Add-Row "round $nm ($class)" $why "disk = $want"
    }
    $why = @()
    foreach ($a in Arr $xr.afters) { if ([int]$pendingPerAfter[$a] -lt [int]$xr.min_pending_rounds_per_after) { $why += "$a`: $([int]$pendingPerAfter[$a]) rounds reached a recovery" } }
    Add-Row 'recoveries reached through consent (each after)' $why "$(@($pendingPerAfter.Keys | ForEach-Object { "$_=$($pendingPerAfter[$_])" }) -join ' ')"
}

# ------------------------------------------------------------------------------------------------ extras

function Test-Extras([string]$Ev, $X) {
    $doc = Read-J (Join-Path $Ev 'guest\m3-extras.json')
    Row 'evidence guest\m3-extras.json' ($null -ne $doc) $(if (-not $doc) { 'missing or unreadable' })
    if (-not $doc) { return }
    $xe = $X.extras
    Test-UacSilent $doc.uac_silent $doc.uac $X.uac_admin

    # allow_irreversible
    $ir = $doc.irrev
    $why = @()
    if (-not $ir) { $why += 'no record' }
    elseif (-not @(Arr $ir.package_rows).Count) { $why += 'the scan offered no package (Notepad++''s sparse package is the fixture)' }
    Add-Row 'irreversible: a package candidate (fixture)' $why "$(@(Arr $ir.package_rows).Count) package rows"
    $shown = @(Arr $ir.flow.shown | ForEach-Object { "$($_.file)" })
    $results = @(Arr $ir.flow.results | ForEach-Object { $_.data })
    $ap = @(Arr $ir.flow.autopress | ForEach-Object { $_.data } | Sort-Object { [int]$_.n })
    $why = @()
    if (-not $ir.off) { $why += 'no run with the flag off' }
    else {
        $k1 = @(Arr $ir.off.asks | ForEach-Object { [int]$_.k }) | Select-Object -First 1
        if ($shown -contains "consent-shown-$k1.json") { $why += 'the run with the flag off opened a dialog' }
        if (-not @(Arr $ir.package_rows_on).Count) { $why += 'the package was gone after the run with the flag off' }
    }
    Add-Row 'irreversible off: "Leave alone", no dialog, the package stays' $why
    $why = @()
    $d1 = $ap | Select-Object -First 1
    if (-not $d1) { $why += 'no dialog with the flag on' }
    else {
        if ($d1.action -ne 'cancel') { $why += "first dialog answered $($d1.action)" }
        if (-not $d1.pre.verify) { $why += 'no verification box' }
        if ($d1.pre.primary_enabled -ne $false) { $why += 'the primary button was enabled before the box was ticked' }
        if (-not @(Arr $d1.pre.texts | Where-Object { "$_" -like "*$($xe.irrev_dialog_text)*" }).Count) { $why += "the dialog does not say '$($xe.irrev_dialog_text)'" }
        if ([int]$d1.pre.attention_total -lt 1) { $why += 'the package is not an attention entry' }
    }
    $r2 = @($results | Where-Object { $_.method -eq 'plan.execute' -and $_.kind -eq 'consent_declined' }).Count
    if ($r2 -lt 1) { $why += 'no declined plan.execute' }
    Add-Row 'irreversible on: the dialog names it, box-gated; Cancel removes nothing' $why
    $why = @()
    $d2 = $ap | Select-Object -Skip 1 -First 1
    $ok = @($results | Where-Object { $_.method -eq 'plan.execute' -and $_.kind -eq 'result' }) | Select-Object -Last 1
    if (-not $d2 -or $d2.action -ne 'approve' -or $d2.ticked -ne $true) { $why += 'no ticked approval' }
    if (-not $ok) { $why += 'no executed plan' } elseif ("$($ok.response.result.outcome)" -ne 'complete') { $why += "outcome $($ok.response.result.outcome)" }
    if ([int]$ir.packages_after -ne 0) { $why += "$($ir.packages_after) package(s) still registered" }
    $u = $ir.undo
    if (-not $u) { $why += 'no undo record' } elseif (-not (Has $u 'error') -and "$($u.result.outcome)" -eq 'complete') { $why += 'the undo claims to have put the package back' }
    Add-Row 'irreversible approved: removed; undo cannot put it back' $why

    # Restart Manager
    $rm = $doc.rm
    $ex = $rm.exec
    $why = @()
    if (-not $ex) { $why += 'no record' }
    else {
        if ("$($ex.exec_result.result.outcome)" -ne $xe.rm_outcome) { $why += "outcome $($ex.exec_result.result.outcome), expected $($xe.rm_outcome)" }
        $h = @(Arr $ex.exec_result.result.held | Where-Object { "$($_.display_name)" -like "*$($xe.rm_held_file)*" }) | Select-Object -First 1
        if (-not $h) { $why += "no held item $($xe.rm_held_file)" }
        elseif (-not @(Arr $h.lockers | Where-Object { [int]$_.pid -eq [int]$ex.lockers.held.pid }).Count) { $why += "the held item names lockers $(@(Arr $h.lockers | ForEach-Object { "$($_.name)($($_.pid))" }) -join ','), not the running app ($($ex.lockers.held.pid))" }
        if ($ex.lockers.held.held -ne $true -or $ex.lockers.boot.held -ne $true) { $why += 'a locker did not hold its file' }
    }
    Add-Row 'Restart Manager: the locked file is held and its locker named' $why
    $why = @()
    if ($ex) {
        if ($ex.lockers_alive.held -ne $true -or $ex.lockers_alive.boot -ne $true) { $why += 'Purge closed a running app' }
        if ($ex.sources_present.held -ne $true) { $why += 'the held file was moved' }
    } else { $why += 'no record' }
    Add-Row 'Restart Manager: report-only, nothing closed' $why
    $why = @()
    if ($ex) {
        $new = @(Arr $ex.pfro_after | Where-Object { @(Arr $ex.pfro_before) -notcontains $_ })
        if (-not @($new | Where-Object { "$_" -like "*$($xe.rm_boot_file)" }).Count) { $why += 'no boot-time move registered for the file in Program Files' }
        elseif (-not @($new | Where-Object { "$_" -like "*$($xe.rm_quarantine_marker)*" }).Count) { $why += 'the boot-time move does not go into the quarantine' }
    } else { $why += 'no record' }
    $b = $rm.boot
    if (-not $b) { $why += 'no record after the restart' }
    else {
        if ($b.boot_before -eq $b.boot_after) { $why += 'the guest did not restart' }
        if ($b.source_present -ne $false) { $why += 'the file is still at its place after the restart' }
        if (-not @(Arr $b.in_quarantine).Count) { $why += 'the file is not in the quarantine after the restart' }
    }
    Add-Row 'Restart Manager: Program Files file moved into quarantine at the restart' $why
    $why = @()
    $t = $rm.retry
    if (-not $t) { $why += 'no record' }
    else {
        if ($t.held_locker_alive -ne $false) { $why += 'the locker was still running' }
        $tr = @(Arr $t.result) | Select-Object -Last 1
        if (-not ($tr -and $tr.kind -eq 'result' -and "$($tr.response.result.outcome)" -eq 'complete')) { $why += "retry answer $($tr.kind) $($tr.response.result.outcome)" }
        if ($t.source_present -ne $false) { $why += 'the file is still at its place' }
    }
    Add-Row 'Restart Manager: retry_held through consent after the app closed' $why

    # System Restore
    foreach ($case in 'off', 'disabled', 'created', 'throttled') {
        $s = $doc.sr.$case; $e = $xe.sr.$case
        $why = @()
        # rig-base has System Restore off: the mode turns it on at start (sr-enable.json); every case needs that record.
        if (-not ($doc.sr_enable -and $doc.sr_enable.ok -eq $true -and "$($doc.sr_enable.rp_session_interval_after)" -eq '1')) { $why += "System Restore not enabled at mode start (sr-enable: $(if ($doc.sr_enable) { "after $($doc.sr_enable.rp_session_interval_after)" } else { 'no record' }))" }
        if (-not $s) { $why += 'no record' }
        else {
            $rp = $s.exec_result.result.restore_point
            if ("$($rp.kind)" -ne "$($e.kind)") { $why += "restore point $($rp.kind), expected $($e.kind)" }
            $texts = @(Arr $s.plan_dialog | ForEach-Object { Arr $_.texts })
            $line = [bool]@($texts | Where-Object { "$_" -match [regex]::Escape($xe.restore_point_text) }).Count
            if (-not @(Arr $s.plan_dialog).Count) { $why += 'the plan dialog was not observed' }
            elseif ($line -ne [bool]$e.dialog_line) { $why += "restore-point line in the dialog: $line, expected $($e.dialog_line)" }
            if ($null -ne $e.new_point) {
                $before = @(Arr $s.points_before | ForEach-Object { [long]$_.sequence })
                $new = @(Arr $s.points_after | Where-Object { $before -notcontains [long]$_.sequence })
                if ($e.new_point -and -not @($new | Where-Object { [long]$_.sequence -eq [long]$rp.sequence }).Count) { $why += "no new restore point with sequence $($rp.sequence)" }
                if (-not $e.new_point -and $new.Count) { $why += "a new restore point appeared: $(@($new | ForEach-Object { $_.sequence }) -join ',')" }
            }
        }
        Add-Row "System Restore $case" $why "$($s.exec_result.result.restore_point.kind)"
    }
}

# ---------------------------------------------------------------------------------------------------- run

function Invoke-Score([string]$M, [string]$Ev, $X, [switch]$Quiet) {
    $script:Rows = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $Ev -PathType Container)) { Row 'evidence directory' $false "missing: $Ev" }
    else {
        try { switch ($M) { 'owner' { Test-Owner $Ev $X } 'recover' { Test-Recover $Ev $X } 'extras' { Test-Extras $Ev $X } } }
        catch { Row 'scorer' $false "error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)" }
    }
    $pass = ($script:Rows.Count -gt 0) -and -not @($script:Rows | Where-Object { -not $_.ok }).Count
    if (-not $Quiet) {
        foreach ($r in $script:Rows) { Write-Host ("{0}  {1}{2}" -f $(if ($r.ok) { 'PASS' } else { 'FAIL' }), $r.row, $(if ($r.detail) { "  ($($r.detail))" })) }
        Write-Host "m3-$M $(if ($pass) { 'PASS' } else { 'FAIL' }) ($(@($script:Rows | Where-Object { $_.ok }).Count)/$($script:Rows.Count) rows)"
    }
    [ordered]@{ mode = $M; pass = $pass; rows = @($script:Rows) }
}

# ---------------------------------------------------------------------------------------------- self-test

function Write-J($O, [string]$Path) {
    New-Item -ItemType Directory -Force (Split-Path -Parent $Path) | Out-Null
    [IO.File]::WriteAllText($Path, (ConvertTo-Json $O -Depth 30), (New-Object Text.UTF8Encoding($false)))
}
function New-Shots([string]$Dir, [string[]]$Names) {
    $list = @()
    foreach ($n in $Names) { [IO.File]::WriteAllBytes((Join-Path $Dir "$n.png"), [byte[]](137, 80, 78, 71)); $list += [ordered]@{ name = $n; file = "$n.png"; bytes = 4 } }
    $list
}
function New-Truth([string]$Label, [string]$State) {
    $files = switch ($State) { 'pre' { @('D|data', 'F|data\a.dat|AA', 'F|data\b.dat|BB', 'F|uninst.exe|CC') } 'complete' { $null } 'half' { @('D|data', 'F|data\b.dat|BB') } }
    $key = switch ($State) { 'pre' { @('K|', 'V||Mode|DWord|7') } 'complete' { $null } 'half' { @('K|', 'V||Mode|DWord|7') } }
    [ordered]@{ fixture = 'rec'; label = $Label; roots = @([ordered]@{ root = 'C:\Program Files\PurgeRigRec'; exists = ($null -ne $files); lines = @($files) },
                                                          [ordered]@{ root = 'HKLM\SOFTWARE\PurgeRigRec'; exists = ($null -ne $key); lines = @($key) }) }
}

function New-OwnerPass($X) {
    $rec = 'O:SYG:SYD:P(A;CI;0x7003f;;;SY)(A;CI;0x7003f;;;BA)(A;CI;KR;;;BU)'
    $tree = @('K|', "K|Parameters\Guarded|$rec", 'V|Parameters\Guarded|Level|DWord|1')
    $doc = [ordered]@{
        uac = [ordered]@{ ConsentPromptBehaviorAdmin = 0 }
        uac_silent = [ordered]@{ ok = $true; before = [ordered]@{ ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1; EnableLUA = 1 }; after = [ordered]@{ ConsentPromptBehaviorAdmin = 0; PromptOnSecureDesktop = 1; EnableLUA = 1 } }
        fixture = [ordered]@{ service = [ordered]@{ guarded_sddl = $rec } }
        exec = [ordered]@{ session = '20261122T101500Z-0123456789abcdef'; sddl_recorded = $rec; tree_before = $tree; exec_result = [ordered]@{ result = [ordered]@{ outcome = 'complete' } }
                           service_after = $false; service_candidate = [ordered]@{ kind = 'service'; display_name = 'PurgeRigOwnSvc' } }
        cut = [ordered]@{ service_op = 3; watch = [ordered]@{ state = 'suspended_killed'; hit_line = 14; hit_text = '{"rec":"undo_intent","op":3,"x":1}' }; listed = $true
                          half_sddl = ($rec -replace '^O:SY', 'O:BA') }
        resume = [ordered]@{
            start = [ordered]@{ dialog = [ordered]@{ found = $true; broker_il = 'high'; labels = [ordered]@{ primary = 'Finish the cleanup' }; footer_code = 'A1B2-C3D4' } }
            flow = [ordered]@{ results = @([ordered]@{ file = 'consent-result-1.json'; data = [ordered]@{ kind = 'result'; response = [ordered]@{ result = [ordered]@{ outcome = 'complete' } } } }) }
            sddl_after = $rec; tree_after = $tree
            pending_after = [ordered]@{ sessions = @(); history_state = 'Undone' }
            privmon = [ordered]@{ state = 'done'; samples = 900; process_token_held_samples = 900; process_token_enabled_samples = 0; thread_restore_enabled_samples = 2
                                  impersonating_at_last_sample = @(); episodes = @([ordered]@{ tid = 7; t_on = 'a'; t_off = 'b'; restore_enabled_seen = $true }) }
            audit = @([ordered]@{ id = 4674; process = 'C:\Program Files\Purge\purge-broker.exe'; object = '\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\PurgeRigOwnSvc\Parameters\Guarded'; privileges = 'SeRestorePrivilege' })
            events = @()
        }
    }
    $sum = [ordered]@{ keys = [ordered]@{ own = [ordered]@{ answered = $true; turns = @([ordered]@{ key = 'shift-tab'; sent = $true }, [ordered]@{ key = 'space'; sent = $true }, [ordered]@{ key = 'done'; sent = $null }) } } }
    @($doc, $sum, @('own-2-dialog', 'own-3-after-01-shift-tab', 'own-3-after-02-space'))
}

function New-RecoverPass($X, [string]$Dir, [int]$N = 3) {
    $cal = Join-Path $Dir 'rounds\cal\guest\round'
    Write-J ([ordered]@{ watch = [ordered]@{ state = 'recorded'; lines = $N }; store = [ordered]@{ index_listed = $true; index_state = 'Committed'; quarantine_ops = @([ordered]@{ op = '1'; files = 1 }, [ordered]@{ op = '2'; files = 1 }) } }) (Join-Path $cal 'arm.json')
    Write-J (New-Truth 'pre' 'pre') (Join-Path $cal 'truth-rec-pre.json')
    Write-J ([ordered]@{ ok = $true; before = [ordered]@{ ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1; EnableLUA = 1 }; after = [ordered]@{ ConsentPromptBehaviorAdmin = 0; PromptOnSecureDesktop = 1; EnableLUA = 1 } }) (Join-Path (Split-Path -Parent $cal) 'uac-silent.json')
    Write-J ([ordered]@{ ConsentPromptBehaviorAdmin = 0; PromptOnSecureDesktop = 1; EnableLUA = 1 }) (Join-Path (Split-Path -Parent $cal) 'uac-check.json')
    Write-J (New-Truth 'complete' 'complete') (Join-Path $cal 'truth-rec-complete.json')
    $rounds = @(); $keys = [ordered]@{}; $shots = @()
    for ($k = 1; $k -le $N; $k++) {
        foreach ($a in 'resume', 'rollback') {
            $nm = 'k{0:D2}-{1}' -f $k, $a
            $g = Join-Path $Dir "rounds\$nm\guest\round"
            $class = $(if ($k -eq $N) { 'finished' } else { 'pending' })
            Write-J ([ordered]@{ watch = [ordered]@{ state = 'suspended'; lines_seen_at_hit = $k; lines_at_suspend = $k } }) (Join-Path $g 'arm.json')
            Write-J ([ordered]@{ class = $class; boot_changed = $true; pending = [ordered]@{ sessions = @($(if ($class -eq 'pending') { 's1' })) } }) (Join-Path $g 'boot.json')
            Write-J (New-Truth 'pre' 'pre') (Join-Path $g 'truth-rec-pre.json')
            if ($class -eq 'pending') {
                Write-J ([ordered]@{ banner = $true; buttons = $true }) (Join-Path $g 'ui.json')
                Write-J ([ordered]@{ via = 'ui'; dialog = [ordered]@{ found = $true; broker_il = 'high'; labels = [ordered]@{ primary = "$($X.recover.labels.$a)" }; footer_code = 'A1B2-C3D4' } }) (Join-Path $g 'recover-start.json')
                $st = $(if ($a -eq 'resume') { 'Committed' } else { 'Undone' })
                $q = $(if ($a -eq 'resume') { @([ordered]@{ op = '1'; files = 1 }, [ordered]@{ op = '2'; files = 1 }) } else { @([ordered]@{ op = '1'; files = 0 }) })
                Write-J ([ordered]@{ pending_after = [ordered]@{ sessions = @(); history_state = $st }; store = [ordered]@{ index_listed = $true; index_state = $st; quarantine_ops = $q }; events = @() }) (Join-Path $g 'result.json')
                Write-J (New-Truth 'after' $(if ($a -eq 'resume') { 'complete' } else { 'pre' })) (Join-Path $g 'truth-rec-after.json')
                $keys[$nm] = [ordered]@{ answered = $true; turns = @([ordered]@{ key = 'shift-tab'; sent = $true }, [ordered]@{ key = 'space'; sent = $true }, [ordered]@{ key = 'done' }) }
                $shots += "$nm-1-banner", "$nm-2-dialog", "$nm-3-after-02-space"
            } else {
                Write-J (New-Truth 'boot' 'complete') (Join-Path $g 'truth-rec-boot.json')
            }
            $rounds += [ordered]@{ name = $nm; k = $k; after = $a; error = $null }
        }
    }
    $sum = [ordered]@{ plan = [ordered]@{ n = $N; steps = @(1..$N); afters = @('resume', 'rollback'); ui = $true; subset = $false }; rounds = $rounds; keys = $keys }
    @($sum, $shots)
}

function New-ExtrasPass {
    $pkg = @([ordered]@{ kind = 'package'; band = 'Likely'; display_name = 'NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww' })
    $pre1 = [ordered]@{ found = $true; verify = [ordered]@{ toggle = 'Off' }; primary_enabled = $false; attention_total = 1; texts = @('Remove 1 item. 1 cannot be put back.') }
    $irrev = [ordered]@{
        package_rows = $pkg; package_rows_on = $pkg
        off = [ordered]@{ asks = @([ordered]@{ k = 1; kind = 'plan_refused' }) }
        flow = [ordered]@{
            shown = @([ordered]@{ file = 'consent-shown-2.json' }, [ordered]@{ file = 'consent-shown-3.json' })
            results = @([ordered]@{ data = [ordered]@{ k = 1; method = 'plan.execute'; kind = 'plan_refused' } }, [ordered]@{ data = [ordered]@{ k = 2; method = 'plan.execute'; kind = 'consent_declined' } },
                        [ordered]@{ data = [ordered]@{ k = 3; method = 'plan.execute'; kind = 'result'; response = [ordered]@{ result = [ordered]@{ outcome = 'complete' } } } })
            autopress = @([ordered]@{ data = [ordered]@{ n = 1; action = 'cancel'; pre = $pre1 } }, [ordered]@{ data = [ordered]@{ n = 2; action = 'approve'; ticked = $true; pre = $pre1 } })
        }
        packages_after = 0
        undo = [ordered]@{ error = [ordered]@{ message = 'nothing in the selection can be put back' } }
    }
    $rm = [ordered]@{
        exec = [ordered]@{ exec_result = [ordered]@{ result = [ordered]@{ outcome = 'partial'; held = @([ordered]@{ op = 4; display_name = 'C:\ProgramData\PurgeRigRm\locked.dat'; lockers = @([ordered]@{ pid = 4242; name = 'PurgeRigLocker' }) }) } }
                           lockers = [ordered]@{ held = [ordered]@{ pid = 4242; held = $true }; boot = [ordered]@{ pid = 4343; held = $true } }
                           lockers_alive = [ordered]@{ held = $true; boot = $true }; sources_present = [ordered]@{ held = $true; boot = $true }
                           pfro_before = @(); pfro_after = @('\??\C:\Program Files\PurgeRigRm\bin\locked.dll', '\??\C:\ProgramData\Purge\Quarantine\s\5\locked.dll') }
        retry = [ordered]@{ held_locker_alive = $false; result = @([ordered]@{ kind = 'result'; response = [ordered]@{ result = [ordered]@{ outcome = 'complete' } } }); source_present = $false }
        boot = [ordered]@{ boot_before = 'a'; boot_after = 'b'; source_present = $false; in_quarantine = @('C:\ProgramData\Purge\Quarantine\s\5\locked.dll') }
    }
    $dlgYes = @([ordered]@{ texts = @('Windows is asked for a restore point first.') }); $dlgNo = @([ordered]@{ texts = @('Move 2 items to quarantine?') })
    $sr = [ordered]@{
        off = [ordered]@{ exec_result = [ordered]@{ result = [ordered]@{ restore_point = [ordered]@{ kind = 'NotRequested' } } }; plan_dialog = $dlgNo }
        disabled = [ordered]@{ exec_result = [ordered]@{ result = [ordered]@{ restore_point = [ordered]@{ kind = 'Disabled' } } }; plan_dialog = $dlgYes }
        created = [ordered]@{ exec_result = [ordered]@{ result = [ordered]@{ restore_point = [ordered]@{ kind = 'Created'; sequence = 12 } } }; plan_dialog = $dlgYes
                              points_before = @([ordered]@{ sequence = 11 }); points_after = @([ordered]@{ sequence = 11 }, [ordered]@{ sequence = 12 }) }
        throttled = [ordered]@{ exec_result = [ordered]@{ result = [ordered]@{ restore_point = [ordered]@{ kind = 'Throttled' } } }; plan_dialog = $dlgYes
                                points_before = @([ordered]@{ sequence = 12 }); points_after = @([ordered]@{ sequence = 12 }) }
    }
    [ordered]@{ uac = [ordered]@{ ConsentPromptBehaviorAdmin = 0 }; uac_silent = [ordered]@{ ok = $true; before = [ordered]@{ ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1; EnableLUA = 1 }; after = [ordered]@{ ConsentPromptBehaviorAdmin = 0; PromptOnSecureDesktop = 1; EnableLUA = 1 } }; sr_enable = [ordered]@{ ok = $true; rp_session_interval_before = 0; rp_session_interval_after = 1 }; irrev = $irrev; rm = $rm; sr = $sr }
}

# Single defects; each must turn a passing evidence directory into a FAIL. owner and extras edit the guest document
# (or the summary with sum=$true), recover edits files of the round tree (act gets the directory).
function Get-Defects {
    @(
        @{ mode = 'owner'; name = 'no uac-silent record'; act = { param($d) $d.uac_silent = $null } },
        @{ mode = 'extras'; name = 'uac-silent left LUA off'; act = { param($d) $d.uac_silent.after.EnableLUA = 0 } },
        @{ mode = 'extras'; name = 'uac not silent when checked'; act = { param($d) $d.uac.ConsentPromptBehaviorAdmin = 5 } },
        @{ mode = 'recover'; name = 'no uac-silent record in the base'; act = { param($dir) Remove-Item -LiteralPath (Join-Path $dir 'rounds\cal\guest\uac-silent.json') } },
        @{ mode = 'extras'; name = 'System Restore not enabled at start'; act = { param($d) $d.sr_enable.ok = $false; $d.sr_enable.rp_session_interval_after = 0 } },
        @{ mode = 'extras'; name = 'no sr-enable record'; act = { param($d) $d.sr_enable = $null } },
        @{ mode = 'owner'; name = 'owner mismatch after the resume'; act = { param($d) $d.resume.sddl_after = ($d.resume.sddl_after -replace '^O:SY', 'O:BA') } },
        @{ mode = 'owner'; name = 'service tree differs'; act = { param($d) $d.resume.tree_after = @($d.resume.tree_after | Select-Object -SkipLast 1) } },
        @{ mode = 'owner'; name = 'privilege on in the process token'; act = { param($d) $d.resume.privmon.process_token_enabled_samples = 3 } },
        @{ mode = 'owner'; name = 'a thread still impersonating at the end'; act = { param($d) $d.resume.privmon.impersonating_at_last_sample = @([ordered]@{ tid = 7; restore_enabled = $false }) } },
        @{ mode = 'owner'; name = 'privilege used on another object'; act = { param($d) $d.resume.audit = @($d.resume.audit) + @([ordered]@{ id = 4674; process = 'C:\Program Files\Purge\purge-broker.exe'; object = '\REGISTRY\MACHINE\SOFTWARE\Other' }) } },
        @{ mode = 'owner'; name = 'no evidence the privilege was used'; act = { param($d) $d.resume.privmon.thread_restore_enabled_samples = 0; $d.resume.audit = @() } },
        @{ mode = 'owner'; name = 'half state already had the owner'; act = { param($d) $d.cut.half_sddl = $d.exec.sddl_recorded } },
        @{ mode = 'owner'; name = 'fixture DACL grants WRITE_OWNER'; act = { param($d) $d.exec.sddl_recorded = 'O:SYG:SYD:P(A;CI;KA;;;BA)'; $d.resume.sddl_after = 'O:SYG:SYD:P(A;CI;KA;;;BA)'; $d.fixture.service.guarded_sddl = 'O:SYG:SYD:P(A;CI;KA;;;BA)'; $d.cut.half_sddl = 'O:BAG:SYD:P(A;CI;KA;;;BA)' } },
        @{ mode = 'owner'; name = 'resume declined'; act = { param($d) $d.resume.flow.results[0].data.kind = 'consent_declined' } },
        @{ mode = 'owner'; name = 'still pending'; act = { param($d) $d.resume.pending_after.sessions = @('s') } },
        @{ mode = 'owner'; name = 'dialog not answered by keys'; sum = $true; act = { param($s) $s.keys.own.answered = $false } },
        @{ mode = 'owner'; name = 'consent screenshot missing'; shots = $true; act = { param($s) @($s | Where-Object { $_ -ne 'own-2-dialog' }) } },
        @{ mode = 'recover'; name = 'half state'; act = { param($dir) Write-J (New-Truth 'after' 'half') (Join-Path $dir 'rounds\k01-resume\guest\round\truth-rec-after.json') } },
        @{ mode = 'recover'; name = 'rollback ended at the finished run'; act = { param($dir) Write-J (New-Truth 'after' 'complete') (Join-Path $dir 'rounds\k02-rollback\guest\round\truth-rec-after.json') } },
        @{ mode = 'recover'; name = 'consent screenshot missing'; shots = $true; act = { param($s) @($s | Where-Object { $_ -ne 'k01-rollback-2-dialog' }) } },
        @{ mode = 'recover'; name = 'banner missing'; act = { param($dir) Write-J ([ordered]@{ banner = $false; buttons = $false }) (Join-Path $dir 'rounds\k02-resume\guest\round\ui.json') } },
        @{ mode = 'recover'; name = 'a round missing'; sum = $true; act = { param($s) $s.rounds = @($s.rounds | Where-Object { $_.name -ne 'k02-resume' }) } },
        @{ mode = 'recover'; name = 'a subset run'; sum = $true; act = { param($s) $s.plan.subset = $true } },
        @{ mode = 'recover'; name = 'not answered by keys'; sum = $true; act = { param($s) $s.keys.'k01-resume'.answered = $false } },
        @{ mode = 'recover'; name = 'session still pending'; act = { param($dir) $f = Join-Path $dir 'rounds\k01-rollback\guest\round\result.json'; $j = Read-J $f; $j.pending_after.sessions = @('s1'); Write-J $j $f } },
        @{ mode = 'recover'; name = 'rollback left files in quarantine'; act = { param($dir) $f = Join-Path $dir 'rounds\k01-rollback\guest\round\result.json'; $j = Read-J $f; $j.store.quarantine_ops = @([ordered]@{ op = '1'; files = 2 }); Write-J $j $f } },
        @{ mode = 'recover'; name = 'wrong index state'; act = { param($dir) $f = Join-Path $dir 'rounds\k02-resume\guest\round\result.json'; $j = Read-J $f; $j.store.index_state = 'Open'; Write-J $j $f } },
        @{ mode = 'recover'; name = 'not suspended at the step'; act = { param($dir) Write-J ([ordered]@{ watch = [ordered]@{ state = 'finished_before_target'; lines_seen_at_hit = 0 } }) (Join-Path $dir 'rounds\k01-resume\guest\round\arm.json') } },
        @{ mode = 'recover'; name = 'no restart'; act = { param($dir) $f = Join-Path $dir 'rounds\k02-rollback\guest\round\boot.json'; $j = Read-J $f; $j.boot_changed = $false; Write-J $j $f } },
        @{ mode = 'extras'; name = 'the flag off removed the package'; act = { param($d) $d.irrev.package_rows_on = @() } },
        @{ mode = 'extras'; name = 'no verification box'; act = { param($d) $d.irrev.flow.autopress[0].data.pre.verify = $null } },
        @{ mode = 'extras'; name = 'undo claims the package back'; act = { param($d) $d.irrev.undo = [ordered]@{ result = [ordered]@{ outcome = 'complete' } } } },
        @{ mode = 'extras'; name = 'a locker was closed'; act = { param($d) $d.rm.exec.lockers_alive.boot = $false } },
        @{ mode = 'extras'; name = 'held item without its locker'; act = { param($d) $d.rm.exec.exec_result.result.held[0].lockers = @() } },
        @{ mode = 'extras'; name = 'restore point not created'; act = { param($d) $d.sr.created.exec_result.result.restore_point = [ordered]@{ kind = 'Throttled' } } },
        @{ mode = 'extras'; name = 'restore-point line missing'; act = { param($d) $d.sr.disabled.plan_dialog = @([ordered]@{ texts = @('Move') }) } }
    )
}

function Invoke-SelfTest {
    $X = Get-Content -LiteralPath $ExpectFile -Raw | ConvertFrom-Json
    $root = Join-Path ([IO.Path]::GetTempPath()) ('m3-recover-score-selftest-' + [guid]::NewGuid().ToString('N'))
    function Check([string]$Name, [bool]$Cond) { $script:checks++; if ($Cond) { Write-Host "ok   $Name" } else { $script:fails++; Write-Host "FAIL $Name" } }
    $script:checks = 0; $script:fails = 0
    try {
        $build = {
            param([string]$M, $Defect)
            $dir = Join-Path $root ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Force (Join-Path $dir 'guest') | Out-Null
            $shots = @(); $sum = [ordered]@{}
            switch ($M) {
                'owner' { $t = New-OwnerPass $X; $doc = $t[0]; $sum = $t[1]; $shots = @($t[2]) }
                'extras' { $doc = New-ExtrasPass }
                'recover' { $t = New-RecoverPass $X $dir; $sum = $t[0]; $shots = @($t[1]); $doc = $null }
            }
            if ($doc) { $doc = (ConvertTo-Json $doc -Depth 30) | ConvertFrom-Json }
            $sum = (ConvertTo-Json $sum -Depth 30) | ConvertFrom-Json
            if ($Defect) {
                if ($Defect.shots) { $shots = @(& $Defect.act $shots) }
                elseif ($Defect.sum) { & $Defect.act $sum }
                elseif ($M -eq 'recover') { & $Defect.act $dir }
                else { & $Defect.act $doc }
            }
            if ($doc) { Write-J $doc (Join-Path $dir "guest\m3-$M.json") }
            $sum | Add-Member -NotePropertyName shots -NotePropertyValue @(New-Shots $dir $shots) -Force
            Write-J $sum (Join-Path $dir 'summary.json')
            $dir
        }
        foreach ($m in 'owner', 'recover', 'extras') {
            $r = Invoke-Score $m (& $build $m $null) $X -Quiet
            Check "$m synthetic pass passes" $r.pass
            if (-not $r.pass) { foreach ($row in $r.rows) { if (-not $row.ok) { Write-Host "       $($row.row): $($row.detail)" } } }
            $empty = Join-Path $root "empty-$m"; New-Item -ItemType Directory -Force $empty | Out-Null
            Check "$m empty evidence fails" (-not (Invoke-Score $m $empty $X -Quiet).pass)
            Check "$m missing directory fails" (-not (Invoke-Score $m (Join-Path $root "none-$m") $X -Quiet).pass)
        }
        foreach ($d in Get-Defects) {
            $r = Invoke-Score $d.mode (& $build $d.mode $d) $X -Quiet
            Check "$($d.mode) defect '$($d.name)' fails" (-not $r.pass)
        }
        # The pure helpers.
        Check 'sddl: owner and rest' ((Get-SddlOwner 'O:SYG:SYD:P(A;;KA;;;SY)') -eq 'SY' -and (Get-SddlRest 'O:BAG:SYD:P(A;;KA;;;SY)') -ceq 'G:SYD:P(A;;KA;;;SY)')
        Check 'sddl: WRITE_OWNER found in KA, 0xf003f, WO; not in 0x7003f, KR' ((Test-DaclWriteOwner 'D:(A;;KA;;;BA)') -and (Test-DaclWriteOwner 'D:(A;;0xf003f;;;BA)') -and (Test-DaclWriteOwner 'D:(A;;RCWO;;;BA)') -and
                                                                                 -not (Test-DaclWriteOwner 'D:P(A;CI;0x7003f;;;SY)(A;CI;KR;;;BU)'))
        Check 'truth: equal truths have equal keys, a changed line differs' (((Get-TruthKey (New-Truth 'a' 'pre')) -ceq (Get-TruthKey (New-Truth 'b' 'pre'))) -and ((Get-TruthKey (New-Truth 'a' 'pre')) -cne (Get-TruthKey (New-Truth 'a' 'half'))))
    } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "m3-recover-score self-test: $($script:checks - $script:fails)/$($script:checks) ok"
    if ($script:fails) { 1 } else { 0 }
}

if ($SelfTest) { exit (Invoke-SelfTest) }
if (-not $Mode -or -not $Evidence) { Write-Host 'usage: m3-recover-score.ps1 -Mode owner|recover|extras -Evidence <run dir>  |  --self-test'; exit 2 }
$X = Get-Content -LiteralPath $ExpectFile -Raw | ConvertFrom-Json
$res = Invoke-Score $Mode $Evidence $X
if (Test-Path -LiteralPath $Evidence -PathType Container) {
    [IO.File]::WriteAllText((Join-Path $Evidence "score-$Mode.json"), (ConvertTo-Json $res -Depth 6), (New-Object Text.UTF8Encoding($false)))
}
if ($res.pass) { exit 0 } else { exit 1 }
