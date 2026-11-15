# Purge rig, M2: boot-time moves (vm\RIG.md §11; docs\M2_DESIGN.json gate G4). Template: the host (rig.ps1
# New-M2JobText) replaces __RUN__, __MODE__ (m2-reboot), __STAGE__ and __OPTS__ and submits it as an agent job.
# Windows PowerShell 5.1. The trap items of group 'locked' (vm\truth\m2-traps.json): boot-admin-locked.file (admin
# directory, expected PendingReboot) and boot-uw-planted.file (user-writable ancestor, expected HeldRetry).
#
# Stages:
#   start           install, traps, PFRO before. Scenario U: both files locked, exec, PFRO checked (admin source
#                   added once, user-writable source never), undo before any reboot -> PFRO as before. Scenario R:
#                   locked again, deep A, exec, PFRO checked -> continuation 'reboot' to after-reboot.
#   after-reboot    recover twice, journal show, PFRO back to before, admin file gone from its path; undo, deep C,
#                   fidelity. Retry: the user-writable ancestor replaced by a junction (plant-boot-junction), the
#                   user-writable item executed again -> must be Skipped (ReparseMismatch / ChangedSinceScan), the
#                   canary intact. Scenario M: admin file locked, exec, the engine's PFRO pair taken out again and
#                   a decoy pair added (the boot move will not happen) -> continuation 'reboot' to after-mismatch.
#   after-mismatch  recover twice, journal show, admin file still at its path and unchanged, undo, fidelity,
#                   PFRO (minus the decoy) as before, final traps check.
# Engine calls: plan from-targets | exec --plan .. --confirm .. --select .. -o .. | undo --session <id> -o .. |
#   journal recover | journal show --session <id>.
$Run = '__RUN__'
$Mode = '__MODE__'
$Stage = '__STAGE__'
$OptsB64 = '__OPTS__'
if ($Run -eq ('__' + 'RUN__') -or $Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { Write-Host ("m2-reboot.ps1: bad or unreplaced run name '{0}'" -f $Run); exit 2 }
if ($Mode -ne 'm2-reboot') { Write-Host ("m2-reboot.ps1: bad or unreplaced mode '{0}'" -f $Mode); exit 2 }
if ($Stage -eq ('__' + 'STAGE__')) { $Stage = 'start' }
if (@('start', 'after-reboot', 'after-mismatch') -cnotcontains $Stage) { Write-Host ("m2-reboot.ps1: bad stage '{0}'" -f $Stage); exit 2 }
. C:\cr\guest\riglib.ps1

$Opts = ConvertFrom-M2Opts $OptsB64
$R = Open-M2Run $Run $Mode $Stage
$D = $R.dir
$S = $R.S
$Calls = $S.engine.calls
$TrapsPs = Join-Path $RigGuestDir 'm2-traps.ps1'
$Work = Join-Path $RigWork $Run
New-Item -ItemType Directory -Force $Work | Out-Null
$StateFile = Join-Path $D 'm2-reboot-state.json'
$TM = Join-Path $D 'm2-traps-manifest.json'
$TT = Join-Path $D 'm2-traps-targets.json'
$DecoySrc = 'C:\PurgeRigDecoy\decoy-not-there.bin'
$PhaseCount0 = $S.phases.Count

function Q([string]$s) { ConvertTo-EngineArg $s }
function F([string]$n) { Join-Path $D $n }
function Read-Json([string]$p) { if (Test-Path -LiteralPath $p) { [IO.File]::ReadAllText($p) | ConvertFrom-Json } else { $null } }
function Save-State($St) { Write-JsonFile $St $StateFile 10 }

function Invoke-Traps([string]$Arguments) {
    $x = Invoke-M2Script $TrapsPs ($Arguments + ' -OutDir ' + (Q $D))
    $x.exit
}

# The 'locked' items of the trap manifest: @{ admin = <item>; uw = <item> }.
function Get-LockedItems {
    $m = Read-Json $TM
    if (-not $m) { throw "no $TM" }
    $h = @{}
    foreach ($t in @($m.traps)) {
        foreach ($it in @($t.items)) {
            if ("$($it.group)" -ne 'locked') { continue }
            if ($t.id -eq 'boot-admin-locked') { $h.admin = $it } elseif ($t.id -eq 'boot-uw-planted') { $h.uw = $it }
        }
    }
    if (-not $h.admin -or -not $h.uw) { throw 'manifest has no boot-admin-locked / boot-uw-planted item in group locked' }
    $h
}

function New-PlanRec([string]$Tag, [string[]]$OnlyIds = @()) {
    $t = F "targets-$Tag.json"
    $ids = @(Write-M2Targets @($TT) 'locked' $t $OnlyIds)
    $plan = F "plan-$Tag.json"
    $null = Invoke-M2Engine -Step "plan-$Tag" -Arguments (New-M2PlanArgs $t $plan) -Calls $Calls
    $ph = Get-M2PlanHash $plan
    [pscustomobject][ordered]@{ tag = $Tag; targets = $t; plan = $plan; select = (Write-M2IdFile $ids (F "select-$Tag.json")); ids = $ids; plan_hash = $ph
        confirm = (Get-M2Confirm $ph $ids); session = $null; journal = $null; report = $null; exit = $null }
}

function Invoke-ExecRec($Rec) {
    $before = @(Get-M2Sessions)
    $rep = F "report-$($Rec.tag).json"
    $r = Invoke-M2Engine -Step "exec-$($Rec.tag)" -Arguments (New-M2ExecArgs $Rec.plan $Rec.confirm $Rec.select $rep) -Calls $Calls -StdoutFile (F "exec-$($Rec.tag).out") -NoThrow
    $s = $null
    if (Test-Path -LiteralPath $rep) { $s = "$((Read-Json $rep).session)"; $Rec.report = $rep }
    if (-not $s) { $s = Get-M2NewSession $before }
    $Rec.session = $s; $Rec.exit = $r.exit
    if ($s) { $Rec.journal = Join-Path (Get-M2SessionDir $s) 'journal.jsonl'; $null = Copy-M2Session $s $D "sess-$($Rec.tag)" }
    $r
}

function Invoke-Undo($Rec, [string]$Tag) {
    $u = Invoke-M2Engine -Step "undo-$Tag" -Arguments (New-M2UndoArgs $Rec.session '' '' (F "undo-$Tag.json")) -Calls $Calls -StdoutFile (F "undo-$Tag.out") -NoThrow
    $null = Copy-M2Session $Rec.session $D "sess-$Tag-undo"
    $u.exit
}

# The executor outcome of one item in a purge.exec/1 report (items[].item / outcome), as text.
function Get-ItemOutcome([string]$Report, [string]$Item) {
    $j = Read-Json $Report
    if (-not $j) { return $null }
    foreach ($it in @($j.items)) {
        if ("$($it.item)" -eq $Item) { $o = $it.outcome; if ($o -is [string]) { return $o }; return (ConvertTo-Json -InputObject $o -Depth 6 -Compress) }
    }
    $null
}

function Save-Pfro([string]$Tag) {
    $l = Get-PfroList
    $list = [string[]]@($l | Where-Object { $null -ne $_ } | ForEach-Object { "$_" })
    Write-JsonFile ([ordered]@{ tag = $Tag; time = (NowIso); present = ($null -ne $l); entries = $list }) (F "pfro-$Tag.json") 4
    # Callers collect with @(...): the entries come out one by one (none when the value is absent).
    $list
}

function Get-FileSha([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-RecoverShow($Rec, [string]$Tag, $Res) {
    $Res.recover_exit = (Invoke-M2Engine -Step "recover-$Tag-1" -Arguments (New-M2JournalArgs 'recover') -Calls $Calls -StdoutFile (F "recover-$Tag-1.out") -NoThrow).exit
    $Res.recover2_exit = (Invoke-M2Engine -Step "recover-$Tag-2" -Arguments (New-M2JournalArgs 'recover') -Calls $Calls -StdoutFile (F "recover-$Tag-2.out") -NoThrow).exit
    $Res.show_exit = (Invoke-M2Engine -Step "show-$Tag" -Arguments (New-M2JournalArgs 'show' $Rec.session) -Calls $Calls -StdoutFile (F "journal-show-$Tag.out") -NoThrow).exit
    $null = Copy-M2Session $Rec.session $D "sess-$Tag-recovered"
}

# ------------------------------------------------------------------------------------------------------ stages

function Invoke-Start {
    $St = [ordered]@{ schema = 'purge.rig.rebootstate/1'; pfro_before = @(); admin = $null; uw = $null; r = $null; m = $null; admin_sha = $null }
    $script:St = $St
    Phase 'edge-pause' { $S.edge_pause = Suspend-EdgeUpdate } $S
    Phase 'traps-pre' { $e = Invoke-Traps '-Stage pre-install'; if ($e -ne 0) { throw "m2-traps pre-install exit $e" } } $S
    Phase 'install' {
        $r1 = Invoke-M2Script $RigInstallScript ('-Engine ' + (Q $RigEngine) + ' -ReportPath ' + (Q (F 'install.json')))
        Set-M2Result $R 'install' ([ordered]@{ exit = $r1.exit })
        if ($r1.exit -ne 0) { throw "install.ps1 exited $($r1.exit)" }
        $S.engine.exe = Get-M2EngineExe
    } $S
    Phase 'traps-build' { $e = Invoke-Traps ''; if ($e -ne 0) { throw "m2-traps build exit $e" } } $S
    Phase 'pfro-before' {
        $St.pfro_before = @(Save-Pfro 'before')
        $li = Get-LockedItems
        $St.admin = "$($li.admin.target.path)"; $St.uw = "$($li.uw.target.path)"
        $St.admin_id = "$($li.admin.id)"; $St.uw_id = "$($li.uw.id)"
        $St.admin_sha = Get-FileSha $St.admin
        Save-State $St
    } $S
    if (-not $St.admin) { return }

    Phase 'scenario-u' {
        $res = [ordered]@{}
        $lk = Start-M2Locker @($St.admin, $St.uw) $Work
        $res.locker_ready = $lk.ready
        try {
            $rec = New-PlanRec 'u'
            $x = Invoke-ExecRec $rec
            $res.exec_exit = $x.exit
            $res.admin_outcome = Get-ItemOutcome $rec.report $St.admin_id
            $res.uw_outcome = Get-ItemOutcome $rec.report $St.uw_id
            $res.pfro_after_exec = Compare-PfroLists $St.pfro_before (Save-Pfro 'u-exec') @($St.admin) @($St.uw)
            $res.undo_exit = Invoke-Undo $rec 'u'
            $after = @(Save-Pfro 'u-undo')
            $cmp = Compare-PfroLists $St.pfro_before $after
            $res.pfro_after_undo = $cmp
            $res.pfro_restored = ($cmp.ok -and $after.Count -eq @($St.pfro_before).Count)
            $res.admin_unchanged = ((Get-FileSha $St.admin) -eq $St.admin_sha)
        } finally { Stop-M2Locker $lk }
        Set-M2Result $R 'scenario_u' $res
    } $S

    Phase 'scenario-r' {
        $res = [ordered]@{}
        $lk = Start-M2Locker @($St.admin, $St.uw) $Work
        $res.locker_ready = $lk.ready
        $rec = New-PlanRec 'r'
        $null = Invoke-M2Deep @($TM, $rec.targets) (F 'deep-r-a.json')
        $x = Invoke-ExecRec $rec
        $res.exec_exit = $x.exit
        $res.admin_outcome = Get-ItemOutcome $rec.report $St.admin_id
        $res.uw_outcome = Get-ItemOutcome $rec.report $St.uw_id
        $res.pfro_after_exec = Compare-PfroLists $St.pfro_before (Save-Pfro 'r-exec') @($St.admin) @($St.uw)
        $St.r = $rec
        Save-State $St
        Set-M2Result $R 'scenario_r' $res
        # The locker keeps both files open until the reboot ends it.
        $null = Request-RigContinuation $Run 'reboot' 'after-reboot' ([ordered]@{ session = $rec.session; locker_pid = $lk.pid })
    } $S
}

function Invoke-AfterReboot {
    $St = $script:St
    $m = Receive-RigContinuation $Run
    $rec = $St.r
    Phase 'reboot-check' {
        $res = [ordered]@{ boot_changed = ($m -and $m.boot_before -and $m.boot_after -and $m.boot_before -ne $m.boot_after) }
        Invoke-RecoverShow $rec 'r' $res
        $after = @(Save-Pfro 'r-boot')
        $cmp = Compare-PfroLists $St.pfro_before $after
        $res.pfro_after_boot = $cmp
        $res.pfro_restored = ($cmp.ok -and $after.Count -eq @($St.pfro_before).Count)
        $res.admin_moved = -not (Test-Path -LiteralPath $St.admin)
        $res.uw_present = (Test-Path -LiteralPath $St.uw)
        Set-M2Result $R 'reboot' $res
    } $S
    Phase 'reboot-undo' {
        $res = [ordered]@{ undo_exit = (Invoke-Undo $rec 'r') }
        $null = Invoke-M2Deep @($TM, $rec.targets) (F 'deep-r-c.json')
        $v = Invoke-M2Fidelity (F 'deep-r-a.json') (F 'deep-r-c.json') $rec.journal (F 'fidelity-r.json')
        $res.fidelity_ok = $v.ok
        $res.admin_restored = ((Get-FileSha $St.admin) -eq $St.admin_sha)
        Set-M2Result $R 'reboot_undo' $res
    } $S
    Phase 'retry-junction' {
        $res = [ordered]@{ plant_exit = (Invoke-Traps '-Action plant-boot-junction') }
        $rr = New-PlanRec 'retry' @($St.uw_id)
        $x = Invoke-ExecRec $rr
        $res.exec_exit = $x.exit
        $res.uw_outcome = Get-ItemOutcome $rr.report $St.uw_id
        $res.skipped = ("$($res.uw_outcome)" -match 'Skipped')
        $res.reason_ok = ("$($res.uw_outcome)" -match 'ReparseMismatch|ChangedSinceScan')
        $res.check_exit = Invoke-Traps '-Action check -Label after-retry'
        Set-M2Result $R 'retry' $res
    } $S
    Phase 'scenario-m' {
        $res = [ordered]@{}
        $lk = Start-M2Locker @($St.admin) $Work
        $res.locker_ready = $lk.ready
        $mr = New-PlanRec 'm' @($St.admin_id)
        $null = Invoke-M2Deep @($TM, $mr.targets) (F 'deep-m-a.json')
        $x = Invoke-ExecRec $mr
        $res.exec_exit = $x.exit
        $res.admin_outcome = Get-ItemOutcome $mr.report $St.admin_id
        $now = @(Save-Pfro 'm-exec')
        $res.pfro_after_exec = Compare-PfroLists $St.pfro_before $now @($St.admin)
        # The engine's pair is taken out again (as a cleaner tool or an administrator could) and a decoy pair for
        # a file that does not exist goes in its place: the boot move will not happen.
        $keep = @($St.pfro_before)
        # A rename pair (no empty destination: .NET writes REG_MULTI_SZ entry by entry, and an empty string in
        # the middle would end the list for the boot-time reader).
        if (@($keep | Where-Object { $_ -eq '' }).Count) { $res.notes = 'the pre-existing PFRO list holds delete pairs; rewriting it may shorten it' }
        Set-PfroList ([string[]](@($keep) + @("\??\$DecoySrc", "\??\$DecoySrc.moved")))
        $res.pfro_tampered = @(Save-Pfro 'm-tampered')
        $St.m = $mr
        Save-State $St
        Set-M2Result $R 'scenario_m' $res
        $null = Request-RigContinuation $Run 'reboot' 'after-mismatch' ([ordered]@{ session = $mr.session; locker_pid = $lk.pid })
    } $S
}

function Invoke-AfterMismatch {
    $St = $script:St
    $m = Receive-RigContinuation $Run
    $rec = $St.m
    Phase 'mismatch-check' {
        $res = [ordered]@{ boot_changed = ($m -and $m.boot_before -and $m.boot_after -and $m.boot_before -ne $m.boot_after) }
        Invoke-RecoverShow $rec 'm' $res
        $res.admin_present = (Test-Path -LiteralPath $St.admin)
        $res.admin_unchanged = ((Get-FileSha $St.admin) -eq $St.admin_sha)
        $res.undo_exit = Invoke-Undo $rec 'm'
        $null = Invoke-M2Deep @($TM, $rec.targets) (F 'deep-m-c.json')
        $res.fidelity_ok = (Invoke-M2Fidelity (F 'deep-m-a.json') (F 'deep-m-c.json') $rec.journal (F 'fidelity-m.json')).ok
        $after = @(Save-Pfro 'm-boot')
        $cmp = Compare-PfroLists $St.pfro_before $after
        $res.pfro_after_boot = $cmp
        $res.pfro_restored = ($cmp.ok -and $after.Count -eq @($St.pfro_before).Count)
        Set-M2Result $R 'mismatch' $res
    } $S
    Phase 'traps-check-final' { Set-M2Result $R 'final_check_exit' (Invoke-Traps '-Action check -Label final') } $S
    Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S
}

$script:St = $null
try {
    if ($Stage -eq 'start') { Invoke-Start }
    else {
        $script:St = Read-Json $StateFile
        if (-not $script:St) { throw "no $StateFile" }
        if ($Stage -eq 'after-reboot') { Invoke-AfterReboot } else { Invoke-AfterMismatch }
    }
} finally {
    Save-M2Run $R -Finished
}
$failed = @(@($S.phases) | Select-Object -Skip $PhaseCount0 | Where-Object { -not $_.ok })
Log "m2-reboot $Stage done: $($failed.Count) failed phase(s)"
if ($failed.Count) { exit 1 }
exit 0
