# Purge rig, M2: crash and recovery matrix (vm\RIG.md §11; docs\M2_DESIGN.json gate G3). Template: the host
# (rig.ps1 New-M2JobText) replaces __RUN__, __MODE__ (m2-crash), __STAGE__ and __OPTS__ (base64 JSON:
# batch, hard_poweroff, points, poweroff_points) and submits it as an agent job. Windows PowerShell 5.1.
#
# Stages (each a separate job; the run directory and m2-crash-state.json carry over):
#   start          install, `journal fault-points`, the iteration list; then the matrix
#   matrix         up to opts.batch iterations; more left -> continuation 'reboot' to matrix again
#   after-poweroff (opts.hard_poweroff) the host powered the VM off while the engine sat at a PURGE_FAULT_PAUSE
#                  point; recover twice, resume, check; another power-off point -> continuation 'poweroff' again
#   (then, inline) torn: a journal with a truncated tail (recover must accept it) and one with a corrupted middle
#                  record (recover must refuse and change nothing)
# Iteration (point p, phase exec|undo, after resume|rollback): fresh fixtures, plan, deep A, scoped snap A; exec
# (or exec then undo) with PURGE_FAULT_AT=p; `journal recover` twice (deep after each: the second must change
# nothing); `journal resume --session` or `journal rollback --session`; resume of an exec-phase crash: scoped
# snap B + execdiff, then undo; resume of an undo-phase crash: the session must be Undone (recovery finished the
# undo; no second undo); deep C; fidelity A vs C; fixtures check after-undo. One crash-<tag>.json per iteration, all appended to
# crash-matrix.json (purge.rig.crashmatrix/1).
# Engine calls: journal fault-points | plan from-targets | exec ... (env PURGE_FAULT_AT=<p>) | undo --session <id>
#   (env PURGE_FAULT_AT=<p> for undo-phase points) | journal recover | journal resume --session <id> |
#   journal rollback --session <id>; power-off: exec ... (env PURGE_FAULT_PAUSE=<p>:600000), detached.
$Run = '__RUN__'
$Mode = '__MODE__'
$Stage = '__STAGE__'
$OptsB64 = '__OPTS__'
if ($Run -eq ('__' + 'RUN__') -or $Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { Write-Host ("m2-crash.ps1: bad or unreplaced run name '{0}'" -f $Run); exit 2 }
if ($Mode -ne 'm2-crash') { Write-Host ("m2-crash.ps1: bad or unreplaced mode '{0}'" -f $Mode); exit 2 }
if ($Stage -eq ('__' + 'STAGE__')) { $Stage = 'start' }
if (@('start', 'matrix', 'after-poweroff') -cnotcontains $Stage) { Write-Host ("m2-crash.ps1: bad stage '{0}'" -f $Stage); exit 2 }
. C:\cr\guest\riglib.ps1

# Points whose fault fires inside an undo (the rest fire inside exec; journal / quarantine housekeeping points
# that neither exec nor undo reaches are listed as not_hit).
$UndoPoints = @('undo.intent', 'undo.act.after', 'regrestore.mid', 'index.write')
$DefaultPoweroffPoints = @('intent.flushed', 'regdelete.mid', 'commit.before')
# Points that need their own scenario: expiry.mid (a `quarantine purge` of a quarantined directory under the clock
# override) and bootmove.registered (a fixture file held open without FILE_SHARE_DELETE, so the move is
# registered for boot time).
$ExpiryPoint = 'expiry.mid'
$BootmovePoint = 'bootmove.registered'
$BootmoveItem = 'file-ads.file'
$BootmoveFile = 'C:\Program Files\PurgeFixtureApp\ads\ads.bin'
$ExpiryItem = 'nested-dirs.dir'
$ExpiryPath = 'C:\Program Files\PurgeFixtureApp\tree'

$Opts = ConvertFrom-M2Opts $OptsB64
$R = Open-M2Run $Run $Mode $Stage
$D = $R.dir
$S = $R.S
$Calls = $S.engine.calls
$FixturesPs = Join-Path $RigGuestDir 'm2-fixtures.ps1'
$Work = Join-Path $RigWork $Run
New-Item -ItemType Directory -Force $Work | Out-Null
$StateFile = Join-Path $D 'm2-crash-state.json'
$MatrixFile = Join-Path $D 'crash-matrix.json'
$PhaseCount0 = $S.phases.Count

function Q([string]$s) { ConvertTo-EngineArg $s }
function F([string]$n) { Join-Path $D $n }
function Read-Json([string]$p) { if (Test-Path -LiteralPath $p) { [IO.File]::ReadAllText($p) | ConvertFrom-Json } else { $null } }
function Save-State($St) { Write-JsonFile $St $StateFile 8 }
function ConvertTo-Tag([string]$s) { ($s -replace '[^A-Za-z0-9_-]', '_').ToLowerInvariant() }

# Files and keys of a deep document, without its header (time, computer); two equal values = the same state.
function Get-DeepState([string]$Path) {
    $j = Read-Json $Path
    if (-not $j) { return $null }
    (ConvertTo-Json -InputObject @{ files = $j.files; keys = $j.keys } -Depth 20 -Compress)
}

function Add-MatrixRow($Row) {
    $rows = New-Object System.Collections.ArrayList
    $m = Read-Json $MatrixFile
    if ($m) { foreach ($x in @($m.rows)) { if ($x) { [void]$rows.Add($x) } } }
    [void]$rows.Add($Row)
    Write-JsonFile ([ordered]@{ schema = 'purge.rig.crashmatrix/1'; run = $Run; points = $script:St.points; rows = @($rows) }) $MatrixFile 10
}

# A fresh fixture tree in $Work\<tag>, planned (group main); deep A and a scoped snap A taken.
function New-CrashRound([string]$Tag, [switch]$BootStable) {
    $w = Join-Path $Work $Tag
    if (Test-Path -LiteralPath $w) { Remove-Item -LiteralPath $w -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Force $w | Out-Null
    $x = Invoke-M2Script $FixturesPs '-Action reset'
    if ($x.exit -ne 0) { Log "  !! fixtures reset exit $($x.exit)" }
    $x = Invoke-M2Script $FixturesPs ('-OutDir ' + (Q $w))
    if ($x.exit -ne 0) { throw "m2-fixtures.ps1 build exited $($x.exit)" }
    $man = Join-Path $w 'm2-fixtures-manifest.json'
    $t = F "targets-$Tag.json"
    $ids = @(Write-M2Targets @((Join-Path $w 'm2-fixtures-targets.json')) 'main' $t)
    $plan = F "plan-$Tag.json"
    $null = Invoke-M2Engine -Step "plan-$Tag" -Arguments (New-M2PlanArgs $t $plan) -Calls $Calls
    $ph = Get-M2PlanHash $plan
    $rec = [pscustomobject][ordered]@{ tag = $Tag; work = $w; manifest = $man; targets = $t; plan = $plan; select = (Write-M2IdFile $ids (F "select-$Tag.json")); ids = $ids
        plan_hash = $ph; confirm = (Get-M2Confirm $ph $ids); roots = @(Get-M2SnapRoots @($man) -BootStable:$BootStable); session = $null; journal = $null; report = $null
        pfro_before = $(if ($BootStable) { , @(Get-PfroList) } else { $null }) }
    $null = Invoke-M2Deep @($man, $t) (F "deep-$Tag-a.json")
    $null = Invoke-M2Snap (F "snap-$Run-$Tag-a.tsv.gz") $rec.roots
    $rec
}

function Invoke-CrashExec($Rec, [hashtable]$Environment = @{}) {
    $before = @(Get-M2Sessions)
    $rep = F "report-$($Rec.tag).json"
    $r = Invoke-M2Engine -Step "exec-$($Rec.tag)" -Arguments (New-M2ExecArgs $Rec.plan $Rec.confirm $Rec.select $rep) -Calls $Calls -Environment $Environment -StdoutFile (F "exec-$($Rec.tag).out") -NoThrow
    $s = $null
    if (Test-Path -LiteralPath $rep) { $s = "$((Read-Json $rep).session)" }
    if (-not $s) { $s = Get-M2NewSession $before }
    $Rec.session = $s
    if ($s) { $Rec.journal = Join-Path (Get-M2SessionDir $s) 'journal.jsonl' }
    $Rec.report = $(if (Test-Path -LiteralPath $rep) { $rep } elseif ($s -and (Test-Path -LiteralPath (Join-Path (Get-M2SessionDir $s) 'report.json'))) { Join-Path (Get-M2SessionDir $s) 'report.json' } else { $null })
    $r
}

function Invoke-Journal([string]$Verb, [string]$Session, [string]$Tag) {
    Invoke-M2Engine -Step "journal-$Verb-$Tag" -Arguments (New-M2JournalArgs $Verb $Session) -Calls $Calls -StdoutFile (F "journal-$Verb-$Tag.out") -NoThrow
}

# recover twice with deep after each; the second recover must exit 0 and change nothing.
function Invoke-RecoverTwice($Rec, $Row) {
    $r1 = Invoke-Journal 'recover' '' "$($Rec.tag)-1"
    $null = Invoke-M2Deep @($Rec.manifest, $Rec.targets) (F "deep-$($Rec.tag)-r1.json")
    $r2 = Invoke-Journal 'recover' '' "$($Rec.tag)-2"
    $null = Invoke-M2Deep @($Rec.manifest, $Rec.targets) (F "deep-$($Rec.tag)-r2.json")
    $Row.recover_exit = $r1.exit
    $Row.recover2_exit = $r2.exit
    $Row.recover_idempotent = ($r2.exit -eq 0 -and (Get-DeepState (F "deep-$($Rec.tag)-r1.json")) -eq (Get-DeepState (F "deep-$($Rec.tag)-r2.json")))
}

# After recover: resume (then execdiff and undo) or rollback; deep C, fidelity A vs C, fixtures check.
function Complete-Round($Rec, $Row, [string]$After) {
    $tag = $Rec.tag
    if ($After -eq 'rollback') {
        $Row.after_exit = (Invoke-Journal 'rollback' $Rec.session $tag).exit
    } else {
        $Row.after_exit = (Invoke-Journal 'resume' $Rec.session $tag).exit
        if ($Row.phase -eq 'exec') {
            $null = Invoke-M2Snap (F "snap-$Run-$tag-b.tsv.gz") $Rec.roots
            if (-not $Rec.report -and $Rec.session -and (Test-Path -LiteralPath (Join-Path (Get-M2SessionDir $Rec.session) 'report.json'))) { $Rec.report = Join-Path (Get-M2SessionDir $Rec.session) 'report.json' }
            if ($Rec.report -and $Rec.journal) {
                $v = Invoke-M2Execdiff -Before (F "snap-$Run-$tag-a.tsv.gz") -After (F "snap-$Run-$tag-b.tsv.gz") -Journal $Rec.journal -Report $Rec.report -Traps @($Rec.manifest) -Groups @('main') -Out (F "execdiff-$tag.json")
                $Row.execdiff_ok = $v.ok
            } else { $Row.execdiff_ok = $null; $Row.notes += 'no report after resume: execdiff skipped' }
            $u = Invoke-M2Engine -Step "undo-$tag" -Arguments (New-M2UndoArgs $Rec.session '' '' (F "undo-$tag.json")) -Calls $Calls -StdoutFile (F "undo-$tag.out") -NoThrow
            $Row.undo_exit = $u.exit
        } elseif ($Row.after_exit -eq 0) {
            # Resume finishes the interrupted undo itself (the ops in progress and the rest of its undo_plan):
            # the session must be Undone now, and no second undo is run. A session the crash left already fully
            # undone (index.write after the last op) passes the same way.
            $st = $null
            try { $o = Read-Json (F "journal-resume-$tag.out"); if ($o) { $st = "$(@($o.sessions)[0].state)" } } catch { $st = $null }
            $Row.undone_by_recovery = ($st -eq 'Undone')
            if (-not $Row.undone_by_recovery) { $Row.notes += "resume left the session '$st', not Undone" }
        }
    }
    $null = Copy-M2Session $Rec.session $D "sess-$tag"
    $null = Invoke-M2Deep @($Rec.manifest, $Rec.targets) (F "deep-$tag-c.json")
    $f = Invoke-M2Fidelity (F "deep-$tag-a.json") (F "deep-$tag-c.json") $Rec.journal (F "fidelity-$tag.json")
    $Row.fidelity_ok = $f.ok
    $c = Invoke-M2Script $FixturesPs ('-Action check -Phase after-undo -OutDir ' + (Q $Rec.work))
    $Row.fixtures_check_exit = $c.exit
    $cf = Join-Path $Rec.work 'm2-fixtures-check-after-undo.json'
    if (Test-Path -LiteralPath $cf) { Copy-Item -LiteralPath $cf -Destination (F "check-$tag.json") -Force }
}

function New-Row([int]$N, [string]$Point, [string]$Phase, [string]$After, [string]$Kind = 'abort') {
    [ordered]@{ n = $N; kind = $Kind; point = $Point; phase = $Phase; after = $After; tag = $null; session = $null; hit = $false; fault_exit = $null; crashed = $false
        recover_exit = $null; recover2_exit = $null; recover_idempotent = $null; after_exit = $null; undo_exit = $null; execdiff_ok = $null
        undone_by_recovery = $null; fidelity_ok = $null; fixtures_check_exit = $null; error = $null; notes = @(); pass = $false }
}

# Pass rule per row (m2.sh applies the same rule): a hit point crashed, recovered twice with the same state, the
# resume / rollback exited 0, an undo-phase resume left the session Undone, every verdict that ran is ok; a point
# not hit is recorded, not failed.
function Set-RowPass($Row) {
    if (-not $Row.hit) { $Row.pass = ($null -eq $Row.error); return }
    if ($Row.point -eq $ExpiryPoint) {
        $Row.pass = ($null -eq $Row.error -and $Row.crashed -and $Row.partial_left -eq $true -and $Row.recover_exit -eq 0 -and $Row.recover_idempotent -eq $true `
                -and $Row.listed_unfinished -eq $true -and $Row.after_exit -eq 0 -and $Row.repurge_outcome -eq 'Purged' -and $Row.second_expire_record -eq $false `
                -and $Row.item_gone -eq $true -and @($Row.outside_store).Count -eq 0)
        return
    }
    if ($Row.point -eq $BootmovePoint) {
        # A resumed session whose item waits for the boot exits 10 (PendingReboot is not "done", RIG.md §11.7).
        $wantExit = $(if ($Row.after -eq 'rollback') { 0 } else { 10 })
        $Row.pass = ($null -eq $Row.error -and $Row.crashed -and $Row.pfro_after_crash.ok -eq $true -and $Row.recover_exit -eq 0 -and $Row.recover_idempotent -eq $true `
                -and $Row.after_exit -eq $wantExit -and $Row.pfro_restored -eq $true -and $Row.fidelity_ok -eq $true -and $Row.fixtures_check_exit -eq 0 `
                -and ($Row.after -eq 'rollback' -or ($Row.bootmove_confirmed -eq $true -and $Row.pfro_after_recovery.ok -eq $true -and $Row.undo_exit -eq 0)))
        return
    }
    $Row.pass = ($null -eq $Row.error -and $Row.crashed -and $Row.recover_exit -eq 0 -and $Row.recover_idempotent -eq $true -and $Row.after_exit -eq 0 `
            -and $Row.fidelity_ok -eq $true -and $Row.execdiff_ok -ne $false -and ($null -eq $Row.undo_exit -or $Row.undo_exit -eq 0) `
            -and $Row.undone_by_recovery -ne $false -and $Row.fixtures_check_exit -eq 0)
}

# Narrows a round's selection to $Ids (the plan keeps every fixture item; --select is the full selection).
function Set-RecSelection($Rec, [string[]]$Ids) {
    $Rec.ids = @($Ids)
    $Rec.select = Write-M2IdFile @($Ids) (F "select-$($Rec.tag).json")
    $Rec.confirm = Get-M2Confirm $Rec.plan_hash @($Ids)
}

# rigtool diff A B --json: the removed and changed records whose path is not under $AllowedPrefix.
function Get-DiffOutside([string]$A, [string]$B, [string]$AllowedPrefix, [string]$Out) {
    $r = Invoke-Native -Exe $RigTool -Arguments ('diff ' + (Q $A) + ' ' + (Q $B) + ' --json') -TimeoutSec 600
    if ($r.exit -ne 0) { throw "rigtool diff exited $($r.exit)" }
    [IO.File]::WriteAllText($Out, "$($r.stdout)", $RigUtf8)
    $d = "$($r.stdout)" | ConvertFrom-Json
    $recs = @(@($d.removed) + @($d.changed) | Where-Object { $_ })
    @($recs | Where-Object { -not "$($_.path)".StartsWith($AllowedPrefix, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { "$($_.op)$($_.rec) $($_.path)" })
}

# Row expiry.mid: exec of the expiry item alone, `quarantine expiring` (clock override), scoped snap X, then
# `quarantine purge --ids <id>` with PURGE_FAULT_AT=expiry.mid:2 (the second listing of the walk: the first level
# deleted, a subdirectory not). Recovery checks: the purge crashed with part of the item still in quarantine;
# `journal recover` twice changes nothing; `quarantine expiring` lists the item as unfinished; a second purge
# (no fault) ends Purged without a second expire record and the item is gone; between snap X and snap Y nothing
# outside the store was removed or changed (canaries and every other fixture untouched).
function Invoke-ExpiryIteration($It, $Row, [string]$Tag) {
    $rec = New-CrashRound $Tag
    Set-RecSelection $rec @($ExpiryItem)
    $x0 = Invoke-CrashExec $rec
    $Row.session = $rec.session
    if ($x0.exit -ne 0) { throw "exec of $ExpiryItem exited $($x0.exit)" }
    $xenv = @{ PURGE_RIG_NOW_OFFSET_DAYS = '400' }
    $e = Invoke-M2Engine -Step "quarantine-expiring-$Tag" -Arguments (New-M2QuarantineArgs 'expiring') -Calls $Calls -Environment $xenv -StdoutFile (F "expiring-$Tag.json") -NoThrow
    if ($e.exit -ne 0) { throw "quarantine expiring exited $($e.exit)" }
    $ids = @(Find-M2ExpiryIds ([IO.File]::ReadAllText((F "expiring-$Tag.json"))) $ExpiryPath)
    if ($ids.Count -ne 1) { throw "quarantine expiring lists $($ids.Count) entries for $ExpiryPath" }
    $Row.expiry_id = $ids[0]
    $entry = @((Read-Json (F "expiring-$Tag.json")).items | Where-Object { "$($_.id)" -eq $ids[0] })[0]
    $qpath = "$($entry.quarantine_path)"
    $null = Invoke-M2Snap (F "snap-$Run-$Tag-x.tsv.gz") $rec.roots
    $fenv = @{ PURGE_RIG_NOW_OFFSET_DAYS = '400'; PURGE_FAULT_AT = "$ExpiryPoint`:2" }
    $p = Invoke-M2Engine -Step "quarantine-purge-fault-$Tag" -Arguments (New-M2QuarantineArgs 'purge' $ids) -Calls $Calls -Environment $fenv -StdoutFile (F "purge-fault-$Tag.out") -NoThrow
    $Row.fault_exit = $p.exit
    $Row.crashed = [bool]$p.crashed
    $Row.hit = $Row.crashed
    if (-not $Row.hit) { $Row.notes += "point not reached (exit $($p.exit))"; return }
    $Row.partial_left = (Test-Path -LiteralPath $qpath)
    Invoke-RecoverTwice $rec $Row
    $e2 = Invoke-M2Engine -Step "quarantine-expiring2-$Tag" -Arguments (New-M2QuarantineArgs 'expiring') -Calls $Calls -Environment $xenv -StdoutFile (F "expiring2-$Tag.json") -NoThrow
    $again = @((Read-Json (F "expiring2-$Tag.json")).items | Where-Object { "$($_.id)" -eq $ids[0] })
    $Row.listed_unfinished = ($e2.exit -eq 0 -and $again.Count -eq 1 -and $again[0].unfinished -eq $true)
    $p2 = Invoke-M2Engine -Step "quarantine-purge-$Tag" -Arguments (New-M2QuarantineArgs 'purge' $ids) -Calls $Calls -Environment $xenv -StdoutFile (F "purge-$Tag.out") -NoThrow
    $Row.after_exit = $p2.exit
    $pr = @((Read-Json (F "purge-$Tag.out")).items | Where-Object { "$($_.id)" -eq $ids[0] })
    $Row.repurge_outcome = $(if ($pr.Count) { "$($pr[0].outcome)" } else { $null })
    $Row.second_expire_record = $(if ($pr.Count) { [bool]$pr[0].expire_recorded } else { $null })
    $Row.item_gone = -not (Test-Path -LiteralPath $qpath)
    $null = Invoke-M2Snap (F "snap-$Run-$Tag-y.tsv.gz") $rec.roots
    $Row.outside_store = @(Get-DiffOutside (F "snap-$Run-$Tag-x.tsv.gz") (F "snap-$Run-$Tag-y.tsv.gz") $RigPurgeData (F "diff-$Tag-xy.json"))
    $null = Copy-M2Session $rec.session $D "sess-$Tag"
}

# Row bootmove.registered (after resume | rollback): the admin fixture file held open without FILE_SHARE_DELETE,
# exec of that item alone with PURGE_FAULT_AT=bootmove.registered: the move is registered in
# PendingFileRenameOperations and the process dies before its `done`. Recovery checks: the pair is in PFRO after
# the crash; `journal recover` twice changes nothing; resume ends with the item PendingReboot (confirmed: true, the
# pair still there once), then undo before any reboot takes the pair out again; rollback takes it out itself.
# Either way PFRO ends as before, the file is unchanged (fidelity A vs C) and every fixture as built.
function Invoke-BootmoveIteration($It, $Row, [string]$Tag) {
    $rec = New-CrashRound $Tag
    Set-RecSelection $rec @($BootmoveItem)
    $pb = Get-PfroList
    $lk = Start-M2Locker @($BootmoveFile) (Join-Path $Work "$Tag-lock")
    try {
        if (-not $lk.ready) { throw 'the locker did not take the file' }
        $x = Invoke-CrashExec $rec @{ PURGE_FAULT_AT = $BootmovePoint }
        $Row.session = $rec.session
        $Row.fault_exit = $x.exit
        $Row.crashed = [bool]$x.crashed
        $Row.hit = $Row.crashed
        $null = Copy-M2Session $rec.session $D "sess-$Tag-crash"
        if (-not $Row.hit) {
            $Row.notes += "point not reached (exit $($x.exit))"
            if ($x.exit -eq 0 -or $x.exit -eq 10) { $null = Invoke-M2Engine -Step "undo-$Tag" -Arguments (New-M2UndoArgs $rec.session '' '' (F "undo-$Tag.json")) -Calls $Calls -StdoutFile (F "undo-$Tag.out") -NoThrow }
            return
        }
        $Row.pfro_after_crash = Compare-PfroLists $pb (Get-PfroList) @($BootmoveFile)
        Invoke-RecoverTwice $rec $Row
        if ($It.after -eq 'rollback') {
            $Row.after_exit = (Invoke-Journal 'rollback' $rec.session $Tag).exit
        } else {
            $Row.after_exit = (Invoke-Journal 'resume' $rec.session $Tag).exit
            $o = "$(if (Test-Path -LiteralPath (F "journal-resume-$Tag.out")) { [IO.File]::ReadAllText((F "journal-resume-$Tag.out")) })"
            $Row.bootmove_confirmed = ($o -match '"kind":\s*"PendingReboot"' -and $o -match '"confirmed":\s*true' -and $o -notmatch '"confirmed":\s*false')
            $Row.pfro_after_recovery = Compare-PfroLists $pb (Get-PfroList) @($BootmoveFile)
            $u = Invoke-M2Engine -Step "undo-$Tag" -Arguments (New-M2UndoArgs $rec.session '' '' (F "undo-$Tag.json")) -Calls $Calls -StdoutFile (F "undo-$Tag.out") -NoThrow
            $Row.undo_exit = $u.exit
        }
        $pa = Get-PfroList
        $Row.pfro_restored = ((@($pb | Where-Object { $null -ne $_ }) -join "`n") -ceq (@($pa | Where-Object { $null -ne $_ }) -join "`n"))
    } finally { Stop-M2Locker $lk }
    $Row.notes += 'execdiff not run: a single locked item whose move waits for a boot; PFRO and fidelity checked instead'
    $null = Copy-M2Session $rec.session $D "sess-$Tag"
    $null = Invoke-M2Deep @($rec.manifest, $rec.targets) (F "deep-$Tag-c.json")
    $f = Invoke-M2Fidelity (F "deep-$Tag-a.json") (F "deep-$Tag-c.json") $rec.journal (F "fidelity-$Tag.json")
    $Row.fidelity_ok = $f.ok
    $c = Invoke-M2Script $FixturesPs ('-Action check -Phase after-undo -OutDir ' + (Q $rec.work))
    $Row.fixtures_check_exit = $c.exit
    $cf = Join-Path $rec.work 'm2-fixtures-check-after-undo.json'
    if (Test-Path -LiteralPath $cf) { Copy-Item -LiteralPath $cf -Destination (F "check-$Tag.json") -Force }
}

function Invoke-Iteration($It) {
    $row = New-Row $It.n $It.point $It.phase $It.after
    $tag = ConvertTo-Tag ('c{0:000}-{1}-{2}-{3}' -f $It.n, $It.phase, $It.point, $It.after)
    $row.tag = $tag
    if ($It.point -eq $ExpiryPoint -or $It.point -eq $BootmovePoint) {
        try {
            if ($It.point -eq $ExpiryPoint) { Invoke-ExpiryIteration $It $row $tag } else { Invoke-BootmoveIteration $It $row $tag }
        } catch {
            $row.error = "$($_.Exception.Message)"
            Log "!! iteration $tag`: $($row.error)"
        }
        Set-RowPass $row
        Write-JsonFile $row (F "crash-$tag.json") 8
        Add-MatrixRow $row
        Log ("iteration {0}: hit={1} pass={2}" -f $tag, $row.hit, $row.pass)
        return
    }
    try {
        $rec = New-CrashRound $tag
        $fault = @{ PURGE_FAULT_AT = $It.point }
        if ($It.phase -eq 'exec') {
            $x = Invoke-CrashExec $rec $fault
        } else {
            $x0 = Invoke-CrashExec $rec
            if ($x0.exit -ne 0) { throw "exec before the undo fault exited $($x0.exit)" }
            $x = Invoke-M2Engine -Step "undo-fault-$tag" -Arguments (New-M2UndoArgs $rec.session '' '' (F "undo-fault-$tag.json")) -Calls $Calls -Environment $fault -StdoutFile (F "undo-fault-$tag.out") -NoThrow
        }
        $row.session = $rec.session
        $row.fault_exit = $x.exit
        $row.crashed = [bool]$x.crashed
        $row.hit = $row.crashed
        $null = Copy-M2Session $rec.session $D "sess-$tag-crash"
        if ($row.hit) {
            Invoke-RecoverTwice $rec $row
            Complete-Round $rec $row $It.after
        } else {
            $row.notes += "point not reached (exit $($x.exit))"
            if ($x.exit -eq 0 -and $rec.session) {
                $u = Invoke-M2Engine -Step "undo-$tag" -Arguments (New-M2UndoArgs $rec.session '' '' (F "undo-$tag.json")) -Calls $Calls -StdoutFile (F "undo-$tag.out") -NoThrow
                if ($It.phase -eq 'exec') { $row.undo_exit = $u.exit }
            }
        }
    } catch {
        $row.error = "$($_.Exception.Message)"
        Log "!! iteration $tag`: $($row.error)"
    }
    Set-RowPass $row
    Write-JsonFile $row (F "crash-$tag.json") 8
    Add-MatrixRow $row
    Log ("iteration {0}: hit={1} pass={2}" -f $tag, $row.hit, $row.pass)
}

# ------------------------------------------------------------------------------------------- power-off part

# exec started detached with PURGE_FAULT_PAUSE=<p>:600000; returns once the session's journal has not grown for
# ~6 s (the engine sits at the pause point), with the process and the session.
function Start-PausedExec($Rec, [string]$Point) {
    $before = @(Get-M2Sessions)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Get-M2EngineExe
    $psi.Arguments = New-M2ExecArgs $Rec.plan $Rec.confirm $Rec.select (F "report-$($Rec.tag).json")
    # Shell execute: CreateProcess without handle inheritance. With UseShellExecute $false the engine inherits the
    # job's redirected output pipe (agent.ps1 `*> <job>.log`), so the agent waits for the engine, which sleeps
    # 600 s at every hit of the point, and the job never ends to let the host power the VM off (gate run
    # 2026-11-16). The pause variable reaches the engine through this process's environment, set just for the start.
    $psi.UseShellExecute = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    Log "engine (detached): [PURGE_FAULT_PAUSE=$Point`:600000] `"$($psi.FileName)`" $($psi.Arguments)"
    $Rec | Add-Member -NotePropertyName durable -NotePropertyValue (Save-RigDurableState) -Force
    $oldPause = $env:PURGE_FAULT_PAUSE
    $env:PURGE_FAULT_PAUSE = "$Point`:600000"
    try { $p = [System.Diagnostics.Process]::Start($psi) } finally { $env:PURGE_FAULT_PAUSE = $oldPause }
    [void]$Calls.Add([ordered]@{ step = "exec-paused-$($Rec.tag)"; cmd = "`"$($psi.FileName)`" $($psi.Arguments)"; env = "PURGE_FAULT_PAUSE=$Point`:600000"; exit = $null; crashed = $false; timed_out = $false; pid = $p.Id; start = (NowIso); end = $null; stderr_tail = @() })
    $deadline = (Get-Date).AddSeconds(240); $last = -1; $stable = 0; $s = $null
    while ((Get-Date) -lt $deadline -and -not $p.HasExited) {
        Start-Sleep -Seconds 1
        if (-not $s) { $s = Get-M2NewSession $before }
        if (-not $s) { continue }
        $j = Join-Path (Get-M2SessionDir $s) 'journal.jsonl'
        $len = $(if (Test-Path -LiteralPath $j) { (Get-Item -LiteralPath $j).Length } else { -1 })
        if ($len -gt 0 -and $len -eq $last) { $stable++ } else { $stable = 0 }
        $last = $len
        if ($stable -ge 6) { break }
    }
    $Rec.session = $s
    if ($s) { $Rec.journal = Join-Path (Get-M2SessionDir $s) 'journal.jsonl' }
    [pscustomobject]@{ process = $p; session = $s; paused = ($stable -ge 6 -and -not $p.HasExited); exited = $p.HasExited; exit = $(if ($p.HasExited) { $p.ExitCode }) }
}

# Prepares the next power-off point and asks the host for a hard power-off. Returns $true when one was requested.
function Request-NextPoweroff {
    $St = $script:St
    while ($St.poweroff_todo.Count) {
        $point = "$($St.poweroff_todo[0])"
        $St.poweroff_todo = @($St.poweroff_todo | Select-Object -Skip 1)
        $n = 900 + $St.poweroff_done.Count
        $tag = ConvertTo-Tag ('p{0:000}-exec-{1}-poweroff' -f $n, $point)
        $rec = $null; $pz = $null
        try {
            $rec = New-CrashRound $tag -BootStable
            $pz = Start-PausedExec $rec $point
        } catch { Log "!! power-off $tag`: $($_.Exception.Message)" }
        if ($pz -and $pz.paused) {
            $St.pending = [ordered]@{ n = $n; point = $point; tag = $tag; rec = $rec }
            Save-State $St
            $null = Request-RigContinuation $Run 'poweroff' 'after-poweroff' ([ordered]@{ point = $point; tag = $tag; session = $rec.session; pid = $pz.process.Id })
            return $true
        }
        $row = New-Row $n $point 'exec' 'resume' 'poweroff'
        $row.tag = $tag
        $row.error = $(if ($pz) { "engine did not pause at $point (exited=$($pz.exited), exit $($pz.exit))" } else { 'power-off round could not be prepared' })
        if ($pz -and -not $pz.process.HasExited) { Stop-Process -Id $pz.process.Id -Force -ErrorAction SilentlyContinue }
        Set-RowPass $row
        Add-MatrixRow $row
        $St.poweroff_done += $point
        Save-State $St
    }
    $false
}

function Complete-Poweroff {
    $St = $script:St
    $m = Receive-RigContinuation $Run
    $pd = $St.pending
    if (-not $pd) { throw 'after-poweroff without a pending power-off round' }
    $rec = $pd.rec
    $row = New-Row $pd.n "$($pd.point)" 'exec' 'resume' 'poweroff'
    $row.tag = $pd.tag; $row.session = $rec.session
    $row.hit = $true; $row.crashed = $true
    $row.boot_changed = ($m -and $m.boot_before -and $m.boot_after -and $m.boot_before -ne $m.boot_after)
    if (-not $row.boot_changed) { $row.notes += 'boot id unchanged: the VM was not powered off' }
    try {
        Invoke-RecoverTwice $rec $row
        Complete-Round $rec $row 'resume'
    } catch { $row.error = "$($_.Exception.Message)" }
    # The scoped snaps of a power-off round leave the Session Manager key out (-BootStable): PFRO compared here.
    $pb = @($rec.pfro_before | Where-Object { $null -ne $_ }); $pa = @(Get-PfroList | Where-Object { $null -ne $_ })
    $row.pfro_unchanged = (($pb -join "`n") -ceq ($pa -join "`n"))
    if (-not $row.pfro_unchanged) { $row.notes += "PendingFileRenameOperations changed: $($pb.Count) -> $($pa.Count) entries" }
    Set-RowPass $row
    if (-not $row.boot_changed -or -not $row.pfro_unchanged) { $row.pass = $false }
    Write-JsonFile $row (F "crash-$($pd.tag).json") 8
    Add-MatrixRow $row
    $St.poweroff_done += "$($pd.point)"
    $St.pending = $null
    Save-State $St
}

# ------------------------------------------------------------------------------------------------- torn journal

function Invoke-Torn {
    $res = [ordered]@{}
    foreach ($v in 'tail', 'middle') {
        $tag = "torn-$v"
        $row = [ordered]@{ variant = $v; session = $null; crashed = $false; journal_bytes = $null; recover_exit = $null; unchanged = $null; rollback_exit = $null; fidelity_ok = $null; error = $null; pass = $false }
        try {
            $rec = New-CrashRound $tag
            $x = Invoke-CrashExec $rec @{ PURGE_FAULT_AT = 'act.after' }
            $row.session = $rec.session; $row.crashed = [bool]$x.crashed
            if (-not $rec.journal -or -not (Test-Path -LiteralPath $rec.journal)) { throw 'no journal after the act.after crash' }
            $bytes = [IO.File]::ReadAllBytes($rec.journal)
            $row.journal_bytes = $bytes.Length
            if ($v -eq 'tail') {
                # Half of a record appended after the last whole one, as a power loss mid-append leaves it. (Not
                # the last record cut: after act.after that is the flushed intent of an op that already acted, and
                # a flushed record cannot be torn; cutting it leaves a quarantined object no record names.)
                $end = $bytes.Length - 1; while ($end -gt 0 -and ($bytes[$end] -eq 10 -or $bytes[$end] -eq 13)) { $end-- }
                $start = $end; while ($start -gt 0 -and $bytes[$start - 1] -ne 10) { $start-- }
                $half = [int][Math]::Max(1, [Math]::Floor(($end - $start) / 2))
                [IO.File]::WriteAllBytes($rec.journal, [byte[]]($bytes + $bytes[$start..($start + $half - 1)]))
            } else {
                # One byte inside a middle record changed: a record with a bad checksum before valid ones.
                $lines = @(); $s0 = 0
                for ($i = 0; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -eq 10) { $lines += , @($s0, $i); $s0 = $i + 1 } }
                if ($lines.Count -lt 3) { throw "journal has $($lines.Count) record(s); need 3" }
                $mid = $lines[[int][Math]::Floor($lines.Count / 2)]
                $k = $mid[0] + [int][Math]::Floor(($mid[1] - $mid[0]) / 2)
                $bytes[$k] = $(if ($bytes[$k] -eq 0x30) { 0x31 } else { 0x30 })
                [IO.File]::WriteAllBytes($rec.journal, $bytes)
            }
            $null = Copy-M2Session $rec.session $D "sess-$tag-torn"
            $null = Invoke-M2Deep @($rec.manifest, $rec.targets) (F "deep-$tag-x.json")
            $row.recover_exit = (Invoke-Journal 'recover' '' $tag).exit
            $null = Invoke-M2Deep @($rec.manifest, $rec.targets) (F "deep-$tag-y.json")
            $row.unchanged = ((Get-DeepState (F "deep-$tag-x.json")) -eq (Get-DeepState (F "deep-$tag-y.json")))
            if ($v -eq 'tail') {
                $row.rollback_exit = (Invoke-Journal 'rollback' $rec.session $tag).exit
                $null = Invoke-M2Deep @($rec.manifest, $rec.targets) (F "deep-$tag-c.json")
                $row.fidelity_ok = (Invoke-M2Fidelity (F "deep-$tag-a.json") (F "deep-$tag-c.json") $rec.journal (F "fidelity-$tag.json")).ok
                $row.pass = ($row.crashed -and $row.recover_exit -eq 0 -and $row.rollback_exit -eq 0 -and $row.fidelity_ok -eq $true)
            } else {
                $row.pass = ($row.crashed -and $row.recover_exit -ne 0 -and $row.unchanged -eq $true)
            }
            $null = Copy-M2Session $rec.session $D "sess-$tag"
        } catch { $row.error = "$($_.Exception.Message)" }
        $res[$v] = $row
    }
    Write-JsonFile $res (F 'crash-torn.json') 8
    Set-M2Result $R 'torn' $res
}

# ------------------------------------------------------------------------------------------------------- main

$script:St = $null
try {
    if ($Stage -eq 'start') {
        Phase 'edge-pause' { $S.edge_pause = Suspend-EdgeUpdate } $S
        Phase 'install' {
            $r1 = Invoke-M2Script $RigInstallScript ('-Engine ' + (Q $RigEngine) + ' -EngineOnly -ReportPath ' + (Q (F 'install.json')))
            Set-M2Result $R 'install' ([ordered]@{ exit = $r1.exit })
            if ($r1.exit -ne 0) { throw "install.ps1 exited $($r1.exit)" }
            $S.engine.exe = Get-M2EngineExe
        } $S
        Phase 'fault-points' {
            $fp = Invoke-M2Engine -Step 'fault-points' -Arguments (New-M2JournalArgs 'fault-points') -Calls $Calls -StdoutFile (F 'fault-points.out')
            $declared = @(ConvertFrom-M2FaultPoints ([IO.File]::ReadAllText((F 'fault-points.out'))))
            if (-not $declared.Count) { throw 'journal fault-points listed no point' }
            $want = @(Get-M2Opt $Opts 'points' @())
            $unknown = @($want | Where-Object { $declared -notcontains $_ })
            if ($unknown.Count) { throw "fault points the engine does not declare: $($unknown -join ', ')" }
            $points = $(if ($want.Count) { @($declared | Where-Object { $want -contains $_ }) } else { $declared })
            $its = New-Object System.Collections.ArrayList
            $n = 0
            foreach ($p in $points) {
                if ($UndoPoints -contains $p) { [void]$its.Add([ordered]@{ n = ++$n; point = $p; phase = 'undo'; after = 'resume' }) }
                # expiry.mid fires in `quarantine purge`, not in a run: one row, finished by the next purge.
                elseif ($p -eq $ExpiryPoint) { [void]$its.Add([ordered]@{ n = ++$n; point = $p; phase = 'expiry'; after = 'repurge' }) }
                else { foreach ($a in 'resume', 'rollback') { [void]$its.Add([ordered]@{ n = ++$n; point = $p; phase = 'exec'; after = $a }) } }
            }
            $po = @()
            if ((Get-M2Opt $Opts 'hard_poweroff' $false) -eq $true) {
                $po = @(@(Get-M2Opt $Opts 'poweroff_points' $DefaultPoweroffPoints) | Where-Object { $declared -contains $_ })
                # Back-to-back power cuts within a minute of boot make Windows count failed boots and stop in WinRE
                # ("It looks like Windows didn't load correctly"; gate run 2026-11-16, second power-off), so the agent
                # never comes back. The boot status policy of this restored snapshot ignores them; the restore of the
                # next run brings the snapshot's BCD back.
                $S.boot_policy = Set-RigBootPolicyIgnoreFailures
            }
            $script:St = [ordered]@{ schema = 'purge.rig.crashstate/1'; points = $declared; todo = @($its); done = 0; poweroff_todo = $po; poweroff_done = @(); pending = $null; torn_done = $false }
            Save-State $script:St
            Set-M2Result $R 'fault_points' $declared
            Remove-Item -LiteralPath $MatrixFile -Force -ErrorAction SilentlyContinue
        } $S
        if (-not $script:St) { throw 'no crash state (fault-points failed)' }
    } else {
        $script:St = Read-Json $StateFile
        if (-not $script:St) { throw "no $StateFile" }
        # Back to plain arrays / hashtables so the state can be edited and saved.
        $script:St = [ordered]@{ schema = $script:St.schema; points = @($script:St.points); todo = @($script:St.todo | Where-Object { $_ }); done = [int]$script:St.done
            poweroff_todo = @($script:St.poweroff_todo | Where-Object { $_ }); poweroff_done = @($script:St.poweroff_done | Where-Object { $_ }); pending = $script:St.pending; torn_done = [bool]$script:St.torn_done }
        if ($Stage -eq 'matrix') { $null = Receive-RigContinuation $Run }
    }

    $continued = $false
    if ($Stage -eq 'after-poweroff') {
        Phase 'poweroff-check' { Complete-Poweroff } $S
    } else {
        $batch = [int](Get-M2Opt $Opts 'batch' 0)
        $k = 0
        while ($script:St.todo.Count -and ($batch -le 0 -or $k -lt $batch)) {
            $it = $script:St.todo[0]
            Phase ("iteration-{0}" -f $it.n) { Invoke-Iteration $it } $S
            $script:St.todo = @($script:St.todo | Select-Object -Skip 1)
            $script:St.done++; $k++
            Save-State $script:St
        }
        if ($script:St.todo.Count) {
            $null = Request-RigContinuation $Run 'reboot' 'matrix' ([ordered]@{ left = $script:St.todo.Count })
            $continued = $true
        }
    }
    if (-not $continued -and $script:St.poweroff_todo.Count) {
        Phase 'poweroff-request' { $script:Requested = Request-NextPoweroff } $S
        $continued = [bool]$script:Requested
    }
    if (-not $continued -and -not $script:St.torn_done) {
        Phase 'torn' { Invoke-Torn } $S
        $script:St.torn_done = $true
        Save-State $script:St
    }
    if (-not $continued) {
        $m = Read-Json $MatrixFile
        $rows = @(); if ($m) { $rows = @(@($m.rows) | Where-Object { $_ }) }
        Set-M2Result $R 'crash' ([ordered]@{ rows = $rows.Count; hit = @($rows | Where-Object { $_.hit }).Count; passed = @($rows | Where-Object { $_.pass }).Count
            not_hit = @($rows | Where-Object { -not $_.hit } | ForEach-Object { "$($_.point)/$($_.phase)" }); complete = $true })
        Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S
    }
} finally {
    Save-M2Run $R -Finished
}
$failed = @(@($S.phases) | Select-Object -Skip $PhaseCount0 | Where-Object { -not $_.ok })
Log "m2-crash $Stage done: $($failed.Count) failed phase(s)"
if ($failed.Count) { exit 1 }
exit 0
