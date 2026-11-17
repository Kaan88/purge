# Purge rig, M1b: typed-object crash matrix and hard power-off rounds (docs\M1B_DESIGN.json M1B-RIG-EXEC, gate G6
# K13; vm\RIG.md section 12). Template: the host (vm\rig-m1b-exec.ps1) replaces __RUN__, __MODE__ (m1b-x-crash),
# __STAGE__ and __OPTS__ (base64 JSON: cases_b64, batch, hard_poweroff, kinds, points) and submits it as an agent
# job. Windows PowerShell 5.1. `. m1b-crash.ps1 -Library` only defines the functions (the host self-test).
#
# Stages (each a separate job; the run directory and m1b-crash-state.json carry over):
#   start          install, `journal fault-points` (must equal the cases file's list), the round list; then matrix
#   matrix         up to opts.batch rounds; more left -> continuation 'reboot' to matrix again
#   after-poweroff (opts.hard_poweroff) the host powered the VM off while the engine sat at a PURGE_FAULT_PAUSE
#                  point; recover twice, resume, check; another power-off round -> continuation 'poweroff' again
# Round (kind k, point p, phase exec|undo, after resume|rollback): a clean slate, the app and ONE object of kind k
# planted under a name of its own (cases crash.round_objects), harvest, the app removed, scan --mode external, the
# object's item selected (it must be offered Safe), deep A, scoped snap A; exec (or exec then undo) with
# PURGE_FAULT_AT=p; `journal recover` twice (the second must change nothing); resume or rollback; resume of an
# exec-phase crash: scoped snap B + execdiff, then undo; resume of an undo-phase crash: the session must be Undone;
# deep C; fidelity A vs C; the object's own state (Get-ExObjectState) equal to the planted one.
# Unlike M2, a declared point that is not hit FAILS its row and the matrix (K13: 0 unreached).
# Engine calls: journal fault-points | harvest | scan --mode external | exec --fp (env PURGE_FAULT_AT) | undo
# --session (env PURGE_FAULT_AT for undo points) | journal recover | journal resume --session | journal rollback
# --session; power-off: exec or undo detached with PURGE_FAULT_PAUSE=<p>:600000.
param([switch]$Library)

# Saved before the dot-source below, which has a $Library of its own. The job file runs from C:\cr\jobs; the guest
# scripts are in C:\cr\guest (the host self-test dot-sources this file from vm\guest).
$CrashLibrary = [bool]$Library
$CrashLibDir = $(if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'm1b-exec.ps1'))) { $PSScriptRoot } else { 'C:\cr\guest' })
. (Join-Path $CrashLibDir 'm1b-exec.ps1') -Library
$Library = $CrashLibrary

$CrashKinds = @('service', 'task', 'firewall')

# ------------------------------------------------------------------------------------------ pure helpers

# The rounds the cases file asks for: per kind, per point reachable for it, per after. Each: {kind, point, phase,
# after}. $Kinds / $Points narrow it (a subset run); the full list is what K13 judges.
function Get-XCrashPlan($Cases, [string[]]$Kinds = @(), [string[]]$Points = @()) {
    $out = New-Object System.Collections.ArrayList
    $ks = $(if ($Kinds.Count) { $Kinds } else { $CrashKinds })
    foreach ($k in $ks) {
        foreach ($fp in @($Cases.crash.fault_points)) {
            if (-not $fp -or -not $fp.phase) { continue }
            if (@($fp.kinds) -notcontains $k) { continue }
            if ($Points.Count -and $Points -notcontains "$($fp.point)") { continue }
            $afters = $(if ("$($fp.phase)" -eq 'undo') { @($Cases.crash.undo_afters) } else { @($Cases.crash.exec_afters) })
            foreach ($a in $afters) { [void]$out.Add([pscustomobject][ordered]@{ kind = $k; point = "$($fp.point)"; phase = "$($fp.phase)"; after = "$a" }) }
        }
    }
    @($out)
}

# Compares the engine's declared points (`journal fault-points`) with the cases file: every declared point listed
# once, none listed that the engine does not declare, and for every kind either reachable or a reason given.
# Returns {missing, unknown, duplicate, no_reason, ok}.
function Test-XCasesCoverPoints($Cases, [string[]]$Declared) {
    $listed = @(@($Cases.crash.fault_points) | Where-Object { $_ } | ForEach-Object { "$($_.point)" })
    $dup = @($listed | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    $missing = @($Declared | Where-Object { $listed -cnotcontains $_ })
    $unknown = @($listed | Where-Object { $Declared -cnotcontains $_ })
    $noReason = @()
    foreach ($fp in @($Cases.crash.fault_points)) {
        if (-not $fp) { continue }
        foreach ($k in $CrashKinds) {
            $reach = (@($fp.kinds) -contains $k)
            $why = $null
            if ($fp.PSObject.Properties['not_reachable'] -and $fp.not_reachable -and $fp.not_reachable.PSObject.Properties[$k]) { $why = "$($fp.not_reachable.$k)" }
            if ($reach -and -not $fp.phase) { $noReason += "$($fp.point)/$k (reachable without a phase)" }
            if (-not $reach -and -not $why) { $noReason += "$($fp.point)/$k" }
            if ($reach -and $why) { $noReason += "$($fp.point)/$k (both reachable and a reason)" }
        }
    }
    [pscustomobject][ordered]@{ missing = $missing; unknown = $unknown; duplicate = $dup; no_reason = $noReason
        ok = (-not $missing.Count -and -not $unknown.Count -and -not $dup.Count -and -not $noReason.Count) }
}

# The pass rule of an abort row (m1b-exec.sh applies the same): the point was hit (the engine aborted), recover
# exited 0 twice with the same state, resume / rollback exited 0, an exec-phase resume's execdiff and undo ok, an
# undo-phase resume left the session Undone, fidelity exact and the object as planted. A point not hit FAILS.
function Set-XRowPass($Row) {
    if (-not $Row.hit) { $Row.pass = $false; return }
    $Row.pass = ($null -eq $Row.error -and $Row.crashed -and $Row.recover_exit -eq 0 -and $Row.recover2_exit -eq 0 -and $Row.recover_idempotent -eq $true `
            -and $Row.after_exit -eq 0 -and $Row.fidelity_ok -eq $true -and $Row.object_restored -eq $true `
            -and ($Row.phase -ne 'exec' -or $Row.after -ne 'resume' -or ($Row.execdiff_ok -eq $true -and $Row.undo_exit -eq 0)) `
            -and ($Row.phase -ne 'undo' -or $Row.undone_by_recovery -eq $true))
    if ($Row.kind -eq 'poweroff') { $Row.pass = ($Row.pass -and $Row.boot_changed -eq $true -and $Row.pfro_unchanged -eq $true) }
}

# The matrix summary (K13) from the rows and the plan: each planned (kind, point, phase, after) must have a row that
# hit and passed; a planned point with no row or with hit=false is unreached; power-off rounds per kind as asked.
function Get-XCrashSummary($Cases, $Rows, [string[]]$Kinds = @(), [string[]]$Points = @(), [switch]$HardPowerOff) {
    $plan = @(Get-XCrashPlan $Cases $Kinds $Points)
    $rows = @($Rows | Where-Object { $_ })
    $abort = @($rows | Where-Object { "$($_.kind)" -ne 'poweroff' })
    $unreached = New-Object System.Collections.ArrayList
    $failed = New-Object System.Collections.ArrayList
    foreach ($p in $plan) {
        $r = @($abort | Where-Object { "$($_.object_kind)" -eq $p.kind -and "$($_.point)" -eq $p.point -and "$($_.phase)" -eq $p.phase -and "$($_.after)" -eq $p.after })
        $id = "$($p.kind)/$($p.point)/$($p.phase)/$($p.after)"
        if (-not $r.Count -or -not ($r | Where-Object { $_.hit })) { [void]$unreached.Add($id); continue }
        if (-not ($r | Where-Object { $_.pass })) { [void]$failed.Add($id) }
    }
    $po = @($rows | Where-Object { "$($_.kind)" -eq 'poweroff' })
    $poKinds = [ordered]@{}
    $want = [int]$Cases.crash.poweroff.rounds_per_kind
    $ks = $(if ($Kinds.Count) { $Kinds } else { $CrashKinds })
    foreach ($k in $ks) {
        $kr = @($po | Where-Object { "$($_.object_kind)" -eq $k })
        $poKinds[$k] = [ordered]@{ rounds = $kr.Count; passed = @($kr | Where-Object { $_.pass }).Count; wanted = $(if ($HardPowerOff) { $want } else { 0 }) }
    }
    $poOk = (-not $HardPowerOff) -or -not @($poKinds.Keys | Where-Object { $poKinds[$_].passed -lt $want -or $poKinds[$_].rounds -ne $want }).Count
    [pscustomobject][ordered]@{ planned = $plan.Count; rows = $abort.Count; unreached = @($unreached); failed = @($failed)
        poweroff = $poKinds; poweroff_ok = $poOk; complete = (-not $Kinds.Count -and -not $Points.Count)
        pass = ($plan.Count -gt 0 -and -not $unreached.Count -and -not $failed.Count -and $poOk) }
}

# Power-off points per kind: the pool's first, then the rest drawn without replacement from a generator seeded by
# $Seed (so a run is repeatable from its name), $N in all.
function Get-XPoweroffPlan($Cases, [string]$Seed, [string[]]$Kinds = @()) {
    $n = [int]$Cases.crash.poweroff.rounds_per_kind
    $ks = $(if ($Kinds.Count) { $Kinds } else { $CrashKinds })
    $h = [Security.Cryptography.SHA256]::Create()
    try { $seedInt = [BitConverter]::ToInt32($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed)), 0) } finally { $h.Dispose() }
    $rng = New-Object System.Random($seedInt)
    $out = New-Object System.Collections.ArrayList
    foreach ($k in $ks) {
        $pool = New-Object System.Collections.ArrayList
        foreach ($x in @($Cases.crash.poweroff.pool.$k)) { if ($x) { [void]$pool.Add($x) } }
        if ($pool.Count -lt $n) { throw "power-off pool of $k has $($pool.Count) point(s), $n wanted" }
        $pick = @($pool[0]); $pool.RemoveAt(0)
        while ($pick.Count -lt $n) { $i = $rng.Next($pool.Count); $pick += $pool[$i]; $pool.RemoveAt($i) }
        foreach ($p in $pick) { [void]$out.Add([pscustomobject][ordered]@{ kind = $k; point = "$($p.point)"; phase = "$($p.phase)" }) }
    }
    @($out)
}

# A round's object: the kind's round variant under a name of its own (n = round number).
function New-XRoundDef($Cases, [string]$Kind, [int]$N) {
    $v = Get-ExVariant $Cases "$($Cases.crash.round_objects.$Kind)"
    $d = $v | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    switch ($Kind) {
        'service' { $d.name = ('PurgeExecCr{0:000}' -f $N); $d.plant.exe = ('PurgeExecCr{0:000}.exe' -f $N) }
        'task' { $d.path = ('{0}\Crash {1:000}' -f $ExTaskRoot, $N) }
        'firewall' { $d.rule = ('PurgeExecFwCr{0:000}' -f $N) }
    }
    $d
}

function New-XRow([int]$N, [string]$ObjectKind, [string]$Point, [string]$Phase, [string]$After, [string]$Kind = 'abort') {
    [ordered]@{ n = $N; kind = $Kind; object_kind = $ObjectKind; point = $Point; phase = $Phase; after = $After; tag = $null; object = $null; item = $null; band = $null
        session = $null; hit = $false; fault_exit = $null; crashed = $false; recover_exit = $null; recover2_exit = $null; recover_idempotent = $null; after_exit = $null
        undo_exit = $null; execdiff_ok = $null; undone_by_recovery = $null; fidelity_ok = $null; object_restored = $null; boot_changed = $null; pfro_unchanged = $null
        error = $null; notes = @(); pass = $false }
}

if ($Library) { return }

# ============================================================================================ main
# (The placeholders sit after the library return so the self-test can dot-source this file.)
$Run = '__RUN__'
$Mode = '__MODE__'
$Stage = '__STAGE__'
$OptsB64 = '__OPTS__'
if ($Run -eq ('__' + 'RUN__') -or $Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { Write-Host ("m1b-crash.ps1: bad or unreplaced run name '{0}'" -f $Run); exit 2 }
if ($Mode -ne 'm1b-x-crash') { Write-Host ("m1b-crash.ps1: bad or unreplaced mode '{0}'" -f $Mode); exit 2 }
if ($Stage -eq ('__' + 'STAGE__')) { $Stage = 'start' }
if (@('start', 'matrix', 'after-poweroff') -cnotcontains $Stage) { Write-Host ("m1b-crash.ps1: bad stage '{0}'" -f $Stage); exit 2 }
. C:\cr\guest\riglib.ps1
Assert-ExRigVm

$Opts = ConvertFrom-M2Opts $OptsB64
$R = Open-M2Run $Run $Mode $Stage
$D = $R.dir
$S = $R.S
$Calls = $S.engine.calls
$StateFile = Join-Path $D 'm1b-crash-state.json'
$MatrixFile = Join-Path $D 'crash-matrix.json'
$PhaseCount0 = $S.phases.Count
$Kinds = @(@(Get-M2Opt $Opts 'kinds' @()) | ForEach-Object { "$_" } | Where-Object { $_ })
$Points = @(@(Get-M2Opt $Opts 'points' @()) | ForEach-Object { "$_" } | Where-Object { $_ })
$HardPO = ((Get-M2Opt $Opts 'hard_poweroff' $false) -eq $true)

function Q([string]$s) { ConvertTo-EngineArg $s }
function F([string]$n) { Join-Path $D $n }
function Read-Json([string]$p) { if (Test-Path -LiteralPath $p) { [IO.File]::ReadAllText($p) | ConvertFrom-Json } else { $null } }
function Save-State($St) { Write-JsonFile $St $StateFile 10 }
function ConvertTo-Tag([string]$s) { ($s -replace '[^A-Za-z0-9_-]', '_').ToLowerInvariant() }

# Files, keys and objects of a deep document without its header; two equal values = the same state.
function Get-XDeepState([string]$Path) {
    $j = Read-Json $Path
    if (-not $j) { return $null }
    (ConvertTo-Json -InputObject @{ files = $j.files; keys = $j.keys; objects = $j.objects } -Depth 20 -Compress)
}

function Add-MatrixRow($Row) {
    $rows = New-Object System.Collections.ArrayList
    $m = Read-Json $MatrixFile
    if ($m) { foreach ($x in @($m.rows)) { if ($x) { [void]$rows.Add($x) } } }
    [void]$rows.Add($Row)
    Write-JsonFile ([ordered]@{ schema = 'purge.rig.m1b-crashmatrix/1'; run = $Run; points = $script:St.points; kinds = $Kinds; filter_points = $Points; rows = @($rows) }) $MatrixFile 10
}

# Scoped snapshot roots of a round's object, the store and the Session Manager key (-BootStable: its Environment
# subkey only; the round compares PendingFileRenameOperations itself).
function Get-XRoots([string]$Kind, [string]$Name, [string]$TaskId, [switch]$BootStable) {
    $r = @()
    switch ($Kind) {
        'service' { $r += "$ExSvcKey\$Name" }
        'task' {
            $r += (Join-Path $ExTasksDir $ExTaskRoot.TrimStart('\'))
            $r += "$ExTaskCache\Tree$ExTaskRoot"
            if ($TaskId) { $r += "$ExTaskCache\Tasks\$TaskId"; $r += "$ExTaskCache\Plain\$TaskId" }
        }
        'firewall' { $r += $ExFwKey }
    }
    $r += $RigPurgeData
    $r += $(if ($BootStable) { "$RigPfroKey\Environment" } else { $RigPfroKey })
    @($r)
}

# A fresh round: clean slate, app + one object planted, harvest, uninstall stand-in, scan; the object's item must be
# offered Safe; deep A and scoped snap A. Returns the round record.
function New-XRound($Cases, [string]$Kind, [int]$N, [string]$Tag, [switch]$BootStable) {
    Clear-ExWorld $Cases
    New-ExApp
    $def = New-XRoundDef $Cases $Kind $N
    $name = Get-ExObjectName $def
    $planted = Add-ExObject $def
    $sc = Invoke-ExHarvestScan $Tag $D $Calls
    $row = Find-ExRow $sc.rows $Kind $name
    if (-not $row) { throw "the plan has no item for $Kind $name" }
    if ($row.band -ne 'Safe') { throw "$Kind $name is offered $($row.band), not Safe" }
    $taskId = $null
    if ($Kind -eq 'task') { $taskId = Get-RegRaw "$ExTaskCache\Tree$name" 'Id' }
    $ids = @($row.id)
    $sp = Split-ExObjects @([pscustomobject]@{ kind = $Kind; name = $name })
    $scope = F "deepscope-$Tag.json"
    Write-JsonFile (New-ExDeepScope $sp.service $sp.task $sp.firewall @($row.target)) $scope 12
    $rec = [pscustomobject][ordered]@{ tag = $Tag; kind = $Kind; name = $name; planted = $planted; scan = $sc; item = $row.id; band = $row.band; ids = $ids
        select = (Write-M2IdFile $ids (F "select-$Tag.json")); confirm = (Get-M2Confirm $sc.plan_hash $ids); scope = $scope
        roots = @(Get-XRoots $Kind $name $taskId -BootStable:$BootStable); session = $null; journal = $null; report = $null
        pfro_before = $(if ($BootStable) { , @(Get-PfroList) } else { $null }) }
    $null = Invoke-M2Deep @($scope) (F "deep-$Tag-a.json")
    $null = Invoke-M2Snap (F "snap-$Run-$Tag-a.tsv.gz") $rec.roots
    $rec
}

function Invoke-XExec($Rec, [hashtable]$Environment = @{}) {
    $before = @(Get-M2Sessions)
    $rep = F "report-$($Rec.tag).json"
    $r = Invoke-M2Engine -Step "exec-$($Rec.tag)" -Arguments (New-ExExecArgs $Rec.scan.plan $Rec.confirm $Rec.select $Rec.scan.fp $rep) -Calls $Calls -Environment $Environment -StdoutFile (F "exec-$($Rec.tag).out") -NoThrow
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

function Invoke-RecoverTwice($Rec, $Row) {
    $r1 = Invoke-Journal 'recover' '' "$($Rec.tag)-1"
    $null = Invoke-M2Deep @($Rec.scope) (F "deep-$($Rec.tag)-r1.json")
    $r2 = Invoke-Journal 'recover' '' "$($Rec.tag)-2"
    $null = Invoke-M2Deep @($Rec.scope) (F "deep-$($Rec.tag)-r2.json")
    $Row.recover_exit = $r1.exit
    $Row.recover2_exit = $r2.exit
    $Row.recover_idempotent = ($r2.exit -eq 0 -and (Get-XDeepState (F "deep-$($Rec.tag)-r1.json")) -eq (Get-XDeepState (F "deep-$($Rec.tag)-r2.json")))
}

# After recover: resume (exec phase: then snap B, execdiff, undo; undo phase: Undone) or rollback; deep C, fidelity
# A vs C, and the object's own state against the planted one.
function Complete-XRound($Rec, $Row, [string]$After) {
    $tag = $Rec.tag
    if ($After -eq 'rollback') {
        $Row.after_exit = (Invoke-Journal 'rollback' $Rec.session $tag).exit
    } else {
        $Row.after_exit = (Invoke-Journal 'resume' $Rec.session $tag).exit
        if ($Row.phase -eq 'exec') {
            $null = Invoke-M2Snap (F "snap-$Run-$tag-b.tsv.gz") $Rec.roots
            if (-not $Rec.report -and $Rec.session -and (Test-Path -LiteralPath (Join-Path (Get-M2SessionDir $Rec.session) 'report.json'))) { $Rec.report = Join-Path (Get-M2SessionDir $Rec.session) 'report.json' }
            if ($Rec.report -and $Rec.journal) {
                $v = Invoke-M2Execdiff -Before (F "snap-$Run-$tag-a.tsv.gz") -After (F "snap-$Run-$tag-b.tsv.gz") -Journal $Rec.journal -Report $Rec.report -Out (F "execdiff-$tag.json")
                $Row.execdiff_ok = $v.ok
            } else { $Row.execdiff_ok = $null; $Row.notes += 'no report after resume: execdiff not run' }
            $u = Invoke-M2Engine -Step "undo-$tag" -Arguments (New-M2UndoArgs $Rec.session '' '' (F "undo-$tag.json")) -Calls $Calls -StdoutFile (F "undo-$tag.out") -NoThrow
            $Row.undo_exit = $u.exit
        } else {
            $st = $null
            try { $o = Read-Json (F "journal-resume-$tag.out"); if ($o) { $st = "$(@($o.sessions)[0].state)" } } catch { $st = $null }
            $Row.undone_by_recovery = ($st -eq 'Undone')
            if (-not $Row.undone_by_recovery) { $Row.notes += "resume left the session '$st', not Undone" }
        }
    }
    $null = Copy-M2Session $Rec.session $D "sess-$tag"
    $null = Invoke-M2Deep @($Rec.scope) (F "deep-$tag-c.json")
    $Row.fidelity_ok = (Invoke-M2Fidelity (F "deep-$tag-a.json") (F "deep-$tag-c.json") $Rec.journal (F "fidelity-$tag.json")).ok
    $now = Get-ExStateRecord $Rec.kind $Rec.name
    $Row.object_restored = ($now.present -and $now.sha256 -eq $Rec.planted.sha256)
    if (-not $Row.object_restored) { $Row.notes += "object state after the round: present=$($now.present) sha $($now.sha256) (planted $($Rec.planted.sha256))" }
}

function Invoke-XRound($It) {
    $row = New-XRow $It.n $It.kind $It.point $It.phase $It.after
    $tag = ConvertTo-Tag ('c{0:000}-{1}-{2}-{3}-{4}' -f $It.n, $It.kind, $It.phase, $It.point, $It.after)
    $row.tag = $tag
    try {
        $rec = New-XRound $script:Cases $It.kind $It.n $tag
        $row.object = $rec.name; $row.item = $rec.item; $row.band = $rec.band
        $fault = @{ PURGE_FAULT_AT = $It.point }
        if ($It.phase -eq 'exec') {
            $x = Invoke-XExec $rec $fault
        } else {
            $x0 = Invoke-XExec $rec
            if ($x0.exit -ne 0) { throw "exec before the undo fault exited $($x0.exit)" }
            $x = Invoke-M2Engine -Step "undo-fault-$tag" -Arguments (New-M2UndoArgs $rec.session '' '' (F "undo-fault-$tag.json")) -Calls $Calls -Environment $fault -StdoutFile (F "undo-fault-$tag.out") -NoThrow
        }
        $row.session = $rec.session
        $row.fault_exit = $x.exit
        $row.crashed = [bool]$x.crashed
        $row.hit = $row.crashed
        if ($rec.session) { $null = Copy-M2Session $rec.session $D "sess-$tag-crash" }
        if ($row.hit) {
            Invoke-RecoverTwice $rec $row
            Complete-XRound $rec $row $It.after
        } else {
            $row.notes += "point not reached (exit $($x.exit)): FAIL"
            # Leave the machine as planted for the next round's clean slate: undo what a finished exec did.
            if ($x.exit -eq 0 -and $rec.session -and $It.phase -eq 'exec') {
                $null = Invoke-M2Engine -Step "undo-$tag" -Arguments (New-M2UndoArgs $rec.session '' '' (F "undo-$tag.json")) -Calls $Calls -StdoutFile (F "undo-$tag.out") -NoThrow
            }
        }
    } catch {
        $row.error = "$($_.Exception.Message)"
        Log "!! round $tag`: $($row.error)"
    }
    Set-XRowPass $row
    Write-JsonFile $row (F "crash-$tag.json") 8
    Add-MatrixRow $row
    Log ("round {0}: hit={1} pass={2}" -f $tag, $row.hit, $row.pass)
}

# ------------------------------------------------------------------------------------------- power-off part

# exec or undo started detached (shell execute, no inherited handles; m2-crash Start-PausedExec) with
# PURGE_FAULT_PAUSE=<p>:600000; returns once the session's journal has not grown for ~6 s.
function Start-XPaused($Rec, [string]$Point, [string]$Phase) {
    $before = @(Get-M2Sessions)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Get-M2EngineExe
    $psi.Arguments = $(if ($Phase -eq 'undo') { New-M2UndoArgs $Rec.session '' '' (F "undo-paused-$($Rec.tag).json") } else { New-ExExecArgs $Rec.scan.plan $Rec.confirm $Rec.select $Rec.scan.fp (F "report-$($Rec.tag).json") })
    $psi.UseShellExecute = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    Log "engine (detached): [PURGE_FAULT_PAUSE=$Point`:600000] `"$($psi.FileName)`" $($psi.Arguments)"
    $Rec | Add-Member -NotePropertyName durable -NotePropertyValue (Save-RigDurableState) -Force
    $oldPause = $env:PURGE_FAULT_PAUSE
    $env:PURGE_FAULT_PAUSE = "$Point`:600000"
    try { $p = [System.Diagnostics.Process]::Start($psi) } finally { $env:PURGE_FAULT_PAUSE = $oldPause }
    [void]$Calls.Add([ordered]@{ step = "$Phase-paused-$($Rec.tag)"; cmd = "`"$($psi.FileName)`" $($psi.Arguments)"; env = "PURGE_FAULT_PAUSE=$Point`:600000"; exit = $null; crashed = $false; timed_out = $false; pid = $p.Id; start = (NowIso); end = $null; stderr_tail = @() })
    $deadline = (Get-Date).AddSeconds(240); $last = -1; $stable = 0
    $s = $(if ($Phase -eq 'undo') { $Rec.session } else { $null })
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
    if ($Phase -ne 'undo') { $Rec.session = $s; if ($s) { $Rec.journal = Join-Path (Get-M2SessionDir $s) 'journal.jsonl' } }
    [pscustomobject]@{ process = $p; session = $s; paused = ($stable -ge 6 -and -not $p.HasExited); exited = $p.HasExited; exit = $(if ($p.HasExited) { $p.ExitCode }) }
}

function Request-XPoweroff {
    $St = $script:St
    while ($St.poweroff_todo.Count) {
        $po = $St.poweroff_todo[0]
        $St.poweroff_todo = @($St.poweroff_todo | Select-Object -Skip 1)
        $n = 900 + $St.poweroff_done.Count
        $tag = ConvertTo-Tag ('p{0:000}-{1}-{2}-{3}-poweroff' -f $n, $po.kind, $po.phase, $po.point)
        $rec = $null; $pz = $null; $err = $null
        try {
            $rec = New-XRound $script:Cases "$($po.kind)" $n $tag -BootStable
            if ("$($po.phase)" -eq 'undo') {
                $x0 = Invoke-XExec $rec
                if ($x0.exit -ne 0) { throw "exec before the paused undo exited $($x0.exit)" }
            }
            $pz = Start-XPaused $rec "$($po.point)" "$($po.phase)"
        } catch { $err = "$($_.Exception.Message)"; Log "!! power-off $tag`: $err" }
        if ($pz -and $pz.paused) {
            $St.pending = [ordered]@{ n = $n; kind = "$($po.kind)"; point = "$($po.point)"; phase = "$($po.phase)"; tag = $tag; rec = $rec }
            Save-State $St
            $null = Request-RigContinuation $Run 'poweroff' 'after-poweroff' ([ordered]@{ point = "$($po.point)"; kind = "$($po.kind)"; tag = $tag; session = $rec.session; pid = $pz.process.Id })
            return $true
        }
        $row = New-XRow $n "$($po.kind)" "$($po.point)" "$($po.phase)" 'resume' 'poweroff'
        $row.tag = $tag
        $row.error = $(if ($err) { $err } elseif ($pz) { "engine did not pause at $($po.point) (exited=$($pz.exited), exit $($pz.exit))" } else { 'power-off round could not be prepared' })
        if ($pz -and -not $pz.process.HasExited) { Stop-Process -Id $pz.process.Id -Force -ErrorAction SilentlyContinue }
        Set-XRowPass $row
        Write-JsonFile $row (F "crash-$tag.json") 8
        Add-MatrixRow $row
        $St.poweroff_done += $tag
        Save-State $St
    }
    $false
}

function Complete-XPoweroff {
    $St = $script:St
    $m = Receive-RigContinuation $Run
    $pd = $St.pending
    if (-not $pd) { throw 'after-poweroff without a pending power-off round' }
    $rec = $pd.rec
    $row = New-XRow ([int]$pd.n) "$($pd.kind)" "$($pd.point)" "$($pd.phase)" 'resume' 'poweroff'
    $row.tag = $pd.tag; $row.session = $rec.session; $row.object = $rec.name; $row.item = $rec.item; $row.band = $rec.band
    $row.hit = $true; $row.crashed = $true
    $row.boot_changed = [bool]($m -and $m.boot_before -and $m.boot_after -and $m.boot_before -ne $m.boot_after)
    if (-not $row.boot_changed) { $row.notes += 'boot id unchanged: the VM was not powered off' }
    try {
        Invoke-RecoverTwice $rec $row
        Complete-XRound $rec $row 'resume'
    } catch { $row.error = "$($_.Exception.Message)" }
    $pb = @($rec.pfro_before | Where-Object { $null -ne $_ }); $pa = @(Get-PfroList | Where-Object { $null -ne $_ })
    $row.pfro_unchanged = (($pb -join "`n") -ceq ($pa -join "`n"))
    if (-not $row.pfro_unchanged) { $row.notes += "PendingFileRenameOperations changed: $($pb.Count) -> $($pa.Count) entries" }
    Set-XRowPass $row
    Write-JsonFile $row (F "crash-$($pd.tag).json") 8
    Add-MatrixRow $row
    $St.poweroff_done += "$($pd.tag)"
    $St.pending = $null
    Save-State $St
}

# ------------------------------------------------------------------------------------------------------- main
$script:St = $null
$script:Cases = $null
try {
    $script:Cases = Read-ExCases $Opts
    if ($Stage -eq 'start') {
        Phase 'edge-pause' { $S.edge_pause = Suspend-EdgeUpdate } $S
        Phase 'telemetry-pause' { $S.telemetry_pause = Suspend-M2Telemetry } $S
        Phase 'install' {
            $r1 = Invoke-M2Script $RigInstallScript ('-Engine ' + (Q $RigEngine) + ' -ReportPath ' + (Q (F 'install.json')))
            Set-M2Result $R 'install' ([ordered]@{ exit = $r1.exit })
            if ($r1.exit -ne 0) { throw "install.ps1 exited $($r1.exit)" }
            $S.engine.exe = Get-M2EngineExe
        } $S
        Phase 'fault-points' {
            Write-JsonFile $script:Cases (F 'm1b-exec-cases.json') 20
            $null = Invoke-M2Engine -Step 'fault-points' -Arguments (New-M2JournalArgs 'fault-points') -Calls $Calls -StdoutFile (F 'fault-points.out')
            $declared = @(ConvertFrom-M2FaultPoints ([IO.File]::ReadAllText((F 'fault-points.out'))))
            if (-not $declared.Count) { throw 'journal fault-points listed no point' }
            $cov = Test-XCasesCoverPoints $script:Cases $declared
            Set-M2Result $R 'fault_points' ([ordered]@{ declared = $declared; cover = $cov })
            if (-not $cov.ok) { throw "cases file and engine fault points differ: missing $($cov.missing -join ',') unknown $($cov.unknown -join ',') dup $($cov.duplicate -join ',') no reason $($cov.no_reason -join ',')" }
            $badKinds = @($Kinds | Where-Object { $CrashKinds -notcontains $_ })
            if ($badKinds.Count) { throw "unknown kinds: $($badKinds -join ', ')" }
            $plan = @(Get-XCrashPlan $script:Cases $Kinds $Points)
            if (-not $plan.Count) { throw 'no crash round planned' }
            $its = New-Object System.Collections.ArrayList
            $n = 0
            foreach ($p in $plan) { [void]$its.Add([ordered]@{ n = ++$n; kind = $p.kind; point = $p.point; phase = $p.phase; after = $p.after }) }
            $po = @()
            if ($HardPO) {
                $po = @(Get-XPoweroffPlan $script:Cases $Run $Kinds | ForEach-Object { [ordered]@{ kind = $_.kind; point = $_.point; phase = $_.phase } })
                $S.boot_policy = Set-RigBootPolicyIgnoreFailures
            }
            $script:St = [ordered]@{ schema = 'purge.rig.m1b-crashstate/1'; points = $declared; todo = @($its); done = 0; poweroff_todo = $po; poweroff_done = @(); pending = $null }
            Save-State $script:St
            Remove-Item -LiteralPath $MatrixFile -Force -ErrorAction SilentlyContinue
        } $S
        if (-not $script:St) { throw 'no crash state (fault-points failed)' }
    } else {
        $j = Read-Json $StateFile
        if (-not $j) { throw "no $StateFile" }
        $script:St = [ordered]@{ schema = $j.schema; points = @($j.points); todo = @($j.todo | Where-Object { $_ }); done = [int]$j.done
            poweroff_todo = @($j.poweroff_todo | Where-Object { $_ }); poweroff_done = @($j.poweroff_done | Where-Object { $_ }); pending = $j.pending }
        if ($Stage -eq 'matrix') { $null = Receive-RigContinuation $Run }
    }
    $continued = $false
    if ($Stage -eq 'after-poweroff') {
        Phase 'poweroff-check' { Complete-XPoweroff } $S
    } else {
        $batch = [int](Get-M2Opt $Opts 'batch' 12)
        $k = 0
        while ($script:St.todo.Count -and ($batch -le 0 -or $k -lt $batch)) {
            $it = $script:St.todo[0]
            Phase ("round-{0}" -f $it.n) { Invoke-XRound $it } $S
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
        Phase 'poweroff-request' { $script:Requested = Request-XPoweroff } $S
        $continued = [bool]$script:Requested
    }
    if (-not $continued) {
        Phase 'cleanup' { Clear-ExWorld $script:Cases } $S
        $m = Read-Json $MatrixFile
        $rows = @(); if ($m) { $rows = @(@($m.rows) | Where-Object { $_ }) }
        $sum = Get-XCrashSummary $script:Cases $rows $Kinds $Points -HardPowerOff:$HardPO
        Set-M2Result $R 'crash' $sum
        Log ("crash matrix: planned {0}, rows {1}, unreached {2}, failed {3}, power-off ok {4}, pass {5}" -f $sum.planned, $sum.rows, $sum.unreached.Count, $sum.failed.Count, $sum.poweroff_ok, $sum.pass)
        Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S
    }
} finally {
    Save-M2Run $R -Finished
}
$failed = @(@($S.phases) | Select-Object -Skip $PhaseCount0 | Where-Object { -not $_.ok })
Log "m1b-crash $Stage done: $($failed.Count) failed phase(s)"
if ($failed.Count) { exit 1 }
exit 0
