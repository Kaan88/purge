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
# A power-off round is hit only when the session journal, read after the boot and before recovery, shows the cut
# inside the run (Test-XCutMidRun, review R4 S1): exec: no commit / aborted, and an open intent at the points between
# intent and done; undo: an undo_intent without its end. An exec/resume round also needs execdiff unexplained = 0.
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

# The phases a fault point is run in: {phase, afters}. `phase` with the cases' exec_afters / undo_afters, then each
# `more_phases` entry ({phase, afters, why}: a point also hit in another phase, e.g. index.write after an exec's
# commit, which has no rollback). None for a point without a phase.
function Get-XPointPhases($Cases, $Fp) {
    $out = New-Object System.Collections.ArrayList
    $def = { param($ph) if ("$ph" -eq 'undo') { @($Cases.crash.undo_afters) } else { @($Cases.crash.exec_afters) } }
    if ($Fp.phase) { [void]$out.Add([pscustomobject]@{ phase = "$($Fp.phase)"; afters = @(& $def $Fp.phase) }) }
    if ($Fp.PSObject.Properties['more_phases']) {
        foreach ($m in @($Fp.more_phases)) {
            if (-not $m -or -not $m.phase) { continue }
            $af = $(if ($m.PSObject.Properties['afters'] -and @($m.afters).Count) { @($m.afters) } else { @(& $def $m.phase) })
            [void]$out.Add([pscustomobject]@{ phase = "$($m.phase)"; afters = $af })
        }
    }
    @($out)
}

# The rounds the cases file asks for: per kind, per point reachable for it, per phase, per after. Each: {kind,
# point, phase, after}. $Kinds / $Points narrow it (a subset run). What K13 judges is m1b-exec.sh GATE_ROUNDS, not
# this list: a cases file that drops a round leaves a gate round unreached.
function Get-XCrashPlan($Cases, [string[]]$Kinds = @(), [string[]]$Points = @()) {
    $out = New-Object System.Collections.ArrayList
    $ks = $(if ($Kinds.Count) { $Kinds } else { $CrashKinds })
    foreach ($k in $ks) {
        foreach ($fp in @($Cases.crash.fault_points)) {
            if (-not $fp) { continue }
            if (@($fp.kinds) -notcontains $k) { continue }
            if ($Points.Count -and $Points -notcontains "$($fp.point)") { continue }
            foreach ($ph in @(Get-XPointPhases $Cases $fp)) {
                foreach ($a in @($ph.afters)) { [void]$out.Add([pscustomobject][ordered]@{ kind = $k; point = "$($fp.point)"; phase = $ph.phase; after = "$a" }) }
            }
        }
    }
    @($out)
}

# What a session journal (journal.jsonl text) says about where its run stood: record counts, whether the run ended
# (commit / aborted), the ops with an intent and no done, the ops with an undo_intent and no undo_done /
# undo_conflict. Only `\n`-terminated lines count (a torn tail is ignored, as the engine's reader does); a line that
# does not parse is counted in bad_lines.
function Get-XJournalFacts([string]$Text) {
    $f = [ordered]@{ lines = 0; bad_lines = 0; torn_tail = $false; recs = [ordered]@{}; commit = $false; aborted = $false
        open_intents = @(); open_undo = @(); last = $null }
    if ($null -eq $Text) { return $null }
    $cut = $Text.LastIndexOf("`n")
    $f.torn_tail = ($cut -lt $Text.Length - 1)
    if ($cut -lt 0) { return [pscustomobject]$f }
    $intent = @{}; $done = @{}; $uintent = @{}; $uend = @{}
    foreach ($line in $Text.Substring(0, $cut).Split("`n")) {
        if (-not $line.Trim()) { continue }
        $f.lines++
        $j = $null; try { $j = $line | ConvertFrom-Json } catch { $j = $null }
        if (-not $j -or -not $j.rec) { $f.bad_lines++; continue }
        $r = "$($j.rec)"; $f.last = $r
        if ($f.recs.Contains($r)) { $f.recs[$r]++ } else { $f.recs[$r] = 1 }
        $op = "$($j.op)"
        switch ($r) {
            'commit' { $f.commit = $true }
            'aborted' { $f.aborted = $true }
            'intent' { $intent[$op] = $true }
            'done' { $done[$op] = $true }
            'undo_intent' { $uintent[$op] = $true }
            { $_ -eq 'undo_done' -or $_ -eq 'undo_conflict' } { $uend[$op] = $true }
        }
    }
    $f.open_intents = @($intent.Keys | Where-Object { -not $done.ContainsKey($_) } | Sort-Object)
    $f.open_undo = @($uintent.Keys | Where-Object { -not $uend.ContainsKey($_) } | Sort-Object)
    [pscustomobject]$f
}

# The exec points a paused run sits at with an intent and no done yet.
$CrashOpenIntentPoints = @('intent.flushed', 'act.before', 'act.after', 'objdelete.after', 'done.before')

# Whether the journal facts show the run cut mid-way at $Point (review R4 S1): exec phase: no commit, no aborted, an
# intent written, and at a point between intent and done an op still open; undo phase: an undo_intent without its
# undo_done / undo_conflict. Returns {ok, why}.
function Test-XCutMidRun($Facts, [string]$Phase, [string]$Point) {
    if (-not $Facts) { return [pscustomobject]@{ ok = $false; why = 'no journal' } }
    if ($Facts.bad_lines) { return [pscustomobject]@{ ok = $false; why = "$($Facts.bad_lines) unreadable journal line(s)" } }
    if ($Phase -eq 'undo') {
        if (-not @($Facts.open_undo).Count) { return [pscustomobject]@{ ok = $false; why = 'no open undo_intent: the undo had finished (or not started) at the cut' } }
        return [pscustomobject]@{ ok = $true; why = "undo op(s) $(@($Facts.open_undo) -join ',') open" }
    }
    if ($Facts.commit -or $Facts.aborted) { return [pscustomobject]@{ ok = $false; why = "the run had ended (commit $($Facts.commit), aborted $($Facts.aborted)) before the cut" } }
    if (-not $Facts.recs.Contains('intent')) { return [pscustomobject]@{ ok = $false; why = 'no intent in the journal' } }
    if ($CrashOpenIntentPoints -contains $Point -and -not @($Facts.open_intents).Count) { return [pscustomobject]@{ ok = $false; why = "no open intent at $Point" } }
    [pscustomobject]@{ ok = $true; why = "no commit; open intent(s) [$(@($Facts.open_intents) -join ',')]" }
}

function Read-XJournalText([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try { $sr = New-Object IO.StreamReader($fs, (New-Object System.Text.UTF8Encoding($false))); $sr.ReadToEnd() } finally { $fs.Dispose() }
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
            if ($reach -and -not @(Get-XPointPhases $Cases $fp).Count) { $noReason += "$($fp.point)/$k (reachable without a phase)" }
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
            -and ($Row.phase -ne 'exec' -or $Row.after -ne 'resume' -or ($Row.execdiff_ok -eq $true -and $Row.execdiff_unexplained -is [int] -and $Row.execdiff_unexplained -eq 0 -and $Row.undo_exit -eq 0)) `
            -and ($Row.phase -ne 'undo' -or $Row.undone_by_recovery -eq $true))
    # A power-off round counts only when the journal read after the boot shows the cut inside the run (review R4 S1).
    if ($Row.kind -eq 'poweroff') { $Row.pass = ($Row.pass -and $Row.boot_changed -eq $true -and $Row.pfro_unchanged -eq $true -and $Row.cut_mid_run -eq $true) }
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
        if (-not $r.Count -or ($r | Where-Object { -not $_.hit })) { [void]$unreached.Add($id); continue }
        if ($r | Where-Object { -not $_.pass }) { [void]$failed.Add($id) }
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
        undo_exit = $null; execdiff_ok = $null; execdiff_unexplained = $null; execdiff_collateral = $null; cut_mid_run = $null; cut = $null; cut_at_pause = $null; undone_by_recovery = $null; fidelity_ok = $null; object_restored = $null; boot_changed = $null; pfro_unchanged = $null
        error = $null; notes = @(); pass = $false }
}

# The rig's GUID pattern (riglib $RigGuidRx; repeated here because the -Library self-test does not load riglib). \A and
# \z, not ^ and $: '$' also matches before a trailing newline, which would pass on into a command line (review R8 M4).
$XGuidRx = '\A\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\z'

# A task's Id value from TaskCache\Tree\<path> (raw REG_SZ) as a braced GUID. The value can carry its NUL
# terminator (2026-11-19: '{...}<NUL>' went into a snap --root and truncated the rigtool command line, so no task
# round ran), so trailing NULs are trimmed; anything that is not then a GUID throws.
function ConvertTo-XTaskId($Raw) {
    if ($null -eq $Raw) { throw 'the task has no Id value in TaskCache\Tree' }
    if ($Raw -isnot [string]) { throw "the task's Id value is a $($Raw.GetType().Name), not a string" }
    $id = $Raw.TrimEnd([char]0)
    if ($id -notmatch $XGuidRx) { throw ("the task's Id value '{0}' is not a GUID" -f ($Raw -replace "`0", '\0')) }
    $id
}

# Scoped snapshot roots of a round's object, the store and the Session Manager key (-BootStable: its Environment
# subkey only; the round compares PendingFileRenameOperations itself). Pure; above the -Library return for the
# self-test ($RigPurgeData / $RigPfroKey come from riglib).
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
    if ($Kind -eq 'task') { $taskId = ConvertTo-XTaskId (Get-RegRaw "$ExTaskCache\Tree$name" 'Id') }
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
                # An added record nothing authorises fails the row (review R4 S2); the counts come from the verdict file.
                $ed = Read-Json (F "execdiff-$tag.json")
                if ($ed -and $ed.counts) {
                    if ($null -ne $ed.counts.unexplained) { $Row.execdiff_unexplained = [int]$ed.counts.unexplained }
                    if ($null -ne $ed.counts.collateral) { $Row.execdiff_collateral = [int]$ed.counts.collateral }
                }
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
    Assert-NoNul $psi.Arguments 'engine command line'                     # as Invoke-Engine (review R8 M4)
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
        $atPause = $null
        if ($pz -and $pz.paused) {
            # Where the paused run stands (diagnostic; the proof is the journal read after the boot).
            $fa = Get-XJournalFacts (Read-XJournalText $rec.journal)
            $atPause = [ordered]@{ facts = $fa; verdict = (Test-XCutMidRun $fa "$($po.phase)" "$($po.point)"); pid = $pz.process.Id; exited = $pz.process.HasExited }
        }
        if ($pz -and $pz.paused) {
            $St.pending = [ordered]@{ n = $n; kind = "$($po.kind)"; point = "$($po.point)"; phase = "$($po.phase)"; tag = $tag; rec = $rec; at_pause = $atPause }
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
    $row.boot_changed = [bool]($m -and $m.boot_before -and $m.boot_after -and $m.boot_before -ne $m.boot_after)
    if (-not $row.boot_changed) { $row.notes += 'boot id unchanged: the VM was not powered off' }
    $row.cut_at_pause = $pd.at_pause
    # Proof that the cut landed inside the run (review R4 S1): the session journal as the boot found it, read before
    # recovery touches it. An exec that had committed, or an undo with no open undo_intent, is not a power-off round.
    $cut = $null
    try {
        $facts = Get-XJournalFacts (Read-XJournalText $rec.journal)
        $cut = Test-XCutMidRun $facts "$($pd.phase)" "$($pd.point)"
        $row.cut = [ordered]@{ journal = $rec.journal; facts = $facts; ok = $cut.ok; why = $cut.why }
    } catch { $row.cut = [ordered]@{ journal = $rec.journal; ok = $false; why = "journal not read: $($_.Exception.Message)" } }
    $row.cut_mid_run = [bool]($cut -and $cut.ok)
    if (-not $row.cut_mid_run) { $row.notes += "cut not inside the run: $($row.cut.why)" }
    $row.hit = $row.cut_mid_run
    $row.crashed = $row.boot_changed
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
            $r1 = Invoke-M2Script $RigInstallScript ('-Engine ' + (Q $RigEngine) + ' -EngineOnly -ReportPath ' + (Q (F 'install.json')))
            Set-M2Result $R 'install' ([ordered]@{ exit = $r1.exit })
            if ($r1.exit -ne 0) { throw "install.ps1 exited $($r1.exit)" }
            $S.engine.exe = Get-M2EngineExe
            Set-M2Result $R 'engine_build' (Get-ExEngineBuild $Opts $RigEngine $RigEngineInstalled)
        } $S
        Phase 'fault-points' {
            Write-JsonFile $script:Cases (F 'm1b-exec-cases.json') 20
            Set-M2Result $R 'cases' ([ordered]@{ schema = "$($script:Cases.schema)"; sha256 = (Get-ExCasesSha $Opts) })
            # The ambient set the rounds' execdiffs use, as m1b-exec.ps1 records it (m1b-exec.sh BIND, review R8 S3).
            Set-M2Result $R 'ambient' (Get-ExAmbientRecord)
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
