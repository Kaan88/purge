# Purge rig, M2: one executor run in the guest (vm\RIG.md §11; docs\M2_DESIGN.json M2-RIG-RUN, gate G0 / G1 / G2 /
# G5 / G6). Template: the host (rig.ps1 New-M2JobText) replaces __RUN__ (run name), __MODE__ (m2-install |
# m2-traps | m2-fidelity), __STAGE__ (start, or app for a real-app round trip of m2-fidelity) and __OPTS__ (base64
# JSON options) and submits it as an agent job (elevated, interactive user). Windows PowerShell 5.1.
#
# Every step is a Phase: a failure is recorded in run.json and the later phases still run. A rigtool verdict
# (execdiff / fidelity exit 1) or an engine refusal is a measurement, not a failed phase; vm\truth\m2.sh judges it.
# Engine calls (rig-exec build, M2-CLI contract; <h> = SHA-256(plan_hash || selection_hash), riglib Get-M2Confirm):
#   plan from-targets <targets.json> -o <plan.json>
#   exec --plan <plan.json> --confirm <h> --select <ids.json> -o <report.json>
#   undo --session <id> [--items <ids.json>] -o <undo.json>
#   quarantine expiring | quarantine purge --ids <id>... --yes-irreversible      (m2-traps, G5)
#   scan --fp <fp.json> --mode post --app purgetrapapp -o plan-forged.json        (m2-traps, forged fingerprint)
# Outputs (flat, in C:\cr\out\<run>\): run.json, run.log, install*.json, the trap / fixture manifests and targets,
# targets-/plan-/select-/report-/exec-<tag>.*, snap-<run>-<tag>.tsv.gz, deep-<tag>.json, execdiff-<tag>.json,
# fidelity-<tag>.json, undo-<tag>.json, sess-<tag>-* (session files), <tag>-sessions.zip / -index.json /
# -quarantine.json (store), m2-traps-check-*.json / m2-fixtures-check-*.json.
$Run = '__RUN__'
$Mode = '__MODE__'
$Stage = '__STAGE__'
$OptsB64 = '__OPTS__'
# Checked before anything is loaded or created; the placeholders are built by concatenation so the host's
# .Replace cannot rewrite them.
if ($Run -eq ('__' + 'RUN__') -or $Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { Write-Host ("exec-run.ps1: bad or unreplaced run name '{0}'" -f $Run); exit 2 }
if (@('m2-install', 'm2-traps', 'm2-fidelity') -cnotcontains $Mode) { Write-Host ("exec-run.ps1: bad or unreplaced mode '{0}'" -f $Mode); exit 2 }
if ($Stage -eq ('__' + 'STAGE__')) { $Stage = 'start' }
if (@('start', 'app') -cnotcontains $Stage) { Write-Host ("exec-run.ps1: bad stage '{0}'" -f $Stage); exit 2 }
. C:\cr\guest\riglib.ps1

$Opts = ConvertFrom-M2Opts $OptsB64
$R = Open-M2Run $Run $Mode $Stage
$D = $R.dir
$S = $R.S
$Calls = $S.engine.calls
$TrapsPs = Join-Path $RigGuestDir 'm2-traps.ps1'
$FixturesPs = Join-Path $RigGuestDir 'm2-fixtures.ps1'
$Work = Join-Path $RigWork $Run
New-Item -ItemType Directory -Force $Work | Out-Null
$PhaseCount0 = $S.phases.Count
# Null run (opts null = true; RIG.md §11.8): the mode's phases up to snap A / deep A exactly as in a real run, then an
# idle wait of null_wait seconds where exec would run, snap B and deep B, and nothing after. diff(snap A, snap B) is
# pure Windows churn of the exec window, the input of rigtool ambient --m2 (vm\truth\m2-ambient.json).
$NullRun = [bool](Get-M2Opt $Opts 'null' $false)
$NullWaitSec = [int](Get-M2Opt $Opts 'null_wait' 3)
if ($NullRun -and ($Stage -ne 'start' -or @('m2-traps', 'm2-fidelity') -notcontains $Mode)) { Log "exec-run.ps1: a null run is for stage start of m2-traps / m2-fidelity only"; Save-M2Run $R -Finished; exit 2 }
$S.null_run = [ordered]@{ null = $NullRun; wait_sec = $(if ($NullRun) { $NullWaitSec } else { $null }) }

function Q([string]$s) { ConvertTo-EngineArg $s }
function F([string]$n) { Join-Path $D $n }
function Read-Json([string]$p) { if (Test-Path -LiteralPath $p) { [IO.File]::ReadAllText($p) | ConvertFrom-Json } else { $null } }
function ConvertTo-Hashtable($o) { $h = @{}; if ($o) { foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = "$($p.Value)" } }; $h }
function Add-Result([string]$Key, [string]$Sub, $Value) {
    $cur = $S.results[$Key]
    $h = [ordered]@{}
    if ($cur -is [System.Collections.IDictionary]) { foreach ($k in $cur.Keys) { $h[$k] = $cur[$k] } }
    elseif ($cur) { foreach ($p in $cur.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    $h[$Sub] = $Value
    Set-M2Result $R $Key $h
}

# Started by m2-traps (race groups); replaced by the self-test.
function Start-M2SwapHelper([string]$TrapId) {
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Start-Native $exe ('-NoProfile -ExecutionPolicy Bypass -File ' + (Q $TrapsPs) + ' -Action swap -TrapId ' + $TrapId + ' -OutDir ' + (Q $D) + ' -TimeoutSec 300')
}

# A command line run at medium integrity (LaunchMedium task), for the attacker steps of G0. cmd.exe /c ends within
# a second, so no process is waited for (LaunchMedium's process wait would miss it and sit out its timeout): the
# step is done when $WaitPath (the file the command creates) is there, at most $WaitSec. Returns whether it is.
function Invoke-M2Medium([string]$CommandLine, [string]$WaitPath = '', [int]$WaitSec = 30) {
    $l = LaunchMedium (Join-Path $env:SystemRoot 'System32\cmd.exe') ('/c ' + $CommandLine) -StartTimeoutSec 0
    $seen = $false
    try {
        for ($i = 0; $i -lt ($WaitSec * 4); $i++) {
            if ($WaitPath -and (Test-Path -LiteralPath $WaitPath)) { $seen = $true; break }
            Start-Sleep -Milliseconds 250
        }
        if ($seen) { Start-Sleep -Milliseconds 500 }   # the redirection that created the file writes its line
        else { Log "  !! medium step: $WaitPath did not appear within $WaitSec s" }
    } finally { Remove-LaunchTask $l }
    $seen
}

# ------------------------------------------------------------------------------------------- building blocks

# install\install.ps1 fresh, again (must change nothing) and -Check (exit 0 = trees exactly as documented).
function Step-Install {
    $a = '-Engine ' + (Q $RigEngine) + ' -ReportPath '
    $r1 = Invoke-M2Script $RigInstallScript ($a + (Q (F 'install.json')))
    $r2 = Invoke-M2Script $RigInstallScript ($a + (Q (F 'install-rerun.json')))
    $r3 = Invoke-M2Script $RigInstallScript '-Check'
    [IO.File]::WriteAllText((F 'install-check.txt'), "exit $($r3.exit)`r`n$($r3.stdout)`r`n$($r3.stderr)", $RigUtf8)
    $j1 = Read-Json (F 'install.json'); $j2 = Read-Json (F 'install-rerun.json')
    $res = [ordered]@{
        exit = $r1.exit; rerun_exit = $r2.exit; check_exit = $r3.exit
        renamed_aside = $(if ($j1 -and $j1.PSObject.Properties['renamed_aside']) { @($j1.renamed_aside).Count } else { $null })
        rerun_changed = $(if ($j2 -and $j2.PSObject.Properties['changed']) { [bool]$j2.changed } else { $null })
    }
    Set-M2Result $R 'install' $res
    $S.engine.exe = Get-M2EngineExe
    if ($r1.exit -ne 0) { throw "install.ps1 exited $($r1.exit)" }
}

function Invoke-TrapsScript([string]$Arguments, [string]$Label, [switch]$Verdict) {
    $x = Invoke-M2Script $TrapsPs ($Arguments + ' -OutDir ' + (Q $D))
    if ($Verdict) { Add-Result 'checks' $Label $x.exit; return }
    if ($x.exit -ne 0) { throw "m2-traps.ps1 $Arguments exited $($x.exit)" }
}

function Invoke-FixturesScript([string]$Arguments, [string]$OutDir, [string]$Label = '', [switch]$Verdict) {
    $x = Invoke-M2Script $FixturesPs ($Arguments + ' -OutDir ' + (Q $OutDir))
    if ($Verdict) { Add-Result 'checks' $Label $x.exit; return }
    if ($x.exit -ne 0) { throw "m2-fixtures.ps1 $Arguments exited $($x.exit)" }
}

# plan from-targets over the targets of $Group; returns the plan record (no exec yet).
function New-PlanRec([string]$Tag, [string[]]$TargetFiles, [string]$Group, [string[]]$OnlyIds = @(), [switch]$Reverse) {
    $t = F "targets-$Tag.json"
    $ids = @(Write-M2Targets $TargetFiles $Group $t $OnlyIds -Reverse:$Reverse)
    $plan = F "plan-$Tag.json"
    $null = Invoke-M2Engine -Step "plan-$Tag" -Arguments (New-M2PlanArgs $t $plan) -Calls $Calls
    $sel = Write-M2IdFile $ids (F "select-$Tag.json")
    $ph = Get-M2PlanHash $plan
    $rec = [pscustomobject][ordered]@{
        tag = $Tag; group = $Group; targets = $t; plan = $plan; select = $sel; ids = $ids; plan_hash = $ph; confirm = (Get-M2Confirm $ph $ids)
        session = $null; exit = $null; crashed = $false; report = $null; journal = $null
    }
    Log "plan $Tag`: $($ids.Count) item(s), plan_hash $ph"
    $rec
}

# exec of a plan record; never throws on the engine's exit code (a refusal is a result).
function Invoke-ExecRec($Rec, [string]$Confirm = '', [string]$Plan = '', [string]$Tag = '', [hashtable]$Environment = @{}, [string]$RestorePoint = '') {
    if (-not $Confirm) { $Confirm = $Rec.confirm }
    if (-not $Plan) { $Plan = $Rec.plan }
    if (-not $Tag) { $Tag = $Rec.tag }
    $before = @(Get-M2Sessions)
    $rep = F "report-$Tag.json"
    $r = Invoke-M2Engine -Step "exec-$Tag" -Arguments (New-M2ExecArgs $Plan $Confirm $Rec.select $rep -RestorePoint $RestorePoint) -Calls $Calls -Environment $Environment -StdoutFile (F "exec-$Tag.out") -NoThrow
    $session = $null
    if (Test-Path -LiteralPath $rep) { $session = "$((Read-Json $rep).session)" }
    if (-not $session) { $session = Get-M2NewSession $before }
    $out = [pscustomobject][ordered]@{ tag = $Tag; exit = $r.exit; crashed = $r.crashed; session = $session; report = $null; journal = $null; new_sessions = @(Get-M2Sessions | Where-Object { $before -notcontains $_ }).Count }
    if (Test-Path -LiteralPath $rep) { $out.report = $rep }
    if ($session) {
        $sd = Get-M2SessionDir $session
        $out.journal = Join-Path $sd 'journal.jsonl'
        if (-not $out.report -and (Test-Path -LiteralPath (Join-Path $sd 'report.json'))) { $out.report = Join-Path $sd 'report.json' }
        $null = Copy-M2Session $session $D "sess-$Tag"
    }
    if ($Tag -eq $Rec.tag) { $Rec.exit = $out.exit; $Rec.crashed = $out.crashed; $Rec.session = $out.session; $Rec.report = $out.report; $Rec.journal = $out.journal }
    $out
}

function Invoke-UndoRec($Rec, [string]$Tag, [string[]]$Items = @()) {
    if (-not $Rec.session) { throw "no session to undo for $($Rec.tag)" }
    $itemsFile = ''
    if ($Items.Count) { $itemsFile = Write-M2IdFile $Items (F "undo-items-$Tag.json") }
    $r = Invoke-M2Engine -Step "undo-$Tag" -Arguments (New-M2UndoArgs $Rec.session $itemsFile '' (F "undo-$Tag.json")) -Calls $Calls -StdoutFile (F "undo-$Tag.out") -NoThrow
    $null = Copy-M2Session $Rec.session $D "sess-$Tag"
    $r
}

# The rest of a null run after deep A: the idle wait standing in for exec, snap B, deep B, the store.
function Invoke-NullWindow([string[]]$DeepScopes) {
    Phase 'null-wait' { Log "null run: idle $NullWaitSec s instead of exec"; Start-Sleep -Seconds $NullWaitSec } $S
    Phase 'snap-b' { $null = Invoke-M2Snap (F "snap-$Run-b.tsv.gz") } $S
    Phase 'deep-b' { $null = Invoke-M2Deep $DeepScopes (F 'deep-b.json') } $S
    Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S
}

function Get-ExecSummary($X, $Verdict) {
    [ordered]@{ session = $X.session; exec_exit = $X.exit; report = $(if ($X.report) { Split-Path -Leaf $X.report }); execdiff_ok = $(if ($Verdict) { $Verdict.ok } else { $null }) }
}

# The manifest record of a trap (by id) or of the trap whose items belong to $Group.
function Get-TrapDef([string]$Manifest, [string]$Id = '', [string]$Group = '') {
    $m = Read-Json $Manifest
    if (-not $m) { throw "no manifest $Manifest" }
    foreach ($t in @($m.traps)) {
        if ($Id -and $t.id -eq $Id) { return $t }
        if ($Group -and @(@($t.items) | Where-Object { $_.group -eq $Group }).Count) { return $t }
    }
    throw "no trap '$Id$Group' in $Manifest"
}

# ----------------------------------------------------------------------------------------------- m2-install (G0)

function Invoke-InstallMode {
    Phase 'edge-pause' { $S.edge_pause = Suspend-EdgeUpdate } $S
    Phase 'telemetry-pause' { $S.telemetry_pause = Suspend-M2Telemetry } $S
    # The attacker pre-creates C:\ProgramData\Purge with planted junctions (trap pd-precreated) before the install.
    Phase 'traps-pre' { Invoke-TrapsScript '-Stage pre-install' 'pre' } $S
    # X:\.purge-q on the second volume, pre-created by a standard user: never adopted as a quarantine root.
    $hasD = (Test-Path -LiteralPath $RigDRoot)
    $dq = Join-Path $RigDRoot '.purge-q'
    $marker = Join-Path $dq 'user-marker.txt'
    Phase 'd-precreate' {
        if (-not $hasD) { Add-Result 'd_volume' 'present' $false; return }
        $null = Invoke-M2Medium ('mkdir ' + (Q $dq) + ' & echo planted-by-user> ' + (Q $marker)) $marker
        Add-Result 'd_volume' 'present' $true
        Add-Result 'd_volume' 'precreated' (Test-Path -LiteralPath $marker)
    } $S
    Phase 'install' { Step-Install } $S
    Phase 'traps-build' { Invoke-TrapsScript '' 'build' } $S
    Phase 'traps-check-after-install' { Invoke-TrapsScript '-Action check -Label after-install' 'after-install' -Verdict } $S
    Phase 'd-exec' {
        if (-not $hasD) { return }
        $dir = Join-Path $RigDRoot 'PurgeRigD'
        New-Item -ItemType Directory -Force $dir | Out-Null
        [IO.File]::WriteAllText((Join-Path $dir 'payload.txt'), 'purge rig D: payload', $RigUtf8)
        $tf = Join-Path $Work 'd-volume-targets.json'
        $doc = [ordered]@{ schema = 'purge.rig.targets/0'; source = 'exec-run.ps1 m2-install'; origin = 'ManualUser'
            targets = @([ordered]@{ id = 'd-volume.payload'; trap = 'd-volume'; group = 'main'; target = [ordered]@{ type = 'Path'; path = "$dir\payload.txt" }; action = 'Quarantine' }) }
        [IO.File]::WriteAllText($tf, (ConvertTo-Json -InputObject $doc -Depth 8), $RigUtf8)
        $rec = New-PlanRec 'd-volume' @($tf) 'main'
        $x = Invoke-ExecRec $rec
        # Expected (engine ceb5999 on, which accepts NETWORK SERVICE, the owner Format-Volume leaves, as the owner
        # of a volume root): exec 0, the payload moved to the engine's own D:\.purge-q\<session>\000001\payload.txt,
        # the user's pre-created D:\.purge-q renamed aside to D:\.purge-q.rejected-<utc> with user-marker.txt
        # unchanged inside, never adopted. An older engine skipped the item (D:\ owner not trusted).
        $userQ = @(Get-ChildItem -LiteralPath $dq -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'payload.txt' })
        $aside = @(Get-ChildItem -LiteralPath $RigDRoot -Filter '.purge-q.rejected-*' -Force -Directory -ErrorAction SilentlyContinue)
        $asideMarker = @($aside | ForEach-Object { Join-Path $_.FullName 'user-marker.txt' } | Where-Object {
                (Test-Path -LiteralPath $_) -and ([IO.File]::ReadAllText($_).Trim() -ceq 'planted-by-user') })
        $inQueue = @(Get-ChildItem -LiteralPath $dq -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName '000001\payload.txt' } |
            Where-Object { Test-Path -LiteralPath $_ })
        Add-Result 'd_volume' 'exec_exit' $x.exit
        Add-Result 'd_volume' 'payload_gone' (-not (Test-Path -LiteralPath "$dir\payload.txt"))
        Add-Result 'd_volume' 'renamed_aside' ($aside.Count -gt 0)
        Add-Result 'd_volume' 'aside' @($aside | ForEach-Object { $_.FullName })
        Add-Result 'd_volume' 'user_marker_intact' ($asideMarker.Count -gt 0)
        Add-Result 'd_volume' 'adopted' ($userQ.Count -gt 0 -and (Test-Path -LiteralPath $marker))
        Add-Result 'd_volume' 'payload_in_queue' $(if ($inQueue.Count) { $inQueue[0] } else { $null })
    } $S
    Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S
}

# ------------------------------------------------------------------------------------------- m2-traps (G1, G5)

function Invoke-TrapsMode {
    $TT = F 'm2-traps-targets.json'; $TM = F 'm2-traps-manifest.json'
    Phase 'edge-pause' { $S.edge_pause = Suspend-EdgeUpdate } $S
    Phase 'telemetry-pause' { $S.telemetry_pause = Suspend-M2Telemetry } $S
    Phase 'traps-pre' { Invoke-TrapsScript '-Stage pre-install' 'pre' } $S
    Phase 'install' { Step-Install } $S
    Phase 'traps-build' { Invoke-TrapsScript '' 'build' } $S
    Phase 'traps-check-after-install' { Invoke-TrapsScript '-Action check -Label after-install' 'after-install' -Verdict } $S
    $script:Main = $null
    Phase 'plan-main' { $script:Main = New-PlanRec 'main' @($TT) 'main' } $S
    if (-not $NullRun) { Phase 'refusals' { Invoke-Refusals $script:Main $TT $TM } $S }
    Phase 'snap-a' { $null = Invoke-M2Snap (F "snap-$Run-a.tsv.gz") } $S
    Phase 'deep-a' { $null = Invoke-M2Deep @($TM, $script:Main.targets) (F 'deep-a.json') } $S
    if ($NullRun) { Invoke-NullWindow @($TM, $script:Main.targets); return }
    Phase 'exec-main' { $x = Invoke-ExecRec $script:Main; if (-not $x.report) { throw "exec main wrote no report (exit $($x.exit))" } } $S
    Phase 'snap-b' { $null = Invoke-M2Snap (F "snap-$Run-b.tsv.gz") } $S
    Phase 'deep-b' { $null = Invoke-M2Deep @($TM, $script:Main.targets) (F 'deep-b.json') } $S
    Phase 'execdiff-main' {
        $v = Invoke-M2Execdiff -Before (F "snap-$Run-a.tsv.gz") -After (F "snap-$Run-b.tsv.gz") -Journal $script:Main.journal -Report $script:Main.report `
            -Traps @($TM) -Groups @('main') -DeepBefore (F 'deep-a.json') -DeepAfter (F 'deep-b.json') -Out (F 'execdiff-main.json')
        Add-Result 'execs' 'main' (Get-ExecSummary $script:Main $v)
    } $S
    Phase 'traps-check-after-exec' { Invoke-TrapsScript '-Action check -Label after-exec' 'after-exec' -Verdict } $S
    # Everything but the expiry trap's item is undone; that one stays quarantined for the expiry walk (G5).
    $expiry = $null
    try { $expiry = Get-TrapDef $TM -Id 'expiry-junction' } catch { Log "  !! $($_.Exception.Message)" }
    $expiryIds = @(); if ($expiry) { $expiryIds = @(@($expiry.items) | ForEach-Object { "$($_.id)" }) }
    Phase 'undo-main' {
        $keep = @($script:Main.ids | Where-Object { $expiryIds -notcontains $_ })
        $u = Invoke-UndoRec $script:Main 'main' $keep
        Add-Result 'undo' 'main' ([ordered]@{ exit = $u.exit; items = $keep.Count; kept_for_expiry = $expiryIds })
    } $S
    Phase 'deep-c' { $null = Invoke-M2Deep @($TM, $script:Main.targets) (F 'deep-c.json') } $S
    Phase 'fidelity-main' { $v = Invoke-M2Fidelity (F 'deep-a.json') (F 'deep-c.json') $script:Main.journal (F 'fidelity-main.json') -KeepItems $expiryIds; Add-Result 'fidelity' 'main' $v.ok } $S
    Phase 'expiry' { Invoke-Expiry $expiry } $S
    Phase 'traps-check-after-expiry' { Invoke-TrapsScript '-Action check -Label after-expiry' 'after-expiry' -Verdict } $S
    foreach ($g in 'race-a', 'race-b') { Phase $g { Invoke-Race $g $TT $TM } $S }
    Phase 'forged-fp' { Invoke-ForgedFp $TM } $S
    Phase 'traps-check-final' { Invoke-TrapsScript '-Action check -Label final' 'final' -Verdict } $S
    Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S
}

# G1: a wrong --confirm, a tampered sidecar and a reordered plan are refused with no change (scoped snaps A == B,
# no new session).
function Invoke-Refusals($Main, [string]$TT, [string]$TM) {
    if (-not $Main) { throw 'no main plan' }
    $roots = @(Get-M2SnapRoots @($TM) | Where-Object { $_ -ne $RigPfroKey -and $_ -notmatch '\\Environment$' })
    $a = F "snap-$Run-refuse-a.tsv.gz"; $b = F "snap-$Run-refuse-b.tsv.gz"
    $null = Invoke-M2Snap $a $roots
    $res = [ordered]@{}
    # Wrong confirm: the same plan under another name, the confirm's last hex digit changed.
    Copy-Item -LiteralPath $Main.plan -Destination (F 'plan-refuse-confirm.json') -Force
    Copy-Item -LiteralPath (Get-M2Sidecar $Main.plan) -Destination (F 'plan-refuse-confirm.scan.json') -Force
    $c = $Main.confirm
    $last = $c.Substring($c.Length - 1)
    $bad = $c.Substring(0, $c.Length - 1) + $(if ($last -eq '0') { '1' } else { '0' })
    $x = Invoke-ExecRec $Main -Confirm $bad -Plan (F 'plan-refuse-confirm.json') -Tag 'refuse-confirm'
    $res.wrong_confirm = [ordered]@{ exit = $x.exit; report = [bool]$x.report; new_sessions = $x.new_sessions; refused = ($x.exit -ne 0 -and -not $x.report) }
    # Tampered sidecar: one trap path in the sidecar changed by one character; plan.json and the confirm unchanged.
    Copy-Item -LiteralPath $Main.plan -Destination (F 'plan-refuse-tamper.json') -Force
    $txt = [IO.File]::ReadAllText((Get-M2Sidecar $Main.plan))
    $i = $txt.IndexOf('PurgeTrapApp')
    if ($i -ge 0) { $txt = $txt.Substring(0, $i) + 'PurgeTrapApq' + $txt.Substring($i + 12) }
    [IO.File]::WriteAllText((F 'plan-refuse-tamper.scan.json'), $txt, $RigUtf8)
    $x = Invoke-ExecRec $Main -Plan (F 'plan-refuse-tamper.json') -Tag 'refuse-tamper'
    $res.tampered_sidecar = [ordered]@{ exit = $x.exit; report = [bool]$x.report; new_sessions = $x.new_sessions; tampered = ($i -ge 0); refused = ($x.exit -ne 0 -and -not $x.report) }
    # Reordered plan: the same targets in reverse order, planned again, executed with the main confirm.
    $ro = New-PlanRec 'refuse-order' @($TT) 'main' -Reverse
    $x = Invoke-ExecRec $ro -Confirm $Main.confirm -Tag 'refuse-order'
    $res.reordered_plan = [ordered]@{ exit = $x.exit; report = [bool]$x.report; new_sessions = $x.new_sessions; plan_hash_differs = ($ro.plan_hash -ne $Main.plan_hash); refused = ($x.exit -ne 0 -and -not $x.report) }
    $null = Invoke-M2Snap $b $roots
    # (Variable names are case-insensitive: nothing here may be called $d, $r or $s, which would hide $D / $R / $S.)
    $dr = Invoke-RigTool ('diff ' + (Q $a) + ' ' + (Q $b) + ' --json')
    [IO.File]::WriteAllText((F 'refuse-diff.json'), "$($dr.stdout)", $RigUtf8)
    $n = $null; $mt = $null
    try {
        $j = "$($dr.stdout)" | ConvertFrom-Json
        # A directory whose only change is its LastWriteTime, with nothing added or removed anywhere: the snapshot
        # reads directory times from the parent's index, which NTFS updates lazily (seen on the VM: 15 trap dirs
        # whose time moved by ~2 ms between two snaps a second apart, with no engine call writing anything).
        $mtOnly = @(@($j.changed) | Where-Object { $_ -and $_.rec -eq 'D' -and @(@($_.changes) | Where-Object { "$_" -notmatch '^mtime ' }).Count -eq 0 })
        $mt = $mtOnly.Count
        $n = @($j.added).Count + @($j.removed).Count + @($j.changed).Count
        if ((@($j.added).Count + @($j.removed).Count) -eq 0) { $n -= $mt }
    } catch { }
    $res.diff_records = $n
    $res.dir_mtime_only = $mt
    $res.no_change = ($n -eq 0)
    Set-M2Result $R 'refusals' $res
}

# G5: links planted inside the quarantined expiry item; the expiry walk deletes the links, never their targets.
function Invoke-Expiry($Trap) {
    if (-not $Trap) { throw 'no expiry trap in the manifest' }
    $res = [ordered]@{ plant_exit = $null; env = $null; expiring_exit = $null; ids = @(); purge_exit = $null }
    $x = Invoke-M2Script $TrapsPs ('-Action plant-expiry-junction -OutDir ' + (Q $D))
    $res.plant_exit = $x.exit
    $xenv = ConvertTo-Hashtable (Get-M2Opt $Opts 'expiry_env' ([pscustomobject]@{ PURGE_RIG_NOW_OFFSET_DAYS = '400' }))
    $res.env = @($xenv.Keys | ForEach-Object { "$_=$($xenv[$_])" })
    $e = Invoke-M2Engine -Step 'quarantine-expiring' -Arguments (New-M2QuarantineArgs 'expiring') -Calls $Calls -Environment $xenv -StdoutFile (F 'expiring.json') -NoThrow
    $res.expiring_exit = $e.exit
    $needle = "$(@($Trap.items)[0].target.path)"
    $res.ids = @(Find-M2ExpiryIds ([IO.File]::ReadAllText((F 'expiring.json'))) $needle)
    if ($res.ids.Count) {
        $p = Invoke-M2Engine -Step 'quarantine-purge' -Arguments (New-M2QuarantineArgs 'purge' $res.ids) -Calls $Calls -Environment $xenv -StdoutFile (F 'expiry-purge.out') -NoThrow
        $res.purge_exit = $p.exit
    } else { Log "  !! quarantine expiring lists nothing for $needle" }
    $res.listed = ($res.ids.Count -gt 0)
    Set-M2Result $R 'expiry' $res
    Set-M2Result $R 'store_after_expiry' (Save-M2Store $D 'expiry')
}

# G1 races: the swap helper replaces the validated directory with a junction to a canary while the engine waits
# at the trap's PURGE_FAULT_PAUSE point.
function Invoke-Race([string]$G, [string]$TT, [string]$TM) {
    $t = Get-TrapDef $TM -Group $G
    $xenv = ConvertTo-Hashtable $t.helper.env
    $rec = New-PlanRec $G @($TT) $G
    $roots = Get-M2SnapRoots @($TM)
    $a = F "snap-$Run-$G-a.tsv.gz"; $b = F "snap-$Run-$G-b.tsv.gz"
    $null = Invoke-M2Snap $a $roots
    $null = Invoke-M2Deep @($TM, $rec.targets) (F "deep-$G-a.json")
    $h = Start-M2SwapHelper $t.id
    $x = Invoke-ExecRec $rec -Environment $xenv
    $done = $h.WaitForExit(330000)
    $hexit = $(if ($done) { $h.ExitCode } else { $null })
    $null = Invoke-M2Snap $b $roots
    $null = Invoke-M2Deep @($TM, $rec.targets) (F "deep-$G-b.json")
    $v = $null
    if ($x.report -and $x.journal) {
        $v = Invoke-M2Execdiff -Before $a -After $b -Journal $x.journal -Report $x.report -Traps @($TM) -Groups @($G) -DeepBefore (F "deep-$G-a.json") -DeepAfter (F "deep-$G-b.json") -Out (F "execdiff-$G.json")
    }
    $sum = Get-ExecSummary $x $v
    $sum.swap_exit = $hexit; $sum.trap = $t.id; $sum.fault_pause = @($xenv.Keys | ForEach-Object { "$_=$($xenv[$_])" })
    Add-Result 'execs' $G $sum
    if (-not $v) { throw "race $G`: no report or journal for execdiff (exec exit $($x.exit))" }
}

# Forged user-store fingerprint (Rule T): a scan with it must not make the canary paths Safe or preselected.
function Invoke-ForgedFp([string]$TM) {
    $t = Get-TrapDef $TM -Id 'forged-user-fp'
    $fpDir = $RigUserFpDir
    $fp = @(Get-ChildItem -LiteralPath $fpDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc) | Select-Object -Last 1
    $res = [ordered]@{ fp = $null; exit = $null; items = 0; violations = @(); ok = $false }
    if (-not $fp) { $res.error = "no forged fingerprint in $fpDir"; Set-M2Result $R 'forged_fp' $res; throw $res.error }
    $res.fp = $fp.FullName
    $plan = F 'plan-forged.json'
    $sc = Invoke-M2Engine -Step 'scan-forged-fp' -Arguments ('scan --fp ' + (Q $fp.FullName) + ' --mode post --app purgetrapapp -o ' + (Q $plan)) -Calls $Calls -NoThrow
    $res.exit = $sc.exit
    $p = Read-Json $plan
    $items = @(); if ($p) { $items = @(@($p.items) | ForEach-Object { $_ } | Where-Object { $_ }) }
    $res.items = $items.Count
    $watch = @(@($t.expect.paths) | ForEach-Object { "$_".TrimEnd('\') })
    foreach ($it in $items) {
        $tp = "$($it.target.path)".TrimEnd('\')
        foreach ($w in $watch) {
            if ($tp -ieq $w -or $tp.StartsWith($w + '\', [StringComparison]::OrdinalIgnoreCase) -or $w.StartsWith($tp + '\', [StringComparison]::OrdinalIgnoreCase)) {
                if ("$($it.band)" -eq 'Safe' -or $it.preselected -eq $true) { $res.violations += "$tp ($($it.band), preselected=$($it.preselected))" }
            }
        }
    }
    $res.ok = ($sc.exit -eq 0 -and -not $res.violations.Count)
    Set-M2Result $R 'forged_fp' $res
}

# ---------------------------------------------------------------------------------------- m2-fidelity (G2, G6)

# A fresh fixture tree (reset + build into the work dir) planned as group main, with deep A taken.
function New-FixtureRound([string]$Tag) {
    $w = Join-Path $Work $Tag
    New-Item -ItemType Directory -Force $w | Out-Null
    $x = Invoke-M2Script $FixturesPs '-Action reset'
    if ($x.exit -ne 0) { Log "  !! fixtures reset exit $($x.exit)" }
    Invoke-FixturesScript '' $w
    Copy-Item -LiteralPath (Join-Path $w 'm2-fixtures-manifest.json') -Destination (F "$Tag-fixtures-manifest.json") -Force
    $rec = New-PlanRec $Tag @((Join-Path $w 'm2-fixtures-targets.json')) 'main'
    $rec | Add-Member -NotePropertyName manifest -NotePropertyValue (Join-Path $w 'm2-fixtures-manifest.json')
    $null = Invoke-M2Deep @($rec.manifest, $rec.targets) (F "deep-$Tag-a.json")
    $rec
}

function Invoke-FidelityMode {
    $FT = F 'm2-fixtures-targets.json'; $FM = F 'm2-fixtures-manifest.json'
    Phase 'edge-pause' { $S.edge_pause = Suspend-EdgeUpdate } $S
    Phase 'telemetry-pause' { $S.telemetry_pause = Suspend-M2Telemetry } $S
    Phase 'install' { Step-Install } $S
    Phase 'fixtures-build' { Invoke-FixturesScript '' $D } $S
    $script:Main = $null
    Phase 'plan-main' { $script:Main = New-PlanRec 'main' @($FT) 'main' } $S
    Phase 'snap-a' { $null = Invoke-M2Snap (F "snap-$Run-a.tsv.gz") } $S
    Phase 'deep-a' { $null = Invoke-M2Deep @($FM, $script:Main.targets) (F 'deep-a.json') } $S
    if ($NullRun) { Invoke-NullWindow @($FM, $script:Main.targets); return }
    Phase 'exec-main' { $x = Invoke-ExecRec $script:Main; if (-not $x.report) { throw "exec main wrote no report (exit $($x.exit))" } } $S
    Phase 'snap-b' { $null = Invoke-M2Snap (F "snap-$Run-b.tsv.gz") } $S
    Phase 'deep-b' { $null = Invoke-M2Deep @($FM, $script:Main.targets) (F 'deep-b.json') } $S
    Phase 'execdiff-main' {
        $v = Invoke-M2Execdiff -Before (F "snap-$Run-a.tsv.gz") -After (F "snap-$Run-b.tsv.gz") -Journal $script:Main.journal -Report $script:Main.report `
            -Traps @($FM) -Groups @('main') -DeepBefore (F 'deep-a.json') -DeepAfter (F 'deep-b.json') -Out (F 'execdiff-main.json')
        Add-Result 'execs' 'main' (Get-ExecSummary $script:Main $v)
    } $S
    Phase 'fixtures-check-after-exec' { Invoke-FixturesScript '-Action check -Phase after-exec' $D 'after-exec' -Verdict } $S
    Phase 'undo-main' { $u = Invoke-UndoRec $script:Main 'main'; Add-Result 'undo' 'main' ([ordered]@{ exit = $u.exit }) } $S
    Phase 'deep-c' { $null = Invoke-M2Deep @($FM, $script:Main.targets) (F 'deep-c.json') } $S
    Phase 'fidelity-main' { $v = Invoke-M2Fidelity (F 'deep-a.json') (F 'deep-c.json') $script:Main.journal (F 'fidelity-main.json'); Add-Result 'fidelity' 'main' $v.ok } $S
    Phase 'fixtures-check-after-undo' { Invoke-FixturesScript '-Action check -Phase after-undo' $D 'after-undo' -Verdict } $S
    Phase 'store-main' { Set-M2Result $R 'store' (Save-M2Store $D 'main') } $S

    # Partial undo: the first half of the items (ordinal order) only.
    Phase 'partial' {
        $rec = New-FixtureRound 'partial'
        $x = Invoke-ExecRec $rec
        $ids = [string[]]@($rec.ids); [Array]::Sort($ids, [StringComparer]::Ordinal)
        $half = @($ids | Select-Object -First ([Math]::Max(1, [int][Math]::Floor($ids.Count / 2))))
        $u = Invoke-UndoRec $rec 'partial' $half
        $null = Invoke-M2Deep @($rec.manifest, $rec.targets) (F 'deep-partial-c.json')
        $v = Invoke-M2Fidelity (F 'deep-partial-a.json') (F 'deep-partial-c.json') $rec.journal (F 'fidelity-partial.json')
        Set-M2Result $R 'partial_undo' ([ordered]@{ exec_exit = $x.exit; undo_exit = $u.exit; undone = $half; not_undone = @($ids | Where-Object { $half -notcontains $_ }); fidelity_exit = $v.exit })
    } $S

    # Undo conflict: a deleted value is recreated with other data before the undo; the undo must report a conflict
    # for it and leave the recreated data alone.
    Phase 'undo-conflict' {
        $rec = New-FixtureRound 'conflict'
        $x = Invoke-ExecRec $rec
        $t = @((Read-Json $rec.targets).targets | Where-Object { $_.target.type -eq 'RegValue' -and $_.action -eq 'DeleteValue' }) | Select-Object -First 1
        $res = [ordered]@{ exec_exit = $x.exit; item = $null; recreated = $false; undo_exit = $null; kept = $null }
        if ($t) {
            $res.item = "$($t.id)"
            $want = 'purge-rig-conflict ' + [guid]::NewGuid().ToString('N')
            $res.recreated = Set-M2RegString "$($t.target.path)" "$($t.target.name)" $want
            $u = Invoke-UndoRec $rec 'conflict'
            $res.undo_exit = $u.exit
            $res.kept = ("$(Get-RegRaw "$($t.target.path)" "$($t.target.name)")" -eq $want)
            $res.reported = ((Test-Path -LiteralPath (F 'undo-conflict.json')) -and ([IO.File]::ReadAllText((F 'undo-conflict.json')).IndexOf($res.item, [StringComparison]::Ordinal) -ge 0))
        } else { $res.error = 'no DeleteValue item in the fixture targets' }
        Set-M2Result $R 'undo_conflict' $res
    } $S

    # Backup tamper: one byte of one backup file flipped; the undo must refuse that item and restore the others.
    Phase 'backup-tamper' {
        $rec = New-FixtureRound 'tamper'
        $x = Invoke-ExecRec $rec
        $res = [ordered]@{ exec_exit = $x.exit; backup = $null; op = $null; item = $null; undo_exit = $null }
        if ($rec.journal -and (Test-Path -LiteralPath $rec.journal)) {
            foreach ($line in [IO.File]::ReadAllLines($rec.journal)) {
                if ($line -notmatch '"rec"\s*:\s*"intent"') { continue }
                $j = $null; try { $j = $line | ConvertFrom-Json } catch { continue }
                $bp = $null
                # The engine journal (purge.journal/1) carries the backup under the intent's inverse
                # (RestoreKeyTree / RestoreValue / RecreateKey: inverse.backup.path, relative to the session dir).
                $holders = @($j)
                if ($j.PSObject.Properties['inverse'] -and $j.inverse) { $holders += $j.inverse }
                foreach ($hd in $holders) {
                    foreach ($k in 'backup', 'definition') { if ($hd.PSObject.Properties[$k] -and $hd.$k -and $hd.$k.path) { $bp = "$($hd.$k.path)"; break } }
                    if ($bp) { break }
                }
                if ($bp) { $res.backup = $bp; $res.op = $j.op; $res.item = "$($j.item)"; break }
            }
        }
        if ($res.backup) {
            $full = Join-Path (Get-M2SessionDir $rec.session) $res.backup
            $bytes = [IO.File]::ReadAllBytes($full)
            $k = [int][Math]::Floor($bytes.Length / 2)
            $bytes[$k] = $bytes[$k] -bxor 0x5A
            [IO.File]::WriteAllBytes($full, $bytes)
            $u = Invoke-UndoRec $rec 'tamper'
            $res.undo_exit = $u.exit
            $null = Invoke-M2Deep @($rec.manifest, $rec.targets) (F 'deep-tamper-c.json')
            $v = Invoke-M2Fidelity (F 'deep-tamper-a.json') (F 'deep-tamper-c.json') $rec.journal (F 'fidelity-tamper.json')
            $res.fidelity_exit = $v.exit
        } else { $res.error = 'no intent with a backup in the journal' }
        Set-M2Result $R 'backup_tamper' $res
    } $S

    # G6: a restore point with --restore-point always (m2-base: SystemRestorePointCreationFrequency 0, no throttle),
    # then the throttling leg: the frequency set to rp_frequency minutes (default 1440, Windows' own default) and a
    # second exec, which must report Throttled. The engine never touches the value; the rig sets it for the test.
    Phase 'restore-point' {
        $res = [ordered]@{ snapshot = (Get-M2Opt $Opts 'snapshot' $null); frequency_before = (Get-RegRaw $RigSrKey 'SystemRestorePointCreationFrequency'); before = $null; after = $null; first = $null; second = $null }
        $res.before = @(Get-M2RestorePoints).Count
        $rec = New-FixtureRound 'rp1'
        $x = Invoke-ExecRec $rec -RestorePoint 'always'
        $res.first = [ordered]@{ exit = $x.exit; restore_point = $(if ($x.report) { (Read-Json $x.report).restore_point }) }
        $res.after = @(Get-M2RestorePoints).Count
        # Undone before rp2 rebuilds the same fixture paths: undone after it, rp1's restore would occupy rp2's paths
        # and rp2's undo would end in conflicts (seen on the VM: 11 conflicts, exit 11).
        $null = Invoke-UndoRec $rec 'rp1'
        $res.frequency_value = Set-M2RestoreFrequency ([int](Get-M2Opt $Opts 'rp_frequency' 1440))
        $rec2 = New-FixtureRound 'rp2'
        $x2 = Invoke-ExecRec $rec2 -RestorePoint 'always'
        $res.second = [ordered]@{ exit = $x2.exit; restore_point = $(if ($x2.report) { (Read-Json $x2.report).restore_point }) }
        $res.after_second = @(Get-M2RestorePoints).Count
        Set-M2Result $R 'restore_point' $res
        $null = Invoke-UndoRec $rec2 'rp2'
    } $S

    # G6 "System Protection off": protection on C: disabled, exec with --restore-point always; the engine reports the
    # restore point Disabled with a warning and executes the plan anyway (docs\M2_DESIGN.json purge-exec prepare:
    # "never blocks the batch on failure"). Protection is enabled again afterwards (the snapshot restore of the next
    # run would undo it in any case).
    Phase 'restore-point-off' {
        $res = [ordered]@{ disabled = $false; before = $null; after = $null; exit = $null; restore_point = $null; warnings = @(); done = $null; reenabled = $null }
        try {
            $res.disabled = -not (Set-M2SystemProtection $false)
            $res.before = @(Get-M2RestorePoints).Count
            $rec = New-FixtureRound 'rp-off'
            $x = Invoke-ExecRec $rec -RestorePoint 'always'
            $res.exit = $x.exit
            if ($x.report) {
                $rp = Read-Json $x.report
                $res.restore_point = $rp.restore_point
                $res.warnings = @(@($rp.warnings) | Where-Object { "$_" -match 'restore' })
                $res.done = $(if ($rp.counts) { $rp.counts.done } else { $null })
            }
            $res.after = @(Get-M2RestorePoints).Count
            $null = Invoke-UndoRec $rec 'rp-off'
        } finally {
            try { $res.reenabled = Set-M2SystemProtection $true } catch { $res.reenabled = $false; Log "  !! enable system protection: $($_.Exception.Message)" }
            Set-M2Result $R 'restore_point_off' $res
        }
    } $S
    Phase 'store' { Set-M2Result $R 'store_final' (Save-M2Store $D 'final') } $S
}

# Real app round trip (stage 'app'): the plan of the M1a engine run <app_run> (installed, engine/vendor uninstall,
# post scan), executed with its default selection (Safe + preselected), execdiff, undo, fidelity.
function Invoke-AppStage {
    $app = "$(Get-M2Opt $Opts 'app' '')"; $appRun = "$(Get-M2Opt $Opts 'app_run' '')"
    if ($app -cnotmatch '^[a-z0-9][a-z0-9_-]*$' -or $appRun -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "app stage needs opts app / app_run ('$app', '$appRun')" }
    $tag = "app-$app"
    $script:AppRec = $null
    Phase "$tag-plan" {
        $src = Join-Path (Join-Path $RigOut $appRun) 'plan-purge.json'
        if (-not (Test-Path -LiteralPath $src)) { throw "no $src (did the run-app job of $appRun finish?)" }
        $plan = F "plan-$tag.json"
        Copy-Item -LiteralPath $src -Destination $plan -Force
        Copy-Item -LiteralPath (Get-M2Sidecar $src) -Destination (Get-M2Sidecar $plan) -Force
        # Every item the plan offers for removal (bands app_bands, default Safe, Likely, Weak; Blocked never), ticked by
        # default or not: --select is the full selection (RIG.md §11.7), so real app leftovers go through exec and undo
        # even when the scan preselects nothing.
        $wantBands = @(@(Get-M2Opt $Opts 'app_bands' @('Safe', 'Likely', 'Weak')) | ForEach-Object { "$_" } | Where-Object { $_ -and $_ -ne 'Blocked' })
        $ids = @(Get-M2BandSelection $plan $wantBands)
        $bands = @(@((Read-Json $plan).items) | Where-Object { $_ } | ForEach-Object { "$($_.band)/$($_.preselected)" } | Group-Object | ForEach-Object { "$($_.Name) x$($_.Count)" })
        if (-not $ids.Count) {
            # The engine refuses an empty selection (exit 6, "nothing is selected"): no round trip to measure. Recorded,
            # not a failed phase; m2.sh then has no fidelity-app-<id>.json for this app.
            Add-Result 'apps' $app ([ordered]@{ app_run = $appRun; selected = 0; bands = $wantBands; skipped = "no item of band $($wantBands -join '/') in the plan"; plan_items = $bands })
            Log "  !! $tag`: the plan has no item of band $($wantBands -join '/') ($($bands -join ', ')); no round trip"
            return
        }
        $sc = Read-Json (Get-M2Sidecar $plan)
        $tg = @(@($sc.items) | ForEach-Object { $_ } | Where-Object { $_ -and $ids -contains "$($_.id)" } | ForEach-Object {
                $act = $_.action; if ($act -and -not ($act -is [string])) { $act = "$(@($act.PSObject.Properties)[0].Name)" }
                [ordered]@{ id = "$($_.id)"; trap = $tag; group = 'main'; target = $_.target; action = $act } })
        $t = F "targets-$tag.json"
        [IO.File]::WriteAllText($t, (ConvertTo-Json -InputObject ([ordered]@{ schema = 'purge.rig.targets/0'; source = "exec-run.ps1 $appRun"; origin = 'ManualUser'; targets = $tg }) -Depth 20), $RigUtf8)
        $ph = Get-M2PlanHash $plan
        $script:AppRec = [pscustomobject][ordered]@{ tag = $tag; group = 'main'; targets = $t; plan = $plan; select = (Write-M2IdFile $ids (F "select-$tag.json")); ids = $ids
            plan_hash = $ph; confirm = (Get-M2Confirm $ph $ids); session = $null; exit = $null; crashed = $false; report = $null; journal = $null }
        Add-Result 'apps' $app ([ordered]@{ app_run = $appRun; selected = $ids.Count; bands = $wantBands; plan_items = $bands })
    } $S
    if (-not $script:AppRec) { return }
    $rec = $script:AppRec
    Phase "$tag-snap-a" { $null = Invoke-M2Snap (F "snap-$Run-$tag-a.tsv.gz") } $S
    Phase "$tag-deep-a" { $null = Invoke-M2Deep @($rec.targets) (F "deep-$tag-a.json") } $S
    Phase "$tag-exec" { $x = Invoke-ExecRec $rec; if (-not $x.report) { throw "exec $tag wrote no report (exit $($x.exit))" } } $S
    Phase "$tag-snap-b" { $null = Invoke-M2Snap (F "snap-$Run-$tag-b.tsv.gz") } $S
    Phase "$tag-execdiff" {
        $v = Invoke-M2Execdiff -Before (F "snap-$Run-$tag-a.tsv.gz") -After (F "snap-$Run-$tag-b.tsv.gz") -Journal $rec.journal -Report $rec.report -Out (F "execdiff-$tag.json")
        Add-Result 'execs' $tag (Get-ExecSummary $rec $v)
    } $S
    Phase "$tag-undo" { $u = Invoke-UndoRec $rec $tag; Add-Result 'undo' $tag ([ordered]@{ exit = $u.exit }) } $S
    Phase "$tag-deep-c" { $null = Invoke-M2Deep @($rec.targets) (F "deep-$tag-c.json") } $S
    Phase "$tag-fidelity" { $v = Invoke-M2Fidelity (F "deep-$tag-a.json") (F "deep-$tag-c.json") $rec.journal (F "fidelity-$tag.json"); Add-Result 'fidelity' $tag $v.ok } $S
}

# ------------------------------------------------------------------------------------------------------- main

try {
    if ($Stage -eq 'app') { Invoke-AppStage }
    elseif ($Mode -eq 'm2-install') { Invoke-InstallMode }
    elseif ($Mode -eq 'm2-traps') { Invoke-TrapsMode }
    else { Invoke-FidelityMode }
} finally {
    Save-M2Run $R -Finished
}
$failed = @(@($S.phases) | Select-Object -Skip $PhaseCount0 | Where-Object { -not $_.ok })
Log "exec-run $Mode/$Stage done: $($failed.Count) failed phase(s)"
if ($failed.Count) { exit 1 }
exit 0
