<#
  Purge rig, M1b executor modes (docs\M1B_DESIGN.json M1B-RIG-EXEC; gates G5 and G6, criteria K10-K13).
  Host driver, Windows PowerShell 5.1; dot-sources rig.ps1 for the VM helpers and leaves it unchanged.

    $env:VMPWFILE = 'C:\path\to\pw.txt'
    .\vm\rig-m1b-exec.ps1 -Mode m1b-x-selftest                       # host only, no VM
    .\vm\rig-m1b-exec.ps1 -Mode m1b-x-null -Count 6 -Engine ...      # ambient set first (once per m2-base, RIG.md 12.8)
    .\vm\rig-m1b-exec.ps1 -Mode m1b-x-fidelity -Engine E:\purge-build\rig-exec\release\purge-engine.exe
    .\vm\rig-m1b-exec.ps1 -Mode m1b-x-traps -Engine ...
    .\vm\rig-m1b-exec.ps1 -Mode m1b-x-undo-traps -Engine ...
    .\vm\rig-m1b-exec.ps1 -Mode m1b-x-crash -HardPowerOff -Engine ...  # whole matrix + 15 power-off rounds
    .\vm\rig-m1b-exec.ps1 -Mode m1b-x-elevated                       # elevated purge-win / purge-exec tests
    bash vm/truth/m1b-exec.sh                                        # K10-K13 (+ E1) -> vm\truth\m1b-exec-score.json

  Every VM mode runs on the rig VM only (rig.ps1 Assert-RigVm; default Inbound-Win11-Test), from a fresh restore of
  -Snapshot (default m2-base), and ends with the VM powered off and restored to that snapshot again. Runs land in
  vm\runs\<prefix><mode>\ (an older one is moved to vm\runs\_old\ first). The rig-exec engine is required (rig.ps1
  Get-M2Engine refuses target\release); rigtool from $env:RIG_RIGTOOL or vm\rigtool\target\release.

  Modes
    m1b-x-fidelity    guest m1b-exec.ps1: every fidelity variant of truth\m1b-exec-cases.json planted for the
                      fabricated app PurgeExecApp, harvest, app removed, scan --mode external, Safe selection
                      executed, execdiff (K10), undo, fidelity (K11).
    m1b-x-traps       guest m1b-exec.ps1: the act-time traps (K12): six changes between scan and exec.
    m1b-x-undo-traps  guest m1b-exec.ps1: the undo traps (K12): four traps between exec and undo.
    m1b-x-crash       guest m1b-crash.ps1: every (kind, reachable fault point, resume|rollback) round, a point not
                      reached fails; -HardPowerOff adds rounds_per_kind power-off rounds per kind (K13). -Kinds and
                      -Points run a subset (the score then fails K13: a subset is not the gate).
    m1b-x-elevated    the M1b elevated tests (cases `elevated`): host `cargo test --release --no-run`, the binaries
                      and a mirror of their package dirs copied to the guest, run by the elevated agent with
                      --include-ignored; writes vm\runs\<prefix>m1b-x-elevated\elevated-tests.json.
    m1b-x-null        the M1b exec ambient set (RIG.md section 12.8): -Count rounds (default 6), each a null run of
                      m1b-x-fidelity and of m1b-x-traps (runs <prefix><k>-<mode>, default prefix xn: xn1-m1b-x-fidelity;
                      the same phases and timing up to deep A, -NullWaitSec idle seconds (default 10) instead of exec,
                      snap B, deep B, nothing after: no restore point, no firewall delete), then host rigtool
                      `ambient --m2 --added --null <run dirs>` -> -AmbientFile (default the VM's: Inbound
                      truth\m1b-exec-ambient.json, Purge-CleanPro truth\m1b-exec-ambient-cleanpro.json). A failed null
                      run writes no file. m1b-x-fidelity and m1b-x-traps refuse to run without it; m1b-x-undo-traps and
                      m1b-x-crash push it when it exists (else the VM's M2 set). Each run records the pushed file and
                      its SHA-256 (opts.ambient; guest run.json results.ambient).
    m1b-x-ambient     host only: the same ambient file again from existing null runs (-Count, -RunPrefix as above).
    m1b-x-selftest    no VM: exec_sh_fails_on_missing_input, exec_cases_json_lists_every_fault_point_per_kind,
                      crash_script_reports_unreached_point_as_failure (and positive controls), the power-off journal
                      proof, and the bad-run controls (review R4 S7): truth\m1b-exec.sh on a synthetic good run set
                      (truth\m1b-exec-fixture.py) must PASS with the gate's figures, and on each one-field mutation of
                      it must FAIL on the named criterion. Needs Python 3 ($env:PYTHON or python). Exit 1 on a failure.

  Binding (review R4 S4, S6): each VM run gets opts.engine_build (engine SHA-256, repo HEAD, whether crates/bins/
  tools/kb/Cargo.*/rust-toolchain.toml differ from HEAD) and records it with the SHA-256 the guest measures of the
  staged and installed engine and of the cases bytes; m1b-x-elevated records the cases SHA-256 and the commit. truth\m1b-exec.sh requires
  one engine, one commit, clean sources and the scored cases file in every run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('m1b-x-fidelity', 'm1b-x-traps', 'm1b-x-undo-traps', 'm1b-x-crash', 'm1b-x-elevated', 'm1b-x-selftest', 'm1b-x-null', 'm1b-x-ambient')]
    [string] $Mode,
    # m1b-x-null / m1b-x-ambient: null rounds (each one m1b-x-fidelity and one m1b-x-traps null run), the idle seconds
    # in place of exec, and the ambient file written (default: the VM's, Get-XAmbientFile). VM modes: the ambient set
    # pushed for execdiff (default the VM's M1b exec set, which must exist).
    [int] $Count = 6,
    [int] $NullWaitSec = 10,
    [string] $AmbientFile = '',
    [string] $Engine = '',
    [string] $RunPrefix = '',
    [string] $Snapshot = 'm2-base',
    [string] $VmName = 'Inbound-Win11-Test',
    [switch] $HardPowerOff,
    [string[]] $Kinds = @(),
    [string[]] $Points = @(),
    [int] $BatchSize = 12,
    [int] $SettleMax = 300,
    [int] $SettleMinUptime = 180,
    [string] $CargoTargetDir = $(if ($env:RIG_TEST_TARGET) { $env:RIG_TEST_TARGET } elseif ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { '' })
)
$ErrorActionPreference = 'Stop'

# rig.ps1 has parameters of its own (Mode, Engine, Snapshot, RunPrefix, ...): ours are kept here first.
$X = [ordered]@{ mode = $Mode; engine = $Engine; prefix = $RunPrefix; snapshot = $Snapshot; vm = $VmName; hard = [bool]$HardPowerOff
    kinds = @($Kinds | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    points = @($Points | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    batch = $BatchSize; settle_max = $SettleMax; settle_min_uptime = $SettleMinUptime; target = $CargoTargetDir
    count = $Count; null_wait = $NullWaitSec; ambient = $AmbientFile }
$XRigDir = $PSScriptRoot
$XRepo = Split-Path -Parent $PSScriptRoot
$XCasesFile = Join-Path $XRigDir 'truth\m1b-exec-cases.json'
$XExecSh = Join-Path $XRigDir 'truth\m1b-exec.sh'
$XFaultRs = Join-Path $XRepo 'crates\purge-exec\src\fault.rs'

# ------------------------------------------------------------------------------------------ pure helpers

function Read-XCases([string]$Path = $XCasesFile) {
    $c = [IO.File]::ReadAllText($Path).TrimStart([char]0xFEFF) | ConvertFrom-Json
    if ("$($c.schema)" -ne 'purge.rig.m1b-exec-cases/1') { throw "cases schema '$($c.schema)'" }
    $c
}

# The point names of purge-exec FAULT_POINTS, from the source (the constants' literals, in list order).
function Get-XFaultPointsFromSource([string]$Path = $XFaultRs) {
    $src = [IO.File]::ReadAllText($Path)
    $consts = @{}
    foreach ($m in [regex]::Matches($src, 'pub const ([A-Z_]+): &str = "([^"]+)";')) { $consts[$m.Groups[1].Value] = $m.Groups[2].Value }
    $list = [regex]::Match($src, '(?s)pub const FAULT_POINTS: &\[&str\] = &\[(.*?)\];')
    if (-not $list.Success) { throw "no FAULT_POINTS list in $Path" }
    $out = @()
    foreach ($m in [regex]::Matches($list.Groups[1].Value, '[A-Z_]+|"[^"]+"')) {
        $v = $m.Value
        if ($v.StartsWith('"')) { $out += $v.Trim('"') } elseif ($consts.ContainsKey($v)) { $out += $consts[$v] } else { throw "FAULT_POINTS names unknown constant $v" }
    }
    $out
}

function Get-XBash {
    foreach ($b in @("$env:ProgramFiles\Git\bin\bash.exe", "${env:ProgramFiles(x86)}\Git\bin\bash.exe")) { if ($b -and (Test-Path -LiteralPath $b)) { return $b } }
    $c = Get-Command bash -CommandType Application -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike "$env:SystemRoot*" } | Select-Object -First 1
    if ($c) { return $c.Source }
    throw 'Git Bash not found (truth\m1b-exec.sh needs bash)'
}

# The build a run is bound to (review R4 S6): the engine file's SHA-256 (lower-case hex; $null without -Path), the
# repository's HEAD and whether its sources (crates, bins, tools, kb, Cargo.toml, Cargo.lock, rust-toolchain.toml;
# kb is compiled into the engine, R4 M11) differ from HEAD. Read-only git calls. The score requires one engine and
# one commit over all runs, and clean sources.
function Get-XBuildInfo([string]$Path = '') {
    $sha = $null
    if ($Path) { $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
    $commit = $null; $dirty = $null
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        $c = @(& git -C $XRepo rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $c.Count) { $commit = "$($c[0])".Trim() }
        $d = @(& git -C $XRepo status --porcelain --untracked-files=no -- crates bins tools kb Cargo.toml Cargo.lock rust-toolchain.toml 2>$null)
        if ($LASTEXITCODE -eq 0) { $dirty = [bool]($d | Where-Object { "$_".Trim() }) }
    } finally { $ErrorActionPreference = $old }
    [ordered]@{ path = $Path; sha256 = $sha; commit = $commit; source_dirty = $dirty }
}

# The M1b executor ambient set of a VM (RIG.md section 12.8), built from its own null runs (m1b-x-null): Inbound
# truth\m1b-exec-ambient.json, Clean-Pro truth\m1b-exec-ambient-cleanpro.json. Another VM has none.
function Get-XAmbientFile([string]$Vm) {
    $leaf = switch -CaseSensitive ($Vm) { 'Inbound-Win11-Test' { 'm1b-exec-ambient.json' } 'Purge-CleanPro' { 'm1b-exec-ambient-cleanpro.json' } default { $null } }
    if (-not $leaf) { throw "no M1b exec ambient set for VM '$Vm'" }
    Join-Path $XRigDir "truth\$leaf"
}

# The guest modes a null round runs (each its exec window with an idle wait instead of exec).
$XNullModes = @('m1b-x-fidelity', 'm1b-x-traps')

# The run name of null round $K of guest mode $M: <prefix><k>-<mode> (default prefix xn: xn1-m1b-x-fidelity), as M2's
# Invoke-M2NullCampaign names its runs; never a gate run's name.
function Get-XNullRunName([int]$K, [string]$M, [string]$Prefix = '') {
    if ($K -lt 1) { throw "bad null round $K" }
    if ($XNullModes -cnotcontains $M) { throw "a null run is for $($XNullModes -join ' / ') only (got '$M')" }
    if (-not $Prefix) { $Prefix = 'xn' }
    $r = "$Prefix$K-$M"
    if ($r -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$r'" }
    $r
}

# The arguments of the host rigtool call that builds the M1b exec ambient set from null run dirs.
function Get-XAmbientArgs([string[]]$Dirs, [string]$Out) {
    if (-not @($Dirs).Count) { throw 'no null run dirs' }
    @('ambient', '--m2', '--added', '--null') + @($Dirs) + @('-o', $Out)
}

function Get-XSha256File([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }

function Get-XPython { if ($env:PYTHON) { $env:PYTHON } else { 'python' } }

# The libtest result lines of one binary's output: {name, result} (ok, FAILED, ignored).
function ConvertFrom-XLibtest([string[]]$Lines) {
    $out = @()
    foreach ($l in $Lines) {
        $m = [regex]::Match("$l", '^test (\S+) \.\.\. (ok|FAILED|ignored)(?:,.*)?\s*$')
        if ($m.Success) { $out += [pscustomobject][ordered]@{ name = $m.Groups[1].Value; result = $m.Groups[2].Value } }
    }
    $out
}

# ------------------------------------------------------------------------------------------ self-test (no VM)

function Invoke-XSelftest {
    $rows = New-Object System.Collections.ArrayList
    $add = { param($n, $ok, $detail) [void]$rows.Add([pscustomobject][ordered]@{ test = $n; pass = [bool]$ok; detail = "$detail" }); Write-Host ("{0} {1}{2}" -f $(if ($ok) { 'ok  ' } else { 'FAIL' }), $n, $(if ($detail) { ": $detail" })) }
    $cases = Read-XCases

    # exec_sh_fails_on_missing_input: an empty runs dir -> exit 2, verdict FAIL, every input listed missing.
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('m1b-exec-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force (Join-Path $tmp 'runs'), (Join-Path $tmp 'out') | Out-Null
    try {
        $bash = Get-XBash
        $old = @{ R = $env:M1B_RUNS; O = $env:M1B_OUT }
        $env:M1B_RUNS = (Join-Path $tmp 'runs') -replace '\\', '/'; $env:M1B_OUT = (Join-Path $tmp 'out') -replace '\\', '/'
        try {
            $ErrorActionPreference = 'Continue'
            $o = & $bash ($XExecSh -replace '\\', '/') 2>&1
            $code = $LASTEXITCODE
            $ErrorActionPreference = 'Stop'
        } finally { $env:M1B_RUNS = $old.R; $env:M1B_OUT = $old.O }
        $sf = Join-Path $tmp 'out\m1b-exec-score.json'
        $score = $(if (Test-Path -LiteralPath $sf) { [IO.File]::ReadAllText($sf) | ConvertFrom-Json } else { $null })
        $ok = ($code -eq 2 -and $score -and $score.verdict -eq 'FAIL' -and $score.pass -eq $false -and @($score.missing).Count -ge 9)
        & $add 'exec_sh_fails_on_missing_input' $ok ("exit $code; verdict $($score.verdict); missing $(@($score.missing).Count)" + $(if (-not $ok) { "; out: $($o -join ' | ')" }))
    } catch { & $add 'exec_sh_fails_on_missing_input' $false $_.Exception.Message }
    finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

    # The guest library (pure functions only; nothing planted, no riglib).
    . (Join-Path $XRigDir 'guest\m1b-crash.ps1') -Library

    # exec_cases_json_lists_every_fault_point_per_kind: the cases file against purge-exec FAULT_POINTS (the list
    # `purge-engine journal fault-points` prints; the guest checks the engine's own output again at crash start).
    try {
        $declared = @(Get-XFaultPointsFromSource)
        $cov = Test-XCasesCoverPoints $cases $declared
        $order = (@(@($cases.crash.fault_points) | ForEach-Object { "$($_.point)" }) -join ',') -ceq ($declared -join ',')
        & $add 'exec_cases_json_lists_every_fault_point_per_kind' ($cov.ok -and $declared.Count -ge 19) ("{0} declared; missing [{1}] unknown [{2}] dup [{3}] no reason [{4}]; same order {5}" -f $declared.Count, ($cov.missing -join ','), ($cov.unknown -join ','), ($cov.duplicate -join ','), ($cov.no_reason -join ','), $order)
        # Negative control: a point dropped from the cases file must be caught.
        $c2 = $cases | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $c2.crash.fault_points = @(@($c2.crash.fault_points) | Where-Object { "$($_.point)" -ne 'objdelete.after' })
        $cov2 = Test-XCasesCoverPoints $c2 $declared
        & $add 'exec_cases_json_detects_a_dropped_point' ((-not $cov2.ok) -and @($cov2.missing) -contains 'objdelete.after') "missing [$($cov2.missing -join ',')]"
    } catch { & $add 'exec_cases_json_lists_every_fault_point_per_kind' $false $_.Exception.Message }

    # crash_script_reports_unreached_point_as_failure: dry rows for a cases file with a fake point; the fake point's
    # row did not hit -> unreached, matrix FAIL. Positive control: the same rows with the point hit -> PASS.
    try {
        $fake = $cases | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $fake.crash.fault_points = @([pscustomobject]@{ point = 'act.after'; phase = 'exec'; kinds = @('service') }, [pscustomobject]@{ point = 'rig.fake'; phase = 'exec'; kinds = @('service') })
        $fake.crash.exec_afters = @('resume')
        $mk = {
            param($Point, [bool]$Hit)
            $r = New-XRow 1 'service' $Point 'exec' 'resume'
            $r.hit = $Hit; $r.crashed = $Hit
            if ($Hit) { $r.recover_exit = 0; $r.recover2_exit = 0; $r.recover_idempotent = $true; $r.after_exit = 0; $r.execdiff_ok = $true; $r.execdiff_unexplained = 0; $r.undo_exit = 0; $r.fidelity_ok = $true; $r.object_restored = $true }
            Set-XRowPass $r
            [pscustomobject]$r
        }
        $plan = @(Get-XCrashPlan $fake @('service'))
        $rowsDry = @((& $mk 'act.after' $true), (& $mk 'rig.fake' $false))
        $sum = Get-XCrashSummary $fake $rowsDry @('service')
        $ok1 = ($plan.Count -eq 2 -and -not $sum.pass -and @($sum.unreached) -contains 'service/rig.fake/exec/resume' -and -not $rowsDry[1].pass)
        & $add 'crash_script_reports_unreached_point_as_failure' $ok1 ("planned $($plan.Count); unreached [$($sum.unreached -join ',')]; pass $($sum.pass)")
        $rowsDry2 = @((& $mk 'act.after' $true))
        $sum2 = Get-XCrashSummary $fake $rowsDry2 @('service')
        & $add 'crash_script_reports_a_missing_row_as_unreached' ((-not $sum2.pass) -and @($sum2.unreached) -contains 'service/rig.fake/exec/resume') "unreached [$($sum2.unreached -join ',')]"
        $rowsDry3 = @((& $mk 'act.after' $true), (& $mk 'rig.fake' $true))
        $sum3 = Get-XCrashSummary $fake $rowsDry3 @('service')
        & $add 'crash_script_passes_when_every_point_is_reached' ($sum3.pass -and -not @($sum3.unreached).Count) "pass $($sum3.pass)"
        # A hit row whose recovery left a difference fails.
        $bad = & $mk 'act.after' $true; $bad.fidelity_ok = $false; Set-XRowPass $bad
        & $add 'crash_row_with_inexact_undo_fails' (-not $bad.pass) "pass $($bad.pass)"
        # An exec/resume row whose execdiff saw an added record nothing authorises fails (R4 S2).
        $bad2 = & $mk 'act.after' $true; $bad2.execdiff_unexplained = 1; Set-XRowPass $bad2
        $bad3 = & $mk 'act.after' $true; $bad3.execdiff_unexplained = $null; Set-XRowPass $bad3
        & $add 'crash_row_with_unexplained_record_fails' (-not $bad2.pass -and -not $bad3.pass) "pass $($bad2.pass) / no count $($bad3.pass)"
        # A power-off row passes only with the cut proven inside the run (R4 S1).
        $po1 = New-XRow 901 'service' 'act.before' 'exec' 'resume' 'poweroff'
        foreach ($k in 'recover_exit', 'recover2_exit', 'after_exit', 'undo_exit', 'execdiff_unexplained') { $po1[$k] = 0 }
        $po1.hit = $true; $po1.crashed = $true; $po1.recover_idempotent = $true; $po1.execdiff_ok = $true; $po1.fidelity_ok = $true; $po1.object_restored = $true
        $po1.boot_changed = $true; $po1.pfro_unchanged = $true; $po1.cut_mid_run = $true
        Set-XRowPass $po1; $poOk = $po1.pass
        $po1.cut_mid_run = $false; Set-XRowPass $po1
        & $add 'poweroff_row_needs_cut_mid_run' ($poOk -and -not $po1.pass) "with cut $poOk, without $($po1.pass)"
        # Repeated rounds: one failing row fails the key even when another passed (R4 M7).
        $rep1 = & $mk 'act.after' $true; $rep2 = & $mk 'act.after' $true; $rep2.fidelity_ok = $false; Set-XRowPass $rep2
        $sumRep = Get-XCrashSummary $fake @($rep1, $rep2, (& $mk 'rig.fake' $true)) @('service')
        & $add 'crash_summary_fails_a_repeated_failing_round' (-not $sumRep.pass -and @($sumRep.failed) -contains 'service/act.after/exec/resume') "failed [$($sumRep.failed -join ',')]"
        # The real plan: every kind, every reachable point; svcrestore / fwrestore only for their kind; index.write
        # in undo (resume) and in exec (resume only, R4 S4). 10 exec points x 3 kinds x 2 + 3 exec index.write
        # + 3 undo points x 3 + 2 = 74 = m1b-exec.sh GATE_ROUNDS.
        $full = @(Get-XCrashPlan $cases)
        $svcOnly = @($full | Where-Object { $_.point -eq 'svcrestore.mid' } | ForEach-Object { $_.kind } | Select-Object -Unique)
        $fwOnly = @($full | Where-Object { $_.point -eq 'fwrestore.mid' } | ForEach-Object { $_.kind } | Select-Object -Unique)
        $iw = @($full | Where-Object { $_.point -eq 'index.write' } | ForEach-Object { "$($_.kind)/$($_.phase)/$($_.after)" } | Sort-Object)
        & $add 'crash_plan_covers_kinds' ($full.Count -eq 74 -and ($svcOnly -join ',') -eq 'service' -and ($fwOnly -join ',') -eq 'firewall' -and $iw.Count -eq 6 -and -not @($iw | Where-Object { $_ -like '*/exec/rollback' }).Count) "rounds $($full.Count); index.write [$($iw -join ',')]"
        $po = @(Get-XPoweroffPlan $cases 'm1b-x-crash')
        $po2 = @(Get-XPoweroffPlan $cases 'm1b-x-crash')
        $firsts = @($CrashKinds | ForEach-Object { $k = $_; @($po | Where-Object { $_.kind -eq $k })[0].point })
        & $add 'poweroff_plan_is_15_seeded_rounds' ($po.Count -eq 15 -and (($po | ForEach-Object { "$($_.kind)/$($_.point)" }) -join ',') -eq (($po2 | ForEach-Object { "$($_.kind)/$($_.point)" }) -join ',') -and -not @($firsts | Where-Object { $_ -ne 'objdelete.after' }).Count) "rounds $($po.Count)"
    } catch { & $add 'crash_script_reports_unreached_point_as_failure' $false $_.Exception.Message }

    # The power-off proof (R4 S1): journal facts and the mid-run verdict on hand-made journals.
    try {
        $j = { param([string[]]$Recs, [string]$Tail = '') (($Recs | ForEach-Object { $_ + "`n" }) -join '') + $Tail }
        $hdr = '{"rec":"header"}', '{"rec":"validated","op":1}'
        $open = & $j ($hdr + '{"rec":"intent","op":1}')
        $done = & $j ($hdr + '{"rec":"intent","op":1}', '{"rec":"done","op":1}', '{"rec":"group_end"}')
        $committed = & $j ($hdr + '{"rec":"intent","op":1}', '{"rec":"done","op":1}', '{"rec":"group_end"}', '{"rec":"commit"}')
        $undoOpen = & $j ($hdr + '{"rec":"intent","op":1}', '{"rec":"done","op":1}', '{"rec":"commit"}', '{"rec":"undo_plan"}', '{"rec":"undo_intent","op":1}')
        $undoDone = & $j ($hdr + '{"rec":"intent","op":1}', '{"rec":"done","op":1}', '{"rec":"commit"}', '{"rec":"undo_intent","op":1}', '{"rec":"undo_done","op":1}')
        $torn = & $j ($hdr + '{"rec":"intent","op":1}') '{"rec":"done","op'
        $v = { param($t, $ph, $p) (Test-XCutMidRun (Get-XJournalFacts $t) $ph $p).ok }
        $ok = ((& $v $open 'exec' 'act.before') -and (& $v $done 'exec' 'commit.before') -and -not (& $v $done 'exec' 'act.after') `
                -and -not (& $v $committed 'exec' 'commit.before') -and -not (& $v $committed 'exec' 'act.before') `
                -and (& $v $undoOpen 'undo' 'undo.act.after') -and -not (& $v $undoDone 'undo' 'undo.act.after') -and -not (& $v $committed 'undo' 'undo.intent') `
                -and (& $v $torn 'exec' 'done.before') -and (Get-XJournalFacts $torn).torn_tail -and -not (& $v $null 'exec' 'act.before') `
                -and -not (& $v ($open + "garbage`n") 'exec' 'act.before'))
        & $add 'poweroff_cut_mid_run_reads_the_journal' $ok ''
    } catch { & $add 'poweroff_cut_mid_run_reads_the_journal' $false $_.Exception.Message }

    # Bad-run controls (R4 S7): m1b-exec.sh on a synthetic run set in which every criterion holds (built by
    # truth\m1b-exec-fixture.py from the cases file) must PASS with the gate's figures; each one-field mutation must
    # FAIL on the criterion it names. A mutation the scorer lets through is a scorer that passes too easily.
    try {
        $py = Get-XPython
        $bash = Get-XBash
        $fx = Join-Path $XRigDir 'truth\m1b-exec-fixture.py'
        $ErrorActionPreference = 'Continue'
        $list = @(& $py -I $fx --cases $XCasesFile --out . --list 2>&1)
        $ErrorActionPreference = 'Stop'
        $muts = @($list | ForEach-Object { "$_" } | Where-Object { $_ -match "`t" } | ForEach-Object { $p = $_ -split "`t"; [pscustomobject]@{ name = $p[0]; crit = $p[1]; what = $p[2] } })
        # The mutations the review asked for must be among them (a fixture that lost one would weaken the test).
        $required = @('collateral', 'unexplained', 'trap-deleted', 'impostor-overwritten', 'unreached-point', 'poweroff-14', 'poweroff-not-mid-run',
            'svc-running-restarted', 'twin-base-not-done', 'cases-min-full', 'cases-drop-trap', 'cases-drop-point', 'engine-differs', 'cases-sha')
        $lost = @($required | Where-Object { @($muts | ForEach-Object { $_.name }) -notcontains $_ })
        & $add 'bad_run_controls_listed' (-not $lost.Count -and $muts.Count -ge $required.Count) "$($muts.Count) mutation(s); missing [$($lost -join ',')]"
        $score = {
            param([string]$Mutation)
            $d = Join-Path ([IO.Path]::GetTempPath()) ('m1b-exec-fx-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            try {
                $ErrorActionPreference = 'Continue'
                $a = @('-I', $fx, '--cases', $XCasesFile, '--out', $d); if ($Mutation) { $a += @('--mutate', $Mutation) }
                $null = & $py @a 2>&1
                if ($LASTEXITCODE -ne 0) { throw "fixture $Mutation exited $LASTEXITCODE" }
                $old = @{ R = $env:M1B_RUNS; O = $env:M1B_OUT; C = $env:M1B_CASES }
                $env:M1B_RUNS = (Join-Path $d 'runs') -replace '\\', '/'; $env:M1B_OUT = $d -replace '\\', '/'; $env:M1B_CASES = (Join-Path $d 'cases.json') -replace '\\', '/'
                try { $null = & $bash ($XExecSh -replace '\\', '/') 2>&1; $code = $LASTEXITCODE } finally { $env:M1B_RUNS = $old.R; $env:M1B_OUT = $old.O; $env:M1B_CASES = $old.C }
                $ErrorActionPreference = 'Stop'
                $sf = Join-Path $d 'm1b-exec-score.json'
                [pscustomobject]@{ code = $code; score = $(if (Test-Path -LiteralPath $sf) { [IO.File]::ReadAllText($sf) | ConvertFrom-Json } else { $null }) }
            } finally { $ErrorActionPreference = 'Stop'; Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
        }
        $base = & $score ''
        $c = $base.score.criteria
        $figures = ($c.K13.planned -eq 74 -and $c.K13.poweroff_total_want -eq 15 -and $c.K12.act_skipped -eq 5 -and $c.K12.act_twin_untouched -eq 1 `
                -and $c.K12.undo_conflicts -eq 4 -and $c.K11.full_passing.service -ge 2 -and $c.K11.full_passing.task -ge 4 -and $c.K11.full_passing.firewall -ge 3 `
                -and $c.K11.min_full.service -eq 2 -and $c.K11.min_full.task -eq 4 -and $c.K11.min_full.firewall -eq 3 -and @($c.E1.targets).Count -eq 6)
        & $add 'exec_sh_passes_a_good_run_set' ($base.code -eq 0 -and $base.score.verdict -eq 'PASS' -and $figures) ("exit $($base.code); verdict $($base.score.verdict); failing [$(@($base.score.failing) -join ',')]; figures $figures")
        foreach ($m in $muts) {
            $r = & $score $m.name
            $ok = ($r.code -eq 1 -and $r.score -and $r.score.verdict -eq 'FAIL' -and @($r.score.failing) -contains $m.crit)
            & $add "exec_sh_fails_bad_run_$($m.name)" $ok ("exit $($r.code); failing [$(@($r.score.failing) -join ',')], want $($m.crit): $($m.what)")
        }
    } catch { & $add 'exec_sh_bad_run_controls' $false $_.Exception.Message }

    # The null mode and the M1b exec ambient set (RIG.md section 12.8).
    try {
        $n1 = Get-XNullRunName 1 'm1b-x-fidelity'
        $n2 = Get-XNullRunName 12 'm1b-x-traps' 'cpxn'
        $bad = 0
        foreach ($b in @(@(0, 'm1b-x-fidelity', ''), @(1, 'm1b-x-undo-traps', ''), @(1, 'm1b-x-crash', ''), @(1, 'm1b-x-traps', 'Bad Prefix'))) {
            try { $null = Get-XNullRunName $b[0] $b[1] $b[2]; $bad++ } catch { }
        }
        & $add 'null_run_names' ($n1 -ceq 'xn1-m1b-x-fidelity' -and $n2 -ceq 'cpxn12-m1b-x-traps' -and $bad -eq 0 -and ($XNullModes -join ',') -ceq 'm1b-x-fidelity,m1b-x-traps') "$n1, $n2; $bad bad name(s) accepted"
        $ai = Get-XAmbientFile 'Inbound-Win11-Test'; $ac = Get-XAmbientFile 'Purge-CleanPro'
        $threw = $false; try { $null = Get-XAmbientFile 'Some-Other-VM' } catch { $threw = $true }
        & $add 'ambient_file_per_vm' ($ai -like '*\truth\m1b-exec-ambient.json' -and $ac -like '*\truth\m1b-exec-ambient-cleanpro.json' -and $threw) "$ai | $ac"
        $aa = @(Get-XAmbientArgs @('runs\xn1-m1b-x-fidelity', 'runs\xn1-m1b-x-traps') 'out.json')
        & $add 'ambient_build_keeps_added_records' (($aa -join ' ') -ceq 'ambient --m2 --added --null runs\xn1-m1b-x-fidelity runs\xn1-m1b-x-traps -o out.json') ($aa -join ' ')
        # The guest flows: the null window replaces exec right after deep A, in both null modes; nothing in the null
        # branch runs the engine.
        $g = [IO.File]::ReadAllText((Join-Path $XRigDir 'guest\m1b-exec.ps1'))
        $okFlow = $true; $why = @()
        foreach ($f in @(@('Invoke-FidelityMode', 'deepscope-main.json', 'exec-main'), @('Invoke-TrapsMode', 'deepscope-traps.json', 'exec-traps'))) {
            $body = [regex]::Match($g, "(?s)function $($f[0]) \{(.*?)\r?\n\}\r?\n").Groups[1].Value
            $iDeep = $body.IndexOf("Phase 'deep-a'"); $iNull = $body.IndexOf('if ($NullRun) {'); $iExec = $body.IndexOf("Phase '$($f[2])'")
            $nullLine = $(if ($iNull -ge 0) { $body.Substring($iNull, $body.IndexOf("`n", $iNull) - $iNull) } else { '' })
            if (-not ($iDeep -ge 0 -and $iNull -gt $iDeep -and $iExec -gt $iNull -and $nullLine -match 'Invoke-ExNullWindow' -and $nullLine -match 'return' -and $nullLine -notmatch 'Invoke-ExExec|Invoke-M2Engine')) { $okFlow = $false; $why += "$($f[0]): deep-a $iDeep, null $iNull, exec $iExec" }
        }
        $win = [regex]::Match($g, '(?s)function Invoke-ExNullWindow\(.*?\r?\n\}\r?\n').Value
        $okWin = ($win -match "Phase 'null-wait'" -and $win -match 'Start-Sleep -Seconds \$NullWaitSec' -and $win -match "Phase 'snap-b'" -and $win -match 'snap-\$Run-b\.tsv\.gz' -and $win -notmatch 'Invoke-M2Engine|Invoke-ExExec|Invoke-M2Execdiff')
        & $add 'guest_null_window_replaces_exec' ($okFlow -and $okWin) (($why + $(if (-not $okWin) { 'Invoke-ExNullWindow' })) -join '; ')
    } catch { & $add 'null_mode' $false $_.Exception.Message }

    # Guest pure helpers: plan rows and outcomes.
    try {
        $plan = [pscustomobject]@{ items = @([pscustomobject]@{ band = 'Safe'; preselected = $true }, [pscustomobject]@{ band = 'Weak'; preselected = $false }) }
        $side = [pscustomobject]@{ items = @([pscustomobject]@{ id = 'a'; target = [pscustomobject]@{ type = 'Service'; name = 'PurgeExecSvcA' } }, [pscustomobject]@{ id = 'b'; target = [pscustomobject]@{ type = 'FirewallRule'; id = 'PurgeExecFwX' } }) }
        $pr = @(ConvertTo-ExPlanRows $plan $side)
        $rep = '{"items":[{"item":"a","op":1,"outcome":{"kind":"Skipped","reason":{"kind":"GateBlocked","blocker":{"kind":"InUse"}}}}]}' | ConvertFrom-Json
        $oc = Get-ExOutcome $rep 'a'
        $ud = '{"items":[{"item":"a","op":1,"result":{"result":"Conflict","conflict":{"kind":"ObjectExists"}}}]}' | ConvertFrom-Json
        $ur = Get-ExUndoResult $ud 'a'
        $ok = ($pr.Count -eq 2 -and (Find-ExRow $pr 'service' 'purgeexecsvca').id -eq 'a' -and -not (Find-ExRow $pr 'firewall' 'purgeexecfwx') -and $oc.kind -eq 'Skipped' -and $oc.reason -eq 'GateBlocked' -and $oc.blocker -eq 'InUse' -and $ur.result -eq 'Conflict' -and $ur.kind -eq 'ObjectExists')
        & $add 'guest_helpers_read_plan_report_and_undo' $ok ''
    } catch { & $add 'guest_helpers_read_plan_report_and_undo' $false $_.Exception.Message }

    $failed = @($rows | Where-Object { -not $_.pass })
    Write-Host ("m1b-x-selftest: {0}/{1} passed" -f ($rows.Count - $failed.Count), $rows.Count)
    [pscustomobject]@{ rows = @($rows); pass = (-not $failed.Count) }
}

if ($X.mode -eq 'm1b-x-selftest') {
    $st = Invoke-XSelftest
    if (-not $st.pass) { exit 1 }
    exit 0
}

# ------------------------------------------------------------------------------------------ VM modes

. (Join-Path $XRigDir 'rig.ps1') -VmName $X.vm -Snapshot $X.snapshot

# Leaves the VM at its snapshot, powered off (a live snapshot comes back 'saved').
function Stop-XVm([string]$Snap) {
    try {
        $st = Get-VmState
        if (@('running', 'paused', 'stuck', 'starting', 'stopping', 'saving', 'restoring', 'livesnapshotting') -contains $st) {
            $r = Invoke-VBox @('controlvm', $script:VmName, 'poweroff')
            if ($r.code -ne 0) { Write-RigLog "  poweroff: $($r.out -join ' ')" }
            $null = Wait-VmState @('poweroff', 'aborted', 'saved') 120
        }
        $ok = $false
        for ($i = 1; $i -le 6 -and -not $ok; $i++) {
            $r = Invoke-VBox @('snapshot', $script:VmName, 'restore', $Snap)
            if ($r.code -eq 0) { $ok = $true } else { Start-Sleep -Seconds 3 }
        }
        Write-RigLog "VM $script:VmName restored to $Snap and left off: $ok (state $(Get-VmState))"
    } catch { Write-RigLog "!! leaving the VM at $Snap failed: $($_.Exception.Message)" }
}

function Get-XRunName([string]$M) {
    $r = "$($X.prefix)$M"
    if ($r -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$r'" }
    $r
}

# The ambient set a run pushes for execdiff (RIG.md section 12.8): -AmbientFile, else the VM's M1b exec set
# (Get-XAmbientFile, built by m1b-x-null). m1b-x-fidelity and m1b-x-traps (K10) require it; the other modes push it
# when it exists, else the VM's M2 set as before (their execdiffs are scoped). rig.ps1 Push-M2Ambient copies the file
# to the guest as C:\cr\bin\m2-ambient.json, where riglib Invoke-M2Execdiff passes it as --ambient; a null run
# pushes none. The Get-M2AmbientFile below replaces rig.ps1's (the M2 set) for this script only.
$XAmbient = $(if ($X.ambient) { $X.ambient } else { Get-XAmbientFile $X.vm })
$XM2Ambient = $(try { Get-M2AmbientFile } catch { $null })
$script:XPushAmbient = $null
function Get-M2AmbientFile([string]$Name = $script:VmName) { $script:XPushAmbient }
$XAmbientModes = @('m1b-x-fidelity', 'm1b-x-traps')

# One guest-mode run from a fresh restore. -GuestMode / -Run default to the script's mode; -Null: a null run of
# m1b-x-fidelity / m1b-x-traps (opts null, null_wait; no ambient set pushed).
function Invoke-XGuestMode([string]$GuestMode = $X.mode, [string]$Run = '', [switch]$NullRun) {
    $run = $(if ($Run) { $Run } else { Get-XRunName $GuestMode })
    $eng = Get-M2Engine -Engine $X.engine
    $casesB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($XCasesFile))
    $opts = [ordered]@{ mode = $GuestMode; snapshot = $X.snapshot; cases_b64 = $casesB64; engine_build = (Get-XBuildInfo $eng) }
    if ($NullRun) {
        if ($XNullModes -cnotcontains $GuestMode) { throw "a null run is for $($XNullModes -join ' / ') only" }
        $opts.null = $true; $opts.null_wait = $X.null_wait
        $script:XPushAmbient = $null
    } else {
        $have = Test-Path -LiteralPath $XAmbient -PathType Leaf
        if (-not $have -and $XAmbientModes -ccontains $GuestMode) { throw "no M1b exec ambient set $XAmbient (run -Mode m1b-x-null first, RIG.md section 12.8, or pass -AmbientFile)" }
        $script:XPushAmbient = $(if ($have) { $XAmbient } else { $XM2Ambient })
        if ($script:XPushAmbient -and (Test-Path -LiteralPath $script:XPushAmbient -PathType Leaf)) { $opts.ambient = [ordered]@{ file = $script:XPushAmbient; sha256 = (Get-XSha256File $script:XPushAmbient) } }
    }
    $tpl = 'm1b-exec.ps1'; $to = 7200
    if ($GuestMode -eq 'm1b-x-crash') {
        $tpl = 'm1b-crash.ps1'; $to = 14400
        $opts.batch = $X.batch; $opts.hard_poweroff = $X.hard
        if ($X.kinds.Count) { $opts.kinds = $X.kinds }
        if ($X.points.Count) { $opts.points = $X.points }
    } else {
        if ($X.hard) { throw '-HardPowerOff is for m1b-x-crash only' }
        $opts.settle_max = $X.settle_max; $opts.settle_min_uptime = $X.settle_min_uptime
    }
    New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:RigLogFile = Join-Path $script:RunsDir "m1b-$run-$stamp.log"
    Write-RigLog "M1b $GuestMode as run $run from $($X.snapshot) on $script:VmName; engine $eng$(if ($NullRun) { "; null run, idle $($X.null_wait) s" } else { "; ambient $($script:XPushAmbient)" })$(if ($X.hard) { '; hard power-off' })$(if ($X.kinds.Count) { '; kinds ' + ($X.kinds -join ',') })$(if ($X.points.Count) { '; points ' + ($X.points -join ',') })"
    $rec = $null
    try {
        $null = Get-PwFile
        $rec = Invoke-SnapshotJob -Run $run -Mode $GuestMode -Opts $opts -Template $tpl -Snapshot $X.snapshot -Engine $eng -HardPowerOff:$X.hard -TimeoutSec $to
        [IO.File]::WriteAllText((Join-Path $script:RunsDir "m1b-$run-$stamp.json"), (ConvertTo-Json -InputObject $rec -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    } finally {
        Stop-XVm $X.snapshot
        Remove-PwTemp
        $script:RigLogFile = $null
    }
    $rec
}

# The host rigtool (ambient builds): $env:RIG_RIGTOOL, else vm\rigtool\target\release\rigtool.exe.
function Get-XHostRigTool {
    $t = $(if ($env:RIG_RIGTOOL) { $env:RIG_RIGTOOL } else { Join-Path $XRigDir 'rigtool\target\release\rigtool.exe' })
    if (-not (Test-Path -LiteralPath $t -PathType Leaf)) { throw "rigtool not built: $t" }
    $t
}

# m1b-x-ambient (host only): the M1b exec ambient set from the null runs <prefix><k>-<mode>, k = 1..-Count, of both
# null modes (every one must hold its snapshot pair) -> $XAmbient. Returns the dirs used.
function Invoke-XBuildAmbient {
    $dirs = @()
    foreach ($k in 1..$X.count) {
        foreach ($m in $XNullModes) {
            $r = Get-XNullRunName $k $m $X.prefix
            $d = Join-Path $script:RunsDir $r
            if (-not (Test-Path -LiteralPath (Join-Path $d "snap-$r-a.tsv.gz")) -or -not (Test-Path -LiteralPath (Join-Path $d "snap-$r-b.tsv.gz"))) { throw "null run $r has no snapshot pair in $d" }
            $dirs += $d
        }
    }
    $a = Get-XAmbientArgs $dirs $XAmbient
    $tool = Get-XHostRigTool
    Write-Host "$tool $($a -join ' ')"
    & $tool @a
    if ($LASTEXITCODE -ne 0) { throw "rigtool ambient --m2 --added exited $LASTEXITCODE" }
    Write-Host "M1b exec ambient set ($($dirs.Count) null runs) -> $XAmbient"
    $dirs
}

# m1b-x-null: -Count null rounds, each a null run of m1b-x-fidelity and of m1b-x-traps from a fresh restore, then the
# ambient set (Invoke-XBuildAmbient). Any failed null run: no ambient file is written (exit 1).
function Invoke-XNullCampaign {
    if ($X.count -lt 1) { throw '-Count must be at least 1' }
    if ($X.hard) { throw '-HardPowerOff is for m1b-x-crash only' }
    $null = Get-XHostRigTool
    $bad = @()
    foreach ($k in 1..$X.count) {
        foreach ($m in $XNullModes) {
            $run = Get-XNullRunName $k $m $X.prefix
            $r = Invoke-XGuestMode -GuestMode $m -Run $run -NullRun
            if (-not $r -or -not $r.ok) { $bad += $run; Write-Host "!! null run $run failed: $(if ($r) { $r.error })" }
        }
    }
    if ($bad.Count) { throw "null run(s) failed: $($bad -join ', '); no ambient set written" }
    $null = Invoke-XBuildAmbient
}

# The M1b elevated tests (cases `elevated`). Binaries read files through env!("CARGO_MANIFEST_DIR") (e.g. the
# no_run_stop_enable_symbols scans of the sources), so the package dirs are mirrored to the same path in the guest
# and each binary runs from its package dir, as cargo test does.
function Invoke-XElevated {
    $run = Get-XRunName 'm1b-x-elevated'
    $cases = Read-XCases
    $targets = @($cases.elevated.targets)
    $tdir = $X.target
    if (-not $tdir) { $tdir = Join-Path $XRepo 'target\rig-elevated' }
    New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
    $null = Move-RunToOld -Run $run
    $dst = Join-Path $script:RunsDir $run
    New-Item -ItemType Directory -Force $dst | Out-Null
    $script:RigLogFile = Join-Path $dst 'rig.log'
    $doc = [ordered]@{ schema = 'purge.rig.m1b-elevated/1'; run = $run; snapshot = $X.snapshot; vm = $script:VmName; start = (Get-Date).ToString('o'); end = $null
        method = 'host cargo test --release --no-run; binaries and package mirrors copied to the guest; run by the elevated agent'; admin = $false; targets = @(); error = $null; pass = $false
        cases_sha256 = (Get-XSha256File $XCasesFile); build = (Get-XBuildInfo) }
    $rows = @()
    $stage = Join-Path (Get-HostTemp) ('m1bel-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    try {
        $null = Get-PwFile
        $ErrorActionPreference = 'Continue'
        New-Item -ItemType Directory -Force $stage | Out-Null
        $exes = @{}
        foreach ($g in @($targets | Group-Object { "$($_.crate)|$($_.features)" })) {
            $c, $f = $g.Name -split '\|', 2
            Write-RigLog "build tests of $c (features $f) into $tdir"
            $old = $env:CARGO_TARGET_DIR; $env:CARGO_TARGET_DIR = $tdir
            Push-Location $XRepo
            try {
                $tests = @($g.Group | ForEach-Object { '--test'; "$($_.test)" })
                $out = @(& cargo test -p $c --features $f --release --no-run --message-format=json @tests 2>$null)
            } finally { Pop-Location; $env:CARGO_TARGET_DIR = $old }
            if ($LASTEXITCODE -ne 0) { throw "cargo test --no-run -p $c --features $f exited $LASTEXITCODE" }
            foreach ($a in @($out | Where-Object { $_ -match '"reason":"compiler-artifact"' } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.profile.test -and $_.executable })) {
                $exes["$c|$($a.target.name)"] = "$($a.executable)"
            }
        }
        # Package mirrors (src, tests, Cargo.toml of each crate) as one archive rooted at the drive.
        $crates = @($targets | ForEach-Object { "$($_.crate)" } | Select-Object -Unique)
        $drive = [IO.Path]::GetPathRoot($XRepo)
        $rel = @()
        foreach ($c in $crates) { foreach ($p in 'src', 'tests', 'Cargo.toml') { $full = Join-Path $XRepo "crates\$c\$p"; if (Test-Path -LiteralPath $full) { $rel += $full.Substring($drive.Length) } } }
        $tar = Join-Path $stage 'mirror.tgz'
        & "$env:SystemRoot\System32\tar.exe" -czf $tar -C $drive @rel
        if ($LASTEXITCODE -ne 0) { throw "tar of the package mirrors exited $LASTEXITCODE" }
        foreach ($t in $targets) {
            $row = [ordered]@{ crate = "$($t.crate)"; test = "$($t.test)"; features = "$($t.features)"; exe = $exes["$($t.crate)|$($t.test)"]; guest_exe = $null; workdir = (Join-Path $XRepo "crates\$($t.crate)")
                args = $null; exit = $null; tests = @(); output_tail = @(); error = $null }
            if (-not $row.exe) { $row.error = 'no test binary built' }
            else {
                $leaf = '{0}-{1}' -f $row.crate, (Split-Path -Leaf $row.exe)
                Copy-Item -LiteralPath $row.exe -Destination (Join-Path $stage $leaf) -Force
                $row.guest_exe = "C:\cr\m1bel\$leaf"
                $a = @('--include-ignored', '--test-threads=1')
                if ($t.PSObject.Properties['require_names'] -and @($t.require_names).Count) { $a += '--exact'; $a += @($t.require_names) }
                $row.args = $a
            }
            $rows += $row
        }
        Restore-Base -Snapshot $X.snapshot
        $null = Invoke-Guest @('mkdir', '--parents', 'C:\cr\m1bel')
        $files = @(Get-ChildItem -LiteralPath $stage -File | ForEach-Object { $_.FullName })
        $r = Invoke-Guest (@('copyto', '--target-directory', 'C:\cr\m1bel\') + $files)
        if ($r.code -ne 0) { throw "copy to the guest failed: $($r.out -join ' ')" }
        $lines = @("`$ErrorActionPreference = 'Continue'", "'admin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            "& tar.exe -xzf C:\cr\m1bel\mirror.tgz -C C:\; 'untar=' + `$LASTEXITCODE", "`$env:RUST_BACKTRACE = '1'")
        foreach ($row in @($rows | Where-Object { $_.guest_exe })) {
            $t = @($targets | Where-Object { "$($_.crate)" -eq $row.crate -and "$($_.test)" -eq $row.test })[0]
            $envSet = ''; $envClr = ''
            if ($t.PSObject.Properties['env'] -and $t.env) { foreach ($p in $t.env.PSObject.Properties) { $envSet += "`$env:$($p.Name) = '$($p.Value)'; "; $envClr += "Remove-Item Env:\$($p.Name) -ErrorAction SilentlyContinue; " } }
            $argText = (@($row.args) | ForEach-Object { "'$_'" }) -join ' '
            $tag = "$($row.crate)/$($row.test)"
            $lines += "Push-Location '$($row.workdir)'; $envSet`$o = & '$($row.guest_exe)' $argText 2>&1; `$x = `$LASTEXITCODE; $envClr Pop-Location"
            $lines += "`$o | ForEach-Object { 'out|$tag|' + `$_ }"
            $lines += "'RIGTEST|$tag|' + `$x"
        }
        $j = Invoke-GuestJob -Text ($lines -join "`r`n") -Name "$run-tests" -TimeoutSec 3600 -LogCopy (Join-Path $dst 'job-tests.log')
        if (-not $j.done) { throw 'the test job did not finish within 3600 s' }
        $log = @("$($j.log)" -split "`r?`n")
        $doc.admin = [bool](@($log | Where-Object { $_ -match '^admin=True' }).Count)
        foreach ($row in $rows) {
            $tag = "$($row.crate)/$($row.test)"
            $m = @($log | Where-Object { $_ -like "RIGTEST|$tag|*" }) | Select-Object -Last 1
            if (-not $m) { if (-not $row.error) { $row.error = 'no result line in the job log' }; continue }
            $row.exit = [int](($m -split '\|')[2])
            $out = @($log | Where-Object { $_ -like "out|$tag|*" } | ForEach-Object { $_.Substring("out|$tag|".Length) })
            $row.tests = @(ConvertFrom-XLibtest $out)
            $row.output_tail = @($out | Select-Object -Last 40)
        }
    } catch {
        $doc.error = $_.Exception.Message
        Write-RigLog "!! elevated tests: $($doc.error)"
    } finally {
        $doc.targets = @($rows | ForEach-Object { [pscustomobject]$_ })
        $doc.end = (Get-Date).ToString('o')
        $doc.pass = (-not $doc.error -and $doc.admin -and $rows.Count -gt 0 -and -not @($rows | Where-Object { $_.exit -ne 0 -or -not @($_.tests).Count -or @($_.tests | Where-Object { $_.result -ne 'ok' }).Count }).Count)
        [IO.File]::WriteAllText((Join-Path $dst 'elevated-tests.json'), (ConvertTo-Json -InputObject $doc -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
        Write-RigLog "elevated tests $run`: pass=$($doc.pass)$(if ($doc.error) { ' - ' + $doc.error })"
        Stop-XVm $X.snapshot
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        Remove-PwTemp
        $script:RigLogFile = $null
    }
    [pscustomobject]$doc
}

if ($X.mode -eq 'm1b-x-ambient') {
    try { $null = Invoke-XBuildAmbient } catch { Write-Host "m1b-x-ambient: $($_.Exception.Message)"; exit 1 }
    exit 0
}
Assert-RigVm
if ($X.mode -eq 'm1b-x-null') {
    try { Invoke-XNullCampaign } catch { Write-Host "m1b-x-null: $($_.Exception.Message)"; exit 1 }
    exit 0
}
if ($X.mode -eq 'm1b-x-elevated') {
    $d = Invoke-XElevated
    if (-not $d.pass) { exit 1 }
    exit 0
}
$rec = Invoke-XGuestMode
if (-not $rec -or -not $rec.ok) { exit 1 }
exit 0
