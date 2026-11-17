<#
  Purge rig, M1b executor modes (docs\M1B_DESIGN.json M1B-RIG-EXEC; gates G5 and G6, criteria K10-K13).
  Host driver, Windows PowerShell 5.1; dot-sources rig.ps1 for the VM helpers and leaves it unchanged.

    $env:VMPWFILE = 'C:\path\to\pw.txt'
    .\vm\rig-m1b-exec.ps1 -Mode m1b-x-selftest                       # host only, no VM
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
    m1b-x-selftest    no VM: exec_sh_fails_on_missing_input, exec_cases_json_lists_every_fault_point_per_kind,
                      crash_script_reports_unreached_point_as_failure (and positive controls). Exit 1 on a failure.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('m1b-x-fidelity', 'm1b-x-traps', 'm1b-x-undo-traps', 'm1b-x-crash', 'm1b-x-elevated', 'm1b-x-selftest')]
    [string] $Mode,
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
    batch = $BatchSize; settle_max = $SettleMax; settle_min_uptime = $SettleMinUptime; target = $CargoTargetDir }
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
            if ($Hit) { $r.recover_exit = 0; $r.recover2_exit = 0; $r.recover_idempotent = $true; $r.after_exit = 0; $r.execdiff_ok = $true; $r.undo_exit = 0; $r.fidelity_ok = $true; $r.object_restored = $true }
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
        # The real plan: every kind, every reachable point; svcrestore / fwrestore only for their kind.
        $full = @(Get-XCrashPlan $cases)
        $svcOnly = @($full | Where-Object { $_.point -eq 'svcrestore.mid' } | ForEach-Object { $_.kind } | Select-Object -Unique)
        $fwOnly = @($full | Where-Object { $_.point -eq 'fwrestore.mid' } | ForEach-Object { $_.kind } | Select-Object -Unique)
        & $add 'crash_plan_covers_kinds' ($full.Count -ge 60 -and ($svcOnly -join ',') -eq 'service' -and ($fwOnly -join ',') -eq 'firewall') "rounds $($full.Count)"
        $po = @(Get-XPoweroffPlan $cases 'm1b-x-crash')
        $po2 = @(Get-XPoweroffPlan $cases 'm1b-x-crash')
        $firsts = @($CrashKinds | ForEach-Object { $k = $_; @($po | Where-Object { $_.kind -eq $k })[0].point })
        & $add 'poweroff_plan_is_15_seeded_rounds' ($po.Count -eq 15 -and (($po | ForEach-Object { "$($_.kind)/$($_.point)" }) -join ',') -eq (($po2 | ForEach-Object { "$($_.kind)/$($_.point)" }) -join ',') -and -not @($firsts | Where-Object { $_ -ne 'objdelete.after' }).Count) "rounds $($po.Count)"
    } catch { & $add 'crash_script_reports_unreached_point_as_failure' $false $_.Exception.Message }

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

function Invoke-XGuestMode {
    $run = Get-XRunName $X.mode
    $eng = Get-M2Engine -Engine $X.engine
    $casesB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($XCasesFile))
    $opts = [ordered]@{ mode = $X.mode; snapshot = $X.snapshot; cases_b64 = $casesB64 }
    $tpl = 'm1b-exec.ps1'; $to = 7200
    if ($X.mode -eq 'm1b-x-crash') {
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
    Write-RigLog "M1b $($X.mode) as run $run from $($X.snapshot) on $script:VmName; engine $eng$(if ($X.hard) { '; hard power-off' })$(if ($X.kinds.Count) { '; kinds ' + ($X.kinds -join ',') })$(if ($X.points.Count) { '; points ' + ($X.points -join ',') })"
    $rec = $null
    try {
        $null = Get-PwFile
        $rec = Invoke-SnapshotJob -Run $run -Mode $X.mode -Opts $opts -Template $tpl -Snapshot $X.snapshot -Engine $eng -HardPowerOff:$X.hard -TimeoutSec $to
        [IO.File]::WriteAllText((Join-Path $script:RunsDir "m1b-$run-$stamp.json"), (ConvertTo-Json -InputObject $rec -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    } finally {
        Stop-XVm $X.snapshot
        Remove-PwTemp
        $script:RigLogFile = $null
    }
    $rec
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
        method = 'host cargo test --release --no-run; binaries and package mirrors copied to the guest; run by the elevated agent'; admin = $false; targets = @(); error = $null; pass = $false }
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

Assert-RigVm
if ($X.mode -eq 'm1b-x-elevated') {
    $d = Invoke-XElevated
    if (-not $d.pass) { exit 1 }
    exit 0
}
$rec = Invoke-XGuestMode
if (-not $rec -or -not $rec.ok) { exit 1 }
exit 0
