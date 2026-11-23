<#
  Scorer of m3-e2e (vm\RIG.md section 17; docs\M3_DESIGN.md 11.2, gate G6, G7, G12; docs\M3_FINISH_PLAN.md B7).
  Windows PowerShell 5.1 or pwsh 7. Reads the evidence directory vm\rig-m3.ps1 -Mode m3-e2e wrote and
  vm\truth\m3-e2e-expect.json.

    powershell -NoProfile -File vm\truth\m3-e2e-score.ps1 -Evidence E:\purge-build\gate-evidence\m3-e2e\<run> -Collect
    powershell -NoProfile -File vm\truth\m3-e2e-score.ps1 -Evidence <dir>            (evaluate only: no rigtool, no cargo)
    powershell -NoProfile -File vm\truth\m3-e2e-score.ps1 --self-test                (or -SelfTest)

  -Collect (host, once per run) first turns the raw evidence into the scored inputs, with the repo's tools:
    * per executing app, <evidence>\runs\<app>\ from <app>\guest\run (snap / lists 0, 1, 2, run.json, the rig CLI plan),
      `rigtool truth` with truth\labels\<label>.json + _m3-e2e.json (+ _os-servicing.json, _m1b-noise.json as M1b),
      plans\purge.json (the CLI plan with the sidecar's actions, as m1a.sh) and plans\ui.json (the executed set: every
      item of the session's report, preselected), then one `rigtool score --set ... --classes` -> score-rigtool.json:
      `danger` is the M1a / M1b scorer's number for the executed set (tool ui) and for the CLI plan (tool purge);
    * per app, `cargo xtask broker-timings <app>\guest\timings.jsonl --out <app>\timings.json` (G12).
    -RigTool <exe> (default vm\rigtool\target\release\rigtool.exe or $env:RIG_RIGTOOL), -Xtask <exe> (a built xtask;
    default `cargo xtask` from the repo root).

  Fail-closed: every row needs its evidence; a missing file, step, record or field is a FAIL of that row, never a pass.
  The ambient set (vm\RIG.md section 17.1): -AmbientFile, default the committed set of the run's VM (summary.json vm:
  Inbound truth\m3-e2e-ambient.json, Purge-CleanPro truth\m3-e2e-ambient-cleanpro.json). Rows: the set itself (schema
  purge.rig.m2ambient/1, at least $E2eMinNullRuns distinct null runs, each id <prefix><k>-m3-e2e-<executing app>, no
  fixture name in any record or pattern), its provenance (the null runs' VM and snapshot == summary.json's, and the
  engine / broker / UI SHA-256 == summary.json binaries when recorded) and, per executing app, host.json ambient.sha256
  == e2e.json ambient declared.sha256 == guest_sha256 == the set's SHA-256 (the gate's execdiff used that very file,
  not the M2 set) and execdiff.json inputs.ambient set. score-m3-e2e.json records the ambient file and its SHA-256.
  -Apps scores a subset and -AmbientFile naming another file than the VM's committed set scores against it; either way
  the result says "not a gate score". Prints one line per row, writes <evidence>\score-m3-e2e.json, exits 0 (PASS,
  gate), 1 (FAIL), 2 (usage) or 3 (every row passes, but -Apps or -AmbientFile made it not a gate score).
  The self-test builds a passing synthetic evidence directory from the expectations, checks it passes, then checks
  that each of a list of single defects (and an empty or missing directory) fails.
#>
[CmdletBinding()]
param(
    [string] $Evidence = '',
    [string] $ExpectFile = '',
    [switch] $Collect,
    [switch] $SelfTest,
    [string[]] $Apps = @(),
    [string] $RigTool = '',
    [string] $Xtask = '',
    [string] $AmbientFile = '',
    [Parameter(ValueFromRemainingArguments = $true)] $Rest
)
$ErrorActionPreference = 'Stop'
if (@($Rest) -contains '--self-test') { $SelfTest = $true }
if (-not $ExpectFile) { $ExpectFile = Join-Path $PSScriptRoot 'm3-e2e-expect.json' }
$VmDir = Split-Path -Parent $PSScriptRoot
$RepoRoot = Split-Path -Parent $VmDir

# ------------------------------------------------------------------------------------------------ helpers

function Read-J([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
}
function Write-J($Object, [string]$Path) { [IO.File]::WriteAllText($Path, (ConvertTo-Json $Object -Depth 30), (New-Object Text.UTF8Encoding($false))) }
function Has($O, [string]$Name) { $null -ne $O -and $null -ne $O.PSObject.Properties[$Name] -and $null -ne $O.$Name }
function Arr($X) { @(@($X) | Where-Object { $null -ne $_ }) }
function Num($V) { if ($null -eq $V -or "$V" -eq '') { $null } else { [double]$V } }

$script:Rows = New-Object System.Collections.ArrayList
function Row([string]$Name, $Ok, [string]$Detail = '') {
    [void]$script:Rows.Add([ordered]@{ row = $Name; ok = ($Ok -eq $true); detail = $Detail })
}

# The screenshot names an app's flow takes (vm\rig-m3.ps1 Get-M3E2eShotNames, kept equal by the rig self-test).
function Get-E2eShotNames($AppDef, [bool]$Undo) {
    $n = @('01-programs-row', '02-uninstall-clicked', '03-confirm')
    if ("$($AppDef.route)" -eq 'broker') { $n += '04-consent-run', '05-run-approved' }
    $n += '06-scan-done'
    if ("$($AppDef.kind)" -like 'fail-*') { return @($n + '07-failure') }
    $n += '07-move-waiting', '08-consent-plan', '09-result'
    if ($Undo) { $n += '10-undo-waiting', '11-consent-undo', '12-undone' }
    $n
}

# The m3-e2e ambient set (RIG.md section 17.1). Same fixture expression as vm\rig-m3.ps1 $M3E2eFixtureRx, same minimum
# as $M3E2eMinNullRuns; a null run id is <prefix><k>-m3-e2e-<app> (rig-m3.ps1 Get-M3E2eNullRunName).
$E2eFixtureRx = '(?i)purgeexec|programdata\\+purge|purgee2emsi|\.purge(\\)?-q'
$E2eMinNullRuns = 6
$E2eNullRunRx = '\A[a-z0-9][a-z0-9_.-]*[0-9]-m3-e2e-([a-z0-9][a-z0-9-]*)\z'

# The committed set of the run's VM (summary.json vm) in $TruthDir (default vm\truth), or $null for a VM that has none.
function Get-E2eAmbientPath($Sum, [string]$TruthDir = $PSScriptRoot) {
    $vm = $(if ($Sum -and (Has $Sum 'vm')) { "$($Sum.vm)" } else { 'Inbound-Win11-Test' })
    $leaf = switch -CaseSensitive ($vm) { 'Inbound-Win11-Test' { 'm3-e2e-ambient.json' } 'Purge-CleanPro' { 'm3-e2e-ambient-cleanpro.json' } default { $null } }
    if ($leaf) { Join-Path $TruthDir $leaf } else { $null }
}

# Why the set's provenance (rig-m3.ps1 Invoke-M3E2eBuildAmbient) does not match the gate run's summary.json: the VM and
# the snapshot always, the binaries' SHA-256 when summary.json records them (binaries). None: it matches.
function Test-E2eAmbientProvenance($Set, $Sum) {
    if (-not $Set) { return @() }
    $p = $(if (Has $Set 'provenance') { $Set.provenance } else { $null })
    if (-not $p) { return @('the set records no provenance') }
    if (-not $Sum) { return @('no summary.json to compare the provenance with') }
    $why = @()
    foreach ($f in 'vm', 'snapshot') {
        if (-not (Has $p $f) -or -not (Has $Sum $f) -or "$($p.$f)" -cne "$($Sum.$f)") { $why += "$f '$(if (Has $p $f) { $p.$f })', the run's '$(if (Has $Sum $f) { $Sum.$f })'" }
    }
    if (Has $Sum 'binaries') {
        foreach ($f in 'engine_sha256', 'broker_sha256', 'ui_sha256') {
            $have = $(if (Has $p $f) { "$($p.$f)" } else { '' }); $want = $(if (Has $Sum.binaries $f) { "$($Sum.binaries.$f)" } else { '' })
            if (-not $want -or $have -cne $want) { $why += "$f $(if ($have) { $have.Substring(0, [Math]::Min(12, $have.Length)) } else { 'none' }), the run's $(if ($want) { $want.Substring(0, [Math]::Min(12, $want.Length)) } else { 'none' })" }
        }
    }
    $why
}

# Why the parsed set $Set is not an m3-e2e ambient set built from null runs; none: it is.
function Test-E2eAmbientSet($Set, $X) {
    if (-not $Set) { return @('missing or unreadable') }
    $why = @()
    if ("$($Set.schema)" -cne 'purge.rig.m2ambient/1') { $why += "schema '$($Set.schema)'" }
    $exec = @(Arr $X.apps | Where-Object { "$($_.kind)" -in 'app', 'fixture' } | ForEach-Object { "$($_.id)" })
    $ids = @(Arr $Set.runs | ForEach-Object { "$($_.id)" })
    $badIds = @($ids | Where-Object { $m = [regex]::Match($_, $E2eNullRunRx); -not $m.Success -or $exec -cnotcontains $m.Groups[1].Value })
    if ($badIds.Count) { $why += "run ids not of a null run: $($badIds -join ', ')" }
    $distinct = @($ids | Select-Object -Unique).Count
    if ($distinct -lt $E2eMinNullRuns) { $why += "$distinct distinct null run(s), want at least $E2eMinNullRuns" }
    $all = @(@(Arr $Set.records) + @(Arr $Set.patterns))
    foreach ($r in Arr $Set.runs) { $all += @(Arr $r.records) + @(Arr $r.patterns) }
    $hits = @($all | Where-Object { "$_" -match $E2eFixtureRx } | ForEach-Object { "$_" } | Select-Object -Unique)
    if ($hits.Count) { $why += "names fixtures: $(@($hits | Select-Object -First 3) -join ' | ')" }
    $why
}

function Get-Step($E2e, [string]$Name) { if ($E2e -and (Has $E2e 'steps') -and $E2e.steps.PSObject.Properties[$Name]) { $E2e.steps.$Name } else { $null } }
function Get-Seen($E2e) { @(Arr (Get-Step $E2e 'ui-wait-scan').seen | ForEach-Object { "$_" }) }

# The rigtool score record of (app, tool), or $null.
function Get-ScoreTool($Score, [string]$App, [string]$Tool) {
    if (-not $Score) { return $null }
    $a = @(Arr $Score.apps | Where-Object { "$($_.id)" -eq $App }) | Select-Object -First 1
    if (-not $a) { return $null }
    @(Arr $a.tools | Where-Object { "$($_.tool)" -eq $Tool }) | Select-Object -First 1
}

# ------------------------------------------------------------------------------------------------ collect

# Pure: plans\purge.json from the CLI plan and its sidecar (each item gets its sidecar action, as m1a.sh step 3) and
# plans\ui.json from the executed items (purge.plan/0, every item Safe and preselected, the CLI's action for the same
# target where the CLI offered it). $KeyOf maps a target to its comparable key.
function New-E2ePlans($Plan, $Sidecar, $Executed, [scriptblock]$KeyOf, [string]$App) {
    $pi = @(Arr $Plan.items); $si = @(Arr $Sidecar.items)
    $action = @{}
    for ($i = 0; $i -lt [Math]::Min($pi.Count, $si.Count); $i++) {
        $act = $si[$i].action
        if ($act -and -not ($act -is [string])) { $act = "$(@($act.PSObject.Properties)[0].Name)" }
        $k = & $KeyOf $si[$i].target
        if ($k) { $action[$k] = $act }
        $pi[$i] | Add-Member -NotePropertyName action -NotePropertyValue $act -Force
    }
    $purge = [ordered]@{ schema = 'purge.plan/0'; app = $App; tool = 'purge'; mode = "$($Plan.mode)"; items = $pi }
    $ui = [ordered]@{ schema = 'purge.plan/0'; app = $App; tool = 'ui'; mode = "$($Plan.mode)"
                      items = @(Arr $Executed.items | ForEach-Object { [ordered]@{ target = $_.target; band = 'Safe'; preselected = $true; scanner = 'executed'; category = 'executed'; action = $action["$($_.key)"] } }) }
    @($purge, $ui)
}

# The target key of the guest (Get-E2eTargetKey), from the guest library itself.
. (Join-Path $VmDir 'guest\m3-e2e-ui.ps1')

function Invoke-Collect([string]$Ev, $X) {
    $rt = $RigTool
    if (-not $rt) { $rt = $(if ($env:RIG_RIGTOOL) { $env:RIG_RIGTOOL } else { Join-Path $VmDir 'rigtool\target\release\rigtool.exe' }) }
    if (-not (Test-Path -LiteralPath $rt -PathType Leaf)) { throw "rigtool not found: $rt (cargo build --release in vm\rigtool, or -RigTool)" }
    $truth = $PSScriptRoot
    $extra = @('_m3-e2e.json', '_os-servicing.json', '_m1b-noise.json' | ForEach-Object { Join-Path $truth "labels\$_" } | Where-Object { Test-Path -LiteralPath $_ })
    $runs = Join-Path $Ev 'runs'
    New-Item -ItemType Directory -Force $runs | Out-Null
    $dirs = @()
    foreach ($a in Arr $X.apps) {
        $id = "$($a.id)"
        $g = Join-Path $Ev "$id\guest"
        # Timings (G12), every app with a timing file.
        $tj = Join-Path $g 'timings.jsonl'
        if ((Test-Path -LiteralPath $tj) -and (Get-Item -LiteralPath $tj).Length -gt 0) {
            $out = Join-Path $Ev "$id\timings.json"
            if ($Xtask) { & $Xtask broker-timings $tj --out $out } else { Push-Location $RepoRoot; try { & cargo xtask broker-timings $tj --out $out } finally { Pop-Location } }
            Write-Host "collect $id`: broker-timings exit $LASTEXITCODE"
        } else { Write-Host "collect $id`: no timing lines" }
        if ("$($a.kind)" -notin 'app', 'fixture') { continue }
        $src = Join-Path $g 'run'
        if (-not (Test-Path -LiteralPath (Join-Path $src 'run.json'))) { Write-Host "collect $id`: no run directory"; continue }
        $d = Join-Path $runs $id
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
        Copy-Item -LiteralPath $src -Destination $d -Recurse
        $snap = { param($n) @(Get-ChildItem -LiteralPath $d -Filter "snap-*-$n.tsv.gz" | Select-Object -First 1)[0].FullName }
        $list = { param($n) @(Get-ChildItem -LiteralPath $d -Filter "lists-*-$n.json" | Select-Object -First 1)[0].FullName }
        $targs = @('truth', '--s0', (& $snap 0), '--s1', (& $snap 1), '--s2', (& $snap 2), '--lists0', (& $list 0), '--lists2', (& $list 2),
                   '--run', (Join-Path $d 'run.json'), '--ambient', (Join-Path $truth 'ambient.json'), '--labels', (Join-Path $truth "labels\$($a.label).json"))
        foreach ($e in $extra) { $targs += '--labels', $e }
        $targs += '--deny', (Join-Path $truth 'deny.json'), '-o', (Join-Path $d 'truth.json')
        & $rt @targs
        if ($LASTEXITCODE -ne 0) { Write-Host "collect $id`: rigtool truth exited $LASTEXITCODE"; continue }
        $plan = Read-J (Join-Path $d 'plan-purge.json'); $side = Read-J (Join-Path $d 'plan-purge.scan.json'); $exe = Read-J (Join-Path $d 'executed.json')
        New-Item -ItemType Directory -Force (Join-Path $d 'plans') | Out-Null
        if ($plan -and $side) {
            $p = New-E2ePlans $plan $side $(if ($exe) { $exe } else { [pscustomobject]@{ items = @() } }) { param($t) Get-E2eTargetKey $t } $id
            Write-J $p[0] (Join-Path $d 'plans\purge.json')
            if ($exe) { Write-J $p[1] (Join-Path $d 'plans\ui.json') }
        }
        $dirs += $d
    }
    if ($dirs.Count) {
        & $rt score --set @dirs --deny (Join-Path $truth 'deny.json') --classes --json (Join-Path $Ev 'score-rigtool.json') --md (Join-Path $Ev 'score-rigtool.md')
        Write-Host "collect: rigtool score over $($dirs.Count) run(s), exit $LASTEXITCODE"
    }
}

# ----------------------------------------------------------------------------------------------- evaluate

function Test-Shots([string]$AppDir, $Host_, [string[]]$Names) {
    $have = @(Arr $Host_.shots | Where-Object { $_.file -and [int64]$_.bytes -gt 0 -and (Test-Path -LiteralPath (Join-Path $AppDir $_.file) -PathType Leaf) } | ForEach-Object { "$($_.name)" })
    @($Names | Where-Object { $have -notcontains $_ })
}

# G12 rows from <app>\timings.json (purge.broker-timings/1): the broker's cold scan (duration, first progress) and,
# for the harvest apps, harvest complete after the UAC click.
function Test-Timings([string]$Id, $T, $X, [bool]$Scan, [bool]$Harvest) {
    $b = @(Arr $T.brokers)
    if ($Scan) {
        $s = @($b | ForEach-Object { Arr $_.scans } | Where-Object { $_.cold -eq $true }) | Select-Object -First 1
        $dur = $(if ($s) { Num $s.duration_ms }); $fp = $(if ($s) { Num $s.first_progress_ms })
        Row "$Id G12 scan, cold broker <= $($X.gates.scan_ms) ms" ($null -ne $dur -and $dur -le [double]$X.gates.scan_ms) $(if ($null -eq $dur) { 'no cold scan timing' } else { "$dur ms" })
        Row "$Id G12 first progress <= $($X.gates.first_progress_ms) ms" ($null -ne $fp -and $fp -le [double]$X.gates.first_progress_ms) $(if ($null -eq $fp) { 'no first_progress timing' } else { "$fp ms" })
    }
    if ($Harvest) {
        $h = @($b | ForEach-Object { Arr $_.harvests }) | Select-Object -First 1
        $ms = $(if ($h) { Num $h.after_uac_ms })
        Row "$Id G12 harvest after UAC <= $($X.gates.harvest_after_uac_ms) ms" ($null -ne $ms -and $ms -le [double]$X.gates.harvest_after_uac_ms) $(if ($null -eq $ms) { 'no harvest timing' } else { "$ms ms" })
    }
}

function Test-App([string]$Ev, $A, $X, $Score, [bool]$Undo, [string]$AmbSha = '') {
    $id = "$($A.id)"
    $dir = Join-Path $Ev $id
    $e2e = Read-J (Join-Path $dir 'guest\e2e.json')
    $host_ = Read-J (Join-Path $dir 'host.json')
    Row "$id evidence (guest\e2e.json, host.json)" ($null -ne $e2e -and $null -ne $host_ -and $host_.pulled -eq $true) $(if (-not $e2e) { 'no e2e.json' } elseif (-not $host_) { 'no host.json' } elseif ($host_.pulled -ne $true) { 'guest outputs not pulled' })
    if (-not $e2e) { return }
    $miss = Test-Shots $dir $host_ (Get-E2eShotNames $A $Undo)
    Row "$id screenshots per step" ($miss.Count -eq 0) $(if ($miss.Count) { "missing: $($miss -join ', ')" })
    $start = Get-Step $e2e 'ui-start'; $un = Get-Step $e2e 'ui-uninstall'; $conf = Get-Step $e2e 'ui-confirm'; $scan = Get-Step $e2e 'ui-wait-scan'
    $why = @()
    if (-not ($start -and $start.ok -eq $true)) { $why += 'program row not selected' }
    if (-not ($un -and $un.ok -eq $true)) { $why += "Uninstall: $(if ($un) { $un.state } else { 'no step' })" }
    if (-not ($conf -and $conf.ok -eq $true)) { $why += 'confirm dialog not answered' }
    if ("$($A.route)" -eq 'broker') {
        $ar = Get-Step $e2e 'consent-approve-run'
        if (-not ($ar -and $ar.ok -eq $true)) { $why += 'uninstall consent not approved' }
    }
    Row "$id UI: row, Uninstall, confirm$(if ("$($A.route)" -eq 'broker') { ', consent' })" ($why.Count -eq 0) ($why -join '; ')
    # The UAC click: with prompts on (5) the host answered the secure desktop by scancode, with a screenshot of the
    # prompt; UAC-silent (0) no prompt came up.
    $keys = @(Arr $(if ($host_ -and $host_.uac_keys) { $host_.uac_keys.run }))
    $uacV = "$($e2e.uac.ConsentPromptBehaviorAdmin)"
    if ($uacV -eq '5') {
        $shot = @(Test-Shots $dir $host_ @('02u-uac-1-prompt')).Count -eq 0
        Row "$id UAC Yes by scancode (secure desktop)" ($keys.Count -gt 0 -and $keys[0] -eq 'alt-y' -and $shot) "keys $($keys -join ','); prompt shot $shot"
    } else {
        Row "$id UAC silent: no prompt" ($uacV -eq '0' -and $keys.Count -eq 0) "ConsentPromptBehaviorAdmin $uacV, keys $($keys -join ',')"
    }
    Row "$id route $($A.route)" ($conf -and "$($conf.route)" -eq "$($A.route)") "$(if ($conf) { $conf.route })"
    $seen = Get-Seen $e2e
    $codes = @(Arr $scan.exit_codes | ForEach-Object { [int64]$_ })
    $fc = Get-Step $e2e 'fail-check'
    switch ("$($A.kind)") {
        'fail-1603' {
            $shown = ($seen -contains "$($X.texts.failed_bar)") -and ($codes -contains 1603)
            Row "$id 1603 reported as a failure" $shown "bar=$($seen -contains "$($X.texts.failed_bar)") codes=$($codes -join ',')"
            $notOk = ($scan -and "$($scan.state)" -eq 'failed' -and -not (Get-Step $e2e 'ui-move') -and -not (Get-Step $e2e 'ui-wait-result'))
            Row "$id not shown as success (no review, no move, no result)" $notOk "scan state $(if ($scan) { $scan.state })"
            $nothing = ($fc -and @(Arr $fc.sessions_new).Count -eq 0 -and (Has $fc 'quarantine_after') -and [int]$fc.quarantine_after -eq [int]$fc.quarantine_before -and $fc.arp_present -eq $true -and $fc.fixture_key_present -eq $true)
            Row "$id nothing purged, the product still installed" $nothing $(if ($fc) { "sessions_new=$(@(Arr $fc.sessions_new).Count) quarantine=$($fc.quarantine_before)->$($fc.quarantine_after) arp=$($fc.arp_present) key=$($fc.fixture_key_present)" } else { 'no fail-check' })
            return
        }
        'fail-3010' {
            $shown = ($seen -contains "$($X.texts.restart_bar)") -and ($codes -contains 3010) -and -not ($seen -contains "$($X.texts.failed_bar)")
            Row "$id 3010 reported as restart needed" $shown "restart_bar=$($seen -contains "$($X.texts.restart_bar)") failed_bar=$($seen -contains "$($X.texts.failed_bar)") codes=$($codes -join ',')"
            $gone = ($scan -and "$($scan.state)" -in 'review', 'empty' -and $fc -and $fc.arp_present -eq $false -and $fc.fixture_key_present -eq $false)
            Row "$id uninstall done, scan reached" $gone $(if ($fc) { "scan=$($scan.state) arp=$($fc.arp_present) key=$($fc.fixture_key_present)" } else { 'no fail-check' })
            Row "$id nothing executed" ($fc -and @(Arr $fc.sessions_new).Count -eq 0 -and -not (Get-Step $e2e 'ui-move')) $(if ($fc) { "sessions_new=$(@(Arr $fc.sessions_new).Count)" })
            Test-Timings $id (Read-J (Join-Path $dir 'timings.json')) $X $true $false
            return
        }
    }
    # Executing apps (kind app, fixture).
    if ("$($A.route)" -eq 'medium') {
        $u = @(Arr $scan.uninstallers)
        # (A process gone before its integrity was read records "unknown(...)": neither proof nor a fault.)
        $med = @($u | Where-Object { "$($_.il)" -eq 'medium' })
        $bad = @($u | Where-Object { "$($_.il)" -in 'high', 'system' })
        Row "$id G7 the per-user uninstaller ran at medium integrity" ($med.Count -gt 0 -and $bad.Count -eq 0) "$(@($u | ForEach-Object { "$($_.name):$($_.il)" }) -join ', ')"
    }
    $post = Get-Step $e2e 'capture-post'; $move = Get-Step $e2e 'ui-move'; $ap = Get-Step $e2e 'consent-approve-plan'; $res = Get-Step $e2e 'ui-wait-result'; $cx = Get-Step $e2e 'capture-exec'
    $why = @()
    if (-not ($scan -and "$($scan.state)" -eq 'review')) { $why += "scan ended '$(if ($scan) { $scan.state })'" }
    if (-not ($post -and $post.ok -eq $true)) { $why += 'no CLI plan / snap A' }
    if (-not ($move -and $move.ok -eq $true)) { $why += "Move: $(if ($move) { $move.state } else { 'no step' })" }
    if (-not ($ap -and $ap.ok -eq $true)) { $why += 'plan consent not approved' }
    if (-not ($res -and "$($res.state)" -eq 'result' -and "$($res.title)" -match '^Moved ')) { $why += "result: $(if ($res) { "$($res.state) '$($res.title)'" } else { 'no step' })" }
    Row "$id UI: review, Move, consent, result" ($why.Count -eq 0) ($why -join '; ')
    $cmp = $(if ($cx) { $cx.compare })
    $eq = ($cmp -and $cmp.equal -eq $true -and [int]$cmp.cli_n -eq [int]$cmp.ui_n -and [int]$cmp.ui_n -gt 0)
    Row "$id executed set == preselected set of the rig CLI plan" $eq $(if ($cmp) { "cli $($cmp.cli_n), ui $($cmp.ui_n), missing $(@(Arr $cmp.missing).Count), extra $(@(Arr $cmp.extra).Count)$(if (@(Arr $cmp.missing).Count) { ': ' + ((Arr $cmp.missing | Select-Object -First 3) -join '; ') })$(if (@(Arr $cmp.extra).Count) { ' extra: ' + ((Arr $cmp.extra | Select-Object -First 3) -join '; ') })" } else { 'no comparison' })
    Row "$id session committed" ($cx -and "$($cx.report_state)" -eq 'Committed') "$(if ($cx) { $cx.report_state })"
    $ui = Get-ScoreTool $Score $id 'ui'; $cli = Get-ScoreTool $Score $id 'purge'
    $dOk = ($ui -and $cli -and [int]$ui.danger_offered -eq 0 -and [int]$ui.danger_preselected -eq 0 -and [int]$cli.danger_blocking -eq 0)
    Row "$id danger 0 (executed set; CLI plan blocking)" $dOk $(if ($ui -and $cli) { "ui danger $($ui.danger_offered) (preselected $($ui.danger_preselected)), cli danger_blocking $($cli.danger_blocking)" } else { 'no rigtool score (run -Collect)' })
    $ed = Read-J (Join-Path $dir 'guest\execdiff.json')
    $col = $(if ($ed -and $ed.counts) { $ed.counts })
    Row "$id collateral 0" ($col -and (Has $col 'collateral') -and [int]$col.collateral -eq 0 -and [int]$col.guard_escapes -eq 0) $(if ($col) { "collateral $($col.collateral), guard_escapes $($col.guard_escapes), unexplained $($col.unexplained), missing_effects $($col.missing_effects)" } else { 'no execdiff.json' })
    # execdiff ran with --ambient (inputs.ambient): without it every Windows record of the window would be judged alone.
    $edAmb = $(if ($ed -and (Has $ed 'inputs') -and (Has $ed.inputs 'ambient')) { "$($ed.inputs.ambient)" } else { '' })
    Row "$id execdiff --ambient given (inputs.ambient)" ([bool]$edAmb) $(if ($edAmb) { $edAmb } else { 'execdiff.json inputs.ambient is null' })
    # The ambient set that execdiff used: the host pushed the committed m3-e2e set and the guest copy is that file.
    $hs = $(if ($host_ -and (Has $host_ 'ambient')) { "$($host_.ambient.sha256)" } else { '' })
    $ga = $(if (Has $e2e 'ambient') { $e2e.ambient } else { $null })
    $ds = $(if ($ga -and (Has $ga 'declared')) { "$($ga.declared.sha256)" } else { '' })
    $gs = $(if ($ga) { "$($ga.guest_sha256)" } else { '' })
    $aOk = [bool]($AmbSha -and $hs -ceq $AmbSha -and $ds -ceq $AmbSha -and $gs -ceq $AmbSha)
    $short = { param($s) if ($s) { "$s".Substring(0, [Math]::Min(12, "$s".Length)) } else { 'none' } }
    Row "$id ambient set pushed (host == guest == committed m3-e2e set)" $aOk "committed $(& $short $AmbSha), host $(& $short $hs), declared $(& $short $ds), guest $(& $short $gs)"
    Test-Timings $id (Read-J (Join-Path $dir 'timings.json')) $X $true (@(Arr $X.gates.harvest_apps) -contains $id)
    if ($Undo) {
        $uu = Get-Step $e2e 'ui-undo'; $ua = Get-Step $e2e 'consent-approve-undo'; $ud = Get-Step $e2e 'ui-wait-undone'
        $w = @()
        if (-not ($uu -and $uu.ok -eq $true)) { $w += 'Undo all not pressed' }
        if (-not ($ua -and $ua.ok -eq $true)) { $w += 'restore consent not approved' }
        if (-not ($ud -and "$($ud.state)" -eq 'undone' -and "$($ud.title)" -eq 'Put back')) { $w += "undone page: $(if ($ud) { "$($ud.state) '$($ud.title)'" } else { 'no step' })" }
        Row "$id undo through the UI" ($w.Count -eq 0) ($w -join '; ')
        $fd = Read-J (Join-Path $dir 'guest\fidelity.json')
        $rows = @(Arr $fd.rows)
        $failing = @($rows | Where-Object { $_.pass -ne $true })
        Row "$id undo_fidelity 100 %" ($fd -and $fd.ok -eq $true -and $rows.Count -gt 0 -and $failing.Count -eq 0) $(if ($fd) { "rows $($rows.Count), failing $($failing.Count)$(if ($failing.Count) { ': ' + (@($failing | ForEach-Object { $_.action }) -join ', ') })" } else { 'no fidelity.json' })
    }
}

function Invoke-Score([string]$Ev, $X, [string[]]$Only = @(), [switch]$Quiet, [string]$Ambient = '', [string]$TruthDir = $PSScriptRoot) {
    $script:Rows = New-Object System.Collections.ArrayList
    $sum = Read-J (Join-Path $Ev 'summary.json')
    Row 'evidence summary.json' ($null -ne $sum) $(if (-not $sum) { 'missing or unreadable' })
    # The ambient set (RIG.md section 17.1): the committed set of the run's VM; -AmbientFile naming another file scores,
    # but is not a gate score.
    $ambCommitted = Get-E2eAmbientPath $sum $TruthDir
    $ambPath = $(if ($Ambient) { $Ambient } else { $ambCommitted })
    $full = { param($p) if ($p) { try { [IO.Path]::GetFullPath($p) } catch { "$p" } } else { '' } }
    $ambIsCommitted = [bool]($ambCommitted -and (& $full $ambPath) -ieq (& $full $ambCommitted))
    $ambSha = ''
    if ($ambPath -and (Test-Path -LiteralPath $ambPath -PathType Leaf)) { $ambSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $ambPath).Hash.ToLowerInvariant() }
    $ambRec = [ordered]@{ file = $ambPath; sha256 = $(if ($ambSha) { $ambSha } else { $null }); committed = $ambIsCommitted }
    $ambSet = $(if ($ambSha) { Read-J $ambPath } else { $null })
    $ambWhy = @(Test-E2eAmbientSet $ambSet $X)
    Row "ambient set: m3-e2e null runs (schema, >= $E2eMinNullRuns null runs, no fixture names)" ($ambSha -and $ambWhy.Count -eq 0) "$ambPath$(if ($ambWhy.Count) { ': ' + ($ambWhy -join '; ') })"
    $provWhy = @(Test-E2eAmbientProvenance $ambSet $sum)
    Row 'ambient provenance == this run (vm, snapshot; binaries when recorded)' ($ambSet -and $provWhy.Count -eq 0) $(if (-not $ambSet) { 'no set' } else { $provWhy -join '; ' })
    if ($ambWhy.Count -or $provWhy.Count) { $ambSha = '' }
    $apps = @(Arr $X.apps)
    $only = @($Only | Where-Object { $_ })
    if ($only.Count) { $apps = @($apps | Where-Object { $only -contains "$($_.id)" }) }
    $undo = @(Arr $(if ($sum -and (Has $sum 'undo_apps')) { $sum.undo_apps } else { $X.undo_apps }) | ForEach-Object { "$_" })
    $score = Read-J (Join-Path $Ev 'score-rigtool.json')
    if ($sum) {
        # Design 11.2 runs m3-e2e UAC-silent (0); RIG.md 13 found rig-base at the Windows default (5), and -UacOn boots
        # m3-uac-on (5). Either way one value for the whole run; with 5 each app's prompt is answered by scancode (below).
        $uacs = @($apps | ForEach-Object { Read-J (Join-Path $Ev "$($_.id)\guest\e2e.json") } | Where-Object { $_ } | ForEach-Object { "$($_.uac.ConsentPromptBehaviorAdmin)" } | Select-Object -Unique)
        $okUac = ($uacs.Count -eq 1 -and $uacs[0] -in '0', '5' -and -not ($sum.uac_on -eq $true -and $uacs[0] -ne '5'))
        Row 'UAC recorded, one value for the run (0 silent, 5 prompt)' $okUac ($uacs -join ',')
    }
    foreach ($a in $apps) { Test-App $Ev $a $X $score ($undo -contains "$($a.id)") $ambSha }
    $undone = @($apps | Where-Object { $undo -contains "$($_.id)" } | Where-Object { $n = "$($_.id) undo_fidelity 100 %"; @($script:Rows | Where-Object { $_.row -eq $n -and $_.ok }).Count -eq 1 })
    Row 'at least one app undone through the UI with undo_fidelity 100 %' ($undone.Count -gt 0) (@($undone | ForEach-Object { $_.id }) -join ',')
    $pass = (@($script:Rows | Where-Object { -not $_.ok }).Count -eq 0) -and $script:Rows.Count -gt 0
    if (-not $Quiet) {
        foreach ($r in $script:Rows) { Write-Host ("{0} {1}{2}" -f $(if ($r.ok) { 'PASS' } else { 'FAIL' }), $r.row, $(if ($r.detail) { "  ($($r.detail))" } else { '' })) }
    }
    $gate = ($only.Count -eq 0 -and $ambIsCommitted)
    $notGate = @($(if ($only.Count) { 'a subset of the apps (-Apps)' }), $(if (-not $ambIsCommitted) { "another ambient file than the VM's committed set (-AmbientFile $ambPath)" }) | Where-Object { $_ })
    [ordered]@{ schema = 'purge.rig.m3e2e-score/1'; evidence = $Ev; pass = $pass; gate = $gate; not_gate = $notGate; ambient = $ambRec; apps = @($apps | ForEach-Object { $_.id }); rows = @($script:Rows) }
}

# ------------------------------------------------------------------------------------------------ self-test

function New-PassEvidence($X, [string]$Dir) {
    New-Item -ItemType Directory -Force $Dir | Out-Null
    $undo = @(Arr $X.undo_apps)
    $bins = [ordered]@{ engine_sha256 = ('e' * 64); broker_sha256 = ('b' * 64); ui_sha256 = ('d' * 64) }
    $sum = [ordered]@{ schema = 'purge.rig.m3e2e.summary/1'; run = 'selftest'; vm = 'Inbound-Win11-Test'; snapshot = 'rig-base'; uac_on = $false; binaries = $bins; undo_apps = $undo; apps = @() }
    $score = [ordered]@{ schema = 'purge.rig.score/1'; apps = @() }
    # A synthetic ambient set of 6 null runs, as the VM's committed set in the evidence dir (the self-test scores with
    # -TruthDir <dir>); every app records its hash.
    $amb = Join-Path $Dir 'm3-e2e-ambient.json'
    Write-J ([ordered]@{ schema = 'purge.rig.m2ambient/1'; note = 'selftest'
                         runs = @(1..6 | ForEach-Object { [ordered]@{ id = "en$_-m3-e2e-vscode"; records = @('~F:C:\WINDOWS\Prefetch\TASKLIST.EXE-2448BC7D.pf'); patterns = @() } })
                         records = @('~F:C:\WINDOWS\Prefetch\TASKLIST.EXE-2448BC7D.pf'); patterns = @()
                         provenance = [ordered]@{ campaign = 'null-selftest'; vm = 'Inbound-Win11-Test'; snapshot = 'rig-base'; engine_sha256 = $bins.engine_sha256
                                                  broker_sha256 = $bins.broker_sha256; ui_sha256 = $bins.ui_sha256; null_wait = 10 } }) $amb
    $ambSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $amb).Hash.ToLowerInvariant()
    foreach ($a in Arr $X.apps) {
        $id = "$($a.id)"; $ad = Join-Path $Dir $id; $gd = Join-Path $ad 'guest'
        New-Item -ItemType Directory -Force $gd | Out-Null
        $isUndo = ($undo -contains $id)
        $shots = @(Get-E2eShotNames $a $isUndo | ForEach-Object { [IO.File]::WriteAllBytes((Join-Path $ad "$_.png"), [byte[]](137, 80, 78, 71)); [ordered]@{ name = $_; file = "$_.png"; bytes = 4 } })
        Write-J ([ordered]@{ app = $id; pulled = $true; shots = $shots; ambient = [ordered]@{ file = $amb; sha256 = $ambSha } }) (Join-Path $ad 'host.json')
        $steps = [ordered]@{
            'ui-start' = [ordered]@{ ok = $true }; 'ui-uninstall' = [ordered]@{ ok = $true; state = 'confirm' }
            'ui-confirm' = [ordered]@{ ok = $true; route = "$($a.route)" }
        }
        if ("$($a.route)" -eq 'broker') { $steps['consent-approve-run'] = [ordered]@{ ok = $true } }
        $key = "Path|c:\program files\$id|"
        switch ("$($a.kind)") {
            'fail-1603' {
                $steps['ui-wait-scan'] = [ordered]@{ ok = $false; state = 'failed'; exit_codes = @(1603); seen = @('The uninstaller failed.', 'The uninstaller ended with exit code 1603. You can run the forced cleanup ...') }
                $steps['fail-check'] = [ordered]@{ ok = $true; arp_present = $true; fixture_key_present = $true; sessions_new = @(); quarantine_before = 3; quarantine_after = 3 }
            }
            'fail-3010' {
                $steps['ui-wait-scan'] = [ordered]@{ ok = $true; state = 'review'; exit_codes = @(3010); seen = @('A restart is needed.', 'Finished, exit code 3010, quiet mode') }
                $steps['fail-check'] = [ordered]@{ ok = $true; arp_present = $false; fixture_key_present = $false; sessions_new = @(); quarantine_before = 3; quarantine_after = 3 }
            }
            default {
                $unin = $(if ("$($a.route)" -eq 'medium') { @([ordered]@{ name = 'unins000.exe'; il = 'medium' }) } else { @([ordered]@{ name = 'unins000.exe'; il = 'high' }) })
                $steps['ui-wait-scan'] = [ordered]@{ ok = $true; state = 'review'; exit_codes = @(0); seen = @('Finished, exit code 0'); uninstallers = $unin }
                $steps['capture-post'] = [ordered]@{ ok = $true; cli = [ordered]@{ preselected_n = 2 } }
                $steps['ui-move'] = [ordered]@{ ok = $true; state = 'prompt' }
                $steps['consent-approve-plan'] = [ordered]@{ ok = $true }
                $steps['ui-wait-result'] = [ordered]@{ ok = $true; state = 'result'; title = 'Moved 2 items to quarantine' }
                $steps['capture-exec'] = [ordered]@{ ok = $true; report_state = 'Committed'; compare = [ordered]@{ equal = $true; cli_n = 2; ui_n = 2; missing = @(); extra = @() } }
                Write-J ([ordered]@{ ok = $true; counts = [ordered]@{ collateral = 0; guard_escapes = 0; unexplained = 0; missing_effects = 0 }
                                     inputs = [ordered]@{ ambient = 'C:\cr\bin\m2-ambient.json' } }) (Join-Path $gd 'execdiff.json')
                if ($isUndo) {
                    $steps['ui-undo'] = [ordered]@{ ok = $true; state = 'prompt' }
                    $steps['consent-approve-undo'] = [ordered]@{ ok = $true }
                    $steps['ui-wait-undone'] = [ordered]@{ ok = $true; state = 'undone'; title = 'Put back' }
                    Write-J ([ordered]@{ ok = $true; rows = @([ordered]@{ action = 'Quarantine'; ops = 2; differing = 0; percent = 100; pass = $true }) }) (Join-Path $gd 'fidelity.json')
                }
                $score.apps += [ordered]@{ id = $id; tools = @([ordered]@{ tool = 'ui'; danger_offered = 0; danger_preselected = 0; danger_blocking = 0 },
                                                               [ordered]@{ tool = 'purge'; danger_offered = 0; danger_preselected = 0; danger_blocking = 0 }) }
            }
        }
        if ("$($a.kind)" -ne 'fail-1603') {
            $harv = $(if (@(Arr $X.gates.harvest_apps) -contains $id) { @([ordered]@{ after_uac_ms = 2100 }) } else { @([ordered]@{ after_uac_ms = 900 }) })
            Write-J ([ordered]@{ schema = 'purge.broker-timings/1'; brokers = @([ordered]@{ harvests = $harv; scans = @([ordered]@{ cold = $true; duration_ms = 4200; first_progress_ms = 12 }) }) }) (Join-Path $ad 'timings.json')
        }
        Write-J ([ordered]@{ schema = 'purge.rig.m3e2e.app/1'; app = $id; kind = "$($a.kind)"; uac = [ordered]@{ ConsentPromptBehaviorAdmin = 0 }; steps = $steps
                             null_run = $false; ambient = [ordered]@{ declared = [ordered]@{ sha256 = $ambSha }; guest = 'C:\cr\bin\m2-ambient.json'; guest_sha256 = $ambSha } }) (Join-Path $gd 'e2e.json')
    }
    Write-J $sum (Join-Path $Dir 'summary.json')
    Write-J $score (Join-Path $Dir 'score-rigtool.json')
}

# Single defects: each edits a passing evidence directory and must turn it into a FAIL.
function Edit-E2eJson([string]$Path, [scriptblock]$Act) { $d = Read-J $Path; & $Act $d; Write-J $d $Path }
function Get-E2eDefects {
    @(
        @{ name = 'a collateral item (npp)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'npp\guest\execdiff.json') { param($d) $d.counts.collateral = 1 } } },
        @{ name = 'a guard escape (git)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'git\guest\execdiff.json') { param($d) $d.counts.guard_escapes = 1 } } },
        @{ name = 'execdiff missing (7zip)'; act = { param($ev) Remove-Item -LiteralPath (Join-Path $ev '7zip\guest\execdiff.json') } },
        @{ name = 'timings missing (vscode)'; act = { param($ev) Remove-Item -LiteralPath (Join-Path $ev 'vscode\timings.json') } },
        @{ name = 'no first-progress mark (git)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'git\timings.json') { param($d) $d.brokers[0].scans[0].first_progress_ms = $null } } },
        @{ name = 'first progress 150 ms (npp)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'npp\timings.json') { param($d) $d.brokers[0].scans[0].first_progress_ms = 150 } } },
        @{ name = 'cold scan 12 s (firefox-tb)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'firefox-tb\timings.json') { param($d) $d.brokers[0].scans[0].duration_ms = 12000 } } },
        @{ name = 'harvest 3.4 s after UAC (vscode-user)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'vscode-user\timings.json') { param($d) $d.brokers[0].harvests[0].after_uac_ms = 3400 } } },
        @{ name = 'a 1603 shown as success (review reached)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'msi1603\guest\e2e.json') { param($d) $d.steps.'ui-wait-scan'.state = 'review'; $d.steps.'ui-wait-scan'.seen = @('Ready for review'); $d.steps.'ui-wait-scan'.exit_codes = @(1603) } } },
        @{ name = 'a 1603 without its exit code'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'msi1603\guest\e2e.json') { param($d) $d.steps.'ui-wait-scan'.exit_codes = @() } } },
        @{ name = 'a 1603 that purged (a new session)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'msi1603\guest\e2e.json') { param($d) $d.steps.'fail-check'.sessions_new = @('20261122-1') } } },
        @{ name = 'a 1603 whose product is gone'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'msi1603\guest\e2e.json') { param($d) $d.steps.'fail-check'.arp_present = $false } } },
        @{ name = 'a 3010 without the restart bar'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'msi3010\guest\e2e.json') { param($d) $d.steps.'ui-wait-scan'.seen = @('Finished, exit code 3010') } } },
        @{ name = 'a 3010 shown as a failure'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'msi3010\guest\e2e.json') { param($d) $d.steps.'ui-wait-scan'.seen = @('A restart is needed.', 'The uninstaller failed.') } } },
        @{ name = 'executed set differs (one extra)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'vscode\guest\e2e.json') { param($d) $c = $d.steps.'capture-exec'.compare; $c.equal = $false; $c.ui_n = 3; $c.extra = @('Path|c:\x|') } } },
        @{ name = 'executed set empty on both sides'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'git\guest\e2e.json') { param($d) $c = $d.steps.'capture-exec'.compare; $c.cli_n = 0; $c.ui_n = 0 } } },
        @{ name = 'danger in the executed set'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'score-rigtool.json') { param($d) ($d.apps | Where-Object { $_.id -eq 'firefox-tb' }).tools[0].danger_offered = 1 } } },
        @{ name = 'no rigtool score for an app'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'score-rigtool.json') { param($d) $d.apps = @($d.apps | Where-Object { $_.id -ne 'execapp' }) } } },
        @{ name = 'undo fidelity row failing'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'npp\guest\fidelity.json') { param($d) $d.ok = $false; $d.rows[0].pass = $false } } },
        @{ name = 'undo not through the UI'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'npp\guest\e2e.json') { param($d) $d.steps.'ui-wait-undone'.state = $null } } },
        @{ name = 'medium-route uninstaller ran high'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'vscode-user\guest\e2e.json') { param($d) $d.steps.'ui-wait-scan'.uninstallers[0].il = 'high' } } },
        @{ name = 'medium-route uninstaller not seen'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'vscode-user\guest\e2e.json') { param($d) $d.steps.'ui-wait-scan'.uninstallers = @() } } },
        @{ name = 'route differs'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'git\guest\e2e.json') { param($d) $d.steps.'ui-confirm'.route = 'medium' } } },
        @{ name = 'uninstall consent not approved'; act = { param($ev) Edit-E2eJson (Join-Path $ev '7zip\guest\e2e.json') { param($d) $d.steps.'consent-approve-run'.ok = $false } } },
        @{ name = 'result page not reached'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'execapp\guest\e2e.json') { param($d) $d.steps.'ui-wait-result'.state = 'interrupted' } } },
        @{ name = 'session not committed'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'npp\guest\e2e.json') { param($d) $d.steps.'capture-exec'.report_state = 'Aborted' } } },
        @{ name = 'a screenshot missing'; act = { param($ev) Remove-Item -LiteralPath (Join-Path $ev 'git\04-consent-run.png') } },
        @{ name = 'an app missing'; act = { param($ev) Remove-Item -LiteralPath (Join-Path $ev 'execapp') -Recurse } },
        @{ name = 'guest outputs not pulled'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'npp\host.json') { param($d) $d.pulled = $false } } },
        @{ name = 'UAC not as the run says'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'npp\guest\e2e.json') { param($d) $d.uac.ConsentPromptBehaviorAdmin = 5 } } },
        @{ name = 'no undo app'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'summary.json') { param($d) $d.undo_apps = @() } } },
        @{ name = 'UAC on, a prompt not answered by scancode'; act = { param($ev) Set-E2eUacOn $ev; Edit-E2eJson (Join-Path $ev 'git\host.json') { param($d) $d.uac_keys.run = @() } } },
        @{ name = 'UAC on, no screenshot of the prompt'; act = { param($ev) Set-E2eUacOn $ev; Remove-Item -LiteralPath (Join-Path $ev 'npp\02u-uac-1-prompt.png') } },
        @{ name = 'UAC silent, but a prompt was answered'; act = { param($ev) Edit-E2eJson (Join-Path $ev '7zip\host.json') { param($d) $d | Add-Member -NotePropertyName uac_keys -NotePropertyValue ([pscustomobject]@{ run = @('alt-y') }) -Force } } },
        # The ambient set (RIG.md section 17.1): the run's records, then the set itself (re-hashed into every record,
        # so only the set check can fail).
        @{ name = 'ambient set not recorded by the host (vscode)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'vscode\host.json') { param($d) $d.PSObject.Properties.Remove('ambient') } } },
        @{ name = 'ambient set of another hash pushed (git)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'git\host.json') { param($d) $d.ambient.sha256 = ('0' * 64) } } },
        @{ name = 'ambient guest copy differs (npp)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'npp\guest\e2e.json') { param($d) $d.ambient.guest_sha256 = ('1' * 64) } } },
        @{ name = 'ambient guest copy missing (execapp)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'execapp\guest\e2e.json') { param($d) $d.ambient.guest_sha256 = $null } } },
        @{ name = 'ambient declared hash missing (7zip)'; act = { param($ev) Edit-E2eJson (Join-Path $ev '7zip\guest\e2e.json') { param($d) $d.ambient.declared = $null } } },
        @{ name = 'ambient set file missing'; act = { param($ev) Remove-Item -LiteralPath (Join-Path $ev 'm3-e2e-ambient.json') } },
        @{ name = 'ambient set from 5 null runs'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.runs = @($d.runs | Select-Object -First 5) }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set with one run twice (5 distinct)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.runs[5].id = $d.runs[0].id }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set with a gate run'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.runs[0].id = 'e2e-20261123-065615' }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set with a null run of a failing uninstaller'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.runs[0].id = 'en1-m3-e2e-msi1603' }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set naming a fixture (record)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.records = @($d.records) + '-K:HKLM\SOFTWARE\PurgeE2eMsi\1603' }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set naming the store (run pattern)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.runs[2].patterns = @('^\~F:C:\\ProgramData\\Purge\\sessions\\[0-9a-f]{16}$') }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set of another schema'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.schema = 'purge.rig.ambient/1' }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set naming a .purge-q (record)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.records = @($d.records) + '~D:D:\.purge-q' }; Set-E2eAmbientHash $ev } },
        @{ name = 'execdiff ran without the ambient set (inputs.ambient null, git)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'git\guest\execdiff.json') { param($d) $d.inputs.ambient = $null } } },
        @{ name = 'execdiff.json without inputs (npp)'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'npp\guest\execdiff.json') { param($d) $d.PSObject.Properties.Remove('inputs') } } },
        # Provenance: the set built on another VM, snapshot or binaries than the gate run (or recording none).
        @{ name = 'ambient set without provenance'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.PSObject.Properties.Remove('provenance') }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set from another VM'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.provenance.vm = 'Purge-CleanPro' }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set from another snapshot'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.provenance.snapshot = 'm3-uac-on' }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set from another engine'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.provenance.engine_sha256 = ('f' * 64) }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set from another broker'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.provenance.broker_sha256 = ('f' * 64) }; Set-E2eAmbientHash $ev } },
        @{ name = 'ambient set from another UI'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'm3-e2e-ambient.json') { param($d) $d.provenance.ui_sha256 = ('f' * 64) }; Set-E2eAmbientHash $ev } },
        @{ name = 'gate run on another snapshot than the set'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'summary.json') { param($d) $d.snapshot = 'm3-uac-on' } } },
        @{ name = 'gate run summary without a snapshot'; act = { param($ev) Edit-E2eJson (Join-Path $ev 'summary.json') { param($d) $d.PSObject.Properties.Remove('snapshot') } } }
    )
}

# After an edit of the synthetic ambient set: its new SHA-256 into every app's host and guest records.
function Set-E2eAmbientHash([string]$Ev) {
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Ev 'm3-e2e-ambient.json')).Hash.ToLowerInvariant()
    foreach ($d in @(Get-ChildItem -LiteralPath $Ev -Directory)) {
        $h = Join-Path $d.FullName 'host.json'; $g = Join-Path $d.FullName 'guest\e2e.json'
        if (Test-Path -LiteralPath $h) { Edit-E2eJson $h { param($x) $x.ambient.sha256 = $sha } }
        if (Test-Path -LiteralPath $g) { Edit-E2eJson $g { param($x) $x.ambient.declared.sha256 = $sha; $x.ambient.guest_sha256 = $sha } }
    }
}

# Turns a passing evidence directory into a passing UAC-on run: every app at 5, its prompt answered with Alt+Y and shot.
function Set-E2eUacOn([string]$Ev) {
    foreach ($d in @(Get-ChildItem -LiteralPath $Ev -Directory)) {
        $g = Join-Path $d.FullName 'guest\e2e.json'
        if (-not (Test-Path -LiteralPath $g)) { continue }
        Edit-E2eJson $g { param($x) $x.uac.ConsentPromptBehaviorAdmin = 5 }
        [IO.File]::WriteAllBytes((Join-Path $d.FullName '02u-uac-1-prompt.png'), [byte[]](137, 80, 78, 71))
        Edit-E2eJson (Join-Path $d.FullName 'host.json') { param($h)
            $h | Add-Member -NotePropertyName uac_keys -NotePropertyValue ([pscustomobject]@{ run = @('alt-y') }) -Force
            $h.shots = @(@($h.shots) + [pscustomobject]@{ name = '02u-uac-1-prompt'; file = '02u-uac-1-prompt.png'; bytes = 4 }) }
    }
}

function Invoke-SelfTest {
    $X = Get-Content -LiteralPath $ExpectFile -Raw | ConvertFrom-Json
    $root = Join-Path ([IO.Path]::GetTempPath()) ('m3-e2e-score-selftest-' + [guid]::NewGuid().ToString('N'))
    $script:checks = 0; $script:fails = 0
    function Check([string]$Name, [bool]$Cond) { $script:checks++; if ($Cond) { Write-Host "ok   $Name" } else { $script:fails++; Write-Host "FAIL $Name" } }
    try {
        $amb = { param($d) Join-Path $d 'm3-e2e-ambient.json' }
        $ev = Join-Path $root 'pass'
        New-PassEvidence $X $ev
        $r = Invoke-Score $ev $X -Quiet -TruthDir $ev
        Check 'synthetic pass passes' ($r.pass -and $r.gate)
        if (-not $r.pass) { foreach ($row in $r.rows) { if (-not $row.ok) { Write-Host "       $($row.row): $($row.detail)" } } }
        Check 'the ambient rows are scored (the set, and one per executing app)' (@($r.rows | Where-Object { $_.row -like '*ambient set*' }).Count -eq 1 + @(Arr $X.apps | Where-Object { "$($_.kind)" -in 'app', 'fixture' }).Count)
        $sub = Invoke-Score $ev $X @('npp') -Quiet -TruthDir $ev
        Check 'a subset passes but is not a gate score' ($sub.pass -and -not $sub.gate)
        $on = Join-Path $root 'uac-on'
        New-PassEvidence $X $on; Set-E2eUacOn $on
        $r2 = Invoke-Score $on $X -Quiet -TruthDir $on
        Check 'a UAC-on run answered by scancode passes' $r2.pass
        if (-not $r2.pass) { foreach ($row in $r2.rows) { if (-not $row.ok) { Write-Host "       $($row.row): $($row.detail)" } } }
        $re = Join-Path $root 'rehash'
        New-PassEvidence $X $re; Set-E2eAmbientHash $re
        Check 'a re-hashed unchanged set still passes (the helper of the set defects)' (Invoke-Score $re $X -Quiet -TruthDir $re).pass
        Check 'the score records the ambient file and its SHA-256' ("$($r.ambient.file)" -eq (& $amb $ev) -and "$($r.ambient.sha256)" -ceq (Get-FileHash -Algorithm SHA256 -LiteralPath (& $amb $ev)).Hash.ToLowerInvariant() -and $r.ambient.committed -eq $true)
        # -AmbientFile: the committed file itself is a gate score; another file (here a copy) scores, but is not one.
        $same = Invoke-Score $ev $X -Quiet -TruthDir $ev -Ambient (& $amb $ev)
        Check '-AmbientFile naming the committed set is a gate score' ($same.pass -and $same.gate)
        $cp = Join-Path $root 'other-ambient.json'; Copy-Item -LiteralPath (& $amb $ev) -Destination $cp
        $oth = Invoke-Score $ev $X -Quiet -TruthDir $ev -Ambient $cp
        Check '-AmbientFile naming another file: rows pass, not a gate score, the file recorded' ($oth.pass -and -not $oth.gate -and "$($oth.ambient.file)" -eq $cp -and $oth.ambient.committed -eq $false -and "$($oth.not_gate -join ' ')" -match 'AmbientFile')
        $nb = Join-Path $root 'no-binaries'
        New-PassEvidence $X $nb; Edit-E2eJson (Join-Path $nb 'summary.json') { param($d) $d.PSObject.Properties.Remove('binaries') }
        Check 'a summary without binaries compares VM and snapshot only (passes)' (Invoke-Score $nb $X -Quiet -TruthDir $nb).pass
        $empty = Join-Path $root 'empty'; New-Item -ItemType Directory -Force $empty | Out-Null
        Check 'empty evidence fails' (-not (Invoke-Score $empty $X -Quiet).pass)
        Check 'missing directory fails' (-not (Invoke-Score (Join-Path $root 'none') $X -Quiet).pass)
        $p = New-E2ePlans ([pscustomobject]@{ mode = 'post'; items = @([pscustomobject]@{ target = [pscustomobject]@{ type = 'Path'; path = 'C:\A' }; band = 'Safe'; preselected = $true }) }) `
                          ([pscustomobject]@{ items = @([pscustomobject]@{ id = 'c1'; target = [pscustomobject]@{ type = 'Path'; path = 'C:\A' }; action = [pscustomobject]@{ Quarantine = @{} } }) }) `
                          ([pscustomobject]@{ items = @([pscustomobject]@{ key = 'Path|c:\a||'; target = [pscustomobject]@{ type = 'Path'; path = 'C:\A' } }) }) { param($t) Get-E2eTargetKey $t } 'x'
        Check 'collect plans: the CLI action rides on the executed item' ("$($p[0].items[0].action)" -eq 'Quarantine' -and "$($p[1].items[0].action)" -eq 'Quarantine' -and $p[1].items[0].preselected -eq $true -and $p[1].tool -eq 'ui')
        Check 'target key folds case, keeps the rule id' ((Get-E2eTargetKey ([pscustomobject]@{ type = 'RegKey'; path = 'HKLM\SOFTWARE\X\' })) -eq 'RegKey|hklm\software\x||' -and (Get-E2eTargetKey ([pscustomobject]@{ type = 'FirewallRule'; id = 'AbC' })) -eq 'FirewallRule|AbC')
        foreach ($d in Get-E2eDefects) {
            $dir = Join-Path $root ([guid]::NewGuid().ToString('N'))
            New-PassEvidence $X $dir
            & $d.act $dir
            Check "defect '$($d.name)' fails" (-not (Invoke-Score $dir $X -Quiet -TruthDir $dir).pass)
        }
    } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "m3-e2e-score self-test: $($script:checks - $script:fails)/$($script:checks) ok"
    if ($script:fails) { 1 } else { 0 }
}

# ---------------------------------------------------------------------------------------------------- main

if ($MyInvocation.InvocationName -eq '.') { return }
if ($SelfTest) { exit (Invoke-SelfTest) }
if (-not $Evidence) { Write-Host 'usage: m3-e2e-score.ps1 -Evidence <dir> [-Collect] [-Apps a,b] | --self-test'; exit 2 }
$X = Get-Content -LiteralPath $ExpectFile -Raw | ConvertFrom-Json
$only = @($Apps | ForEach-Object { "$_" -split ',' } | Where-Object { $_ })
if ($Collect) { Invoke-Collect $Evidence $X }
$res = Invoke-Score $Evidence $X $only -Ambient $AmbientFile
if (Test-Path -LiteralPath $Evidence -PathType Container) { Write-J $res (Join-Path $Evidence 'score-m3-e2e.json') }
if (-not $res.pass) { Write-Host 'm3-e2e: FAIL'; exit 1 }
if (-not $res.gate) { Write-Host "m3-e2e: every row passes, but $($res.not_gate -join ' and '): not a gate score"; exit 3 }
Write-Host 'm3-e2e: PASS'
exit 0
