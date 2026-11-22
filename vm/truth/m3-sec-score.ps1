<#
  Scorer of the M3 security modes (vm\RIG.md section 14): m3-broker (gate G3, G10), m3-consent (G4), m3-uac (G5).
  Windows PowerShell 5.1 or pwsh 7. Reads the evidence directory vm\rig-m3.ps1 wrote (summary.json, *.png,
  guest\m3-broker.json | guest\m3-consent.json | guest\m3-uac.json) and vm\truth\m3-sec-expect.json.

    powershell -NoProfile -File vm\truth\m3-sec-score.ps1 -Mode broker  -Evidence E:\purge-build\gate-evidence\m3-broker
    powershell -NoProfile -File vm\truth\m3-sec-score.ps1 -Mode consent -Evidence E:\purge-build\gate-evidence\m3-consent
    powershell -NoProfile -File vm\truth\m3-sec-score.ps1 -Mode uac     -Evidence E:\purge-build\gate-evidence\m3-uac
    powershell -NoProfile -File vm\truth\m3-sec-score.ps1 --self-test      (or -SelfTest)

  Fail-closed: every row needs its evidence; a missing file, case, record or field is a FAIL of that row, never a
  pass. Prints one line per row, writes <evidence>\score-<mode>.json, exits 0 (PASS), 1 (FAIL) or 2 (usage).
  The self-test builds a passing synthetic evidence directory per mode in %TEMP% from the expectations, checks that it
  passes, then checks that each of a list of single defects (and an empty directory) fails.
#>
[CmdletBinding()]
param(
    [ValidateSet('', 'broker', 'consent', 'uac')] [string] $Mode = '',
    [string] $Evidence = '',
    [string] $ExpectFile = '',
    [switch] $SelfTest,
    [Parameter(ValueFromRemainingArguments = $true)] $Rest
)
$ErrorActionPreference = 'Stop'
if (@($Rest) -contains '--self-test') { $SelfTest = $true }
if (-not $ExpectFile) { $ExpectFile = Join-Path $PSScriptRoot 'm3-sec-expect.json' }

# ------------------------------------------------------------------------------------------------ helpers

function Read-J([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
}
function Has($O, [string]$Name) { $null -ne $O -and $null -ne $O.PSObject.Properties[$Name] -and $null -ne $O.$Name }
function Arr($X) { @(@($X) | Where-Object { $null -ne $_ }) }

$script:Rows = New-Object System.Collections.ArrayList
function Row([string]$Name, $Ok, [string]$Detail = '') {
    $v = ($Ok -eq $true)
    [void]$script:Rows.Add([ordered]@{ row = $Name; ok = $v; detail = $Detail })
}

# The k of a collected guest file (dialog-3.json, attack-1-uia.json, page-2-03.json, ...).
function Get-K([string]$File) { $m = [regex]::Match($File, '(\d+)'); if ($m.Success) { [int]$m.Groups[1].Value } else { -1 } }
function Find-File($List, [string]$Pattern) { @(Arr $List | Where-Object { $_.file -match $Pattern } | ForEach-Object { $_.data }) }

# Screenshots: the summary names them and each file exists with bytes.
function Get-Shots([string]$Ev, $Summary) {
    @(Arr $Summary.shots | Where-Object { $_.file -and $_.bytes -gt 0 -and (Test-Path -LiteralPath (Join-Path $Ev $_.file) -PathType Leaf) -and (Get-Item -LiteralPath (Join-Path $Ev $_.file)).Length -gt 0 } | ForEach-Object { "$($_.name)" })
}

# The silent UAC the mode set itself (guest phase uac-silent, ruling 2026-11-22: rig-base is at the Windows defaults):
# the recorded state after the set is silent with LUA on, and it still was when the summary was written. The value the
# snapshot had before is recorded, never asserted.
function Test-UacSilent($Doc, $Want) {
    $s = $Doc.uac_silent
    $okSet = ($s -and $s.ok -eq $true -and "$($s.after.ConsentPromptBehaviorAdmin)" -eq "$Want" -and "$($s.after.EnableLUA)" -eq '1')
    Row 'uac made silent by the mode (recorded before/after)' $okSet $(if ($s) { "before $($s.before.ConsentPromptBehaviorAdmin)/$($s.before.PromptOnSecureDesktop)/$($s.before.EnableLUA), after $($s.after.ConsentPromptBehaviorAdmin)/$($s.after.PromptOnSecureDesktop)/$($s.after.EnableLUA)" } else { 'no uac_silent record' })
    Row 'uac still silent at the end (ConsentPromptBehaviorAdmin)' ((Has $Doc 'uac') -and "$($Doc.uac.ConsentPromptBehaviorAdmin)" -eq "$Want") "$($Doc.uac.ConsentPromptBehaviorAdmin)"
}

# ------------------------------------------------------------------------------------------------- broker

function Test-Broker([string]$Ev, $X) {
    $doc = Read-J (Join-Path $Ev 'guest\m3-broker.json')
    Row 'evidence guest\m3-broker.json' ($null -ne $doc) $(if (-not $doc) { 'missing or unreadable' })
    if (-not $doc) { return }
    Test-UacSilent $doc $X.broker.uac_admin
    foreach ($c in Arr $X.broker.cases) {
        $r = @(Arr $doc.cases | Where-Object { $_.id -eq $c.id }) | Select-Object -First 1
        $n = "case $($c.id)"
        if (-not $r) { Row $n $false 'no record'; continue }
        $why = @()
        if ($r.error) { $why += "error: $($r.error)" }
        if (-not ((Has $r 'exit_code') -and [int]$r.exit_code -eq [int]$c.exit -and $r.broker_exited -eq $true)) { $why += "exit $($r.exit_code) (exited $($r.broker_exited)), expected $($c.exit)" }
        $events = @(Arr $r.events)
        if ([int]$c.exit -ne 0) {
            $hit = @($events | Where-Object { [int]$_.id -eq [int]$c.exit -and $(foreach ($s in Arr $c.reason_all) { if ("$($_.message)".IndexOf($s, [StringComparison]::Ordinal) -lt 0) { $false } }) -notcontains $false })
            if (-not $hit.Count) { $why += "no event $($c.exit) with [$((Arr $c.reason_all) -join ' | ')]" }
            elseif (Has $c 'reason_count') {
                $cnt = ([regex]::Matches("$($hit[0].message)", [regex]::Escape("$(@(Arr $c.reason_all)[0])"))).Count
                if ($cnt -lt [int]$c.reason_count) { $why += "event names the refusal $cnt times, expected $($c.reason_count)" }
            }
            if ($r.data_root_changed -ne $false) { $why += "data root changed or not compared: $((Arr $r.data_root_diff | Select-Object -First 3) -join '; ')" }
        } else {
            $bad = @($events | Where-Object { [int]$_.id -ge 20 -and [int]$_.id -le 27 })
            if ($bad.Count) { $why += "start-failure events: $(@($bad | ForEach-Object { $_.id }) -join ',')" }
        }
        $conn = @(Arr $r.client.connects)
        if ($c.hello) {
            $last = $conn | Select-Object -Last 1
            if (-not ($last -and $last.hello_answered -eq $true -and $last.hello.result.elevated -eq $true)) { $why += 'no elevated engine.hello answer' }
            if (-not ($last -and $last.server_check -eq 'ok')) { $why += "server check $($last.server_check)" }
        }
        if (Has $c 'second_client_error') {
            $f = $conn | Select-Object -First 1
            if (-not ($f -and "$($f.second_client_open_error)" -eq "$($c.second_client_error)")) { $why += "second client got $($f.second_client_open_error), expected $($c.second_client_error)" }
        }
        if (Has $c 'server_check') {
            $f = $conn | Select-Object -First 1
            if (-not ($f -and $f.server_check -eq $c.server_check)) { $why += "server check $($f.server_check), expected $($c.server_check)" }
        }
        if ($c.planted_unchanged) {
            if (-not $r.planted -or $r.planted_changed -ne $false) { $why += "planted tree changed or not compared: $((Arr $r.planted_diff | Select-Object -First 3) -join '; ')" }
        }
        Row $n ($why.Count -eq 0) $(if ($why.Count) { $why -join '; ' } else { "exit $($r.exit_code)" })
    }
    foreach ($e in Arr $X.broker.excluded) { if (-not $script:QuietInfo) { Write-Host ("INFO  excluded exit {0} {1}: {2}" -f $e.exit, $e.code, $e.why) } }
}

# ------------------------------------------------------------------------------------------------ consent

function Test-Consent([string]$Ev, $X) {
    $doc = Read-J (Join-Path $Ev 'guest\m3-consent.json')
    $sum = Read-J (Join-Path $Ev 'summary.json')
    Row 'evidence guest\m3-consent.json' ($null -ne $doc) $(if (-not $doc) { 'missing or unreadable' })
    Row 'evidence summary.json' ($null -ne $sum) $(if (-not $sum) { 'missing or unreadable' })
    if (-not $doc) { return }
    Test-UacSilent $doc $X.consent.uac_admin
    $ready = @(Arr $doc.ready | ForEach-Object { $_.data })
    $kinds = @{}
    foreach ($r in $ready) { $kinds[[int]$r.k] = "$($r.method)" }
    $total = 0
    foreach ($kind in Arr $X.consent.kinds) {
        $att = @(Arr $doc.attacks | ForEach-Object { $_.data } | Where-Object { $_.kind -eq $kind })
        foreach ($m in Arr $X.consent.methods) {
            $a = @($att | Where-Object { $_.method -eq $m }) | Select-Object -First 1
            $n = "medium $kind $m"
            if (-not $a) { Row $n $false 'no attack record'; continue }
            $why = @()
            $tries = @(Arr $a.drive.attempts | Where-Object { -not $_.skipped })
            if ($a.drive.driver_il -ne 'medium') { $why += "driver at $($a.drive.driver_il)" }
            if (-not ($a.pre.found -eq $true -and $a.pre.broker_il -eq 'high')) { $why += "dialog not found or not high ($($a.pre.broker_il))" }
            if (-not $tries.Count) { $why += 'no attempt' }
            $reached = @($tries | Where-Object { $_.reached -ne $false })
            if ($reached.Count) { $why += "reached: $(@($reached | ForEach-Object { $_.name }) -join '; ')" }
            if (-not (Has $a 'effect_count') -or [int]$a.effect_count -ne 0) {
                $on = @($a.effects.PSObject.Properties | Where-Object { $_.Value -ne $false } | ForEach-Object { $_.Name })
                $why += "effects: $($on -join ', ')"
            }
            if ($m -like 'sendinput-*') {
                $nofg = @($tries | Where-Object { $_.foreground_is_dialog -ne $true })
                if ($nofg.Count) { $why += "$($nofg.Count) SendInput attempts without the dialog in front (not a fair test)" }
            }
            if ($kind -eq 'plan.execute' -and $X.consent.plan_needs_verification_box -and -not $a.pre.verify) { $why += 'no verification box on the plan dialog (fixture without attention items)' }
            $total += $tries.Count
            Row $n ($why.Count -eq 0) $(if ($why.Count) { $why -join '; ' } else { "$($tries.Count) attempts, 0 reached, 0 effects" })
        }
        $ctl = @(Arr $doc.controls | ForEach-Object { $_.data } | Where-Object { $_.kind -eq $kind })
        foreach ($m in Arr $X.consent.methods) {
            $c = @($ctl | Where-Object { $_.method -eq $m }) | Select-Object -First 1
            $n = "high control $kind $m"
            if (-not $c) { Row $n $false 'no control record'; continue }
            $why = @()
            if ($c.drive.driver_il -ne 'high') { $why += "driver at $($c.drive.driver_il)" }
            if ($c.declined -ne $true) { $why += "not declined ($($c.result_kind))" }
            if ($c.journal_changed -ne $false) { $why += 'journal changed' }
            if ($kind -eq 'uninstall.run' -and $c.uninstaller_ran -ne $false) { $why += 'the uninstaller ran' }
            Row $n ($why.Count -eq 0) $(if ($why.Count) { $why -join '; ' } else { 'Cancel reached the dialog: consent_declined, nothing changed' })
        }
        $ap = @(Arr $doc.approves | ForEach-Object { $_.data } | Where-Object { $_.kind -eq $kind }) | Select-Object -First 1
        $n = "high approval $kind"
        if (-not $ap) { Row $n $false 'no approval record' }
        elseif ($kind -eq 'uninstall.run') { Row $n ($ap.result_kind -eq 'result' -and $ap.uninstaller_ran -eq $true) "result $($ap.result_kind), uninstaller ran $($ap.uninstaller_ran)" }
        else {
            $oc = "$($ap.response.result.outcome)"
            Row $n ($ap.result_kind -eq 'result' -and @('complete', 'partial') -contains $oc -and $ap.journal_changed -eq $true) "result $($ap.result_kind), outcome $oc, journal changed $($ap.journal_changed)"
        }
    }
    Row "medium attempts (at least $($X.consent.min_medium_attempts))" ($total -ge [int]$X.consent.min_medium_attempts) "$total"
    $shots = @(if ($sum) { Get-Shots $Ev $sum })
    foreach ($p in $X.consent.shot_patterns.PSObject.Properties) {
        $have = @($shots | Where-Object { $_ -match "-$($p.Name)" }).Count
        Row "screenshots *-$($p.Name)* (at least $($p.Value))" ($have -ge [int]$p.Value) "$have"
    }
}

# ---------------------------------------------------------------------------------------------------- uac

function Test-Uac([string]$Ev, $X) {
    $doc = Read-J (Join-Path $Ev 'guest\m3-uac.json')
    $sum = Read-J (Join-Path $Ev 'summary.json')
    Row 'evidence guest\m3-uac.json' ($null -ne $doc) $(if (-not $doc) { 'missing or unreadable' })
    Row 'evidence summary.json' ($null -ne $sum) $(if (-not $sum) { 'missing or unreadable' })
    if (-not $doc) { return }
    $u = $doc.uac
    Row 'uac on (5, secure desktop, LUA)' ($u -and "$($u.ConsentPromptBehaviorAdmin)" -eq "$($X.uac.uac_admin)" -and "$($u.PromptOnSecureDesktop)" -eq "$($X.uac.prompt_on_secure_desktop)" -and "$($u.EnableLUA)" -eq '1') "$($u.ConsentPromptBehaviorAdmin)/$($u.PromptOnSecureDesktop)/$($u.EnableLUA)"

    # The real UI: No -> the cancelled bar; no broker, nothing written, the program still there.
    $us = $doc.ui_start; $ur = $doc.ui_result
    $why = @()
    if (-not ($us -and $us.present -eq $true)) { $why += 'no real UI installed (pass -UiPublish)' }
    elseif (-not $us.consent_pid) { $why += 'the Windows prompt did not come up' }
    if (-not ($ur -and $ur.bar_found -eq $true)) { $why += 'no "You cancelled the admin prompt." bar' }
    if (-not ($ur -and (Has $ur 'broker_processes') -and @(Arr $ur.broker_processes).Count -eq 0)) { $why += 'a broker process ran' }
    if (-not ($ur -and $ur.data_root_changed -eq $false)) { $why += 'data root changed or not compared' }
    if (-not ($ur -and $ur.fixture_arp_present -eq $true -and $ur.uninstaller_ran -eq $false)) { $why += 'the program changed' }
    if ($ur -and @(Arr $ur.events).Count) { $why += "Purge events: $(@(Arr $ur.events | ForEach-Object { $_.id }) -join ',')" }
    Row 'No at the prompt (real UI): cancelled bar, nothing runs' ($why.Count -eq 0) ($why -join '; ')

    # The rig client: No -> 1223.
    $no = $doc.no
    $why = @()
    if (-not ($no -and $no.start -and $no.start.consent_pid)) { $why += 'the Windows prompt did not come up' }
    if (-not ($no -and $no.launch -and $no.launch.launched -and $no.launch.launched.ok -eq $false -and [int]$no.launch.launched.error -eq 1223)) { $why += "launch result $($no.launch.launched.error)" }
    if (-not ($no -and (Has $no.launch 'broker_processes') -and @(Arr $no.launch.broker_processes).Count -eq 0)) { $why += 'a broker process ran' }
    if (-not ($no -and $no.launch.data_root_changed -eq $false)) { $why += 'data root changed or not compared' }
    if ($no -and @(Arr $no.launch.events).Count) { $why += "Purge events: $(@(Arr $no.launch.events | ForEach-Object { $_.id }) -join ',')" }
    Row 'No at the prompt (client): error 1223, no broker' ($why.Count -eq 0) ($why -join '; ')

    # Yes -> the full flow.
    $y = $doc.yes; $yl = $doc.yes_launch
    $why = @()
    if (-not ($y -and $y.start -and $y.start.consent_pid)) { $why += 'the Windows prompt did not come up' }
    if (-not ($yl -and $yl.launched.ok -eq $true -and $yl.broker.il -eq 'high')) { $why += "broker not started at high ($($yl.broker.il))" }
    Row 'Yes at the prompt: the broker runs elevated' ($why.Count -eq 0) ($why -join '; ')
    if (-not $y) { Row 'Yes: full flow' $false 'no m3-uac-flow-yes record'; }
    else {
        $ready = @(Arr $y.ready | ForEach-Object { $_.data })
        $r1 = $ready | Where-Object { [int]$_.k -eq 1 } | Select-Object -First 1
        $r2 = $ready | Where-Object { [int]$_.k -eq 2 } | Select-Object -First 1
        $shown = @{}; foreach ($s in Arr $y.shown) { $shown[(Get-K $s.file)] = "$($s.data.params.code)".ToUpperInvariant() }
        $a1 = @(Find-File $y.arms '^arm-1\.json$') | Select-Object -First 1
        $d1 = @(Find-File $y.dialogs '^dialog-1\.json$') | Select-Object -First 1
        $why = @()
        if (-not ($r1 -and $r1.method -eq 'uninstall.run')) { $why += 'no uninstall.run dialog' }
        if (-not ($a1 -and $a1.found -eq $true)) { $why += 'arming: dialog not found' }
        else {
            if (-not ((Has $a1 'early_click_ms') -and [int]$a1.early_click_ms -lt [int]$X.uac.early_click_max_ms)) { $why += "early click at $($a1.early_click_ms) ms" }
            if ($a1.dialog_alive_after_early -ne $true) { $why += 'a click before the arming delay answered the dialog' }
            if ($a1.primary_enabled_late -ne $true) { $why += 'the button was not enabled after the delay' }
            if ($a1.foreground_at_found -ne $true) { $why += 'the dialog was not in front when it appeared' }
        }
        if (-not ($d1 -and $d1.found -eq $true -and $d1.broker_il -eq 'high')) { $why += 'dialog not observed at high' }
        elseif (-not ($d1.footer_code -and $shown.ContainsKey(1) -and $d1.footer_code -eq $shown[1])) { $why += "footer code $($d1.footer_code) vs consent.shown $($shown[1])" }
        $ap1 = @(Arr $y.approves | ForEach-Object { $_.data } | Where-Object { [int]$_.k -eq 1 }) | Select-Object -First 1
        if (-not ($ap1 -and $ap1.result_kind -eq 'result' -and $ap1.uninstaller_ran -eq $true)) { $why += 'the approved uninstaller did not run' }
        Row 'Yes: uninstall dialog (arming, code, foreground, approval)' ($why.Count -eq 0) ($why -join '; ')

        $why = @()
        $d2 = @(Find-File $y.dialogs '^dialog-2\.json$') | Select-Object -First 1
        $pages = @(@($d2) + @(Find-File $y.pages '^page-2-\d+\.json$') | Where-Object { $_ -and $_.found })
        if (-not ($r2 -and $r2.method -eq 'plan.execute')) { $why += 'no plan.execute dialog' }
        if (-not $d2) { $why += 'plan dialog not observed' }
        else {
            $n = [int]$d2.pages
            if ($n -lt [int]$X.uac.min_plan_pages -or $d2.paged -ne $true) { $why += "$n page(s), expected at least $($X.uac.min_plan_pages)" }
            $seen = @($pages | ForEach-Object { [int]$_.page } | Sort-Object -Unique)
            for ($p = 1; $p -le $n; $p++) { if ($seen -notcontains $p) { $why += "page $p not observed" } }
            $plan = "$($r2.plan_code)".ToUpperInvariant()
            foreach ($pg in $pages) {
                if ($pg.footer_code -ne $plan -or -not $plan) { $why += "page $($pg.page) footer $($pg.footer_code) vs plan.create $plan" }
                $last = ([int]$pg.page -eq $n)
                if ([bool]$pg.has_primary -ne $last) { $why += "page $($pg.page): primary button present=$($pg.has_primary)" }
            }
            if (-not ($shown.ContainsKey(2) -and $shown[2] -eq $plan)) { $why += "consent.shown $($shown[2]) vs plan.create $plan" }
            if ($d2.foreground -ne $true) { $why += 'the dialog was not in front when observed' }
            if ([int]$d2.attention_total -lt 41) { $why += "attention total $($d2.attention_total) (the fixture needs over 40)" }
        }
        $a2 = @(Find-File $y.arms '^arm-2\.json$') | Select-Object -First 1
        if (-not ($a2 -and $a2.renavigated -eq $true)) { $why += 'arming on the last page not run' }
        else {
            if (-not ((Has $a2 'early_click_ms') -and [int]$a2.early_click_ms -lt [int]$X.uac.early_click_max_ms)) { $why += "early click at $($a2.early_click_ms) ms" }
            if ($a2.dialog_alive_after_early -ne $true -or $a2.primary_enabled_after_early -ne $false) { $why += 'the box ticked early enabled the button or a click answered it' }
            if ($a2.primary_enabled_late -ne $true) { $why += 'the button was not enabled after the delay' }
        }
        $ap2 = @(Arr $y.approves | ForEach-Object { $_.data } | Where-Object { [int]$_.k -eq 2 }) | Select-Object -First 1
        $oc = "$($ap2.response.result.outcome)"
        if (-not ($ap2 -and $ap2.result_kind -eq 'result' -and @('complete', 'partial') -contains $oc -and $ap2.journal_changed -eq $true)) { $why += "execute result $($ap2.result_kind) $oc" }
        Row 'Yes: plan dialog (paging, code on every page, arming, foreground, execute)' ($why.Count -eq 0) ($why -join '; ')
    }

    # A standard user with administrator credentials typed: the UI's pre-check refuses, the broker serves nothing.
    $s = $doc.std
    $why = @()
    if (-not $s) { $why += 'no record' }
    else {
        if ($s.client.precheck -ne 'standard_user') { $why += "pre-check $($s.client.precheck)" }
        if (-not ($s.launched -and $s.launched.ok -eq $true)) { $why += "credentials not accepted (launch error $($s.launched.error))" }
        if (-not ($s.broker -and $s.broker.il -eq 'high' -and "$($s.broker.user)" -notmatch 'purgestd')) { $why += "broker $($s.broker.user) at $($s.broker.il)" }
        $served = @(Arr $s.client.connects | Where-Object { $_.hello_answered -eq $true })
        if ($served.Count) { $why += 'the broker answered the standard user' }
        if (@(Arr $X.uac.std_exit_codes | ForEach-Object { "$_" }) -notcontains "$($s.broker_exit_code)") { $why += "broker exit $($s.broker_exit_code)" }
        if ("$($s.broker_exit_code)" -eq '25' -and -not @(Arr $s.events | Where-Object { "$($_.message)" -match 'other_account' }).Count) { $why += 'exit 25 without other_account refusals' }
        if ($s.data_root_changed -ne $false) { $why += 'data root changed or not compared' }
    }
    Row 'standard user refused (T8)' ($why.Count -eq 0) ($why -join '; ')

    $shots = @(if ($sum) { Get-Shots $Ev $sum })
    $miss = @(Arr $X.uac.required_shots | Where-Object { $shots -notcontains $_ })
    Row 'screenshots' ($miss.Count -eq 0) $(if ($miss.Count) { "missing: $($miss -join ', ')" } else { "$($shots.Count)" })
}

# ---------------------------------------------------------------------------------------------------- run

function Invoke-Score([string]$M, [string]$Ev, $X, [switch]$Quiet) {
    $script:Rows = New-Object System.Collections.ArrayList
    $script:QuietInfo = [bool]$Quiet
    if (-not (Test-Path -LiteralPath $Ev -PathType Container)) { Row 'evidence directory' $false "missing: $Ev" }
    else {
        switch ($M) { 'broker' { Test-Broker $Ev $X } 'consent' { Test-Consent $Ev $X } 'uac' { Test-Uac $Ev $X } }
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

function New-BrokerPass($X) {
    $cases = foreach ($c in Arr $X.broker.cases) {
        $msg = $(if ([int]$c.exit -eq 25) { 'purge-broker ended: RefusedClients (exit code 25); refused clients: [' + ((1..3 | ForEach-Object { @(Arr $c.reason_all)[0] }) -join '; ') + ']' }
                 else { "purge-broker did not start: x (exit code $($c.exit)): " + ((Arr $c.reason_all) -join ' / ') })
        $conn = [ordered]@{ attempt = 1; opened = $true; server_check = $(if ($c.server_check) { $c.server_check } else { 'ok' }); hello_answered = [bool]$c.hello
                            hello = [ordered]@{ result = [ordered]@{ elevated = $true } } }
        if (Has $c 'second_client_error') { $conn.second_client_open_error = $c.second_client_error }
        [ordered]@{ id = $c.id; exit_code = $c.exit; broker_exited = $true; error = $null
                    events = @(if ([int]$c.exit -ne 0) { [ordered]@{ id = $c.exit; message = $msg } })
                    data_root_changed = $false; data_root_diff = @(); client = [ordered]@{ connects = @($conn) }
                    planted = $(if ($c.planted_unchanged) { 'C:\PurgePlant' }); planted_changed = $(if ($c.planted_unchanged) { $false }) }
    }
    [ordered]@{ schema = 'purge.rig.m3sec.broker/1'; uac = [ordered]@{ ConsentPromptBehaviorAdmin = 0 }; uac_silent = [ordered]@{ ok = $true; before = [ordered]@{ ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1; EnableLUA = 1 }; after = [ordered]@{ ConsentPromptBehaviorAdmin = 0; PromptOnSecureDesktop = 1; EnableLUA = 1 } }; cases = @($cases) }
}

function New-ConsentPass($X, [string]$Dir) {
    $ready = @(); $attacks = @(); $controls = @(); $approves = @(); $names = @()
    $k = 1
    foreach ($kind in Arr $X.consent.kinds) {
        $pre = [ordered]@{ found = $true; broker_il = 'high'; verify = $(if ($kind -eq 'plan.execute') { [ordered]@{ toggle = 'Off' } }) }
        foreach ($m in Arr $X.consent.methods) {
            $tries = @(1..3 | ForEach-Object { [ordered]@{ name = "$m $_"; reached = $false; foreground_is_dialog = $true } })
            $attacks += [ordered]@{ file = "attack-$k-$m.json"; data = [ordered]@{ k = $k; kind = $kind; method = $m; drive = [ordered]@{ driver_il = 'medium'; attempts = $tries }; pre = $pre
                                    effects = [ordered]@{ dialog_gone = $false; answered = $false; journal_changed = $false }; effect_count = 0 } }
            $names += "c$k-$kind-attack-$m"
        }
        foreach ($m in Arr $X.consent.methods) {
            $ready += [ordered]@{ file = "ready-$k.json"; data = [ordered]@{ k = $k; method = $kind } }
            $controls += [ordered]@{ file = "control-$k-$m.json"; data = [ordered]@{ k = $k; kind = $kind; method = $m; drive = [ordered]@{ driver_il = 'high' }; declined = $true; journal_changed = $false; uninstaller_ran = $false } }
            $names += "c$k-$kind-shown", "c$k-$kind-control-$m"
            $k++
        }
        $approves += [ordered]@{ file = "approve-$k.json"; data = [ordered]@{ k = $k; kind = $kind; result_kind = 'result'; uninstaller_ran = $true; journal_changed = ($kind -eq 'plan.execute')
                                 response = [ordered]@{ result = [ordered]@{ outcome = 'complete' } } } }
        $names += "c$k-$kind-shown", "c$k-$kind-approved"
        $k++
    }
    $shots = New-Shots $Dir $names
    $doc = [ordered]@{ uac = [ordered]@{ ConsentPromptBehaviorAdmin = 0 }; uac_silent = [ordered]@{ ok = $true; before = [ordered]@{ ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1; EnableLUA = 1 }; after = [ordered]@{ ConsentPromptBehaviorAdmin = 0; PromptOnSecureDesktop = 1; EnableLUA = 1 } }; ready = $ready; attacks = $attacks; controls = $controls; approves = $approves }
    @($doc, $shots)
}

function New-UacPass($X, [string]$Dir) {
    $code = 'A1B2-C3D4'; $code1 = 'B1B1-C1C1'
    $dialogs = @([ordered]@{ file = 'dialog-1.json'; data = [ordered]@{ found = $true; broker_il = 'high'; footer_code = $code1; page = 1; pages = 1; paged = $false; has_primary = $true; foreground = $true } },
                 [ordered]@{ file = 'dialog-2.json'; data = [ordered]@{ found = $true; broker_il = 'high'; footer_code = $code; page = 1; pages = 2; paged = $true; has_primary = $false; foreground = $true; attention_total = 45 } })
    $pages = @([ordered]@{ file = 'page-2-02.json'; data = [ordered]@{ found = $true; footer_code = $code; page = 2; pages = 2; paged = $true; has_primary = $true } })
    $yes = [ordered]@{
        start = [ordered]@{ consent_pid = 10 }
        ready = @([ordered]@{ file = 'ready-1.json'; data = [ordered]@{ k = 1; method = 'uninstall.run' } }, [ordered]@{ file = 'ready-2.json'; data = [ordered]@{ k = 2; method = 'plan.execute'; plan_code = $code } })
        shown = @([ordered]@{ file = 'consent-shown-1.json'; data = [ordered]@{ params = [ordered]@{ code = $code1 } } }, [ordered]@{ file = 'consent-shown-2.json'; data = [ordered]@{ params = [ordered]@{ code = $code } } })
        arms = @([ordered]@{ file = 'arm-1.json'; data = [ordered]@{ found = $true; early_click_ms = 320; dialog_alive_after_early = $true; primary_enabled_late = $true; foreground_at_found = $true } },
                 [ordered]@{ file = 'arm-2.json'; data = [ordered]@{ found = $true; renavigated = $true; early_click_ms = 330; dialog_alive_after_early = $true; primary_enabled_after_early = $false; primary_enabled_late = $true } })
        dialogs = $dialogs; pages = $pages
        approves = @([ordered]@{ file = 'approve-1.json'; data = [ordered]@{ k = 1; result_kind = 'result'; uninstaller_ran = $true } },
                     [ordered]@{ file = 'approve-2.json'; data = [ordered]@{ k = 2; result_kind = 'result'; journal_changed = $true; response = [ordered]@{ result = [ordered]@{ outcome = 'complete' } } } })
    }
    $doc = [ordered]@{
        uac = [ordered]@{ ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1; EnableLUA = 1 }
        ui_start = [ordered]@{ present = $true; consent_pid = 9 }
        ui_result = [ordered]@{ present = $true; bar_found = $true; broker_processes = @(); data_root_changed = $false; fixture_arp_present = $true; uninstaller_ran = $false }
        no = [ordered]@{ start = [ordered]@{ consent_pid = 11 }; launch = [ordered]@{ launched = [ordered]@{ ok = $false; error = 1223 }; broker_processes = @(); data_root_changed = $false } }
        yes = $yes
        yes_launch = [ordered]@{ launched = [ordered]@{ ok = $true; broker_pid = 99 }; broker = [ordered]@{ il = 'high'; user = 'HOST\tester' } }
        std = [ordered]@{ client = [ordered]@{ precheck = 'standard_user'; connects = @([ordered]@{ opened = $false; open_error = 5 }) }; launched = [ordered]@{ ok = $true }
                          broker = [ordered]@{ il = 'high'; user = 'HOST\tester' }; broker_exit_code = 0; events = @(); data_root_changed = $false }
    }
    $shots = New-Shots $Dir @(Arr $X.uac.required_shots)
    @($doc, $shots)
}

# Single defects; each must turn a passing evidence directory into a FAIL.
function Get-Defects {
    @(
        @{ mode = 'broker'; name = 'a case missing'; act = { param($d) $d.cases = @($d.cases | Select-Object -Skip 1) } },
        @{ mode = 'broker'; name = 'wrong exit code'; act = { param($d) ($d.cases | Where-Object { $_.id -eq 'off-volume' }).exit_code = 0 } },
        @{ mode = 'broker'; name = 'event without the reason'; act = { param($d) ($d.cases | Where-Object { $_.id -eq 'junction' }).events = @([ordered]@{ id = 21; message = 'purge-broker did not start: install_untrusted (exit code 21): other' }) } },
        @{ mode = 'broker'; name = 'refused case wrote the data root'; act = { param($d) ($d.cases | Where-Object { $_.id -eq 'kb-user-writable' }).data_root_changed = $true } },
        @{ mode = 'broker'; name = 'data root not compared'; act = { param($d) ($d.cases | Where-Object { $_.id -eq 'bad-args' }).data_root_changed = $null } },
        @{ mode = 'broker'; name = 'planted tree touched'; act = { param($d) ($d.cases | Where-Object { $_.id -eq 'env-planted' }).planted_changed = $true } },
        @{ mode = 'broker'; name = 'two refusals of three'; act = { param($d) $c = $d.cases | Where-Object { $_.id -eq 'client-image' }; $c.events[0].message = 'purge-broker ended: (exit code 25); refused clients: [client image is not Purge.exe in the install directory; client image is not Purge.exe in the install directory]' } },
        @{ mode = 'broker'; name = 'squatter not detected'; act = { param($d) ($d.cases | Where-Object { $_.id -eq 'pipe-squat' }).client.connects[0].server_check = 'ok' } },
        @{ mode = 'broker'; name = 'uac not silent'; act = { param($d) $d.uac.ConsentPromptBehaviorAdmin = 5 } },
        @{ mode = 'broker'; name = 'no uac-silent record'; act = { param($d) $d.uac_silent = $null } },
        @{ mode = 'broker'; name = 'uac-silent left LUA off'; act = { param($d) $d.uac_silent.after.EnableLUA = 0 } },
        @{ mode = 'consent'; name = 'uac-silent did not take'; act = { param($d) $d.uac_silent.ok = $false; $d.uac_silent.after.ConsentPromptBehaviorAdmin = 5 } },
        @{ mode = 'consent'; name = 'a medium attempt reached'; act = { param($d) $d.attacks[0].data.drive.attempts[1].reached = $true } },
        @{ mode = 'consent'; name = 'a medium effect (journal)'; act = { param($d) $d.attacks[5].data.effect_count = 1; $d.attacks[5].data.effects.journal_changed = $true } },
        @{ mode = 'consent'; name = 'medium driver ran high'; act = { param($d) $d.attacks[2].data.drive.driver_il = 'high' } },
        @{ mode = 'consent'; name = 'SendInput without the dialog in front'; act = { param($d) $d.attacks[0].data.drive.attempts[0].foreground_is_dialog = $false } },
        @{ mode = 'consent'; name = 'an attack record missing'; act = { param($d) $d.attacks = @($d.attacks | Select-Object -Skip 1) } },
        @{ mode = 'consent'; name = 'control not declined'; act = { param($d) $d.controls[3].data.declined = $false } },
        @{ mode = 'consent'; name = 'plan approval left no journal'; act = { param($d) $d.approves[1].data.journal_changed = $false } },
        @{ mode = 'consent'; name = 'no verification box'; act = { param($d) foreach ($a in $d.attacks) { if ($a.data.kind -eq 'plan.execute') { $a.data.pre = [ordered]@{ found = $true; broker_il = 'high'; verify = $null } } } } },
        @{ mode = 'consent'; name = 'screenshots missing'; shots = $true; act = { param($s) @($s | Where-Object { $_.name -notmatch 'control' }) } },
        @{ mode = 'uac'; name = 'no cancelled bar'; act = { param($d) $d.ui_result.bar_found = $false } },
        @{ mode = 'uac'; name = 'No gave a broker'; act = { param($d) $d.no.launch.broker_processes = @('C:\Program Files\Purge\purge-broker.exe') } },
        @{ mode = 'uac'; name = 'No not 1223'; act = { param($d) $d.no.launch.launched.error = 5 } },
        @{ mode = 'uac'; name = 'early click answered'; act = { param($d) $d.yes.arms[1].data.dialog_alive_after_early = $false } },
        @{ mode = 'uac'; name = 'early click too late'; act = { param($d) $d.yes.arms[0].data.early_click_ms = 1500 } },
        @{ mode = 'uac'; name = 'footer code differs'; act = { param($d) $d.yes.pages[0].data.footer_code = 'FFFF-0000' } },
        @{ mode = 'uac'; name = 'one page only'; act = { param($d) $d.yes.dialogs[1].data.pages = 1; $d.yes.dialogs[1].data.paged = $false } },
        @{ mode = 'uac'; name = 'page 2 not observed'; act = { param($d) $d.yes.pages = @() } },
        @{ mode = 'uac'; name = 'dialog not in front'; act = { param($d) $d.yes.dialogs[1].data.foreground = $false } },
        @{ mode = 'uac'; name = 'standard user served'; act = { param($d) $d.std.client.connects = @([ordered]@{ opened = $true; hello_answered = $true }) } },
        @{ mode = 'uac'; name = 'standard user pre-check missing'; act = { param($d) $d.std.client.precheck = 'limited_admin' } },
        @{ mode = 'uac'; name = 'uac off'; act = { param($d) $d.uac.ConsentPromptBehaviorAdmin = 0 } },
        @{ mode = 'uac'; name = 'a screenshot missing'; shots = $true; act = { param($s) @($s | Select-Object -Skip 1) } }
    )
}

function Invoke-SelfTest {
    $X = Get-Content -LiteralPath $ExpectFile -Raw | ConvertFrom-Json
    $root = Join-Path ([IO.Path]::GetTempPath()) ('m3-sec-score-selftest-' + [guid]::NewGuid().ToString('N'))
    $fails = 0; $checks = 0
    function Check([string]$Name, [bool]$Cond) { $script:checks++; if ($Cond) { Write-Host "ok   $Name" } else { $script:fails++; Write-Host "FAIL $Name" } }
    $script:checks = 0; $script:fails = 0
    try {
        # Builds an evidence directory for $M; $Defect (optional) changes the document or the shot list first.
        $build = {
            param([string]$M, $Defect)
            $dir = Join-Path $root ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Force (Join-Path $dir 'guest') | Out-Null
            $shots = @()
            switch ($M) {
                'broker' { $doc = New-BrokerPass $X; $file = 'm3-broker.json' }
                'consent' { $pair = New-ConsentPass $X $dir; $doc = $pair[0]; $shots = $pair[1]; $file = 'm3-consent.json' }
                'uac' { $pair = New-UacPass $X $dir; $doc = $pair[0]; $shots = $pair[1]; $file = 'm3-uac.json' }
            }
            # Round-trip through JSON so the defects edit the same object shapes the scorer reads.
            $doc = (ConvertTo-Json $doc -Depth 30) | ConvertFrom-Json
            if ($Defect) { if ($Defect.shots) { $shots = & $Defect.act $shots } else { & $Defect.act $doc } }
            Write-J $doc (Join-Path $dir "guest\$file")
            Write-J ([ordered]@{ mode = "m3-$M"; shots = @($shots) }) (Join-Path $dir 'summary.json')
            $dir
        }
        foreach ($m in 'broker', 'consent', 'uac') {
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
    } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "m3-sec-score self-test: $($script:checks - $script:fails)/$($script:checks) ok"
    if ($script:fails) { 1 } else { 0 }
}

if ($SelfTest) { exit (Invoke-SelfTest) }
if (-not $Mode -or -not $Evidence) { Write-Host 'usage: m3-sec-score.ps1 -Mode broker|consent|uac -Evidence <dir>  |  --self-test'; exit 2 }
$X = Get-Content -LiteralPath $ExpectFile -Raw | ConvertFrom-Json
$res = Invoke-Score $Mode $Evidence $X
if (Test-Path -LiteralPath $Evidence -PathType Container) {
    [IO.File]::WriteAllText((Join-Path $Evidence "score-$Mode.json"), (ConvertTo-Json $res -Depth 6), (New-Object Text.UTF8Encoding($false)))
}
if ($res.pass) { exit 0 } else { exit 1 }
