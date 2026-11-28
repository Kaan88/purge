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
    # -Mode consent: which consent dialog the run must have been of (package BROKER-CONSENT-UI). Every dialog that was
    # observed, attacked, controlled and approved must be of that renderer, by m3sec.exe's "flavour" (the window class);
    # a toolkit run in which the broker fell back to the TaskDialog proves nothing about the toolkit dialog and fails.
    [ValidateSet('taskdialog', 'toolkit')] [string] $ConsentUi = 'taskdialog',
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

# Every record of the run is of the renderer asked for. A record without a flavour (m3sec.exe from before the toolkit
# dialog) counts as the TaskDialog, which is all that tool could find.
function Test-ConsentFlavour($Doc, [string]$Want) {
    $flav = { param($f) if ("$f") { "$f" } else { 'taskdialog' } }
    $seen = @()
    foreach ($d in Arr $Doc.dialogs) { if ($d.data -and $d.data.found) { $seen += [ordered]@{ what = $d.file; flavour = (& $flav $d.data.flavour) } } }
    foreach ($a in Arr $Doc.attacks) {
        $seen += [ordered]@{ what = "$($a.file) pre"; flavour = (& $flav $a.data.pre.flavour) }
        $seen += [ordered]@{ what = "$($a.file) drive"; flavour = (& $flav $a.data.drive.flavour) }
    }
    foreach ($c in Arr $Doc.controls) { $seen += [ordered]@{ what = "$($c.file) drive"; flavour = (& $flav $c.data.drive.flavour) } }
    foreach ($p in Arr $Doc.approves) { $seen += [ordered]@{ what = "$($p.file) press"; flavour = (& $flav $p.data.press.flavour) } }
    # What the broker itself said it drew, in consent.shown ("ui":"toolkit", nothing for a TaskDialog): the rig's tool
    # tells the two apart by the window's class alone (review S10).
    foreach ($s in Arr $Doc.shown) { $seen += [ordered]@{ what = "$($s.file) broker"; flavour = (& $flav $s.data.params.ui) } }
    $other = @($seen | Where-Object { $_.flavour -ne $Want })
    Row "every dialog is the $Want dialog" ($seen.Count -gt 0 -and $other.Count -eq 0) $(if (-not $seen.Count) { 'no dialog record' } elseif ($other.Count) { "$($other.Count) of $($seen.Count) are not: $(@($other | Select-Object -First 4 | ForEach-Object { "$($_.what)=$($_.flavour)" }) -join '; ')" } else { "$($seen.Count) records" })
    if ($Want -eq 'toolkit') {
        $asked = "$($Doc.consent_ui)" -eq 'toolkit' -and "$($Doc.launched.args)" -match '--consent toolkit'
        Row 'the broker was started with --consent toolkit' $asked "consent_ui=$($Doc.consent_ui) args=$($Doc.launched.args)"
        # Found by its ids: the button, Cancel and the footer of every dialog, and on the plan dialog the box.
        $noids = @()
        foreach ($a in Arr $Doc.attacks) {
            $ids = @(Arr $a.data.pre.uia_ids)
            foreach ($need in 'ConsentApprove', 'ConsentCancel', 'ConsentFooter', 'ConsentList') { if ($ids -notcontains $need) { $noids += "$($a.file): $need" } }
            if ($a.data.kind -eq 'plan.execute' -and $ids -notcontains 'ConsentVerify') { $noids += "$($a.file): ConsentVerify" }
            if (-not ([int]$a.data.pre.lines -gt 0)) { $noids += "$($a.file): no ConsentLine_<n>" }
        }
        Row 'the toolkit dialog is read by its UI Automation ids (from high)' ($noids.Count -eq 0) $(if ($noids.Count) { "missing: $(@($noids | Select-Object -First 6) -join '; ')" } else { 'ConsentApprove, ConsentCancel, ConsentFooter, ConsentList, lines; ConsentVerify on the plan dialog' })
    }
}

# The code a dialog shows is the code the broker told its client (consent.shown) and, for a plan, the code plan.create
# gave: every dialog the rig observed from high, the approved one among them (review B3: a broker that drew another
# code passed this mode). $Kinds is the request of each k.
function Test-ConsentCode($Doc, $X, $Kinds) {
    $shown = @{}; foreach ($s in Arr $Doc.shown) { $shown[(Get-K $s.file)] = "$($s.data.params.code)".ToUpperInvariant() }
    $plan = @{}; foreach ($r in Arr $Doc.ready) { $plan[[int]$r.data.k] = "$($r.data.plan_code)".ToUpperInvariant() }
    $need = @(Arr $X.consent.methods).Count + 1
    foreach ($kind in Arr $X.consent.kinds) {
        $why = @(); $seen = @()
        foreach ($d in Arr $Doc.dialogs) {
            $k = Get-K $d.file
            if ("$($Kinds[$k])" -ne $kind -or -not ($d.data -and $d.data.found -eq $true)) { continue }
            $seen += $k
            $code = "$($d.data.footer_code)".ToUpperInvariant()
            if (-not $code) { $why += "dialog $k shows no code" }
            elseif (-not $shown.ContainsKey($k) -or $shown[$k] -ne $code) { $why += "dialog $k shows $code, consent.shown says '$($shown[$k])'" }
            elseif ($kind -eq 'plan.execute' -and "$($plan[$k])" -ne $code) { $why += "dialog $k shows $code, plan.create gave '$($plan[$k])'" }
        }
        if ($seen.Count -lt $need) { $why += "$($seen.Count) dialogs observed, expected at least $need" }
        $ap = @(Arr $Doc.approves | ForEach-Object { $_.data } | Where-Object { $_.kind -eq $kind }) | Select-Object -First 1
        if ($ap -and $seen -notcontains [int]$ap.k) { $why += "the approved dialog $($ap.k) was not observed" }
        Row "consent code $kind (the dialog, consent.shown$(if ($kind -eq 'plan.execute') { ', plan.create' }))" ($why.Count -eq 0) $(if ($why.Count) { @($why | Select-Object -First 4) -join '; ' } else { "$($seen.Count) dialogs" })
    }
}

# The names of the probes a toolkit run must make from medium, in m3sec.cs's words, derived from the lists of the
# expectations (review S-C: every message winit registers, never a count written by hand): SetProp and RemoveProp of
# each property, WM_GETOBJECT, and for each message one to the dialog's thread and a post and a send to each window.
function Get-ToolkitProbeNames($Lim) {
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($p in Arr $Lim.probe_props) { $names.Add("SetProp $p"); $names.Add("RemoveProp $p") }
    $names.Add('SendMessageTimeout WM_GETOBJECT (UiaRootObjectId)')
    foreach ($m in Arr $Lim.winit_messages) {
        $names.Add("PostThreadMessage $m to the dialog's thread")
        foreach ($w in Arr $Lim.probe_windows) { $names.Add("PostMessage $m to the $w window"); $names.Add("SendMessageTimeout $m to the $w window") }
    }
    $names.ToArray()
}

# What one internals control from high (m3sec drive internals control) says is wrong; empty when it passed.
function Get-ControlFaults($C, [string]$When) {
    if (-not $C) { return @("no control $When") }
    $w = @()
    if ($C.driver_il -ne 'high') { $w += "control $When at $($C.driver_il)" }
    if ($C.control_ok -ne $true) { $w += "from high $When the plain calls did not all work (no test): $(@(Arr $C.checks | Where-Object { $_.ok -ne $true } | ForEach-Object { $_.name }) -join '; ')" }
    $w
}

# What only a toolkit run has (review B3 and S1): the calls that must not even be accepted from medium, the dialog's
# own rules by real input from high, and the client lost while a dialog is up.
function Test-ConsentToolkit($Doc, $X) {
    $lim = $X.consent.toolkit
    # $early: the dialog may have been cancelled before it was on screen (Enter as it opens). The broker then sends no
    # consent.shown at all (review S2), which is right; one that was sent must still say toolkit.
    $nothing = { param($r, $kind, $early) $w = @()
        if (-not ($early -and -not $r.shown) -and "$($r.shown.params.ui)" -ne 'toolkit') { $w += "consent.shown did not say toolkit ('$($r.shown.params.ui)')" }
        if ($r.declined -ne $true) { $w += "not declined ($($r.result_kind))" }
        if ($r.cancelled_by_rig -ne $false) { $w += 'the rig had to cancel the dialog' }
        if ($r.journal_changed -ne $false) { $w += 'journal changed' }
        if ($kind -eq 'uninstall.run' -and $r.uninstaller_ran -ne $false) { $w += 'the uninstaller ran' }
        $w }
    $tool = { param($t) if (-not $t -or $t.found -ne $true) { 'dialog not found' } elseif ($t.not_toolkit -eq $true -or "$($t.flavour)" -ne 'toolkit') { "the dialog was the $($t.flavour) one" } }
    foreach ($kind in Arr $X.consent.kinds) {
        $p = @(Arr $Doc.probes | ForEach-Object { $_.data } | Where-Object { $_.kind -eq $kind }) | Select-Object -First 1
        $n = "medium $kind internals (winit's messages, AccessKit's property, WM_GETOBJECT)"
        if (-not $p) { Row $n $false 'no probe record' }
        else {
            $why = @()
            # The control from high before the medium probes and again after them (review S-B).
            $why += @(Get-ControlFaults $p.control 'before')
            $why += @(Get-ControlFaults $p.control_after 'after')
            if ($p.drive.driver_il -ne 'medium') { $why += "driver at $($p.drive.driver_il)" }
            if ("$($p.drive.flavour)" -ne 'toolkit') { $why += "the dialog was the $($p.drive.flavour) one" }
            # The tool probed the messages the expectations list, and every probe they ask for, once (review S-C).
            $wantNames = @(Get-ToolkitProbeNames $lim)
            if ((@(Arr $p.drive.winit_messages) -join '|') -ne (@(Arr $lim.winit_messages) -join '|')) { $why += "the tool probed the messages '$(@(Arr $p.drive.winit_messages) -join ', ')', expected '$(@(Arr $lim.winit_messages) -join ', ')'" }
            $tries = @(Arr $p.drive.attempts | Where-Object { -not $_.skipped })
            $skipped = @(Arr $p.drive.attempts | Where-Object { $_.skipped })
            if ($tries.Count -ne $wantNames.Count) { $why += "$($tries.Count) attempts, expected $($wantNames.Count) ($(@(Arr $lim.probe_props).Count) properties x 2, WM_GETOBJECT, $(@(Arr $lim.winit_messages).Count) messages x (the thread + $(@(Arr $lim.probe_windows).Count) windows x 2))" }
            $made = @($tries | ForEach-Object { "$($_.name)" })
            $missing = @($wantNames | Where-Object { $made -notcontains $_ })
            if ($missing.Count) { $why += "not probed: $(@($missing | Select-Object -First 3) -join '; ')$(if ($missing.Count -gt 3) { " and $($missing.Count - 3) more" })" }
            if ($skipped.Count) { $why += "skipped: $(@($skipped | Select-Object -First 3 | ForEach-Object { $_.name }) -join '; ')" }
            $reached = @($tries | Where-Object { $_.reached -ne $false })
            if ($reached.Count) { $why += "accepted: $(@($reached | Select-Object -First 4 | ForEach-Object { $_.name }) -join '; ')" }
            # Refused by UIPI, not failed for another reason: the call failed and its last error is ERROR_ACCESS_DENIED.
            $notDenied = @($tries | Where-Object { $_.call_succeeded -ne $false -or -not (Has $_ 'lasterror') -or "$($_.lasterror)" -ne "$($lim.probe_lasterror)" })
            if ($notDenied.Count) { $why += "not refused with $($lim.probe_lasterror): $(@($notDenied | Select-Object -First 3 | ForEach-Object { "$($_.name) (lasterror $(if (Has $_ 'lasterror') { $_.lasterror } else { 'not recorded' }))" }) -join '; ')" }
            # The three targets are still windows after the probes.
            $gone = @(Arr $lim.probe_windows | Where-Object { -not ($p.drive.alive_after -and (Has $p.drive.alive_after $_) -and $p.drive.alive_after.$_ -eq $true) })
            if ($gone.Count) { $why += "not a window after the probes: $($gone -join ', ')" }
            if (-not (Has $p 'effect_count') -or [int]$p.effect_count -ne 0) { $why += "effects: $(@($p.effects.PSObject.Properties | Where-Object { $_.Value -ne $false } | ForEach-Object { $_.Name }) -join ', ')" }
            Row $n ($why.Count -eq 0) $(if ($why.Count) { $why -join '; ' } else { "$($tries.Count) calls, each refused with $($lim.probe_lasterror), 0 accepted, 0 effects; the windows alive and the control passing after" })
        }

        $a = @(Arr $Doc.rule_arms | ForEach-Object { $_.data } | Where-Object { $_.kind -eq $kind }) | Select-Object -First 1
        $n = "high $kind rule: no press before the button is armed (early click, press held across the arming)"
        if (-not $a) { Row $n $false 'no record' }
        else {
            $t = $a.arm
            $why = @(& $tool $t)
            if (-not $why.Count) {
                if ($t.end_in_view -ne $true) { $why += 'the end of the list never came on screen' }
                # Review S-D: on a long kind the list must not fit, so that the end had to be scrolled to.
                if ((Arr $lim.long_kinds) -contains $kind -and $t.end_at_start -ne $false) { $why += 'the list fitted (end_at_start), so the end did not have to be scrolled to (no test of a long list)' }
                if (-not ((Has $t 'early_click_ms') -and [int]$t.early_click_ms -lt [int]$lim.early_click_max_ms)) { $why += "early click at '$($t.early_click_ms)' ms" }
                if ($t.primary_enabled_after_early -ne $false) { $why += 'the button was enabled at the early click' }
                if ($t.dialog_alive_after_early -ne $true -or $t.answered_after_early -ne $false) { $why += 'a click before the arming delay answered the dialog' }
                if ($t.hold_aborted -ne $false) { $why += 'no press was held from before the arming (no test)' }
                else {
                    if (-not ([int]$t.hold_down_ms -lt [int]$lim.hold_down_max_ms)) { $why += "press began at $($t.hold_down_ms) ms" }
                    if (-not ([int]$t.hold_up_ms -ge [int]$lim.hold_up_min_ms)) { $why += "press let go at $($t.hold_up_ms) ms" }
                    if ($t.primary_enabled_at_up -ne $true) { $why += 'the button was not armed when the press was let go (no test)' }
                    if ($t.dialog_alive_after_hold -ne $true -or $t.answered_after_hold -ne $false) { $why += 'a press held across the arming moment answered the dialog' }
                }
                if ($t.primary_enabled_late -ne $true) { $why += 'the button was not enabled after the delay' }
            }
            $why += @(& $nothing $a $kind $false)
            Row $n ($why.Count -eq 0) $(if ($why.Count) { $why -join '; ' } else { "click at $($t.early_click_ms) ms, press $($t.hold_down_ms)-$($t.hold_up_ms) ms: still up; then Esc: consent_declined" })
        }

        $e = @(Arr $Doc.rule_enters | ForEach-Object { $_.data } | Where-Object { $_.kind -eq $kind }) | Select-Object -First 1
        $n = "high $kind rule: Enter as the dialog opens cancels"
        if (-not $e) { Row $n $false 'no record' }
        else {
            $t = $e.arm
            $why = @(& $tool $t)
            if (-not $why.Count) {
                if ($t.foreground_at_enter -ne $true) { $why += 'the dialog was not in front (no test)' }
                if (-not ((Has $t 'enter_ms') -and [int]$t.enter_ms -lt [int]$lim.enter_max_ms)) { $why += "Enter at '$($t.enter_ms)' ms" }
                if ($t.dialog_alive_after_enter -ne $false) { $why += 'the dialog was still up after Enter' }
            }
            $why += @(& $nothing $e $kind $true)
            Row $n ($why.Count -eq 0) $(if ($why.Count) { $why -join '; ' } else { "Enter at $($t.enter_ms) ms: consent_declined" })
        }

        # Review S-D: the rules of a list that does not fit, on the long kinds only.
        if ((Arr $lim.long_kinds) -notcontains $kind) { continue }
        $unseenFaults = { param($t) $w = @()
            if ($t.end_at_start -ne $false) { $w += 'the list fitted (no test)' }
            if (-not ((Has $t 'unseen_ms') -and [int]$t.unseen_ms -ge [int]$lim.unseen_min_ms)) { $w += "up only '$($t.unseen_ms)' ms (no test of the dialog's own second having passed)" }
            if ($t.end_in_view_before -ne $false) { $w += 'the end was on screen before the input (no test)' }
            $w }
        $u = @(Arr $Doc.rule_unseens | ForEach-Object { $_.data } | Where-Object { $_.kind -eq $kind }) | Select-Object -First 1
        $n = "high $kind rule: up over a second, the end not seen: a real click on the button and on the box do nothing"
        if (-not $u) { Row $n $false 'no record' }
        else {
            $t = $u.arm
            $why = @(& $tool $t)
            if (-not $why.Count) {
                $why += @(& $unseenFaults $t)
                if ($t.primary_enabled_before -ne $false) { $why += 'the button was enabled before the end was seen' }
                if ($t.verify_enabled_before -ne $false) { $why += 'the box was enabled before the end was seen' }
                if ($t.has_primary -ne $true -or $t.has_verify -ne $true) { $why += "no rectangle to click (button $($t.has_primary), box $($t.has_verify)): no test" }
                if ($t.dialog_alive_after_primary -ne $true -or $t.answered_after_primary -ne $false) { $why += 'the click on the button answered the dialog' }
                if ($t.dialog_alive_after_verify -ne $true -or $t.answered_after_verify -ne $false) { $why += 'the click on the box answered the dialog' }
                if ("$($t.verify_after)" -ne 'Off') { $why += "the click ticked the box ($($t.verify_after))" }
                if ($t.primary_enabled_after -ne $false) { $why += 'the button was enabled after the clicks' }
            }
            $why += @(& $nothing $u $kind $false)
            Row $n ($why.Count -eq 0) $(if ($why.Count) { $why -join '; ' } else { "clicks at $($t.primary_click_ms) and $($t.verify_click_ms) ms: nothing; then Esc: consent_declined" })
        }

        $s = @(Arr $Doc.rule_tabspaces | ForEach-Object { $_.data } | Where-Object { $_.kind -eq $kind }) | Select-Object -First 1
        $n = "high $kind rule: Tab then Space, the end not seen, cancels"
        if (-not $s) { Row $n $false 'no record' }
        else {
            $t = $s.arm
            $why = @(& $tool $t)
            if (-not $why.Count) {
                $why += @(& $unseenFaults $t)
                if ($t.foreground_at_keys -ne $true) { $why += 'the dialog was not in front (no test)' }
                if ("$($t.focus_after_tab)" -ne 'ConsentCancel') { $why += "Tab put the keyboard on '$($t.focus_after_tab)', not Cancel" }
                if ($t.dialog_alive_after_space -ne $false) { $why += 'the dialog was still up after Space' }
            }
            $why += @(& $nothing $s $kind $false)
            Row $n ($why.Count -eq 0) $(if ($why.Count) { $why -join '; ' } else { "Tab: Cancel; Space at $($t.space_ms) ms: consent_declined" })
        }

        $b = @(Arr $Doc.rule_tabearlies | ForEach-Object { $_.data } | Where-Object { $_.kind -eq $kind }) | Select-Object -First 1
        $n = "high $kind rule: Tab does not reach the button inside the second after the end"
        if (-not $b) { Row $n $false 'no record' }
        else {
            $t = $b.arm
            $why = @(& $tool $t)
            if (-not $why.Count) {
                if ($t.end_at_start -ne $false) { $why += 'the list fitted (no test)' }
                if ($t.end_in_view -ne $true) { $why += 'the end of the list never came on screen' }
                if ($t.foreground_at_keys -ne $true) { $why += 'the dialog was not in front (no test)' }
                if ("$($t.focus_after_tab1)" -ne 'ConsentVerify') { $why += "the first Tab put the keyboard on '$($t.focus_after_tab1)', not the box (no test)" }
                if ("$($t.verify_after_space)" -ne 'On') { $why += "Space did not tick the box ($($t.verify_after_space)): no test" }
                if (-not ((Has $t 'tab2_ms') -and [int]$t.tab2_ms -lt [int]$lim.tab_early_max_ms)) { $why += "the second Tab at '$($t.tab2_ms)' ms (no test)" }
                if ("$($t.focus_after_tab2)" -eq 'ConsentApprove' -or $t.enter_withheld -ne $false) { $why += 'the second Tab reached the button before it was armed' }
                elseif ("$($t.focus_after_tab2)" -ne 'ConsentCancel') { $why += "the second Tab put the keyboard on '$($t.focus_after_tab2)', not Cancel" }
                if ($t.primary_enabled_at_tab2 -ne $false) { $why += 'the button was enabled at the second Tab' }
                if ($t.dialog_alive_after_enter -ne $false) { $why += 'the dialog was still up after Enter' }
            }
            $why += @(& $nothing $b $kind $false)
            Row $n ($why.Count -eq 0) $(if ($why.Count) { $why -join '; ' } else { "Tab: the box, Space: ticked, Tab at $($t.tab2_ms) ms: Cancel; Enter: consent_declined" })
        }
    }

    $kl = $Doc.kill
    $n = 'the client killed with a dialog up: the dialog goes, the broker ends, nothing ran'
    if (-not $kl) { Row $n $false 'no record' }
    else {
        $o = $kl.orphan
        $why = @()
        if (-not ($o -and $o.found -eq $true)) { $why += 'dialog not found' }
        else {
            if ("$($o.flavour)" -ne 'toolkit') { $why += "the dialog was the $($o.flavour) one" }
            if ($o.broker_il -ne 'high') { $why += "broker at $($o.broker_il)" }
            if ($o.dialog_up_before -ne $true) { $why += 'the dialog was not up before the kill' }
            if ($o.killed -ne $true) { $why += "the client was not ended ($($o.kill_error))" }
            if ($o.dialog_gone -ne $true -or [int]$o.dialog_gone_ms -gt [int]$lim.kill_dialog_gone_max_ms) { $why += "dialog gone=$($o.dialog_gone) after $($o.dialog_gone_ms) ms" }
            if ($o.broker_exited -ne $true -or [int]$o.broker_exit_ms -gt [int]$lim.kill_exit_max_ms) { $why += "broker exited=$($o.broker_exited) after $($o.broker_exit_ms) ms" }
            elseif ("$($o.exit_code)" -ne "$($lim.kill_exit_code)") { $why += "exit code $($o.exit_code)" }
        }
        if ("$($kl.shown.params.ui)" -ne 'toolkit') { $why += "consent.shown did not say toolkit ('$($kl.shown.params.ui)')" }
        if ($kl.broker_running -ne $false) { $why += 'the broker was still running' }
        if ($kl.journal_changed -ne $false) { $why += 'journal changed' }
        if ($kl.uninstaller_ran -ne $false) { $why += 'the uninstaller ran' }
        if ($kl.fixture_arp_present -ne $true) { $why += 'the program is no longer installed' }
        Row $n ($why.Count -eq 0) $(if ($why.Count) { $why -join '; ' } else { "dialog gone after $($o.dialog_gone_ms) ms, broker ended after $($o.broker_exit_ms) ms with $($o.exit_code)" })
    }
}

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
    Test-ConsentCode $doc $X $kinds
    Test-ConsentFlavour $doc $script:ConsentUi
    if ($script:ConsentUi -eq 'toolkit') { Test-ConsentToolkit $doc $X }
    $shots = @(if ($sum) { Get-Shots $Ev $sum })
    $patterns = @($X.consent.shot_patterns.PSObject.Properties)
    if ($script:ConsentUi -eq 'toolkit') { $patterns += @($X.consent.toolkit.shot_patterns.PSObject.Properties) }
    foreach ($p in $patterns) {
        $have = @($shots | Where-Object { $_ -match "-$([regex]::Escape($p.Name))" }).Count
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
    if (-not ($ur -and $ur.bar_found -eq $true)) { $why += 'no "You cancelled the Windows prompt." bar' }
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
    $ready = @(); $attacks = @(); $controls = @(); $approves = @(); $names = @(); $dialogs = @(); $shown = @()
    $k = 1
    # One dialog: what the client was told, what the rig read from high, and for a plan the code plan.create gave.
    $ask = {
        param([int]$K, [string]$Kind)
        $code = 'C0DE-{0:X4}' -f $K
        [ordered]@{
            ready = [ordered]@{ file = "ready-$K.json"; data = [ordered]@{ k = $K; method = $Kind; plan_code = $(if ($Kind -eq 'plan.execute') { $code.ToLowerInvariant() }) } }
            dialog = [ordered]@{ file = "dialog-$K.json"; data = [ordered]@{ found = $true; broker_il = 'high'; footer_code = $code } }
            shown = [ordered]@{ file = "consent-shown-$K.json"; data = [ordered]@{ params = [ordered]@{ kind = $Kind; code = $code } } }
        }
    }
    foreach ($kind in Arr $X.consent.kinds) {
        $pre = [ordered]@{ found = $true; broker_il = 'high'; verify = $(if ($kind -eq 'plan.execute') { [ordered]@{ toggle = 'Off' } }) }
        foreach ($m in Arr $X.consent.methods) {
            $tries = @(1..3 | ForEach-Object { [ordered]@{ name = "$m $_"; reached = $false; foreground_is_dialog = $true } })
            $attacks += [ordered]@{ file = "attack-$k-$m.json"; data = [ordered]@{ k = $k; kind = $kind; method = $m; drive = [ordered]@{ driver_il = 'medium'; attempts = $tries }; pre = $pre
                                    effects = [ordered]@{ dialog_gone = $false; answered = $false; journal_changed = $false }; effect_count = 0 } }
            $names += "c$k-$kind-attack-$m"
        }
        foreach ($m in Arr $X.consent.methods) {
            $one = & $ask $k $kind; $ready += $one.ready; $dialogs += $one.dialog; $shown += $one.shown
            $controls += [ordered]@{ file = "control-$k-$m.json"; data = [ordered]@{ k = $k; kind = $kind; method = $m; drive = [ordered]@{ driver_il = 'high' }; declined = $true; journal_changed = $false; uninstaller_ran = $false } }
            $names += "c$k-$kind-shown", "c$k-$kind-control-$m"
            $k++
        }
        $one = & $ask $k $kind; $ready += $one.ready; $dialogs += $one.dialog; $shown += $one.shown
        $approves += [ordered]@{ file = "approve-$k.json"; data = [ordered]@{ k = $k; kind = $kind; result_kind = 'result'; uninstaller_ran = $true; journal_changed = ($kind -eq 'plan.execute')
                                 response = [ordered]@{ result = [ordered]@{ outcome = 'complete' } } } }
        $names += "c$k-$kind-shown", "c$k-$kind-approved"
        $k++
        # What only a toolkit run photographs (more files than a TaskDialog run needs do no harm).
        $names += "c$k-$kind-probe", "c$k-$kind-rule-arm", "c$k-$kind-rule-enter", "c$k-$kind-rule-unseen", "c$k-$kind-rule-tabspace", "c$k-$kind-rule-tabearly"
    }
    $names += 'k00-client', 'k01-after-kill'
    $shots = New-Shots $Dir $names
    $doc = [ordered]@{ uac = [ordered]@{ ConsentPromptBehaviorAdmin = 0 }; uac_silent = [ordered]@{ ok = $true; before = [ordered]@{ ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1; EnableLUA = 1 }; after = [ordered]@{ ConsentPromptBehaviorAdmin = 0; PromptOnSecureDesktop = 1; EnableLUA = 1 } }; ready = $ready; attacks = $attacks; controls = $controls; approves = $approves
                       dialogs = $dialogs; shown = $shown }
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
        @{ mode = 'consent'; name = 'a dialog shows another code than consent.shown'; act = { param($d) $d.dialogs[2].data.footer_code = 'FFFF-0000' } },
        @{ mode = 'consent'; name = 'the approved plan dialog shows another code than plan.create'; act = { param($d) $last = $d.ready.Count - 1; $d.ready[$last].data.plan_code = 'ffff-0000' } },
        @{ mode = 'consent'; name = 'a dialog shows no code'; act = { param($d) $d.dialogs[0].data.footer_code = $null } },
        @{ mode = 'consent'; name = 'no consent.shown for a dialog'; act = { param($d) $d.shown = @($d.shown | Select-Object -Skip 1) } },
        @{ mode = 'consent'; name = 'the approved dialog was not observed'; act = { param($d) $d.dialogs = @($d.dialogs | Select-Object -First ($d.dialogs.Count - 1)) } },
        @{ mode = 'consent'; name = 'no dialog was observed'; act = { param($d) $d.dialogs = @() } },
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

# Turns a passing consent document into one of a toolkit run (-ConsentUi toolkit): every record of that renderer, the
# broker started with the argument, the dialog read by its ids.
function Set-ToolkitEvidence($d) {
    $d | Add-Member -NotePropertyName consent_ui -NotePropertyValue 'toolkit' -Force
    $d | Add-Member -NotePropertyName launched -NotePropertyValue ([pscustomobject]@{ args = '--pipe 0123 --parent 1 --parent-ctime 2 --consent toolkit' }) -Force
    foreach ($a in $d.attacks) {
        $ids = @('ConsentInstruction', 'ConsentList', 'ConsentFooter', 'ConsentApprove', 'ConsentCancel', 'ConsentClose')
        if ($a.data.kind -eq 'plan.execute') { $ids += 'ConsentVerify' }
        $a.data.pre | Add-Member -NotePropertyName flavour -NotePropertyValue 'toolkit' -Force
        $a.data.pre | Add-Member -NotePropertyName uia_ids -NotePropertyValue $ids -Force
        $a.data.pre | Add-Member -NotePropertyName lines -NotePropertyValue 9 -Force
        $a.data.drive | Add-Member -NotePropertyName flavour -NotePropertyValue 'toolkit' -Force
    }
    foreach ($c in $d.controls) { $c.data.drive | Add-Member -NotePropertyName flavour -NotePropertyValue 'toolkit' -Force }
    foreach ($a in $d.approves) { $a.data | Add-Member -NotePropertyName press -NotePropertyValue ([pscustomobject]@{ flavour = 'toolkit' }) -Force }
    # The broker says it drew them, and the toolkit run's own records: the probes, the two rules, the lost client.
    foreach ($s in $d.shown) { $s.data.params | Add-Member -NotePropertyName ui -NotePropertyValue 'toolkit' -Force }
    foreach ($g in $d.dialogs) { $g.data | Add-Member -NotePropertyName flavour -NotePropertyValue 'toolkit' -Force }
    $said = [ordered]@{ params = [ordered]@{ code = 'C0DE-0099'; ui = 'toolkit' } }
    $probes = @(); $arms = @(); $enters = @(); $unseens = @(); $tabspaces = @(); $tabearlies = @()
    $k = 90
    foreach ($kind in @($d.approves | ForEach-Object { $_.data.kind })) {
        $lim = $X.consent.toolkit
        $tries = @(Get-ToolkitProbeNames $lim | ForEach-Object { [ordered]@{ target = 'dialog'; name = $_; call_succeeded = $false; lasterror = 5; access_denied = $true; dialog_alive = $true; broker_alive = $true; answered = $false; reached = $false } })
        $alive = [ordered]@{}; foreach ($w in Arr $lim.probe_windows) { $alive[$w] = $true }
        $ctl = [ordered]@{ driver_il = 'high'; flavour = 'toolkit'; control_ok = $true; checks = @([ordered]@{ name = 'PostMessage WM_NULL to the dialog window'; ok = $true }) }
        $probes += [ordered]@{ file = "probe-$k.json"; data = [ordered]@{ k = $k; kind = $kind; method = 'internals'
                               control = $ctl; control_after = $ctl
                               drive = [ordered]@{ driver_il = 'medium'; flavour = 'toolkit'; winit_messages = @(Arr $lim.winit_messages); attempts = $tries; alive_after = $alive }
                               effects = [ordered]@{ dialog_gone = $false; hint_changed = $false; scroll_changed = $false; code_changed = $false; broker_gone = $false }; effect_count = 0 } }
        $none = [ordered]@{ kind = $kind; shown = $said; result_kind = 'consent_declined'; declined = $true; cancelled_by_rig = $false; journal_changed = $false; uninstaller_ran = $false }
        $arm = [ordered]@{ k = $k; rule = 'arm'; arm = [ordered]@{ found = $true; flavour = 'toolkit'; end_in_view = $true; early_click_ms = 252; primary_enabled_after_early = $false; dialog_alive_after_early = $true; answered_after_early = $false
                           hold_aborted = $false; hold_down_ms = 601; primary_enabled_at_down = $false; primary_enabled_at_up = $true; hold_up_ms = 1704; dialog_alive_after_hold = $true; answered_after_hold = $false
                           primary_enabled_late = $true; late_ms = 1810; dialog_alive_after_cancel = $false } }
        $enter = [ordered]@{ k = $k; rule = 'enter'; arm = [ordered]@{ found = $true; flavour = 'toolkit'; foreground_at_enter = $true; enter_ms = 140; dialog_alive_after_enter = $false; answered_after_enter = $true } }
        foreach ($key in $none.Keys) { $arm[$key] = $none[$key]; $enter[$key] = $none[$key] }
        $long = (Arr $lim.long_kinds) -contains $kind
        $arm.arm['end_at_start'] = -not $long
        $arms += [ordered]@{ file = "rule-arm-$k.json"; data = $arm }
        $enters += [ordered]@{ file = "rule-enter-$k.json"; data = $enter }
        if ($long) {
            # Review S-D: the three rules of a list that does not fit.
            $base = [ordered]@{ found = $true; flavour = 'toolkit'; end_at_start = $false; unseen_ms = 1302; end_in_view_before = $false }
            $u = [ordered]@{ k = $k; rule = 'unseen'; arm = [ordered]@{} }
            foreach ($key in $base.Keys) { $u.arm[$key] = $base[$key] }
            foreach ($pair in @(@('primary_enabled_before', $false), @('verify_enabled_before', $false), @('has_primary', $true), @('has_verify', $true), @('primary_click_ms', 1310),
                                @('dialog_alive_after_primary', $true), @('answered_after_primary', $false), @('verify_click_ms', 1820), @('dialog_alive_after_verify', $true),
                                @('answered_after_verify', $false), @('verify_after', 'Off'), @('primary_enabled_after', $false), @('dialog_alive_after_cancel', $false))) { $u.arm[$pair[0]] = $pair[1] }
            $s = [ordered]@{ k = $k; rule = 'tabspace'; arm = [ordered]@{} }
            foreach ($key in $base.Keys) { $s.arm[$key] = $base[$key] }
            foreach ($pair in @(@('foreground_at_keys', $true), @('focus_after_tab', 'ConsentCancel'), @('space_ms', 1460), @('dialog_alive_after_space', $false), @('answered_after_space', $true))) { $s.arm[$pair[0]] = $pair[1] }
            $e2 = [ordered]@{ k = $k; rule = 'tabearly'; arm = [ordered]@{ found = $true; flavour = 'toolkit'; end_at_start = $false; end_in_view = $true; foreground_at_keys = $true
                                                                  focus_after_tab1 = 'ConsentVerify'; verify_after_space = 'On'; tab2_ms = 190; focus_after_tab2 = 'ConsentCancel'
                                                                  primary_enabled_at_tab2 = $false; enter_withheld = $false; enter_ms = 260; dialog_alive_after_enter = $false; answered_after_enter = $true } }
            foreach ($key in $none.Keys) { $u[$key] = $none[$key]; $s[$key] = $none[$key]; $e2[$key] = $none[$key] }
            $unseens += [ordered]@{ file = "rule-unseen-$k.json"; data = $u }
            $tabspaces += [ordered]@{ file = "rule-tabspace-$k.json"; data = $s }
            $tabearlies += [ordered]@{ file = "rule-tabearly-$k.json"; data = $e2 }
        }
        $k++
    }
    $kill = [ordered]@{ consent_ui = 'toolkit'; kind = 'uninstall.run'; shown = $said
                        orphan = [ordered]@{ found = $true; flavour = 'toolkit'; broker_il = 'high'; dialog_up_before = $true; killed = $true; dialog_gone = $true; dialog_gone_ms = 180; broker_exited = $true; broker_exit_ms = 420; exit_code = 0 }
                        answered = $false; journal_changed = $false; uninstaller_ran = $false; fixture_arp_present = $true; broker_running = $false }
    # Through JSON, as the rest of the document was: the scorer and the defects see the shapes a guest file has.
    $more = (ConvertTo-Json ([ordered]@{ probes = $probes; rule_arms = $arms; rule_enters = $enters; rule_unseens = $unseens; rule_tabspaces = $tabspaces; rule_tabearlies = $tabearlies; kill = $kill }) -Depth 30) | ConvertFrom-Json
    foreach ($name in 'probes', 'rule_arms', 'rule_enters', 'rule_unseens', 'rule_tabspaces', 'rule_tabearlies', 'kill') { $d | Add-Member -NotePropertyName $name -NotePropertyValue $more.$name -Force }
}

# Single defects of a toolkit run; each must turn its passing evidence into a FAIL under -ConsentUi toolkit.
function Get-ToolkitDefects {
    @(
        @{ name = 'the broker fell back to the TaskDialog for one dialog'; act = { param($d) $d.attacks[3].data.drive.flavour = 'taskdialog' } },
        @{ name = 'a control drove a TaskDialog'; act = { param($d) $d.controls[2].data.drive.flavour = 'taskdialog' } },
        @{ name = 'the approval was of a TaskDialog'; act = { param($d) $d.approves[0].data.press.flavour = 'taskdialog' } },
        @{ name = 'an approval without a flavour'; act = { param($d) $d.approves[1].data.press = [pscustomobject]@{ found = $true } } },
        @{ name = 'the broker was not started with --consent toolkit'; act = { param($d) $d.launched.args = '--pipe 0123 --parent 1 --parent-ctime 2' } },
        @{ name = 'the button has no id'; act = { param($d) $d.attacks[0].data.pre.uia_ids = @('ConsentCancel', 'ConsentFooter', 'ConsentList') } },
        @{ name = 'the plan dialog has no box id'; act = { param($d) foreach ($a in $d.attacks) { $a.data.pre.uia_ids = @($a.data.pre.uia_ids | Where-Object { $_ -ne 'ConsentVerify' }) } } },
        @{ name = 'no line of the list was read'; act = { param($d) $d.attacks[1].data.pre.lines = 0 } },
        @{ name = 'a medium attempt reached the toolkit dialog'; act = { param($d) $d.attacks[6].data.drive.attempts[0].reached = $true } },
        @{ name = 'the broker said TaskDialog for a dialog found as the toolkit one'; act = { param($d) $d.shown[4].data.params.PSObject.Properties.Remove('ui') } },
        @{ name = 'no probe record of the plan dialog'; act = { param($d) $d.probes = @($d.probes | Where-Object { $_.data.kind -ne 'plan.execute' }) } },
        @{ name = 'a probe call was accepted from medium'; act = { param($d) $d.probes[0].data.drive.attempts[7].call_succeeded = $true; $d.probes[0].data.drive.attempts[7].reached = $true } },
        @{ name = 'the plain calls from high did not work'; act = { param($d) $d.probes[1].data.control.control_ok = $false; $d.probes[1].data.control.checks[0].ok = $false } },
        @{ name = 'a probe was skipped'; act = { param($d) $d.probes[0].data.drive.attempts[3] | Add-Member -NotePropertyName skipped -NotePropertyValue $true } },
        @{ name = 'too few probes'; act = { param($d) $d.probes[1].data.drive.attempts = @($d.probes[1].data.drive.attempts | Select-Object -First 12) } },
        # Review S-B: a refusal that is not UIPI's, the windows after, the control after.
        @{ name = 'a probe failed with another error than access denied'; act = { param($d) $d.probes[0].data.drive.attempts[9].lasterror = 1400; $d.probes[0].data.drive.attempts[9].access_denied = $false } },
        @{ name = 'a probe without its last error'; act = { param($d) $d.probes[1].data.drive.attempts[2].PSObject.Properties.Remove('lasterror') } },
        @{ name = 'a probe whose call succeeded but was not counted as reached'; act = { param($d) $d.probes[0].data.drive.attempts[4].call_succeeded = $true } },
        @{ name = 'the contrast window was gone after the probes'; act = { param($d) $d.probes[0].data.drive.alive_after.contrast = $false } },
        @{ name = 'no record of the windows after the probes'; act = { param($d) $d.probes[1].data.drive.PSObject.Properties.Remove('alive_after') } },
        @{ name = 'no control after the probes'; act = { param($d) $d.probes[0].data.control_after = $null } },
        @{ name = 'the plain calls from high did not work after the probes'; act = { param($d) $d.probes[1].data.control_after = [pscustomobject]@{ driver_il = 'high'; control_ok = $false; checks = @([pscustomobject]@{ name = 'PostMessage WM_NULL to the event-target window'; ok = $false }) } } },
        # Review S-C: every registered message, the count derived from the list.
        @{ name = 'TaskbarCreated was not probed'; act = { param($d) $d.probes[0].data.drive.attempts = @($d.probes[0].data.drive.attempts | Where-Object { $_.name -notmatch 'TaskbarCreated' }) } },
        @{ name = 'the tool probed only three of winit''s messages'; act = { param($d) $d.probes[1].data.drive.winit_messages = @('Winit::WakeupMsg', 'Winit::DestroyMsg', 'Winit::ExecMsg') } },
        @{ name = 'one probe made twice in place of another'; act = { param($d) $a = $d.probes[0].data.drive.attempts; $a[$a.Count - 1].name = $a[0].name } },
        @{ name = 'a probe more than the list asks for'; act = { param($d) $a = @($d.probes[1].data.drive.attempts); $d.probes[1].data.drive.attempts = $a + @($a[0]) } },
        @{ name = 'the probes ran from high'; act = { param($d) $d.probes[0].data.drive.driver_il = 'high' } },
        @{ name = 'the probes ended the broker'; act = { param($d) $d.probes[0].data.effects.broker_gone = $true; $d.probes[0].data.effect_count = 1 } },
        @{ name = 'the probes were of a TaskDialog'; act = { param($d) $d.probes[1].data.drive.flavour = 'taskdialog' } },
        @{ name = 'no arming record'; act = { param($d) $d.rule_arms = @() } },
        @{ name = 'the early click answered the dialog'; act = { param($d) $d.rule_arms[0].data.arm.dialog_alive_after_early = $false; $d.rule_arms[0].data.arm.answered_after_early = $true } },
        @{ name = 'the button was enabled at the early click'; act = { param($d) $d.rule_arms[1].data.arm.primary_enabled_after_early = $true } },
        @{ name = 'the early click came late'; act = { param($d) $d.rule_arms[0].data.arm.early_click_ms = 1100 } },
        @{ name = 'the end of the list was never on screen'; act = { param($d) $d.rule_arms[1].data.arm.end_in_view = $false } },
        @{ name = 'the held press began on an armed button'; act = { param($d) $d.rule_arms[0].data.arm.hold_aborted = $true } },
        @{ name = 'no press was held'; act = { param($d) $d.rule_arms[0].data.arm.PSObject.Properties.Remove('hold_aborted') } },
        @{ name = 'the held press was let go before the arming'; act = { param($d) $d.rule_arms[1].data.arm.hold_up_ms = 800; $d.rule_arms[1].data.arm.primary_enabled_at_up = $false } },
        @{ name = 'the held press approved'; act = { param($d) $d.rule_arms[1].data.arm.answered_after_hold = $true; $d.rule_arms[1].data.result_kind = 'result'; $d.rule_arms[1].data.declined = $false } },
        @{ name = 'the held press closed the dialog'; act = { param($d) $d.rule_arms[0].data.arm.dialog_alive_after_hold = $false } },
        @{ name = 'the button never armed'; act = { param($d) $d.rule_arms[0].data.arm.primary_enabled_late = $false } },
        @{ name = 'the arming test was of a TaskDialog'; act = { param($d) $d.rule_arms[0].data.arm = [pscustomobject]@{ found = $true; flavour = 'taskdialog'; not_toolkit = $true } } },
        @{ name = 'the arming test ran the uninstaller'; act = { param($d) $d.rule_arms[0].data.uninstaller_ran = $true } },
        @{ name = 'the rig had to cancel after the arming test'; act = { param($d) $d.rule_arms[1].data.cancelled_by_rig = $true } },
        @{ name = 'no Enter record of the uninstall dialog'; act = { param($d) $d.rule_enters = @($d.rule_enters | Where-Object { $_.data.kind -ne 'uninstall.run' }) } },
        @{ name = 'Enter approved'; act = { param($d) $d.rule_enters[1].data.result_kind = 'result'; $d.rule_enters[1].data.declined = $false; $d.rule_enters[1].data.journal_changed = $true } },
        @{ name = 'Enter went to another window'; act = { param($d) $d.rule_enters[0].data.arm.foreground_at_enter = $false } },
        @{ name = 'Enter left the dialog up'; act = { param($d) $d.rule_enters[0].data.arm.dialog_alive_after_enter = $true; $d.rule_enters[0].data.cancelled_by_rig = $true } },
        @{ name = 'Enter came late'; act = { param($d) $d.rule_enters[1].data.arm.enter_ms = 2400 } },
        @{ name = 'the broker said TaskDialog for the Enter dialog'; act = { param($d) $d.rule_enters[0].data.shown.params.PSObject.Properties.Remove('ui') } },
        @{ name = 'the broker did not say toolkit for the arming dialog'; act = { param($d) $d.rule_arms[0].data.shown = $null } },
        # Review S-D: the long list and the rules made on it.
        @{ name = 'the plan dialog''s arming test was on a list that fitted'; act = { param($d) ($d.rule_arms | Where-Object { $_.data.kind -eq 'plan.execute' }).data.arm.end_at_start = $true } },
        @{ name = 'no unseen record'; act = { param($d) $d.rule_unseens = @() } },
        @{ name = 'the unseen test came inside the first second'; act = { param($d) $d.rule_unseens[0].data.arm.unseen_ms = 700 } },
        @{ name = 'the unseen test was on a list that fitted'; act = { param($d) $d.rule_unseens[0].data.arm.end_at_start = $true } },
        @{ name = 'a click on the disabled button answered'; act = { param($d) $d.rule_unseens[0].data.arm.dialog_alive_after_primary = $false; $d.rule_unseens[0].data.arm.answered_after_primary = $true } },
        @{ name = 'a click on the disabled box ticked it'; act = { param($d) $d.rule_unseens[0].data.arm.verify_after = 'On' } },
        @{ name = 'the button was enabled with the end not seen'; act = { param($d) $d.rule_unseens[0].data.arm.primary_enabled_before = $true } },
        @{ name = 'the box had no rectangle to click'; act = { param($d) $d.rule_unseens[0].data.arm.has_verify = $false } },
        @{ name = 'the unseen test approved'; act = { param($d) $d.rule_unseens[0].data.result_kind = 'result'; $d.rule_unseens[0].data.declined = $false; $d.rule_unseens[0].data.journal_changed = $true } },
        @{ name = 'no Tab-Space record'; act = { param($d) $d.rule_tabspaces = @() } },
        @{ name = 'Tab went to the box with the end not seen'; act = { param($d) $d.rule_tabspaces[0].data.arm.focus_after_tab = 'ConsentVerify' } },
        @{ name = 'Tab-Space left the dialog up'; act = { param($d) $d.rule_tabspaces[0].data.arm.dialog_alive_after_space = $true; $d.rule_tabspaces[0].data.cancelled_by_rig = $true } },
        @{ name = 'Tab-Space went to another window'; act = { param($d) $d.rule_tabspaces[0].data.arm.foreground_at_keys = $false } },
        @{ name = 'no early-Tab record'; act = { param($d) $d.rule_tabearlies = @() } },
        @{ name = 'the second Tab reached the button early'; act = { param($d) $d.rule_tabearlies[0].data.arm.focus_after_tab2 = 'ConsentApprove'; $d.rule_tabearlies[0].data.arm.enter_withheld = $true } },
        @{ name = 'the second Tab came after the second'; act = { param($d) $d.rule_tabearlies[0].data.arm.tab2_ms = 1300 } },
        @{ name = 'Space did not tick the box before the second Tab'; act = { param($d) $d.rule_tabearlies[0].data.arm.verify_after_space = 'Off' } },
        @{ name = 'the early-Tab test was on a list that fitted'; act = { param($d) $d.rule_tabearlies[0].data.arm.end_at_start = $true } },
        @{ name = 'the button was enabled at the second Tab'; act = { param($d) $d.rule_tabearlies[0].data.arm.primary_enabled_at_tab2 = $true } },
        @{ name = 'Enter after the early Tab approved'; act = { param($d) $d.rule_tabearlies[0].data.result_kind = 'result'; $d.rule_tabearlies[0].data.declined = $false } },
        @{ name = 'no screenshot of the unseen test'; shots_act = { param($s) @($s | Where-Object { $_.name -notmatch 'rule-unseen' }) }; act = { param($d) } },
        @{ name = 'no record of the lost client'; act = { param($d) $d.kill = $null } },
        @{ name = 'the dialog stayed after the client was lost'; act = { param($d) $d.kill.orphan.dialog_gone = $false; $d.kill.orphan.dialog_gone_ms = -1 } },
        @{ name = 'the dialog went too late'; act = { param($d) $d.kill.orphan.dialog_gone_ms = 9000 } },
        @{ name = 'the broker stayed after the client was lost'; act = { param($d) $d.kill.orphan.broker_exited = $false; $d.kill.orphan.broker_exit_ms = -1; $d.kill.broker_running = $true } },
        @{ name = 'the broker ended with a failure code'; act = { param($d) $d.kill.orphan.exit_code = 101 } },
        @{ name = 'the client was not ended'; act = { param($d) $d.kill.orphan.killed = $false } },
        @{ name = 'the lost client''s request ran the uninstaller'; act = { param($d) $d.kill.uninstaller_ran = $true; $d.kill.fixture_arp_present = $false } },
        @{ name = 'the lost client''s dialog was a TaskDialog'; act = { param($d) $d.kill.orphan.flavour = 'taskdialog' } },
        @{ name = 'no screenshot of the probes'; shots_act = { param($s) @($s | Where-Object { $_.name -notmatch '-probe' }) }; act = { param($d) } },
        @{ name = 'no screenshot after the kill'; shots_act = { param($s) @($s | Where-Object { $_.name -notmatch 'after-kill' }) }; act = { param($d) } }
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
            if ($Defect -and $Defect.shots_act) { $shots = & $Defect.shots_act $shots }
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
        # The toolkit consent dialog (-ConsentUi toolkit): the same rows, and every record of that renderer.
        $asked = $script:ConsentUi
        try {
            $toolkit = @{ act = { param($d) Set-ToolkitEvidence $d } }
            Check 'consent toolkit evidence fails as a TaskDialog run' (-not (Invoke-Score 'consent' (& $build 'consent' $toolkit) $X -Quiet).pass)
            $script:ConsentUi = 'toolkit'
            $r = Invoke-Score 'consent' (& $build 'consent' $toolkit) $X -Quiet
            Check 'consent toolkit synthetic pass passes' $r.pass
            if (-not $r.pass) { foreach ($row in $r.rows) { if (-not $row.ok) { Write-Host "       $($row.row): $($row.detail)" } } }
            Check 'consent TaskDialog evidence fails as a toolkit run' (-not (Invoke-Score 'consent' (& $build 'consent' $null) $X -Quiet).pass)
            # Enter that cancelled a dialog before it was on screen: no consent.shown was sent, and that is no defect.
            $unseen = @{ act = { param($d) Set-ToolkitEvidence $d; $d.rule_enters[0].data.shown = $null } }
            Check 'consent toolkit: Enter before the dialog was shown (no consent.shown) passes' (Invoke-Score 'consent' (& $build 'consent' $unseen) $X -Quiet).pass
            foreach ($d in Get-ToolkitDefects) {
                $both = @{ act = [scriptblock]::Create('param($d) Set-ToolkitEvidence $d; & { ' + $d.act.ToString() + ' } $d'); shots_act = $d.shots_act }
                $r = Invoke-Score 'consent' (& $build 'consent' $both) $X -Quiet
                Check "consent toolkit defect '$($d.name)' fails" (-not $r.pass)
            }
        } finally { $script:ConsentUi = $asked }
    } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "m3-sec-score self-test: $($script:checks - $script:fails)/$($script:checks) ok"
    if ($script:fails) { 1 } else { 0 }
}

if ($SelfTest) { exit (Invoke-SelfTest) }
if (-not $Mode -or -not $Evidence) { Write-Host 'usage: m3-sec-score.ps1 -Mode broker|consent|uac -Evidence <dir> [-ConsentUi taskdialog|toolkit]  |  --self-test'; exit 2 }
$X = Get-Content -LiteralPath $ExpectFile -Raw | ConvertFrom-Json
$res = Invoke-Score $Mode $Evidence $X
if (Test-Path -LiteralPath $Evidence -PathType Container) {
    [IO.File]::WriteAllText((Join-Path $Evidence "score-$Mode.json"), (ConvertTo-Json $res -Depth 6), (New-Object Text.UTF8Encoding($false)))
}
if ($res.pass) { exit 0 } else { exit 1 }
