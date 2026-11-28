# Purge rig: the host-side probe of the broker's toolkit consent dialog (package BROKER-CONSENT-UI, M3_DESIGN 8.3),
# before the VM mode m3-consent -ConsentUi toolkit is run against the real, elevated broker. It needs no VM, no broker
# and no elevation, and nothing it presses can run anything: the dialog is the preview harness's
# (bins\purge-broker\examples\consent_preview.rs), which draws the real dialog from sample views and prints its answers.
#
# What it checks: that m3sec.exe (vm\guest\m3sec.cs, built here with the guest's csc line) finds the toolkit dialog,
# reads it by its UI Automation ids and drives it, with the driver and the dialog at the SAME integrity level. That is
# the rig's "high control" row: every method reaches the dialog when UIPI is not in the way. So when the VM run then
# shows 0 of the medium attempts reaching the high dialog, it is UIPI that stopped them and not a driver that cannot
# press this dialog. It is NOT the T1 test itself: that needs the elevated broker and a medium driver (the VM).
#
# The last part asks through the broker's own consent service (consent_preview --service: the real ToolkitConsent on a
# second thread and its window on the first, as under --consent toolkit), approves and cancels through it, and fires the
# closer while a dialog is up.
#
# By default only the methods that are aimed at the dialog's own window are run (uia, postmessage). -WithInput also
# runs sendinput-key and sendinput-mouse, which move the real pointer and type real keys on this desktop: use it only
# with nobody at the keyboard and nothing else in front.
#
# Each check prints PASS or FAIL. Exit code: 0 when nothing FAILs, 1 otherwise.
#
# The preview waits -GapMs between an answer and its next dialog, as the rig's client does not ask again until the
# agent says so: m3sec.exe takes a dialog for answered when its window is gone 1.2 s after an attempt.
#
#   powershell -NoProfile -File vm\guest\tests\consent-ui-probe.ps1 [-Preview <consent_preview.exe>] [-Work <dir>] [-GapMs <n>] [-WithInput]
param(
    [string]$Preview = 'E:\purge-target\consent\release\examples\consent_preview.exe',
    [string]$Work = '',
    [int]$GapMs = 8000,
    [switch]$WithInput
)
$ErrorActionPreference = 'Stop'
$Guest = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath $Preview)) { Write-Host "no preview at $Preview (cargo build --release -p purge-broker --example consent_preview)"; exit 2 }
if (-not $Work) { $Work = Join-Path ([IO.Path]::GetTempPath()) ('consent-ui-probe-' + [guid]::NewGuid().ToString('N')) }
New-Item -ItemType Directory -Force $Work | Out-Null

$results = New-Object System.Collections.ArrayList
function Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
    [void]$results.Add([ordered]@{ ok = $Ok; check = $Name; detail = $Detail })
    "{0,-5} {1}{2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $(if ($Detail) { " -- $Detail" } else { '' })
}
function Read-J([string]$Path) { if (Test-Path -LiteralPath $Path) { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } }
function Write-J($Obj, [string]$Path) { [IO.File]::WriteAllText($Path, (ConvertTo-Json $Obj -Depth 8), (New-Object Text.UTF8Encoding($false))) }

# ---- the rig tool, built as the guest builds it (m3-sec.ps1, phase build)
$Exe = Join-Path $Work 'm3sec.exe'
$fw = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$wpf = Join-Path $fw 'WPF'
$o = & (Join-Path $fw 'csc.exe') /nologo /target:winexe /platform:x64 /optimize "/out:$Exe" "/r:$wpf\UIAutomationClient.dll" "/r:$wpf\UIAutomationTypes.dll" `
    "/r:$wpf\WindowsBase.dll" '/r:System.Web.Extensions.dll' '/r:System.Windows.Forms.dll' '/r:System.Drawing.dll' (Join-Path $Guest 'm3sec.cs') 2>&1
Check 'm3sec.cs builds with the guest''s csc line' (Test-Path -LiteralPath $Exe) (@($o) -join ' ')
if (-not (Test-Path -LiteralPath $Exe)) { exit 1 }
function Invoke-Sec([string[]]$A, [int]$Sec = 60) {
    $p = Start-Process -FilePath $Exe -ArgumentList ($A | ForEach-Object { '"' + $_ + '"' }) -PassThru -WindowStyle Hidden
    if (-not $p.WaitForExit($Sec * 1000)) { try { $p.Kill() } catch { }; return -1 }
    $p.ExitCode
}

# ---- the preview: one process, the named samples one after another in its one window
$script:Proc = $null; $script:Log = $null
function Start-Preview([string]$Samples, [string]$Name, [string[]]$Extra = @()) {
    $script:Log = Join-Path $Work "preview-$Name.log"
    Remove-Item -LiteralPath $script:Log -Force -ErrorAction SilentlyContinue
    $script:Proc = Start-Process -FilePath $Preview -ArgumentList (@($Samples, '--theme', 'light', '--gap', "$GapMs") + $Extra) -PassThru -RedirectStandardOutput $script:Log -RedirectStandardError (Join-Path $Work "preview-$Name.err") -WindowStyle Normal
}
function Stop-Preview { if ($script:Proc -and -not $script:Proc.HasExited) { try { $script:Proc.Kill() } catch { } }; $script:Proc = $null }
function Get-Lines { if (Test-Path -LiteralPath $script:Log) { @(Get-Content -LiteralPath $script:Log -ErrorAction SilentlyContinue) } else { @() } }
# Waits until the log holds $Count lines that match.
function Wait-Lines([string]$Pattern, [int]$Count, [int]$Sec = 20) {
    $d = (Get-Date).AddSeconds($Sec)
    while ((Get-Date) -lt $d) {
        if (@(Get-Lines | Where-Object { $_ -match $Pattern }).Count -ge $Count) { return $true }
        Start-Sleep -Milliseconds 200
    }
    $false
}
function Invoke-Observe([string]$Name, [int]$WaitMs = 10000) {
    $f = Join-Path $Work "$Name.json"
    Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    $null = Invoke-Sec @('observe', "$($script:Proc.Id)", $f, "$WaitMs")
    Read-J $f
}
function Invoke-Drive([string]$Name, [string]$Method, [string]$Mode, [string[]]$Targets, $Seen) {
    $seenFile = Join-Path $Work "$Name-seen.json"
    Write-J $Seen $seenFile
    $spec = [ordered]@{ out = (Join-Path $Work "$Name.json"); broker_pid = $script:Proc.Id; method = $Method; mode = $Mode; targets = @($Targets); seen = $seenFile }
    $sp = Join-Path $Work "$Name-spec.json"
    Write-J $spec $sp
    Remove-Item -LiteralPath $spec.out -Force -ErrorAction SilentlyContinue
    $null = Invoke-Sec @('drive', $sp) 120
    Read-J $spec.out
}
function Invoke-Press([string]$Name, [bool]$Tick, [int]$Button, [int]$ArmWaitMs) {
    $spec = [ordered]@{ out = (Join-Path $Work "$Name.json"); broker_pid = $script:Proc.Id; tick = $Tick; button = $Button; arm_wait_ms = $ArmWaitMs; wait_ms = 15000 }
    $sp = Join-Path $Work "$Name-spec.json"
    Write-J $spec $sp
    Remove-Item -LiteralPath $spec.out -Force -ErrorAction SilentlyContinue
    $null = Invoke-Sec @('press', $sp) 60
    Read-J $spec.out
}

try {
    # ---- 1. observe: the plan dialog with attention entries (a box), read by its ids
    $methods = @('uia', 'postmessage') + $(if ($WithInput) { @('sendinput-key', 'sendinput-mouse') } else { @() })
    $n = $methods.Count
    Start-Preview ((@('restore') * ($n + 4)) -join ',') 'matrix'
    Check 'the preview shows its first dialog' (Wait-Lines '^shown: restore' 1 30)
    $d = Invoke-Observe 'observe-1'
    Check 'observe: found, and told apart from a TaskDialog' ($d -and $d.found -eq $true -and $d.flavour -eq 'toolkit') "flavour=$($d.flavour) class=$($d.window.class)"
    $ids = @($d.uia_ids)
    $need = @('ConsentInstruction', 'ConsentList', 'ConsentVerify', 'ConsentFooter', 'ConsentApprove', 'ConsentCancel', 'ConsentClose')
    $miss = @($need | Where-Object { $ids -notcontains $_ })
    Check 'observe: every part has its UI Automation id' ($miss.Count -eq 0) $(if ($miss.Count) { "missing $($miss -join ', ')" } else { $need -join ', ' })
    Check 'observe: the lines of the list are list items' ([int]$d.lines -ge 8) "lines=$($d.lines)"
    Check 'observe: the footer code is read' ("$($d.footer_code)" -match '^[0-9A-F]{4}-[0-9A-F]{4}$') "code=$($d.footer_code)"
    Check 'observe: the attention count is read' ([int]$d.attention_total -eq 2) "attention=$($d.attention_total)"
    Check 'observe: the box is there and not ticked' ($d.verify -and $d.verify.toggle -eq 'Off') "toggle=$(if ($d.verify) { $d.verify.toggle })"
    Check 'observe: the button is there, disabled until the box is ticked' ($d.has_primary -eq $true -and $d.primary_enabled -eq $false) "primary=$($d.has_primary)/$($d.primary_enabled)"
    Check 'observe: Cancel is there; no Next or Back' ($d.has_cancel -eq $true -and $d.has_next -eq $false -and $d.has_back -eq $false)
    Check 'observe: the button, Cancel and the box have rectangles' ($d.rects.primary -and $d.rects.cancel -and $d.rects.verify) "primary=$($d.rects.primary -join ',') cancel=$($d.rects.cancel -join ',') verify=$($d.rects.verify -join ',')"
    Check 'observe: a list that fits has its end on screen, and its box takes a tick' ($d.end_in_view -eq $true -and $d.verify.enabled -eq $true -and @($d.lines_in_view).Count -eq 2) "end=$($d.end_in_view) box_enabled=$(if ($d.verify) { $d.verify.enabled }) lines_in_view=$(@($d.lines_in_view) -join '-')"
    Check 'observe: the labels are the view''s' ($d.labels.primary -eq 'Restore 3 items' -and $d.labels.cancel -eq 'Cancel') "primary='$($d.labels.primary)' cancel='$($d.labels.cancel)'"

    # ---- 2. the control: Cancel by every method reaches the dialog (a new one follows in the same window)
    $k = 1
    foreach ($m in $methods) {
        $seen = Invoke-Observe "cpre-$m"
        $dr = Invoke-Drive "control-$m" $m 'control' @() $seen
        $ok = Wait-Lines '^answered: restore: Declined' $k 15
        Check "control $m`: Cancel reaches the dialog (Declined)" ($ok -and $dr -and $dr.flavour -eq 'toolkit' -and $dr.reached -eq $true) "reached=$($dr.reached) attempts=$(@($dr.attempts | ForEach-Object { $_.name }) -join '; ')"
        $k++
        Check "control $m`: the next dialog comes up in the same window" (Wait-Lines '^shown: restore' $k 15)
    }

    # ---- 3. the attempts of an attack, at the same level: each must be able to work (they are what the VM blocks)
    # On a fresh dialog (Cancel has the keyboard, the box is off) the three posted attempts on the box are: keys Tab,
    # Space (on), a posted click (off), a sent click (on).
    $seen = Invoke-Observe 'apre-post'
    $dr = Invoke-Drive 'attack-post-verify' 'postmessage' 'attack' @('verify') $seen
    $after = Invoke-Observe 'apost-post'
    Check 'attack postmessage: posted keys and clicks toggle the box (on, off, on)' ($after.verify -and $after.verify.toggle -eq 'On' -and @($dr.attempts).Count -eq 3) "toggle=$(if ($after.verify) { $after.verify.toggle }) attempts=$(@($dr.attempts | ForEach-Object { $_.name }) -join '; ')"
    $dr = Invoke-Drive 'attack-uia-verify' 'uia' 'attack' @('verify') $after
    $after2 = Invoke-Observe 'apost-uia'
    Check 'attack uia: the tree is listed and TogglePattern toggles the box (off)' ($after2.verify -and $after2.verify.toggle -eq 'Off') "toggle=$(if ($after2.verify) { $after2.verify.toggle }) attempts=$(@($dr.attempts | ForEach-Object { $_.name }) -join '; ')"
    $null = Invoke-Drive 'attack-uia-verify-2' 'uia' 'attack' @('verify') $after2
    $armed = Invoke-Observe 'aarmed'
    Check 'the button is enabled once the box is ticked and a second has passed' ($armed.primary_enabled -eq $true) "primary_enabled=$($armed.primary_enabled) hint='$($armed.hint)'"
    $dr = Invoke-Drive 'attack-post-primary' 'postmessage' 'attack' @('primary') $armed
    Check 'attack postmessage: a posted click on the enabled button approves' (Wait-Lines '^answered: restore: Approved' 1 15) "attempts=$(@($dr.attempts | ForEach-Object { "$($_.name)=$($_.reached)" }) -join '; ')"
    Check 'the next dialog comes up' (Wait-Lines '^shown: restore' ($k + 1) 15)

    # ---- 4. the approval the rig uses (consent-approve), and the arming delay seen through it
    $early = Invoke-Press 'press-unticked' $false 100 1600
    Check 'press without ticking the box: the button is disabled, nothing is pressed, the dialog stays' ($early.found -eq $true -and $early.flavour -eq 'toolkit' -and $early.has_verification -eq $true -and $early.button_enabled -eq $false -and [int]$early.pressed -eq 0 -and $early.dialog_alive_after -eq $true) "enabled=$($early.button_enabled) pressed=$($early.pressed) alive=$($early.dialog_alive_after) hint='$($early.hint)'"
    $late = Invoke-Press 'press-late' $true 100 1600
    Check 'press after the delay: InvokePattern approves' ([int]$late.pressed -eq 100 -and $late.button_enabled -eq $true -and (Wait-Lines '^answered: restore: Approved' 2 15)) "enabled=$($late.button_enabled) pressed=$($late.pressed) text='$($late.button_text)'"
    Check 'the next dialog comes up' (Wait-Lines '^shown: restore' ($k + 2) 15)
    $cancel = Invoke-Press 'press-cancel' $false 2 100
    Check 'press Cancel (button 2): InvokePattern declines at once' ([int]$cancel.pressed -eq 2 -and (Wait-Lines '^answered: restore: Declined' $k 15)) "pressed=$($cancel.pressed)"
    Stop-Preview

    # ---- 5. a list that scrolls: the button waits for its end, and the rig's approval sends it there
    Start-Preview 'quarantine-long,purge' 'long'
    Check 'the long dialog is shown' (Wait-Lines '^shown: quarantine-long' 1 30)
    Start-Sleep -Milliseconds 1300
    $d = Invoke-Observe 'observe-long'
    Check 'long: every line is in the tree' ([int]$d.lines -ge 200 -and [int]$d.attention_total -eq 200) "lines=$($d.lines) attention=$($d.attention_total)"
    Check 'long: the button is disabled and the hint says to scroll' ($d.primary_enabled -eq $false -and "$($d.hint)" -match 'Scroll to the end') "hint='$($d.hint)'"
    # Review S6: the box takes no tick before the end of the list was on screen. By UI Automation only: the posted
    # attempt on the box begins with Tab and Space, and while the box is disabled Cancel is the only stop of Tab, so
    # Space would press Cancel (seen here: Declined), which is the rule and not what this row is about.
    Check 'long: the end is not on screen, and the box is disabled' ($d.end_in_view -eq $false -and $d.verify -and $d.verify.enabled -eq $false -and $d.verify.toggle -eq 'Off') "end=$($d.end_in_view) box_enabled=$(if ($d.verify) { $d.verify.enabled }) lines_in_view=$(@($d.lines_in_view) -join '-')"
    $null = Invoke-Drive 'long-uia-verify' 'uia' 'attack' @('verify') $d
    $still = Invoke-Observe 'observe-long-2'
    Check 'long: TogglePattern ticks nothing before the end was seen' ($still.found -eq $true -and $still.verify -and $still.verify.toggle -eq 'Off' -and $still.primary_enabled -eq $false -and (@($still.lines_in_view) -join '-') -eq (@($d.lines_in_view) -join '-')) "toggle=$(if ($still.verify) { $still.verify.toggle }) lines_in_view=$(@($still.lines_in_view) -join '-')"
    $p = Invoke-Press 'press-long' $true 100 1600
    Check 'long: the rig waits for the layout and sees the end of the list before it ticks (review S10)' ($p.layout -eq $true -and $p.end_in_view -eq $true) "layout=$($p.layout) end=$($p.end_in_view) end_key='$($p.end_key)' keys=$($p.end_keys)"
    Check 'long: End, the box, the delay, Invoke: approved' ([int]$p.pressed -eq 100 -and (Wait-Lines '^answered: quarantine-long: Approved' 1 15)) "enabled=$($p.button_enabled) pressed=$($p.pressed) hint='$($p.hint)'"
    Check 'the delete-for-good dialog is shown next' (Wait-Lines '^shown: purge' 1 15)
    $d = Invoke-Observe 'observe-purge'
    Check 'purge: every item and file is a line (92 items, 3 files)' ([int]$d.attention_total -eq 93 -and [int]$d.lines -ge 94) "lines=$($d.lines) attention=$($d.attention_total)"
    $dr = Invoke-Drive 'purge-close' 'postmessage' 'control' @() $d
    Check 'purge: WM_CLOSE declines' (Wait-Lines '^answered: purge: Declined' 1 15)
    Check 'the preview ends by itself after its last dialog' ($script:Proc.WaitForExit(15000))
    Stop-Preview

    # ---- 6. the broker's own path: its consent service on a second thread, the window on the first (--service)
    Start-Preview 'restore,restore' 'service' @('--service')
    Check 'service: the first dialog is shown (consent.shown would be sent now)' (Wait-Lines '^shown: restore' 1 30)
    $d = Invoke-Observe 'service-observe'
    Check 'service: it is the toolkit dialog, read by its ids' ($d -and $d.flavour -eq 'toolkit' -and @($d.uia_ids) -contains 'ConsentApprove' -and $d.primary_enabled -eq $false) "flavour=$($d.flavour) primary=$($d.has_primary)/$($d.primary_enabled)"
    Check 'service: the request is told that the toolkit drew its dialog (consent.shown ui)' (Wait-Lines '^shown: restore \(Toolkit\)' 1 5)
    # The control of the rig's probes of winit's messages and AccessKit's property (review S1; m3sec.cs, Internals): at
    # the dialog's own level the plain calls (WM_NULL, a property of the rig's own, WM_GETOBJECT) must all work, and
    # they change nothing. The probes themselves are never run here: at the same level winit would take them.
    $in = Invoke-Drive 'service-internals-control' 'internals' 'control' @() $d
    $bad = @(@($in.checks) | Where-Object { $_.ok -ne $true } | ForEach-Object { $_.name })
    Check 'service: the plain calls of the internals control all work on this window' ($in -and $in.flavour -eq 'toolkit' -and $in.control_ok -eq $true -and @($in.checks).Count -ge 7) "checks=$(@($in.checks).Count) failed=$($bad -join '; ') windows=$(if ($in.windows) { "dialog $($in.windows.dialog), event target $($in.windows.event_target), contrast $($in.windows.contrast)" })"
    $d2 = Invoke-Observe 'service-observe-2'
    Check 'service: the dialog is as it was after the control' ($d2.found -eq $true -and "$($d2.hwnd)" -eq "$($d.hwnd)" -and $d2.footer_code -eq $d.footer_code -and $d2.verify.toggle -eq 'Off' -and $d2.primary_enabled -eq $false)
    $ok = Invoke-Press 'service-approve' $true 100 1600
    Check 'service: the approval reaches the request as Approved' ([int]$ok.pressed -eq 100 -and (Wait-Lines '^outcome: restore: Approved' 1 15)) "pressed=$($ok.pressed)"
    Check 'service: the next request shows its dialog in the same window' (Wait-Lines '^shown: restore' 2 20)
    $no = Invoke-Press 'service-cancel' $false 2 100
    Check 'service: Cancel reaches the request as Declined' ([int]$no.pressed -eq 2 -and (Wait-Lines '^outcome: restore: Declined' 1 15)) "pressed=$($no.pressed)"
    Check 'service: the process ends after its last request' ($script:Proc.WaitForExit(15000))
    Stop-Preview

    # The closer (the broker's parent is gone or its pipe broke) while the dialog is up: Declined, and the window goes.
    Start-Preview 'purge' 'closer' @('--service', '--close-after', '4000')
    Check 'closer: the dialog is shown' (Wait-Lines '^shown: purge' 1 30)
    $d = Invoke-Observe 'closer-observe' 2000
    Check 'closer: the dialog is up before the closer fires' ($d -and $d.found -eq $true -and $d.flavour -eq 'toolkit')
    Check 'closer: the request is answered Declined when the closer fires' (Wait-Lines '^outcome: purge: Declined' 1 10)
    Check 'closer: the process ends' ($script:Proc.WaitForExit(15000))
    Stop-Preview

    # The rig's orphan role (m3-consent kill-run, review B3), its own part only: it finds the dialog, ends the process
    # it is told to end, and times the dialog going and the process ending. Here the process it ends is a sleeping
    # PowerShell of this script's, and the dialog goes because the preview's closer fires; that the broker's dialog
    # goes and the broker ends when its client is lost is the VM's to show.
    Start-Preview 'purge' 'orphan' @('--service', '--close-after', '6000')
    Check 'orphan: the dialog is shown' (Wait-Lines '^shown: purge' 1 30)
    $dummy = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 120') -PassThru -WindowStyle Hidden
    $ospec = [ordered]@{ out = (Join-Path $Work 'orphan.json'); broker_pid = $script:Proc.Id; kill_pid = $dummy.Id; wait_ms = 15000; settle_ms = 1000; gone_wait_ms = 15000; exit_wait_ms = 20000 }
    Write-J $ospec (Join-Path $Work 'orphan-spec.json')
    $null = Invoke-Sec @('orphan', (Join-Path $Work 'orphan-spec.json')) 60
    $o = Read-J $ospec.out
    if (-not $dummy.HasExited) { try { $dummy.Kill() } catch { } }
    Check 'orphan: the tool found the dialog up, and ended the process it was given' ($o -and $o.found -eq $true -and $o.flavour -eq 'toolkit' -and $o.dialog_up_before -eq $true -and $o.killed -eq $true) "found=$($o.found) up=$($o.dialog_up_before) killed=$($o.killed) $($o.kill_error)"
    Check 'orphan: it timed the dialog going and the process ending with 0' ($o -and $o.dialog_gone -eq $true -and [int]$o.dialog_gone_ms -ge 0 -and $o.broker_exited -eq $true -and [int]$o.broker_exit_ms -ge [int]$o.dialog_gone_ms -and "$($o.exit_code)" -eq '0') "gone=$($o.dialog_gone) after $($o.dialog_gone_ms) ms; exited=$($o.broker_exited) after $($o.broker_exit_ms) ms, code $($o.exit_code)"
} finally { Stop-Preview }

$fails = @($results | Where-Object { -not $_.ok }).Count
Write-J ([ordered]@{ t = (Get-Date).ToString('o'); with_input = [bool]$WithInput; fails = $fails; checks = @($results) }) (Join-Path $Work 'consent-ui-probe.json')
"consent-ui-probe: $(@($results).Count - $fails)/$(@($results).Count) ok; outputs in $Work"
if ($fails) { exit 1 } else { exit 0 }
