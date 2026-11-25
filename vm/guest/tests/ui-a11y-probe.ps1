# Purge rig: the host-side probe of the Rust UI's UI Automation tree (docs\UI_RUST_PLAN.md "AutomationIds"). Starts
# Purge.exe --sample (no engine; its made-up broker answers from the protocol fixtures), then makes every lookup the VM rig makes (vm\guest\m3-e2e-ui.ps1, which
# it dot-sources, so the probe runs the rig's own functions; m3-e2e.ps1, m3-clean.ps1, m3sec.cs) and walks the sample
# flow: Programs, the confirmation, the pipeline, the leftovers review, Move, the result, Put back all.
#
# Each check prints PASS, FAIL or BLOCKED (a lookup the current UI cannot answer yet, with the package it waits on).
# Exit code: 0 when nothing FAILs, 1 otherwise. Rerun it as pages land: a BLOCKED that now passes prints PASS (and
# should become a plain check here).
#
#   powershell -NoProfile -File vm\guest\tests\ui-a11y-probe.ps1 [-Exe <Purge.exe>] [-Json <out.json>]
param(
    [string]$Exe = 'E:\purge-target\ui\release\Purge.exe',
    [string]$Program = '7-Zip 24.08 (x64)',
    [int]$ScanWaitSec = 90,
    [string]$Json = ''
)
$ErrorActionPreference = 'Stop'
$Guest = Split-Path -Parent $PSScriptRoot
. (Join-Path $Guest 'm3-e2e-ui.ps1')
Initialize-E2eUia
$ae = [System.Windows.Automation.AutomationElement]
$CT = [System.Windows.Automation.ControlType]

$results = New-Object System.Collections.ArrayList
function Add-Result([string]$Status, [string]$Name, [string]$Detail = '') {
    [void]$results.Add([ordered]@{ status = $Status; check = $Name; detail = $Detail })
    "{0,-8} {1}{2}" -f $Status, $Name, $(if ($Detail) { " -- $Detail" } else { '' })
}
function Check([string]$Name, [bool]$Ok, [string]$Detail = '') { Add-Result $(if ($Ok) { 'PASS' } else { 'FAIL' }) $Name $Detail }
# A lookup the current UI does not answer yet: PASS when it does, else BLOCKED on $On (never FAIL).
function Blocked([string]$Name, [bool]$Ok, [string]$On, [string]$Detail = '') { Add-Result $(if ($Ok) { 'PASS' } else { 'BLOCKED' }) $Name $(if ($Ok) { $Detail } else { "on $On$(if ($Detail) { "; $Detail" })" }) }

function Get-Patterns($El) { if ($El) { @($El.GetSupportedPatterns() | ForEach-Object { $_.ProgrammaticName -replace 'PatternIdentifiers\.Pattern$', '' }) } else { @() } }
function Test-Pattern($El, [string]$P) { (Get-Patterns $El) -contains $P }
function Get-Type($El) { if ($El) { $El.Current.ControlType.ProgrammaticName -replace '^ControlType\.', '' } else { $null } }
function Describe($El) { if ($El) { "$(Get-Type $El) '$(Get-E2eName $El)' [$((Get-Patterns $El) -join ',')] enabled=$($El.Current.IsEnabled)" } else { 'not found' } }
function Wait-Id($Win, [string]$Id, [int]$Sec = 10) { (Wait-E2eElement { Find-E2eById $Win $Id } $Sec).el }

if (-not (Test-Path -LiteralPath $Exe)) { throw "no Purge.exe at $Exe (cargo build --release -p purge-ui)" }
$proc = Start-Process -FilePath $Exe -ArgumentList '--sample' -PassThru
try {
    # ---- the window (Get-E2eWindow, m3-clean Find-UiWindow, m3sec: the top-level window of the pid)
    $win = Get-E2eWindow $proc.Id 30
    Check 'window: a top-level element of the process' ([bool]$win) "name='$(Get-E2eName $win)'"
    if (-not $win) { throw 'no window' }
    Start-Sleep -Seconds 1

    # ---- Programs (m3-e2e ui-start, m3-clean ui-start, m3sec start-uninstall)
    $list = Wait-Id $win 'ProgramList' 20
    Check 'ProgramList: a List with Selection' ((Get-Type $list) -eq 'List' -and (Test-Pattern $list 'Selection')) (Describe $list)
    $items = @(if ($list) { $list.FindAll([System.Windows.Automation.TreeScope]::Children, (New-Object System.Windows.Automation.PropertyCondition($ae::ControlTypeProperty, $CT::ListItem))) })
    Check 'ProgramList: every row a ListItem with SelectionItem and ScrollItem' ($items.Count -gt 0 -and @($items | Where-Object { -not ((Test-Pattern $_ 'SelectionItem') -and (Test-Pattern $_ 'ScrollItem')) }).Count -eq 0) "$($items.Count) rows"
    $sp = $null
    Add-Result 'INFO' 'ProgramList: no ScrollPattern (AccessKit has none); the rig needs none, every row is in the tree' "scroll=$(if ($list) { $list.TryGetCurrentPattern([System.Windows.Automation.ScrollPattern]::Pattern, [ref]$sp) })"
    $row = @($items | Where-Object { Test-E2eRowLabel (Get-E2eName $_) $Program })
    Check "row of '$Program' by Test-E2eRowLabel (exactly one)" ($row.Count -eq 1) "$(@($row | ForEach-Object { Get-E2eName $_ }) -join ' | ')"
    $names = @($items | ForEach-Object { Get-E2eName $_ })
    # m3-clean Test-NameShown: '^Name(?:$|[\r\n\s]|, )' over the list's names.
    Check 'm3-clean: the ARP name shows as a row (Test-NameShown shape)' (@($names | Where-Object { $_ -match ('^' + [regex]::Escape($Program) + '(?:$|[\r\n\s]|, )') }).Count -ge 1)
    $none = Select-E2eProgramRow $win 'No Such Program 0.0' '' 3
    Check 'Select-E2eProgramRow: a name not listed is not selected' (-not $none.ok -and -not $none.row_text) "how=$($none.how)"
    $sel = Select-E2eProgramRow $win $Program '' 30
    Check 'Select-E2eProgramRow: the row selected by name, the only one, DName says the name' ($sel.ok -and $sel.by -eq 'name' -and $sel.selected_n -eq 1 -and $sel.dname -ceq $Program) "how=$($sel.how) row='$($sel.row_text)' dname='$($sel.dname)' selected=$($sel.selected_n)"
    $ub = (Wait-E2eElement { Find-E2eById $win 'UninstallButton' } 10 -Enabled).el
    Check 'UninstallButton: an enabled Button with Invoke' ((Get-Type $ub) -eq 'Button' -and (Test-Pattern $ub 'Invoke')) (Describe $ub)
    $db = Find-E2eById $win 'DUninstallButton'
    Add-Result 'INFO' 'DUninstallButton: drawn by the D3/Bold looks only (the D1 pane shows a verdict chip); the rig presses UninstallButton' (Describe $db)
    $info = Find-E2eById $win 'InfoBarHost'
    Blocked 'm3-clean: InfoBarHost on Programs (the page''s notices)' ([bool]$info) 'UI-PAGES (Programs bars: engine missing, scan notices)' (Describe $info)

    # ---- Leftovers before any scan (m3-e2e ui-wait-scan 'empty'; NavLeftovers)
    $nl = Find-E2eById $win 'NavLeftovers'
    $how = Invoke-E2eElement $nl
    Check 'NavLeftovers: a TabItem pressed by Invoke-E2eElement (SelectionItem)' ((Get-Type $nl) -eq 'TabItem' -and $how -eq 'SelectionItem') "pattern=$how"
    $et = Wait-Id $win 'EmptyTitle' 10
    Check 'EmptyTitle: a Text on the leftovers page before a scan' ((Get-Type $et) -eq 'Text') (Describe $et)
    $null = Invoke-E2eElement (Find-E2eById $win 'NavPrograms'); Start-Sleep -Milliseconds 800

    # ---- the first-elevation explanation (m3-e2e ui-uninstall, m3sec start-uninstall): it comes before the
    # confirmation, as in the WinUI app (the confirmation shows what the broker's prepare read).
    $null = Invoke-E2eElement (Find-E2eById $win 'UninstallButton')
    $cont = (Wait-E2eElement { Find-E2eDialogButton $win 'Continue' } 10).el
    Check 'ui-uninstall / ui-undo: the first-elevation explanation''s Continue (DialogPrimaryButton)' ("$($cont.Current.AutomationId)" -eq 'DialogPrimaryButton' -and (Test-Pattern $cont 'Invoke')) (Describe $cont)
    $dlg = Find-E2eById $win 'ContentDialog'
    Check 'the explanation is a dialog element (ContentDialog) with DialogCloseButton "Not now"' ($dlg -and (Get-E2eName (Find-E2eById $dlg 'DialogCloseButton')) -eq 'Not now') (Describe $dlg)
    $null = Invoke-E2eElement $cont

    # ---- the confirmation (m3-e2e ui-uninstall, ui-await-confirm, ui-confirm)
    $ok = (Wait-E2eElement { Find-E2eDialogButton $win 'Uninstall' } 10).el
    Check 'Find-E2eDialogButton Uninstall: ConfirmUninstallButton, a Button with Invoke' ("$($ok.Current.AutomationId)" -eq 'ConfirmUninstallButton' -and (Test-Pattern $ok 'Invoke')) (Describe $ok)
    $dlg = Find-E2eById $win 'ContentDialog'
    Check 'the confirmation is a dialog element (ContentDialog) holding its buttons' ($dlg -and [bool](Find-E2eById $dlg 'ConfirmUninstallButton') -and [bool](Find-E2eById $dlg 'ConfirmNotNowButton')) (Describe $dlg)
    $other = @(if ($dlg) { $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition($ae::AutomationIdProperty, 'UninstallButton'))) })
    Check 'while it is open the page''s own UninstallButton is out of the tree (modal)' ($other.Count -eq 0) "found=$($other.Count)"
    $t = @(Get-E2eTexts $win)
    Check "ui-uninstall: the title 'Uninstall $($Program)?' is a text (whole, not elided)" ($t -contains "Uninstall $($Program)?")
    Check 'ui-confirm: the route line is a text (broker route)' (Test-E2eSaid $t '2. Run its uninstaller as administrator')
    Blocked 'ui-confirm: the medium route line ("at your level")' (Test-E2eSaid $t '2. Run its uninstaller at your level') 'UI-PAGES (consent flow: the route comes from the engine plan; the sample always says administrator)'
    $q = Find-E2eQuietToggle $win
    Check 'ui-confirm: the quiet toggle (QuietSwitch in the dialog) reads by Toggle' ("$($q.Current.AutomationId)" -eq 'QuietSwitch' -and $null -ne (Get-E2eToggle $q)) "$(Describe $q) state=$(Get-E2eToggle $q)"
    $nn = Find-E2eDialogButton $win 'Not now' 'CloseButton'
    Check 'Find-E2eDialogButton Not now / CloseButton: ConfirmNotNowButton' ("$($nn.Current.AutomationId)" -eq 'ConfirmNotNowButton') (Describe $nn)
    $wrong = Find-E2eDialogButton $win 'Uninstall' 'CloseButton'
    Check 'Find-E2eDialogButton: Uninstall asked as the CloseButton is no button (not the primary one)' ($null -eq $wrong) (Describe $wrong)
    $null = Invoke-E2eElement $nn
    $gone = (Wait-E2eElement { if (-not (Find-E2eById $win 'ContentDialog')) { $win } } 5).el
    Check 'Not now closes the dialog' ([bool]$gone)
    $ib = (Wait-E2eElement { Find-E2eById $win 'InfoBarHost' } 5).el
    Check 'InfoBarHost after Not now: one Text named "Title Message" (m3-clean reads its own name)' ((Get-Type $ib) -eq 'Text' -and (Get-E2eName $ib) -like 'Uninstall cancelled.*') (Describe $ib)
    Blocked 'ui-uninstall: the cancelled bar ("You cancelled the Windows prompt.")' $false 'the VM rig (a real Windows prompt to cancel; the sample broker shows none)'

    # ---- the pipeline (NavQueue, the stepper) and the scan (MoveButton = review). Uninstall opened the Uninstall
    # page; its button is on Programs. Explained once: no explanation the second time.
    $null = Invoke-E2eElement (Find-E2eById $win 'NavPrograms'); Start-Sleep -Milliseconds 800
    $null = Invoke-E2eElement (Wait-Id $win 'UninstallButton' 5)
    $ok = (Wait-E2eElement { Find-E2eDialogButton $win 'Uninstall' } 10).el
    $how = Invoke-E2eElement $ok
    Check 'ui-confirm: Uninstall pressed by Invoke' ($how -eq 'Invoke')
    $nq = Wait-Id $win 'NavQueue' 10
    Check 'NavQueue: a TabItem with SelectionItem' ((Get-Type $nq) -eq 'TabItem' -and (Test-Pattern $nq 'SelectionItem')) (Describe $nq)
    $null = Invoke-E2eElement $nq; Start-Sleep -Seconds 1
    $qt = @(Get-E2eTexts $win)
    Check 'the pipeline page says its steps (Step_n texts)' ([bool](Find-E2eById $win 'Step_1') -and [bool](Find-E2eById $win 'StepperHost')) "$(@($qt | Where-Object { $_ -match '^\d\. ' }).Count) step texts"
    $ec = (Wait-E2eElement { if (@(Get-E2eTexts $win | Where-Object { $null -ne (Get-E2eExitCodeFromText $_) }).Count -gt 0) { $win } } 20).el
    Check 'ui-wait-scan: an exit code in a step detail ("exit code N")' ([bool]$ec) "$(@(Get-E2eTexts $win | Where-Object { $null -ne (Get-E2eExitCodeFromText $_) }) -join ' | ')"
    $mv = (Wait-E2eElement { Find-E2eById $win 'MoveButton' } $ScanWaitSec).el
    Check 'ui-wait-scan: MoveButton appears (review)' ([bool]$mv) (Describe $mv)
    $fc = Find-E2eById $win 'FooterCount'; $mt = Find-E2eById $win 'MoveText'
    Check 'ui-move: FooterCount and MoveText are texts with names' ((Get-Type $fc) -eq 'Text' -and (Get-E2eName $fc) -and (Get-Type $mt) -eq 'Text' -and (Get-E2eName $mt)) "footer='$(Get-E2eName $fc)' move='$(Get-E2eName $mt)'"
    Check 'ui-move: MoveButton enabled with Invoke' ($mv -and $mv.Current.IsEnabled -and (Test-Pattern $mv 'Invoke'))
    # A plain run of one program has no bar on the review (the model shows one only for a held scan, a queued next
    # program or a notice); the bar's shape is checked after Not now above.
    $ib = Find-E2eById $win 'InfoBarHost'
    Add-Result 'INFO' 'InfoBarHost on the review (none for a plain run of one program)' (Describe $ib)
    $null = Invoke-E2eElement (Find-E2eById $win 'NavQueue'); Start-Sleep -Milliseconds 800
    $nl = Find-E2eById $win 'NavLeftovers'; $null = Invoke-E2eElement $nl; Start-Sleep -Milliseconds 800
    Check 'ui-wait-scan: NavQueue then NavLeftovers comes back to the review' ([bool](Find-E2eById $win 'MoveButton'))

    # ---- Move, the result, Put back all
    $null = Invoke-E2eElement (Find-E2eById $win 'MoveButton')
    $prompt = (Wait-E2eElement { if (@(Get-E2eTexts $win) | Where-Object { $_ -like 'Confirm*Purge security prompt*' }) { $win } } 3).el
    Check 'ui-move: the waiting page ("Confirm ... Purge security prompt") with WaitingCodeText' ($prompt -and [bool](Find-E2eById $win 'WaitingCodeText')) "code='$(Get-E2eName (Find-E2eById $win 'WaitingCodeText'))'"
    $rt = (Wait-E2eElement { Find-E2eById $win 'ResultTitleText' } 15).el
    Check 'ui-wait-result: ResultTitleText and ResultDetailText are texts' ((Get-Type $rt) -eq 'Text' -and (Get-E2eName (Find-E2eById $win 'ResultDetailText'))) "title='$(Get-E2eName $rt)'"
    $ua = (Wait-E2eElement { Find-E2eById $win 'UndoAllButton' } 5 -Enabled).el
    Check 'ui-wait-result / ui-undo: UndoAllButton an enabled Button with Invoke' ((Get-Type $ua) -eq 'Button' -and (Test-Pattern $ua 'Invoke')) (Describe $ua)
    Blocked 'ui-wait-result: the declined text ("Nothing was moved: the prompt was cancelled.")' $false 'the VM rig (a real Purge security prompt to decline; the sample broker always confirms)'
    $null = Invoke-E2eElement $ua
    $uw = (Wait-E2eElement { $w = Find-E2eById $win 'WaitingTitleText'; if ($w -and (Get-E2eName $w) -like 'Confirm putting it back*') { $w } } 8).el
    Check 'ui-undo: the restore consent wait ("Confirm putting it back ...") in WaitingTitleText' ([bool]$uw) "title='$(Get-E2eName $uw)'"
    $ut = (Wait-E2eElement { Find-E2eById $win 'UndoTitleText' } 15).el
    Check 'ui-wait-undone: UndoTitleText and UndoDetailText are texts' ((Get-Type $ut) -eq 'Text' -and (Get-E2eName (Find-E2eById $win 'UndoDetailText'))) "title='$(Get-E2eName $ut)'"
} catch {
    Add-Result 'FAIL' 'probe' $_.Exception.Message
} finally {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}

# ---- m3sec.cs `ui` start-uninstall (m3-consent): built with the guest's csc line, run at this host's level against a
# fresh window, through the first-elevation dialog's Continue.
$fw = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$tmp = Join-Path ([IO.Path]::GetTempPath()) "purge-ui-a11y-probe-$PID"
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    $sec = Join-Path $tmp 'm3sec.exe'
    $wpf = Join-Path $fw 'WPF'
    $o = & (Join-Path $fw 'csc.exe') /nologo /target:winexe /platform:x64 /optimize "/out:$sec" "/r:$wpf\UIAutomationClient.dll" "/r:$wpf\UIAutomationTypes.dll" `
        "/r:$wpf\WindowsBase.dll" '/r:System.Web.Extensions.dll' '/r:System.Windows.Forms.dll' '/r:System.Drawing.dll' (Join-Path $Guest 'm3sec.cs') 2>&1
    Check 'm3sec.cs builds with the guest csc line' (Test-Path -LiteralPath $sec) "$(@($o) -join ' ')"
    if (Test-Path -LiteralPath $sec) {
        $proc = Start-Process -FilePath $Exe -ArgumentList '--sample' -PassThru
        try {
            $null = Get-E2eWindow $proc.Id 30
            $spec = Join-Path $tmp 'spec.json'; $out = Join-Path $tmp 'ui.json'
            ConvertTo-Json @{ out = $out; pid = $proc.Id; action = 'start-uninstall'; program = $Program; wait_ms = 20000 } | Set-Content -LiteralPath $spec -Encoding ASCII
            $null = Start-Process -FilePath $sec -ArgumentList 'ui', "`"$spec`"" -PassThru -Wait
            $r = $(if (Test-Path -LiteralPath $out) { Get-Content -LiteralPath $out -Raw | ConvertFrom-Json })
            $st = @(if ($r) { $r.steps })
            $find = $st | Where-Object { $_.step -eq 'find row' } | Select-Object -First 1
            $pick = $st | Where-Object { $_.step -eq 'select row' } | Select-Object -First 1
            Check 'm3sec ui: the row is the one ListItem of the name, selected by SelectionItem' ($find -and $find.ok -and "$($find.type)" -eq 'ControlType.ListItem' -and "$($find.name)".StartsWith("$Program, ") -and "$($pick.how)" -like 'SelectionItem.Select*') "name='$($find.name)' how='$($pick.how)'"
            Check 'm3sec ui: UninstallButton found enabled and invoked' (@($st | Where-Object { $_.step -eq 'find Uninstall' -and $_.ok -and $_.enabled }).Count -eq 1 -and @($st | Where-Object { $_.step -eq 'invoke Uninstall' }).Count -eq 1)
            Check 'm3sec ui: Continue (DialogPrimaryButton) invoked' (@($st | Where-Object { $_.step -eq 'invoke Continue' }).Count -eq 1)
        } finally { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    }
} catch {
    Add-Result 'FAIL' 'm3sec probe' $_.Exception.Message
} finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

$n = @{}; foreach ($s in 'PASS', 'FAIL', 'BLOCKED', 'INFO') { $n[$s] = @($results | Where-Object { $_.status -eq $s }).Count }
"ui-a11y-probe: $($n.PASS) pass, $($n.FAIL) fail, $($n.BLOCKED) blocked, $($n.INFO) info"
if ($Json) { ConvertTo-Json @{ exe = $Exe; results = @($results) } -Depth 4 | Set-Content -LiteralPath $Json -Encoding UTF8 }
if ($n.FAIL) { exit 1 } else { exit 0 }
