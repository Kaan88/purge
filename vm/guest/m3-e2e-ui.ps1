# Purge rig, M3 e2e: the UI Automation driver of the real UI (vm\RIG.md section 17; docs\M3_DESIGN.md 11.2, 13 "UI
# Automation of a WinUI AOT app is flaky in the VM"). Windows PowerShell 5.1, functions only: dot-sourced by
# m3-e2e.ps1, which runs elevated through the agent (UI Automation from high integrity reads and drives a medium
# window; the reverse is what m3-consent proves impossible). The host self-test dot-sources it for the pure helpers.
#
# Elements are found by automation id (the x:Name of the XAML, which WinUI exposes as AutomationId when no explicit
# id is set: ProgramList, UninstallButton, MoveButton, ResultTitleText, UndoAllButton, UndoTitleText, NavQueue, ...)
# or, for ContentDialog buttons and the controls built in code, by the template part id (PrimaryButton, CloseButton)
# plus the name. No coordinates: rows are reached by ScrollPattern / ScrollItemPattern and selected with
# SelectionItemPattern; buttons are pressed with InvokePattern. Every wait polls with a deadline; each retry is counted
# and lands in the step record (design 13: "retries are counted and reported").

# ----------------------------------------------------------------------------------------------- pure helpers

# Pure: whether the text of a program row (the row's TextBlock: Name, the "new" tag, a line break, the sub line) is the
# row of the program called $Name. The name must be followed by nothing, by the tag "new" and the end or a line break,
# or by a line break: "Microsoft Visual Studio Code (User)" is not the row of "Microsoft Visual Studio Code".
function Test-E2eRowText([string]$Text, [string]$Name) {
    if (-not $Text -or -not $Name) { return $false }
    if (-not $Text.StartsWith($Name, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    $rest = $Text.Substring($Name.Length)
    # The "new" tag: "Gitnew" before 0293f8f, "Git  new" since (the UI run put spaces before the badge).
    $tag = $rest.TrimStart(' ')
    if ($tag.StartsWith('new', [StringComparison]::Ordinal)) { $rest = $tag.Substring(3) }
    return ($rest.Length -eq 0 -or $rest[0] -eq "`r" -or $rest[0] -eq "`n")
}

# Pure: the first line of a row text without the "new" tag (what the scorer records as the row seen).
function Get-E2eRowName([string]$Text) {
    $first = (("$Text" -split "`r?`n")[0])
    if ($first.EndsWith('new', [StringComparison]::Ordinal)) { $first = $first.Substring(0, $first.Length - 3).TrimEnd(' ') }
    $first
}

# Pure: a comparable key of a plan / report target (type, then the identifying fields; paths and names fold case as
# Windows does; a firewall rule id does not, as the executor matches it exactly). The guest keys the CLI's preselected
# set and the session's executed items with it; the scorer keys the plans it writes with it.
function Get-E2eTargetKey($Target) {
    if (-not $Target) { return $null }
    $t = "$($Target.type)"
    $f = { param($n) $v = $Target.PSObject.Properties[$n]; if ($v -and $null -ne $v.Value) { "$($v.Value)" } else { '' } }
    switch ($t) {
        'FirewallRule' { return "FirewallRule|$(& $f 'id')" }
        'AppxPackage' { return "AppxPackage|$((& $f 'full_name').ToLowerInvariant())" }
        'Service' { return "Service|$((& $f 'name').ToLowerInvariant())" }
        'Task' { return "Task|$((& $f 'path').ToLowerInvariant())" }
        default { return ("$t|" + (& $f 'path').TrimEnd('\').ToLowerInvariant() + '|' + (& $f 'name').ToLowerInvariant() + '|' + (& $f 'segment').ToLowerInvariant()) }
    }
}

# Pure: {equal, cli_n, ui_n, missing (preselected by the CLI, not executed), extra (executed, not preselected)}.
function Compare-E2eSets([string[]]$Cli, [string[]]$Ui) {
    $a = @($Cli | Where-Object { $_ } | Select-Object -Unique); $b = @($Ui | Where-Object { $_ } | Select-Object -Unique)
    $missing = @($a | Where-Object { $b -cnotcontains $_ }); $extra = @($b | Where-Object { $a -cnotcontains $_ })
    [ordered]@{ equal = ($missing.Count -eq 0 -and $extra.Count -eq 0); cli_n = $a.Count; ui_n = $b.Count; missing = $missing; extra = $extra }
}

# Pure: the journal text and the report of an empty execution, for `rigtool execdiff` on the window of an app whose
# plan preselected nothing (vm\RIG.md section 17, "Nothing preselected"): no session exists, Move was never pressed,
# but snap A / snap B must still show no collateral. The rig writes them (session rig-empty-<app>, zero items,
# committed), never Purge; execdiff then authorises nothing by op, so every record of the window is ambient,
# store, broker-exit or collateral. $At: FILETIME (100 ns since 1601) of the record times.
function New-E2eEmptyExecDocs([string]$App, [uint64]$At) {
    if ($App -cnotmatch '^[a-z0-9][a-z0-9-]*$') { throw "bad app '$App'" }
    $session = "rig-empty-$App"
    $zero = ('0' * 64)
    $counts = [ordered]@{ done = 0; vanished = 0; skipped = 0; held_retry = 0; pending_reboot = 0; failed = 0 }
    $header = [ordered]@{ rec = 'header'; schema = 'purge.journal/1'; session = $session; created = $At; engine_version = 'rig'; app = $App
                          plan_hash = $zero; selection_hash = $zero; policy_version = 'rig'; mode = 'post'; items = 0; allow_irreversible = $false; volumes = @() }
    $commit = [ordered]@{ rec = 'commit'; at = $At; counts = $counts; backup_bytes = 0 }
    $journal = (ConvertTo-Json $header -Compress -Depth 5) + "`n" + (ConvertTo-Json $commit -Compress -Depth 5) + "`n"
    $report = [ordered]@{ schema = 'purge.exec/1'; session = $session; app = $App; plan_hash = $zero; selection_hash = $zero; state = 'Committed'
                          started = $At; finished = $At; items = @(); counts = $counts; backup_bytes = 0; pending_reboot = $false
                          restore_point = [ordered]@{ kind = 'NotRequested' }; warnings = @('rig: nothing was preselected; no session exists') }
    [ordered]@{ session = $session; journal = $journal; report = (ConvertTo-Json $report -Depth 5) }
}

# Pure: the uninstaller records of the background watcher ($Watch, its procs) and of ui-wait-scan's own polling ($List)
# in one list, each pid once (the watcher's record first: it saw the process earlier).
function Merge-E2eUninstallers($Watch, $List) {
    $out = New-Object System.Collections.ArrayList
    foreach ($p in @(@($Watch) + @($List) | Where-Object { $_ })) {
        if (@($out | Where-Object { "$($_.pid)" -eq "$($p.pid)" }).Count) { continue }
        [void]$out.Add($p)
    }
    $out.ToArray()
}

# Pure: the exit code a step detail or a bar names ("Finished, exit code 3010", "... exit code 1603. ..."), or $null.
function Get-E2eExitCodeFromText([string]$Text) {
    $m = [regex]::Match("$Text", 'exit code (\d+)')
    if ($m.Success) { [int64]$m.Groups[1].Value } else { $null }
}

# ------------------------------------------------------------------------------------------------- UIA access

$script:E2eUiaLoaded = $false
function Initialize-E2eUia {
    if ($script:E2eUiaLoaded) { return }
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    $script:E2eUiaLoaded = $true
}

function New-E2eStep([string]$Name) { [ordered]@{ step = $Name; t = (Get-Date).ToString('o'); ok = $false; retries = 0; detail = $null } }

# The top-level window of process $ProcessId (or $null after $TimeoutSec).
function Get-E2eWindow([int]$ProcessId, [int]$TimeoutSec = 60) {
    Initialize-E2eUia
    $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcessId)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        try { $w = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond) } catch { $w = $null }
        if ($w) { return $w }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    $null
}

function Find-E2eById($Root, [string]$Id) {
    if (-not $Root) { return $null }
    $c = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $Id)
    try { $Root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c) } catch { $null }
}

# A Button by name, optionally with a given automation id (ContentDialog parts: PrimaryButton, CloseButton).
function Find-E2eButton($Root, [string]$Name, [string]$Id = '') {
    if (-not $Root) { return $null }
    $ae = [System.Windows.Automation.AutomationElement]
    $conds = @((New-Object System.Windows.Automation.PropertyCondition($ae::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)),
               (New-Object System.Windows.Automation.PropertyCondition($ae::NameProperty, $Name)))
    if ($Id) { $conds += (New-Object System.Windows.Automation.PropertyCondition($ae::AutomationIdProperty, $Id)) }
    try { $Root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.AndCondition([System.Windows.Automation.Condition[]]$conds))) } catch { $null }
}

# A ContentDialog button: the template part (PrimaryButton, CloseButton) with that name; else any Button with that name
# that is not one of the pages' own buttons (UninstallButton, DUninstallButton carry the name "Uninstall" too).
function Find-E2eDialogButton($Root, [string]$Name, [string]$Part = 'PrimaryButton') {
    $b = Find-E2eButton $Root $Name $Part
    if ($b) { return $b }
    if (-not $Root) { return $null }
    $ae = [System.Windows.Automation.AutomationElement]
    $c = New-Object System.Windows.Automation.AndCondition(
        (New-Object System.Windows.Automation.PropertyCondition($ae::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)),
        (New-Object System.Windows.Automation.PropertyCondition($ae::NameProperty, $Name)))
    try {
        foreach ($e in $Root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $c)) {
            if (@('UninstallButton', 'DUninstallButton') -notcontains "$($e.Current.AutomationId)") { return $e }
        }
    } catch { }
    $null
}

# Waits until $Find returns an element (and, with -Enabled, one that is enabled). Returns {el, retries}.
function Wait-E2eElement([scriptblock]$Find, [int]$TimeoutSec = 60, [switch]$Enabled, [int]$PollMs = 500) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $n = 0
    do {
        $el = $null
        try { $el = & $Find } catch { $el = $null }
        if ($el) {
            $ok = $true
            if ($Enabled) { try { $ok = [bool]$el.Current.IsEnabled } catch { $ok = $false } }
            if ($ok) { return [pscustomobject]@{ el = $el; retries = $n } }
        }
        $n++
        Start-Sleep -Milliseconds $PollMs
    } while ((Get-Date) -lt $deadline)
    [pscustomobject]@{ el = $null; retries = $n }
}

# Presses an element by its pattern: Invoke, else Toggle, else SelectionItem.Select. Returns the pattern used or $null.
function Invoke-E2eElement($El) {
    if (-not $El) { return $null }
    $p = $null
    if ($El.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$p)) { $p.Invoke(); return 'Invoke' }
    if ($El.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$p)) { $p.Toggle(); return 'Toggle' }
    if ($El.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$p)) { $p.Select(); return 'SelectionItem' }
    $null
}

function Get-E2eToggle($El) {
    $p = $null
    if ($El -and $El.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$p)) { return "$($p.Current.ToggleState)" }
    $null
}

function Get-E2eName($El) { if ($El) { try { "$($El.Current.Name)" } catch { $null } } else { $null } }

# Names of every Text element (and every element with a name, capped) under $Root: what the page says now.
function Get-E2eTexts($Root, [int]$Max = 600) {
    $out = New-Object System.Collections.Generic.List[string]
    if (-not $Root) { return @() }
    try {
        $all = $Root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
        foreach ($e in $all) {
            if ($out.Count -ge $Max) { break }
            $n = $null
            try { $n = "$($e.Current.Name)" } catch { }
            if ($n -and $n.Trim()) { $out.Add($n) }
        }
    } catch { }
    @($out)
}

# The program row of $Name in the list ProgramList: scrolls from the top a page at a time until a Text element whose
# name is the row of $Name (Test-E2eRowText) is realized, then selects its ListItem (SelectionItemPattern). $Match (a
# regex on the first line) is the fallback when no row has the exact name. Returns {ok, row_text, how, scrolls}.
function Select-E2eProgramRow($Win, [string]$Name, [string]$Match = '', [int]$TimeoutSec = 120) {
    Initialize-E2eUia
    $rec = [ordered]@{ ok = $false; row_text = $null; how = $null; scrolls = 0; list_found = $false; by = $null }
    $w = Wait-E2eElement { Find-E2eById $Win 'ProgramList' } $TimeoutSec
    $list = $w.el
    if (-not $list) { return $rec }
    $rec.list_found = $true
    $ae = [System.Windows.Automation.AutomationElement]
    $textCond = New-Object System.Windows.Automation.PropertyCondition($ae::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
    $sp = $null
    $hasScroll = $list.TryGetCurrentPattern([System.Windows.Automation.ScrollPattern]::Pattern, [ref]$sp)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $hit = $null
    # The list fills asynchronously (programs.batch, then patches): wait for a first row, then search page by page.
    $null = Wait-E2eElement { $list.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $textCond) } 60
    if ($hasScroll -and $sp.Current.VerticallyScrollable) { try { $sp.SetScrollPercent([System.Windows.Automation.ScrollPattern]::NoScroll, 0) } catch { } }
    while (-not $hit -and (Get-Date) -lt $deadline) {
        $texts = $list.FindAll([System.Windows.Automation.TreeScope]::Descendants, $textCond)
        foreach ($t in $texts) { $n = Get-E2eName $t; if (Test-E2eRowText $n $Name) { $hit = $t; $rec.by = 'name'; break } }
        if (-not $hit -and $Match) {
            foreach ($t in $texts) { $n = Get-E2eName $t; if ($n -and (Get-E2eRowName $n) -match $Match) { $hit = $t; $rec.by = 'match'; break } }
        }
        if ($hit) { break }
        if ($hasScroll -and $sp.Current.VerticallyScrollable -and $sp.Current.VerticalScrollPercent -lt 99.5) {
            try { $sp.Scroll([System.Windows.Automation.ScrollAmount]::NoAmount, [System.Windows.Automation.ScrollAmount]::LargeIncrement) } catch { }
            $rec.scrolls++
            Start-Sleep -Milliseconds 400
        } else {
            # At the end (or no scroll bar): the list may still be filling; start over from the top.
            Start-Sleep -Seconds 2
            if ($hasScroll -and $sp.Current.VerticallyScrollable) { try { $sp.SetScrollPercent([System.Windows.Automation.ScrollPattern]::NoScroll, 0) } catch { } }
        }
    }
    if (-not $hit) { return $rec }
    $rec.row_text = Get-E2eName $hit
    # Up to the ListItem; ScrollIntoView, then Select (single selection: the list's other ticks are cleared).
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    $item = $hit
    while ($item -and $item.Current.ControlType -ne [System.Windows.Automation.ControlType]::ListItem) { $item = $walker.GetParent($item); if ($item -and $item.Current.AutomationId -eq 'ProgramList') { $item = $null } }
    if (-not $item) { $rec.how = 'no ListItem above the row text'; return $rec }
    $p = $null
    if ($item.TryGetCurrentPattern([System.Windows.Automation.ScrollItemPattern]::Pattern, [ref]$p)) { try { $p.ScrollIntoView() } catch { } }
    if ($item.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$p)) {
        $p.Select()
        Start-Sleep -Milliseconds 600
        $rec.how = 'SelectionItem.Select'
        $rec.ok = [bool]$p.Current.IsSelected
    } else { $rec.how = 'no SelectionItemPattern on the ListItem' }
    $rec
}

# Collects what the window says while $Until (a scriptblock returning a non-empty state string) is not met; every
# distinct text seen on the way is kept (a bar may be replaced when the page changes). $Each runs every poll (the
# uninstaller watch). Returns {state, seen[], polls, seconds}.
function Watch-E2eWindow($Win, [scriptblock]$Until, [int]$TimeoutSec, [scriptblock]$Each = $null, [int]$PollMs = 700) {
    $seen = New-Object System.Collections.Generic.List[string]
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $t0 = Get-Date
    $deadline = $t0.AddSeconds($TimeoutSec)
    $polls = 0
    $state = $null
    while (-not $state -and (Get-Date) -lt $deadline) {
        $polls++
        foreach ($s in Get-E2eTexts $Win) { if ($set.Add($s)) { $seen.Add($s) } }
        if ($Each) { try { & $Each } catch { } }
        try { $state = & $Until } catch { $state = $null }
        if (-not $state) { Start-Sleep -Milliseconds $PollMs }
    }
    foreach ($s in Get-E2eTexts $Win) { if ($set.Add($s)) { $seen.Add($s) } }
    [pscustomobject]@{ state = $state; seen = @($seen); polls = $polls; seconds = [int]((Get-Date) - $t0).TotalSeconds }
}
