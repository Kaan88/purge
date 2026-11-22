<#
  Scorer of the M3 mode m3-clean-start (vm\RIG.md section 15; docs\M3_DESIGN.md 12 G11, 9.1; docs\M3_FINISH_PLAN.md B9).
  Windows PowerShell 5.1 or pwsh 7. Reads the evidence directory vm\rig-m3-clean.ps1 wrote: summary.json, *.png and
  guest\ (pre.json, install-1.json, ui.json, bench.json, uninstall-no.json, install-2.json, uninstall-yes-start.json,
  uninstall-yes-answer.json, rollback.json).

    powershell -NoProfile -File vm\truth\m3-clean-score.ps1 -Evidence E:\purge-build\gate-evidence\m3-clean-start\<run>
    powershell -NoProfile -File vm\truth\m3-clean-score.ps1 --self-test      (or -SelfTest)

  Fail-closed: every row needs its evidence; a missing file, record or field is a FAIL of that row, never a pass.
  Rows named "report: ..." need only that the numbers or states were recorded (SmartScreen, Smart App Control, the
  WARP launch numbers: 9.1 "VM: functional only; WARP numbers reported"); their values are never gated. Prints one line
  per row, writes <evidence>\score.json, exits 0 (PASS), 1 (FAIL) or 2 (usage). The self-test builds a passing
  synthetic evidence directory in %TEMP%, checks that it passes, then that an empty and a missing directory fail and
  that each of a list of single defects fails.
#>
[CmdletBinding()]
param(
    [string] $Evidence = '',
    [switch] $SelfTest,
    [Parameter(ValueFromRemainingArguments = $true)] $Rest
)
$ErrorActionPreference = 'Stop'
if (@($Rest) -contains '--self-test') { $SelfTest = $true }

# The payload the setup installs (install\inno\purge.iss [Files] + the uninstaller) and the ARP name.
$LayoutFiles = @('purge-engine.exe', 'purge-broker.exe', 'Purge.exe', 'kb', 'setup\install.ps1', 'unins000.exe', 'unins000.dat')
$DataParts = @('sessions', 'Quarantine', 'fp', 'kb', 'sessions\index.json')
$Shots = @('ui-names', 'uninstall-yes-dialog')

# ------------------------------------------------------------------------------------------------ helpers

function Read-J([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
}
function Has($O, [string]$Name) { $null -ne $O -and $null -ne $O.PSObject.Properties[$Name] -and $null -ne $O.$Name }
function Arr($X) { @(@($X) | Where-Object { $null -ne $_ }) }
function IsTrue($X) { $X -eq $true }
function IsFalse($X) { $X -eq $false }

$script:Rows = New-Object System.Collections.ArrayList
function Row([string]$Name, $Ok, [string]$Detail = '') {
    [void]$script:Rows.Add([ordered]@{ row = $Name; ok = ($Ok -eq $true); detail = $Detail })
}

# Every file of the layout is there (install) or none is (uninstall, rollback).
function Test-AllFiles($Files, [bool]$Want) {
    if ($null -eq $Files) { return $false }
    foreach ($f in $LayoutFiles) { if (-not (Has $Files $f) -or ($Files.$f -ne $Want)) { return $false } }
    $true
}

function Test-Install($D, [string]$Tag) {
    $p = "install $Tag"
    Row "$p evidence" ($null -ne $D) $(if (-not $D) { "guest\install-$Tag.json missing or unreadable" })
    if (-not $D) { return }
    Row "$p setup exit 0 (silent, elevated)" ((Has $D 'setup') -and "$($D.setup.exit)" -eq '0' -and (IsFalse $D.setup.timed_out)) "exit $($D.setup.exit)"
    Row "$p layout under %ProgramFiles%\Purge" ((Has $D 'layout') -and (IsTrue $D.layout.dir) -and (Test-AllFiles $D.layout.files $true)) $(if (Has $D 'layout') { (@($LayoutFiles | Where-Object { -not ((Has $D.layout.files $_) -and $D.layout.files.$_ -eq $true) }) -join ', ') })
    $c = $D.check
    Row "$p install.ps1 -Check exit 0" ((Has $D 'check') -and "$($c.exit)" -eq '0' -and (IsTrue $c.ok)) "exit $($c.exit) ok $($c.ok) $((Arr $c.payload_problems | Select-Object -First 3) -join '; ')"
    Row "$p owners and ACLs pass the broker's start checks (-Check: program files good, payload ok)" ((Has $D 'check') -and "$($c.program_files)" -eq 'good' -and (IsTrue $c.payload_ok)) "program_files $($c.program_files) payload $($c.payload_ok)"
    $dr = $D.data_root
    $parts = $(if (Has $dr 'parts') { @($DataParts | Where-Object { -not ((Has $dr.parts $_) -and $dr.parts.$_ -eq $true) }) } else { @('all') })
    Row "$p %ProgramData%\Purge created with protected descriptors" ((Has $D 'data_root') -and (IsTrue $dr.exists) -and (IsTrue $dr.protected) -and -not $parts.Count -and "$($c.data_root)" -eq 'good') "exists $($dr.exists) protected $($dr.protected) missing [$($parts -join ', ')] check $($c.data_root)"
    Row "$p event source 'Purge' registered" ((Has $D 'event_source') -and (IsTrue $D.event_source.key) -and (IsTrue $c.event_log_source)) "key $($D.event_source.key) check $($c.event_log_source)"
    Row "$p Installed-apps entry" ((Has $D 'arp') -and (IsTrue $D.arp.present) -and "$($D.arp.display_name)" -eq 'Purge' -and "$($D.arp.uninstall_string)".Trim()) "present $($D.arp.present) name '$($D.arp.display_name)'"
    Row "$p Start-menu shortcut" ((Has $D 'shortcuts') -and (IsTrue $D.shortcuts.start_menu)) "$($D.shortcuts.start_menu)"
    if ($Tag -eq '2') {
        Row "$p the kept data root is adopted, not renamed aside" ((Has $D 'data_root_before') -and (IsTrue $D.data_root_before.exists) -and (Has $dr 'aside') -and -not (Arr $dr.aside).Count) "before $($D.data_root_before.exists) aside [$((Arr $dr.aside) -join ', ')]"
    }
}

# What an uninstall must leave: no entry, no source, no files, no shortcuts, no Purge process.
function Test-Removed([string]$P, $After) {
    Row "$P Installed-apps entry removed" ((Has $After 'arp') -and (IsFalse $After.arp.present)) "$($After.arp.present)"
    Row "$P event source removed" ((Has $After 'event_source') -and (IsFalse $After.event_source.key)) "$($After.event_source.key)"
    Row "$P files removed (no %ProgramFiles%\Purge, no leftover)" ((Has $After 'pf_exists') -and (IsFalse $After.pf_exists) -and -not (Arr $After.leftovers).Count) "pf $($After.pf_exists) leftovers [$((Arr $After.leftovers | Select-Object -First 3) -join '; ')]"
    Row "$P shortcuts removed" ((Has $After 'shortcuts') -and (IsFalse $After.shortcuts.start_menu) -and (IsFalse $After.shortcuts.desktop)) "start $($After.shortcuts.start_menu) desktop $($After.shortcuts.desktop)"
    Row "$P no Purge process left" ((Has $After 'processes') -and -not (Arr $After.processes).Count) "$((Arr $After.processes | ForEach-Object { "$($_.name)[$($_.pid)]" }) -join ', ')"
}

function Invoke-Score([string]$Ev, [switch]$Quiet) {
    $script:Rows = New-Object System.Collections.ArrayList
    $g = Join-Path $Ev 'guest'
    $sum = Read-J (Join-Path $Ev 'summary.json')
    Row 'evidence summary.json' ($null -ne $sum) $(if (-not $sum) { 'missing or unreadable' })
    Row 'every rig step ran' ((Has $sum 'failed_step') -and (IsFalse $sum.failed_step) -and -not (Has $sum 'aborted')) "failed_step $($sum.failed_step) $($sum.aborted)"
    Row 'VM Purge-CleanPro' ((Has $sum 'vm') -and "$($sum.vm)" -ceq 'Purge-CleanPro') "$($sum.vm)"

    # Preconditions and the report-only states.
    $pre = Read-J (Join-Path $g 'pre.json')
    Row 'evidence guest\pre.json' ($null -ne $pre) $(if (-not $pre) { 'missing or unreadable' })
    Row 'setup under test = the setup given to the rig (SHA-256)' ((Has $pre 'setup') -and (Has $sum 'setup') -and "$($pre.setup.sha256)" -and "$($pre.setup.sha256)" -eq "$($sum.setup.sha256)") "guest $($pre.setup.sha256) host $($sum.setup.sha256)"
    Row 'precondition: no .NET runtime' ((Has $pre 'dotnet') -and (IsFalse $pre.dotnet.present)) "$((Arr $pre.dotnet.runtimes) -join ', ')"
    Row 'precondition: no Windows App Runtime' ((Has $pre 'windows_app_runtime') -and -not (Arr $pre.windows_app_runtime.appx).Count -and -not (Arr $pre.windows_app_runtime.arp).Count) "$((@(Arr $pre.windows_app_runtime.appx) + @(Arr $pre.windows_app_runtime.arp)) -join ', ')"
    Row 'precondition: no VC++ redistributable' ((Has $pre 'dotnet') -and -not (Arr $pre.vc_redist).Count) "$((Arr $pre.vc_redist) -join ', ')"
    Row 'precondition: nothing of Purge before the install' ((Has $pre 'preexisting') -and (IsFalse $pre.preexisting.pf) -and (IsFalse $pre.preexisting.data_root) -and (IsFalse $pre.preexisting.arp) -and (IsFalse $pre.preexisting.event_source)) ''
    Row 'report: SmartScreen and Smart App Control state recorded' ((Has $pre 'smartscreen') -and (Has $pre 'smart_app_control') -and (Has $pre.smart_app_control 'state')) "SAC $($pre.smart_app_control.state); SmartScreen $($pre.smartscreen.explorer_SmartScreenEnabled); signature $($pre.setup.signature); mark of the web '$($pre.setup.mark_of_the_web)'"

    Test-Install (Read-J (Join-Path $g 'install-1.json')) '1'

    # The first start: medium, the window, real names.
    $ui = Read-J (Join-Path $g 'ui.json')
    Row 'evidence guest\ui.json' ($null -ne $ui) $(if (-not $ui) { 'missing or unreadable' })
    Row 'Purge.exe runs at medium integrity' ((Has $ui 'ui_il') -and "$($ui.ui_il)" -eq 'Medium') "$($ui.ui_il)"
    Row 'purge-engine.exe started by it, medium' ((Has $ui 'engine_pid') -and "$($ui.engine_il)" -eq 'Medium') "pid $($ui.engine_pid) il $($ui.engine_il)"
    Row 'window shows names (UIA ProgramList, the Purge ARP row)' ((IsTrue $ui.window_found) -and (IsTrue $ui.list_found) -and (IsTrue $ui.purge_row) -and (Arr $ui.names_shown).Count -ge 1) "window $($ui.window_found) list $($ui.list_found) names $((Arr $ui.names_shown) -join ', ')"
    $foreign = @(@(Arr $ui.ui_modules.foreign) + @(Arr $ui.engine_modules.foreign))
    Row 'no runtime loaded from outside the install directory' ((Has $ui 'ui_modules') -and (Has $ui 'engine_modules') -and -not (Has $ui.ui_modules 'error') -and -not (Has $ui.engine_modules 'error') -and [int]$ui.ui_modules.count -gt 0 -and -not $foreign.Count) "$($foreign -join ', ')"

    # WARP numbers: report only (9.1), but they must exist and come from the real engine.
    $b = Read-J (Join-Path $g 'bench.json')
    $nv = $(if (Has $b 'stats') { $b.stats.names_visible } else { $null })
    Row 'report: WARP launch numbers recorded (real engine, no fallback)' ((Has $b 'stats') -and (Has $nv 'p50') -and [int]$nv.n -ge 1 -and "$($b.fallbacks)" -eq '0') "names_visible p50 $($nv.p50) p90 $($nv.p90) (n $($nv.n)); icons_visible p50 $($b.stats.icons_visible.p50); cold icons $($b.cold_icons_ms); fallbacks $($b.fallbacks); timeouts $($b.timeouts)"

    # Uninstall 1: silent, default No.
    $un = Read-J (Join-Path $g 'uninstall-no.json')
    Row 'uninstall (silent) evidence' ($null -ne $un) $(if (-not $un) { 'guest\uninstall-no.json missing or unreadable' })
    if ($un) {
        Row 'uninstall (silent) ran from the Installed-apps entry and ended' ((Has $un 'uninstaller') -and "$($un.uninstaller.exit)" -eq '0' -and (IsTrue $un.finished)) "exit $($un.uninstaller.exit) finished $($un.finished) $($un.error)"
        Row 'uninstall (silent) killed the running Purge processes' ((Arr $un.procs_before).Count -ge 1 -and (Has $un 'before_pids_alive') -and -not (Arr $un.before_pids_alive).Count) "before $((Arr $un.procs_before).Count) alive [$((Arr $un.before_pids_alive) -join ', ')]"
        Test-Removed 'uninstall (silent)' $un.after
        Row 'uninstall (silent) kept %ProgramData%\Purge as it was (default No)' ((Has $un 'after') -and (IsTrue $un.after.data_root.exists) -and (IsTrue $un.data_root_unchanged)) "exists $($un.after.data_root.exists) unchanged $($un.data_root_unchanged)"
    }

    Test-Install (Read-J (Join-Path $g 'install-2.json')) '2'

    # Uninstall 2: the data-folder question answered Yes.
    $ys = Read-J (Join-Path $g 'uninstall-yes-start.json')
    $ya = Read-J (Join-Path $g 'uninstall-yes-answer.json')
    Row 'uninstall (Yes) evidence' ($null -ne $ys -and $null -ne $ya) 'guest\uninstall-yes-start.json, guest\uninstall-yes-answer.json'
    if ($ys -and $ya) {
        Row 'uninstall (Yes) the data-folder question was shown and answered Yes' ((IsTrue $ys.dialog_found) -and (IsTrue $ya.answered) -and (IsTrue $ya.finished)) "dialog $($ys.dialog_found) answered $($ya.answered) finished $($ya.finished) $($ya.error)"
        Test-Removed 'uninstall (Yes)' $ya.after
        Row 'uninstall (Yes) removed %ProgramData%\Purge' ((Has $ya 'after') -and (IsFalse $ya.after.data_root.exists)) "$($ya.after.data_root.exists)"
    }

    # Rollback: a failing post-install step leaves nothing.
    $rb = Read-J (Join-Path $g 'rollback.json')
    Row 'rollback evidence' ($null -ne $rb) $(if (-not $rb) { 'guest\rollback.json missing or unreadable' })
    if ($rb) {
        Row 'rollback: clean machine before the plant' (IsTrue $rb.clean_before) ''
        Row 'rollback: the junction was planted' ((Has $rb 'planted') -and (IsTrue $rb.planted.is_reparse)) "mklink exit $($rb.planted.mklink_exit)"
        Row 'rollback: the setup failed (exit not 0)' ((Has $rb 'setup') -and $null -ne $rb.setup.exit -and "$($rb.setup.exit)" -ne '0' -and (IsFalse $rb.setup.timed_out)) "exit $($rb.setup.exit)"
        Row 'rollback: no Installed-apps entry' ((Has $rb 'after') -and (IsFalse $rb.after.arp.present)) "$($rb.after.arp.present)"
        Row 'rollback: no payload file left, nothing else in the directory' ((Has $rb 'payload_left') -and -not (Arr $rb.payload_left).Count -and -not (Arr $rb.pf_other).Count) "payload [$((Arr $rb.payload_left) -join ', ')] other [$((Arr $rb.pf_other) -join ', ')]"
        Row 'rollback: no event source, no data root, no shortcut' ((Has $rb 'after') -and (IsFalse $rb.after.event_source.key) -and (IsFalse $rb.after.data_root.exists) -and (IsFalse $rb.after.shortcuts.start_menu) -and (IsFalse $rb.after.shortcuts.desktop)) "source $($rb.after.event_source.key) data root $($rb.after.data_root.exists) start $($rb.after.shortcuts.start_menu)"
        Row 'rollback: the junction target is untouched' ((IsTrue $rb.canary_unchanged) -and (IsTrue $rb.junction_kept)) "canary $($rb.canary_unchanged) junction kept $($rb.junction_kept)"
    }

    # Screenshots: the summary names them and each file exists with bytes.
    $have = @(Arr $sum.shots | Where-Object { $_.file -and [int64]$_.bytes -gt 0 -and (Test-Path -LiteralPath (Join-Path $Ev $_.file) -PathType Leaf) } | ForEach-Object { "$($_.name)" })
    foreach ($s in $Shots) { Row "screenshot $s" ($have -contains $s) '' }

    $pass = (@($script:Rows | Where-Object { -not $_.ok }).Count -eq 0) -and $script:Rows.Count -gt 0
    if (-not $Quiet) {
        foreach ($r in $script:Rows) { Write-Host ("{0}  {1}{2}" -f $(if ($r.ok) { 'PASS' } else { 'FAIL' }), $r.row, $(if ($r.detail) { "  ($($r.detail))" })) }
        Write-Host "m3-clean-start: $(if ($pass) { 'PASS' } else { 'FAIL' }) ($(@($script:Rows | Where-Object { $_.ok }).Count)/$($script:Rows.Count) rows)"
    }
    [ordered]@{ schema = 'purge.rig.m3clean.score/1'; evidence = $Ev; pass = $pass; rows = @($script:Rows) }
}

# ---------------------------------------------------------------------------------------------- self-test

function Write-J($O, [string]$Path) { [IO.File]::WriteAllText($Path, (ConvertTo-Json $O -Depth 30), (New-Object Text.UTF8Encoding($false))) }

function New-Removed([bool]$DataRoot) {
    [ordered]@{ arp = [ordered]@{ present = $false }; event_source = [ordered]@{ key = $false; source_exists = $false }; pf_exists = $false; leftovers = @()
                shortcuts = [ordered]@{ start_menu = $false; desktop = $false }; processes = @()
                data_root = [ordered]@{ exists = $DataRoot; protected = $DataRoot; aside = @(); tree = @() } }
}

function New-InstallPass([string]$Tag) {
    $files = [ordered]@{}; foreach ($f in $LayoutFiles) { $files[$f] = $true }
    $parts = [ordered]@{}; foreach ($p in $DataParts) { $parts[$p] = $true }
    [ordered]@{ tag = $Tag; setup = [ordered]@{ exit = 0; timed_out = $false }; layout = [ordered]@{ dir = $true; files = $files }
                check = [ordered]@{ exit = 0; ok = $true; program_files = 'good'; payload_ok = $true; payload_problems = @(); data_root = 'good'; event_log_source = $true }
                data_root_before = [ordered]@{ exists = ($Tag -eq '2') }
                data_root = [ordered]@{ exists = $true; protected = $true; parts = $parts; aside = @() }
                event_source = [ordered]@{ key = $true; source_exists = $true }
                arp = [ordered]@{ present = $true; display_name = 'Purge'; uninstall_string = '"C:\Program Files\Purge\unins000.exe"' }
                shortcuts = [ordered]@{ start_menu = $true; desktop = $false } }
}

function New-Pass {
    [ordered]@{
        summary = [ordered]@{ mode = 'm3-clean-start'; vm = 'Purge-CleanPro'; failed_step = $false; setup = [ordered]@{ sha256 = 'AB' * 32 }
                              shots = @($Shots + @('pre', 'install-1') | ForEach-Object { [ordered]@{ name = $_; file = "$_.png"; bytes = 10 } }) }
        pre = [ordered]@{ setup = [ordered]@{ sha256 = 'AB' * 32; signature = 'NotSigned'; mark_of_the_web = $null }
                          dotnet = [ordered]@{ present = $false; runtimes = @() }; windows_app_runtime = [ordered]@{ appx = @(); arp = @() }; vc_redist = @()
                          preexisting = [ordered]@{ pf = $false; data_root = $false; arp = $false; event_source = $false }
                          smartscreen = [ordered]@{ explorer_SmartScreenEnabled = 'Warn' }; smart_app_control = [ordered]@{ state = 'off' } }
        install1 = (New-InstallPass '1')
        ui = [ordered]@{ ui_pid = 100; ui_il = 'Medium'; engine_pid = 101; engine_il = 'Medium'; window_found = $true; list_found = $true; purge_row = $true
                         names_shown = @('Purge', 'Microsoft Edge'); ui_modules = [ordered]@{ count = 120; foreign = @() }; engine_modules = [ordered]@{ count = 30; foreign = @() } }
        bench = [ordered]@{ fallbacks = 0; timeouts = 0; cold_icons_ms = 900.0
                            stats = [ordered]@{ names_visible = [ordered]@{ n = 5; p50 = 700.0; p90 = 800.0 }; icons_visible = [ordered]@{ n = 5; p50 = 900.0; p90 = 950.0 } } }
        unno = [ordered]@{ uninstaller = [ordered]@{ exit = 0 }; finished = $true; procs_before = @([ordered]@{ pid = 100; name = 'Purge.exe' }, [ordered]@{ pid = 101; name = 'purge-engine.exe' })
                           before_pids_alive = @(); after = (New-Removed $true); data_root_unchanged = $true }
        install2 = (New-InstallPass '2')
        ystart = [ordered]@{ dialog_found = $true }
        yanswer = [ordered]@{ answered = $true; finished = $true; after = (New-Removed $false) }
        rollback = [ordered]@{ clean_before = $true; planted = [ordered]@{ is_reparse = $true; mklink_exit = 0 }; setup = [ordered]@{ exit = 1; timed_out = $false }
                               after = (New-Removed $false); payload_left = @(); pf_other = @(); canary_unchanged = $true; junction_kept = $true }
    }
}

$FileOf = [ordered]@{ pre = 'pre.json'; install1 = 'install-1.json'; ui = 'ui.json'; bench = 'bench.json'; unno = 'uninstall-no.json'; install2 = 'install-2.json'
                      ystart = 'uninstall-yes-start.json'; yanswer = 'uninstall-yes-answer.json'; rollback = 'rollback.json' }

function Get-Defects {
    @(
        @{ name = 'missing event source after install'; act = { param($d) $d.install1.event_source.key = $false; $d.install1.check.event_log_source = $false } }
        @{ name = 'leftover file after uninstall'; act = { param($d) $d.unno.after.pf_exists = $true; $d.unno.after.leftovers = @('C:\Program Files\Purge\kb\x.tsv.gz|10|1') } }
        @{ name = 'install.ps1 -Check exit not 0'; act = { param($d) $d.install1.check.exit = 1 } }
        @{ name = 'install.ps1 -Check report not ok'; act = { param($d) $d.install1.check.ok = $false } }
        @{ name = 'setup exit not 0'; act = { param($d) $d.install1.setup.exit = 4 } }
        @{ name = 'a layout file missing'; act = { param($d) $d.install1.layout.files.'purge-broker.exe' = $false } }
        @{ name = 'data root not protected'; act = { param($d) $d.install1.data_root.protected = $false } }
        @{ name = 'no Installed-apps entry'; act = { param($d) $d.install1.arp.present = $false } }
        @{ name = '.NET runtime present before'; act = { param($d) $d.pre.dotnet.present = $true } }
        @{ name = 'Windows App Runtime present before'; act = { param($d) $d.pre.windows_app_runtime.appx = @('Microsoft.WindowsAppRuntime.1.6_x64') } }
        @{ name = 'VC++ redistributable present before'; act = { param($d) $d.pre.vc_redist = @('Microsoft Visual C++ 2015-2022 Redistributable (x64)') } }
        @{ name = 'another setup ran in the guest'; act = { param($d) $d.pre.setup.sha256 = 'CD' * 32 } }
        @{ name = 'UI at high integrity'; act = { param($d) $d.ui.ui_il = 'High' } }
        @{ name = 'no names shown'; act = { param($d) $d.ui.purge_row = $false; $d.ui.names_shown = @() } }
        @{ name = 'a runtime loaded from WindowsApps'; act = { param($d) $d.ui.ui_modules.foreign = @('C:\Program Files\WindowsApps\Microsoft.WindowsAppRuntime.1.6\x.dll') } }
        @{ name = 'bench fell back to the sample data'; act = { param($d) $d.bench.fallbacks = 2 } }
        @{ name = 'no bench numbers'; act = { param($d) $d.bench.stats.names_visible = [ordered]@{ n = 0; p50 = $null; p90 = $null } } }
        @{ name = 'a Purge process survived the uninstall'; act = { param($d) $d.unno.before_pids_alive = @(100) } }
        @{ name = 'event source left after uninstall'; act = { param($d) $d.unno.after.event_source.key = $true } }
        @{ name = 'shortcut left after uninstall'; act = { param($d) $d.unno.after.shortcuts.start_menu = $true } }
        @{ name = 'data root deleted by the silent uninstall'; act = { param($d) $d.unno.after.data_root.exists = $false } }
        @{ name = 'data root changed by the silent uninstall'; act = { param($d) $d.unno.data_root_unchanged = $false } }
        @{ name = 'second install renamed the kept data root aside'; act = { param($d) $d.install2.data_root.aside = @('Purge.aside-1') } }
        @{ name = 'data-folder question not shown'; act = { param($d) $d.ystart.dialog_found = $false } }
        @{ name = 'data root kept after Yes'; act = { param($d) $d.yanswer.after.data_root.exists = $true } }
        @{ name = 'rollback: setup succeeded'; act = { param($d) $d.rollback.setup.exit = 0 } }
        @{ name = 'rollback: ARP entry left'; act = { param($d) $d.rollback.after.arp.present = $true } }
        @{ name = 'rollback: payload left'; act = { param($d) $d.rollback.payload_left = @('purge-broker.exe') } }
        @{ name = 'rollback: event source left'; act = { param($d) $d.rollback.after.event_source.key = $true } }
        @{ name = 'rollback: canary changed'; act = { param($d) $d.rollback.canary_unchanged = $false } }
        @{ name = 'a rig step failed'; act = { param($d) $d.summary.failed_step = $true } }
        @{ name = 'run on Inbound'; act = { param($d) $d.summary.vm = 'Inbound-Win11-Test' } }
        @{ name = 'screenshot ui-names missing'; act = { param($d) $d.summary.shots = @($d.summary.shots | Where-Object { $_.name -ne 'ui-names' }) } }
        @{ name = 'uninstall-no.json missing'; drop = 'unno' }
        @{ name = 'rollback.json missing'; drop = 'rollback' }
    )
}

function Invoke-SelfTest {
    $root = Join-Path ([IO.Path]::GetTempPath()) ('m3-clean-score-selftest-' + [guid]::NewGuid().ToString('N'))
    $script:checks = 0; $script:fails = 0
    function Check([string]$Name, [bool]$Cond) { $script:checks++; if ($Cond) { Write-Host "ok   $Name" } else { $script:fails++; Write-Host "FAIL $Name" } }
    try {
        $build = {
            param($Defect)
            $dir = Join-Path $root ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Force (Join-Path $dir 'guest') | Out-Null
            # Round-trip through JSON so the defects edit the same object shapes the scorer reads.
            $d = (ConvertTo-Json (New-Pass) -Depth 30) | ConvertFrom-Json
            if ($Defect -and $Defect.act) { & $Defect.act $d }
            foreach ($k in $FileOf.Keys) {
                if ($Defect -and $Defect.drop -eq $k) { continue }
                Write-J $d.$k (Join-Path $dir "guest\$($FileOf[$k])")
            }
            Write-J $d.summary (Join-Path $dir 'summary.json')
            foreach ($s in Arr $d.summary.shots) { [IO.File]::WriteAllBytes((Join-Path $dir $s.file), [byte[]](1..10)) }
            $dir
        }
        $r = Invoke-Score (& $build $null) -Quiet
        Check 'synthetic pass passes' $r.pass
        if (-not $r.pass) { foreach ($row in $r.rows) { if (-not $row.ok) { Write-Host "       $($row.row): $($row.detail)" } } }
        $empty = Join-Path $root 'empty'; New-Item -ItemType Directory -Force $empty | Out-Null
        Check 'empty evidence fails' (-not (Invoke-Score $empty -Quiet).pass)
        Check 'missing directory fails' (-not (Invoke-Score (Join-Path $root 'none') -Quiet).pass)
        foreach ($df in Get-Defects) {
            $r = Invoke-Score (& $build $df) -Quiet
            Check "defect '$($df.name)' fails" (-not $r.pass)
        }
    } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "m3-clean-score self-test: $($script:checks - $script:fails)/$($script:checks) ok"
    if ($script:fails) { 1 } else { 0 }
}

if ($SelfTest) { exit (Invoke-SelfTest) }
if (-not $Evidence) { Write-Host 'usage: m3-clean-score.ps1 -Evidence <run dir>  |  --self-test'; exit 2 }
$res = Invoke-Score $Evidence
if (Test-Path -LiteralPath $Evidence -PathType Container) {
    [IO.File]::WriteAllText((Join-Path $Evidence 'score.json'), (ConvertTo-Json $res -Depth 6), (New-Object Text.UTF8Encoding($false)))
}
if ($res.pass) { exit 0 } else { exit 1 }
