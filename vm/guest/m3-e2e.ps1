<#
  Purge rig, M3 mode m3-e2e (vm\RIG.md section 17; docs\M3_DESIGN.md 11.2 row m3-e2e, 12 G6, G7, G12, 9.1;
  docs\M3_FINISH_PLAN.md B7). Guest side, Windows PowerShell 5.1, run elevated by C:\cr\agent.ps1 as one job per
  phase; the host driver is vm\rig-m3.ps1 -Mode m3-e2e (one VM boot per app, from rig-base).

    & C:\cr\guest\m3-e2e.ps1 -Phase <phase> -App <app> [-Step run|plan|undo] [-WaitSec <n>]

  Apps: vscode, vscode-user, git, firefox-tb, npp, 7zip (apps.ps1, official installers), execapp (the M1b executor
  app PurgeExecApp of m1b-exec.ps1 with the service svc-full and the task task-simple of vm\truth\m1b-exec-cases.json),
  msi1603, msi3010 (the failing-uninstaller MSI fixtures of m3-e2e-msi.ps1).

  Outputs: C:\cr\out\m3-e2e\<app>\ (log e2e.log, state.json, step-*.json, e2e.json, execdiff.json, fidelity.json,
  timings.jsonl, sess-*), and the rigtool run directory C:\cr\out\e2e-<app>\ (snap/lists 0, 1, 2, run.json, fp.json,
  plan-purge.json + .scan.json, executed.json), copied into <app>\run by phase finish, which zips <app> to
  C:\cr\out\m3-e2e-<app>.zip. Result lines start with "M3E ".

  Phases, in the host's order:
    setup        m3sec.exe built, the payload installed (install.ps1: release engine + broker + the real UI as
                 C:\Program Files\Purge\Purge.exe), Edge update and telemetry paused, UAC values recorded
    prepare      pre-apps, lists/snap 0, install (or plant), launch, lists/snap 1, CLI inventory + harvest (fp.json)
    ui-start     the real UI at medium (task PurgeRigM3E2eUi), the program row found and selected
    ui-uninstall Uninstall pressed, "Continue" of the first-elevation explanation pressed; ends when the UAC prompt is
                 up (the host answers it by scancode), the confirm dialog is up, or a bar says why not
    ui-await-confirm, ui-confirm   the confirm dialog read (command, quiet toggle, steps) and its "Uninstall" pressed
    consent-wait / consent-approve -Step run|plan|undo   the broker's TaskDialog observed, then approved by
                 m3sec press (TDM_CLICK_VERIFICATION + TDM_CLICK_BUTTON 100 after the arming delay, from high)
    ui-wait-scan the stepper to its end: the review page, an empty result, or a failure bar; the uninstaller
                 processes seen meanwhile with their integrity (G7)
    capture-post lists/snap 2, the rig CLI scan of the same state (plan-purge.json), the preselected set, snap A, deep A
    ui-move, ui-wait-result, capture-exec       Move pressed, the result page read, snap B, deep B, the session,
                 execdiff (collateral), the executed set against the CLI's preselected set
    ui-undo, ui-wait-undone, capture-undo       Undo all, the undone page, deep C, fidelity (undo_fidelity)
    fail-check   (msi1603, msi3010) ARP entry, sessions, quarantine and the fixture key after the uninstaller ran
    finish       broker timing lines (broker-timings.ps1), the UI closed, e2e.json, the zip
#>
param(
    [Parameter(Mandatory)]
    [ValidateSet('setup', 'prepare', 'ui-start', 'ui-uninstall', 'uac-front', 'ui-await-confirm', 'ui-confirm', 'consent-wait', 'consent-approve',
                 'ui-wait-scan', 'capture-post', 'ui-move', 'ui-wait-result', 'capture-exec', 'ui-undo', 'ui-wait-undone',
                 'capture-undo', 'fail-check', 'finish')]
    [string] $Phase,
    [Parameter(Mandatory)] [string] $App,
    [ValidateSet('', 'run', 'plan', 'undo')] [string] $Step = '',
    [int] $WaitSec = 0
)
. C:\cr\guest\riglib.ps1
. C:\cr\guest\apps.ps1
. C:\cr\guest\m3-e2e-ui.ps1
. C:\cr\guest\m3-e2e-msi.ps1
. C:\cr\guest\m1b-exec.ps1 -Library
$ErrorActionPreference = 'Continue'
if ($App -cnotmatch '^[a-z0-9][a-z0-9-]*$') { throw "bad app '$App'" }

$Out = 'C:\cr\out\m3-e2e'
$AD = Join-Path $Out $App
$Run = "e2e-$App"
$RD = Join-Path $RigOut $Run
$W = Join-Path 'C:\cr\work\m3-e2e' $App
$Bin = 'C:\cr\m3e2e'
$Exe = Join-Path $Bin 'm3sec.exe'
$Payload = Join-Path $Bin 'payload'
$PF = 'C:\Program Files\Purge'
$UiExe = Join-Path $PF 'Purge.exe'
$UiTask = 'PurgeRigM3E2eUi'
$StateFile = Join-Path $AD 'state.json'
New-Item -ItemType Directory -Force $Out, $AD, $W, $Bin | Out-Null
Set-RunLog (Join-Path $AD 'e2e.log')

# The app kinds (the scorer's expectations name the same ids, vm\truth\m3-e2e-expect.json).
$E2eRealApps = @('vscode', 'vscode-user', 'git', 'firefox-tb', 'npp', '7zip')
$E2eFixtures = [ordered]@{
    execapp = [ordered]@{ kind = 'fixture'; name = 'PurgeExecApp'; key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PurgeExecApp'; label = 'e2e-execapp'
                          variants = @('svc-full', 'task-simple') }
    msi1603 = [ordered]@{ kind = 'fail-1603'; variant = '1603' }
    msi3010 = [ordered]@{ kind = 'fail-3010'; variant = '3010' }
}
function Get-E2eKind([string]$Id) {
    if ($E2eRealApps -contains $Id) { return 'app' }
    if ($E2eFixtures.Contains($Id)) { return $E2eFixtures[$Id].kind }
    throw "unknown m3-e2e app '$Id'"
}

# ------------------------------------------------------------------------------------------------ helpers

function Read-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { [IO.File]::ReadAllText($Path) | ConvertFrom-Json } catch { $null }
}
function Read-State { $s = Read-Json $StateFile; if ($s) { $s } else { [pscustomobject]@{} } }
function Set-StateValue($State, [string]$Name, $Value) { $State | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force }
function Save-State($State) { Write-JsonFile $State $StateFile 12 }
function Save-Step($Rec, [string]$Name) { Write-JsonFile $Rec (Join-Path $AD "step-$Name.json") 12 }

# Runs m3sec.exe from the (high) agent and waits.
function Invoke-Sec([string[]]$Arguments, [int]$TimeoutSec = 120) {
    $q = @($Arguments | ForEach-Object { if ("$_" -match '\s') { '"' + $_ + '"' } else { "$_" } })
    $p = Start-Process -FilePath $Exe -ArgumentList $q -PassThru -WindowStyle Hidden
    if (-not $p.WaitForExit($TimeoutSec * 1000)) { Log "  !! m3sec $($Arguments[0]) still running after $TimeoutSec s; killed"; Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; return $false }
    $true
}

function Get-UacValues {
    $p = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    [ordered]@{ ConsentPromptBehaviorAdmin = $p.ConsentPromptBehaviorAdmin; PromptOnSecureDesktop = $p.PromptOnSecureDesktop; EnableLUA = $p.EnableLUA }
}

function Get-UiWindow($State, [int]$TimeoutSec = 30) {
    if (-not $State.ui_pid) { return $null }
    Get-E2eWindow ([int]$State.ui_pid) $TimeoutSec
}

function Get-BrokerPid {
    $b = @(Get-Process -Name 'purge-broker' -ErrorAction SilentlyContinue | Sort-Object StartTime -Descending)
    if ($b.Count) { $b[0].Id } else { $null }
}

function Test-ConsentUp { @(Get-Process -Name consent -ErrorAction SilentlyContinue).Count -gt 0 }

# The foreground window's process and whether the secure desktop is the input desktop (OpenInputDesktop from this
# high-integrity agent fails with error 5 while the Winlogon desktop is the input desktop; vm\truth\m3-rig-uac.md).
Add-Type -Namespace E2e -Name Fg -MemberDefinition @'
[DllImport("user32.dll")] public static extern System.IntPtr GetForegroundWindow();
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(System.IntPtr h, out uint pid);
[DllImport("user32.dll", SetLastError = true)] public static extern System.IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
[DllImport("user32.dll")] public static extern bool CloseDesktop(System.IntPtr h);
'@
function Get-E2eForeground {
    $h = [E2e.Fg]::GetForegroundWindow(); $fpid = [uint32]0
    $null = [E2e.Fg]::GetWindowThreadProcessId($h, [ref]$fpid)
    $p = Get-Process -Id $fpid -ErrorAction SilentlyContinue
    "$(if ($p) { $p.ProcessName } else { 'none' }):$fpid"
}
function Test-E2eSecureDesktop {
    $d = [E2e.Fg]::OpenInputDesktop(0, $false, 0x0100)
    if ($d -eq [IntPtr]::Zero) { return ([Runtime.InteropServices.Marshal]::GetLastWin32Error() -eq 5) }
    $null = [E2e.Fg]::CloseDesktop($d); $false
}

# (Get-E2eTargetKey and Compare-E2eSets live in m3-e2e-ui.ps1, which the scorer and the self-test load too.)

# A deep scope (purge.rig.deepscope/0) over plan targets: services, tasks and firewall rules by name, the rest as targets.
function New-E2eDeepScope($Targets) {
    $svc = @(); $tasks = @(); $rules = @(); $rest = @()
    foreach ($t in @($Targets | Where-Object { $_ })) {
        switch ("$($t.type)") { 'Service' { $svc += "$($t.name)" } 'Task' { $tasks += "$($t.path)" } 'FirewallRule' { $rules += "$($t.id)" } default { $rest += $t } }
    }
    New-ExDeepScope $svc $tasks $rules $rest
}

function Get-E2eEngine { Get-M2EngineExe }

# The installer of a real app (apps.ps1) in C:\cr\inst: the host cache file when its SHA-256 matches the pushed manifest
# (cache-sources.json), else the rig-base copy, else a download from the vendor URL; a pinned 'sha256' must match.
function Resolve-E2eInstaller($A, $Rec) {
    $file = Join-Path $RigInst $A.file
    $mf = Join-Path $RigInst 'cache-sources.json'
    $m = $null
    if (Test-Path -LiteralPath $mf) { $cj = [IO.File]::ReadAllText($mf) | ConvertFrom-Json; foreach ($pr in @($cj.PSObject.Properties)) { if ($pr.Name -ieq $A.file) { $m = $pr.Value; break } } }
    $Rec.installer_source = 'rig-base'
    if ($m -and (Test-Path -LiteralPath $file)) {
        $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash
        if ($h -eq "$($m.sha256)".ToUpperInvariant()) { $Rec.installer_source = 'host cache'; $Rec.url = $m.url } else { Log "!! $file sha256 $h != cache manifest; downloading again"; Remove-Item -LiteralPath $file -Force }
    }
    if (-not (Test-InstallerFile $file)) {
        $urls = @(& $A.url)
        if ($m -and $m.url) { $urls = @($m.url) + $urls }
        $f = Fetch $urls $A.file
        $Rec.url = $f.url; $Rec.installer_source = 'download'
    }
    $info = Get-FileInfoRecord $file $Rec.url
    $Rec.installer = $file; $Rec.installer_sha256 = $info.sha256; $Rec.installer_sig = "$($info.sig) $($info.signer)".Trim()
    if ($A.sha256 -and $info.sha256 -ne "$($A.sha256)".ToUpperInvariant()) { throw "$($A.file): sha256 $($info.sha256) != pinned $($A.sha256)" }
    if ($m -and $info.sha256 -ne "$($m.sha256)".ToUpperInvariant()) { Log "!! $($A.file): not the cache manifest's file (version drift)" }
    $file
}

# Installs a real app silently (elevated, or at medium through a one-shot task for install_il = 'medium') and waits for
# its process tree; returns the record.
function Install-E2eApp($A) {
    $rec = [ordered]@{ id = $A.id; url = $null; installer = $null; installer_sha256 = $null; installer_sig = $null; installer_source = $null
                       cmd = $null; ran_as = $null; exit = $null; timed_out = $false; start = (NowIso); end = $null }
    $file = Resolve-E2eInstaller $A $rec
    if ($A.install -eq 'msi') { $exe = Join-Path $env:SystemRoot 'System32\msiexec.exe'; $args_ = '/i "' + $file + '" /qn /norestart' }
    else { $exe = $file; $args_ = [Environment]::ExpandEnvironmentVariables("$($A.install)") }
    $rec.cmd = "`"$exe`" $args_"
    $pre = New-ProcKeySet
    $t = Get-Date
    if ($A.install_il -eq 'medium') {
        $rec.ran_as = 'medium'
        try {
            $L = LaunchMedium -Exe $exe -Arguments $args_ -TaskName 'PurgeRigInstall' -StartTimeoutSec 60
            if (-not $L.found) { throw "installer $exe did not start through task PurgeRigInstall" }
            $w = WaitTree -Since $t -TimeoutSec 1200 -RootPid @([int]$L.pid) -Preexisting $pre
        } finally { Unregister-ScheduledTask -TaskName 'PurgeRigInstall' -Confirm:$false -ErrorAction SilentlyContinue }
    } else {
        $rec.ran_as = 'elevated'
        $p = Start-Native $exe $args_
        if ($p.WaitForExit(1200 * 1000)) { $rec.exit = $p.ExitCode } else { $rec.timed_out = $true }
        $w = WaitTree -Since $t -TimeoutSec 600 -RootPid @($p.Id) -Preexisting $pre
    }
    $rec.timed_out = ($rec.timed_out -or $w.timed_out)
    $rec.end = NowIso
    Log "install $($A.id): exit=$($rec.exit) timed_out=$($rec.timed_out) ran_as=$($rec.ran_as); settle 20 s"
    Start-Sleep -Seconds 20
    $rec
}

function Invoke-E2eLaunch($A, $Main) {
    $rec = [ordered]@{ done = $false; exe = $null; found = $false; closed = @(); killed = @() }
    if (-not $A.launch) { return $rec }
    $exe = Resolve-LaunchExe $A $Main
    if (-not $exe) { throw "launch exe '$($A.launch.exe)' not found" }
    $rec.exe = $exe
    $L = [pscustomobject]@{ task = 'PurgeRigLaunch'; start = (Get-Date); found = $false }
    try { $L = LaunchMedium -Exe $exe -Arguments $A.launch.args -TaskName 'PurgeRigLaunch'; $rec.found = $L.found; Start-Sleep -Seconds 25 }
    finally { $r = Stop-Launch $L -GraceSec 5; $rec.closed = @($r.closed); $rec.killed = @($r.killed) }
    $rec.done = $true
    Start-Sleep -Seconds 10
    $rec
}

# The uninstallers the UI started: processes newer than $Since whose image lies under the install location, or whose
# name says uninstaller (unins*.exe and the _iu*.tmp copy Inno runs from %TEMP%, NSIS's Un_A.exe / Au_.exe, Mozilla's
# helper.exe, msiexec.exe, the fixture's uninst.exe); each is
# recorded once with its integrity (m3sec procinfo).
function Update-E2eUninstallers($List, [datetime]$Since, [string]$Loc) {
    foreach ($p in @(Get-ProcList | Where-Object { $_.start -ge $Since -and $_.path })) {
        $seen = @($List | Where-Object { $_.pid -eq $p.pid }).Count
        if ($seen) { continue }
        $under = ($Loc -and $p.path.StartsWith($Loc.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase))
        $named = ("$($p.name)" -match '^(unins\d*|un_a|au_|uninstall|uninst|helper)\.exe$|^msiexec\.exe$|^_iu[0-9a-z]+\.tmp$')
        if (-not ($under -or $named)) { continue }
        $f = Join-Path $AD "proc-$($p.pid).json"
        $null = Invoke-Sec @('procinfo', "$($p.pid)", $f) 20
        $pi = Read-Json $f
        [void]$List.Add([ordered]@{ pid = $p.pid; name = $p.name; path = $p.path; start = "$($p.start)"; il = $(if ($pi) { "$($pi.il)" }); user = $(if ($pi) { "$($pi.user)" }) })
    }
}

# --------------------------------------------------------------------------------------- fixture programs

function Install-E2eExecApp($Fx) {
    Assert-ExRigVm
    $cases = Read-ExCases $null 'C:\cr\guest\m1b-exec-cases.json'
    Clear-ExWorld $cases
    New-ExApp
    # A working uninstaller (m3sec fixture-uninstall: removes the ARP key and app.exe, leaves the service, the task and
    # the rest; proof in C:\cr\out\m3-e2e\fixture-PurgeExecApp.json).
    Copy-Item -LiteralPath $Exe -Destination (Join-Path $ExDir 'uninst.exe') -Force
    Set-ItemProperty -LiteralPath ('HKLM:\' + $ExArp.Substring(5)) -Name 'UninstallString' -Value ('"' + (Join-Path $ExDir 'uninst.exe') + '" fixture-uninstall PurgeExecApp')
    $planted = @()
    foreach ($id in $Fx.variants) { $planted += Add-ExObject (Get-ExVariant $cases $id) }
    [ordered]@{ id = 'execapp'; ran_as = 'elevated'; planted = $planted; variants = $Fx.variants; exit = 0 }
}

function Install-E2eMsi($Fx) {
    $msi = New-E2eMsi $Fx.variant (Join-Path $W "purge-e2e-$($Fx.variant).msi")
    $log = Join-Path $AD "msi-install-$($Fx.variant).log"
    $r = Invoke-Native (Join-Path $env:SystemRoot 'System32\msiexec.exe') ('/i "' + $msi.path + '" /qn /norestart /L*v "' + $log + '"') 600
    [ordered]@{ id = "msi$($Fx.variant)"; ran_as = 'elevated'; msi = $msi; exit = $r.exit }
}

# ------------------------------------------------------------------------------------------------- phases

Log "== phase $Phase app=$App$(if ($Step) { " step=$Step" })"
$st = Read-State
switch ($Phase) {
    'setup' {
        $rec = [ordered]@{ t = (NowIso); build = $null; install = @(); uac = (Get-UacValues); edge = $null; telemetry = $null }
        # The display never sleeps: VBoxManage screenshotpng fails (E_FAIL) while the guest display is off.
        $null = & powercfg.exe /change monitor-timeout-ac 0 2>&1
        $fw = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
        $wpf = Join-Path $fw 'WPF'
        Remove-Item -LiteralPath $Exe -Force -ErrorAction SilentlyContinue
        $o = & (Join-Path $fw 'csc.exe') /nologo /target:winexe /platform:x64 /optimize "/out:$Exe" "/r:$wpf\UIAutomationClient.dll" "/r:$wpf\UIAutomationTypes.dll" `
            "/r:$wpf\WindowsBase.dll" '/r:System.Web.Extensions.dll' '/r:System.Windows.Forms.dll' '/r:System.Drawing.dll' 'C:\cr\guest\m3sec.cs' 2>&1
        foreach ($l in @($o)) { Log "  csc: $l" }
        $rec.build = (Test-Path -LiteralPath $Exe)
        if (Test-Path -LiteralPath $Payload) { Remove-Item -LiteralPath $Payload -Recurse -Force }
        Expand-Archive -LiteralPath (Join-Path $Bin 'payload.zip') -DestinationPath $Payload -Force
        $ok = $rec.build -and (Test-Path -LiteralPath (Join-Path $Payload 'ui\Purge.exe'))
        if ($ok) {
            $a = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\cr\install\install.ps1', '-SkipBuild',
                   '-Engine', (Join-Path $Payload 'purge-engine.exe'), '-Broker', (Join-Path $Payload 'purge-broker.exe'), '-Kb', (Join-Path $Payload 'kb'),
                   '-UiPublishDir', (Join-Path $Payload 'ui'))
            $io = @(& powershell.exe @a 2>&1 | ForEach-Object { "$_" }); $code = $LASTEXITCODE
            foreach ($l in $io) { Log "  install: $l" }
            $c = @(& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'C:\cr\install\install.ps1' -Check 2>&1 | ForEach-Object { "$_" }); $cc = $LASTEXITCODE
            $rec.install = [ordered]@{ exit = $code; check_exit = $cc; tail = @($io | Select-Object -Last 5); check_tail = @($c | Select-Object -Last 5) }
            $ok = ($code -eq 0 -and $cc -eq 0 -and (Test-Path -LiteralPath $UiExe) -and (Test-Path -LiteralPath (Join-Path $PF 'purge-broker.exe')))
        }
        try { $rec.edge = Suspend-EdgeUpdate } catch { $rec.edge = "error: $($_.Exception.Message)" }
        $rec.telemetry = Suspend-M2Telemetry
        $rec.ok = [bool]$ok
        Write-JsonFile $rec (Join-Path $AD 'setup.json') 8
        "M3E SETUP $(if ($ok) { 'OK' } else { 'FAIL' }) app=$App build=$($rec.build) uac_admin=$($rec.uac.ConsentPromptBehaviorAdmin)"
    }

    'prepare' {
        $kind = Get-E2eKind $App
        $null = New-RunDir $Run
        $runRec = [ordered]@{ schema = 'purge.rig.run/1'; id = $App; run = $Run; kind = 'm3-e2e'; computer = $env:COMPUTERNAME; sid = $RigUserSid; user_sid = $RigUserSid
                              started = (NowIso); finished = $null; main = $null; pre = @(); install = $null; launch = $null; entries_created = @(); entries_left = @() }
        $state = [ordered]@{ app = $App; kind = $kind; label = $App; t0 = (NowIso); program = $null; ok = $false; error = $null }
        try {
            $A = $null
            if ($kind -eq 'app') {
                $A = Get-App $App
                foreach ($pid_ in @(@($A.pre) | Where-Object { $_ })) {
                    $pa = Get-App $pid_
                    $before = @(UninstallEntries)
                    $pr = Install-E2eApp $pa
                    $pr.entry = Find-MainEntry $pa $before @(UninstallEntries)
                    $runRec.pre += $pr
                }
            }
            try { $null = Wait-DefenderIdle -OutDir $AD -MaxWaitSec 300 } catch { Log "  !! defender idle: $($_.Exception.Message)" }
            $e0 = @(UninstallEntries)
            $null = Lists $Run 0; $null = Snap $Run 0
            $main = $null
            switch ($kind) {
                'app' {
                    $runRec.install = Install-E2eApp $A
                    $main = Find-MainEntry $A $e0 @(UninstallEntries)
                    if (-not $main) { throw "no ARP entry matches '$($A.match)'" }
                    $runRec.launch = Invoke-E2eLaunch $A $main
                    $state.match = "$($A.match)"
                }
                'fixture' {
                    $runRec.install = Install-E2eExecApp $E2eFixtures[$App]
                    $main = @(UninstallEntries | Where-Object { $_.key -ieq $E2eFixtures[$App].key }) | Select-Object -First 1
                    $state.label = $E2eFixtures[$App].label
                    $state.match = '^PurgeExecApp$'
                }
                default {
                    $runRec.install = Install-E2eMsi $E2eFixtures[$App]
                    if ($runRec.install.exit -ne 0) { throw "msiexec /i exited $($runRec.install.exit)" }
                    $code = $runRec.install.msi.product
                    $main = @(UninstallEntries | Where-Object { $_.key -like "*\Uninstall\$code" }) | Select-Object -First 1
                    $state.match = '^Purge E2E '
                    $state.msi_product = $code
                }
            }
            if (-not $main) { throw 'the installed program has no ARP entry' }
            $runRec.main = $main
            $runRec.entries_created = @(@(UninstallEntries) | Where-Object { $k = $_.key; -not @($e0 | Where-Object { $_.key -eq $k }).Count })
            $null = Lists $Run 1; $null = Snap $Run 1
            # The rig CLI path (RIG.md 4a): inventory, the program id of the main entry, harvest -> fp.json.
            $engine = Get-E2eEngine
            $inv = Join-Path $RD 'inv-1.json'
            $r = Invoke-Engine -Exe $engine -Arguments 'inventory --json' -StdoutFile $inv -TimeoutSec 900
            if ($r.exit -ne 0) { throw "inventory exited $($r.exit)" }
            $programId = Find-InventoryProgramId ([IO.File]::ReadAllText($inv) | ConvertFrom-Json) $main.key
            $r = Invoke-Engine -Exe $engine -Arguments ('harvest ' + (ConvertTo-EngineArg $programId) + ' -o ' + (ConvertTo-EngineArg (Join-Path $RD 'fp.json'))) -TimeoutSec 900
            if ($r.exit -ne 0) { throw "harvest exited $($r.exit)" }
            $state.program = [ordered]@{ name = "$($main.name)"; key = "$($main.key)"; program_id = $programId; loc = "$($main.loc)"; uninstall = "$($main.uninstall)"; quiet = "$($main.quiet)" }
            $state.engine = $engine
            $state.sessions_before = @(Get-M2Sessions)
            $state.quarantine_before = @(Get-M2QuarantineListing).Count
            $state.ok = $true
        } catch { $state.error = $_.Exception.Message; Log "!! prepare: $($state.error)" }
        $runRec.finished = NowIso
        Write-JsonFile $runRec (Join-Path $RD 'run.json') 12
        Save-State ([pscustomobject]$state)
        "M3E PREPARE $App ok=$($state.ok) kind=$kind name=$(if ($state.program) { $state.program.name -replace '\s', '_' }) program=$(if ($state.program) { $state.program.program_id }) error=$($state.error)"
    }

    'ui-start' {
        $rec = New-E2eStep 'ui-start'
        try {
            $l = LaunchMedium -Exe $UiExe -TaskName $UiTask -StartTimeoutSec 60
            Set-StateValue $st 'ui_pid' $l.pid
            $win = Get-UiWindow $st 60
            $rec.window = [bool]$win
            if ($win) {
                $sel = Select-E2eProgramRow $win "$($st.program.name)" "$($st.match)" 180
                $rec.select = $sel
                $rec.retries = $sel.scrolls
                $rec.ok = $sel.ok
                Set-StateValue $st 'row_text' $sel.row_text
            }
        } catch { $rec.detail = $_.Exception.Message }
        Save-State $st; Save-Step $rec 'ui-start'
        "M3E UI-START $App ok=$($rec.ok) ui_pid=$($st.ui_pid) row=$(if ($rec.select) { $rec.select.by }) scrolls=$(if ($rec.select) { $rec.select.scrolls })"
    }

    'ui-uninstall' {
        $rec = New-E2eStep 'ui-uninstall'
        $win = Get-UiWindow $st
        $w = Wait-E2eElement { Find-E2eById $win 'UninstallButton' } 60 -Enabled
        $rec.retries = $w.retries
        if ($w.el) {
            $rec.invoked = Invoke-E2eElement $w.el
            Set-StateValue $st 't_uninstall_click' (NowIso)
            $script:continued = $null
            $name = "$($st.program.name)"
            $watch = Watch-E2eWindow $win {
                # Continue is pressed by the host with a real key (rig-m3.ps1): Windows shows the UAC prompt of a
                # process that had no real input only as a flashing taskbar button (e2e-20261123-034653, 02u-uac-3).
                if ($script:continued -eq 'Focus') { return 'continue-focused' }
                if (Test-ConsentUp) { return 'uac' }
                if (Find-E2eDialogButton $win 'Uninstall') { return 'confirm' }
                $t = Get-E2eTexts $win
                if ($t -contains "Uninstall $name?") { return 'confirm' }
                if ($t -contains 'You cancelled the admin prompt.') { return 'cancelled' }
                foreach ($x in 'The administrator part could not start.', 'Purge needs an administrator account.', 'Something went wrong.') { if ($t -contains $x) { return 'error' } }
                $null
            } 240 -Each {
                if (-not $script:continued) {
                    $c = Find-E2eDialogButton $win 'Continue'
                    if ($c) {
                        $rec.fg_before_focus = Get-E2eForeground
                        try { $c.SetFocus(); $script:continued = 'Focus' } catch { $script:continued = Invoke-E2eElement $c }
                        $rec.fg_after_focus = Get-E2eForeground
                        Set-StateValue $st 't_continue' (NowIso)
                    }
                }
            }
            $rec.state = $watch.state; $rec.continue = $script:continued; $rec.seen = $watch.seen
            $rec.ok = ($watch.state -in 'uac', 'confirm', 'continue-focused')
        } else { $rec.detail = 'UninstallButton not found or not enabled' }
        Save-State $st; Save-Step $rec 'ui-uninstall'
        "M3E UI-UNINSTALL $App ok=$($rec.ok) state=$($rec.state) continue=$($rec.continue) uac=$(if ($rec.state -eq 'uac') { 'up' } elseif ($rec.state -eq 'continue-focused') { 'after-key' } else { 'none' }) fg_before=$($rec.fg_before_focus) fg_after=$($rec.fg_after_focus)"
    }

    'uac-front' {
        # Is the UAC prompt on the secure desktop? If it only sits on the taskbar (Windows does that when the asking
        # app was not the foreground app), press its taskbar button the way a user would, and check again.
        $rec = New-E2eStep "uac-front-$Step"
        $rec.consent = Test-ConsentUp
        $rec.fg = Get-E2eForeground
        $rec.secure_before = Test-E2eSecureDesktop
        $rec.invoked = $null; $rec.buttons = @()
        if ($rec.consent -and -not $rec.secure_before) {
            $root = [System.Windows.Automation.AutomationElement]::RootElement
            $trayCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'Shell_TrayWnd')
            $tray = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $trayCond)
            if ($tray) {
                $btnCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
                $btns = @($tray.FindAll([System.Windows.Automation.TreeScope]::Descendants, $btnCond))
                $rec.buttons = @($btns | ForEach-Object { "$($_.Current.Name)" })
                $uac = $btns | Where-Object { "$($_.Current.Name)" -match 'User Account Control|consent' } | Select-Object -First 1
                if ($uac) { $rec.invoked = Invoke-E2eElement $uac; Start-Sleep -Seconds 4 }
            }
        }
        $rec.secure_after = Test-E2eSecureDesktop
        $rec.ok = [bool]($rec.consent -and $rec.secure_after)
        Save-Step $rec "uac-front-$Step"
        "M3E UAC-FRONT $App ok=$($rec.ok) consent=$($rec.consent) fg=$($rec.fg) secure_before=$($rec.secure_before) invoked=$($rec.invoked) secure_after=$($rec.secure_after) buttons=$(@($rec.buttons) -join '|' -replace '\s', '_')"
    }

    'ui-await-confirm' {
        $rec = New-E2eStep 'ui-await-confirm'
        $win = Get-UiWindow $st
        $w = Wait-E2eElement { Find-E2eDialogButton $win 'Uninstall' } $(if ($WaitSec) { $WaitSec } else { 240 })
        $rec.retries = $w.retries; $rec.ok = [bool]$w.el; $rec.consent_up = (Test-ConsentUp)
        Set-StateValue $st 'broker_pid' (Get-BrokerPid)
        Save-State $st; Save-Step $rec 'ui-await-confirm'
        "M3E UI-AWAIT-CONFIRM $App ok=$($rec.ok) broker=$($st.broker_pid) consent_up=$($rec.consent_up)"
    }

    'ui-confirm' {
        $rec = New-E2eStep 'ui-confirm'
        $win = Get-UiWindow $st
        $btn = Find-E2eDialogButton $win 'Uninstall'
        $rec.texts = @(Get-E2eTexts $win)
        $q = $null
        try {
            $qc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, 'Use quiet mode when available')
            $q = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $qc)
        } catch { }
        $rec.quiet = Get-E2eToggle $q
        $rec.quiet_enabled = $(if ($q) { [bool]$q.Current.IsEnabled } else { $null })
        $route = $(if ($rec.texts -contains '2. Run its uninstaller at your level') { 'medium' } elseif ($rec.texts -contains '2. Run its uninstaller as administrator') { 'broker' } else { $null })
        $rec.route = $route
        Set-StateValue $st 'route' $route
        if ($btn) {
            $rec.invoked = Invoke-E2eElement $btn
            Set-StateValue $st 't_confirm' (NowIso)
            $rec.ok = [bool]$rec.invoked
        } else { $rec.detail = 'no confirm dialog' }
        Set-StateValue $st 'broker_pid' (Get-BrokerPid)
        Save-State $st; Save-Step $rec 'ui-confirm'
        "M3E UI-CONFIRM $App ok=$($rec.ok) route=$route quiet=$($rec.quiet) broker=$($st.broker_pid)"
    }

    'consent-wait' {
        if (-not $Step) { throw 'consent-wait needs -Step' }
        $rec = New-E2eStep "consent-wait-$Step"
        $bp = Get-BrokerPid
        $rec.broker_pid = $bp
        if ($bp) {
            $f = Join-Path $AD "dialog-$Step.json"
            $null = Invoke-Sec @('observe', "$bp", $f, "$(1000 * $(if ($WaitSec) { $WaitSec } else { 300 }))") $(if ($WaitSec) { $WaitSec + 60 } else { 360 })
            $rec.dialog = Read-Json $f
            $rec.ok = [bool]($rec.dialog -and $rec.dialog.found)
        }
        Save-Step $rec "consent-wait-$Step"
        $d = $rec.dialog
        "M3E DIALOG $App $Step found=$($rec.ok) broker=$bp footer=$(if ($d) { $d.footer_code }) primary=$(if ($d) { $d.has_primary }) il=$(if ($d) { $d.broker_il })"
    }

    'consent-approve' {
        if (-not $Step) { throw 'consent-approve needs -Step' }
        $rec = New-E2eStep "consent-approve-$Step"
        $bp = Get-BrokerPid
        $rec.broker_pid = $bp
        if ($bp) {
            $spec = [ordered]@{ out = (Join-Path $AD "press-$Step.json"); broker_pid = $bp; tick = $true; button = 100; arm_wait_ms = 1600; wait_ms = 30000 }
            Write-JsonFile $spec (Join-Path $AD "press-spec-$Step.json") 4
            $null = Invoke-Sec @('press', (Join-Path $AD "press-spec-$Step.json")) 90
            $rec.press = Read-Json $spec.out
            $rec.ok = [bool]($rec.press -and $rec.press.found -and $rec.press.button_enabled -and -not $rec.press.dialog_alive_after)
        }
        Set-StateValue $st "t_approved_$Step" (NowIso)
        Save-State $st; Save-Step $rec "consent-approve-$Step"
        "M3E APPROVE $App $Step ok=$($rec.ok) broker=$bp enabled=$(if ($rec.press) { $rec.press.button_enabled }) gone=$(if ($rec.press) { -not $rec.press.dialog_alive_after })"
    }

    'ui-wait-scan' {
        $rec = New-E2eStep 'ui-wait-scan'
        $win = Get-UiWindow $st
        $procs = New-Object System.Collections.ArrayList
        $since = $(if ($st.t_uninstall_click) { [datetime]$st.t_uninstall_click } else { (Get-Date).AddMinutes(-5) })
        $loc = "$($st.program.loc)"
        $watch = Watch-E2eWindow $win {
            if (Find-E2eById $win 'MoveButton') { return 'review' }
            if (Find-E2eById $win 'EmptyTitle') { return 'empty' }
            $t = Get-E2eTexts $win
            if ($t -contains 'The uninstaller failed.') { return 'failed' }
            foreach ($x in 'The wrong part was asked to run this.', 'The administrator part ended.', "Purge's engine ended.", 'Something went wrong.', 'The administrator part refused the request.') { if ($t -contains $x) { return 'error' } }
            $null
        } $(if ($WaitSec) { $WaitSec } else { 2400 }) -Each { Update-E2eUninstallers $procs $since $loc } -PollMs 600
        $rec.state = $watch.state
        # The pipeline page holds the stepper details and the bars (a failure stays on it; after a scan the UI moves to
        # the leftovers page): for the failing uninstallers, and whenever the stepper did not reach its end, read it
        # (then, after a scan, go back to the leftovers page). A flow that goes on to Move is not navigated.
        $seen = New-Object System.Collections.Generic.List[string]
        foreach ($s in $watch.seen) { $seen.Add($s) }
        $nav = $null
        if ((Get-E2eKind $App) -like 'fail-*' -or $watch.state -notin 'review', 'empty') { $nav = Find-E2eById $win 'NavQueue' }
        if ($nav) {
            $null = Invoke-E2eElement $nav
            Start-Sleep -Seconds 2
            foreach ($s in Get-E2eTexts $win) { if (-not $seen.Contains($s)) { $seen.Add($s) } }
            $rec.queue_texts = @(Get-E2eTexts $win)
            if ($watch.state -in 'review', 'empty' -and (Get-E2eKind $App) -notlike 'fail-*') { $back = Find-E2eById $win 'NavLeftovers'; if ($back) { $null = Invoke-E2eElement $back; Start-Sleep -Seconds 2 } }
        }
        $rec.seen = @($seen)
        $rec.uninstallers = @($procs)
        $rec.exit_codes = @($seen | ForEach-Object { Get-E2eExitCodeFromText $_ } | Where-Object { $null -ne $_ } | Select-Object -Unique)
        $mode = $(if ($seen -contains 'Some parts remain') { 'forced' } else { 'post' })
        Set-StateValue $st 'scan_state' $watch.state; Set-StateValue $st 'mode' $mode
        $rec.mode = $mode
        $rec.ok = ($watch.state -in 'review', 'empty')
        Save-State $st; Save-Step $rec 'ui-wait-scan'
        "M3E SCAN $App state=$($watch.state) mode=$mode seconds=$($watch.seconds) exit_codes=$($rec.exit_codes -join ',') uninstallers=$(@($procs | ForEach-Object { "$($_.name):$($_.il)" }) -join ',')"
    }

    'capture-post' {
        $rec = New-E2eStep 'capture-post'
        try {
            $null = Lists $Run 2; $null = Snap $Run 2
            $runRec = Read-Json (Join-Path $RD 'run.json')
            $e2 = @(UninstallEntries)
            $left = @(@($runRec.entries_created) | Where-Object { $k = $_.key; @($e2 | Where-Object { $_.key -eq $k }).Count })
            $runRec | Add-Member -NotePropertyName entries_left -NotePropertyValue $left -Force
            Write-JsonFile $runRec (Join-Path $RD 'run.json') 12
            # The rig CLI scan of the same machine state (the UI's broker scanned it a moment ago; nothing ran since).
            $plan = Join-Path $RD 'plan-purge.json'
            # The fingerprint the broker stored with the uninstall window (C:\ProgramData\Purge\fp\fp-<sha256 of
            # the program id>.json, bins\purge-broker\src\uninstall.rs); the rig's own fp.json has no window, and
            # --mode post refuses it. Copied first so the scan reads a rig-owned file.
            $fp = Join-Path $RD 'fp.json'
            if ("$($st.mode)" -eq 'post') {
                $sha = [Security.Cryptography.SHA256]::Create()
                $hash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$($st.program.program_id)")) | ForEach-Object { $_.ToString('x2') })
                $src = Join-Path $env:ProgramData "Purge\fp\fp-$hash.json"
                if (-not (Test-Path -LiteralPath $src)) { throw "no broker fingerprint at $src" }
                $fp = Join-Path $RD 'fp-broker.json'
                Copy-Item -LiteralPath $src -Destination $fp -Force
                $rec.fp = $src
            }
            $a = 'scan --fp ' + (ConvertTo-EngineArg $fp) + ' --mode ' + $st.mode + ' --app ' + $App + ' -o ' + (ConvertTo-EngineArg $plan)
            $r = Invoke-Engine -Exe $st.engine -Arguments $a -TimeoutSec 900
            if ($r.exit -ne 0 -or -not (Test-Path -LiteralPath $plan)) { throw "rig CLI scan exited $($r.exit)" }
            # The preselected set: every item the plan ticks (preselected, not Blocked), as the review page ticks it;
            # the M2 rig's default selection (Safe and preselected) is recorded beside it.
            $pp = Read-Json $plan
            $sc = Read-Json (Get-M2Sidecar $plan)
            $pi = @(@($pp.items) | ForEach-Object { $_ } | Where-Object { $_ }); $si = @(@($sc.items) | ForEach-Object { $_ } | Where-Object { $_ })
            if ($pi.Count -ne $si.Count) { throw "the CLI plan has $($pi.Count) items, its sidecar $($si.Count)" }
            $ids = @(for ($i = 0; $i -lt $pi.Count; $i++) { if ($pi[$i].preselected -eq $true -and "$($pi[$i].band)" -ne 'Blocked') { "$($si[$i].id)" } })
            $safeDefault = @(Get-M2DefaultSelection $plan)
            $items = @(@($sc.items) | ForEach-Object { $_ } | Where-Object { $_ -and $ids -contains "$($_.id)" })
            $keys = @($items | ForEach-Object { Get-E2eTargetKey $_.target })
            $rec.cli = [ordered]@{ plan = 'run\plan-purge.json'; items = $si.Count; preselected_n = $ids.Count; preselected_keys = $keys; safe_default_n = $safeDefault.Count }
            Set-StateValue $st 'cli' $rec.cli
            Write-JsonFile (New-E2eDeepScope @($items | ForEach-Object { $_.target })) (Join-Path $W 'deepscope.json') 12
            $rec.settle = Wait-M2BootSettle -MaxSec 300 -MinUptimeSec 180
            $null = Invoke-M2Snap (Join-Path $W 'snap-a.tsv.gz')
            $null = Invoke-M2Deep @((Join-Path $W 'deepscope.json')) (Join-Path $AD 'deep-a.json')
            Set-StateValue $st 'sessions_before' @(Get-M2Sessions)
            $rec.ok = $true
        } catch { $rec.detail = $_.Exception.Message; Log "!! capture-post: $($rec.detail)" }
        Save-State $st; Save-Step $rec 'capture-post'
        "M3E CAPTURE-POST $App ok=$($rec.ok) cli_preselected=$(if ($rec.cli) { $rec.cli.preselected_n }) error=$($rec.detail)"
    }

    'ui-move' {
        $rec = New-E2eStep 'ui-move'
        $win = Get-UiWindow $st
        $w = Wait-E2eElement { Find-E2eById $win 'MoveButton' } 60 -Enabled
        $rec.retries = $w.retries
        $rec.footer = Get-E2eName (Find-E2eById $win 'FooterCount')
        $rec.move_text = Get-E2eName (Find-E2eById $win 'MoveText')
        if ($w.el) {
            $rec.invoked = Invoke-E2eElement $w.el
            Set-StateValue $st 't_move' (NowIso)
            $watch = Watch-E2eWindow $win {
                $t = Get-E2eTexts $win
                if ($t -contains 'Confirm in the Purge security prompt.') { return 'prompt' }
                if (Find-E2eById $win 'ResultTitleText') { return 'result' }
                if ($t | Where-Object { $_ -like '*cannot be quarantined*' }) { return 'refused' }
                $null
            } 600
            $rec.state = $watch.state; $rec.seen = $watch.seen
            $rec.code = Get-E2eName (Find-E2eById $win 'WaitingCodeText')
            $rec.ok = ($watch.state -eq 'prompt')
        } else { $rec.detail = 'MoveButton not found or not enabled'; $rec.state = 'no-move' }
        Save-State $st; Save-Step $rec 'ui-move'
        "M3E UI-MOVE $App ok=$($rec.ok) state=$($rec.state) footer=$($rec.footer -replace '\s', '_') code=$($rec.code)"
    }

    'ui-wait-result' {
        $rec = New-E2eStep 'ui-wait-result'
        $win = Get-UiWindow $st
        $watch = Watch-E2eWindow $win {
            if (Find-E2eById $win 'ResultTitleText') { return 'result' }
            $t = Get-E2eTexts $win
            if ($t | Where-Object { $_ -like 'The administrator part ended during the move*' }) { return 'interrupted' }
            if ($t -contains 'Nothing was moved: the prompt was cancelled.') { return 'declined' }
            $null
        } $(if ($WaitSec) { $WaitSec } else { 1800 })
        $rec.state = $watch.state; $rec.seen = $watch.seen
        $rec.title = Get-E2eName (Find-E2eById $win 'ResultTitleText')
        $rec.detail_text = Get-E2eName (Find-E2eById $win 'ResultDetailText')
        $rec.undo_offered = [bool](Find-E2eById $win 'UndoAllButton')
        $rec.ok = ($watch.state -eq 'result')
        Save-Step $rec 'ui-wait-result'
        "M3E RESULT $App state=$($watch.state) title=$($rec.title -replace '\s', '_') undo=$($rec.undo_offered)"
    }

    'capture-exec' {
        $rec = New-E2eStep 'capture-exec'
        try {
            $null = Invoke-M2Snap (Join-Path $W 'snap-b.tsv.gz')
            $null = Invoke-M2Deep @((Join-Path $W 'deepscope.json')) (Join-Path $AD 'deep-b.json')
            $new = @(Get-M2Sessions | Where-Object { @($st.sessions_before) -notcontains $_ })
            $rec.sessions_new = $new
            $session = $(if ($new.Count) { $new[$new.Count - 1] } else { $null })
            Set-StateValue $st 'session' $session
            if (-not $session) { throw 'no new session under C:\ProgramData\Purge\sessions' }
            $null = Copy-M2Session $session $AD 'sess-exec'
            $sd = Get-M2SessionDir $session
            $journal = Join-Path $sd 'journal.jsonl'; $report = Join-Path $sd 'report.json'
            $v = Invoke-M2Execdiff -Before (Join-Path $W 'snap-a.tsv.gz') -After (Join-Path $W 'snap-b.tsv.gz') -Journal $journal -Report $report `
                -DeepBefore (Join-Path $AD 'deep-a.json') -DeepAfter (Join-Path $AD 'deep-b.json') -Out (Join-Path $AD 'execdiff.json')
            $ed = Read-Json (Join-Path $AD 'execdiff.json')
            $rec.execdiff = [ordered]@{ ok = $v.ok; counts = $ed.counts }
            $rep = Read-Json $report
            $items = @(@($rep.items) | ForEach-Object { $_ } | Where-Object { $_ })
            $exec = [ordered]@{ schema = 'purge.rig.m3e2e.executed/1'; app = $App; session = $session; state = "$($rep.state)"; counts = $rep.counts; restore_point = $rep.restore_point
                                items = @($items | ForEach-Object { [ordered]@{ item = "$($_.item)"; key = (Get-E2eTargetKey $_.target); target = $_.target; outcome = "$($_.outcome.kind)" } }) }
            Write-JsonFile $exec (Join-Path $RD 'executed.json') 12
            $rec.compare = Compare-E2eSets @($st.cli.preselected_keys) @($exec.items | ForEach-Object { $_.key })
            $rec.report_state = $exec.state
            $rec.ok = $true
        } catch { $rec.detail = $_.Exception.Message; Log "!! capture-exec: $($rec.detail)" }
        Save-State $st; Save-Step $rec 'capture-exec'
        "M3E CAPTURE-EXEC $App ok=$($rec.ok) session=$($st.session) equal=$(if ($rec.compare) { $rec.compare.equal }) collateral=$(if ($rec.execdiff) { $rec.execdiff.counts.collateral }) error=$($rec.detail)"
    }

    'ui-undo' {
        $rec = New-E2eStep 'ui-undo'
        $win = Get-UiWindow $st
        $w = Wait-E2eElement { Find-E2eById $win 'UndoAllButton' } 60 -Enabled
        $rec.retries = $w.retries
        if ($w.el) {
            $rec.invoked = Invoke-E2eElement $w.el
            $watch = Watch-E2eWindow $win {
                if (Test-ConsentUp) { return 'uac' }
                $t = Get-E2eTexts $win
                if ($t -contains 'Confirm in the Purge security prompt.') { return 'prompt' }
                if (Find-E2eById $win 'UndoTitleText') { return 'undone' }
                $null
            } 300
            $rec.state = $watch.state; $rec.seen = $watch.seen
            $rec.ok = ($watch.state -in 'prompt', 'uac')
        } else { $rec.detail = 'UndoAllButton not found or not enabled' }
        Save-Step $rec 'ui-undo'
        "M3E UI-UNDO $App ok=$($rec.ok) state=$($rec.state) uac=$(if ($rec.state -eq 'uac') { 'up' } else { 'none' })"
    }

    'ui-wait-undone' {
        $rec = New-E2eStep 'ui-wait-undone'
        $win = Get-UiWindow $st
        $watch = Watch-E2eWindow $win { if (Find-E2eById $win 'UndoTitleText') { 'undone' } else { $null } } $(if ($WaitSec) { $WaitSec } else { 1800 })
        $rec.state = $watch.state; $rec.seen = $watch.seen
        $rec.title = Get-E2eName (Find-E2eById $win 'UndoTitleText')
        $rec.detail_text = Get-E2eName (Find-E2eById $win 'UndoDetailText')
        $rec.ok = ($watch.state -eq 'undone')
        Save-Step $rec 'ui-wait-undone'
        "M3E UNDONE $App state=$($watch.state) title=$($rec.title -replace '\s', '_')"
    }

    'capture-undo' {
        $rec = New-E2eStep 'capture-undo'
        try {
            if (-not $st.session) { throw 'no session to check' }
            $null = Invoke-M2Deep @((Join-Path $W 'deepscope.json')) (Join-Path $AD 'deep-c.json')
            $null = Copy-M2Session $st.session $AD 'sess-undo'
            $journal = Join-Path (Get-M2SessionDir $st.session) 'journal.jsonl'
            $v = Invoke-M2Fidelity (Join-Path $AD 'deep-a.json') (Join-Path $AD 'deep-c.json') $journal (Join-Path $AD 'fidelity.json')
            $fd = Read-Json (Join-Path $AD 'fidelity.json')
            $rec.fidelity = [ordered]@{ ok = $v.ok; rows = @(@($fd.rows) | Where-Object { $_ } | ForEach-Object { [ordered]@{ action = $_.action; ops = $_.ops; differing = $_.differing; percent = $_.percent; pass = $_.pass } }) }
            $rec.ok = $true
        } catch { $rec.detail = $_.Exception.Message; Log "!! capture-undo: $($rec.detail)" }
        Save-Step $rec 'capture-undo'
        "M3E CAPTURE-UNDO $App ok=$($rec.ok) fidelity=$(if ($rec.fidelity) { $rec.fidelity.ok }) error=$($rec.detail)"
    }

    'fail-check' {
        $rec = New-E2eStep 'fail-check'
        $rec.arp_present = (Test-RegKey "$($st.program.key)")
        $variant = $E2eFixtures[$App].variant
        $rec.fixture_key_present = (Test-RegKey "HKLM\SOFTWARE\PurgeE2eMsi\$variant")
        $rec.sessions_new = @(Get-M2Sessions | Where-Object { @($st.sessions_before) -notcontains $_ })
        $rec.quarantine_before = $st.quarantine_before
        $rec.quarantine_after = @(Get-M2QuarantineListing).Count
        $rec.msi_products = @(MsiProducts | Where-Object { "$($_.code)" -eq "$($st.msi_product)" } | ForEach-Object { "$($_.code)" })
        $rec.ok = $true
        Save-Step $rec 'fail-check'
        "M3E FAIL-CHECK $App arp_present=$($rec.arp_present) fixture_key=$($rec.fixture_key_present) sessions_new=$($rec.sessions_new.Count) quarantine=$($rec.quarantine_before)->$($rec.quarantine_after)"
    }

    'finish' {
        $rec = New-E2eStep 'finish'
        $since = $(if ($st.t0) { [datetime]$st.t0 } else { (Get-Date).AddHours(-3) })
        try { $null = & C:\cr\guest\broker-timings.ps1 -Out (Join-Path $AD 'timings.jsonl') -Since $since } catch { $rec.detail = "broker-timings: $($_.Exception.Message)"; Log "!! $($rec.detail)" }
        $rec.brokers_alive = @(Get-Process -Name 'purge-broker' -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
        # Every other "Purge" Application event (warnings, errors) and the crash records of Purge processes, for
        # a broker that ended early.
        try {
            $utc = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            $ev = @(Get-WinEvent -LogName Application -FilterXPath "*[System[TimeCreated[@SystemTime>='$utc']]]" -ErrorAction SilentlyContinue |
                Where-Object { ($_.ProviderName -eq 'Purge' -and $_.Id -ne 100) -or ($_.ProviderName -in @('Application Error', 'Windows Error Reporting', '.NET Runtime') -and "$($_.Message)" -match 'purge') } |
                Sort-Object RecordId | ForEach-Object { [ordered]@{ t = $_.TimeCreated.ToString('o'); provider = $_.ProviderName; id = $_.Id; level = $_.LevelDisplayName; message = "$($_.Message)" } })
            Write-JsonFile $ev (Join-Path $AD 'app-events.json') 6
            $rec.app_events = $ev.Count
        } catch { Log "!! app events: $($_.Exception.Message)" }
        Unregister-ScheduledTask -TaskName $UiTask -Confirm:$false -ErrorAction SilentlyContinue
        Get-ProcList | Where-Object { $_.path -and $_.path -ieq $UiExe } | ForEach-Object { Stop-Process -Id $_.pid -Force -ErrorAction SilentlyContinue }
        $steps = [ordered]@{}
        foreach ($f in @(Get-ChildItem -LiteralPath $AD -Filter 'step-*.json' -File | Sort-Object LastWriteTimeUtc)) { $steps[$f.BaseName.Substring(5)] = Read-Json $f.FullName }
        $doc = [ordered]@{
            schema = 'purge.rig.m3e2e.app/1'; app = $App; kind = (Get-E2eKind $App); label = $st.label; t0 = $st.t0; ended = (NowIso); uac = (Get-UacValues)
            setup = (Read-Json (Join-Path $AD 'setup.json')); state = $st; steps = $steps
            run = (Read-Json (Join-Path $RD 'run.json')); executed = (Read-Json (Join-Path $RD 'executed.json'))
            files = [ordered]@{ execdiff = (Test-Path -LiteralPath (Join-Path $AD 'execdiff.json')); fidelity = (Test-Path -LiteralPath (Join-Path $AD 'fidelity.json'))
                                timings = (Test-Path -LiteralPath (Join-Path $AD 'timings.jsonl')); plan = (Test-Path -LiteralPath (Join-Path $RD 'plan-purge.json')) }
        }
        Write-JsonFile $doc (Join-Path $AD 'e2e.json') 16
        # The rigtool run directory goes with the evidence (the host scores danger from it); snap A / B stay in the guest.
        $rdCopy = Join-Path $AD 'run'
        if (Test-Path -LiteralPath $rdCopy) { Remove-Item -LiteralPath $rdCopy -Recurse -Force }
        if (Test-Path -LiteralPath $RD) { Copy-Item -LiteralPath $RD -Destination $rdCopy -Recurse }
        $zip = Join-Path 'C:\cr\out' "m3-e2e-$App.zip"
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path (Join-Path $AD '*') -DestinationPath $zip -Force
        "M3E FINISH $App zip=$((Get-Item $zip).Length) timings=$($doc.files.timings) brokers_alive=$($rec.brokers_alive.Count)"
    }
}
