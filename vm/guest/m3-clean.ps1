<#
  Purge rig, M3 mode m3-clean-start (vm\RIG.md section 15; docs\M3_DESIGN.md 11.2, 12 G11, 9.1 "VM: functional only;
  WARP numbers reported"; docs\M3_FINISH_PLAN.md B9). Guest side, Windows PowerShell 5.1, run elevated by
  C:\cr\agent.ps1 as one job per phase on Purge-CleanPro; the host driver is vm\rig-m3-clean.ps1, the scorer
  vm\truth\m3-clean-score.ps1.

    & C:\cr\guest\m3-clean.ps1 -Phase <phase> [-Tag <t>] [-WaitSec <n>]

  The setup under test is C:\cr\m3clean\<Purge-Setup-*.exe> (pushed by the host; the only one in that folder). Every
  output is under C:\cr\out\m3-clean\ (log clean.log, one JSON per phase); result lines start with "M3C ".

  Phases, in the host's order:
    pre                   preconditions (no .NET runtime, no Windows App Runtime, no VC++ redistributable), SmartScreen,
                          Smart App Control, Defender and UAC state, the setup's hash, signature and mark of the web
    motw-start            (skipped with the host's -NoMotw) gives the setup a mark of the web (Zone.Identifier ADS,
                          ZoneId=3, ReferrerUrl/HostUrl = a GitHub release URL of the project; nothing is downloaded),
                          then starts it interactively at medium through the shell (explorer.exe "<setup>") and
                          records what SmartScreen / Smart App Control do; the host takes a screenshot
    motw-end              after the host's Esc keys: records again, stops whatever is left of that start; report only
    install -Tag 1|2      the setup, silent and elevated (/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=); then the
                          layout, owners, install.ps1 -Check, the data root, the event source, the ARP entry, shortcuts
    ui-start              Purge.exe at medium integrity (no arguments); UI Automation: the window, the list
                          (automation id ProgramList) and the rows that carry the machine's ARP names; the integrity
                          of Purge.exe and purge-engine.exe; the modules both loaded (no runtime from outside)
    ui-stop               closes it
    bench -Tag <n>        n launches of Purge.exe --bench-exit --bench-until icons_visible at medium with
                          PURGE_BENCH_OUT (the real-engine mode of xtask bench-launch, run here without cargo);
                          WARP numbers reported, launch 1 = cold icon cache
    uninstall-no          Purge.exe started at medium first; the Installed-apps entry's UninstallString, silent;
                          processes gone, event source, files and shortcuts removed, %ProgramData%\Purge kept as it was
    uninstall-yes-start   the same entry with /SILENT only: the data-folder question is shown; the dialog is found
    uninstall-yes-answer  "Yes" by UI Automation (the agent is elevated like the uninstaller); everything removed,
                          the data root too
    rollback              a junction planted below a pre-created %ProgramFiles%\Purge (install.ps1 -ProtectOnly refuses
                          a reparse point, so the post-install step fails); the setup must fail and leave nothing
    pack                  zips C:\cr\out\m3-clean\ to C:\cr\out\m3-clean.zip
#>
param(
    [Parameter(Mandatory)]
    [ValidateSet('pre', 'motw-start', 'motw-end', 'install', 'ui-start', 'ui-stop', 'bench', 'uninstall-no', 'uninstall-yes-start',
                 'uninstall-yes-answer', 'rollback', 'pack')]
    [string] $Phase,
    [string] $Tag = '',
    [int] $WaitSec = 120
)
. C:\cr\guest\riglib.ps1
$ErrorActionPreference = 'Continue'

$Out = 'C:\cr\out\m3-clean'
$Bin = 'C:\cr\m3clean'
$PF = 'C:\Program Files\Purge'
$DataRoot = 'C:\ProgramData\Purge'
$AppId = '{7C1B9E64-2D58-4F1A-9B03-6E4C5A8D7F21}_is1'
$ArpKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$AppId"
$EventKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Purge'
$StartLnk = Join-Path ([Environment]::GetFolderPath('CommonStartMenu')) 'Programs\Purge.lnk'
$DesktopLnk = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Purge.lnk'
$UiTask = 'PurgeRigM3CleanUi'
$Canary = 'C:\cr\m3clean-canary'
$Planted = Join-Path $PF 'zz-planted'
# Payload of the setup (install\inno\purge.iss [Files]) and what the uninstaller must remove.
$Layout = @('purge-engine.exe', 'purge-broker.exe', 'Purge.exe', 'kb', 'setup\install.ps1', 'unins000.exe', 'unins000.dat')
$Images = @('Purge.exe', 'purge-broker.exe', 'purge-engine.exe')
New-Item -ItemType Directory -Force $Out, $Bin | Out-Null
Set-RunLog (Join-Path $Out 'clean.log')
if ($Tag -and $Tag -notmatch '^[A-Za-z0-9_-]+$') { throw "bad tag '$Tag'" }

# ----------------------------------------------------------------------------------------------- helpers

function Get-Setup {
    $s = @(Get-ChildItem -LiteralPath $Bin -Filter 'Purge-Setup-*.exe' -File -ErrorAction SilentlyContinue)
    if ($s.Count -ne 1) { throw "expected one Purge-Setup-*.exe in $Bin, found $($s.Count)" }
    $s[0].FullName
}

function Read-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
}

function Get-TreeList([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    $items = @(Get-Item -LiteralPath $Root -Force) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue)
    @($items | ForEach-Object {
        $len = $(if ($_.PSIsContainer) { -1 } else { $_.Length })
        '{0}|{1}|{2}' -f $_.FullName, $len, $_.LastWriteTimeUtc.Ticks
    } | Sort-Object)
}

function Get-ArpNames {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
               'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    $n = foreach ($r in $roots) {
        Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and $p.PSObject.Properties['DisplayName'] -and "$($p.DisplayName)".Trim() -and -not ($p.PSObject.Properties['SystemComponent'] -and $p.SystemComponent -eq 1)) { "$($p.DisplayName)".Trim() }
        }
    }
    @($n | Sort-Object -Unique)
}

function Get-Arp {
    $p = Get-ItemProperty -LiteralPath $ArpKey -ErrorAction SilentlyContinue
    if (-not $p) { return [ordered]@{ present = $false } }
    $v = { param($n) if ($p.PSObject.Properties[$n]) { "$($p.$n)" } else { $null } }
    [ordered]@{ present = $true; key = $ArpKey; display_name = (& $v 'DisplayName'); display_version = (& $v 'DisplayVersion'); publisher = (& $v 'Publisher')
                uninstall_string = (& $v 'UninstallString'); quiet_uninstall_string = (& $v 'QuietUninstallString'); install_location = (& $v 'InstallLocation') }
}

function Get-EventSource {
    $src = $false
    try { $src = [Diagnostics.EventLog]::SourceExists('Purge') } catch { }
    [ordered]@{ key = (Test-Path -LiteralPath $EventKey); source_exists = $src }
}

function Get-Layout {
    $files = [ordered]@{}
    foreach ($f in $Layout) { $files[$f] = (Test-Path -LiteralPath (Join-Path $PF $f)) }
    $owners = [ordered]@{}
    foreach ($f in @('.', 'purge-broker.exe', 'Purge.exe', 'purge-engine.exe', 'kb')) {
        $p = $(if ($f -eq '.') { $PF } else { Join-Path $PF $f })
        $owners[$f] = $(if (Test-Path -LiteralPath $p) { try { (Get-Acl -LiteralPath $p).Owner } catch { "error: $($_.Exception.Message)" } } else { $null })
    }
    [ordered]@{ dir = (Test-Path -LiteralPath $PF -PathType Container); files = $files; owners = $owners
                pf_sddl = $(if (Test-Path -LiteralPath $PF) { try { (Get-Acl -LiteralPath $PF).Sddl } catch { $null } } else { $null })
                tree = @(Get-TreeList $PF | Select-Object -First 400) }
}

function Get-DataRoot {
    $exists = Test-Path -LiteralPath $DataRoot -PathType Container
    $parts = [ordered]@{}
    foreach ($p in @('sessions', 'Quarantine', 'fp', 'kb', 'sessions\index.json')) { $parts[$p] = (Test-Path -LiteralPath (Join-Path $DataRoot $p)) }
    $sddl = $(if ($exists) { try { (Get-Acl -LiteralPath $DataRoot).Sddl } catch { $null } } else { $null })
    $aside = @(Get-ChildItem -LiteralPath 'C:\ProgramData' -Directory -Force -Filter 'Purge*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'Purge' } | ForEach-Object { $_.Name })
    [ordered]@{ exists = $exists; parts = $parts; sddl = $sddl; protected = ("$sddl" -match 'D:P'); aside = $aside; tree = @(Get-TreeList $DataRoot) }
}

function Get-Shortcuts { [ordered]@{ start_menu = (Test-Path -LiteralPath $StartLnk); desktop = (Test-Path -LiteralPath $DesktopLnk) } }

function Get-PurgeProcs {
    @(Get-ProcList | Where-Object { $Images -contains $_.name } | ForEach-Object { [ordered]@{ pid = $_.pid; ppid = $_.ppid; name = $_.name; path = $_.path } })
}

function Get-CiEvents([datetime]$Since) {
    @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; StartTime = $Since } -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in 3033, 3034, 3076, 3077, 3089, 3118, 3119 } | Select-Object -First 50 |
        ForEach-Object { [ordered]@{ id = $_.Id; time = $_.TimeCreated.ToString('o'); message = ("$($_.Message)" -split "`r?`n")[0] } })
}

# Runs a program elevated (the agent's token) to the end; exit code and seconds.
function Invoke-Wait([string]$Exe, [string]$Arguments, [int]$TimeoutSec) {
    $t = Get-Date
    Log "run: `"$Exe`" $Arguments"
    $p = Start-Native $Exe $Arguments
    $done = $p.WaitForExit($TimeoutSec * 1000)
    if (-not $done) { Log "  !! still running after $TimeoutSec s; killed"; try { $p.Kill() } catch { } }
    $code = $(if ($done) { $p.ExitCode } else { $null })
    Log "  exit $code after $([int]((Get-Date) - $t).TotalSeconds) s"
    [ordered]@{ exit = $code; timed_out = (-not $done); seconds = [math]::Round(((Get-Date) - $t).TotalSeconds, 1); pid = $p.Id }
}

# Inno's uninstaller hands over to a copy of itself in %TEMP% (_iu*.tmp): wait for that copy too.
function Wait-UninstallDone([int]$TimeoutSec = 300) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        $busy = @(Get-ProcList | Where-Object { $_.name -match '^_iu.*\.tmp$' -or $_.name -match '^unins\d+\.exe$' })
        if (-not $busy.Count) { return $true }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    Log "  !! uninstaller processes still running after $TimeoutSec s: $(@($busy | ForEach-Object { $_.name }) -join ', ')"
    $false
}

function Get-InnoLogTail([string]$Path, [int]$N = 40) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue | Select-Object -Last $N)
}

function Get-UninstallCommand($Arp) {
    if (-not $Arp.present -or -not $Arp.uninstall_string) { return $null }
    Split-CommandLine $Arp.uninstall_string
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class M3CleanIl {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, int access, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr t, int cls, IntPtr buf, int len, out int need);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, int i);
    // The integrity RID of a process (0x2000 medium, 0x3000 high), -1 when it cannot be read.
    public static int Rid(int pid) {
        IntPtr p = OpenProcess(0x1000, false, pid);
        if (p == IntPtr.Zero) return -1;
        IntPtr t;
        try {
            if (!OpenProcessToken(p, 8, out t)) return -1;
            try {
                int need; GetTokenInformation(t, 25, IntPtr.Zero, 0, out need);
                IntPtr buf = Marshal.AllocHGlobal(need);
                try {
                    if (!GetTokenInformation(t, 25, buf, need, out need)) return -1;
                    IntPtr sid = Marshal.ReadIntPtr(buf);
                    int n = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                    return Marshal.ReadInt32(GetSidSubAuthority(sid, n - 1));
                } finally { Marshal.FreeHGlobal(buf); }
            } finally { CloseHandle(t); }
        } finally { CloseHandle(p); }
    }
}
'@ -ErrorAction SilentlyContinue

function Get-Il([int]$ProcessId) {
    $r = [M3CleanIl]::Rid($ProcessId)
    switch ($r) { 0x1000 { 'Low' } 0x2000 { 'Medium' } 0x2100 { 'MediumPlus' } 0x3000 { 'High' } 0x4000 { 'System' } default { "rid $r" } }
}

# Modules of a process outside Windows and outside the install directory; "foreign" = a runtime the app should not
# need (dotnet, a WindowsApps framework package, a Windows App SDK DLL from elsewhere).
function Get-ModuleReport([int]$ProcessId) {
    $rec = [ordered]@{ pid = $ProcessId; count = 0; outside = @(); foreign = @(); error = $null }
    try {
        $mods = @((Get-Process -Id $ProcessId -ErrorAction Stop).Modules | ForEach-Object { $_.FileName })
        $rec.count = $mods.Count
        $win = $env:WINDIR.TrimEnd('\') + '\'
        $rec.outside = @($mods | Where-Object { -not $_.StartsWith($win, [StringComparison]::OrdinalIgnoreCase) -and -not $_.StartsWith($PF + '\', [StringComparison]::OrdinalIgnoreCase) })
        $rec.foreign = @($mods | Where-Object { $_ -match '(?i)\\dotnet\\|\\WindowsApps\\|WindowsAppRuntime|Microsoft\.WindowsAppSDK' -and -not $_.StartsWith($PF + '\', [StringComparison]::OrdinalIgnoreCase) })
        $rec.vcruntime = @($mods | Where-Object { $_ -match '(?i)\\(vcruntime|msvcp)1\d\d[^\\]*\.dll$' })
    } catch { $rec.error = $_.Exception.Message }
    $rec
}

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes -ErrorAction SilentlyContinue

function Find-UiWindow([int]$ProcessId, [int]$Sec) {
    $root = [Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcessId)
    $deadline = (Get-Date).AddSeconds($Sec)
    do {
        $w = $root.FindFirst([Windows.Automation.TreeScope]::Children, $cond)
        if ($w) { return $w }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    $null
}

function Get-UiNames($Element) {
    @($Element.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition) |
        ForEach-Object { "$($_.Current.Name)" } | Where-Object { $_ } | Select-Object -First 800)
}

# An ARP name shown as a row: an element name that is the name, or starts with it followed by a line break or space
# (the row's text block: name, then the sub-line). "Purge.App.ProgramRow" (a type name) does not count as "Purge".
function Test-NameShown([string]$Name, [string[]]$Texts) {
    $rx = '^' + [regex]::Escape($Name) + '(?:$|[\r\n\s])'
    foreach ($t in $Texts) { if ($t -match $rx) { return $true } }
    $false
}

# A top-level window of any process that shows $Text (the Inno uninstaller's message box), or $null.
function Find-TextWindow([string]$Text, [int]$Sec) {
    $root = [Windows.Automation.AutomationElement]::RootElement
    $deadline = (Get-Date).AddSeconds($Sec)
    do {
        foreach ($w in $root.FindAll([Windows.Automation.TreeScope]::Children, [Windows.Automation.Condition]::TrueCondition)) {
            try {
                foreach ($e in $w.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)) {
                    if ("$($e.Current.Name)".IndexOf($Text, [StringComparison]::Ordinal) -ge 0) { return $w }
                }
            } catch { }
        }
        Start-Sleep -Milliseconds 700
    } while ((Get-Date) -lt $deadline)
    $null
}

function Stop-PurgeUi {
    Unregister-ScheduledTask -TaskName $UiTask -Confirm:$false -ErrorAction SilentlyContinue
    foreach ($p in Get-PurgeProcs) {
        try { $gp = Get-Process -Id $p.pid -ErrorAction Stop; if ($gp.MainWindowHandle -ne [IntPtr]::Zero) { $null = $gp.CloseMainWindow() } } catch { }
    }
    Start-Sleep -Seconds 3
    foreach ($p in Get-PurgeProcs) { Stop-Process -Id $p.pid -Force -ErrorAction SilentlyContinue }
}

# Purge.exe at medium; returns its pid and the purge-engine.exe it started (waits up to $Sec for both).
function Start-PurgeUi([int]$Sec = 60) {
    Stop-PurgeUi
    $exe = Join-Path $PF 'Purge.exe'
    $l = LaunchMedium -Exe $exe -TaskName $UiTask -StartTimeoutSec $Sec
    $engine = $null
    $deadline = (Get-Date).AddSeconds($Sec)
    while ($l.pid -and -not $engine -and (Get-Date) -lt $deadline) {
        $engine = Get-ProcList | Where-Object { $_.name -eq 'purge-engine.exe' -and $_.ppid -eq $l.pid } | Select-Object -First 1
        if (-not $engine) { Start-Sleep -Milliseconds 500 }
    }
    [ordered]@{ ui_pid = $l.pid; engine_pid = $(if ($engine) { $engine.pid }); engine_path = $(if ($engine) { $engine.path }) }
}

function Get-RemovalState {
    $leftover = @()
    if (Test-Path -LiteralPath $PF) { $leftover = @(Get-TreeList $PF) }
    [ordered]@{ arp = (Get-Arp); event_source = (Get-EventSource); pf_exists = (Test-Path -LiteralPath $PF); leftovers = $leftover
                shortcuts = (Get-Shortcuts); processes = @(Get-PurgeProcs); data_root = (Get-DataRoot) }
}

function Get-Motw([string]$Path) {
    try { (@(Get-Content -LiteralPath $Path -Stream Zone.Identifier -ErrorAction Stop) -join "`n") } catch { $null }
}

function Stop-SetupProcs {
    Get-ProcList | Where-Object { $_.name -match '^Purge-Setup-.*\.(exe|tmp)$' } | ForEach-Object { Stop-Process -Id $_.pid -Force -ErrorAction SilentlyContinue }
}

# What a shell start of the marked setup led to: SmartScreen's process, the setup's processes, a UAC prompt, the Code
# Integrity events (3077/3033: blocked, 3076/3034: audit = Smart App Control in evaluation), the setup's own window.
function Get-MotwState([datetime]$Since) {
    $procs = @(Get-ProcList)
    $wiz = Find-TextWindow 'Setup - Purge' 2
    [ordered]@{ smartscreen_proc = (@($procs | Where-Object { $_.name -eq 'smartscreen.exe' }).Count -gt 0)
                setup_procs = @($procs | Where-Object { $_.name -match '^Purge-Setup-.*\.(exe|tmp)$' } | ForEach-Object { $_.name })
                consent = (@($procs | Where-Object { $_.name -eq 'consent.exe' }).Count -gt 0)
                wizard = [bool]$wiz
                code_integrity = @(Get-CiEvents $Since)
                smartscreen_events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-SmartScreen/Debug'; StartTime = $Since } -ErrorAction SilentlyContinue | Select-Object -First 20 |
                                       ForEach-Object { [ordered]@{ id = $_.Id; message = ("$($_.Message)" -split "`r?`n")[0] } }) }
}

# Pure: one word for the report. Never a verdict: the scorer's MOTW rows are report-only.
function Get-MotwOutcome([bool]$Dialog, $State) {
    $ci = @($State.code_integrity)
    if (@($ci | Where-Object { $_.id -in 3033, 3077 }).Count) { return 'blocked (Smart App Control / Code Integrity)' }
    if ($Dialog) { return 'warned (SmartScreen dialog)' }
    if ($State.consent) { return 'allowed (UAC prompt shown)' }
    if ($State.wizard -or @($State.setup_procs).Count) { return 'allowed (setup started)' }
    'nothing seen'
}

function Get-Percentile([double[]]$Values, [double]$P) {
    $v = @($Values | Sort-Object)
    if (-not $v.Count) { return $null }
    $i = [math]::Max(0, [math]::Ceiling($P / 100 * $v.Count) - 1)
    [math]::Round($v[$i], 1)
}

# ------------------------------------------------------------------------------------------------- phases

switch ($Phase) {
    'pre' {
        $setup = Get-Setup
        $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $pol = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
        $dotnetDirs = @()
        foreach ($d in 'C:\Program Files\dotnet\shared', 'C:\Program Files (x86)\dotnet\shared') {
            if (Test-Path -LiteralPath $d) { $dotnetDirs += @(Get-ChildItem -LiteralPath $d -Directory -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } | ForEach-Object { $_.FullName }) }
        }
        $arp = Get-ArpNames
        $appx = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
        $sig = Get-AuthenticodeSignature -LiteralPath $setup
        $motw = $null
        try { $motw = @(Get-Content -LiteralPath $setup -Stream Zone.Identifier -ErrorAction Stop) -join ' ' } catch { }
        $ss = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction SilentlyContinue
        $ssPol = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue
        $ci = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue
        $sacState = $(if ($ci -and $ci.PSObject.Properties['VerifiedAndReputablePolicyState']) { [int]$ci.VerifiedAndReputablePolicyState } else { $null })
        $mp = $null
        try { $s = Get-MpComputerStatus -ErrorAction Stop; $mp = [ordered]@{ realtime = $s.RealTimeProtectionEnabled; av_signature = $s.AntivirusSignatureVersion } } catch { $mp = [ordered]@{ error = $_.Exception.Message } }
        $gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)" })
        $rec = [ordered]@{
            t = (NowIso); build = "$($cv.CurrentBuildNumber).$($cv.UBR)"; edition = "$($cv.EditionID)"; display = $gpu
            uac = [ordered]@{ ConsentPromptBehaviorAdmin = $pol.ConsentPromptBehaviorAdmin; PromptOnSecureDesktop = $pol.PromptOnSecureDesktop; EnableLUA = $pol.EnableLUA }
            setup = [ordered]@{ path = $setup; bytes = (Get-Item -LiteralPath $setup).Length; sha256 = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash
                                signature = "$($sig.Status)"; signer = $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject }); mark_of_the_web = $motw }
            dotnet = [ordered]@{ present = ($dotnetDirs.Count -gt 0); runtimes = $dotnetDirs; on_path = [bool](Get-Command dotnet.exe -ErrorAction SilentlyContinue) }
            windows_app_runtime = [ordered]@{ appx = @($appx | Where-Object { $_.Name -match '(?i)WindowsAppRuntime|WinAppRuntime' } | ForEach-Object { $_.PackageFullName } | Sort-Object -Unique)
                                              arp = @($arp | Where-Object { $_ -match '(?i)Windows App Runtime|WindowsAppRuntime|Windows App SDK' }) }
            vc_redist = @($arp | Where-Object { $_ -match '(?i)Microsoft Visual C\+\+ .*Redistributable' })
            vclibs_appx = @($appx | Where-Object { $_.Name -match '(?i)VCLibs' } | ForEach-Object { $_.PackageFullName } | Sort-Object -Unique)
            arp_names = $arp
            smartscreen = [ordered]@{ explorer_SmartScreenEnabled = $(if ($ss -and $ss.PSObject.Properties['SmartScreenEnabled']) { "$($ss.SmartScreenEnabled)" })
                                      policy_EnableSmartScreen = $(if ($ssPol -and $ssPol.PSObject.Properties['EnableSmartScreen']) { $ssPol.EnableSmartScreen })
                                      note = 'the rig copies the setup with guestcontrol: no mark of the web, so the SmartScreen reputation check of a downloaded file is not exercised' }
            smart_app_control = [ordered]@{ VerifiedAndReputablePolicyState = $sacState; state = $(switch ($sacState) { 0 { 'off' } 1 { 'on' } 2 { 'evaluation' } default { 'unknown' } }) }
            defender = $mp
            preexisting = [ordered]@{ pf = (Test-Path -LiteralPath $PF); data_root = (Test-Path -LiteralPath $DataRoot); arp = (Get-Arp).present; event_source = (Get-EventSource).key }
        }
        $rec.clean = (-not $rec.dotnet.present) -and -not @($rec.windows_app_runtime.appx).Count -and -not @($rec.windows_app_runtime.arp).Count -and -not @($rec.vc_redist).Count
        Write-JsonFile $rec (Join-Path $Out 'pre.json') 8
        "M3C PRE clean=$($rec.clean) dotnet=$($rec.dotnet.present) war=$(@($rec.windows_app_runtime.appx).Count + @($rec.windows_app_runtime.arp).Count) vcredist=$(@($rec.vc_redist).Count) sac=$($rec.smart_app_control.state) sig=$($rec.setup.signature) build=$($rec.build)"
    }

    'motw-start' {
        $setup = Get-Setup
        $leaf = Split-Path -Leaf $setup
        $ver = [regex]::Match($leaf, '^Purge-Setup-(.+)\.exe$').Groups[1].Value
        $zone = "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://github.com/Kaan88/purge/releases`r`nHostUrl=https://github.com/Kaan88/purge/releases/download/v$ver/$leaf`r`n"
        Set-Content -LiteralPath $setup -Stream Zone.Identifier -Value $zone -Encoding Ascii
        $since = Get-Date
        $rec = [ordered]@{ t = (NowIso); enabled = $true; zone_identifier = (Get-Motw $setup); since = $since.ToString('o') }
        Stop-SetupProcs
        # Through the shell, as a double-click would: the path where SmartScreen and Smart App Control look at the file.
        $l = LaunchMedium -Exe "$env:WINDIR\explorer.exe" -Arguments "`"$setup`"" -TaskName $UiTask -StartTimeoutSec 0
        $w = Find-TextWindow 'Windows protected your PC' 20
        $rec.smartscreen_dialog = [bool]$w
        if ($w) { $rec.smartscreen_texts = @(Get-UiNames $w | Select-Object -First 40) }
        Start-Sleep -Seconds 3
        $rec.state = Get-MotwState $since
        $rec.outcome = Get-MotwOutcome $rec.smartscreen_dialog $rec.state
        Write-JsonFile $rec (Join-Path $Out 'motw-start.json') 8
        "M3C MOTW-START outcome=$($rec.outcome) smartscreen_dialog=$($rec.smartscreen_dialog) ci_blocks=$(@($rec.state.code_integrity | Where-Object { $_.id -in 3033, 3077 }).Count) setup_running=$(@($rec.state.setup_procs).Count) consent=$($rec.state.consent)"
    }

    'motw-end' {
        $st = Read-Json (Join-Path $Out 'motw-start.json')
        $since = $(if ($st -and $st.since) { [datetime]$st.since } else { (Get-Date).AddMinutes(-5) })
        $rec = [ordered]@{ t = (NowIso); state_after_keys = (Get-MotwState $since) }
        Stop-SetupProcs
        Unregister-ScheduledTask -TaskName $UiTask -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $rec.left = @(Get-ProcList | Where-Object { $_.name -match '^Purge-Setup-.*\.(exe|tmp)$' } | ForEach-Object { $_.name })
        # The interactive start must not have installed anything (the wizard was never clicked through).
        $rec.installed = [ordered]@{ arp = (Get-Arp).present; pf = (Test-Path -LiteralPath $PF) }
        $rec.zone_identifier = Get-Motw (Get-Setup)
        Write-JsonFile $rec (Join-Path $Out 'motw-end.json') 8
        "M3C MOTW-END left=$(@($rec.left).Count) arp=$($rec.installed.arp) pf=$($rec.installed.pf) motw=$([bool]$rec.zone_identifier)"
    }

    'install' {
        if ($Tag -notin '1', '2') { throw 'install needs -Tag 1|2' }
        $setup = Get-Setup
        $since = Get-Date
        $rec = [ordered]@{ t = (NowIso); tag = $Tag; data_root_before = (Get-DataRoot); mark_of_the_web = (Get-Motw $setup) }
        $log = Join-Path $Out "setup-install-$Tag.log"
        $rec.setup = Invoke-Wait $setup "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=`"$log`"" 900
        $rec.setup_log_tail = Get-InnoLogTail $log
        $rec.code_integrity = @(Get-CiEvents $since)
        $rec.layout = Get-Layout
        $report = Join-Path $Out "check-$Tag.json"
        Remove-Item -LiteralPath $report -Force -ErrorAction SilentlyContinue
        $ps = Join-Path $PF 'setup\install.ps1'
        if (Test-Path -LiteralPath $ps) {
            $o = @(& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ps -Check -ReportPath $report 2>&1 | ForEach-Object { "$_" }); $cc = $LASTEXITCODE
            foreach ($l in $o) { Log "  check: $l" }
            $r = Read-Json $report
            $rec.check = [ordered]@{ exit = $cc; tail = @($o | Select-Object -Last 12); ok = $(if ($r) { $r.ok }); program_files = $(if ($r -and $r.check) { $r.check.program_files.verdict })
                                     payload_ok = $(if ($r -and $r.check) { $r.check.payload.ok }); payload_problems = $(if ($r -and $r.check) { @($r.check.payload.problems) })
                                     data_root = $(if ($r -and $r.check) { $r.check.data_root.verdict }); event_log_source = $(if ($r -and $r.check) { $r.check.event_log_source }) }
        } else { $rec.check = [ordered]@{ exit = $null; error = "missing $ps" } }
        $rec.data_root = Get-DataRoot
        $rec.event_source = Get-EventSource
        $rec.arp = Get-Arp
        $rec.shortcuts = Get-Shortcuts
        $rec.processes_after = @(Get-PurgeProcs)
        Write-JsonFile $rec (Join-Path $Out "install-$Tag.json") 8
        "M3C INSTALL $Tag exit=$($rec.setup.exit) check=$($rec.check.exit) arp=$($rec.arp.present) source=$($rec.event_source.key) data_root=$($rec.data_root.exists) protected=$($rec.data_root.protected)"
    }

    'ui-start' {
        $rec = [ordered]@{ t = (NowIso) }
        $s = Start-PurgeUi 60
        foreach ($k in $s.Keys) { $rec[$k] = $s[$k] }
        $rec.ui_il = $(if ($s.ui_pid) { Get-Il $s.ui_pid })
        $rec.engine_il = $(if ($s.engine_pid) { Get-Il $s.engine_pid })
        $arp = Get-ArpNames
        $rec.arp_names = $arp
        $win = $(if ($s.ui_pid) { Find-UiWindow $s.ui_pid 60 })
        $rec.window_found = [bool]$win
        $rec.names_shown = @(); $rec.list_found = $false; $rec.purge_row = $false
        if ($win) {
            $rec.window_name = "$($win.Current.Name)"
            $listCond = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty, 'ProgramList')
            $deadline = (Get-Date).AddSeconds([math]::Max(30, $WaitSec))
            do {
                $list = $win.FindFirst([Windows.Automation.TreeScope]::Descendants, $listCond)
                if ($list) {
                    $rec.list_found = $true
                    $texts = @(Get-UiNames $list)
                    $rec.names_shown = @($arp | Where-Object { Test-NameShown $_ $texts })
                    $rec.purge_row = ($rec.names_shown -contains 'Purge')
                    $rec.list_texts = @($texts | Select-Object -First 120)
                }
                if (-not $rec.purge_row) { Start-Sleep -Seconds 1 }
            } while (-not $rec.purge_row -and (Get-Date) -lt $deadline)
            $notice = $win.FindFirst([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty, 'InfoBarHost')))
            $rec.notices = $(if ($notice) { @(Get-UiNames $notice) } else { @() })
        }
        $rec.ui_modules = $(if ($s.ui_pid) { Get-ModuleReport $s.ui_pid })
        $rec.engine_modules = $(if ($s.engine_pid) { Get-ModuleReport $s.engine_pid })
        Write-JsonFile $rec (Join-Path $Out 'ui.json') 8
        "M3C UI-START ui_pid=$($s.ui_pid) il=$($rec.ui_il) engine=$($s.engine_pid) engine_il=$($rec.engine_il) window=$($rec.window_found) list=$($rec.list_found) names=$(@($rec.names_shown).Count) purge_row=$($rec.purge_row)"
    }

    'ui-stop' {
        Stop-PurgeUi
        $left = @(Get-PurgeProcs)
        "M3C UI-STOP left=$($left.Count)"
    }

    'bench' {
        $n = $(if ($Tag) { [int]$Tag } else { 6 })
        if ($n -lt 2) { throw 'bench needs at least 2 launches (launch 1 is the cold icon cache and dropped)' }
        Stop-PurgeUi
        $dir = Join-Path $Out 'bench'
        if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
        Grant-UsersModify $dir
        $markers = Join-Path $dir 'markers.txt'
        $cmd = Join-Path $dir 'launch.cmd'
        $exe = Join-Path $PF 'Purge.exe'
        [IO.File]::WriteAllText($cmd, ("@echo off`r`nset `"PURGE_BENCH_OUT=$markers`"`r`nset `"PURGE_BENCH_ICON_ATLAS=$(Join-Path $dir 'icons.atlas')`"`r`n" +
            "set `"PURGE_ENGINE=$(Join-Path $PF 'purge-engine.exe')`"`r`n`"$exe`" --bench-exit --bench-until icons_visible`r`n"), [Text.Encoding]::ASCII)
        $runs = @()
        for ($i = 1; $i -le $n; $i++) {
            $before = $(if (Test-Path -LiteralPath $markers) { @(Get-Content -LiteralPath $markers).Count } else { 0 })
            $t = Get-Date
            $l = LaunchMedium -Exe "$env:WINDIR\System32\cmd.exe" -Arguments "/d /c $cmd" -TaskName $UiTask -StartTimeoutSec 0
            $line = $null
            $deadline = $t.AddSeconds(60)
            while (-not $line -and (Get-Date) -lt $deadline) {
                Start-Sleep -Milliseconds 500
                $all = @(if (Test-Path -LiteralPath $markers) { Get-Content -LiteralPath $markers })
                if ($all.Count -gt $before) { $line = $all[$all.Count - 1] }
            }
            # The window closes itself (--bench-exit); give it time, then make sure nothing is left.
            $end = (Get-Date).AddSeconds(15)
            while (@(Get-PurgeProcs).Count -and (Get-Date) -lt $end) { Start-Sleep -Milliseconds 500 }
            $left = @(Get-PurgeProcs)
            Stop-PurgeUi
            $m = [ordered]@{}
            foreach ($pair in ("$line" -split '\s+')) { $kv = $pair -split '=', 2; if ($kv.Count -eq 2) { $d = 0.0; if ([double]::TryParse($kv[1], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $m[$kv[0]] = $d } } }
            $runs += [ordered]@{ i = $i; line = $line; markers = $m; left_running = $left.Count; seconds = [math]::Round(((Get-Date) - $t).TotalSeconds, 1) }
            Log "  bench run $i/$n$(if ($i -eq 1) { ' (cold icon cache, dropped)' }): $line"
        }
        $warm = @($runs | Select-Object -Skip 1)
        $series = { param($name) @($warm | Where-Object { $_.markers.Contains($name) -and -not $_.markers.Contains('engine_fallback') -and -not $_.markers.Contains('bench_timeout') } | ForEach-Object { [double]$_.markers[$name] }) }
        $stat = [ordered]@{}
        foreach ($name in 'first_tick', 'presented', 'names_visible', 'icons_visible', 'list_reply') {
            $v = & $series $name
            $stat[$name] = [ordered]@{ n = $v.Count; p50 = (Get-Percentile $v 50); p90 = (Get-Percentile $v 90) }
        }
        $first = $runs[0]
        $rec = [ordered]@{ t = (NowIso); mode = 'real-engine (xtask bench-launch --real-engine protocol, run in the guest)'; gated = $false
                           note = 'VM: functional only; WARP numbers reported (M3_DESIGN 9.1)'; display = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)" })
                           n = $n; runs = $runs; stats = $stat
                           cold_icons_ms = $(if ($first.markers.Contains('icons_visible')) { $first.markers['icons_visible'] })
                           fallbacks = @($runs | Where-Object { $_.markers.Contains('engine_fallback') }).Count
                           timeouts = @($runs | Where-Object { $_.markers.Contains('bench_timeout') -or -not $_.line }).Count }
        Write-JsonFile $rec (Join-Path $Out 'bench.json') 8
        "M3C BENCH n=$n names_p50=$($stat.names_visible.p50) names_p90=$($stat.names_visible.p90) icons_p50=$($stat.icons_visible.p50) cold_icons=$($rec.cold_icons_ms) fallbacks=$($rec.fallbacks) timeouts=$($rec.timeouts)"
    }

    'uninstall-no' {
        $rec = [ordered]@{ t = (NowIso) }
        # Something for the uninstaller to stop: the UI and the engine it hosts, at medium.
        $rec.running_before = Start-PurgeUi 60
        $rec.procs_before = @(Get-PurgeProcs)
        $rec.data_root_before = Get-DataRoot
        $rec.arp = Get-Arp
        $u = Get-UninstallCommand $rec.arp
        if (-not $u) { $rec.error = 'no Installed-apps entry or no UninstallString' }
        else {
            $log = Join-Path $Out 'uninstall-no.log'
            $rec.command = "`"$($u.exe)`" $($u.args) /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=`"$log`""
            $uargs = ("$($u.args) /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=`"$log`"").Trim()
            $rec.uninstaller = Invoke-Wait $u.exe $uargs 600
            $rec.finished = Wait-UninstallDone 300
            $rec.log_tail = Get-InnoLogTail $log
        }
        Unregister-ScheduledTask -TaskName $UiTask -Confirm:$false -ErrorAction SilentlyContinue
        $rec.after = Get-RemovalState
        $rec.before_pids_alive = @($rec.procs_before | Where-Object { Get-Process -Id $_.pid -ErrorAction SilentlyContinue } | ForEach-Object { $_.pid })
        $rec.data_root_unchanged = ((@($rec.data_root_before.tree) -join "`n") -eq (@($rec.after.data_root.tree) -join "`n"))
        Write-JsonFile $rec (Join-Path $Out 'uninstall-no.json') 8
        "M3C UNINSTALL-NO exit=$($rec.uninstaller.exit) arp=$($rec.after.arp.present) source=$($rec.after.event_source.key) pf=$($rec.after.pf_exists) data_root=$($rec.after.data_root.exists) unchanged=$($rec.data_root_unchanged) alive=$(@($rec.before_pids_alive).Count)"
    }

    'uninstall-yes-start' {
        $rec = [ordered]@{ t = (NowIso); arp = (Get-Arp); data_root_before = (Get-DataRoot) }
        $u = Get-UninstallCommand $rec.arp
        if (-not $u) { $rec.error = 'no Installed-apps entry or no UninstallString' }
        else {
            # /SILENT without /SUPPRESSMSGBOXES: no start confirmation, but the data-folder question is shown.
            $log = Join-Path $Out 'uninstall-yes.log'
            $rec.command = "`"$($u.exe)`" $($u.args) /SILENT /NORESTART /LOG=`"$log`""
            $uargs = ("$($u.args) /SILENT /NORESTART /LOG=`"$log`"").Trim()
            $p = Start-Native $u.exe $uargs
            $rec.uninstaller_pid = $p.Id
            $w = Find-TextWindow 'Also delete Purge' ([math]::Max(30, $WaitSec))
            $rec.dialog_found = [bool]$w
            if ($w) {
                $rec.dialog = [ordered]@{ name = "$($w.Current.Name)"; pid = $w.Current.ProcessId; texts = @(Get-UiNames $w)
                                          process = $(try { (Get-Process -Id $w.Current.ProcessId).ProcessName } catch { $null }); il = (Get-Il $w.Current.ProcessId) }
            }
        }
        Write-JsonFile $rec (Join-Path $Out 'uninstall-yes-start.json') 8
        "M3C UNINSTALL-YES-START dialog=$($rec.dialog_found) process=$($rec.dialog.process)"
    }

    'uninstall-yes-answer' {
        $rec = [ordered]@{ t = (NowIso); answered = $false }
        $w = Find-TextWindow 'Also delete Purge' 20
        if ($w) {
            $yes = $null
            foreach ($b in $w.FindAll([Windows.Automation.TreeScope]::Descendants, (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Button)))) {
                if (("$($b.Current.Name)" -replace '&', '') -eq 'Yes') { $yes = $b; break }
            }
            $rec.yes_found = [bool]$yes
            if ($yes) {
                try { $yes.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke(); $rec.answered = $true; $rec.how = 'UIA InvokePattern on "Yes"' }
                catch { $rec.invoke_error = $_.Exception.Message }
            }
        } else { $rec.error = 'the data-folder question is not on screen' }
        $rec.finished = Wait-UninstallDone 300
        if (-not $rec.finished) { Get-ProcList | Where-Object { $_.name -match '^_iu.*\.tmp$|^unins\d+\.exe$' } | ForEach-Object { Stop-Process -Id $_.pid -Force -ErrorAction SilentlyContinue } }
        $rec.log_tail = Get-InnoLogTail (Join-Path $Out 'uninstall-yes.log')
        $rec.after = Get-RemovalState
        Write-JsonFile $rec (Join-Path $Out 'uninstall-yes-answer.json') 8
        "M3C UNINSTALL-YES answered=$($rec.answered) arp=$($rec.after.arp.present) source=$($rec.after.event_source.key) pf=$($rec.after.pf_exists) data_root=$($rec.after.data_root.exists)"
    }

    'rollback' {
        $setup = Get-Setup
        $rec = [ordered]@{ t = (NowIso); condition = 'a junction below a pre-created C:\Program Files\Purge: install.ps1 -ProtectOnly (the first post-install run) refuses a reparse point in the tree (Protect-Tree), -Check would name it too (Test-PayloadLayout)' }
        $rec.before = Get-RemovalState
        $rec.clean_before = (-not $rec.before.pf_exists) -and (-not $rec.before.arp.present) -and (-not $rec.before.event_source.key) -and (-not $rec.before.data_root.exists)
        # The plant: a canary target outside the install directory, a junction to it inside.
        if (Test-Path -LiteralPath $Canary) { Remove-Item -LiteralPath $Canary -Recurse -Force }
        New-Item -ItemType Directory -Force $Canary | Out-Null
        [IO.File]::WriteAllText((Join-Path $Canary 'canary.txt'), "m3-clean-start canary $(NowIso)")
        $canaryBefore = [ordered]@{ sha256 = (Get-FileHash -LiteralPath (Join-Path $Canary 'canary.txt') -Algorithm SHA256).Hash; sddl = (Get-Acl -LiteralPath $Canary).Sddl; files = @(Get-TreeList $Canary) }
        New-Item -ItemType Directory -Force $PF | Out-Null
        $mk = Invoke-Native "$env:WINDIR\System32\cmd.exe" "/d /c mklink /J `"$Planted`" `"$Canary`"" 30
        $pi = Get-Item -LiteralPath $Planted -Force -ErrorAction SilentlyContinue
        $rec.planted = [ordered]@{ path = $Planted; target = $Canary; mklink_exit = $mk.exit; is_reparse = [bool]($pi -and ($pi.Attributes -band [IO.FileAttributes]::ReparsePoint)) }
        $since = Get-Date
        $log = Join-Path $Out 'setup-rollback.log'
        $rec.setup = Invoke-Wait $setup "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=`"$log`"" 900
        $rec.setup_log_tail = Get-InnoLogTail $log 60
        $rec.rollback_lines = @(if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log | Where-Object { $_ -match '(?i)roll|abort|install\.ps1|exit code' } | Select-Object -First 40 })
        $rec.code_integrity = @(Get-CiEvents $since)
        $rec.after = Get-RemovalState
        $rec.payload_left = @($Layout | Where-Object { Test-Path -LiteralPath (Join-Path $PF $_) })
        $pi = Get-Item -LiteralPath $Planted -Force -ErrorAction SilentlyContinue
        $rec.junction_kept = [bool]($pi -and ($pi.Attributes -band [IO.FileAttributes]::ReparsePoint))
        $rec.pf_other = @(if (Test-Path -LiteralPath $PF) { Get-ChildItem -LiteralPath $PF -Force | Where-Object { $_.Name -ne 'zz-planted' } | ForEach-Object { $_.Name } })
        $rec.canary_unchanged = ((Get-FileHash -LiteralPath (Join-Path $Canary 'canary.txt') -Algorithm SHA256).Hash -eq $canaryBefore.sha256) -and
                                ((Get-Acl -LiteralPath $Canary).Sddl -eq $canaryBefore.sddl) -and ((@(Get-TreeList $Canary) -join "`n") -eq ($canaryBefore.files -join "`n"))
        # Clean up the plant without following the junction (rmdir on a junction removes the link only).
        $null = Invoke-Native "$env:WINDIR\System32\cmd.exe" "/d /c rmdir `"$Planted`"" 30
        if (Test-Path -LiteralPath $PF) { if (-not @(Get-ChildItem -LiteralPath $PF -Force).Count) { Remove-Item -LiteralPath $PF -Force } }
        $rec.cleanup = [ordered]@{ pf_exists = (Test-Path -LiteralPath $PF); canary_intact = (Test-Path -LiteralPath (Join-Path $Canary 'canary.txt')) }
        Write-JsonFile $rec (Join-Path $Out 'rollback.json') 8
        "M3C ROLLBACK exit=$($rec.setup.exit) planted=$($rec.planted.is_reparse) arp=$($rec.after.arp.present) payload_left=$(@($rec.payload_left).Count) source=$($rec.after.event_source.key) data_root=$($rec.after.data_root.exists) canary=$($rec.canary_unchanged)"
    }

    'pack' {
        $zip = 'C:\cr\out\m3-clean.zip'
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path (Join-Path $Out '*') -DestinationPath $zip -Force
        "M3C PACK $((Get-Item $zip).Length)"
    }
}
