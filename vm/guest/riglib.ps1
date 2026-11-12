# Purge rig v2: shared helpers for the guest scripts (dot-sourced). Windows PowerShell 5.1.
# Contract: vm\RIG.md. Runs elevated inside the VM through C:\cr\agent.ps1, as the interactive user.
#
#   . C:\cr\guest\riglib.ps1
#   Set-RunLog C:\cr\out\npp\run.log
#   Lists npp 0;  Snap npp 0
#
# Every function that returns data writes its diagnostics with Log (host stream + run.log), never to the
# pipeline, so callers can assign results directly.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is ~10x slower with the progress bar

$RigRoot   = 'C:\cr'
$RigTool   = 'C:\cr\bin\rigtool.exe'
$RigOut    = 'C:\cr\out'
$RigInst   = 'C:\cr\inst'
$RigUtf8   = New-Object System.Text.UTF8Encoding($false)
$script:RigLogFile = $null

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# ---------------------------------------------------------------------------------------------- logging

function NowIso { (Get-Date).ToString('o') }

function Set-RunLog([string]$Path) {
    $script:RigLogFile = $Path
    $d = Split-Path -Parent $Path
    if ($d) { New-Item -ItemType Directory -Force $d | Out-Null }
}

function Log([string]$Message) {
    $line = '[{0}] {1}' -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fff'), $Message
    Write-Host $line
    if ($script:RigLogFile) {
        try { [IO.File]::AppendAllText($script:RigLogFile, $line + "`r`n", $RigUtf8) } catch { }
    }
}

function Write-JsonFile($Object, [string]$Path, [int]$Depth = 10) {
    $json = ConvertTo-Json -InputObject $Object -Depth $Depth
    [IO.File]::WriteAllText($Path, $json, $RigUtf8)
}

function New-RunDir([string]$Run) {
    if ($Run -notmatch '^[A-Za-z0-9_.-]+$') { throw "bad run name '$Run'" }
    $d = Join-Path $RigOut $Run
    if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Force $d | Out-Null
    $d
}

# Runs one protocol phase. A failure is recorded and logged, never thrown, so later phases (and the
# final snapshot) still run. $Record must hold a 'phases' ArrayList.
function Phase([string]$Name, [scriptblock]$Body, $Record) {
    $ph = [ordered]@{ name = $Name; start = (NowIso); end = $null; ok = $false; error = $null }
    Log "== phase $Name"
    try {
        $ErrorActionPreference = 'Stop'
        $null = & $Body
        $ph.ok = $true
    } catch {
        $pos = ''
        if ($_.InvocationInfo) { $pos = ' at line ' + $_.InvocationInfo.ScriptLineNumber + ': ' + ("$($_.InvocationInfo.Line)".Trim()) }
        $ph.error = "$($_.Exception.Message)$pos"
        Log "!! phase $Name failed: $($ph.error)"
    }
    $ph.end = NowIso
    if ($Record -and $null -ne $Record.phases) { [void]$Record.phases.Add($ph) }
    Log ("== phase {0} {1}" -f $Name, $(if ($ph.ok) { 'ok' } else { 'FAILED' }))
}

# ----------------------------------------------------------------------------------- native processes

# Starts a program with a verbatim argument string (Windows PowerShell 5.1 does not quote embedded
# quotes for native programs, so arguments are never passed as an array).
function Start-Native([string]$Exe, [string]$Arguments = '', [string]$WorkDir = '') {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    if ($WorkDir) { $psi.WorkingDirectory = $WorkDir }
    [System.Diagnostics.Process]::Start($psi)
}

# Runs a console program to completion with stdout/stderr captured (read asynchronously, no deadlock).
function Invoke-Native([string]$Exe, [string]$Arguments = '', [int]$TimeoutSec = 3600) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    $exited = $p.WaitForExit($TimeoutSec * 1000)
    if (-not $exited) { try { $p.Kill() } catch { } }
    else { $p.WaitForExit() }
    $code = $null
    if ($exited) { $code = $p.ExitCode }
    [pscustomobject]@{ exit = $code; timed_out = (-not $exited); stdout = $o.Result; stderr = $e.Result }
}

# Splits an UninstallString-style command line into exe + verbatim argument tail. Handles a quoted exe,
# and an unquoted exe path with spaces (picks the first '.exe' boundary that exists, else the first one).
function Split-CommandLine([string]$Cmd) {
    $c = "$Cmd".Trim()
    if (-not $c) { return $null }
    if ($c.StartsWith('"')) {
        $i = $c.IndexOf('"', 1)
        if ($i -gt 1) { return [pscustomobject]@{ exe = $c.Substring(1, $i - 1); args = $c.Substring($i + 1).Trim() } }
    }
    $ms = [regex]::Matches($c, '(?i)\.exe(?=\s|$)')
    foreach ($m in $ms) {
        $exe = $c.Substring(0, $m.Index + 4)
        if (Test-Path -LiteralPath $exe -PathType Leaf) {
            return [pscustomobject]@{ exe = $exe; args = $c.Substring($m.Index + 4).Trim() }
        }
    }
    if ($ms.Count -gt 0) {
        $m = $ms[0]
        return [pscustomobject]@{ exe = $c.Substring(0, $m.Index + 4); args = $c.Substring($m.Index + 4).Trim() }
    }
    $sp = $c.IndexOf(' ')
    if ($sp -lt 0) { return [pscustomobject]@{ exe = $c; args = '' } }
    [pscustomobject]@{ exe = $c.Substring(0, $sp); args = $c.Substring($sp + 1).Trim() }
}

# ------------------------------------------------------------------------------------------- downloads

# True when the file looks like an installer: PE ('MZ') or OLE compound file (MSI), at least 100 KB.
# (v1 lesson: a mirror served an HTML page instead of the VLC installer.)
function Test-InstallerFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $fi = Get-Item -LiteralPath $Path
    if ($fi.Length -lt 100KB) { return $false }
    $fs = [IO.File]::OpenRead($Path)
    try { $b = New-Object byte[] 8; [void]$fs.Read($b, 0, 8) } finally { $fs.Dispose() }
    if ($b[0] -eq 0x4D -and $b[1] -eq 0x5A) { return $true }
    ($b[0] -eq 0xD0 -and $b[1] -eq 0xCF -and $b[2] -eq 0x11 -and $b[3] -eq 0xE0)
}

function Get-FileInfoRecord([string]$Path, [string]$Url = $null) {
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    $signer = $null
    if ($sig.SignerCertificate) { $signer = ($sig.SignerCertificate.Subject -replace ',.*$', '') }
    [pscustomobject][ordered]@{
        file   = $Path
        url    = $Url
        size   = (Get-Item -LiteralPath $Path).Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
        sig    = [string]$sig.Status
        signer = $signer
    }
}

# Downloads the first candidate URL that yields a real installer into C:\cr\inst\<File> (kept if already
# present and valid), then logs size and Authenticode status. Returns a record {file,url,size,sha256,sig,signer}.
function Fetch($Url, [string]$File, [string]$Dir = $RigInst, [switch]$Force) {
    New-Item -ItemType Directory -Force $Dir | Out-Null
    $dst = Join-Path $Dir $File
    $src = $null
    if ((-not $Force) -and (Test-InstallerFile $dst)) {
        Log "have $File"
    } else {
        foreach ($u in @($Url)) {
            if (-not $u) { continue }
            $tmp = "$dst.part"
            try {
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                Invoke-WebRequest -Uri $u -OutFile $tmp -UseBasicParsing -MaximumRedirection 10 -ErrorAction Stop `
                    -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) rig-download'
                if (Test-InstallerFile $tmp) {
                    Move-Item -LiteralPath $tmp -Destination $dst -Force
                    $src = $u
                    break
                }
                Log "not an installer (HTML or truncated?) from $u"
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            } catch {
                Log "download failed: $u : $($_.Exception.Message)"
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            }
        }
        if (-not $src) { throw "could not fetch $File from: $(@($Url) -join ' | ')" }
    }
    $rec = Get-FileInfoRecord $dst $src
    Log ('fetched {0}  {1:N1} MB  sig={2} {3}  sha256={4}' -f $File, ($rec.size / 1MB), $rec.sig, $rec.signer, $rec.sha256)
    $rec
}

function GitHubAsset([string]$Repo, [string]$Pattern) {
    $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing -Headers @{ 'User-Agent' = 'rig-download' }
    # (ConvertFrom-Json / Invoke-RestMethod in 5.1 can hand back an array as one object: unroll it.)
    $assets = @(@($rel.assets) | ForEach-Object { $_ })
    ($assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1).browser_download_url
}

# ------------------------------------------------------------------------------------------- registry

$RigUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# 'HKEY_LOCAL_MACHINE\X' / 'HKLM:\X' / 'HKCU\X' / 'HKCR\X' -> canonical 'HKLM\X', 'HKU\<sid>\X' (RIG.md §2).
function ConvertTo-CanonKey([string]$Key, [string]$UserSid = $RigUserSid) {
    $k = "$Key" -replace '^Microsoft\.PowerShell\.Core\\Registry::', '' -replace '^Registry::', ''
    $k = $k -replace '^(HKLM|HKCU|HKU|HKCR):\\?', '$1\'
    $k = $k -replace '^(?i)HKEY_LOCAL_MACHINE(\\|$)', 'HKLM$1'
    $k = $k -replace '^(?i)HKEY_USERS(\\|$)', 'HKU$1'
    $k = $k -replace '^(?i)HKEY_CURRENT_USER(\\|$)', 'HKCU$1'
    $k = $k -replace '^(?i)HKEY_CLASSES_ROOT(\\|$)', 'HKCR$1'
    $k = $k -replace '^(?i)HKCU(\\|$)', ('HKU\' + $UserSid + '$1')
    $k = $k -replace '^(?i)HKCR(\\|$)', 'HKLM\SOFTWARE\Classes$1'
    $k = $k -replace '^(?i)HKLM\\Software(\\|$)', 'HKLM\SOFTWARE$1'
    $k.TrimEnd('\')
}

# Canonical key -> PowerShell provider path usable with Test-Path / Get-ItemProperty.
function ConvertTo-PsRegPath([string]$Canon) {
    $k = ConvertTo-CanonKey $Canon
    $k = $k -replace '^HKLM(\\|$)', 'HKEY_LOCAL_MACHINE$1' -replace '^HKU(\\|$)', 'HKEY_USERS$1'
    'Registry::' + $k
}

# Opens a canonical key read-only in the 64-bit view. Returns $null when missing.
function Open-RegKey([string]$Canon) {
    $k = ConvertTo-CanonKey $Canon
    $hiveName, $rest = $k -split '\\', 2
    $hive = switch ($hiveName) {
        'HKLM' { [Microsoft.Win32.RegistryHive]::LocalMachine }
        'HKU'  { [Microsoft.Win32.RegistryHive]::Users }
        default { throw "unsupported hive in '$Canon'" }
    }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
    if (-not $rest) { return $base }
    try { $base.OpenSubKey($rest, $false) } catch { $null }
}

function Test-RegKey([string]$Canon) {
    $k = Open-RegKey $Canon
    if ($k) { $k.Dispose(); return $true }
    $false
}

# Raw (unexpanded) value, or $null.
function Get-RegRaw([string]$Canon, [string]$Name) {
    $k = Open-RegKey $Canon
    if (-not $k) { return $null }
    try { $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $k.Dispose() }
}

function Get-LoadedUserSids {
    $u = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    try { @($u.GetSubKeyNames() | Where-Object { $_ -match '^S-1-5-21-[\d-]+$' }) } finally { $u.Dispose() }
}

$RigGuidRx = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'

# MSI product code of an ARP entry: the key name when it is a GUID and the entry is a Windows Installer
# one (WindowsInstaller=1 or an msiexec UninstallString naming it), else a GUID named by msiexec /I|/X in
# the UninstallString when WindowsInstaller=1. Burn bundles also use GUID keys but are not MSI: $null.
function Get-EntryMsiCode([string]$Leaf, $WindowsInstaller, [string]$UninstallString) {
    $wi = ("$WindowsInstaller" -eq '1')
    $msiUs = "$UninstallString" -match '(?i)msiexec(\.exe)?"?\s+.*?/[IX]\s*(\{[0-9A-F-]{36}\})'
    $usGuid = $null
    if ($msiUs) { $usGuid = $Matches[2].ToUpperInvariant() }
    if ($Leaf -match $RigGuidRx) {
        if ($wi -or ($usGuid -and $usGuid -eq $Leaf.ToUpperInvariant())) { return $Leaf.ToUpperInvariant() }
        return $null
    }
    if ($wi -and $usGuid) { return $usGuid }
    $null
}

# All ARP entries: HKLM (64-bit view), HKLM WOW6432Node, and every loaded user hive.
function UninstallEntries {
    $roots = @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
               'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($sid in Get-LoadedUserSids) { $roots += "HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    foreach ($root in $roots) {
        $rk = Open-RegKey $root
        if (-not $rk) { continue }
        try {
            foreach ($leaf in $rk.GetSubKeyNames()) {
                $k = $null
                try { $k = $rk.OpenSubKey($leaf, $false) } catch { }
                if (-not $k) { continue }
                try {
                    $g = { param($n) $k.GetValue($n, $null) }
                    $us = & $g 'UninstallString'
                    $wi = & $g 'WindowsInstaller'
                    [pscustomobject][ordered]@{
                        key        = "$root\$leaf"
                        name       = & $g 'DisplayName'
                        version    = & $g 'DisplayVersion'
                        publisher  = & $g 'Publisher'
                        sys        = ("$(& $g 'SystemComponent')" -eq '1')
                        parent     = & $g 'ParentKeyName'
                        uninstall  = $us
                        quiet      = & $g 'QuietUninstallString'
                        loc        = & $g 'InstallLocation'
                        icon       = & $g 'DisplayIcon'
                        msi        = Get-EntryMsiCode $leaf $wi $us
                        size       = & $g 'EstimatedSize'
                        install_date = & $g 'InstallDate'
                        bundle     = [bool](& $g 'BundleCachePath')
                    }
                } finally { $k.Dispose() }
            }
        } finally { $rk.Dispose() }
    }
}

# 32-hex packed GUID (Installer\Products, UserData) -> '{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}'.
function ConvertFrom-PackedGuid([string]$Packed) {
    if ($Packed -notmatch '^[0-9A-Fa-f]{32}$') { return $null }
    $p = $Packed.ToUpperInvariant()
    $rev = { param($s) -join ($s.ToCharArray()[($s.Length - 1)..0]) }
    $swap = { param($s) -join (0..($s.Length / 2 - 1) | ForEach-Object { $s.Substring($_ * 2 + 1, 1) + $s.Substring($_ * 2, 1) }) }
    '{' + (& $rev $p.Substring(0, 8)) + '-' + (& $rev $p.Substring(8, 4)) + '-' + (& $rev $p.Substring(12, 4)) + '-' +
        (& $swap $p.Substring(16, 4)) + '-' + (& $swap $p.Substring(20, 12)) + '}'
}

function ConvertTo-PackedGuid([string]$Guid) {
    $g = $Guid.Trim('{}').Replace('-', '').ToUpperInvariant()
    if ($g -notmatch '^[0-9A-F]{32}$') { return $null }
    $rev = { param($s) -join ($s.ToCharArray()[($s.Length - 1)..0]) }
    $swap = { param($s) -join (0..($s.Length / 2 - 1) | ForEach-Object { $s.Substring($_ * 2 + 1, 1) + $s.Substring($_ * 2, 1) }) }
    (& $rev $g.Substring(0, 8)) + (& $rev $g.Substring(8, 4)) + (& $rev $g.Substring(12, 4)) + (& $swap $g.Substring(16, 16))
}

# Installed MSI products from the Installer UserData registry (no COM): machine context under S-1-5-18,
# per-user products under the user's SID (managed when listed under Installer\Managed\<sid>).
function MsiProducts {
    $ud = Open-RegKey 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
    if (-not $ud) { return }
    try {
        foreach ($sid in $ud.GetSubKeyNames()) {
            $pk = $null
            try { $pk = $ud.OpenSubKey("$sid\Products", $false) } catch { }
            if (-not $pk) { continue }
            try {
                foreach ($packed in $pk.GetSubKeyNames()) {
                    $ip = $null
                    try { $ip = $pk.OpenSubKey("$packed\InstallProperties", $false) } catch { }
                    $name = $null; $ver = $null
                    if ($ip) { try { $name = $ip.GetValue('DisplayName'); $ver = $ip.GetValue('DisplayVersion') } finally { $ip.Dispose() } }
                    $ctx = 'machine'
                    if ($sid -ne 'S-1-5-18') {
                        $ctx = 'user_unmanaged'
                        if (Test-RegKey "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Managed\$sid\Installer\Products\$packed") { $ctx = 'user_managed' }
                    }
                    [pscustomobject][ordered]@{ code = ConvertFrom-PackedGuid $packed; name = $name; version = $ver; context = $ctx; sid = $sid }
                }
            } finally { $pk.Dispose() }
        }
    } finally { $ud.Dispose() }
}

# ------------------------------------------------------------------------------------------ processes

function Get-ProcList {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            pid = [int]$_.ProcessId; ppid = [int]$_.ParentProcessId; name = $_.Name; path = $_.ExecutablePath
            cmd = $_.CommandLine; session = [int]$_.SessionId; start = $_.CreationDate
        }
    }
}

# Windows background processes that start on their own and must not hold up a wait. msiexec.exe in
# session 0 (the Windows Installer service and its custom-action servers) is handled separately: it is
# ignored as a process, and Test-MsiBusy (the Global\_MSIExecute mutex) keeps the wait open while an
# install/uninstall transaction is active.
$RigAmbientProcs = @(
    'svchost.exe', 'wmiprvse.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe', 'searchindexer.exe',
    'msmpeng.exe', 'mpcmdrun.exe', 'nissrv.exe', 'mpdefendercoreservice.exe', 'securityhealthservice.exe',
    'securityhealthhost.exe', 'tiworker.exe', 'trustedinstaller.exe', 'backgroundtaskhost.exe',
    'runtimebroker.exe', 'dllhost.exe', 'taskhostw.exe', 'sppsvc.exe', 'sppextcomobj.exe', 'slui.exe',
    'compattelrunner.exe', 'mousocoreworker.exe', 'usoclient.exe', 'wuauclt.exe', 'smartscreen.exe',
    'audiodg.exe', 'werfault.exe', 'wermgr.exe', 'wersvc.exe', 'vssvc.exe', 'srtasks.exe', 'sgrmbroker.exe',
    'wudfhost.exe', 'aggregatorhost.exe', 'mscorsvw.exe', 'ngen.exe', 'ngentask.exe', 'devicecensus.exe',
    'sihclient.exe', 'microsoftedgeupdate.exe', 'msedge.exe', 'msedgewebview2.exe', 'explorer.exe', 'sihost.exe',
    'shellexperiencehost.exe', 'startmenuexperiencehost.exe', 'searchhost.exe', 'searchapp.exe',
    'textinputhost.exe', 'ctfmon.exe', 'dwm.exe', 'fontdrvhost.exe', 'useroobebroker.exe', 'lockapp.exe',
    'systemsettings.exe', 'applicationframehost.exe', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'lsass.exe', 'services.exe', 'spoolsv.exe', 'consent.exe', 'dashost.exe', 'unsecapp.exe', 'cleanmgr.exe',
    'defrag.exe', 'dsregcmd.exe', 'gamebarpresencewriter.exe', 'securityhealthsystray.exe', 'vboxtray.exe',
    'vboxservice.exe', 'provtool.exe', 'mobsync.exe', 'wsqmcons.exe'
)

# Rig processes: the agent and job PowerShells, rigtool, VBoxService children (guestcontrol run), and
# conhost.exe attached to any of those.
function Test-RigProc($P) {
    $n = "$($P.name)".ToLowerInvariant()
    if ($n -eq 'rigtool.exe') { return $true }
    if (($n -eq 'powershell.exe' -or $n -eq 'pwsh.exe') -and "$($P.cmd)" -match '(?i)\\cr\\(agent\.ps1|jobs\\|guest\\)') { return $true }
    if ($n -eq 'cmd.exe' -and "$($P.cmd)" -match '(?i)\\cr\\start-agent') { return $true }
    $false
}

# Pure: which of $Procs (objects with pid, ppid, name, cmd, session, start) still hold up a wait that
# started at $Since. Used by WaitTree; testable with a fake list.
function Get-BlockingProcs($Procs, [datetime]$Since, [int[]]$ExtraRigPids = @()) {
    $all = @($Procs)
    $byPid = @{}
    foreach ($p in $all) { $byPid[[int]$p.pid] = $p }
    $rig = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($x in $ExtraRigPids) { [void]$rig.Add([int]$x) }
    foreach ($p in $all) { if (Test-RigProc $p) { [void]$rig.Add([int]$p.pid) } }
    foreach ($p in $all) {
        $par = $byPid[[int]$p.ppid]
        if ($par -and "$($par.name)" -ieq 'VBoxService.exe') { [void]$rig.Add([int]$p.pid) }
    }
    foreach ($p in $all) {
        if ("$($p.name)" -ieq 'conhost.exe' -and $rig.Contains([int]$p.ppid)) { [void]$rig.Add([int]$p.pid) }
    }
    foreach ($p in $all) {
        if ($null -eq $p.start -or $p.start -lt $Since) { continue }
        if ($rig.Contains([int]$p.pid)) { continue }
        $n = "$($p.name)".ToLowerInvariant()
        if ($RigAmbientProcs -contains $n) { continue }
        if ($n -eq 'msiexec.exe' -and [int]$p.session -eq 0) { continue }
        $p
    }
}

# Pure: the live members of a process tree. $Known (HashSet[int]) starts with the root PID(s) and grows on
# every call with any process whose parent is already known, so a child that outlives its parent (NSIS
# Au_.exe, Inno _iu*.tmp, Burn's %TEMP% copy) is still caught as long as it was seen once, and its own
# children are caught through it. No start times are used: after a snapshot restore the guest clock jumps
# by hours, which made time-based filtering count System, Registry and post-boot maintenance as "new".
function Get-TreeProcs($Procs, $Known) {
    $all = @($Procs)
    $grew = $true
    while ($grew) {
        $grew = $false
        foreach ($p in $all) {
            if (-not $Known.Contains([int]$p.pid) -and $Known.Contains([int]$p.ppid) -and [int]$p.pid -gt 4) {
                [void]$Known.Add([int]$p.pid); $grew = $true
            }
        }
    }
    foreach ($p in $all) {
        if (-not $Known.Contains([int]$p.pid)) { continue }
        if ([int]$p.pid -le 4 -or (Test-RigProc $p)) { continue }
        if ("$($p.name)" -ieq 'conhost.exe') { continue }
        $p
    }
}

function New-PidSet([int[]]$Pids) {
    $s = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($x in @($Pids)) { if ($x -gt 4) { [void]$s.Add([int]$x) } }
    , $s
}

# True while a Windows Installer transaction is running (the service holds Global\_MSIExecute).
function Test-MsiBusy {
    $m = $null
    try {
        if ([System.Threading.Mutex]::TryOpenExisting('Global\_MSIExecute', [System.Security.AccessControl.MutexRights]::Synchronize, [ref]$m)) {
            $m.Dispose(); return $true
        }
        return $false
    } catch [System.UnauthorizedAccessException] {
        return $true
    } catch {
        return $false
    }
}

# Waits until no process started at/after $Since is still running (rig and Windows background processes
# excluded, see Get-BlockingProcs), no MSI transaction is active, and $Until (if given) is true, seen on
# $QuietPolls consecutive polls. Gives up after $TimeoutSec (timed_out) or, when the tree is idle but
# $Until stays false, after $IdleGiveUpSec (cond_met = false). $GetProcs/$MsiBusy can be replaced for tests.
function WaitTree {
    param(
        [datetime]$Since, [int]$TimeoutSec = 900, [int]$PollSec = 2, [scriptblock]$Until = $null,
        [int]$QuietPolls = 2, [int]$IdleGiveUpSec = 0,
        [scriptblock]$GetProcs = { Get-ProcList }, [scriptblock]$MsiBusy = { Test-MsiBusy },
        # Root PID(s) of the tree to wait for. When given, only that tree blocks (clock-jump safe, see
        # Get-TreeProcs); $Since is then ignored. $Known is returned so callers can kill the same tree.
        [int[]]$RootPid = @()
    )
    $start = Get-Date
    $deadline = $start.AddSeconds($TimeoutSec)
    $quiet = 0; $last = $null; $idleSince = $null
    $known = New-PidSet $RootPid
    while ($true) {
        if ($RootPid.Count) { $block = @(Get-TreeProcs -Procs (& $GetProcs) -Known $known) }
        else { $block = @(Get-BlockingProcs -Procs (& $GetProcs) -Since $Since) }
        $msi = [bool](& $MsiBusy)
        $cond = $true
        if ($Until) { $cond = [bool](& $Until) }
        $desc = (@($block | ForEach-Object { "$($_.name)[$($_.pid)]" }) -join ',')
        if ($msi) { $desc += ' +MSI' }
        if (-not $cond) { $desc += ' +cond' }
        if ($desc -ne $last) { Log "  wait: $(if ($desc) { $desc } else { 'idle' })"; $last = $desc }
        $idle = ($block.Count -eq 0 -and -not $msi)
        if ($idle -and $cond) {
            $quiet++
            if ($quiet -ge $QuietPolls) {
                return [pscustomobject]@{ timed_out = $false; cond_met = $true; end = (Get-Date); still = @(); known = $known }
            }
        } else { $quiet = 0 }
        if ($idle -and -not $cond) {
            if (-not $idleSince) { $idleSince = Get-Date }
            if ($IdleGiveUpSec -gt 0 -and ((Get-Date) - $idleSince).TotalSeconds -ge $IdleGiveUpSec) {
                return [pscustomobject]@{ timed_out = $false; cond_met = $false; end = (Get-Date); still = @(); known = $known }
            }
        } else { $idleSince = $null }
        if ((Get-Date) -ge $deadline) {
            return [pscustomobject]@{ timed_out = $true; cond_met = $cond; end = (Get-Date); still = @($block); known = $known }
        }
        Start-Sleep -Seconds $PollSec
    }
}

function Stop-Procs($Procs, [string]$Why) {
    foreach ($p in @($Procs)) {
        if (-not $p) { continue }
        Log "  kill $($p.name)[$($p.pid)] ($Why)"
        Stop-Process -Id $p.pid -Force -ErrorAction SilentlyContinue
    }
}

# ----------------------------------------------------------------------------- medium-integrity launch

# Pure: the scheduled-task action for a launch (exe, verbatim argument string, working directory).
function New-LaunchSpec([string]$Exe, [string]$Arguments = '', [string]$WorkDir = '') {
    if (-not $Exe) { throw 'no exe' }
    if (-not $WorkDir) { $WorkDir = Split-Path -Parent $Exe }
    $display = '"' + $Exe + '"'
    if ($Arguments) { $display += ' ' + $Arguments }
    [pscustomobject][ordered]@{ execute = $Exe; argument = $Arguments; workdir = $WorkDir; display = $display }
}

# Starts $Exe at medium integrity in the interactive session through a one-shot scheduled task
# ('PurgeRigLaunch': interactive token, limited run level, i.e. schtasks /it /rl LIMITED). The elevated
# agent cannot drop its own integrity, and explorer.exe "<exe>" cannot pass arguments. Returns a launch
# record; call Stop-Launch to close the app and delete the task.
function LaunchMedium([string]$Exe, [string]$Arguments = '', [string]$WorkDir = '', [string]$TaskName = 'PurgeRigLaunch', [int]$StartTimeoutSec = 30) {
    $spec = New-LaunchSpec $Exe $Arguments $WorkDir
    $user = "$env:USERDOMAIN\$env:USERNAME"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    $aa = @{ Execute = $spec.execute }
    if ($spec.argument) { $aa.Argument = $spec.argument }
    if ($spec.workdir) { $aa.WorkingDirectory = $spec.workdir }
    $action = New-ScheduledTaskAction @aa
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    # Priority 4 = normal: the default (7) runs the task, and everything the app starts, below normal.
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -Priority 4
    $t = Get-Date
    $found = $null
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        Log "launch (medium IL via task $TaskName as $user): $($spec.display)"
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $deadline = $t.AddSeconds($StartTimeoutSec)
        while (-not $found -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
            $found = Get-ProcList | Where-Object { $_.path -and $_.path -ieq $Exe -and $_.start -ge $t.AddSeconds(-2) } | Select-Object -First 1
        }
    } catch {
        # No launch record reaches the caller, so Stop-Launch would never delete the task: do it here, or
        # PurgeRigLaunch would stay through snap 1 and snap 2 and land in the truth.
        Log "  !! launch failed: $($_.Exception.Message); deleting task $TaskName"
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        throw
    }
    if ($found) { Log "  started $($found.name)[$($found.pid)]" } else { Log "  !! $Exe did not appear within $StartTimeoutSec s" }
    [pscustomobject][ordered]@{
        task = $TaskName; exe = $Exe; args = $Arguments; start = $t; pid = $(if ($found) { $found.pid } else { $null })
        found = [bool]$found
    }
}

# Closes every process started since the launch (CloseMainWindow), waits $GraceSec, kills what is left,
# then deletes the launch task.
function Stop-Launch($Launch, [int]$GraceSec = 5) {
    $closed = @(); $killed = @()
    $known = New-PidSet @($(if ($Launch.pid) { [int]$Launch.pid }))
    $mine = { param($all) @(Get-TreeProcs -Procs $all -Known $known) + @($all | Where-Object { $Launch.exe -and $_.path -and $_.path -ieq $Launch.exe -and -not $known.Contains([int]$_.pid) }) }
    $procs = @(& $mine @(Get-ProcList))
    foreach ($p in $procs) {
        try {
            $gp = Get-Process -Id $p.pid -ErrorAction Stop
            if ($gp.MainWindowHandle -ne [IntPtr]::Zero) {
                if ($gp.CloseMainWindow()) { $closed += "$($p.name)[$($p.pid)]" }
            }
        } catch { }
    }
    if ($closed.Count) { Log "  closed windows: $($closed -join ', ')" }
    Start-Sleep -Seconds $GraceSec
    $left = @(& $mine @(Get-ProcList))
    foreach ($p in $left) { $killed += "$($p.name)[$($p.pid)]" }
    Stop-Procs $left 'launch cleanup'
    Unregister-ScheduledTask -TaskName $Launch.task -Confirm:$false -ErrorAction SilentlyContinue
    [pscustomobject]@{ closed = $closed; killed = $killed }
}

# ---------------------------------------------------------------------------------------------- lists

function Get-AppxRecords {
    $pm = $null
    try {
        $null = [Windows.Management.Deployment.PackageManager, Windows.Management.Deployment, ContentType = WindowsRuntime]
        $pm = New-Object Windows.Management.Deployment.PackageManager
    } catch { }
    foreach ($p in @(Get-AppxPackage -AllUsers -ErrorAction Stop)) {
        $users = @()
        foreach ($u in @($p.PackageUserInformation)) {
            if (-not $u) { continue }
            $sid = "$($u.UserSecurityId)"
            if ($sid -notmatch '^S-1-') { $sid = "$($u.UserSecurityId.Sid)" }
            if ($sid -notmatch '^S-1-') { $sid = "$($u.UserSecurityId.Value)" }
            $users += $sid
        }
        $sparse = $false; $ext = $null
        if ($p.InstallLocation) {
            $man = Join-Path $p.InstallLocation 'AppxManifest.xml'
            if (Test-Path -LiteralPath $man) {
                try { $sparse = [bool](Select-String -LiteralPath $man -Pattern 'AllowExternalContent>\s*true' -Quiet) } catch { }
            }
        }
        if ($pm) {
            try {
                $pk = $null
                try { $pk = $pm.FindPackage($p.PackageFullName) } catch { }        # all users; needs elevation
                if (-not $pk) { $pk = $pm.FindPackageForUser('', $p.PackageFullName) }   # current user
                if ($pk) {
                    if ($pk.EffectiveExternalLocation) { $ext = $pk.EffectiveExternalLocation.Path }
                    elseif ($pk.EffectiveExternalPath) { $ext = $pk.EffectiveExternalPath }
                }
            } catch { }
        }
        if ($ext) { $sparse = $true } else { $ext = $null }
        [pscustomobject][ordered]@{
            full_name = $p.PackageFullName; family = $p.PackageFamilyName; install_location = $p.InstallLocation
            users = $users; sparse = $sparse; external_location = $ext
        }
    }
}

function Get-TaskRecords {
    foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
        $acts = @()
        foreach ($a in @($t.Actions)) {
            if (-not $a) { continue }
            if ($a.CimClass.CimClassName -eq 'MSFT_TaskExecAction') { $acts += ("$($a.Execute) $($a.Arguments)").Trim() }
            elseif ($a.CimClass.CimClassName -eq 'MSFT_TaskComHandlerAction') { $acts += ("com:$($a.ClassId) $($a.Data)").Trim() }
            else { $acts += "$($a.CimClass.CimClassName)" }
        }
        [pscustomobject][ordered]@{ path = "$($t.TaskPath)$($t.TaskName)"; actions = $acts; enabled = ("$($t.State)" -ne 'Disabled') }
    }
}

function Get-ServiceRecords {
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
        [pscustomobject][ordered]@{ name = $s.Name; display = $s.DisplayName; image_path = $s.PathName; start = $s.StartMode; type = $s.ServiceType }
    }
    foreach ($s in @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
        [pscustomobject][ordered]@{ name = $s.Name; display = $s.DisplayName; image_path = $s.PathName; start = $s.StartMode; type = "driver:$($s.ServiceType)" }
    }
}

# One call for all application filters, joined to rules by InstanceID (per-rule filter calls take minutes).
function Get-FirewallRecords {
    $prog = @{}
    foreach ($f in @(Get-NetFirewallApplicationFilter -All -ErrorAction Stop)) { $prog[[string]$f.InstanceID] = $f.Program }
    foreach ($r in @(Get-NetFirewallRule -ErrorAction Stop)) {
        [pscustomobject][ordered]@{
            id = $r.Name; display = $r.DisplayName; program = $prog[[string]$r.InstanceID]
            direction = "$($r.Direction)"; enabled = ("$($r.Enabled)" -eq 'True')
        }
    }
}

function Get-CertRecords {
    foreach ($loc in 'LocalMachine', 'CurrentUser') {
        foreach ($store in @(Get-ChildItem "Cert:\$loc" -ErrorAction SilentlyContinue)) {
            foreach ($c in @(Get-ChildItem "Cert:\$loc\$($store.Name)" -ErrorAction SilentlyContinue)) {
                if (-not $c.Thumbprint) { continue }
                [pscustomobject][ordered]@{ store = "$loc\$($store.Name)"; thumbprint = $c.Thumbprint; subject = $c.Subject }
            }
        }
    }
}

function Get-FontRecords {
    $keys = @(@{ k = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'; s = 'machine' })
    foreach ($sid in Get-LoadedUserSids) { $keys += @{ k = "HKU\$sid\Software\Microsoft\Windows NT\CurrentVersion\Fonts"; s = "user:$sid" } }
    foreach ($e in $keys) {
        $rk = Open-RegKey $e.k
        if (-not $rk) { continue }
        try {
            foreach ($n in $rk.GetValueNames()) {
                [pscustomobject][ordered]@{ name = $n; file = "$($rk.GetValue($n, $null, 'DoNotExpandEnvironmentNames'))"; scope = $e.s }
            }
        } finally { $rk.Dispose() }
    }
}

# PATH segments exactly as stored (REG_EXPAND_SZ not expanded), empty segments dropped.
function Split-PathValue($Raw) { @("$Raw" -split ';' | Where-Object { $_ -ne '' }) }

# Both values are always arrays (RIG.md §3 [segments]): @() keeps a single segment from being unrolled
# into a JSON string and an empty PATH from becoming {}.
function Get-EnvRecords {
    [ordered]@{
        machine_path = @(Split-PathValue (Get-RegRaw 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' 'Path'))
        user_path    = @(Split-PathValue (Get-RegRaw "HKU\$RigUserSid\Environment" 'Path'))
    }
}

function Get-ProcessRecords {
    foreach ($p in @(Get-ProcList)) {
        $st = $null
        if ($p.start) { $st = $p.start.ToString('o') }
        [pscustomobject][ordered]@{ pid = $p.pid; ppid = $p.ppid; name = $p.name; path = $p.path; start = $st; session = $p.session; cmd = $p.cmd }
    }
}

# Structured lists (RIG.md §3) -> C:\cr\out\<run>\lists-<run>-<phase>.json. Each section is captured
# independently; a failing section is empty and named in 'errors'.
function Lists([string]$Run, [string]$Phase) {
    $dir = Join-Path $RigOut $Run
    New-Item -ItemType Directory -Force $dir | Out-Null
    $out = Join-Path $dir "lists-$Run-$Phase.json"
    $errors = New-Object System.Collections.ArrayList
    $t0 = Get-Date
    $section = {
        param([string]$Name, [scriptblock]$Get)
        $s = Get-Date
        try {
            $ErrorActionPreference = 'Stop'
            $v = @(& $Get)
            Log ("  lists {0}: {1} ({2:N1} s)" -f $Name, $v.Count, ((Get-Date) - $s).TotalSeconds)
            , $v
        } catch {
            [void]$errors.Add("${Name}: $($_.Exception.Message)")
            Log "  !! lists ${Name}: $($_.Exception.Message)"
            , @()
        }
    }
    $doc = [ordered]@{
        schema = 'purge.rig.lists/1'; run = $Run; phase = $Phase; time = (NowIso)
        computer = $env:COMPUTERNAME; user_sid = $RigUserSid
    }
    $doc.uninstall        = & $section 'uninstall' { UninstallEntries }
    $doc.msi              = & $section 'msi' { MsiProducts }
    $doc.appx             = & $section 'appx' { Get-AppxRecords }
    $doc.appx_provisioned = & $section 'appx_provisioned' { Get-AppxProvisionedPackage -Online -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ package_name = $_.PackageName } } }
    $doc.tasks            = & $section 'tasks' { Get-TaskRecords }
    $doc.services         = & $section 'services' { Get-ServiceRecords }
    $doc.firewall         = & $section 'firewall' { Get-FirewallRecords }
    $doc.certs            = & $section 'certs' { Get-CertRecords }
    $doc.fonts            = & $section 'fonts' { Get-FontRecords }
    try { $doc.env = Get-EnvRecords } catch { $doc.env = [ordered]@{ machine_path = @(); user_path = @() }; [void]$errors.Add("env: $($_.Exception.Message)") }
    $doc.processes        = & $section 'processes' { Get-ProcessRecords }
    $doc.errors = @($errors)
    Write-JsonFile $doc $out
    Log ("lists {0} -> {1} ({2:N0} s, {3} errors)" -f $Phase, $out, ((Get-Date) - $t0).TotalSeconds, $errors.Count)
    $doc
}

# ---------------------------------------------------------------------------------------------- snaps

# Raw filesystem + registry capture (RIG.md §2) -> C:\cr\out\<run>\snap-<run>-<phase>.tsv.gz.
function Snap([string]$Run, [string]$Phase) {
    if (-not (Test-Path -LiteralPath $RigTool)) { throw "missing $RigTool (run Push-Tools on the host)" }
    $dir = Join-Path $RigOut $Run
    New-Item -ItemType Directory -Force $dir | Out-Null
    $out = Join-Path $dir "snap-$Run-$Phase.tsv.gz"
    $t0 = Get-Date
    $r = Invoke-Native -Exe $RigTool -Arguments ('snap -o "' + $out + '"') -TimeoutSec 3600
    foreach ($l in @("$($r.stdout)" -split "`r?`n") + @("$($r.stderr)" -split "`r?`n")) { if ($l.Trim()) { Log "  rigtool: $l" } }
    $ok = ($r.exit -eq 0 -and (Test-Path -LiteralPath $out))
    $size = 0
    if (Test-Path -LiteralPath $out) { $size = (Get-Item -LiteralPath $out).Length }
    Log ("snap {0} -> {1} exit={2} {3:N1} MB ({4:N0} s)" -f $Phase, $out, $r.exit, ($size / 1MB), ((Get-Date) - $t0).TotalSeconds)
    if (-not $ok) { throw "rigtool snap failed (exit $($r.exit), timed_out=$($r.timed_out))" }
    $out
}

# ---------------------------------------------------------------------------------------- purge-engine
#
# Engine mode of run-app.ps1 (RIG.md §4a): the engine CLI of ENGINE_PLAN §3.4, pushed by the host to
# C:\cr\bin\purge-engine.exe with the (edition, build) baselines in C:\cr\bin\kb\baselines\.

$RigEngine = 'C:\cr\bin\purge-engine.exe'

# Pure: one argument quoted for a verbatim argument string (CommandLineToArgvW rules). Program ids hold
# '|' and ARP key names hold spaces, so anything but a plain word is quoted.
function ConvertTo-EngineArg([string]$Value) {
    if ($Value -ne '' -and $Value -notmatch '[\s"|&<>^%]') { return $Value }
    $v = [regex]::Replace($Value, '(\\*)"', { param($m) ($m.Groups[1].Value * 2) + '\"' })
    $v = [regex]::Replace($v, '(\\+)$', { param($m) $m.Groups[1].Value * 2 })
    '"' + $v + '"'
}

# Pure: a purge.run/0 FILETIME (u64, 100 ns since 1601 UTC) as a local ISO time like the rig's own; $null stays $null.
function ConvertFrom-EngineFileTime($FileTime) {
    if ($null -eq $FileTime -or "$FileTime" -eq '') { return $null }
    [DateTimeOffset]::FromFileTime([long]$FileTime).ToLocalTime().ToString('o')
}

# Pure: the program_id of the inventory entry (purge.inventory/0, parsed) whose key_path is the rig's ARP
# key $Key (compared canonically and case-insensitively). Throws when there is none or more than one.
function Find-InventoryProgramId($Inventory, [string]$Key) {
    if (-not $Key) { throw 'no ARP key to look up' }
    $want = (ConvertTo-CanonKey $Key).ToLowerInvariant()
    # (ConvertFrom-Json in 5.1 can hand back an array as one object: unroll it.)
    $entries = @(@($Inventory.entries) | ForEach-Object { $_ } | Where-Object { $_ })
    $hits = @($entries | Where-Object { $_.key_path -and (ConvertTo-CanonKey "$($_.key_path)").ToLowerInvariant() -eq $want })
    if ($hits.Count -eq 0) { throw "no inventory entry has key_path '$Key' ($($entries.Count) entries)" }
    if ($hits.Count -gt 1) { throw "$($hits.Count) inventory entries have key_path '$Key': $(@($hits | ForEach-Object { $_.program_id }) -join ', ')" }
    if (-not "$($hits[0].program_id)") { throw "inventory entry '$Key' has no program_id" }
    "$($hits[0].program_id)"
}

# Runs purge-engine with a verbatim argument string, stdout and stderr captured and logged line by line.
# With -StdoutFile, stdout goes to that file (UTF-8, no BOM) instead of the log. A child the engine starts
# (the vendor uninstaller) may inherit the pipes and hold them open after the engine exits, so the reads
# get at most $DrainSec more; output_complete says whether they finished. Never throws on a non-zero exit.
function Invoke-Engine {
    param([string]$Arguments = '', [int]$TimeoutSec = 1800, [string]$StdoutFile = '', [string]$Exe = $RigEngine, [int]$DrainSec = 30)
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw "missing $Exe (push it with Push-Tools -Engine on the host)" }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $RigUtf8
    $psi.StandardErrorEncoding = $RigUtf8
    $cmd = '"' + $Exe + '" ' + $Arguments
    Log "engine: $cmd"
    $t = Get-Date
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    $exited = $p.WaitForExit($TimeoutSec * 1000)
    if (-not $exited) {
        Log "  !! purge-engine still running after $TimeoutSec s; killing it"
        try { $p.Kill() } catch { }
        [void]$p.WaitForExit(10000)
    }
    $code = $null
    if ($exited) { $p.WaitForExit(); $code = $p.ExitCode }
    $complete = [System.Threading.Tasks.Task]::WaitAll(@($o, $e), $DrainSec * 1000)
    $stdout = ''; $stderr = ''
    if ($o.IsCompleted) { $stdout = $o.Result }
    if ($e.IsCompleted) { $stderr = $e.Result }
    foreach ($l in "$stderr" -split "`r?`n") { if ($l.Trim()) { Log "  engine stderr: $l" } }
    if ($StdoutFile) {
        [IO.File]::WriteAllText($StdoutFile, $stdout, $RigUtf8)
        Log "  engine stdout -> $StdoutFile ($($stdout.Length) chars)"
    } else {
        foreach ($l in "$stdout" -split "`r?`n") { if ($l.Trim()) { Log "  engine: $l" } }
    }
    if (-not $complete) { Log "  !! engine output still held open by a child after $DrainSec s; output incomplete" }
    $end = Get-Date
    Log ("  engine exit={0} timed_out={1} ({2:N0} s)" -f $code, (-not $exited), ($end - $t).TotalSeconds)
    [pscustomobject][ordered]@{
        cmd = $cmd; exit = $code; timed_out = (-not $exited); pid = $p.Id; start = $t; end = $end
        stdout = $stdout; stderr = $stderr; output_complete = $complete
    }
}

# One engine call of a run: Invoke-Engine, recorded in $Calls (an ArrayList that run.json holds), then a
# throw on timeout or a non-zero exit so the enclosing Phase is marked failed. Returns the Invoke-Engine record.
function Invoke-EngineStep {
    param([Parameter(Mandatory)][string]$Step, [string]$Arguments = '', $Calls = $null, [int]$TimeoutSec = 1800, [string]$StdoutFile = '')
    $r = Invoke-Engine -Arguments $Arguments -TimeoutSec $TimeoutSec -StdoutFile $StdoutFile
    if ($null -ne $Calls) {
        $tail = @("$($r.stderr)" -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 5)
        [void]$Calls.Add([ordered]@{
            step = $Step; cmd = $r.cmd; exit = $r.exit; timed_out = $r.timed_out; pid = $r.pid
            start = $r.start.ToString('o'); end = $r.end.ToString('o'); output_complete = $r.output_complete; stderr_tail = $tail
        })
    }
    if ($r.timed_out) { throw "purge-engine $Step timed out after $TimeoutSec s" }
    if ($r.exit -ne 0) { throw "purge-engine $Step exited $($r.exit)" }
    $r
}
