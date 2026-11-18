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
# $Preexisting (optional, from New-ProcKeySet taken BEFORE the root was started) guards against PID reuse:
# Windows keeps a dead parent's PID in its children's ppid, so a root that reuses such a PID (e.g. that of
# the exited smss.exe instance that started csrss/wininit) would adopt the whole system. A process that was
# already running before the root started can never be one of its descendants, so it is never added. The
# guard compares process identities (PID + kernel creation time) for equality only, never orders times, so a
# guest clock step (forward or backward, at any point of the wait) cannot change the answer.
function Get-TreeProcs($Procs, $Known, $Preexisting = $null) {
    $all = @($Procs)
    $grew = $true
    while ($grew) {
        $grew = $false
        foreach ($p in $all) {
            if ($Preexisting -and $Preexisting.Contains((Get-ProcKey $p))) { continue }
            if (-not $Known.Contains([int]$p.pid) -and $Known.Contains([int]$p.ppid) -and [int]$p.pid -gt 4) {
                [void]$Known.Add([int]$p.pid); $grew = $true
            }
        }
    }
    foreach ($p in $all) {
        if (-not $Known.Contains([int]$p.pid)) { continue }
        if ($Preexisting -and $Preexisting.Contains((Get-ProcKey $p))) { continue }
        if ([int]$p.pid -le 4 -or (Test-RigProc $p)) { continue }
        if ("$($p.name)" -ieq 'conhost.exe') { continue }
        $p
    }
}

# Identity of a process: PID plus its kernel creation time (as Get-ProcList reports it). The creation time of
# a process never changes, so the same process gives the same key on every poll, and a later process that
# reuses the PID gets another key. Only compared for equality (no clock ordering anywhere).
function Get-ProcKey($P) {
    $s = ''
    if ($null -ne $P.start) { try { $s = ([datetime]$P.start).Ticks } catch { $s = "$($P.start)" } }
    "$([int]$P.pid)|$s"
}

# The identities of every process in $Procs (default: running now). Take it before starting a root process
# and pass it to WaitTree/Get-TreeProcs -Preexisting.
function New-ProcKeySet($Procs = $null) {
    if ($null -eq $Procs) { $Procs = @(Get-ProcList) }
    $s = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($p in @($Procs)) { if ($p) { [void]$s.Add((Get-ProcKey $p)) } }
    , $s
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
        [int[]]$RootPid = @(),
        # PID-reuse guard for -RootPid: New-ProcKeySet taken before the root was started (see Get-TreeProcs).
        $Preexisting = $null
    )
    $start = Get-Date
    $deadline = $start.AddSeconds($TimeoutSec)
    $quiet = 0; $last = $null; $idleSince = $null
    $known = New-PidSet $RootPid
    while ($true) {
        if ($RootPid.Count) { $block = @(Get-TreeProcs -Procs (& $GetProcs) -Known $known -Preexisting $Preexisting) }
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
    $found = $null; $pre = $null
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        Log "launch (medium IL via task $TaskName as $user): $($spec.display)"
        $pre = New-ProcKeySet    # PID-reuse guard for the tree of the started exe (Get-TreeProcs)
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $deadline = $t.AddSeconds($StartTimeoutSec)
        # -StartTimeoutSec 0: no process wait (a short-lived command; the caller waits for its own result).
        while ($StartTimeoutSec -gt 0 -and -not $found -and (Get-Date) -lt $deadline) {
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
    if ($found) { Log "  started $($found.name)[$($found.pid)]" } elseif ($StartTimeoutSec -gt 0) { Log "  !! $Exe did not appear within $StartTimeoutSec s" } else { Log '  started (no process wait)' }
    [pscustomobject][ordered]@{
        task = $TaskName; exe = $Exe; args = $Arguments; start = $t; pid = $(if ($found) { $found.pid } else { $null })
        found = [bool]$found; pre = $pre
    }
}

# M2 telemetry pause (RIG.md §11.8): the Connected User Experiences and Telemetry service (DiagTrack) stopped and
# set to Disabled before snap A of every exec-run job (null runs included), as the Edge updater is paused, so its
# occasional upload (HKLM\...\Diagnostics\DiagTrack LastSuccessful*UploadTime) never lands in an exec window. The
# snapshot restore of the next run undoes it. Never throws; returns the record for run.json `telemetry_pause`.
function Suspend-M2Telemetry {
    $rec = [ordered]@{ service = 'DiagTrack'; before = $null; start_before = $null; after = $null; start_after = $null; error = $null }
    try {
        $s = Get-Service -Name 'DiagTrack' -ErrorAction Stop
        $rec.before = "$($s.Status)"; $rec.start_before = "$($s.StartType)"
        Set-Service -Name 'DiagTrack' -StartupType Disabled -ErrorAction Stop
        if ($s.Status -ne 'Stopped') { Stop-Service -Name 'DiagTrack' -Force -ErrorAction Stop; (Get-Service -Name 'DiagTrack').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
        $s = Get-Service -Name 'DiagTrack'
        $rec.after = "$($s.Status)"; $rec.start_after = "$($s.StartType)"
    } catch { $rec.error = $_.Exception.Message }
    Log "telemetry pause: DiagTrack $($rec.before)/$($rec.start_before) -> $($rec.after)/$($rec.start_after)$(if ($rec.error) { ' !! ' + $rec.error })"
    $rec
}

# M2 settle wait (RIG.md §11.8), right before snap A of every exec-run job (null runs included): waits until the
# ReadyBoot ETW session (`logman query ReadyBoot -ets`) has stopped, or $MaxSec, whichever comes first, then
# $AfterSec more for the trace file to be written, then until the uptime is at least $MinUptimeSec (all within
# $MaxSec). On m2-base the trace stops about 60 s after boot (ReadyBoot.etl deleted); written while it ran, it was
# m2-traps collateral in the gate run of 2026-11-16, and so were Explorer's first-run writes at uptime ~71 s, hence
# the 180 s floor. Never throws; returns the record for run.json `results.settle`.
function Wait-M2BootSettle([int]$MaxSec = 300, [int]$AfterSec = 5, [int]$PollSec = 3, [int]$MinUptimeSec = 180) {
    $t0 = Get-Date
    $rec = [ordered]@{ session = 'ReadyBoot'; active_at_start = $null; first_query = $null; stopped = $false; bounded = $false; min_uptime_sec = $MinUptimeSec
        floor_wait_sec = 0; waited_sec = $null; uptime_sec = $null; error = $null }
    try {
        $logman = Join-Path $env:SystemRoot 'System32\logman.exe'
        while ($true) {
            $q = Invoke-Native -Exe $logman -Arguments 'query ReadyBoot -ets' -TimeoutSec 30
            $active = ($q.exit -eq 0)
            if ($null -eq $rec.active_at_start) {
                $rec.active_at_start = $active
                $rec.first_query = [ordered]@{ exit = $q.exit; out = @("$($q.stdout)$($q.stderr)" -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 6) }
            }
            if (-not $active) { $rec.stopped = $true; break }
            if (((Get-Date) - $t0).TotalSeconds -ge $MaxSec) { $rec.bounded = $true; break }
            Start-Sleep -Seconds $PollSec
        }
        if ($rec.stopped -and $rec.active_at_start) { Start-Sleep -Seconds $AfterSec }
        # Uptime floor: the shell's first-run writes after logon come later than the trace stop (Explorer
        # TaskbarStateLastRun and Component Categories64 at uptime ~71 s in the gate run of 2026-11-16).
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        $up = ((Get-Date) - $boot).TotalSeconds
        if ($up -lt $MinUptimeSec) {
            $wait = [math]::Min($MinUptimeSec - $up, [math]::Max(0, $MaxSec - ((Get-Date) - $t0).TotalSeconds))
            if ($wait -lt $MinUptimeSec - $up) { $rec.bounded = $true }
            $rec.floor_wait_sec = [math]::Round($wait, 1)
            Start-Sleep -Milliseconds ([int]($wait * 1000))
        }
        $rec.uptime_sec = [int]((Get-Date) - $boot).TotalSeconds
    } catch { $rec.error = $_.Exception.Message }
    $rec.waited_sec = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    Log "settle: ReadyBoot session $(if ($rec.active_at_start) { 'was active' } else { 'not active' }); $(if ($rec.bounded) { "bound of $MaxSec s reached" } else { 'stopped' }); uptime floor $MinUptimeSec s (waited $($rec.floor_wait_sec) s for it); waited $($rec.waited_sec) s; uptime $($rec.uptime_sec) s$(if ($rec.error) { ' !! ' + $rec.error })"
    $rec
}

# Deletes the launch task of a short-lived medium-IL command that ended by itself (nothing to close or kill).
function Remove-LaunchTask($Launch) {
    if ($Launch -and $Launch.task) { Unregister-ScheduledTask -TaskName $Launch.task -Confirm:$false -ErrorAction SilentlyContinue }
}

# Closes every process started since the launch (CloseMainWindow), waits $GraceSec, kills what is left,
# then deletes the launch task.
function Stop-Launch($Launch, [int]$GraceSec = 5) {
    $closed = @(); $killed = @()
    $known = New-PidSet @($(if ($Launch.pid) { [int]$Launch.pid }))
    $mine = { param($all) @(Get-TreeProcs -Procs $all -Known $known -Preexisting $Launch.pre) + @($all | Where-Object { $Launch.exe -and $_.path -and $_.path -ieq $Launch.exe -and -not $known.Contains([int]$_.pid) }) }
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

# ------------------------------------------------------------------------------ Edge updater pause (§4)
#
# Microsoft Edge and the WebView2 runtime update themselves through MicrosoftEdgeUpdate.exe: the scheduled tasks
# MicrosoftEdgeUpdateTaskMachineCore* (logon + daily) and MicrosoftEdgeUpdateTaskMachineUA* (hourly) run it
# directly, and the services edgeupdate / edgeupdatem host it on demand (Edge and WebView2 ask them over COM).
# In the r0 campaign an update ran inside Git's install window (about 140 Edge/WebView2 items in git's truth) and
# once between a lists and an inventory capture (an invdiff failure). Every job (app run and null run alike)
# therefore calls Suspend-EdgeUpdate first, before anything is captured: both services are stopped and set to
# Disabled, every MicrosoftEdgeUpdate* task is disabled, and an update already running is waited for (then
# killed). Disabled services cannot be started on demand and disabled tasks do not fire, so the pause holds for
# the whole job; the snapshot restore of the next run undoes it (rig-base itself is unchanged). The EdgeUpdate
# policy (HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate UpdateDefault=0) is not used: Microsoft documents that the
# Edge update policies take effect only on domain-joined or MDM-enrolled devices, which the rig VMs are not.
# Everything the pause changes happens before lists 0 / snap 0, so it is part of the clean state of every run
# and never appears in a diff. The record goes to run.json `edge_pause`.

$RigEdgeServices = @('edgeupdate', 'edgeupdatem')
$RigEdgeTaskPattern = 'MicrosoftEdgeUpdate*'
# Updater and installer processes: MicrosoftEdgeUpdate.exe, its setup and the per-product installer setup.exe
# (msedge / WebView2 Installer directories).
function Test-EdgeUpdaterProc($P) {
    $n = "$($P.name)".ToLowerInvariant()
    if ($n -like 'microsoftedgeupdate*.exe' -or $n -like 'microsoftedge_x64_*.exe' -or $n -like 'microsoftedgewebview2*setup*.exe') { return $true }
    ($n -eq 'setup.exe' -or $n -eq 'mini_installer.exe') -and "$($P.path)" -match '(?i)\\(EdgeUpdate|Edge\\Application|EdgeWebView\\Application|EdgeCore)\\'
}

# Edge/WebView2/updater versions: EdgeUpdate\Clients\{app guid} name + pv (both registry views and the user hive).
function Get-EdgeVersions {
    $out = [ordered]@{}
    $roots = @('HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients', 'HKLM\SOFTWARE\Microsoft\EdgeUpdate\Clients', "HKU\$RigUserSid\Software\Microsoft\EdgeUpdate\Clients")
    foreach ($root in $roots) {
        $rk = Open-RegKey $root
        if (-not $rk) { continue }
        try {
            foreach ($sub in $rk.GetSubKeyNames()) {
                $k = $rk.OpenSubKey($sub, $false)
                if (-not $k) { continue }
                try { $out["$root\$sub"] = ('{0} {1}' -f $k.GetValue('name'), $k.GetValue('pv')).Trim() } finally { $k.Dispose() }
            }
        } finally { $rk.Dispose() }
    }
    $u = Open-RegKey 'HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate'
    if ($u) { try { $out['EdgeUpdate|version'] = "$($u.GetValue('version'))" } finally { $u.Dispose() } }
    $out
}

function Suspend-EdgeUpdate {
    param([int]$WaitSec = 120)
    $r = [ordered]@{
        method = 'services stopped+disabled, MicrosoftEdgeUpdate* tasks disabled, running updater waited for/killed'
        start = (NowIso); end = $null; services = @(); tasks = @(); updater_seen = @(); waited_sec = 0; killed = @(); errors = @()
        versions_before = $null; versions_after = $null
    }
    try { $r.versions_before = Get-EdgeVersions } catch { $r.errors += "versions: $($_.Exception.Message)" }
    foreach ($n in $RigEdgeServices) {
        $rec = [ordered]@{ name = $n; present = $false; start_before = $null; state_before = $null; start_after = $null; state_after = $null }
        try {
            $s = Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction Stop
            if ($s) {
                $rec.present = $true; $rec.start_before = "$($s.StartMode)"; $rec.state_before = "$($s.State)"
                Set-Service -Name $n -StartupType Disabled -ErrorAction Stop
                if ("$($s.State)" -ne 'Stopped') { Stop-Service -Name $n -Force -ErrorAction Stop }
                $s = Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction Stop
                $rec.start_after = "$($s.StartMode)"; $rec.state_after = "$($s.State)"
            }
        } catch { $r.errors += "service ${n}: $($_.Exception.Message)" }
        $r.services += [pscustomobject]$rec
    }
    try {
        foreach ($t in @(Get-ScheduledTask -TaskName $RigEdgeTaskPattern -ErrorAction SilentlyContinue)) {
            $rec = [ordered]@{ path = "$($t.TaskPath)$($t.TaskName)"; state_before = "$($t.State)"; state_after = $null }
            try {
                $d = Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop
                $rec.state_after = "$($d.State)"
            } catch { $r.errors += "task $($rec.path): $($_.Exception.Message)" }
            $r.tasks += [pscustomobject]$rec
        }
    } catch { $r.errors += "tasks: $($_.Exception.Message)" }
    # An update that was already running when the job started: let it finish (it installs completely, before
    # snap 0), then kill whatever is left after $WaitSec.
    $t0 = Get-Date
    $seen = @{}
    while ($true) {
        $ups = @(Get-ProcList | Where-Object { Test-EdgeUpdaterProc $_ })
        foreach ($p in $ups) { $seen["$($p.name)[$($p.pid)]"] = $true }
        if (-not $ups.Count) { break }
        if (((Get-Date) - $t0).TotalSeconds -ge $WaitSec) {
            $r.killed = @($ups | ForEach-Object { "$($_.name)[$($_.pid)]" })
            Stop-Procs $ups 'Edge updater still running after the pause wait'
            break
        }
        Start-Sleep -Seconds 3
    }
    $r.updater_seen = @($seen.Keys)
    $r.waited_sec = [int]((Get-Date) - $t0).TotalSeconds
    try { $r.versions_after = Get-EdgeVersions } catch { $r.errors += "versions: $($_.Exception.Message)" }
    $r.end = NowIso
    Log ("edge pause: services {0}; tasks disabled {1}; updater seen [{2}] waited {3} s killed [{4}]{5}" -f
        (@($r.services | ForEach-Object { "$($_.name)=$($_.start_after)/$($_.state_after)" }) -join ' '),
        @($r.tasks | Where-Object { $_.state_after -eq 'Disabled' }).Count, ($r.updater_seen -join ','), $r.waited_sec,
        ($r.killed -join ','), $(if ($r.errors.Count) { '; ERRORS: ' + ($r.errors -join ' | ') } else { '' }))
    $r
}

# ------------------------------------------------------------------- Defender signature idle (RIG.md 12.7)
#
# The rig snapshots ship Defender definitions 1.463.242.0, and every boot pulls newer ones. In the M1b gate4 campaign
# (2026-11-18) a signature / engine update landed ~20 s after snap 0 in 4 of 8 rig-base app runs: its 18-23 files and
# keys (Definition Updates\{guid}, Scans\mpcache-*, MpSigStub, DefenderSignature.amd64|Version, the antimalware engine's
# event publisher, AppX PackageVolumes flags) became truth noise. Ruling 2026-11-18: proper fix and full rerun. So every
# app and null run, before arp0 / lists 0 / snap 0, triggers one signature update itself (MpCmdRun -SignatureUpdate,
# bounded) and then waits until Defender's state is unchanged for $StableSec (bounded too); the versions are recorded at
# snap 0 and snap 2 (run.json `defender`), and truth/m1b.sh calls a run whose versions differ INVALID. Fail-safe: these
# functions never throw and never wait unbounded (no network: MpCmdRun fails or times out, the record says so).

$RigDefenderData = 'C:\ProgramData\Microsoft\Windows Defender'

# Defender's signature, engine and platform versions: MSFT_MpComputerStatus (what Get-MpComputerStatus reads; CIM call
# bounded to 30 s), else the Signature Updates registry key. Never throws; `error` says what failed.
function Get-DefenderVersions {
    $v = [ordered]@{ source = $null; av_signature = $null; as_signature = $null; nis_signature = $null; engine = $null; platform = $null
        av_signature_updated = $null; at = (NowIso); error = $null }
    try {
        $c = Get-CimInstance -Namespace 'root/Microsoft/Windows/Defender' -ClassName 'MSFT_MpComputerStatus' -OperationTimeoutSec 30 -ErrorAction Stop
        $v.source = 'MSFT_MpComputerStatus'
        $v.av_signature = "$($c.AntivirusSignatureVersion)"; $v.as_signature = "$($c.AntispywareSignatureVersion)"
        $v.nis_signature = "$($c.NISSignatureVersion)"; $v.engine = "$($c.AMEngineVersion)"; $v.platform = "$($c.AMProductVersion)"
        if ($c.AntivirusSignatureLastUpdated) { $v.av_signature_updated = ([datetime]$c.AntivirusSignatureLastUpdated).ToString('o') }
    } catch {
        $v.error = "MSFT_MpComputerStatus: $($_.Exception.Message)"
        try {
            $k = Open-RegKey 'HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates'
            if ($k) {
                try {
                    $v.source = 'registry'
                    $v.av_signature = "$($k.GetValue('AVSignatureVersion'))"; $v.as_signature = "$($k.GetValue('ASSignatureVersion'))"
                    $v.nis_signature = "$($k.GetValue('NISSignatureVersion'))"; $v.engine = "$($k.GetValue('EngineVersion'))"
                } finally { $k.Dispose() }
            }
            $loc = "$(Get-RegRaw 'HKLM\SOFTWARE\Microsoft\Windows Defender' 'InstallLocation')"
            if ($loc -match '\\Platform\\([0-9][0-9.\-]*)\\?$') { $v.platform = $Matches[1] -replace '-\d+$', '' }
        } catch { $v.error += "; registry: $($_.Exception.Message)" }
    }
    foreach ($n in 'av_signature', 'as_signature', 'nis_signature', 'engine', 'platform') { if (-not "$($v[$n])".Trim()) { $v[$n] = $null } }
    $v
}

# What a signature / engine update changes: the versions, the Definition Updates folders (names) and the engine scan
# cache (Scans\mpcache-*: names and sizes). Never throws (a listing error is part of the text).
function Get-DefenderFingerprint {
    $v = Get-DefenderVersions
    $parts = New-Object System.Collections.ArrayList
    [void]$parts.Add("v $($v.av_signature) $($v.as_signature) $($v.engine) $($v.platform)")
    try {
        foreach ($d in @(Get-ChildItem -LiteralPath (Join-Path $RigDefenderData 'Definition Updates') -Force -ErrorAction Stop)) { [void]$parts.Add("d $($d.Name)") }
    } catch { [void]$parts.Add("d! $($_.Exception.Message)") }
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $RigDefenderData 'Scans') -Filter 'mpcache-*' -File -Force -ErrorAction Stop)) { [void]$parts.Add("m $($f.Name) $($f.Length)") }
    } catch { [void]$parts.Add("m! $($_.Exception.Message)") }
    [pscustomobject]@{ versions = $v; text = (@($parts) | Sort-Object) -join "`n" }
}

# MpCmdRun.exe -SignatureUpdate, waited for at most $TimeoutSec (killed after). No output redirection: a child of
# MpCmdRun that inherited the pipes could keep a stream read open past the kill. Never throws.
function Invoke-DefenderSignatureUpdate([int]$TimeoutSec = 300) {
    $r = [ordered]@{ exe = $null; args = '-SignatureUpdate'; exit = $null; timed_out = $false; sec = $null; error = $null }
    $t0 = Get-Date
    try {
        $cands = @(Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe')
        $cands += @(Get-ChildItem -LiteralPath (Join-Path $RigDefenderData 'Platform') -Directory -ErrorAction SilentlyContinue |
            Sort-Object { try { [version]($_.Name -replace '-.*$', '') } catch { [version]'0.0' } } -Descending |
            ForEach-Object { Join-Path $_.FullName 'MpCmdRun.exe' })
        $r.exe = @($cands | Where-Object { Test-Path -LiteralPath $_ }) | Select-Object -First 1
        if (-not $r.exe) { throw 'MpCmdRun.exe not found' }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $r.exe; $psi.Arguments = $r.args; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        if ($p.WaitForExit($TimeoutSec * 1000)) { $r.exit = $p.ExitCode }
        else { $r.timed_out = $true; try { $p.Kill() } catch { } }
    } catch { $r.error = $_.Exception.Message }
    $r.sec = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    $r
}

# Before arp0 / lists 0 / snap 0 of every app and null run: one signature update (bounded by $UpdateTimeoutSec), then
# polls Get-DefenderFingerprint every $PollSec until it has not changed for $StableSec, or $MaxStableWaitSec passed
# (`bounded`). Never throws; returns the record for run.json `defender.idle`.
function Wait-DefenderIdle([int]$UpdateTimeoutSec = 300, [int]$StableSec = 60, [int]$MaxStableWaitSec = 300, [int]$PollSec = 5) {
    $t0 = Get-Date
    $rec = [ordered]@{ method = 'MpCmdRun -SignatureUpdate (bounded), then versions + Definition Updates + Scans\mpcache-* unchanged for stable_sec (bounded)'
        start = (NowIso); end = $null; before = $null; trigger = $null; changes = 0; stable = $false; stable_sec = $StableSec
        bounded = $false; max_stable_wait_sec = $MaxStableWaitSec; after = $null; updated = $null; waited_sec = $null; error = $null }
    try {
        $rec.before = Get-DefenderVersions
        $rec.trigger = Invoke-DefenderSignatureUpdate -TimeoutSec $UpdateTimeoutSec
        $fp = Get-DefenderFingerprint
        $t1 = Get-Date; $since = $t1
        while ($true) {
            if (((Get-Date) - $since).TotalSeconds -ge $StableSec) { $rec.stable = $true; break }
            if (((Get-Date) - $t1).TotalSeconds -ge $MaxStableWaitSec) { $rec.bounded = $true; break }
            Start-Sleep -Milliseconds ([int]($PollSec * 1000))
            $n = Get-DefenderFingerprint
            if ($n.text -ne $fp.text) { $rec.changes++; $since = Get-Date }
            $fp = $n
        }
        $rec.after = $fp.versions
        $rec.updated = (@('av_signature', 'as_signature', 'engine', 'platform') | Where-Object { "$($rec.before[$_])" -ne "$($rec.after[$_])" }).Count -gt 0
    } catch { $rec.error = $_.Exception.Message }
    $rec.end = NowIso
    $rec.waited_sec = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    $tg = $rec.trigger
    Log ("defender idle: signatures {0} -> {1} (engine {2} -> {3}); MpCmdRun exit {4}{5}{6} in {7} s; {8} after {9} change(s); waited {10} s{11}" -f
        $rec.before.av_signature, $rec.after.av_signature, $rec.before.engine, $rec.after.engine, $tg.exit,
        $(if ($tg.timed_out) { ' TIMED OUT' }), $(if ($tg.error) { ' !! ' + $tg.error }), $tg.sec,
        $(if ($rec.stable) { "stable $StableSec s" } else { "NOT stable (bound $MaxStableWaitSec s)" }), $rec.changes, $rec.waited_sec,
        $(if ($rec.error) { ' !! ' + $rec.error }))
    $rec
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

# M1b (C-OBJECT): besides the M0 fields, each task carries hidden, logon_type (the Principal's LogonType name:
# Password, S4U, Interactive, Group, ServiceAccount, InteractiveOrPassword, None), has_stored_password (LogonType
# Password or InteractiveOrPassword) and actions_detail (one record per action: kind exec | com_handler | other,
# path, arguments, working_dir, clsid, data; 'actions' keeps its M0 string form). -Tasks: test input.
function Get-TaskRecords {
    param($Tasks = $null)
    if ($null -eq $Tasks) { $Tasks = @(Get-ScheduledTask -ErrorAction Stop) }
    foreach ($t in @($Tasks)) {
        if (-not $t) { continue }
        $acts = @()
        $detail = @()
        foreach ($a in @($t.Actions)) {
            if (-not $a) { continue }
            $cls = "$($a.CimClass.CimClassName)"
            if ($cls -eq 'MSFT_TaskExecAction') {
                $acts += ("$($a.Execute) $($a.Arguments)").Trim()
                $detail += [pscustomobject][ordered]@{ kind = 'exec'; path = $a.Execute; arguments = $a.Arguments; working_dir = $a.WorkingDirectory; clsid = $null; data = $null }
            } elseif ($cls -eq 'MSFT_TaskComHandlerAction') {
                $acts += ("com:$($a.ClassId) $($a.Data)").Trim()
                $detail += [pscustomobject][ordered]@{ kind = 'com_handler'; path = $null; arguments = $null; working_dir = $null; clsid = $a.ClassId; data = $a.Data }
            } else {
                $acts += $cls
                $detail += [pscustomobject][ordered]@{ kind = 'other'; path = $null; arguments = $null; working_dir = $null; clsid = $null; data = $cls }
            }
        }
        $logon = $(if ($t.Principal -and $null -ne $t.Principal.LogonType) { "$($t.Principal.LogonType)" } else { $null })
        [pscustomobject][ordered]@{
            path = "$($t.TaskPath)$($t.TaskName)"; actions = $acts; enabled = ("$($t.State)" -ne 'Disabled')
            hidden = [bool]($t.Settings -and $t.Settings.Hidden); logon_type = $logon
            has_stored_password = (@('Password', 'InteractiveOrPassword') -contains $logon); actions_detail = $detail
        }
    }
}

# M1b (C-OBJECT): besides the M0 fields (WMI view), each service carries the registry view of
# HKLM\SYSTEM\CurrentControlSet\Services\<name>: image_path_raw (ImagePath as stored, REG_EXPAND_SZ not expanded),
# service_dll (Parameters\ServiceDll, else the top-level ServiceDll, as stored), service_type (Type), start_value
# (Start), object_name, depend_on_service (array), and state (WMI State). A value that is absent is null.
# -Services / -Drivers / -OpenKey: test input (OpenKey: { param($canon) <RegistryKey-like or $null> }).
function Get-ServiceRecords {
    param($Services = $null, $Drivers = $null, [scriptblock]$OpenKey = $null)
    if ($null -eq $Services) { $Services = @(Get-CimInstance Win32_Service -ErrorAction Stop) }
    if ($null -eq $Drivers) { $Drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue) }
    if (-not $OpenKey) { $OpenKey = { param($c) Open-RegKey $c } }
    $raw = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
    $reg = {
        param([string]$Name)
        $r = [ordered]@{ image_path_raw = $null; service_dll = $null; service_type = $null; start_value = $null; object_name = $null; depend_on_service = @() }
        $k = $null
        try { $k = & $OpenKey "HKLM\SYSTEM\CurrentControlSet\Services\$Name" } catch { }
        if (-not $k) { return $r }
        try {
            $r.image_path_raw = $k.GetValue('ImagePath', $null, $raw)
            $ty = $k.GetValue('Type', $null); if ($null -ne $ty) { $r.service_type = [uint32]([int64]$ty -band [int64]4294967295) }
            $st = $k.GetValue('Start', $null); if ($null -ne $st) { $r.start_value = [uint32]([int64]$st -band [int64]4294967295) }
            $r.object_name = $k.GetValue('ObjectName', $null, $raw)
            $dep = $k.GetValue('DependOnService', $null); if ($null -ne $dep) { $r.depend_on_service = @($dep | Where-Object { "$_" -ne '' }) }
            $r.service_dll = $k.GetValue('ServiceDll', $null, $raw)
            $p = $null
            try { $p = $k.OpenSubKey('Parameters', $false) } catch { }
            if ($p) { try { $d = $p.GetValue('ServiceDll', $null, $raw); if ($null -ne $d) { $r.service_dll = $d } } finally { $p.Dispose() } }
        } catch { } finally { $k.Dispose() }
        $r
    }
    foreach ($s in @($Services)) {
        if (-not $s) { continue }
        $g = & $reg $s.Name
        [pscustomobject][ordered]@{ name = $s.Name; display = $s.DisplayName; image_path = $s.PathName; start = $s.StartMode; type = $s.ServiceType
            image_path_raw = $g.image_path_raw; service_dll = $g.service_dll; service_type = $g.service_type; start_value = $g.start_value
            object_name = $g.object_name; depend_on_service = $g.depend_on_service; state = $s.State }
    }
    foreach ($s in @($Drivers)) {
        if (-not $s) { continue }
        $g = & $reg $s.Name
        [pscustomobject][ordered]@{ name = $s.Name; display = $s.DisplayName; image_path = $s.PathName; start = $s.StartMode; type = "driver:$($s.ServiceType)"
            image_path_raw = $g.image_path_raw; service_dll = $g.service_dll; service_type = $g.service_type; start_value = $g.start_value
            object_name = $g.object_name; depend_on_service = $g.depend_on_service; state = $s.State }
    }
}

# One call for all application filters, joined to rules by InstanceID (per-rule filter calls take minutes).
# M1b (C-OBJECT): each rule also carries value_name (the registry value name, = id, when the rule is in one of the
# rule stores below: value name = rule id = WMI InstanceID; else null), raw (that value's string, as stored) and
# reg_key (the key it was found in). -Rules / -Filters / -RegRules (hashtable id -> @{ raw; key }): test input.
function Get-FirewallRecords {
    param($Rules = $null, $Filters = $null, [hashtable]$RegRules = $null)
    if ($null -eq $Filters) { $Filters = @(Get-NetFirewallApplicationFilter -All -ErrorAction Stop) }
    if ($null -eq $Rules) { $Rules = @(Get-NetFirewallRule -ErrorAction Stop) }
    if ($null -eq $RegRules) {
        $RegRules = @{}
        $fp = 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
        foreach ($kp in "$fp\FirewallRules", "$fp\RestrictedServices\AppIso\FirewallRules", "$fp\RestrictedServices\Configurable\System") {
            $k = Open-RegKey $kp
            if (-not $k) { continue }
            try {
                foreach ($n in $k.GetValueNames()) {
                    if (-not $RegRules.ContainsKey($n)) { $RegRules[$n] = @{ raw = "$($k.GetValue($n, $null, 'DoNotExpandEnvironmentNames'))"; key = $kp } }
                }
            } finally { $k.Dispose() }
        }
    }
    $prog = @{}
    foreach ($f in @($Filters)) { if ($f) { $prog[[string]$f.InstanceID] = $f.Program } }
    foreach ($r in @($Rules)) {
        if (-not $r) { continue }
        $id = [string]$r.Name
        $rr = $(if ($id -and $RegRules.ContainsKey($id)) { $RegRules[$id] } else { $null })
        [pscustomobject][ordered]@{
            id = $r.Name; display = $r.DisplayName; program = $prog[[string]$r.InstanceID]
            direction = "$($r.Direction)"; enabled = ("$($r.Enabled)" -eq 'True')
            value_name = $(if ($rr) { $id } else { $null }); raw = $(if ($rr) { $rr.raw } else { $null }); reg_key = $(if ($rr) { $rr.key } else { $null })
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
    param([string]$Arguments = '', [int]$TimeoutSec = 1800, [string]$StdoutFile = '', [string]$Exe = $RigEngine, [int]$DrainSec = 30,
          # Extra environment variables for the engine process only (M2: PURGE_FAULT_AT / PURGE_FAULT_PAUSE).
          [hashtable]$Environment = @{})
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
    foreach ($k in @($Environment.Keys)) { $psi.EnvironmentVariables[[string]$k] = [string]$Environment[$k] }
    $cmd = '"' + $Exe + '" ' + $Arguments
    $envText = @($Environment.Keys | Sort-Object | ForEach-Object { "$_=$($Environment[$_])" }) -join ' '
    Log "engine: $(if ($envText) { "[$envText] " })$cmd"
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
        cmd = $cmd; env = $envText; exit = $code; timed_out = (-not $exited); pid = $p.Id; start = $t; end = $end
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

# ============================================================================== M2 executor runs (RIG.md §11)
#
# Helpers of the M2 guest scripts exec-run.ps1, m2-crash.ps1 and m2-reboot.ps1: the engine verbs exec / undo /
# journal / quarantine / plan from-targets of the rig-exec build (docs\M2_DESIGN.json M2-CLI), the store copies
# that go into the run output, rigtool deep / snap / execdiff / fidelity, and the continuation marker of the
# reboot-in-job mechanism. Every path the rig hands to the engine is absolute; every output file name in the run
# directory matches [\w.-]+ (rig.ps1 Pull-Run copies only such top-level files).

$RigPurgeData       = 'C:\ProgramData\Purge'
$RigEngineInstalled = 'C:\Program Files\Purge\purge-engine.exe'
$RigInstallScript   = 'C:\cr\install\install.ps1'
$RigGuestDir        = 'C:\cr\guest'
$RigWork            = 'C:\cr\work'
# std::process::abort of an injected fault: STATUS_STACK_BUFFER_OVERRUN (0xC0000409) as a signed Int32.
$RigFaultAbortExit  = -1073740791
$RigPfroKey         = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager'
# The second fixed volume of m2-base (G0: X:\.purge-q pre-created by a standard user) and the user-store
# fingerprint directory a standard user can write (forged-user-fp trap).
$RigDRoot           = 'D:\'
$RigUserFpDir       = $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Purge\fp' } else { '' })
# The M2 ambient set (vm\truth\m2-ambient.json, pushed by rig.ps1 Push-M2Ambient when it exists; RIG.md §11.8).
$RigM2Ambient       = 'C:\cr\bin\m2-ambient.json'
# System Restore settings the G6 legs change (the snapshot restore of the next run undoes them).
$RigSrKey           = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'

# The engine M2 runs call: the copy install.ps1 put under Program Files when it is there, else the pushed one.
function Get-M2EngineExe { if (Test-Path -LiteralPath $RigEngineInstalled -PathType Leaf) { $RigEngineInstalled } else { $RigEngine } }

# ------------------------------------------------------------------ engine command lines (pure; M2-CLI contract)

function New-M2PlanArgs([string]$Targets, [string]$Out) {
    'plan from-targets ' + (ConvertTo-EngineArg $Targets) + ' -o ' + (ConvertTo-EngineArg $Out)
}

function New-M2ExecArgs([string]$Plan, [string]$Confirm, [string]$Select = '', [string]$Out = '', [switch]$AllowIrreversible, [string]$RestorePoint = '') {
    if ($RestorePoint -and @('off', 'high-risk', 'always') -notcontains $RestorePoint) { throw "bad --restore-point '$RestorePoint'" }
    $a = 'exec --plan ' + (ConvertTo-EngineArg $Plan) + ' --confirm ' + (ConvertTo-EngineArg $Confirm)
    if ($Select) { $a += ' --select ' + (ConvertTo-EngineArg $Select) }
    if ($AllowIrreversible) { $a += ' --allow-irreversible' }
    if ($RestorePoint) { $a += ' --restore-point ' + $RestorePoint }
    if ($Out) { $a += ' -o ' + (ConvertTo-EngineArg $Out) }
    $a
}

function New-M2UndoArgs([string]$Session, [string]$Items = '', [string]$Confirm = '', [string]$Out = '') {
    if (-not $Session) { throw 'undo needs a session id' }
    $a = 'undo --session ' + (ConvertTo-EngineArg $Session)
    if ($Items) { $a += ' --items ' + (ConvertTo-EngineArg $Items) }
    if ($Confirm) { $a += ' --confirm ' + (ConvertTo-EngineArg $Confirm) }
    if ($Out) { $a += ' -o ' + (ConvertTo-EngineArg $Out) }
    $a
}

function New-M2JournalArgs([string]$Verb, [string]$Session = '') {
    if (@('recover', 'resume', 'rollback', 'fault-points', 'show') -notcontains $Verb) { throw "bad journal verb '$Verb'" }
    if ($Verb -eq 'show' -and -not $Session) { throw 'journal show needs a session id' }
    $a = "journal $Verb"
    if ($Session) { $a += ' --session ' + (ConvertTo-EngineArg $Session) }
    $a
}

# quarantine expiring | quarantine purge --ids <id> [<id>...] --yes-irreversible
function New-M2QuarantineArgs([string]$Verb, [string[]]$Ids = @()) {
    if ($Verb -eq 'expiring') { return 'quarantine expiring' }
    if ($Verb -ne 'purge') { throw "bad quarantine verb '$Verb'" }
    $ids = @($Ids | Where-Object { "$_" -ne '' })
    if (-not $ids.Count) { throw 'quarantine purge needs at least one id' }
    'quarantine purge --ids ' + (@($ids | ForEach-Object { ConvertTo-EngineArg "$_" }) -join ' ') + ' --yes-irreversible'
}

# --------------------------------------------------------------------------------- plan, selection, confirm

function Get-Sha256Hex([byte[]]$Bytes) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { -join @($h.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $h.Dispose() }
}

# selection_hash = SHA-256 (lower-case hex) of the selected candidate ids, de-duplicated, sorted ordinally and joined
# with LF (UTF-8). confirm = SHA-256 of the UTF-8 text plan_hash || selection_hash (both lower-case hex).
# docs\M2_DESIGN.json fixes "confirm = SHA-256(plan_hash || selection_hash)" and "selection_hash = SHA-256 of sorted
# ids"; the byte encoding (hex text, LF joiner) is the rig's reading of it and must match M2-CLI.
function Get-M2SelectionHash([string[]]$Ids) {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($i in @($Ids)) { if ("$i" -ne '') { [void]$set.Add("$i") } }
    $arr = [string[]]@($set)
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    Get-Sha256Hex ($RigUtf8.GetBytes(($arr -join "`n")))
}

function Get-M2Confirm([string]$PlanHash, [string[]]$Ids) {
    if ($PlanHash -notmatch '^[0-9A-Fa-f]+$') { throw "bad plan hash '$PlanHash'" }
    Get-Sha256Hex ($RigUtf8.GetBytes($PlanHash.ToLowerInvariant() + (Get-M2SelectionHash $Ids)))
}

# The engine writes the scan sidecar next to the plan: plan.json -> plan.scan.json.
function Get-M2Sidecar([string]$Plan) { $Plan -replace '\.json$', '.scan.json' }

function Get-M2PlanHash([string]$Plan) {
    $sc = Get-M2Sidecar $Plan
    if (-not (Test-Path -LiteralPath $sc)) { throw "no scan sidecar $sc" }
    $h = "$(([IO.File]::ReadAllText($sc) | ConvertFrom-Json).plan_hash)"
    if (-not $h) { throw "no plan_hash in $sc" }
    $h
}

# Candidate ids the plan ticks by default (band Safe and preselected): plan items and sidecar items are in the same
# order (ScanDoc.items = the plan's items in full).
function Get-M2DefaultSelection([string]$Plan) {
    $p = [IO.File]::ReadAllText($Plan) | ConvertFrom-Json
    $s = [IO.File]::ReadAllText((Get-M2Sidecar $Plan)) | ConvertFrom-Json
    $pi = @(@($p.items) | ForEach-Object { $_ } | Where-Object { $_ }); $si = @(@($s.items) | ForEach-Object { $_ } | Where-Object { $_ })
    @(for ($i = 0; $i -lt [Math]::Min($pi.Count, $si.Count); $i++) { if ("$($pi[$i].band)" -eq 'Safe' -and $pi[$i].preselected -eq $true -and $si[$i].id) { "$($si[$i].id)" } })
}

# Candidate ids of the plan items whose band is one of $Bands, preselected or not (the m2-fidelity app stage: every
# item the plan offers for removal, i.e. not Blocked, goes through exec and undo; RIG.md §11.3).
function Get-M2BandSelection([string]$Plan, [string[]]$Bands = @('Safe', 'Likely', 'Weak')) {
    $p = [IO.File]::ReadAllText($Plan) | ConvertFrom-Json
    $s = [IO.File]::ReadAllText((Get-M2Sidecar $Plan)) | ConvertFrom-Json
    $pi = @(@($p.items) | ForEach-Object { $_ } | Where-Object { $_ }); $si = @(@($s.items) | ForEach-Object { $_ } | Where-Object { $_ })
    @(for ($i = 0; $i -lt [Math]::Min($pi.Count, $si.Count); $i++) { if ($Bands -contains "$($pi[$i].band)" -and "$($pi[$i].band)" -ne 'Blocked' -and $si[$i].id) { "$($si[$i].id)" } })
}

# Where a target lives for the nesting test: @(kind, path) with kind fs | key | inkey (a value or segment of the
# key at path), or $null (service, task, ...). Mirrors purge-plan collapse::place.
function Get-M2TargetPlace($Target) {
    $p = "$($Target.path)".TrimEnd('\')
    switch ("$($Target.type)") {
        'Path' { return @('fs', $p) }
        'RegKey' { return @('key', $p) }
        { @('RegValue', 'RegMultiSzSegment') -contains $_ } { return @('inkey', $p) }
    }
    $null
}

# Whether target $Child lies inside target $Parent (purge-plan collapse::nests_in: strictly inside, except that a
# value lies inside its own key; paths compared case-insensitively).
function Test-M2TargetNests($Child, $Parent) {
    $c = Get-M2TargetPlace $Child; $p = Get-M2TargetPlace $Parent
    if (-not $c -or -not $p) { return $false }
    $inside = $c[1].StartsWith($p[1] + '\', [StringComparison]::OrdinalIgnoreCase)
    if ($c[0] -eq 'fs' -and $p[0] -eq 'fs') { return $inside }
    if ($c[0] -eq 'key' -and $p[0] -eq 'key') { return $inside }
    if ($c[0] -eq 'inkey' -and $p[0] -eq 'key') { return ($inside -or [string]::Equals($c[1], $p[1], [StringComparison]::OrdinalIgnoreCase)) }
    $false
}

# The engine refuses a plan in which an item comes before an item nested in it (purge-exec plan_in step 5, "the
# inner one comes first"). Each target is placed before the first earlier target that contains it; the order is
# otherwise kept.
function Sort-M2TargetsInnerFirst([object[]]$Targets) {
    $out = New-Object System.Collections.ArrayList
    foreach ($t in @($Targets)) {
        $at = $out.Count
        for ($i = 0; $i -lt $out.Count; $i++) { if (Test-M2TargetNests $t.target $out[$i].target) { $at = $i; break } }
        $out.Insert($at, $t)
    }
    @($out)
}

# Merges purge.rig.targets/0 files into one for `plan from-targets`: the targets of group $Group (all groups when
# empty), optionally only $OnlyIds, optionally in reverse order. Returns the ids written (the candidate ids
# `plan from-targets` keeps).
function Write-M2Targets([string[]]$Files, [string]$Group, [string]$Out, [string[]]$OnlyIds = @(), [switch]$Reverse) {
    $all = New-Object System.Collections.ArrayList
    foreach ($f in $Files) {
        $d = [IO.File]::ReadAllText($f) | ConvertFrom-Json
        if ("$($d.schema)" -ne 'purge.rig.targets/0') { throw "$f is not purge.rig.targets/0 ('$($d.schema)')" }
        foreach ($t in @(@($d.targets) | ForEach-Object { $_ } | Where-Object { $_ })) {
            if ($Group -and "$($t.group)" -ne $Group) { continue }
            if ($OnlyIds.Count -and $OnlyIds -notcontains "$($t.id)") { continue }
            [void]$all.Add($t)
        }
    }
    $list = @($all)
    if ($Reverse) { [Array]::Reverse($list) }
    $list = @(Sort-M2TargetsInnerFirst $list)
    $doc =[ordered]@{ schema = 'purge.rig.targets/0'; source = 'riglib Write-M2Targets'; origin = 'ManualUser'; group = $Group; targets = $list }
    [IO.File]::WriteAllText($Out, (ConvertTo-Json -InputObject $doc -Depth 20), $RigUtf8)
    @($list | ForEach-Object { "$($_.id)" })
}

# --select / --items file: a JSON array of candidate (item) ids.
function Write-M2IdFile([string[]]$Ids, [string]$Path) {
    $arr = @($Ids | Where-Object { "$_" -ne '' } | ForEach-Object { "$_" })
    $json = $(if ($arr.Count) { ConvertTo-Json -InputObject $arr } else { '[]' })
    [IO.File]::WriteAllText($Path, $json, $RigUtf8)
    $Path
}

# ----------------------------------------------------------------------------------------- engine calls

# One engine call of an M2 run: Invoke-Engine with the M2 engine, recorded in $Calls. Exit codes outside $OkExit
# (and a timeout) throw unless -NoThrow; an injected abort (0xC0000409) is marked crashed.
function Invoke-M2Engine {
    param([Parameter(Mandatory)][string]$Step, [string]$Arguments = '', $Calls = $null, [hashtable]$Environment = @{},
          [string]$StdoutFile = '', [int]$TimeoutSec = 1800, [int[]]$OkExit = @(0), [switch]$NoThrow)
    $r = Invoke-Engine -Exe (Get-M2EngineExe) -Arguments $Arguments -TimeoutSec $TimeoutSec -StdoutFile $StdoutFile -Environment $Environment
    $crashed = ($r.exit -eq $RigFaultAbortExit)
    $r | Add-Member -NotePropertyName crashed -NotePropertyValue $crashed -Force
    $r | Add-Member -NotePropertyName step -NotePropertyValue $Step -Force
    if ($null -ne $Calls) {
        $tail = @("$($r.stderr)" -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 5)
        [void]$Calls.Add([ordered]@{
            step = $Step; cmd = $r.cmd; env = $r.env; exit = $r.exit; crashed = $crashed; timed_out = $r.timed_out; pid = $r.pid
            start = $r.start.ToString('o'); end = $r.end.ToString('o'); stderr_tail = $tail
        })
    }
    if (-not $NoThrow) {
        if ($r.timed_out) { throw "purge-engine $Step timed out after $TimeoutSec s" }
        if ($OkExit -notcontains $r.exit) { throw "purge-engine $Step exited $($r.exit)" }
    }
    $r
}

# `journal fault-points` output -> point names. Accepts a JSON array (strings or objects with name/point) or text
# lines that start with the point name (every declared point has a dot: intent.flushed, regdelete.mid, ...).
function ConvertFrom-M2FaultPoints([string]$Text) {
    $t = "$Text".Trim()
    if ($t.StartsWith('[') -or $t.StartsWith('{')) {
        $j = $t | ConvertFrom-Json
        $items = @(@($j) | ForEach-Object { $_ })
        if ($j.PSObject -and $j.PSObject.Properties['points']) { $items = @(@($j.points) | ForEach-Object { $_ }) }
        return @($items | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_.name) { "$($_.name)" } elseif ($_.point) { "$($_.point)" } } | Where-Object { $_ })
    }
    @($t -split "`r?`n" | ForEach-Object { $m = [regex]::Match($_, '^\s*([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)(?=\s|:|$)'); if ($m.Success) { $m.Groups[1].Value } } | Select-Object -Unique)
}

# Ids under which `quarantine expiring` lists the entries whose JSON mentions $Needle (an item path).
function Find-M2ExpiryIds([string]$Text, [string]$Needle) {
    $found = New-Object System.Collections.ArrayList
    $esc = (ConvertTo-Json -InputObject $Needle -Compress).Trim('"')
    $walk = $null
    $walk = {
        param($o)
        if ($null -eq $o) { return }
        if ($o -is [System.Array]) { foreach ($x in $o) { & $walk $x }; return }
        if ($o -is [System.Management.Automation.PSCustomObject]) {
            $id = $o.PSObject.Properties['id']
            $js = ConvertTo-Json -InputObject $o -Depth 20 -Compress
            if ($id -and ($js.IndexOf($Needle, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $js.IndexOf($esc, [StringComparison]::OrdinalIgnoreCase) -ge 0)) { [void]$found.Add("$($id.Value)"); return }
            foreach ($p in $o.PSObject.Properties) { & $walk $p.Value }
        }
    }
    try { & $walk ("$Text" | ConvertFrom-Json) } catch { }
    @($found | Select-Object -Unique)
}

# ----------------------------------------------------------------------------------- store and sessions

# Session directories under C:\ProgramData\Purge\sessions, oldest first (by creation time, then name).
function Get-M2Sessions {
    $d = Join-Path $RigPurgeData 'sessions'
    if (-not (Test-Path -LiteralPath $d)) { return @() }
    @(Get-ChildItem -LiteralPath $d -Directory -ErrorAction SilentlyContinue | Sort-Object CreationTimeUtc, Name | ForEach-Object { $_.Name })
}

# The session a call created: the newest directory not in $Before.
function Get-M2NewSession([string[]]$Before) {
    $new = @(Get-M2Sessions | Where-Object { $Before -notcontains $_ })
    if ($new.Count) { return $new[$new.Count - 1] }
    $null
}

function Get-M2SessionDir([string]$Session) { Join-Path (Join-Path $RigPurgeData 'sessions') $Session }

# Copies the top-level files of a session (journal.jsonl, report.json, plan copies, ...) into $Dest as
# <Tag>-<file>. Returns the copied names.
function Copy-M2Session([string]$Session, [string]$Dest, [string]$Tag) {
    $sd = $(if ($Session) { Get-M2SessionDir $Session } else { '' })
    if (-not $sd -or -not (Test-Path -LiteralPath $sd)) { Log "  !! no session dir for '$Session'"; return @() }
    $out = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $sd -File -ErrorAction SilentlyContinue)) {
        $n = "$Tag-" + ($f.Name -replace '[^\w.-]', '_')
        Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $Dest $n) -Force
        $out += $n
    }
    Log "  session $Session -> $($out.Count) file(s) as $Tag-*"
    $out
}

# File-system listing of every quarantine root (C:\ProgramData\Purge\Quarantine and X:\.purge-q of each fixed
# drive), never descending into a reparse point.
function Get-M2QuarantineListing([int]$Max = 20000) {
    $roots = @(Join-Path $RigPurgeData 'Quarantine')
    foreach ($dr in @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' })) { $roots += (Join-Path $dr.RootDirectory.FullName '.purge-q') }
    $rows = New-Object System.Collections.ArrayList
    $walk = $null
    $walk = {
        param([string]$Dir, [int]$Depth)
        if ($Depth -gt 64 -or $rows.Count -ge $Max) { return }
        $di = New-Object IO.DirectoryInfo ('\\?\' + $Dir)
        $entries = @()
        try { $entries = @($di.EnumerateFileSystemInfos()) } catch { [void]$rows.Add([ordered]@{ path = $Dir; error = $_.Exception.Message }); return }
        foreach ($e in $entries) {
            $p = $e.FullName -replace '^\\\\\?\\', ''
            $a = [int]$e.Attributes
            $isDir = (($a -band 0x10) -ne 0); $rp = (($a -band 0x400) -ne 0)
            [void]$rows.Add([ordered]@{ path = $p; dir = $isDir; reparse = $rp; attrs = ('0x{0:x}' -f $a); size = $(if ($isDir) { $null } else { $e.Length }) })
            if ($isDir -and -not $rp) { & $walk $p ($Depth + 1) }
        }
    }
    $present = @()
    foreach ($r in $roots) { if (Test-Path -LiteralPath $r) { $present += $r; & $walk $r 0 } }
    [ordered]@{ schema = 'purge.rig.quarantine-listing/1'; time = (NowIso); roots = $present; truncated = ($rows.Count -ge $Max); entries = @($rows) }
}

# The store as it is now, into the run output: sessions\index.json, a zip of the sessions tree and the
# quarantine listing, named <Tag>-*. Never throws (each part records its own error).
function Save-M2Store([string]$Dest, [string]$Tag) {
    $rec = [ordered]@{ tag = $Tag; index = $null; zip = $null; listing = $null; errors = @() }
    $idx = Join-Path $RigPurgeData 'sessions\index.json'
    try { if (Test-Path -LiteralPath $idx) { Copy-Item -LiteralPath $idx -Destination (Join-Path $Dest "$Tag-index.json") -Force; $rec.index = "$Tag-index.json" } } catch { $rec.errors += "index: $($_.Exception.Message)" }
    try {
        $sd = Join-Path $RigPurgeData 'sessions'
        if (Test-Path -LiteralPath $sd) {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = Join-Path $Dest "$Tag-sessions.zip"
            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
            [IO.Compression.ZipFile]::CreateFromDirectory($sd, $zip)
            $rec.zip = "$Tag-sessions.zip"
        }
    } catch { $rec.errors += "zip: $($_.Exception.Message)" }
    try { Write-JsonFile (Get-M2QuarantineListing) (Join-Path $Dest "$Tag-quarantine.json") 6; $rec.listing = "$Tag-quarantine.json" } catch { $rec.errors += "listing: $($_.Exception.Message)" }
    Log "  store saved as $Tag-* ($(if ($rec.errors.Count) { 'errors: ' + ($rec.errors -join ' | ') } else { 'ok' }))"
    $rec
}

# ------------------------------------------------------------------------------------- rigtool and scripts

function Invoke-RigTool([string]$Arguments, [int]$TimeoutSec = 3600) {
    if (-not (Test-Path -LiteralPath $RigTool)) { throw "missing $RigTool (run Push-Tools on the host)" }
    Log "rigtool $Arguments"
    $r = Invoke-Native -Exe $RigTool -Arguments $Arguments -TimeoutSec $TimeoutSec
    foreach ($l in @("$($r.stdout)" -split "`r?`n") + @("$($r.stderr)" -split "`r?`n")) { if ($l.Trim()) { Log "  rigtool: $l" } }
    $r
}

# rigtool snap (RIG.md §2) into $Out; $Roots replaces the default roots (each root a path or a registry key).
function Invoke-M2Snap([string]$Out, [string[]]$Roots = @()) {
    $a = 'snap'
    foreach ($x in @($Roots | Where-Object { $_ })) { $a += ' --root ' + (ConvertTo-EngineArg $x) }
    $r = Invoke-RigTool ($a + ' -o ' + (ConvertTo-EngineArg $Out))
    if ($r.exit -ne 0 -or -not (Test-Path -LiteralPath $Out)) { throw "rigtool snap failed (exit $($r.exit))" }
    $Out
}

# rigtool deep over scope files (purge.rig.targets/0 or an m2 manifest) into $Out.
function Invoke-M2Deep([string[]]$Scopes, [string]$Out) {
    $a = 'deep --scope ' + (@($Scopes | ForEach-Object { ConvertTo-EngineArg $_ }) -join ' ') + ' --sid ' + $RigUserSid + ' -o ' + (ConvertTo-EngineArg $Out)
    $r = Invoke-RigTool $a
    if ($r.exit -ne 0 -or -not (Test-Path -LiteralPath $Out)) { throw "rigtool deep failed (exit $($r.exit))" }
    $Out
}

# A rigtool verdict (execdiff / fidelity): exit 0 = ok, 1 = a failing verdict with its report written; anything
# else, or no report, throws. Returns {exit, ok, out}.
function Get-RigVerdict($R, [string]$Out, [string]$What) {
    if (-not (Test-Path -LiteralPath $Out)) { throw "rigtool $What wrote no $Out (exit $($R.exit))" }
    if ($R.exit -ne 0 -and $R.exit -ne 1) { throw "rigtool $What exited $($R.exit)" }
    [pscustomobject]@{ exit = $R.exit; ok = ($R.exit -eq 0); out = $Out }
}

function Invoke-M2Execdiff {
    param([string]$Before, [string]$After, [string]$Journal, [string]$Report, [string[]]$Traps = @(), [string[]]$Groups = @(),
          [string]$DeepBefore = '', [string]$DeepAfter = '', [Parameter(Mandatory)][string]$Out)
    $a = 'execdiff --before ' + (ConvertTo-EngineArg $Before) + ' --after ' + (ConvertTo-EngineArg $After) + ' --journal ' + (ConvertTo-EngineArg $Journal) + ' --report ' + (ConvertTo-EngineArg $Report)
    if ($Traps.Count) { $a += ' --traps ' + (@($Traps | ForEach-Object { ConvertTo-EngineArg $_ }) -join ' ') }
    if ($Groups.Count) { $a += ' --group ' + ($Groups -join ' ') }
    if ($DeepBefore -and $DeepAfter) { $a += ' --deep-before ' + (ConvertTo-EngineArg $DeepBefore) + ' --deep-after ' + (ConvertTo-EngineArg $DeepAfter) }
    # The M2 ambient set: record-level, exact or token-generalised, never a subtree (RIG.md §11.8).
    if (Test-Path -LiteralPath $RigM2Ambient -PathType Leaf) { $a += ' --ambient ' + (ConvertTo-EngineArg $RigM2Ambient) } else { Log "  !! no ${RigM2Ambient}: execdiff runs without an ambient set" }
    $a += ' --sid ' + $RigUserSid + ' -o ' + (ConvertTo-EngineArg $Out)
    Get-RigVerdict (Invoke-RigTool $a) $Out 'execdiff'
}

# -KeepItems: item ids the run left quarantined on purpose (not undone); rigtool reports them, never compares them.
function Invoke-M2Fidelity([string]$Before, [string]$After, [string]$Journal, [string]$Out, [string[]]$KeepItems = @()) {
    $a = 'fidelity --before ' + (ConvertTo-EngineArg $Before) + ' --after ' + (ConvertTo-EngineArg $After) + ' --journal ' + (ConvertTo-EngineArg $Journal) + ' --sid ' + $RigUserSid
    $keep = @($KeepItems | Where-Object { "$_" -ne '' })
    if ($keep.Count) { $a += ' --keep-items ' + (@($keep | ForEach-Object { ConvertTo-EngineArg "$_" }) -join ' ') }
    $a += ' -o ' + (ConvertTo-EngineArg $Out)
    Get-RigVerdict (Invoke-RigTool $a) $Out 'fidelity'
}

# Another script in a child Windows PowerShell (m2-traps.ps1, m2-fixtures.ps1, install.ps1), output logged.
function Invoke-M2Script([string]$Script, [string]$Arguments = '', [int]$TimeoutSec = 3600) {
    if (-not (Test-Path -LiteralPath $Script)) { throw "missing $Script" }
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $a = '-NoProfile -ExecutionPolicy Bypass -File ' + (ConvertTo-EngineArg $Script) + $(if ($Arguments) { ' ' + $Arguments } else { '' })
    Log "script: $(Split-Path -Leaf $Script) $Arguments"
    $r = Invoke-Native -Exe $exe -Arguments $a -TimeoutSec $TimeoutSec
    foreach ($l in @("$($r.stdout)" -split "`r?`n") + @("$($r.stderr)" -split "`r?`n")) { if ($l.Trim()) { Log "  | $l" } }
    Log "  $(Split-Path -Leaf $Script) exit=$($r.exit)"
    $r
}

# Snapshot roots of the objects an m2 manifest describes (its `roots`: paths and keys), plus the store, the
# Session Manager key (PATH, PendingFileRenameOperations) and the user's Environment key. For the crash loop and
# the race runs, where a full default snap per iteration would take too long.
# -BootStable (m2-crash power-off rounds, whose snap B is taken after a boot): the Session Manager key is replaced
# by its Environment subkey, since Windows rewrites Executive, kernel\RNG, Memory Management(\PrefetchParameters)
# and Power at every boot (gate run 2026-11-16: 12 to 20 collateral records per round, all boot churn); the
# round compares PendingFileRenameOperations itself instead (Get-PfroList before and after).
function Get-M2SnapRoots([string[]]$Manifests, [switch]$BootStable) {
    $set = New-Object System.Collections.ArrayList
    $add = { param($v) $s = "$v"; if ($s -match '^[A-Za-z]:\\' -or $s -match '^HK(LM|U)\\') { if (-not ($set -contains $s)) { [void]$set.Add($s) } } }
    foreach ($m in $Manifests) {
        if (-not (Test-Path -LiteralPath $m)) { continue }
        $d = [IO.File]::ReadAllText($m) | ConvertFrom-Json
        if ($d.roots) { foreach ($p in $d.roots.PSObject.Properties) { foreach ($v in @($p.Value)) { & $add $v } } }
    }
    $sm = $(if ($BootStable) { "$RigPfroKey\Environment" } else { $RigPfroKey })
    foreach ($x in @($RigPurgeData, $sm, "HKU\$RigUserSid\Environment")) { & $add $x }
    @($set)
}

# -------------------------------------------------------------------------- PendingFileRenameOperations (G4)

# The value as a string list ($null when absent): REG_MULTI_SZ pairs (source, destination); an empty destination
# is a delete.
function Get-PfroList {
    $v = Get-RegRaw $RigPfroKey 'PendingFileRenameOperations'
    if ($null -eq $v) { return $null }
    , @($v | ForEach-Object { "$_" })
}

# Writes PendingFileRenameOperations (REG_MULTI_SZ, 64-bit view); an empty list deletes the value. Entries must
# not be empty strings: .NET writes the list entry by entry, and an empty one would end it for the boot reader.
function Set-PfroList([string[]]$Entries) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $k = $base.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager', $true)
        try {
            if (@($Entries).Count) { $k.SetValue('PendingFileRenameOperations', [string[]]$Entries, [Microsoft.Win32.RegistryValueKind]::MultiString) }
            else { $k.DeleteValue('PendingFileRenameOperations', $false) }
        } finally { $k.Dispose() }
    } finally { $base.Dispose() }
}

# Writes a REG_SZ through the 64-bit view (an undo-conflict run's recreated value). Returns $true on success.
function Set-M2RegString([string]$Canon, [string]$Name, [string]$Data) {
    $k = ConvertTo-CanonKey $Canon
    $hiveName, $rest = $k -split '\\', 2
    $hive = $(if ($hiveName -eq 'HKLM') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::Users })
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $sub = $base.OpenSubKey($rest, $true)
        if (-not $sub) { return $false }
        try { $sub.SetValue($Name, $Data, [Microsoft.Win32.RegistryValueKind]::String); $true } finally { $sub.Dispose() }
    } catch { Log "  !! set $Canon|$Name : $($_.Exception.Message)"; $false } finally { $base.Dispose() }
}

# System Restore points as "<sequence> <description>" (G6).
function Get-M2RestorePoints { @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | ForEach-Object { "$($_.SequenceNumber) $($_.Description)" }) }

# G6 throttling leg: SystemRestorePointCreationFrequency (minutes, REG_DWORD) as the rig sets it for the test
# (m2-base carries 0 = no throttle; Windows' default when the value is absent is 1440). Returns the value read back.
function Set-M2RestoreFrequency([int]$Minutes) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $k = $base.CreateSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore')
        try { $k.SetValue('SystemRestorePointCreationFrequency', $Minutes, [Microsoft.Win32.RegistryValueKind]::DWord) } finally { $k.Dispose() }
    } finally { $base.Dispose() }
    Get-RegRaw $RigSrKey 'SystemRestorePointCreationFrequency'
}

# G6 "System Protection off" leg: protection on C: off ($false) or back on ($true). Returns $true when protection is
# on afterwards (RPSessionInterval / the volume's config are not readable portably; Get-ComputerRestorePoint is).
function Set-M2SystemProtection([bool]$On) {
    if ($On) { Enable-ComputerRestore -Drive 'C:\' -ErrorAction Stop } else { Disable-ComputerRestore -Drive 'C:\' -ErrorAction Stop }
    $v = Get-RegRaw $RigSrKey 'RPSessionInterval'
    Log "  system protection on C: $(if ($On) { 'enabled' } else { 'disabled' }) (RPSessionInterval $v)"
    $On
}

# Pure: a PFRO entry's path without the '*1' flag and the \??\ prefix.
function ConvertFrom-PfroPath([string]$Entry) { ("$Entry" -replace '^\*1', '') -replace '^\\\?\?\\', '' }

# Pure: compares two PFRO lists. Pre-existing pairs must be byte-identical and first; the added pairs must name
# only sources in $ExpectSrc, each once, and never a source in $ForbidSrc (paths compared case-insensitively).
function Compare-PfroLists($Before, $After, [string[]]$ExpectSrc = @(), [string[]]$ForbidSrc = @()) {
    $b = @($Before | Where-Object { $null -ne $_ }); $a = @($After | Where-Object { $null -ne $_ })
    $same = ($a.Count -ge $b.Count)
    for ($i = 0; $same -and $i -lt $b.Count; $i++) { if (-not [string]::Equals($a[$i], $b[$i], [StringComparison]::Ordinal)) { $same = $false } }
    $added = @(); $unexpected = @(); $forbidden = @(); $hits = @{}
    if ($same) {
        for ($i = $b.Count; $i -lt $a.Count; $i += 2) {
            $src = ConvertFrom-PfroPath $a[$i]; $dst = $(if ($i + 1 -lt $a.Count) { ConvertFrom-PfroPath $a[$i + 1] } else { $null })
            $added += [ordered]@{ src = $src; dst = $dst; raw_src = $a[$i] }
            $key = $src.ToLowerInvariant()
            if (@($ExpectSrc | Where-Object { $_ -ieq $src }).Count) { $hits[$key] = 1 + [int]$hits[$key] } else { $unexpected += $src }
            if (@($ForbidSrc | Where-Object { $_ -ieq $src }).Count) { $forbidden += $src }
        }
    }
    $missing = @($ExpectSrc | Where-Object { -not $hits.ContainsKey($_.ToLowerInvariant()) })
    $dupes = @($hits.Keys | Where-Object { $hits[$_] -gt 1 })
    [ordered]@{
        before_entries = $b.Count; after_entries = $a.Count; preexisting_identical = $same; added = $added
        expected_missing = $missing; unexpected = $unexpected; forbidden = $forbidden; duplicates = $dupes
        ok = ($same -and -not $missing.Count -and -not $unexpected.Count -and -not $forbidden.Count -and -not $dupes.Count)
    }
}

# Holds files open without FILE_SHARE_DELETE in a separate process (the m2-reboot locker) until Stop-M2Locker or
# the next reboot. Returns {pid, paths, ready, stop_file}.
function Start-M2Locker([string[]]$Paths, [string]$WorkDir, [int]$TimeoutSec = 60) {
    New-Item -ItemType Directory -Force $WorkDir | Out-Null
    $tag = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $script = Join-Path $WorkDir "locker-$tag.ps1"; $list = Join-Path $WorkDir "locker-$tag.txt"
    $ready = Join-Path $WorkDir "locker-$tag.ready"; $stop = Join-Path $WorkDir "locker-$tag.stop"
    [IO.File]::WriteAllLines($list, [string[]]@($Paths), $RigUtf8)
    $body = @'
param([string]$List, [string]$Ready, [string]$Stop)
$h = @()
foreach ($p in [IO.File]::ReadAllLines($List)) { if ($p) { $h += [IO.File]::Open('\\?\' + $p, 'Open', 'Read', 'Read, Write') } }
[IO.File]::WriteAllText($Ready, "locked $($h.Count)")
while (-not (Test-Path -LiteralPath $Stop)) { Start-Sleep -Milliseconds 500 }
foreach ($x in $h) { $x.Dispose() }
'@
    [IO.File]::WriteAllText($script, $body, $RigUtf8)
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    # Shell-executed, not Start-Native: a CreateProcess child inherits the job's redirected stdout, and the agent
    # (agent.ps1 '*>') then waits for the locker, which lives until the reboot, so <job>.done is never written.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ' + (ConvertTo-EngineArg $script) + ' -List ' + (ConvertTo-EngineArg $list) + ' -Ready ' + (ConvertTo-EngineArg $ready) + ' -Stop ' + (ConvertTo-EngineArg $stop)
    $psi.UseShellExecute = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $p = [System.Diagnostics.Process]::Start($psi)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while (-not (Test-Path -LiteralPath $ready) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
    $ok = (Test-Path -LiteralPath $ready)
    Log "locker pid $($p.Id): $(if ($ok) { [IO.File]::ReadAllText($ready) } else { 'NOT ready' }) ($($Paths -join ', '))"
    [pscustomobject]@{ pid = $p.Id; paths = @($Paths); ready = $ok; stop_file = $stop }
}

function Stop-M2Locker($Locker, [int]$WaitSec = 10) {
    if (-not $Locker) { return }
    [IO.File]::WriteAllText($Locker.stop_file, 'stop')
    $deadline = (Get-Date).AddSeconds($WaitSec)
    while ((Get-Process -Id $Locker.pid -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
    Stop-Process -Id $Locker.pid -Force -ErrorAction SilentlyContinue
    Log "locker $($Locker.pid) stopped"
}

# ------------------------------------------------------------------- run record and continuations (§11.2)

function Get-RigBootId {
    try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o') } catch { $null }
}

# The run record of an M2 run (run.json, schema purge.rig.m2/1). Stage 'start' begins a new run directory; a
# continuation stage (after a reboot or a host power-off) reopens it and appends.
function Open-M2Run([string]$Run, [string]$Mode, [string]$Stage) {
    if ($Stage -eq 'start') { $dir = New-RunDir $Run } else { $dir = Join-Path $RigOut $Run; New-Item -ItemType Directory -Force $dir | Out-Null }
    Set-RunLog (Join-Path $dir 'run.log')
    $f = Join-Path $dir 'run.json'
    $S = [ordered]@{
        schema = 'purge.rig.m2/1'; run = $Run; mode = $Mode; computer = $env:COMPUTERNAME; user_sid = $RigUserSid
        started = (NowIso); finished = $null; stages = (New-Object System.Collections.ArrayList); phases = (New-Object System.Collections.ArrayList)
        engine = [ordered]@{ exe = $null; calls = (New-Object System.Collections.ArrayList) }; results = [ordered]@{}
    }
    if ($Stage -ne 'start' -and (Test-Path -LiteralPath $f)) {
        $j = [IO.File]::ReadAllText($f) | ConvertFrom-Json
        $S.started = $j.started
        foreach ($x in @($j.stages)) { if ($x) { [void]$S.stages.Add($x) } }
        foreach ($x in @($j.phases)) { if ($x) { [void]$S.phases.Add($x) } }
        if ($j.engine) { $S.engine.exe = $j.engine.exe; foreach ($x in @($j.engine.calls)) { if ($x) { [void]$S.engine.calls.Add($x) } } }
        if ($j.results) { foreach ($p in $j.results.PSObject.Properties) { $S.results[$p.Name] = $p.Value } }
    }
    [void]$S.stages.Add([ordered]@{ stage = $Stage; start = (NowIso); boot = (Get-RigBootId) })
    Log "== M2 run $Run, mode $Mode, stage $Stage"
    [pscustomobject]@{ dir = $dir; file = $f; S = $S }
}

function Save-M2Run($R, [switch]$Finished) {
    if ($Finished) { $R.S.finished = NowIso }
    try { Write-JsonFile $R.S $R.file 12 } catch { Log "!! cannot write run.json: $($_.Exception.Message)" }
}

function Set-M2Result($R, [string]$Key, $Value) { $R.S.results[$Key] = $Value; Save-M2Run $R }

# Hard power-off rounds (m2-crash -HardPowerOff), right before the paused exec starts: makes the state the round
# built durable, so the power cut can only lose what the engine itself wrote afterwards. Flushes volume C: (every
# file and the NTFS log; Write-VolumeCache) and the registry hives the fixtures live in (RegFlushKey, P/Invoke:
# HKLM\SOFTWARE, HKLM\SYSTEM, HKU\<sid>, HKU\<sid>_Classes). Without it the gate run of 2026-11-16
# lost the fixture keys created seconds before the cut (HKLM\SOFTWARE\PurgeFixtureApp gone after the boot, HKU keys
# with older write times), and every power-off row failed on state the engine never touched. Elevated.
function Save-RigDurableState([string]$Sid = $RigUserSid) {
    $r = [ordered]@{ volume = $null; hives = [ordered]@{} }
    if (-not ('PurgeRig.RegFlush' -as [type])) {
        Add-Type -Namespace PurgeRig -Name RegFlush -MemberDefinition '[DllImport("advapi32.dll")] public static extern int RegFlushKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey);'
    }
    try { Write-VolumeCache -DriveLetter C -ErrorAction Stop; $r.volume = 'flushed' } catch { $r.volume = "failed: $($_.Exception.Message)" }
    $hives = @(@([Microsoft.Win32.Registry]::LocalMachine, 'SOFTWARE'), @([Microsoft.Win32.Registry]::LocalMachine, 'SYSTEM'),
        @([Microsoft.Win32.Registry]::Users, $Sid), @([Microsoft.Win32.Registry]::Users, "$Sid`_Classes"))
    foreach ($h in $hives) {
        $name = "$($h[0].Name)\$($h[1])"
        # RegFlushKey itself: .NET's RegistryKey.Flush() calls it only for a key this process wrote through that object.
        try { $k = $h[0].OpenSubKey($h[1], $false); if ($k) { try { $e = [PurgeRig.RegFlush]::RegFlushKey($k.Handle); $r.hives[$name] = $(if ($e -eq 0) { 'flushed' } else { "error $e" }) } finally { $k.Close() } } else { $r.hives[$name] = 'absent' } }
        catch { $r.hives[$name] = "failed: $($_.Exception.Message)" }
    }
    Log "durable state before the paused exec: volume $($r.volume); hives $(@($r.hives.Keys | ForEach-Object { "$_ $($r.hives[$_])" }) -join ', ')"
    $r
}

# Hard power-off rounds (m2-crash -HardPowerOff): the restored snapshot's boot entry ignores failed boots and has
# no automatic recovery, so back-to-back power cuts do not end in WinRE. Elevated; throws when bcdedit fails.
function Set-RigBootPolicyIgnoreFailures {
    $out = [ordered]@{}
    foreach ($a in @('/set {current} bootstatuspolicy IgnoreAllFailures', '/set {current} recoveryenabled No')) {
        $b = Invoke-Native -Exe (Join-Path $env:SystemRoot 'System32\bcdedit.exe') -Arguments $a -TimeoutSec 60
        Log "bcdedit $a`: exit $($b.exit)"
        $out[$a] = $b.exit
        if ($b.exit -ne 0) { throw "bcdedit $a exited $($b.exit)" }
    }
    $out
}

function Invoke-RigShutdown([int]$DelaySec, [string]$Reason) {
    $r = Invoke-Native -Exe (Join-Path $env:SystemRoot 'System32\shutdown.exe') -Arguments ('/r /t ' + $DelaySec + ' /d p:4:1 /c ' + (ConvertTo-EngineArg $Reason)) -TimeoutSec 60
    Log "shutdown /r in $DelaySec s: exit $($r.exit)"
}

# Ends this stage with a continuation marker C:\cr\out\<run>\continue.json (purge.rig.continue/1). kind 'reboot':
# the guest restarts itself $DelaySec seconds later (after the job has finished and the host has read the
# marker); kind 'poweroff': the host powers the VM off hard (VBoxManage controlvm poweroff) and boots it again.
# The host then waits for the agent and runs the same script with __STAGE__ = $Next.
function Request-RigContinuation([string]$Run, [string]$Kind, [string]$Next, $Data = $null, [int]$DelaySec = 45) {
    if (@('reboot', 'poweroff') -notcontains $Kind) { throw "bad continuation kind '$Kind'" }
    if ($Next -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad continuation stage '$Next'" }
    $dir = Join-Path $RigOut $Run
    $seq = @(Get-ChildItem -LiteralPath $dir -Filter 'continue-*.json' -File -ErrorAction SilentlyContinue).Count + 1
    $m = [ordered]@{ schema = 'purge.rig.continue/1'; run = $Run; seq = $seq; kind = $Kind; next = $Next; data = $Data; boot_before = (Get-RigBootId); written = (NowIso); delay_sec = $DelaySec }
    Write-JsonFile $m (Join-Path $dir 'continue.json') 8
    Log "continuation $seq requested: $Kind, then stage $Next"
    if ($Kind -eq 'reboot') { Invoke-RigShutdown $DelaySec "purge rig: continue $Run at $Next" }
    $m
}

# At the start of a continuation stage: the marker that led here (archived as continue-<seq>.json), or $null.
function Receive-RigContinuation([string]$Run) {
    $dir = Join-Path $RigOut $Run
    $f = Join-Path $dir 'continue.json'
    if (-not (Test-Path -LiteralPath $f)) { return $null }
    $m = [IO.File]::ReadAllText($f) | ConvertFrom-Json
    Move-Item -LiteralPath $f -Destination (Join-Path $dir ("continue-{0}.json" -f $m.seq)) -Force
    $m | Add-Member -NotePropertyName boot_after -NotePropertyValue (Get-RigBootId) -Force
    $m
}

# Pure: the options a host passes as __OPTS__ (base64 of UTF-8 JSON); empty or the placeholder -> {}.
function ConvertFrom-M2Opts([string]$B64) {
    if (-not $B64 -or $B64 -eq ('__' + 'OPTS__')) { return [pscustomobject]@{} }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($B64)) | ConvertFrom-Json
}

# Option value with a default (opts come from ConvertFrom-M2Opts).
function Get-M2Opt($Opts, [string]$Name, $Default) {
    if ($Opts -and $Opts.PSObject.Properties[$Name] -and $null -ne $Opts.$Name) { return $Opts.$Name }
    $Default
}
