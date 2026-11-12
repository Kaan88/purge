# Purge rig v2: the test apps (dot-sourced after riglib.ps1). Official vendor URLs only; each app covers a
# different installer technology. Ids, URLs, silent install arguments and 'match' are unchanged from v1.
#
#   id      truth label file (vm\truth\labels\<id>.json) and default run name (rig.ps1 -RunPrefix adds a prefix)
#   file    installer file name in C:\cr\inst\
#   url     scriptblock returning one URL or several candidates (tried in order)
#   install silent install arguments; 'msi' = msiexec /i <file> /qn /norestart
#   match   regex on the DisplayName of the main ARP entry the install creates
#   un      vendor uninstall, quiet:
#             'msi'      -> msiexec /x {ProductCode} /qn /norestart (product code of the main entry)
#             '{U} ...'  -> UninstallString + extra arguments
#             '{Q}'      -> QuietUninstallString (Burn bundles); falls back to '{U} /quiet /norestart'
#   launch  $null, or @{ exe; args; dirs; regdir }: the main program started once at medium integrity
#           after install. The exe is looked up in the main entry's InstallLocation, then next to its
#           DisplayIcon, then under regdir's default value, then in dirs (environment variables expanded),
#           then App Paths.
# Optional (M1a, vm\RIG.md §4):
#   pre        ids of other apps installed (and settled) before lists 0 / snap 0, so everything of theirs is
#              in the clean state and anything of theirs a cleaner offers scores as danger
#   install_il 'medium': the installer runs at medium integrity through the one-shot task PurgeRigInstall
#              (LaunchMedium pattern), as a per-user install by a normal user would; default: the elevated
#              agent token

# Pure: a shallow copy of an app definition with some fields replaced (a corpus variant of another app).
function Copy-AppDef($App, [hashtable]$Changes) {
    if (-not $App) { throw 'Copy-AppDef: no base app definition' }
    $c = @{}
    foreach ($k in $App.Keys) { $c[$k] = $App[$k] }
    foreach ($k in $Changes.Keys) { $c[$k] = $Changes[$k] }
    $c
}

$Apps = @(
  @{ id = 'npp'; tech = 'NSIS'; file = 'npp.exe'
     url = { GitHubAsset 'notepad-plus-plus/notepad-plus-plus' 'Installer\.x64\.exe$' }
     install = '/S'; match = '^Notepad\+\+'; un = '{U} /S'
     launch = @{ exe = 'notepad++.exe'; args = ''; dirs = @('%ProgramFiles%\Notepad++') } }

  @{ id = '7zip'; tech = 'MSI'; file = '7zip.msi'
     url = { 'https://www.7-zip.org/a/7z2408-x64.msi' }
     install = 'msi'; match = '^7-Zip'; un = 'msi'
     launch = @{ exe = '7zFM.exe'; args = ''; dirs = @('%ProgramFiles%\7-Zip') } }

  @{ id = 'vscode'; tech = 'Inno Setup'; file = 'vscode.exe'
     url = { 'https://update.code.visualstudio.com/latest/win32-x64/stable' }
     install = '/VERYSILENT /NORESTART /MERGETASKS=!runcode'; match = '^Microsoft Visual Studio Code'
     un = '{U} /VERYSILENT /NORESTART /SUPPRESSMSGBOXES'
     launch = @{ exe = 'Code.exe'; args = ''; dirs = @('%ProgramFiles%\Microsoft VS Code') } }

  @{ id = 'git'; tech = 'Inno Setup'; file = 'git.exe'
     url = { GitHubAsset 'git-for-windows/git' '^Git-[\d.]+-64-bit\.exe$' }
     install = '/VERYSILENT /NORESTART'; match = '^Git$|^Git version'
     un = '{U} /VERYSILENT /NORESTART /SUPPRESSMSGBOXES'
     launch = @{ exe = 'git-bash.exe'; args = ''; dirs = @('%ProgramFiles%\Git') } }

  @{ id = 'vlc'; tech = 'NSIS'; file = 'vlc.exe'
     url = { 'https://download.videolan.org/pub/videolan/vlc/3.0.21/win64/vlc-3.0.21-win64.exe',
             'https://get.videolan.org/vlc/3.0.21/win64/vlc-3.0.21-win64.exe' }
     install = '/S /L=1033'; match = '^VLC media player'; un = '{U} /S'
     launch = @{ exe = 'vlc.exe'; args = ''; dirs = @('%ProgramFiles%\VideoLAN\VLC') } }

  @{ id = 'python'; tech = 'WiX Burn bundle'; file = 'python.exe'
     url = { 'https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe' }
     install = '/quiet InstallAllUsers=1 PrependPath=1 Include_test=0'; match = '^Python 3\.12\.7 \(64-bit\)$'; un = '{Q}'
     # IDLE: pythonw.exe -m idlelib. The bundle's ARP entry points into Package Cache, so the install
     # directory comes from PythonCore\3.12\InstallPath.
     launch = @{ exe = 'pythonw.exe'; args = '-m idlelib'; regdir = 'HKLM\SOFTWARE\Python\PythonCore\3.12\InstallPath'
                 dirs = @('%ProgramFiles%\Python312') } }

  @{ id = 'node'; tech = 'MSI (WiX)'; file = 'node.msi'
     url = { 'https://nodejs.org/dist/v20.18.0/node-v20.18.0-x64.msi' }
     install = 'msi'; match = '^Node\.js'; un = 'msi'; launch = $null }

  @{ id = 'vcredist'; tech = 'WiX Burn bundle'; file = 'vc_redist.exe'
     url = { 'https://aka.ms/vs/17/release/vc_redist.x64.exe' }
     install = '/install /quiet /norestart'; match = '^Microsoft Visual C\+\+ 2015-20\d\d Redistributable \(x64\)'; un = '{Q}'
     launch = $null }

  @{ id = 'firefox'; tech = 'NSIS (Mozilla)'; file = 'firefox.exe'
     url = { 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US' }
     install = '/S'; match = '^Mozilla Firefox'; un = '{U} /S'
     launch = @{ exe = 'firefox.exe'; args = ''; dirs = @('%ProgramFiles%\Mozilla Firefox') } }

  @{ id = 'vs'; tech = 'Visual Studio Installer'; file = 'vs_community.exe'
     url = { 'https://aka.ms/vs/17/release/vs_community.exe' }
     install = '--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.CoreEditor --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
     match = '^Visual Studio Community 2022'; un = '{U} --quiet --norestart --wait'; launch = $null }

  # VS Code per-user build (ENGINE_PLAN §10.4 #7): %LOCALAPPDATA%\Programs, HKU Classes. Installed at
  # medium integrity: the guest user is an admin and the agent is elevated.
  @{ id = 'vscode-user'; tech = 'Inno Setup (per-user)'; file = 'vscode-user.exe'
     url = { 'https://update.code.visualstudio.com/latest/win32-x64-user/stable' }
     install = '/VERYSILENT /NORESTART /MERGETASKS=!runcode'; install_il = 'medium'
     match = '^Microsoft Visual Studio Code \(User\)'
     un = '{U} /VERYSILENT /NORESTART /SUPPRESSMSGBOXES'
     launch = @{ exe = 'Code.exe'; args = ''; dirs = @('%LOCALAPPDATA%\Programs\Microsoft VS Code') } }

  @{ id = 'thunderbird'; tech = 'NSIS (Mozilla)'; file = 'thunderbird.exe'
     url = { 'https://download.mozilla.org/?product=thunderbird-latest-ssl&os=win64&lang=en-US' }
     install = '/S'; match = '^Mozilla Thunderbird'; un = '{U} /S'
     launch = @{ exe = 'thunderbird.exe'; args = ''; dirs = @('%ProgramFiles%\Mozilla Thunderbird') } }
)

# firefox-tb (ENGINE_PLAN §10.4 #2): the firefox run with Thunderbird installed before snap 0, so the shared
# Mozilla parts (Maintenance Service, vendor keys and dirs) are pre-existing and offering them is danger.
$Apps += (Copy-AppDef ($Apps | Where-Object { $_.id -eq 'firefox' } | Select-Object -First 1) @{ id = 'firefox-tb'; pre = @('thunderbird') })

function Get-App([string]$Id) {
    $a = $Apps | Where-Object { $_.id -eq $Id } | Select-Object -First 1
    if (-not $a) { throw "unknown app id '$Id' (known: $(($Apps | ForEach-Object { $_.id }) -join ', '))" }
    $a
}

# Main ARP entry: a new entry (key absent before install) whose name matches and is not a system
# component; else any new matching entry; else any matching entry.
function Find-MainEntry($App, $Before, $After) {
    $old = @{}
    foreach ($e in @($Before)) { if ($e) { $old[$e.key] = $true } }
    $new = @(@($After) | Where-Object { $_ -and -not $old.ContainsKey($_.key) })
    $m = $new | Where-Object { "$($_.name)" -match $App.match -and -not $_.sys } | Select-Object -First 1
    if (-not $m) { $m = $new | Where-Object { "$($_.name)" -match $App.match } | Select-Object -First 1 }
    if (-not $m) { $m = @($After) | Where-Object { "$($_.name)" -match $App.match } | Select-Object -First 1 }
    $m
}

# Pure: the quiet vendor uninstall command for the main entry -> {exe, args, display}.
function Build-UninstallCommand($App, $Main, [string]$MsiLog = '') {
    if ($App.un -eq 'msi') {
        if (-not $Main.msi) { throw "app '$($App.id)' uninstalls through msiexec but entry '$($Main.key)' has no product code" }
        $a = "/x $($Main.msi) /qn /norestart"
        if ($MsiLog) { $a += ' /L*v "' + $MsiLog + '"' }
        $exe = Join-Path $env:SystemRoot 'System32\msiexec.exe'
        return [pscustomobject]@{ exe = $exe; args = $a; display = "`"$exe`" $a" }
    }
    $tpl = $App.un
    if ($tpl -match '\{Q\}' -and -not "$($Main.quiet)".Trim()) {
        if (-not "$($Main.uninstall)".Trim()) { throw "entry '$($Main.key)' has neither QuietUninstallString nor UninstallString" }
        $tpl = $tpl.Replace('{Q}', '{U} /quiet /norestart')
    }
    if ($tpl -match '\{U\}' -and -not "$($Main.uninstall)".Trim()) { throw "entry '$($Main.key)' has no UninstallString" }
    $line = $tpl.Replace('{U}', "$($Main.uninstall)".Trim()).Replace('{Q}', "$($Main.quiet)".Trim())
    $sc = Split-CommandLine $line
    [pscustomobject]@{ exe = $sc.exe; args = $sc.args; display = $line }
}

# The launch exe for an installed app, or $null (see 'launch' above).
function Resolve-LaunchExe($App, $Main) {
    $L = $App.launch
    if (-not $L) { return $null }
    $cands = New-Object System.Collections.Generic.List[string]
    $add = { param($dir) if ("$dir".Trim()) { try { $cands.Add((Join-Path ("$dir".Trim().Trim('"')) $L.exe)) } catch { } } }
    if ($Main) {
        & $add $Main.loc
        if ($Main.icon) {
            $icon = ("$($Main.icon)" -replace ',\s*-?\d+\s*$', '').Trim().Trim('"')
            if ($icon) { try { & $add (Split-Path -Parent $icon) } catch { } }
        }
    }
    if ($L.regdir) {
        $k = Open-RegKey $L.regdir
        if ($k) { try { & $add $k.GetValue('') } finally { $k.Dispose() } }
    }
    foreach ($d in @($L.dirs)) { if ($d) { & $add ([Environment]::ExpandEnvironmentVariables($d)) } }
    $ap = Open-RegKey "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$($L.exe)"
    if ($ap) { try { $v = "$($ap.GetValue(''))".Trim().Trim('"'); if ($v) { $cands.Add($v) } } finally { $ap.Dispose() } }
    foreach ($c in $cands) { if (Test-Path -LiteralPath $c -PathType Leaf) { return $c } }
    $null
}
