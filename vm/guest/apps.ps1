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
# Optional (x0 variants, vm\RIG.md §4b; environment variables in 'install' are expanded in the guest):
#   pre_launch    $true: every pre-app is launched once (as the main app's launch) after its install, so its
#                 profile and first-run registrations exist in snap 0
#   pre_uninstall $true: every pre-app is then removed with its vendor uninstaller (reinstall-after-uninstall)
#   plant_pre     name of a function in x0-plants.ps1 run after the pre-apps, before lists 0 / snap 0
#   plant_post    name of a function in x0-plants.ps1 run after the launch (and the post-apps), before lists 1
#   post          ids of apps installed and launched after the main app's launch, before lists 1 (a sibling
#                 installed after the app)
#   upgrade_from  id of an app installed first in the install phase (after snap 0), then the main installer runs
#                 over it (an in-place upgrade)
#   plant_files   files of the host installer cache (vm\cache\inst) a plant function needs, pushed with the run
# Installer files: when vm\cache\inst holds the app's 'file' (listed in vm\cache\inst\cache-sources.json with its
# URL and SHA-256), rig.ps1 pushes it to C:\cr\inst before the run and the guest uses it after checking the hash;
# otherwise the guest downloads from 'url' (rig-base already holds the M0 installers).

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

  # The installer must not be named vlc.exe: VLC's installer ends running vlc.exe processes before it copies its
  # files, so under that name it ends itself (exit 0 after a few seconds, empty VideoLAN\VLC, no ARP entry). The
  # official file name is used; it is in the host cache (rig-base's C:\cr\inst\vlc.exe is the same file, unused).
  @{ id = 'vlc'; tech = 'NSIS'; file = 'vlc-3.0.21-win64.exe'
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

  # ---- x0 records (vm\RIG.md §4b). Pinned official URLs; the files are in the host cache vm\cache\inst with
  # their SHA-256 in cache-sources.json (downloaded 2026-11-13). Fallbacks are the vendors' own "latest" links.
  @{ id = 'firefox-dev'; tech = 'NSIS (Mozilla)'; file = 'firefox-dev.exe'
     url = { 'https://ftp.mozilla.org/pub/devedition/releases/161.0b2/win64/en-US/Firefox%20Setup%20161.0b2.exe',
             'https://download.mozilla.org/?product=firefox-devedition-latest-ssl&os=win64&lang=en-US' }
     install = '/S'; match = '^Firefox Developer Edition'; un = '{U} /S'
     launch = @{ exe = 'firefox.exe'; args = ''; dirs = @('%ProgramFiles%\Firefox Developer Edition') } }

  # ESR's default folder is the release's own 'Mozilla Firefox': /InstallDirectoryPath (Mozilla's documented full
  # installer option) puts it next to it. Its ARP name 'Mozilla Firefox ESR ...' also matches firefox's '^Mozilla
  # Firefox', which is harmless as a pre-app: Find-MainEntry prefers entries created by the main install.
  @{ id = 'firefox-esr'; tech = 'NSIS (Mozilla)'; file = 'firefox-esr.exe'
     url = { 'https://ftp.mozilla.org/pub/firefox/releases/153.7.0esr/win64/en-US/Firefox%20Setup%20153.7.0esr.exe',
             'https://download.mozilla.org/?product=firefox-esr-latest-ssl&os=win64&lang=en-US' }
     install = '/S /InstallDirectoryPath="C:\Program Files\Mozilla Firefox ESR"'; match = '^Mozilla Firefox ESR'; un = '{U} /S'
     launch = @{ exe = 'firefox.exe'; args = ''; dirs = @('%ProgramFiles%\Mozilla Firefox ESR') } }

  @{ id = 'vscode-insiders'; tech = 'Inno Setup'; file = 'vscode-insiders.exe'
     url = { 'https://vscode.download.prss.microsoft.com/dbazure/download/insider/54ab79431a5858c9546c7161e5afe5fd9e8570d6/VSCodeSetup-x64-1.147.0-insider.exe',
             'https://update.code.visualstudio.com/latest/win32-x64/insider' }
     install = '/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /MERGETASKS=!runcode'; match = '^Microsoft Visual Studio Code Insiders'
     un = '{U} /VERYSILENT /NORESTART /SUPPRESSMSGBOXES'
     launch = @{ exe = 'Code - Insiders.exe'; args = ''; dirs = @('%ProgramFiles%\Microsoft VS Code Insiders') } }

  @{ id = 'vscode-1145'; tech = 'Inno Setup'; file = 'vscode-1145.exe'
     url = { 'https://update.code.visualstudio.com/1.145.0/win32-x64/stable' }
     install = '/VERYSILENT /NORESTART /MERGETASKS=!runcode'; match = '^Microsoft Visual Studio Code'
     un = '{U} /VERYSILENT /NORESTART /SUPPRESSMSGBOXES'
     launch = @{ exe = 'Code.exe'; args = ''; dirs = @('%ProgramFiles%\Microsoft VS Code') } }

  # tortoisegit.org/download lists "stable 2.19.0" and links 2.19.1.0 under /tgit/2.19.0.0/ (re-checked 2026-11-13);
  # the MSI is Authenticode-signed (Open Source Developer, Sven Strickroth).
  @{ id = 'tortoisegit'; tech = 'MSI'; file = 'tortoisegit.msi'
     url = { 'https://download.tortoisegit.org/tgit/2.19.0.0/TortoiseGit-2.19.1.0-64bit.msi' }
     install = 'msi'; match = '^TortoiseGit'; un = 'msi'; launch = $null }

  @{ id = 'winmerge'; tech = 'Inno Setup'; file = 'winmerge.exe'
     url = { 'https://github.com/WinMerge/winmerge/releases/download/v2.16.60/WinMerge-2.16.60-x64-Setup.exe' }
     install = '/VERYSILENT /NORESTART /SP- /SUPPRESSMSGBOXES'; match = '^WinMerge'
     un = '{U} /VERYSILENT /NORESTART /SUPPRESSMSGBOXES'
     launch = @{ exe = 'WinMergeU.exe'; args = ''; dirs = @('%ProgramFiles%\WinMerge') } }

  @{ id = 'git-2560'; tech = 'Inno Setup'; file = 'git-2560.exe'
     url = { 'https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.1/Git-2.56.0-64-bit.exe' }
     install = '/VERYSILENT /NORESTART'; match = '^Git$|^Git version'
     un = '{U} /VERYSILENT /NORESTART /SUPPRESSMSGBOXES'
     launch = @{ exe = 'git-bash.exe'; args = ''; dirs = @('%ProgramFiles%\Git') } }
)

function Get-BaseApp([string]$Id) { $Apps | Where-Object { $_.id -eq $Id } | Select-Object -First 1 }

# firefox-tb (ENGINE_PLAN §10.4 #2): the firefox run with Thunderbird installed before snap 0, so the shared
# Mozilla parts (Maintenance Service, vendor keys and dirs) are pre-existing and offering them is danger.
$Apps += (Copy-AppDef (Get-BaseApp 'firefox') @{ id = 'firefox-tb'; pre = @('thunderbird') })

# x0 variants (vm\RIG.md §4b, design in the M1a x0 spec). The label file of each is vm\truth\labels\<id>.json.
$Apps += @(
    # 1: user files written into the install root while installed; a portable copy's Open-with registration,
    #    OpenWithList entry, desktop shortcut and Run value (all before snap 0).
    (Copy-AppDef (Get-BaseApp 'npp') @{ id = 'npp-userfiles'; plant_pre = 'Plant-NppPortable'; plant_post = 'Plant-NppUserFiles'
                                        plant_files = @('npp-portable.zip') })
    # 2: Git installed into the user's existing, non-empty tools folder.
    (Copy-AppDef (Get-BaseApp 'git') @{ id = 'git-toolsdir'; plant_pre = 'Plant-GitToolsDir'; plant_files = @('ripgrep.zip')
                                        install = '/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /DIR="%USERPROFILE%\Tools"'
                                        launch = @{ exe = 'git-bash.exe'; args = ''; dirs = @('%USERPROFILE%\Tools') } })
    # 3: Firefox Developer Edition installed and launched before snap 0.
    (Copy-AppDef (Get-BaseApp 'firefox') @{ id = 'ff-devedition'; pre = @('firefox-dev'); pre_launch = $true })
    # 4: the per-user VS Code installed and launched before snap 0, then the system build.
    (Copy-AppDef (Get-BaseApp 'vscode') @{ id = 'vscode-with-user'; pre = @('vscode-user'); pre_launch = $true
                                           plant_pre = 'Plant-VscodeTxtOpenWith'
                                           install = '/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /MERGETASKS=!runcode' })
    # 5: TortoiseGit and the user's own Git references (config values, PATH, Run, Start menu shortcut, .sh key).
    (Copy-AppDef (Get-BaseApp 'git') @{ id = 'git-userstate'; pre = @('vcredist', 'tortoisegit'); plant_pre = 'Plant-GitUserState' })
    # 10: Thunderbird installed and launched AFTER Firefox's launch (footprint reference: the solo 'thunderbird' run).
    (Copy-AppDef (Get-BaseApp 'firefox') @{ id = 'ff-tbafter'; post = @('thunderbird') })
    # 11: pre-existing .ext keys, prior VS Code user data, an Open-with registration of a zip copy; a user file in
    #     the install root.
    (Copy-AppDef (Get-BaseApp 'vscode') @{ id = 'vscode-userstate'; plant_pre = 'Plant-VscodeUserState'; plant_post = 'Plant-VscodeWorkspace' })
    # 13: VS Code Insiders installed and launched before snap 0.
    (Copy-AppDef (Get-BaseApp 'vscode') @{ id = 'vscode-insiders-pair'; pre = @('vscode-insiders'); pre_launch = $true })
    # 15: 1.145.0 installed first, the current build over it (both after snap 0).
    (Copy-AppDef (Get-BaseApp 'vscode') @{ id = 'vscode-upgrade'; upgrade_from = 'vscode-1145' })
    # 16: Firefox ESR in its own folder, installed and launched before snap 0. The release build gets its own
    #     explicit folder: a plain /S reuses the install directory Mozilla's installer finds in the registry (ESR's),
    #     which replaced ESR's install and ARP entry in the first x0-ff-esr run.
    (Copy-AppDef (Get-BaseApp 'firefox') @{ id = 'ff-esr'; pre = @('firefox-esr'); pre_launch = $true
                                           install = '/S /InstallDirectoryPath="C:\Program Files\Mozilla Firefox"' })
    # 17: an unregistered zip copy of VS Code launched before snap 0, then the per-user build.
    (Copy-AppDef (Get-BaseApp 'vscode-user') @{ id = 'vscode-zipcopy'; plant_pre = 'Plant-VscodeZipCopy'; plant_files = @('vscode-archive.zip') })
    # 18: Firefox installed, launched and removed with its own uninstaller before snap 0, then installed again.
    (Copy-AppDef (Get-BaseApp 'firefox') @{ id = 'ff-reinstall'; pre = @('firefox'); pre_launch = $true; pre_uninstall = $true })
    # 20: Git 2.56.0 first, then 2.56.1 over it.
    (Copy-AppDef (Get-BaseApp 'git') @{ id = 'git-upgrade'; upgrade_from = 'git-2560' })
)

# Pure: every installer or plant file a run of $Id needs (the app, its pre/post apps, upgrade_from, plant_files).
function Get-AppFiles([string]$Id) {
    $a = Get-App $Id
    $files = New-Object System.Collections.Generic.List[string]
    $files.Add($a.file)
    foreach ($x in @(@($a.pre) + @($a.post) + @($a.upgrade_from) | Where-Object { $_ })) { $files.Add((Get-App $x).file) }
    foreach ($f in @($a.plant_files | Where-Object { $_ })) { $files.Add($f) }
    @($files | Select-Object -Unique)
}

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
