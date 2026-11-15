# Purge rig v2: plant functions of the x0 variants (vm\RIG.md §4b; apps.ps1 'plant_pre' / 'plant_post'). Dot-sourced
# by run-app.ps1 after riglib.ps1 and apps.ps1. Each Plant-* function takes the plant context
#   $Ctx = { Phase ('plant-pre' | 'plant-post'), S (the run record; planted items go to S.planted), App, Main, Dir }
# and writes what a real user (or another product) would have on the machine: files, registry keys and values,
# shortcuts, PATH segments. Every write is recorded in run.json `planted[]` as {phase, kind, target, note}.
# The job runs elevated as the interactive user, so HKCU is that user's hive (written through HKU\<sid>).
# Zips come from the host installer cache (C:\cr\inst, pushed by rig.ps1, SHA-256 checked against
# cache-sources.json) or, failing that, from the official URL in that manifest.

$X0User = [Environment]::GetFolderPath('UserProfile')

function Add-Planted($Ctx, [string]$Kind, [string]$Target, [string]$Note = '') {
    [void]$Ctx.S.planted.Add([ordered]@{ phase = $Ctx.Phase; kind = $Kind; target = $Target; note = $Note })
    Log ("  planted ({0}) {1} {2}{3}" -f $Ctx.Phase, $Kind, $Target, $(if ($Note) { " [$Note]" } else { '' }))
}

# A canonical key (HKLM\..., HKCU\..., HKU\...) opened writable in the 64-bit view, created when missing.
function Open-RegKeyWrite([string]$Canon) {
    $k = ConvertTo-CanonKey $Canon
    $hiveName, $rest = $k -split '\\', 2
    $hive = switch ($hiveName) {
        'HKLM' { [Microsoft.Win32.RegistryHive]::LocalMachine }
        'HKU'  { [Microsoft.Win32.RegistryHive]::Users }
        default { throw "unsupported hive in '$Canon'" }
    }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
    try { $base.CreateSubKey($rest) } finally { $base.Dispose() }
}

function Plant-RegKey($Ctx, [string]$Key) {
    $existed = Test-RegKey $Key
    $k = Open-RegKeyWrite $Key; $k.Dispose()
    Add-Planted $Ctx 'key' ('K:' + (ConvertTo-CanonKey $Key)) $(if ($existed) { 'existed already' } else { '' })
}

function Plant-RegValue($Ctx, [string]$Key, [string]$Name, $Value, [Microsoft.Win32.RegistryValueKind]$Kind = [Microsoft.Win32.RegistryValueKind]::String) {
    $k = Open-RegKeyWrite $Key
    try {
        $before = $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $k.SetValue($Name, $Value, $Kind)
    } finally { $k.Dispose() }
    $shown = if ($Value -is [byte[]]) { "($($Value.Length) bytes)" } else { "$Value" }
    Add-Planted $Ctx 'value' ('V:' + (ConvertTo-CanonKey $Key) + '|' + $Name) ($shown + $(if ($null -ne $before) { " (was: $before)" } else { '' }))
}

function Plant-File($Ctx, [string]$Path, [string]$Text) {
    $d = Split-Path -Parent $Path
    if ($d) { New-Item -ItemType Directory -Force $d | Out-Null }
    [IO.File]::WriteAllText($Path, $Text, $RigUtf8)
    Add-Planted $Ctx 'file' ('P:' + $Path)
}

function Plant-Dir($Ctx, [string]$Path) {
    New-Item -ItemType Directory -Force $Path | Out-Null
    Add-Planted $Ctx 'dir' ('P:' + $Path)
}

function Plant-Shortcut($Ctx, [string]$Lnk, [string]$Target, [string]$Arguments = '', [string]$WorkDir = '') {
    $d = Split-Path -Parent $Lnk
    New-Item -ItemType Directory -Force $d | Out-Null
    $sh = New-Object -ComObject WScript.Shell
    try {
        $s = $sh.CreateShortcut($Lnk)
        $s.TargetPath = $Target
        if ($Arguments) { $s.Arguments = $Arguments }
        if ($WorkDir) { $s.WorkingDirectory = $WorkDir }
        $s.Save()
    } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($sh) }
    Add-Planted $Ctx 'shortcut' ('P:' + $Lnk) ("-> $Target $Arguments".Trim())
}

# Appends a segment to the user PATH, keeping the value's registry type (REG_EXPAND_SZ on clean Windows).
function Add-UserPathSegment($Ctx, [string]$Segment) {
    $key = "HKU\$RigUserSid\Environment"
    $k = Open-RegKeyWrite $key
    try {
        $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
        $old = ''
        if ($k.GetValueNames() -contains 'Path') {
            $kind = $k.GetValueKind('Path')
            $old = "$($k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))"
        }
        $new = $old.TrimEnd(';')
        $new = $(if ($new) { "$new;$Segment" } else { $Segment })
        $k.SetValue('Path', $new, $kind)
    } finally { $k.Dispose() }
    Add-Planted $Ctx 'path-segment' ("S:$key|Path|$Segment")
}

# Adds $Exe to HKCU ...\Explorer\FileExts\<ext>\OpenWithList under the next free letter and puts it first in
# MRUList, as Explorer's "Open with" does (an existing entry for the exe is left as it is).
function Add-OpenWithList($Ctx, [string]$Ext, [string]$Exe) {
    $key = "HKU\$RigUserSid\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Ext\OpenWithList"
    $k = Open-RegKeyWrite $key
    try {
        $names = @($k.GetValueNames())
        foreach ($n in $names) { if ($n -ne 'MRUList' -and "$($k.GetValue($n))" -ieq $Exe) { Add-Planted $Ctx 'value' "V:$key|$n" "$Exe (existed already)"; return } }
        $letter = $null
        foreach ($c in [char[]]'abcdefghijklmnopqrstuvwxyz') { if ($names -notcontains [string]$c) { $letter = [string]$c; break } }
        if (-not $letter) { throw "OpenWithList of $Ext is full" }
        $mru = "$($k.GetValue('MRUList'))"
        $k.SetValue($letter, $Exe, [Microsoft.Win32.RegistryValueKind]::String)
        $k.SetValue('MRUList', $letter + $mru, [Microsoft.Win32.RegistryValueKind]::String)
    } finally { $k.Dispose() }
    Add-Planted $Ctx 'value' "V:$key|$letter" $Exe
    Add-Planted $Ctx 'value' "V:$key|MRUList" "$letter first"
}

# A plant file (zip) from C:\cr\inst (host cache, hash checked) or its official URL; returns the local path.
function Get-PlantFile($Ctx, [string]$File) {
    $man = @{}
    $mf = Join-Path $RigInst 'cache-sources.json'
    if (Test-Path -LiteralPath $mf) {
        $j = [IO.File]::ReadAllText($mf) | ConvertFrom-Json
        foreach ($p in @($j.PSObject.Properties)) { $man[$p.Name] = $p.Value }
    }
    $m = $man[$File]
    if (-not $m) { throw "plant file $File is not in cache-sources.json" }
    $dst = Join-Path $RigInst $File
    $src = 'host cache'
    if (Test-Path -LiteralPath $dst) {
        $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $dst).Hash
        if ($h -ne "$($m.sha256)".ToUpperInvariant()) { Log "  !! $dst sha256 $h != manifest $($m.sha256): downloading again"; Remove-Item -LiteralPath $dst -Force }
    }
    if (-not (Test-Path -LiteralPath $dst)) {
        $src = $m.url
        Invoke-WebRequest -Uri $m.url -OutFile $dst -UseBasicParsing -MaximumRedirection 10 -ErrorAction Stop -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) rig-download'
    }
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $dst).Hash
    if ($h -ne "$($m.sha256)".ToUpperInvariant()) { throw "plant file $File sha256 $h does not match the manifest ($($m.sha256))" }
    if (-not $Ctx.S.plant_files) { $Ctx.S.plant_files = New-Object System.Collections.ArrayList }
    [void]$Ctx.S.plant_files.Add([ordered]@{ file = $File; url = $m.url; version = $m.version; sha256 = $h; source = $src })
    Log "  plant file $File $($m.version) sha256=$h ($src)"
    $dst
}

# Unpacks a zip into $Dest. -Strip: a top-level folder of the archive whose content goes to $Dest directly.
function Expand-PlantZip($Ctx, [string]$File, [string]$Dest, [string]$Strip = '') {
    $zip = Get-PlantFile $Ctx $File
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if ($Strip) {
        $tmp = Join-Path $RigRoot ('unzip-' + [guid]::NewGuid().ToString('N'))
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $tmp)
        New-Item -ItemType Directory -Force (Split-Path -Parent $Dest) | Out-Null
        Move-Item -LiteralPath (Join-Path $tmp $Strip) -Destination $Dest
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        New-Item -ItemType Directory -Force $Dest | Out-Null
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $Dest)
    }
    $n = @(Get-ChildItem -LiteralPath $Dest -Recurse -File).Count
    Add-Planted $Ctx 'dir' ('P:' + $Dest) "$File unpacked, $n files"
}

# The main app's install folder (plant_post): the folder of its launch exe, else InstallLocation.
function Get-PlantInstallDir($Ctx) {
    $exe = $null
    try { $exe = Resolve-LaunchExe $Ctx.App $Ctx.Main } catch { }
    if ($exe) { return (Split-Path -Parent $exe) }
    if ($Ctx.Main -and "$($Ctx.Main.loc)".Trim()) { return "$($Ctx.Main.loc)".Trim().Trim('"').TrimEnd('\') }
    throw 'cannot find the install folder for the plant'
}

$X0Run = "HKU\$RigUserSid\Software\Microsoft\Windows\CurrentVersion\Run"
$X0Desktop = [Environment]::GetFolderPath('Desktop')

# ------------------------------------------------------------------------------- x0-npp-userfiles (rank 1)
# Before snap 0: the official portable build in the user's tools folder, registered the way Explorer's
# "Open with -> Browse" does, an OpenWithList entry, a desktop shortcut and a Run value.
function Plant-NppPortable($Ctx) {
    $dir = Join-Path $X0User 'Tools\npp-portable'
    Expand-PlantZip $Ctx 'npp-portable.zip' $dir
    $exe = Join-Path $dir 'notepad++.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw "no notepad++.exe in the portable zip ($dir)" }
    Plant-RegValue $Ctx "HKU\$RigUserSid\Software\Classes\Applications\notepad++.exe\shell\open\command" '' ('"' + $exe + '" "%1"')
    Add-OpenWithList $Ctx '.log' 'notepad++.exe'
    Plant-Shortcut $Ctx (Join-Path $X0Desktop 'Notepad++.lnk') $exe '' $dir
    $todo = Join-Path $X0User 'Documents\todo.txt'
    Plant-File $Ctx $todo "buy milk`r`n"
    Plant-RegValue $Ctx $X0Run 'Notepad++ Notes' ('"' + $exe + '" ' + $todo)
}

# After the launch: user files inside the install folder and an export in the app's roaming folder.
function Plant-NppUserFiles($Ctx) {
    $root = Get-PlantInstallDir $Ctx
    Plant-File $Ctx (Join-Path $root 'my-notes\todo.txt') "my notes, kept next to the editor`r`n"
    Plant-File $Ctx (Join-Path $root 'session-backup.txt') "session backup written by the user`r`n"
    Plant-File $Ctx (Join-Path $env:APPDATA 'Notepad++\my-macros-export.xml') "<NotepadPlus><Macros /></NotepadPlus>`r`n"
}

# --------------------------------------------------------------------------------- x0-git-toolsdir (rank 2)
# Before snap 0: the user's tools folder (ripgrep, notes, a script), on the user PATH, with an App Paths entry and a
# Run value. Git is then installed INTO this folder (apps.ps1 install /DIR=%USERPROFILE%\Tools).
function Plant-GitToolsDir($Ctx) {
    $tools = Join-Path $X0User 'Tools'
    Expand-PlantZip $Ctx 'ripgrep.zip' (Join-Path $tools 'ripgrep') 'ripgrep-15.2.0-x86_64-pc-windows-msvc'
    $rg = Join-Path $tools 'ripgrep\rg.exe'
    if (-not (Test-Path -LiteralPath $rg)) { throw "no rg.exe after unpacking ($rg)" }
    Plant-File $Ctx (Join-Path $tools 'notes\my-tool-notes.txt') "which tool does what`r`n"
    $ps1 = Join-Path $tools 'scripts\backup.ps1'
    Plant-File $Ctx $ps1 "Copy-Item `$env:USERPROFILE\Documents -Destination D:\Backup -Recurse`r`n"
    Add-UserPathSegment $Ctx (Join-Path $tools 'ripgrep')
    Plant-RegValue $Ctx "HKU\$RigUserSid\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe" '' $rg
    Plant-RegValue $Ctx $X0Run 'Backup' ('powershell -File ' + $ps1)
}

# ----------------------------------------------------------------------------- x0-vscode-with-user (rank 4)
# Before snap 0 (after the per-user build was installed and launched): a .txt opened once with Code.exe.
function Plant-VscodeTxtOpenWith($Ctx) {
    Add-OpenWithList $Ctx '.txt' 'Code.exe'
}

# -------------------------------------------------------------------------------- x0-git-userstate (rank 5)
# Before snap 0 (TortoiseGit installed): references to Git that the user or other products created.
function Plant-GitUserState($Ctx) {
    $u = "HKU\$RigUserSid"
    Plant-RegValue $Ctx "$u\Software\TortoiseGit" 'MSysGit' 'C:\Program Files\Git\bin'
    Plant-RegValue $Ctx "$u\Software\ContosoTools\Settings" 'GitExecutable' 'C:\Program Files\Git\cmd\git.exe'
    Add-UserPathSegment $Ctx 'C:\Program Files\Git\cmd'
    Plant-RegValue $Ctx "$u\Environment" 'GIT_SSH' 'C:\Program Files\Git\usr\bin\ssh.exe'
    Plant-RegValue $Ctx "$u\Environment" 'DIGIT_HOME' (Join-Path $X0User 'digit')
    Plant-RegValue $Ctx $X0Run 'GitAutoFetch' '"C:\Program Files\Git\git-bash.exe" --hide -c "git -C ~/repo fetch"'
    Plant-RegValue $Ctx $X0Run 'GitHubSync' (Join-Path $X0User 'Tools\ghsync\ghsync.exe')
    Plant-Dir $Ctx (Join-Path $X0User 'repos')
    Plant-Shortcut $Ctx 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Git\My Repos.lnk' 'C:\Windows\explorer.exe' (Join-Path $X0User 'repos')
    Plant-Shortcut $Ctx (Join-Path $X0Desktop 'Git Bash.lnk') (Join-Path $X0User 'Tools\PortableGit\git-bash.exe')
    if (Test-RegKey 'HKLM\SOFTWARE\Classes\.sh') {
        Add-Planted $Ctx 'note' 'K:HKLM\SOFTWARE\Classes\.sh' 'exists on this machine already: not planted'
    } else {
        Plant-RegKey $Ctx 'HKLM\SOFTWARE\Classes\.sh\OpenWithProgids'
    }
}

# ----------------------------------------------------------------------------- x0-vscode-userstate (rank 11)
# Before snap 0: four extension keys VS Code associates (taken from the r0-vscode truth), prior VS Code user data,
# and an "Open with" registration of a zip copy (absent).
function Plant-VscodeUserState($Ctx) {
    $c = 'HKLM\SOFTWARE\Classes'
    foreach ($e in '.gemspec', '.edn') {
        if (Test-RegKey "$c\$e") { Add-Planted $Ctx 'note' "K:$c\$e" 'exists already: not planted'; continue }
        Plant-RegKey $Ctx "$c\$e\OpenWithProgids"
    }
    Plant-RegValue $Ctx "$c\.toml\OpenWithProgids" 'MyEditor.toml' ([byte[]]@()) ([Microsoft.Win32.RegistryValueKind]::None)
    Plant-RegValue $Ctx "$c\.lua" '' 'MyEditor.lua'
    $code = Join-Path $env:APPDATA 'Code\User'
    Plant-File $Ctx (Join-Path $code 'settings.json') "{`r`n    `"editor.fontSize`": 15`r`n}`r`n"
    Plant-File $Ctx (Join-Path $code 'snippets\mine.code-snippets') "{ `"log`": { `"prefix`": `"log`", `"body`": [`"console.log(`$1)`"] } }`r`n"
    Plant-RegValue $Ctx "HKU\$RigUserSid\Software\Classes\Applications\Code.exe\shell\open\command" '' ('"' + (Join-Path $X0User 'Tools\VSCode\Code.exe') + '" "%1"')
}

# After the launch: a user file in the install folder.
function Plant-VscodeWorkspace($Ctx) {
    $root = Get-PlantInstallDir $Ctx
    Plant-File $Ctx (Join-Path $root 'my-workspace\notes.md') "# notes kept in the editor's folder`r`n"
}

# ------------------------------------------------------------------------------- x0-vscode-zipcopy (rank 17)
# Before snap 0: the official VS Code zip archive unpacked to the user's tools folder and started once (medium
# integrity), so it creates %APPDATA%\Code and its runtime registrations. The engine knows nothing of this copy.
function Plant-VscodeZipCopy($Ctx) {
    $dir = Join-Path $X0User 'Tools\VSCode'
    Expand-PlantZip $Ctx 'vscode-archive.zip' $dir
    $exe = Join-Path $dir 'Code.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw "no Code.exe in the archive ($dir)" }
    $L = [pscustomobject]@{ task = 'PurgeRigLaunch'; start = (Get-Date); found = $false; pid = $null; exe = $exe; pre = $null }
    try {
        $L = LaunchMedium -Exe $exe -Arguments '' -TaskName 'PurgeRigLaunch'
        Start-Sleep -Seconds 25
    } finally {
        $r = Stop-Launch $L -GraceSec 5
        Add-Planted $Ctx 'launch' ('P:' + $exe) ("started=$($L.found) closed=$(@($r.closed).Count) killed=$(@($r.killed).Count)")
    }
    Start-Sleep -Seconds 10
}
