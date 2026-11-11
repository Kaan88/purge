# Purge rig v2: builds the dirty-baseline state (ENGINE_PLAN §10.2) on top of rig-base. Run once as an
# agent job, then the host shuts the guest down and takes the offline snapshot 'dirty-base'.
# Official vendor URLs only. Every step is wrapped: a failed install is recorded and the rest still run.
# Outputs in C:\cr\out\dirty-base\: run.log, dirty.json (what was installed / planted / skipped),
# lists-dirty-base-0.json and snap-dirty-base-0.tsv.gz (the dirty state itself, for danger checks).
. C:\cr\guest\riglib.ps1

$Run = 'dirty-base'
$Dir = New-RunDir $Run
Set-RunLog (Join-Path $Dir 'run.log')
Log "setup-dirty on $env:COMPUTERNAME as $env:USERNAME"

$S = [ordered]@{ schema = 'purge.rig.dirty/1'; started = (NowIso); finished = $null; free_gb_before = $null
                 installs = New-Object System.Collections.ArrayList; planted = New-Object System.Collections.ArrayList
                 skipped = @(); phases = New-Object System.Collections.ArrayList }
$S.free_gb_before = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
Log "C: free $($S.free_gb_before) GB"

function Install-One([string]$Name, $Url, [string]$File, [string]$Arguments, [int]$TimeoutSec = 1800, [string]$Match = '') {
    $r = [ordered]@{ name = $Name; file = $File; url = $null; sha256 = $null; sig = $null; cmd = $null; exit = $null; timed_out = $false; arp = @(); error = $null }
    try {
        if ($Url -is [scriptblock]) { $Url = & $Url }
        $rec = Fetch $Url $File
        $r.url = $rec.url; $r.sha256 = $rec.sha256; $r.sig = "$($rec.sig) $($rec.signer)".Trim()
        $path = Join-Path $RigInst $File
        if ($File -like '*.msi') { $exe = Join-Path $env:SystemRoot 'System32\msiexec.exe'; $a = "/i `"$path`" $Arguments" }
        else { $exe = $path; $a = $Arguments }
        $r.cmd = "`"$exe`" $a"
        Log "install $Name : $($r.cmd)"
        $t = Get-Date
        $p = Start-Native $exe $a
        $exited = $p.WaitForExit($TimeoutSec * 1000)
        if ($exited) { $r.exit = $p.ExitCode } else { $r.timed_out = $true }
        $w = WaitTree -Since $t -TimeoutSec ([Math]::Max(60, $TimeoutSec - [int]((Get-Date) - $t).TotalSeconds)) -RootPid @($p.Id)
        if ($w.timed_out) {
            # An installer that starts its app (NVDA, Steam) leaves a long-lived child: stop the tree.
            $r.timed_out = $true
            $still = @(Get-TreeProcs -Procs (Get-ProcList) -Known $w.known)
            if ($still.Count) { Log "  stopping: $(($still | ForEach-Object { "$($_.name)[$($_.pid)]" }) -join ', ')"; Stop-Procs $still "$Name tree" }
        }
        Log "  $Name exit=$($r.exit) timed_out=$($r.timed_out) in $([int]((Get-Date) - $t).TotalSeconds) s"
        if ($Match) { $r.arp = @(UninstallEntries | Where-Object { $_.name -match $Match } | ForEach-Object { "$($_.name) $($_.version)" }) }
        Log "  ARP: $($r.arp -join '; ')"
    } catch { $r.error = $_.Exception.Message; Log "!! $Name failed: $($r.error)" }
    [void]$S.installs.Add($r)
    Start-Sleep -Seconds 10
}

function Plant([string]$Path, [string]$Text) {
    try {
        New-Item -ItemType Directory -Force (Split-Path -Parent $Path) | Out-Null
        [IO.File]::WriteAllText($Path, $Text, $RigUtf8)
        [void]$S.planted.Add($Path); Log "planted $Path"
    } catch { Log "!! plant $Path failed: $($_.Exception.Message)" }
}

function Get-Zip([string]$Name, $Url, [string]$Dest) {
    try {
        New-Item -ItemType Directory -Force $RigInst | Out-Null
        $zip = Join-Path $RigInst "$Name.zip"
        Invoke-WebRequest -Uri $Url -OutFile $zip -UseBasicParsing -MaximumRedirection 10 -ErrorAction Stop -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) rig-download'
        $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLower()
        Expand-Archive -LiteralPath $zip -DestinationPath $Dest -Force
        [void]$S.installs.Add([ordered]@{ name = $Name; file = "$Name.zip"; url = $Url; sha256 = $h; cmd = "expand to $Dest"; exit = 0 })
        Log "portable $Name -> $Dest (sha256 $h)"
    } catch { [void]$S.installs.Add([ordered]@{ name = $Name; url = $Url; error = $_.Exception.Message }); Log "!! portable $Name failed: $($_.Exception.Message)" }
}

$Q = '/quiet InstallAllUsers=1 PrependPath=1 Include_test=0'

# ------------------------------------------------------------------------------------------- installs
Install-One 'Thunderbird' 'https://download.mozilla.org/?product=thunderbird-latest-ssl&os=win64&lang=en-US' 'thunderbird.exe' '/S' 900 '^Mozilla Thunderbird'
Install-One 'NVDA' { GitHubAsset 'nvaccess/nvda' '^nvda_[\d.]+\.exe$' } 'nvda.exe' '--install-silent' 600 '^NVDA'
Install-One 'Steam' 'https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe' 'steam.exe' '/S' 600 '^Steam'
Install-One 'Zotero' 'https://www.zotero.org/download/client/dl?channel=release&platform=win-x64' 'zotero.exe' '/S' 600 '^Zotero'
Install-One 'Python 3.13' 'https://www.python.org/ftp/python/3.13.1/python-3.13.1-amd64.exe' 'python313.exe' $Q 1800 '^Python 3\.13'
Install-One 'Python 3.11' 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' 'python311.exe' $Q 1800 '^Python 3\.11'
Install-One 'Node.js 20' 'https://nodejs.org/dist/v20.18.0/node-v20.18.0-x64.msi' 'node.msi' '/qn /norestart' 1200 '^Node\.js'
Install-One 'VS Code' 'https://update.code.visualstudio.com/latest/win32-x64/stable' 'vscode.exe' '/VERYSILENT /NORESTART /MERGETASKS=!runcode' 1200 '^Microsoft Visual Studio Code'
Install-One 'VS Build Tools 2022 (MSBuild)' 'https://aka.ms/vs/17/release/vs_BuildTools.exe' 'vs_buildtools.exe' '--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.MSBuildTools' 3600 '^Visual Studio Build Tools'

# ------------------------------------------------------------------------------------- portable tools
Get-Zip 'SysinternalsSuite' 'https://download.sysinternals.com/files/SysinternalsSuite.zip' 'C:\Tools\Sysinternals'
try {
    $rg = GitHubAsset 'BurntSushi/ripgrep' 'x86_64-pc-windows-msvc\.zip$'
    if ($rg) { Get-Zip 'ripgrep' $rg 'C:\Tools' }
} catch { Log "!! ripgrep lookup failed: $($_.Exception.Message)" }

# ------------------------------------------------------------------------------ planted user files
# User data inside app roots and AppData that no cleaner may preselect (userdata_preselected gate).
$U = $env:USERPROFILE; $AD = $env:APPDATA; $LAD = $env:LOCALAPPDATA
Plant "$U\Zotero\storage\ABCD1234\paper-notes.txt" "Planted: Zotero attachment note (user data)."
Plant "$U\Zotero\zotero-library-export.rdf" "<rdf>planted Zotero library export</rdf>"
Plant "$AD\Code\User\settings.json" '{ "editor.fontSize": 15, "planted": true }'
Plant "$AD\Code\User\snippets\planted.code-snippets" '{ "hello": { "prefix": "hi", "body": "planted" } }'
Plant "$AD\Thunderbird\planted-address-book-export.ldif" "dn: cn=Planted Contact`nmail: planted@example.invalid"
Plant "$AD\nvda\nvda.ini" "[general]`nlanguage = en`n# planted user config"
Plant "$LAD\Programs\Python\planted-venv-notes.txt" "Planted: notes next to per-user Python installs."
Plant "C:\Tools\notes\my-tool-notes.txt" "Planted: user notes inside the portable tools folder."
Plant "C:\Program Files\Microsoft VS Code\planted-user-file.txt" "Planted: user file inside an app install root."
Plant "C:\Program Files (x86)\Steam\steamapps\common\PlantedGame\save\slot1.sav" "planted save game"
Plant "$U\Documents\Projects\demo\main.py" "print('planted user project')"
Plant "$U\.gitconfig" "[user]`n`tname = Planted Tester`n`temail = tester@example.invalid"
Plant "$U\.npmrc" "fund=false`n# planted"

$S.skipped = @(
    'Office C2R: needs the Office Deployment Tool, ~3 GB and a licence to be useful; not installed in M0.',
    'Visual Studio IDE: replaced by VS Build Tools 2022 (MSBuild workload) to keep the VM disk and time small.',
    'OneDrive Known Folder Move: needs a Microsoft account sign-in.',
    'Steam library on D:: the VM has no D: volume; a planted steamapps folder under the install root stands in.'
)
foreach ($x in $S.skipped) { Log "skipped: $x" }

# ------------------------------------------------------------------------------- capture dirty state
Phase 'lists0' { Lists $Run 0 } $S
Phase 'snap0' { Snap $Run 0 } $S
$S.finished = NowIso
Write-JsonFile $S (Join-Path $Dir 'dirty.json')
Log ("setup-dirty finished: {0} installs, {1} failed, {2} planted" -f $S.installs.Count, @($S.installs | Where-Object { $_.error -or ($_.exit -ne $null -and $_.exit -ne 0 -and $_.exit -ne 3010) }).Count, $S.planted.Count)
exit 0
