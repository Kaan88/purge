<#
  Purge rig, M3 security modes m3-broker, m3-consent, m3-uac (vm\RIG.md section 14; docs\M3_DESIGN.md 4 T1, T2, T5-T8,
  11.2, 11.3, gate G3, G4, G5, G10; docs\M3_FINISH_PLAN.md B4-B6). Guest side, Windows PowerShell 5.1, run elevated by
  C:\cr\agent.ps1 as one job per phase; the host driver is vm\rig-m3.ps1. The tool is C:\cr\m3sec\m3sec.exe, built
  from vm\guest\m3sec.cs (roles: client, drive, observe, focus, focuswin, procinfo, arm, press, ui, inputdesk,
  fixture-uninstall).

    & C:\cr\guest\m3-sec.ps1 -Phase <phase> [-Tag <t>] [-Method <m>] [-WaitSec <n>]

  Every output is under C:\cr\out\m3-sec\ (log sec.log); result lines start with "M3S ".

  Layout (phase install): C:\cr\m3sec\payload.zip (pushed by the host: purge-engine.exe, purge-broker.exe, kb\ and,
  when given, ui\ = the UI publish folder) is unpacked; install\install.ps1 (-SkipBuild) deploys C:\Program Files\Purge
  with the rig client as Purge.exe (so the broker's client check accepts the rig's pipe client) and, when ui\ is there,
  C:\Program Files\PurgeUI with the real UI (m3-uac's cancelled-bar row only). Then the fixture program
  "Purge Rig App" (HKLM ARP key PurgeRigApp, program id HKLM|64|PurgeRigApp; its uninstaller is a copy of m3sec.exe
  that removes only its ARP key and app.exe, so the rest stays as leftovers). -Tag picks the leftover data files:
  plain3 | lookalike3 | lookalike45 (a Cyrillic letter inside an ASCII name: each is an attention entry of the
  consent dialog, 45 of them make it page).

  Phases:
    build, install -Tag <fixture>, uac-check, uac-silent, pack
  uac-silent (m3-broker, m3-consent; coordinator ruling 2026-11-22): rig-base is at the Windows UAC defaults (5/1/1),
  so these two modes make UAC silent themselves: ConsentPromptBehaviorAdmin=0 (design 11.2 'silent'). EnableLUA stays 1,
  so medium and high integrity still differ; PromptOnSecureDesktop is left as it is (a silent elevation shows no prompt).
  The values before and after go to uac-silent.json, which both summaries carry as uac_silent.
    m3-broker:  broker-case -Tag <case id>, broker-summary
    m3-consent: consent-start, consent-next -Tag k, consent-attack -Tag k -Method m, consent-control -Tag k -Method m,
                consent-approve -Tag k, client-end -Tag consent
    m3-uac:     ui-start, ui-result, flow-start -Tag no|yes, flow-launch -Tag no|yes, arm-next -Tag k, consent-next,
                page-next -Tag k, arm-current -Tag k, consent-approve, client-end -Tag yes, std-start, std-result
  Methods: sendinput-key, sendinput-mouse, postmessage, uia.
#>
param(
    [Parameter(Mandatory)]
    [ValidateSet('build', 'install', 'uac-check', 'uac-silent', 'pack', 'broker-case', 'broker-summary',
                 'consent-start', 'consent-next', 'consent-attack', 'consent-control', 'consent-approve', 'client-end',
                 'ui-start', 'ui-result', 'flow-start', 'flow-launch', 'arm-next', 'page-next', 'arm-current',
                 'std-start', 'std-result', 'uac-summary')]
    [string] $Phase,
    [string] $Tag = '',
    [ValidateSet('', 'sendinput-key', 'sendinput-mouse', 'postmessage', 'uia')] [string] $Method = '',
    [int] $WaitSec = 120
)
. C:\cr\guest\riglib.ps1
$ErrorActionPreference = 'Continue'

$Out = 'C:\cr\out\m3-sec'
$Bin = 'C:\cr\m3sec'
$Exe = Join-Path $Bin 'm3sec.exe'
$Src = 'C:\cr\guest\m3sec.cs'
$Payload = Join-Path $Bin 'payload'
$ClientDir = Join-Path $Bin 'client'
$PF = 'C:\Program Files\Purge'
$PFUI = 'C:\Program Files\PurgeUI'
$Broker = Join-Path $PF 'purge-broker.exe'
$ClientImg = Join-Path $PF 'Purge.exe'
$DataRoot = 'C:\ProgramData\Purge'
$CaseCopy = 'C:\Program Files\PurgeCase'
$UserCopy = 'C:\PurgeUserCopy'
$Junction = 'C:\PurgeJ'
$Plant = 'C:\PurgePlant'
$FixKey = 'PurgeRigApp'
$FixName = 'Purge Rig App'
$FixDir = 'C:\Program Files\PurgeRigApp'
$FixProgram = 'HKLM|64|PurgeRigApp'
$FixArp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$FixKey"
$FixMarker = Join-Path $Out 'fixture-uninstalled.json'
$PolKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$StdUser = 'purgestd'
$Tasks = @{ client = 'PurgeRigM3Client'; clientb = 'PurgeRigM3ClientB'; drive = 'PurgeRigM3Drive'; ui = 'PurgeRigM3Ui' }
New-Item -ItemType Directory -Force $Out, $Bin | Out-Null
Set-RunLog (Join-Path $Out 'sec.log')
if ($Tag -and $Tag -notmatch '^[A-Za-z0-9_-]+$') { throw "bad tag '$Tag'" }

# ----------------------------------------------------------------------------------------------- helpers

# Users may write the output tree: the medium client and the medium drivers write their results there.
function Grant-UsersModify([string]$Dir) {
    New-Item -ItemType Directory -Force $Dir | Out-Null
    $null = & icacls.exe $Dir /grant '*S-1-5-32-545:(OI)(CI)M' /q
}

function Read-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
}

function Wait-File([string]$Path, [int]$Sec) {
    $d = (Get-Date).AddSeconds($Sec)
    while (-not (Test-Path -LiteralPath $Path) -and (Get-Date) -lt $d) { Start-Sleep -Milliseconds 250 }
    Test-Path -LiteralPath $Path
}

function Write-Spec($Spec, [string]$Path) { Write-JsonFile $Spec $Path 8 }

# Runs m3sec.exe from the (high) agent and waits.
function Invoke-Sec([string[]]$Arguments, [int]$TimeoutSec = 120) {
    $q = @($Arguments | ForEach-Object { if ("$_" -match '\s') { '"' + $_ + '"' } else { "$_" } })
    $p = Start-Process -FilePath $Exe -ArgumentList $q -PassThru -WindowStyle Hidden
    if (-not $p.WaitForExit($TimeoutSec * 1000)) { Log "  !! m3sec $($Arguments[0]) still running after $TimeoutSec s; killed"; Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; return $false }
    $true
}

# Starts $ExePath at medium integrity (riglib LaunchMedium: a one-shot task at the limited run level).
function Start-Medium([string]$ExePath, [string]$Arguments, [string]$TaskName) {
    $null = LaunchMedium -Exe $ExePath -Arguments $Arguments -TaskName $TaskName -StartTimeoutSec 0
}
function Stop-Task([string]$TaskName) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue }

function Get-UacValues {
    $p = Get-ItemProperty -LiteralPath $PolKey -ErrorAction SilentlyContinue
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [ordered]@{
        ConsentPromptBehaviorAdmin = $p.ConsentPromptBehaviorAdmin
        ConsentPromptBehaviorUser  = $p.ConsentPromptBehaviorUser
        PromptOnSecureDesktop      = $p.PromptOnSecureDesktop
        EnableLUA                  = $p.EnableLUA
        build                      = "$($cv.CurrentBuildNumber).$($cv.UBR)"
        edition                    = "$($cv.EditionID)"
        agent_integrity            = ((& whoami.exe /groups) | Select-String 'Mandatory Label\\(\w+) Mandatory Level' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -First 1)
    }
}

# Every object under the data root: path, size, last write, attributes. Two listings that differ mean a write.
function Get-TreeList([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    $items = @(Get-Item -LiteralPath $Root -Force) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue)
    @($items | ForEach-Object {
        $len = $(if ($_.PSIsContainer) { -1 } else { $_.Length })
        '{0}|{1}|{2}|{3}' -f $_.FullName, $len, $_.LastWriteTimeUtc.Ticks, [int]$_.Attributes
    } | Sort-Object)
}
function Compare-TreeList($Before, $After) {
    @(Compare-Object -ReferenceObject @($Before) -DifferenceObject @($After) | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" })
}

# The journal state: the session directories and the index (a new session or a changed index is a change).
function Get-JournalState {
    $s = Join-Path $DataRoot 'sessions'
    $dirs = @(Get-ChildItem -LiteralPath $s -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Sort-Object)
    $idx = Join-Path $s 'index.json'
    $hash = $(if (Test-Path -LiteralPath $idx) { (Get-FileHash -LiteralPath $idx -Algorithm SHA256).Hash } else { $null })
    [ordered]@{ sessions = $dirs; index_sha256 = $hash }
}
function Test-JournalSame($A, $B) { ((@($A.sessions) -join '|') -eq (@($B.sessions) -join '|')) -and ($A.index_sha256 -eq $B.index_sha256) }

function Get-PurgeEvents([datetime]$Since) {
    @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Purge'; StartTime = $Since } -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated | ForEach-Object {
            # The Purge source has no message file (install\README.md): Windows renders no .Message, and the
            # broker's line is the event's insertion string (m3-broker 2026-11-25: every message read empty).
            $msg = "$($_.Message)"
            if (-not $msg.Trim()) { $msg = (@($_.Properties | ForEach-Object { "$($_.Value)" }) -join ' ').Trim() }
            [ordered]@{ id = $_.Id; time = $_.TimeCreated.ToString('o'); message = $msg }
        })
}

function Get-DaclSddl([string]$Path) {
    if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) { ([IO.Directory]::GetAccessControl($Path, 'Access')).GetSecurityDescriptorSddlForm('Access') }
    else { ([IO.File]::GetAccessControl($Path, 'Access')).GetSecurityDescriptorSddlForm('Access') }
}
# Puts back the DACL (only the DACL: the owner stays as it is) saved by Get-DaclSddl.
function Set-DaclSddl([string]$Path, [string]$Sddl) {
    if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) {
        $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm($Sddl, 'Access'); [IO.Directory]::SetAccessControl($Path, $s)
    } else {
        $s = New-Object Security.AccessControl.FileSecurity; $s.SetSecurityDescriptorSddlForm($Sddl, 'Access'); [IO.File]::SetAccessControl($Path, $s)
    }
}

# An admin-only copy of the installed layout (owner Administrators, protected DACL SYSTEM and Administrators full,
# Users read and execute, also on every object below; on the system volume when $Dest is). The control case copy-ok
# proves the copy passes the broker's start checks, so each variant that loosens one object fails for that object.
function Copy-Layout([string]$Dest) {
    if (Test-Path -LiteralPath $Dest) { Remove-Item -LiteralPath $Dest -Recurse -Force }
    $null = & robocopy.exe $PF $Dest /E /R:0 /W:0 /NP /NFL /NDL /NJH /NJS
    $null = & icacls.exe $Dest /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /q
    $null = & icacls.exe "$Dest\*" /reset /T /C /Q
    $null = & icacls.exe $Dest /setowner '*S-1-5-32-544' /T /C /Q
    Test-Path -LiteralPath (Join-Path $Dest 'purge-broker.exe')
}

# A volume other than the system volume: an existing fixed NTFS volume (D: on m2-base), else a 256 MB VHDX made with
# diskpart under C:\cr\m3sec and mounted as R:. Returns the drive root (e.g. 'R:\') or $null.
function Get-OffVolume {
    $sys = $env:SystemDrive.TrimEnd('\').ToUpperInvariant()
    $vol = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue |
        Where-Object { $_.DeviceID.ToUpperInvariant() -ne $sys -and $_.FileSystem -eq 'NTFS' } | Select-Object -First 1
    if ($vol) { return "$($vol.DeviceID)\" }
    $vhd = Join-Path $Bin 'offvol.vhdx'
    if (-not (Test-Path -LiteralPath 'R:\')) {
        $script = Join-Path $Bin 'offvol.txt'
        $lines = @("create vdisk file=`"$vhd`" maximum=256 type=expandable", "select vdisk file=`"$vhd`"", 'attach vdisk',
                   'convert mbr noerr', 'create partition primary', 'format fs=ntfs quick label=PURGEOFF', 'assign letter=R')
        [IO.File]::WriteAllLines($script, $lines)
        $o = & diskpart.exe /s $script 2>&1
        foreach ($l in @($o)) { if ("$l".Trim()) { Log "  diskpart: $l" } }
    }
    if (Test-Path -LiteralPath 'R:\') { 'R:\' } else { $null }
}

# ------------------------------------------------------------------------------------------- fixture

function Install-Fixture([string]$Variant) {
    $n = 3; $look = $true
    switch ($Variant) { 'plain3' { $look = $false } 'lookalike3' { } 'lookalike45' { $n = 45 } default { throw "unknown fixture '$Variant'" } }
    if (Test-Path -LiteralPath $FixDir) { Remove-Item -LiteralPath $FixDir -Recurse -Force }
    New-Item -ItemType Directory -Force (Join-Path $FixDir 'data') | Out-Null
    Copy-Item -LiteralPath $Exe -Destination (Join-Path $FixDir 'app.exe') -Force
    Copy-Item -LiteralPath $Exe -Destination (Join-Path $FixDir 'uninst.exe') -Force
    # A Cyrillic small a (U+0430) inside an ASCII word: the dialog writes it \u{430} and lists the item for attention.
    $cy = [string][char]0x0430
    for ($i = 1; $i -le $n; $i++) {
        $name = $(if ($look) { "Purge${cy}pp-data-{0:D2}.dat" -f $i } else { 'data-{0:D2}.dat' -f $i })
        [IO.File]::WriteAllText((Join-Path (Join-Path $FixDir 'data') $name), "fixture $i`r`n")
    }
    New-Item -ItemType Directory -Force 'C:\ProgramData\PurgeRigApp' | Out-Null
    [IO.File]::WriteAllText('C:\ProgramData\PurgeRigApp\settings.ini', "[rig]`r`nfixture=1`r`n")
    $null = New-Item -Path 'HKLM:\SOFTWARE\PurgeRigApp' -Force
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\PurgeRigApp' -Name 'InstallDir' -Value $FixDir
    $null = New-Item -Path 'HKCU:\Software\PurgeRigApp' -Force
    Set-ItemProperty -LiteralPath 'HKCU:\Software\PurgeRigApp' -Name 'LastRun' -Value 'fixture'
    $null = New-Item -Path $FixArp -Force
    $u = '"' + (Join-Path $FixDir 'uninst.exe') + '" fixture-uninstall'
    $props = [ordered]@{ DisplayName = $FixName; DisplayVersion = '1.0.0'; Publisher = 'Purge rig'; InstallLocation = $FixDir
                         DisplayIcon = (Join-Path $FixDir 'app.exe'); UninstallString = $u; QuietUninstallString = "$u /S" }
    foreach ($k in $props.Keys) { Set-ItemProperty -LiteralPath $FixArp -Name $k -Value $props[$k] }
    Set-ItemProperty -LiteralPath $FixArp -Name 'NoModify' -Value 1 -Type DWord
    Set-ItemProperty -LiteralPath $FixArp -Name 'NoRepair' -Value 1 -Type DWord
    Remove-Item -LiteralPath $FixMarker -Force -ErrorAction SilentlyContinue
    Log "fixture $Variant installed: $n data files (look-alike names: $look), ARP $FixKey"
    [ordered]@{ variant = $Variant; files = $n; lookalike = $look; program_id = $FixProgram; dir = $FixDir }
}

# ------------------------------------------------------------------------------------- broker cases

# The client spec every case starts from: the installed broker, started like the UI does, one connect, hello first.
function New-CaseSpec([string]$Dir) {
    [ordered]@{ out = $Dir; broker = $Broker; launch = 'runas'; connects = 1; first_line = 'hello'; connect_wait_ms = 15000; exit_wait_ms = 30000; go = $false }
}

# One case of m3-broker (design 3.3, 3.4, T2, T5, T6, T7; gate G3, G10). Returns the record kept in cases\<id>.json.
function Invoke-BrokerCase([string]$Id) {
    $dir = Join-Path $Out "broker\$Id"
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    Grant-UsersModify $dir
    $rec = [ordered]@{ id = $Id; t = (NowIso); prep = [ordered]@{}; client = $null; client_b = $null; exit_code = $null; broker_exited = $null
                       events = @(); data_root_changed = $null; data_root_diff = @(); planted = $null; planted_changed = $null; planted_diff = @(); error = $null }
    $spec = New-CaseSpec $dir
    $client = $ClientImg
    $cleanup = @()
    $plantRoot = $null
    switch ($Id) {
        'start-ok' { $spec.steps = @(@{ op = 'shutdown' }); $spec.second_client_probe = $true }
        'not-elevated' { $spec.launch = 'create'; $spec.connects = 0 }
        'bad-args' { $spec.args = '--pipe short --parent {pid} --parent-ctime {ctime}'; $spec.connects = 0 }
        'parent-pid' { $spec.parent_pid = -1; $spec.connects = 0 }
        'parent-ctime' { $spec.ctime_delta = 1; $spec.connects = 0 }
        'pipe-squat' { $spec.squat = $true; $spec.connect_wait_ms = 3000 }
        'client-image' {
            $client = Join-Path $Bin 'elsewhere\Purge.exe'
            New-Item -ItemType Directory -Force (Split-Path $client) | Out-Null
            Copy-Item -LiteralPath $ClientImg -Destination $client -Force
            $spec.connects = 3; $rec.prep.client = $client
        }
        'second-client' { $spec.connects = 0; $spec.hold_ms = 60000; $spec.exit_wait_ms = 5000 }
        'not-hello' { $spec.connects = 3; $spec.first_line = 'garbage' }
        'copy-ok' {
            $rec.prep.copied = Copy-Layout $CaseCopy
            $spec.broker = Join-Path $CaseCopy 'purge-broker.exe'; $client = Join-Path $CaseCopy 'Purge.exe'; $spec.steps = @(@{ op = 'shutdown' })
            $cleanup += { Remove-Item -LiteralPath $CaseCopy -Recurse -Force -ErrorAction SilentlyContinue }
        }
        'user-writable-copy' {
            if (Test-Path -LiteralPath $UserCopy) { Remove-Item -LiteralPath $UserCopy -Recurse -Force }
            $null = & robocopy.exe $PF $UserCopy /E /R:0 /W:0 /NP /NFL /NDL /NJH /NJS
            $null = & icacls.exe $UserCopy /reset /T /C /Q
            $null = & icacls.exe $UserCopy /grant '*S-1-5-32-545:(OI)(CI)M' /q
            # T6: a DLL planted next to the broker in that copy (a copy of the system's version.dll; the broker must refuse
            # the directory before anything of it matters).
            Copy-Item -LiteralPath "$env:WINDIR\System32\version.dll" -Destination (Join-Path $UserCopy 'version.dll') -Force
            $rec.prep.dacl = Get-DaclSddl $UserCopy; $rec.prep.planted_dll = (Join-Path $UserCopy 'version.dll')
            $spec.broker = Join-Path $UserCopy 'purge-broker.exe'; $client = Join-Path $UserCopy 'Purge.exe'
            $cleanup += { Remove-Item -LiteralPath $UserCopy -Recurse -Force -ErrorAction SilentlyContinue }
        }
        'off-volume' {
            $root = Get-OffVolume
            $rec.prep.volume = $root
            if (-not $root) { throw 'no volume other than the system volume (diskpart failed)' }
            $null = & icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /q
            $dest = Join-Path $root 'Purge'
            $rec.prep.copied = Copy-Layout $dest
            $rec.prep.dacl = Get-DaclSddl $dest
            $spec.broker = Join-Path $dest 'purge-broker.exe'; $client = Join-Path $dest 'Purge.exe'
            $cleanup += { Remove-Item -LiteralPath (Join-Path $root 'Purge') -Recurse -Force -ErrorAction SilentlyContinue }
        }
        'junction' {
            if (Test-Path -LiteralPath $Junction) { cmd /c rmdir "$Junction" | Out-Null }
            $o = cmd /c mklink /J "$Junction" "$PF" 2>&1
            $rec.prep.mklink = "$o"
            $spec.broker = Join-Path $Junction 'purge-broker.exe'
            $cleanup += { cmd /c rmdir "$Junction" | Out-Null }
        }
        { $_ -in 'exe-user-writable', 'kb-user-writable', 'kb-file-user-writable', 'client-image-user-writable' } {
            $rec.prep.copied = Copy-Layout $CaseCopy
            $target = switch ($Id) {
                'exe-user-writable' { Join-Path $CaseCopy 'purge-broker.exe' }
                'kb-user-writable' { Join-Path $CaseCopy 'kb' }
                'kb-file-user-writable' { @(Get-ChildItem -LiteralPath (Join-Path $CaseCopy 'kb\baselines') -Filter '*.tsv.gz' -File | Select-Object -First 1)[0].FullName }
                'client-image-user-writable' { Join-Path $CaseCopy 'Purge.exe' }
            }
            $null = & icacls.exe $target /grant '*S-1-5-32-545:M' /q
            $rec.prep.target = $target; $rec.prep.dacl = Get-DaclSddl $target
            $spec.broker = Join-Path $CaseCopy 'purge-broker.exe'; $client = Join-Path $CaseCopy 'Purge.exe'
            $cleanup += { Remove-Item -LiteralPath $CaseCopy -Recurse -Force -ErrorAction SilentlyContinue }
        }
        'data-root-user-writable' {
            $saved = Get-DaclSddl $DataRoot
            $null = & icacls.exe $DataRoot /grant '*S-1-5-32-545:(M)' /q
            $rec.prep.dacl = Get-DaclSddl $DataRoot
            # (Run with & from this function below, so $saved is still in scope.)
            $cleanup += { Set-DaclSddl $DataRoot $saved }
        }
        'index-user-writable' {
            $idx = Join-Path $DataRoot 'sessions\index.json'
            $saved = Get-DaclSddl $idx
            $null = & icacls.exe $idx /grant '*S-1-5-32-545:M' /q
            $rec.prep.dacl = Get-DaclSddl $idx
            $cleanup += { Set-DaclSddl $idx $saved }
        }
        { $_ -in 'env-planted', 'env-planted-hkcu' } {
            # T7: a user-writable tree that looks like a data root and a KB; the broker must not read or write it.
            if (Test-Path -LiteralPath $Plant) { Remove-Item -LiteralPath $Plant -Recurse -Force }
            foreach ($d in 'ProgramData\Purge\sessions', 'ProgramData\Purge\fp', 'kb\baselines') { New-Item -ItemType Directory -Force (Join-Path $Plant $d) | Out-Null }
            [IO.File]::WriteAllText((Join-Path $Plant 'ProgramData\Purge\sessions\index.json'), '{}')
            [IO.File]::WriteAllText((Join-Path $Plant 'kb\baselines\EnterpriseSEval-26100.1742.tsv.gz'), 'planted, not a baseline')
            $null = & icacls.exe $Plant /grant '*S-1-5-32-545:(OI)(CI)M' /q
            $plantRoot = $Plant
            $vars = [ordered]@{ ProgramData = "$Plant\ProgramData"; ALLUSERSPROFILE = "$Plant\ProgramData"; PURGE_KB_DIR = "$Plant\kb"; SystemDrive = $Plant }
            if ($Id -eq 'env-planted') { $spec.env = $vars }
            else {
                foreach ($k in $vars.Keys) { Set-ItemProperty -LiteralPath 'HKCU:\Environment' -Name $k -Value $vars[$k] }
                $cleanup += { foreach ($k in 'ProgramData', 'ALLUSERSPROFILE', 'PURGE_KB_DIR', 'SystemDrive') { Remove-ItemProperty -LiteralPath 'HKCU:\Environment' -Name $k -ErrorAction SilentlyContinue } }
            }
            $rec.prep.env = $vars
            $spec.steps = @(@{ op = 'shutdown' })
            $cleanup += { Remove-Item -LiteralPath $Plant -Recurse -Force -ErrorAction SilentlyContinue }
        }
        default { throw "unknown case '$Id'" }
    }
    $rec.prep.client_exe = $client; $rec.prep.broker = $spec.broker
    $plantBefore = $(if ($plantRoot) { Get-TreeList $plantRoot } else { @() })
    $before = Get-TreeList $DataRoot
    $since = (Get-Date).AddSeconds(-2)
    try {
        $specPath = Join-Path $dir 'spec.json'
        Write-Spec $spec $specPath
        Start-Medium $client "client `"$specPath`"" $Tasks.client
        if ($Id -eq 'second-client') {
            # T2: a second instance of the installed Purge.exe (another pid) talks to the first one's broker.
            if (-not (Wait-File (Join-Path $dir 'launched.json') 60)) { throw 'the first client wrote no launched.json' }
            $bdir = Join-Path $dir 'b'; Grant-UsersModify $bdir
            $bspec = New-CaseSpec $bdir
            $bspec.launch = 'attach'; $bspec.attach_file = (Join-Path $dir 'launched.json'); $bspec.connects = 3; $bspec.exit_wait_ms = 30000
            Write-Spec $bspec (Join-Path $bdir 'spec.json')
            Start-Medium $client "client `"$(Join-Path $bdir 'spec.json')`"" $Tasks.clientb
            $null = Wait-File (Join-Path $bdir 'client.json') $WaitSec
            $rec.client_b = Read-Json (Join-Path $bdir 'client.json')
            Stop-Task $Tasks.clientb
        }
        if (-not (Wait-File (Join-Path $dir 'client.json') $WaitSec)) { $rec.error = "no client.json within $WaitSec s" }
        $rec.client = Read-Json (Join-Path $dir 'client.json')
        $rec.launched = Read-Json (Join-Path $dir 'launched.json')
        if ($rec.client) {
            $rec.broker_exited = $rec.client.broker_exited
            $rec.exit_code = $rec.client.exit_code
            if ($Id -eq 'second-client' -and $rec.client_b -and $null -ne $rec.client_b.exit_code) { $rec.exit_code = $rec.client_b.exit_code; $rec.broker_exited = $rec.client_b.broker_exited }
        }
    } catch { $rec.error = $_.Exception.Message; Log "  !! case ${Id}: $($rec.error)" }
    finally { Stop-Task $Tasks.client }
    Start-Sleep -Seconds 2
    $rec.events = @(Get-PurgeEvents $since)
    $after = Get-TreeList $DataRoot
    $rec.data_root_diff = @(Compare-TreeList $before $after)
    $rec.data_root_changed = ($rec.data_root_diff.Count -gt 0)
    if ($plantRoot) {
        $rec.planted = $plantRoot
        $rec.planted_diff = @(Compare-TreeList $plantBefore (Get-TreeList $plantRoot))
        $rec.planted_changed = ($rec.planted_diff.Count -gt 0)
    }
    foreach ($c in $cleanup) { try { & $c } catch { Log "  !! cleanup of ${Id}: $($_.Exception.Message)" } }
    $rec
}

# ------------------------------------------------------------------------------------- consent helpers

function Get-ConsentDir([string]$Name) { Join-Path $Out "consent-$Name" }
$CDir = $null

function Get-Ready([int]$K, [int]$Sec) {
    $f = Join-Path $CDir "ready-$K.json"
    if (-not (Wait-File $f $Sec)) { return $null }
    Read-Json $f
}

function Invoke-Observe([int]$BrokerPid, [string]$Path, [int]$WaitMs = 10000) {
    $null = Invoke-Sec @('observe', "$BrokerPid", $Path, "$WaitMs") ([int]($WaitMs / 1000) + 60)
    Read-Json $Path
}

function Format-Dialog($D) {
    if (-not $D -or -not $D.found) { return 'found=False' }
    "found=True page=$($D.page)/$($D.pages) footer=$($D.footer_code) primary=$($D.has_primary)/$($D.primary_enabled) next=$($D.has_next) verify=$(if ($D.verify) { $D.verify.toggle } else { 'none' }) fg=$($D.foreground) broker_il=$($D.broker_il) attention=$($D.attention_total)"
}

# The targets a medium attack aims at on the dialog as observed: the box first, then Next, the primary button, Cancel.
function Get-AttackTargets($D) {
    $t = @()
    if ($D.verify) { $t += 'verify' }
    if ($D.has_next) { $t += 'next' }
    if ($D.has_primary) { $t += 'primary' }
    $t + @('cancel')
}

function Get-ClientDirFor([string]$Name) {
    $d = Get-ConsentDir $Name
    if (-not (Test-Path -LiteralPath $d)) { throw "no client directory $d (consent-start / flow-start first)" }
    $d
}

# Consent phases share one client directory: m3-consent uses consent-consent, m3-uac's full flow consent-yes. The
# directory of the most recent start is kept in current.txt.
function Use-CurrentClient {
    $cur = Join-Path $Out 'current.txt'
    if (-not (Test-Path -LiteralPath $cur)) { throw 'no client started (current.txt missing)' }
    $script:CDir = (Get-Content -LiteralPath $cur -Raw).Trim()
}
function Set-CurrentClient([string]$Dir) { [IO.File]::WriteAllText((Join-Path $Out 'current.txt'), $Dir); $script:CDir = $Dir }

function Start-Client([string]$Name, $Spec, [switch]$Window) {
    $dir = Get-ConsentDir $Name
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    Grant-UsersModify $dir
    $Spec.out = $dir
    $Spec.start_file = (Join-Path $dir 'start')
    $sp = Join-Path $dir 'spec.json'
    Write-Spec $Spec $sp
    Set-CurrentClient $dir
    [IO.File]::WriteAllText((Join-Path $dir 'journal-start.json'), (ConvertTo-Json (Get-JournalState) -Depth 4))
    Start-Medium $ClientImg "client `"$sp`"" $Tasks.client
    # The client waits for 'start': its window is put in front first (as a user's click on the UI would).
    $proc = $null
    $d = (Get-Date).AddSeconds(30)
    while (-not $proc -and (Get-Date) -lt $d) {
        Start-Sleep -Milliseconds 500
        $proc = Get-ProcList | Where-Object { $_.path -and $_.path -ieq $ClientImg -and $_.cmd -like "*$sp*" } | Select-Object -First 1
    }
    $fw = $null
    if ($proc) { $null = Invoke-Sec @('focuswin', "$($proc.pid)", (Join-Path $dir 'focuswin.json')) 60; $fw = Read-Json (Join-Path $dir 'focuswin.json') }
    [IO.File]::WriteAllText($Spec.start_file, (NowIso))
    [ordered]@{ dir = $dir; client_pid = $(if ($proc) { $proc.pid }); window_foreground = $(if ($fw) { $fw.foreground }) }
}

function Wait-Consent([int]$Sec) {
    $c = $null
    $d = (Get-Date).AddSeconds($Sec)
    while (-not $c -and (Get-Date) -lt $d) { Start-Sleep -Milliseconds 500; $c = Get-Process consent -ErrorAction SilentlyContinue | Select-Object -First 1 }
    $c
}

function Get-InputDesk([string]$Path) { $null = Invoke-Sec @('inputdesk', $Path) 30; Read-Json $Path }

# ------------------------------------------------------------------------------------------------ phases

Log "== phase $Phase$(if ($Tag) { " tag=$Tag" })$(if ($Method) { " method=$Method" })"
switch ($Phase) {
    'build' {
        # The display never sleeps: VBoxManage screenshotpng fails (E_FAIL) while the guest display is off.
        $null = & powercfg.exe /change monitor-timeout-ac 0 2>&1
        $fw = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
        $wpf = Join-Path $fw 'WPF'
        Remove-Item -LiteralPath $Exe -Force -ErrorAction SilentlyContinue
        $o = & (Join-Path $fw 'csc.exe') /nologo /target:winexe /platform:x64 /optimize "/out:$Exe" "/r:$wpf\UIAutomationClient.dll" "/r:$wpf\UIAutomationTypes.dll" `
            "/r:$wpf\WindowsBase.dll" '/r:System.Web.Extensions.dll' '/r:System.Windows.Forms.dll' '/r:System.Drawing.dll' $Src 2>&1
        foreach ($l in @($o)) { Log "  csc: $l" }
        if (-not (Test-Path -LiteralPath $Exe)) { 'M3S BUILD FAIL'; break }
        New-Item -ItemType Directory -Force $ClientDir | Out-Null
        Copy-Item -LiteralPath $Exe -Destination (Join-Path $ClientDir 'Purge.exe') -Force
        "M3S BUILD OK $((Get-Item $Exe).Length)"
    }
    'install' {
        $rec = [ordered]@{ t = (NowIso); fixture = $null; install = @(); check = @(); ui = $false }
        if (Test-Path -LiteralPath $Payload) { Remove-Item -LiteralPath $Payload -Recurse -Force }
        Expand-Archive -LiteralPath (Join-Path $Bin 'payload.zip') -DestinationPath $Payload -Force
        $common = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\cr\install\install.ps1', '-SkipBuild',
                    '-Engine', (Join-Path $Payload 'purge-engine.exe'), '-Broker', (Join-Path $Payload 'purge-broker.exe'), '-Kb', (Join-Path $Payload 'kb'))
        $runs = @(@{ name = 'Purge'; args = @('-UiPublishDir', $ClientDir); check = @() })
        if (Test-Path -LiteralPath (Join-Path $Payload 'ui\Purge.exe')) {
            $rec.ui = $true
            $sm = Join-Path $Bin 'startmenu-ui'; New-Item -ItemType Directory -Force $sm | Out-Null
            $runs += @{ name = 'PurgeUI'; args = @('-UiPublishDir', (Join-Path $Payload 'ui'), '-ProgramFilesDir', $PFUI, '-StartMenuDir', $sm); check = @('-ProgramFilesDir', $PFUI, '-StartMenuDir', $sm) }
        }
        $ok = $true
        foreach ($r in $runs) {
            $o = @(& powershell.exe @($common + $r.args) 2>&1 | ForEach-Object { "$_" }); $code = $LASTEXITCODE
            foreach ($l in $o) { Log "  install $($r.name): $l" }
            $rec.install += [ordered]@{ name = $r.name; exit = $code; tail = @($o | Select-Object -Last 5) }
            $c = @(& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'C:\cr\install\install.ps1' -Check @($r.check) 2>&1 | ForEach-Object { "$_" }); $cc = $LASTEXITCODE
            $rec.check += [ordered]@{ name = $r.name; exit = $cc; tail = @($c | Select-Object -Last 5) }
            if ($code -ne 0 -or $cc -ne 0) { $ok = $false }
        }
        if ($Tag) { $rec.fixture = Install-Fixture $Tag }
        $rec.uac = Get-UacValues
        Write-JsonFile $rec (Join-Path $Out 'install.json') 8
        "M3S INSTALL $(if ($ok) { 'OK' } else { 'FAIL' }) ui=$($rec.ui) fixture=$Tag"
    }
    'uac-check' {
        $v = Get-UacValues
        Write-JsonFile $v (Join-Path $Out "uac-check$(if ($Tag) { "-$Tag" }).json")
        "M3S UAC-CHECK $(ConvertTo-Json $v -Compress)"
    }
    'uac-silent' {
        $before = Get-UacValues
        $err = $null
        try { Set-ItemProperty -LiteralPath $PolKey -Name 'ConsentPromptBehaviorAdmin' -Value 0 -Type DWord -ErrorAction Stop } catch { $err = $_.Exception.Message }
        $after = Get-UacValues
        $ok = (-not $err -and "$($after.ConsentPromptBehaviorAdmin)" -eq '0' -and "$($after.EnableLUA)" -eq '1')
        $rec = [ordered]@{ t = (NowIso); set = [ordered]@{ ConsentPromptBehaviorAdmin = 0 }; before = $before; after = $after; error = $err; ok = $ok }
        Write-JsonFile $rec (Join-Path $Out 'uac-silent.json') 8
        "M3S UAC-SILENT $(if ($ok) { 'OK' } else { 'FAIL' }) before=$($before.ConsentPromptBehaviorAdmin)/$($before.PromptOnSecureDesktop)/$($before.EnableLUA) after=$($after.ConsentPromptBehaviorAdmin)/$($after.PromptOnSecureDesktop)/$($after.EnableLUA) error=$err"
    }
    'pack' {
        $zip = 'C:\cr\out\m3-sec.zip'
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path (Join-Path $Out '*') -DestinationPath $zip -Force
        "M3S PACK $((Get-Item $zip).Length)"
    }

    # ------------------------------------------------------------------------------------------ m3-broker
    'broker-case' {
        if (-not $Tag) { throw 'broker-case needs -Tag <case id>' }
        $rec = Invoke-BrokerCase $Tag
        New-Item -ItemType Directory -Force (Join-Path $Out 'broker-cases') | Out-Null
        Write-JsonFile $rec (Join-Path $Out "broker-cases\$Tag.json") 12
        $ev = @($rec.events | ForEach-Object { $_.id }) -join ','
        "M3S CASE $Tag exit=$($rec.exit_code) exited=$($rec.broker_exited) events=$ev data_root_changed=$($rec.data_root_changed) planted_changed=$($rec.planted_changed) error=$($rec.error)"
    }
    'broker-summary' {
        $cases = @(Get-ChildItem -LiteralPath (Join-Path $Out 'broker-cases') -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { Read-Json $_.FullName })
        $sum = [ordered]@{ schema = 'purge.rig.m3sec.broker/1'; t = (NowIso); uac = (Get-UacValues); uac_silent = (Read-Json (Join-Path $Out 'uac-silent.json')); install = (Read-Json (Join-Path $Out 'install.json')); cases = $cases }
        Write-JsonFile $sum (Join-Path $Out 'm3-broker.json') 14
        "M3S BROKER-SUMMARY cases=$($cases.Count)"
    }

    # ----------------------------------------------------------------------------------------- m3-consent
    'consent-start' {
        $spec = [ordered]@{ broker = $Broker; launch = 'runas'; window = $true; connects = 1; connect_wait_ms = 20000; exit_wait_ms = 120000; go = $true
                            steps = @(@{ op = 'prepare'; program = $FixProgram }, @{ op = 'run'; quiet = $true; repeat = 8 }, @{ op = 'scan' },
                                      @{ op = 'plan_execute'; select = 'all'; repeat = 8; restore_point = 'off' }) }
        $s = Start-Client 'consent' $spec
        Write-JsonFile $s (Join-Path $s.dir 'start.json')
        $l = $null
        if (Wait-File (Join-Path $s.dir 'launched.json') 60) { $l = Read-Json (Join-Path $s.dir 'launched.json') }
        "M3S CONSENT-START client=$($s.client_pid) window_fg=$($s.window_foreground) launch_ok=$(if ($l) { $l.ok }) broker=$(if ($l) { $l.broker_pid })"
    }
    'consent-next' {
        Use-CurrentClient
        $k = [int]$Tag
        $r = Get-Ready $k $WaitSec
        if (-not $r) { "M3S DIALOG $k ready=False"; break }
        $j = Get-JournalState
        [IO.File]::WriteAllText((Join-Path $CDir "journal-before-$k.json"), (ConvertTo-Json $j -Depth 4))
        [IO.File]::WriteAllText((Join-Path $CDir "go-$k"), (NowIso))
        $d = Invoke-Observe ([int]$r.broker_pid) (Join-Path $CDir "dialog-$k.json") 120000
        $null = Wait-File (Join-Path $CDir "consent-shown-$k.json") 15
        $sh = Read-Json (Join-Path $CDir "consent-shown-$k.json")
        "M3S DIALOG $k method=$($r.method) $(Format-Dialog $d) shown_code=$(if ($sh) { $sh.params.code }) plan_code=$($r.plan_code)"
    }
    'consent-attack' {
        Use-CurrentClient
        $k = [int]$Tag
        $r = Read-Json (Join-Path $CDir "ready-$k.json")
        $bp = [int]$r.broker_pid
        $pre = Invoke-Observe $bp (Join-Path $CDir "pre-$k-$Method.json")
        $j0 = Get-JournalState
        $null = Invoke-Sec @('focus', "$bp", (Join-Path $CDir "focus-$k-$Method.json")) 30
        $dspec = [ordered]@{ out = (Join-Path $CDir "drive-$k-$Method.json"); broker_pid = $bp; method = $Method; mode = 'attack'
                             targets = @(Get-AttackTargets $pre); seen = (Join-Path $CDir "pre-$k-$Method.json") }
        $sp = Join-Path $CDir "drive-spec-$k-$Method.json"
        Write-Spec $dspec $sp
        Remove-Item -LiteralPath $dspec.out -Force -ErrorAction SilentlyContinue
        Start-Medium $Exe "drive `"$sp`"" $Tasks.drive
        $null = Wait-File $dspec.out 180
        Stop-Task $Tasks.drive
        Start-Sleep -Seconds 1
        $drive = Read-Json $dspec.out
        $post = Invoke-Observe $bp (Join-Path $CDir "post-$k-$Method.json") 3000
        $j1 = Get-JournalState
        $effects = [ordered]@{
            dialog_gone       = (-not ($post -and $post.found))
            hwnd_changed      = ($pre -and $post -and $post.found -and "$($post.hwnd)" -ne "$($pre.hwnd)")
            verify_changed    = ($pre -and $post -and $pre.verify -and $post.verify -and "$($pre.verify.toggle)" -ne "$($post.verify.toggle)")
            page_changed      = ($pre -and $post -and $post.found -and "$($pre.page)" -ne "$($post.page)")
            primary_enabled_changed = ($pre -and $post -and $post.found -and "$($pre.primary_enabled)" -ne "$($post.primary_enabled)" -and -not $pre.primary_enabled)
            answered          = (Test-Path -LiteralPath (Join-Path $CDir "consent-result-$k.json"))
            journal_changed   = (-not (Test-JournalSame $j0 $j1))
            uninstaller_ran   = (Test-Path -LiteralPath $FixMarker)
        }
        $n = @($effects.Values | Where-Object { $_ -eq $true }).Count
        $rec = [ordered]@{ k = $k; method = $Method; kind = $r.method; level = 'medium'; drive = $drive; pre = $pre; post = $post; effects = $effects; effect_count = $n }
        Write-JsonFile $rec (Join-Path $CDir "attack-$k-$Method.json") 12
        $att = @($drive.attempts | Where-Object { -not $_.skipped })
        "M3S ATTACK $k $Method driver_il=$($drive.driver_il) attempts=$($att.Count) reached=$(@($att | Where-Object { $_.reached }).Count) effects=$n fg=$(@($att | Where-Object { $_.foreground_is_dialog }).Count)/$($att.Count)"
    }
    'consent-control' {
        Use-CurrentClient
        $k = [int]$Tag
        $r = Read-Json (Join-Path $CDir "ready-$k.json")
        $bp = [int]$r.broker_pid
        $pre = Invoke-Observe $bp (Join-Path $CDir "cpre-$k-$Method.json")
        $j0 = Get-JournalState
        $null = Invoke-Sec @('focus', "$bp", (Join-Path $CDir "cfocus-$k-$Method.json")) 30
        $dspec = [ordered]@{ out = (Join-Path $CDir "control-drive-$k-$Method.json"); broker_pid = $bp; method = $Method; mode = 'control'; seen = (Join-Path $CDir "cpre-$k-$Method.json") }
        $sp = Join-Path $CDir "control-spec-$k-$Method.json"
        Write-Spec $dspec $sp
        $null = Invoke-Sec @('drive', $sp) 120
        $drive = Read-Json $dspec.out
        $null = Wait-File (Join-Path $CDir "consent-result-$k.json") 30
        $res = Read-Json (Join-Path $CDir "consent-result-$k.json")
        $j1 = Get-JournalState
        $rec = [ordered]@{ k = $k; method = $Method; kind = $r.method; level = 'high'; drive = $drive; pre = $pre; result_kind = $(if ($res) { $res.kind })
                           declined = ($res -and $res.kind -eq 'consent_declined'); journal_changed = (-not (Test-JournalSame $j0 $j1)); uninstaller_ran = (Test-Path -LiteralPath $FixMarker) }
        Write-JsonFile $rec (Join-Path $CDir "control-$k-$Method.json") 12
        "M3S CONTROL $k $Method driver_il=$($drive.driver_il) declined=$($rec.declined) journal_changed=$($rec.journal_changed)"
    }
    'consent-approve' {
        Use-CurrentClient
        $k = [int]$Tag
        $r = Read-Json (Join-Path $CDir "ready-$k.json")
        $bp = [int]$r.broker_pid
        $j0 = Get-JournalState
        $pspec = [ordered]@{ out = (Join-Path $CDir "press-$k.json"); broker_pid = $bp; tick = $true; button = 100; arm_wait_ms = 1600; wait_ms = 15000 }
        Write-Spec $pspec (Join-Path $CDir "press-spec-$k.json")
        $null = Invoke-Sec @('press', (Join-Path $CDir "press-spec-$k.json")) 60
        $null = Wait-File (Join-Path $CDir "consent-result-$k.json") $WaitSec
        $res = Read-Json (Join-Path $CDir "consent-result-$k.json")
        $j1 = Get-JournalState
        $jb = Read-Json (Join-Path $CDir "journal-before-$k.json")
        $rec = [ordered]@{ k = $k; kind = $r.method; press = (Read-Json $pspec.out); result_kind = $(if ($res) { $res.kind }); response = $(if ($res) { $res.response })
                           journal_changed = (-not (Test-JournalSame $(if ($jb) { $jb } else { $j0 }) $j1)); uninstaller_ran = (Test-Path -LiteralPath $FixMarker); fixture_marker = (Read-Json $FixMarker) }
        Write-JsonFile $rec (Join-Path $CDir "approve-$k.json") 12
        $outcome = $(if ($res -and $res.response -and $res.response.result) { "$($res.response.result.outcome)" } else { '' })
        "M3S APPROVE $k method=$($r.method) result=$($rec.result_kind) outcome=$outcome journal_changed=$($rec.journal_changed) uninstaller_ran=$($rec.uninstaller_ran)"
    }
    'client-end' {
        Use-CurrentClient
        $null = Wait-File (Join-Path $CDir 'client.json') $WaitSec
        Stop-Task $Tasks.client
        $client = Read-Json (Join-Path $CDir 'client.json')
        $col = { param($p) @(Get-ChildItem -LiteralPath $CDir -Filter $p -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { [ordered]@{ file = $_.Name; data = (Read-Json $_.FullName) } }) }
        $sum = [ordered]@{
            schema = "purge.rig.m3sec.$Tag/1"; t = (NowIso); uac = (Get-UacValues); uac_silent = (Read-Json (Join-Path $Out 'uac-silent.json')); install = (Read-Json (Join-Path $Out 'install.json'))
            start = (Read-Json (Join-Path $CDir 'start.json')); launched = (Read-Json (Join-Path $CDir 'launched.json')); client = $client
            dialogs = (& $col 'dialog-*.json'); shown = (& $col 'consent-shown-*.json'); ready = (& $col 'ready-*.json'); results = (& $col 'consent-result-*.json')
            attacks = (& $col 'attack-*.json'); controls = (& $col 'control-[0-9]*.json'); approves = (& $col 'approve-*.json'); arms = (& $col 'arm-*.json')
            pages = (& $col 'page-*.json'); journal_start = (Read-Json (Join-Path $CDir 'journal-start.json')); journal_end = (Get-JournalState)
            fixture_marker = (Read-Json $FixMarker); fixture_arp_present = (Test-Path -LiteralPath $FixArp)
        }
        $name = $(if ($Tag -eq 'consent') { 'm3-consent.json' } else { "m3-uac-flow-$Tag.json" })
        Write-JsonFile $sum (Join-Path $Out $name) 16
        "M3S CLIENT-END $Tag exit=$(if ($client) { $client.exit_code }) dialogs=$(@($sum.dialogs).Count) attacks=$(@($sum.attacks).Count) controls=$(@($sum.controls).Count) approves=$(@($sum.approves).Count)"
    }

    # --------------------------------------------------------------------------------------------- m3-uac
    'ui-start' {
        $exe = Join-Path $PFUI 'Purge.exe'
        $rec = [ordered]@{ t = (NowIso); ui_exe = $exe; present = (Test-Path -LiteralPath $exe); data_root_before = @(Get-TreeList $DataRoot); since = (Get-Date).AddSeconds(-2).ToString('o') }
        if (-not $rec.present) { Write-JsonFile $rec (Join-Path $Out 'ui-start.json') 8; 'M3S UI-START present=False'; break }
        $l = LaunchMedium -Exe $exe -TaskName $Tasks.ui -StartTimeoutSec 60
        $rec.ui_pid = $l.pid
        Start-Sleep -Seconds 8
        if ($l.pid) { $null = Invoke-Sec @('focuswin', "$($l.pid)", (Join-Path $Out 'ui-focus.json')) 60 }
        $spec = [ordered]@{ out = (Join-Path $Out 'ui-drive-start.json'); pid = $l.pid; action = 'start-uninstall'; program = $FixName; wait_ms = 90000 }
        Write-Spec $spec (Join-Path $Out 'ui-spec-start.json')
        $null = Invoke-Sec @('ui', (Join-Path $Out 'ui-spec-start.json')) 180
        $rec.drive = Read-Json $spec.out
        $c = Wait-Consent 45
        $rec.consent_pid = $(if ($c) { $c.Id })
        Start-Sleep -Seconds 2
        $rec.inputdesk = Get-InputDesk (Join-Path $Out 'ui-inputdesk.json')
        Write-JsonFile $rec (Join-Path $Out 'ui-start.json') 8
        "M3S UI-START present=True ui_pid=$($l.pid) consent=$(if ($c) { $c.Id } else { 'none' }) steps=$(@($rec.drive.steps).Count)"
    }
    'ui-result' {
        $st = Read-Json (Join-Path $Out 'ui-start.json')
        $rec = [ordered]@{ t = (NowIso); present = ($st -and $st.present) }
        if ($rec.present) {
            Start-Sleep -Seconds 3
            $spec = [ordered]@{ out = (Join-Path $Out 'ui-drive-bar.json'); pid = $st.ui_pid; action = 'read-bar'; wait_ms = 30000 }
            Write-Spec $spec (Join-Path $Out 'ui-spec-bar.json')
            $null = Invoke-Sec @('ui', (Join-Path $Out 'ui-spec-bar.json')) 120
            $bar = Read-Json $spec.out
            $rec.bar_found = ($bar -and $bar.bar_found)
            $rec.bar = $bar
            $rec.broker_processes = @(Get-ProcList | Where-Object { $_.name -ieq 'purge-broker.exe' } | ForEach-Object { $_.path })
            $rec.consent_still_up = (@(Get-Process consent -ErrorAction SilentlyContinue).Count -gt 0)
            $rec.events = @(Get-PurgeEvents ([datetime]$st.since))
            $rec.data_root_diff = @(Compare-TreeList @($st.data_root_before) (Get-TreeList $DataRoot))
            $rec.data_root_changed = ($rec.data_root_diff.Count -gt 0)
            $rec.fixture_arp_present = (Test-Path -LiteralPath $FixArp)
            $rec.uninstaller_ran = (Test-Path -LiteralPath $FixMarker)
            Stop-Task $Tasks.ui
            Get-ProcList | Where-Object { $_.path -and $_.path -ieq (Join-Path $PFUI 'Purge.exe') } | ForEach-Object { Stop-Process -Id $_.pid -Force -ErrorAction SilentlyContinue }
        }
        Write-JsonFile $rec (Join-Path $Out 'ui-result.json') 8
        "M3S UI-RESULT present=$($rec.present) bar=$($rec.bar_found) brokers=$(@($rec.broker_processes).Count) data_root_changed=$($rec.data_root_changed) arp=$($rec.fixture_arp_present)"
    }
    'flow-start' {
        if ($Tag -notin 'no', 'yes') { throw 'flow-start needs -Tag no|yes' }
        $spec = [ordered]@{ broker = $Broker; launch = 'runas'; window = $true; connects = 1; connect_wait_ms = 20000; exit_wait_ms = 120000; go = $true }
        if ($Tag -eq 'yes') {
            $spec.steps = @(@{ op = 'prepare'; program = $FixProgram }, @{ op = 'run'; quiet = $true; repeat = 1 }, @{ op = 'scan' },
                            @{ op = 'plan_execute'; select = 'all'; repeat = 1; restore_point = 'off' })
        } else { $spec.steps = @(@{ op = 'shutdown' }) }
        $before = @(Get-TreeList $DataRoot)
        $s = Start-Client $Tag $spec
        $c = Wait-Consent 45
        Start-Sleep -Seconds 2
        $desk = Get-InputDesk (Join-Path $s.dir 'inputdesk-prompt.json')
        $rec = [ordered]@{ tag = $Tag; client = $s; consent_pid = $(if ($c) { $c.Id }); consent_session = $(if ($c) { $c.SessionId }); inputdesk = $desk; data_root_before = $before; since = (Get-Date).AddSeconds(-60).ToString('o') }
        Write-JsonFile $rec (Join-Path $s.dir 'start.json') 8
        "M3S FLOW-START $Tag client=$($s.client_pid) window_fg=$($s.window_foreground) consent=$(if ($c) { $c.Id } else { 'none' }) inputdesk_open=$($desk.open) inputdesk_error=$($desk.error)"
    }
    'flow-launch' {
        Use-CurrentClient
        $null = Wait-File (Join-Path $CDir 'launched.json') $WaitSec
        $l = Read-Json (Join-Path $CDir 'launched.json')
        $st = Read-Json (Join-Path $CDir 'start.json')
        $rec = [ordered]@{ tag = $Tag; launched = $l; consent_still_up = (@(Get-Process consent -ErrorAction SilentlyContinue).Count -gt 0) }
        if ($l -and $l.broker_pid) { $null = Invoke-Sec @('procinfo', "$($l.broker_pid)", (Join-Path $CDir 'broker-proc.json')) 30; $rec.broker = Read-Json (Join-Path $CDir 'broker-proc.json') }
        if ($Tag -eq 'no') {
            Start-Sleep -Seconds 3
            $rec.broker_processes = @(Get-ProcList | Where-Object { $_.name -ieq 'purge-broker.exe' } | ForEach-Object { $_.path })
            $rec.events = @(Get-PurgeEvents ([datetime]$st.since))
            $rec.data_root_diff = @(Compare-TreeList @($st.data_root_before) (Get-TreeList $DataRoot))
            $rec.data_root_changed = ($rec.data_root_diff.Count -gt 0)
            $null = Wait-File (Join-Path $CDir 'client.json') 30
            $rec.client = Read-Json (Join-Path $CDir 'client.json')
            Stop-Task $Tasks.client
        }
        Write-JsonFile $rec (Join-Path $CDir 'flow-launch.json') 8
        "M3S FLOW-LAUNCH $Tag ok=$(if ($l) { $l.ok }) error=$(if ($l) { $l.error }) broker=$(if ($l) { $l.broker_pid }) broker_il=$(if ($rec.broker) { $rec.broker.il }) broker_user=$(if ($rec.broker) { $rec.broker.user })"
    }
    'arm-next' {
        # The first appearance of dialog k: the arming test (a click before the delay does nothing), then an observe.
        Use-CurrentClient
        $k = [int]$Tag
        $r = Get-Ready $k $WaitSec
        if (-not $r) { "M3S ARM $k ready=False"; break }
        [IO.File]::WriteAllText((Join-Path $CDir "journal-before-$k.json"), (ConvertTo-Json (Get-JournalState) -Depth 4))
        $aspec = [ordered]@{ out = (Join-Path $CDir "arm-$k.json"); broker_pid = [int]$r.broker_pid; go_file = (Join-Path $CDir "go-$k"); wait_ms = 300000
                             renavigate = $false; tick = $false; early_ms = 300; late_ms = 1800; click_late = $false }
        Write-Spec $aspec (Join-Path $CDir "spec-arm-$k.json")
        $null = Invoke-Sec @('arm', (Join-Path $CDir "spec-arm-$k.json")) 400
        $a = Read-Json $aspec.out
        $d = Invoke-Observe ([int]$r.broker_pid) (Join-Path $CDir "dialog-$k.json")
        $null = Wait-File (Join-Path $CDir "consent-shown-$k.json") 10
        $sh = Read-Json (Join-Path $CDir "consent-shown-$k.json")
        "M3S ARM $k method=$($r.method) found=$($a.found) fg_at_found=$($a.foreground_at_found) early_ms=$($a.early_click_ms) alive_after_early=$($a.dialog_alive_after_early) enabled_late=$($a.primary_enabled_late) $(Format-Dialog $d) shown_code=$(if ($sh) { $sh.params.code })"
    }
    'page-next' {
        Use-CurrentClient
        $k = [int]$Tag
        $r = Read-Json (Join-Path $CDir "ready-$k.json")
        $bp = [int]$r.broker_pid
        $pspec = [ordered]@{ out = (Join-Path $CDir "press-page-$k.json"); broker_pid = $bp; tick = $false; button = 9001; arm_wait_ms = 200; wait_ms = 10000 }
        Write-Spec $pspec (Join-Path $CDir "spec-page-$k.json")
        $null = Invoke-Sec @('press', (Join-Path $CDir "spec-page-$k.json")) 60
        $tmp = Join-Path $CDir "page-$k-tmp.json"
        $d = Invoke-Observe $bp $tmp
        $f = Join-Path $CDir ("page-$k-{0:D2}.json" -f [int]$d.page)
        Move-Item -LiteralPath $tmp -Destination $f -Force
        "M3S PAGE $k last=$([bool]$d.has_primary) $(Format-Dialog $d)"
    }
    'arm-current' {
        # The last page again (Back, Next restarts the delay): tick the box at +100 ms, click the button at +300 ms.
        Use-CurrentClient
        $k = [int]$Tag
        $r = Read-Json (Join-Path $CDir "ready-$k.json")
        $aspec = [ordered]@{ out = (Join-Path $CDir "arm-$k.json"); broker_pid = [int]$r.broker_pid; wait_ms = 10000
                             renavigate = $true; tick = $true; early_ms = 300; late_ms = 1800; click_late = $false }
        Write-Spec $aspec (Join-Path $CDir "spec-arm-$k.json")
        $null = Invoke-Sec @('arm', (Join-Path $CDir "spec-arm-$k.json")) 120
        $a = Read-Json $aspec.out
        $d = Invoke-Observe ([int]$r.broker_pid) (Join-Path $CDir "dialog-$k-last.json")
        "M3S ARM $k renavigated=$($a.renavigated) early_ms=$($a.early_click_ms) alive_after_early=$($a.dialog_alive_after_early) enabled_after_early=$($a.primary_enabled_after_early) enabled_late=$($a.primary_enabled_late) $(Format-Dialog $d)"
    }
    'std-start' {
        # T8: a standard user (purgestd) runs the rig client; the host types the administrator's password at the
        # credential prompt. The password of purgestd is random, used once here and never written anywhere.
        $dir = Get-ConsentDir 'std'
        if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
        Grant-UsersModify $dir
        Set-CurrentClient $dir
        $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
        $bytes = New-Object byte[] 20; $rng.GetBytes($bytes)
        $pw = 'Px9!' + (-join @($bytes | ForEach-Object { $chars[$_ % $chars.Length] }))
        $null = & net.exe user $StdUser /delete 2>&1
        $o = & net.exe user $StdUser $pw /add /passwordchg:no /expires:never 2>&1
        $rec = [ordered]@{ t = (NowIso); user_created = ($LASTEXITCODE -eq 0); net = "$o" -replace [regex]::Escape($pw), '***'; data_root_before = @(Get-TreeList $DataRoot); since = (Get-Date).AddSeconds(-2).ToString('o') }
        $spec = [ordered]@{ out = $dir; broker = $Broker; launch = 'runas'; connects = 3; connect_wait_ms = 15000; hold_ms = 60000; exit_wait_ms = 5000; go = $false; steps = @(@{ op = 'shutdown' }) }
        Write-Spec $spec (Join-Path $dir 'spec.json')
        $sec = ConvertTo-SecureString $pw -AsPlainText -Force
        $cred = New-Object Management.Automation.PSCredential(".\$StdUser", $sec)
        $pw = $null
        try {
            $p = Start-Process -FilePath $ClientImg -ArgumentList @('client', "`"$(Join-Path $dir 'spec.json')`"") -Credential $cred -LoadUserProfile -WorkingDirectory $PF -PassThru
            $rec.client_pid = $p.Id
        } catch { $rec.start_error = $_.Exception.Message }
        $c = Wait-Consent 60
        $rec.consent_pid = $(if ($c) { $c.Id })
        Start-Sleep -Seconds 2
        $rec.inputdesk = Get-InputDesk (Join-Path $dir 'inputdesk-prompt.json')
        Write-JsonFile $rec (Join-Path $dir 'start.json') 8
        "M3S STD-START user_created=$($rec.user_created) client=$($rec.client_pid) consent=$(if ($c) { $c.Id } else { 'none' }) error=$($rec.start_error)"
    }
    'std-result' {
        Use-CurrentClient
        $st = Read-Json (Join-Path $CDir 'start.json')
        $null = Wait-File (Join-Path $CDir 'launched.json') $WaitSec
        $l = Read-Json (Join-Path $CDir 'launched.json')
        $rec = [ordered]@{ t = (NowIso); launched = $l; consent_still_up = (@(Get-Process consent -ErrorAction SilentlyContinue).Count -gt 0) }
        $bp = $null
        if ($l -and $l.broker_pid) {
            $null = Invoke-Sec @('procinfo', "$($l.broker_pid)", (Join-Path $CDir 'broker-proc.json')) 30
            $rec.broker = Read-Json (Join-Path $CDir 'broker-proc.json')
            try { $bp = [Diagnostics.Process]::GetProcessById([int]$l.broker_pid); $null = $bp.Handle } catch { $bp = $null }
        }
        $null = Wait-File (Join-Path $CDir 'client.json') 90
        $rec.client = Read-Json (Join-Path $CDir 'client.json')
        if ($bp) { if ($bp.WaitForExit(90000)) { $rec.broker_exit_code = $bp.ExitCode } else { $rec.broker_exit_code = 'running' } }
        Start-Sleep -Seconds 2
        $rec.events = @(Get-PurgeEvents ([datetime]$st.since))
        $rec.data_root_diff = @(Compare-TreeList @($st.data_root_before) (Get-TreeList $DataRoot))
        $rec.data_root_changed = ($rec.data_root_diff.Count -gt 0)
        $null = & net.exe user $StdUser /delete 2>&1
        $rec.start = $st
        Write-JsonFile $rec (Join-Path $Out 'm3-uac-std.json') 10
        $cn = @($rec.client.connects)
        "M3S STD-RESULT launch_ok=$(if ($l) { $l.ok }) broker_user=$(if ($rec.broker) { $rec.broker.user }) precheck=$($rec.client.precheck) opened=$(@($cn | Where-Object { $_.opened }).Count) open_error=$(@($cn | ForEach-Object { $_.open_error }) -join ',') exit=$($rec.broker_exit_code)"
    }
    'uac-summary' {
        $no = Get-ConsentDir 'no'
        $sum = [ordered]@{
            schema = 'purge.rig.m3sec.uac/1'; t = (NowIso); uac = (Read-Json (Join-Path $Out 'uac-check-start.json')); install = (Read-Json (Join-Path $Out 'install.json'))
            ui_start = (Read-Json (Join-Path $Out 'ui-start.json')); ui_result = (Read-Json (Join-Path $Out 'ui-result.json'))
            no = [ordered]@{ start = (Read-Json (Join-Path $no 'start.json')); launch = (Read-Json (Join-Path $no 'flow-launch.json')) }
            yes = (Read-Json (Join-Path $Out 'm3-uac-flow-yes.json')); yes_launch = (Read-Json (Join-Path (Get-ConsentDir 'yes') 'flow-launch.json'))
            std = (Read-Json (Join-Path $Out 'm3-uac-std.json'))
        }
        Write-JsonFile $sum (Join-Path $Out 'm3-uac.json') 18
        "M3S UAC-SUMMARY ui=$([bool]$sum.ui_result) no=$([bool]$sum.no.launch) yes=$([bool]$sum.yes) std=$([bool]$sum.std)"
    }
}
