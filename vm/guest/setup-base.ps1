# Purge rig v2: one-time preparation of the clean VM before taking the 'rig-base' snapshots (vm\RIG.md §1).
# Run ONCE, elevated, through the agent (host: Push-Tools, then Invoke-SetupBase in rig.ps1). It:
#   1. creates C:\cr\bin, C:\cr\guest, C:\cr\out, C:\cr\inst, C:\cr\jobs
#   2. writes C:\cr\start-agent-direct.cmd and registers the logon task PurgeRigAgent
#      (equivalent of: schtasks /create /tn PurgeRigAgent /sc onlogon /it /rl highest /ru tester)
#   3. pauses Windows Update by policy (AU\NoAutoUpdate = 1)
#   4. downloads every installer in apps.ps1 into C:\cr\inst (official URLs only), printing size and
#      Authenticode status, and records them in C:\cr\inst\sources.json
#   5. reports autologon and anything that makes the VM not clean (test apps already installed)
. C:\cr\guest\riglib.ps1
. C:\cr\guest\apps.ps1
$User = 'tester'
$problems = New-Object System.Collections.ArrayList
Set-RunLog 'C:\cr\out\setup-base.log'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "setup-base as $($id.Name) admin=$admin on $env:COMPUTERNAME"
if (-not $admin) { Log '!! not elevated: run this through the agent'; exit 2 }

# 1. directories
foreach ($d in 'C:\cr\bin', 'C:\cr\guest', 'C:\cr\out', 'C:\cr\inst', 'C:\cr\jobs', 'C:\cr\stage') { New-Item -ItemType Directory -Force $d | Out-Null }
if (-not (Test-Path 'C:\cr\agent.ps1')) { [void]$problems.Add('C:\cr\agent.ps1 is missing (copy vm\agent.ps1 there)') }
if (-not (Test-Path $RigTool)) { [void]$problems.Add("$RigTool is missing (Push-Tools)") }

# 2. agent at logon. The task already runs elevated, so the cmd starts agent.ps1 directly (no RunAs).
$cmd = "@echo off`r`n" +
       "rem Purge rig: started at logon by the PurgeRigAgent task (interactive, highest run level).`r`n" +
       "start `"`" /NORMAL powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\cr\agent.ps1`r`n"
[IO.File]::WriteAllText('C:\cr\start-agent-direct.cmd', $cmd, (New-Object System.Text.ASCIIEncoding))
$account = "$env:COMPUTERNAME\$User"
try {
    $action = New-ScheduledTaskAction -Execute 'C:\cr\start-agent-direct.cmd' -WorkingDirectory 'C:\cr'
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $account
    $principal = New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Highest
    # Priority 4 = normal. The default 7 is below normal, and every job (installers, uninstallers, rigtool
    # snap) would inherit it from the agent. start /NORMAL in the cmd above is the second guard.
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -Priority 4
    Register-ScheduledTask -TaskName 'PurgeRigAgent' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
    $t = Get-ScheduledTask -TaskName 'PurgeRigAgent'
    Log "task PurgeRigAgent: user=$($t.Principal.UserId) logon=$($t.Principal.LogonType) runlevel=$($t.Principal.RunLevel) priority=$($t.Settings.Priority) action=$($t.Actions[0].Execute)"
} catch {
    [void]$problems.Add("PurgeRigAgent task: $($_.Exception.Message)")
    Log "!! PurgeRigAgent task: $($_.Exception.Message)"
}

# 3. Windows Update paused by policy
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $wu -Force | Out-Null
New-ItemProperty -Path $wu -Name 'NoAutoUpdate' -PropertyType DWord -Value 1 -Force | Out-Null
Log "Windows Update policy: NoAutoUpdate=$((Get-ItemProperty $wu).NoAutoUpdate)"

# 4. installers
$sources = [ordered]@{}
foreach ($a in $Apps) {
    try {
        $urls = & $a.url
        Log "[$($a.id)] $(@($urls) -join ' | ')"
        $rec = Fetch $urls $a.file
        if ("$($rec.sig)" -ne 'Valid') { Log "   note: $($a.file) signature status is $($rec.sig)" }
        $sources[$a.id] = $rec
    } catch {
        [void]$problems.Add("download $($a.id): $($_.Exception.Message)")
        Log "!! [$($a.id)] $($_.Exception.Message)"
    }
}
# Keep the URL of installers that were already present (Fetch does not know it then).
$srcFile = Join-Path $RigInst 'sources.json'
if (Test-Path $srcFile) {
    try {
        $old = Get-Content $srcFile -Raw | ConvertFrom-Json
        foreach ($k in @($sources.Keys)) { if (-not $sources[$k].url -and $old.$k.url) { $sources[$k].url = $old.$k.url } }
    } catch { }
}
Write-JsonFile $sources $srcFile
Log "wrote $srcFile"

# 5. autologon and cleanliness (the DefaultPassword value is never read or printed)
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Log "autologon: AutoAdminLogon=$($wl.AutoAdminLogon) DefaultUserName=$($wl.DefaultUserName)"
if ("$($wl.AutoAdminLogon)" -ne '1') { [void]$problems.Add('autologon is not enabled (AutoAdminLogon != 1): rig-base-off needs it') }
$entries = @(UninstallEntries)
foreach ($a in $Apps) {
    $hit = @($entries | Where-Object { "$($_.name)" -match $a.match })
    foreach ($h in $hit) { [void]$problems.Add("not clean: '$($h.name)' is installed ($($h.key))") }
}
foreach ($p in 'C:\Program Files\BCUninstaller', 'C:\Program Files\Notepad++', 'C:\Program Files\Mozilla Firefox', 'C:\Program Files\Git', 'C:\Program Files\Microsoft VS Code') {
    if (Test-Path $p) { [void]$problems.Add("not clean: $p exists") }
}
Log 'ARP entries on this machine:'
foreach ($x in $entries | Sort-Object key) { Log ("  {0} | {1} | sys={2}" -f $x.key, $x.name, $x.sys) }

if ($problems.Count) {
    Log "PROBLEMS ($($problems.Count)):"
    foreach ($p in $problems) { Log "  - $p" }
    exit 1
}
Log 'setup-base OK. Next (host): rig.ps1 Save-BaseSnapshot (rig-base, live) and Save-BaseSnapshot -Off (rig-base-off).'
exit 0
