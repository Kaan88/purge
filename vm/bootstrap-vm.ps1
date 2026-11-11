<#
Bootstraps the rig agent in a freshly installed guest without a UAC click (vm\RIG.md §1, Clean-Pro).

Preconditions (set by `VBoxManage unattended install ... --post-install-command`):
  HKLM\...\Policies\System\ConsentPromptBehaviorAdmin = 0, so an administrator's elevation request is
  granted without a prompt; guest additions installed; `tester` logged on.

Steps: copy agent.ps1 to C:\cr, start it elevated through guestcontrol, wait for it, push the tools,
run guest\setup-base.ps1 (registers PurgeRigAgent, autologon check, installers), then restore
ConsentPromptBehaviorAdmin to the Windows default (5) so the snapshot is not left with silent elevation.

    $env:VMPWFILE = '<file with the guest password>'
    .\vm\bootstrap-vm.ps1 -VmName Purge-CleanPro
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$VmName)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'rig.ps1') -VmName $VmName

# Right after setup the guest additions report run level 3 before the execution service accepts sessions,
# and VirtualBox's post-install script may still reboot the guest: retry for up to 15 min.
$deadline = (Get-Date).AddMinutes(15)
do {
    $r = Invoke-Guest @('mkdir', '--parents', 'C:\cr\jobs')
    if ($r.code -eq 0) { break }
    Write-RigLog "  guest control not ready: $((($r.out -join ' ') -split 'Details')[0].Trim())"
    Start-Sleep -Seconds 20
} while ((Get-Date) -lt $deadline)
if ($r.code -ne 0) { throw "mkdir C:\cr\jobs failed: $($r.out -join ' ')" }
$r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\', (Join-Path $PSScriptRoot 'agent.ps1'))
if ($r.code -ne 0) { throw "copyto agent.ps1 failed: $($r.out -join ' ')" }
Write-RigLog 'agent.ps1 copied; arming an HKCU RunOnce entry that starts it elevated at the next logon'
# guestcontrol runs with tester's filtered (medium) token outside the console session, where
# Start-Process -Verb RunAs cannot elevate. In the autologon session it can, silently, because
# ConsentPromptBehaviorAdmin=0. So: RunOnce (writable at medium integrity, removed after it fires) + reboot.
# The launcher is a .cmd file so no quotes cross guestcontrol (PowerShell 5.1 mangles nested quotes).
$r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\', (Join-Path $PSScriptRoot 'guest\start-agent-elevated.cmd'))
if ($r.code -ne 0) { throw "copyto start-agent-elevated.cmd failed: $($r.out -join ' ')" }
$r = Invoke-GuestCmd 'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /v PurgeAgentBootstrap /t REG_SZ /f /d C:\cr\start-agent-elevated.cmd'
if ($r.code -ne 0) { throw "RunOnce entry failed: $($r.out -join ' ')" }
Write-RigLog "  $((Invoke-GuestCmd 'reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /v PurgeAgentBootstrap').out -join ' ')"
$null = Invoke-Guest @('run', '--exe', 'C:\Windows\System32\shutdown.exe', '--', '/r', '/t', '0')
Write-RigLog 'guest rebooting; waiting for autologon to start the agent'
Start-Sleep -Seconds 45

Wait-Agent -TimeoutSec 900
Push-Tools
Invoke-SetupBase

$fix = @'
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty $k -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord
"ConsentPromptBehaviorAdmin=$((Get-ItemProperty $k).ConsentPromptBehaviorAdmin) (Windows default 5 restored)"
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
"AutoAdminLogon=$($wl.AutoAdminLogon) AutoLogonCount=$($wl.AutoLogonCount) DefaultUserName=$($wl.DefaultUserName)"
'@
$j = Invoke-GuestJob -Text $fix -Name 'uac-default' -TimeoutSec 120
$j.log

# Eject the unattended install media (the aux .viso still boots Windows Setup). Left attached, the next cold
# boot of an offline snapshot reinstalls Windows over the restored disk.
$info = ConvertFrom-MachineReadable (Invoke-VBox @('showvminfo', $script:VmName, '--machinereadable')).out
foreach ($k in @($info.Keys | Where-Object { $_ -match '^(.+)-(\d+)-(\d+)$' -and "$($info[$_])" -match '\.(iso|viso)$' })) {
    $null = $k -match '^(.+)-(\d+)-(\d+)$'
    $r = Invoke-VBox @('storageattach', $script:VmName, '--storagectl', $Matches[1], '--port', $Matches[2], '--device', $Matches[3],
        '--type', 'dvddrive', '--medium', 'emptydrive', '--forceunmount')
    Write-RigLog "ejected $($info[$k]) from $k (exit $($r.code))"
}
