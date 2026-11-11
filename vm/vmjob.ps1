<#
  Runs a PowerShell script elevated inside the test VM through agent.ps1 and prints its log.
    vmjob.ps1 -Script <local .ps1> [-TimeoutSec 1800]
  Needs: VM running, agent.ps1 started (see start-agent in README-vm.md), scratch password file.
#>
param(
    [Parameter(Mandatory)] [string] $Script,
    [int] $TimeoutSec = 1800,
    [string] $Vm = "Inbound-Win11-Test",
    [string] $PasswordFile = "$env:VMPWFILE"
)
$ErrorActionPreference = "Stop"
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$g = @($Vm, "--username", "tester", "--passwordfile", $PasswordFile)
$name = "{0:yyyyMMdd-HHmmss}-{1}" -f (Get-Date), [IO.Path]::GetFileName($Script)
& $vb guestcontrol @g copyto --target-directory "C:\cr\stage\" $Script 2>$null
if ($LASTEXITCODE) { & $vb guestcontrol @g mkdir --parents "C:\cr\stage"; & $vb guestcontrol @g copyto --target-directory "C:\cr\stage\" $Script }
& $vb guestcontrol @g mv "C:\cr\stage\$([IO.Path]::GetFileName($Script))" "C:\cr\jobs\$name"
$t = (Get-Date).AddSeconds($TimeoutSec)
do {
    Start-Sleep 3
    $done = & $vb guestcontrol @g stat "C:\cr\jobs\$name.done" 2>$null
} while ($LASTEXITCODE -ne 0 -and (Get-Date) -lt $t)
& $vb guestcontrol @g run --exe "C:\Windows\System32\cmd.exe" --wait-stdout -- cmd /c "type C:\cr\jobs\$name.log"
