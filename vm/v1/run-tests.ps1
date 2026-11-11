<#
  Host side: copies guest\ scripts into the VM and runs test-app.ps1 for each app id through the
  elevated agent, then copies C:\cr\out back to vm\results\.
    $env:VMPWFILE = <bare password file>;  .\run-tests.ps1 -Ids npp,7zip,...
#>
param([string[]] $Ids = @("npp","7zip","vscode","git","vlc","python","node","vcredist","firefox","vs"),
      [string] $Vm = "Inbound-Win11-Test")
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$g = @($Vm, "--username", "tester", "--passwordfile", $env:VMPWFILE)
& $vb guestcontrol @g mkdir --parents "C:\cr\guest"
& $vb guestcontrol @g copyto --target-directory "C:\cr\guest\" "$PSScriptRoot\guest\lib.ps1" "$PSScriptRoot\guest\apps.ps1"
$tmp = Join-Path $env:TEMP "vmjobs"; New-Item -ItemType Directory -Force $tmp | Out-Null
foreach ($id in $Ids) {
    $job = Join-Path $tmp "test-$id.ps1"
    (Get-Content "$PSScriptRoot\guest\test-app.ps1" -Raw).Replace('__ID__', $id) | Set-Content $job -Encoding utf8
    & "$PSScriptRoot\vmjob.ps1" -Script $job -TimeoutSec 5400 -Vm $Vm
}
New-Item -ItemType Directory -Force "$PSScriptRoot\results" | Out-Null
& $vb guestcontrol @g run --exe "C:\Windows\System32\cmd.exe" --wait-stdout -- cmd /c "dir /b C:\cr\out\*-result.json C:\cr\out\*-clone-*.json" |
  Where-Object { $_ } | ForEach-Object { & $vb guestcontrol @g copyfrom --target-directory "$PSScriptRoot\results\" "C:\cr\out\$_" }
