<#
  Host helpers for driving a GUI in the VM through the elevated agent.
    . .\ui.ps1;  VmDo 'Click 120 300; Keys "{ENTER}"';  VmShot name   (-> shots\name.png)
    VmJob guest\ut-snap.ps1 @{ __ID__='npp'; __PHASE__='pre' }
#>
$script:vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$script:vm = "Inbound-Win11-Test"
function VmJob([string]$template, [hashtable]$subs = @{}, [int]$timeout = 900) {
    $text = Get-Content (Join-Path $PSScriptRoot $template) -Raw
    foreach ($k in $subs.Keys) { $text = $text.Replace($k, $subs[$k]) }
    $tmp = Join-Path $env:TEMP "vmjobs"; New-Item -ItemType Directory -Force $tmp | Out-Null
    $name = [IO.Path]::GetFileNameWithoutExtension($template) + "-" + (($subs.Values | ForEach-Object { $_ -replace '\W', '' }) -join "-") + ".ps1"
    $name = $name.Substring(0, [Math]::Min(60, $name.Length)) -replace '-?\.ps1$', ''
    $f = Join-Path $tmp "$name.ps1"
    Set-Content $f $text -Encoding utf8
    & (Join-Path $PSScriptRoot "vmjob.ps1") -Script $f -TimeoutSec $timeout
}
function VmDo([string]$steps) { VmJob "guest\ui-do.ps1" @{ "__STEPS__" = $steps } 120 | Where-Object { $_ -ne 'ok' } }
function VmShot([string]$name) {
    $p = Join-Path $PSScriptRoot "shots\$name.png"
    & $script:vb controlvm $script:vm screenshotpng $p | Out-Null
    $p
}
