# Why did "uninstall.exe /S" leave Notepad++ installed when started by the clone's run_and_wait?
$u = 'C:\Program Files\Notepad++\uninstall.exe'
"before: entry=$(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++') folder=$(Test-Path 'C:\Program Files\Notepad++')"
$t = Get-Date
$p = Start-Process $u -ArgumentList '/S' -PassThru -Wait
"uninstall.exe exit=$($p.ExitCode) after $([int]((Get-Date)-$t).TotalSeconds)s"
for ($i = 0; $i -lt 40; $i++) {
    $kids = Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(Un_\w|Au_|uninstall)' }
    if ($kids) { "  t+$i*2s running: $($kids.Name -join ',')" }
    if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++')) { break }
    Start-Sleep 2
}
"after: entry=$(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++') folder=$(Test-Path 'C:\Program Files\Notepad++')"
Get-ChildItem 'C:\Program Files\Notepad++' -ErrorAction SilentlyContinue | Select-Object -First 10 Name
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$t.AddMinutes(-40)} -MaxEvents 5 -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, Message
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$t.AddMinutes(-40); Level=2} -MaxEvents 5 -ErrorAction SilentlyContinue | Format-List TimeCreated, ProviderName, Message
