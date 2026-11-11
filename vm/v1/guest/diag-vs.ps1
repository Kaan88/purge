# Retry the Visual Studio uninstall directly (not through the clone harness) to see if it works at all.
$setup = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe'
$t = Get-Date
$p = Start-Process $setup -ArgumentList 'uninstall --installPath "C:\Program Files\Microsoft Visual Studio\2022\Community" --quiet --norestart --wait --force' -Wait -PassThru
"setup.exe exit=$($p.ExitCode) after $([int]((Get-Date)-$t).TotalSeconds)s"
"entry still present: $(Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\3be8a4b0')"
"folder still present: $(Test-Path 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7')"
$log = Get-ChildItem "$env:TEMP\dd_setup_*.log" | Where-Object { $_.Name -notmatch '_\d{3}_' } | Sort-Object LastWriteTime | Select-Object -Last 1
"log: $($log.Name)"
Get-Content $log.FullName -Tail 8 | ForEach-Object { $_.Substring(0, [Math]::Min(200, $_.Length)) }
