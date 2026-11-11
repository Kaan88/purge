# Starts the original (copied to C:\ut) from the elevated agent, so no UAC prompt is needed,
# and maximizes it for screenshots. Logs whether it came up.
. C:\cr\guest\ui.ps1
Get-Process UninstallTool*, UninstallToolHelper -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Process C:\ut\UninstallTool64.exe
for ($i = 0; $i -lt 30 -and -not (Front 'UninstallTool64'); $i++) { Start-Sleep 1 }
Start-Sleep 6
Get-Process UninstallTool* | Format-Table Name, Id, MainWindowTitle -AutoSize | Out-String
