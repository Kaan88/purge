# Reinstall Notepad++, then uninstall it through the clone harness with stdout to a file (no pipe).
$e = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++'
Start-Process C:\cr\inst\npp.exe -ArgumentList '/S' -Wait
"installed: $(Test-Path $e)"
$t = Get-Date
$p = Start-Process C:\cr\clone-harness.exe -ArgumentList 'uninstall', '"Notepad++ (64-bit x64)"', '"\"C:\Program Files\Notepad++\uninstall.exe\" /S"', '120' -RedirectStandardOutput C:\cr\out\diag-npp2.json -RedirectStandardError C:\cr\out\diag-npp2.err -PassThru -NoNewWindow
for ($i = 0; $i -lt 70 -and -not $p.HasExited; $i++) {
    $kids = Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(Un_\w|Au_|uninstall)' -or $_.ParentProcessId -eq $p.Id }
    if ($kids -and $i % 5 -eq 0) { "  t+$($i*2)s: " + (($kids | ForEach-Object { "$($_.Name)[$($_.CommandLine)]" }) -join ' ; ') }
    Start-Sleep 2
}
"harness exited=$($p.HasExited) after $([int]((Get-Date)-$t).TotalSeconds)s; entry=$(Test-Path $e)"
Get-Content C:\cr\out\diag-npp2.json -TotalCount 12
Get-Content C:\cr\out\diag-npp2.err
