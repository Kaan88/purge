# Elevated job runner inside the test VM. Started once (one UAC approval via start-agent.cmd),
# then runs every C:\cr\jobs\*.ps1 it finds, writing <job>.log and leaving <job>.done.
$jobs = "C:\cr\jobs"; $run = "C:\cr\jobs\run"
New-Item -ItemType Directory -Force $jobs, $run | Out-Null
# Only one agent at a time: stop any older copy.
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'agent\.ps1' -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
"agent started $(Get-Date -f s) admin=$(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators'))" | Out-File "$jobs\agent.alive" -Encoding utf8
while ($true) {
    Get-ChildItem "$jobs\*.ps1" | Sort-Object Name | ForEach-Object {
        $name = $_.Name
        $script = Join-Path $run $name
        Move-Item $_.FullName $script -Force
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script *> "$jobs\$name.log"
        "exit=$LASTEXITCODE" | Out-File "$jobs\$name.log" -Append -Encoding utf8
        New-Item -ItemType File -Force "$jobs\$name.done" | Out-Null
    }
    Start-Sleep -Milliseconds 700
}
