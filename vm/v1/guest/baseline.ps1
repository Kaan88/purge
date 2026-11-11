# Clean-VM baseline: what the clone lists (elevated) before any test software is installed.
& C:\cr\clone-harness.exe list | Out-File C:\cr\out\baseline-clone-list.json -Encoding utf8
$j = Get-Content C:\cr\out\baseline-clone-list.json -Raw | ConvertFrom-Json
"admin=$($j.admin) counts: $($j.counts | ConvertTo-Json -Compress)"
$j.programs | ForEach-Object { "{0,-8} {1} | {2}" -f $_.category, $_.name, $_.version }
