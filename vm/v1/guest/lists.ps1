# Same machine state, three program lists: raw registry, the clone, BCU. (The original is captured
# from its window separately.)
. C:\cr\guest\lib.ps1
UninstallEntries | ConvertTo-Json -Depth 3 | Out-File "$Out\lists-registry.json" -Encoding utf8
& C:\cr\clone-harness.exe list | Out-File "$Out\lists-clone.json" -Encoding utf8
$console = Get-ChildItem 'C:\Program Files*\BCUninstaller*' -Recurse -Filter 'BCU-console.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
"bcu console: $console"
$t = Get-Date
& $console list /F=json 2> "$Out\lists-bcu.err" | Out-File "$Out\lists-bcu.json" -Encoding utf8
"bcu list exit=$LASTEXITCODE $([int]((Get-Date)-$t).TotalSeconds)s"
$c = Get-Content "$Out\lists-clone.json" -Raw | ConvertFrom-Json
"clone counts: $($c.counts | ConvertTo-Json -Compress)"
try { $b = Get-Content "$Out\lists-bcu.json" -Raw | ConvertFrom-Json; "bcu json top-level: $(($b | Get-Member -MemberType NoteProperty).Name -join ',')" } catch { "bcu json parse failed: $_"; Get-Content "$Out\lists-bcu.json" -TotalCount 20 }
Get-Content "$Out\lists-bcu.err" -Tail 5
