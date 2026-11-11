# One full cycle for one app: fetch -> snapshot -> silent install -> clone list -> snapshot ->
# uninstall through the clone harness (which then runs the clone's leftover scan) -> snapshot.
# The line below is rewritten per app by run-tests.ps1 on the host.
$Id = "__ID__"
. C:\cr\guest\lib.ps1
. C:\cr\guest\apps.ps1
$a = $Apps | Where-Object id -eq $Id
$t0 = Get-Date
"== $Id ($($a.tech))"
$url = & $a.url
"url: $url"
$file = (Fetch $url $a.file)[-1]

$e0 = UninstallEntries
$s0 = Snap "$Id-0"
if ($a.install -eq 'msi') { $p = Start-Process msiexec.exe -ArgumentList "/i `"$file`" /qn /norestart" -Wait -PassThru }
else { $p = Start-Process $file -ArgumentList $a.install -Wait -PassThru }
"install exit=$($p.ExitCode)  $([int]((Get-Date)-$t0).TotalSeconds)s"
Start-Sleep 5
$e1 = UninstallEntries
$newEntries = @($e1 | Where-Object { $k = $_.key; -not ($e0 | Where-Object key -eq $k) })
"new uninstall entries: $($newEntries.Count)"
$newEntries | ForEach-Object { "   [{0}] {1} {2} sys={3} parent={4}" -f ($_.key -replace '^.*\\'), $_.name, $_.version, $_.sys, $_.parent }
$main = $newEntries | Where-Object { $_.name -match $a.match -and -not $_.sys } | Select-Object -First 1
if (-not $main) { $main = $e1 | Where-Object { $_.name -match $a.match } | Select-Object -First 1 }
if (-not $main) { "NO MAIN ENTRY"; exit 3 }
"main: $($main.name)"

& C:\cr\clone-harness.exe list | Out-File "$Out\$Id-clone-list.json" -Encoding utf8

$cmd = $a.un.Replace('{U}', $main.uninstall).Replace('{Q}', $main.quiet) -replace '(?i)msiexec\.exe /I\{', 'MsiExec.exe /X{'
"uninstall cmd: $cmd"
# Windows PowerShell 5.1 does not escape embedded quotes for native programs, so quote each argument by hand.
$q = { param($s) '"' + ($s -replace '"', '\"') + '"' }
$hp = Start-Process C:\cr\clone-harness.exe -ArgumentList 'uninstall', (& $q $main.name), (& $q $cmd), '1800' `
      -RedirectStandardOutput "$Out\$Id-clone-uninstall.json" -RedirectStandardError "$Out\$Id-clone-uninstall.err" -Wait -PassThru -NoNewWindow
"harness exit=$($hp.ExitCode)"
$s2 = Snap "$Id-2"

$foot = [pscustomobject]@{ fs = @(); reg = @() }
$left = NewItems $s0 $s2
$e2 = UninstallEntries
$res = [pscustomobject]@{
    id = $Id; tech = $a.tech; url = $url; main = $main.name; version = $main.version
    entries_created = $newEntries; entries_left = @($e2 | Where-Object { $k = $_.key; -not ($e0 | Where-Object key -eq $k) })
    footprint = @{ fs = $foot.fs.Count; reg = $foot.reg.Count }
    truth = @{ fs = @(TopMost $left.fs); reg = @(TopMost $left.reg) }
    seconds = [int]((Get-Date) - $t0).TotalSeconds
}
$res | ConvertTo-Json -Depth 5 | Out-File "$Out\$Id-result.json" -Encoding utf8
"footprint fs=$($foot.fs.Count) reg=$($foot.reg.Count); left fs=$($left.fs.Count) reg=$($left.reg.Count); topmost fs=$($res.truth.fs.Count) reg=$($res.truth.reg.Count)"
"done in $($res.seconds)s"
