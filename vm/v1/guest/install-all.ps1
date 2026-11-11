# Installs every test app again (installers are already in C:\cr\inst), plus BCU itself, so the
# three tools can list the same machine. Re-fetches anything missing.
. C:\cr\guest\lib.ps1
. C:\cr\guest\apps.ps1
$only = "__ONLY__"
foreach ($a in $Apps) {
    if ($only -ne "" -and $only -notmatch "\b$($a.id)\b") { continue }
    $file = "C:\cr\inst\$($a.file)"
    if (-not (Test-Path $file) -or (Get-Item $file).Length -lt 100KB) { Remove-Item $file -ErrorAction SilentlyContinue; $file = (Fetch (& $a.url) $a.file)[-1] }
    $t = Get-Date
    if ($a.install -eq 'msi') { $p = Start-Process msiexec.exe -ArgumentList "/i `"$file`" /qn /norestart" -Wait -PassThru }
    else { $p = Start-Process $file -ArgumentList $a.install -Wait -PassThru }
    "{0,-9} exit={1} {2}s" -f $a.id, $p.ExitCode, [int]((Get-Date) - $t).TotalSeconds
}
if ($only -eq "" -or $only -match '\bbcu\b') {
    $bcu = (Fetch (GitHubAsset "BCUninstaller/Bulk-Crap-Uninstaller" '_setup\.exe$') "bcu_setup.exe")[-1]
    $p = Start-Process $bcu -ArgumentList '/VERYSILENT /NORESTART /SUPPRESSMSGBOXES' -Wait -PassThru
    "bcu       exit=$($p.ExitCode)"
    Get-ChildItem 'C:\Program Files*\BCUninstaller*' -Recurse -Filter 'BCU-console.exe' -ErrorAction SilentlyContinue | ForEach-Object FullName
}
