<#
  Scores each tool's leftover list against the ground truth from the VM runs.
    truth   = items present after uninstall that were absent before install (results\<id>-result.json),
              minus Windows churn ($Ambient below)
    hit     = a tool item equal to, inside, or containing a truth item
    danger  = a tool item that already existed BEFORE the install (snap-<id>-0.json) -> deleting it
              would remove something the app did not create
    other   = neither (usually a sub-key the truth already covers, or ambient noise)
  Usage: .\score.ps1 [-Ids ...]   (needs results\snap-<id>-0.json copied from the VM)
#>
param([string[]] $Ids)
$R = Join-Path $PSScriptRoot "results"
$Ambient = '(?i)AppX[0-9a-z]{20,}|\\AppContainer\\|\\AppModel\\|Extensions\\ContractId|\\windowsdefender$|\\RestartManager$|\\Wbem\\Tracing|Windows Security Health|\\Flighting\\|\\WindowsUpdate\\|USOShared|\\Microsoft\\(Pim|Poom|Unistore|Unified Store|UserData)$|\\AppData\\Local\\Comms$|\\Classes\\(CLSID\\\{[^}]+\}\\Elevation|Interface\\\{[^}]+\})$|\\Classes\\\.all$|MoNotificationUx|CryptnetUrlCache|\\Comms\\|\\Comms$|TokenBroker|ServicesForNFS|\\Windows Error Reporting\\|\\Schedule\\TaskCache\\|\\System32\\Tasks\\(elev|agent|crshot|utrun)|\\UFH$|\\PackagedCom$|\\Installer\\UserData$|\\Classes\\Installer\\Dependencies$|\\Classes\\Installer$|\\CurrentVersion\\RunOnce$|\\ProgramData\\Package Cache$|\\Microsoft\\SecurityManager\\CapAuthz$'
function Norm([string]$p) {
    $p = $p -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM\' -replace '^HKEY_CURRENT_USER\\', 'HKCU\'
    $p.TrimEnd('\').ToLowerInvariant()
}
function Overlaps([string]$a, [string]$b) { $a -eq $b -or $a.StartsWith("$b\") -or $b.StartsWith("$a\") }

if (-not $Ids) { $Ids = Get-ChildItem "$R\*-result.json" | ForEach-Object { $_.Name -replace '-result\.json$' } }
$rows = foreach ($id in $Ids) {
    $res = Get-Content "$R\$id-result.json" -Raw | ConvertFrom-Json
    $truth = @(@($res.truth.fs) + @($res.truth.reg) | Where-Object { $_ -and $_ -notmatch $Ambient } | ForEach-Object { Norm $_ })
    $before = $null
    if (Test-Path "$R\snap-$id-0.json") {
        $s0 = Get-Content "$R\snap-$id-0.json" -Raw | ConvertFrom-Json
        $before = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($x in @($s0.fs) + @($s0.reg)) { [void]$before.Add((Norm $x)) }
    }
    $tools = @{}
    $cu = "$R\$id-clone-uninstall.json"
    if (Test-Path $cu) { $tools["clone"] = @((Get-Content $cu -Raw | ConvertFrom-Json).leftovers | ForEach-Object { $_.path }) }
    # BCU / original: what disappeared during their uninstall run (vendor uninstaller + their cleanup),
    # measured by before/after snapshots. Filter Windows churn the same way as the truth.
    foreach ($t in "bcu", "ut") {
        $f = "$R\$id-$t-removed.json"
        # (ConvertFrom-Json in PowerShell 5.1 emits an array as ONE pipeline object; unroll it first.)
        if (Test-Path $f) { $tools[$t] = @(@(Get-Content $f -Raw | ConvertFrom-Json) | ForEach-Object { $_ } | Where-Object { $_ -and $_ -notmatch $Ambient }) }
    }
    foreach ($tool in $tools.Keys) {
        $items = @($tools[$tool] | ForEach-Object { Norm $_ })
        $hit = @($items | Where-Object { $i = $_; $truth | Where-Object { Overlaps $i $_ } | Select-Object -First 1 })
        $found = @($truth | Where-Object { $t = $_; $items | Where-Object { Overlaps $t $_ } | Select-Object -First 1 })
        $danger = @($items | Where-Object { $before -and $before.Contains($_) })
        [pscustomobject]@{
            app = $id; tech = $res.tech; tool = $tool; truth = $truth.Count; flagged = $items.Count
            hits = $hit.Count; recall = if ($truth.Count) { "{0:P0}" -f ($found.Count / $truth.Count) } else { "n/a" }
            danger = $danger.Count; danger_items = ($danger -join " | "); missed = (($truth | Where-Object { $_ -notin $found }) | Select-Object -First 6) -join " | "
        }
    }
}
$rows | Sort-Object app, tool
