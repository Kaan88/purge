# Shared helpers for VM test jobs (dot-sourced). Runs elevated inside the guest.
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$Out = "C:\cr\out"
New-Item -ItemType Directory -Force $Out, "C:\cr\inst" | Out-Null

# Filesystem + registry state, as two sorted string sets. Used as ground truth:
# (after uninstall) - (before install) = what really stayed behind.
$FsRoots = @("C:\Program Files", "C:\Program Files (x86)", "C:\ProgramData", "C:\Users\tester\AppData",
             "C:\Users\tester\Desktop", "C:\Users\Public", "C:\Windows\System32\Tasks", "C:\Windows\Tasks")
$RegRoots = @("HKLM\SOFTWARE", "HKCU\Software", "HKLM\SYSTEM\CurrentControlSet\Services")
# Churn that Windows itself causes and that no uninstaller is responsible for.
$Noise = '\\(Microsoft\\Windows Defender|Microsoft\\Windows\\WER|Microsoft\\Windows\\Caches|Microsoft\\Windows\\Explorer|Microsoft\\Windows\\INetCache|Microsoft\\Windows\\WebCache|Microsoft\\Edge|Packages\\|Microsoft\\Diagnosis|Microsoft\\Search|Microsoft\\Network\\Downloader|Microsoft\\Windows\\Notifications|Microsoft\\Windows\\ActionCenterCache|Microsoft\\CLR_v|Temp\\|ConnectedDevicesPlatform|Microsoft\\Windows\\PowerShell|Microsoft\\Windows\\Recent|SoftwareDistribution|Microsoft\\Windows\\DeliveryOptimization|Microsoft\\Windows\\AppRepository|Microsoft\\Windows\\SystemData|Microsoft\\Crypto|Microsoft\\Vault|Microsoft\\Protect|Microsoft\\Windows\\CurrentVersion\\(Explorer|CloudStore|Diagnostics|WINEVT|Notifications|Store|Search|BackgroundAccessApplications|CapabilityAccessManager|DeliveryOptimization|AppHost|Group Policy|Authentication|PushNotifications|Shell Extensions\\Cached)|bam\\|Microsoft\\Windows NT\\CurrentVersion\\(AppCompatFlags|Schedule\\TaskCache\\Tree\\Microsoft|NetworkList|Prefetcher|Winlogon)|Microsoft\\WindowsUpdate|Microsoft\\Cryptography|Microsoft\\SystemCertificates|Microsoft\\Windows Search|Microsoft\\Input|Microsoft\\InputPersonalization|Microsoft\\Speech_OneCore|Microsoft\\IdentityCRL|Microsoft\\SQMClient|Microsoft\\Windows\\Shell|Microsoft\\Tracing|Microsoft\\RADAR|Microsoft\\Office|SessionInfo|UserAssist|MuiCache|ShellBags|Services\\bam|Services\\(Tcpip|Dnscache|NlaSvc|iphlpsvc|W32Time|WinDefend|wscsvc|DoSvc|wuauserv|BITS|Netlogon|SharedAccess|mpssvc|EventLog)\\|Microsoft\\Windows\\CurrentVersion\\Installer\\(UserData\\S-1-5-18\\Components)|Microsoft\\Windows\\CurrentVersion\\Component Based Servicing|cr\\)'

function Snap([string]$tag) {
    $fs = foreach ($r in $FsRoots) { if (Test-Path $r) { Get-ChildItem -LiteralPath $r -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } } }
    $reg = foreach ($r in $RegRoots) {
        $f = "$env:TEMP\snap-$([guid]::NewGuid()).reg"
        reg export $r $f /y | Out-Null
        Select-String -Path $f -Pattern '^\[(.+)\]$' -Encoding Unicode | ForEach-Object { $_.Matches[0].Groups[1].Value }
        Remove-Item $f -Force
    }
    $s = [pscustomobject]@{ fs = @($fs | Sort-Object -Unique); reg = @($reg | Sort-Object -Unique) }
    $s | ConvertTo-Json -Depth 3 -Compress | Out-File "$Out\snap-$tag.json" -Encoding utf8
    $s
}
function NewItems($before, $after) {
    $bf = [Collections.Generic.HashSet[string]]::new([string[]]$before.fs, [StringComparer]::OrdinalIgnoreCase)
    $br = [Collections.Generic.HashSet[string]]::new([string[]]$before.reg, [StringComparer]::OrdinalIgnoreCase)
    [pscustomobject]@{
        fs  = @($after.fs  | Where-Object { -not $bf.Contains($_) -and $_ -notmatch $Noise })
        reg = @($after.reg | Where-Object { -not $br.Contains($_) -and $_ -notmatch $Noise })
    }
}
# Keep only top-most new items (a new folder implies its contents).
function TopMost([string[]]$items) {
    $sorted = $items | Sort-Object
    $keep = New-Object System.Collections.Generic.List[string]
    foreach ($i in $sorted) { if (-not ($keep | Where-Object { $i.StartsWith("$_\", [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)) { $keep.Add($i) } }
    $keep
}
function UninstallEntries {
    foreach ($k in "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall") {
        Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            [pscustomobject]@{ key = $_.Name; name = $p.DisplayName; version = $p.DisplayVersion; sys = $p.SystemComponent; parent = $p.ParentKeyName; uninstall = $p.UninstallString; quiet = $p.QuietUninstallString; size = $p.EstimatedSize; loc = $p.InstallLocation }
        }
    }
}
function Fetch([string]$url, [string]$file) {
    $dst = "C:\cr\inst\$file"
    if (-not (Test-Path $dst)) { Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing -MaximumRedirection 10 }
    $sig = Get-AuthenticodeSignature $dst
    "fetched $file  $([math]::Round((Get-Item $dst).Length/1MB,1)) MB  sig=$($sig.Status) $($sig.SignerCertificate.Subject -replace ',.*')"
    $dst
}
function GitHubAsset([string]$repo, [string]$pattern) {
    $rel = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers @{ "User-Agent" = "vm-test" }
    ($rel.assets | Where-Object name -match $pattern | Select-Object -First 1).browser_download_url
}
