# Pester (3.4, the version in Windows PowerShell 5.1) tests of the M1b guest scripts: vm\guest\m1b-traps.ps1, the M1b
# records of apps.ps1 and the richer task / service / firewall records of riglib.ps1. Host only, no VM, nothing is
# planted or registered (the plant functions are called only to see them refuse on a computer that is not a rig VM).
#   powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Pester vm\guest\tests\m1b-traps.tests.ps1"
$TestsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Guest = Split-Path -Parent $TestsDir
$Vm = Split-Path -Parent $Guest
$Traps = Join-Path $Guest 'm1b-traps.ps1'
$TruthTraps = Join-Path $Vm 'truth\m1b-traps.json'

# The case ids of M1B-RIG-HOST (docs/M1B_DESIGN.json) with their phase.
$ExpectedCases = [ordered]@{
    'svc-owned' = 'pre'; 'svc-owned-running' = 'pre'; 'svc-shared' = 'pre'; 'svc-dependent' = 'pre'; 'svc-svchost' = 'pre'
    'task-owned' = 'pre'; 'task-similar-name' = 'pre'; 'task-interpreter' = 'pre'
    'fw-owned' = 'pre'; 'fw-same-display-name' = 'pre'; 'fw-no-app' = 'pre'
    'com-owned' = 'pre'; 'com-shared-class' = 'pre'; 'shellex-approved' = 'pre'; 'shareddlls-count' = 'pre'
    'eventlog-shared-source' = 'pre'; 'tracing' = 'pre'; 'privacy-twins' = 'pre'; 'wer-twins' = 'pre'
    'msi-remnants' = 'post'; 'msi-remnants-foreign' = 'post'; 'msi-shared-component' = 'post'; 'com-isimpledom' = 'post'
    'burn-shared-package' = 'post'; 'pkgcache-foreign' = 'post'; 'instfolders' = 'post'
}

function Get-FunctionAsts([string]$Path) {
    $tok = $null; $err = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tok, [ref]$err)
    [pscustomobject]@{ errors = @($err); functions = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) }
}

# Fake RegistryKey for Get-ServiceRecords: GetValue(name, default[, options]), OpenSubKey(name, writable), Dispose().
function New-FakeKey([hashtable]$Values, [hashtable]$Subs = @{}) {
    $o = [pscustomobject]@{ V = $Values; S = $Subs }
    $o | Add-Member ScriptMethod GetValue { param($n, $d, $opt) if ($this.V.ContainsKey($n)) { $this.V[$n] } else { $d } }
    $o | Add-Member ScriptMethod OpenSubKey { param($n, $w) if ($this.S.ContainsKey($n)) { $this.S[$n] } else { $null } }
    $o | Add-Member ScriptMethod Dispose { }
    $o
}

Describe 'm1b-traps.ps1' {
    It 'traps_script_parses_and_lists_every_case' {
        $p = Get-FunctionAsts $Traps
        @($p.errors).Count | Should Be 0
        $defs = @($p.functions | ForEach-Object { $_.Name })

        $lines = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Traps -List)
        $LASTEXITCODE | Should Be 0
        $listed = @{}
        foreach ($l in $lines) { $f = "$l".Trim() -split '\s+'; if ($f.Count -ge 3) { $listed[$f[0]] = @{ phase = $f[1]; plant = $f[2] } } }
        $missing = @($ExpectedCases.Keys | Where-Object { -not $listed.ContainsKey($_) -or $listed[$_].phase -ne $ExpectedCases[$_] })
        ($missing -join ',') | Should Be ''
        $listed.Count | Should Be 26

        # Every function the case table names (plant and between step) is defined in the script.
        . $Traps -Library
        $named = @($M1bCases | ForEach-Object { $_.plant; $_.between } | Where-Object { $_ })
        (@($named | Where-Object { $defs -notcontains $_ }) -join ',') | Should Be ''
        (@($M1bCases | ForEach-Object { $_.id } | Select-Object -Unique)).Count | Should Be 26

        # Against the trap list of M1B-RIG-HOST once it exists: every case id is in the table with the same phase, and
        # every plant function it names exists.
        if (Test-Path -LiteralPath $TruthTraps) {
            $j = [IO.File]::ReadAllText($TruthTraps) | ConvertFrom-Json
            $bad = @()
            foreach ($c in @($j.cases)) {
                $t = @($M1bCases | Where-Object { $_.id -eq $c.id })[0]
                if (-not $t) { $bad += "$($c.id): no case"; continue }
                if ($c.phase -ne $t.phase) { $bad += "$($c.id): phase $($c.phase) vs $($t.phase)" }
                if ($defs -notcontains $c.plant) { $bad += "$($c.id): no function $($c.plant)" }
            }
            ($bad -join '; ') | Should Be ''
        }
    }

    It 'plants_refuse_outside_rig_vm' {
        . (Join-Path $Guest 'riglib.ps1')
        . $Traps -Library
        { Assert-M1bRigVm 'INBOUND-WIN11-T' } | Should Not Throw
        { Assert-M1bRigVm 'Purge-CleanPro' } | Should Not Throw
        { Assert-M1bRigVm 'DESKTOP-ABC123' } | Should Throw 'not a rig VM'
        { Assert-M1bRigVm '' } | Should Throw 'not a rig VM'
        $M1bRigComputers -contains $env:COMPUTERNAME.ToUpperInvariant() | Should Be $false   # the host is not a rig VM

        # Statically: the first statement of every plant and between function is the guard.
        $p = Get-FunctionAsts $Traps
        $fns = @($p.functions | Where-Object { $_.Name -like 'Plant-*' -or $_.Name -like 'Repoint-*' })
        $fns.Count | Should Be 27
        $noGuard = @($fns | Where-Object { "$(@($_.Body.EndBlock.Statements)[0].Extent.Text)".Trim() -ne 'Assert-M1bRigVm' } | ForEach-Object { $_.Name })
        ($noGuard -join ',') | Should Be ''

        # Called on this host, every one refuses before writing anything (the trap folders stay empty).
        $a = Join-Path $TestDrive 'A'; $b = Join-Path $TestDrive 'B'
        New-Item -ItemType Directory -Force $a, $b | Out-Null
        $mk = { param($d, $n) [pscustomobject]@{ id = $n; short = $n; name = $n; version = '1.0'; dir = $d; exe = (Join-Path $d "$n.exe"); exe_name = "$n.exe"; product_code = '{8E119FF9-1F7E-461D-B983-12CB719287A1}'; upgrade_code = $null; arp_leaf = $null; bundle = $false; installed = $true } }
        $ctx = [pscustomobject]@{ Case = 'test'; Phase = 'pre'; A = (& $mk $a 'TrapA'); B = (& $mk $b 'TrapB'); Planted = (New-Object System.Collections.ArrayList); Skipped = $false }
        $notRefused = @()
        foreach ($f in $fns) {
            $m = $null
            try { & $f.Name $ctx } catch { $m = $_.Exception.Message }
            if ("$m" -notmatch 'not a rig VM') { $notRefused += "$($f.Name): $m" }
        }
        ($notRefused -join '; ') | Should Be ''
        $ctx.Planted.Count | Should Be 0
        @(Get-ChildItem -LiteralPath $a, $b -Force).Count | Should Be 0
        Get-Service -Name 'PurgeTrapSvcA' -ErrorAction SilentlyContinue | Should Be $null

        # The script itself refuses before it creates its output directory.
        $out = Join-Path $TestDrive 'out'
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Traps -Phase pre -OutDir $out 2>&1
        $LASTEXITCODE | Should Not Be 0
        Test-Path -LiteralPath $out | Should Be $false
    }

    It 'case selection, unknown ids and the WER folder name are pure' {
        . (Join-Path $Guest 'riglib.ps1')
        . $Traps -Library
        @(Get-M1bCases 'pre').Count | Should Be 19
        @(Get-M1bCases 'post').Count | Should Be 7
        (@(Get-M1bCases 'between') | ForEach-Object { $_.id }) -join ',' | Should Be 'com-shared-class'
        (@(Get-M1bCases 'pre' @('tracing', 'msi-remnants')) | ForEach-Object { $_.id }) -join ',' | Should Be 'tracing'
        { Get-M1bCases 'pre' @('no-such-case') } | Should Throw 'unknown trap case'
        $w = Get-M1bWerFolderName '7zFM.exe'
        $w | Should Match '^AppCrash_7zFM\.exe_[0-9a-f]{40}_[0-9a-f]{8}_[0-9a-f]{8}$'
        Get-M1bWerFolderName '7zFM.exe' | Should Be $w
        Get-M1bWerFolderName 'node.exe' | Should Not Be $w
    }
}

Describe 'apps.ps1 M1b records' {
    It 'apps_entries_have_url_sha256_install_uninstall' {
        . (Join-Path $Guest 'riglib.ps1')
        . (Join-Path $Guest 'apps.ps1')
        $hosts = @{ powershell = '^https://github\.com/PowerShell/PowerShell/releases/download/v7\.6\.\d+/PowerShell-7\.6\.\d+-win-x64\.msi$'
                    temurin = '^https://github\.com/adoptium/temurin21-binaries/releases/download/jdk-21\.[^/]+/OpenJDK21U-jdk_x64_windows_hotspot_[\d_.]+\.msi$'
                    python313 = '^https://www\.python\.org/ftp/python/3\.13\.\d+/python-3\.13\.\d+-amd64\.exe$' }
        $bad = @()
        foreach ($id in 'powershell', 'temurin', 'python313') {
            $a = Get-App $id
            $u = @(& $a.url)
            if ($u.Count -ne 1 -or $u[0] -notmatch $hosts[$id]) { $bad += "${id}: url $($u -join ' ')" }
            if ("$($a.sha256)" -cnotmatch '^[0-9a-f]{64}$') { $bad += "${id}: sha256" }
            if (-not "$($a.version)") { $bad += "${id}: version" }
            if (-not "$($a.install)".Trim() -or -not "$($a.un)".Trim() -or -not "$($a.match)" -or -not "$($a.file)") { $bad += "${id}: install/un/match/file" }
            if ($u[0] -notmatch [regex]::Escape($a.version.Split('+')[0])) { $bad += "${id}: url does not carry version $($a.version)" }
        }
        ($bad -join '; ') | Should Be ''
        (Get-App 'powershell').install | Should Be 'msi'
        (Get-App 'temurin').un | Should Be 'msi'
        (Get-App 'python313').un | Should Be '{Q}'
        'PowerShell 7-x64' | Should Match (Get-App 'powershell').match
        'Eclipse Temurin JDK with Hotspot 21.0.13+9 (x64)' | Should Match (Get-App 'temurin').match
        'Python 3.13.17 (64-bit)' | Should Match (Get-App 'python313').match
        'Python 3.12.7 (64-bit)' | Should Not Match (Get-App 'python313').match

        # Variants: the other Python as a pre-app, everything else from the base record.
        $v1 = Get-App 'python312-with-313'; $v2 = Get-App 'python313-with-312'
        (@($v1.pre) -join ',') | Should Be 'python313'
        (@($v2.pre) -join ',') | Should Be 'python'
        $v1.match | Should Be (Get-App 'python').match
        $v2.match | Should Be (Get-App 'python313').match
        (Get-AppFiles 'python312-with-313') -join ',' | Should Be 'python.exe,python313.exe'
        (Get-AppFiles 'python313-with-312') -join ',' | Should Be 'python313.exe,python.exe'

        # 7zip is already the MSI build (no 7zip-msi record needed); node and vcredist are present.
        $z = Get-App '7zip'
        "$(& $z.url)" | Should Match '^https://www\.7-zip\.org/a/7z\d+-x64\.msi$'
        $z.install | Should Be 'msi'
        (Get-App 'node').install | Should Be 'msi'
        (Get-App 'vcredist').un | Should Be '{Q}'
        $ids = @($Apps | ForEach-Object { $_.id })
        @($ids | Select-Object -Unique).Count | Should Be $ids.Count
    }
}

Describe 'riglib.ps1 object records' {
    . (Join-Path $Guest 'riglib.ps1')

    It 'Get-TaskRecords: hidden, logon type, stored password, typed actions; M0 fields unchanged' {
        $exec = [pscustomobject]@{ CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskExecAction' }; Execute = 'C:\A\a.exe'; Arguments = '/x'; WorkingDirectory = 'C:\A' }
        $com = [pscustomobject]@{ CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskComHandlerAction' }; ClassId = '{11111111-2222-3333-4444-555555555555}'; Data = 'd' }
        $t1 = [pscustomobject]@{ TaskPath = '\PurgeTrap\'; TaskName = 'A Update'; State = 'Ready'; Actions = @($exec, $com)
                                 Settings = [pscustomobject]@{ Hidden = $true }; Principal = [pscustomobject]@{ LogonType = 'Password' } }
        $t2 = [pscustomobject]@{ TaskPath = '\'; TaskName = 'B'; State = 'Disabled'; Actions = @($exec)
                                 Settings = [pscustomobject]@{ Hidden = $false }; Principal = [pscustomobject]@{ LogonType = 'ServiceAccount' } }
        $r = @(Get-TaskRecords -Tasks @($t1, $t2))
        $r.Count | Should Be 2
        $r[0].path | Should Be '\PurgeTrap\A Update'
        (@($r[0].actions) -join '|') | Should Be 'C:\A\a.exe /x|com:{11111111-2222-3333-4444-555555555555} d'
        $r[0].enabled | Should Be $true
        $r[0].hidden | Should Be $true
        $r[0].logon_type | Should Be 'Password'
        $r[0].has_stored_password | Should Be $true
        $r[0].actions_detail[0].kind | Should Be 'exec'
        $r[0].actions_detail[0].path | Should Be 'C:\A\a.exe'
        $r[0].actions_detail[0].arguments | Should Be '/x'
        $r[0].actions_detail[0].working_dir | Should Be 'C:\A'
        $r[0].actions_detail[1].kind | Should Be 'com_handler'
        $r[0].actions_detail[1].clsid | Should Be '{11111111-2222-3333-4444-555555555555}'
        $r[1].enabled | Should Be $false
        $r[1].hidden | Should Be $false
        $r[1].has_stored_password | Should Be $false
        $j = ConvertTo-Json -InputObject $r -Depth 6 | ConvertFrom-Json
        @($j[1].actions_detail).Count | Should Be 1
    }

    It 'Get-ServiceRecords: registry view (raw ImagePath, ServiceDll, Type, Start, ObjectName, DependOnService) and state' {
        $params = New-FakeKey @{ ServiceDll = '%ProgramFiles%\A\s.dll' }
        $keys = @{
            'HKLM\SYSTEM\CurrentControlSet\Services\SvcHost1' = (New-FakeKey @{ ImagePath = '%SystemRoot%\System32\svchost.exe -k G'; Type = 32; Start = 3; ObjectName = 'LocalSystem'; DependOnService = [string[]]@('RpcSs', 'PurgeTrapSvcA2'); ServiceDll = 'C:\top.dll' } @{ Parameters = $params })
            'HKLM\SYSTEM\CurrentControlSet\Services\Own' = (New-FakeKey @{ ImagePath = '"C:\A\own.exe"'; Type = 16; Start = 2 })
        }
        $open = { param($c) $keys[$c] }.GetNewClosure()
        $svcs = @(
            [pscustomobject]@{ Name = 'SvcHost1'; DisplayName = 'S1'; PathName = 'C:\Windows\System32\svchost.exe -k G'; StartMode = 'Manual'; ServiceType = 'Share Process'; State = 'Stopped' }
            [pscustomobject]@{ Name = 'Own'; DisplayName = 'O'; PathName = '"C:\A\own.exe"'; StartMode = 'Auto'; ServiceType = 'Own Process'; State = 'Running' }
            [pscustomobject]@{ Name = 'NoKey'; DisplayName = 'N'; PathName = 'x'; StartMode = 'Manual'; ServiceType = 'Own Process'; State = 'Stopped' }
        )
        $drv = @([pscustomobject]@{ Name = 'Drv'; DisplayName = 'D'; PathName = 'C:\d.sys'; StartMode = 'Boot'; ServiceType = 'Kernel Driver'; State = 'Running' })
        $r = @(Get-ServiceRecords -Services $svcs -Drivers $drv -OpenKey $open)
        $r.Count | Should Be 4
        $r[0].image_path | Should Be 'C:\Windows\System32\svchost.exe -k G'
        $r[0].image_path_raw | Should Be '%SystemRoot%\System32\svchost.exe -k G'
        $r[0].service_dll | Should Be '%ProgramFiles%\A\s.dll'          # Parameters wins over the top-level value
        $r[0].service_type | Should Be 32
        $r[0].start_value | Should Be 3
        $r[0].start | Should Be 'Manual'
        $r[0].object_name | Should Be 'LocalSystem'
        (@($r[0].depend_on_service) -join ',') | Should Be 'RpcSs,PurgeTrapSvcA2'
        $r[0].state | Should Be 'Stopped'
        $r[1].service_dll | Should Be $null
        $r[1].start_value | Should Be 2
        $r[1].state | Should Be 'Running'
        $r[2].image_path_raw | Should Be $null
        $r[3].type | Should Be 'driver:Kernel Driver'
        $j = ConvertTo-Json -InputObject $r -Depth 6
        $j | Should Match '"depend_on_service":\s*\['
    }

    It 'Get-FirewallRecords: registry value name and raw string joined by rule id' {
        $rules = @(
            [pscustomobject]@{ Name = 'PurgeTrapFwA'; InstanceID = 'PurgeTrapFwA'; DisplayName = 'PurgeTrap'; Direction = 'Inbound'; Enabled = 'True' }
            [pscustomobject]@{ Name = 'NotInReg'; InstanceID = 'NotInReg'; DisplayName = 'X'; Direction = 'Outbound'; Enabled = 'False' }
        )
        $filters = @([pscustomobject]@{ InstanceID = 'PurgeTrapFwA'; Program = 'C:\A\a.exe' })
        $raw = 'v2.31|Action=Allow|Active=TRUE|Dir=In|App=C:\A\a.exe|Name=PurgeTrap|'
        $reg = @{ PurgeTrapFwA = @{ raw = $raw; key = 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules' } }
        $r = @(Get-FirewallRecords -Rules $rules -Filters $filters -RegRules $reg)
        $r.Count | Should Be 2
        $r[0].id | Should Be 'PurgeTrapFwA'
        $r[0].program | Should Be 'C:\A\a.exe'
        $r[0].enabled | Should Be $true
        $r[0].value_name | Should Be 'PurgeTrapFwA'
        $r[0].raw | Should BeExactly $raw
        $r[0].reg_key | Should Match 'FirewallRules$'
        $r[1].value_name | Should Be $null
        $r[1].raw | Should Be $null
        $r[1].enabled | Should Be $false
    }
}
