# Host self-test for install\install.ps1. Needs no elevation and no VM: the pure parts (SDDL builder,
# canonical form, integrity verdict, rename-aside naming, the install loop over a fake file system) run in
# memory, and the native layer is exercised only inside a fresh folder under %TEMP% (create with a
# descriptor, CREATE_NEW refusal, reparse detection, handle-based rename of a junction, non-following
# removal). M3-INSTALL adds the payload copy (engine, broker, UI tree, kb), re-run/update/stale, the
# broker's per-object protection rule and its repair, the shortcut, the executor-marker check and the
# -WhatIf plan; nothing outside that folder is written. Windows PowerShell 5.1:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\tests\install-selftest.ps1
# Exit 0 when every check passes. The real install checks (pre-created dir, planted junction, medium-IL
# attacker via LaunchMedium) run in the VM gate G0; see install\README.md.
$ErrorActionPreference = 'Stop'
$InstallDir = Split-Path -Parent $PSScriptRoot
$InstallPs1 = Join-Path $InstallDir 'install.ps1'
$Readme = Join-Path $InstallDir 'README.md'
$script:passes = 0; $script:fails = 0
function Check([string]$Name, [bool]$Cond, [string]$Detail = '') {
    if ($Cond) { $script:passes++; Write-Host "ok   $Name" } else { $script:fails++; Write-Host "FAIL $Name  $Detail" }
}
$Work = Join-Path ([IO.Path]::GetTempPath()) ('install-selftest-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $Work | Out-Null
Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)); work dir $Work"

try {
# ------------------------------------------------------------------------------------------ parse
foreach ($f in @($InstallPs1, $PSCommandPath)) {
    $tok = $null; $err = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($f, [ref]$tok, [ref]$err)
    Check "parse $(Split-Path -Leaf $f)" (@($err).Count -eq 0) (@($err | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ')
    $bytes = [IO.File]::ReadAllBytes($f)
    $nonAscii = @($bytes | Where-Object { $_ -gt 127 }).Count
    Check "$(Split-Path -Leaf $f) is ASCII (Windows PowerShell 5.1 reads BOM-less files as ANSI)" ($nonAscii -eq 0) "$nonAscii byte(s) above 127"
}
$sb = [scriptblock]::Create([IO.File]::ReadAllText($InstallPs1))
Check 'install.ps1 compiles as a script block' ($null -ne $sb)

& {
    Set-StrictMode -Version 2.0
    . $InstallPs1        # defines functions only: InvocationName is '.', so the installer does not run
    $ErrorActionPreference = 'Stop'
    Check 'dot-sourcing defines the functions without running the installer' ([bool](Get-Command Get-TreeVerdict -ErrorAction SilentlyContinue))

    # -------------------------------------------------------------------- SDDL builder and README source
    $table = Get-PurgeSddlTable
    Check 'builder: DataRoot' ($table.DataRoot -eq 'O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x100020;;;BU)') $table.DataRoot
    Check 'builder: Index' ($table.Index -eq 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)') $table.Index
    Check 'builder: arbitrary owner and ACEs' ((New-PurgeSddl 'S-1-5-21-1-2-3-1001' @(, @('OICIIO', 'GA', 'CO'))) -eq 'O:S-1-5-21-1-2-3-1001D:P(A;OICIIO;GA;;;CO)')

    $readmeRows = @{}
    foreach ($line in [IO.File]::ReadAllLines($Readme)) {
        $m = [regex]::Match($line, '^\|\s*`(?<name>\w+)`\s*\|[^|]*\|\s*`(?<sddl>O:[^`]+)`\s*\|\s*$')
        if ($m.Success) { $readmeRows[$m.Groups['name'].Value] = $m.Groups['sddl'].Value }
    }
    Check 'README lists exactly the builder constants' ((@($readmeRows.Keys | Sort-Object) -join ',') -eq (@($table.Keys | Sort-Object) -join ',')) (@($readmeRows.Keys) -join ',')
    foreach ($k in $table.Keys) {
        Check "README constant $k equals the builder output" ($readmeRows[$k] -ceq $table[$k]) "readme '$($readmeRows[$k])' vs '$($table[$k])'"
        Check "constant $k is in canonical form" ((ConvertTo-CanonicalSddl $table[$k]) -ceq $table[$k]) (ConvertTo-CanonicalSddl $table[$k])
        Check "constant $k has no security findings" ((Get-SddlFindings $table[$k]).Count -eq 0) ((Get-SddlFindings $table[$k]) -join '; ')
    }

    # ------------------------------------------------------------------------------- canonical form
    Check 'canonical: PAI reduces to P' ((ConvertTo-CanonicalSddl 'O:BAD:PAI(A;OICI;FA;;;SY)') -eq 'O:BAD:P(A;OICI;FA;;;SY)')
    Check 'canonical: AI alone is dropped (unprotected stays unprotected)' ((ConvertTo-CanonicalSddl 'O:BAD:AI(A;OICIID;FA;;;SY)') -eq 'O:BAD:(A;OICIID;FA;;;SY)') (ConvertTo-CanonicalSddl 'O:BAD:AI(A;OICIID;FA;;;SY)')
    Check 'canonical: group is ignored' ((ConvertTo-CanonicalSddl 'O:BAG:SYD:P(A;;FA;;;BA)') -eq 'O:BAD:P(A;;FA;;;BA)')
    Check 'canonical: hex FILE_ALL_ACCESS renders as FA' ((ConvertTo-CanonicalSddl 'O:BAD:P(A;;0x1f01ff;;;BA)') -eq 'O:BAD:P(A;;FA;;;BA)')
    Check 'canonical: bare 0x20 renders as WP (why the traverse mask carries SYNCHRONIZE)' ((ConvertTo-CanonicalSddl 'O:BAD:P(A;;0x20;;;BU)') -eq 'O:BAD:P(A;;WP;;;BU)')
    Check 'canonical: NO_ACCESS_CONTROL kept' ((ConvertTo-CanonicalSddl 'O:BAD:NO_ACCESS_CONTROL') -eq 'O:BAD:NO_ACCESS_CONTROL')
    Check 'canonical: garbage -> null' ($null -eq (ConvertTo-CanonicalSddl 'not sddl'))

    # ------------------------------------------------------------------------------- findings
    $user = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
    $f1 = Get-SddlFindings "O:${user}D:P(A;OICI;FA;;;$user)"
    Check 'findings: user owner and user write ACE' ((($f1 -join ';') -match 'is not BUILTIN\\Administrators') -and (($f1 -join ';') -match "non-admin $user")) ($f1 -join '; ')
    Check 'findings: unprotected DACL' (((Get-SddlFindings 'O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)') -join ';') -match 'not protected')
    Check 'findings: null DACL' (((Get-SddlFindings 'O:BAD:NO_ACCESS_CONTROL') -join ';') -match 'null DACL')
    Check 'findings: inherit-only CREATOR OWNER write counts' (((Get-SddlFindings 'O:BAD:P(A;;FA;;;BA)(A;OICIIO;GA;;;CO)') -join ';') -match 'S-1-3-0')
    Check 'findings: Users append (add subdirectory) counts' (((Get-SddlFindings 'O:BAD:P(A;;FA;;;BA)(A;CI;0x4;;;BU)') -join ';') -match 'S-1-5-32-545')
    Check 'findings: Users read/list is not a write finding' ((Get-SddlFindings 'O:BAD:P(A;;FA;;;BA)(A;;0x1200a9;;;BU)').Count -eq 0)
    Check 'findings: TrustedInstaller write is privileged' ((Get-SddlFindings "O:BAD:P(A;;FA;;;BA)(A;;FA;;;$script:SidTrustedInstaller)").Count -eq 0)
    Check 'findings: deny ACE for Users is not a write finding' ((Get-SddlFindings 'O:BAD:P(D;;FA;;;BU)(A;;FA;;;BA)').Count -eq 0)

    # ------------------------------------------------------------------------------- verdict (fake facts)
    $layout = Get-PurgeDataLayout
    function Facts([string]$Sddl, [bool]$Dir = $true, [bool]$Reparse = $false, [bool]$Exists = $true, [int]$Err = 0) {
        [pscustomobject]@{ Exists = $Exists; AttributesKnown = $Exists; IsDirectory = $Dir; IsReparsePoint = $Reparse; Sddl = $Sddl; Error = $Err }
    }
    function GoodTree {
        $o = @{}
        foreach ($e in $layout) { $o[$e.Rel] = Facts ($e.Sddl -replace '^(O:BAD:)P\(', '$1PAI(') ($e.Kind -eq 'dir') }
        [pscustomobject]@{ Root = 'C:\ProgramData\Purge'; Objects = $o; Reparse = @(); ScanErrors = @() }
    }
    function Verdict($tf) { Get-TreeVerdict $tf $layout }

    $v = Verdict ([pscustomobject]@{ Root = 'x'; Objects = @{ '' = (Facts $null -Exists $false) }; Reparse = @(); ScanErrors = @() })
    Check 'verdict: absent root -> absent, everything missing' ($v.Verdict -eq 'absent' -and @($v.Missing).Count -eq 6) "$($v.Verdict) $(@($v.Missing) -join ',')"
    $v = Verdict (GoodTree)
    Check 'verdict: exact tree (D:PAI on disk) -> good' ($v.Verdict -eq 'good' -and @($v.Reasons).Count -eq 0) (@($v.Reasons) -join '; ')
    $t = GoodTree; $t.Objects['sessions\index.json'] = Facts $null -Exists $false
    $v = Verdict $t
    Check 'verdict: index.json missing -> incomplete [index.json]' ($v.Verdict -eq 'incomplete' -and (@($v.Missing) -join ',') -eq 'sessions\index.json') "$($v.Verdict) $(@($v.Missing) -join ',')"
    $t = GoodTree; $t.Objects.Remove('fp'); $t.Objects['kb'] = Facts $null -Exists $false
    $v = Verdict $t
    Check 'verdict: two dirs missing -> incomplete in layout order' ($v.Verdict -eq 'incomplete' -and (@($v.Missing) -join ',') -eq 'fp,kb') "$($v.Verdict) $(@($v.Missing) -join ',')"

    $rejects = @(
        @{ n = 'user-pre-created root (user owner, inherited DACL)'; m = 'not BUILTIN\\Administrators'; f = { $t = GoodTree; $t.Objects[''] = Facts "O:${user}D:AI(A;OICIID;FA;;;$user)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)"; $t } },
        @{ n = 'admin-owned root with unprotected DACL'; m = 'not protected'; f = { $t = GoodTree; $t.Objects[''] = Facts 'O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;CIID;0x100006;;;BU)'; $t } },
        @{ n = 'root is a junction'; m = 'is a reparse point'; f = { $t = GoodTree; $t.Objects[''] = Facts $table.DataRoot -Reparse $true; $t } },
        @{ n = 'root is a file'; m = 'expected a directory'; f = { $t = GoodTree; $t.Objects[''] = Facts $table.DataRoot -Dir $false; $t } },
        @{ n = 'root descriptor unreadable'; m = 'unreadable \(Win32 error 5\)'; f = { $t = GoodTree; $t.Objects[''] = Facts $null -Err 5; $t } },
        @{ n = 'root owned by SYSTEM'; m = 'not BUILTIN\\Administrators'; f = { $t = GoodTree; $t.Objects[''] = Facts ($table.DataRoot -replace '^O:BA', 'O:SY'); $t } },
        @{ n = 'root with null DACL'; m = 'null DACL'; f = { $t = GoodTree; $t.Objects[''] = Facts 'O:BAD:NO_ACCESS_CONTROL'; $t } },
        @{ n = 'root with an extra Users list ACE'; m = 'differs from'; f = { $t = GoodTree; $t.Objects[''] = Facts ($table.DataRoot + '(A;;0x1200a9;;;BU)'); $t } },
        @{ n = 'Quarantine is a planted junction'; m = 'Quarantine: is a reparse point'; f = { $t = GoodTree; $t.Objects['Quarantine'] = Facts $table.Store -Reparse $true; $t.Reparse = @('C:\ProgramData\Purge\Quarantine'); $t } },
        @{ n = 'sessions\<x> junction at level 2'; m = 'reparse point inside the tree'; f = { $t = GoodTree; $t.Reparse = @('C:\ProgramData\Purge\sessions\x'); $t } },
        @{ n = 'sessions grants Users write'; m = 'sessions: write access'; f = { $t = GoodTree; $t.Objects['sessions'] = Facts ($table.Sessions + '(A;;0x2;;;BU)'); $t } },
        @{ n = 'index.json is a directory'; m = 'expected a file'; f = { $t = GoodTree; $t.Objects['sessions\index.json'] = Facts $table.Index -Dir $true; $t } },
        @{ n = 'index.json without Users read'; m = 'differs from'; f = { $t = GoodTree; $t.Objects['sessions\index.json'] = Facts 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)' -Dir $false; $t } },
        @{ n = 'level-1 enumeration failed'; m = 'cannot enumerate'; f = { $t = GoodTree; $t.ScanErrors = @('C:\ProgramData\Purge\fp: denied'); $t } }
    )
    foreach ($c in $rejects) {
        $v = Verdict (& $c.f)
        $rs = @($v.Reasons) -join '; '
        Check "verdict: $($c.n) -> reject" ($v.Verdict -eq 'reject' -and $rs -match $c.m -and @($v.Missing).Count -eq 0) "$($v.Verdict): $rs"
    }
    $t = GoodTree; $t.Objects[''] = Facts "O:${user}D:P(A;;FA;;;$user)"; $t.Objects['sessions'] = Facts $table.Sessions -Reparse $true; $t.Reparse = @('C:\ProgramData\Purge\x')
    $v = Verdict $t
    Check 'verdict: a bad root reports only root reasons (never looked into)' ($v.Verdict -eq 'reject' -and -not ((@($v.Reasons) -join ';') -match 'sessions|inside the tree')) (@($v.Reasons) -join '; ')

    $pfl = Get-PurgeProgramFilesLayout
    $v = Get-TreeVerdict ([pscustomobject]@{ Root = 'p'; Objects = @{ '' = (Facts $table.ProgramFiles) }; Reparse = @(); ScanErrors = @() }) $pfl
    Check 'verdict: Program Files exact -> good' ($v.Verdict -eq 'good') (@($v.Reasons) -join '; ')
    $v = Get-TreeVerdict ([pscustomobject]@{ Root = 'p'; Objects = @{ '' = (Facts 'O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;OICIIOID;GA;;;CO)') }; Reparse = @(); ScanErrors = @() }) $pfl
    Check 'verdict: Program Files with inherited defaults -> reject' ($v.Verdict -eq 'reject') (@($v.Reasons) -join '; ')

    # ------------------------------------------------------------------------------- rename-aside naming
    $now = [datetime]::new(2026, 11, 12, 10, 15, 0, [DateTimeKind]::Utc)
    Check 'aside name' ((Get-AsideName 'C:\ProgramData\Purge' $now { param($p) $false }) -eq 'C:\ProgramData\Purge.rejected-20261112T101500Z')
    $taken = @('C:\ProgramData\Purge.rejected-20261112T101500Z', 'C:\ProgramData\Purge.rejected-20261112T101500Z-2')
    Check 'aside name on collision' ((Get-AsideName 'C:\ProgramData\Purge' $now { param($p) $taken -contains $p }) -eq 'C:\ProgramData\Purge.rejected-20261112T101500Z-3')
}

# ---------------------------------------------------------------------- install loop over a fake file system
& {
    Set-StrictMode -Version 2.0
    . $InstallPs1
    $ErrorActionPreference = 'Stop'
    $user = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
    $script:fs = @{}         # lower-case path -> @{ Path; Kind; Sddl; Reparse }
    $script:calls = New-Object System.Collections.ArrayList
    $script:onRename = $null
    function Add-Fake([string]$Path, [string]$Kind, [string]$Sddl, [bool]$Reparse = $false) {
        $script:fs[$Path.ToLowerInvariant()] = @{ Path = $Path; Kind = $Kind; Sddl = $Sddl; Reparse = $Reparse }
    }
    function Get-ObjectFacts([string]$Path) {
        [void]$script:calls.Add("facts:$Path")
        $o = $script:fs[$Path.ToLowerInvariant()]
        if (-not $o) { return [pscustomobject]@{ Path = $Path; Exists = $false; AttributesKnown = $false; IsDirectory = $false; IsReparsePoint = $false; Links = 0; Sddl = $null; Error = 2 } }
        [pscustomobject]@{ Path = $Path; Exists = $true; AttributesKnown = $true; IsDirectory = ($o.Kind -eq 'dir'); IsReparsePoint = $o.Reparse; Links = 1; Sddl = $o.Sddl; Error = 0 }
    }
    function Get-ReparseEntries([string]$Root) {
        [void]$script:calls.Add("scan:$Root")
        $pre = $Root.ToLowerInvariant() + '\'
        $found = @($script:fs.Values | Where-Object {
            $_.Reparse -and $_.Path.ToLowerInvariant().StartsWith($pre) -and ($_.Path.Substring($pre.Length).Split('\').Count -le 2)
        } | ForEach-Object { $_.Path })
        [pscustomobject]@{ Reparse = $found; Errors = @() }
    }
    function Invoke-NativeCreate([string]$Path, $Entry) {
        [void]$script:calls.Add("create:$Path")
        if ($script:fs.ContainsKey($Path.ToLowerInvariant())) { if ($Entry.Kind -eq 'dir') { return 183 } else { return 80 } }
        $parent = (Split-Path -Parent $Path).ToLowerInvariant()
        if ($parent -ne 'c:\pd' -and -not $script:fs.ContainsKey($parent)) { return 3 }
        Add-Fake $Path $Entry.Kind ($Entry.Sddl -replace '^(O:BAD:)P\(', '$1PAI(')     # Windows may add AI
        0
    }
    function Invoke-NativeRename([string]$Path, [string]$NewPath) {
        [void]$script:calls.Add("rename:$Path->$NewPath")
        $pre = $Path.ToLowerInvariant()
        foreach ($k in @($script:fs.Keys)) {
            if ($k -eq $pre -or $k.StartsWith($pre + '\')) {
                $o = $script:fs[$k]; $script:fs.Remove($k)
                $np = $NewPath + $o.Path.Substring($Path.Length)
                $o.Path = $np; $script:fs[$np.ToLowerInvariant()] = $o
            }
        }
        if ($script:onRename) { & $script:onRename }
        0
    }
    function Test-PathNoFollow([string]$Path) { $script:fs.ContainsKey($Path.ToLowerInvariant()) }
    function Write-InstallLog([string]$Message) { }     # keep the loop's log lines out of the test output
    $layout = Get-PurgeDataLayout
    $root = 'C:\pd\Purge'

    # 1. attacker pre-created the root (user-owned, inherited DACL) with a junction at Quarantine.
    Add-Fake $root 'dir' "O:${user}D:AI(A;OICIID;FA;;;$user)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)"
    Add-Fake "$root\Quarantine" 'dir' "O:${user}D:AI(A;OICIID;FA;;;$user)" $true
    Add-Fake "$root\sessions" 'dir' "O:${user}D:AI(A;OICIID;FA;;;$user)"
    $rec = Install-Tree $root $layout 'data-root'
    $firstRename = [array]::FindIndex([object[]]$script:calls.ToArray(), [Predicate[object]] { param($c) $c -like 'rename:*' })
    $before = @($script:calls.ToArray()[0..($firstRename - 1)])
    Check 'loop: pre-created tree renamed aside once' (@($rec.renamed_aside).Count -eq 1 -and $rec.renamed_aside[0].to -like 'C:\pd\Purge.rejected-*') ($rec.renamed_aside | ConvertTo-Json -Compress)
    Check 'loop: nothing inside the rejected root was looked at before the rename' ((@($before) -join '|') -eq "facts:$root") (@($before) -join '|')
    Check 'loop: fresh tree created (6 objects) and verified' (@($rec.created).Count -eq 6 -and $rec.changed -and $rec.final -and $rec.final['sessions\index.json'] -eq 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)') (($rec.final | ConvertTo-Json -Compress) + ' created=' + @($rec.created).Count)
    $asideQ = $script:fs[($rec.renamed_aside[0].to + '\Quarantine').ToLowerInvariant()]
    Check 'loop: the planted junction moved with the rejected tree, untouched' ($asideQ -and $asideQ.Reparse)
    Check 'loop: reasons reported' ((@($rec.renamed_aside[0].reasons) -join ';') -match 'not BUILTIN\\Administrators')

    # 2. re-run on the good tree: no-op.
    $script:calls.Clear()
    $rec2 = Install-Tree $root $layout 'data-root'
    Check 'loop: re-run is a no-op' (-not $rec2.changed -and @($rec2.created).Count -eq 0 -and @($rec2.renamed_aside).Count -eq 0 -and -not (@($script:calls) -match '^(create|rename):')) (@($script:calls) -join '|')

    # 3. index.json gone: recreated alone.
    $script:fs.Remove("$root\sessions\index.json".ToLowerInvariant())
    $rec3 = Install-Tree $root $layout 'data-root'
    Check 'loop: missing index.json recreated, nothing renamed' ((@($rec3.created) -join ',') -eq "$root\sessions\index.json" -and @($rec3.renamed_aside).Count -eq 0) ((@($rec3.created) -join ',') + ' / ' + @($rec3.renamed_aside).Count)

    # 4. level-2 junction planted in an otherwise good tree: whole tree renamed aside.
    Add-Fake "$root\sessions\x" 'dir' "O:${user}D:P(A;;FA;;;$user)" $true
    $rec4 = Install-Tree $root $layout 'data-root'
    Check 'loop: level-2 junction -> renamed aside and recreated' (@($rec4.renamed_aside).Count -eq 1 -and @($rec4.created).Count -eq 6 -and ((@($rec4.renamed_aside[0].reasons) -join ';') -match 'sessions\\x')) ($rec4 | ConvertTo-Json -Compress -Depth 5)

    # 5. an attacker re-creates the root after every rename: bounded, never adopted.
    $script:fs.Clear(); $script:calls.Clear()
    Add-Fake $root 'dir' "O:${user}D:P(A;OICI;FA;;;$user)"
    $script:onRename = { Add-Fake $root 'dir' "O:${user}D:P(A;OICI;FA;;;$user)" }
    $threw = $null
    try { $null = Install-Tree $root $layout 'data-root' } catch { $threw = $_.Exception.Message }
    $renames = @($script:calls | Where-Object { $_ -like 'rename:*' })
    Check 'loop: persistent attacker -> fails after 4 passes, never adopts' ($threw -match 'did not reach a verified state' -and $renames.Count -eq 4 -and -not (@($script:calls) -match '^create:')) "$threw / $($renames.Count)"
    Check 'loop: colliding aside names get -2, -3 ...' (@($renames | Where-Object { $_ -match 'rejected-\d{8}T\d{6}Z-2$' }).Count -ge 1) ($renames -join ' | ')
    $script:onRename = $null

    # 6. the root appears between the check and the create (CreateDirectoryW says 183): re-checked, then rejected.
    $script:fs.Clear(); $script:calls.Clear()
    $script:raceOnce = $true
    function Invoke-NativeCreate([string]$Path, $Entry) {
        [void]$script:calls.Add("create:$Path")
        if ($script:raceOnce) { $script:raceOnce = $false; Add-Fake $Path 'dir' "O:${user}D:P(A;OICI;FA;;;$user)"; return 183 }
        if ($script:fs.ContainsKey($Path.ToLowerInvariant())) { return 183 }
        Add-Fake $Path $Entry.Kind $Entry.Sddl
        0
    }
    $rec6 = Install-Tree $root $layout 'data-root'
    Check 'loop: create race (183) -> re-check, rename aside, create' (@($rec6.renamed_aside).Count -eq 1 -and @($rec6.created).Count -eq 6 -and $rec6.final) ($rec6 | ConvertTo-Json -Compress -Depth 5)
}

# ---------------------------------------------------------------------- native layer (temp folder only)
& {
    Set-StrictMode -Version 2.0
    . $InstallPs1
    $ErrorActionPreference = 'Stop'
    Initialize-PurgeNative
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    # Same shape as DataRoot, owned by the current user (a non-elevated token cannot assign Administrators as
    # owner) and with a full-control ACE for that user so the folder can be cleaned up afterwards.
    $sddl = New-PurgeSddl $me @(@('OICI', 'FA', 'SY'), @('OICI', 'FA', 'BA'), @('OICI', 'FA', $me), @('', '0x100020', 'BU'))
    $fileSddl = New-PurgeSddl $me @(@('', 'FA', 'SY'), @('', 'FA', 'BA'), @('', 'FA', $me), @('', 'FR', 'BU'))
    $tree = Join-Path $Work 'tree'

    Check 'native: create dir with descriptor' ([PurgeInstall.Native]::CreateDirWithSddl($tree, $sddl) -eq 0)
    $f = Get-ObjectFacts $tree
    Check 'native: dir facts (exists, directory, not reparse)' ($f.Exists -and $f.AttributesKnown -and $f.IsDirectory -and -not $f.IsReparsePoint) ($f | ConvertTo-Json -Compress)
    Check 'native: protected DACL and ACEs survive creation (canonical round trip)' ((ConvertTo-CanonicalSddl $f.Sddl) -eq (ConvertTo-CanonicalSddl $sddl)) "on disk '$($f.Sddl)' vs '$sddl'"
    Check 'native: create dir again -> 183 (never adopts)' ([PurgeInstall.Native]::CreateDirWithSddl($tree, $sddl) -eq 183)

    $idx = Join-Path $tree 'index.json'
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes('{}')
    Check 'native: create file with descriptor' ([PurgeInstall.Native]::CreateFileWithSddl($idx, $fileSddl, $bytes) -eq 0)
    $ff = Get-ObjectFacts $idx
    Check 'native: file content is {} without BOM' ([IO.File]::ReadAllText($idx) -ceq '{}' -and (Get-Item -LiteralPath $idx).Length -eq 2)
    Check 'native: file descriptor round trip (explicit ACEs, protected)' ((ConvertTo-CanonicalSddl $ff.Sddl) -eq (ConvertTo-CanonicalSddl $fileSddl) -and -not $ff.IsDirectory) "on disk '$($ff.Sddl)'"
    Check 'native: CREATE_NEW on an existing file -> 80' ([PurgeInstall.Native]::CreateFileWithSddl($idx, $fileSddl, $bytes) -eq 80)
    Check 'native: missing object -> Exists false' (-not (Get-ObjectFacts (Join-Path $tree 'nope\x')).Exists)

    # Junctions: one at level 1 and one at level 2, both pointing at a canary outside the tree.
    $target = Join-Path $Work 'canary'
    New-Item -ItemType Directory $target | Out-Null
    [IO.File]::WriteAllText((Join-Path $target 'canary.txt'), 'canary')
    $sub = Join-Path $tree 'sessions'
    New-Item -ItemType Directory $sub | Out-Null
    $j1 = Join-Path $tree 'Quarantine'; $j2 = Join-Path $sub 'x'
    $null = cmd.exe /c mklink /J "$j1" "$target"
    $null = cmd.exe /c mklink /J "$j2" "$target"
    $jf = Get-ObjectFacts $j1
    Check 'native: junction facts are the link''s own (reparse, directory)' ($jf.Exists -and $jf.IsReparsePoint -and $jf.IsDirectory) ($jf | ConvertTo-Json -Compress)
    $scan = Get-ReparseEntries $tree
    Check 'native: top-two-level scan finds both junctions' ((@($scan.Reparse | Sort-Object) -join ',') -eq (@($j1, $j2 | Sort-Object) -join ',')) (@($scan.Reparse) -join ',')
    $deep = Join-Path $sub 'deeper'
    New-Item -ItemType Directory $deep | Out-Null
    $null = cmd.exe /c mklink /J "$(Join-Path $deep 'y')" "$target"
    Check 'native: the scan stays at two levels' (@((Get-ReparseEntries $tree).Reparse).Count -eq 2)

    $j1Aside = Join-Path $tree 'Quarantine.rejected-test'
    Check 'native: handle rename of a junction' ([PurgeInstall.Native]::RenameNoFollow($j1, $j1Aside) -eq 0)
    $af = Get-ObjectFacts $j1Aside
    Check 'native: the junction itself moved; the target did not' ($af.IsReparsePoint -and -not (Get-ObjectFacts $j1).Exists -and (Test-Path -LiteralPath (Join-Path $target 'canary.txt')))
    Check 'native: rename never replaces' ([PurgeInstall.Native]::RenameNoFollow($j2, $j1Aside) -ne 0 -and (Get-ObjectFacts $j2).Exists)

    $treeAside = Get-AsideName $tree ([datetime]::UtcNow) { param($p) Test-PathNoFollow $p }
    Check 'native: whole tree renamed aside by handle' ([PurgeInstall.Native]::RenameNoFollow($tree, $treeAside) -eq 0 -and (Get-ObjectFacts $treeAside).IsDirectory -and -not (Test-PathNoFollow $tree))

    Remove-TreeNoFollow $treeAside
    Check 'native: non-following removal deletes the tree and the links only' (-not (Test-Path -LiteralPath $treeAside) -and ([IO.File]::ReadAllText((Join-Path $target 'canary.txt')) -eq 'canary'))

    # An object whose descriptor the caller may not read (no elevation needed to see this).
    $svi = 'C:\System Volume Information'
    $sf = Get-ObjectFacts $svi
    if ($sf.Exists -and -not $sf.Sddl) {
        $r = Test-ObjectFacts $sf ([pscustomobject]@{ Rel = ''; Kind = 'dir'; Sddl = (Get-PurgeSddlTable).DataRoot })
        Check 'native: unreadable descriptor -> exists, reason reported' (($r -join ';') -match 'security descriptor unreadable') ($r -join '; ')
    } else {
        Write-Host "skip native unreadable-descriptor check ($svi readable or absent here)"
    }
}

# ---------------------------------------------------------------------- payload, protection, markers (M3-INSTALL)
& {
    Set-StrictMode -Version 2.0
    . $InstallPs1
    $ErrorActionPreference = 'Stop'
    function Write-InstallLog([string]$Message) { }     # keep the payload log lines out of the test output
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    # The ProgramFiles shape with the test user where Administrators would be: a non-elevated test cannot
    # assign BUILTIN\Administrators as owner, so the user is added to the accepted owners for this block.
    $sddl = New-PurgeSddl $me @(@('OICI', 'FA', 'SY'), @('OICI', 'FA', 'BA'), @('OICI', 'FA', $me), @('OICI', '0x1200a9', 'BU'))
    $admins = @($me, $script:SidSystem, $script:SidAdmins)

    $src = Join-Path $Work 'payload-src'
    New-Item -ItemType Directory (Join-Path $src 'ui\Assets') -Force | Out-Null
    New-Item -ItemType Directory (Join-Path $src 'kb\baselines') -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $src 'purge-engine.exe'), 'engine')
    [IO.File]::WriteAllText((Join-Path $src 'purge-broker.exe'), 'broker')
    [IO.File]::WriteAllText((Join-Path $src 'ui\Purge.exe'), 'ui')
    [IO.File]::WriteAllText((Join-Path $src 'ui\Purge.Client.dll'), 'v1')
    [IO.File]::WriteAllText((Join-Path $src 'ui\Assets\Purge.ico'), 'ico')
    [IO.File]::WriteAllText((Join-Path $src 'kb\view.json'), '{}')
    [IO.File]::WriteAllText((Join-Path $src 'kb\baselines\a.tsv.gz'), 'gz')
    $dest = Join-Path $Work 'payload-install'
    Check 'payload: create the test install root with a descriptor' ([PurgeInstall.Native]::CreateDirWithSddl($dest, $sddl) -eq 0)

    $r = Copy-Payload $dest (Join-Path $src 'purge-engine.exe') (Join-Path $src 'purge-broker.exe') (Join-Path $src 'ui') (Join-Path $src 'kb') $sddl $admins
    Check 'payload: fresh copy writes engine, broker, the UI tree and kb' ((Test-Path (Join-Path $dest 'Purge.exe')) -and (Test-Path (Join-Path $dest 'Assets\Purge.ico')) -and (Test-Path (Join-Path $dest 'kb\baselines\a.tsv.gz')))
    Check 'payload: fresh copy is a change' ($r.changed -and @($r.files | Where-Object { $_.action -eq 'copied' }).Count -eq 7)
    Check 'payload: an inherited descriptor needs no re-protection' (@($r.reprotected).Count -eq 0) (@($r.reprotected) -join ',')

    $r2 = Copy-Payload $dest (Join-Path $src 'purge-engine.exe') (Join-Path $src 'purge-broker.exe') (Join-Path $src 'ui') (Join-Path $src 'kb') $sddl $admins
    Check 'payload: re-run is a no-op' (-not $r2.changed -and @($r2.files | Where-Object { $_.action -ne 'unchanged' }).Count -eq 0 -and @($r2.reprotected).Count -eq 0)

    [IO.File]::WriteAllText((Join-Path $src 'ui\Purge.Client.dll'), 'v2')
    $r3 = Copy-Payload $dest (Join-Path $src 'purge-engine.exe') (Join-Path $src 'purge-broker.exe') (Join-Path $src 'ui') (Join-Path $src 'kb') $sddl $admins
    Check 'payload: a changed source updates one file' ($r3.changed -and @($r3.files | Where-Object { $_.action -eq 'updated' }).Count -eq 1 -and [IO.File]::ReadAllText((Join-Path $dest 'Purge.Client.dll')) -eq 'v2')

    [IO.File]::WriteAllText((Join-Path $dest 'old.dll'), 'old')
    $r4 = Copy-Payload $dest (Join-Path $src 'purge-engine.exe') (Join-Path $src 'purge-broker.exe') (Join-Path $src 'ui') (Join-Path $src 'kb') $sddl $admins
    Check 'payload: a stale file is reported and left in place' (@($r4.files | Where-Object { $_.action -eq 'stale (left in place)' }).Count -eq 1 -and (Test-Path (Join-Path $dest 'old.dll')) -and -not $r4.changed)

    $lnk = Join-Path $Work 'Purge.lnk'
    Check 'shortcut: created with the right target' ((Install-Shortcut $lnk (Join-Path $dest 'Purge.exe') $dest) -and (Get-ShortcutTarget $lnk) -eq (Join-Path $dest 'Purge.exe'))
    Check 'shortcut: a second call is a no-op' (-not (Install-Shortcut $lnk (Join-Path $dest 'Purge.exe') $dest))
    $c = Test-PayloadLayout $dest $lnk $admins
    Check 'check: a complete payload passes' ($c.ok -and $c.files -eq 8) ($c.problems -join '; ')
    Check 'check: -EngineOnly accepts the engine and kb alone' ((Test-PayloadLayout $dest $null $admins -EngineOnly).ok)

    $bad = Join-Path $dest 'bad.dll'
    [IO.File]::WriteAllText($bad, 'bad')
    Check 'native: apply a descriptor with an Everyone write ACE' ([PurgeInstall.Native]::SetSddl($bad, (New-PurgeSddl $me @(@('', 'FA', $me), @('', 'FA', 'WD')))) -eq 0)
    $c2 = Test-PayloadLayout $dest $lnk $admins
    Check 'check: a user-writable file is named' (-not $c2.ok -and (($c2.problems -join ';') -match 'bad\.dll') -and (($c2.problems -join ';') -match 'S-1-1-0')) ($c2.problems -join '; ')
    $r5 = Copy-Payload $dest (Join-Path $src 'purge-engine.exe') (Join-Path $src 'purge-broker.exe') (Join-Path $src 'ui') (Join-Path $src 'kb') $sddl $admins
    Check 'payload: the next run re-protects only the failing file' (@($r5.reprotected).Count -eq 1 -and $r5.changed) (@($r5.reprotected) -join ',')
    Check 'check: the repaired payload passes' ((Test-PayloadLayout $dest $lnk $admins).ok)

    Check 'shortcut: removed' (Remove-Shortcut $lnk)
    Remove-TreeNoFollow $dest
    Check 'uninstall: the payload tree is gone' (-not (Test-Path $dest))

    # The Rust UI: -Ui passes Purge.exe itself, copied as <dest>\Purge.exe alone.
    $dest1 = Join-Path $Work 'payload-install-exe'
    Check 'payload (one-file UI): create the test install root' ([PurgeInstall.Native]::CreateDirWithSddl($dest1, $sddl) -eq 0)
    $r6 = Copy-Payload $dest1 (Join-Path $src 'purge-engine.exe') (Join-Path $src 'purge-broker.exe') (Join-Path $src 'ui\Purge.exe') (Join-Path $src 'kb') $sddl $admins
    Check 'payload (one-file UI): Purge.exe is copied, nothing else of the UI folder' ((Test-Path (Join-Path $dest1 'Purge.exe')) -and -not (Test-Path (Join-Path $dest1 'Purge.Client.dll')) -and -not (Test-Path (Join-Path $dest1 'Assets')) -and @($r6.files | Where-Object { $_.action -eq 'copied' }).Count -eq 5)
    $r7 = Copy-Payload $dest1 (Join-Path $src 'purge-engine.exe') (Join-Path $src 'purge-broker.exe') (Join-Path $src 'ui\Purge.exe') (Join-Path $src 'kb') $sddl $admins
    Check 'payload (one-file UI): re-run is a no-op' (-not $r7.changed)
    Remove-TreeNoFollow $dest1

    $good = Join-Path $Work 'clean.exe'
    $badEngine = Join-Path $Work 'executor.exe'
    [IO.File]::WriteAllText($good, 'nothing to see here')
    [IO.File]::WriteAllText($badEngine, 'prefix purge-exec\src\execute.rs suffix')
    Check 'engine marker: a clean binary has none' ((Get-ExecutorMarkers $good).Count -eq 0)
    Check 'engine marker: an executor path is found' ((Get-ExecutorMarkers $badEngine) -contains 'purge-exec\src')
    $threw = $null
    try { Assert-EngineWithoutExecutor $badEngine } catch { $threw = $_.Exception.Message }
    Check 'engine marker: the install refuses an executor build' ($threw -match 'rig-exec')
}

# ---------------------------------------------------------------------- the -WhatIf plan (no elevation)
& {
    $rep = Join-Path $Work 'whatif.json'
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InstallPs1 -WhatIf -ReportPath $rep 2>&1
    $code = $LASTEXITCODE
    $text = ($out | Out-String)
    $j = if (Test-Path -LiteralPath $rep) { [IO.File]::ReadAllText($rep) | ConvertFrom-Json } else { $null }
    Check 'what-if: install exits 0 and names every step' ($code -eq 0 -and $text -match 'cargo build --release -p purge-engine' -and $text -match 'cargo build --release -p purge-broker' -and $text -match 'cargo build --release -p purge-ui' -and $text -notmatch 'dotnet' -and $text -match 'copy purge-engine\.exe, purge-broker\.exe' -and $text -match 'event-log source' -and $text -match 'Start-menu shortcut') "exit $code; $text"
    Check 'what-if: the report says what_if and changed false' ($j -and $j.what_if -and $j.ok -and -not $j.changed -and $j.mode -eq 'install')
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InstallPs1 -Check -WhatIf 2>&1
    $code = $LASTEXITCODE
    Check 'what-if: check exits 0 and changes nothing' ($code -eq 0 -and (($out | Out-String) -match 'check ok')) "exit $code; $($out | Out-String)"
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InstallPs1 -Uninstall -WhatIf 2>&1
    $code = $LASTEXITCODE
    Check 'what-if: uninstall exits 0 and names the shortcut and source' ($code -eq 0 -and (($out | Out-String) -match 'remove the shortcut') -and (($out | Out-String) -match 'event-log source')) "exit $code; $($out | Out-String)"
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InstallPs1 -WhatIf -EngineOnly 2>&1
    $code = $LASTEXITCODE
    $text = ($out | Out-String)
    Check 'what-if: -EngineOnly names the engine and kb, not the broker or UI' ($code -eq 0 -and $text -match 'engine-only mode' -and $text -match 'purge-engine\.exe and kb' -and $text -notmatch 'purge-broker\.exe') "exit $code; $text"
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InstallPs1 -ProtectOnly -DataRootOnly -SkipBuild -WhatIf -ProgramFilesDir (Join-Path $Work 'inno-pf') -DataRoot (Join-Path $Work 'inno-dr') 2>&1
    $code = $LASTEXITCODE
    $text = ($out | Out-String)
    Check 'what-if: the setup mode protects the payload and makes the data root, no build' ($code -eq 0 -and $text -match 'setup mode' -and $text -match 'protect .* and every object below it' -and $text -match 'data-root tree' -and $text -match 'event-log source' -and $text -notmatch 'cargo build') "exit $code; $text"
}

# ---------------------------------------------------------------------- the real entry point refuses without elevation
$elevated = (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) {
    $rep = Join-Path $Work 'report.json'
    $ErrorActionPreference = 'Continue'
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $InstallPs1 -Check -ReportPath $rep 2>&1
    $ErrorActionPreference = 'Stop'
    $code = $LASTEXITCODE
    $j = if (Test-Path -LiteralPath $rep) { [IO.File]::ReadAllText($rep) | ConvertFrom-Json } else { $null }
    Check 'entry: non-elevated run exits 1 and says why' ($code -eq 1 -and (($out | Out-String) -match 'run elevated')) "exit $code; $($out | Out-String)"
    Check 'entry: report written with schema purge.install/1' ($j -and $j.schema -eq 'purge.install/1' -and -not $j.ok -and $j.error -match 'elevated')
} else {
    Write-Host 'skip non-elevated entry-point check (this shell is elevated)'
}
} catch {
    Check 'self-test ran without an unexpected error' $false "$($_.Exception.Message) at $($_.InvocationInfo.PositionMessage)"
} finally {
    # The temp tree may still hold junctions if a check failed midway: remove links as links.
    Get-ChildItem -LiteralPath $Work -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue | ForEach-Object { try { [IO.Directory]::Delete($_.FullName, $false) } catch { } }
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "$script:passes passed, $script:fails failed"
if ($script:fails) { exit 1 }
exit 0
