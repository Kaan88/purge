# Host self-test for install\install.ps1. Needs no elevation and no VM: the pure parts (SDDL builder,
# canonical form, integrity verdict, rename-aside naming, the install loop over a fake file system) run in
# memory, and the native layer is exercised only inside a fresh folder under %TEMP% (create with a
# descriptor, CREATE_NEW refusal, reparse detection, handle-based rename of a junction, non-following
# removal). Nothing outside that folder is written. Windows PowerShell 5.1:
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
