# Purge rig, M2: benign per-action-type fidelity fixtures (ENGINE_PLAN.md section 10.2 "Execute, then deep
# round-trip undo", 10.3 undo_fidelity). Windows PowerShell 5.1, 64-bit, elevated, inside the test VM only.
#
# Builds, under C:\Program Files\PurgeFixtureApp, HKLM\SOFTWARE\PurgeFixtureApp, HKU\<sid>\Software\
# PurgeFixtureApp (+ PurgeFixtureNested, + the shared key HKLM\SOFTWARE\PurgeFixtureShared and one segment
# appended to the machine and user PATH), one fixture per executor action type and per 10.3 fidelity field:
#   files     content, attributes, ADS list, link count (two hard links both inside the plan), FileId,
#             nested directories, unicode names, delete-if-empty (empty and no-longer-empty)
#   registry  a key tree with every value type, odd data (no terminator, embedded NULs, wrong-size DWORD,
#             unknown type, empty binary), odd names, a key class, a custom DACL; single value deletes;
#             delete-if-empty keys; a ';' PATH segment (machine and user); a REG_MULTI_SZ segment
#   nesting   the nested-delete sequence leftover lists emit (a value, its key, then each ancestor listed
#             as its own item, deepest first), for files and keys, to exercise absorption and ordering
#
# A hand-built purge.scan/0 + plan with a correct plan hash cannot be produced from PowerShell, so the
# script emits, into -OutDir:
#   m2-fixtures-manifest.json  purge.rig.m2fixtures/0: objects, items with expected outcomes, protected
#                              objects (canaries) with hashes, and the measured fidelity fields of every
#                              fixture object after the build (the reference for a post-undo comparison)
#   m2-fixtures-targets.json   purge.rig.targets/0 for `purge-engine plan from-targets` (rig-exec only)
#   m2-fixtures-select.json    purge.rig.select/0: the rig item ids (mapped to candidate ids by target)
#   m2-fixtures-paths.txt      file-system item paths for `purge-engine scan --path`
#
# Actions: build (default) | check -Phase after-exec|after-undo | reset.  -DryRun prints the static
# manifest (placeholders {user-sid}, ControlSet001) and changes nothing.
#   check after-exec  canaries intact; each list value (PATH, multi-sz) equals its data before the build
#   check after-undo  canaries intact; list values equal their data after the build; every measured
#                     fidelity field of every fixture object equals the build-time measurement
# The native helpers, object interpreter and outputs are shared with m2-traps.ps1 (dot-sourced -Library).
[CmdletBinding()]
param(
    [ValidateSet('build', 'check', 'reset')]
    [string]$Action = 'build',
    [ValidateSet('after-exec', 'after-undo')]
    [string]$Phase = 'after-undo',
    [string]$OutDir = '',
    [switch]$DryRun
)

# Dot-sourcing m2-traps.ps1 binds its parameters in this scope too: keep ours first.
$Fx = @{ Action = $Action; Phase = $Phase; OutDir = $OutDir; DryRun = [bool]$DryRun }
. (Join-Path $PSScriptRoot 'm2-traps.ps1') -Library
$Action = $Fx.Action; $Phase = $Fx.Phase; $OutDir = $Fx.OutDir; $DryRun = $Fx.DryRun
$ErrorActionPreference = 'Stop'

$M2FixRoot = 'C:\Program Files\PurgeFixtureApp'

# Names built from code points so this file stays ASCII (Windows PowerShell reads BOM-less files as ANSI).
$U8 = -join @([char]0x00FC, '-', [char]0x540D, [char]0x524D)                     # u-umlaut, two CJK characters
$UGreek = -join @([char]0x03A9, [char]0x03BC, [char]0x03B5, [char]0x03B3, [char]0x03B1)

function Get-M2FixtureTable([string]$Sid, [string]$ControlSet) {
    $R = $M2FixRoot; $K = 'HKLM\SOFTWARE\PurgeFixtureApp'; $UK = "HKU\$Sid\Software\PurgeFixtureApp"
    $NK = "HKU\$Sid\Software\PurgeFixtureNested"; $SK = 'HKLM\SOFTWARE\PurgeFixtureShared'
    $Env = "HKLM\SYSTEM\$ControlSet\Control\Session Manager\Environment"; $UEnv = "HKU\$Sid\Environment"
    $binAll = [byte[]](0..255)
    $tf = New-Object System.Collections.ArrayList
    function Add-Fx([string]$Id, [string]$Kind, [string]$Summary, $Objects, $Items, $FsRoots = @(), $RegRoots = @(), [hashtable]$More = @{}) {
        $f = [ordered]@{
            id = $Id; gate = $Kind; stage = 'post-install'; summary = $Summary
            objects = @($Objects); items = @($Items); fs_roots = @($FsRoots); reg_roots = @($RegRoots)
            fs_root_globs = @(); guarded_roots = @(); expect = $null; post_checks = @(); helper = $null; medium = $null
        }
        foreach ($n in $More.Keys) { $f[$n] = $More[$n] }
        [void]$tf.Add($f)
    }

    # ---------------------------------------------------------------------------------------- files
    Add-Fx 'file-ads' 'QuarantineMove' 'A file with two alternate data streams (one of them Zone.Identifier).' @(
        (O 'file' @{ path = "$R\ads\ads.bin"; bytes = [byte[]]($binAll + $binAll + $binAll + $binAll) }),
        (O 'stream' @{ path = "$R\ads\ads.bin"; stream = 'meta'; text = "fixture stream`n" }),
        (O 'stream' @{ path = "$R\ads\ads.bin"; stream = 'Zone.Identifier'; text = "[ZoneTransfer]`r`nZoneId=3`r`n" })
    ) @((TItem 'file-ads.file' (TPath "$R\ads\ads.bin") 'Quarantine' (EDone 'content, attributes, ADS list and FileId restored'))) @("$R\ads")

    Add-Fx 'hardlink-in-plan' 'QuarantineMove' 'Two hard links to one file, both inside the moved directory: not blocked; link count 2 after undo.' @(
        (O 'file' @{ path = "$R\hardlinks\a.dll"; text = "hard linked inside the plan`n" }),
        (O 'hardlink' @{ path = "$R\hardlinks\copy\a-link.dll"; existing = "$R\hardlinks\a.dll" })
    ) @((TItem 'hardlink-in-plan.dir' (TPath "$R\hardlinks") 'Quarantine' (EDone 'moved; undo restores both names with link count 2'))) @("$R\hardlinks")

    Add-Fx 'nested-dirs' 'QuarantineMove' 'Nested directories with files at every depth, empty directories and unicode names.' @(
        (O 'file' @{ path = "$R\tree\top.txt"; text = "top`n" }),
        (O 'file' @{ path = "$R\tree\a\one.txt"; text = "one`n" }),
        (O 'file' @{ path = "$R\tree\a\b\two.txt"; text = "two`n" }),
        (O 'file' @{ path = "$R\tree\a\b\c\three.bin"; bytes = $binAll }),
        (O 'file' @{ path = "$R\tree\$U8\$UGreek.txt"; text = "unicode`n" }),
        (O 'file' @{ path = "$R\tree\empty-file.txt"; text = '' }),
        (O 'dir' @{ path = "$R\tree\empty\deeper" })
    ) @((TItem 'nested-dirs.dir' (TPath "$R\tree") 'Quarantine' (EDone 'moved whole; undo restores every name, file and empty directory'))) @("$R\tree")

    Add-Fx 'empty-dir' 'RemoveDirIfEmpty' 'An empty directory.' @(
        (O 'dir' @{ path = "$R\empty-dir" })
    ) @((TItem 'empty-dir.dir' (TPath "$R\empty-dir") 'RemoveDirIfEmpty' (EDone 'removed; undo recreates it'))) @("$R\empty-dir")

    Add-Fx 'not-empty-dir' 'RemoveDirIfEmpty' 'A delete-if-empty directory that holds a file outside the plan.' @(
        (O 'canary-file' @{ id = 'fx.not-empty.user-file'; path = "$R\not-empty\user-added.txt" })
    ) @((TItem 'not-empty-dir.dir' (TPath "$R\not-empty") 'RemoveDirIfEmpty' (ESkipped 'NoLongerEmpty'))) @("$R\not-empty")

    # ------------------------------------------------------------------------------------- registry
    $longName = 'long-' + ('n' * 300)
    $treeVals = @(
        (V '' $REG_SZ (BSz 'default value')),
        (V 'sz' $REG_SZ (BSz 'hello')),
        (V 'sz-empty' $REG_SZ (BSz '')),
        (V 'sz-noterm-odd' $REG_SZ ([byte[]](0x41, 0x00, 0x42))),
        (V 'sz-embedded-nul' $REG_SZ ([Text.Encoding]::Unicode.GetBytes("a$([char]0)b$([char]0)"))),
        (V 'expand' $REG_EXPAND_SZ (BSz '%ProgramFiles%\PurgeFixtureApp')),
        (V 'binary' $REG_BINARY $binAll),
        (V 'binary-empty' $REG_BINARY ([byte[]]@())),
        (V 'dword' $REG_DWORD (BHex 'EFBEADDE')),   # 0xDEADBEEF (a PowerShell literal would be a negative Int32)
        (V 'dword-short' $REG_DWORD ([byte[]](1, 2, 3))),
        (V 'dword-be' $REG_DWORD_BE ([byte[]](1, 2, 3, 4))),
        (V 'multi' $REG_MULTI_SZ (BMulti @('one', '', 'three'))),
        (V 'multi-empty' $REG_MULTI_SZ ([byte[]](0, 0))),
        (V 'resource-list' $REG_RESOURCE_LIST (BHex '0100000000000000')),
        (V 'full-resource' $REG_FULL_RESOURCE (BHex '00000000000000000100')),
        (V 'requirements' $REG_RESOURCE_REQ (BHex '20000000')),
        (V 'qword' $REG_QWORD (BQword 0x0123456789ABCDEF)),
        (V 'none' $REG_NONE ([byte[]](1, 2))),
        (V 'custom-type' 0x12345678 ([byte[]](9, 8, 7))),
        (V 'name\with\backslashes' $REG_SZ (BSz 'backslash name')),
        (V "$U8 $UGreek" $REG_SZ (BSz $UGreek)),
        (V $longName $REG_DWORD (BDword 7))
    )
    $treeObjs = New-Object System.Collections.ArrayList
    [void]$treeObjs.Add((O 'key' @{ path = "$K\Tree"; class = 'PurgeFixtureClass' }))
    foreach ($v in $treeVals) { [void]$treeObjs.Add((O 'value' @{ path = "$K\Tree"; name = $v.name; type = $v.type; data = $v.data })) }
    foreach ($o in @(
            (O 'key' @{ path = "$K\Tree\Sub1"; class = 'Sub1Class' }),
            (O 'value' @{ path = "$K\Tree\Sub1"; name = 'v'; type = $REG_DWORD; data = (BDword 1) }),
            (O 'key' @{ path = "$K\Tree\Sub1\Sub2 trailing space " }),
            (O 'value' @{ path = "$K\Tree\Sub1\Sub2 trailing space "; name = 'v'; type = $REG_SZ; data = (BSz 'deep') }),
            (O 'key' @{ path = "$K\Tree\$U8" }),
            (O 'value' @{ path = "$K\Tree\$U8"; name = ''; type = $REG_SZ; data = (BSz 'unicode key') }),
            (O 'key' @{ path = "$K\Tree\EmptySub" }),
            (O 'key-sddl' @{ path = "$K\Tree"; sddl = 'O:BAG:SYD:PAI(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KR;;;BU)(A;CI;KR;;;S-1-15-2-1)' }),
            (O 'key-sddl' @{ path = "$K\Tree\Sub1"; sddl = 'O:SYG:SYD:PAI(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CIIO;GR;;;BU)' }))) { [void]$treeObjs.Add($o) }
    Add-Fx 'key-tree' 'DeleteKeyTree' 'A key tree with every value type, odd data and names, key classes, a trailing-space and a unicode subkey, custom DACLs.' $treeObjs @(
        (TItem 'key-tree.key' (TKey "$K\Tree") 'DeleteKey' (EDone 'every value (name, type, raw bytes), class and owner/group/DACL restored'))
    ) @() @("$K\Tree")

    Add-Fx 'user-key-tree' 'DeleteKeyTree' 'A key tree in the user hive.' @(
        (O 'key' @{ path = "$UK\Settings" }),
        (O 'value' @{ path = "$UK\Settings"; name = 'Theme'; type = $REG_SZ; data = (BSz 'dark') }),
        (O 'value' @{ path = "$UK\Settings"; name = 'Window'; type = $REG_BINARY; data = (BHex '0A000B000C000D00') }),
        (O 'key' @{ path = "$UK\Settings\Recent" }),
        (O 'value' @{ path = "$UK\Settings\Recent"; name = 'MRUList'; type = $REG_SZ; data = (BSz 'ba') }),
        (O 'value' @{ path = "$UK\Settings\Recent"; name = 'a'; type = $REG_SZ; data = (BSz 'C:\one.txt') }),
        (O 'value' @{ path = "$UK\Settings\Recent"; name = 'b'; type = $REG_SZ; data = (BSz 'C:\two.txt') })
    ) @((TItem 'user-key-tree.key' (TKey "$UK\Settings") 'DeleteKey' (EDone 'restored with every value'))) @() @("$UK\Settings")

    Add-Fx 'value-delete' 'DeleteValue' 'Single values deleted from a key that stays (with a value outside the plan).' @(
        (O 'key' @{ path = "$K\Values" }),
        (O 'canary-value' @{ id = 'fx.values.keep'; path = "$K\Values"; name = 'keep'; type = $REG_SZ; data = (BSz 'not in the plan') }),
        (O 'value' @{ path = "$K\Values"; name = ''; type = $REG_SZ; data = (BSz 'default to delete') }),
        (O 'value' @{ path = "$K\Values"; name = 'del-sz'; type = $REG_EXPAND_SZ; data = (BSz '%TEMP%\x') }),
        (O 'value' @{ path = "$K\Values"; name = 'del-binary'; type = $REG_BINARY; data = $binAll }),
        (O 'value' @{ path = "$K\Values"; name = 'del-multi'; type = $REG_MULTI_SZ; data = (BMulti @('a', 'b')) }),
        (O 'value' @{ path = "$K\Values"; name = 'del-odd'; type = 0x12345678; data = ([byte[]](0xFF)) })
    ) @(
        (TItem 'value-delete.default' (TVal "$K\Values" '') 'DeleteValue' (EDone)),
        (TItem 'value-delete.sz' (TVal "$K\Values" 'del-sz') 'DeleteValue' (EDone)),
        (TItem 'value-delete.binary' (TVal "$K\Values" 'del-binary') 'DeleteValue' (EDone)),
        (TItem 'value-delete.multi' (TVal "$K\Values" 'del-multi') 'DeleteValue' (EDone)),
        (TItem 'value-delete.odd' (TVal "$K\Values" 'del-odd') 'DeleteValue' (EDone))
    ) @() @("$K\Values")

    Add-Fx 'empty-key' 'DeleteKeyIfEmpty' 'An empty key.' @(
        (O 'key' @{ path = "$K\EmptyKey" })
    ) @((TItem 'empty-key.key' (TKey "$K\EmptyKey") 'RemoveDirIfEmpty' (EDone 'removed; undo recreates it'))) @() @("$K\EmptyKey")

    Add-Fx 'not-empty-key' 'DeleteKeyIfEmpty' 'A delete-if-empty key that holds a value outside the plan.' @(
        (O 'key' @{ path = "$K\NotEmptyKey" }),
        (O 'canary-value' @{ id = 'fx.not-empty-key.foreign'; path = "$K\NotEmptyKey"; name = 'foreign'; type = $REG_DWORD; data = (BDword 42) })
    ) @((TItem 'not-empty-key.key' (TKey "$K\NotEmptyKey") 'RemoveDirIfEmpty' (ESkipped 'NoLongerEmpty'))) @() @("$K\NotEmptyKey")

    $seg = 'C:\Program Files\PurgeFixtureApp\bin'
    Add-Fx 'path-segment-machine' 'EditSegment' 'One segment appended to the machine PATH (REG_EXPAND_SZ); the other segments are not in the plan.' @(
        (O 'path-segment' @{ path = $Env; name = 'Path'; segment = $seg })
    ) @((TItem 'path-segment-machine.seg' (TSeg $Env 'Path' $seg) 'EditSegment' (EDone 'segment removed, the rest byte-identical; undo re-inserts it at its index'))) @() @()

    Add-Fx 'path-segment-user' 'EditSegment' 'One segment appended to the user PATH, when the profile has one (optional).' @(
        (O 'path-segment' @{ path = $UEnv; name = 'Path'; segment = $seg; optional = $true })
    ) @((TItem 'path-segment-user.seg' (TSeg $UEnv 'Path' $seg) 'EditSegment' (EDone 'segment removed, the rest byte-identical; undo re-inserts it') 'main' @() 'only when build.objects shows the segment added')) @() @()

    Add-Fx 'multisz-segment' 'EditSegment' 'One string of a REG_MULTI_SZ in a key outside the plan.' @(
        (O 'key' @{ path = $SK }),
        (O 'value' @{ path = $SK; name = 'Members'; type = $REG_MULTI_SZ; data = (BMulti @('Other.One', 'PurgeFixtureApp', 'Other.Two')) })
    ) @((TItem 'multisz-segment.seg' (TSeg $SK 'Members' 'PurgeFixtureApp' 1) 'EditSegment' (EDone 'string removed, the others kept in order; undo re-inserts it at index 1'))) @() @($SK) @{
        phase_values = @([ordered]@{
                path = $SK; name = 'Members'; type = $REG_MULTI_SZ
                after_exec_b64 = (M2-B64 (BMulti @('Other.One', 'Other.Two'))); after_undo_b64 = (M2-B64 (BMulti @('Other.One', 'PurgeFixtureApp', 'Other.Two')))
            })
    }

    # ------------------------------------------------------------------------------ nested sequence
    Add-Fx 'nested-sequence' 'Nesting' 'Leftover lists name a value, its key and every ancestor as separate items (and a file, its directory and every ancestor): deepest first, absorbed children may report Vanished.' @(
        (O 'file' @{ path = "$R\nested\A\a.txt"; text = "a`n" }),
        (O 'file' @{ path = "$R\nested\A\B\b.txt"; text = "b`n" }),
        (O 'file' @{ path = "$R\nested\A\B\C\leaf.txt"; text = "leaf`n" }),
        (O 'key' @{ path = "$NK\A" }),
        (O 'value' @{ path = "$NK\A"; name = 'a'; type = $REG_SZ; data = (BSz 'a') }),
        (O 'key' @{ path = "$NK\A\B" }),
        (O 'value' @{ path = "$NK\A\B"; name = 'b'; type = $REG_SZ; data = (BSz 'b') }),
        (O 'key' @{ path = "$NK\A\B\C" }),
        (O 'value' @{ path = "$NK\A\B\C"; name = 'leaf'; type = $REG_SZ; data = (BSz 'leaf') })
    ) @(
        (TItem 'nested-sequence.file' (TPath "$R\nested\A\B\C\leaf.txt") 'Quarantine' (EDone) 'main' @((EOutcome 'Vanished' 'absorbed by an ancestor item'))),
        (TItem 'nested-sequence.dir-c' (TPath "$R\nested\A\B\C") 'Quarantine' (EDone) 'main' @((EOutcome 'Vanished' 'absorbed by an ancestor item'))),
        (TItem 'nested-sequence.dir-b' (TPath "$R\nested\A\B") 'Quarantine' (EDone) 'main' @((EOutcome 'Vanished' 'absorbed by an ancestor item'))),
        (TItem 'nested-sequence.dir-a' (TPath "$R\nested\A") 'Quarantine' (EDone 'the whole tree is gone; undo restores every level')),
        (TItem 'nested-sequence.value' (TVal "$NK\A\B\C" 'leaf') 'DeleteValue' (EDone) 'main' @((EOutcome 'Vanished' 'absorbed by an ancestor item'))),
        (TItem 'nested-sequence.key-c' (TKey "$NK\A\B\C") 'DeleteKey' (EDone) 'main' @((EOutcome 'Vanished' 'absorbed by an ancestor item'))),
        (TItem 'nested-sequence.key-b' (TKey "$NK\A\B") 'DeleteKey' (EDone) 'main' @((EOutcome 'Vanished' 'absorbed by an ancestor item'))),
        (TItem 'nested-sequence.key-a' (TKey "$NK\A") 'DeleteKey' (EDone 'the whole tree is gone; undo restores every level'))
    ) @("$R\nested") @($NK)

    , $tf
}

# Fidelity fields (10.3) of every file-system and registry object a fixture created, after the build.
function Measure-M2FixtureObjects($Table) {
    $N = [PurgeRigM2.Native]
    $seen = @{}
    foreach ($t in $Table) {
        foreach ($o in $t.objects) {
            if (-not $o.Contains('path')) { continue }
            $isReg = $o.k -in @('key', 'value', 'key-sddl', 'canary-value')
            $isFs = $o.k -in @('file', 'dir', 'hardlink', 'stream', 'canary-file')
            if (-not ($isReg -or $isFs) -or $seen.ContainsKey("$isReg|$($o.path)")) { continue }
            $seen["$isReg|$($o.path)"] = $true
            $m = [ordered]@{ fixture = $t.id; kind = $(if ($isReg) { 'regkey' } else { 'path' }); path = $o.path }
            try {
                if ($isFs) {
                    $f = $N::Facts($o.path)
                    if (-not $f) { $m.present = $false } else {
                        $m.present = $true; $m.is_dir = $f.IsDir; $m.attributes = ('0x{0:X8}' -f $f.Attributes); $m.links = $f.Links
                        $m.file_id = $f.FileId; $m.volume_serial = $f.VolumeSerial
                        if (-not $f.IsDir) { $m.sha256 = M2-Sha256 ($N::ReadAll($o.path)); $m.streams = @($N::Streams($o.path)) }
                    }
                } else {
                    $vals = $N::Values($o.path)
                    if ($null -eq $vals) { $m.present = $false } else {
                        $m.present = $true; $m.class = $N::KeyClass($o.path); $m.sddl = $N::GetKeySddl($o.path)
                        $m.values_sha256 = Get-RegValuesHash @($vals | ForEach-Object { [ordered]@{ name = $_.Name; type = $_.Type; data = $_.Data } })
                        $m.value_count = @($vals).Count
                    }
                }
            } catch { $m.error = $_.Exception.Message }
            $m
        }
    }
}

# ==================================================================================== main (fixtures)

$sidForTable = $(if ($DryRun) { '{user-sid}' } else { $RigUserSid })
$cs = 'ControlSet001'
if (-not $DryRun) {
    $sel = Get-M2RawValue 'HKLM\SYSTEM\Select' 'Current'
    if ($sel) { $cs = 'ControlSet{0:000}' -f [BitConverter]::ToUInt32($sel.Data, 0) }
}
$Table = Get-M2FixtureTable $sidForTable $cs
$Roots = [ordered]@{
    fixture_root = $M2FixRoot; fixture_keys = @('HKLM\SOFTWARE\PurgeFixtureApp', "HKU\$sidForTable\Software\PurgeFixtureApp", "HKU\$sidForTable\Software\PurgeFixtureNested", 'HKLM\SOFTWARE\PurgeFixtureShared')
    control_set = $(if ($DryRun) { 'ControlSet001 in a dry run; resolved from HKLM\SYSTEM\Select\Current when built' } else { $cs })
}
if (-not $OutDir -and -not $DryRun) { $OutDir = 'C:\cr\out\m2-fixtures' }
if ($OutDir) { New-Item -ItemType Directory -Force $OutDir | Out-Null }
$ManifestPath = $(if ($OutDir) { Join-Path $OutDir 'm2-fixtures-manifest.json' } else { $null })

switch ($Action) {
    'build' {
        $doc = New-M2Doc 'purge.rig.m2fixtures/0' 'vm/guest/m2-fixtures.ps1' $Table $Roots $sidForTable $DryRun
        if ($DryRun) {
            if ($OutDir) {
                Write-M2Json $doc $ManifestPath
                Write-M2Targets $Table $OutDir 'm2-fixtures' 'm2-fixtures'
                Log "dry run: manifest and targets -> $OutDir"
            } else { ConvertTo-Json -InputObject $doc -Depth 30 }
            exit 0
        }
        Assert-M2Elevated
        if (Get-Command Set-RunLog -ErrorAction SilentlyContinue) { Set-RunLog (Join-Path $OutDir 'm2-fixtures.log') }
        Log "m2-fixtures build on $env:COMPUTERNAME (sid $RigUserSid, $cs)"
        Remove-Item -LiteralPath $ManifestPath -Force -ErrorAction SilentlyContinue
        $failed = Invoke-M2Build $Table $doc $ManifestPath ''
        # List values: the data before and after the build, for the after-exec / after-undo checks.
        $pv = New-Object System.Collections.ArrayList
        foreach ($i in 0..($Table.Count - 1)) {
            $t = $Table[$i]; $d = $doc.traps[$i]
            foreach ($p in @($t['phase_values'])) { if ($p) { [void]$pv.Add($p) } }
            if ($d.build) {
                foreach ($s in @($d.build.objects)) {
                    if ($s.k -eq 'path-segment' -and $s.ok) {
                        $o = @($t.objects | Where-Object { $_.k -eq 'path-segment' })[0]
                        [void]$pv.Add([ordered]@{ path = $o.path; name = $o.name; type = $s.detail.type; after_exec_b64 = $s.detail.before_b64; after_undo_b64 = $s.detail.after_b64 })
                        $it = @($d.items | Where-Object { $_.target.type -eq 'RegMultiSzSegment' })[0]
                        if ($it) { $it.target.index = [int]$s.detail.index }
                    }
                }
            }
        }
        $doc.phase_values = $pv
        $doc.fidelity = @(Measure-M2FixtureObjects $Table)
        Write-M2Json $doc $ManifestPath
        # Targets from the built document (PATH segment indexes filled in).
        $built = @(for ($i = 0; $i -lt $Table.Count; $i++) { $x = $Table[$i]; $x.items = $doc.traps[$i].items; $x })
        Write-M2Targets $built $OutDir 'm2-fixtures' 'm2-fixtures'
        if ($failed) { exit 1 }
        exit 0
    }
    'check' {
        if (-not (Test-Path -LiteralPath $ManifestPath)) { throw "no manifest at $ManifestPath (run build first)" }
        $doc = Get-Content -Raw -Encoding UTF8 -LiteralPath $ManifestPath | ConvertFrom-Json
        $r = Invoke-M2Check $doc $Phase
        $r.schema = 'purge.rig.m2fixtures.check/0'
        $vals = @(foreach ($p in @($doc.phase_values)) {
                $want = $(if ($Phase -eq 'after-exec') { $p.after_exec_b64 } else { $p.after_undo_b64 })
                $v = Get-M2RawValue $p.path $p.name
                $got = $(if ($v) { M2-B64 ([byte[]]$v.Data) } else { $null })
                [ordered]@{ path = $p.path; name = $p.name; ok = ($got -eq $want -and (-not $v -or $v.Type -eq [int]$p.type)); expected_b64 = $want; actual_b64 = $got }
            })
        $r.phase_values = $vals
        $diff = @()
        if ($Phase -eq 'after-undo') {
            $now = @(Measure-M2FixtureObjects $Table)
            # Directories a RemoveDirIfEmpty item removed: undo recreates them, a new directory with a new FileId by
            # design (docs\M2_DESIGN.json: RecreateDir); every other field is still compared.
            $recreated = @(foreach ($t in $Table) { foreach ($i in @($t.items)) { if ($i.action -eq 'RemoveDirIfEmpty' -and $i.target.type -eq 'Path') { "$($i.target.path)" } } })
            $diff = @(foreach ($a in @($doc.fidelity)) {
                    $b = @($now | Where-Object { $_.kind -eq $a.kind -and $_.path -eq $a.path }) | Select-Object -First 1
                    $skip = @('fixture', 'kind', 'path', 'error')
                    if ($a.kind -eq 'path' -and $a.is_dir -and @($recreated | Where-Object { $_ -ieq $a.path }).Count) { $skip += 'file_id' }
                    $vals = [ordered]@{}
                    $fields = @(foreach ($p in $a.PSObject.Properties) {
                            if ($p.Name -in $skip) { continue }
                            # (Not $( ): it unrolls a one-element array, e.g. streams, to a scalar.)
                            $bv = $null; if ($b -and $b.Contains($p.Name)) { $bv = $b[$p.Name] }
                            $ja = ConvertTo-Json -InputObject $p.Value -Compress; $jb = ConvertTo-Json -InputObject $bv -Compress
                            if ($ja -ne $jb) { $vals[$p.Name] = [ordered]@{ build = $ja; now = $jb }; $p.Name }
                        })
                    if ($fields.Count) { [ordered]@{ fixture = $a.fixture; kind = $a.kind; path = $a.path; fields = $fields; values = $vals } }
                })
        }
        $r.fidelity_mismatches = $diff
        $r.ok = $r.ok -and -not @($vals | Where-Object { -not $_.ok }).Count -and -not $diff.Count
        Write-M2Json $r (Join-Path $OutDir "m2-fixtures-check-$Phase.json")
        Log "check $Phase : guard_escapes=$($r.guard_escapes) list values bad=$(@($vals | Where-Object { -not $_.ok }).Count) fidelity mismatches=$($diff.Count)"
        if ($r.ok) { exit 0 } else { exit 1 }
    }
    'reset' {
        Assert-M2Elevated
        $bad = 0
        foreach ($t in $Table) { try { Reset-M2Trap $t -Lenient } catch { $bad++; Log "  !! reset $($t.id): $($_.Exception.Message)" } }
        $N = [PurgeRigM2.Native]
        try { $N::RemoveTree($M2FixRoot) } catch { $bad++; Log "  !! $M2FixRoot : $($_.Exception.Message)" }
        foreach ($k in @('HKLM\SOFTWARE\PurgeFixtureApp', "HKU\$RigUserSid\Software\PurgeFixtureApp", "HKU\$RigUserSid\Software\PurgeFixtureNested", 'HKLM\SOFTWARE\PurgeFixtureShared')) {
            try { [void]$N::DeleteTree($k) } catch { $bad++; Log "  !! $k : $($_.Exception.Message)" }
        }
        Log "reset done ($bad problem(s))"
        if ($bad) { exit 1 } else { exit 0 }
    }
}
