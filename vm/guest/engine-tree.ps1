# Purge rig v2: the engine's baseline tree C:\cr\bin\kb as the engine's directory rule wants it
# (docs\BASELINE_LOCAL_DESIGN.md section 5 "The shipped directory", review BL-R1 M1; vm\RIG.md section 4a).
#
# An elevated engine uses <exe dir>\kb\baselines only when administrators and the system alone can write that
# directory and every ancestor (purge-win sid.rs is_admin_only_writable: every component is owned by SYSTEM,
# Administrators or TrustedInstaller; nobody else may delete, rename, re-ACL or take a component, or write the
# directory itself; the exact baseline file is judged the same way). C:\cr is made below the drive root and
# inherits Modify for Authenticated Users, and the host copies the files as the unelevated guest user, so without
# this file the rig's elevated engine drops every shipped baseline, says so in one warning line and scans
# values-only.
#
# Functions only: nothing runs when the file is dot-sourced. The host (rig.ps1 Push-Tools) appends one call of
# Invoke-RigEngineTreeJob and submits the text as an agent job (elevated); run-app.ps1 gets the functions through
# riglib.ps1. Windows PowerShell 5.1.
#
#   protect: C:\cr\bin\kb  and everything in it: owner Administrators; protected DACL: SYSTEM and Administrators
#                          full, Users read and execute; the files inherit exactly that.
#            C:\cr\bin,    the two ancestors below the drive root: owner Administrators; protected DACL like a
#            C:\cr         drive root's: SYSTEM and Administrators full; Authenticated Users read/execute and
#                          "create files / create folders" on the folder itself, Modify on what lies below
#                          (inherit-only). The rig's unelevated copies into C:\cr\bin, \guest, \stage, \jobs, \out
#                          and \inst work as before, and nobody but an administrator can delete, rename or re-ACL
#                          C:\cr, C:\cr\bin or C:\cr\bin\kb.
#   open:    all three back to plain inheritance from the drive root, so the unelevated host copy can replace the
#            baselines (a second Push-Tools without a snapshot restore in between).

$RigEngineTree = 'C:\cr\bin'
$RigEngineTreeParent = 'C:\cr'
# SYSTEM, Administrators, TrustedInstaller: the owners and writers the directory rule accepts.
$RigAdminSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
# CREATOR OWNER, CREATOR GROUP, OWNER RIGHTS: they grant nothing on the object itself.
$RigPlaceholderSids = @('S-1-3-0', 'S-1-3-1', 'S-1-3-4')
# sid.rs LEAF_WRITE_MASK: write data, append, delete child, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE.
$RigLeafWriteMask = 0x500D0046
# sid.rs ANCESTOR_WRITE_MASK: delete child, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL.
$RigAncestorWriteMask = 0x100D0040
# The baseline tree. O:BA G:BA, protected and auto-inherited DACL. FA = full, 0x1200a9 = read and execute.
$RigBaselineTreeSddl = 'O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
# Its ancestors. 0x1200af = read and execute plus FILE_ADD_FILE and FILE_ADD_SUBDIRECTORY (this folder only);
# 0x1301bf = Modify (inherit-only: what lies below).
$RigAncestorSddl = 'O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200af;;;AU)(A;OICIIO;0x1301bf;;;AU)'
# Pure: what keeps one security descriptor (SDDL) from being admin-only, as sid.rs `admin_only` judges it:
# a non-administrative owner, no DACL, or an allow ACE that applies to the object itself (not inherit-only) and
# gives a non-administrative SID a right of the mask. -Leaf selects the stricter mask of the path itself.
function Get-RigSddlProblems([string]$Sddl, [switch]$Leaf) {
    $out = @()
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    $owner = $null
    if ($sd.Owner) { $owner = $sd.Owner.Value }
    if (-not $owner -or $RigAdminSids -notcontains $owner) { $out += "owner $owner is not SYSTEM, Administrators or TrustedInstaller" }
    if ($null -eq $sd.DiscretionaryAcl) { return @($out + 'no DACL (everyone has full access)') }
    $mask = $RigAncestorWriteMask
    if ($Leaf) { $mask = $RigLeafWriteMask }
    foreach ($ace in $sd.DiscretionaryAcl) {
        $type = "$($ace.AceType)"
        if ($type -notmatch '^AccessAllowed') { continue }
        if (([int]$ace.AceFlags -band 0x08) -ne 0) { continue }
        $sid = $null
        if ($ace.SecurityIdentifier) { $sid = $ace.SecurityIdentifier.Value }
        if (-not $sid) { $out += "an allow ACE ($type) without a readable SID"; continue }
        if (($ace.AccessMask -band $mask) -eq 0) { continue }
        if ($RigAdminSids -contains $sid -or $RigPlaceholderSids -contains $sid) { continue }
        $out += ('{0} may write (mask 0x{1:x})' -f $sid, ($ace.AccessMask -band $mask))
    }
    @($out)
}

# What keeps $Path from being admin-only writable: the path itself (leaf mask) and every ancestor up to the
# volume root (ancestor mask), no reparse point on the way. Empty = the engine's rule accepts it.
function Get-RigAdminOnlyProblems([string]$Path) {
    $out = @()
    $leaf = $true
    $p = $Path.TrimEnd('\')
    while ($p) {
        $at = $p
        if ($at -match '^[A-Za-z]:$') { $at = $at + '\' }
        try {
            $item = Get-Item -LiteralPath $at -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $out += "${at}: a reparse point" }
            $sddl = (Get-Acl -LiteralPath $at -ErrorAction Stop).GetSecurityDescriptorSddlForm('Owner, Access')
            foreach ($problem in @(Get-RigSddlProblems -Sddl $sddl -Leaf:$leaf)) { $out += "${at}: $problem" }
        } catch {
            $out += "${at}: cannot be read ($($_.Exception.Message))"
        }
        $leaf = $false
        if ($at -match '^[A-Za-z]:\\$') { break }
        $p = Split-Path -Parent $p
    }
    @($out)
}

# What keeps the engine's baseline directory from passing the engine's rule: <tree>\kb\baselines with its
# ancestors, and every file in it (the exact baseline and view.json are judged themselves). Empty = an elevated
# engine uses kb\baselines.
function Get-RigEngineTreeProblems([string]$Tree = $RigEngineTree) {
    $baselines = Join-Path $Tree 'kb\baselines'
    if (-not (Test-Path -LiteralPath $baselines -PathType Container)) { return @("$baselines is missing") }
    $out = @()
    $paths = @($baselines) + @(Get-ChildItem -LiteralPath $baselines -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    foreach ($p in $paths) { $out += @(Get-RigAdminOnlyProblems $p) }
    @($out | Select-Object -Unique)
}

function Set-RigSddl([string]$Path, [string]$Sddl) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    # Owner, group and DACL only: no audit section, so no SeSecurityPrivilege is asked for.
    $acl.SetSecurityDescriptorSddlForm($Sddl, [System.Security.AccessControl.AccessControlSections]'Owner, Group, Access')
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Invoke-RigIcacls([string[]]$Arguments) {
    $out = & "$env:SystemRoot\System32\icacls.exe" @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls $($Arguments -join ' ') exited ${LASTEXITCODE}: $(@($out | Select-Object -Last 3) -join ' | ')" }
}

# Elevated. Makes C:\cr, C:\cr\bin and C:\cr\bin\kb what the header says and returns Get-RigEngineTreeProblems
# (empty = ok).
function Protect-RigEngineTree([string]$Tree = $RigEngineTree, [string]$Parent = $RigEngineTreeParent) {
    $kb = Join-Path $Tree 'kb'
    if (-not (Test-Path -LiteralPath (Join-Path $kb 'baselines') -PathType Container)) { throw "$kb\baselines is missing" }
    Set-RigSddl $Parent $RigAncestorSddl
    Set-RigSddl $Tree $RigAncestorSddl
    # The host copied the baselines as the unelevated guest user: they are that user's.
    Invoke-RigIcacls @($kb, '/setowner', '*S-1-5-32-544', '/T', '/C', '/Q')
    Set-RigSddl $kb $RigBaselineTreeSddl
    # Everything below: no ACE of its own, only what the tree hands down.
    Invoke-RigIcacls @((Join-Path $kb '*'), '/reset', '/T', '/C', '/Q')
    @(Get-RigEngineTreeProblems $Tree)
}

# Elevated. C:\cr, C:\cr\bin and everything below it back to plain inheritance, so the unelevated host copy can
# write the baselines.
function Open-RigEngineTree([string]$Tree = $RigEngineTree, [string]$Parent = $RigEngineTreeParent) {
    if (-not (Test-Path -LiteralPath $Parent -PathType Container)) { return }
    Invoke-RigIcacls @($Parent, '/reset', '/Q')
    if (Test-Path -LiteralPath $Tree -PathType Container) { Invoke-RigIcacls @($Tree, '/reset', '/T', '/C', '/Q') }
}
# The body of the host's engine-tree job (rig.ps1 Invoke-EngineTreeJob). The last line of the job log is
# 'ENGINE-TREE <action> OK' or 'ENGINE-TREE <action> FAILED: <why>'; the host reads nothing else.
function Invoke-RigEngineTreeJob([string]$Action) {
    try {
        if ($Action -eq 'open') {
            Open-RigEngineTree
        } elseif ($Action -eq 'protect') {
            $problems = @(Protect-RigEngineTree)
            if ($problems.Count) { throw ($problems -join '; ') }
        } else {
            throw "unknown action '$Action' (open, protect)"
        }
        "ENGINE-TREE $Action OK"
    } catch {
        "ENGINE-TREE $Action FAILED: $($_.Exception.Message)"
    }
}
