# Purge v1 deploy script (ENGINE_PLAN.md 3.2, 7.4, 7.9; M3-INSTALL). Windows PowerShell 5.1, 64-bit,
# elevated. -WhatIf needs no elevation: it prints the plan and changes nothing.
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -WhatIf
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -Check
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -Uninstall
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -ProtectOnly -DataRootOnly -SkipBuild
#       (Inno Setup's post-install step: the setup copied the payload; this protects it, creates the
#        data root and registers the event-log source. -Check then verifies the whole layout.)
#
# What it does (contract and the SDDL constants: install\README.md, the single documented source):
#   1. Builds the release artifacts: cargo build --release -p purge-engine, then
#      cargo build --release -p purge-broker, then cargo build --release -p purge-ui (separate builds,
#      install\README.md; purge-ui is the Rust UI, Purge.exe). -SkipBuild deploys artifacts that
#      already exist.
#   2. %ProgramFiles%\Purge: created with a protected admin-only-write DACL; purge-engine.exe,
#      purge-broker.exe, Purge.exe (or a folder holding it, -UiPublishDir) and the kb\ tree are
#      copied in (files whose SHA-256 already matches are left alone). Every deployed object is checked
#      against the broker's rule (owner, no non-administrator write) and re-protected when it fails.
#      purge-broker.exe must be the release build: one built with the cargo feature toolkit-consent
#      is refused (the staging marker, Assert-ReleaseBroker; -ToolkitBroker is the VM rig's way in).
#   3. %ProgramData%\Purge with sessions, Quarantine, fp, kb and sessions\index.json (created as "{}"):
#      every object is created with its own protected DACL in the same call that creates it
#      (CreateDirectoryW / CreateFileW CREATE_NEW with a security descriptor), so there is no window in
#      which an inherited ProgramData ACE lets a standard user in.
#   4. An existing tree is adopted only when every object in it is exactly what step 2/3 would create
#      (owner, protected DACL, ACEs; compared after canonical rendering) and nothing at its top two levels
#      is a reparse point. Anything else is never adopted and never recursed into: the tree's root is
#      renamed aside to <name>.rejected-<utc> through a handle opened with FILE_FLAG_OPEN_REPARSE_POINT
#      (so a junction is renamed, never followed), reported, and a fresh tree is created.
#   5. Registers the "Purge" Application event-log source (the broker's start failures go there), and
#      creates one all-users Start-menu shortcut to Purge.exe.
#   6. A run on a good tree changes nothing (idempotent). -Uninstall removes the Program Files copy, the
#      shortcut and the event-log source, never ProgramData\Purge. -Check verifies both trees, every
#      deployed file, the shortcut and the source, and changes nothing.
# It never downloads anything, never touches Defender or System Restore settings and signs nothing. It
# creates no service, task, run value or uninstall (ARP) entry; the event-log source is the one registry
# key M3-HARDEN requires.
#
# Dot-sourcing the script (". install.ps1") only defines its functions; install\tests\install-selftest.ps1
# uses that to test the pure parts (SDDL builder, canonical form, integrity verdict) without elevation.

[CmdletBinding()]
param(
    # purge-engine.exe to deploy. Default: the repo's target\release\purge-engine.exe.
    [string]$Engine = '',
    # purge-broker.exe to deploy. Default: the repo's target\release\purge-broker.exe. It must be the
    # release build: a broker built with --features toolkit-consent is refused (Assert-ReleaseBroker,
    # review S-A), wherever it is; the rig builds that one into its own --target-dir (vm\RIG.md 14).
    [string]$Broker = '',
    # Purge.exe (the Rust UI, bins\purge-ui) to deploy. Default: the repo's target\release\Purge.exe.
    [string]$Ui = '',
    # Instead of -Ui: a folder holding Purge.exe, copied as a whole (the VM rig's client folders).
    [string]$UiPublishDir = '',
    # kb directory to deploy beside the broker. Default: <engine dir>\kb when it exists, else the repo's kb\.
    [string]$Kb = '',
    # Use the artifacts as they are; run no cargo.
    [switch]$SkipBuild,
    # Inno Setup mode: the setup has already copied the payload into the program-files directory.
    # Create (or verify) only the data root and the event-log source; no build, no payload copy, no
    # shortcut (the setup's [Icons] entry makes it). Install mode only.
    [switch]$DataRootOnly,
    # Inno Setup mode: give the payload an installer already put in the program-files directory the
    # ProgramFiles descriptor (install only; the setup creates it with the Program Files inheritance,
    # which grants Users no write but is not the exact constant -Check compares against). Install mode
    # only.
    [switch]$ProtectOnly,
    # Legacy M1b/M2 rig mode: deploy purge-engine.exe and kb\ plus the data root, nothing else (no
    # broker, no UI, no event-log source, no shortcut). -Check and -Uninstall honour it too.
    [switch]$EngineOnly,
    # Overrides for tests in a VM only; production uses the defaults.
    [string]$ProgramFilesDir = '',
    [string]$DataRoot = '',
    # Test override for the all-users Start-menu folder (production: %ProgramData%\...\Start Menu\Programs).
    [string]$StartMenuDir = '',
    # Remove the Program Files copy, the shortcut and the event-log source (never the data root).
    [switch]$Uninstall,
    # Verify everything, change nothing; exit 0 only when it is exactly as installed.
    [switch]$Check,
    # Print every step and change nothing; needs no elevation. Alias: -DryRun.
    [Alias('DryRun')]
    [switch]$WhatIf,
    # Optional JSON report (schema purge.install/1).
    [string]$ReportPath = '',
    # VM rig only (m3-consent -ConsentUi toolkit): the broker is a build with the cargo feature
    # toolkit-consent and is installed knowingly; it must then be one. Needs -SkipBuild (this script
    # builds only the release broker). Without it a toolkit broker is refused (review S-A); -Check
    # takes it too, for the installed broker.
    [switch]$ToolkitBroker
)

# ============================================================================================ constants

# ACE sets of every object the script creates. New-PurgeSddl turns them into the SDDL constants that
# install\README.md lists verbatim (the self-test checks that the two agree).
#   FA         FILE_ALL_ACCESS (0x1f01ff)
#   FR         FILE_GENERIC_READ (0x120089): read data, EA, attributes, READ_CONTROL, SYNCHRONIZE
#   0x1200a9   FILE_GENERIC_READ | FILE_GENERIC_EXECUTE (read and execute)
#   0x100020   FILE_TRAVERSE | SYNCHRONIZE: traverse only; no list, no read-attributes, no create.
#              (0x20 alone would render as the directory-service token "WP", hence SYNCHRONIZE.)
$script:PurgeAceSets = [ordered]@{
    DataRoot     = @(@('OICI', 'FA', 'SY'), @('OICI', 'FA', 'BA'), @('', '0x100020', 'BU'))
    Sessions     = @(@('OICI', 'FA', 'SY'), @('OICI', 'FA', 'BA'), @('', '0x100020', 'BU'))
    Store        = @(@('OICI', 'FA', 'SY'), @('OICI', 'FA', 'BA'))
    Index        = @(@('', 'FA', 'SY'), @('', 'FA', 'BA'), @('', 'FR', 'BU'))
    ProgramFiles = @(@('OICI', 'FA', 'SY'), @('OICI', 'FA', 'BA'), @('OICI', '0x1200a9', 'BU'))
}

$script:SidSystem = 'S-1-5-18'
$script:SidAdmins = 'S-1-5-32-544'
$script:SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:AdminSids = @($script:SidSystem, $script:SidAdmins, $script:SidTrustedInstaller)

# Access bits that let a principal change an object or its children: WRITE_DATA/ADD_FILE (0x2),
# APPEND_DATA/ADD_SUBDIRECTORY (0x4), WRITE_EA (0x10), DELETE_CHILD (0x40), WRITE_ATTRIBUTES (0x100),
# DELETE, WRITE_DAC, WRITE_OWNER, MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_WRITE.
$script:WriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x2000000 -bor 0x10000000 -bor 0x40000000

$script:FileAttrDirectory = 0x10
$script:FileAttrReparse = 0x400

# purge_win::sid::is_admin_only_writable's leaf rule, mirrored here so the install can check and repair
# the objects the broker judges one by one (its client image and every file in kb\baselines): an
# effective allow ACE with one of these rights for a principal other than SYSTEM, Administrators or
# TrustedInstaller refuses the object. Deny ACEs are ignored; inherit-only ACEs do not apply to the object.
$script:LeafWriteMask = 0x2 -bor 0x4 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
$script:SidCreatorOwner = 'S-1-3-0'
$script:SidCreatorGroup = 'S-1-3-1'
$script:SidOwnerRights = 'S-1-3-4'

# The broker's start failures are written to the Application log under this source (bins/purge-broker/
# src/start.rs, EVENT_SOURCE).
$script:EventLogSource = 'Purge'
$script:EventLogKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Purge'
$script:StartMenuShortcutName = 'Purge.lnk'

# Strings a purge-engine built with the executor would carry (panic locations of purge-exec); a release
# engine must contain none of them (M3-INSTALL test: "the installed purge-engine.exe imports no executor
# symbol").
$script:ExecutorMarkers = @('purge-exec\src', 'purge-exec/src')

# The staging guard of the broker (review S-A of BROKER-CONSENT-UI): a purge-broker.exe built with the
# cargo feature toolkit-consent (the rig's and the preview's build) is never installed as the release
# broker. A release broker holds the words it refuses "--consent toolkit" with (purge_broker::args::
# STAGING_MARKER, compiled only without the feature and reached from the command line, so always kept);
# a toolkit build holds none of them, and holds the toolkit's source paths (its panic locations).
# Both are checked: the marker must be there (a check that fails closed), the toolkit's paths must not.
# tests/staging_marker.rs of purge-broker keeps these two lines equal to the broker's constants.
$script:BrokerReleaseMarker = 'this purge-broker was built without the toolkit consent dialog'
$script:BrokerToolkitMarkers = @('mdshared-ui\src', 'mdshared-ui/src')

# Set by the driver from -WhatIf; the action helpers below ask it before they touch the machine.
$script:DryRun = [bool]$WhatIf

# ============================================================================================ pure part

# Builds "O:<owner>D:P(A;<flags>;<rights>;;;<sid>)..." from an ACE set: a protected DACL of allow ACEs in
# the given order.
function New-PurgeSddl([string]$Owner, [object[]]$Aces) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("O:${Owner}D:P")
    foreach ($a in $Aces) { [void]$sb.Append(('(A;{0};{1};;;{2})' -f $a[0], $a[1], $a[2])) }
    $sb.ToString()
}

# The SDDL constant for each object kind (owner BUILTIN\Administrators).
function Get-PurgeSddlTable {
    $t = [ordered]@{}
    foreach ($k in $script:PurgeAceSets.Keys) { $t[$k] = New-PurgeSddl 'BA' $script:PurgeAceSets[$k] }
    $t
}

# Canonical form used for every comparison: owner + DACL rendered by Windows
# (ConvertStringSecurityDescriptorToSecurityDescriptorW -> ConvertSecurityDescriptorToStringSecurityDescriptorW
# with OWNER|DACL, which is what RawSecurityDescriptor.GetSddlForm calls), then the DACL control flags
# reduced to P / NO_ACCESS_CONTROL: AI and AR are auto-inheritance bookkeeping that SetSecurityInfo and
# CreateDirectoryW may or may not set, and grant nothing. Group and SACL are not compared.
# Returns $null for an unparseable string.
function ConvertTo-CanonicalSddl([string]$Sddl) {
    if (-not $Sddl) { return $null }
    try {
        $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor $Sddl
    } catch { return $null }
    $s = $raw.GetSddlForm([System.Security.AccessControl.AccessControlSections]'Owner, Access')
    $m = [regex]::Match($s, 'D:(?<flags>(?:NO_ACCESS_CONTROL|PAI|PAR|P|AI|AR)*)')
    if ($m.Success) {
        $f = $m.Groups['flags'].Value
        $keep = ''
        if ($f -like '*NO_ACCESS_CONTROL*') { $keep = 'NO_ACCESS_CONTROL' }
        elseif ($f.StartsWith('P')) { $keep = 'P' }
        $s = $s.Substring(0, $m.Index) + 'D:' + $keep + $s.Substring($m.Index + $m.Length)
    }
    $s
}

# True for the principals that may hold write access: SYSTEM, BUILTIN\Administrators, TrustedInstaller.
function Test-PrivilegedSid([string]$Sid) {
    $Sid -eq $script:SidSystem -or $Sid -eq $script:SidAdmins -or $Sid -eq $script:SidTrustedInstaller
}

# Security findings for one SDDL, independent of the expected constant: wrong owner, unprotected or null
# DACL, and allow ACEs (inherit-only ones included: they reach every child created later) that give a
# non-privileged principal any write-class right. Returns a list of strings (empty = no finding).
function Get-SddlFindings([string]$Sddl) {
    $out = New-Object System.Collections.Generic.List[string]
    try {
        $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor $Sddl
    } catch {
        $out.Add("unparseable SDDL '$Sddl'"); return , $out
    }
    $owner = if ($raw.Owner) { $raw.Owner.Value } else { '<none>' }
    if ($owner -ne $script:SidAdmins) { $out.Add("owner $owner is not BUILTIN\Administrators") }
    $ctl = $raw.ControlFlags
    if (-not ($ctl -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -or $null -eq $raw.DiscretionaryAcl) {
        $out.Add('null DACL (everyone has full access)'); return , $out
    }
    if (-not ($ctl -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)) {
        $out.Add('DACL is not protected (inherits from the parent)')
    }
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.KnownAce]) { $out.Add("unrecognised ACE type $($ace.AceType)"); continue }
        if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed -and
            $ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowedObject -and
            $ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowedCallback) { continue }
        $sid = $ace.SecurityIdentifier.Value
        if (Test-PrivilegedSid $sid) { continue }
        $w = $ace.AccessMask -band $script:WriteMask
        if ($w -ne 0) { $out.Add(('write access 0x{0:x} for non-admin {1} (flags {2})' -f $w, $sid, $ace.AceFlags)) }
    }
    , $out
}

# The broker's per-object rule (purge_win::sid::is_admin_only_writable, leaf): the owner is SYSTEM,
# BUILTIN\Administrators or TrustedInstaller and no effective allow ACE gives any other principal a
# right to change the object. Mirrors the broker's own judgement of its executable, Purge.exe and every
# file in kb\baselines. Returns the reasons (empty = accepted). -AdminSids is a test seam: production
# always uses the script default.
function Test-AdminOnlyWritable($Facts, [string[]]$AdminSids = $script:AdminSids) {
    $r = New-Object System.Collections.Generic.List[string]
    if (-not $Facts.Exists) { $r.Add('does not exist'); return , $r }
    if ($Facts.IsReparsePoint) { $r.Add('is a reparse point'); return , $r }
    if (-not $Facts.Sddl) { $r.Add("security descriptor unreadable (Win32 error $($Facts.Error))"); return , $r }
    try { $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor $Facts.Sddl }
    catch { $r.Add("unparseable SDDL '$($Facts.Sddl)'"); return , $r }
    $owner = if ($raw.Owner) { $raw.Owner.Value } else { '<none>' }
    if ($AdminSids -notcontains $owner) { $r.Add("owner $owner is not SYSTEM, Administrators or TrustedInstaller") }
    if ($null -eq $raw.DiscretionaryAcl) { $r.Add('null DACL (everyone has full access)'); return , $r }
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.KnownAce]) { $r.Add("unrecognised ACE type $($ace.AceType)"); continue }
        if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed -and
            $ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowedObject -and
            $ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowedCallback) { continue }
        if (([int]$ace.AceFlags -band 0x8) -ne 0) { continue }
        $sid = $ace.SecurityIdentifier.Value
        if ($AdminSids -contains $sid) { continue }
        if ($sid -eq $script:SidCreatorOwner -or $sid -eq $script:SidCreatorGroup -or $sid -eq $script:SidOwnerRights) { continue }
        $w = $ace.AccessMask -band $script:LeafWriteMask
        if ($w -ne 0) { $r.Add(('write access 0x{0:x} for non-admin {1}' -f $w, $sid)) }
    }
    , $r
}

# The objects of each tree, parents before children. Rel '' is the root.
function Get-PurgeDataLayout {
    $t = Get-PurgeSddlTable
    @(
        [pscustomobject]@{ Rel = '';                    Kind = 'dir';  Sddl = $t.DataRoot; Content = $null },
        [pscustomobject]@{ Rel = 'sessions';            Kind = 'dir';  Sddl = $t.Sessions; Content = $null },
        [pscustomobject]@{ Rel = 'Quarantine';          Kind = 'dir';  Sddl = $t.Store;    Content = $null },
        [pscustomobject]@{ Rel = 'fp';                  Kind = 'dir';  Sddl = $t.Store;    Content = $null },
        [pscustomobject]@{ Rel = 'kb';                  Kind = 'dir';  Sddl = $t.Store;    Content = $null },
        [pscustomobject]@{ Rel = 'sessions\index.json'; Kind = 'file'; Sddl = $t.Index;    Content = '{}' }
    )
}

function Get-PurgeProgramFilesLayout {
    $t = Get-PurgeSddlTable
    @([pscustomobject]@{ Rel = ''; Kind = 'dir'; Sddl = $t.ProgramFiles; Content = $null })
}

# Whether an existing directory is exactly the layout root: a protected DACL and the same canonical
# SDDL (owner included). Unlike Test-ObjectFacts this does not judge the ACEs by principal, so it also
# holds for a tree whose descriptor was built with a test's accepted-owner list; the root of an install
# tree must be the constant itself, not merely a descriptor the broker's rule accepts.
function Test-TreeRoot($Facts, [string]$Sddl) {
    $r = New-Object System.Collections.Generic.List[string]
    if (-not $Facts.Exists) { $r.Add('does not exist'); return , $r }
    if (-not $Facts.AttributesKnown) { $r.Add("attributes unreadable (Win32 error $($Facts.Error))"); return , $r }
    if ($Facts.IsReparsePoint) { $r.Add('is a reparse point'); return , $r }
    if (-not $Facts.IsDirectory) { $r.Add('is a file, expected a directory'); return , $r }
    if (-not $Facts.Sddl) { $r.Add("security descriptor unreadable (Win32 error $($Facts.Error))"); return , $r }
    try { $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor $Facts.Sddl }
    catch { $r.Add("unparseable SDDL '$($Facts.Sddl)'"); return , $r }
    if (-not [bool]($raw.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)) {
        $r.Add('DACL is not protected')
    }
    $actual = ConvertTo-CanonicalSddl $Facts.Sddl
    $expected = ConvertTo-CanonicalSddl $Sddl
    if ($actual -ne $expected) { $r.Add("SDDL '$actual' differs from '$expected'") }
    , $r
}

# Integrity findings for one existing object against its layout entry. Facts are a plain object
# {Exists, AttributesKnown, IsDirectory, IsReparsePoint, Sddl, Error}, so the self-test can pass fakes.
# Returns a list of strings; empty means the object is exactly what install would create.
function Test-ObjectFacts($Facts, $Entry) {
    $r = New-Object System.Collections.Generic.List[string]
    if ($Facts.AttributesKnown) {
        if ($Facts.IsReparsePoint) { $r.Add('is a reparse point') }
        if ($Entry.Kind -eq 'dir' -and -not $Facts.IsDirectory) { $r.Add('is a file, expected a directory') }
        if ($Entry.Kind -eq 'file' -and $Facts.IsDirectory) { $r.Add('is a directory, expected a file') }
    } else {
        $r.Add("attributes unreadable (Win32 error $($Facts.Error))")
    }
    if (-not $Facts.Sddl) {
        $r.Add("security descriptor unreadable (Win32 error $($Facts.Error))")
        return , $r
    }
    foreach ($f in (Get-SddlFindings $Facts.Sddl)) { $r.Add($f) }
    $actual = ConvertTo-CanonicalSddl $Facts.Sddl
    $expected = ConvertTo-CanonicalSddl $Entry.Sddl
    if ($actual -ne $expected) { $r.Add("SDDL '$actual' differs from '$expected'") }
    , $r
}

# Verdict over a tree's facts: {Root; Objects = @{rel -> facts}; Reparse = @(paths); ScanErrors = @()}.
#   absent      the root does not exist: create everything (Missing = every layout entry)
#   good        every layout object exists and passes; nothing at the top two levels is a reparse point
#   incomplete  everything present passes; Missing lists what to create
#   reject      anything else: rename the root aside, never adopt it, never recurse into it
function Get-TreeVerdict($TreeFacts, [object[]]$Layout) {
    $reasons = New-Object System.Collections.Generic.List[string]
    $missing = New-Object System.Collections.Generic.List[string]
    $rootFacts = $TreeFacts.Objects['']
    if (-not $rootFacts -or -not $rootFacts.Exists) {
        foreach ($e in $Layout) { $missing.Add($e.Rel) }
        return [pscustomobject]@{ Verdict = 'absent'; Reasons = @(); Missing = @($missing) }
    }
    foreach ($e in $Layout) {
        $f = $TreeFacts.Objects[$e.Rel]
        $label = if ($e.Rel) { $e.Rel } else { '<root>' }
        if (-not $f -or -not $f.Exists) { $missing.Add($e.Rel); continue }
        foreach ($x in (Test-ObjectFacts $f $e)) { $reasons.Add("${label}: $x") }
        if ($e.Rel -eq '' -and $reasons.Count) { break }    # a bad root is never looked into
    }
    if ($reasons.Count -eq 0) {
        foreach ($p in @($TreeFacts.Reparse)) { if ($p) { $reasons.Add("reparse point inside the tree: $p") } }
        foreach ($p in @($TreeFacts.ScanErrors)) { if ($p) { $reasons.Add("cannot enumerate: $p") } }
    }
    $v = if ($reasons.Count) { 'reject' } elseif ($missing.Count) { 'incomplete' } else { 'good' }
    [pscustomobject]@{ Verdict = $v; Reasons = @($reasons); Missing = $(if ($v -eq 'reject') { @() } else { @($missing) }) }
}

# "<leaf>.rejected-<yyyyMMddTHHmmssZ>" beside $Path, with "-2", "-3"... when the name is taken.
# $Exists is a scriptblock (path -> bool) so the self-test can fake the file system.
function Get-AsideName([string]$Path, [datetime]$UtcNow, [scriptblock]$Exists) {
    $parent = Split-Path -Parent $Path
    $leaf = Split-Path -Leaf $Path
    $base = Join-Path $parent ('{0}.rejected-{1}' -f $leaf, $UtcNow.ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
    $cand = $base
    for ($n = 2; & $Exists $cand; $n++) {
        if ($n -gt 99) { throw "no free rename-aside name for $Path" }
        $cand = "$base-$n"
    }
    $cand
}

# ============================================================================================ native part

$script:NativeSource = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PurgeInstall {
    public sealed class ObjectFacts {
        public string Path;
        public bool Exists;
        public bool AttributesKnown;
        public uint Attributes;
        public uint Links;
        public string Sddl;
        public int Error;
    }

    public static class Native {
        const uint READ_CONTROL = 0x20000, SYNCHRONIZE = 0x100000, DELETE = 0x10000;
        const uint FILE_READ_ATTRIBUTES = 0x80, GENERIC_WRITE = 0x40000000;
        const uint SHARE_ALL = 7, CREATE_NEW = 1, OPEN_EXISTING = 3;
        const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        const uint FLAG_BACKUP_SEMANTICS = 0x02000000, FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint OWNER_SECURITY_INFORMATION = 1, DACL_SECURITY_INFORMATION = 4;
        const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
        const int SE_FILE_OBJECT = 1, FileRenameInfo = 3;

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }

        [StructLayout(LayoutKind.Sequential)]
        struct BY_HANDLE_FILE_INFORMATION {
            public uint Attributes, CreateLow, CreateHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
            public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
        static extern SafeFileHandle CreateFileSa(string name, uint access, uint share, ref SECURITY_ATTRIBUTES sa, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateDirectoryW(string name, ref SECURITY_ATTRIBUTES sa);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFileInformationByHandle(SafeFileHandle h, int infoClass, IntPtr buffer, uint size);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint GetSecurityInfo(SafeFileHandle h, int objectType, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr sd);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint revision, uint info, out IntPtr text, IntPtr length);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr sd, IntPtr size);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool SetFileSecurityW(string name, uint info, IntPtr sd);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetVolumePathNameW(string fileName, StringBuilder volumePathName, uint bufferLength);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetVolumeNameForVolumeMountPointW(string volumeMountPoint, StringBuilder volumeName, uint bufferLength);
        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr p);

        static SafeFileHandle OpenNoFollow(string path, uint access) {
            return CreateFileW(path, access, SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, FLAG_BACKUP_SEMANTICS | FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        }

        // Facts about the object at path itself (a reparse point is opened, never followed): existence,
        // attributes, link count and the owner + DACL rendered as SDDL. Never throws for Win32 failures;
        // Error carries the first failure code.
        public static ObjectFacts GetFacts(string path) {
            ObjectFacts f = new ObjectFacts();
            f.Path = path;
            bool canReadSd = true;
            SafeFileHandle h = OpenNoFollow(path, READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE);
            if (h.IsInvalid) {
                int e = Marshal.GetLastWin32Error();
                h.Dispose();
                if (e == 2 || e == 3) { f.Exists = false; return f; }
                f.Exists = true;
                f.Error = e;
                canReadSd = false;
                h = OpenNoFollow(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE);
                if (h.IsInvalid) { h.Dispose(); return f; }
            }
            f.Exists = true;
            using (h) {
                BY_HANDLE_FILE_INFORMATION info;
                if (GetFileInformationByHandle(h, out info)) {
                    f.AttributesKnown = true;
                    f.Attributes = info.Attributes;
                    f.Links = info.Links;
                } else if (f.Error == 0) {
                    f.Error = Marshal.GetLastWin32Error();
                }
                if (canReadSd) {
                    IntPtr sd;
                    uint si = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
                    uint rc = GetSecurityInfo(h, SE_FILE_OBJECT, si, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd);
                    if (rc != 0) {
                        if (f.Error == 0) f.Error = (int)rc;
                    } else {
                        try {
                            IntPtr text;
                            if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, si, out text, IntPtr.Zero)) {
                                f.Sddl = Marshal.PtrToStringUni(text);
                                LocalFree(text);
                            } else if (f.Error == 0) {
                                f.Error = Marshal.GetLastWin32Error();
                            }
                        } finally { LocalFree(sd); }
                    }
                }
            }
            return f;
        }

        // Renames the object at path (a reparse point itself, never its target) to newPath in the same
        // directory, through a handle opened with FILE_FLAG_OPEN_REPARSE_POINT. Never replaces. 0 or a Win32 error.
        public static int RenameNoFollow(string path, string newPath) {
            using (SafeFileHandle h = OpenNoFollow(path, DELETE | SYNCHRONIZE)) {
                if (h.IsInvalid) return Marshal.GetLastWin32Error();
                byte[] name = Encoding.Unicode.GetBytes(newPath);
                int rootOff = IntPtr.Size == 8 ? 8 : 4;
                int lenOff = rootOff + IntPtr.Size;
                int nameOff = lenOff + 4;
                int size = nameOff + name.Length + 2;
                IntPtr buf = Marshal.AllocHGlobal(size);
                try {
                    for (int i = 0; i < size; i++) Marshal.WriteByte(buf, i, 0);   // ReplaceIfExists = FALSE
                    Marshal.WriteIntPtr(buf, rootOff, IntPtr.Zero);
                    Marshal.WriteInt32(buf, lenOff, name.Length);
                    Marshal.Copy(name, 0, new IntPtr(buf.ToInt64() + nameOff), name.Length);
                    if (!SetFileInformationByHandle(h, FileRenameInfo, buf, (uint)size)) return Marshal.GetLastWin32Error();
                } finally { Marshal.FreeHGlobal(buf); }
            }
            return 0;
        }

        static IntPtr ParseSd(string sddl, out int error) {
            IntPtr sd;
            error = 0;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, IntPtr.Zero)) {
                error = Marshal.GetLastWin32Error();
                return IntPtr.Zero;
            }
            return sd;
        }

        // CreateDirectoryW with the descriptor applied at creation. Fails (183) if anything exists at path.
        public static int CreateDirWithSddl(string path, string sddl) {
            int e;
            IntPtr sd = ParseSd(sddl, out e);
            if (sd == IntPtr.Zero) return e;
            try {
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = sd;
                if (!CreateDirectoryW(path, ref sa)) return Marshal.GetLastWin32Error();
                return 0;
            } finally { LocalFree(sd); }
        }

        // CreateFileW CREATE_NEW with the descriptor applied at creation, then data written and flushed.
        // Fails (80) if anything, a link included, exists at path.
        public static int CreateFileWithSddl(string path, string sddl, byte[] data) {
            int e;
            IntPtr sd = ParseSd(sddl, out e);
            if (sd == IntPtr.Zero) return e;
            try {
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = sd;
                SafeFileHandle h = CreateFileSa(path, GENERIC_WRITE | SYNCHRONIZE, 0, ref sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
                if (h.IsInvalid) { int le = Marshal.GetLastWin32Error(); h.Dispose(); return le; }
                using (FileStream fs = new FileStream(h, FileAccess.Write)) {
                    fs.Write(data, 0, data.Length);
                    fs.Flush(true);
                }
                return 0;
            } finally { LocalFree(sd); }
        }

        // The volume identifier (\\?\Volume{...}\) of the volume that holds a path, or null. The
        // path's parent must exist: GetVolumePathNameW resolves the mount point from it.
        public static string VolumeOf(string path) {
            StringBuilder mount = new StringBuilder(261);
            if (!GetVolumePathNameW(path, mount, (uint)mount.Capacity)) return null;
            StringBuilder name = new StringBuilder(64);
            if (!GetVolumeNameForVolumeMountPointW(mount.ToString(), name, (uint)name.Capacity)) return null;
            return name.ToString().TrimEnd('\\');
        }

        // Whether two paths are on the same volume. The installer only deploys to the running
        // system's volume (M3-INSTALL: "Refuses an install directory off the system volume").
        public static bool SameVolume(string a, string b) {
            string va = VolumeOf(a);
            string vb = VolumeOf(b);
            return va != null && vb != null && string.Equals(va, vb, StringComparison.OrdinalIgnoreCase);
        }

        // Replaces the owner and the protected DACL of an existing object with the descriptor in sddl
        // (the ProgramFiles constant). New files inherit, but an object that already existed may carry
        // another descriptor (a replaced binary, a file copied from elsewhere), and the broker judges
        // the client image and every KB file on their own. 0 or a Win32 error.
        public static int SetSddl(string path, string sddl) {
            int e;
            IntPtr sd = ParseSd(sddl, out e);
            if (sd == IntPtr.Zero) return e;
            try {
                uint info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
                if (!SetFileSecurityW(path, info, sd)) return Marshal.GetLastWin32Error();
                return 0;
            } finally { LocalFree(sd); }
        }
    }
}
'@

function Initialize-PurgeNative {
    if (-not ('PurgeInstall.Native' -as [type])) { Add-Type -TypeDefinition $script:NativeSource -Language CSharp }
}

function Format-Win32Error([int]$Code) { '{0} ({1})' -f $Code, (New-Object System.ComponentModel.Win32Exception $Code).Message }

# Whether two existing paths are on the same volume (GetVolumePathNameW + GetVolumeNameForVolumeMountPointW).
function Test-SameVolume([string]$A, [string]$B) { [PurgeInstall.Native]::SameVolume($A, $B) }

# Native facts as a plain object (the shape Test-ObjectFacts takes).
function Get-ObjectFacts([string]$Path) {
    $n = [PurgeInstall.Native]::GetFacts($Path)
    [pscustomobject]@{
        Path            = $Path
        Exists          = $n.Exists
        AttributesKnown = $n.AttributesKnown
        IsDirectory     = [bool]($n.Attributes -band $script:FileAttrDirectory)
        IsReparsePoint  = [bool]($n.Attributes -band $script:FileAttrReparse)
        Links           = $n.Links
        Sddl            = $n.Sddl
        Error           = $n.Error
    }
}

# Reparse points among the entries of $Root (level 1) and of its non-reparse subdirectories (level 2).
# Enumeration reads directory entries only and never descends into a reparse point. Called only on a
# root that passed its own check (admin-owned, protected), so nobody else can change it meanwhile.
function Get-ReparseEntries([string]$Root) {
    $found = New-Object System.Collections.Generic.List[string]
    $errors = New-Object System.Collections.Generic.List[string]
    $reparse = [IO.FileAttributes]::ReparsePoint
    $l1 = @()
    try { $l1 = @((New-Object IO.DirectoryInfo $Root).GetFileSystemInfos()) } catch { $errors.Add("${Root}: $($_.Exception.Message)") }
    foreach ($e in $l1) {
        if ($e.Attributes -band $reparse) { $found.Add($e.FullName); continue }
        if (-not ($e.Attributes -band [IO.FileAttributes]::Directory)) { continue }
        try {
            foreach ($e2 in @($e.GetFileSystemInfos())) { if ($e2.Attributes -band $reparse) { $found.Add($e2.FullName) } }
        } catch { $errors.Add("$($e.FullName): $($_.Exception.Message)") }
    }
    [pscustomobject]@{ Reparse = @($found); Errors = @($errors) }
}

# Every object below $Root (the root itself excluded), without following a reparse point: a link is
# reported as an object and never entered. Used by the payload copy/check and by -Uninstall's guard.
function Get-ObjectTree([string]$Root) {
    $out = New-Object System.Collections.Generic.List[object]
    if (-not (Get-ObjectFacts $Root).Exists) { return , $out }
    $stack = New-Object System.Collections.Stack
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = [string]$stack.Pop()
        $entries = @((New-Object IO.DirectoryInfo $dir).GetFileSystemInfos())
        foreach ($e in $entries) {
            $isDir = [bool]($e.Attributes -band [IO.FileAttributes]::Directory)
            $link = [bool]($e.Attributes -band [IO.FileAttributes]::ReparsePoint)
            $out.Add([pscustomobject]@{ Path = $e.FullName; IsDirectory = $isDir; IsReparsePoint = $link })
            if ($isDir -and -not $link) { $stack.Push($e.FullName) }
        }
    }
    , $out
}

function Get-TreeFacts([string]$Root, [object[]]$Layout) {
    $objects = @{}
    $rootFacts = Get-ObjectFacts $Root
    $objects[''] = $rootFacts
    $tf = [pscustomobject]@{ Root = $Root; Objects = $objects; Reparse = @(); ScanErrors = @() }
    if (-not $rootFacts.Exists) { return $tf }
    $rootEntry = $Layout | Where-Object { $_.Rel -eq '' } | Select-Object -First 1
    if ((Test-ObjectFacts $rootFacts $rootEntry).Count) { return $tf }   # never look inside a bad root
    foreach ($e in $Layout) {
        if ($e.Rel -ne '') { $objects[$e.Rel] = Get-ObjectFacts (Join-Path $Root $e.Rel) }
    }
    $scan = Get-ReparseEntries $Root
    $tf.Reparse = $scan.Reparse
    $tf.ScanErrors = $scan.Errors
    $tf
}

function Invoke-NativeCreate([string]$Path, $Entry) {
    if ($Entry.Kind -eq 'dir') { return [PurgeInstall.Native]::CreateDirWithSddl($Path, $Entry.Sddl) }
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes([string]$Entry.Content)
    [PurgeInstall.Native]::CreateFileWithSddl($Path, $Entry.Sddl, $bytes)
}

function Invoke-NativeRename([string]$Path, [string]$NewPath) { [PurgeInstall.Native]::RenameNoFollow($Path, $NewPath) }

function Test-PathNoFollow([string]$Path) { (Get-ObjectFacts $Path).Exists }

# ============================================================================================ driver

$script:InstallLog = New-Object System.Collections.Generic.List[string]
function Write-InstallLog([string]$Message) {
    $line = 'install: ' + $Message
    $script:InstallLog.Add($line)
    Write-Host $line
}

# Brings one tree to the verified state: create what is absent, rename aside what fails, adopt nothing
# else. Bounded passes (an attacker re-creating the root between passes only costs a pass).
function Install-Tree([string]$Root, [object[]]$Layout, [string]$Label, [int]$MaxPasses = 4) {
    $rec = [ordered]@{ path = $Root; changed = $false; created = @(); renamed_aside = @(); final = $null }
    for ($pass = 1; $pass -le $MaxPasses; $pass++) {
        $tf = Get-TreeFacts $Root $Layout
        $v = Get-TreeVerdict $tf $Layout
        switch ($v.Verdict) {
            'good' {
                $rec.final = [ordered]@{}
                foreach ($e in $Layout) { $rec.final[$(if ($e.Rel) { $e.Rel } else { '.' })] = ConvertTo-CanonicalSddl $tf.Objects[$e.Rel].Sddl }
                if (-not $rec.changed) { Write-InstallLog "${Label}: $Root verified, nothing to do" }
                else { Write-InstallLog "${Label}: $Root verified" }
                return $rec
            }
            'reject' {
                $aside = Get-AsideName $Root ([datetime]::UtcNow) { param($p) Test-PathNoFollow $p }
                Write-InstallLog "${Label}: REJECTED $Root, never adopted:"
                foreach ($x in $v.Reasons) { Write-InstallLog "    $x" }
                $e = Invoke-NativeRename $Root $aside
                if ($e -ne 0) { throw "${Label}: cannot rename $Root aside to ${aside}: $(Format-Win32Error $e)" }
                Write-InstallLog "${Label}: renamed aside (not followed, not recursed): $Root -> $aside"
                $rec.renamed_aside += [ordered]@{ from = $Root; to = $aside; reasons = @($v.Reasons) }
                $rec.changed = $true
            }
            default {
                # 'absent' or 'incomplete': create the missing objects, parents first, each with its own SD.
                foreach ($e in $Layout) {
                    if ($v.Missing -notcontains $e.Rel) { continue }
                    $p = if ($e.Rel) { Join-Path $Root $e.Rel } else { $Root }
                    $err = Invoke-NativeCreate $p $e
                    if ($err -eq 183 -or $err -eq 80) {
                        Write-InstallLog "${Label}: $p appeared while creating; re-checking"
                        break
                    }
                    if ($err -ne 0) { throw "${Label}: cannot create ${p}: $(Format-Win32Error $err)" }
                    Write-InstallLog "${Label}: created $p"
                    $rec.created += $p
                    $rec.changed = $true
                }
            }
        }
    }
    throw "${Label}: $Root did not reach a verified state in $MaxPasses passes"
}

# Read-only verification of one tree (for -Check).
function Test-Tree([string]$Root, [object[]]$Layout, [string]$Label) {
    $v = Get-TreeVerdict (Get-TreeFacts $Root $Layout) $Layout
    Write-InstallLog "${Label}: $Root -> $($v.Verdict)"
    foreach ($x in $v.Reasons) { Write-InstallLog "    $x" }
    foreach ($m in $v.Missing) { Write-InstallLog "    missing: $(if ($m) { $m } else { '<root>' })" }
    [ordered]@{ path = $Root; verdict = $v.Verdict; reasons = @($v.Reasons); missing = @($v.Missing) }
}

# Copies one file unless the destination already has the same SHA-256. Refuses a reparse destination.
function Copy-PayloadFile([string]$Source, [string]$Dest) {
    $df = Get-ObjectFacts $Dest
    if ($df.Exists) {
        if (-not $df.AttributesKnown -or $df.IsReparsePoint -or $df.IsDirectory) { throw "refusing to overwrite $Dest (not a plain file)" }
        if ((Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $Dest -Algorithm SHA256).Hash) {
            return [ordered]@{ file = $Dest; action = 'unchanged' }
        }
    }
    [IO.File]::Copy($Source, $Dest, $true)
    [ordered]@{ file = $Dest; action = $(if ($df.Exists) { 'updated' } else { 'copied' }) }
}

# Copies the regular files of $SourceDir into $DestDir, keeping the relative paths. Directories are
# created as needed; a reparse point in the source is reported and skipped, never followed.
function Copy-FileTree([string]$SourceDir, [string]$DestDir, [string]$Label) {
    $out = New-Object System.Collections.Generic.List[object]
    if ($script:DryRun) {
        Write-InstallLog "what-if: copy $Label from $SourceDir into $DestDir"
        return , $out
    }
    $srcRoot = (Resolve-Path -LiteralPath $SourceDir).ProviderPath.TrimEnd('\')
    foreach ($o in (Get-ObjectTree $srcRoot)) {
        $rel = $o.Path.Substring($srcRoot.Length + 1)
        $dest = Join-Path $DestDir $rel
        if ($o.IsReparsePoint) { Write-InstallLog "payload: skipping reparse point $($o.Path)"; continue }
        if ($o.IsDirectory) {
            $ddf = Get-ObjectFacts $dest
            if ($ddf.Exists -and ($ddf.IsReparsePoint -or -not $ddf.IsDirectory)) { throw "refusing to write into $dest (not a plain directory)" }
            if (-not $ddf.Exists) { [void][IO.Directory]::CreateDirectory($dest) }
            continue
        }
        $dd = Split-Path -Parent $dest
        $ddf = Get-ObjectFacts $dd
        if ($ddf.Exists -and ($ddf.IsReparsePoint -or -not $ddf.IsDirectory)) { throw "refusing to write into $dd (not a plain directory)" }
        if (-not $ddf.Exists) { [void][IO.Directory]::CreateDirectory($dd) }
        $out.Add((Copy-PayloadFile $o.Path $dest))
    }
    , $out
}

# Applies the install tree's descriptor (owner Administrators, protected DACL, Users read and execute) to
# $Dir and to every object below it that does not already pass the broker's per-object rule. The root is
# judged exactly, not by that rule: a directory another program created (an Inno Setup file copy)
# inherits the parent's DACL, which grants Users no write but is not the constant -Check compares
# against, so the root always ends up with the layout descriptor itself.
function Protect-Tree([string]$Dir, [string]$Sddl, [string[]]$AdminSids = $script:AdminSids) {
    $reprotected = New-Object System.Collections.Generic.List[string]
    if ($script:DryRun) {
        Write-InstallLog "what-if: protect $Dir and every object below it with '$Sddl'"
        return
    }
    if (-not (Get-ObjectFacts $Dir).Exists) { throw "payload: $Dir does not exist; nothing to protect" }
    $targets = @($Dir) + @((Get-ObjectTree $Dir) | ForEach-Object { $_.Path })
    foreach ($path in $targets) {
        $f = Get-ObjectFacts $path
        if ($f.IsReparsePoint) { throw "payload: $path is a reparse point; refusing to follow it" }
        $why = if ($path -eq $Dir) { Test-TreeRoot $f $Sddl } else { Test-AdminOnlyWritable $f $AdminSids }
        if ($why.Count -eq 0) { continue }
        $e = [PurgeInstall.Native]::SetSddl($path, $Sddl)
        if ($e -ne 0) { throw "payload: cannot protect ${path}: $(Format-Win32Error $e)" }
        $reprotected.Add($path)
        Write-InstallLog "payload: re-protected $path ($($why -join '; '))"
    }
    $reprotected
}

# Engine, broker, the UI (Purge.exe, or a folder holding it) and kb into the verified Program Files tree. New files and
# subdirectories inherit the root's protected DACL; every deployed object is then checked with the
# broker's rule and re-protected (owner + protected DACL) when it does not pass (a replaced binary, a
# file copied from a tree with other permissions). Files in the destination but not in the sources are
# reported as stale, never deleted.
# $UiPath is Purge.exe itself (copied as <Dir>\Purge.exe) or a folder holding it (copied as a tree).
function Copy-Payload([string]$Dir, [string]$EnginePath, [string]$BrokerPath, [string]$UiPath, [string]$KbDir, [string]$Sddl, [string[]]$AdminSids = $script:AdminSids) {
    $out = New-Object System.Collections.Generic.List[object]
    $out.Add((Copy-PayloadFile $EnginePath (Join-Path $Dir 'purge-engine.exe')))
    if ($BrokerPath) { $out.Add((Copy-PayloadFile $BrokerPath (Join-Path $Dir 'purge-broker.exe'))) }
    if ($UiPath) {
        if (Test-Path -LiteralPath $UiPath -PathType Leaf) { $out.Add((Copy-PayloadFile $UiPath (Join-Path $Dir 'Purge.exe'))) }
        else { foreach ($r in (Copy-FileTree $UiPath $Dir 'the UI folder')) { $out.Add($r) } }
    }
    if ($KbDir) { foreach ($r in (Copy-FileTree $KbDir (Join-Path $Dir 'kb') 'kb')) { $out.Add($r) } }

    # Stale files: present in the install directory, part of no source.
    if (-not $script:DryRun) {
        $wanted = @{}
        foreach ($r in $out) { if ($r.file) { $wanted[$r.file.ToLowerInvariant()] = $true } }
        foreach ($o in (Get-ObjectTree $Dir)) {
            if ($o.IsDirectory -or $o.IsReparsePoint) { continue }
            if (-not $wanted.ContainsKey($o.Path.ToLowerInvariant())) {
                $out.Add([ordered]@{ file = $o.Path; action = 'stale (left in place)' })
            }
        }
    }

    # Protection: the broker judges purge-broker.exe, Purge.exe and every file in kb\baselines on their
    # own, and trusts kb only as a directory. Nothing in the deployed tree may be a reparse point.
    $reprotected = @(Protect-Tree $Dir $Sddl $AdminSids)

    foreach ($o in $out) { if ($o.action -ne 'unchanged') { Write-InstallLog "payload: $($o.action) $($o.file)" } }
    $fileList = $out.ToArray()
    $protList = @($reprotected)
    $changedFiles = @($fileList | Where-Object { $_.action -eq 'copied' -or $_.action -eq 'updated' }).Count
    $changed = ($changedFiles -gt 0) -or ($protList.Count -gt 0)
    [ordered]@{
        files       = $fileList
        reprotected = $protList
        changed     = $changed
    }
}

# Read-only verification of the deployed files (for -Check): the programs exist and pass the broker's
# rule (purge-engine.exe alone with -EngineOnly), kb is a plain directory that passes it, no entry is a
# reparse point, every entry is admin-only writable, and the shortcut points at <Dir>\Purge.exe.
function Test-PayloadLayout([string]$Dir, [string]$ShortcutPath, [string[]]$AdminSids = $script:AdminSids, [switch]$EngineOnly) {
    $problems = New-Object System.Collections.Generic.List[string]
    $required = if ($EngineOnly) { @('purge-engine.exe') } else { @('purge-engine.exe', 'purge-broker.exe', 'Purge.exe') }
    foreach ($name in $required) {
        $f = Get-ObjectFacts (Join-Path $Dir $name)
        if (-not $f.Exists) { $problems.Add("missing: $name"); continue }
        if ($f.IsDirectory) { $problems.Add("${name}: is a directory"); continue }
        foreach ($why in (Test-AdminOnlyWritable $f $AdminSids)) { $problems.Add("${name}: $why") }
    }
    $kb = Get-ObjectFacts (Join-Path $Dir 'kb')
    if (-not $kb.Exists) { $problems.Add('missing: kb\') }
    elseif (-not $kb.IsDirectory) { $problems.Add('kb: is not a directory') }
    else { foreach ($why in (Test-AdminOnlyWritable $kb $AdminSids)) { $problems.Add("kb: $why") } }
    $files = 0
    foreach ($o in (Get-ObjectTree $Dir)) {
        if ($o.IsReparsePoint) { $problems.Add("$($o.Path): is a reparse point"); continue }
        if (-not $o.IsDirectory) { $files++ }
        foreach ($why in (Test-AdminOnlyWritable (Get-ObjectFacts $o.Path) $AdminSids)) { $problems.Add("$($o.Path): $why") }
    }
    if ($ShortcutPath -and -not $EngineOnly) {
        if (-not (Test-Path -LiteralPath $ShortcutPath -PathType Leaf)) {
            $problems.Add("shortcut missing: $ShortcutPath")
        } else {
            try {
                $target = Get-ShortcutTarget $ShortcutPath
                if ($target -ne (Join-Path $Dir 'Purge.exe')) { $problems.Add("shortcut $ShortcutPath points at '$target'") }
            } catch {
                $problems.Add("shortcut $ShortcutPath is unreadable: $($_.Exception.Message)")
            }
        }
    }
    [ordered]@{ path = $Dir; files = $files; problems = @($problems); ok = ($problems.Count -eq 0) }
}

# Deletes $Dir and everything below it without following any reparse point: a link is removed as a link
# (RemoveDirectory / DeleteFile on the link itself), its target is never entered.
function Remove-TreeNoFollow([string]$Dir) {
    foreach ($e in @((New-Object IO.DirectoryInfo $Dir).GetFileSystemInfos())) {
        $isDir = [bool]($e.Attributes -band [IO.FileAttributes]::Directory)
        if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            if ($isDir) { [IO.Directory]::Delete($e.FullName, $false) } else { [IO.File]::Delete($e.FullName) }
        } elseif ($isDir) {
            Remove-TreeNoFollow $e.FullName
        } else {
            if ($e.Attributes -band [IO.FileAttributes]::ReadOnly) { $e.Attributes = $e.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly) }
            [IO.File]::Delete($e.FullName)
        }
    }
    [IO.Directory]::Delete($Dir, $false)
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# The target of a .lnk, read through the shell's own shortcut object. Throws when it cannot be read.
function Get-ShortcutTarget([string]$Path) {
    $wsh = New-Object -ComObject WScript.Shell
    try { return $wsh.CreateShortcut($Path).TargetPath }
    finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($wsh) }
}

# One all-users Start-menu shortcut. An existing shortcut with the right target is left alone.
function Install-Shortcut([string]$Path, [string]$Target, [string]$WorkDir) {
    $existing = $null
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try { $existing = Get-ShortcutTarget $Path } catch { $existing = $null }
    }
    if ($existing -eq $Target) { Write-InstallLog "shortcut: $Path already points at $Target"; return $false }
    if ($script:DryRun) { Write-InstallLog "what-if: create the Start-menu shortcut $Path -> $Target"; return $false }
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { [void][IO.Directory]::CreateDirectory($parent) }
    $wsh = New-Object -ComObject WScript.Shell
    try {
        $lnk = $wsh.CreateShortcut($Path)
        $lnk.TargetPath = $Target
        $lnk.WorkingDirectory = $WorkDir
        $lnk.IconLocation = "$Target,0"
        $lnk.Description = 'Purge'
        $lnk.Save()
    } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($wsh) }
    Write-InstallLog "shortcut: created $Path -> $Target"
    $true
}

function Remove-Shortcut([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { Write-InstallLog "uninstall: no shortcut at $Path, nothing to do"; return $false }
    if ($script:DryRun) { Write-InstallLog "what-if: remove the shortcut $Path"; return $false }
    $f = Get-ObjectFacts $Path
    if (-not $f.Exists -or $f.IsReparsePoint -or $f.IsDirectory) { throw "uninstall: $Path is not a plain file; left untouched" }
    [IO.File]::Delete($Path)
    Write-InstallLog "uninstall: removed the shortcut $Path"
    $true
}

# The "Purge" Application event-log source: the broker's start failures are written there when no pipe
# exists yet (bins/purge-broker/src/start.rs). The key alone registers the source; the line the broker
# passes is the event's text, so no message DLL is needed.
function Test-EventLogSourceKey {
    $item = Get-Item -LiteralPath $script:EventLogKey -ErrorAction SilentlyContinue
    ($null -ne $item -and [bool]$item.PSIsContainer)
}

function Install-EventLogSource {
    if (Test-EventLogSourceKey) { Write-InstallLog "event log: the Application source '$($script:EventLogSource)' is registered"; return $false }
    if ($script:DryRun) {
        Write-InstallLog "what-if: register the Application event-log source '$($script:EventLogSource)' at $($script:EventLogKey)"
        return $false
    }
    New-Item -Path $script:EventLogKey -Force | Out-Null
    Write-InstallLog "event log: registered the Application source '$($script:EventLogSource)'"
    $true
}

function Remove-EventLogSource {
    if (-not (Test-EventLogSourceKey)) { Write-InstallLog "uninstall: the event-log source '$($script:EventLogSource)' is not registered"; return $false }
    if ($script:DryRun) {
        Write-InstallLog "what-if: remove the Application event-log source '$($script:EventLogSource)'"
        return $false
    }
    Remove-Item -LiteralPath $script:EventLogKey -Recurse -Force
    Write-InstallLog "uninstall: removed the Application event-log source '$($script:EventLogSource)'"
    $true
}

# The release build of install\README.md: three separate cargo builds (never one, never --workspace:
# a joint build would unify features), then the dependency check. No RUSTFLAGS (it would replace the
# crt-static flags of .cargo\config.toml). The defaults of -Engine, -Broker and -Ui are
# <repo>\target\release; with CARGO_TARGET_DIR set, pass the three paths.
function Invoke-ReleaseBuild([string]$Repo) {
    $steps = @(@('build', '--release', '-p', 'purge-engine'), @('build', '--release', '-p', 'purge-broker'), @('build', '--release', '-p', 'purge-ui'), @('xtask', 'check-deps'))
    if ($script:DryRun) {
        foreach ($cargoArgs in $steps) { Write-InstallLog ('what-if: cargo ' + ($cargoArgs -join ' ')) }
        return
    }
    if ($env:RUSTFLAGS) { throw 'RUSTFLAGS is set; it replaces .cargo\config.toml (crt-static) and must be unset for a release build' }
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) { throw 'cargo was not found on PATH' }
    foreach ($cargoArgs in $steps) {
        $line = 'cargo ' + ($cargoArgs -join ' ')
        Write-InstallLog "build: $line"
        & $cargo.Source @cargoArgs
        if ($LASTEXITCODE -ne 0) { throw "$line failed with exit code $LASTEXITCODE" }
    }
}

# The strings a purge-engine built with the executor carries (M3-INSTALL: the installed engine imports
# no executor symbol). Empty means the binary is the release engine.
function Get-ExecutorMarkers([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($m in $script:ExecutorMarkers) {
        if ($text.IndexOf($m, [StringComparison]::Ordinal) -ge 0) { $found.Add($m) }
    }
    , $found
}

function Assert-EngineWithoutExecutor([string]$Path) {
    $found = Get-ExecutorMarkers $Path
    if ($found.Count -gt 0) {
        throw "purge-engine.exe carries executor markers ($($found -join ', ')): it was built with rig-exec; rebuild it with 'cargo build --release -p purge-engine'"
    }
    Write-InstallLog "engine: no executor marker in $Path"
}

# Which build a purge-broker.exe is (review S-A): 'release' (the release marker, no toolkit path),
# 'toolkit' (a toolkit path, no release marker: built with --features toolkit-consent) or 'unknown'
# (neither or both: not a broker this repository builds, refused either way).
function Get-BrokerBuild([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    $release = $text.IndexOf($script:BrokerReleaseMarker, [StringComparison]::Ordinal) -ge 0
    $toolkit = $false
    foreach ($m in $script:BrokerToolkitMarkers) {
        if ($text.IndexOf($m, [StringComparison]::Ordinal) -ge 0) { $toolkit = $true }
    }
    if ($release -and -not $toolkit) { 'release' } elseif ($toolkit -and -not $release) { 'toolkit' } else { 'unknown' }
}

# Refuses a broker that is not the release build. -Toolkit (the VM rig's m3-consent -ConsentUi toolkit
# only, through install.ps1 -ToolkitBroker): it must be the toolkit build instead, so that a run meant
# for the toolkit dialog never tests the TaskDialog by mistake either.
function Assert-ReleaseBroker([string]$Path, [switch]$Toolkit) {
    $build = Get-BrokerBuild $Path
    $want = if ($Toolkit) { 'toolkit' } else { 'release' }
    if ($build -ne $want) {
        if ($build -eq 'toolkit') {
            throw "purge-broker.exe was built with the feature toolkit-consent (a rig or preview build): $Path. A release broker is 'cargo build --release -p purge-broker' without features; a rig build of the toolkit broker goes to its own --target-dir (vm\RIG.md 14)"
        }
        if ($Toolkit) { throw "-ToolkitBroker: $Path is not a broker built with --features toolkit-consent (it is '$build')" }
        throw "purge-broker.exe is not a release broker this repository builds (no staging marker): $Path"
    }
    Write-InstallLog "broker: $want build ($Path)"
}

# The install directory must be on the running system's volume (M3-INSTALL). The parent is used as the
# probe because the directory itself may not exist yet.
function Assert-SystemVolume([string]$Dir, [string]$WindowsDir) {
    if ($script:DryRun) { Write-InstallLog "what-if: verify $Dir is on the system volume ($WindowsDir)"; return }
    $probe = Split-Path -Parent $Dir
    if (-not (Test-SameVolume $probe $WindowsDir)) { throw "install directory is off the system volume (Windows is on $WindowsDir): $Dir" }
    Write-InstallLog "volume: $Dir is on the system volume"
}

function Write-InstallReport($Report, [string]$Path) {
    if (-not $Path) { return }
    $Report.log = @($script:InstallLog)
    $json = $Report | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-PurgeInstall {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 2.0
    $script:DryRun = [bool]$WhatIf
    $mode = if ($Uninstall) { 'uninstall' } elseif ($Check) { 'check' } else { 'install' }
    $report = [ordered]@{ schema = 'purge.install/1'; mode = $mode; what_if = $script:DryRun; engine_only = [bool]$EngineOnly; utc = [datetime]::UtcNow.ToString('o'); ok = $false; changed = $false; error = $null }
    try {
        if (-not [Environment]::Is64BitProcess) { throw 'run from 64-bit PowerShell (Program Files would resolve to the x86 folder)' }
        if (-not $script:DryRun -and -not (Test-Elevated)) { throw 'run elevated (as administrator)' }
        if ($script:DryRun) { Write-InstallLog 'what-if: dry run; the machine will not be changed and elevation is not needed' }
        if ($EngineOnly) { Write-InstallLog 'engine-only mode: purge-engine.exe, kb\ and the data root; no broker, UI, event-log source or shortcut' }
        if ($DataRootOnly -or $ProtectOnly) {
            if ($mode -ne 'install') { throw '-DataRootOnly and -ProtectOnly are install-mode switches; -Check verifies the whole layout and -Uninstall removes it' }
            if ($EngineOnly) { throw '-DataRootOnly and -ProtectOnly cannot be combined with -EngineOnly' }
            Write-InstallLog 'setup mode: the setup copied the payload; fewer steps than a full install'
        }
        Initialize-PurgeNative
        $repo = Split-Path -Parent $PSScriptRoot
        $pf = if ($ProgramFilesDir) { $ProgramFilesDir } else { Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Purge' }
        $dr = if ($DataRoot) { $DataRoot } else { Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Purge' }
        $startMenu = if ($StartMenuDir) { $StartMenuDir } else { Join-Path ([Environment]::GetFolderPath('CommonStartMenu')) 'Programs' }
        $shortcut = Join-Path $startMenu $script:StartMenuShortcutName
        $windowsDir = [Environment]::GetFolderPath('Windows')
        if (-not $windowsDir) { $windowsDir = $env:SystemRoot }
        $paths = if ($EngineOnly) { @($pf, $dr) } else { @($pf, $dr, $startMenu) }
        foreach ($p in $paths) {
            if (-not [IO.Path]::IsPathRooted($p) -or $p -notmatch '^[A-Za-z]:\\') { throw "not an absolute drive path: $p" }
            if (-not (Test-Path -LiteralPath (Split-Path -Parent $p) -PathType Container)) { throw "parent folder missing: $p" }
        }
        $report.program_files = $pf; $report.data_root_path = $dr
        if (-not $EngineOnly) { $report.shortcut = $shortcut }

        if ($mode -eq 'check') {
            if ($script:DryRun) {
                Write-InstallLog "what-if: verify the program-files tree $pf (ProgramFiles descriptor, no reparse point)"
                if ($EngineOnly) { Write-InstallLog "what-if: verify purge-engine.exe, kb\ and every deployed file (admin-only write)" }
                else { Write-InstallLog "what-if: verify purge-engine.exe, purge-broker.exe, Purge.exe, kb\ and every deployed file (admin-only write)" }
                Write-InstallLog "what-if: verify the data-root tree $dr"
                if (-not $EngineOnly) { Write-InstallLog "what-if: verify the event-log source '$($script:EventLogSource)' and the shortcut $shortcut" }
                $report.ok = $true
            } else {
                $a = Test-Tree $pf (Get-PurgeProgramFilesLayout) 'program-files'
                $payload = Test-PayloadLayout $pf $(if ($EngineOnly) { $null } else { $shortcut }) $script:AdminSids -EngineOnly:$EngineOnly
                $b = Test-Tree $dr (Get-PurgeDataLayout) 'data-root'
                $sourceOk = $true
                $brokerBuild = $null; $brokerOk = $true
                if (-not $EngineOnly) {
                    $sourceOk = Test-EventLogSourceKey
                    if (-not $sourceOk) { Write-InstallLog "event log: the Application source '$($script:EventLogSource)' is not registered" }
                    # The installed broker is the release build (review S-A); -ToolkitBroker: the rig's toolkit build.
                    $installedBroker = Join-Path $pf 'purge-broker.exe'
                    $wantBuild = if ($ToolkitBroker) { 'toolkit' } else { 'release' }
                    $brokerBuild = if (Test-Path -LiteralPath $installedBroker -PathType Leaf) { Get-BrokerBuild $installedBroker } else { 'missing' }
                    $brokerOk = ($brokerBuild -eq $wantBuild)
                    if (-not $brokerOk) { Write-InstallLog "broker: $installedBroker is the '$brokerBuild' build, not the $wantBuild build" }
                }
                $report.check = [ordered]@{ program_files = $a; payload = $payload; data_root = $b; event_log_source = $sourceOk; broker_build = $brokerBuild }
                $report.ok = ($a.verdict -eq 'good' -and $payload.ok -and $b.verdict -eq 'good' -and $sourceOk -and $brokerOk)
            }
        } elseif ($mode -eq 'uninstall') {
            if ($script:DryRun) {
                if ($EngineOnly) {
                    Write-InstallLog "what-if: remove $pf (engine-only mode; data root $dr is never touched)"
                } else {
                    Write-InstallLog "what-if: remove the shortcut $shortcut"
                    Write-InstallLog "what-if: remove the Application event-log source '$($script:EventLogSource)'"
                    Write-InstallLog "what-if: remove $pf (data root $dr is never touched)"
                }
                $report.ok = $true
            } else {
                $changed = $false
                if (-not $EngineOnly) {
                    $changed = Remove-Shortcut $shortcut
                    if (Remove-EventLogSource) { $changed = $true }
                }
                $f = Get-ObjectFacts $pf
                if (-not $f.Exists) {
                    Write-InstallLog "uninstall: $pf does not exist, nothing to do"
                } elseif (-not $f.AttributesKnown -or $f.IsReparsePoint -or -not $f.IsDirectory) {
                    throw "uninstall: $pf is not a plain directory (reparse point or file); left untouched"
                } else {
                    Remove-TreeNoFollow $pf
                    Write-InstallLog "uninstall: removed $pf (data root $dr left in place)"
                    $changed = $true
                }
                $report.changed = $changed
                $report.ok = $true
            }
        } elseif ($DataRootOnly -or $ProtectOnly) {
            # Inno Setup mode: the setup copied the payload into $pf before this step runs, so there is
            # nothing to build or copy. Protect that tree with the ProgramFiles descriptor (the setup
            # creates it with the Program Files inheritance, which grants Users no write but is not the
            # exact constant -Check compares against), create the data root and register the event-log
            # source. The shortcut is the setup's [Icons] entry, not this script's.
            Write-InstallLog "setup mode: the payload in $pf is already installed by the setup; no build, no payload copy, no shortcut"
            Assert-SystemVolume $pf $windowsDir
            if ($script:DryRun) {
                if ($ProtectOnly) { Write-InstallLog "what-if: protect $pf and every object below it with the ProgramFiles descriptor" }
                if ($DataRootOnly) {
                    Write-InstallLog "what-if: install the data-root tree $dr (sessions, Quarantine, fp, kb, sessions\index.json)"
                    Write-InstallLog "what-if: register the Application event-log source '$($script:EventLogSource)'"
                }
                $report.ok = $true
            } else {
                $reprotected = @()
                if ($ProtectOnly) {
                    # The setup's payload: never a toolkit broker (review S-A; build-installer.ps1 refuses
                    # one before ISCC, this is the installed copy).
                    Assert-ReleaseBroker (Join-Path $pf 'purge-broker.exe')
                    $reprotected = @(Protect-Tree $pf (Get-PurgeSddlTable).ProgramFiles)
                }
                $changed = ($reprotected.Count -gt 0)
                if ($DataRootOnly) {
                    $b = Install-Tree $dr (Get-PurgeDataLayout) 'data-root'
                    $report.data_root = $b
                    if ($b.changed) { $changed = $true }
                    if (Install-EventLogSource) { $changed = $true }
                }
                $report.reprotected = $reprotected
                $report.changed = $changed
                $report.ok = $true
            }
        } else {
            $enginePath = if ($Engine) { $Engine } else { Join-Path $repo 'target\release\purge-engine.exe' }
            $brokerPath = if ($EngineOnly) { '' } elseif ($Broker) { $Broker } else { Join-Path $repo 'target\release\purge-broker.exe' }
            if ($Ui -and $UiPublishDir) { throw 'pass -Ui (Purge.exe) or -UiPublishDir (a folder holding it), not both' }
            if ($ToolkitBroker -and ($EngineOnly -or -not $SkipBuild -or -not $Broker)) { throw '-ToolkitBroker (VM rig only) needs -SkipBuild and -Broker <a broker built with --features toolkit-consent>, and no -EngineOnly' }
            $uiDir = if ($EngineOnly) { '' } elseif ($UiPublishDir) { $UiPublishDir } elseif ($Ui) { $Ui } else { Join-Path $repo 'target\release\Purge.exe' }
            $kbDir = $Kb
            if (-not $kbDir) {
                $nextTo = Join-Path (Split-Path -Parent $enginePath) 'kb'
                $kbDir = if (Test-Path -LiteralPath $nextTo -PathType Container) { $nextTo } else { Join-Path $repo 'kb' }
            }
            $report.engine = $enginePath; $report.kb = $kbDir
            if (-not $EngineOnly) { $report.broker = $brokerPath; $report.ui = $uiDir }
            if ($EngineOnly) { Write-InstallLog "engine $enginePath; kb $kbDir" }
            else { Write-InstallLog "engine $enginePath; broker $brokerPath; UI $uiDir; kb $kbDir" }

            Assert-SystemVolume $pf $windowsDir
            if ($EngineOnly) { Write-InstallLog 'build: skipped (engine-only mode); purge-engine.exe must already exist' }
            elseif (-not $SkipBuild) { Invoke-ReleaseBuild $repo }
            else { Write-InstallLog 'build: skipped (-SkipBuild); the artifacts must already exist' }

            if ($script:DryRun) {
                Write-InstallLog "what-if: check that purge-engine.exe carries no executor marker"
                if (-not $EngineOnly) { Write-InstallLog "what-if: check that purge-broker.exe is the $(if ($ToolkitBroker) { 'toolkit' } else { 'release' }) build (staging marker)" }
                Write-InstallLog "what-if: install the program-files tree $pf with the ProgramFiles descriptor"
                if ($EngineOnly) { Write-InstallLog "what-if: copy purge-engine.exe and kb\ into $pf" }
                else { Write-InstallLog "what-if: copy purge-engine.exe, purge-broker.exe, Purge.exe ($uiDir) and kb\ into $pf" }
                Write-InstallLog "what-if: protect every deployed file and folder (owner Administrators, admin-only write)"
                Write-InstallLog "what-if: install the data-root tree $dr (sessions, Quarantine, fp, kb, sessions\index.json)"
                if (-not $EngineOnly) {
                    Write-InstallLog "what-if: register the Application event-log source '$($script:EventLogSource)'"
                    Write-InstallLog "what-if: create the all-users Start-menu shortcut $shortcut -> $(Join-Path $pf 'Purge.exe')"
                }
                Write-InstallLog 'what-if: nothing was changed'
                $report.ok = $true
            } else {
                if (-not (Test-Path -LiteralPath $enginePath -PathType Leaf)) { throw "engine not found: $enginePath (cargo build --release -p purge-engine, or pass -Engine)" }
                if ((Split-Path -Leaf $enginePath) -ne 'purge-engine.exe') { throw "the engine file must be named purge-engine.exe: $enginePath" }
                if (-not $EngineOnly) {
                    if (-not (Test-Path -LiteralPath $brokerPath -PathType Leaf)) { throw "broker not found: $brokerPath (cargo build --release -p purge-broker, or pass -Broker)" }
                    if ((Split-Path -Leaf $brokerPath) -ne 'purge-broker.exe') { throw "the broker file must be named purge-broker.exe: $brokerPath" }
                    $uiFacts = Get-ObjectFacts $uiDir
                    if (-not $uiFacts.Exists -or $uiFacts.IsReparsePoint) { throw "UI not found or a reparse point: $uiDir (cargo build --release -p purge-ui, or pass -Ui)" }
                    if ($uiFacts.IsDirectory) {
                        if (-not (Test-Path -LiteralPath (Join-Path $uiDir 'Purge.exe') -PathType Leaf)) { throw "Purge.exe is not in the UI folder: $uiDir" }
                    } elseif ((Split-Path -Leaf $uiDir) -ne 'Purge.exe') { throw "the UI file must be named Purge.exe: $uiDir" }
                }
                if (-not (Test-Path -LiteralPath $kbDir -PathType Container)) { throw "kb folder not found: $kbDir" }

                Assert-EngineWithoutExecutor $enginePath
                if (-not $EngineOnly) { Assert-ReleaseBroker $brokerPath -Toolkit:$ToolkitBroker }
                $a = Install-Tree $pf (Get-PurgeProgramFilesLayout) 'program-files'
                $payload = Copy-Payload $pf $enginePath $brokerPath $uiDir $kbDir (Get-PurgeSddlTable).ProgramFiles
                $b = Install-Tree $dr (Get-PurgeDataLayout) 'data-root'
                $changed = $a.changed -or $b.changed -or $payload.changed
                if (-not $EngineOnly) {
                    if (Install-EventLogSource) { $changed = $true }
                    if (Install-Shortcut $shortcut (Join-Path $pf 'Purge.exe') $pf) { $changed = $true }
                }
                $report.program_files_tree = $a
                $report.payload = $payload
                $report.data_root = $b
                $report.changed = $changed
                $n = @($a.renamed_aside).Count + @($b.renamed_aside).Count
                if ($n) { Write-Warning "install: $n tree(s) renamed aside; see the log above" }
                $report.ok = $true
            }
        }
    } catch {
        $report.error = $_.Exception.Message
        Write-InstallLog "FAILED: $($_.Exception.Message)"
    }
    Write-InstallReport $report $ReportPath
    if ($report.ok) {
        $tail = if ($script:DryRun) { ' (what-if: nothing changed)' } elseif ($report.changed) { ' (changed)' } else { ' (no changes)' }
        Write-InstallLog "$mode ok$tail"
        return 0
    }
    return 1
}

if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-PurgeInstall) }
