# Purge v1 deploy script (ENGINE_PLAN.md 3.2, 7.4, 7.9). Windows PowerShell 5.1, 64-bit, elevated.
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 [-Engine <exe>] [-Kb <dir>]
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -Check
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -Uninstall
#
# What it does (contract and the SDDL constants: install\README.md, the single documented source):
#   1. %ProgramFiles%\Purge: created with a protected admin-only-write DACL; purge-engine.exe and the kb\
#      tree are copied in (files whose SHA-256 already matches are left alone).
#   2. %ProgramData%\Purge with sessions, Quarantine, fp, kb and sessions\index.json (created as "{}"):
#      every object is created with its own protected DACL in the same call that creates it
#      (CreateDirectoryW / CreateFileW CREATE_NEW with a security descriptor), so there is no window in
#      which an inherited ProgramData ACE lets a standard user in.
#   3. An existing tree is adopted only when every object in it is exactly what step 1/2 would create
#      (owner, protected DACL, ACEs; compared after canonical rendering) and nothing at its top two levels
#      is a reparse point. Anything else is never adopted and never recursed into: the tree's root is
#      renamed aside to <name>.rejected-<utc> through a handle opened with FILE_FLAG_OPEN_REPARSE_POINT
#      (so a junction is renamed, never followed), reported, and a fresh tree is created.
#   4. A run on a good tree changes nothing (idempotent). -Uninstall removes only the Program Files copy,
#      never ProgramData\Purge. -Check verifies both trees and changes nothing.
# It never downloads anything, never touches Defender or System Restore settings and signs nothing.
#
# Dot-sourcing the script (". install.ps1") only defines its functions; install\tests\install-selftest.ps1
# uses that to test the pure parts (SDDL builder, canonical form, integrity verdict) without elevation.

[CmdletBinding()]
param(
    # purge-engine.exe to deploy. Default: the repo's target\release\purge-engine.exe.
    [string]$Engine = '',
    # kb directory to deploy beside the engine. Default: <engine dir>\kb when it exists, else the repo's kb\.
    [string]$Kb = '',
    # Overrides for tests in a VM only; production uses the defaults.
    [string]$ProgramFilesDir = '',
    [string]$DataRoot = '',
    # Remove %ProgramFiles%\Purge only (never the data root).
    [switch]$Uninstall,
    # Verify both trees, change nothing; exit 0 only when both are exactly as installed.
    [switch]$Check,
    # Optional JSON report (schema purge.install/1).
    [string]$ReportPath = ''
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

# Access bits that let a principal change an object or its children: WRITE_DATA/ADD_FILE (0x2),
# APPEND_DATA/ADD_SUBDIRECTORY (0x4), WRITE_EA (0x10), DELETE_CHILD (0x40), WRITE_ATTRIBUTES (0x100),
# DELETE, WRITE_DAC, WRITE_OWNER, MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_WRITE.
$script:WriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x2000000 -bor 0x10000000 -bor 0x40000000

$script:FileAttrDirectory = 0x10
$script:FileAttrReparse = 0x400

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
    }
}
'@

function Initialize-PurgeNative {
    if (-not ('PurgeInstall.Native' -as [type])) { Add-Type -TypeDefinition $script:NativeSource -Language CSharp }
}

function Format-Win32Error([int]$Code) { '{0} ({1})' -f $Code, (New-Object System.ComponentModel.Win32Exception $Code).Message }

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

# Engine + kb into the verified Program Files tree. New files and subdirectories inherit the root's
# protected DACL. Files already in the destination but not in the source are reported, never deleted.
function Copy-Payload([string]$Dir, [string]$EnginePath, [string]$KbDir) {
    $out = @()
    $out += Copy-PayloadFile $EnginePath (Join-Path $Dir 'purge-engine.exe')
    if ($KbDir) {
        $kbDest = Join-Path $Dir 'kb'
        $srcRoot = (Resolve-Path -LiteralPath $KbDir).ProviderPath.TrimEnd('\')
        $wanted = @{}
        foreach ($f in @(Get-ChildItem -LiteralPath $srcRoot -Recurse -Force -File)) {
            if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { Write-InstallLog "payload: skipping reparse point $($f.FullName)"; continue }
            $rel = $f.FullName.Substring($srcRoot.Length + 1)
            $dest = Join-Path $kbDest $rel
            $wanted[$dest.ToLowerInvariant()] = $true
            $dd = Split-Path -Parent $dest
            $ddf = Get-ObjectFacts $dd
            if ($ddf.Exists -and ($ddf.IsReparsePoint -or -not $ddf.IsDirectory)) { throw "refusing to write into $dd (not a plain directory)" }
            if (-not $ddf.Exists) { [void][IO.Directory]::CreateDirectory($dd) }
            $out += Copy-PayloadFile $f.FullName $dest
        }
        if (Test-Path -LiteralPath $kbDest) {
            foreach ($f in @(Get-ChildItem -LiteralPath $kbDest -Recurse -Force -File -ErrorAction SilentlyContinue)) {
                if (-not $wanted.ContainsKey($f.FullName.ToLowerInvariant())) { $out += [ordered]@{ file = $f.FullName; action = 'stale (left in place)' } }
            }
        }
    }
    foreach ($o in $out) { if ($o.action -ne 'unchanged') { Write-InstallLog "payload: $($o.action) $($o.file)" } }
    $out
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

function Write-InstallReport($Report, [string]$Path) {
    if (-not $Path) { return }
    $Report.log = @($script:InstallLog)
    $json = $Report | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-PurgeInstall {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 2.0
    $mode = if ($Uninstall) { 'uninstall' } elseif ($Check) { 'check' } else { 'install' }
    $report = [ordered]@{ schema = 'purge.install/1'; mode = $mode; utc = [datetime]::UtcNow.ToString('o'); ok = $false; changed = $false; error = $null }
    try {
        if (-not [Environment]::Is64BitProcess) { throw 'run from 64-bit PowerShell (Program Files would resolve to the x86 folder)' }
        if (-not (Test-Elevated)) { throw 'run elevated (as administrator)' }
        Initialize-PurgeNative
        $repo = Split-Path -Parent $PSScriptRoot
        $pf = if ($ProgramFilesDir) { $ProgramFilesDir } else { Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Purge' }
        $dr = if ($DataRoot) { $DataRoot } else { Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Purge' }
        foreach ($p in $pf, $dr) {
            if (-not [IO.Path]::IsPathRooted($p) -or $p -notmatch '^[A-Za-z]:\\') { throw "not an absolute drive path: $p" }
            if (-not (Test-Path -LiteralPath (Split-Path -Parent $p) -PathType Container)) { throw "parent folder missing: $p" }
        }
        $report.program_files = $pf; $report.data_root_path = $dr

        if ($mode -eq 'check') {
            $a = Test-Tree $pf (Get-PurgeProgramFilesLayout) 'program-files'
            $b = Test-Tree $dr (Get-PurgeDataLayout) 'data-root'
            $report.check = [ordered]@{ program_files = $a; data_root = $b }
            $report.ok = ($a.verdict -eq 'good' -and $b.verdict -eq 'good')
        } elseif ($mode -eq 'uninstall') {
            $f = Get-ObjectFacts $pf
            if (-not $f.Exists) {
                Write-InstallLog "uninstall: $pf does not exist, nothing to do"
            } elseif (-not $f.AttributesKnown -or $f.IsReparsePoint -or -not $f.IsDirectory) {
                throw "uninstall: $pf is not a plain directory (reparse point or file); left untouched"
            } else {
                Remove-TreeNoFollow $pf
                Write-InstallLog "uninstall: removed $pf (data root $dr left in place)"
                $report.changed = $true
            }
            $report.ok = $true
        } else {
            if (-not $Engine) { $Engine = Join-Path $repo 'target\release\purge-engine.exe' }
            if (-not (Test-Path -LiteralPath $Engine -PathType Leaf)) { throw "engine not found: $Engine (cargo build --release -p purge-engine, or pass -Engine)" }
            if ((Split-Path -Leaf $Engine) -ne 'purge-engine.exe') { throw "the engine file must be named purge-engine.exe: $Engine" }
            if (-not $Kb) {
                $nextTo = Join-Path (Split-Path -Parent $Engine) 'kb'
                $Kb = if (Test-Path -LiteralPath $nextTo -PathType Container) { $nextTo } else { Join-Path $repo 'kb' }
            }
            if (-not (Test-Path -LiteralPath $Kb -PathType Container)) { throw "kb folder not found: $Kb" }
            Write-InstallLog "engine $Engine; kb $Kb"
            $a = Install-Tree $pf (Get-PurgeProgramFilesLayout) 'program-files'
            $payload = @(Copy-Payload $pf $Engine $Kb)
            $b = Install-Tree $dr (Get-PurgeDataLayout) 'data-root'
            $report.program_files_tree = $a
            $report.payload = $payload
            $report.data_root = $b
            $report.changed = ($a.changed -or $b.changed -or @($payload | Where-Object { $_.action -eq 'copied' -or $_.action -eq 'updated' }).Count -gt 0)
            $n = @($a.renamed_aside).Count + @($b.renamed_aside).Count
            if ($n) { Write-Warning "install: $n tree(s) renamed aside; see the log above" }
            $report.ok = $true
        }
    } catch {
        $report.error = $_.Exception.Message
        Write-InstallLog "FAILED: $($_.Exception.Message)"
    }
    Write-InstallReport $report $ReportPath
    if ($report.ok) { Write-InstallLog "$mode ok$(if ($report.changed) { ' (changed)' } else { ' (no changes)' })"; return 0 }
    return 1
}

if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-PurgeInstall) }
