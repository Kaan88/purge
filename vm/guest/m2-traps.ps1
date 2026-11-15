# Purge rig, M2: guest trap builder and trap manifest (ENGINE_PLAN.md section 10.2 "M2 traps", 11.2).
# Windows PowerShell 5.1, 64-bit, elevated, inside the test VM only. Never run it on a real machine.
#
# Builds, inside the synthetic app root C:\Program Files\PurgeTrapApp, its keys HKLM\SOFTWARE\PurgeTrapApp
# and HKU\<sid>\Software\PurgeTrapApp, a user-writable root C:\PurgeTrapUW and a canary tree C:\PurgeCanary
# (+ HKLM\SOFTWARE\PurgeCanary, HKU\<sid>\Software\PurgeCanary), one trap per row of section 10.2, and
# writes the trap manifest: every protected object (canary) with its content hash, and per plan item the
# executor outcome the gate expects (a blocker name, or e.g. "link removed, target intact").
#
# The rule behind every trap: no canary may change. A canary is anything outside what the plan may touch
# (a junction's target, a hard link's other name, a REG_LINK's target key, a TrustedInstaller-owned
# object, a sibling a normalised name would hit). `-Action check` re-hashes them all.
#
# Actions
#   build   (default) reset this stage's traps, build them, write into -OutDir:
#             m2-traps-manifest.json  purge.rig.m2traps/0 + build records + measured canaries
#             m2-traps-targets.json   purge.rig.targets/0: plan items for `purge-engine plan from-targets`
#             m2-traps-select.json    purge.rig.select/0: the rig ids of those items (the rig maps them to
#                                     candidate ids by target after planning; PowerShell cannot compute
#                                     a plan hash or candidate ids)
#             m2-traps-paths.txt      file-system item paths, one per line (for `scan --path`)
#           -Stage pre-install  builds only the traps that must exist before install\install.ps1 runs
#                               (a user-created C:\ProgramData\Purge with planted junctions);
#           -Stage post-install (default) builds everything else. The manifest of both stages merges.
#   check   re-measures every canary of the built traps and the traps' post-checks; writes
#           m2-traps-check[-<Label>].json; exit 1 when any canary changed (a guard escape).
#   swap    race helper for the swap-after-validate traps (-TrapId race-validate-open|race-open-act):
#           waits until the newest session journal names the item in an intent record (the engine is then
#           paused by PURGE_FAULT_PAUSE, see the manifest's helper.fault_pause), renames the validated
#           directory aside and puts a junction to the canary in its place. Start it before `exec`.
#   plant-boot-junction    after the m2-reboot locker released C:\PurgeTrapUW\boot\user-locked.dll and
#           before the retry run: a medium-IL user replaces C:\PurgeTrapUW\boot with a junction to the canary.
#   plant-expiry-junction  after exec quarantined PurgeTrapApp\expiry\payload: plants a directory junction
#           and a file symlink to canaries inside that quarantined item, for `quarantine purge`.
#   reset   removes everything this script creates (never a C:\ProgramData\Purge it did not create).
#
# -DryRun (with build): no system change. Compiles the native helper, prints the static manifest (the
# source of vm\truth\m2-traps.json) with placeholders {user-sid} and {localappdata}, writes it and the
# targets files to -OutDir when given. -Library: only define the functions (dot-sourced by m2-fixtures.ps1).
#
# Medium-IL steps run through riglib's LaunchMedium (one-shot task PurgeRigM2Medium), as a standard user
# would act. Every file-system operation goes through \\?\ paths and never follows a reparse point when
# deleting, so a reset cannot reach a canary through a planted link; registry deletes open every key with
# REG_OPTION_OPEN_LINK and delete links as links.
[CmdletBinding()]
param(
    [ValidateSet('build', 'check', 'swap', 'plant-boot-junction', 'plant-expiry-junction', 'reset')]
    [string]$Action = 'build',
    [ValidateSet('pre-install', 'post-install')]
    [string]$Stage = 'post-install',
    [string]$OutDir = '',
    [string]$TrapId = '',
    [string]$Label = '',
    [int]$TimeoutSec = 300,
    [switch]$DryRun,
    [switch]$Library
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------------------------------- constants

$M2TrapRoot   = 'C:\Program Files\PurgeTrapApp'
$M2CanaryRoot = 'C:\PurgeCanary'
$M2UwRoot     = 'C:\PurgeTrapUW'
$M2PdRoot     = 'C:\ProgramData\Purge'
$M2Jobs       = 'C:\cr\jobs\m2-medium'
$M2TiSid      = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'   # NT SERVICE\TrustedInstaller
$M2Utf8       = New-Object System.Text.UTF8Encoding($false)
# Security descriptors (SDDL). Set with SeRestorePrivilege through backup-semantics handles.
$M2SddlTiDir    = "O:${M2TiSid}G:${M2TiSid}D:PAI(A;OICI;FA;;;${M2TiSid})(A;OICI;0x1200a9;;;BA)(A;OICI;0x1200a9;;;SY)(A;OICI;0x1200a9;;;BU)"
$M2SddlTiFile   = "O:${M2TiSid}G:${M2TiSid}D:PAI(A;;FA;;;${M2TiSid})(A;;0x1200a9;;;BA)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BU)"
$M2SddlTiKey    = "O:${M2TiSid}G:SYD:PAI(A;CI;KA;;;${M2TiSid})(A;CI;KR;;;BA)(A;CI;KR;;;SY)(A;CI;KR;;;BU)"
$M2SddlTiAceKey = "O:BAG:SYD:PAI(A;CI;KA;;;${M2TiSid})(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KR;;;BU)"
$M2SddlUwDir    = 'O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;BU)'   # Users: modify
$M2SddlAdminFile = 'O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)'
$M2SddlAdminKey  = 'O:BAG:SYD:PAI(A;CI;KA;;;BA)(A;CI;KA;;;SY)'

# Registry value types.
$REG_NONE = 0; $REG_SZ = 1; $REG_EXPAND_SZ = 2; $REG_BINARY = 3; $REG_DWORD = 4; $REG_DWORD_BE = 5
$REG_MULTI_SZ = 7; $REG_RESOURCE_LIST = 8; $REG_FULL_RESOURCE = 9; $REG_RESOURCE_REQ = 10; $REG_QWORD = 11

# File attributes the traps set.
$M2Attr = @{ ReadOnly = 0x1; Hidden = 0x2; System = 0x4; Offline = 0x1000; RecallOnOpen = 0x40000; RecallOnDataAccess = 0x400000 }

# ------------------------------------------------------------------------------------------ native code

if (-not ('PurgeRigM2.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PurgeRigM2
{
    public class RegValueRaw { public string Name; public int Type; public byte[] Data; }
    public class FsFacts { public uint Attributes; public uint ReparseTag; public uint VolumeSerial; public string FileId; public uint Links; public bool IsDir; public long Size; }
    public class DirEntry { public string Name; public uint Attributes; }

    // Rig-only Win32 helpers: \\?\ paths everywhere, deletes that never follow reparse points, registry
    // links, raw registry values, security descriptors through backup/restore privileges.
    public static class Native
    {
        static readonly UIntPtr HKLM = new UIntPtr(0x80000002u);
        static readonly UIntPtr HKU = new UIntPtr(0x80000003u);
        const int KEY_QUERY_VALUE = 0x1, KEY_SET_VALUE = 0x2, KEY_CREATE_LINK = 0x20, KEY_WOW64_64KEY = 0x100;
        const int KEY_READ = 0x20019, KEY_WRITE = 0x20006, DELETE = 0x10000, READ_CONTROL = 0x20000, WRITE_DAC = 0x40000, WRITE_OWNER = 0x80000;
        const int REG_OPTION_CREATE_LINK = 0x2, REG_OPTION_BACKUP_RESTORE = 0x4, REG_OPTION_OPEN_LINK = 0x8;
        const int SI_OWNER_GROUP_DACL = 0x7;
        const int BACKUP = 0x02000000, OPEN_REPARSE = 0x00200000, DELETE_ON_CLOSE = 0x04000000;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegCreateKeyExW(UIntPtr hKey, string sub, int reserved, string cls, int options, int sam, IntPtr sa, out UIntPtr result, out int disp);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegOpenKeyExW(UIntPtr hKey, string sub, int options, int sam, out UIntPtr result);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegSetValueExW(UIntPtr hKey, string name, int reserved, int type, byte[] data, int cb);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegQueryValueExW(UIntPtr hKey, string name, IntPtr reserved, out int type, byte[] data, ref int cb);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegEnumValueW(UIntPtr hKey, int index, StringBuilder name, ref int cchName, IntPtr reserved, out int type, byte[] data, ref int cbData);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegEnumKeyExW(UIntPtr hKey, int index, StringBuilder name, ref int cchName, IntPtr reserved, IntPtr cls, IntPtr cchCls, IntPtr ft);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegQueryInfoKeyW(UIntPtr hKey, StringBuilder cls, ref int cchCls, IntPtr reserved, out int subKeys, out int maxSubKeyLen, out int maxClassLen, out int values, out int maxValueNameLen, out int maxValueLen, out int cbSd, IntPtr ft);
        [DllImport("advapi32.dll")] static extern int RegCloseKey(UIntPtr hKey);
        [DllImport("advapi32.dll")] static extern int RegSetKeySecurity(UIntPtr hKey, int si, IntPtr sd);
        [DllImport("advapi32.dll")] static extern int RegGetKeySecurity(UIntPtr hKey, int si, byte[] sd, ref int cb);
        [DllImport("ntdll.dll")] static extern int NtDeleteKey(UIntPtr hKey);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, int rev, out IntPtr sd, IntPtr size);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(byte[] sd, int rev, int si, out IntPtr sddl, IntPtr len);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetKernelObjectSecurity(SafeFileHandle h, int si, IntPtr sd);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetKernelObjectSecurity(SafeFileHandle h, int si, byte[] sd, int cb, out int needed);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr proc, int access, out IntPtr token);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool LookupPrivilegeValueW(string sys, string name, out long luid);
        [StructLayout(LayoutKind.Sequential, Pack = 4)] struct TOKEN_PRIV { public int Count; public long Luid; public int Attr; }
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIV p, int len, IntPtr prev, IntPtr retLen);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFileW(string name, int access, int share, IntPtr sa, int disp, int flags, IntPtr tmpl);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateDirectoryW(string name, IntPtr sa);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFileAttributesW(string name);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool SetFileAttributesW(string name, uint attrs);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateHardLinkW(string link, string existing, IntPtr sa);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.I1)] static extern bool CreateSymbolicLinkW(string link, string target, int flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool MoveFileExW(string from, string to, int flags);
        [StructLayout(LayoutKind.Sequential)] struct BY_HANDLE_FILE_INFORMATION { public uint Attr, CtL, CtH, AtL, AtH, WtL, WtH, VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
        [StructLayout(LayoutKind.Sequential)] struct FILE_ATTRIBUTE_TAG_INFO { public uint Attr; public uint Tag; }
        [StructLayout(LayoutKind.Sequential)] struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Info; }
        [StructLayout(LayoutKind.Sequential)] struct FILE_BASIC_INFORMATION { public long C, A, W, Ch; public uint Attr; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct WIN32_FIND_DATAW { public uint Attr, CtL, CtH, AtL, AtH, WtL, WtH, SizeHigh, SizeLow, Reserved0, Reserved1; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string Alt; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct WIN32_FIND_STREAM_DATA { public long Size; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string Name; }
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int cls, out FILE_ATTRIBUTE_TAG_INFO info, int size);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool DeviceIoControl(SafeFileHandle h, int code, byte[] inBuf, int inSize, IntPtr outBuf, int outSize, out int returned, IntPtr ov);
        [DllImport("ntdll.dll")] static extern int NtSetInformationFile(SafeFileHandle h, out IO_STATUS_BLOCK iosb, ref FILE_BASIC_INFORMATION info, int len, int cls);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstFileW(string name, out WIN32_FIND_DATAW data);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool FindNextFileW(IntPtr h, out WIN32_FIND_DATAW data);
        [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstStreamW(string name, int level, out WIN32_FIND_STREAM_DATA data, int flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool FindNextStreamW(IntPtr h, out WIN32_FIND_STREAM_DATA data);

        static readonly IntPtr INVALID = new IntPtr(-1);

        // ------------------------------------------------------------------ common
        public static string L(string p)
        {
            if (p.StartsWith(@"\\?\")) return p;
            if (p.StartsWith(@"\\")) return @"\\?\UNC\" + p.Substring(2);
            return @"\\?\" + p;
        }
        static Win32Exception Err(int code, string what, string path)
        {
            return new Win32Exception(code, what + " '" + path + "': " + new Win32Exception(code).Message);
        }
        static Win32Exception Last(string what, string path) { return Err(Marshal.GetLastWin32Error(), what, path); }

        public static bool EnablePrivilege(string name)
        {
            IntPtr tok;
            if (!OpenProcessToken(GetCurrentProcess(), 0x28 /* ADJUST_PRIVILEGES | QUERY */, out tok)) return false;
            try
            {
                long luid;
                if (!LookupPrivilegeValueW(null, name, out luid)) return false;
                TOKEN_PRIV tp = new TOKEN_PRIV(); tp.Count = 1; tp.Luid = luid; tp.Attr = 2;
                if (!AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
                return Marshal.GetLastWin32Error() == 0;
            }
            finally { CloseHandle(tok); }
        }

        static IntPtr Sd(string sddl)
        {
            IntPtr sd;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, IntPtr.Zero)) throw Last("SDDL", sddl);
            return sd;
        }
        static string SdToString(byte[] sd)
        {
            IntPtr s;
            if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, SI_OWNER_GROUP_DACL, out s, IntPtr.Zero)) throw Last("SD to SDDL", "");
            try { return Marshal.PtrToStringUni(s); } finally { LocalFree(s); }
        }

        // ------------------------------------------------------------------ files
        public static uint Attributes(string p) { return GetFileAttributesW(L(p)); }

        // Facts of the object itself (a link is not followed); null when it does not exist.
        public static FsFacts Facts(string p)
        {
            SafeFileHandle h = CreateFileW(L(p), 0x80, 7, IntPtr.Zero, 3, BACKUP | OPEN_REPARSE, IntPtr.Zero);
            if (h.IsInvalid)
            {
                int e = Marshal.GetLastWin32Error();
                if (e == 2 || e == 3) return null;
                throw Err(e, "open", p);
            }
            using (h)
            {
                BY_HANDLE_FILE_INFORMATION i;
                if (!GetFileInformationByHandle(h, out i)) throw Last("GetFileInformationByHandle", p);
                FILE_ATTRIBUTE_TAG_INFO t;
                uint tag = 0;
                if (GetFileInformationByHandleEx(h, 9, out t, 8)) tag = t.Tag;
                FsFacts f = new FsFacts();
                f.Attributes = i.Attr; f.ReparseTag = (i.Attr & 0x400) != 0 ? tag : 0; f.VolumeSerial = i.VolumeSerial;
                f.FileId = ((((ulong)i.IndexHigh) << 32) | i.IndexLow).ToString("x16");
                f.Links = i.Links; f.IsDir = (i.Attr & 0x10) != 0; f.Size = (((long)i.SizeHigh) << 32) | i.SizeLow;
                return f;
            }
        }

        public static void MkDir(string p)
        {
            if (CreateDirectoryW(L(p), IntPtr.Zero)) return;
            int e = Marshal.GetLastWin32Error();
            uint a = Attributes(p);
            if (e == 183 && a != 0xFFFFFFFF && (a & 0x10) != 0) return;
            throw Err(e, "CreateDirectory", p);
        }
        public static void MkDirs(string p)
        {
            string full = p.TrimEnd('\\');
            int start = full.IndexOf('\\') + 1;
            for (int i = start; i <= full.Length; i++)
                if (i == full.Length || full[i] == '\\') MkDir(full.Substring(0, i));
        }
        public static void WriteAll(string p, byte[] data)
        {
            SafeFileHandle h = CreateFileW(L(p), 0x40000000, 0, IntPtr.Zero, 2, 0x80, IntPtr.Zero);
            if (h.IsInvalid) throw Last("create", p);
            using (FileStream fs = new FileStream(h, FileAccess.Write)) fs.Write(data, 0, data.Length);
        }
        public static byte[] ReadAll(string p)
        {
            SafeFileHandle h = CreateFileW(L(p), unchecked((int)0x80000000), 7, IntPtr.Zero, 3, BACKUP, IntPtr.Zero);
            if (h.IsInvalid) throw Last("open for read", p);
            using (FileStream fs = new FileStream(h, FileAccess.Read))
            using (MemoryStream ms = new MemoryStream())
            {
                fs.CopyTo(ms);
                return ms.ToArray();
            }
        }
        public static void SetAttributes(string p, uint a)
        {
            if (!SetFileAttributesW(L(p), a)) throw Last("SetFileAttributes", p);
        }
        // Tries SetFileAttributes, then NtSetInformationFile(FileBasicInformation); returns how the bits
        // stuck, or why they did not (RECALL_* are normally kept by the kernel for cloud filters only).
        public static string ForceAttributes(string p, uint a)
        {
            SetFileAttributesW(L(p), a);
            uint got = Attributes(p);
            if (got != 0xFFFFFFFF && (got & a) == a) return "set:SetFileAttributes";
            SafeFileHandle h = CreateFileW(L(p), 0x180, 7, IntPtr.Zero, 3, BACKUP | OPEN_REPARSE, IntPtr.Zero);
            if (h.IsInvalid) return "not-set:open error " + Marshal.GetLastWin32Error();
            int st;
            using (h)
            {
                FILE_BASIC_INFORMATION fbi = new FILE_BASIC_INFORMATION();
                fbi.Attr = a;
                IO_STATUS_BLOCK io;
                st = NtSetInformationFile(h, out io, ref fbi, Marshal.SizeOf(typeof(FILE_BASIC_INFORMATION)), 4);
            }
            got = Attributes(p);
            if (got != 0xFFFFFFFF && (got & a) == a) return "set:NtSetInformationFile";
            return "not-set:status 0x" + st.ToString("X8") + " attributes 0x" + got.ToString("X8");
        }
        // Puts an IO_REPARSE_TAG_CLOUD_1 reparse point on an existing file; returns the Win32 error (0 = ok).
        public static int SetCloudTag(string p)
        {
            SafeFileHandle h = CreateFileW(L(p), unchecked((int)0xC0000000), 0, IntPtr.Zero, 3, BACKUP | OPEN_REPARSE, IntPtr.Zero);
            if (h.IsInvalid) return Marshal.GetLastWin32Error();
            using (h)
            {
                byte[] buf = new byte[16];
                BitConverter.GetBytes(0x9000101Au).CopyTo(buf, 0);
                BitConverter.GetBytes((ushort)8).CopyTo(buf, 4);
                for (int i = 0; i < 8; i++) buf[8 + i] = (byte)(i + 1);
                int ret;
                return DeviceIoControl(h, 0x000900A4, buf, buf.Length, IntPtr.Zero, 0, out ret, IntPtr.Zero) ? 0 : Marshal.GetLastWin32Error();
            }
        }
        public static void Junction(string link, string target)
        {
            MkDir(link);
            SafeFileHandle h = CreateFileW(L(link), 0x40000000, 0, IntPtr.Zero, 3, BACKUP | OPEN_REPARSE, IntPtr.Zero);
            if (h.IsInvalid) throw Last("open junction", link);
            using (h)
            {
                byte[] s = Encoding.Unicode.GetBytes(@"\??\" + target), pr = Encoding.Unicode.GetBytes(target);
                int dataLen = 8 + s.Length + 2 + pr.Length + 2;
                byte[] buf = new byte[8 + dataLen];
                BitConverter.GetBytes(0xA0000003u).CopyTo(buf, 0);
                BitConverter.GetBytes((ushort)dataLen).CopyTo(buf, 4);
                BitConverter.GetBytes((ushort)0).CopyTo(buf, 8);
                BitConverter.GetBytes((ushort)s.Length).CopyTo(buf, 10);
                BitConverter.GetBytes((ushort)(s.Length + 2)).CopyTo(buf, 12);
                BitConverter.GetBytes((ushort)pr.Length).CopyTo(buf, 14);
                s.CopyTo(buf, 16);
                pr.CopyTo(buf, 16 + s.Length + 2);
                int ret;
                if (!DeviceIoControl(h, 0x000900A4, buf, buf.Length, IntPtr.Zero, 0, out ret, IntPtr.Zero)) throw Last("FSCTL_SET_REPARSE_POINT", link);
            }
        }
        public static void Symlink(string link, string target, bool dir)
        {
            if (!CreateSymbolicLinkW(L(link), target, dir ? 1 : 0)) throw Last("CreateSymbolicLink", link);
        }
        public static void HardLink(string link, string existing)
        {
            if (!CreateHardLinkW(L(link), L(existing), IntPtr.Zero)) throw Last("CreateHardLink", link);
        }
        public static void Move(string from, string to)
        {
            if (!MoveFileExW(L(from), L(to), 0)) throw Last("MoveFileEx", from);
        }
        public static DirEntry[] List(string dir)
        {
            List<DirEntry> r = new List<DirEntry>();
            WIN32_FIND_DATAW d;
            IntPtr h = FindFirstFileW(L(dir) + @"\*", out d);
            if (h == INVALID)
            {
                int e = Marshal.GetLastWin32Error();
                if (e == 2 || e == 18) return r.ToArray();
                throw Err(e, "FindFirstFile", dir);
            }
            try
            {
                do
                {
                    if (d.Name == "." || d.Name == "..") continue;
                    DirEntry x = new DirEntry(); x.Name = d.Name; x.Attributes = d.Attr; r.Add(x);
                } while (FindNextFileW(h, out d));
            }
            finally { FindClose(h); }
            return r.ToArray();
        }
        public static string[] Streams(string p)
        {
            List<string> r = new List<string>();
            WIN32_FIND_STREAM_DATA d;
            IntPtr h = FindFirstStreamW(L(p), 0, out d, 0);
            if (h == INVALID) return r.ToArray();
            try { do { r.Add(d.Name + "|" + d.Size); } while (FindNextStreamW(h, out d)); }
            finally { FindClose(h); }
            r.Sort(StringComparer.Ordinal);
            return r.ToArray();
        }
        // Deletes the object itself (a link, never its target).
        public static void DeleteNoFollow(string p)
        {
            SafeFileHandle h = CreateFileW(L(p), DELETE, 7, IntPtr.Zero, 3, BACKUP | OPEN_REPARSE | DELETE_ON_CLOSE, IntPtr.Zero);
            if (h.IsInvalid)
            {
                int e = Marshal.GetLastWin32Error();
                if (e == 2 || e == 3) return;
                throw Err(e, "delete", p);
            }
            h.Dispose();
        }
        // Recursive delete that removes reparse points as links and never descends into them.
        public static void RemoveTree(string p)
        {
            uint a = Attributes(p);
            if (a == 0xFFFFFFFF)
            {
                int e = Marshal.GetLastWin32Error();
                if (e == 2 || e == 3) return;
                throw Err(e, "attributes", p);
            }
            bool dir = (a & 0x10) != 0, rp = (a & 0x400) != 0;
            if (!rp && (a & 0x7) != 0)
            {
                uint n = a & ~0x7u & ~0x10u;
                SetFileAttributesW(L(p), n == 0 ? 0x80u : n);
            }
            if (dir && !rp)
                foreach (DirEntry e in List(p)) RemoveTree(p + "\\" + e.Name);
            DeleteNoFollow(p);
        }
        public static void SetFileSddl(string p, string sddl)
        {
            SafeFileHandle h = CreateFileW(L(p), READ_CONTROL | WRITE_DAC | WRITE_OWNER, 7, IntPtr.Zero, 3, BACKUP | OPEN_REPARSE, IntPtr.Zero);
            if (h.IsInvalid) throw Last("open for security", p);
            IntPtr sd = Sd(sddl);
            try { using (h) { if (!SetKernelObjectSecurity(h, SI_OWNER_GROUP_DACL, sd)) throw Last("SetKernelObjectSecurity", p); } }
            finally { LocalFree(sd); }
        }
        public static string GetFileSddl(string p)
        {
            SafeFileHandle h = CreateFileW(L(p), READ_CONTROL, 7, IntPtr.Zero, 3, BACKUP | OPEN_REPARSE, IntPtr.Zero);
            if (h.IsInvalid) throw Last("open for security", p);
            using (h)
            {
                int need;
                GetKernelObjectSecurity(h, SI_OWNER_GROUP_DACL, null, 0, out need);
                byte[] b = new byte[need];
                if (!GetKernelObjectSecurity(h, SI_OWNER_GROUP_DACL, b, b.Length, out need)) throw Last("GetKernelObjectSecurity", p);
                return SdToString(b);
            }
        }

        // ------------------------------------------------------------------ registry (canonical HKLM\ / HKU\ paths, 64-bit view)
        static UIntPtr Root(string canon, out string sub)
        {
            int i = canon.IndexOf('\\');
            string hive = i < 0 ? canon : canon.Substring(0, i);
            sub = i < 0 ? "" : canon.Substring(i + 1);
            if (string.Equals(hive, "HKLM", StringComparison.OrdinalIgnoreCase)) return HKLM;
            if (string.Equals(hive, "HKU", StringComparison.OrdinalIgnoreCase)) return HKU;
            throw new ArgumentException("unsupported hive in '" + canon + "'");
        }
        static UIntPtr OpenLink(string canon, int sam, bool mustExist)
        {
            string sub; UIntPtr root = Root(canon, out sub); UIntPtr h;
            int rc = RegOpenKeyExW(root, sub, REG_OPTION_OPEN_LINK, sam | KEY_WOW64_64KEY, out h);
            if (rc == 2 && !mustExist) return UIntPtr.Zero;
            if (rc != 0) throw Err(rc, "RegOpenKeyEx", canon);
            return h;
        }
        public static bool KeyExists(string canon)
        {
            UIntPtr h = OpenLink(canon, KEY_QUERY_VALUE, false);
            if (h == UIntPtr.Zero) return false;
            RegCloseKey(h);
            return true;
        }
        public static void CreateKey(string canon, string cls)
        {
            string sub; UIntPtr root = Root(canon, out sub); UIntPtr h; int disp;
            int rc = RegCreateKeyExW(root, sub, 0, cls, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, IntPtr.Zero, out h, out disp);
            if (rc != 0) throw Err(rc, "RegCreateKeyEx", canon);
            RegCloseKey(h);
        }
        public static void SetValue(string canon, string name, int type, byte[] data)
        {
            if (data == null) data = new byte[0];
            UIntPtr h = OpenLink(canon, KEY_SET_VALUE, true);
            try
            {
                int rc = RegSetValueExW(h, name, 0, type, data, data.Length);
                if (rc != 0) throw Err(rc, "RegSetValueEx '" + name + "'", canon);
            }
            finally { RegCloseKey(h); }
        }
        static bool IsLinkH(UIntPtr h, out string target)
        {
            target = null; int type; int cb = 0;
            int rc = RegQueryValueExW(h, "SymbolicLinkValue", IntPtr.Zero, out type, null, ref cb);
            if (rc != 0 && rc != 234) return false;
            if (type != 6) return false;
            byte[] b = new byte[cb];
            if (RegQueryValueExW(h, "SymbolicLinkValue", IntPtr.Zero, out type, b, ref cb) != 0) return false;
            target = Encoding.Unicode.GetString(b, 0, cb);
            return true;
        }
        // The REG_LINK target (an NT path) of the key itself, or null when it is not a link or is missing.
        public static string LinkTarget(string canon)
        {
            UIntPtr h = OpenLink(canon, KEY_QUERY_VALUE, false);
            if (h == UIntPtr.Zero) return null;
            try { string t; return IsLinkH(h, out t) ? t : null; } finally { RegCloseKey(h); }
        }
        public static void CreateLink(string canon, string ntTarget)
        {
            string sub; UIntPtr root = Root(canon, out sub); UIntPtr h; int disp;
            int rc = RegCreateKeyExW(root, sub, 0, null, REG_OPTION_CREATE_LINK, KEY_WRITE | KEY_CREATE_LINK | DELETE | KEY_WOW64_64KEY, IntPtr.Zero, out h, out disp);
            if (rc != 0) throw Err(rc, "RegCreateKeyEx(CREATE_LINK)", canon);
            try
            {
                byte[] d = Encoding.Unicode.GetBytes(ntTarget);
                rc = RegSetValueExW(h, "SymbolicLinkValue", 0, 6, d, d.Length);
                if (rc != 0) { NtDeleteKey(h); throw Err(rc, "RegSetValueEx(SymbolicLinkValue)", canon); }
            }
            finally { RegCloseKey(h); }
        }
        public static RegValueRaw[] Values(string canon)
        {
            UIntPtr h = OpenLink(canon, KEY_READ, false);
            if (h == UIntPtr.Zero) return null;
            try
            {
                StringBuilder cls = new StringBuilder(1024); int cchCls = 1024;
                int nSub, maxSub, maxCls, nVal, maxName, maxVal, cbSd;
                int rc = RegQueryInfoKeyW(h, cls, ref cchCls, IntPtr.Zero, out nSub, out maxSub, out maxCls, out nVal, out maxName, out maxVal, out cbSd, IntPtr.Zero);
                if (rc != 0) throw Err(rc, "RegQueryInfoKey", canon);
                List<RegValueRaw> r = new List<RegValueRaw>();
                for (int i = 0; ; i++)
                {
                    StringBuilder name = new StringBuilder(maxName + 2); int cch = maxName + 2;
                    byte[] data = new byte[Math.Max(maxVal, 1)]; int cb = data.Length; int type;
                    rc = RegEnumValueW(h, i, name, ref cch, IntPtr.Zero, out type, data, ref cb);
                    if (rc == 259) break;
                    if (rc != 0) throw Err(rc, "RegEnumValue", canon);
                    RegValueRaw v = new RegValueRaw(); v.Name = name.ToString(0, cch); v.Type = type;
                    v.Data = new byte[cb]; Array.Copy(data, v.Data, cb); r.Add(v);
                }
                return r.ToArray();
            }
            finally { RegCloseKey(h); }
        }
        public static string KeyClass(string canon)
        {
            UIntPtr h = OpenLink(canon, KEY_READ, false);
            if (h == UIntPtr.Zero) return null;
            try
            {
                StringBuilder cls = new StringBuilder(1024); int cchCls = 1024;
                int nSub, maxSub, maxCls, nVal, maxName, maxVal, cbSd;
                int rc = RegQueryInfoKeyW(h, cls, ref cchCls, IntPtr.Zero, out nSub, out maxSub, out maxCls, out nVal, out maxName, out maxVal, out cbSd, IntPtr.Zero);
                if (rc != 0) throw Err(rc, "RegQueryInfoKey", canon);
                return cls.ToString(0, cchCls);
            }
            finally { RegCloseKey(h); }
        }
        static List<string> SubKeysH(UIntPtr h)
        {
            List<string> r = new List<string>();
            for (int i = 0; ; i++)
            {
                StringBuilder n = new StringBuilder(512); int cch = 512;
                int rc = RegEnumKeyExW(h, i, n, ref cch, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (rc == 259) break;
                if (rc != 0) throw new Win32Exception(rc);
                r.Add(n.ToString(0, cch));
            }
            return r;
        }
        static void DeleteTreeH(UIntPtr h, string where)
        {
            try
            {
                string t;
                if (!IsLinkH(h, out t))
                {
                    foreach (string n in SubKeysH(h))
                    {
                        UIntPtr c;
                        int rc = RegOpenKeyExW(h, n, REG_OPTION_OPEN_LINK, KEY_READ | DELETE | KEY_WOW64_64KEY, out c);
                        if (rc == 2) continue;
                        if (rc != 0) throw Err(rc, "RegOpenKeyEx", where + "\\" + n);
                        DeleteTreeH(c, where + "\\" + n);
                    }
                }
                int st = NtDeleteKey(h);
                if (st != 0) throw new Win32Exception("NtDeleteKey '" + where + "': NTSTATUS 0x" + st.ToString("X8"));
            }
            finally { RegCloseKey(h); }
        }
        // Deletes a key tree; a link anywhere in it is deleted as a link, never followed.
        public static bool DeleteTree(string canon)
        {
            UIntPtr h = OpenLink(canon, KEY_READ | DELETE, false);
            if (h == UIntPtr.Zero) return false;
            DeleteTreeH(h, canon);
            return true;
        }
        // Sets owner, group and DACL (needs SeRestorePrivilege and SeTakeOwnershipPrivilege enabled). First
        // through a backup/restore handle; if that handle lacks WRITE_OWNER/WRITE_DAC, in two steps: take
        // the owner (SeTakeOwnership grants WRITE_OWNER, SeRestore allows any owner SID), then the DACL.
        public static void SetKeySddl(string canon, string sddl)
        {
            string sub; UIntPtr root = Root(canon, out sub); UIntPtr h; int disp;
            IntPtr sd = Sd(sddl);
            try
            {
                int rc = RegCreateKeyExW(root, sub, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_WOW64_64KEY, IntPtr.Zero, out h, out disp);
                if (rc == 0)
                {
                    rc = RegSetKeySecurity(h, SI_OWNER_GROUP_DACL, sd);
                    RegCloseKey(h);
                    if (rc == 0) return;
                }
                rc = RegOpenKeyExW(root, sub, REG_OPTION_OPEN_LINK, WRITE_OWNER | READ_CONTROL | KEY_WOW64_64KEY, out h);
                if (rc != 0) throw Err(rc, "RegOpenKeyEx(WRITE_OWNER)", canon);
                rc = RegSetKeySecurity(h, 0x1, sd);
                RegCloseKey(h);
                if (rc != 0) throw Err(rc, "RegSetKeySecurity(owner)", canon);
                rc = RegOpenKeyExW(root, sub, REG_OPTION_OPEN_LINK, WRITE_DAC | READ_CONTROL | KEY_WOW64_64KEY, out h);
                if (rc != 0) throw Err(rc, "RegOpenKeyEx(WRITE_DAC)", canon);
                rc = RegSetKeySecurity(h, 0x6, sd);
                RegCloseKey(h);
                if (rc != 0) throw Err(rc, "RegSetKeySecurity(group, DACL)", canon);
            }
            finally { LocalFree(sd); }
        }
        public static string GetKeySddl(string canon)
        {
            UIntPtr h = OpenLink(canon, READ_CONTROL, false);
            if (h == UIntPtr.Zero) return null;
            try
            {
                int cb = 0;
                RegGetKeySecurity(h, SI_OWNER_GROUP_DACL, null, ref cb);
                byte[] b = new byte[cb];
                int rc = RegGetKeySecurity(h, SI_OWNER_GROUP_DACL, b, ref cb);
                if (rc != 0) throw Err(rc, "RegGetKeySecurity", canon);
                return SdToString(b);
            }
            finally { RegCloseKey(h); }
        }
    }
}
'@
}

# ---------------------------------------------------------------------------------------- pure helpers

if (-not (Get-Command Log -ErrorAction SilentlyContinue)) {
    $rl = Join-Path $PSScriptRoot 'riglib.ps1'
    if (Test-Path -LiteralPath $rl) { . $rl } else { function Log([string]$Message) { Write-Host ('[{0}] {1}' -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fff'), $Message) } }
    $ErrorActionPreference = 'Stop'   # riglib sets Continue for its own scripts
}
if (-not (Get-Variable -Name RigUserSid -ErrorAction SilentlyContinue)) { $RigUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }

function M2-Sha256([byte[]]$Bytes) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { -join ($h.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $h.Dispose() }
}
function M2-B64([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes) }
function BUtf8([string]$s) { , $M2Utf8.GetBytes($s) }
function BSz([string]$s) { , [Text.Encoding]::Unicode.GetBytes($s + [char]0) }
function BMulti([string[]]$a) { , [Text.Encoding]::Unicode.GetBytes(((@($a) | ForEach-Object { $_ + [char]0 }) -join '') + [char]0) }
function BDword([uint32]$n) { , [BitConverter]::GetBytes($n) }
function BQword([uint64]$n) { , [BitConverter]::GetBytes($n) }
function BHex([string]$hex) { , [byte[]]@(for ($i = 0; $i -lt $hex.Length; $i += 2) { [Convert]::ToByte($hex.Substring($i, 2), 16) }) }

# Deterministic canary content: its expected hash is known without building anything.
function Get-CanaryBytes([string]$Id) { BUtf8 "PURGE-CANARY $Id do-not-touch`n" }

# Hash of a set of raw registry values: lines "<name_b64>:<type>:<data_b64>" sorted ordinally, LF-joined.
function Get-RegValuesHash($Values) {
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($v in @($Values)) {
        if ($null -eq $v) { continue }
        $lines.Add(('{0}:{1}:{2}' -f (M2-B64 ([Text.Encoding]::Unicode.GetBytes([string]$v.name))), [int]$v.type, (M2-B64 ([byte[]]$v.data))))
    }
    $arr = $lines.ToArray()
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    M2-Sha256 ($M2Utf8.GetBytes(($arr -join "`n")))
}
function Get-RegValueHash([int]$Type, [byte[]]$Data) { M2-Sha256 ($M2Utf8.GetBytes(('{0}:{1}' -f $Type, (M2-B64 $Data)))) }

# Canonical key -> NT registry path for a REG_LINK target.
function ConvertTo-NtRegPath([string]$Canon) {
    if ($Canon -match '^(?i)HKLM\\(.+)$') { return '\REGISTRY\MACHINE\' + $Matches[1] }
    if ($Canon -match '^(?i)HKU\\(.+)$') { return '\REGISTRY\USER\' + $Matches[1] }
    throw "cannot map '$Canon' to an NT registry path"
}

# PowerShell single-quoted literal.
function Q([string]$s) { "'" + $s.Replace("'", "''") + "'" }

# Parent of a path or canonical key, by string (keeps trailing dots and spaces exactly).
function Get-M2Parent([string]$p) { $i = $p.LastIndexOf('\'); if ($i -le 2) { return $null }; $p.Substring(0, $i) }

# ------------------------------------------------------------------------------- table constructors

function TPath([string]$p) { [ordered]@{ type = 'Path'; path = $p } }
function TKey([string]$p) { [ordered]@{ type = 'RegKey'; path = $p } }
function TVal([string]$p, [string]$n) { [ordered]@{ type = 'RegValue'; path = $p; name = $n } }
function TSeg([string]$p, [string]$n, [string]$s, $Index = $null) {
    $t = [ordered]@{ type = 'RegMultiSzSegment'; path = $p; name = $n; segment = $s }
    if ($null -ne $Index) { $t.index = [int]$Index }
    $t
}
function EBlocked([string]$Blocker) { [ordered]@{ outcome = 'Skipped'; reason = 'GateBlocked'; blocker = $Blocker; summary = "blocked: $Blocker" } }
function ESkipped([string]$Reason) { [ordered]@{ outcome = 'Skipped'; reason = $Reason; blocker = $null; summary = "skipped: $Reason" } }
function EOutcome([string]$Outcome, [string]$Summary) { [ordered]@{ outcome = $Outcome; reason = $null; blocker = $null; summary = $Summary } }
function EDone([string]$Summary = 'done; undo restores it exactly') { EOutcome 'Done' $Summary }

# One plan item. $Group: 'main' (one exec), 'race-a' / 'race-b' (one exec each, with the trap's
# PURGE_FAULT_PAUSE), 'locked' (m2-reboot). $Accept: other outcomes that are not a failure as long as
# every canary stays intact.
function TItem([string]$Id, $Target, [string]$Action, $Expect, [string]$Group = 'main', $Accept = @(), $Condition = $null) {
    [ordered]@{ id = $Id; target = $Target; action = $Action; group = $Group; expect = $Expect; accept = @($Accept); condition = $Condition }
}

# Objects (built in order by Invoke-M2Object):
#   dir path | file path text|bytes | canary-file id path | junction path target | dirsym path target |
#   filesym path target | hardlink path existing | attrs path attrs[] optional | cloud-tag path |
#   file-sddl path sddl | stream path stream text | key path class | value path name type data |
#   canary-key id path values[] | canary-value id path name type data | reglink path target |
#   key-sddl path sddl | medium step | path-segment path name segment optional
function O([string]$Kind, [hashtable]$P) {
    $o = [ordered]@{ k = $Kind }
    foreach ($n in @('id', 'path', 'target', 'existing', 'text', 'bytes', 'attrs', 'optional', 'sddl', 'stream', 'class', 'name', 'type', 'data', 'values', 'step', 'segment')) {
        if ($P.ContainsKey($n)) { $o[$n] = $P[$n] }
    }
    $o
}
function V([string]$Name, [int]$Type, [byte[]]$Data) { [ordered]@{ name = $Name; type = $Type; data = $Data } }

# ------------------------------------------------------------------------------------- the trap table

function Get-M2TrapTable([string]$Sid, [string]$LocalAppData) {
    $R = $M2TrapRoot; $C = $M2CanaryRoot; $U = $M2UwRoot; $PD = $M2PdRoot
    $K = 'HKLM\SOFTWARE\PurgeTrapApp'; $KC = 'HKLM\SOFTWARE\PurgeCanary'
    $UK = "HKU\$Sid\Software\PurgeTrapApp"; $UKC = "HKU\$Sid\Software\PurgeCanary"
    $seg = 'segment-' + ('x' * 42)   # 50 characters
    $long = (1..5 | ForEach-Object { "$seg$_" }) -join '\'
    $canaryVals = { param($tag) @((V 'CanaryValue' $REG_SZ (BSz "PURGE-CANARY $tag")), (V 'CanaryDword' $REG_DWORD (BDword 0x5EC0DE)), (V 'CanaryBinary' $REG_BINARY (BHex 'DEADBEEF00FF'))) }
    $fp = [ordered]@{
        schema = 'purge.fp/0'; note = 'FORGED by the M2 rig (m2-traps forged-user-fp); the user-store format is provisional (ENGINE_PLAN 6.2)'
        app = 'PurgeTrapApp'; scope = 'machine'
        roots = @($R, "$C\fp\victim"); keys = @($K, "$KC\FpVictim"); exe_names = @('purgetrapapp.exe')
    }
    $fpJson = ConvertTo-Json -InputObject $fp -Depth 5

    $TrapList = New-Object System.Collections.ArrayList
    function Add-Trap([string]$Id, [string]$Gate, [string]$Summary, $Objects, $Items = @(), $FsRoots = @(), $RegRoots = @(), [hashtable]$More = @{}) {
        $t = [ordered]@{
            id = $Id; gate = $Gate; stage = 'post-install'; summary = $Summary
            objects = @($Objects); items = @($Items); fs_roots = @($FsRoots); reg_roots = @($RegRoots)
            fs_root_globs = @(); guarded_roots = @(); expect = $null; post_checks = @(); helper = $null; medium = $null
        }
        foreach ($n in $More.Keys) { $t[$n] = $More[$n] }
        [void]$TrapList.Add($t)
    }

    # --- G1: links as plan items, links inside a moved directory, a junction parent -------------------
    Add-Trap 'link-junction-item' 'G1' 'The plan item is a directory junction to a canary tree.' @(
        (O 'canary-file' @{ id = 'links-j.a'; path = "$C\links-j\target\a.txt" }),
        (O 'canary-file' @{ id = 'links-j.b'; path = "$C\links-j\target\sub\b.txt" }),
        (O 'dir' @{ path = "$R\links-j" }),
        (O 'junction' @{ path = "$R\links-j\j"; target = "$C\links-j\target" })
    ) @((TItem 'link-junction-item.link' (TPath "$R\links-j\j") 'Quarantine' (EBlocked 'ReparseMismatch'))) @("$R\links-j", "$C\links-j")

    Add-Trap 'link-dirsym-item' 'G1' 'The plan item is a directory symbolic link to a canary tree.' @(
        (O 'canary-file' @{ id = 'links-ds.a'; path = "$C\links-ds\target\a.txt" }),
        (O 'dir' @{ path = "$R\links-ds" }),
        (O 'dirsym' @{ path = "$R\links-ds\ds"; target = "$C\links-ds\target" })
    ) @((TItem 'link-dirsym-item.link' (TPath "$R\links-ds\ds") 'Quarantine' (EBlocked 'ReparseMismatch'))) @("$R\links-ds", "$C\links-ds")

    Add-Trap 'link-filesym-item' 'G1' 'The plan item is a file symbolic link to a canary file.' @(
        (O 'canary-file' @{ id = 'links-fs.target'; path = "$C\links-fs\target.txt" }),
        (O 'dir' @{ path = "$R\links-fs" }),
        (O 'filesym' @{ path = "$R\links-fs\fs.txt"; target = "$C\links-fs\target.txt" })
    ) @((TItem 'link-filesym-item.link' (TPath "$R\links-fs\fs.txt") 'Quarantine' (EBlocked 'ReparseMismatch'))) @("$R\links-fs", "$C\links-fs")

    Add-Trap 'links-inside-dir' 'G1' 'A directory moved whole holds a junction, a directory symlink and a file symlink to canaries.' @(
        (O 'canary-file' @{ id = 'links-in.j'; path = "$C\links-in\jtarget\a.txt" }),
        (O 'canary-file' @{ id = 'links-in.ds'; path = "$C\links-in\dstarget\a.txt" }),
        (O 'canary-file' @{ id = 'links-in.fs'; path = "$C\links-in\fstarget.txt" }),
        (O 'file' @{ path = "$R\links-in\payload.txt"; text = "payload`n" }),
        (O 'junction' @{ path = "$R\links-in\j"; target = "$C\links-in\jtarget" }),
        (O 'dirsym' @{ path = "$R\links-in\ds"; target = "$C\links-in\dstarget" }),
        (O 'filesym' @{ path = "$R\links-in\fs.txt"; target = "$C\links-in\fstarget.txt" })
    ) @((TItem 'links-inside-dir.dir' (TPath "$R\links-in") 'Quarantine' (EDone 'link removed, target intact: the links move with their directory as links; undo restores them as links') 'main' @((EBlocked 'ReparseMismatch')))) @("$R\links-in", "$C\links-in")

    Add-Trap 'junction-parent' 'G1' 'A junction inside the install dir is the PARENT of the plan item: the item path traverses it into the canary tree.' @(
        (O 'canary-file' @{ id = 'jparent.victim'; path = "$C\jparent\target\victim.txt" }),
        (O 'junction' @{ path = "$R\jparent"; target = "$C\jparent\target" })
    ) @(
        (TItem 'junction-parent.file' (TPath "$R\jparent\victim.txt") 'Quarantine' (EBlocked 'ReparseMismatch'))
    ) @("$R\jparent", "$C\jparent")

    # --- G6: hard links ------------------------------------------------------------------------------
    Add-Trap 'hardlink-out-file' 'G6' 'The plan item is a file whose other hard link lies outside the plan.' @(
        (O 'canary-file' @{ id = 'hardlink.shared'; path = "$C\hardlink\shared.dll" }),
        (O 'dir' @{ path = "$R\hl-file" }),
        (O 'hardlink' @{ path = "$R\hl-file\h.dll"; existing = "$C\hardlink\shared.dll" })
    ) @((TItem 'hardlink-out-file.file' (TPath "$R\hl-file\h.dll") 'Quarantine' (EBlocked 'HardLinkOutsidePlan'))) @("$R\hl-file", "$C\hardlink")

    Add-Trap 'hardlink-out-dir' 'G6' 'A directory moved whole holds a file whose other hard link lies outside the plan.' @(
        (O 'canary-file' @{ id = 'hardlink-dir.shared'; path = "$C\hardlink-dir\shared2.dll" }),
        (O 'file' @{ path = "$R\hl-dir\own.txt"; text = "own`n" }),
        (O 'hardlink' @{ path = "$R\hl-dir\h2.dll"; existing = "$C\hardlink-dir\shared2.dll" })
    ) @((TItem 'hardlink-out-dir.dir' (TPath "$R\hl-dir") 'Quarantine' (EBlocked 'HardLinkOutsidePlan'))) @("$R\hl-dir", "$C\hardlink-dir")

    # --- names and attributes (benign: must round-trip) --------------------------------------------------
    Add-Trap 'long-path-file' 'G1' 'A file whose full path is longer than 260 characters.' @(
        (O 'file' @{ path = "$R\long-file\$long\deep-file.txt"; text = "deep`n" })
    ) @((TItem 'long-path-file.file' (TPath "$R\long-file\$long\deep-file.txt") 'Quarantine' (EDone 'moved and restored at a path over 260 characters'))) @("$R\long-file")

    Add-Trap 'long-path-dir' 'G1' 'A directory whose own path is longer than 260 characters.' @(
        (O 'file' @{ path = "$R\long-dir\$long\deep.txt"; text = "deep`n" })
    ) @((TItem 'long-path-dir.dir' (TPath "$R\long-dir\$long") 'Quarantine' (EDone 'moved and restored at a path over 260 characters'))) @("$R\long-dir")

    Add-Trap 'odd-names' 'G1' 'Trailing-dot and trailing-space names next to the siblings a Win32-normalised name would hit.' @(
        (O 'canary-file' @{ id = 'odd.sibling-file'; path = "$R\odd\name" }),
        (O 'canary-file' @{ id = 'odd.sibling-dir'; path = "$R\odd\dir\inner.txt" }),
        (O 'file' @{ path = "$R\odd\name."; text = "trailing dot`n" }),
        (O 'file' @{ path = "$R\odd\name "; text = "trailing space`n" }),
        (O 'file' @{ path = "$R\odd\dir.\inner.txt"; text = "inside a trailing-dot dir`n" })
    ) @(
        (TItem 'odd-names.dot' (TPath "$R\odd\name.") 'Quarantine' (EDone "moved and restored under its exact name; sibling 'name' intact")),
        (TItem 'odd-names.space' (TPath "$R\odd\name ") 'Quarantine' (EDone "moved and restored under its exact name; sibling 'name' intact")),
        (TItem 'odd-names.dotdir' (TPath "$R\odd\dir.") 'Quarantine' (EDone "moved and restored under its exact name; sibling 'dir' intact"))
    ) @("$R\odd")

    Add-Trap 'attributes' 'G1' 'Read-only, hidden and system files and directories.' @(
        (O 'file' @{ path = "$R\attrs\ro.txt"; text = "ro`n" }),
        (O 'file' @{ path = "$R\attrs\hidden.txt"; text = "hidden`n" }),
        (O 'file' @{ path = "$R\attrs\system.txt"; text = "system`n" }),
        (O 'file' @{ path = "$R\attrs\rhs.txt"; text = "rhs`n" }),
        (O 'file' @{ path = "$R\attrs\rodir\inner.txt"; text = "inner`n" }),
        (O 'file' @{ path = "$R\attrs\hsdir\inner.txt"; text = "inner`n" }),
        (O 'attrs' @{ path = "$R\attrs\ro.txt"; attrs = @('ReadOnly') }),
        (O 'attrs' @{ path = "$R\attrs\hidden.txt"; attrs = @('Hidden') }),
        (O 'attrs' @{ path = "$R\attrs\system.txt"; attrs = @('System') }),
        (O 'attrs' @{ path = "$R\attrs\rhs.txt"; attrs = @('ReadOnly', 'Hidden', 'System') }),
        (O 'attrs' @{ path = "$R\attrs\rodir"; attrs = @('ReadOnly') }),
        (O 'attrs' @{ path = "$R\attrs\hsdir"; attrs = @('Hidden', 'System') }),
        (O 'file' @{ path = "$R\attrs-one\rhs.txt"; text = "rhs alone`n" }),
        (O 'attrs' @{ path = "$R\attrs-one\rhs.txt"; attrs = @('ReadOnly', 'Hidden', 'System') })
    ) @(
        (TItem 'attributes.dir' (TPath "$R\attrs") 'Quarantine' (EDone 'moved; undo restores every attribute exactly')),
        (TItem 'attributes.file' (TPath "$R\attrs-one\rhs.txt") 'Quarantine' (EDone 'moved; undo restores read-only + hidden + system'))
    ) @("$R\attrs", "$R\attrs-one")

    # --- G11: registry links -------------------------------------------------------------------------
    Add-Trap 'reglink-leaf' 'G11' 'The plan key is a REG_LINK to a canary key.' @(
        (O 'canary-key' @{ id = 'reglink.leaf'; path = "$KC\LeafTarget"; values = (& $canaryVals 'leaf') }),
        (O 'key' @{ path = $K }),
        (O 'reglink' @{ path = "$K\LinkLeaf"; target = "$KC\LeafTarget" })
    ) @(
        (TItem 'reglink-leaf.key' (TKey "$K\LinkLeaf") 'DeleteKey' (EBlocked 'RegLink')),
        (TItem 'reglink-leaf.value' (TVal "$K\LinkLeaf" 'CanaryValue') 'DeleteValue' (EBlocked 'RegLink'))
    ) @() @("$K\LinkLeaf", "$KC\LeafTarget")

    Add-Trap 'reglink-mid' 'G11' 'A REG_LINK in the middle of the plan key path leads into a canary tree.' @(
        (O 'canary-key' @{ id = 'reglink.mid'; path = "$KC\MidTarget"; values = (& $canaryVals 'mid') }),
        (O 'canary-key' @{ id = 'reglink.mid-child'; path = "$KC\MidTarget\Child"; values = @((V 'ChildValue' $REG_SZ (BSz 'PURGE-CANARY mid-child'))) }),
        (O 'key' @{ path = $K }),
        (O 'reglink' @{ path = "$K\LinkMid"; target = "$KC\MidTarget" })
    ) @(
        (TItem 'reglink-mid.key' (TKey "$K\LinkMid\Child") 'DeleteKey' (EBlocked 'RegLink')),
        (TItem 'reglink-mid.value' (TVal "$K\LinkMid\Child" 'ChildValue') 'DeleteValue' (EBlocked 'RegLink'))
    ) @() @("$K\LinkMid", "$KC\MidTarget")

    Add-Trap 'reglink-inside-tree' 'G11' 'A plain plan key holds a REG_LINK subkey to a canary key.' @(
        (O 'canary-key' @{ id = 'reglink.inside'; path = "$KC\InsideTarget"; values = (& $canaryVals 'inside') }),
        (O 'key' @{ path = "$K\LinkHolder" }),
        (O 'value' @{ path = "$K\LinkHolder"; name = 'own'; type = $REG_SZ; data = (BSz 'own') }),
        (O 'reglink' @{ path = "$K\LinkHolder\inner"; target = "$KC\InsideTarget" })
    ) @(
        (TItem 'reglink-inside-tree.key' (TKey "$K\LinkHolder") 'DeleteKey' (EBlocked 'RegLink') 'main' @((EDone 'link removed, target intact: the link key is deleted as a link and undo recreates it')))
    ) @() @("$K\LinkHolder", "$KC\InsideTarget")

    Add-Trap 'reglink-user' 'G11' 'A REG_LINK in the user hive to a canary key of the same hive.' @(
        (O 'canary-key' @{ id = 'reglink.user'; path = "$UKC\UserTarget"; values = (& $canaryVals 'user') }),
        (O 'key' @{ path = $UK }),
        (O 'reglink' @{ path = "$UK\LinkUser"; target = "$UKC\UserTarget"; optional = $true })
    ) @((TItem 'reglink-user.key' (TKey "$UK\LinkUser") 'DeleteKey' (EBlocked 'RegLink'))) @() @("$UK\LinkUser", "$UKC\UserTarget")

    # --- G3: TrustedInstaller ------------------------------------------------------------------------
    Add-Trap 'ti-dir' 'G3' 'A folder (and its file) owned by TrustedInstaller.' @(
        (O 'canary-file' @{ id = 'ti.dir-payload'; path = "$R\ti-dir\payload.dll" }),
        (O 'file-sddl' @{ path = "$R\ti-dir\payload.dll"; sddl = $M2SddlTiFile }),
        (O 'file-sddl' @{ path = "$R\ti-dir"; sddl = $M2SddlTiDir })
    ) @((TItem 'ti-dir.dir' (TPath "$R\ti-dir") 'Quarantine' (EBlocked 'TrustedInstallerOwned'))) @("$R\ti-dir")

    Add-Trap 'ti-file' 'G3' 'A file owned by TrustedInstaller in an ordinary folder.' @(
        (O 'canary-file' @{ id = 'ti.file'; path = "$R\ti-file\payload.dll" }),
        (O 'file-sddl' @{ path = "$R\ti-file\payload.dll"; sddl = $M2SddlTiFile })
    ) @((TItem 'ti-file.file' (TPath "$R\ti-file\payload.dll") 'Quarantine' (EBlocked 'TrustedInstallerOwned'))) @("$R\ti-file")

    Add-Trap 'ti-key' 'G3' 'A key owned by TrustedInstaller (administrators: read only).' @(
        (O 'canary-key' @{ id = 'ti.key'; path = "$K\TiOwned"; values = (& $canaryVals 'ti-key') }),
        (O 'key-sddl' @{ path = "$K\TiOwned"; sddl = $M2SddlTiKey })
    ) @(
        (TItem 'ti-key.key' (TKey "$K\TiOwned") 'DeleteKey' (EBlocked 'TrustedInstallerOwned')),
        (TItem 'ti-key.value' (TVal "$K\TiOwned" 'CanaryValue') 'DeleteValue' (EBlocked 'TrustedInstallerOwned'))
    ) @() @("$K\TiOwned")

    Add-Trap 'ti-ace-key' 'G3' 'A key owned by administrators that carries a TrustedInstaller ACE.' @(
        (O 'canary-key' @{ id = 'ti.ace-key'; path = "$K\TiAce"; values = (& $canaryVals 'ti-ace') }),
        (O 'key-sddl' @{ path = "$K\TiAce"; sddl = $M2SddlTiAceKey })
    ) @((TItem 'ti-ace-key.key' (TKey "$K\TiAce") 'DeleteKey' (EBlocked 'TrustedInstallerOwned'))) @() @("$K\TiAce")

    # --- G7: attribute-faked placeholders --------------------------------------------------------------
    Add-Trap 'placeholder-attrs' 'G7' 'Files carrying placeholder attributes (OFFLINE, RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS) and a cloud reparse tag, where Windows lets them be set; an item whose bits did not stick is not scored (see build.objects).' @(
        (O 'canary-file' @{ id = 'ph.offline'; path = "$R\ph\offline.txt" }),
        (O 'canary-file' @{ id = 'ph.recall-open'; path = "$R\ph\recall-open.txt" }),
        (O 'canary-file' @{ id = 'ph.recall-data'; path = "$R\ph\recall-data.txt" }),
        (O 'file' @{ path = "$R\ph\cloud-tag.txt"; text = "cloud placeholder`n" }),
        (O 'attrs' @{ path = "$R\ph\offline.txt"; attrs = @('Offline'); optional = $true }),
        (O 'attrs' @{ path = "$R\ph\recall-open.txt"; attrs = @('RecallOnOpen'); optional = $true }),
        (O 'attrs' @{ path = "$R\ph\recall-data.txt"; attrs = @('RecallOnDataAccess'); optional = $true }),
        (O 'cloud-tag' @{ path = "$R\ph\cloud-tag.txt"; optional = $true })
    ) @(
        (TItem 'placeholder-attrs.offline' (TPath "$R\ph\offline.txt") 'Quarantine' (EBlocked 'SyncRoot') 'main' @() 'scored only when build.objects shows the attribute set'),
        (TItem 'placeholder-attrs.recall-open' (TPath "$R\ph\recall-open.txt") 'Quarantine' (EBlocked 'SyncRoot') 'main' @() 'scored only when build.objects shows the attribute set'),
        (TItem 'placeholder-attrs.recall-data' (TPath "$R\ph\recall-data.txt") 'Quarantine' (EBlocked 'SyncRoot') 'main' @() 'scored only when build.objects shows the attribute set'),
        (TItem 'placeholder-attrs.cloud-tag' (TPath "$R\ph\cloud-tag.txt") 'Quarantine' (EBlocked 'SyncRoot') 'main' @() 'scored only when build.objects shows the reparse tag set')
    ) @("$R\ph") @() @{
        # Not a canary: a reparse point cannot be hashed like a file. Presence is checked instead.
        post_checks = @([ordered]@{ kind = 'present'; path = "$R\ph\cloud-tag.txt" })
    }

    Add-Trap 'placeholder-dir' 'G7' 'A directory moved whole holds an OFFLINE placeholder.' @(
        (O 'file' @{ path = "$R\ph-dir\own.txt"; text = "own`n" }),
        (O 'canary-file' @{ id = 'ph-dir.offline'; path = "$R\ph-dir\offline.txt" }),
        (O 'attrs' @{ path = "$R\ph-dir\offline.txt"; attrs = @('Offline'); optional = $true })
    ) @((TItem 'placeholder-dir.dir' (TPath "$R\ph-dir") 'Quarantine' (EBlocked 'SyncRoot') 'main' @() 'scored only when build.objects shows the attribute set')) @("$R\ph-dir")

    # --- Purge's own storage -------------------------------------------------------------------------
    $preBody = @(
        "Op 'mkdir Purge' { New-Item -ItemType Directory -Path $(Q $PD) -ErrorAction Stop }",
        "Op 'mkdir sessions' { New-Item -ItemType Directory -Path $(Q "$PD\sessions") -ErrorAction Stop }",
        "Op 'mkdir Quarantine' { New-Item -ItemType Directory -Path $(Q "$PD\Quarantine") -ErrorAction Stop }",
        "Op 'marker' { Set-Content -LiteralPath $(Q "$PD\purge-trap-precreated.txt") -Value 'created by a standard user (m2-traps pd-precreated)' -ErrorAction Stop }",
        "Op 'junction Quarantine\planted' { MkJunction $(Q "$PD\Quarantine\planted") $(Q "$C\pd\quarantine-target") }",
        "Op 'junction sessions\planted' { MkJunction $(Q "$PD\sessions\planted") $(Q "$C\pd\sessions-target") }"
    ) -join "`r`n"
    Add-Trap 'pd-precreated' 'storage' 'Before install: a standard user (medium IL) creates C:\ProgramData\Purge with planted junctions in Quarantine and sessions.' @(
        (O 'canary-file' @{ id = 'pd.quarantine-target'; path = "$C\pd\quarantine-target\keep.txt" }),
        (O 'canary-file' @{ id = 'pd.sessions-target'; path = "$C\pd\sessions-target\keep.txt" }),
        (O 'medium' @{ step = 'pd-precreate' })
    ) @() @("$C\pd") @() @{
        stage = 'pre-install'
        guarded_roots = @([ordered]@{ path = $PD; marker = 'purge-trap-precreated.txt' })
        fs_root_globs = @([ordered]@{ parent = 'C:\ProgramData'; like = 'Purge.rejected-*'; marker = 'purge-trap-precreated.txt' })
        medium = [ordered]@{ 'pd-precreate' = [ordered]@{ body = $preBody; expect_ok = [ordered]@{ 'mkdir Purge' = $true; 'mkdir sessions' = $true; 'mkdir Quarantine' = $true; 'marker' = $true; 'junction Quarantine\planted' = $true; 'junction sessions\planted' = $true } } }
        expect = [ordered]@{ phase = 'install'; outcome = 'RenamedAside'; summary = 'install.ps1 never adopts the user-created tree: it renames it to Purge.rejected-<utc> without following the planted junctions and creates a fresh protected tree; canaries intact' }
        post_checks = @(
            [ordered]@{ kind = 'exists'; path = 'C:\ProgramData\Purge.rejected-*\purge-trap-precreated.txt' },
            [ordered]@{ kind = 'not-reparse'; path = $PD },
            [ordered]@{ kind = 'absent'; path = "$PD\purge-trap-precreated.txt" },
            [ordered]@{ kind = 'absent'; path = "$PD\Quarantine\planted" },
            [ordered]@{ kind = 'absent'; path = "$PD\sessions\planted" }
        )
    }

    $plantBody = @(
        "Op 'create Quarantine\user-file.txt' { Set-Content -LiteralPath $(Q "$PD\Quarantine\user-file.txt") -Value x -ErrorAction Stop }",
        "Op 'junction Quarantine\planted-post' { MkJunction $(Q "$PD\Quarantine\planted-post") $(Q "$C\pd-post\target") }",
        "Op 'create sessions\user-file.txt' { Set-Content -LiteralPath $(Q "$PD\sessions\user-file.txt") -Value x -ErrorAction Stop }",
        "Op 'junction sessions\planted-post' { MkJunction $(Q "$PD\sessions\planted-post") $(Q "$C\pd-post\target") }",
        "Op 'create Purge\user-file.txt' { Set-Content -LiteralPath $(Q "$PD\user-file.txt") -Value x -ErrorAction Stop }",
        "Op 'list Quarantine' { Get-ChildItem -LiteralPath $(Q "$PD\Quarantine") -Force -ErrorAction Stop }",
        "Op 'read sessions\index.json' { Get-Content -LiteralPath $(Q "$PD\sessions\index.json") -ErrorAction Stop }"
    ) -join "`r`n"
    Add-Trap 'pd-plant-denied' 'storage' 'After install: a standard user (medium IL) tries to plant files and junctions in Quarantine and sessions; only sessions\index.json is readable.' @(
        (O 'canary-file' @{ id = 'pd-post.target'; path = "$C\pd-post\target\keep.txt" }),
        (O 'medium' @{ step = 'pd-plant' })
    ) @() @("$C\pd-post") @() @{
        medium = [ordered]@{ 'pd-plant' = [ordered]@{ body = $plantBody; requires = $PD; expect_ok = [ordered]@{
            'create Quarantine\user-file.txt' = $false; 'junction Quarantine\planted-post' = $false; 'create sessions\user-file.txt' = $false
            'junction sessions\planted-post' = $false; 'create Purge\user-file.txt' = $false; 'list Quarantine' = $false; 'read sessions\index.json' = $true } } }
        expect = [ordered]@{ phase = 'build'; outcome = 'Denied'; summary = 'every create/plant/list attempt is denied by the installer-created DACL; reading sessions\index.json is allowed (see build.medium)' }
        post_checks = @(
            [ordered]@{ kind = 'absent'; path = "$PD\Quarantine\user-file.txt" }, [ordered]@{ kind = 'absent'; path = "$PD\Quarantine\planted-post" },
            [ordered]@{ kind = 'absent'; path = "$PD\sessions\user-file.txt" }, [ordered]@{ kind = 'absent'; path = "$PD\sessions\planted-post" },
            [ordered]@{ kind = 'absent'; path = "$PD\user-file.txt" }
        )
    }

    # --- boot-time moves (m2-reboot locks these) -----------------------------------------------------
    Add-Trap 'boot-admin-locked' 'boot-move' 'A file in an admin-only directory, locked by the m2-reboot locker.' @(
        (O 'file' @{ path = "$R\locked\admin-locked.dll"; text = "admin-only ancestors`n" })
    ) @((TItem 'boot-admin-locked.file' (TPath "$R\locked\admin-locked.dll") 'Quarantine' (EOutcome 'PendingReboot' 'every ancestor is admin-only writable: a boot-time move into quarantine is registered (ENGINE_PLAN 7.6 step 4); reconcile after reboot finds the recorded FileId') 'locked' @((EDone 'not locked')) 'held open without FILE_SHARE_DELETE by the m2-reboot locker')) @("$R\locked")

    $bootPlant = @(
        "Op 'rename boot aside' { Rename-Item -LiteralPath $(Q "$U\boot") -NewName ('boot.planted-orig-' + (Get-Date -Format yyyyMMddHHmmss)) -ErrorAction Stop }",
        "Op 'junction boot -> canary' { MkJunction $(Q "$U\boot") $(Q "$C\boot\target") }"
    ) -join "`r`n"
    Add-Trap 'boot-uw-planted' 'boot-move' 'A locked file under a user-writable ancestor; later a standard user replaces that ancestor with a junction to a canary holding a file of the same name.' @(
        (O 'canary-file' @{ id = 'boot.target'; path = "$C\boot\target\user-locked.dll" }),
        (O 'dir' @{ path = $U }),
        (O 'file-sddl' @{ path = $U; sddl = $M2SddlUwDir }),
        (O 'file' @{ path = "$U\boot\user-locked.dll"; text = "user-writable ancestor`n" })
    ) @((TItem 'boot-uw-planted.file' (TPath "$U\boot\user-locked.dll") 'Quarantine' (EOutcome 'HeldRetry' 'an ancestor is user-writable: no boot-time move; held as retry at the next run') 'locked' @((EDone 'not locked')) 'held open without FILE_SHARE_DELETE by the m2-reboot locker')) @("$U\boot", "$C\boot") @() @{
        fs_root_globs = @([ordered]@{ parent = $U; like = 'boot.planted-orig-*'; marker = $null })
        medium = [ordered]@{ 'boot-plant' = [ordered]@{ body = $bootPlant; expect_ok = [ordered]@{ 'rename boot aside' = $true; 'junction boot -> canary' = $true } } }
        helper = [ordered]@{
            action = 'plant-boot-junction'; when = 'after the locker released the file (after the reboot), before the retry run'
            expect_after = (EBlocked 'ReparseMismatch'); summary = 'the retry re-validates through the handle (G1) and refuses: the canary of the same name stays intact'
        }
    }

    # --- swap-after-validate races -------------------------------------------------------------------
    foreach ($r in @(
            @{ id = 'race-validate-open'; dir = 'race-a'; group = 'race-a'; pause = 'intent.flushed:8000'; expect = (EBlocked 'ReparseMismatch'); accept = @((ESkipped 'ChangedSinceScan'), (EDone 'the original directory object moved through the handle; the junction and its target untouched')) },
            @{ id = 'race-open-act'; dir = 'race-b'; group = 'race-b'; pause = 'act.before:8000'; expect = (EDone 'the handle opened before the swap moves the original directory object; the planted junction and its target are untouched'); accept = @((EBlocked 'ReparseMismatch'), (ESkipped 'ChangedSinceScan')) })) {
        Add-Trap $r.id 'G1' "A validated directory is replaced by a junction to a canary while the engine is paused at $($r.pause) (PURGE_FAULT_PAUSE; separate exec, group $($r.group))." @(
            (O 'canary-file' @{ id = "$($r.dir).own1"; path = "$C\$($r.dir)\target\own1.txt" }),
            (O 'dir' @{ path = $U }),
            (O 'file-sddl' @{ path = $U; sddl = $M2SddlUwDir }),
            (O 'file' @{ path = "$U\$($r.dir)\payload\own1.txt"; text = "payload`n" })
        ) @((TItem "$($r.id).dir" (TPath "$U\$($r.dir)\payload") 'Quarantine' $r.expect $r.group $r.accept)) @("$U\$($r.dir)", "$C\$($r.dir)") @() @{
            helper = [ordered]@{
                action = 'swap'; fault_pause = $r.pause; env = [ordered]@{ PURGE_FAULT_PAUSE = $r.pause }
                dir = "$U\$($r.dir)\payload"; link_to = "$C\$($r.dir)\target"
                trigger = 'a line of the newest sessions\*\journal.jsonl that names the item path and contains "intent"'
                when = 'start before exec of this group'
            }
        }
    }

    # --- expiry walk ---------------------------------------------------------------------------------
    Add-Trap 'expiry-junction' 'expiry' 'After exec, a junction and a file symlink to canaries are planted inside the quarantined item; the expiry walk must delete the links and never descend.' @(
        (O 'canary-file' @{ id = 'expiry.target'; path = "$C\expiry\target\keep.txt" }),
        (O 'canary-file' @{ id = 'expiry.target-file'; path = "$C\expiry\target-file.txt" }),
        (O 'file' @{ path = "$R\expiry\payload\expiry-marker.txt"; text = "PURGE-EXPIRY-MARKER m2-traps`n" }),
        (O 'file' @{ path = "$R\expiry\payload\own.txt"; text = "own`n" })
    ) @((TItem 'expiry-junction.dir' (TPath "$R\expiry\payload") 'Quarantine' (EDone 'quarantined; later purged by the expiry walk'))) @("$R\expiry", "$C\expiry") @() @{
        helper = [ordered]@{
            action = 'plant-expiry-junction'; when = 'after the main exec committed, before `purge-engine quarantine purge --ids <op> --yes-irreversible`'
            marker = 'expiry-marker.txt'; plants = @([ordered]@{ name = 'escape-dir'; kind = 'junction'; target = "$C\expiry\target" }, [ordered]@{ name = 'escape-file.txt'; kind = 'filesym'; target = "$C\expiry\target-file.txt" })
            expect_after = (EDone 'link removed, target intact: the walk deletes both links without descending')
        }
    }

    # --- forged user-store fingerprint (scan time, Rule T) -------------------------------------------
    $fpPath = "$LocalAppData\Purge\fp\PurgeTrapApp.json"
    $fpBody = @(
        "Op 'mkdir fp' { New-Item -ItemType Directory -Force -Path $(Q "$LocalAppData\Purge\fp") -ErrorAction Stop }",
        "Op 'write forged fingerprint' { [IO.File]::WriteAllText($(Q $fpPath), [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($(Q (M2-B64 ($M2Utf8.GetBytes($fpJson))))))) }"
    ) -join "`r`n"
    Add-Trap 'forged-user-fp' 'RuleT' 'A standard user writes a user-store fingerprint claiming machine-scope paths and a canary (ENGINE_PLAN 6.2).' @(
        (O 'canary-file' @{ id = 'fp.victim'; path = "$C\fp\victim\data.txt" }),
        (O 'canary-key' @{ id = 'fp.victim-key'; path = "$KC\FpVictim"; values = (& $canaryVals 'fp') }),
        (O 'medium' @{ step = 'fp-forge' })
    ) @() @("$C\fp", $fpPath) @("$KC\FpVictim") @{
        medium = [ordered]@{ 'fp-forge' = [ordered]@{ body = $fpBody; expect_ok = [ordered]@{ 'mkdir fp' = $true; 'write forged fingerprint' = $true } } }
        expect = [ordered]@{ phase = 'scan'; outcome = 'NotPreselected'; paths = @("$C\fp\victim", "$KC\FpVictim"); summary = 'user-store evidence is Tier B for machine-scope targets (Rule T): the canary paths are never Safe or preselected; no plan item is emitted for them' }
    }

    , $TrapList
}

# ------------------------------------------------------------------------------- build interpreter

function Get-M2Placeholder {
    [ordered]@{ '{user-sid}' = 'SID of the rig user: HKU\<sid>'; '{localappdata}' = '%LOCALAPPDATA% of the rig user' }
}

# A JSON-ready copy of an object definition (bytes as base64).
function ConvertTo-M2ObjectDoc($o) {
    $d = [ordered]@{}
    foreach ($k in $o.Keys) {
        $v = $o[$k]
        if ($k -eq 'bytes' -or $k -eq 'data') { $d["${k}_b64"] = M2-B64 ([byte[]]$v); continue }
        if ($k -eq 'values') { $d.values = @(foreach ($x in $v) { [ordered]@{ name = $x.name; type = $x.type; data_b64 = (M2-B64 ([byte[]]$x.data)) } }); continue }
        $d[$k] = $v
    }
    $d
}

function Get-M2Canaries($Table) {
    foreach ($t in $Table) {
        foreach ($o in $t.objects) {
            if ($o.k -eq 'canary-file') {
                [ordered]@{ id = $o.id; trap = $t.id; kind = 'file'; path = $o.path; sha256 = (M2-Sha256 (Get-CanaryBytes $o.id)) }
            } elseif ($o.k -eq 'canary-key') {
                [ordered]@{ id = $o.id; trap = $t.id; kind = 'regkey'; path = $o.path; sha256 = (Get-RegValuesHash $o.values) }
            } elseif ($o.k -eq 'canary-value') {
                [ordered]@{ id = $o.id; trap = $t.id; kind = 'regvalue'; path = $o.path; name = $o.name; sha256 = (Get-RegValueHash $o.type $o.data) }
            }
        }
    }
}

function Measure-M2Canary($c) {
    $m = [ordered]@{ id = $c.id; present = $false; sha256 = $null; reparse = $false; file_id = $null; volume_serial = $null; links = $null; error = $null }
    try {
        if ($c.kind -eq 'file') {
            $f = [PurgeRigM2.Native]::Facts($c.path)
            if ($f) {
                $m.present = $true; $m.file_id = $f.FileId; $m.volume_serial = $f.VolumeSerial; $m.links = $f.Links
                $m.reparse = ($f.Attributes -band 0x400) -ne 0
                if (-not $m.reparse -and -not $f.IsDir) { $m.sha256 = M2-Sha256 ([PurgeRigM2.Native]::ReadAll($c.path)) }
            }
        } elseif ($c.kind -eq 'regkey') {
            $vals = [PurgeRigM2.Native]::Values($c.path)
            if ($null -ne $vals) {
                $m.present = $true
                $m.reparse = $null -ne [PurgeRigM2.Native]::LinkTarget($c.path)
                $m.sha256 = Get-RegValuesHash @($vals | ForEach-Object { [ordered]@{ name = $_.Name; type = $_.Type; data = $_.Data } })
            }
        } elseif ($c.kind -eq 'regvalue') {
            $vals = [PurgeRigM2.Native]::Values($c.path)
            $v = @($vals | Where-Object { $_.Name -ceq $c.name }) | Select-Object -First 1
            if ($v) { $m.present = $true; $m.sha256 = Get-RegValueHash $v.Type $v.Data }
        }
    } catch { $m.error = $_.Exception.Message }
    $m
}

# Runs a medium-IL step through riglib's LaunchMedium and returns its JSON result.
function Invoke-M2Medium([string]$Name, [string]$Body, [int]$WaitSec = 120) {
    if (-not (Get-Command LaunchMedium -ErrorAction SilentlyContinue)) { throw 'LaunchMedium is not loaded (riglib.ps1 missing next to this script)' }
    New-Item -ItemType Directory -Force $M2Jobs | Out-Null
    $ps1 = Join-Path $M2Jobs "$Name.ps1"; $res = Join-Path $M2Jobs "$Name.json"
    Remove-Item -LiteralPath $res -Force -ErrorAction SilentlyContinue
    $script = @(
        'param([string]$Result)',
        '$ErrorActionPreference = ''Continue''',
        ('$out = [ordered]@{ step = ' + (Q $Name) + '; il = $null; ops = New-Object System.Collections.ArrayList; error = $null }'),
        'try { $out.il = ((whoami.exe /groups) | Select-String -Pattern ''S-1-16-\d+'' | ForEach-Object { $_.Matches[0].Value } | Select-Object -First 1) } catch { }',
        'function Op([string]$Name, [scriptblock]$Body) { try { & $Body | Out-Null; [void]$out.ops.Add([ordered]@{ op = $Name; ok = $true; error = $null }) } catch { [void]$out.ops.Add([ordered]@{ op = $Name; ok = $false; error = $_.Exception.Message }) } }',
        'function MkJunction([string]$Link, [string]$Target) { $o = & cmd.exe /c mklink /J "$Link" "$Target" 2>&1; if ($LASTEXITCODE -ne 0) { throw "mklink /J exit ${LASTEXITCODE}: $o" } }',
        'try {',
        $Body,
        '} catch { $out.error = $_.Exception.Message }',
        '[IO.File]::WriteAllText($Result, (ConvertTo-Json -InputObject $out -Depth 5), (New-Object System.Text.UTF8Encoding($false)))'
    ) -join "`r`n"
    [IO.File]::WriteAllText($ps1, $script, $M2Utf8)
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $task = 'PurgeRigM2Medium'
    $ErrorActionPreference = 'Continue'   # riglib's helpers are written for Continue (this scope only)
    try {
        $l = LaunchMedium -Exe $exe -Arguments ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Result "{1}"' -f $ps1, $res) -TaskName $task -StartTimeoutSec 60
        $deadline = (Get-Date).AddSeconds($WaitSec)
        while (-not (Test-Path -LiteralPath $res) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
        Start-Sleep -Milliseconds 300
        if (-not (Test-Path -LiteralPath $res)) {
            if ($l.pid) { Stop-Process -Id $l.pid -Force -ErrorAction SilentlyContinue }
            throw "medium step $Name wrote no result within $WaitSec s"
        }
        $r = Get-Content -Raw -LiteralPath $res | ConvertFrom-Json
        if ($r.il -ne 'S-1-16-8192') { Log "  !! medium step $Name ran at integrity $($r.il), not medium (S-1-16-8192)" }
        $r
    } finally {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# Builds one object; returns its status record. Throws on a failure of a non-optional object.
function Invoke-M2Object($o, $Trap) {
    $st = [ordered]@{ k = $o.k; path = $(if ($o.Contains('path')) { $o.path } else { $null }); ok = $true; detail = $null }
    $N = [PurgeRigM2.Native]
    $parent = { param($p) $d = Get-M2Parent $p; if ($d) { $N::MkDirs($d) } }
    try {
        switch ($o.k) {
            'dir'         { $N::MkDirs($o.path) }
            'file'        { & $parent $o.path; $b = $(if ($o.Contains('bytes')) { [byte[]]$o.bytes } else { $M2Utf8.GetBytes([string]$o.text) }); $N::WriteAll($o.path, $b) }
            'canary-file' { & $parent $o.path; $N::WriteAll($o.path, (Get-CanaryBytes $o.id)) }
            'stream'      { $N::WriteAll(($o.path + ':' + $o.stream), $M2Utf8.GetBytes([string]$o.text)) }
            'junction'    { & $parent $o.path; $N::Junction($o.path, $o.target) }
            'dirsym'      { & $parent $o.path; $N::Symlink($o.path, $o.target, $true) }
            'filesym'     { & $parent $o.path; $N::Symlink($o.path, $o.target, $false) }
            'hardlink'    { & $parent $o.path; $N::HardLink($o.path, $o.existing) }
            'attrs' {
                $a = 0; foreach ($n in $o.attrs) { $a = $a -bor $M2Attr[$n] }
                # Keep what is there, minus DIRECTORY (0x10) and NORMAL (0x80), which SetFileAttributes rejects in a combination.
                $cur = [int64]$N::Attributes($o.path)
                $want = ($cur -band [int64]0xFFFFFF6F) -bor $a
                if ($o.Contains('optional') -and $o.optional) {
                    $st.detail = $N::ForceAttributes($o.path, [uint32]$want)
                    $st.ok = $st.detail -like 'set:*'
                } else { $N::SetAttributes($o.path, [uint32]$want); $st.detail = ('0x{0:X8}' -f $N::Attributes($o.path)) }
            }
            'cloud-tag' {
                $e = $N::SetCloudTag($o.path)
                $st.ok = $e -eq 0
                $st.detail = $(if ($e -eq 0) { 'set:IO_REPARSE_TAG_CLOUD_1' } else { "not-set:win32 error $e" })
            }
            'file-sddl'   { $N::SetFileSddl($o.path, $o.sddl); $st.detail = $N::GetFileSddl($o.path) }
            'key'         { $N::CreateKey($o.path, $(if ($o.Contains('class')) { [string]$o.class } else { $null })) }
            'value'       { $N::CreateKey($o.path, $null); $N::SetValue($o.path, [string]$o.name, [int]$o.type, [byte[]]$o.data) }
            'canary-key' {
                $N::CreateKey($o.path, $null)
                foreach ($v in $o.values) { $N::SetValue($o.path, [string]$v.name, [int]$v.type, [byte[]]$v.data) }
            }
            'canary-value' { $N::CreateKey($o.path, $null); $N::SetValue($o.path, [string]$o.name, [int]$o.type, [byte[]]$o.data) }
            'reglink' {
                $N::CreateKey((Get-M2Parent $o.path), $null)
                $nt = ConvertTo-NtRegPath $o.target
                $N::CreateLink($o.path, $nt)
                $got = $N::LinkTarget($o.path)
                if ($got -ne $nt) { throw "link reads back '$got', not '$nt'" }
                $st.detail = $nt
            }
            'key-sddl'    { $N::SetKeySddl($o.path, $o.sddl); $st.detail = $N::GetKeySddl($o.path) }
            'medium' {
                $m = $Trap.medium[$o.step]
                if ($m.Contains('requires') -and $m.requires -and -not (Test-Path -LiteralPath $m.requires)) { throw "precondition: $($m.requires) does not exist (run install\install.ps1 first)" }
                $r = Invoke-M2Medium $o.step $m.body
                $ops = @(foreach ($x in @($r.ops)) {
                        $exp = $null; if ($m.expect_ok.Contains($x.op)) { $exp = [bool]$m.expect_ok[$x.op] }
                        [ordered]@{ op = $x.op; ok = [bool]$x.ok; expected_ok = $exp; as_expected = ($null -eq $exp -or $exp -eq [bool]$x.ok); error = $x.error }
                    })
                $st.detail = [ordered]@{ il = $r.il; medium = ($r.il -eq 'S-1-16-8192'); error = $r.error; ops = $ops }
                $st.ok = ($r.il -eq 'S-1-16-8192') -and -not $r.error -and -not @($ops | Where-Object { -not $_.as_expected }).Count
            }
            'path-segment' { $st.detail = Invoke-M2PathSegment $o }
            default       { throw "unknown object kind '$($o.k)'" }
        }
    } catch {
        $st.ok = $false; $st.detail = $_.Exception.Message
        if (-not ($o.Contains('optional') -and $o.optional) -and $o.k -ne 'medium') { throw "$($o.k) $($st.path): $($_.Exception.Message)" }
    }
    $st
}

# Resets one trap's objects: security descriptors back to administrators (reverse order), owned file and
# registry roots removed without following links, guarded roots only when they carry the marker.
function Reset-M2Trap($Trap, [switch]$Lenient) {
    $N = [PurgeRigM2.Native]
    $objs = @($Trap.objects); [Array]::Reverse($objs)
    foreach ($o in $objs) {
        try {
            if ($o.k -eq 'file-sddl' -and $N::Facts($o.path)) { $N::SetFileSddl($o.path, $M2SddlAdminFile) }
            if ($o.k -eq 'key-sddl' -and $N::KeyExists($o.path)) { $N::SetKeySddl($o.path, $M2SddlAdminKey) }
            if ($o.k -eq 'path-segment') { Reset-M2PathSegment $o }
        } catch { Log "  !! reset security of $($o.path): $($_.Exception.Message)" }
    }
    foreach ($p in @($Trap.fs_roots)) { $N::RemoveTree($p) }
    foreach ($k in @($Trap.reg_roots)) { [void]$N::DeleteTree($k) }
    foreach ($g in @($Trap.guarded_roots)) {
        if (-not $N::Facts($g.path)) { continue }
        if ($N::Facts((Join-Path $g.path $g.marker))) { Log "  reset: removing $($g.path) (rig-created, marker present)"; $N::RemoveTree($g.path) }
        elseif ($Lenient) { Log "  reset: leaving $($g.path) (not created by this script)" }
        else { throw "$($g.path) exists and was not created by this script (no $($g.marker)); refusing to touch it" }
    }
    foreach ($g in @($Trap.fs_root_globs)) {
        if (-not $N::Facts($g.parent)) { continue }
        foreach ($e in $N::List($g.parent)) {
            if ($e.Name -notlike $g.like) { continue }
            $p = Join-Path $g.parent $e.Name
            if ($g.marker -and -not $N::Facts((Join-Path $p $g.marker))) { Log "  reset: leaving $p (no $($g.marker))"; continue }
            $N::RemoveTree($p)
        }
    }
}

# path-segment objects (used by m2-fixtures): append one ';' segment to a list value, recording the data
# before and after. Reset removes every occurrence of the segment again.
function Get-M2RawValue([string]$Key, [string]$Name) {
    $v = @([PurgeRigM2.Native]::Values($Key) | Where-Object { $_ -and $_.Name -ceq $Name }) | Select-Object -First 1
    $v
}
function Split-M2Segments([byte[]]$Data) {
    $s = [Text.Encoding]::Unicode.GetString($Data).TrimEnd([char]0)
    @($s -split ';')
}
function Invoke-M2PathSegment($o) {
    $v = Get-M2RawValue $o.path $o.name
    if (-not $v) {
        if ($o.optional) { throw "value $($o.path)\$($o.name) does not exist (optional: skipped)" }
        throw "value $($o.path)\$($o.name) does not exist"
    }
    Reset-M2PathSegment $o
    $v = Get-M2RawValue $o.path $o.name
    $before = [byte[]]$v.Data
    $segs = @(Split-M2Segments $before | Where-Object { $_ -ne '' })
    $index = $segs.Count
    $new = ($segs + @($o.segment)) -join ';'
    $after = [Text.Encoding]::Unicode.GetBytes($new + [char]0)
    [PurgeRigM2.Native]::SetValue($o.path, $o.name, $v.Type, $after)
    [ordered]@{ type = $v.Type; index = $index; before_b64 = (M2-B64 $before); after_b64 = (M2-B64 $after); before_sha256 = (Get-RegValueHash $v.Type $before); after_sha256 = (Get-RegValueHash $v.Type $after) }
}
function Reset-M2PathSegment($o) {
    $v = Get-M2RawValue $o.path $o.name
    if (-not $v) { return }
    $segs = @(Split-M2Segments ([byte[]]$v.Data))
    $keep = @($segs | Where-Object { $_ -ine $o.segment })
    if ($keep.Count -eq $segs.Count) { return }
    $keep = @($keep | Where-Object { $_ -ne '' })
    [PurgeRigM2.Native]::SetValue($o.path, $o.name, $v.Type, [Text.Encoding]::Unicode.GetBytes(($keep -join ';') + [char]0))
}

# --------------------------------------------------------------------------------- documents / outputs

function New-M2Doc([string]$Schema, [string]$GeneratedBy, $Table, $Roots, [string]$Sid, [bool]$Dry) {
    $canaries = @(Get-M2Canaries $Table)
    $traps = @(foreach ($t in $Table) {
            $d = [ordered]@{}
            foreach ($k in $t.Keys) {
                if ($k -eq 'objects') { $d.objects = @(foreach ($o in $t.objects) { ConvertTo-M2ObjectDoc $o }); continue }
                if ($k -eq 'medium' -and $t.medium) { $d.medium = [ordered]@{}; foreach ($s in $t.medium.Keys) { $d.medium[$s] = [ordered]@{ expect_ok = $t.medium[$s].expect_ok; body = $t.medium[$s].body } }; continue }
                $d[$k] = $t[$k]
            }
            $d.canaries = @($canaries | Where-Object { $_.trap -eq $t.id } | ForEach-Object { $_.id })
            $d.build = $null
            $d
        })
    [ordered]@{
        schema = $Schema; generated_by = $GeneratedBy; dry_run = $Dry
        built_at = $null; computer = $(if ($Dry) { $null } else { $env:COMPUTERNAME }); user_sid = $(if ($Dry) { '{user-sid}' } else { $Sid })
        placeholders = $(if ($Dry) { Get-M2Placeholder } else { $null })
        roots = $Roots
        rules = [ordered]@{
            canaries = 'every canary must keep its sha256 (file: content; regkey: values; regvalue: type+data) and must not become a reparse point; any change is a guard escape'
            expect = 'items[].expect is the executor outcome the gate expects; items[].accept lists outcomes that are not failures as long as every canary stays intact'
            outcomes = 'Done | Vanished | Skipped{reason: GateBlocked{blocker} | NoLongerEmpty | ChangedSinceScan} | HeldRetry | PendingReboot (purge-model ItemOutcome); trap-level expect: RenamedAside | Denied | NotPreselected'
            groups = 'main: one exec; race-a / race-b: one exec each with helper.env and the swap helper; locked: m2-reboot'
        }
        canaries = $canaries
        traps = $traps
    }
}

function Write-M2Json($Object, [string]$Path) { [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Object -Depth 30), $M2Utf8) }

# purge.rig.targets/0, purge.rig.select/0 and the path list for a set of items.
function Write-M2Targets($Table, [string]$Dir, [string]$Prefix, [string]$Source, [string[]]$OnlyStages = @()) {
    $items = @(foreach ($t in $Table) {
            if ($OnlyStages.Count -and $OnlyStages -notcontains $t.stage) { continue }
            foreach ($i in $t.items) { [ordered]@{ id = $i.id; trap = $t.id; group = $i.group; target = $i.target; action = $i.action } }
        })
    Write-M2Json ([ordered]@{ schema = 'purge.rig.targets/0'; source = $Source; origin = 'ManualUser'; note = 'rig fixtures for `purge-engine plan from-targets` (rig-exec only); filter by group'; targets = $items }) (Join-Path $Dir "$Prefix-targets.json")
    Write-M2Json ([ordered]@{ schema = 'purge.rig.select/0'; source = $Source; note = 'rig item ids; map to candidate ids by target after planning'; ids = @($items | ForEach-Object { $_.id }) }) (Join-Path $Dir "$Prefix-select.json")
    $paths = @($items | Where-Object { $_.target.type -eq 'Path' } | ForEach-Object { $_.target.path })
    [IO.File]::WriteAllText((Join-Path $Dir "$Prefix-paths.txt"), (($paths -join "`r`n") + "`r`n"), $M2Utf8)
}

# Evaluates canaries (+ trap post_checks) against a built manifest; returns the check document.
function Invoke-M2Check($Doc, [string]$Label) {
    $built = @{}
    foreach ($t in @($Doc.traps)) { if ($t.build -and $t.build.ok) { $built[$t.id] = $true } }
    $rows = @(foreach ($c in @($Doc.canaries)) {
            if (-not $built.ContainsKey($c.trap)) { continue }
            $m = Measure-M2Canary $c
            $was = $null
            if ($Doc.PSObject.Properties['measured'] -and $Doc.measured) { $was = @($Doc.measured | Where-Object { $_.id -eq $c.id }) | Select-Object -First 1 }
            $same = $null
            if ($was -and $was.file_id -and $m.file_id) { $same = ($was.file_id -eq $m.file_id) -and ($was.volume_serial -eq $m.volume_serial) }
            [ordered]@{ id = $c.id; trap = $c.trap; kind = $c.kind; path = $c.path; expected_sha256 = $c.sha256; actual_sha256 = $m.sha256; present = $m.present; reparse = $m.reparse; same_file_id = $same; intact = ($m.present -and -not $m.reparse -and $m.sha256 -eq $c.sha256); error = $m.error }
        })
    $checks = @(foreach ($t in @($Doc.traps)) {
            if (-not $built.ContainsKey($t.id)) { continue }
            foreach ($p in @($t.post_checks)) {
                if (-not $p) { continue }
                $ok = $false; $detail = $null
                try {
                    switch ($p.kind) {
                        'exists' { $hits = @(Get-ChildItem -Path $p.path -Force -ErrorAction SilentlyContinue); $ok = $hits.Count -gt 0; $detail = @($hits | ForEach-Object { $_.FullName }) }
                        'absent' { $ok = -not [PurgeRigM2.Native]::Facts($p.path) }
                        'present' { $ok = [bool][PurgeRigM2.Native]::Facts($p.path) }
                        'not-reparse' { $f = [PurgeRigM2.Native]::Facts($p.path); $ok = $f -and (($f.Attributes -band 0x400) -eq 0); $detail = $(if ($f) { '0x{0:X8}' -f $f.Attributes } else { 'missing' }) }
                    }
                } catch { $detail = $_.Exception.Message }
                [ordered]@{ trap = $t.id; kind = $p.kind; path = $p.path; ok = $ok; detail = $detail }
            }
        })
    $esc = @($rows | Where-Object { -not $_.intact })
    [ordered]@{
        schema = 'purge.rig.m2traps.check/0'; label = $Label; at = (Get-Date).ToString('o'); computer = $env:COMPUTERNAME
        canaries = $rows; post_checks = $checks
        guard_escapes = $esc.Count; post_checks_failed = @($checks | Where-Object { -not $_.ok }).Count
        ok = ($esc.Count -eq 0 -and @($checks | Where-Object { -not $_.ok }).Count -eq 0)
    }
}

function Assert-M2Elevated {
    if (-not [Environment]::Is64BitProcess) { throw 'run in 64-bit PowerShell' }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run elevated (through the rig agent)' }
    foreach ($p in 'SeRestorePrivilege', 'SeBackupPrivilege', 'SeTakeOwnershipPrivilege', 'SeCreateSymbolicLinkPrivilege') {
        if (-not [PurgeRigM2.Native]::EnablePrivilege($p)) { Log "  !! could not enable $p" }
    }
}

# Builds a table's traps of one stage into a manifest (merged with an existing one in $Dir).
function Invoke-M2Build($Table, $Doc, [string]$ManifestPath, [string]$StageName) {
    $old = $null
    if (Test-Path -LiteralPath $ManifestPath) { try { $old = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json } catch { Log "  !! unreadable $ManifestPath; starting a new manifest" } }
    $measured = New-Object System.Collections.ArrayList
    $failed = 0
    for ($i = 0; $i -lt $Table.Count; $i++) {
        $t = $Table[$i]; $d = $Doc.traps[$i]
        if ($StageName -and $t.stage -ne $StageName) {
            if ($old) { $o = @($old.traps | Where-Object { $_.id -eq $t.id }) | Select-Object -First 1; if ($o) { $d.build = $o.build } }
            continue
        }
        Log "== trap $($t.id)"
        $b = [ordered]@{ ok = $false; at = (Get-Date).ToString('o'); objects = New-Object System.Collections.ArrayList; error = $null }
        try {
            Reset-M2Trap $t
            foreach ($o in $t.objects) { [void]$b.objects.Add((Invoke-M2Object $o $t)) }
            $b.ok = $true
            foreach ($s in $b.objects) { if (-not $s.ok) { Log "  note: $($s.k) $($s.path): $($s.detail | ConvertTo-Json -Compress -Depth 6)" } }
            if (@($b.objects | Where-Object { $_.k -eq 'medium' -and -not $_.ok }).Count) { $b.ok = $false; $b.error = 'a medium-IL step did not behave as expected (see objects)' }
        } catch {
            $b.error = $_.Exception.Message; $failed++
            Log "  !! trap $($t.id) not built: $($b.error)"
        }
        $d.build = $b
    }
    foreach ($c in $Doc.canaries) {
        $d = @($Doc.traps | Where-Object { $_.id -eq $c.trap }) | Select-Object -First 1
        $isStage = (-not $StageName) -or (@($Table | Where-Object { $_.id -eq $c.trap -and $_.stage -eq $StageName }).Count -gt 0)
        if ($isStage) {
            if ($d.build -and $d.build.ok) {
                $m = Measure-M2Canary $c
                if ($m.sha256 -ne $c.sha256) { Log "  !! canary $($c.id) measures $($m.sha256), expected $($c.sha256)"; $failed++ }
                [void]$measured.Add($m)
            }
        } elseif ($old -and $old.PSObject.Properties['measured']) {
            $o = @($old.measured | Where-Object { $_.id -eq $c.id }) | Select-Object -First 1
            if ($o) { [void]$measured.Add($o) }
        }
    }
    $Doc.built_at = (Get-Date).ToString('o')
    $Doc.measured = $measured
    $Doc.stages_built = @(@($Doc.traps | Where-Object { $_.build } | ForEach-Object { $_.stage }) | Sort-Object -Unique)
    Write-M2Json $Doc $ManifestPath
    Log "manifest -> $ManifestPath ($failed problem(s))"
    $failed
}

if ($Library) { return }

# ===================================================================================== main (traps)

$sidForTable = $(if ($DryRun) { '{user-sid}' } else { $RigUserSid })
$lad = $(if ($DryRun) { '{localappdata}' } else { $env:LOCALAPPDATA })
$Table = Get-M2TrapTable $sidForTable $lad
$Roots = [ordered]@{
    trap_root = $M2TrapRoot; canary_root = $M2CanaryRoot; user_writable_root = $M2UwRoot; programdata = $M2PdRoot
    trap_keys = @('HKLM\SOFTWARE\PurgeTrapApp', "HKU\$sidForTable\Software\PurgeTrapApp"); canary_keys = @('HKLM\SOFTWARE\PurgeCanary', "HKU\$sidForTable\Software\PurgeCanary")
}
if (-not $OutDir -and -not $DryRun) { $OutDir = 'C:\cr\out\m2-traps' }
if ($OutDir) { New-Item -ItemType Directory -Force $OutDir | Out-Null }
$ManifestPath = $(if ($OutDir) { Join-Path $OutDir 'm2-traps-manifest.json' } else { $null })

switch ($Action) {
    'build' {
        $doc = New-M2Doc 'purge.rig.m2traps/0' 'vm/guest/m2-traps.ps1' $Table $Roots $sidForTable ([bool]$DryRun)
        if ($DryRun) {
            if ($OutDir) {
                Write-M2Json $doc $ManifestPath
                Write-M2Targets $Table $OutDir 'm2-traps' 'm2-traps'
                Log "dry run: manifest and targets -> $OutDir"
            } else { ConvertTo-Json -InputObject $doc -Depth 30 }
            exit 0
        }
        Assert-M2Elevated
        if (Get-Command Set-RunLog -ErrorAction SilentlyContinue) { Set-RunLog (Join-Path $OutDir "m2-traps-$Stage.log") }
        Log "m2-traps build, stage $Stage, on $env:COMPUTERNAME (sid $RigUserSid)"
        $failed = Invoke-M2Build $Table $doc $ManifestPath $Stage
        Write-M2Targets $Table $OutDir 'm2-traps' 'm2-traps'
        if ($failed) { exit 1 }
        exit 0
    }
    'check' {
        if (-not (Test-Path -LiteralPath $ManifestPath)) { throw "no manifest at $ManifestPath (run build first)" }
        $doc = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
        $r = Invoke-M2Check $doc $Label
        $name = $(if ($Label) { "m2-traps-check-$Label.json" } else { 'm2-traps-check.json' })
        Write-M2Json $r (Join-Path $OutDir $name)
        Log "check: guard_escapes=$($r.guard_escapes) post_checks_failed=$($r.post_checks_failed) -> $name"
        if ($r.ok) { exit 0 } else { exit 1 }
    }
    'swap' {
        Assert-M2Elevated
        $t = @($Table | Where-Object { $_.id -eq $TrapId -and $_.helper -and $_.helper.action -eq 'swap' }) | Select-Object -First 1
        if (-not $t) { throw "no swap trap '$TrapId' (race-validate-open | race-open-act)" }
        $h = $t.helper
        $needle = ConvertTo-Json -InputObject $h.dir -Compress   # the JSON-escaped item path, with quotes
        $needle = $needle.Substring(1, $needle.Length - 2)
        $rec = [ordered]@{ trap = $t.id; dir = $h.dir; link_to = $h.link_to; started = (Get-Date).ToString('o'); triggered = $null; journal = $null; swapped = $null; error = $null }
        try {
            $deadline = (Get-Date).AddSeconds($TimeoutSec)
            while (-not $rec.triggered -and (Get-Date) -lt $deadline) {
                $j = Get-ChildItem -Path (Join-Path $M2PdRoot 'sessions\*\journal.jsonl') -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($j) {
                    try {
                        $fs = [IO.File]::Open($j.FullName, 'Open', 'Read', 'ReadWrite, Delete')
                        try { $text = (New-Object IO.StreamReader($fs, $M2Utf8)).ReadToEnd() } finally { $fs.Dispose() }
                        foreach ($line in $text -split "`n") {
                            if ($line.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and $line -match '(?i)"intent') { $rec.triggered = (Get-Date).ToString('o'); $rec.journal = $j.FullName; break }
                        }
                    } catch { }
                }
                if (-not $rec.triggered) { Start-Sleep -Milliseconds 100 }
            }
            if (-not $rec.triggered) { throw "no intent record for $($h.dir) within $TimeoutSec s" }
            $aside = $h.dir + '.swapped-orig'
            [PurgeRigM2.Native]::Move($h.dir, $aside)
            [PurgeRigM2.Native]::Junction($h.dir, $h.link_to)
            $rec.swapped = (Get-Date).ToString('o')
            Log "swap $($t.id): $($h.dir) -> junction to $($h.link_to) (original at $aside)"
        } catch { $rec.error = $_.Exception.Message; Log "  !! swap: $($rec.error)" }
        if ($OutDir) { Write-M2Json $rec (Join-Path $OutDir "m2-traps-swap-$($t.id).json") }
        if ($rec.error) { exit 1 } else { exit 0 }
    }
    'plant-boot-junction' {
        Assert-M2Elevated
        $t = @($Table | Where-Object { $_.id -eq 'boot-uw-planted' })[0]
        $r = Invoke-M2Object (O 'medium' @{ step = 'boot-plant' }) $t
        if ($OutDir) { Write-M2Json $r (Join-Path $OutDir 'm2-traps-plant-boot.json') }
        Log "plant-boot-junction: ok=$($r.ok)"
        if ($r.ok) { exit 0 } else { exit 1 }
    }
    'plant-expiry-junction' {
        Assert-M2Elevated
        $t = @($Table | Where-Object { $_.id -eq 'expiry-junction' })[0]
        $want = $M2Utf8.GetBytes("PURGE-EXPIRY-MARKER m2-traps`n")
        $found = New-Object System.Collections.ArrayList
        # Walks the quarantine without descending into reparse points.
        $walk = {
            param([string]$Dir, [int]$Depth)
            if ($Depth -gt 12) { return }
            foreach ($e in [PurgeRigM2.Native]::List($Dir)) {
                $p = Join-Path $Dir $e.Name
                if (($e.Attributes -band 0x400) -ne 0) { continue }
                if (($e.Attributes -band 0x10) -ne 0) { & $walk $p ($Depth + 1); continue }
                if ($e.Name -eq $t.helper.marker) {
                    $b = [PurgeRigM2.Native]::ReadAll($p)
                    if ([Convert]::ToBase64String($b) -eq [Convert]::ToBase64String($want)) { [void]$found.Add($Dir) }
                }
            }
        }
        & $walk (Join-Path $M2PdRoot 'Quarantine') 0
        $rec = [ordered]@{ trap = $t.id; quarantined_dirs = @($found); planted = New-Object System.Collections.ArrayList; error = $null }
        if ($found.Count -ne 1) { $rec.error = "expected one quarantined copy of $($t.helper.marker), found $($found.Count)" }
        else {
            foreach ($pl in $t.helper.plants) {
                $p = Join-Path $found[0] $pl.name
                try {
                    if ($pl.kind -eq 'junction') { [PurgeRigM2.Native]::Junction($p, $pl.target) } else { [PurgeRigM2.Native]::Symlink($p, $pl.target, $false) }
                    [void]$rec.planted.Add([ordered]@{ path = $p; kind = $pl.kind; target = $pl.target; ok = $true })
                } catch { [void]$rec.planted.Add([ordered]@{ path = $p; kind = $pl.kind; target = $pl.target; ok = $false; error = $_.Exception.Message }); $rec.error = 'a plant failed' }
            }
        }
        if ($OutDir) { Write-M2Json $rec (Join-Path $OutDir 'm2-traps-plant-expiry.json') }
        Log "plant-expiry-junction: $(if ($rec.error) { $rec.error } else { "planted in $($found[0])" })"
        if ($rec.error) { exit 1 } else { exit 0 }
    }
    'reset' {
        Assert-M2Elevated
        $bad = 0
        foreach ($t in $Table) { try { Reset-M2Trap $t -Lenient } catch { $bad++; Log "  !! reset $($t.id): $($_.Exception.Message)" } }
        $N = [PurgeRigM2.Native]
        foreach ($p in @($M2TrapRoot, $M2UwRoot, $M2CanaryRoot)) { try { $N::RemoveTree($p) } catch { $bad++; Log "  !! $p : $($_.Exception.Message)" } }
        foreach ($k in @('HKLM\SOFTWARE\PurgeTrapApp', "HKU\$RigUserSid\Software\PurgeTrapApp", 'HKLM\SOFTWARE\PurgeCanary', "HKU\$RigUserSid\Software\PurgeCanary")) { try { [void]$N::DeleteTree($k) } catch { $bad++; Log "  !! $k : $($_.Exception.Message)" } }
        foreach ($d in @("$env:LOCALAPPDATA\Purge\fp", "$env:LOCALAPPDATA\Purge")) { if ($N::Facts($d) -and -not @($N::List($d)).Count) { $N::DeleteNoFollow($d) } }
        Log "reset done ($bad problem(s))"
        if ($bad) { exit 1 } else { exit 0 }
    }
}
