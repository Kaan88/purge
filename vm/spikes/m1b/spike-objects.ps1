<#
  M1B-SPIKE (docs/M1B_DESIGN.json, package M1B-SPIKE): can a service, a scheduled task and a firewall rule be
  deleted and re-created exactly? Result: vm\spikes\m1b\RESULT.json (schema purge.m1b.spike/1), summary README.md.

  Two modes in one file (Windows PowerShell 5.1):
    Host:  powershell -NoProfile -File vm\spikes\m1b\spike-objects.ps1 -Drive [-Runs 2]
           $env:VMPWFILE must name the guest password file. For each run: restore Inbound-Win11-Test to m2-base,
           start it, push guest\riglib.ps1, submit this file as an agent job (elevated, in the guest) with the run
           name and stage filled in, follow the reboot continuation (stage 'main' -> reboot -> stage 'reboot'),
           pull C:\cr\out\<run>\ to vm\runs\<run>\. Afterwards the VM is powered off and restored to m2-base.
    Guest: the agent job (stage main / reboot). Refuses to run anywhere but the rig VM.

  Everything it creates is its own: firewall rules 'PurgeSpike *', tasks \PurgeSpike*, services PurgeSpike*, a
  local account purgespike (random password, never written anywhere). Official tooling only: NetSecurity and
  ScheduledTasks COM, WMI (System.Management = IWbemServices/IWbemContext, MI = CimSession), sc.exe, advapi32.
#>
param([switch]$Drive, [int]$Runs = 2, [string]$Prefix = 'm1b-spike-r')

# =============================================================================================== host driver
if ($Drive) {
    $ErrorActionPreference = 'Stop'
    $spikeRuns = $Runs; $spikePrefix = $Prefix; $spikeFile = $PSCommandPath
    . (Join-Path $PSScriptRoot '..\..\rig.ps1') -VmName 'Inbound-Win11-Test'
    Assert-RigVm
    $spikeSnap = 'm2-base'
    $tokRun = '__' + 'RUN__'; $tokStage = '__' + 'STAGE__'
    $spikeResults = @()
    try {
        $null = Get-PwFile
        foreach ($k in 1..$spikeRuns) {
            $run = "$spikePrefix$k"
            $t0 = Get-Date
            $null = Move-RunToOld -Run $run
            Restore-Base -Snapshot $spikeSnap
            foreach ($d in 'C:\cr\guest', 'C:\cr\out', 'C:\cr\stage', 'C:\cr\work') { $null = Invoke-Guest @('mkdir', '--parents', $d) }
            $r = Invoke-Guest @('copyto', '--target-directory', 'C:\cr\guest\', (Join-Path $script:RigDir 'guest\riglib.ps1'))
            if ($r.code -ne 0) { throw "copy riglib.ps1 failed: $($r.out -join ' ')" }
            $logs = @(); $stage = 'main'; $n = 0
            while ($true) {
                $n++
                if ($n -gt 4) { throw 'too many stages' }
                $text = [IO.File]::ReadAllText($spikeFile).Replace($tokRun, $run).Replace($tokStage, $stage)
                $logFile = Join-Path (Get-HostTemp) ("{0}-job-{1}-{2}.log" -f $run, $n, $stage)
                $j = Invoke-GuestJob -Text $text -Name "$run-$stage" -TimeoutSec 3600 -LogCopy $logFile
                $logs += [pscustomobject]@{ n = $n; stage = $stage; file = $logFile }
                Write-RigLog "  job $($j.name) done=$($j.done) after $($j.seconds) s"
                if (-not $j.done) { throw "stage $stage did not finish" }
                $m = Get-GuestContinuation -Run $run
                if (-not $m) { break }
                $null = Wait-GuestReboot -BootBefore "$($m.boot_before)"
                $stage = "$($m.next)"
            }
            $pulled = @(Pull-Run -Run $run)
            $dst = Join-Path $script:RunsDir $run
            foreach ($l in $logs) { if (Test-Path -LiteralPath $l.file) { Move-Item -LiteralPath $l.file -Destination (Join-Path $dst ('job-{0}-{1}.log' -f $l.n, $l.stage)) -Force } }
            $spikeResults += [pscustomobject]@{ run = $run; pulled = $pulled.Count; seconds = [int]((Get-Date) - $t0).TotalSeconds }
        }
    } finally {
        try {
            $st = Get-VmState
            if (@('running', 'paused', 'stuck', 'starting') -contains $st) { $null = Invoke-VBox @('controlvm', $script:VmName, 'poweroff'); $null = Wait-VmState @('poweroff', 'aborted') 120 }
            $r = Invoke-VBox @('snapshot', $script:VmName, 'restore', $spikeSnap)
            Write-RigLog "final: VM powered off, restore $spikeSnap exit $($r.code)"
        } finally { Remove-PwTemp }
    }
    $spikeResults
    return
}

# =============================================================================================== guest
$Run = '__RUN__'; $Stage = '__STAGE__'
if ($Run.StartsWith('__') -or $Stage.StartsWith('__')) { throw 'guest mode needs the run name and stage filled in by -Drive' }
$model = "$((Get-CimInstance Win32_ComputerSystem).Model)"
if ($model -notmatch 'VirtualBox' -or -not (Test-Path -LiteralPath 'C:\cr\jobs\agent.alive')) { throw "guest mode refused: not the rig VM (model '$model')" }

. 'C:\cr\guest\riglib.ps1'
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Management

Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32;

namespace PurgeSpike
{
    public class RegVal { public string name; public uint type; public string hex; }
    public class RegKeyCap { public string path; public RegVal[] values; public string[] subkeys; public string error; }

    public static class Reg
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegQueryValueExW(IntPtr hKey, string name, IntPtr reserved, out uint type, byte[] data, ref uint cb);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegSetValueExW(IntPtr hKey, string name, uint reserved, uint type, byte[] data, uint cb);

        static RegistryKey Hklm() { return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64); }
        public static string Hex(byte[] b) { return b == null ? null : BitConverter.ToString(b).Replace("-", ""); }
        public static byte[] Unhex(string h)
        {
            if (h == null) return null;
            byte[] b = new byte[h.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
            return b;
        }
        static RegVal Read(RegistryKey k, string name)
        {
            IntPtr h = k.Handle.DangerousGetHandle();
            uint type; uint cb = 0;
            int e = RegQueryValueExW(h, name, IntPtr.Zero, out type, null, ref cb);
            if (e != 0 && e != 234) return null;
            byte[] d = new byte[cb];
            e = RegQueryValueExW(h, name, IntPtr.Zero, out type, d, ref cb);
            if (e != 0) return null;
            if (cb != d.Length) Array.Resize(ref d, (int)cb);
            RegVal v = new RegVal(); v.name = name; v.type = type; v.hex = Hex(d);
            return v;
        }
        public static RegVal ReadValue(string sub, string name)
        {
            using (RegistryKey b = Hklm())
            using (RegistryKey k = b.OpenSubKey(sub))
            {
                if (k == null) return null;
                return Read(k, name);
            }
        }
        public static bool KeyExists(string sub)
        {
            using (RegistryKey b = Hklm())
            using (RegistryKey k = b.OpenSubKey(sub)) { return k != null; }
        }
        public static RegKeyCap[] Tree(string sub)
        {
            List<RegKeyCap> l = new List<RegKeyCap>();
            using (RegistryKey b = Hklm()) { Walk(b, sub, "", l, 0); }
            return l.Count == 0 ? null : l.ToArray();
        }
        static void Walk(RegistryKey b, string full, string rel, List<RegKeyCap> l, int depth)
        {
            RegKeyCap c = new RegKeyCap(); c.path = rel;
            RegistryKey k = null;
            try { k = b.OpenSubKey(full); }
            catch (Exception ex) { c.error = ex.GetType().Name; c.values = new RegVal[0]; c.subkeys = new string[0]; l.Add(c); return; }
            if (k == null) return;
            using (k)
            {
                string[] names = k.GetValueNames();
                Array.Sort(names, StringComparer.OrdinalIgnoreCase);
                List<RegVal> vs = new List<RegVal>();
                foreach (string n in names) { RegVal v = Read(k, n); if (v != null) vs.Add(v); }
                c.values = vs.ToArray();
                string[] subs = k.GetSubKeyNames();
                Array.Sort(subs, StringComparer.OrdinalIgnoreCase);
                c.subkeys = subs;
                l.Add(c);
                if (depth < 16) foreach (string s in subs) Walk(b, full + "\\" + s, rel.Length == 0 ? s : rel + "\\" + s, l, depth + 1);
            }
        }
        public static int Write(string sub, string name, uint type, string hex)
        {
            using (RegistryKey b = Hklm())
            using (RegistryKey k = b.CreateSubKey(sub))
            {
                byte[] d = Unhex(hex); if (d == null) d = new byte[0];
                return RegSetValueExW(k.Handle.DangerousGetHandle(), name, 0, type, d, (uint)d.Length);
            }
        }
        public static void CreateKey(string sub) { using (RegistryKey b = Hklm()) using (RegistryKey k = b.CreateSubKey(sub)) { } }
        public static void DeleteValue(string sub, string name)
        {
            using (RegistryKey b = Hklm())
            using (RegistryKey k = b.OpenSubKey(sub, true)) { if (k != null) k.DeleteValue(name, false); }
        }
    }

    public class FailAction { public uint type; public uint delay_ms; }
    public class FailureActions { public uint reset_period; public string reboot_msg; public string command; public FailAction[] actions; }
    public class TriggerData { public uint type; public string hex; }
    public class Trigger { public uint type; public uint action; public string subtype; public TriggerData[] data; }
    public class SvcConfig { public uint service_type; public uint start_type; public uint error_control; public string binary_path; public string load_order_group; public uint tag_id; public string[] dependencies; public string service_start_name; public string display_name; }
    public class SvcConfig2 { public string description; public bool? delayed_auto_start; public FailureActions failure_actions; public bool? failure_actions_flag; public uint? service_sid_type; public string[] required_privileges; public uint? preshutdown_timeout_ms; public Trigger[] triggers; public uint? launch_protected; }
    public class SvcDef { public string name; public SvcConfig config; public SvcConfig2 config2; public string sddl; public int state; public string[] errors; }

    public static class Scm
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr OpenSCManagerW(string machine, string db, uint access);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr CreateServiceW(IntPtr scm, string name, string display, uint access, uint type, uint start, uint err, string bin, string group, IntPtr tag, string deps, string startName, string password);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool DeleteService(IntPtr h);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool CloseServiceHandle(IntPtr h);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool QueryServiceConfigW(IntPtr h, IntPtr buf, uint size, out uint needed);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool QueryServiceConfig2W(IntPtr h, uint level, IntPtr buf, uint size, out uint needed);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool ChangeServiceConfig2W(IntPtr h, uint level, IntPtr info);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool QueryServiceObjectSecurity(IntPtr h, uint si, IntPtr buf, uint size, out uint needed);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetServiceObjectSecurity(IntPtr h, uint si, byte[] sd);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool QueryServiceStatusEx(IntPtr h, int level, IntPtr buf, uint size, out uint needed);

        [StructLayout(LayoutKind.Sequential)] struct QSC { public uint type; public uint start; public uint err; public IntPtr bin; public IntPtr group; public uint tag; public IntPtr deps; public IntPtr startName; public IntPtr display; }
        [StructLayout(LayoutKind.Sequential)] struct SFA { public uint reset; public IntPtr reboot; public IntPtr cmd; public uint c; public IntPtr actions; }
        [StructLayout(LayoutKind.Sequential)] struct STI { public uint c; public IntPtr triggers; public IntPtr reserved; }
        [StructLayout(LayoutKind.Sequential)] struct ST { public uint type; public uint action; public IntPtr subtype; public uint c; public IntPtr data; }
        [StructLayout(LayoutKind.Sequential)] struct SDI { public uint type; public uint cb; public IntPtr p; }

        public const uint QUERY_CONFIG = 0x1, CHANGE_CONFIG = 0x2, QUERY_STATUS = 0x4, START = 0x10, ACCESS_DELETE = 0x10000, READ_CONTROL = 0x20000, WRITE_DAC = 0x40000, WRITE_OWNER = 0x80000;
        public static int LastError;
        public static string LastStage;

        static IntPtr Mgr(uint access)
        {
            IntPtr m = OpenSCManagerW(null, null, access);
            if (m == IntPtr.Zero) throw new Exception("OpenSCManagerW error " + Marshal.GetLastWin32Error());
            return m;
        }
        public static IntPtr OpenHandle(string name, uint access)
        {
            IntPtr m = Mgr(1);
            try { IntPtr h = OpenServiceW(m, name, access); LastError = h == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0; return h; }
            finally { CloseServiceHandle(m); }
        }
        public static void Close(IntPtr h) { if (h != IntPtr.Zero) CloseServiceHandle(h); }
        public static int DeleteHandle(IntPtr h) { return DeleteService(h) ? 0 : Marshal.GetLastWin32Error(); }
        public static int DeleteByName(string name)
        {
            IntPtr h = OpenHandle(name, ACCESS_DELETE | QUERY_STATUS);
            if (h == IntPtr.Zero) { LastStage = "open"; return LastError; }
            try { LastStage = "delete"; return DeleteHandle(h); } finally { CloseServiceHandle(h); }
        }
        static string Str(IntPtr p) { return p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p); }
        static string[] MultiSz(IntPtr p)
        {
            if (p == IntPtr.Zero) return null;
            List<string> l = new List<string>();
            while (true)
            {
                string s = Marshal.PtrToStringUni(p);
                if (string.IsNullOrEmpty(s)) break;
                l.Add(s);
                p = new IntPtr(p.ToInt64() + (s.Length + 1) * 2);
            }
            return l.ToArray();
        }
        static IntPtr Q2(IntPtr h, uint level, List<string> errs)
        {
            uint need;
            QueryServiceConfig2W(h, level, IntPtr.Zero, 0, out need);
            int e = Marshal.GetLastWin32Error();
            if (e != 122) { errs.Add("config2 level " + level + ": " + e); return IntPtr.Zero; }
            IntPtr b = Marshal.AllocHGlobal((int)need);
            if (!QueryServiceConfig2W(h, level, b, need, out need)) { errs.Add("config2 level " + level + ": " + Marshal.GetLastWin32Error()); Marshal.FreeHGlobal(b); return IntPtr.Zero; }
            return b;
        }
        public static SvcDef Query(string name)
        {
            IntPtr h = OpenHandle(name, QUERY_CONFIG | QUERY_STATUS | READ_CONTROL);
            if (h == IntPtr.Zero) { if (LastError == 1060) return null; throw new Exception("OpenServiceW error " + LastError); }
            try { return QueryHandle(h, name); } finally { CloseServiceHandle(h); }
        }
        static SvcDef QueryHandle(IntPtr h, string name)
        {
            SvcDef d = new SvcDef(); d.name = name;
            List<string> errs = new List<string>();
            uint need;
            QueryServiceConfigW(h, IntPtr.Zero, 0, out need);
            uint size = Math.Max(need, 64);
            IntPtr buf = Marshal.AllocHGlobal((int)size);
            try
            {
                if (!QueryServiceConfigW(h, buf, size, out need)) errs.Add("QueryServiceConfigW " + Marshal.GetLastWin32Error());
                else
                {
                    QSC q = (QSC)Marshal.PtrToStructure(buf, typeof(QSC));
                    SvcConfig c = new SvcConfig();
                    c.service_type = q.type; c.start_type = q.start; c.error_control = q.err; c.binary_path = Str(q.bin);
                    c.load_order_group = Str(q.group); c.tag_id = q.tag; c.dependencies = MultiSz(q.deps);
                    c.service_start_name = Str(q.startName); c.display_name = Str(q.display);
                    d.config = c;
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
            SvcConfig2 c2 = new SvcConfig2();
            IntPtr p;
            p = Q2(h, 1, errs); if (p != IntPtr.Zero) { c2.description = Str(Marshal.ReadIntPtr(p)); Marshal.FreeHGlobal(p); }
            p = Q2(h, 2, errs);
            if (p != IntPtr.Zero)
            {
                SFA f = (SFA)Marshal.PtrToStructure(p, typeof(SFA));
                FailureActions fa = new FailureActions(); fa.reset_period = f.reset; fa.reboot_msg = Str(f.reboot); fa.command = Str(f.cmd);
                List<FailAction> al = new List<FailAction>();
                for (int i = 0; i < f.c; i++) { FailAction a = new FailAction(); a.type = (uint)Marshal.ReadInt32(f.actions, i * 8); a.delay_ms = (uint)Marshal.ReadInt32(f.actions, i * 8 + 4); al.Add(a); }
                fa.actions = al.ToArray(); c2.failure_actions = fa; Marshal.FreeHGlobal(p);
            }
            p = Q2(h, 3, errs); if (p != IntPtr.Zero) { c2.delayed_auto_start = Marshal.ReadInt32(p) != 0; Marshal.FreeHGlobal(p); }
            p = Q2(h, 4, errs); if (p != IntPtr.Zero) { c2.failure_actions_flag = Marshal.ReadInt32(p) != 0; Marshal.FreeHGlobal(p); }
            p = Q2(h, 5, errs); if (p != IntPtr.Zero) { c2.service_sid_type = (uint)Marshal.ReadInt32(p); Marshal.FreeHGlobal(p); }
            p = Q2(h, 6, errs); if (p != IntPtr.Zero) { c2.required_privileges = MultiSz(Marshal.ReadIntPtr(p)); Marshal.FreeHGlobal(p); }
            p = Q2(h, 7, errs); if (p != IntPtr.Zero) { c2.preshutdown_timeout_ms = (uint)Marshal.ReadInt32(p); Marshal.FreeHGlobal(p); }
            p = Q2(h, 8, errs);
            if (p != IntPtr.Zero)
            {
                STI ti = (STI)Marshal.PtrToStructure(p, typeof(STI));
                List<Trigger> tl = new List<Trigger>();
                int stSize = Marshal.SizeOf(typeof(ST)); int sdiSize = Marshal.SizeOf(typeof(SDI));
                for (int i = 0; i < ti.c; i++)
                {
                    ST st = (ST)Marshal.PtrToStructure(new IntPtr(ti.triggers.ToInt64() + i * stSize), typeof(ST));
                    Trigger t = new Trigger(); t.type = st.type; t.action = st.action;
                    if (st.subtype != IntPtr.Zero) { byte[] g = new byte[16]; Marshal.Copy(st.subtype, g, 0, 16); t.subtype = new Guid(g).ToString("B"); }
                    List<TriggerData> dl = new List<TriggerData>();
                    for (int j = 0; j < st.c; j++)
                    {
                        SDI di = (SDI)Marshal.PtrToStructure(new IntPtr(st.data.ToInt64() + j * sdiSize), typeof(SDI));
                        byte[] db = new byte[di.cb]; if (di.cb > 0) Marshal.Copy(di.p, db, 0, (int)di.cb);
                        TriggerData td = new TriggerData(); td.type = di.type; td.hex = Reg.Hex(db); dl.Add(td);
                    }
                    t.data = dl.ToArray(); tl.Add(t);
                }
                c2.triggers = tl.ToArray(); Marshal.FreeHGlobal(p);
            }
            p = Q2(h, 12, errs); if (p != IntPtr.Zero) { c2.launch_protected = (uint)Marshal.ReadInt32(p); Marshal.FreeHGlobal(p); }
            d.config2 = c2;
            IntPtr sb = Marshal.AllocHGlobal(64);
            try { if (QueryServiceStatusEx(h, 0, sb, 64, out need)) d.state = Marshal.ReadInt32(sb, 4); else errs.Add("QueryServiceStatusEx " + Marshal.GetLastWin32Error()); }
            finally { Marshal.FreeHGlobal(sb); }
            QueryServiceObjectSecurity(h, 7, IntPtr.Zero, 0, out need);
            if (need > 0)
            {
                uint sz = need;
                IntPtr sd = Marshal.AllocHGlobal((int)sz);
                try
                {
                    if (QueryServiceObjectSecurity(h, 7, sd, sz, out need)) { byte[] sdb = new byte[sz]; Marshal.Copy(sd, sdb, 0, (int)sz); d.sddl = new RawSecurityDescriptor(sdb, 0).GetSddlForm(AccessControlSections.All); }
                    else errs.Add("QueryServiceObjectSecurity " + Marshal.GetLastWin32Error());
                }
                finally { Marshal.FreeHGlobal(sd); }
            }
            else errs.Add("QueryServiceObjectSecurity size " + Marshal.GetLastWin32Error());
            d.errors = errs.ToArray();
            return d;
        }
        public static int Create(SvcDef d, string password)
        {
            IntPtr m = Mgr(1 | 2);
            try
            {
                SvcConfig c = d.config;
                string deps = null;
                if (c.dependencies != null && c.dependencies.Length > 0) deps = string.Join("\0", c.dependencies) + "\0";
                string grp = string.IsNullOrEmpty(c.load_order_group) ? null : c.load_order_group;
                IntPtr h = CreateServiceW(m, d.name, c.display_name, QUERY_STATUS, c.service_type, c.start_type, c.error_control, c.binary_path, grp, IntPtr.Zero, deps, c.service_start_name, password);
                if (h == IntPtr.Zero) return Marshal.GetLastWin32Error();
                CloseServiceHandle(h);
                return 0;
            }
            finally { CloseServiceHandle(m); }
        }
        public static int CreateSimple(string name, string display, uint type, uint start, string bin, string account, string password)
        {
            IntPtr m = Mgr(1 | 2);
            try
            {
                IntPtr h = CreateServiceW(m, name, display, QUERY_STATUS, type, start, 1, bin, null, IntPtr.Zero, null, account, password);
                if (h == IntPtr.Zero) return Marshal.GetLastWin32Error();
                CloseServiceHandle(h);
                return 0;
            }
            finally { CloseServiceHandle(m); }
        }
        static bool Want(string[] only, string item) { return only == null || Array.IndexOf(only, item) >= 0; }
        static IntPtr Keep(List<IntPtr> mem, IntPtr p) { mem.Add(p); return p; }
        static IntPtr Zeroed(List<IntPtr> mem, int n) { IntPtr p = Marshal.AllocHGlobal(n); for (int i = 0; i < n; i++) Marshal.WriteByte(p, i, 0); mem.Add(p); return p; }
        static int Set2(IntPtr h, uint level, IntPtr info) { return ChangeServiceConfig2W(h, level, info) ? 0 : Marshal.GetLastWin32Error(); }
        static int SetDword(IntPtr h, uint level, uint v, List<IntPtr> mem) { IntPtr p = Zeroed(mem, 8); Marshal.WriteInt32(p, (int)v); return Set2(h, level, p); }
        public static Dictionary<string, int> ApplyConfig2(string name, SvcConfig2 c2, string[] only)
        {
            Dictionary<string, int> r = new Dictionary<string, int>();
            IntPtr h = OpenHandle(name, CHANGE_CONFIG | QUERY_CONFIG | START);
            if (h == IntPtr.Zero) { r["open"] = LastError; return r; }
            List<IntPtr> mem = new List<IntPtr>();
            try
            {
                if (c2.description != null && Want(only, "description"))
                {
                    IntPtr s = Keep(mem, Marshal.StringToHGlobalUni(c2.description)); IntPtr p = Zeroed(mem, IntPtr.Size); Marshal.WriteIntPtr(p, s);
                    r["description"] = Set2(h, 1, p);
                }
                if (c2.failure_actions != null && Want(only, "failure_actions"))
                {
                    FailureActions fa = c2.failure_actions;
                    SFA f = new SFA(); f.reset = fa.reset_period;
                    f.reboot = fa.reboot_msg == null ? IntPtr.Zero : Keep(mem, Marshal.StringToHGlobalUni(fa.reboot_msg));
                    f.cmd = fa.command == null ? IntPtr.Zero : Keep(mem, Marshal.StringToHGlobalUni(fa.command));
                    int n = fa.actions == null ? 0 : fa.actions.Length;
                    f.c = (uint)n; f.actions = Zeroed(mem, Math.Max(8, n * 8));
                    for (int i = 0; i < n; i++) { Marshal.WriteInt32(f.actions, i * 8, (int)fa.actions[i].type); Marshal.WriteInt32(f.actions, i * 8 + 4, (int)fa.actions[i].delay_ms); }
                    IntPtr p = Zeroed(mem, Marshal.SizeOf(typeof(SFA))); Marshal.StructureToPtr(f, p, false);
                    r["failure_actions"] = Set2(h, 2, p);
                }
                if (c2.failure_actions_flag.HasValue && Want(only, "failure_actions_flag")) r["failure_actions_flag"] = SetDword(h, 4, c2.failure_actions_flag.Value ? 1u : 0u, mem);
                if (c2.delayed_auto_start.HasValue && Want(only, "delayed_auto_start")) r["delayed_auto_start"] = SetDword(h, 3, c2.delayed_auto_start.Value ? 1u : 0u, mem);
                if (c2.service_sid_type.HasValue && Want(only, "service_sid_type")) r["service_sid_type"] = SetDword(h, 5, c2.service_sid_type.Value, mem);
                if (c2.required_privileges != null && Want(only, "required_privileges"))
                {
                    string ms = string.Join("\0", c2.required_privileges) + "\0";
                    IntPtr s = Keep(mem, Marshal.StringToHGlobalUni(ms)); IntPtr p = Zeroed(mem, IntPtr.Size); Marshal.WriteIntPtr(p, s);
                    r["required_privileges"] = Set2(h, 6, p);
                }
                if (c2.preshutdown_timeout_ms.HasValue && Want(only, "preshutdown_timeout_ms")) r["preshutdown_timeout_ms"] = SetDword(h, 7, c2.preshutdown_timeout_ms.Value, mem);
                if (c2.triggers != null && Want(only, "triggers"))
                {
                    int n = c2.triggers.Length; int stSize = Marshal.SizeOf(typeof(ST)); int sdiSize = Marshal.SizeOf(typeof(SDI));
                    IntPtr arr = Zeroed(mem, Math.Max(stSize, n * stSize));
                    for (int i = 0; i < n; i++)
                    {
                        Trigger t = c2.triggers[i];
                        ST st = new ST(); st.type = t.type; st.action = t.action;
                        if (t.subtype != null) { st.subtype = Zeroed(mem, 16); Marshal.Copy(new Guid(t.subtype).ToByteArray(), 0, st.subtype, 16); }
                        int dn = t.data == null ? 0 : t.data.Length; st.c = (uint)dn;
                        if (dn > 0)
                        {
                            st.data = Zeroed(mem, dn * sdiSize);
                            for (int j = 0; j < dn; j++)
                            {
                                byte[] db = Reg.Unhex(t.data[j].hex); SDI di = new SDI(); di.type = t.data[j].type; di.cb = (uint)db.Length;
                                di.p = Zeroed(mem, Math.Max(1, db.Length)); if (db.Length > 0) Marshal.Copy(db, 0, di.p, db.Length);
                                Marshal.StructureToPtr(di, new IntPtr(st.data.ToInt64() + j * sdiSize), false);
                            }
                        }
                        Marshal.StructureToPtr(st, new IntPtr(arr.ToInt64() + i * stSize), false);
                    }
                    STI ti = new STI(); ti.c = (uint)n; ti.triggers = n > 0 ? arr : IntPtr.Zero;
                    IntPtr p = Zeroed(mem, Marshal.SizeOf(typeof(STI))); Marshal.StructureToPtr(ti, p, false);
                    r["triggers"] = Set2(h, 8, p);
                }
                if (c2.launch_protected.HasValue && Want(only, "launch_protected")) r["launch_protected"] = SetDword(h, 12, c2.launch_protected.Value, mem);
            }
            finally { foreach (IntPtr x in mem) Marshal.FreeHGlobal(x); CloseServiceHandle(h); }
            return r;
        }
        public static int SetSecurity(string name, string sddl, uint si)
        {
            IntPtr h = OpenHandle(name, WRITE_DAC | WRITE_OWNER | READ_CONTROL);
            if (h == IntPtr.Zero) return LastError;
            try
            {
                RawSecurityDescriptor sd = new RawSecurityDescriptor(sddl);
                byte[] b = new byte[sd.BinaryLength]; sd.GetBinaryForm(b, 0);
                return SetServiceObjectSecurity(h, si, b) ? 0 : Marshal.GetLastWin32Error();
            }
            finally { CloseServiceHandle(h); }
        }
    }
}
'@

# ----------------------------------------------------------------------------------------------- helpers

$OutDir = Join-Path $RigOut $Run
$FwRel = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
$SvcRel = 'SYSTEM\CurrentControlSet\Services'
$TcRel = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'
$Utf8 = New-Object System.Text.UTF8Encoding($false)

function Save-Json($Object, [string]$Name, [int]$Depth = 20) {
    [IO.File]::WriteAllText((Join-Path $OutDir $Name), (ConvertTo-Json -InputObject $Object -Depth $Depth), $Utf8)
}
function Read-Json([string]$Name) { [IO.File]::ReadAllText((Join-Path $OutDir $Name)) | ConvertFrom-Json }

function Err($E) {
    $x = $E
    if ($x -is [System.Management.Automation.ErrorRecord]) { $x = $x.Exception }
    while ($x.InnerException) { $x = $x.InnerException }
    $code = '0x{0:X8}' -f $x.HResult
    if ($x -is [System.Management.ManagementException]) { $code = "WBEM $($x.ErrorCode)" }
    elseif ($x.GetType().FullName -eq 'Microsoft.Management.Infrastructure.CimException') { $code = "MI $($x.NativeErrorCode)/$($x.StatusCode)" }
    ("$code " + ("$($x.Message)" -replace '\s+', ' ')).Trim()
}

function Wait-Until([scriptblock]$Cond, [int]$Ms = 5000) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        if (& $Cond) { return $true }
        if ($sw.ElapsedMilliseconds -ge $Ms) { return $false }
        Start-Sleep -Milliseconds 200
    }
}

# Multiset difference of two string lists: '-x' only in A, '+x' only in B (ordinal, sorted).
function Compare-Multiset([string[]]$A, [string[]]$B) {
    $d = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)
    foreach ($x in @($A)) { if ($null -eq $x) { continue }; if ($d.ContainsKey($x)) { $d[$x]++ } else { $d[$x] = 1 } }
    foreach ($x in @($B)) { if ($null -eq $x) { continue }; if ($d.ContainsKey($x)) { $d[$x]-- } else { $d[$x] = -1 } }
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($k in $d.Keys) { $keys.Add($k) }
    $keys.Sort([StringComparer]::Ordinal)
    $out = New-Object System.Collections.ArrayList
    foreach ($k in $keys) {
        $n = $d[$k]
        if ($n -gt 0) { for ($i = 0; $i -lt $n; $i++) { [void]$out.Add("-$k") } }
        elseif ($n -lt 0) { for ($i = 0; $i -lt -$n; $i++) { [void]$out.Add("+$k") } }
    }
    $out.ToArray()
}

function Get-RegString([string]$Hex) { if (-not $Hex) { return '' }; [Text.Encoding]::Unicode.GetString([PurgeSpike.Reg]::Unhex($Hex)).TrimEnd([char]0) }

function Format-Short([string]$Hex) { if ($null -eq $Hex) { return '' }; if ($Hex.Length -gt 48) { $Hex.Substring(0, 48) + '...' } else { $Hex } }

# Diff of two registry trees ([PurgeSpike.RegKeyCap[]], or the same deserialised from JSON). Entries:
# {key, name, kind (key_missing|key_extra|missing|extra|type|data|error), before, after}.
function Compare-RegTree($A, $B) {
    $out = New-Object System.Collections.ArrayList
    $ka = @{}; $kb = @{}
    foreach ($k in @($A)) { if ($k) { $ka["$($k.path)"] = $k } }
    foreach ($k in @($B)) { if ($k) { $kb["$($k.path)"] = $k } }
    foreach ($p in @($ka.Keys | Sort-Object)) {
        if (-not $kb.ContainsKey($p)) { [void]$out.Add([ordered]@{ key = $p; name = $null; kind = 'key_missing'; before = $null; after = $null }); continue }
        if ("$($ka[$p].error)" -ne "$($kb[$p].error)") { [void]$out.Add([ordered]@{ key = $p; name = $null; kind = 'error'; before = $ka[$p].error; after = $kb[$p].error }) }
        $va = @{}; foreach ($v in @($ka[$p].values)) { if ($v) { $va["$($v.name)"] = $v } }
        $vb = @{}; foreach ($v in @($kb[$p].values)) { if ($v) { $vb["$($v.name)"] = $v } }
        foreach ($n in @($va.Keys | Sort-Object)) {
            if (-not $vb.ContainsKey($n)) { [void]$out.Add([ordered]@{ key = $p; name = $n; kind = 'missing'; before = $va[$n]; after = $null }) }
            elseif ([uint32]$va[$n].type -ne [uint32]$vb[$n].type) { [void]$out.Add([ordered]@{ key = $p; name = $n; kind = 'type'; before = $va[$n]; after = $vb[$n] }) }
            elseif ("$($va[$n].hex)" -cne "$($vb[$n].hex)") { [void]$out.Add([ordered]@{ key = $p; name = $n; kind = 'data'; before = $va[$n]; after = $vb[$n] }) }
        }
        foreach ($n in @($vb.Keys | Sort-Object)) { if (-not $va.ContainsKey($n)) { [void]$out.Add([ordered]@{ key = $p; name = $n; kind = 'extra'; before = $null; after = $vb[$n] }) } }
    }
    foreach ($p in @($kb.Keys | Sort-Object)) { if (-not $ka.ContainsKey($p)) { [void]$out.Add([ordered]@{ key = $p; name = $null; kind = 'key_extra'; before = $null; after = $null }) } }
    $out.ToArray()
}

$RegTypeNames = @{ 0 = 'REG_NONE'; 1 = 'REG_SZ'; 2 = 'REG_EXPAND_SZ'; 3 = 'REG_BINARY'; 4 = 'REG_DWORD'; 7 = 'REG_MULTI_SZ'; 11 = 'REG_QWORD' }
function Format-RegVal($V) { if (-not $V) { return '-' }; $t = $RegTypeNames[[int]$V.type]; if (-not $t) { $t = "type$($V.type)" }; "${t}:$(Format-Short $V.hex)" }
function Format-RegDiff($D) {
    $n = if ($null -eq $D.name) { '' } elseif ("$($D.name)" -eq '') { '(default)' } else { "$($D.name)" }
    $k = "$($D.key)"
    switch ($D.kind) {
        'key_missing' { "$k\ key missing" }
        'key_extra' { "$k\ key extra" }
        'error' { "$k\ read error $($D.before) -> $($D.after)" }
        'missing' { "$k|$n missing (was $(Format-RegVal $D.before))" }
        'extra' { "$k|$n extra ($(Format-RegVal $D.after))" }
        default { "$k|$n $($D.kind) $(Format-RegVal $D.before) -> $(Format-RegVal $D.after)" }
    }
}
function Get-RegDiffName($D) { $n = if ("$($D.name)" -eq '') { '(default)' } else { "$($D.name)" }; if ($null -eq $D.name) { "$($D.key)\" } else { "$($D.key)|$n" } }

# Writes back every value (and creates every key) of the backed-up tree $Orig that is absent or different in the
# live tree under $Base. Never deletes anything. Returns the names written with the RegSetValueExW result.
function Invoke-WriteBack([string]$Base, $Orig) {
    $cur = [PurgeSpike.Reg]::Tree($Base)
    $ci = @{}; $ck = @{}
    foreach ($k in @($cur)) { if ($k) { $ck["$($k.path)"] = $true; foreach ($v in @($k.values)) { if ($v) { $ci["$($k.path)|$($v.name)"] = $v } } } }
    $done = New-Object System.Collections.ArrayList
    foreach ($k in @($Orig)) {
        if (-not $k) { continue }
        $sub = if ("$($k.path)") { "$Base\$($k.path)" } else { $Base }
        if (-not $ck.ContainsKey("$($k.path)")) { try { [PurgeSpike.Reg]::CreateKey($sub); [void]$done.Add("$($k.path)\ created") } catch { [void]$done.Add("$($k.path)\ create failed: $(Err $_)") } }
        foreach ($v in @($k.values)) {
            if (-not $v) { continue }
            $c = $ci["$($k.path)|$($v.name)"]
            if (-not $c -or [uint32]$c.type -ne [uint32]$v.type -or "$($c.hex)" -cne "$($v.hex)") {
                try { $e = [PurgeSpike.Reg]::Write($sub, "$($v.name)", [uint32]$v.type, "$($v.hex)") } catch { $e = Err $_ }
                [void]$done.Add("$($k.path)|$($v.name) -> $e")
            }
        }
    }
    $done.ToArray()
}

function Get-HostInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [ordered]@{ caption = "$($os.Caption)"; edition = "$($cv.EditionID)"; version = "$($os.Version)"; build = "$($cv.CurrentBuildNumber)"; ubr = [int]$cv.UBR
        display_version = "$($cv.DisplayVersion)"; os_build = "$($cv.CurrentBuildNumber).$($cv.UBR)"; powershell = "$($PSVersionTable.PSVersion)" }
}

# ----------------------------------------------------------------------------------------------- firewall

function Get-FwRaw([string]$Id) {
    $v = [PurgeSpike.Reg]::ReadValue($FwRel, $Id)
    if (-not $v) { return $null }
    [pscustomobject]@{ id = $Id; type = [int]$v.type; hex = $v.hex; rule = (Get-RegString $v.hex) }
}
function Get-FwNames {
    $b = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    $k = $b.OpenSubKey($FwRel)
    try { @($k.GetValueNames()) } finally { $k.Close(); $b.Close() }
}
# C-OBJECT parse_firewall_rule: first segment = version; every other non-empty segment key=value (first '=').
function ConvertFrom-FwRule([string]$Raw) {
    $segs = $Raw.Split('|')
    $fields = New-Object System.Collections.ArrayList
    for ($i = 1; $i -lt $segs.Count; $i++) {
        $s = $segs[$i]
        if ($s -eq '') { continue }
        $j = $s.IndexOf('=')
        if ($j -lt 0) { throw "segment $i without '='" }
        [void]$fields.Add([pscustomobject]@{ k = $s.Substring(0, $j); v = $s.Substring($j + 1) })
    }
    [pscustomobject]@{ version = $segs[0]; fields = $fields.ToArray() }
}
function Get-FwMultiset($P) { @($P.fields | ForEach-Object { $_.k.ToUpperInvariant() + '=' + $_.v }) }

# Rule string fields -> MSFT_NetFirewallRule properties (instance) and filter values (operation options / IWbemContext),
# the split NetFirewallRule.cmdletDefinition.cdxml uses for New-NetFirewallRule (cim:CreateInstance).
function ConvertTo-FwMap($P) {
    $props = [ordered]@{}; $opts = [ordered]@{}; $unm = New-Object System.Collections.ArrayList
    $prof = 0; $ift = 0; $la = @(); $ra = @(); $lp = @(); $rp = @(); $icmp = @(); $edge = $false; $defer = $null
    foreach ($f in $P.fields) {
        $k = $f.k.ToUpperInvariant(); $v = $f.v
        if ($k -eq 'ACTION') { if ($v -ceq 'Allow') { $props.Action = [uint16]2 } elseif ($v -ceq 'Block') { $props.Action = [uint16]4 } else { [void]$unm.Add("$($f.k)=$v") } }
        elseif ($k -eq 'ACTIVE') { $props.Enabled = [uint16]$(if ($v -ceq 'TRUE') { 1 } else { 2 }) }
        elseif ($k -eq 'DIR') { $props.Direction = [uint16]$(if ($v -ceq 'In') { 1 } else { 2 }) }
        elseif ($k -eq 'PROFILE') { $b = @{ Domain = 1; Private = 2; Public = 4 }[$v]; if ($b) { $prof = $prof -bor $b } else { [void]$unm.Add("$($f.k)=$v") } }
        elseif ($k -eq 'NAME') { $props.ElementName = $v }
        elseif ($k -eq 'DESC') { $props.Description = $v }
        elseif ($k -eq 'EMBEDCTXT') { $props.RuleGroup = $v }
        elseif ($k -eq 'EDGE') { $edge = ($v -ceq 'TRUE') }
        elseif ($k -eq 'DEFER') { $defer = $v }
        elseif ($k -eq 'LSM') { $props.LooseSourceMapping = ($v -ceq 'TRUE') }
        elseif ($k -eq 'LOM') { $props.LocalOnlyMapping = ($v -ceq 'TRUE') }
        elseif ($k -eq 'PROTOCOL') { $opts.Protocol = $v }
        elseif ($k -eq 'LPORT' -or $k -like 'LPORT2_*') { $lp += $v }
        elseif ($k -eq 'RPORT' -or $k -like 'RPORT2_*') { $rp += $v }
        elseif ($k -eq 'LA4' -or $k -eq 'LA6') { if ($la -notcontains $v) { $la += $v } }
        elseif ($k -eq 'RA4' -or $k -eq 'RA6') { if ($ra -notcontains $v) { $ra += $v } }
        elseif ($k -eq 'APP') { $opts.Program = $v }
        elseif ($k -eq 'SVC') { $opts.Service = $v }
        elseif ($k -eq 'IFTYPE') { $b = @{ Lan = 1; Wireless = 2; RemoteAccess = 4 }[$v]; if ($b) { $ift = $ift -bor $b } else { [void]$unm.Add("$($f.k)=$v") } }
        elseif ($k -eq 'ICMP4' -or $k -eq 'ICMP6') { $icmp += $v }
        else { [void]$unm.Add("$($f.k)=$v") }
    }
    if ($prof) { $props.Profiles = [uint16]$prof }
    if ($defer -ceq 'User') { $props.EdgeTraversalPolicy = [uint16]2 } elseif ($defer -ceq 'App') { $props.EdgeTraversalPolicy = [uint16]3 } elseif ($edge) { $props.EdgeTraversalPolicy = [uint16]1 }
    if ($lp.Count) { $opts.LocalPort = [string[]]$lp }
    if ($rp.Count) { $opts.RemotePort = [string[]]$rp }
    if ($la.Count) { $opts.LocalAddress = [string[]]$la }
    if ($ra.Count) { $opts.RemoteAddress = [string[]]$ra }
    if ($icmp.Count) { $opts.IcmpType = [string[]]$icmp }
    if ($ift) { $opts.InterfaceType = [uint32]$ift }
    [pscustomobject]@{ props = $props; options = $opts; unmapped = $unm.ToArray() }
}

function New-FwCtx($Options) {
    $c = New-Object System.Management.ManagementNamedValueCollection
    $c.Add('PolicyStore', 'PersistentStore')
    if ($Options) { foreach ($k in $Options.Keys) { $c.Add($k, $Options[$k]) } }
    , $c
}
function Get-FwScope { $s = New-Object System.Management.ManagementScope('\\.\root\StandardCimv2'); $s.Connect(); $s }

# C-WIN delete_by_instance_id: IWbemServices ExecQuery (WQL, InstanceID literal escaped) + DeleteInstance, both with an
# IWbemContext PolicyStore=PersistentStore; deletes only when exactly one instance matches.
function Remove-FwById([string]$Id) {
    $r = [ordered]@{ matched = $null; deleted = 0; error = $null; value_gone = $false }
    try {
        $esc = $Id.Replace('\', '\\').Replace("'", "\'")
        $eo = New-Object System.Management.EnumerationOptions
        $eo.Context = (New-FwCtx $null)
        $q = New-Object System.Management.ObjectQuery("SELECT * FROM MSFT_NetFirewallRule WHERE InstanceID = '$esc'")
        $s = New-Object System.Management.ManagementObjectSearcher((Get-FwScope), $q, $eo)
        $m = @(); foreach ($o in $s.Get()) { $m += $o }
        $r.matched = $m.Count
        if ($m.Count -eq 1) {
            $do = New-Object System.Management.DeleteOptions
            $do.Context = (New-FwCtx $null)
            $m[0].Delete($do)
            $r.deleted = 1
        }
    } catch { $r.error = Err $_ }
    $r.value_gone = Wait-Until { -not (Get-FwRaw $Id) } 5000
    $r
}

# (cim_create, the Rust path) IWbemServices::PutInstance(WBEM_FLAG_CREATE_ONLY) of a spawned MSFT_NetFirewallRule with
# InstanceID set; filter fields travel as IWbemContext values next to PolicyStore (System.Management = WMI COM).
function New-FwByWmi([string]$Id, $Map) {
    $ctx = New-FwCtx $Map.options
    $cls = New-Object System.Management.ManagementClass((Get-FwScope), (New-Object System.Management.ManagementPath('MSFT_NetFirewallRule')), (New-Object System.Management.ObjectGetOptions($ctx)))
    $inst = $cls.CreateInstance()
    $inst['InstanceID'] = $Id
    foreach ($k in $Map.props.Keys) { $inst[$k] = $Map.props[$k] }
    $po = New-Object System.Management.PutOptions($ctx)
    $po.Type = [System.Management.PutType]::CreateOnly
    [void]$inst.Put($po)
}
# MI CreateInstance with custom operation options (what New-NetFirewallRule's CDXML does); -NoOptions: rule only.
function New-FwByMi([string]$Id, $Map, [switch]$NoOptions) {
    $sess = [Microsoft.Management.Infrastructure.CimSession]::Create($null)
    try {
        $opt = New-Object Microsoft.Management.Infrastructure.Options.CimOperationOptions
        $opt.SetCustomOption('PolicyStore', 'PersistentStore', $false)
        if (-not $NoOptions) {
            foreach ($k in $Map.options.Keys) {
                $v = $Map.options[$k]
                if ($v -is [array]) { $opt.SetCustomOption($k, [object]([string[]]$v), [Microsoft.Management.Infrastructure.CimType]::StringArray, $false) }
                elseif ($v -is [uint32]) { $opt.SetCustomOption($k, [object]$v, [Microsoft.Management.Infrastructure.CimType]::UInt32, $false) }
                else { $opt.SetCustomOption($k, [string]$v, $false) }
            }
        }
        # Client-side instance holding only the properties that are set (as the CDXML adapter builds it).
        $inst = New-Object Microsoft.Management.Infrastructure.CimInstance('MSFT_NetFirewallRule', 'root/StandardCimv2')
        $inst.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create('InstanceID', $Id, [Microsoft.Management.Infrastructure.CimType]::String, [Microsoft.Management.Infrastructure.CimFlags]::None))
        foreach ($k in $Map.props.Keys) {
            $v = $Map.props[$k]
            $ct = if ($v -is [uint16]) { 'UInt16' } elseif ($v -is [bool]) { 'Boolean' } else { 'String' }
            $inst.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create($k, $v, [Microsoft.Management.Infrastructure.CimType]$ct, [Microsoft.Management.Infrastructure.CimFlags]::None))
        }
        [void]$sess.CreateInstance('root/StandardCimv2', $inst, $opt)
    } finally { $sess.Dispose() }
}
# The design's literal (a): create the rule instance, then ModifyInstance of its associated filter instances.
function New-FwByCimFilters([string]$Id, $Map) {
    New-FwByWmi -Id $Id -Map ([pscustomobject]@{ props = $Map.props; options = [ordered]@{}; unmapped = @() })
    $null = Wait-Until { Get-FwRaw $Id } 5000
    $r = Get-NetFirewallRule -Name $Id -PolicyStore PersistentStore -ErrorAction Stop
    $o = $Map.options
    if ($o.Contains('Program')) { $r | Get-NetFirewallApplicationFilter | Set-NetFirewallApplicationFilter -Program $o['Program'] -ErrorAction Stop }
    if ($o.Contains('Service')) { $r | Get-NetFirewallServiceFilter | Set-NetFirewallServiceFilter -Service $o['Service'] -ErrorAction Stop }
    $pp = @{}; foreach ($n in 'Protocol', 'LocalPort', 'RemotePort', 'IcmpType') { if ($o.Contains($n)) { $pp[$n] = $o[$n] } }
    if ($pp.Count) { $r | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter @pp -ErrorAction Stop }
    $ap = @{}; foreach ($n in 'LocalAddress', 'RemoteAddress') { if ($o.Contains($n)) { $ap[$n] = $o[$n] } }
    if ($ap.Count) { $r | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter @ap -ErrorAction Stop }
    if ($o.Contains('InterfaceType')) { $r | Get-NetFirewallInterfaceTypeFilter | Set-NetFirewallInterfaceTypeFilter -InterfaceType ([int]$o['InterfaceType']) -ErrorAction Stop }
}
# (b) New-NetFirewallRule -Name <old id> with parameters derived from the string.
function New-FwByCmdlet([string]$Id, $Map) {
    $p = @{ Name = $Id; PolicyStore = 'PersistentStore'; ErrorAction = 'Stop' }
    $pm = @{ ElementName = 'DisplayName'; Description = 'Description'; RuleGroup = 'Group'; Enabled = 'Enabled'; Profiles = 'Profile'; Direction = 'Direction'
        Action = 'Action'; EdgeTraversalPolicy = 'EdgeTraversalPolicy'; LooseSourceMapping = 'LooseSourceMapping'; LocalOnlyMapping = 'LocalOnlyMapping' }
    foreach ($k in $Map.props.Keys) { $p[$pm[$k]] = $Map.props[$k] }
    foreach ($k in $Map.options.Keys) { $p[$k] = $Map.options[$k] }
    $null = New-NetFirewallRule @p
}

function Compare-FwRule($Orig, $After) {
    $po = ConvertFrom-FwRule $Orig.rule
    $pa = ConvertFrom-FwRule $After.rule
    $diff = @(Compare-Multiset (Get-FwMultiset $po) (Get-FwMultiset $pa))
    [ordered]@{ name_equal = ($After.id -ceq $Orig.id); same_rule = ($diff.Count -eq 0); raw_equal = ("$($After.hex)" -ceq "$($Orig.hex)"); type_equal = ($After.type -eq $Orig.type)
        version_before = $po.version; version_after = $pa.version; diff = $diff; after = $After.rule }
}

$FwSpecs = @(
    [ordered]@{ case = 'fw1-program'; p = @{ DisplayName = 'PurgeSpike F1 program'; Direction = 'Inbound'; Action = 'Allow'; Program = 'C:\Program Files\PurgeSpike\app1.exe'; Protocol = 'TCP'; EdgeTraversalPolicy = 'DeferToUser' } }
    [ordered]@{ case = 'fw2-port'; p = @{ DisplayName = 'PurgeSpike F2 port'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = @('8080', '8090-8095') } }
    [ordered]@{ case = 'fw3-remote-address-list'; p = @{ DisplayName = 'PurgeSpike F3 remote'; Direction = 'Outbound'; Action = 'Block'; Protocol = 'UDP'; RemotePort = @('53')
            RemoteAddress = @('10.0.0.1', '192.168.1.0/24', '10.1.1.1-10.1.1.9', 'fe80::1', 'LocalSubnet') } }
    [ordered]@{ case = 'fw4-service'; p = @{ DisplayName = 'PurgeSpike F4 service'; Direction = 'Inbound'; Action = 'Allow'; Program = '%SystemRoot%\System32\svchost.exe'; Service = 'PurgeSpikeS1'; Protocol = 'TCP'; LocalPort = @('9000') } }
    [ordered]@{ case = 'fw5-interface-type-profile'; p = @{ DisplayName = 'PurgeSpike F5 iftype'; Direction = 'Inbound'; Action = 'Allow'; InterfaceType = 'Wireless, RemoteAccess'; Profile = 'Private, Public'; Enabled = 'False'; Program = 'C:\Program Files\PurgeSpike\app5.exe' } }
    [ordered]@{ case = 'fw6-group-description'; p = @{ DisplayName = 'PurgeSpike F6 group'; Group = 'PurgeSpike Group'; Description = 'Purge spike rule 6: a=b, c'; Direction = 'Outbound'; Action = 'Allow'; Program = 'C:\Program Files\PurgeSpike\app6.exe' } }
)
$FwControlSpec = [ordered]@{ case = 'fw-control'; p = @{ DisplayName = 'PurgeSpike FC control'; Group = 'PurgeSpike Group'; Description = 'Purge spike control rule (never deleted)'; Direction = 'Outbound'; Action = 'Allow'; Program = 'C:\Program Files\PurgeSpike\appc.exe' } }
$FwMethods = @('new_rule_name', 'cim_filters', 'mi_options', 'wmi_context')   # wmi_context last: the final state is the Rust path's

function Invoke-FirewallSpike {
    $res = [ordered]@{ delete_api = 'IWbemServices::ExecQuery("SELECT * FROM MSFT_NetFirewallRule WHERE InstanceID = ''<id>''") + DeleteInstance, namespace ROOT\StandardCimv2, IWbemContext PolicyStore=PersistentStore'
        methods = [ordered]@{
            wmi_context = 'IWbemServices::PutInstance(WBEM_FLAG_CREATE_ONLY) of MSFT_NetFirewallRule.SpawnInstance with InstanceID and the rule properties; filters (Program, Service, Protocol, LocalPort, RemotePort, LocalAddress, RemoteAddress, InterfaceType, IcmpType) as IWbemContext values beside PolicyStore=PersistentStore'
            mi_options = 'MI CreateInstance (CimSession) with the same split: filters as custom operation options (the New-NetFirewallRule CDXML mapping)'
            cim_filters = 'IWbemServices::PutInstance of the rule without filter values, then ModifyInstance of the associated MSFT_Net*Filter instances (Set-NetFirewall*Filter)'
            new_rule_name = 'New-NetFirewallRule -Name <old id> -PolicyStore PersistentStore with parameters derived from the string'
        }
        cases = (New-Object System.Collections.ArrayList); control = $null; duplicate = $null }
    foreach ($spec in @($FwSpecs) + @($FwControlSpec)) {
        $p = $spec.p
        $c = [ordered]@{ case = $spec.case; id = $null; created_with = 'New-NetFirewallRule'; create_error = $null; original = $null; reread_equal = $null; map = $null; methods = [ordered]@{} }
        try { $r = New-NetFirewallRule @p -PolicyStore PersistentStore -ErrorAction Stop; $c.id = "$($r.Name)" } catch { $c.create_error = Err $_ }
        if (-not $c.id) { [void]$res.cases.Add($c); continue }
        $null = Wait-Until { Get-FwRaw $c.id } 5000
        $orig = Get-FwRaw $c.id
        $c.original = $orig
        Start-Sleep -Milliseconds 500
        $orig2 = Get-FwRaw $c.id
        $c.reread_equal = ($orig2 -and $orig2.hex -ceq $orig.hex)
        Log "fw $($spec.case): id $($c.id) $($orig.rule)"
        if ($spec.case -eq 'fw-control') { $res.control = $c; continue }
        $parsed = ConvertFrom-FwRule $orig.rule
        $map = ConvertTo-FwMap $parsed
        $c.map = [ordered]@{ props = $map.props; options = $map.options; unmapped = $map.unmapped }
        foreach ($m in $FwMethods) {
            $mr = [ordered]@{ delete = $null; ok = $false; error = $null; new_ids = @(); name_equal = $false; same_rule = $false; raw_equal = $false; diff = @(); version_before = $null; version_after = $null; after = $null }
            $mr.delete = Remove-FwById $c.id
            if (-not $mr.delete.value_gone) { $mr.error = 'delete did not remove the registry value'; $c.methods[$m] = $mr; Log "fw $($spec.case) $m`: $($mr.error)"; continue }
            $before = Get-FwNames
            try {
                switch ($m) {
                    'wmi_context' { New-FwByWmi -Id $c.id -Map $map }
                    'mi_options' { New-FwByMi -Id $c.id -Map $map }
                    'cim_filters' { New-FwByCimFilters -Id $c.id -Map $map }
                    'new_rule_name' { New-FwByCmdlet -Id $c.id -Map $map }
                }
                $mr.ok = $true
            } catch { $mr.error = Err $_ }
            $null = Wait-Until { Get-FwRaw $c.id } 3000
            $new = @(Get-FwNames | Where-Object { $before -notcontains $_ })
            $mr.new_ids = $new
            $after = Get-FwRaw $c.id
            if (-not $after -and $new.Count -eq 1) { $after = Get-FwRaw $new[0] }
            if ($after) {
                $cmp = Compare-FwRule $orig $after
                foreach ($k in $cmp.Keys) { $mr[$k] = $cmp[$k] }
                if (-not $mr.name_equal) { $null = Remove-FwById $after.id }   # keep one rule per case
            } elseif (-not $mr.error) { $mr.error = 'no rule value after create' }
            Log "fw $($spec.case) $m`: ok=$($mr.ok) name_equal=$($mr.name_equal) same_rule=$($mr.same_rule) raw_equal=$($mr.raw_equal) diff=$($mr.diff -join ' ') err=$($mr.error)"
            $c.methods[$m] = $mr
            if (-not (Get-FwRaw $c.id)) {
                # The method did not leave a rule under the old id: put the original back for the next method.
                try { New-FwByCmdlet -Id $c.id -Map $map } catch { }
                $null = Wait-Until { Get-FwRaw $c.id } 3000
            }
        }
        [void]$res.cases.Add($c)
    }
    # Creating an id that exists: must fail and leave the rule as it is (undo AlreadyRestored / ObjectExists logic).
    $first = @($res.cases | Where-Object { $_.id })[0]
    if ($first) {
        $now = Get-FwRaw $first.id
        $map = ConvertTo-FwMap (ConvertFrom-FwRule $now.rule)
        $alt = [pscustomobject]@{ props = [ordered]@{}; options = [ordered]@{}; unmapped = @() }
        foreach ($k in $map.props.Keys) { $alt.props[$k] = $map.props[$k] }
        foreach ($k in $map.options.Keys) { $alt.options[$k] = $map.options[$k] }
        $alt.props.ElementName = 'PurgeSpike duplicate'
        $dup = [ordered]@{ id = $first.id; tries = [ordered]@{} }
        foreach ($m in 'wmi_context', 'mi_options', 'new_rule_name') {
            $t = [ordered]@{ ok = $false; error = $null; value_unchanged = $null; instances = $null }
            try { switch ($m) { 'wmi_context' { New-FwByWmi -Id $first.id -Map $alt } 'mi_options' { New-FwByMi -Id $first.id -Map $alt } 'new_rule_name' { New-FwByCmdlet -Id $first.id -Map $alt } }; $t.ok = $true } catch { $t.error = Err $_ }
            Start-Sleep -Milliseconds 500
            $t.value_unchanged = ("$((Get-FwRaw $first.id).hex)" -ceq "$($now.hex)")
            try { $t.instances = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Name -eq $first.id }).Count } catch { $t.instances = Err $_ }
            $dup.tries[$m] = $t
            Log "fw duplicate $m`: ok=$($t.ok) unchanged=$($t.value_unchanged) instances=$($t.instances) err=$($t.error)"
        }
        $res.duplicate = $dup
    }
    $res
}

# ----------------------------------------------------------------------------------------------- tasks

$TS = $null
function Connect-TS { if (-not $script:TS) { $script:TS = New-Object -ComObject Schedule.Service; $script:TS.Connect() }; $script:TS }
function Split-TaskPath([string]$Path) { $i = $Path.LastIndexOf('\'); [pscustomobject]@{ parent = $(if ($i -le 0) { '\' } else { $Path.Substring(0, $i) }); leaf = $Path.Substring($i + 1) } }
function Get-TaskFolder([string]$Parent, [switch]$Create) {
    $ts = Connect-TS
    try { return $ts.GetFolder($Parent) } catch { if (-not $Create) { throw } }
    $ts.GetFolder('\').CreateFolder($Parent.TrimStart('\'))
}
function Get-TaskObj([string]$Path) { $s = Split-TaskPath $Path; try { (Get-TaskFolder $s.parent).GetTask($s.leaf) } catch { $null } }
function Get-TaskCacheCap([string]$Path) {
    $tree = [PurgeSpike.Reg]::Tree("$TcRel\Tree$Path")
    $id = $null
    if ($tree) { $v = @($tree[0].values | Where-Object { $_.name -eq 'Id' })[0]; if ($v) { $id = Get-RegString $v.hex } }
    $tasks = $null
    if ($id) { $tasks = [PurgeSpike.Reg]::Tree("$TcRel\Tasks\$id") }
    [ordered]@{ id = $id; tree = $tree; tasks = $tasks }
}
function Get-TaskCap([string]$Path) {
    $t = Get-TaskObj $Path
    if (-not $t) { return $null }
    $c = [ordered]@{ path = $Path; xml = "$($t.Xml)"; sddl = $null; sddl_error = $null; enabled = [bool]$t.Enabled; taskcache = (Get-TaskCacheCap $Path); file = $null }
    try { $c.sddl = "$($t.GetSecurityDescriptor(7))" } catch { $c.sddl_error = Err $_ }
    $f = Join-Path $env:SystemRoot ('System32\Tasks' + $Path)
    try {
        $b = [IO.File]::ReadAllBytes($f)
        $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b)).Replace('-', '').ToLowerInvariant()
        $c.file = [ordered]@{ length = $b.Length; sha256 = $sha }
    } catch { $c.file = [ordered]@{ error = (Err $_) } }
    $c
}
# XML flattened to path=value lines (elements with text, attributes as /@name) for a multiset diff.
function Get-XmlLines([string]$Xml) {
    $d = New-Object System.Xml.XmlDocument
    $d.LoadXml($Xml)
    $out = New-Object System.Collections.ArrayList
    Add-XmlLines $d.DocumentElement '' $out
    $out.ToArray()
}
function Add-XmlLines($Node, [string]$Prefix, $Out) {
    $p = "$Prefix/$($Node.LocalName)"
    foreach ($a in @($Node.Attributes)) { if ($a -and $a.Name -notlike 'xmlns*') { [void]$Out.Add("$p/@$($a.LocalName)=$($a.Value)") } }
    $kids = @($Node.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })
    if ($kids.Count -eq 0) { [void]$Out.Add("$p=$($Node.InnerText)") }
    foreach ($k in $kids) { Add-XmlLines $k $p $Out }
}
function Get-DiffElement([string]$Line) { $s = $Line.Substring(1); $i = $s.IndexOf('='); if ($i -ge 0) { $s.Substring(0, $i) } else { $s } }

function Compare-TaskCap($A, $B) {
    $diff = @(Compare-Multiset (Get-XmlLines $A.xml) (Get-XmlLines $B.xml))
    $tc = @(Compare-RegTree $A.taskcache.tree $B.taskcache.tree | ForEach-Object { 'Tree' + (Format-RegDiff $_) }) + @(Compare-RegTree $A.taskcache.tasks $B.taskcache.tasks | ForEach-Object { 'Tasks\{id}' + (Format-RegDiff $_) })
    [ordered]@{ xml_equal = ($A.xml -ceq $B.xml); sddl_equal = ("$($A.sddl)" -ceq "$($B.sddl)"); enabled_equal = ($A.enabled -eq $B.enabled); diff = $diff
        diff_elements = @($diff | ForEach-Object { Get-DiffElement $_ } | Sort-Object -Unique); sddl_before = $A.sddl; sddl_after = $B.sddl
        taskcache_id_equal = ($A.taskcache.id -eq $B.taskcache.id); taskcache_diff = $tc; file_equal = ("$($A.file.sha256)" -eq "$($B.file.sha256)") }
}

$TaskUser = "$env:USERDOMAIN\$env:USERNAME"
$TaskSpecs = @(
    [ordered]@{ case = 'task1-exec'; path = '\PurgeSpikeT1'; actions = @(@{ kind = 'exec'; path = 'C:\Program Files\PurgeSpike\t1.exe'; args = '--update'; dir = 'C:\Program Files\PurgeSpike' }); trigger = 'daily'; logon = 3; user = $null; desc = 'Purge spike task 1'; date = '2026-11-16T10:00:00' }
    [ordered]@{ case = 'task2-hidden-two-actions'; path = '\PurgeSpikeT2'; hidden = $true; actions = @(@{ kind = 'exec'; path = 'C:\Program Files\PurgeSpike\t2a.exe'; args = '/a' }, @{ kind = 'exec'; path = 'C:\Program Files\PurgeSpike\t2b.exe'; args = '/b "quoted arg"' }); trigger = 'logon'; logon = 5; user = 'SYSTEM' }
    [ordered]@{ case = 'task3-com-handler'; path = '\PurgeSpikeT3'; disabled = $true; actions = @(@{ kind = 'com'; clsid = '{0E7D1D1B-5C1F-4B5C-9C21-6B5A1E9F7A11}'; data = 'spike-data' }); trigger = 'time'; logon = 4; user = 'BUILTIN\Users' }
    [ordered]@{ case = 'task4-s4u'; path = '\PurgeSpikeT4'; actions = @(@{ kind = 'exec'; path = 'C:\Program Files\PurgeSpike\t4.exe' }); trigger = 'time'; logon = 2; user = $TaskUser; runlevel = 1 }
    [ordered]@{ case = 'task5-subfolder-sddl'; path = '\PurgeSpikeVendor\T5'; actions = @(@{ kind = 'exec'; path = 'C:\Program Files\PurgeSpike\t5.exe'; args = '-x' }); trigger = 'daily'; logon = 3; user = $null; sddl = 'D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;AU)' }
)
$TaskControlSpec = [ordered]@{ case = 'task-control'; path = '\PurgeSpikeTC'; hidden = $true; actions = @(@{ kind = 'exec'; path = 'C:\Program Files\PurgeSpike\tc.exe'; args = '/c' }); trigger = 'logon'; logon = 5; user = 'SYSTEM' }
$TaskPasswordSpec = [ordered]@{ case = 'task6-stored-password'; path = '\PurgeSpikeT6'; actions = @(@{ kind = 'exec'; path = 'C:\Program Files\PurgeSpike\t6.exe' }); trigger = 'time'; logon = 1; user = "$env:COMPUTERNAME\purgespike" }

function Register-SpikeTask($Spec, $Password = $null) {
    $ts = Connect-TS
    $def = $ts.NewTask(0)
    $def.RegistrationInfo.Author = 'PurgeSpike Vendor'
    if ($Spec.desc) { $def.RegistrationInfo.Description = $Spec.desc }
    if ($Spec.date) { $def.RegistrationInfo.Date = $Spec.date }
    if ($Spec.disabled) { $def.Settings.Enabled = $false }
    if ($Spec.hidden) { $def.Settings.Hidden = $true }
    if ($Spec.runlevel) { $def.Principal.RunLevel = $Spec.runlevel }
    foreach ($a in $Spec.actions) {
        if ($a.kind -eq 'exec') { $x = $def.Actions.Create(0); $x.Path = $a.path; if ($a.args) { $x.Arguments = $a.args }; if ($a.dir) { $x.WorkingDirectory = $a.dir } }
        else { $x = $def.Actions.Create(5); $x.ClassId = $a.clsid; if ($a.data) { $x.Data = $a.data } }
    }
    switch ($Spec.trigger) {
        'daily' { $t = $def.Triggers.Create(2); $t.StartBoundary = '2026-01-01T03:00:00'; $t.DaysInterval = 1 }
        'logon' { $null = $def.Triggers.Create(9) }
        'time' { $t = $def.Triggers.Create(1); $t.StartBoundary = '2027-01-01T04:00:00' }
    }
    $s = Split-TaskPath $Spec.path
    $f = Get-TaskFolder $s.parent -Create
    if ($Spec.sddl) { $null = $f.RegisterTaskDefinition($s.leaf, $def, 2, $Spec.user, $Password, $Spec.logon, $Spec.sddl) }
    else { $null = $f.RegisterTaskDefinition($s.leaf, $def, 2, $Spec.user, $Password, $Spec.logon) }
}
# C-WIN register_xml: ITaskFolder::RegisterTask(path, xml, TASK_CREATE, user, password, logonType, sddl).
function Register-TaskXml([string]$Path, [string]$Xml, $Sddl = $null, $User = $null, $Password = $null, [int]$LogonType = 0) {
    $s = Split-TaskPath $Path
    $f = Get-TaskFolder $s.parent -Create
    if ($null -ne $Sddl) { $null = $f.RegisterTask($s.leaf, $Xml, 2, $User, $Password, $LogonType, $Sddl) }
    else { $null = $f.RegisterTask($s.leaf, $Xml, 2, $User, $Password, $LogonType) }
}
function Remove-SpikeTask([string]$Path) { $s = Split-TaskPath $Path; (Get-TaskFolder $s.parent).DeleteTask($s.leaf, 0) }

function Invoke-TaskSpike([string]$Password) {
    $res = [ordered]@{ api = 'capture: IRegisteredTask::get_Xml + GetSecurityDescriptor(OWNER|GROUP|DACL); delete: ITaskFolder::DeleteTask(name, 0); re-create: ITaskFolder::RegisterTask(name, xml, TASK_CREATE, user=VT_EMPTY, password=VT_EMPTY, TASK_LOGON_NONE, sddl)'
        cases = (New-Object System.Collections.ArrayList); control = $null; create_existing = $null; stored_password = $null }
    foreach ($spec in @($TaskSpecs) + @($TaskControlSpec)) {
        $c = [ordered]@{ case = $spec.case; path = $spec.path; create_error = $null; original = $null; reread = $null; delete_error = $null; gone = $null; register_error = $null; after = $null; compare = $null }
        try { Register-SpikeTask $spec } catch { $c.create_error = Err $_ }
        $c.original = Get-TaskCap $spec.path
        if (-not $c.original) { [void]$res.cases.Add($c); Log "task $($spec.case): create failed $($c.create_error)"; continue }
        Start-Sleep -Milliseconds 500
        $c.reread = Compare-TaskCap $c.original (Get-TaskCap $spec.path)
        if ($spec.case -eq 'task-control') { $res.control = $c; continue }
        # Two re-registrations from the same capture: with_getsd_sddl passes GetSecurityDescriptor's SDDL as the sddl
        # argument (C-WIN register_xml as written); xml_only passes no sddl (the XML carries its own SecurityDescriptor
        # element when the task was registered with one). The last one (xml_only) is the state kept.
        $c.modes = [ordered]@{}
        foreach ($mode in 'with_getsd_sddl', 'xml_only') {
            $mr = [ordered]@{ delete_error = $null; gone = $null; register_error = $null; after = $null; compare = $null }
            if (Get-TaskObj $spec.path) { try { Remove-SpikeTask $spec.path } catch { $mr.delete_error = Err $_ } }
            $mr.gone = (-not (Get-TaskObj $spec.path)) -and (-not [PurgeSpike.Reg]::KeyExists("$TcRel\Tree$($spec.path)"))
            $sd = if ($mode -eq 'with_getsd_sddl') { $c.original.sddl } else { $null }
            try { Register-TaskXml $spec.path $c.original.xml $sd } catch { $mr.register_error = Err $_ }
            $mr.after = Get-TaskCap $spec.path
            if ($mr.after) { $mr.compare = Compare-TaskCap $c.original $mr.after }
            $c.modes[$mode] = $mr
            Log "task $($spec.case) ${mode}: register_error=$($mr.register_error) xml_equal=$($mr.compare.xml_equal) sddl_equal=$($mr.compare.sddl_equal) sddl $($c.original.sddl) -> $($mr.compare.sddl_after) diff=$($mr.compare.diff -join ' ')"
        }
        $c.delete_error = $c.modes.xml_only.delete_error; $c.gone = $c.modes.xml_only.gone; $c.register_error = $c.modes.xml_only.register_error
        $c.after = $c.modes.xml_only.after; $c.compare = $c.modes.xml_only.compare
        [void]$res.cases.Add($c)
    }
    # TASK_CREATE over an existing task: must fail and leave the task unchanged.
    $t1 = @($res.cases | Where-Object { $_.after })[0]
    if ($t1) {
        $ce = [ordered]@{ path = $t1.path; error = $null; unchanged = $null }
        $other = $t1.after.xml.Replace('--update', '--other')
        try { Register-TaskXml $t1.path $other } catch { $ce.error = Err $_ }
        $now = Get-TaskCap $t1.path
        $ce.unchanged = ($now.xml -ceq $t1.after.xml)
        $res.create_existing = $ce
        Log "task create over existing: error=$($ce.error) unchanged=$($ce.unchanged)"
    }
    # Stored password (TASK_LOGON_PASSWORD).
    $sp = [ordered]@{ path = $TaskPasswordSpec.path; create_error = $null; original = $null; delete_error = $null; tries = [ordered]@{} }
    try { Register-SpikeTask $TaskPasswordSpec $Password } catch { $sp.create_error = Err $_ }
    $sp.original = Get-TaskCap $TaskPasswordSpec.path
    if ($sp.original) {
        $tries = @(
            @{ name = 'xml_only_logon_none'; user = $null; pw = $null; lt = 0 }
            @{ name = 'user_no_password_logon_password'; user = $TaskPasswordSpec.user; pw = $null; lt = 1 }
            @{ name = 'user_and_password_logon_password'; user = $TaskPasswordSpec.user; pw = 'PW'; lt = 1 }
        )
        foreach ($t in $tries) {
            if (Get-TaskObj $TaskPasswordSpec.path) { try { Remove-SpikeTask $TaskPasswordSpec.path } catch { $sp.delete_error = Err $_ } }
            $tr = [ordered]@{ error = $null; registered = $false; compare = $null }
            $pw = if ($t.pw) { $Password } else { $null }
            try { Register-TaskXml $TaskPasswordSpec.path $sp.original.xml $null $t.user $pw $t.lt; $tr.registered = $true } catch { $tr.error = Err $_ }
            $a = Get-TaskCap $TaskPasswordSpec.path
            if ($a) { $tr.registered = $true; $tr.compare = Compare-TaskCap $sp.original $a }
            $sp.tries[$t.name] = $tr
            Log "task stored password $($t.name): registered=$($tr.registered) error=$($tr.error) xml_equal=$($tr.compare.xml_equal)"
        }
    }
    $res.stored_password = $sp
    $res
}

# ----------------------------------------------------------------------------------------------- services

function Invoke-Sc([string]$A) {
    $r = Invoke-Native -Exe (Join-Path $env:SystemRoot 'System32\sc.exe') -Arguments $A -TimeoutSec 60
    [ordered]@{ args = $A; exit = $r.exit; out = ("$($r.stdout)$($r.stderr)" -replace '\s+', ' ').Trim() }
}
function Get-SvcCap([string]$Name) {
    $c = [ordered]@{ name = $Name; tree = [PurgeSpike.Reg]::Tree("$SvcRel\$Name"); scm = $null; scm_error = $null }
    try { $c.scm = [PurgeSpike.Scm]::Query($Name) } catch { $c.scm_error = Err $_ }
    $c
}
function ConvertTo-JsonLine($O) { ConvertTo-Json -InputObject $O -Depth 8 -Compress }
function Compare-SvcCap($A, $B) {
    $reg = @(Compare-RegTree $A.tree $B.tree)
    $scm = New-Object System.Collections.ArrayList
    if ($A.scm -and $B.scm) {
        foreach ($f in 'service_type', 'start_type', 'error_control', 'binary_path', 'load_order_group', 'tag_id', 'dependencies', 'service_start_name', 'display_name') {
            $x = ConvertTo-JsonLine $A.scm.config.$f; $y = ConvertTo-JsonLine $B.scm.config.$f
            if ($x -cne $y) { [void]$scm.Add("config.$f $x -> $y") }
        }
        foreach ($f in 'description', 'delayed_auto_start', 'failure_actions', 'failure_actions_flag', 'service_sid_type', 'required_privileges', 'preshutdown_timeout_ms', 'triggers', 'launch_protected') {
            $x = ConvertTo-JsonLine $A.scm.config2.$f; $y = ConvertTo-JsonLine $B.scm.config2.$f
            if ($x -cne $y) { [void]$scm.Add("config2.$f $x -> $y") }
        }
    } elseif ([bool]$A.scm -ne [bool]$B.scm) { [void]$scm.Add("present $([bool]$A.scm) -> $([bool]$B.scm)") }
    [ordered]@{ reg_equal = ($reg.Count -eq 0); scm_equal = ($scm.Count -eq 0); sddl_equal = ("$($A.scm.sddl)" -ceq "$($B.scm.sddl)")
        reg_diff = @($reg | ForEach-Object { Format-RegDiff $_ }); reg_diff_names = @($reg | ForEach-Object { Get-RegDiffName $_ }); reg_diff_raw = $reg
        scm_diff = $scm.ToArray(); sddl_before = $A.scm.sddl; sddl_after = $B.scm.sddl }
}
function Wait-SvcGone([string]$Name) { Wait-Until { -not [PurgeSpike.Reg]::KeyExists("$SvcRel\$Name") } 10000 }

$SvcSpecs = @(
    [ordered]@{ case = 'svc1-own-process-localsystem'; name = 'PurgeSpikeS1'; sc = @('create PurgeSpikeS1 binPath= "\"C:\Program Files\PurgeSpike\s1.exe\" --service" type= own start= demand error= normal DisplayName= "Purge Spike S1"') }
    [ordered]@{ case = 'svc2-localservice-config2'; name = 'PurgeSpikeS2'; sc = @(
            'create PurgeSpikeS2 binPath= "C:\Program Files\PurgeSpike\s2.exe" type= own start= delayed-auto obj= "NT AUTHORITY\LocalService" DisplayName= "Purge Spike S2" depend= RpcSs/Tcpip'
            'description PurgeSpikeS2 "Purge spike service two"'
            'failure PurgeSpikeS2 reset= 86400 actions= restart/60000/restart/120000 command= "\"C:\Program Files\PurgeSpike\recover.exe\" --fail"'
            'failureflag PurgeSpikeS2 1'
            'privs PurgeSpikeS2 SeChangeNotifyPrivilege/SeCreateGlobalPrivilege'
            'sidtype PurgeSpikeS2 unrestricted') }
    [ordered]@{ case = 'svc3-trigger'; name = 'PurgeSpikeS3'; sc = @(
            'create PurgeSpikeS3 binPath= "C:\Program Files\PurgeSpike\s3.exe" type= own start= demand DisplayName= "Purge Spike S3"'
            'triggerinfo PurgeSpikeS3 start/networkon start/strcustom/6e3b8b3b-1e6c-4d8a-9c5e-1b2f3a4d5e6f/hello/world') }
    [ordered]@{ case = 'svc4-parameters-extra-values'; name = 'PurgeSpikeS4'; extra = $true; sc = @(
            'create PurgeSpikeS4 binPath= "%SystemRoot%\System32\svchost.exe -k PurgeSpikeGroup" type= share start= demand DisplayName= "Purge Spike S4"') }
    # Fifth case beyond the package's four: a custom service SD (sc sdset), so the Security subkey path is exercised.
    [ordered]@{ case = 'svc5-custom-sddl'; name = 'PurgeSpikeS8'; sc = @(
            'create PurgeSpikeS8 binPath= "C:\Program Files\PurgeSpike\s8.exe" type= own start= demand DisplayName= "Purge Spike S8"'
            'sdset PurgeSpikeS8 D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RPWPCR;;;AU)') }
)
$SvcControlSpec = [ordered]@{ case = 'svc-control'; name = 'PurgeSpikeSC'; sc = @(
        'create PurgeSpikeSC binPath= "C:\Program Files\PurgeSpike\sc.exe" type= own start= delayed-auto obj= "NT AUTHORITY\LocalService" DisplayName= "Purge Spike SC" depend= RpcSs/Tcpip'
        'description PurgeSpikeSC "Purge spike control service (never deleted)"'
        'failure PurgeSpikeSC reset= 86400 actions= restart/60000/restart/120000'
        'failureflag PurgeSpikeSC 1'
        'privs PurgeSpikeSC SeChangeNotifyPrivilege/SeCreateGlobalPrivilege'
        'sidtype PurgeSpikeSC unrestricted'
        'triggerinfo PurgeSpikeSC start/networkon') }

function Add-S4Extras {
    $b = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    try {
        $k = $b.CreateSubKey("$SvcRel\PurgeSpikeS4\Parameters")
        $k.SetValue('ServiceDll', '%ProgramFiles%\PurgeSpike\s4.dll', 'ExpandString')
        $k.SetValue('ServiceMain', 'SpikeMain', 'String')
        $k.SetValue('ServiceDllUnloadOnStop', 1, 'DWord')
        $k.SetValue('Hosts', [string[]]@('a.example', 'b.example'), 'MultiString')
        $k.SetValue('Blob', [byte[]](1, 2, 3, 0, 255), 'Binary')
        $k.SetValue('Big', [long]81985529216486895, 'QWord')
        $s = $k.CreateSubKey('Sub'); $s.SetValue('Level', 3, 'DWord'); $s.Close(); $k.Close()
        $r = $b.OpenSubKey("$SvcRel\PurgeSpikeS4", $true); $r.SetValue('VendorTag', 'spike', 'String'); $r.Close()
    } finally { $b.Close() }
}

# Config2 items whose registry value is present in the backed-up key (root values / TriggerInfo subkey).
$Config2Values = [ordered]@{ description = @('Description'); failure_actions = @('FailureActions', 'FailureCommand', 'RebootMessage'); failure_actions_flag = @('FailureActionsOnNonCrashFailures')
    delayed_auto_start = @('DelayedAutostart'); service_sid_type = @('ServiceSidType'); required_privileges = @('RequiredPrivileges'); preshutdown_timeout_ms = @('PreshutdownTimeout')
    triggers = @('TriggerInfo\'); launch_protected = @('LaunchProtected') }
function Get-PresentConfig2($Tree) {
    $root = @($Tree | Where-Object { "$($_.path)" -eq '' })[0]
    $names = @($root.values | ForEach-Object { "$($_.name)" }) + @($root.subkeys | ForEach-Object { "$_\" })
    @($Config2Values.Keys | Where-Object { $item = $_; @($Config2Values[$item] | Where-Object { $names -contains $_ }).Count -gt 0 })
}

function Invoke-Recreate($C0, [string]$Mode, $Password = $null) {
    # Mode naive: CreateService + every non-null config2 item + SetServiceObjectSecurity (as the design's undo reads).
    # Mode guided: CreateService + only the config2 items whose value the backup holds + security only when the backup
    # has a Security subkey; then the registry write-back of the backed-up tree.
    $name = $C0.name
    $r = [ordered]@{ mode = $Mode; create = $null; config2 = $null; config2_items = $null; security = $null; after_scm = $null; compare_scm = $null; write_back = $null; after_write_back = $null; compare_write_back = $null }
    $def = $C0.scm
    if ($Mode -eq 'guided') {
        # CreateServiceW from the raw ImagePath of the key backup (QueryServiceConfigW returns it expanded).
        $def = New-Object PurgeSpike.SvcDef; $def.name = $C0.scm.name; $def.config2 = $C0.scm.config2
        $cfg = New-Object PurgeSpike.SvcConfig
        foreach ($p in 'service_type', 'start_type', 'error_control', 'binary_path', 'load_order_group', 'tag_id', 'dependencies', 'service_start_name', 'display_name') { $cfg.$p = $C0.scm.config.$p }
        $root = @($C0.tree | Where-Object { "$($_.path)" -eq '' })[0]
        $ip = @($root.values | Where-Object { $_.name -eq 'ImagePath' })[0]
        if ($ip) { $cfg.binary_path = Get-RegString $ip.hex }
        $def.config = $cfg
    }
    $r.create = [PurgeSpike.Scm]::Create($def, $Password)
    if ($r.create -ne 0) { return $r }
    $only = $null
    if ($Mode -eq 'guided') { $only = [string[]]@(Get-PresentConfig2 $C0.tree) }
    $r.config2_items = $(if ($Mode -eq 'guided') { @($only) } else { 'all non-null' })
    $r.config2 = [PurgeSpike.Scm]::ApplyConfig2($name, $C0.scm.config2, $only)
    $hasSec = @($C0.tree | Where-Object { "$($_.path)" -eq 'Security' }).Count -gt 0
    if ($Mode -eq 'naive' -or $hasSec) {
        $s7 = [PurgeSpike.Scm]::SetSecurity($name, $C0.scm.sddl, 7)
        $r.security = [ordered]@{ owner_group_dacl = $s7; dacl_only = $null }
        if ($s7 -ne 0) { $r.security.dacl_only = [PurgeSpike.Scm]::SetSecurity($name, $C0.scm.sddl, 4) }
    } else { $r.security = 'skipped: the backup has no Security subkey' }
    $a = Get-SvcCap $name
    $r.after_scm = $a
    $r.compare_scm = Compare-SvcCap $C0 $a
    if ($Mode -eq 'guided') {
        $r.write_back = @(Invoke-WriteBack "$SvcRel\$name" $C0.tree)
        $b = Get-SvcCap $name
        $r.after_write_back = $b
        $r.compare_write_back = Compare-SvcCap $C0 $b
    }
    $r
}

function Test-LsaSecret([string]$Service) {
    # HKLM\SECURITY is readable by SYSTEM only: a one-shot SYSTEM task runs reg.exe query and writes the result.
    $out = "C:\cr\work\lsa-$Service.txt"
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    $tr = "cmd.exe /c reg.exe query HKLM\SECURITY\Policy\Secrets\_SC_$Service > $out 2>&1"
    $null = Invoke-Native -Exe (Join-Path $env:SystemRoot 'System32\schtasks.exe') -Arguments "/create /tn PurgeSpikeProbe /ru SYSTEM /sc once /st 23:59 /f /tr `"$tr`"" -TimeoutSec 60
    $null = Invoke-Native -Exe (Join-Path $env:SystemRoot 'System32\schtasks.exe') -Arguments '/run /tn PurgeSpikeProbe' -TimeoutSec 60
    $ok = Wait-Until { Test-Path -LiteralPath $out } 20000
    Start-Sleep -Milliseconds 500
    $null = Invoke-Native -Exe (Join-Path $env:SystemRoot 'System32\schtasks.exe') -Arguments '/delete /tn PurgeSpikeProbe /f' -TimeoutSec 60
    if (-not $ok) { return 'probe did not run' }
    $t = [IO.File]::ReadAllText($out)
    if ($t -match [regex]::Escape("_SC_$Service") -and $t -notmatch 'ERROR') { 'present' } elseif ($t -match 'ERROR') { 'absent' } else { "unclear: $($t.Trim())" }
}

function Invoke-ServiceSpike([string]$Password) {
    $res = [ordered]@{ api = 'capture: Services\<name> key tree (raw RegQueryValueExW: name, type, bytes) + QueryServiceConfigW + QueryServiceConfig2W (levels 1-8, 12) + QueryServiceObjectSecurity(OWNER|GROUP|DACL); delete: DeleteService; re-create: CreateServiceW + ChangeServiceConfig2W + SetServiceObjectSecurity (+ registry write-back)'
        cases = (New-Object System.Collections.ArrayList); control = $null; marked_for_delete = $null; stored_password = $null }
    foreach ($spec in @($SvcSpecs) + @($SvcControlSpec)) {
        $c = [ordered]@{ case = $spec.case; name = $spec.name; sc = @(); original = $null; reread = $null; delete = $null; naive = $null; delete2 = $null; guided = $null }
        foreach ($a in $spec.sc) { $c.sc += Invoke-Sc $a }
        if ($spec.extra) { try { Add-S4Extras } catch { $c.sc += [ordered]@{ args = 'S4 extras'; exit = -1; out = (Err $_) } } }
        $c.original = Get-SvcCap $spec.name
        Start-Sleep -Milliseconds 500
        $c.reread = Compare-SvcCap $c.original (Get-SvcCap $spec.name)
        if ($spec.case -eq 'svc-control') { $res.control = $c; continue }
        $c.delete = [ordered]@{ code = [PurgeSpike.Scm]::DeleteByName($spec.name); stage = [PurgeSpike.Scm]::LastStage; key_gone = (Wait-SvcGone $spec.name) }
        $c.naive = Invoke-Recreate $c.original 'naive'
        $c.delete2 = [ordered]@{ code = [PurgeSpike.Scm]::DeleteByName($spec.name); stage = [PurgeSpike.Scm]::LastStage; key_gone = (Wait-SvcGone $spec.name) }
        $c.guided = Invoke-Recreate $c.original 'guided'
        Log "svc $($spec.case): naive reg=$($c.naive.compare_scm.reg_diff -join '; ') scm=$($c.naive.compare_scm.scm_diff -join '; ')"
        Log "svc $($spec.case): guided reg=$($c.guided.compare_scm.reg_diff -join '; ') / after write-back reg=$($c.guided.compare_write_back.reg_diff -join '; ') scm=$($c.guided.compare_write_back.scm_diff -join '; ') sddl_equal=$($c.guided.compare_write_back.sddl_equal)"
        [void]$res.cases.Add($c)
    }
    # DeleteService while handles are open.
    $md = [ordered]@{}
    $def5 = $null
    foreach ($v in @(
            @{ key = 'other_handle_open'; name = 'PurgeSpikeS5'; hold = $true }
            @{ key = 'own_handle_only'; name = 'PurgeSpikeS7'; hold = $false })) {
        $n = $v.name
        $x = [ordered]@{ create = $null; delete = $null; reopen_while_own_delete_handle_open = $null; reopen_after_own_handle_closed = $null; key_present_while_marked = $null; delete_flag = $null
            query_while_marked = $null; delete_again = $null; create_while_marked = $null; after_last_handle_closed = $null; create_after_close = $null }
        $x.create = (Invoke-Sc "create $n binPath= `"C:\Program Files\PurgeSpike\$n.exe`" type= own start= demand").exit
        $defN = [PurgeSpike.Scm]::Query($n)
        $hold = [IntPtr]::Zero
        if ($v.hold) { $hold = [PurgeSpike.Scm]::OpenHandle($n, [PurgeSpike.Scm]::QUERY_STATUS) }
        $hdel = [PurgeSpike.Scm]::OpenHandle($n, [PurgeSpike.Scm]::ACCESS_DELETE -bor [PurgeSpike.Scm]::QUERY_STATUS)
        $x.delete = [PurgeSpike.Scm]::DeleteHandle($hdel)
        $h2 = [PurgeSpike.Scm]::OpenHandle($n, [PurgeSpike.Scm]::QUERY_STATUS)
        $x.reopen_while_own_delete_handle_open = [ordered]@{ opened = ($h2 -ne [IntPtr]::Zero); error = [PurgeSpike.Scm]::LastError }
        [PurgeSpike.Scm]::Close($h2)
        [PurgeSpike.Scm]::Close($hdel)
        Start-Sleep -Milliseconds 300
        $h3 = [PurgeSpike.Scm]::OpenHandle($n, [PurgeSpike.Scm]::QUERY_STATUS)
        $x.reopen_after_own_handle_closed = [ordered]@{ opened = ($h3 -ne [IntPtr]::Zero); error = [PurgeSpike.Scm]::LastError }
        [PurgeSpike.Scm]::Close($h3)
        $x.key_present_while_marked = [PurgeSpike.Reg]::KeyExists("$SvcRel\$n")
        $df = [PurgeSpike.Reg]::ReadValue("$SvcRel\$n", 'DeleteFlag'); $x.delete_flag = $(if ($df) { Format-RegVal $df } else { $null })
        try { $q = [PurgeSpike.Scm]::Query($n); $x.query_while_marked = $(if ($q) { 'ok' } else { 'absent (1060)' }) } catch { $x.query_while_marked = Err $_ }
        $x.delete_again = [ordered]@{ code = [PurgeSpike.Scm]::DeleteByName($n); stage = [PurgeSpike.Scm]::LastStage }
        $x.create_while_marked = if ($x.key_present_while_marked) { [PurgeSpike.Scm]::Create($defN, $null) } else { 'not tried: the service was already gone' }
        if ($v.hold) { [PurgeSpike.Scm]::Close($hold) }
        $gone = Wait-SvcGone $n
        $h4 = [PurgeSpike.Scm]::OpenHandle($n, [PurgeSpike.Scm]::QUERY_STATUS)
        $x.after_last_handle_closed = [ordered]@{ key_gone = $gone; open_error = [PurgeSpike.Scm]::LastError }
        [PurgeSpike.Scm]::Close($h4)
        $x.create_after_close = [PurgeSpike.Scm]::Create($defN, $null)
        $null = [PurgeSpike.Scm]::DeleteByName($n); $null = Wait-SvcGone $n
        $md[$v.key] = $x
        Log "svc marked-for-delete $($v.key): $(ConvertTo-Json -InputObject $x -Compress)"
    }
    $res.marked_for_delete = $md
    # Service under an account with a stored password (LSA secret _SC_<name>).
    $n = 'PurgeSpikeS6'
    $sp = [ordered]@{ name = $n; account = '.\purgespike'; create = $null; original = $null; secret_after_create = $null; delete = $null; secret_after_delete = $null
        recreate_without_password = $null; after = $null; compare = $null; secret_after_recreate = $null }
    $sp.create = [PurgeSpike.Scm]::CreateSimple($n, 'Purge Spike S6', 0x10, 3, '"C:\Program Files\PurgeSpike\s6.exe"', '.\purgespike', $Password)
    $sp.original = Get-SvcCap $n
    $sp.secret_after_create = Test-LsaSecret $n
    $sp.delete = [ordered]@{ code = [PurgeSpike.Scm]::DeleteByName($n); key_gone = (Wait-SvcGone $n) }
    $sp.secret_after_delete = Test-LsaSecret $n
    if ($sp.original.scm) {
        $sp.recreate_without_password = [PurgeSpike.Scm]::Create($sp.original.scm, $null)
        $sp.after = Get-SvcCap $n
        if ($sp.after.scm) { $sp.compare = Compare-SvcCap $sp.original $sp.after }
        $sp.secret_after_recreate = Test-LsaSecret $n
    }
    Log "svc stored password: create=$($sp.create) secret=$($sp.secret_after_create)/$($sp.secret_after_delete)/$($sp.secret_after_recreate) recreate=$($sp.recreate_without_password) reg=$($sp.compare.reg_diff -join '; ')"
    $res.stored_password = $sp
    $res
}

function New-SpikePassword {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $b = New-Object byte[] 24; $rng.GetBytes($b)
    $set = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    (-join ($b | ForEach-Object { $set[$_ % $set.Length] })) + 'Aa1!'
}

# ----------------------------------------------------------------------------------------------- stages

function Get-FinalCaptures($State) {
    [ordered]@{
        firewall = @($State.fw_ids | ForEach-Object { Get-FwRaw $_ })
        tasks = @($State.task_paths | ForEach-Object { Get-TaskCap $_ })
        services = @($State.svc_names | ForEach-Object { Get-SvcCap $_ })
    }
}

if ($Stage -eq 'main') {
    $null = New-RunDir $Run
    New-Item -ItemType Directory -Force 'C:\cr\work' | Out-Null
    Set-RunLog (Join-Path $OutDir 'spike.log')
    Log "M1B-SPIKE run $Run stage main"
    $hostInfo = Get-HostInfo
    Save-Json $hostInfo 'host.json'
    $pw = New-SpikePassword
    try {
        $sec = ConvertTo-SecureString $pw -AsPlainText -Force
        $null = New-LocalUser -Name 'purgespike' -Password $sec -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop
        Add-LocalGroupMember -SID 'S-1-5-32-544' -Member 'purgespike' -ErrorAction Stop
        Log 'local account purgespike created (random password, not recorded)'
    } catch { Log "!! local account: $(Err $_)" }
    $fw = Invoke-FirewallSpike; Save-Json $fw 'raw-firewall.json'
    $tk = Invoke-TaskSpike $pw; Save-Json $tk 'raw-task.json'
    $sv = Invoke-ServiceSpike $pw; Save-Json $sv 'raw-service.json'
    $pw = $null
    $state = [ordered]@{
        fw_ids = @(@($fw.cases | Where-Object { $_.id } | ForEach-Object { $_.id }) + @($fw.control.id))
        task_paths = @(@($tk.cases | Where-Object { $_.after } | ForEach-Object { $_.path }) + @($tk.control.path))
        svc_names = @(@($sv.cases | ForEach-Object { $_.name }) + @($sv.control.name))
    }
    $state.before_reboot = Get-FinalCaptures $state
    Save-Json $state 'state.json'
    Log 'main stage done; reboot for the stability check'
    $null = Request-RigContinuation -Run $Run -Kind 'reboot' -Next 'reboot' -DelaySec 30
    return
}

if ($Stage -ne 'reboot') { throw "unknown stage '$Stage'" }

# ------------------------------------------------------------------------------- stage reboot: stability + RESULT
Set-RunLog (Join-Path $OutDir 'spike.log')
$cont = Receive-RigContinuation -Run $Run
Log "M1B-SPIKE run $Run stage reboot (boot $($cont.boot_before) -> $($cont.boot_after))"
$state = Read-Json 'state.json'
$after = Get-FinalCaptures $state
$rb = [ordered]@{ boot_before = $cont.boot_before; boot_after = $cont.boot_after; firewall = @(); tasks = @(); services = @() }
for ($i = 0; $i -lt @($state.fw_ids).Count; $i++) {
    $a = @($state.before_reboot.firewall)[$i]; $b = @($after.firewall)[$i]
    $rb.firewall += [ordered]@{ id = $a.id; equal = ($b -and "$($b.hex)" -ceq "$($a.hex)"); diff = $(if ($b) { @(Compare-Multiset (Get-FwMultiset (ConvertFrom-FwRule $a.rule)) (Get-FwMultiset (ConvertFrom-FwRule $b.rule))) } else { @('rule gone') }) }
}
for ($i = 0; $i -lt @($state.task_paths).Count; $i++) {
    $a = @($state.before_reboot.tasks)[$i]; $b = @($after.tasks)[$i]
    $rb.tasks += [ordered]@{ path = $a.path; compare = $(if ($b) { Compare-TaskCap $a $b } else { 'task gone' }) }
}
for ($i = 0; $i -lt @($state.svc_names).Count; $i++) {
    $a = @($state.before_reboot.services)[$i]; $b = @($after.services)[$i]
    $cmp = Compare-SvcCap $a $b
    $cmp.Remove('reg_diff_raw')
    $rb.services += [ordered]@{ name = $a.name; compare = $cmp }
}
Save-Json $rb 'raw-reboot.json'
Log "reboot: fw unchanged $(@($rb.firewall | Where-Object { $_.equal }).Count)/$(@($rb.firewall).Count); tasks xml unchanged $(@($rb.tasks | Where-Object { $_.compare.xml_equal }).Count)/$(@($rb.tasks).Count); services reg unchanged $(@($rb.services | Where-Object { $_.compare.reg_equal }).Count)/$(@($rb.services).Count)"

# ---- RESULT.json (purge.m1b.spike/1)
$fw = Read-Json 'raw-firewall.json'
$tk = Read-Json 'raw-task.json'
$sv = Read-Json 'raw-service.json'
$hostInfo = Read-Json 'host.json'

# Firewall: the method whose re-creation is exact for every case (name equal and C-OBJECT same_rule).
$fwCases = @($fw.cases)
$exactBy = [ordered]@{}
foreach ($m in 'wmi_context', 'mi_options', 'cim_filters', 'new_rule_name') {
    $exactBy[$m] = (@($fwCases | Where-Object { -not ($_.methods.$m.ok -and $_.methods.$m.name_equal -and $_.methods.$m.same_rule) }).Count -eq 0) -and $fwCases.Count -eq 6
}
$fwKey = @('wmi_context', 'mi_options', 'cim_filters', 'new_rule_name' | Where-Object { $exactBy[$_] })[0]
$fwMethod = switch ($fwKey) { 'wmi_context' { 'cim_create' } 'mi_options' { 'cim_create' } 'cim_filters' { 'cim_create' } 'new_rule_name' { 'new_rule_name' } default { 'none' } }
if (-not $fwKey) { $fwKey = 'wmi_context' }
$fwRebootStable = (@($rb.firewall | Where-Object { -not $_.equal }).Count -eq 0)
$firewall = [ordered]@{
    method = $fwMethod
    method_detail = $(if ($fwMethod -ne 'none') { "$fwKey`: $($fw.methods.$fwKey)" } else { 'no tried method re-creates every rule with its old id and an equal field multiset' })
    exact = ($fwMethod -ne 'none')
    exact_by_method = $exactBy
    delete_api = $fw.delete_api
    cases = @($fwCases | ForEach-Object {
            $c = $_; $mm = $c.methods.$fwKey
            [ordered]@{ id = $c.id; case = $c.case; name_equal = [bool]$mm.name_equal; same_rule = [bool]$mm.same_rule; diff = @($mm.diff)
                raw_equal = [bool]$mm.raw_equal; version = "$($mm.version_before)"; delete_matched = $mm.delete.matched; unmapped_fields = @($c.map.unmapped)
                original = "$($c.original.rule)"
                by_method = [ordered]@{ wmi_context = $null; mi_options = $null; cim_filters = $null; new_rule_name = $null } }
        })
    duplicate_create = $fw.duplicate
    reread_stable = (@($fwCases | Where-Object { -not $_.reread_equal }).Count -eq 0) -and [bool]$fw.control.reread_equal
    reboot_stable = $fwRebootStable
}
for ($i = 0; $i -lt $fwCases.Count; $i++) {
    foreach ($m in 'wmi_context', 'mi_options', 'cim_filters', 'new_rule_name') {
        $mm = $fwCases[$i].methods.$m
        $firewall.cases[$i].by_method[$m] = [ordered]@{ ok = [bool]$mm.ok; name_equal = [bool]$mm.name_equal; same_rule = [bool]$mm.same_rule; raw_equal = [bool]$mm.raw_equal; diff = @($mm.diff); error = $mm.error }
    }
}

# Tasks: an element may be normalised only when Windows also changes it on an untouched task (control re-read or
# reboot) - otherwise a difference makes the round trip inexact.
$tkCases = @($tk.cases)
$taskChurn = @(@($tkCases | ForEach-Object { @($_.reread.diff_elements) }) + @($tk.control.reread.diff_elements) + @($rb.tasks | ForEach-Object { @($_.compare.diff_elements) })) | Where-Object { $_ } | Sort-Object -Unique
$taskCand = @($tkCases | ForEach-Object { @($_.compare.diff_elements) }) | Where-Object { $_ } | Sort-Object -Unique
$taskNorm = @($taskCand | Where-Object { $taskChurn -contains $_ })
$taskUnexplained = @($taskCand | Where-Object { $taskChurn -notcontains $_ })
$taskOk = @($tkCases | Where-Object { $_.compare -and -not $_.register_error -and $_.compare.sddl_equal -and $_.compare.enabled_equal }).Count -eq 5
# TaskCache values (names only; the data holds GUIDs and times) that differ after re-registering identical XML.
function Get-TcNames($Lines) { @($Lines | Where-Object { $_ } | ForEach-Object { ("$_" -split ' ')[0] } | Sort-Object -Unique) }
$tcPerCase = @($tkCases | ForEach-Object { , @(Get-TcNames $_.compare.taskcache_diff) })
$tcAll = @($tcPerCase | ForEach-Object { $_ } | Sort-Object -Unique)
$tcRegenerated = @($tcAll | Where-Object { $n = $_; @($tcPerCase | Where-Object { $_ -contains $n }).Count -eq $tcPerCase.Count })
$task = [ordered]@{
    exact = ($taskOk -and $taskUnexplained.Count -eq 0)
    normalise = $taskNorm
    unexplained_differences = $taskUnexplained
    api = $tk.api
    register_mode = 'xml_only'
    register_mode_note = 'RegisterTask(name, xml, TASK_CREATE, VT_EMPTY, VT_EMPTY, TASK_LOGON_NONE) without the sddl argument: the XML carries RegistrationInfo/SecurityDescriptor when the task had one. Passing the GetSecurityDescriptor SDDL (with_getsd_sddl) is not exact: it adds that element to the XML and stores the SD with the AI flag and the explicit ACE moved before the inherited ones.'
    taskcache_regenerated = $tcRegenerated
    taskcache_note = 'Task Scheduler regenerates these TaskCache values on every registration of identical XML (Tree Id = new task GUID and Tasks\{id} key name, DynamicInfo = registration time, Hash, Triggers bytes); they are outside the task fidelity measure (XML + SDDL) and must be ignored by an execdiff of the TaskCache.'
    cases = @($tkCases | ForEach-Object {
            $g = $_.modes.with_getsd_sddl
            [ordered]@{ path = $_.path; case = $_.case; register_error = $_.register_error; xml_equal = [bool]$_.compare.xml_equal; sddl_equal = [bool]$_.compare.sddl_equal
                enabled_equal = [bool]$_.compare.enabled_equal; diff = @($_.compare.diff); sddl_before = $_.compare.sddl_before; sddl_after = $_.compare.sddl_after
                file_equal = [bool]$_.compare.file_equal; taskcache_id_equal = [bool]$_.compare.taskcache_id_equal; taskcache_diff = @(Get-TcNames $_.compare.taskcache_diff)
                reread_diff = @($_.reread.diff)
                with_getsd_sddl = [ordered]@{ register_error = $g.register_error; xml_equal = [bool]$g.compare.xml_equal; sddl_equal = [bool]$g.compare.sddl_equal; diff = @($g.compare.diff); sddl_after = $g.compare.sddl_after } }
        })
    create_existing = $tk.create_existing
    stored_password = [ordered]@{ path = $tk.stored_password.path; create_error = $tk.stored_password.create_error
        logon_type = $(if ($tk.stored_password.original) { ([xml]$tk.stored_password.original.xml).Task.Principals.Principal.LogonType } else { $null })
        tries = $(if ($tk.stored_password.tries) { $o = [ordered]@{}; foreach ($p in $tk.stored_password.tries.PSObject.Properties) { $o[$p.Name] = [ordered]@{ registered = $p.Value.registered; error = $p.Value.error; xml_equal = $p.Value.compare.xml_equal; sddl_equal = $p.Value.compare.sddl_equal; diff = $(if ($p.Value.compare) { @($p.Value.compare.diff) } else { @() }) } }; $o } else { $null }) }
    control_reread_diff = @($tk.control.reread.diff)
    reboot = @($rb.tasks | ForEach-Object { [ordered]@{ path = $_.path; xml_equal = [bool]$_.compare.xml_equal; sddl_equal = [bool]$_.compare.sddl_equal; diff = @($_.compare.diff); taskcache_diff = @(Get-TcNames $_.compare.taskcache_diff) } })
}

# Services: write_back_needed = values the SCM re-creation (guided) did not reproduce and the write-back did;
# scm_owned_values = differences left after the write-back that Windows also produces on an untouched service.
$svCases = @($sv.cases)
$wbNeeded = @()
$remaining = @()
foreach ($c in $svCases) {
    $b1 = @($c.guided.compare_scm.reg_diff_names)
    $b2 = @($c.guided.compare_write_back.reg_diff_names)
    $wbNeeded += @($b1 | Where-Object { $b2 -notcontains $_ })
    $remaining += @($b2)
}
$svcChurn = @(@($svCases | ForEach-Object { @($_.reread.reg_diff_names) }) + @($sv.control.reread.reg_diff_names) + @($rb.services | ForEach-Object { @($_.compare.reg_diff_names) })) | Where-Object { $_ } | Sort-Object -Unique
$wbNeeded = @($wbNeeded | Where-Object { $_ } | Sort-Object -Unique)
$remaining = @($remaining | Where-Object { $_ } | Sort-Object -Unique)
$scmOwned = @($remaining | Where-Object { $svcChurn -contains $_ })
$svcUnexplained = @($remaining | Where-Object { $svcChurn -notcontains $_ })
$svcOk = @($svCases | Where-Object { $_.guided.create -eq 0 -and $_.guided.compare_write_back -and $_.guided.compare_write_back.scm_equal -and $_.guided.compare_write_back.sddl_equal }).Count -eq @($SvcSpecs).Count
$service = [ordered]@{
    exact = ($svcOk -and $svcUnexplained.Count -eq 0)
    scm_owned_values = $scmOwned
    write_back_needed = $wbNeeded
    unexplained_differences = $svcUnexplained
    api = $sv.api
    procedure = 'guided: CreateServiceW(config from QueryServiceConfigW, but lpBinaryPathName = the raw ImagePath string of the key backup; password NULL) -> ChangeServiceConfig2W only for the items whose value the key backup holds -> SetServiceObjectSecurity(OWNER|GROUP|DACL) only when the key backup has a Security subkey -> write back every backed-up value/key that is absent or different (RegSetValueExW with the backed-up type and bytes)'
    query_config_expands_image_path = (@($svCases | Where-Object { @($_.naive.compare_scm.reg_diff | Where-Object { "$_" -like '|ImagePath data*' }).Count -gt 0 }).Count -gt 0)
    naive_extra_values = @($svCases | ForEach-Object { @($_.naive.compare_scm.reg_diff) } | Where-Object { "$_" -match ' extra' } | ForEach-Object { ("$_" -split ' ')[0] } | Sort-Object -Unique)
    naive_note = 'naive = CreateServiceW + every non-null config2 item + SetServiceObjectSecurity always (the M1B-X-SERVICE undo as written): each applied default item and the security call leave values/keys the original never had.'
    marked_for_delete = $sv.marked_for_delete
    cases = @($svCases | ForEach-Object {
            $c = $_
            [ordered]@{ name = $c.name; case = $c.case; sc_exit = @($c.sc | ForEach-Object { $_.exit }); delete = $c.delete.code
                naive = [ordered]@{ create = $c.naive.create; config2 = $c.naive.config2; security = $c.naive.security; reg_diff = @($c.naive.compare_scm.reg_diff); scm_diff = @($c.naive.compare_scm.scm_diff); sddl_equal = [bool]$c.naive.compare_scm.sddl_equal }
                guided = [ordered]@{ create = $c.guided.create; config2_items = $c.guided.config2_items; config2 = $c.guided.config2; security = $c.guided.security
                    reg_diff_scm_only = @($c.guided.compare_scm.reg_diff); write_back = @($c.guided.write_back); reg_diff_after_write_back = @($c.guided.compare_write_back.reg_diff)
                    scm_diff = @($c.guided.compare_write_back.scm_diff); sddl_equal = [bool]$c.guided.compare_write_back.sddl_equal; sddl = $c.guided.compare_write_back.sddl_after }
                reread_diff = @($c.reread.reg_diff) }
        })
    stored_password = [ordered]@{ name = $sv.stored_password.name; account = $sv.stored_password.account; create = $sv.stored_password.create; secret_after_create = $sv.stored_password.secret_after_create
        delete = $sv.stored_password.delete.code; secret_after_delete = $sv.stored_password.secret_after_delete; recreate_without_password = $sv.stored_password.recreate_without_password
        secret_after_recreate = $sv.stored_password.secret_after_recreate; reg_diff = @($sv.stored_password.compare.reg_diff); scm_diff = @($sv.stored_password.compare.scm_diff) }
    reboot = @($rb.services | ForEach-Object { [ordered]@{ name = $_.name; reg_diff = @($_.compare.reg_diff); scm_diff = @($_.compare.scm_diff); sddl_equal = [bool]$_.compare.sddl_equal } })
}

$result = [ordered]@{
    schema = 'purge.m1b.spike/1'
    host = $hostInfo
    vm = 'Inbound-Win11-Test, snapshot m2-base'
    run = $Run
    firewall = $firewall
    task = $task
    service = $service
}
Save-Json $result 'RESULT.json' 24
Log "RESULT: firewall method=$($firewall.method) exact=$($firewall.exact); task exact=$($task.exact) normalise=$($task.normalise -join ',') unexplained=$($task.unexplained_differences -join ','); service exact=$($service.exact) scm_owned=$($service.scm_owned_values -join ',') write_back=$($service.write_back_needed -join ',') unexplained=$($service.unexplained_differences -join ',')"
Log 'done'
