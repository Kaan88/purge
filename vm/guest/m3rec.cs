// m3rec.cs: the roles and client steps of the M3 recovery modes m3-owner, m3-recover and m3-extras (vm\rig-m3-recover.ps1,
// vm\RIG.md section 15; M3_DESIGN.md 11.2, 12 G8, G9). Compiled together with m3sec.cs (partial class M3Sec) into
// C:\cr\m3rec\m3rec.exe by vm\guest\m3-recover.ps1 (csc.exe of .NET Framework 4, C# 5). m3sec.cs alone still builds the
// m3sec.exe of the security modes: its two hooks (ExtMain, ExtStep) are then empty.
//
//   watch <spec.json>        high: follows one session journal (C:\ProgramData\Purge\sessions\<id>\journal.jsonl) and, at
//                            a step (the n-th line, or a new line matching match_regex or holding every string of
//                            match_all), suspends the broker
//                            (NtSuspendProcess) and/or ends it (TerminateProcess); "record" only counts the lines.
//   privmon <spec.json>      high: samples the broker's process token and every thread's impersonation token for
//                            SeRestorePrivilege (design T10: on only inside purge-win's closure) until the broker exits.
//   hold <path> <stop>       a running app that holds <path> open without delete sharing until <stop> exists.
//   focused <pid> <out>      high: the consent dialog of <pid> as observe reads it, plus the element with the keyboard focus.
//   autopress <spec.json>    high: answers every consent dialog of the brokers of one install directory in turn
//                            (approve: tick the box when there is one, wait for the arming delay, press the primary button;
//                            cancel: press Cancel), observing each first.
//   uihist <spec.json>       high: the real UI's History & undo page through UI Automation (check, resume, rollback, read).
//   regsd <path> <sddl> <sections>  high: sets parts of a key's security descriptor (o, g, d, p = protected DACL) with
//                            SeRestorePrivilege enabled in this process (the fixture's SYSTEM-owned key; the staged half state).
//   rec-uninstall <Key> [/S] a fixture program's uninstaller: removes HKLM ARP key <Key> (PurgeRig...) and its app.exe.
//
// Client steps (spec steps[], after m3sec.cs's prepare, run, scan, plan_execute, shutdown):
//   {op: call, method, params, save?, timeout_ms?}    one request without a dialog; "{name}" in a string is spec vars[name]
//   {op: consent, method, params, repeat?}            one request that ends in the consent dialog (ready-k, go-k as m3sec)
//   {op: scan_full, forced?, save?}                    leftovers.scan of the prepared session, every row kept
//   {op: execute, select, allow_irreversible?, restore_point?, repeat?}   plan.create of the rows selected (all | kind:<k> |
//                                                     not-kind:<k> | name:<text>), then plan.execute; vars.session = its session
//   {op: sleep, ms}
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Automation;
using Microsoft.Win32;

static partial class M3Sec {
    [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenThreadToken(IntPtr thread, uint access, bool openAsSelf, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string system, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokPriv1 state, int len, IntPtr prev, IntPtr retLen);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int RegOpenKeyEx(UIntPtr root, string sub, int options, int access, out IntPtr key);
    [DllImport("advapi32.dll", SetLastError = true)] static extern int RegSetKeySecurity(IntPtr key, uint info, IntPtr sd);
    [DllImport("advapi32.dll", SetLastError = true)] static extern int RegCloseKey(IntPtr key);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint rev, out IntPtr sd, IntPtr size);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);

    [StructLayout(LayoutKind.Sequential, Pack = 4)] struct TokPriv1 { public int Count; public long Luid; public int Attributes; }

    const uint PROCESS_TERMINATE = 0x1, PROCESS_SUSPEND_RESUME = 0x800, PROCESS_QUERY_LIMITED = 0x1000;
    const uint THREAD_QUERY_INFORMATION = 0x40, THREAD_QUERY_LIMITED = 0x800, TOKEN_QUERY = 0x8, TOKEN_ADJUST = 0x20;
    const int SE_PRIVILEGE_ENABLED = 2, TokenPrivilegesClass = 3;
    const string RecOut = @"C:\cr\out\m3-recover";

    static Dictionary<string, object> RecVars;
    static readonly List<Dictionary<string, object>> RecRows = new List<Dictionary<string, object>>();

    static partial void ExtMain(string[] a, ref int code) {
        switch (a[0]) {
            case "watch": code = Watch(a[1]); break;
            case "privmon": code = PrivMon(a[1]); break;
            case "hold": code = Hold(a[1], a[2]); break;
            case "focused": code = Focused(int.Parse(a[1]), a[2]); break;
            case "autopress": code = AutoPress(a[1]); break;
            case "uihist": code = UiHistory(a[1]); break;
            case "regsd": code = RegSd(a[1], a[2], a[3]); break;
            case "rec-uninstall": code = RecUninstall(a); break;
        }
    }

    // ------------------------------------------------------------------------------------------ shared

    // A status file that survives a hard power-off: written through and flushed to the disk.
    static void WriteDurable(string path, object o) {
        string text = Json.Serialize(o);
        lock (FileLock) {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough)) {
                byte[] b = new UTF8Encoding(false).GetBytes(text);
                fs.Write(b, 0, b.Length);
                fs.Flush(true);
            }
        }
    }

    // The newest running purge-broker.exe started at or after $since whose image is <dir>\purge-broker.exe.
    static Process FindBroker(string image, DateTime since) {
        Process best = null;
        foreach (var p in Process.GetProcessesByName("purge-broker")) {
            try {
                if (p.HasExited) continue;
                if (image != null && !string.Equals(p.MainModule.FileName, image, StringComparison.OrdinalIgnoreCase)) continue;
                if (p.StartTime < since) continue;
                if (best == null || p.StartTime > best.StartTime) best = p;
            } catch { }
        }
        return best;
    }

    static long PrivLuid(string name) { long l; return LookupPrivilegeValue(null, name, out l) ? l : -1; }

    // The attributes of privilege $luid in $token: -1 not held, -2 unreadable.
    static int PrivAttr(IntPtr token, long luid) {
        int len;
        GetTokenInformation(token, TokenPrivilegesClass, IntPtr.Zero, 0, out len);
        if (len <= 0) return -2;
        IntPtr buf = Marshal.AllocHGlobal(len);
        try {
            if (!GetTokenInformation(token, TokenPrivilegesClass, buf, len, out len)) return -2;
            int n = Marshal.ReadInt32(buf);
            for (int i = 0; i < n; i++) {
                if (Marshal.ReadInt64(buf, 4 + i * 12) == luid) return Marshal.ReadInt32(buf, 4 + i * 12 + 8);
            }
            return -1;
        } finally { Marshal.FreeHGlobal(buf); }
    }

    static bool EnableOwnPrivilege(string name) {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST | TOKEN_QUERY, out tok)) return false;
        try {
            var tp = new TokPriv1 { Count = 1, Luid = PrivLuid(name), Attributes = SE_PRIVILEGE_ENABLED };
            return AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) && Marshal.GetLastWin32Error() == 0;
        } finally { CloseHandle(tok); }
    }

    // ------------------------------------------------------------------------------------------ watch

    // spec: {out, sessions, session?, existing[], broker_image, target, match_all[], action: suspend|kill|suspend-kill|record,
    //        timeout_ms}. Without "session" the journal is the first session directory not in existing[]. "target" counts
    //        the journal's complete lines (a new journal) and match_all looks at lines written after the watch began.
    static int Watch(string specPath) {
        var spec = ReadJson(specPath);
        string outPath = S(spec, "out", null);
        string action = S(spec, "action", "suspend");
        string sessions = S(spec, "sessions", @"C:\ProgramData\Purge\sessions");
        string image = S(spec, "broker_image", null);
        int target = I(spec, "target", 0);
        var match = new List<string>();
        var ml = L(spec, "match_all");
        if (ml != null) foreach (object o in ml) match.Add(Convert.ToString(o));
        string mr = S(spec, "match_regex", null);
        Regex matchRe = mr == null ? null : new Regex(mr, RegexOptions.CultureInvariant);
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var el = L(spec, "existing");
        if (el != null) foreach (object o in el) existing.Add(Convert.ToString(o));
        DateTime started = DateTime.Now.AddSeconds(-2);
        var end = DateTime.Now.AddMilliseconds(I(spec, "timeout_ms", 900000));
        var rec = new Dictionary<string, object> { { "t_start", Now() }, { "action", action }, { "target", target }, { "match_all", match }, { "state", "armed" }, { "watcher_il", MyIl() } };
        WriteDurable(outPath, rec);
        try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.High; Thread.CurrentThread.Priority = ThreadPriority.Highest; } catch { }

        string session = S(spec, "session", null), journal = null;
        while (journal == null) {
            if (session == null && Directory.Exists(sessions)) {
                foreach (var d in Directory.GetDirectories(sessions)) {
                    string n = Path.GetFileName(d);
                    if (!existing.Contains(n) && File.Exists(Path.Combine(d, "journal.jsonl"))) { session = n; break; }
                }
            }
            if (session != null && File.Exists(Path.Combine(sessions, session, "journal.jsonl"))) journal = Path.Combine(sessions, session, "journal.jsonl");
            else if (DateTime.Now > end) { rec["state"] = "timeout_no_journal"; rec["t_end"] = Now(); WriteDurable(outPath, rec); return 0; }
            else Thread.Sleep(2);
        }
        rec["session"] = session; rec["journal"] = journal; rec["t_journal"] = Now();
        var lines = new List<string>();
        var pending = new List<byte>();
        var buf = new byte[65536];
        int startLines = -1;
        // The broker is looked up before the first line is read, so the step itself costs no process walk.
        Process broker = FindBroker(image, started);
        using (var fs = new FileStream(journal, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
            Func<int> drain = () => {
                int got = 0, n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0) {
                    for (int i = 0; i < n; i++) {
                        if (buf[i] == (byte)'\n') { lines.Add(Encoding.UTF8.GetString(pending.ToArray())); pending.Clear(); got++; }
                        else pending.Add(buf[i]);
                    }
                }
                return got;
            };
            drain();
            startLines = lines.Count;
            rec["start_lines"] = startLines;
            bool hit = false;
            int spin = 0;
            while (!hit) {
                int before = lines.Count;
                drain();
                for (int i = Math.Max(before, startLines); i < lines.Count && !hit; i++) {
                    if (matchRe != null && matchRe.IsMatch(lines[i])) { hit = true; rec["hit_line"] = i + 1; rec["hit_text"] = lines[i]; }
                    if (!hit && match.Count > 0) {
                        bool all = true;
                        foreach (string m in match) if (lines[i].IndexOf(m, StringComparison.Ordinal) < 0) { all = false; break; }
                        if (all) { hit = true; rec["hit_line"] = i + 1; }
                    }
                }
                if (!hit && target > 0 && lines.Count >= target) { hit = true; rec["hit_line"] = target; }
                if (hit || action == "record") {
                    if (broker == null) broker = FindBroker(image, started);
                }
                if (hit) break;
                if (broker == null && (++spin % 200) == 0) broker = FindBroker(image, started);
                if (action == "record" && broker != null) {
                    try { if (broker.HasExited) { drain(); break; } } catch { }
                } else if (broker != null && (spin % 50) == 0) {
                    try { if (broker.HasExited) { drain(); rec["state"] = "finished_before_target"; break; } } catch { }
                }
                if (DateTime.Now > end) { rec["state"] = "timeout"; break; }
                if (spin % 64 == 0) Thread.Sleep(0); else Thread.SpinWait(400);
                spin++;
            }
            if (hit && action != "record") {
                if (broker == null) broker = FindBroker(image, started);
                rec["broker_pid"] = broker == null ? (object)null : (long)broker.Id;
                if (broker == null) rec["state"] = "no_broker";
                else {
                    IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED, false, (uint)broker.Id);
                    rec["open_error"] = h == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
                    if (h != IntPtr.Zero) {
                        if (action.StartsWith("suspend")) {
                            int st = NtSuspendProcess(h);
                            rec["suspend_status"] = st; rec["t_suspended"] = Now();
                            rec["lines_seen_at_hit"] = lines.Count;
                            Thread.Sleep(200);
                            drain();
                            rec["lines_at_suspend"] = lines.Count;
                            rec["state"] = st == 0 ? "suspended" : "suspend_failed";
                        }
                        if (action.EndsWith("kill")) {
                            bool k = TerminateProcess(h, 0xDEAD);
                            rec["t_killed"] = Now(); rec["killed"] = k;
                            long code;
                            rec["exited"] = WaitExit(h, 10000, out code);
                            rec["exit_code"] = code;
                            drain();
                            rec["lines_at_kill"] = lines.Count;
                            if (k) rec["state"] = action == "kill" ? "killed" : "suspended_killed";
                        }
                        CloseHandle(h);
                    }
                }
            } else if (action == "record") {
                rec["state"] = (broker != null && broker.HasExited) ? "recorded" : S(rec, "state", "recorded");
            }
        }
        var recs = new List<object>();
        for (int i = 0; i < lines.Count; i++) {
            var m1 = Regex.Match(lines[i], "\"rec\":\"([a-z_]+)\"");
            var m2 = Regex.Match(lines[i], "\"op\":(\\d+)");
            recs.Add(new Dictionary<string, object> { { "n", i + 1 }, { "rec", m1.Success ? m1.Groups[1].Value : "?" }, { "op", m2.Success ? (object)int.Parse(m2.Groups[1].Value) : null } });
        }
        rec["lines"] = lines.Count;
        rec["recs"] = recs;
        rec["last_line"] = lines.Count > 0 ? lines[lines.Count - 1] : null;
        rec["torn_tail_bytes"] = pending.Count;
        rec["t_end"] = Now();
        WriteDurable(outPath, rec);
        return 0;
    }

    // ----------------------------------------------------------------------------------------- privmon

    // spec: {out, broker_image, stop_file, max_ms}. Waits for a broker of that image started after the monitor, then
    // samples until it exits: the process token's SeRestorePrivilege attributes, and for every thread whether it
    // impersonates and whether its token has SeRestorePrivilege enabled. Only changes are kept (episodes per thread).
    static int PrivMon(string specPath) {
        var spec = ReadJson(specPath);
        string outPath = S(spec, "out", null), image = S(spec, "broker_image", null), stop = S(spec, "stop_file", null);
        DateTime started = DateTime.Now.AddSeconds(-1);
        var end = DateTime.Now.AddMilliseconds(I(spec, "max_ms", 1800000));
        long luid = PrivLuid("SeRestorePrivilege");
        var rec = new Dictionary<string, object> { { "t_start", Now() }, { "monitor_il", MyIl() }, { "luid_ok", luid != -1 } };
        WriteJson(outPath, rec);
        Process broker = null;
        while (broker == null && DateTime.Now < end && (stop == null || !File.Exists(stop))) { broker = FindBroker(image, started); if (broker == null) Thread.Sleep(20); }
        if (broker == null) { rec["state"] = "no_broker"; rec["t_end"] = Now(); WriteJson(outPath, rec); return 0; }
        rec["broker_pid"] = (long)broker.Id; rec["t_broker_seen"] = Now();
        IntPtr hp = OpenProcess(PROCESS_QUERY_LIMITED, false, (uint)broker.Id);
        long samples = 0, procEnabled = 0, procHeld = 0, threadSamples = 0, threadEnabled = 0, imperson = 0;
        var episodes = new List<object>();
        var open = new Dictionary<int, Dictionary<string, object>>();
        var lastImpersonating = new List<object>();
        while (DateTime.Now < end && (stop == null || !File.Exists(stop))) {
            uint code;
            if (hp == IntPtr.Zero || (GetExitCodeProcess(hp, out code) && code != 259)) break;
            samples++;
            IntPtr pt;
            if (OpenProcessToken(hp, TOKEN_QUERY, out pt)) {
                int at = PrivAttr(pt, luid);
                if (at >= 0) procHeld++;
                if (at > 0 && (at & SE_PRIVILEGE_ENABLED) != 0) { procEnabled++; if (procEnabled == 1) rec["process_enabled_first"] = Now(); }
                CloseHandle(pt);
            }
            var nowImp = new List<object>();
            try {
                broker.Refresh();
                foreach (ProcessThread th in broker.Threads) {
                    IntPtr ht = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED, false, (uint)th.Id);
                    if (ht == IntPtr.Zero) continue;
                    IntPtr tt;
                    bool has = OpenThreadToken(ht, TOKEN_QUERY, true, out tt);
                    bool enabled = false;
                    if (has) {
                        imperson++; threadSamples++;
                        int at = PrivAttr(tt, luid);
                        enabled = at > 0 && (at & SE_PRIVILEGE_ENABLED) != 0;
                        if (enabled) threadEnabled++;
                        CloseHandle(tt);
                        nowImp.Add(new Dictionary<string, object> { { "tid", th.Id }, { "restore_enabled", enabled } });
                    }
                    CloseHandle(ht);
                    Dictionary<string, object> ep;
                    bool isOpen = open.TryGetValue(th.Id, out ep);
                    if (has && !isOpen) { ep = new Dictionary<string, object> { { "tid", th.Id }, { "t_on", Now() }, { "restore_enabled_seen", enabled } }; open[th.Id] = ep; episodes.Add(ep); }
                    else if (has && enabled) ep["restore_enabled_seen"] = true;
                    else if (!has && isOpen) { ep["t_off"] = Now(); open.Remove(th.Id); }
                }
            } catch (Exception e) { rec["thread_error"] = e.Message; }
            lastImpersonating = nowImp;
            Thread.Sleep(1);
        }
        foreach (var ep in open.Values) ep["t_off"] = null;
        if (hp != IntPtr.Zero) CloseHandle(hp);
        rec["t_end"] = Now();
        rec["samples"] = samples; rec["process_token_held_samples"] = procHeld; rec["process_token_enabled_samples"] = procEnabled;
        rec["thread_token_samples"] = threadSamples; rec["thread_restore_enabled_samples"] = threadEnabled; rec["impersonation_samples"] = imperson;
        rec["episodes"] = episodes;
        rec["impersonating_at_last_sample"] = lastImpersonating;
        rec["state"] = "done";
        WriteJson(outPath, rec);
        return 0;
    }

    // -------------------------------------------------------------------------------------------- hold

    static int Hold(string path, string stop) {
        var rec = new Dictionary<string, object> { { "t", Now() }, { "pid", (long)Process.GetCurrentProcess().Id }, { "path", path }, { "il", MyIl() } };
        string note = stop + ".holding.json";
        try {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                rec["held"] = true;
                WriteJson(note, rec);
                while (!File.Exists(stop)) Thread.Sleep(500);
            }
        } catch (Exception e) { rec["held"] = false; rec["error"] = e.Message; WriteJson(note, rec); }
        return 0;
    }

    // ----------------------------------------------------------------------------------------- focused

    static int Focused(int pid, string outPath) {
        IntPtr h = WaitDialog((uint)pid, 5000, 100);
        var d = Observe((uint)pid, h);
        if (h != IntPtr.Zero) {
            try {
                var f = AutomationElement.FocusedElement;
                d["focused_name"] = f == null ? null : f.Current.Name;
                d["focused_type"] = f == null ? null : f.Current.ControlType.ProgrammaticName;
                bool inside = false;
                for (var e = f; e != null; e = TreeWalker.RawViewWalker.GetParent(e)) {
                    if (new IntPtr(e.Current.NativeWindowHandle) == h) { inside = true; break; }
                }
                d["focused_in_dialog"] = inside;
            } catch (Exception e) { d["focused_error"] = e.Message; }
        }
        WriteJson(outPath, d);
        return 0;
    }

    // --------------------------------------------------------------------------------------- autopress

    // spec: {out (directory), broker_image, stop_file, sequence [approve|cancel], tick, arm_wait_ms, max, max_ms}
    static int AutoPress(string specPath) {
        var spec = ReadJson(specPath);
        string dir = S(spec, "out", null), image = S(spec, "broker_image", null), stop = S(spec, "stop_file", null);
        Directory.CreateDirectory(dir);
        var seq = new List<string>();
        var sl = L(spec, "sequence");
        if (sl != null) foreach (object o in sl) seq.Add(Convert.ToString(o));
        int max = I(spec, "max", 20), n = 0;
        var end = DateTime.Now.AddMilliseconds(I(spec, "max_ms", 3600000));
        var done = new HashSet<long>();
        DateTime started = DateTime.Now.AddSeconds(-5);
        while (n < max && DateTime.Now < end && (stop == null || !File.Exists(stop))) {
            Thread.Sleep(200);
            foreach (var p in Process.GetProcessesByName("purge-broker")) {
                try {
                    if (image != null && !string.Equals(p.MainModule.FileName, image, StringComparison.OrdinalIgnoreCase)) continue;
                    if (p.StartTime < started) continue;
                } catch { continue; }
                IntPtr h = FindDialog((uint)p.Id);
                if (h == IntPtr.Zero || done.Contains(h.ToInt64())) continue;
                done.Add(h.ToInt64());
                n++;
                Thread.Sleep(700);
                var pre = Observe((uint)p.Id, h);
                string act = seq.Count == 0 ? "approve" : seq[Math.Min(n - 1, seq.Count - 1)];
                var rec = new Dictionary<string, object> { { "n", n }, { "broker_pid", (long)p.Id }, { "action", act }, { "pre", pre }, { "t", Now() } };
                if (act == "cancel") SendMessage(h, TDM_CLICK_BUTTON, (IntPtr)ID_CANCEL, IntPtr.Zero);
                else {
                    if (B(spec, "tick", true) && D(pre, "verify") != null) { SendMessage(h, TDM_CLICK_VERIFICATION, (IntPtr)1, IntPtr.Zero); rec["ticked"] = true; }
                    Thread.Sleep(I(spec, "arm_wait_ms", 1600));
                    IntPtr c = Child(h, ID_PRIMARY);
                    rec["primary_enabled"] = c != IntPtr.Zero && IsWindowEnabled(c);
                    SendMessage(h, TDM_CLICK_BUTTON, (IntPtr)ID_PRIMARY, IntPtr.Zero);
                }
                Thread.Sleep(1500);
                rec["dialog_alive_after"] = IsWindow(h) && IsWindowVisible(h);
                WriteJson(Path.Combine(dir, "autopress-" + n.ToString("D2") + ".json"), rec);
            }
        }
        return 0;
    }

    // ------------------------------------------------------------------------------------------ uihist

    static AutomationElement UiFindName(AutomationElement root, string name, ControlType type) {
        foreach (AutomationElement e in root.FindAll(TreeScope.Descendants, Condition.TrueCondition)) {
            try {
                if ((e.Current.Name ?? "") != name) continue;
                if (type != null && e.Current.ControlType != type) continue;
                return e;
            } catch { }
        }
        return null;
    }
    static string UiActivate(AutomationElement e) {
        object p;
        if (e.TryGetCurrentPattern(InvokePattern.Pattern, out p)) { ((InvokePattern)p).Invoke(); return "Invoke"; }
        if (e.TryGetCurrentPattern(SelectionItemPattern.Pattern, out p)) { ((SelectionItemPattern)p).Select(); return "SelectionItem.Select"; }
        var r = e.Current.BoundingRectangle;
        return Click((int)(r.Left + r.Width / 2), (int)(r.Top + r.Height / 2));
    }
    static List<string> UiTexts(AutomationElement root) {
        var t = new List<string>();
        foreach (AutomationElement e in root.FindAll(TreeScope.Descendants, Condition.TrueCondition)) {
            try { string n = e.Current.Name ?? ""; if (n.Length > 0 && t.Count < 600) t.Add(n); } catch { }
        }
        return t;
    }

    // spec: {out, pid, action: check|resume|rollback|read, wait_ms}. check: the History & undo page, then "Check for
    // interrupted cleanups", then waits for the recovery banner or the "No cleanup was interrupted." answer.
    static int UiHistory(string specPath) {
        var spec = ReadJson(specPath);
        string outPath = S(spec, "out", null), action = S(spec, "action", "read");
        int pid = I(spec, "pid", 0), waitMs = I(spec, "wait_ms", 90000);
        var rec = new Dictionary<string, object> { { "t", Now() }, { "action", action }, { "ui_pid", pid }, { "driver_il", MyIl() } };
        var steps = new List<object>();
        rec["steps"] = steps;
        AutomationElement win = null;
        var end = DateTime.Now.AddMilliseconds(waitMs);
        while (win == null && DateTime.Now < end) {
            // The process's Window, never one of its top-level Win32 panes (the Rust UI's winit event target and
            // text input indicator windows; m3-e2e-ui.ps1 Get-E2eWindow).
            win = UiWindow(pid);
            if (win == null) Thread.Sleep(500);
        }
        rec["window_found"] = win != null;
        if (win == null) { WriteJson(outPath, rec); return 0; }
        const string Banner = "The session was not recorded completely.";
        const string NoneText = "No cleanup was interrupted.";
        if (action == "check") {
            AutomationElement nav = null;
            while (nav == null && DateTime.Now < end) { nav = UiFindName(win, "History & undo", null); if (nav == null) Thread.Sleep(1000); }
            steps.Add(new Dictionary<string, object> { { "step", "find History & undo" }, { "ok", nav != null } });
            if (nav == null) { rec["texts"] = UiTexts(win); WriteJson(outPath, rec); return 0; }
            steps.Add(new Dictionary<string, object> { { "step", "open History & undo" }, { "how", UiActivate(nav) } });
            AutomationElement check = null;
            while (check == null && DateTime.Now < end) { check = UiFindName(win, "Check for interrupted cleanups", ControlType.Button); if (check == null) Thread.Sleep(1000); }
            steps.Add(new Dictionary<string, object> { { "step", "find Check for interrupted cleanups" }, { "ok", check != null } });
            if (check == null) { rec["texts"] = UiTexts(win); WriteJson(outPath, rec); return 0; }
            steps.Add(new Dictionary<string, object> { { "step", "invoke Check" }, { "how", UiActivate(check) }, { "t", Now() } });
            List<string> texts = null;
            bool banner = false, none = false;
            while (!banner && !none && DateTime.Now < end) {
                Thread.Sleep(1000);
                texts = UiTexts(win);
                foreach (string s in texts) { if (s.IndexOf(Banner, StringComparison.Ordinal) >= 0) banner = true; if (s.IndexOf(NoneText, StringComparison.Ordinal) >= 0) none = true; }
            }
            rec["banner"] = banner; rec["no_interrupted"] = none; rec["texts"] = texts;
            rec["resume_button"] = UiFindName(win, "Resume", ControlType.Button) != null;
            rec["rollback_button"] = UiFindName(win, "Roll back", ControlType.Button) != null;
        } else if (action == "resume" || action == "rollback") {
            string label = action == "resume" ? "Resume" : "Roll back";
            AutomationElement b = null;
            while (b == null && DateTime.Now < end) { b = UiFindName(win, label, ControlType.Button); if (b == null) Thread.Sleep(1000); }
            steps.Add(new Dictionary<string, object> { { "step", "find " + label }, { "ok", b != null } });
            if (b != null) steps.Add(new Dictionary<string, object> { { "step", "invoke " + label }, { "how", UiActivate(b) }, { "t", Now() } });
            rec["invoked"] = b != null;
        } else {
            rec["texts"] = UiTexts(win);
        }
        WriteJson(outPath, rec);
        return 0;
    }

    // ------------------------------------------------------------------------------------------- regsd

    // Sets the parts of <path>'s descriptor that <sections> names (o owner, g group, d DACL, p protected DACL) from
    // <sddl>, with SeRestorePrivilege and SeTakeOwnershipPrivilege enabled in this process only (a fixture tool).
    static int RegSd(string path, string sddl, string sections) {
        var rec = new Dictionary<string, object> { { "t", Now() }, { "path", path }, { "sddl", sddl }, { "sections", sections } };
        rec["restore_enabled"] = EnableOwnPrivilege("SeRestorePrivilege");
        rec["take_ownership_enabled"] = EnableOwnPrivilege("SeTakeOwnershipPrivilege");
        if (!path.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("HKLM only: " + path);
        uint info = 0; int access = 0x20000;   // READ_CONTROL
        if (sections.IndexOf('o') >= 0) { info |= 1; access |= 0x80000; }
        if (sections.IndexOf('g') >= 0) { info |= 2; access |= 0x80000; }
        if (sections.IndexOf('d') >= 0) { info |= 4; access |= 0x40000; }
        if (sections.IndexOf('p') >= 0) info |= 0x80000000;
        IntPtr key, sd;
        int e = RegOpenKeyEx((UIntPtr)0x80000002u, path.Substring(5), 0, access | 0x0100 /* KEY_WOW64_64KEY */, out key);
        if (e == 5) {
            // A DACL that grants no WRITE_OWNER: the backup-restore open, which the enabled privilege allows.
            e = RegOpenKeyEx((UIntPtr)0x80000002u, path.Substring(5), 0x4 /* REG_OPTION_BACKUP_RESTORE */, access | 0x0100, out key);
            rec["backup_restore_open"] = true;
        }
        rec["open"] = e;
        if (e == 0) {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out sd, IntPtr.Zero)) rec["convert_error"] = Marshal.GetLastWin32Error();
            else { rec["set"] = RegSetKeySecurity(key, info, sd); LocalFree(sd); }
            RegCloseKey(key);
        }
        WriteJson(Path.Combine(RecOut, "regsd-last.json"), rec);
        return e == 0 && rec.ContainsKey("set") && Convert.ToInt32(rec["set"]) == 0 ? 0 : 4;
    }

    // ----------------------------------------------------------------------------------- rec-uninstall

    static int RecUninstall(string[] a) {
        string key = a.Length > 1 ? a[1] : "";
        if (!Regex.IsMatch(key, "^PurgeRig[A-Za-z0-9]+$")) return 2;
        var rec = new Dictionary<string, object> { { "t", Now() }, { "key", key }, { "pid", (long)Process.GetCurrentProcess().Id }, { "il", MyIl() }, { "args", string.Join(" ", a) } };
        using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) {
            try { hklm.DeleteSubKeyTree(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + key, false); rec["arp_deleted"] = true; } catch (Exception e) { rec["arp_error"] = e.Message; }
        }
        string dir = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
        try { File.Delete(Path.Combine(dir, "app.exe")); rec["app_deleted"] = true; } catch (Exception e) { rec["app_error"] = e.Message; }
        try { WriteJson(Path.Combine(RecOut, "uninstalled-" + key + ".json"), rec); } catch { }
        return 0;
    }

    // --------------------------------------------------------------------------------------- client steps

    static object Subst(object o) {
        var s = o as string;
        if (s != null) {
            var whole = Regex.Match(s, @"^\{([a-z_]+)\}$");
            object v;
            if (whole.Success && RecVars.TryGetValue(whole.Groups[1].Value, out v)) return v;
            return Regex.Replace(s, @"\{([a-z_]+)\}", m => RecVars.TryGetValue(m.Groups[1].Value, out v) ? Convert.ToString(v) : m.Value);
        }
        var d = o as Dictionary<string, object>;
        if (d != null) { var c = new Dictionary<string, object>(); foreach (var kv in d) c[kv.Key] = Subst(kv.Value); return c; }
        var l = o as ArrayList;
        if (l != null) { var c = new ArrayList(); foreach (object x in l) c.Add(Subst(x)); return c; }
        return o;
    }

    static List<string> SelectRows(string sel, List<string> candidates) {
        var ids = new List<string>();
        if (sel == "all" && RecRows.Count == 0) { ids.AddRange(candidates); return ids; }
        foreach (var row in RecRows) {
            if (S(row, "band", "") == "Blocked") continue;
            string kind = S(row, "kind", ""), name = S(row, "display_name", "");
            bool take = sel == "all"
                || (sel.StartsWith("kind:") && kind == sel.Substring(5))
                || (sel.StartsWith("not-kind:") && kind != sel.Substring(9))
                || (sel.StartsWith("name:") && name.IndexOf(sel.Substring(5), StringComparison.OrdinalIgnoreCase) >= 0);
            if (take) ids.Add(S(row, "candidate_id", ""));
        }
        return ids;
    }

    static partial void ExtStep(RpcLink link, Dictionary<string, object> st, Dictionary<string, object> r, uint brokerPid,
                                Dictionary<string, object> spec, ref string session, ref string scan, List<string> candidates, ref bool handled) {
        if (RecVars == null) {
            RecVars = new Dictionary<string, object>();
            var v = D(spec, "vars");
            if (v != null) foreach (var kv in v) RecVars[kv.Key] = kv.Value;
        }
        string op = S(st, "op", "");
        switch (op) {
            case "call": {
                string method = S(st, "method", "");
                var prm = (Subst(D(st, "params")) as Dictionary<string, object>) ?? new Dictionary<string, object>();
                var resp = link.Call(method, prm, I(st, "timeout_ms", 120000));
                r["method"] = method; r["params"] = prm; r["response"] = resp;
                string save = S(st, "save", null);
                if (save != null) ClientNote(save, resp);
                handled = true;
                break;
            }
            case "consent": {
                string method = S(st, "method", "");
                var prm = (Subst(D(st, "params")) as Dictionary<string, object>) ?? new Dictionary<string, object>();
                r["method"] = method; r["params"] = prm;
                Consent(link, r, brokerPid, spec, st, method, () => prm, null);
                handled = true;
                break;
            }
            case "scan_full": {
                var resp = link.Call("leftovers.scan", new Dictionary<string, object> { { "session_id", session }, { "forced", B(st, "forced", false) } }, 900000);
                r["response"] = resp;
                scan = S(D(resp, "result"), "scan_id", null);
                RecRows.Clear(); candidates.Clear();
                int offset = 0;
                while (scan != null) {
                    var page = link.Call("scan.candidates", new Dictionary<string, object> { { "scan_id", scan }, { "offset", offset }, { "limit", 500 } }, 60000);
                    var items = L(D(page, "result"), "items");
                    if (items == null || items.Count == 0) break;
                    foreach (object io in items) {
                        var it = (Dictionary<string, object>)io;
                        RecRows.Add(it);
                        if (S(it, "band", "") != "Blocked") candidates.Add(S(it, "candidate_id", ""));
                    }
                    offset += items.Count;
                    if (offset >= I(D(page, "result"), "total", 0)) break;
                }
                r["candidates"] = RecRows.Count;
                ClientNote(S(st, "save", "candidates-full.json"), RecRows);
                handled = true;
                break;
            }
            case "execute": {
                string sel = S(st, "select", "all");
                var ids = SelectRows(sel, candidates);
                r["select"] = sel; r["selected"] = ids.Count;
                if (ids.Count == 0 || scan == null) { r["error"] = "nothing selected by " + sel + (scan == null ? " (no scan)" : ""); handled = true; break; }
                string sc = scan;
                Consent(link, r, brokerPid, spec, st, "plan.execute", null, () => {
                    var p = new Dictionary<string, object> { { "scan_id", sc }, { "selected", ids.ToArray() } };
                    if (B(st, "allow_irreversible", false)) p["allow_irreversible"] = true;
                    return p;
                });
                var asks = r.ContainsKey("asks") ? r["asks"] as List<object> : null;
                if (asks != null) {
                    foreach (object ao in asks) {
                        var a = (Dictionary<string, object>)ao;
                        object resp;
                        if (!a.TryGetValue("response", out resp)) continue;
                        string sess = S(D(resp as Dictionary<string, object>, "result"), "session", null);
                        if (sess != null) { RecVars["session"] = sess; r["session"] = sess; }
                    }
                }
                handled = true;
                break;
            }
            case "sleep":
                Thread.Sleep(I(st, "ms", 1000));
                handled = true;
                break;
        }
    }
}
