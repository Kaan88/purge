// m3sec.exe: the Purge rig's M3 security tool (vm\RIG.md section 14; modes m3-broker, m3-consent, m3-uac of
// vm\rig-m3.ps1; M3_DESIGN.md 4 T1, T2, T5-T8, 11.2, 11.3, gate G3, G4, G5, G10). Built in the guest by
// vm\guest\m3-sec.ps1 with csc.exe of .NET Framework 4 (C# 5). Nothing here changes the system except the
// fixture uninstaller (its own ARP key and main exe) and the files it is told to write.
//
//   client <spec.json>      the rig's pipe client. Deployed as Purge.exe beside purge-broker.exe, so the broker's
//                           client check (design 3.3 step 4: <own directory>\Purge.exe) accepts it. Starts the
//                           broker the way the UI does (ShellExecuteExW "runas", SEE_MASK_NOCLOSEPROCESS), checks the
//                           server pid, speaks JSON-RPC lines, and records everything in <out>\client.json.
//   drive <spec.json>       presses at the broker's consent dialog by one method (SendInput key or mouse,
//                           PostMessage/SendMessage, UI Automation); run at medium (the attack) or high (the control).
//   observe <pid> <out> [ms] high: reads the consent dialog of process <pid> (buttons, check box, texts, page, code).
//   focus <pid> <out>       high: brings the dialog of <pid> to the foreground (so medium SendInput is a fair test).
//   arm <spec.json>         high: the arming-delay test (a click in the first second does nothing; a later one works).
//   press <spec.json>       high: ticks the box and presses a button by TDM messages (approval of a dialog).
//   ui <spec.json>          high: drives the real Purge UI through UI Automation (Uninstall click, cancelled bar).
//   inputdesk <out>         the name of the input desktop now.
//   fixture-uninstall [/S]  the fixture program's uninstaller (copied as uninst.exe).
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Automation;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

// partial: vm\guest\m3rec.cs (modes m3-owner, m3-recover, m3-extras of vm\rig-m3-recover.ps1) adds roles and client
// steps through ExtMain and ExtStep when it is compiled with this file; built alone, both hooks are empty.
static partial class M3Sec {
    static partial void ExtMain(string[] a, ref int code);
    static partial void ExtStep(RpcLink link, Dictionary<string, object> st, Dictionary<string, object> r, uint brokerPid,
                                Dictionary<string, object> spec, ref string session, ref string scan, List<string> candidates, ref bool handled);

    // ------------------------------------------------------------------------------------------ Win32
    const int WM_USER = 0x400, WM_COMMAND = 0x111, WM_CLOSE = 0x10, BM_CLICK = 0xF5, BM_GETCHECK = 0xF0;
    const int TDM_CLICK_BUTTON = WM_USER + 102, TDM_CLICK_VERIFICATION = WM_USER + 113;
    const int ID_PRIMARY = 100, ID_CANCEL = 2, ID_NEXT = 9001, ID_BACK = 9002;
    const int INPUT_MOUSE = 0, INPUT_KEYBOARD = 1, KEYEVENTF_KEYUP = 2;
    const int MOUSEEVENTF_MOVE = 1, MOUSEEVENTF_LEFTDOWN = 2, MOUSEEVENTF_LEFTUP = 4, MOUSEEVENTF_ABSOLUTE = 0x8000;
    const ushort VK_TAB = 0x09, VK_RETURN = 0x0D, VK_MENU = 0x12, VK_ESCAPE = 0x1B, VK_SPACE = 0x20;
    const uint SEE_MASK_NOCLOSEPROCESS = 0x40, SEE_MASK_NOASYNC = 0x100;
    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000, OPEN_EXISTING = 3;
    const uint FILE_ATTRIBUTE_NORMAL = 0x80, FILE_FLAG_OVERLAPPED = 0x40000000;
    const uint SECURITY_SQOS_PRESENT = 0x00100000, SECURITY_IDENTIFICATION = 0x00010000;
    const string DialogTitle = "Purge security prompt";

    [StructLayout(LayoutKind.Sequential)] struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT { public int dx, dy; public uint mouseData, dwFlags, time; public IntPtr extra; }
    [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr extra; }
    [StructLayout(LayoutKind.Explicit)] struct INPUT { [FieldOffset(0)] public int type; [FieldOffset(8)] public MOUSEINPUT mi; [FieldOffset(8)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct SHELLEXECUTEINFO {
        public int cbSize; public uint fMask; public IntPtr hwnd; public string lpVerb; public string lpFile; public string lpParameters;
        public string lpDirectory; public int nShow; public IntPtr hInstApp; public IntPtr lpIDList; public string lpClass; public IntPtr hkeyClass;
        public uint dwHotKey; public IntPtr hIcon; public IntPtr hProcess;
    }
    delegate bool EnumProc(IntPtr hwnd, IntPtr l);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ShellExecuteEx(ref SHELLEXECUTEINFO i);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint GetProcessId(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessTimes(IntPtr p, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sec, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);
    [DllImport("user32.dll", SetLastError = true)] static extern bool AllowSetForegroundWindow(uint pid);
    [DllImport("user32.dll", SetLastError = true)] static extern bool PostMessage(IntPtr h, int msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr SendMessageTimeout(IntPtr h, int msg, IntPtr w, IntPtr l, int flags, int ms, out IntPtr result);
    [DllImport("user32.dll", SetLastError = true)] static extern uint SendInput(uint n, INPUT[] inputs, int size);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] static extern bool BringWindowToTop(IntPtr h);
    [DllImport("user32.dll")] static extern bool AttachThreadInput(uint a, uint b, bool attach);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc p, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc p, IntPtr l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr h);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern bool IsWindow(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr h);
    [DllImport("user32.dll")] static extern int GetSystemMetrics(int i);
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr OpenInputDesktop(int flags, bool inherit, uint access);
    [DllImport("user32.dll", SetLastError = true)] static extern bool CloseDesktop(IntPtr h);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool GetUserObjectInformation(IntPtr h, int index, StringBuilder buf, int len, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr t, int cls, IntPtr buf, int len, out int ret);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, uint i);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024 };
    static readonly object FileLock = new object();

    [STAThread]
    static int Main(string[] a) {
        SetProcessDPIAware();
        if (a.Length == 0) return 2;
        try {
            switch (a[0]) {
                case "client": return Client(a[1]);
                case "drive": return Drive(a[1]);
                case "observe": return ObserveCmd(int.Parse(a[1]), a[2], a.Length > 3 ? int.Parse(a[3]) : 10000);
                case "focus": return FocusCmd(int.Parse(a[1]), a[2]);
                case "focuswin": return FocusWin(int.Parse(a[1]), a[2]);
                case "procinfo": return ProcInfo(int.Parse(a[1]), a[2]);
                case "arm": return Arm(a[1]);
                case "press": return Press(a[1]);
                case "ui": return Ui(a[1]);
                case "inputdesk": return InputDesk(a[1]);
                case "fixture-uninstall": return FixtureUninstall(a);
            }
            int code = 2;
            ExtMain(a, ref code);
            return code;
        } catch (Exception e) {
            try {
                string dir = a.Length > 1 ? (Directory.Exists(a[a.Length - 1]) ? a[a.Length - 1] : Path.GetDirectoryName(Path.GetFullPath(a[a.Length - 1]))) : ".";
                File.AppendAllText(Path.Combine(dir, "error-" + a[0] + ".txt"), DateTime.Now.ToString("o") + " " + e + "\r\n");
            } catch { }
            return 3;
        }
    }

    // ---------------------------------------------------------------------------------------- helpers

    static string Now() { return DateTime.Now.ToString("o"); }

    static string Integrity(IntPtr process) {
        IntPtr tok;
        if (!OpenProcessToken(process, 0x8, out tok)) return "unknown(open " + Marshal.GetLastWin32Error() + ")";
        try {
            int len; GetTokenInformation(tok, 25, IntPtr.Zero, 0, out len);
            IntPtr buf = Marshal.AllocHGlobal(len);
            try {
                if (!GetTokenInformation(tok, 25, buf, len, out len)) return "unknown(info " + Marshal.GetLastWin32Error() + ")";
                IntPtr sid = Marshal.ReadIntPtr(buf);
                int n = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                int rid = Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(n - 1)));
                if (rid >= 0x4000) return "system";
                if (rid >= 0x3000) return "high";
                if (rid >= 0x2000) return "medium";
                if (rid >= 0x1000) return "low";
                return "untrusted";
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(tok); }
    }
    static string MyIl() { return Integrity(GetCurrentProcess()); }

    // The integrity level of another process (PROCESS_QUERY_LIMITED_INFORMATION); "unknown(...)" when it cannot be read.
    static string IntegrityOf(uint pid) {
        IntPtr h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return "unknown(open process " + Marshal.GetLastWin32Error() + ")";
        try { return Integrity(h); } finally { CloseHandle(h); }
    }

    // TokenElevationType: 1 default (no split token: a standard user, or UAC off), 2 full, 3 limited.
    static int ElevationType() {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x8, out tok)) return 0;
        try {
            IntPtr buf = Marshal.AllocHGlobal(4);
            try { int ret; return GetTokenInformation(tok, 18, buf, 4, out ret) ? Marshal.ReadInt32(buf) : 0; }
            finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(tok); }
    }

    static void WriteJson(string path, object o) {
        lock (FileLock) {
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, Json.Serialize(o), new UTF8Encoding(false));
            if (File.Exists(path)) File.Delete(path);
            File.Move(tmp, path);
        }
    }
    static string ReadShared(string path) {
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (var r = new StreamReader(fs)) return r.ReadToEnd();
    }
    static Dictionary<string, object> ReadJson(string path) { return Json.Deserialize<Dictionary<string, object>>(ReadShared(path)); }
    static string S(Dictionary<string, object> d, string k, string def) { object v; return d != null && d.TryGetValue(k, out v) && v != null ? Convert.ToString(v) : def; }
    static int I(Dictionary<string, object> d, string k, int def) { object v; return d != null && d.TryGetValue(k, out v) && v != null ? Convert.ToInt32(v) : def; }
    static bool B(Dictionary<string, object> d, string k, bool def) { object v; return d != null && d.TryGetValue(k, out v) && v != null ? Convert.ToBoolean(v) : def; }
    static Dictionary<string, object> D(Dictionary<string, object> d, string k) { object v; return d != null && d.TryGetValue(k, out v) ? v as Dictionary<string, object> : null; }
    static ArrayList L(Dictionary<string, object> d, string k) { object v; return d != null && d.TryGetValue(k, out v) ? v as ArrayList : null; }
    static bool WaitFile(string path, int ms) {
        var end = DateTime.Now.AddMilliseconds(ms);
        while (!File.Exists(path)) { if (DateTime.Now > end) return false; Thread.Sleep(100); }
        return true;
    }

    static Dictionary<string, object> WindowInfo(IntPtr h) {
        var d = new Dictionary<string, object>();
        uint pid; GetWindowThreadProcessId(h, out pid);
        var cls = new StringBuilder(256); GetClassName(h, cls, 256);
        var txt = new StringBuilder(512); GetWindowText(h, txt, 512);
        d["hwnd"] = h.ToInt64(); d["pid"] = (long)pid; d["class"] = cls.ToString(); d["text"] = txt.ToString();
        return d;
    }

    // The consent dialog of process <pid>: a visible top-level #32770 window titled "Purge security prompt".
    static IntPtr FindDialog(uint pid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((h, l) => {
            uint p; GetWindowThreadProcessId(h, out p);
            if (p != pid || !IsWindowVisible(h)) return true;
            var cls = new StringBuilder(64); GetClassName(h, cls, 64);
            var txt = new StringBuilder(256); GetWindowText(h, txt, 256);
            if (cls.ToString() == "#32770" && txt.ToString() == DialogTitle) { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    static IntPtr WaitDialog(uint pid, int ms, int pollMs) {
        var end = DateTime.Now.AddMilliseconds(ms);
        while (true) {
            IntPtr h = FindDialog(pid);
            if (h != IntPtr.Zero || DateTime.Now > end) return h;
            Thread.Sleep(pollMs);
        }
    }
    static List<Dictionary<string, object>> Children(IntPtr h) {
        var list = new List<Dictionary<string, object>>();
        EnumChildWindows(h, (c, l) => {
            var d = WindowInfo(c); RECT r; GetWindowRect(c, out r);
            d["id"] = GetDlgCtrlID(c); d["rect"] = new[] { r.Left, r.Top, r.Right, r.Bottom };
            d["enabled"] = IsWindowEnabled(c); d["visible"] = IsWindowVisible(c);
            list.Add(d); return true;
        }, IntPtr.Zero);
        return list;
    }
    static IntPtr Child(IntPtr dlg, int id) {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(dlg, (c, l) => {
            if (GetDlgCtrlID(c) == id) {
                var cls = new StringBuilder(64); GetClassName(c, cls, 64);
                if (cls.ToString().IndexOf("Button", StringComparison.OrdinalIgnoreCase) >= 0) { found = c; return false; }
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    static IntPtr FirstVisibleButton(IntPtr dlg) {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(dlg, (c, l) => {
            var cls = new StringBuilder(64); GetClassName(c, cls, 64);
            if (cls.ToString() == "Button" && IsWindowVisible(c)) { found = c; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    static string Focus(IntPtr hwnd) {
        if (GetForegroundWindow() == hwnd) return "already";
        uint pid; uint fgThread = GetWindowThreadProcessId(GetForegroundWindow(), out pid), me = GetCurrentThreadId();
        bool att = fgThread != 0 && fgThread != me && AttachThreadInput(me, fgThread, true);
        SetForegroundWindow(hwnd); BringWindowToTop(hwnd);
        if (att) AttachThreadInput(me, fgThread, false);
        Thread.Sleep(300);
        return GetForegroundWindow() == hwnd ? (att ? "attach" : "plain") : "failed";
    }

    static string Keys(params ushort[] seq) {
        // A vk is pressed when it first appears and released when it appears again.
        var inputs = new List<INPUT>(); var down = new HashSet<ushort>();
        foreach (ushort vk in seq) {
            var i = new INPUT { type = INPUT_KEYBOARD }; i.ki.wVk = vk;
            if (down.Contains(vk)) { i.ki.dwFlags = KEYEVENTF_KEYUP; down.Remove(vk); } else down.Add(vk);
            inputs.Add(i);
        }
        uint n = SendInput((uint)inputs.Count, inputs.ToArray(), Marshal.SizeOf(typeof(INPUT)));
        return "SendInput inserted " + n + "/" + inputs.Count + " lasterror=" + Marshal.GetLastWin32Error();
    }
    static string Click(int x, int y) {
        int sw = GetSystemMetrics(0), sh = GetSystemMetrics(1);
        int ax = (int)((x * 65535L) / Math.Max(1, sw - 1)), ay = (int)((y * 65535L) / Math.Max(1, sh - 1));
        var seq = new INPUT[3];
        for (int k = 0; k < 3; k++) { seq[k].type = INPUT_MOUSE; seq[k].mi.dx = ax; seq[k].mi.dy = ay; }
        seq[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
        seq[1].mi.dwFlags = MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_ABSOLUTE;
        seq[2].mi.dwFlags = MOUSEEVENTF_LEFTUP | MOUSEEVENTF_ABSOLUTE;
        uint n = SendInput(3, seq, Marshal.SizeOf(typeof(INPUT)));
        return "click at " + x + "," + y + " (screen " + sw + "x" + sh + "): SendInput inserted " + n + "/3 lasterror=" + Marshal.GetLastWin32Error();
    }
    static string ClickRect(int[] r) { return Click((r[0] + r[2]) / 2, (r[1] + r[3]) / 2); }
    static int[] RectOf(IntPtr h) { RECT r; return GetWindowRect(h, out r) ? new[] { r.Left, r.Top, r.Right, r.Bottom } : null; }

    // ------------------------------------------------------------------------------------- observe

    // Reads the dialog from a high process: window, buttons (child windows), the UI Automation tree (texts, the check
    // box and its state), the page ("page i of n" of the attention list), Next/Back, the footer code.
    static Dictionary<string, object> Observe(uint pid, IntPtr hwnd) {
        var d = new Dictionary<string, object>();
        d["t"] = Now(); d["broker_pid"] = (long)pid; d["observer_il"] = MyIl();
        d["found"] = hwnd != IntPtr.Zero;
        if (hwnd == IntPtr.Zero) return d;
        d["window"] = WindowInfo(hwnd);
        d["hwnd"] = hwnd.ToInt64();
        d["broker_il"] = IntegrityOf(pid);
        d["foreground"] = GetForegroundWindow() == hwnd;
        d["foreground_window"] = WindowInfo(GetForegroundWindow());
        d["rect"] = RectOf(hwnd);
        var kids = Children(hwnd);
        d["children"] = kids;
        IntPtr primary = Child(hwnd, ID_PRIMARY), next = Child(hwnd, ID_NEXT), back = Child(hwnd, ID_BACK), cancel = Child(hwnd, ID_CANCEL);
        d["has_primary"] = primary != IntPtr.Zero; d["primary_enabled"] = primary != IntPtr.Zero && IsWindowEnabled(primary);
        d["has_next"] = next != IntPtr.Zero; d["has_back"] = back != IntPtr.Zero; d["has_cancel"] = cancel != IntPtr.Zero;
        var rects = new Dictionary<string, object>();
        if (primary != IntPtr.Zero) rects["primary"] = RectOf(primary);
        if (next != IntPtr.Zero) rects["next"] = RectOf(next);
        if (back != IntPtr.Zero) rects["back"] = RectOf(back);
        if (cancel != IntPtr.Zero) rects["cancel"] = RectOf(cancel);
        var labels = new Dictionary<string, object>();
        foreach (var k in kids) {
            int id = Convert.ToInt32(k["id"]);
            if (id == ID_PRIMARY) labels["primary"] = k["text"];
            if (id == ID_CANCEL) labels["cancel"] = k["text"];
        }
        d["labels"] = labels;
        var texts = new List<object>();
        var elements = new List<object>();
        object verify = null;
        try {
            var root = AutomationElement.FromHandle(hwnd);
            foreach (AutomationElement e in root.FindAll(TreeScope.Descendants, Condition.TrueCondition)) {
                var ct = e.Current.ControlType;
                string name = e.Current.Name ?? "";
                var r = e.Current.BoundingRectangle;
                int[] rr = r.IsEmpty ? null : new[] { (int)r.Left, (int)r.Top, (int)r.Right, (int)r.Bottom };
                var el = new Dictionary<string, object> { { "type", ct.ProgrammaticName }, { "name", name }, { "enabled", e.Current.IsEnabled }, { "rect", rr } };
                if (ct == ControlType.CheckBox) {
                    object p; string state = "unknown";
                    if (e.TryGetCurrentPattern(TogglePattern.Pattern, out p)) state = ((TogglePattern)p).Current.ToggleState.ToString();
                    el["toggle"] = state;
                    verify = new Dictionary<string, object> { { "name", name }, { "toggle", state }, { "rect", rr }, { "enabled", e.Current.IsEnabled } };
                    if (rr != null) rects["verify"] = rr;
                }
                if (name.Length > 0 && (ct == ControlType.Text || ct == ControlType.Pane || ct == ControlType.Document)) texts.Add(name);
                elements.Add(el);
            }
        } catch (Exception e) { d["uia_error"] = e.GetType().Name + ": " + e.Message; }
        d["elements"] = elements;
        d["texts"] = texts;
        d["verify"] = verify;
        d["rects"] = rects;
        string all = string.Join("\n", texts.ConvertAll(x => (string)x).ToArray());
        var pm = Regex.Match(all, @"\(page (\d+) of (\d+)\)");
        d["page"] = pm.Success ? int.Parse(pm.Groups[1].Value) : 1;
        d["pages"] = pm.Success ? int.Parse(pm.Groups[2].Value) : 1;
        d["paged"] = pm.Success;
        var cm = Regex.Match(all, @"Code ([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})");
        d["footer_code"] = cm.Success ? cm.Groups[1].Value.ToUpperInvariant() : null;
        var am = Regex.Match(all, @"Needs your attention(?:: \d+ to \d+ of (\d+)| \((\d+)\))");
        d["attention_total"] = am.Success ? int.Parse(am.Groups[1].Success ? am.Groups[1].Value : am.Groups[2].Value) : 0;
        return d;
    }

    static int ObserveCmd(int pid, string outPath, int waitMs) {
        IntPtr h = WaitDialog((uint)pid, waitMs, 100);
        WriteJson(outPath, Observe((uint)pid, h));
        return 0;
    }

    static int FocusCmd(int pid, string outPath) {
        IntPtr h = WaitDialog((uint)pid, 10000, 100);
        var d = new Dictionary<string, object> { { "t", Now() }, { "found", h != IntPtr.Zero } };
        if (h != IntPtr.Zero) { d["how"] = Focus(h); d["foreground"] = GetForegroundWindow() == h; d["hwnd"] = h.ToInt64(); }
        WriteJson(outPath, d);
        return 0;
    }

    // The first visible top-level window of <pid> (the rig client's or the UI's main window) to the foreground, as a
    // user's click on it would: the broker's SetForegroundWindow then works through AllowSetForegroundWindow.
    static int FocusWin(int pid, string outPath) {
        IntPtr found = IntPtr.Zero;
        var end = DateTime.Now.AddSeconds(30);
        while (found == IntPtr.Zero && DateTime.Now < end) {
            EnumWindows((h, l) => {
                uint p; GetWindowThreadProcessId(h, out p);
                if (p == (uint)pid && IsWindowVisible(h)) { found = h; return false; }
                return true;
            }, IntPtr.Zero);
            if (found == IntPtr.Zero) Thread.Sleep(250);
        }
        var d = new Dictionary<string, object> { { "t", Now() }, { "found", found != IntPtr.Zero } };
        if (found != IntPtr.Zero) { d["window"] = WindowInfo(found); d["how"] = Focus(found); d["foreground"] = GetForegroundWindow() == found; }
        WriteJson(outPath, d);
        return 0;
    }

    // A process's integrity level and account (high reader).
    static int ProcInfo(int pid, string outPath) {
        var d = new Dictionary<string, object> { { "t", Now() }, { "pid", pid } };
        try {
            var p = Process.GetProcessById(pid);
            d["alive"] = !p.HasExited;
            d["image"] = p.MainModule.FileName;
        } catch (Exception e) { d["alive"] = false; d["error"] = e.Message; }
        d["il"] = IntegrityOf((uint)pid);
        IntPtr h = OpenProcess(0x1000, false, (uint)pid), tok;
        if (h != IntPtr.Zero) {
            if (OpenProcessToken(h, 0x8, out tok)) {
                try { d["user"] = new WindowsIdentity(tok).Name; } catch (Exception e) { d["user_error"] = e.Message; }
                CloseHandle(tok);
            }
            CloseHandle(h);
        }
        WriteJson(outPath, d);
        return 0;
    }

    // ------------------------------------------------------------------------------------------ drive

    static List<object> Attempts;
    static IntPtr DriveHwnd;

    // One attempt: act, wait, and judge from the window alone (the dialog closes on an answer). The agent judges the
    // other effects (box, page, response, journal) from a high process afterwards.
    static void Attempt(string target, string name, Func<string> act) {
        var a = new Dictionary<string, object> { { "target", target }, { "name", name }, { "t", Now() } };
        a["foreground_is_dialog"] = GetForegroundWindow() == DriveHwnd;
        try { a["detail"] = act(); } catch (Exception e) { a["detail"] = "exception " + e.GetType().Name + ": " + e.Message; }
        Thread.Sleep(1200);
        a["dialog_alive"] = IsWindow(DriveHwnd) && IsWindowVisible(DriveHwnd);
        a["reached"] = !(bool)a["dialog_alive"];
        Attempts.Add(a);
    }

    static string Post(IntPtr h, int msg, long w, long l) {
        bool ok = PostMessage(h, msg, (IntPtr)w, (IntPtr)l);
        return "PostMessage(0x" + msg.ToString("x") + ", " + w + ") returned " + ok + " lasterror=" + Marshal.GetLastWin32Error();
    }
    static string SendTimeout(IntPtr h, int msg, long w) {
        IntPtr res; IntPtr ok = SendMessageTimeout(h, msg, (IntPtr)w, IntPtr.Zero, 0x2, 5000, out res);
        return "SendMessageTimeout(0x" + msg.ToString("x") + ", " + w + ") returned " + ok + " lasterror=" + Marshal.GetLastWin32Error();
    }
    static int TargetId(string target) {
        switch (target) { case "primary": return ID_PRIMARY; case "cancel": return ID_CANCEL; case "next": return ID_NEXT; case "back": return ID_BACK; }
        return 0;
    }
    static int[] TargetRect(string target, Dictionary<string, object> seen) {
        int id = TargetId(target);
        if (id != 0) { IntPtr c = Child(DriveHwnd, id); if (c != IntPtr.Zero) return RectOf(c); }
        var rects = D(seen, "rects");
        var r = L(rects, target);
        if (r == null) return null;
        return new[] { Convert.ToInt32(r[0]), Convert.ToInt32(r[1]), Convert.ToInt32(r[2]), Convert.ToInt32(r[3]) };
    }
    static string Label(string target, Dictionary<string, object> seen) {
        if (target == "verify") { var v = D(seen, "verify"); return v == null ? null : S(v, "name", null); }
        if (target == "cancel") return "Cancel";
        if (target == "next") return "Next";
        if (target == "back") return "Back";
        return S(D(seen, "labels"), target, null);
    }
    static AutomationElement UiaFind(AutomationElement root, ControlType type, string name) {
        foreach (AutomationElement e in root.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, type))) {
            string n = (e.Current.Name ?? "").Replace("&", "");
            if (name != null && n == name.Replace("&", "")) return e;
        }
        return null;
    }
    static ushort Accelerator(string label) {
        if (label == null) return 0;
        int i = label.IndexOf('&');
        if (i < 0 || i + 1 >= label.Length || label[i + 1] == '&') return 0;
        char c = char.ToUpperInvariant(label[i + 1]);
        return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ? (ushort)c : (ushort)0;
    }

    // spec: {out, broker_pid, method, mode: attack|control, targets: [...], seen: <observe json path>}
    // attack: every way the method has to press each target (the box first, then Next, the primary, Cancel last).
    // control: one press of Cancel by the method (the dialog then ends as declined, which is the visible effect).
    static int Drive(string specPath) {
        var spec = ReadJson(specPath);
        string outPath = S(spec, "out", null), method = S(spec, "method", ""), mode = S(spec, "mode", "attack");
        uint pid = (uint)I(spec, "broker_pid", 0);
        Dictionary<string, object> seen = null;
        string seenPath = S(spec, "seen", null);
        if (seenPath != null && File.Exists(seenPath)) seen = ReadJson(seenPath);
        var rec = new Dictionary<string, object> { { "t", Now() }, { "method", method }, { "mode", mode }, { "driver_pid", (long)Process.GetCurrentProcess().Id }, { "driver_il", MyIl() } };
        Attempts = new List<object>();
        rec["attempts"] = Attempts;
        DriveHwnd = WaitDialog(pid, 15000, 100);
        rec["dialog_found"] = DriveHwnd != IntPtr.Zero;
        rec["dialog_hwnd"] = DriveHwnd.ToInt64();
        rec["broker_il_seen_by_driver"] = IntegrityOf(pid);
        rec["foreground_before"] = WindowInfo(GetForegroundWindow());
        if (DriveHwnd == IntPtr.Zero) { rec["reached"] = false; WriteJson(outPath, rec); return 0; }
        var targets = new List<string>();
        var tl = L(spec, "targets");
        if (mode == "control") targets.Add("cancel");
        else if (tl != null) foreach (object o in tl) targets.Add(Convert.ToString(o));
        foreach (string target in targets) {
            if (!IsWindow(DriveHwnd)) break;
            int id = TargetId(target);
            string label = Label(target, seen);
            switch (method) {
                case "sendinput-key":
                    if (mode == "control") { Attempt(target, "SendInput Esc", () => Keys(VK_ESCAPE, VK_ESCAPE)); break; }
                    if (target == "primary") {
                        ushort acc = Accelerator(label);
                        if (acc != 0) Attempt(target, "SendInput Alt+" + (char)acc + " (accelerator of '" + label + "')", () => Keys(VK_MENU, acc, acc, VK_MENU));
                        Attempt(target, "SendInput Tab, Tab, Space (move the focus, press the focused button)", () => Keys(VK_TAB, VK_TAB, VK_TAB, VK_TAB, VK_SPACE, VK_SPACE));
                        Attempt(target, "SendInput Enter (the default button)", () => Keys(VK_RETURN, VK_RETURN));
                    } else if (target == "verify") {
                        Attempt(target, "SendInput Space (the focused control)", () => Keys(VK_SPACE, VK_SPACE));
                    } else if (target == "next") {
                        Attempt(target, "SendInput Tab, Enter", () => Keys(VK_TAB, VK_TAB, VK_RETURN, VK_RETURN));
                    } else if (target == "cancel") {
                        Attempt(target, "SendInput Esc", () => Keys(VK_ESCAPE, VK_ESCAPE));
                    }
                    break;
                case "sendinput-mouse": {
                    int[] r = TargetRect(target, seen);
                    if (r == null) Attempts.Add(new Dictionary<string, object> { { "target", target }, { "name", "SendInput mouse click" }, { "detail", "skipped: no rectangle for " + target }, { "reached", false }, { "skipped", true } });
                    else Attempt(target, "SendInput mouse click on " + target, () => ClickRect(r));
                    break;
                }
                case "postmessage":
                    if (target == "verify") {
                        Attempt(target, "PostMessage TDM_CLICK_VERIFICATION(1)", () => Post(DriveHwnd, TDM_CLICK_VERIFICATION, 1, 0));
                        Attempt(target, "SendMessageTimeout TDM_CLICK_VERIFICATION(1)", () => SendTimeout(DriveHwnd, TDM_CLICK_VERIFICATION, 1));
                        break;
                    }
                    Attempt(target, "PostMessage TDM_CLICK_BUTTON " + id, () => Post(DriveHwnd, TDM_CLICK_BUTTON, id, 0));
                    if (mode == "control") break;
                    Attempt(target, "PostMessage WM_COMMAND " + id, () => Post(DriveHwnd, WM_COMMAND, id, 0));
                    {
                        IntPtr c = Child(DriveHwnd, id);
                        if (c != IntPtr.Zero) Attempt(target, "PostMessage BM_CLICK to child button " + id, () => Post(c, BM_CLICK, 0, 0));
                    }
                    Attempt(target, "SendMessageTimeout TDM_CLICK_BUTTON " + id, () => SendTimeout(DriveHwnd, TDM_CLICK_BUTTON, id));
                    if (target == "cancel") Attempt(target, "PostMessage WM_CLOSE", () => Post(DriveHwnd, WM_CLOSE, 0, 0));
                    break;
                case "uia": {
                    AutomationElement root = null;
                    if (Attempts.Count == 0 && mode == "attack") Attempt("list", "UIA FromHandle + list descendants", () => {
                        root = AutomationElement.FromHandle(DriveHwnd);
                        var names = new List<string>();
                        foreach (AutomationElement e in root.FindAll(TreeScope.Descendants, Condition.TrueCondition))
                            names.Add(e.Current.ControlType.ProgrammaticName + " '" + e.Current.Name + "'");
                        return names.Count + " descendants: " + string.Join("; ", names.ToArray());
                    });
                    if (target == "verify") {
                        Attempt(target, "UIA TogglePattern.Toggle on the check box", () => {
                            var r2 = AutomationElement.FromHandle(DriveHwnd);
                            var b = UiaFind(r2, ControlType.CheckBox, label);
                            if (b == null) return "check box not found through UIA";
                            object p; if (!b.TryGetCurrentPattern(TogglePattern.Pattern, out p)) return "no TogglePattern";
                            ((TogglePattern)p).Toggle(); return "Toggle returned";
                        });
                    } else {
                        Attempt(target, "UIA InvokePattern.Invoke on '" + label + "'", () => {
                            var r2 = AutomationElement.FromHandle(DriveHwnd);
                            var b = UiaFind(r2, ControlType.Button, label);
                            if (b == null) return "button '" + label + "' not found through UIA";
                            object p; if (!b.TryGetCurrentPattern(InvokePattern.Pattern, out p)) return "no InvokePattern";
                            ((InvokePattern)p).Invoke(); return "Invoke returned";
                        });
                    }
                    break;
                }
                default: throw new ArgumentException("unknown method " + method);
            }
        }
        bool any = false;
        foreach (object o in Attempts) if ((bool)((Dictionary<string, object>)o)["reached"]) any = true;
        rec["reached"] = any;
        rec["dialog_alive_at_end"] = IsWindow(DriveHwnd);
        WriteJson(outPath, rec);
        return 0;
    }

    // ------------------------------------------------------------------------------------ arm, press

    // spec: {out, broker_pid, wait_ms, go_file, renavigate, tick, early_ms, late_ms, click_late}
    // Polls for the dialog (so the first appearance is seen within ~30 ms), or re-shows the last page (Back, Next), then
    // clicks the primary button with real input (SendInput) before the arming delay has passed and again after it.
    static int Arm(string specPath) {
        var spec = ReadJson(specPath);
        string outPath = S(spec, "out", null);
        uint pid = (uint)I(spec, "broker_pid", 0);
        var rec = new Dictionary<string, object> { { "t", Now() }, { "arm_il", MyIl() } };
        string go = S(spec, "go_file", null);
        if (go != null) File.WriteAllText(go, Now());
        var sw = Stopwatch.StartNew();
        IntPtr h = WaitDialog(pid, I(spec, "wait_ms", 600000), 30);
        rec["found"] = h != IntPtr.Zero;
        if (h == IntPtr.Zero) { WriteJson(outPath, rec); return 0; }
        var shown = Stopwatch.StartNew();
        rec["found_after_ms"] = sw.ElapsedMilliseconds;
        rec["foreground_at_found"] = GetForegroundWindow() == h;
        if (B(spec, "renavigate", false)) {
            IntPtr back = Child(h, ID_BACK);
            rec["renavigated"] = back != IntPtr.Zero;
            if (back != IntPtr.Zero) {
                SendMessage(h, TDM_CLICK_BUTTON, (IntPtr)ID_BACK, IntPtr.Zero);
                Thread.Sleep(400);
                SendMessage(h, TDM_CLICK_BUTTON, (IntPtr)ID_NEXT, IntPtr.Zero);
                shown = Stopwatch.StartNew();
            }
        }
        rec["focus"] = Focus(h);
        int early = I(spec, "early_ms", 300), late = I(spec, "late_ms", 1800);
        if (B(spec, "tick", false)) {
            while (shown.ElapsedMilliseconds < 100) Thread.Sleep(5);
            SendMessage(h, TDM_CLICK_VERIFICATION, (IntPtr)1, IntPtr.Zero);
            rec["ticked_at_ms"] = shown.ElapsedMilliseconds;
        }
        while (shown.ElapsedMilliseconds < early) Thread.Sleep(5);
        IntPtr primary = Child(h, ID_PRIMARY);
        rec["has_primary"] = primary != IntPtr.Zero;
        if (primary == IntPtr.Zero) { WriteJson(outPath, rec); return 0; }
        rec["primary_enabled_before_early"] = IsWindowEnabled(primary);
        rec["early_click"] = ClickRect(RectOf(primary));
        rec["early_click_ms"] = shown.ElapsedMilliseconds;
        Thread.Sleep(500);
        rec["dialog_alive_after_early"] = IsWindow(h) && IsWindowVisible(h);
        rec["primary_enabled_after_early"] = IsWindow(h) && IsWindowEnabled(primary);
        while (shown.ElapsedMilliseconds < late) Thread.Sleep(20);
        rec["primary_enabled_late"] = IsWindow(h) && IsWindowEnabled(primary);
        rec["late_ms"] = shown.ElapsedMilliseconds;
        if (B(spec, "click_late", true) && IsWindow(h)) {
            Focus(h);
            rec["late_click"] = ClickRect(RectOf(primary));
            Thread.Sleep(1500);
            rec["dialog_alive_after_late"] = IsWindow(h) && IsWindowVisible(h);
        }
        WriteJson(outPath, rec);
        return 0;
    }

    // spec: {out, broker_pid, tick, button, wait_ms, arm_wait_ms}: the approval of a dialog by TDM messages from high.
    static int Press(string specPath) {
        var spec = ReadJson(specPath);
        string outPath = S(spec, "out", null);
        uint pid = (uint)I(spec, "broker_pid", 0);
        var rec = new Dictionary<string, object> { { "t", Now() }, { "press_il", MyIl() } };
        IntPtr h = WaitDialog(pid, I(spec, "wait_ms", 15000), 100);
        rec["found"] = h != IntPtr.Zero;
        if (h != IntPtr.Zero) {
            // TDM_CLICK_VERIFICATION on a page without a verification box crashed the broker inside comctl32
            // (0xc0000005, e2e-20261123-063603 app-events.json): tick only when the page shows a check box.
            bool hasBox = false;
            try {
                hasBox = AutomationElement.FromHandle(h).FindFirst(TreeScope.Descendants,
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.CheckBox)) != null;
            } catch (Exception e) { rec["box_error"] = e.Message; }
            rec["has_verification"] = hasBox;
            rec["ticked"] = false;
            if (B(spec, "tick", false) && hasBox) { SendMessage(h, TDM_CLICK_VERIFICATION, (IntPtr)1, IntPtr.Zero); rec["ticked"] = true; }
            Thread.Sleep(I(spec, "arm_wait_ms", 1600));
            int id = I(spec, "button", ID_PRIMARY);
            IntPtr c = Child(h, id);
            rec["button_by"] = "id";
            if (c == IntPtr.Zero && id == ID_PRIMARY) {
                // On Windows 11 24H2 the TaskDialog's buttons can report control id 0 (dialog-run.json,
                // e2e-20261123-062157); the primary is then the first visible Button, ahead of Cancel.
                c = FirstVisibleButton(h);
                rec["button_by"] = c != IntPtr.Zero ? "first-visible" : "none";
            }
            if (c != IntPtr.Zero) { var t = new StringBuilder(256); GetWindowText(c, t, 256); rec["button_text"] = t.ToString(); }
            rec["button_enabled"] = c != IntPtr.Zero && IsWindowEnabled(c);
            SendMessage(h, TDM_CLICK_BUTTON, (IntPtr)id, IntPtr.Zero);
            rec["pressed"] = id;
            Thread.Sleep(1500);
            rec["dialog_alive_after"] = IsWindow(h) && IsWindowVisible(h);
        }
        WriteJson(outPath, rec);
        return 0;
    }

    // ------------------------------------------------------------------------------------------ client

    static string ClientDir;
    static int ConsentK;

    static void ClientNote(string name, object o) { WriteJson(Path.Combine(ClientDir, name), o); }

    // spec keys: out, broker, launch (runas|create|none), args (template with {pipe} {pid} {ctime}), parent_pid
    // (-1: explorer's pid), ctime_delta, env {k: v}, squat, window, connects, first_line (hello|garbage),
    // connect_wait_ms, steps [...], hold_ms, exit_wait_ms, go (wait for go-<k> before each consent request).
    static int Client(string specPath) {
        var spec = ReadJson(specPath);
        ClientDir = S(spec, "out", Path.GetDirectoryName(specPath));
        Directory.CreateDirectory(ClientDir);
        var rec = new Dictionary<string, object>();
        rec["t_start"] = Now();
        rec["pid"] = (long)Process.GetCurrentProcess().Id;
        rec["image"] = Process.GetCurrentProcess().MainModule.FileName;
        rec["il"] = MyIl();
        rec["user"] = Environment.UserDomainName + "\\" + Environment.UserName;
        int et = ElevationType();
        rec["elevation_type"] = et;
        bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        rec["in_admin_role"] = admin;
        // The UI's own pre-check (design 3.5): neither elevated nor the limited half of an administrator token.
        rec["precheck"] = et == 3 ? "limited_admin" : et == 2 ? "elevated" : admin ? "elevated" : "standard_user";
        System.Windows.Forms.Form form = null;
        Exception failure = null;
        if (B(spec, "window", false)) {
            form = new System.Windows.Forms.Form { Text = "Purge rig client", Width = 420, Height = 160, StartPosition = System.Windows.Forms.FormStartPosition.Manual, Left = 40, Top = 40 };
            var label = new System.Windows.Forms.Label { Dock = System.Windows.Forms.DockStyle.Fill, Text = "Purge rig client (vm\\guest\\m3sec.cs): pid " + rec["pid"] };
            form.Controls.Add(label);
            var f2 = form;
            form.Shown += (s, e) => {
                rec["window"] = f2.Handle.ToInt64();
                var worker = new Thread(() => {
                    try { ClientFlow(spec, rec, f2.Handle); } catch (Exception x) { failure = x; }
                    try { f2.BeginInvoke(new Action(() => f2.Close())); } catch { }
                }) { IsBackground = true };
                worker.SetApartmentState(ApartmentState.STA);   // ShellExecuteExW "runas" on an STA thread, as the UI does
                worker.Start();
            };
            System.Windows.Forms.Application.Run(form);
        } else {
            try { ClientFlow(spec, rec, IntPtr.Zero); } catch (Exception x) { failure = x; }
        }
        if (failure != null) rec["error"] = failure.ToString();
        rec["t_end"] = Now();
        ClientNote("client.json", rec);
        return 0;
    }

    // Polls GetExitCodeProcess (STILL_ACTIVE = 259) for up to ms; works with PROCESS_QUERY_LIMITED_INFORMATION alone.
    static bool WaitExit(IntPtr h, int ms, out long code) {
        var end = DateTime.Now.AddMilliseconds(ms);
        while (true) {
            uint c;
            if (!GetExitCodeProcess(h, out c)) { code = -1; return false; }
            if (c != 259) { code = c; return true; }
            if (DateTime.Now > end) { code = -1; return false; }
            Thread.Sleep(100);
        }
    }

    static string Template(string t, string pipe, ulong pid, ulong ctime) {
        return t.Replace("{pipe}", pipe).Replace("{pid}", pid.ToString()).Replace("{ctime}", ctime.ToString());
    }

    static void ClientFlow(Dictionary<string, object> spec, Dictionary<string, object> rec, IntPtr owner) {
        var env = D(spec, "env");
        if (env != null) {
            var set = new Dictionary<string, object>();
            foreach (var kv in env) { Environment.SetEnvironmentVariable(kv.Key, Convert.ToString(kv.Value)); set[kv.Key] = kv.Value; }
            rec["env_set"] = set;
        }
        var seen = new Dictionary<string, object>();
        foreach (string v in new[] { "ProgramData", "ALLUSERSPROFILE", "PURGE_KB_DIR", "SystemDrive" }) seen[v] = Environment.GetEnvironmentVariable(v);
        rec["env_seen"] = seen;   // what the runas call inherits (T7)
        string startFile = S(spec, "start_file", null);
        if (startFile != null) rec["start_seen"] = WaitFile(startFile, 300000);   // the agent focuses the window first
        byte[] rnd = new byte[16]; using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(rnd);
        string pipe = BitConverter.ToString(rnd).Replace("-", "").ToLowerInvariant();
        string path = @"\\.\pipe\purge-" + pipe;
        rec["pipe"] = pipe;
        NamedPipeServerStream squat = null;
        if (B(spec, "squat", false)) {
            try {
                squat = new NamedPipeServerStream("purge-" + pipe, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                squat.BeginWaitForConnection(ar => { try { squat.EndWaitForConnection(ar); } catch { } }, null);
                rec["squat"] = new Dictionary<string, object> { { "created", true } };
            } catch (Exception e) { rec["squat"] = new Dictionary<string, object> { { "created", false }, { "error", e.Message } }; }
        }
        long created, x1, x2, x3;
        GetProcessTimes(GetCurrentProcess(), out created, out x1, out x2, out x3);
        ulong myPid = (ulong)Process.GetCurrentProcess().Id;
        ulong parentPid = myPid;
        int po = I(spec, "parent_pid", 0);
        if (po == -1) { var ex = Process.GetProcessesByName("explorer"); parentPid = ex.Length > 0 ? (ulong)ex[0].Id : 4; }
        else if (po > 0) parentPid = (ulong)po;
        ulong ctime = (ulong)created + (ulong)I(spec, "ctime_delta", 0);
        string args = Template(S(spec, "args", "--pipe {pipe} --parent {pid} --parent-ctime {ctime}"), pipe, parentPid, ctime);
        string broker = S(spec, "broker", null);
        string launch = S(spec, "launch", "runas");
        var lr = new Dictionary<string, object> { { "mode", launch }, { "broker", broker }, { "args", args }, { "pipe", pipe }, { "t", Now() } };
        rec["launch"] = lr;
        IntPtr hProcess = IntPtr.Zero;
        Process created2 = null;
        uint brokerPid = 0;
        if (launch == "runas") {
            var sei = new SHELLEXECUTEINFO();
            sei.cbSize = Marshal.SizeOf(typeof(SHELLEXECUTEINFO));
            sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
            // No owner window, as BrokerLauncher (DECISIONS 2026-11-23 "UAC prompt owner").
            sei.hwnd = IntPtr.Zero; sei.lpVerb = "runas"; sei.lpFile = broker; sei.lpParameters = args;
            sei.lpDirectory = Path.GetDirectoryName(broker); sei.nShow = 1;
            bool ok = ShellExecuteEx(ref sei);
            int err = ok ? 0 : Marshal.GetLastWin32Error();
            lr["ok"] = ok; lr["error"] = err; lr["t_answered"] = Now();
            if (!ok) lr["message"] = new Win32Exception(err).Message;
            hProcess = sei.hProcess;
        } else if (launch == "create") {
            var psi = new ProcessStartInfo(broker, args) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(broker) };
            try { created2 = Process.Start(psi); hProcess = created2.Handle; lr["ok"] = true; lr["error"] = 0; }
            catch (Win32Exception e) { lr["ok"] = false; lr["error"] = e.NativeErrorCode; lr["message"] = e.Message; }
        } else if (launch == "attach") {
            // Another client's broker (its launched.json): the second-client case of design T2.
            var other = ReadJson(S(spec, "attach_file", ""));
            pipe = S(other, "pipe", ""); path = @"\\.\pipe\purge-" + pipe; lr["pipe"] = pipe; rec["pipe"] = pipe;
            uint opid = (uint)I(other, "broker_pid", 0);
            // PROCESS_QUERY_LIMITED_INFORMATION is what a medium process may open an elevated one with; the exit is
            // polled with GetExitCodeProcess (WaitExit), which needs nothing more.
            hProcess = OpenProcess(0x1000, false, opid);
            lr["ok"] = hProcess != IntPtr.Zero; lr["error"] = hProcess != IntPtr.Zero ? 0 : Marshal.GetLastWin32Error();
        } else { lr["ok"] = false; lr["error"] = -1; }
        if (hProcess != IntPtr.Zero) { brokerPid = GetProcessId(hProcess); lr["broker_pid"] = (long)brokerPid; }
        ClientNote("launched.json", lr);
        if (hProcess == IntPtr.Zero) { if (squat != null) squat.Dispose(); return; }

        var connects = new List<object>();
        rec["connects"] = connects;
        int n = I(spec, "connects", 1);
        var steps = L(spec, "steps");
        for (int i = 0; i < n; i++) {
            var c = new Dictionary<string, object> { { "attempt", i + 1 }, { "t", Now() } };
            connects.Add(c);
            IntPtr raw = IntPtr.Zero;
            var end = DateTime.Now.AddMilliseconds(I(spec, "connect_wait_ms", 10000));
            while (true) {
                raw = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 3, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, IntPtr.Zero);
                if (raw != (IntPtr)(-1)) break;
                int e = Marshal.GetLastWin32Error();
                c["open_error"] = e;
                uint code; bool exited = GetExitCodeProcess(hProcess, out code) && code != 259;
                if (exited || DateTime.Now > end || (e != 2 && e != 231 && e != 121)) { raw = IntPtr.Zero; break; }
                Thread.Sleep(50);
            }
            if (raw == IntPtr.Zero) { c["opened"] = false; break; }
            c["opened"] = true; c.Remove("open_error");
            uint server; bool got = GetNamedPipeServerProcessId(raw, out server);
            c["server_pid"] = got ? (long)server : -1;
            c["server_check"] = got && server == brokerPid ? "ok" : "pid_mismatch";
            var handle = new SafePipeHandle(raw, true);
            if ((string)c["server_check"] != "ok") { handle.Dispose(); continue; }
            using (var stream = new NamedPipeClientStream(PipeDirection.InOut, true, true, handle))
            using (var link = new RpcLink(stream)) {
                string first = S(spec, "first_line", "hello");
                Dictionary<string, object> hello;
                if (first == "hello") hello = link.Call("engine.hello", new Dictionary<string, object>(), 30000);
                else { link.WriteRaw("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"history.get\",\"params\":{\"session\":\"x\"}}"); hello = link.Wait(1, 15000); }
                c["hello"] = hello;
                c["hello_answered"] = hello != null && !hello.ContainsKey("closed");
                if (B(spec, "second_client_probe", false) && (bool)c["hello_answered"]) {
                    IntPtr r2 = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 3, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, IntPtr.Zero);
                    c["second_client_open_error"] = r2 == (IntPtr)(-1) ? Marshal.GetLastWin32Error() : 0;
                    if (r2 != (IntPtr)(-1)) CloseHandle(r2);
                }
                if ((bool)c["hello_answered"] && steps != null && i == n - 1) {
                    var srec = new List<object>();
                    rec["steps"] = srec;
                    RunSteps(link, steps, srec, brokerPid, spec);
                }
                c["notifications"] = link.NotificationCounts();
            }
        }
        int hold = I(spec, "hold_ms", 0);
        if (hold > 0) Thread.Sleep(hold);
        long xc;
        bool exitedNow = WaitExit(hProcess, I(spec, "exit_wait_ms", 30000), out xc);
        rec["broker_exited"] = exitedNow;
        rec["exit_code"] = exitedNow ? (object)xc : null;
        rec["t_exit_seen"] = Now();
        if (squat != null) squat.Dispose();
    }

    static void RunSteps(RpcLink link, ArrayList steps, List<object> srec, uint brokerPid, Dictionary<string, object> spec) {
        string session = null, scan = null;
        var candidates = new List<string>();
        foreach (object so in steps) {
            var st = (Dictionary<string, object>)so;
            string op = S(st, "op", "");
            var r = new Dictionary<string, object> { { "op", op }, { "t", Now() } };
            srec.Add(r);
            ClientNote("progress.json", srec);
            switch (op) {
                case "shutdown":
                    r["response"] = link.Call("broker.shutdown", new Dictionary<string, object>(), 15000);
                    break;
                case "prepare": {
                    var resp = link.Call("uninstall.prepare", new Dictionary<string, object> { { "program_ids", new[] { S(st, "program", "") } } }, 600000);
                    r["response"] = resp;
                    var progs = L(D(resp, "result"), "programs");
                    if (progs != null && progs.Count > 0) { var p0 = (Dictionary<string, object>)progs[0]; session = S(p0, "session_id", null); r["route"] = S(p0, "route", null); }
                    r["session_id"] = session;
                    break;
                }
                case "run":
                    Consent(link, r, brokerPid, spec, st, "uninstall.run", () => new Dictionary<string, object> { { "session_id", session }, { "quiet", B(st, "quiet", true) } }, null);
                    break;
                case "scan": {
                    var resp = link.Call("leftovers.scan", new Dictionary<string, object> { { "session_id", session }, { "forced", B(st, "forced", false) } }, 900000);
                    r["response"] = resp;
                    scan = S(D(resp, "result"), "scan_id", null);
                    int offset = 0;
                    while (scan != null) {
                        var page = link.Call("scan.candidates", new Dictionary<string, object> { { "scan_id", scan }, { "offset", offset }, { "limit", 500 } }, 60000);
                        var items = L(D(page, "result"), "items");
                        if (items == null || items.Count == 0) break;
                        foreach (object io in items) {
                            var it = (Dictionary<string, object>)io;
                            if (S(it, "band", "") == "Blocked") continue;
                            candidates.Add(S(it, "candidate_id", ""));
                        }
                        offset += items.Count;
                        if (offset >= I(D(page, "result"), "total", 0)) break;
                    }
                    r["candidates"] = candidates.Count;
                    ClientNote("candidates.json", candidates);
                    break;
                }
                case "plan_execute":
                    Consent(link, r, brokerPid, spec, st, "plan.execute", null, () => {
                        var p = new Dictionary<string, object> { { "scan_id", scan } };
                        if (S(st, "select", "all") == "preselected") p["preselected"] = true; else p["selected"] = candidates.ToArray();
                        return p;
                    });
                    break;
                default: {
                    bool handled = false;
                    ExtStep(link, st, r, brokerPid, spec, ref session, ref scan, candidates, ref handled);
                    if (!handled) r["error"] = "unknown op";
                    break;
                }
            }
        }
        ClientNote("progress.json", srec);
    }

    // One consent request, asked again after each decline (up to "repeat" times). Before each ask the client writes
    // ready-<k>.json and, when the spec says "go", waits for go-<k> from the agent; consent.shown lands in
    // consent-shown-<k>.json, the answer in consent-result-<k>.json.
    static void Consent(RpcLink link, Dictionary<string, object> r, uint brokerPid, Dictionary<string, object> spec, Dictionary<string, object> st,
                        string method, Func<Dictionary<string, object>> runParams, Func<Dictionary<string, object>> planParams) {
        var asks = new List<object>();
        r["asks"] = asks;
        int repeat = I(st, "repeat", 1);
        for (int i = 0; i < repeat; i++) {
            int k = ++ConsentK;
            var a = new Dictionary<string, object> { { "k", k }, { "method", method } };
            asks.Add(a);
            Dictionary<string, object> prm;
            if (planParams != null) {
                var plan = link.Call("plan.create", planParams(), 600000);
                a["plan"] = plan;
                var pr = D(plan, "result");
                string planId = S(pr, "plan_id", null);
                a["plan_code"] = S(pr, "code", null);
                if (planId == null) { ClientNote("consent-result-" + k + ".json", new Dictionary<string, object> { { "k", k }, { "method", method }, { "refused", plan } }); break; }
                prm = new Dictionary<string, object> { { "plan_id", planId }, { "restore_point", S(st, "restore_point", "off") } };
            } else prm = runParams();
            ClientNote("ready-" + k + ".json", new Dictionary<string, object> { { "k", k }, { "method", method }, { "broker_pid", (long)brokerPid }, { "plan_code", a.ContainsKey("plan_code") ? a["plan_code"] : null }, { "t", Now() } });
            if (B(spec, "go", true)) {
                string go = Path.Combine(ClientDir, "go-" + k);
                if (!WaitFile(go, I(spec, "go_wait_ms", 1800000))) { a["error"] = "no go-" + k; break; }
            }
            AllowSetForegroundWindow(brokerPid);
            link.ShownFile = Path.Combine(ClientDir, "consent-shown-" + k + ".json");
            var resp = link.Call(method, prm, 3600000);
            a["response"] = resp;
            string kind = S(D(D(resp, "error"), "data"), "kind", null);
            a["kind"] = kind ?? (resp != null && resp.ContainsKey("result") ? "result" : "none");
            ClientNote("consent-result-" + k + ".json", new Dictionary<string, object> { { "k", k }, { "method", method }, { "kind", a["kind"] }, { "response", resp }, { "t", Now() } });
            if (kind != "consent_declined") break;
        }
    }

    // JSON-RPC 2.0 lines over the pipe; a reader thread files answers by id and writes consent.shown to ShownFile.
    sealed class RpcLink : IDisposable {
        readonly Stream stream;
        readonly StreamWriter writer;
        readonly Dictionary<long, Dictionary<string, object>> answers = new Dictionary<long, Dictionary<string, object>>();
        readonly Dictionary<string, int> counts = new Dictionary<string, int>();
        readonly object gate = new object();
        bool closed;
        long nextId = 1;
        public string ShownFile;

        public RpcLink(Stream s) {
            stream = s;
            writer = new StreamWriter(s, new UTF8Encoding(false)) { NewLine = "\n", AutoFlush = true };
            new Thread(Reader) { IsBackground = true }.Start();
        }
        void Reader() {
            try {
                var reader = new StreamReader(stream, new UTF8Encoding(false));
                string line;
                while ((line = reader.ReadLine()) != null) {
                    Dictionary<string, object> m;
                    try { m = Json.Deserialize<Dictionary<string, object>>(line); } catch { continue; }
                    object id;
                    if (m.TryGetValue("id", out id) && id != null && !m.ContainsKey("method")) {
                        lock (gate) { answers[Convert.ToInt64(id)] = m; Monitor.PulseAll(gate); }
                    } else {
                        string method = S(m, "method", "?");
                        lock (gate) { int c; counts.TryGetValue(method, out c); counts[method] = c + 1; }
                        if (method == "consent.shown" && ShownFile != null) {
                            var p = D(m, "params");
                            WriteJson(ShownFile, new Dictionary<string, object> { { "t", Now() }, { "params", p } });
                        }
                    }
                }
            } catch { }
            lock (gate) { closed = true; Monitor.PulseAll(gate); }
        }
        public void WriteRaw(string line) { try { writer.Write(line + "\n"); } catch { } }
        public Dictionary<string, object> Call(string method, Dictionary<string, object> prm, int timeoutMs) {
            long id;
            lock (gate) id = nextId++;
            var msg = new Dictionary<string, object> { { "jsonrpc", "2.0" }, { "id", id }, { "method", method }, { "params", prm } };
            try { writer.Write(Json.Serialize(msg) + "\n"); }
            catch (Exception e) { return new Dictionary<string, object> { { "closed", true }, { "write_error", e.Message } }; }
            return Wait(id, timeoutMs);
        }
        public Dictionary<string, object> Wait(long id, int timeoutMs) {
            var end = DateTime.Now.AddMilliseconds(timeoutMs);
            lock (gate) {
                while (!answers.ContainsKey(id)) {
                    if (closed) return new Dictionary<string, object> { { "closed", true } };
                    var left = end - DateTime.Now;
                    if (left <= TimeSpan.Zero) return new Dictionary<string, object> { { "timed_out", true } };
                    Monitor.Wait(gate, left);
                }
                var a = answers[id]; answers.Remove(id); return a;
            }
        }
        public Dictionary<string, object> NotificationCounts() {
            lock (gate) { var d = new Dictionary<string, object>(); foreach (var kv in counts) d[kv.Key] = kv.Value; return d; }
        }
        public void Dispose() { try { writer.Dispose(); } catch { } try { stream.Dispose(); } catch { } }
    }

    // ---------------------------------------------------------------------------------------- real UI

    // spec: {out, pid, action: start-uninstall|read-bar, program, wait_ms}
    static int Ui(string specPath) {
        var spec = ReadJson(specPath);
        string outPath = S(spec, "out", null), action = S(spec, "action", "");
        int pid = I(spec, "pid", 0), waitMs = I(spec, "wait_ms", 60000);
        var rec = new Dictionary<string, object> { { "t", Now() }, { "action", action }, { "ui_pid", pid }, { "driver_il", MyIl() } };
        var steps = new List<object>();
        rec["steps"] = steps;
        AutomationElement win = null;
        var end = DateTime.Now.AddMilliseconds(waitMs);
        while (win == null && DateTime.Now < end) {
            win = AutomationElement.RootElement.FindFirst(TreeScope.Children, new PropertyCondition(AutomationElement.ProcessIdProperty, pid));
            if (win == null) Thread.Sleep(500);
        }
        rec["window_found"] = win != null;
        if (win == null) { WriteJson(outPath, rec); return 0; }
        rec["window_name"] = win.Current.Name;
        if (action == "start-uninstall") {
            string program = S(spec, "program", "");
            AutomationElement row = null;
            while (row == null && DateTime.Now < end) {
                foreach (AutomationElement e in win.FindAll(TreeScope.Descendants, Condition.TrueCondition)) {
                    string n = e.Current.Name ?? "";
                    if (n.IndexOf(program, StringComparison.OrdinalIgnoreCase) >= 0) { row = e; break; }
                }
                if (row == null) Thread.Sleep(1000);
            }
            steps.Add(new Dictionary<string, object> { { "step", "find row" }, { "ok", row != null }, { "name", row == null ? null : row.Current.Name }, { "type", row == null ? null : row.Current.ControlType.ProgrammaticName } });
            if (row == null) { WriteJson(outPath, rec); return 0; }
            // Select the row: SelectionItem on it or an ancestor list item; else a real click on it.
            string how = null;
            for (var e = row; e != null && how == null; e = TreeWalker.RawViewWalker.GetParent(e)) {
                object p;
                if (e.TryGetCurrentPattern(SelectionItemPattern.Pattern, out p)) { ((SelectionItemPattern)p).Select(); how = "SelectionItem.Select on " + e.Current.ControlType.ProgrammaticName; }
                if (e == win) break;
            }
            if (how == null) {
                var r = row.Current.BoundingRectangle;
                how = Click((int)(r.Left + r.Width / 2), (int)(r.Top + r.Height / 2));
            }
            steps.Add(new Dictionary<string, object> { { "step", "select row" }, { "how", how } });
            Thread.Sleep(1500);
            AutomationElement btn = win.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.AutomationIdProperty, "UninstallButton"));
            if (btn == null) btn = win.FindFirst(TreeScope.Descendants, new AndCondition(new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button), new PropertyCondition(AutomationElement.NameProperty, "Uninstall")));
            steps.Add(new Dictionary<string, object> { { "step", "find Uninstall" }, { "ok", btn != null }, { "enabled", btn != null && btn.Current.IsEnabled } });
            if (btn == null) { WriteJson(outPath, rec); return 0; }
            object ip;
            if (btn.TryGetCurrentPattern(InvokePattern.Pattern, out ip)) ((InvokePattern)ip).Invoke();
            steps.Add(new Dictionary<string, object> { { "step", "invoke Uninstall" }, { "t", Now() } });
            // The first-elevation explanation (ElevationPrompts.ConfirmFirstElevationAsync): Continue.
            AutomationElement cont = null;
            var end2 = DateTime.Now.AddSeconds(15);
            while (cont == null && DateTime.Now < end2) {
                cont = win.FindFirst(TreeScope.Descendants, new AndCondition(new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button), new PropertyCondition(AutomationElement.NameProperty, "Continue")));
                if (cont == null) {
                    if (Process.GetProcessesByName("consent").Length > 0) break;
                    Thread.Sleep(500);
                }
            }
            if (cont != null && cont.TryGetCurrentPattern(InvokePattern.Pattern, out ip)) {
                ((InvokePattern)ip).Invoke();
                steps.Add(new Dictionary<string, object> { { "step", "invoke Continue" }, { "t", Now() } });
            } else steps.Add(new Dictionary<string, object> { { "step", "no Continue button" }, { "consent_up", Process.GetProcessesByName("consent").Length > 0 } });
        } else if (action == "read-bar") {
            string want = S(spec, "text", "You cancelled the Windows prompt.");
            bool found = false;
            var texts = new List<string>();
            while (!found && DateTime.Now < end) {
                texts.Clear();
                foreach (AutomationElement e in win.FindAll(TreeScope.Descendants, Condition.TrueCondition)) {
                    string n = e.Current.Name ?? "";
                    if (n.Length > 0 && texts.Count < 400) texts.Add(n);
                    if (n.IndexOf(want, StringComparison.Ordinal) >= 0) found = true;
                }
                if (!found) Thread.Sleep(1000);
            }
            rec["bar_found"] = found;
            rec["texts"] = texts;
        }
        WriteJson(outPath, rec);
        return 0;
    }

    // ----------------------------------------------------------------------------------- the rest

    static int InputDesk(string path) {
        var r = new Dictionary<string, object> { { "t", Now() }, { "il", MyIl() } };
        IntPtr h = OpenInputDesktop(0, false, 0x1);
        if (h == IntPtr.Zero) { r["open"] = false; r["error"] = Marshal.GetLastWin32Error(); }
        else {
            var sb = new StringBuilder(256); int need;
            r["open"] = true;
            r["name"] = GetUserObjectInformation(h, 2, sb, 512, out need) ? sb.ToString() : ("error " + Marshal.GetLastWin32Error());
            CloseDesktop(h);
        }
        WriteJson(path, r);
        return 0;
    }

    // The fixture program's uninstaller: removes its ARP entry and its main exe (so verify-gone passes) and leaves
    // everything else as leftovers; writes C:\cr\out\m3-sec\fixture-uninstalled.json as the proof that it ran.
    // m3-e2e (vm\RIG.md section 17) names another ARP key: "fixture-uninstall <Key>" (letters and digits only, HKLM
    // 64-bit Uninstall\<Key>); its proof is then C:\cr\out\m3-e2e\fixture-<Key>.json. A first argument starting with
    // '/' (m3-sec's quiet "/S") keeps the default key.
    static int FixtureUninstall(string[] a) {
        string key = "PurgeRigApp";
        string marker = @"C:\cr\out\m3-sec\fixture-uninstalled.json";
        if (a.Length > 1 && !a[1].StartsWith("/")) {
            if (!Regex.IsMatch(a[1], "^[A-Za-z0-9]{1,64}$")) return 2;
            key = a[1];
            marker = @"C:\cr\out\m3-e2e\fixture-" + key + ".json";
        }
        string Arp = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + key;
        var rec = new Dictionary<string, object> { { "t", Now() }, { "pid", (long)Process.GetCurrentProcess().Id }, { "il", MyIl() }, { "args", string.Join(" ", a) }, { "key", key } };
        using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) {
            try { hklm.DeleteSubKeyTree(Arp, false); rec["arp_deleted"] = true; } catch (Exception e) { rec["arp_error"] = e.Message; }
        }
        string dir = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
        try { File.Delete(Path.Combine(dir, "app.exe")); rec["app_deleted"] = true; } catch (Exception e) { rec["app_error"] = e.Message; }
        try {
            Directory.CreateDirectory(Path.GetDirectoryName(marker));
            WriteJson(marker, rec);
        } catch { }
        return 0;
    }
}
