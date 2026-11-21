<#
  Purge rig, M3-RIG-UAC (docs\M3_DESIGN.json, M3_DESIGN.md section 4 T1 and 11.2; vm\RIG.md section 13). Guest side,
  Windows PowerShell 5.1, run elevated by C:\cr\agent.ps1 as one job per phase; the host driver is vm\rig-m3.ps1.

    & C:\cr\guest\m3-uipi-probe.ps1 -Phase <phase> [-Tag <name>] [-WaitSec <n>]

  Phases (every output under C:\cr\out\m3-rig-uac\, log probe.log; result lines start with "M3 "):
    uac-set     sets HKLM\...\Policies\System ConsentPromptBehaviorAdmin=5 and PromptOnSecureDesktop=1 (the Windows
                defaults) and checks EnableLUA=1; used once, before the snapshot m3-uac-on is taken.
    uac-check   prints the three values, the build, and the agent's integrity level.
    build       compiles C:\cr\m3\m3probe.exe (csc.exe of .NET Framework 4, comctl32 v6 manifest; source below).
    uipi        the UIPI matrix: for each driver level (medium first, then high as the control) and each method
                (sendinput-key, sendinput-mouse, postmessage, uia) a fresh high-integrity dummy TaskDialog
                (custom button 1001 "Delete (probe)", Cancel default, a verification check box) is shown, the driver
                tries to press it, and the dialog's own event log tells whether anything arrived. uipi.json.
    dialog-show / dialog-quit   one dummy dialog left open for a host screenshot, then closed.
    uac-arm     -Tag t: a medium process (one-shot task PurgeRigM3RunAs) asks for elevation (ShellExecute runas); the
                phase waits for consent.exe and records the input desktop seen from the agent (high, not SYSTEM).
    uac-result  -Tag t -WaitSec n: waits up to n s for the runas outcome (runas.json, elevated.json), records whether
                consent.exe is still up, and deletes the task once there is an outcome.
    inputdesk   -Tag t: records the input desktop name now.
    pack        zips C:\cr\out\m3-rig-uac\ to C:\cr\out\m3-rig-uac.zip for the host.
#>
param(
    [Parameter(Mandatory)]
    [ValidateSet('uac-set', 'uac-check', 'build', 'uipi', 'dialog-show', 'dialog-quit', 'uac-arm', 'uac-result', 'inputdesk', 'pack')]
    [string] $Phase,
    [string] $Tag = '',
    [int] $WaitSec = 15
)
. C:\cr\guest\riglib.ps1
$ErrorActionPreference = 'Continue'

$Out = 'C:\cr\out\m3-rig-uac'
$Bin = 'C:\cr\m3'
$Probe = Join-Path $Bin 'm3probe.exe'
$PolKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$RunAsTask = 'PurgeRigM3RunAs'
$DriveTask = 'PurgeRigM3Drive'
New-Item -ItemType Directory -Force $Out, $Bin | Out-Null
Set-RunLog (Join-Path $Out 'probe.log')
if ($Tag -and $Tag -notmatch '^[A-Za-z0-9_-]+$') { throw "bad tag '$Tag'" }

# Users may write the output tree: the medium driver and the medium runas process write their results there.
function Grant-UsersModify([string]$Dir) {
    New-Item -ItemType Directory -Force $Dir | Out-Null
    $null = & icacls.exe $Dir /grant '*S-1-5-32-545:(OI)(CI)M' /q
}

function Get-UacValues {
    $p = Get-ItemProperty -LiteralPath $PolKey -ErrorAction SilentlyContinue
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [ordered]@{
        ConsentPromptBehaviorAdmin = $p.ConsentPromptBehaviorAdmin
        PromptOnSecureDesktop      = $p.PromptOnSecureDesktop
        EnableLUA                  = $p.EnableLUA
        build                      = "$($cv.CurrentBuildNumber).$($cv.UBR)"
        edition                    = "$($cv.EditionID)"
        agent_elevated             = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
        agent_integrity            = ((& whoami.exe /groups) | Select-String 'Mandatory Label\\(\w+) Mandatory Level' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -First 1)
    }
}

function Read-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { $null }
}

function Wait-File([string]$Path, [int]$Sec) {
    $d = (Get-Date).AddSeconds($Sec)
    while (-not (Test-Path -LiteralPath $Path) -and (Get-Date) -lt $d) { Start-Sleep -Milliseconds 250 }
    Test-Path -LiteralPath $Path
}

# ------------------------------------------------------------------------------------- the probe (C#)

$ProbeSource = @'
// m3probe.exe: M3-RIG-UAC dummy consent dialog, drivers, runas and desktop probes. Nothing here changes the system.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Automation;

static class Probe {
    const int WM_USER = 0x400, TDM_CLICK_BUTTON = WM_USER + 102, WM_COMMAND = 0x111, BM_CLICK = 0xF5;
    const uint TDN_CREATED = 0, TDN_BUTTON_CLICKED = 2, TDN_TIMER = 4, TDN_DESTROYED = 5, TDN_VERIFICATION_CLICKED = 8;
    const int TDF_ALLOW_DIALOG_CANCELLATION = 0x8, TDF_CALLBACK_TIMER = 0x800, TDCBF_CANCEL_BUTTON = 0x8;
    const int IDCANCEL = 2, CUSTOM_ID = 1001;
    const int INPUT_MOUSE = 0, INPUT_KEYBOARD = 1, KEYEVENTF_KEYUP = 2;
    const int MOUSEEVENTF_MOVE = 1, MOUSEEVENTF_LEFTDOWN = 2, MOUSEEVENTF_LEFTUP = 4, MOUSEEVENTF_ABSOLUTE = 0x8000;
    const ushort VK_MENU = 0x12, VK_RETURN = 0x0D, VK_D = 0x44;

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct TASKDIALOGCONFIG {
        public uint cbSize; public IntPtr hwndParent; public IntPtr hInstance; public int dwFlags; public int dwCommonButtons;
        public IntPtr pszWindowTitle; public IntPtr hMainIcon; public IntPtr pszMainInstruction; public IntPtr pszContent;
        public uint cButtons; public IntPtr pButtons; public int nDefaultButton; public uint cRadioButtons; public IntPtr pRadioButtons;
        public int nDefaultRadioButton; public IntPtr pszVerificationText; public IntPtr pszExpandedInformation;
        public IntPtr pszExpandedControlText; public IntPtr pszCollapsedControlText; public IntPtr hFooterIcon; public IntPtr pszFooter;
        public IntPtr pfCallback; public IntPtr lpCallbackData; public uint cxWidth;
    }
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT { public int dx, dy; public uint mouseData, dwFlags, time; public IntPtr extra; }
    [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr extra; }
    [StructLayout(LayoutKind.Explicit)] struct INPUT { [FieldOffset(0)] public int type; [FieldOffset(8)] public MOUSEINPUT mi; [FieldOffset(8)] public KEYBDINPUT ki; }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate int TaskDialogCallback(IntPtr hwnd, uint msg, IntPtr w, IntPtr l, IntPtr data);
    delegate bool EnumProc(IntPtr hwnd, IntPtr l);

    [DllImport("comctl32.dll")] static extern int TaskDialogIndirect(ref TASKDIALOGCONFIG c, out int button, out int radio, out bool verify);
    [DllImport("user32.dll", SetLastError = true)] static extern bool PostMessage(IntPtr h, int msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr SendMessageTimeout(IntPtr h, int msg, IntPtr w, IntPtr l, int flags, int ms, out IntPtr result);
    [DllImport("user32.dll", SetLastError = true)] static extern uint SendInput(uint n, INPUT[] inputs, int size);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] static extern bool BringWindowToTop(IntPtr h);
    [DllImport("user32.dll")] static extern bool AttachThreadInput(uint a, uint b, bool attach);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc p, IntPtr l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr h);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern int GetSystemMetrics(int i);
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr OpenInputDesktop(int flags, bool inherit, uint access);
    [DllImport("user32.dll", SetLastError = true)] static extern bool CloseDesktop(IntPtr h);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool GetUserObjectInformation(IntPtr h, int index, StringBuilder buf, int len, out int needed);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr t, int cls, IntPtr buf, int len, out int ret);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, uint i);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();

    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static readonly object EvLock = new object();
    static string Dir;
    static IntPtr DialogHwnd;
    static bool Quitting;
    static DateTime T0;
    static TaskDialogCallback Cb;

    [STAThread]
    static int Main(string[] a) {
        SetProcessDPIAware();
        string errDir = a.Length > 1 ? (Directory.Exists(a[a.Length - 1]) ? a[a.Length - 1] : Path.GetDirectoryName(a[a.Length - 1])) : ".";
        try {
            switch (a[0]) {
                case "dialog": return Dialog(a[1]);
                case "drive": return Drive(a[1], a[2]);
                case "runas": return RunAs(a[1]);
                case "whoami": return WhoAmI(a[1]);
                case "inputdesk": return InputDesk(a[1]);
            }
            return 2;
        } catch (Exception e) {
            try { File.AppendAllText(Path.Combine(errDir, "error-" + a[0] + ".txt"), DateTime.Now.ToString("o") + " " + e + "\r\n"); } catch { }
            return 3;
        }
    }

    // ---------------------------------------------------------------------------------------- helpers

    static string Integrity(IntPtr process) {
        IntPtr tok;
        if (!OpenProcessToken(process, 0x8, out tok)) return "unknown(open " + Marshal.GetLastWin32Error() + ")";
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
    }
    static string MyIl() { return Integrity(GetCurrentProcess()); }

    static void WriteJson(string path, object o) { File.WriteAllText(path, Json.Serialize(o), new UTF8Encoding(false)); }
    static Dictionary<string, object> ReadJson(string path) { return Json.Deserialize<Dictionary<string, object>>(ReadShared(path)); }
    static string ReadShared(string path) {
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (var r = new StreamReader(fs)) return r.ReadToEnd();
    }
    static void Ev(string line) {
        lock (EvLock) {
            using (var fs = new FileStream(Path.Combine(Dir, "events.log"), FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
            using (var w = new StreamWriter(fs, new UTF8Encoding(false))) w.WriteLine(DateTime.Now.ToString("o") + " " + line);
        }
    }
    // Clicks that reached the dialog: "button <id>" and "verification <n>" lines not caused by the dialog's own quit.
    static int Clicks(string dir) {
        string p = Path.Combine(dir, "events.log");
        if (!File.Exists(p)) return 0;
        int n = 0;
        foreach (string l in ReadShared(p).Split('\n')) {
            if ((l.Contains(" button ") || l.Contains(" verification ")) && !l.Contains("(quit)")) n++;
        }
        return n;
    }
    static Dictionary<string, object> WindowInfo(IntPtr h) {
        var d = new Dictionary<string, object>();
        uint pid; GetWindowThreadProcessId(h, out pid);
        var cls = new StringBuilder(256); GetClassName(h, cls, 256);
        var txt = new StringBuilder(256); GetWindowText(h, txt, 256);
        d["hwnd"] = h.ToInt64(); d["pid"] = (long)pid; d["class"] = cls.ToString(); d["text"] = txt.ToString();
        return d;
    }
    static List<object> Children(IntPtr h) {
        var list = new List<object>();
        EnumChildWindows(h, (c, l) => {
            var d = WindowInfo(c); RECT r; GetWindowRect(c, out r);
            d["id"] = GetDlgCtrlID(c); d["rect"] = new[] { r.Left, r.Top, r.Right, r.Bottom };
            list.Add(d); return true;
        }, IntPtr.Zero);
        return list;
    }

    // ------------------------------------------------------------------------------------- the dialog

    static int Dialog(string dir) {
        Dir = dir; T0 = DateTime.Now;
        Ev("start pid=" + Process.GetCurrentProcess().Id + " il=" + MyIl());
        var c = new TASKDIALOGCONFIG();
        c.cbSize = (uint)Marshal.SizeOf(typeof(TASKDIALOGCONFIG));
        c.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_CALLBACK_TIMER;
        c.dwCommonButtons = TDCBF_CANCEL_BUTTON;
        c.pszWindowTitle = Marshal.StringToHGlobalUni("Purge M3 probe (elevated)");
        c.pszMainInstruction = Marshal.StringToHGlobalUni("Dummy consent dialog");
        c.pszContent = Marshal.StringToHGlobalUni("M3-RIG-UAC: a high-integrity TaskDialog. Nothing is deleted; every click is logged.");
        IntPtr btn = Marshal.AllocHGlobal(12);   // TASKDIALOG_BUTTON, pack 1: int id, PCWSTR text
        Marshal.WriteInt32(btn, 0, CUSTOM_ID);
        Marshal.WriteIntPtr(btn, 4, Marshal.StringToHGlobalUni("&Delete (probe)"));
        c.cButtons = 1; c.pButtons = btn; c.nDefaultButton = IDCANCEL;
        c.pszVerificationText = Marshal.StringToHGlobalUni("I &understand (probe)");
        Cb = Callback;
        c.pfCallback = Marshal.GetFunctionPointerForDelegate(Cb);
        int b, radio; bool ver;
        int hr = TaskDialogIndirect(ref c, out b, out radio, out ver);
        Ev("end hr=0x" + hr.ToString("x8") + " result=" + b + " verify=" + ver);
        return hr == 0 ? 0 : 1;
    }

    static int Callback(IntPtr hwnd, uint msg, IntPtr w, IntPtr l, IntPtr data) {
        try {
            switch (msg) {
                case TDN_CREATED: {
                    DialogHwnd = hwnd;
                    Ev("created hwnd=" + hwnd.ToInt64());
                    string how = Focus(hwnd);
                    var d = WindowInfo(hwnd);
                    d["dialog_pid"] = (long)Process.GetCurrentProcess().Id;
                    d["il"] = MyIl();
                    d["foreground"] = GetForegroundWindow() == hwnd;
                    d["focus_how"] = how;
                    d["children"] = Children(hwnd);
                    WriteJson(Path.Combine(Dir, "dialog.json"), d);
                    new Thread(SelfScan) { IsBackground = true }.Start();
                    break;
                }
                case TDN_BUTTON_CLICKED:
                    Ev("button " + w.ToInt32() + (Quitting ? " (quit)" : ""));
                    return Quitting ? 0 : 1;   // S_FALSE keeps the dialog open: one dialog takes every attempt
                case TDN_VERIFICATION_CLICKED:
                    Ev("verification " + w.ToInt32());
                    break;
                case TDN_TIMER:
                    if (!Quitting && (File.Exists(Path.Combine(Dir, "quit")) || (DateTime.Now - T0).TotalSeconds > 240)) {
                        Quitting = true;
                        PostMessage(hwnd, TDM_CLICK_BUTTON, (IntPtr)IDCANCEL, IntPtr.Zero);
                    }
                    break;
                case TDN_DESTROYED:
                    Ev("destroyed");
                    break;
            }
        } catch (Exception e) { try { Ev("callback error " + e.Message); } catch { } }
        return 0;
    }

    // The dialog asks for the foreground itself (it is high; the drivers never touch the focus).
    static string Focus(IntPtr hwnd) {
        if (GetForegroundWindow() == hwnd) return "already";
        uint pid; uint fgThread = GetWindowThreadProcessId(GetForegroundWindow(), out pid), me = GetCurrentThreadId();
        bool att = fgThread != 0 && fgThread != me && AttachThreadInput(me, fgThread, true);
        SetForegroundWindow(hwnd); BringWindowToTop(hwnd);
        if (att) AttachThreadInput(me, fgThread, false);
        return GetForegroundWindow() == hwnd ? (att ? "attach" : "plain") : "failed";
    }

    // The dialog's own UI Automation view (from a second thread of the dialog process): button names and rectangles,
    // so the mouse driver knows where the custom button is without reading across the integrity boundary.
    static void SelfScan() {
        var res = new Dictionary<string, object>();
        try {
            Thread.Sleep(500);
            var root = AutomationElement.FromHandle(DialogHwnd);
            var list = new List<object>();
            foreach (AutomationElement e in root.FindAll(TreeScope.Descendants, Condition.TrueCondition)) {
                var ct = e.Current.ControlType;
                if (ct != ControlType.Button && ct != ControlType.CheckBox) continue;
                var r = e.Current.BoundingRectangle;
                list.Add(new Dictionary<string, object> {
                    { "name", e.Current.Name }, { "type", ct.ProgrammaticName }, { "automation_id", e.Current.AutomationId },
                    { "rect", new[] { (int)r.Left, (int)r.Top, (int)r.Right, (int)r.Bottom } } });
            }
            res["elements"] = list;
        } catch (Exception e) { res["error"] = e.GetType().Name + ": " + e.Message; }
        WriteJson(Path.Combine(Dir, "buttons.json"), res);
    }

    // ------------------------------------------------------------------------------------- the drivers

    static Dictionary<string, object> Rec;
    static List<object> Attempts;

    static void Attempt(string dir, string name, Func<string> act) {
        int before = Clicks(dir);
        var a = new Dictionary<string, object> { { "name", name }, { "t", DateTime.Now.ToString("o") } };
        IntPtr fg = GetForegroundWindow();
        a["foreground_is_dialog"] = fg == DialogHwnd;
        try { a["detail"] = act(); } catch (Exception e) { a["detail"] = "exception " + e.GetType().Name + ": " + e.Message; }
        Thread.Sleep(1200);
        int after = Clicks(dir);
        a["clicks_before"] = before; a["clicks_after"] = after; a["reached"] = after > before;
        Attempts.Add(a);
    }

    static string Keys(params ushort[] seq) {
        // seq: vk codes; a vk is pressed when it first appears and released when it appears again.
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

    static string Post(IntPtr h, int msg, long w) {
        bool ok = PostMessage(h, msg, (IntPtr)w, IntPtr.Zero);
        return "PostMessage returned " + ok + " lasterror=" + Marshal.GetLastWin32Error();
    }

    static AutomationElement UiaFind(AutomationElement root, ControlType type, string namePart) {
        foreach (AutomationElement e in root.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, type)))
            if (e.Current.Name.Contains(namePart)) return e;
        return null;
    }

    static int Drive(string method, string dir) {
        var dj = ReadJson(Path.Combine(dir, "dialog.json"));
        DialogHwnd = new IntPtr(Convert.ToInt64(dj["hwnd"]));
        Rec = new Dictionary<string, object>();
        Attempts = new List<object>();
        Rec["method"] = method; Rec["driver_pid"] = (long)Process.GetCurrentProcess().Id; Rec["driver_il"] = MyIl();
        Rec["dialog_hwnd"] = DialogHwnd.ToInt64(); Rec["dialog_il"] = dj["il"];
        Rec["window_now"] = WindowInfo(DialogHwnd); Rec["foreground_before"] = WindowInfo(GetForegroundWindow());
        Rec["attempts"] = Attempts;
        switch (method) {
            case "sendinput-key":
                Attempt(dir, "SendInput Alt+D (accelerator of the custom button)", () => Keys(VK_MENU, VK_D, VK_D, VK_MENU));
                Attempt(dir, "SendInput Enter (default button Cancel)", () => Keys(VK_RETURN, VK_RETURN));
                break;
            case "sendinput-mouse": {
                int[] rect = null;
                string bp = Path.Combine(dir, "buttons.json");
                if (File.Exists(bp)) {
                    var bj = ReadJson(bp);
                    if (bj.ContainsKey("elements"))
                        foreach (object o in (System.Collections.ArrayList)bj["elements"]) {
                            var e = (Dictionary<string, object>)o;
                            if (((string)e["name"]).Contains("Delete")) { var r = (System.Collections.ArrayList)e["rect"]; rect = new[] { (int)r[0], (int)r[1], (int)r[2], (int)r[3] }; }
                        }
                }
                if (rect == null) Attempts.Add(new Dictionary<string, object> { { "name", "SendInput mouse click" }, { "detail", "skipped: no rectangle for the custom button in buttons.json" }, { "reached", false } });
                else Attempt(dir, "SendInput mouse click on the custom button", () => Click((rect[0] + rect[2]) / 2, (rect[1] + rect[3]) / 2));
                break;
            }
            case "postmessage": {
                Attempt(dir, "PostMessage TDM_CLICK_BUTTON 1001 to the dialog", () => Post(DialogHwnd, TDM_CLICK_BUTTON, CUSTOM_ID));
                Attempt(dir, "PostMessage WM_COMMAND 1001 (BN_CLICKED) to the dialog", () => Post(DialogHwnd, WM_COMMAND, CUSTOM_ID));
                foreach (object o in Children(DialogHwnd)) {
                    var ch = (Dictionary<string, object>)o;
                    if (((string)ch["class"]).IndexOf("Button", StringComparison.OrdinalIgnoreCase) >= 0 && ((string)ch["text"]).Contains("Delete")) {
                        var h = new IntPtr(Convert.ToInt64(ch["hwnd"]));
                        Attempt(dir, "PostMessage BM_CLICK to child " + ch["class"] + " '" + ch["text"] + "'", () => Post(h, BM_CLICK, 0));
                    }
                }
                Attempt(dir, "SendMessageTimeout TDM_CLICK_BUTTON 1001 to the dialog", () => {
                    IntPtr res; IntPtr ok = SendMessageTimeout(DialogHwnd, TDM_CLICK_BUTTON, (IntPtr)CUSTOM_ID, IntPtr.Zero, 0x2, 5000, out res);
                    return "SendMessageTimeout returned " + ok + " lasterror=" + Marshal.GetLastWin32Error();
                });
                break;
            }
            case "uia": {
                AutomationElement root = null;
                Attempt(dir, "UIA FromHandle + list descendants", () => {
                    root = AutomationElement.FromHandle(DialogHwnd);
                    var names = new List<string>();
                    foreach (AutomationElement e in root.FindAll(TreeScope.Descendants, Condition.TrueCondition))
                        names.Add(e.Current.ControlType.ProgrammaticName + " '" + e.Current.Name + "'");
                    return "root '" + root.Current.Name + "', " + names.Count + " descendants: " + string.Join("; ", names.ToArray());
                });
                Attempt(dir, "UIA InvokePattern.Invoke on the custom button", () => {
                    if (root == null) return "no root element";
                    var b = UiaFind(root, ControlType.Button, "Delete");
                    if (b == null) return "custom button not found through UIA";
                    object p; if (!b.TryGetCurrentPattern(InvokePattern.Pattern, out p)) return "no InvokePattern";
                    ((InvokePattern)p).Invoke(); return "Invoke returned";
                });
                Attempt(dir, "UIA TogglePattern.Toggle on the verification check box", () => {
                    if (root == null) return "no root element";
                    var b = UiaFind(root, ControlType.CheckBox, "understand");
                    if (b == null) return "check box not found through UIA";
                    object p; if (!b.TryGetCurrentPattern(TogglePattern.Pattern, out p)) return "no TogglePattern";
                    ((TogglePattern)p).Toggle(); return "Toggle returned";
                });
                break;
            }
            default: throw new ArgumentException("unknown method " + method);
        }
        bool any = false;
        foreach (object o in Attempts) if ((bool)((Dictionary<string, object>)o)["reached"]) any = true;
        Rec["reached"] = any;
        WriteJson(Path.Combine(dir, "drive.json"), Rec);
        return 0;
    }

    // ---------------------------------------------------------------------------- runas, whoami, desktop

    static int RunAs(string dir) {
        string self = Process.GetCurrentProcess().MainModule.FileName;
        WriteJson(Path.Combine(dir, "runas-start.json"), new Dictionary<string, object> {
            { "pid", (long)Process.GetCurrentProcess().Id }, { "il", MyIl() }, { "t", DateTime.Now.ToString("o") } });
        var r = new Dictionary<string, object>();
        var psi = new ProcessStartInfo(self, "whoami \"" + Path.Combine(dir, "elevated.json") + "\"") { UseShellExecute = true, Verb = "runas" };
        try {
            var p = Process.Start(psi);
            r["ok"] = true; r["child_pid"] = (long)p.Id; r["error"] = 0;
        } catch (Win32Exception e) {
            r["ok"] = false; r["error"] = e.NativeErrorCode; r["message"] = e.Message;
        }
        r["t"] = DateTime.Now.ToString("o");
        WriteJson(Path.Combine(dir, "runas.json"), r);
        return 0;
    }

    static int WhoAmI(string path) {
        WriteJson(path, new Dictionary<string, object> {
            { "pid", (long)Process.GetCurrentProcess().Id }, { "il", MyIl() }, { "user", Environment.UserDomainName + "\\" + Environment.UserName },
            { "t", DateTime.Now.ToString("o") } });
        return 0;
    }

    static int InputDesk(string path) {
        var r = new Dictionary<string, object> { { "t", DateTime.Now.ToString("o") }, { "il", MyIl() } };
        IntPtr h = OpenInputDesktop(0, false, 0x1);   // DESKTOP_READOBJECTS
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
}
'@

$ProbeManifest = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" name="Purge.Rig.M3Probe" type="win32"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <dependency><dependentAssembly>
    <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
  </dependentAssembly></dependency>
</assembly>
'@

function Build-Probe {
    $fw = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
    $wpf = Join-Path $fw 'WPF'
    $src = Join-Path $Bin 'm3probe.cs'; $man = Join-Path $Bin 'm3probe.manifest'
    [IO.File]::WriteAllText($src, $ProbeSource, $RigUtf8)
    [IO.File]::WriteAllText($man, $ProbeManifest, $RigUtf8)
    Remove-Item -LiteralPath $Probe -Force -ErrorAction SilentlyContinue
    $out = & (Join-Path $fw 'csc.exe') /nologo /target:winexe /platform:x64 /optimize "/out:$Probe" "/win32manifest:$man" `
        "/r:$wpf\UIAutomationClient.dll" "/r:$wpf\UIAutomationTypes.dll" "/r:$wpf\WindowsBase.dll" '/r:System.Web.Extensions.dll' $src 2>&1
    foreach ($l in @($out)) { Log "  csc: $l" }
    if (-not (Test-Path -LiteralPath $Probe)) { throw 'm3probe.exe was not built' }
    Log "built $Probe ($((Get-Item $Probe).Length) bytes)"
}

function Ensure-Probe { if (-not (Test-Path -LiteralPath $Probe)) { Build-Probe } }

# A high-integrity dummy dialog (started by the agent, which is high) in $Dir; returns the process once dialog.json is
# written, or $null.
function Start-Dialog([string]$Dir) {
    if (Test-Path -LiteralPath $Dir) { Remove-Item -LiteralPath $Dir -Recurse -Force }
    Grant-UsersModify $Dir
    $p = Start-Process -FilePath $Probe -ArgumentList @('dialog', "`"$Dir`"") -PassThru
    if (-not (Wait-File (Join-Path $Dir 'dialog.json') 15)) { Log "  !! dialog.json not written in $Dir"; return $null }
    $null = Wait-File (Join-Path $Dir 'buttons.json') 15
    $p
}

function Stop-Dialog($P, [string]$Dir) {
    if (-not $P) { return }
    [IO.File]::WriteAllText((Join-Path $Dir 'quit'), '')
    if (-not $P.WaitForExit(10000)) { Log "  !! dialog $($P.Id) did not close; killed"; Stop-Process -Id $P.Id -Force -ErrorAction SilentlyContinue }
}

function Invoke-Driver([string]$Level, [string]$Method, [string]$Dir) {
    $args1 = "drive $Method `"$Dir`""
    if ($Level -eq 'medium') {
        $null = LaunchMedium -Exe $Probe -Arguments $args1 -TaskName $DriveTask -StartTimeoutSec 0
        $null = Wait-File (Join-Path $Dir 'drive.json') 120
        Unregister-ScheduledTask -TaskName $DriveTask -Confirm:$false -ErrorAction SilentlyContinue
    } else {
        $d = Start-Process -FilePath $Probe -ArgumentList @('drive', $Method, "`"$Dir`"") -PassThru
        if (-not $d.WaitForExit(120000)) { Stop-Process -Id $d.Id -Force -ErrorAction SilentlyContinue }
    }
    Read-Json (Join-Path $Dir 'drive.json')
}

# ------------------------------------------------------------------------------------------------ phases

Log "== phase $Phase$(if ($Tag) { " tag=$Tag" })"
switch ($Phase) {
    'uac-set' {
        $before = Get-UacValues
        Set-ItemProperty -LiteralPath $PolKey -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord
        Set-ItemProperty -LiteralPath $PolKey -Name PromptOnSecureDesktop -Value 1 -Type DWord
        $after = Get-UacValues
        Log "before: $(ConvertTo-Json $before -Compress)"
        Log "after:  $(ConvertTo-Json $after -Compress)"
        Write-JsonFile ([ordered]@{ before = $before; after = $after }) (Join-Path $Out 'uac-set.json')
        if ($after.EnableLUA -ne 1) { "M3 UAC-SET FAIL EnableLUA=$($after.EnableLUA) (needs 1 and a reboot)" } else { 'M3 UAC-SET OK' }
    }
    'uac-check' {
        $v = Get-UacValues
        Log "values: $(ConvertTo-Json $v -Compress)"
        Write-JsonFile $v (Join-Path $Out 'uac-check.json')
        $ok = ($v.ConsentPromptBehaviorAdmin -eq 5 -and $v.PromptOnSecureDesktop -eq 1 -and $v.EnableLUA -eq 1 -and $v.agent_integrity -eq 'High')
        "M3 UAC-CHECK $(if ($ok) { 'OK' } else { 'FAIL' }) $(ConvertTo-Json $v -Compress)"
    }
    'build' {
        Build-Probe
        'M3 BUILD OK'
    }
    'uipi' {
        Ensure-Probe
        $root = Join-Path $Out 'uipi'
        $cases = New-Object System.Collections.ArrayList
        foreach ($level in 'medium', 'high') {
            foreach ($method in 'sendinput-key', 'sendinput-mouse', 'postmessage', 'uia') {
                $dir = Join-Path $root "$level-$method"
                Log "case $level / $method"
                $p = Start-Dialog $dir
                $dj = Read-Json (Join-Path $dir 'dialog.json')
                if ($dj) { Log "  dialog pid=$($dj.dialog_pid) il=$($dj.il) hwnd=$($dj.hwnd) foreground=$($dj.foreground) ($($dj.focus_how))" }
                $r = $null
                if ($p) { Start-Sleep -Milliseconds 800; $r = Invoke-Driver $level $method $dir }
                Start-Sleep -Milliseconds 500
                Stop-Dialog $p $dir
                $c = [ordered]@{ level = $level; method = $method; dialog_il = $(if ($dj) { $dj.il }); dialog_foreground = $(if ($dj) { $dj.foreground })
                                 driver_il = $(if ($r) { $r.driver_il }); reached = $(if ($r) { [bool]$r.reached } else { $null }); attempts = @() }
                if ($r) {
                    foreach ($a in @($r.attempts)) {
                        $c.attempts += [ordered]@{ name = $a.name; detail = $a.detail; reached = [bool]$a.reached; foreground_is_dialog = $a.foreground_is_dialog }
                        Log "  [$level] $($a.name): reached=$($a.reached) fg=$($a.foreground_is_dialog) | $($a.detail)"
                    }
                } else { Log "  !! no drive.json for $level / $method" }
                [void]$cases.Add($c)
            }
        }
        $med = @($cases | Where-Object { $_.level -eq 'medium' })
        $high = @($cases | Where-Object { $_.level -eq 'high' })
        $medBlocked = (@($med | Where-Object { $_.reached -ne $false -or $_.driver_il -ne 'medium' -or $_.dialog_il -ne 'high' }).Count -eq 0)
        $ctlReached = @($high | Where-Object { $_.reached -eq $true -and $_.driver_il -eq 'high' }).Count
        $sum = [ordered]@{ uac = (Get-UacValues); cases = $cases; medium_blocked_all = $medBlocked; control_reached = $ctlReached; control_cases = $high.Count }
        Write-JsonFile $sum (Join-Path $Out 'uipi.json') 8
        "M3 UIPI medium_blocked_all=$medBlocked control_reached=$ctlReached/$($high.Count)"
        foreach ($c in $cases) { "M3 UIPI-CASE $($c.level) $($c.method) driver_il=$($c.driver_il) dialog_il=$($c.dialog_il) reached=$($c.reached)" }
    }
    'dialog-show' {
        Ensure-Probe
        $dir = Join-Path $Out 'shot'
        $p = Start-Dialog $dir
        $dj = Read-Json (Join-Path $dir 'dialog.json')
        "M3 DIALOG-SHOW pid=$(if ($p) { $p.Id }) il=$(if ($dj) { $dj.il }) foreground=$(if ($dj) { $dj.foreground })"
    }
    'dialog-quit' {
        $dir = Join-Path $Out 'shot'
        [IO.File]::WriteAllText((Join-Path $dir 'quit'), '')
        Start-Sleep -Seconds 3
        $left = @(Get-ProcList | Where-Object { $_.path -and $_.path -ieq $Probe })
        foreach ($x in $left) { Stop-Process -Id $x.pid -Force -ErrorAction SilentlyContinue }
        "M3 DIALOG-QUIT left=$($left.Count)"
    }
    'inputdesk' {
        Ensure-Probe
        $f = Join-Path $Out "inputdesk-$Tag.json"
        $null = Start-Process -FilePath $Probe -ArgumentList @('inputdesk', "`"$f`"") -PassThru -Wait
        $j = Read-Json $f
        "M3 INPUTDESK $Tag open=$($j.open) name=$($j.name) error=$($j.error)"
    }
    'uac-arm' {
        Ensure-Probe
        if (-not $Tag) { throw 'uac-arm needs -Tag' }
        $dir = Join-Path $Out "uac-$Tag"
        if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
        Grant-UsersModify $dir
        $pre = @(Get-Process consent -ErrorAction SilentlyContinue).Count
        $null = LaunchMedium -Exe $Probe -Arguments "runas `"$dir`"" -TaskName $RunAsTask -StartTimeoutSec 0
        $start = $null; $consent = $null
        $d = (Get-Date).AddSeconds(45)
        while (-not $consent -and (Get-Date) -lt $d) {
            Start-Sleep -Milliseconds 500
            $consent = Get-Process consent -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        $start = Read-Json (Join-Path $dir 'runas-start.json')
        Start-Sleep -Seconds 2   # let the secure desktop finish switching before the desktop check and the screenshot
        $f = Join-Path $dir 'inputdesk-prompt.json'
        $null = Start-Process -FilePath $Probe -ArgumentList @('inputdesk', "`"$f`"") -PassThru -Wait
        $desk = Read-Json $f
        $rec = [ordered]@{ tag = $Tag; consent_before = $pre; consent_pid = $(if ($consent) { $consent.Id }); consent_session = $(if ($consent) { $consent.SessionId })
                           requester = $start; inputdesk = $desk }
        Write-JsonFile $rec (Join-Path $dir 'arm.json')
        Log "arm: $(ConvertTo-Json $rec -Compress)"
        "M3 UAC-ARM $Tag consent=$(if ($consent) { $consent.Id } else { 'none' }) requester_il=$($start.il) inputdesk_open=$($desk.open) inputdesk_name=$($desk.name) inputdesk_error=$($desk.error)"
    }
    'uac-result' {
        if (-not $Tag) { throw 'uac-result needs -Tag' }
        $dir = Join-Path $Out "uac-$Tag"
        $null = Wait-File (Join-Path $dir 'runas.json') $WaitSec
        $r = Read-Json (Join-Path $dir 'runas.json')
        if ($r -and $r.ok) { $null = Wait-File (Join-Path $dir 'elevated.json') 15 }
        $e = Read-Json (Join-Path $dir 'elevated.json')
        $consent = @(Get-Process consent -ErrorAction SilentlyContinue)
        $rec = [ordered]@{ tag = $Tag; runas = $r; elevated = $e; consent_still_up = ($consent.Count -gt 0) }
        Write-JsonFile $rec (Join-Path $dir 'result.json')
        Log "result: $(ConvertTo-Json $rec -Compress)"
        if ($r) { Unregister-ScheduledTask -TaskName $RunAsTask -Confirm:$false -ErrorAction SilentlyContinue }
        $state = $(if (-not $r) { 'pending' } elseif ($r.ok) { 'approved' } elseif ($r.error -eq 1223) { 'cancelled' } else { "error$($r.error)" })
        "M3 UAC-RESULT $Tag state=$state error=$(if ($r) { $r.error }) elevated_il=$(if ($e) { $e.il }) consent_still_up=$($consent.Count -gt 0)"
    }
    'pack' {
        $zip = 'C:\cr\out\m3-rig-uac.zip'
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path (Join-Path $Out '*') -DestinationPath $zip -Force
        "M3 PACK $((Get-Item $zip).Length)"
    }
}
