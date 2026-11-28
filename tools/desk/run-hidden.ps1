<#
.SYNOPSIS
  Runs a program on a hidden Windows desktop, so UI tests (Purge.exe --script, --seconds/--shot, the launch bench,
  UI Automation drivers) never show a window on the person's screen or take their focus.

.DESCRIPTION
  Creates (or opens) the desktop "PurgeTest" in this window station and starts -Exe there with CreateProcess
  (STARTUPINFO.lpDesktop). Every process the program starts inherits the desktop, so a UIA driver started this way
  sees the Purge.exe it launches (UI Automation only sees windows on its own desktop). Nothing on it is ever the input
  desktop: no window can come to the front, and SendInput from it reaches nothing. Windows render normally (the app's
  own framebuffer, so Purge's --shot works); the DWM backdrop (Mica/Acrylic) is not composed off-screen.

  Waits for the program, then returns its exit code. Its stdout and stderr go to -Log (default: a file in %TEMP%),
  printed after it ends.

.EXAMPLE
  powershell -NoProfile -File tools\desk\run-hidden.ps1 -Exe E:\purge-target\ui\release\Purge.exe -Args '--sample --script'
#>
param(
    [Parameter(Mandatory)][string]$Exe,
    [Alias('Args')][string]$ArgList = '',
    [int]$TimeoutSec = 900,
    [string]$Desktop = 'PurgeTest',
    [string]$Log = '',
    [string]$WorkDir = ''
)
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class HiddenDesk {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateDesktopW(string name, IntPtr dev, IntPtr mode, uint flags, uint access, IntPtr sa);
    [DllImport("user32.dll", SetLastError = true)] static extern bool CloseDesktop(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags,
        IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES sa, uint disp,
        uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    // Runs cmdLine on the desktop `desk` of this window station, its output into `log`; returns the exit code,
    // 124 after `timeoutMs`. Throws with the Win32 error on a failed start.
    public static int Run(string desk, string cmdLine, string dir, string log, uint timeoutMs) {
        IntPtr d = CreateDesktopW(desk, IntPtr.Zero, IntPtr.Zero, 0, 0x10000000, IntPtr.Zero);
        if (d == IntPtr.Zero) throw new Exception("CreateDesktop failed: " + Marshal.GetLastWin32Error());
        var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), bInheritHandle = 1 };
        IntPtr o = CreateFileW(log, 0x40000000, 3, ref sa, 2, 0x80, IntPtr.Zero);
        if (o == new IntPtr(-1)) { CloseDesktop(d); throw new Exception("cannot open the log: " + Marshal.GetLastWin32Error()); }
        var si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        si.lpDesktop = desk;          // a desktop of this process's window station
        si.dwFlags = 0x100;           // STARTF_USESTDHANDLES
        si.hStdOutput = o; si.hStdError = o;
        PROCESS_INFORMATION pi;
        // CREATE_NO_WINDOW: a console child gets no console window; its handles are the log.
        bool ok = CreateProcessW(null, new StringBuilder(cmdLine), IntPtr.Zero, IntPtr.Zero, true, 0x08000000,
            IntPtr.Zero, dir, ref si, out pi);
        int err = Marshal.GetLastWin32Error();
        CloseHandle(o);
        if (!ok) { CloseDesktop(d); throw new Exception("CreateProcess failed: " + err); }
        CloseHandle(pi.hThread);
        int code;
        if (WaitForSingleObject(pi.hProcess, timeoutMs) != 0) { TerminateProcess(pi.hProcess, 124); code = 124; }
        else { uint c; GetExitCodeProcess(pi.hProcess, out c); code = (int)c; }
        CloseHandle(pi.hProcess);
        CloseDesktop(d);
        return code;
    }
}
'@

if (-not $Log) { $Log = Join-Path $env:TEMP ("run-hidden-{0}-{1}.log" -f [IO.Path]::GetFileNameWithoutExtension($Exe), [guid]::NewGuid().ToString('N').Substring(0, 8)) }
$Exe = [IO.Path]::GetFullPath($Exe)
if (-not (Test-Path -LiteralPath $Exe)) { throw "no such program: $Exe" }
if (-not $WorkDir) { $WorkDir = Split-Path -Parent $Exe }
$ms = [uint32][Math]::Min([int64]$TimeoutSec * 1000, [int64][uint32]::MaxValue - 1)
$code = [HiddenDesk]::Run($Desktop, ('"' + $Exe + '" ' + $ArgList), $WorkDir, $Log, $ms)
if ($code -eq 124) { Write-Warning "run-hidden: $Exe ended after the $TimeoutSec s limit (exit 124)" }

Get-Content -LiteralPath $Log -ErrorAction SilentlyContinue
Write-Host "run-hidden: exit $code (log $Log)"
exit $code
