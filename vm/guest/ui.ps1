# Mouse/keyboard input for driving a GUI in the VM session (dot-source, then Click x y / Keys "...").
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class UiIn {
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, UIntPtr e);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
}
"@
function Click([int]$x, [int]$y, [switch]$Double, [switch]$Right) {
    [UiIn]::SetCursorPos($x, $y) | Out-Null; Start-Sleep -Milliseconds 120
    $down, $up = if ($Right) { 0x8, 0x10 } else { 0x2, 0x4 }
    $n = if ($Double) { 2 } else { 1 }
    for ($i = 0; $i -lt $n; $i++) { [UiIn]::mouse_event($down, 0, 0, 0, [UIntPtr]::Zero); [UiIn]::mouse_event($up, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 80 }
    Start-Sleep -Milliseconds 400
}
function Keys([string]$s) { Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait($s); Start-Sleep -Milliseconds 300 }
function Front([string]$procName) {
    $p = Get-Process $procName -ErrorAction SilentlyContinue | Where-Object MainWindowHandle -ne 0 | Select-Object -First 1
    if ($p) { [UiIn]::ShowWindow($p.MainWindowHandle, 3) | Out-Null; [UiIn]::SetForegroundWindow($p.MainWindowHandle) | Out-Null; Start-Sleep -Milliseconds 500 }
    [bool]$p
}
