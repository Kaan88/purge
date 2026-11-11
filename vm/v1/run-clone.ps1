<#
  Runs the clone app (..\draft_clone) inside the Windows test VM and copies its
  --screenshot PNG back to vm\shots\.

  Setup notes (found on 2026-11-11):
   * The clone's normal debug build needs vcruntime140.dll, which a clean Windows
     install lacks. Build a static-CRT copy into vm\build first:
       $env:RUSTFLAGS="-C target-feature=+crt-static"
       cargo build --manifest-path ..\draft_clone\Cargo.toml --target-dir vm\build
   * eframe uses the glow (OpenGL 2+) renderer, so the VM needs 3D acceleration:
       VBoxManage modifyvm Inbound-Win11-Test --accelerate-3d on
   * VBoxManage guestcontrol starts programs without a desktop, so the app is
     started through a one-shot /IT scheduled task in the logged-in session.

  Usage:  powershell -File vm\run-clone.ps1 -PasswordFile <file: bare password or "password=...">
#>
param(
    [Parameter(Mandatory)] [string] $PasswordFile,
    [string] $Vm       = "Inbound-Win11-Test",
    [string] $User     = "tester",
    [string] $Exe      = "",
    [string] $ShotName = "clone-start.png",
    [int]    $WaitSec  = 45
)
$ErrorActionPreference = "Stop"
# $PSScriptRoot is empty inside param defaults on Windows PowerShell 5.1.
if (-not $Exe) { $Exe = Join-Path $PSScriptRoot "build\debug\clean-remover.exe" }
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

$raw = (Get-Content $PasswordFile | Select-Object -First 2) -join "`n"
$pw  = if ($raw -match 'password=(.+)') { $Matches[1].Trim() } else { (Get-Content $PasswordFile -TotalCount 1).Trim() }
$pf  = New-TemporaryFile
[IO.File]::WriteAllText($pf, $pw)

try {
    $g = @($Vm, "--username", $User, "--passwordfile", $pf)
    & $vb guestcontrol @g mkdir --parents "C:\cr\shots"
    & $vb guestcontrol @g copyto --target-directory "C:\cr\" (Resolve-Path $Exe).Path
    $cmd = "del /q C:\cr\shots\$ShotName 2>nul & " +
           "schtasks /create /f /tn crshot /sc once /st 23:59 /it /tr ""C:\cr\clean-remover.exe --screenshot C:\cr\shots\$ShotName"" >nul & " +
           "schtasks /run /tn crshot >nul & ping -n $WaitSec 127.0.0.1 >nul & dir /b C:\cr\shots"
    & $vb guestcontrol @g run --timeout (($WaitSec + 30) * 1000) --wait-stdout --exe "C:\Windows\System32\cmd.exe" -- cmd /c $cmd
    New-Item -ItemType Directory -Force "$PSScriptRoot\shots" | Out-Null
    & $vb guestcontrol @g copyfrom --target-directory "$PSScriptRoot\shots\" "C:\cr\shots\$ShotName"
    if ($LASTEXITCODE -eq 0) { "Saved $PSScriptRoot\shots\$ShotName" } else { "No screenshot produced" }
}
finally { Remove-Item $pf -Force }
