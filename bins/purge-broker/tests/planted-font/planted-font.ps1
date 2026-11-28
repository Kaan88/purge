<#
.SYNOPSIS
The planted per-user font test of the toolkit consent dialog (TOOLKIT_REQUESTS.md TK-1, what must hold 1;
M3_DESIGN 8.3, review B1).

.DESCRIPTION
Shows that a font any process of the user can install for that user alone, with no elevation, no longer
changes what the toolkit consent dialog draws. Unelevated and without a window: it draws every sample of
the dialog into PNG files with the preview harness (`consent_preview --shots`, the dialog's own measuring,
layout and drawing), before and after planting, and compares the files byte for byte.

1. Writes four fonts with gen.py (fontTools; nothing is downloaded): families "Segoe UI Variable Text",
   "Segoe UI" (400, 600) and "Noto Sans", every glyph a filled box.
2. Draws the samples twice: with the dialog's three font files (as the broker draws) and with
   `--system-fonts` (the system's collection, as the dialog drew before TK-1: the control).
3. Plants the fonts as a per-user install does: the files under %LOCALAPPDATA%\Microsoft\Windows\Fonts and
   one value each under HKCU\Software\Microsoft\Windows NT\CurrentVersion\Fonts, then
   `AddFontResourceW` and a `WM_FONTCHANGE` broadcast, as the shell's install does.
4. Draws both again, and removes the files and the values (also when something failed).

Beside the pictures without a window, the real window: the preview opens the sample "hostile" with the
toolkit's host (`Config::fonts`, the host's own `Gfx`) on the hidden desktop (tools\desk\run-hidden.ps1)
and writes its first armed frame, before and after planting; the two must be the same file too.

Passes when every picture drawn with the dialog's fonts is the same file before and after, and the
control shows the plant was seen (some picture drawn with the system's collection changed). Exit 0: pass;
1: a picture of the dialog's fonts changed; 2: the control did not change, so the test proved nothing;
3: the harness failed.

.PARAMETER Preview
The preview harness: `cargo build --release -p purge-broker --features toolkit-consent --example
consent_preview` builds it.
#>
param(
    [Parameter(Mandatory = $true)][string]$Preview,
    [string]$Python = 'python',
    [string]$Work = (Join-Path $env:TEMP "purge-planted-font-$PID")
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$fontsKey = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Fonts'
$userFonts = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Fonts'
$tag = "purge-tk1-planted-$PID"

Add-Type -Namespace PurgePlanted -Name Gdi -MemberDefinition @'
[DllImport("gdi32.dll", CharSet = CharSet.Unicode)] public static extern int AddFontResourceW(string file);
[DllImport("gdi32.dll", CharSet = CharSet.Unicode)] public static extern bool RemoveFontResourceW(string file);
[DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr hwnd, uint msg, IntPtr w, IntPtr l, uint flags, uint timeout, out IntPtr result);
'@

function Send-FontChange {
    $r = [IntPtr]::Zero
    # HWND_BROADCAST, WM_FONTCHANGE, SMTO_ABORTIFHUNG, 2 s.
    [void][PurgePlanted.Gdi]::SendMessageTimeoutW([IntPtr]0xffff, 0x001D, [IntPtr]::Zero, [IntPtr]::Zero, 2, 2000, [ref]$r)
}

function Invoke-Shots([string]$dir, [switch]$System) {
    $a = @('--shots', $dir)
    if ($System) { $a += '--system-fonts' }
    $out = & $Preview @a 2>&1
    if ($LASTEXITCODE -ne 0) { throw "consent_preview $($a -join ' ') failed ($LASTEXITCODE): $out" }
}

function Invoke-Window([string]$file) {
    $desk = Join-Path $PSScriptRoot '..\..\..\..\tools\desk\run-hidden.ps1'
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $desk -Exe $Preview -Args "hostile --theme light --seconds 2 --shot $file" -TimeoutSec 120 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) { throw "the window did not draw ($LASTEXITCODE): $out" }
}

function Get-Pictures([string]$dir) {
    $h = @{}
    foreach ($f in Get-ChildItem -LiteralPath $dir -Filter '*.png') {
        $h[$f.Name] = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
    }
    $h
}

function Compare-Pictures($before, $after) {
    $changed = @()
    foreach ($k in $before.Keys) {
        if (-not $after.ContainsKey($k) -or $after[$k] -ne $before[$k]) { $changed += $k }
    }
    foreach ($k in $after.Keys) { if (-not $before.ContainsKey($k)) { $changed += $k } }
    , $changed
}

$planted = @()
try {
    if (-not (Test-Path -LiteralPath $Preview)) { throw "no preview at $Preview" }
    New-Item -ItemType Directory -Force -Path $Work | Out-Null
    $gen = Join-Path $Work 'gen'
    & $Python -I (Join-Path $PSScriptRoot 'gen.py') $gen
    if ($LASTEXITCODE -ne 0) { throw "gen.py failed ($LASTEXITCODE)" }

    Invoke-Shots (Join-Path $Work 'before-fixed')
    Invoke-Shots (Join-Path $Work 'before-system') -System
    New-Item -ItemType Directory -Force -Path (Join-Path $Work 'before-window'), (Join-Path $Work 'after-window') | Out-Null
    Invoke-Window (Join-Path $Work 'before-window\hostile.png')

    New-Item -ItemType Directory -Force -Path $userFonts | Out-Null
    foreach ($f in Get-ChildItem -LiteralPath $gen -Filter '*.ttf') {
        $dest = Join-Path $userFonts "$tag-$($f.Name)"
        Copy-Item -LiteralPath $f.FullName -Destination $dest
        $name = "Purge TK1 planted $PID $($f.BaseName) (TrueType)"
        $planted += [pscustomobject]@{ File = $dest; Value = $name; Added = $false }
        New-ItemProperty -Path $fontsKey -Name $name -Value $dest -PropertyType String -Force | Out-Null
        $planted[-1].Added = ([PurgePlanted.Gdi]::AddFontResourceW($dest) -gt 0)
    }
    Send-FontChange
    Start-Sleep -Seconds 3

    Invoke-Shots (Join-Path $Work 'after-fixed')
    Invoke-Shots (Join-Path $Work 'after-system') -System
    Invoke-Window (Join-Path $Work 'after-window\hostile.png')
}
catch {
    Write-Host "planted-font: harness failed: $_"
    $failed = $true
}
finally {
    foreach ($p in $planted) {
        if ($p.Added) { [void][PurgePlanted.Gdi]::RemoveFontResourceW($p.File) }
        Remove-ItemProperty -Path $fontsKey -Name $p.Value -ErrorAction SilentlyContinue
    }
    if ($planted.Count -gt 0) { Send-FontChange }
    foreach ($p in $planted) {
        for ($i = 0; $i -lt 20 -and (Test-Path -LiteralPath $p.File); $i++) {
            try { Remove-Item -LiteralPath $p.File -Force -ErrorAction Stop } catch { Start-Sleep -Milliseconds 500 }
        }
    }
    $left = @($planted | Where-Object { Test-Path -LiteralPath $_.File })
    $keys = @($planted | Where-Object { $null -ne (Get-ItemProperty -Path $fontsKey -Name $_.Value -ErrorAction SilentlyContinue) })
    Write-Host "planted-font: cleaned up: $($planted.Count) files and values planted; files left: $($left.Count); values left: $($keys.Count)"
    foreach ($l in $left) { Write-Host "  left: $($l.File)" }
}
if (Get-Variable -Name failed -ErrorAction SilentlyContinue) { exit 3 }

$fixed = Compare-Pictures (Get-Pictures (Join-Path $Work 'before-fixed')) (Get-Pictures (Join-Path $Work 'after-fixed'))
$system = Compare-Pictures (Get-Pictures (Join-Path $Work 'before-system')) (Get-Pictures (Join-Path $Work 'after-system'))
$window = Compare-Pictures (Get-Pictures (Join-Path $Work 'before-window')) (Get-Pictures (Join-Path $Work 'after-window'))
$fixed = @($fixed) + @($window | ForEach-Object { "window: $_" })
$count = (Get-ChildItem -LiteralPath (Join-Path $Work 'before-fixed') -Filter '*.png').Count
Write-Host "planted-font: $count pictures each way, and one frame of the real window"
Write-Host "planted-font: the dialog's fonts: $($fixed.Count) changed"
foreach ($c in $fixed) { Write-Host "  changed: $c" }
Write-Host "planted-font: the system's collection (control): $($system.Count) changed"
foreach ($c in $system | Select-Object -First 10) { Write-Host "  changed: $c" }
Write-Host "planted-font: pictures in $Work"
if ($fixed.Count -gt 0) { Write-Host 'planted-font: FAIL: a planted per-user font changed the dialog'; exit 1 }
if ($system.Count -eq 0) { Write-Host 'planted-font: INCONCLUSIVE: the plant changed nothing, not even the control'; exit 2 }
Write-Host 'planted-font: PASS'
exit 0
