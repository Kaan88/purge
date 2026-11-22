# Host self-test of the M3 recovery modes (vm\rig-m3-recover.ps1, vm\guest\m3-recover.ps1, vm\guest\m3rec.cs,
# vm\truth\m3-recover-score.ps1; vm\RIG.md section 15). Needs no VM and starts nothing in one: the host driver is
# dot-sourced for its pure functions, the C# is compiled with the .NET Framework csc.exe when the host has it (into a
# temporary directory, never run), the scorer runs its own self-test. Windows PowerShell 5.1:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File vm\guest\tests\rig-m3-recover.tests.ps1
# Exit 0 when every check passes. (Not under guest\*.ps1, so nothing copies it to the guest.)
$ErrorActionPreference = 'Stop'
$Vm = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Guest = Join-Path $Vm 'guest'
$Repo = Split-Path -Parent $Vm
$script:passes = 0; $script:fails = 0
function Check([string]$Name, [bool]$Cond, [string]$Detail = '') {
    if ($Cond) { $script:passes++; Write-Host "ok   $Name" } else { $script:fails++; Write-Host "FAIL $Name  $Detail" }
}
$Work = Join-Path ([IO.Path]::GetTempPath()) ('rig-m3-recover-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $Work | Out-Null

try {
# ------------------------------------------------------------------------------------------------ parse
$files = @((Join-Path $Vm 'rig-m3-recover.ps1'), (Join-Path $Guest 'm3-recover.ps1'), (Join-Path $Vm 'truth\m3-recover-score.ps1'), $PSCommandPath)
foreach ($f in $files) {
    $tok = $null; $err = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($f, [ref]$tok, [ref]$err)
    Check "parse $(Split-Path -Leaf $f)" (@($err).Count -eq 0) (@($err | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ')
}
foreach ($f in @($files) + @((Join-Path $Guest 'm3rec.cs'), (Join-Path $Guest 'm3sec.cs'), (Join-Path $Vm 'truth\m3-recover-expect.json'))) {
    # Windows PowerShell reads a BOM-less script in the ANSI code page and csc reads the guest's: ASCII only.
    Check "ascii $(Split-Path -Leaf $f)" (-not ([IO.File]::ReadAllText($f) -match '[^\x00-\x7F]'))
}
$x = Get-Content -LiteralPath (Join-Path $Vm 'truth\m3-recover-expect.json') -Raw | ConvertFrom-Json
Check 'expectations parse' ($x.schema -eq 'purge.rig.m3rec.expect/1')

# ------------------------------------------------------------------------------------ host driver (pure)
& {
    . (Join-Path $Vm 'rig-m3-recover.ps1')
    $ErrorActionPreference = 'Stop'
    Check 'phase job text' ((New-RecPhaseText 'recover-start' '3-resume' '' 'ui' 300) -eq "& 'C:\cr\guest\m3-recover.ps1' -Phase 'recover-start' -Tag '3-resume' -Via 'ui' -WaitSec 300")
    Check 'phase job text with a fixture' ((New-RecPhaseText 'fixture' '' 'own') -eq "& 'C:\cr\guest\m3-recover.ps1' -Phase 'fixture' -Fix 'own' -WaitSec 120")
    $threw = $false; try { $null = New-RecPhaseText 'truth' "x'; Remove-Item C:\" } catch { $threw = $true }
    Check 'a tag with quotes is refused' $threw
    Check 'afters' (((Get-RecAfters 'both') -join ',') -eq 'resume,rollback' -and ((Get-RecAfters 'rollback') -join ',') -eq 'rollback')
    Check 'steps: every line 1..N by default' (((Get-RecStepList 4) -join ',') -eq '1,2,3,4')
    Check 'steps: -Steps kept, sorted, unique' (((Get-RecStepList 9 @(5, 2, 5)) -join ',') -eq '2,5')
    $threw = $false; try { $null = Get-RecStepList 4 @(5) } catch { $threw = $true }
    Check 'steps: a step past N is refused' $threw
    $threw = $false; try { $null = Get-RecStepList 0 } catch { $threw = $true }
    Check 'steps: an empty calibration journal is refused' $threw
    Check 'round names' ((Get-RecRoundName 3 'resume') -eq 'k03-resume' -and (Get-RecRoundName 12 'rollback') -eq 'k12-rollback')
    # The scorer builds the same names.
    Check 'round names as the scorer spells them' ((Get-RecRoundName 7 'rollback') -eq ('k{0:D2}-{1}' -f 7, 'rollback'))
    $fl = "M3R FOCUS k01-resume-1 refocused=False found=True focused='Cancel' type=ControlType.Button in_dialog=True primary='Finish the cleanup' enabled=True verify=none"
    Check 'keys: Cancel focused -> shift-tab' ((Get-RecKeyChoice $fl) -eq 'shift-tab')
    Check 'keys: the armed primary focused -> space' ((Get-RecKeyChoice ($fl -replace "focused='Cancel'", "focused='Finish the cleanup'")) -eq 'space')
    Check 'keys: the primary focused but disarmed -> wait' ((Get-RecKeyChoice (($fl -replace "focused='Cancel'", "focused='Finish the cleanup'") -replace 'enabled=True', 'enabled=False')) -eq 'wait')
    Check 'keys: an unticked box, not focused -> tab' ((Get-RecKeyChoice ($fl -replace 'verify=none', 'verify=Off')) -eq 'tab')
    Check 'keys: an unticked box focused -> space' ((Get-RecKeyChoice (($fl -replace 'verify=none', 'verify=Off') -replace 'type=ControlType.Button', 'type=ControlType.CheckBox')) -eq 'space')
    Check 'keys: no dialog any more -> done' ((Get-RecKeyChoice ($fl -replace 'found=True', 'found=False')) -eq 'done' -and (Get-RecKeyChoice '') -eq 'done')
    Check 'field reader: quoted values with spaces' ((Get-RecField $fl 'primary') -eq 'Finish the cleanup' -and (Get-RecField $fl 'found') -eq 'True' -and $null -eq (Get-RecField $fl 'nothing'))
    Check 'keys: shift-tab and space scancodes' ((($M3Keys['shift-tab']) -join ' ') -eq '2a 0f 8f aa' -and (($M3Keys['space']) -join ' ') -eq '39 b9')
    $a = Join-Path $Work 'a.bin'; [IO.File]::WriteAllText($a, 'one')
    $h1 = Get-RecPayloadHash @($a, (Join-Path $Work 'missing.bin'))
    Check 'payload hash: stable' ($h1 -eq (Get-RecPayloadHash @((Join-Path $Work 'missing.bin'), $a)) -and $h1 -match '^[0-9a-f]{16}$')
    [IO.File]::WriteAllText($a, 'two')
    Check 'payload hash: follows the content' ($h1 -ne (Get-RecPayloadHash @($a, (Join-Path $Work 'missing.bin'))))
    Check 'dot-sourced: no evidence directory made' (-not (Test-Path -LiteralPath 'unused'))
    Check 'the guest files pushed exist' (@($RecGuestScripts | Where-Object { -not (Test-Path -LiteralPath (Join-Path $Guest $_)) }).Count -eq 0)
}

# --------------------------------------------------------------------- host and guest agree on phase names
$hostText = [IO.File]::ReadAllText((Join-Path $Vm 'rig-m3-recover.ps1'))
$guestText = [IO.File]::ReadAllText((Join-Path $Guest 'm3-recover.ps1'))
$tok = $null; $err = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Guest 'm3-recover.ps1'), [ref]$tok, [ref]$err)
$phaseParam = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Phase' }
$valid = @($phaseParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' } | ForEach-Object { $_.PositionalArguments | ForEach-Object { $_.Value } })
$called = @([regex]::Matches($hostText, "Invoke-RecPhase '([a-z-]+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
Check 'every phase the host calls is a guest phase' (@($called | Where-Object { $valid -notcontains $_ }).Count -eq 0) (@($called | Where-Object { $valid -notcontains $_ }) -join ', ')
$branches = @($valid | Where-Object { $guestText -notmatch ("(?m)^\s+'" + [regex]::Escape($_) + "' \{") })
Check 'every guest phase has its switch branch' ($branches.Count -eq 0) ($branches -join ', ')
$cs = [IO.File]::ReadAllText((Join-Path $Guest 'm3rec.cs'))
$roles = @([regex]::Matches($guestText, "Invoke-Rec @\('([a-z-]+)'|Start-RecDetached @\('([a-z-]+)'") | ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value } } | Sort-Object -Unique)
$m3sec = [IO.File]::ReadAllText((Join-Path $Guest 'm3sec.cs'))
$missing = @($roles | Where-Object { $cs -notmatch ('case "' + [regex]::Escape($_) + '":') -and $m3sec -notmatch ('case "' + [regex]::Escape($_) + '":') })
Check 'every m3rec.exe role the guest runs has a case' ($missing.Count -eq 0) ($missing -join ', ')
$ops = @([regex]::Matches($guestText, "op = '([a-z_]+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
$missing = @($ops | Where-Object { $cs -notmatch ('case "' + [regex]::Escape($_) + '":') -and $m3sec -notmatch ('case "' + [regex]::Escape($_) + '":') })
Check 'every client step the guest asks for has a case' ($missing.Count -eq 0) ($missing -join ', ')

# ------------------------------------------------------------- the strings the rig looks for are the product's
$view = [IO.File]::ReadAllText((Join-Path $Repo 'bins\purge-broker\src\consent\view.rs'))
Check 'labels: resume and rollback buttons as the broker draws them' ($view.Contains('"' + $x.recover.labels.resume + '"') -and $view.Contains('"' + $x.recover.labels.rollback + '"') -and $x.owner.resume_label -eq $x.recover.labels.resume)
$ui = (@(Get-ChildItem -LiteralPath (Join-Path $Repo 'ui') -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.cs', '.xaml' } | ForEach-Object { [IO.File]::ReadAllText($_.FullName) })) -join "`n"
foreach ($s in 'History &amp; undo', 'Check for interrupted cleanups', 'The session was not recorded completely.', 'No cleanup was interrupted.', '"Resume"', '"Roll back"') {
    Check "ui string $s" ($ui.Contains($s))
}
Check 'cs: the UI strings uihist looks for' ($cs.Contains('"History & undo"') -and $cs.Contains('"Check for interrupted cleanups"') -and $cs.Contains('"The session was not recorded completely."'))
$fault = [IO.File]::ReadAllText((Join-Path $Repo 'crates\purge-exec\src\fault.rs'))
Check 'journal record names the watcher matches (undo_intent)' ($fault.Contains('`undo_intent`') -and $guestText.Contains('"rec":"undo_intent"'))

# --------------------------------------------------------------------------------------- C# (compile only)
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (Test-Path -LiteralPath $csc) {
    $wpf = Join-Path (Split-Path $csc) 'WPF'
    $common = @('/nologo', '/target:winexe', '/platform:x64', '/optimize', "/r:$wpf\UIAutomationClient.dll", "/r:$wpf\UIAutomationTypes.dll", "/r:$wpf\WindowsBase.dll",
                '/r:System.Web.Extensions.dll', '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll')
    $o1 = @(& $csc @common "/out:$Work\m3rec.exe" (Join-Path $Guest 'm3sec.cs') (Join-Path $Guest 'm3rec.cs') 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -match 'error|warning' })
    Check 'csc: m3sec.cs + m3rec.cs build m3rec.exe, no warning' ((Test-Path -LiteralPath "$Work\m3rec.exe") -and $o1.Count -eq 0) ($o1 -join ' | ')
    $o2 = @(& $csc @common "/out:$Work\m3sec.exe" (Join-Path $Guest 'm3sec.cs') 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -match 'error|warning' })
    Check 'csc: m3sec.cs alone still builds m3sec.exe (empty hooks)' ((Test-Path -LiteralPath "$Work\m3sec.exe") -and $o2.Count -eq 0) ($o2 -join ' | ')
} else { Write-Host 'skip csc: no .NET Framework 4 compiler on this host' }

# ------------------------------------------------------------------------------------------------ scorer
$o = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Vm 'truth\m3-recover-score.ps1') --self-test 2>&1 | ForEach-Object { "$_" })
Check 'scorer self-test passes' ($LASTEXITCODE -eq 0) (($o | Where-Object { $_ -match '^FAIL' }) -join ' | ')
$o = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Vm 'truth\m3-recover-score.ps1') 2>&1 | ForEach-Object { "$_" })
Check 'scorer without arguments: usage, exit 2' ($LASTEXITCODE -eq 2)
$empty = Join-Path $Work 'empty-run'; New-Item -ItemType Directory -Force $empty | Out-Null
$null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Vm 'truth\m3-recover-score.ps1') -Mode recover -Evidence $empty 2>&1
Check 'scorer on an empty run: FAIL, exit 1' ($LASTEXITCODE -eq 1)

} catch {
    $script:fails++
    Write-Host "FAIL unexpected error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)"
} finally {
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ("{0} passed, {1} failed" -f $script:passes, $script:fails)
if ($script:fails) { exit 1 }
exit 0
