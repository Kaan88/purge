# Host self-test for the rig v2 scripts. Needs no VM: VBoxManage, the guest and Task Scheduler are
# replaced by fakes (VBoxManage by a .cmd that only reports whether the password file exists). Nothing is
# registered and nothing outside a temporary directory is written. Windows PowerShell 5.1:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File vm\guest\tests\rig-selftest.ps1
# Exit 0 when every check passes. (Not under guest\*.ps1, so Push-Tools does not copy it to the guest.)
# The M1a part runs run-app.ps1 end to end in a child powershell.exe against fakes and a stub
# purge-engine.cmd (engine mode, run names, pre-apps, the medium-integrity install), and checks the host's
# run-name, engine-push and plan-copy logic.
$ErrorActionPreference = 'Stop'
$Vm = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Guest = Join-Path $Vm 'guest'
$script:passes = 0; $script:fails = 0
function Check([string]$Name, [bool]$Cond, [string]$Detail = '') {
    if ($Cond) { $script:passes++; Write-Host "ok   $Name" } else { $script:fails++; Write-Host "FAIL $Name  $Detail" }
}
$Work = Join-Path ([IO.Path]::GetTempPath()) ('rig-selftest-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $Work | Out-Null
$savedPw = $env:VMPWFILE
Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)); work dir $Work"

try {
# ------------------------------------------------------------------------------------------ parse
foreach ($f in @(Get-ChildItem -LiteralPath $Guest -Filter '*.ps1') + @(Get-Item (Join-Path $Vm 'rig.ps1')) + @(Get-Item $PSCommandPath)) {
    $tok = $null; $err = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
    Check "parse $($f.Name)" (@($err).Count -eq 0) (@($err | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ')
}

# --------------------------------------------------------------------- riglib: env PATH is always an array
& {
    . (Join-Path $Guest 'riglib.ps1')
    $ErrorActionPreference = 'Stop'
    function Get-RegRaw([string]$Canon, [string]$Name) { $script:FakePath }
    $cases = @(
        @{ name = 'none (empty)'; raw = ''; n = 0 },
        @{ name = 'none (missing value)'; raw = $null; n = 0 },
        @{ name = 'one (clean Windows user PATH)'; raw = '%USERPROFILE%\AppData\Local\Microsoft\WindowsApps;'; n = 1 },
        @{ name = 'two'; raw = 'a;;b'; n = 2 }
    )
    foreach ($c in $cases) {
        $script:FakePath = $c.raw
        $f = Join-Path $Work 'env.json'
        Write-JsonFile ([ordered]@{ env = Get-EnvRecords }) $f      # same writer and nesting as Lists
        $json = [IO.File]::ReadAllText($f)
        $isArr = ($json -match '"machine_path":\s*\[') -and ($json -match '"user_path":\s*\[')
        $back = $json | ConvertFrom-Json
        Check "env PATH $($c.name): JSON arrays with $($c.n) segment(s)" ($isArr -and @($back.env.user_path).Count -eq $c.n -and @($back.env.machine_path).Count -eq $c.n) ($json -replace '\s+', ' ')
    }
}

# ------------------------------------------------------- riglib: LaunchMedium deletes its task on failure
& {
    . (Join-Path $Guest 'riglib.ps1')
    $ErrorActionPreference = 'Stop'
    $script:calls = New-Object System.Collections.ArrayList
    $script:startFails = $true
    function Register-ScheduledTask { [CmdletBinding()] param([string]$TaskName, $Action, $Principal, $Settings, [switch]$Force) [void]$script:calls.Add("register:${TaskName}:prio=$($Settings.Priority)") }
    function Start-ScheduledTask { [CmdletBinding()] param([string]$TaskName) if ($script:startFails) { throw 'simulated start failure' } }
    function Unregister-ScheduledTask { [CmdletBinding(SupportsShouldProcess)] param([string]$TaskName) [void]$script:calls.Add("unregister:$TaskName") }
    function Get-ProcList { @([pscustomobject]@{ pid = 4242; ppid = 1; name = 'app.exe'; path = 'C:\fake\app.exe'; start = (Get-Date); session = 1; cmd = 'app.exe' }) }
    function Stop-Procs($Procs, [string]$Why) { foreach ($p in @($Procs)) { if ($p) { [void]$script:calls.Add("kill:$($p.name)") } } }

    $msg = $null
    try { $null = LaunchMedium -Exe 'C:\fake\app.exe' } catch { $msg = $_.Exception.Message }
    Check 'LaunchMedium rethrows a start failure' ($msg -match 'simulated start failure') "got '$msg'"
    Check 'LaunchMedium registers PurgeRigLaunch at priority 4' ($script:calls -contains 'register:PurgeRigLaunch:prio=4') ($script:calls -join ', ')
    Check 'LaunchMedium deletes PurgeRigLaunch after a failed start' ($script:calls[$script:calls.Count - 1] -eq 'unregister:PurgeRigLaunch') ($script:calls -join ', ')

    $script:calls.Clear(); $script:startFails = $false
    $L = LaunchMedium -Exe 'C:\fake\app.exe'
    Check 'LaunchMedium success: task kept for Stop-Launch, process found' ($L.found -and $script:calls[$script:calls.Count - 1] -like 'register:*') ($script:calls -join ', ')

    # run-app's finally calls Stop-Launch with a placeholder record when LaunchMedium threw.
    $script:calls.Clear()
    $ph = [pscustomobject]@{ task = 'PurgeRigLaunch'; start = (Get-Date).AddSeconds(-1); found = $false }
    $r = Stop-Launch $ph -GraceSec 0
    Check 'Stop-Launch with the placeholder record deletes the task' ($script:calls -contains 'unregister:PurgeRigLaunch') ($script:calls -join ', ')
}

# ------------------------------------------------------------------- task priority in setup-base / riglib
$sb = [IO.File]::ReadAllText((Join-Path $Guest 'setup-base.ps1'))
Check 'setup-base registers PurgeRigAgent with -Priority 4' ($sb -match 'New-ScheduledTaskSettingsSet[^\r\n]*-Priority 4')
Check 'start-agent-direct.cmd uses start /NORMAL' ($sb -match 'start `"`" /NORMAL powershell\.exe')
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -Priority 4
Check 'a settings set built with -Priority 4 has Priority=4 (not registered)' ($set.Priority -eq 4) "Priority=$($set.Priority)"

# ------------------------------------------------------------------------ run-app.ps1 placeholder check
& {
    . (Join-Path $Vm 'rig.ps1')
    $tpl = [IO.File]::ReadAllText((Join-Path $Guest 'run-app.ps1'))
    # Everything up to the first dot-source, then 'exit 7': 7 means the id check passed.
    function Test-IdCheck([string]$Text) {
        $i = $Text.IndexOf('. C:\cr\guest\riglib.ps1')
        $f = Join-Path $Work ('idcheck-' + [guid]::NewGuid().ToString('N') + '.ps1')
        [IO.File]::WriteAllText($f, $Text.Substring(0, $i) + "`r`nexit 7`r`n", (New-Object System.Text.UTF8Encoding($true)))
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f 2>&1
        [pscustomobject]@{ code = $LASTEXITCODE; out = ($out -join ' ') }
    }
    Check 'run-app: check runs before riglib is loaded' ($tpl.IndexOf('-cnotmatch') -lt $tpl.IndexOf('. C:\cr\guest\riglib.ps1'))
    $r = Test-IdCheck $tpl
    Check 'run-app: unreplaced template exits 2' ($r.code -eq 2 -and $r.out -match 'not replaced') "exit $($r.code): $($r.out)"
    $r = Test-IdCheck $tpl.Replace('__ID__', 'NPP')
    Check 'run-app: uppercase id exits 2' ($r.code -eq 2) "exit $($r.code): $($r.out)"
    $r = Test-IdCheck (New-RunJobText -Id 'npp')
    Check 'run-app: host-replaced id npp passes the check' ($r.code -eq 7) "exit $($r.code): $($r.out)"
    $r = Test-IdCheck (New-RunJobText -Id 'vcredist')
    Check 'run-app: host-replaced id vcredist passes the check' ($r.code -eq 7) "exit $($r.code): $($r.out)"
    $msg = $null; try { $null = New-RunJobText -Id 'NPP' } catch { $msg = $_.Exception.Message }
    Check 'New-RunJobText rejects an uppercase id' ($msg -match 'bad app id')
    $msg = $null; try { $null = New-RunJobText -Id '__ID__' } catch { $msg = $_.Exception.Message }
    Check 'New-RunJobText rejects the placeholder as an id' ($msg -match 'bad app id')
}

# --------------------------------------------------- rig.ps1: run directories never mix two runs
function New-RunJson([string]$Run, [datetime]$Started, [bool]$AllOk = $true, [bool]$Finished = $true) {
    $ph = @([ordered]@{ name = 'snap0'; ok = $true }, [ordered]@{ name = 'snap2'; ok = $AllOk })
    ConvertTo-Json -Depth 5 -InputObject ([ordered]@{
        schema = 'purge.rig.run/1'; run = $Run; started = $Started.ToString('o')
        finished = $(if ($Finished) { $Started.AddMinutes(20).ToString('o') } else { $null }); phases = $ph
    })
}

& {
    . (Join-Path $Vm 'rig.ps1')
    $ErrorActionPreference = 'Stop'
    $script:RunsDir = Join-Path $Work 'runs'
    $script:GuestFiles = [ordered]@{}
    $script:JobDone = $true
    $script:RestoreThrows = $false
    function Invoke-GuestCmd([string]$CommandLine, [int]$TimeoutSec = 120) { [pscustomobject]@{ code = 0; out = @($script:GuestFiles.Keys) } }
    function Invoke-Guest([string[]]$Sub) {
        if ($Sub[0] -eq 'copyfrom') {
            $n = Split-Path -Leaf $Sub[1]
            [IO.File]::WriteAllText($Sub[2], [string]$script:GuestFiles[$n])
            return [pscustomobject]@{ code = 0; out = @() }
        }
        throw "unexpected guest call: $($Sub -join ' ')"
    }
    function Invoke-GuestJob { param($Text, $Name, $TimeoutSec, $LogCopy) [IO.File]::WriteAllText($LogCopy, 'NEW job log'); [pscustomobject]@{ name = $Name; done = $script:JobDone; seconds = 1; log = ''; log_file = $LogCopy } }
    function Restore-Base { param($Snapshot, $AgentTimeoutSec) if ($script:RestoreThrows) { throw 'simulated restore failure' } }
    function Push-Tools { }
    function Get-PwFile { 'C:\nonexistent\pw.txt' }

    $npp = Join-Path $script:RunsDir 'npp'
    function Fill-Stale {
        New-Item -ItemType Directory -Force (Join-Path $npp 'plans') | Out-Null
        foreach ($n in 'snap-npp-0.tsv.gz', 'snap-npp-2.tsv.gz', 'lists-npp-2.json', 'truth.json') { [IO.File]::WriteAllText((Join-Path $npp $n), 'OLD') }
        [IO.File]::WriteAllText((Join-Path $npp 'run.json'), (New-RunJson 'npp' (Get-Date).AddHours(-3)))
        [IO.File]::WriteAllText((Join-Path $npp 'plans\clone.json'), 'OLD plan')
    }
    function Names { @(Get-ChildItem -LiteralPath $npp -File | ForEach-Object { $_.Name } | Sort-Object) -join ',' }
    function AnyOld { @(Get-ChildItem -LiteralPath $npp -File -Recurse | Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match '^OLD' }).Count -gt 0 }

    # Invoke-Run after a failed re-run (no snap 2 / lists 2 in the guest)
    Fill-Stale
    $script:GuestFiles = [ordered]@{ 'run.log' = 'NEW'; 'run.json' = (New-RunJson 'npp' (Get-Date) $false); 'snap-npp-0.tsv.gz' = 'NEW'; 'snap-npp-1.tsv.gz' = 'NEW'; 'lists-npp-0.json' = 'NEW' }
    $res = Invoke-Run -Id npp
    Check 'Invoke-Run: run dir holds only this run''s files' ((Names) -eq 'job.log,lists-npp-0.json,run.json,run.log,snap-npp-0.tsv.gz,snap-npp-1.tsv.gz' -and -not (AnyOld)) (Names)
    $arch = @(Get-ChildItem -LiteralPath (Join-Path $script:RunsDir '_old') -Directory -Filter 'npp-*')
    Check 'Invoke-Run: previous run dir moved to _old (stale snap 2, truth, plans kept there)' ($arch.Count -eq 1 -and (Test-Path (Join-Path $arch[0].FullName 'snap-npp-2.tsv.gz')) -and (Test-Path (Join-Path $arch[0].FullName 'truth.json')) -and (Test-Path (Join-Path $arch[0].FullName 'plans\clone.json')))
    Check 'Invoke-Run: pulled 5 files' (@($res.pulled).Count -eq 5) "pulled $(@($res.pulled).Count)"

    # Pull-Run alone over a directory with a stale host file
    [IO.File]::WriteAllText((Join-Path $npp 'truth.json'), 'OLD')
    $null = Pull-Run -Run npp
    Check 'Pull-Run: file the guest lacks moved aside, job.log kept' (-not (Test-Path (Join-Path $npp 'truth.json')) -and (Test-Path (Join-Path $npp 'job.log')) -and @(Get-ChildItem (Join-Path $script:RunsDir '_old') -Directory -Filter 'npp-stale-*').Count -eq 1) (Names)

    # Test-RunResult
    $t0 = Get-Date
    $cases = @(
        @{ name = 'fresh, all phases ok'; json = (New-RunJson 'npp' $t0.AddSeconds(30)); ok = $true; err = '' },
        @{ name = 'stale (3 h old)'; json = (New-RunJson 'npp' $t0.AddHours(-3)); ok = $false; err = 'stale' },
        @{ name = 'a failed phase'; json = (New-RunJson 'npp' $t0.AddSeconds(30) $false); ok = $false; err = 'failed phases: snap2' },
        @{ name = 'other run'; json = (New-RunJson 'firefox' $t0.AddSeconds(30)); ok = $false; err = 'is for run' },
        @{ name = 'not finished'; json = (New-RunJson 'npp' $t0.AddSeconds(30) $true $false); ok = $false; err = 'no finished' },
        @{ name = 'guest clock 2 min behind'; json = (New-RunJson 'npp' $t0.AddMinutes(-2)); ok = $true; err = '' }
    )
    foreach ($c in $cases) {
        [IO.File]::WriteAllText((Join-Path $npp 'run.json'), $c.json)
        $chk = Test-RunResult -Run npp -NotBefore $t0
        Check "Test-RunResult: $($c.name)" ($chk.ok -eq $c.ok -and (-not $c.err -or "$($chk.error)" -match [regex]::Escape($c.err))) "ok=$($chk.ok) error=$($chk.error)"
    }
    Remove-Item -LiteralPath (Join-Path $npp 'run.json')
    Check 'Test-RunResult: missing run.json' (-not (Test-RunResult -Run npp -NotBefore $t0).ok)

    # Invoke-Campaign: the guest wrote nothing, a stale (once good) run.json is on the host
    Fill-Stale
    $script:GuestFiles = [ordered]@{}; $script:JobDone = $false
    $rec = @(Invoke-Campaign -Ids npp -Nulls 0)[0]
    Check 'campaign: nothing pulled + stale run.json -> not ok' (-not $rec.ok -and -not (AnyOld)) "ok=$($rec.ok) error=$($rec.error) files=$(Names)"

    # Invoke-Campaign: restore fails, catch path pulls nothing new; stale files must not be counted
    Fill-Stale
    $script:RestoreThrows = $true
    $rec = @(Invoke-Campaign -Ids npp -Nulls 0)[0]
    Check 'campaign: restore failure -> not ok, stale dir archived' (-not $rec.ok -and "$($rec.error)" -match 'simulated restore' -and -not (Test-Path (Join-Path $npp 'run.json'))) "ok=$($rec.ok) error=$($rec.error)"
    $script:RestoreThrows = $false

    # Invoke-Campaign: guest reports a failed phase
    $script:JobDone = $true
    $script:GuestFiles = [ordered]@{ 'run.log' = 'NEW'; 'run.json' = (New-RunJson 'npp' (Get-Date) $false) }
    $rec = @(Invoke-Campaign -Ids npp -Nulls 0)[0]
    Check 'campaign: failed phase -> not ok, phase named' (-not $rec.ok -and @($rec.failed_phases) -contains 'snap2') "ok=$($rec.ok) error=$($rec.error)"

    # Invoke-Campaign: good run
    $script:GuestFiles = [ordered]@{ 'run.log' = 'NEW'; 'run.json' = (New-RunJson 'npp' (Get-Date)); 'snap-npp-0.tsv.gz' = 'NEW'; 'snap-npp-1.tsv.gz' = 'NEW'; 'snap-npp-2.tsv.gz' = 'NEW' }
    $rec = @(Invoke-Campaign -Ids npp -Nulls 0)[0]
    Check 'campaign: good run -> ok' ($rec.ok -and $rec.pulled -eq 5) "ok=$($rec.ok) pulled=$($rec.pulled) error=$($rec.error)"
}

# --------------------------------------------- rig.ps1: no plaintext password copy left in %TEMP%
& {
    . (Join-Path $Vm 'rig.ps1')
    $ErrorActionPreference = 'Stop'
    $fake = Join-Path $Work 'fakevbox.cmd'
    # %6 is the --passwordfile argument (guestcontrol VM --username U --passwordfile F ...).
    [IO.File]::WriteAllText($fake, "@if exist `"%~6`" (echo PWFILE-EXISTS) else (echo PWFILE-MISSING)`r`n@exit /b 0`r`n", (New-Object System.Text.ASCIIEncoding))
    $script:VBox = $fake
    $pw = Join-Path $Work 'pw.txt'
    [IO.File]::WriteAllText($pw, "user=tester`r`npassword=not-a-real-password`r`n")
    $env:VMPWFILE = $pw
    $tmp = [IO.Path]::GetTempPath()
    $before = @(Get-ChildItem -LiteralPath $tmp -Filter 'rigpw-*.txt' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $r1 = Invoke-Guest @('stat', 'C:\cr\jobs\agent.alive')
    $r2 = Invoke-GuestCmd 'type C:\cr\jobs\agent.alive'
    $after = @(Get-ChildItem -LiteralPath $tmp -Filter 'rigpw-*.txt' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } | Where-Object { $before -notcontains $_ })
    Check 'Invoke-Guest: the temp password file exists during the call' (($r1.out -join ' ') -match 'PWFILE-EXISTS' -and ($r2.out -join ' ') -match 'PWFILE-EXISTS') "$($r1.out) / $($r2.out)"
    Check 'Invoke-Guest: no rigpw-*.txt left in %TEMP% after direct calls' ($after.Count -eq 0) ($after -join ', ')

    $held = Get-PwFile
    $r3 = Invoke-Guest @('stat', 'x')
    Check 'Invoke-Guest: a copy held by the caller survives the call' ((Test-Path -LiteralPath $held) -and ($r3.out -join ' ') -match 'PWFILE-EXISTS')
    Remove-PwTemp
    Check 'Remove-PwTemp deletes the held copy' (-not (Test-Path -LiteralPath $held))
    $content = [IO.File]::ReadAllText($pw)
    Check 'bare-file form: the original file is never deleted' ($content -match 'password=')
}

# =============================================================================================== M1a (P36)
# Engine mode, run names and the new corpus entries. A stub purge-engine.cmd stands in for the engine.

# Runs everything up to the first dot-source, then prints $Run/$Engine and exits 7 (the checks passed).
function Test-HeadCheck([string]$Text) {
    $i = $Text.IndexOf('. C:\cr\guest\riglib.ps1')
    $f = Join-Path $Work ('head-' + [guid]::NewGuid().ToString('N') + '.ps1')
    [IO.File]::WriteAllText($f, $Text.Substring(0, $i) + "`r`nWrite-Host ('RUN=' + `$Run + ' ENGINE=' + `$Engine)`r`nexit 7`r`n", (New-Object System.Text.UTF8Encoding($true)))
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f 2>&1
    [pscustomobject]@{ code = $LASTEXITCODE; out = ($out -join ' ') }
}

$StubCmd = @'
@echo off
setlocal
>>"%STUB_EV%" echo engine:%*
set "VERB=%~1"
set "SUB=%~2"
set "OUT="
set "PLAN=none"
set "SESS="
:loop
if "%~1"=="" goto run
if "%~1"=="-o" set "OUT=%~2"
if "%~1"=="--plan" set "PLAN=%~2"
if "%~1"=="--session" set "SESS=%~2"
shift
goto loop
:run
if /i "%STUB_FAIL%"=="%VERB%" (
  echo stub: %VERB% fails 1>&2
  exit /b 3
)
if "%VERB%"=="inventory" (
  type "%STUB_DIR%\inv.json"
  exit /b 0
)
if "%VERB%"=="harvest" (
  copy /y "%STUB_DIR%\fp.json" "%OUT%" >nul
  exit /b 0
)
if "%VERB%"=="uninstall" (
  copy /y "%STUB_DIR%\engine-run.json" "%OUT%" >nul
  echo gone>"%STUB_DIR%\uninstalled.txt"
  exit /b 0
)
if "%VERB%"=="scan" (
  copy /y "%STUB_DIR%\plan.json" "%OUT%" >nul
  copy /y "%STUB_DIR%\plan.scan.json" "%OUT:.json=.scan.json%" >nul
  echo scan: 3 candidates 1>&2
  exit /b 0
)
if "%VERB%"=="plan" goto m2plan
if "%VERB%"=="exec" goto m2exec
if "%VERB%"=="undo" goto m2undo
if "%VERB%"=="journal" goto m2journal
if "%VERB%"=="quarantine" goto m2quar
echo stub: unknown verb %VERB% 1>&2
exit /b 1
:m2plan
set "PH=m2plan.scan.json"
if not "%OUT:refuse=%"=="%OUT%" set "PH=m2plan-b.scan.json"
copy /y "%STUB_DIR%\m2plan.json" "%OUT%" >nul
copy /y "%STUB_DIR%\%PH%" "%OUT:.json=.scan.json%" >nul
exit /b 0
:m2exec
if not "%PLAN:refuse=%"=="%PLAN%" goto m2refuse
:m2sid
set "SID=s%RANDOM%%RANDOM%"
set "SD=%STUB_DATA%\sessions\%SID%"
if exist "%SD%" goto m2sid
mkdir "%SD%"
>"%STUB_DATA%\sessions\index.json" echo {"last":"%SID%"}
copy /y "%STUB_DIR%\journal.jsonl" "%SD%\journal.jsonl" >nul
copy /y "%STUB_DIR%\backup.bin" "%SD%\b1.bin" >nul
if defined PURGE_FAULT_AT exit /b -1073740791
>"%SD%\report.json" echo {"schema":"purge.exec/1","session":"%SID%","items":[],"restore_point":null}
if defined OUT copy /y "%SD%\report.json" "%OUT%" >nul
exit /b 0
:m2refuse
echo stub: confirm or plan mismatch, nothing done 1>&2
exit /b 6
:m2undo
if defined PURGE_FAULT_AT exit /b -1073740791
if defined OUT >"%OUT%" echo {"schema":"purge.undo/1","session":"%SESS%","items":[]}
exit /b 0
:m2journal
if "%SUB%"=="fault-points" goto m2fp
if "%SUB%"=="resume" goto m2recovered
if "%SUB%"=="rollback" goto m2recovered
echo journal %SUB% %SESS%: ok
exit /b 0
:m2recovered
echo {"schema":"purge.cli.recovered/1","mode":"%SUB%","sessions":[{"session":"%SESS%","state":"Undone"}]}
exit /b 0
:m2fp
echo journal.header	before the header record
echo intent.flushed	after the intent is flushed
echo act.after	after the action
echo undo.intent	after the undo intent
exit /b 0
:m2quar
if "%SUB%"=="purge" exit /b 0
type "%STUB_DIR%\expiring.json"
exit /b 0
'@

# Writes the stub engine and its canned JSON into $Dir; $MainKey is the ARP key name of the main entry.
function New-StubEngine([string]$Dir, [string]$MainKey) {
    $stub = Join-Path $Dir 'stub'
    New-Item -ItemType Directory -Force $stub | Out-Null
    $exe = Join-Path $Dir 'purge-engine.cmd'
    [IO.File]::WriteAllText($exe, $StubCmd.Replace("`r`n", "`n").Replace("`n", "`r`n"), (New-Object System.Text.ASCIIEncoding))
    $root = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    # The main entry is spelled 'Software' on purpose: the lookup compares canonically.
    $inv = '{"schema":"purge.inventory/0","entries":[' +
        '{"program_id":"HKLM|32|Decoy","key_path":"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Decoy","display_name":"Decoy"},' +
        '{"program_id":"HKLM|64|' + $MainKey + '","key_path":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' + $MainKey + '","display_name":"Main"},' +
        '{"program_id":"HKU:S-1-5-21-1-2-3-1001|64|Other","key_path":"HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Other","display_name":"Other"}' +
        '],"msi_only":[]}'
    [IO.File]::WriteAllText((Join-Path $stub 'inv.json'), $inv)
    [IO.File]::WriteAllText((Join-Path $stub 'fp.json'), '{"schema":"purge.fp/0"}')
    [IO.File]::WriteAllText((Join-Path $stub 'plan.json'), '{"schema":"purge.plan/0","app":"x","tool":"purge","mode":"post","items":[{"target":{"type":"Path","path":"C:\\fake"},"band":"Likely","preselected":false,"scanner":"FS-INSTALLDIR"}]}')
    [IO.File]::WriteAllText((Join-Path $stub 'plan.scan.json'), '{"schema":"purge.scan/0","plan_hash":"abc123","items":[]}')
    $t0 = (Get-Date).AddSeconds(-50).ToFileTime()
    $run = '{"schema":"purge.run/0","program_id":"HKLM|64|' + $MainKey + '","cmd":"\"C:\\fake\\unins000.exe\" /S","signer":null,' +
        '"t_start":' + $t0 + ',"t_end":' + ($t0 + 450000000) + ',"exit_code":0,"outcome":"Success",' +
        '"verify_gone":{"arp_gone":true,"msi_unknown_all_ctx":true,"main_exes_gone":true,"passed":true},"processes":[],"co_removed":[]}'
    [IO.File]::WriteAllText((Join-Path $stub 'engine-run.json'), $run)
    # M2 verbs (plan from-targets, exec, undo, journal, quarantine).
    [IO.File]::WriteAllText((Join-Path $stub 'm2plan.json'), '{"schema":"purge.plan/0","app":"x","tool":"purge","mode":"targets","items":[]}')
    [IO.File]::WriteAllText((Join-Path $stub 'm2plan.scan.json'), '{"schema":"purge.scan/0","plan_hash":"abc123","items":[{"id":"t1","target":{"type":"Path","path":"C:\\Program Files\\PurgeTrapApp\\a"}}]}')
    [IO.File]::WriteAllText((Join-Path $stub 'm2plan-b.scan.json'), '{"schema":"purge.scan/0","plan_hash":"abc124","items":[]}')
    [IO.File]::WriteAllText((Join-Path $stub 'journal.jsonl'), ('{"rec":"header","v":1}' + "`n" + '{"rec":"intent","item":"i1","op":"o1","backup":{"path":"b1.bin"}}' + "`n" + '{"rec":"done","item":"i1","op":"o1"}' + "`n" + '{"rec":"commit"}' + "`n"))
    [IO.File]::WriteAllText((Join-Path $stub 'backup.bin'), 'backup bytes of o1')
    [IO.File]::WriteAllText((Join-Path $stub 'expiring.json'), '[{"id":"q1","original":"C:\\Program Files\\PurgeTrapApp\\expiry\\payload","quarantined":"2025-01-01T00:00:00Z"},{"id":"q2","original":"C:\\Other"}]')
    [pscustomobject]@{ exe = $exe; stub = $stub; t_start = $t0; root = $root }
}

# ------------------------------------------------- New-RunJobText: __ID__, __RUN__ and __ENGINE__
& {
    . (Join-Path $Vm 'rig.ps1')
    $ErrorActionPreference = 'Stop'
    $tpl = [IO.File]::ReadAllText((Join-Path $Guest 'run-app.ps1'))
    Check 'run-app template has the __RUN__ and __ENGINE__ placeholders' ($tpl.Contains("`$Run = '__RUN__'") -and $tpl.Contains("`$EngineFlag = '__ENGINE__'"))
    $t = New-RunJobText -Id 'npp'
    Check 'New-RunJobText -Id npp: run = id, engine off, nothing left unreplaced' ($t.Contains("`$Id = 'npp'") -and $t.Contains("`$Run = 'npp'") -and $t.Contains("`$EngineFlag = '0'") -and -not ($t -match '__(ID|RUN|ENGINE)__'))
    $t = New-RunJobText -Id 'npp' -Run 'r0-npp' -Engine
    Check 'New-RunJobText -Run r0-npp -Engine: both placeholders replaced' ($t.Contains("`$Id = 'npp'") -and $t.Contains("`$Run = 'r0-npp'") -and $t.Contains("`$EngineFlag = '1'"))
    foreach ($bad in 'R0-npp', '-npp', 'r0 npp', 'r0\npp') {
        $msg = $null; try { $null = New-RunJobText -Id 'npp' -Run $bad } catch { $msg = $_.Exception.Message }
        Check "New-RunJobText rejects the run name '$bad'" ($msg -match 'bad run name') "got '$msg'"
    }
    Check 'New-RunJobText -Null 2 still fills null-run.ps1' ((New-RunJobText -NullRun 2).Contains("`$Run = 'null2'"))
    $t = New-RunJobText -NullRun 2
    Check 'New-RunJobText -Null 2: wait defaults to 60, nothing left unreplaced' ($t.Contains("`$WaitArg = '60'") -and -not ($t -match '__(RUN|WAIT)__'))
    $t = New-RunJobText -NullRun 3 -Run (Get-NullRunName -N 3 -RunPrefix 'r0-') -NullWaitSec 120
    Check 'New-RunJobText null with prefix and wait: r0-null3, 120 s' ($t.Contains("`$Run = 'r0-null3'") -and $t.Contains("`$WaitArg = '120'"))
    Check 'Get-NullRunName: no prefix keeps null<n> (M0)' ((Get-NullRunName -N 1) -eq 'null1')
    $msg = $null; try { $null = Get-NullRunName -N 1 -RunPrefix 'r0' } catch { $msg = $_.Exception.Message }
    Check 'Get-NullRunName: a prefix without a trailing dash is rejected' ($msg -match 'bad null run name') "got '$msg'"
    $o = @(Get-CampaignOrder -Nulls @('n1', 'n2', 'n3') -Apps @('a', 'b', 'c', 'd', 'e', 'f') -NullOrder spread) -join ','
    Check 'Get-CampaignOrder spread: nulls first, middle and last' ($o -eq 'n1,a,b,c,n2,d,e,f,n3') $o
    $o = @(Get-CampaignOrder -Nulls @('n1', 'n2', 'n3') -Apps @('a', 'b') -NullOrder first) -join ','
    Check 'Get-CampaignOrder first: nulls, then apps (M0 order)' ($o -eq 'n1,n2,n3,a,b') $o
    $tpl0 = [IO.File]::ReadAllText((Join-Path $Guest 'null-run.ps1'))
    Check 'null-run template has the __RUN__ and __WAIT__ placeholders' ($tpl0.Contains("`$Run = '__RUN__'") -and $tpl0.Contains("`$WaitArg = '__WAIT__'"))

    $t = New-RunJobText -Id 'npp-userfiles' -Run 'x0-npp-userfiles' -Engine -Extra
    Check 'New-RunJobText -Engine -Extra: __EXTRA__ = 1, nothing left unreplaced' ($t.Contains("`$ExtraFlag = '1'") -and -not ($t -match '__(ID|RUN|ENGINE|EXTRA)__'))
    Check 'New-RunJobText without -Extra: __EXTRA__ = 0' ((New-RunJobText -Id 'npp' -Run 'r0-npp' -Engine).Contains("`$ExtraFlag = '0'"))
    $msg = $null; try { $null = New-RunJobText -Id 'npp' -Extra } catch { $msg = $_.Exception.Message }
    Check 'New-RunJobText -Extra without -Engine throws' ($msg -match 'needs -Engine') "got '$msg'"
    $r = Test-HeadCheck (New-RunJobText -Id 'npp' -Run 'r0-npp' -Engine)
    Check 'run-app head: r0-npp in engine mode passes' ($r.code -eq 7 -and $r.out -match 'RUN=r0-npp ENGINE=True') "exit $($r.code): $($r.out)"
    $r = Test-HeadCheck (New-RunJobText -Id 'firefox-tb')
    Check 'run-app head: plain id run, engine off' ($r.code -eq 7 -and $r.out -match 'RUN=firefox-tb ENGINE=False') "exit $($r.code): $($r.out)"
    $r = Test-HeadCheck $tpl.Replace('__ID__', 'npp')
    Check 'run-app head: __RUN__/__ENGINE__ left in place -> run = id, engine off (M0)' ($r.code -eq 7 -and $r.out -match 'RUN=npp ENGINE=False') "exit $($r.code): $($r.out)"
    $r = Test-HeadCheck $tpl.Replace('__ID__', 'npp').Replace('__RUN__', 'R0-NPP')
    Check 'run-app head: an uppercase run name exits 2' ($r.code -eq 2 -and $r.out -match 'bad run name') "exit $($r.code): $($r.out)"
}

# --------------------------------------------------------------------------------- apps.ps1 corpus
& {
    . (Join-Path $Guest 'riglib.ps1')
    . (Join-Path $Guest 'apps.ps1')
    $ErrorActionPreference = 'Stop'
    $ff = Get-App 'firefox'; $ft = Get-App 'firefox-tb'; $vu = Get-App 'vscode-user'; $tb = Get-App 'thunderbird'
    $same = $true
    foreach ($k in $ff.Keys) { if ($k -ne 'id' -and "$($ff[$k])" -ne "$($ft[$k])") { $same = $false } }
    Check 'firefox-tb = firefox + pre thunderbird' ($same -and $ft.id -eq 'firefox-tb' -and @($ft.pre) -join ',' -eq 'thunderbird' -and -not $ff.pre) (($ft.Keys | Sort-Object) -join ',')
    Check 'vscode-user: official user build URL, medium install, (User) match' ((& $vu.url) -eq 'https://update.code.visualstudio.com/latest/win32-x64-user/stable' -and $vu.install_il -eq 'medium' -and 'Microsoft Visual Studio Code (User)' -match $vu.match -and -not ('Microsoft Visual Studio Code' -match $vu.match))
    Check 'vscode-user: same Inno switches as vscode, launch from %LOCALAPPDATA%\Programs' ($vu.install -eq (Get-App 'vscode').install -and @($vu.launch.dirs)[0] -eq '%LOCALAPPDATA%\Programs\Microsoft VS Code')
    Check 'thunderbird: official Mozilla URL, /S' ((& $tb.url) -eq 'https://download.mozilla.org/?product=thunderbird-latest-ssl&os=win64&lang=en-US' -and $tb.install -eq '/S' -and 'Mozilla Thunderbird (x64 en-US)' -match $tb.match)
    $ids = @($Apps | ForEach-Object { $_.id })
    Check 'app ids are unique' (@($ids | Select-Object -Unique).Count -eq $ids.Count) ($ids -join ',')

    # x0 variants (RIG.md §4b)
    $x0 = 'npp-userfiles', 'git-toolsdir', 'ff-devedition', 'vscode-with-user', 'git-userstate', 'ff-tbafter', 'vscode-userstate',
          'vscode-insiders-pair', 'vscode-upgrade', 'ff-esr', 'vscode-zipcopy', 'ff-reinstall', 'git-upgrade'
    $miss = @($x0 + 'thunderbird', 'vlc', 'winmerge' | Where-Object { $ids -notcontains $_ })
    Check 'x0: every variant and new base record exists' ($miss.Count -eq 0) ($miss -join ',')
    $bad = @()
    foreach ($a in $Apps) {
        foreach ($ref in @(@($a.pre) + @($a.post) + @($a.upgrade_from) | Where-Object { $_ })) { if ($ids -notcontains $ref) { $bad += "$($a.id)->$ref" } }
    }
    Check 'x0: pre / post / upgrade_from name known apps' ($bad.Count -eq 0) ($bad -join ',')
    $np = Get-App 'npp-userfiles'; $n0 = Get-App 'npp'
    Check 'x0: npp-userfiles = npp + plants (install, match, un, launch unchanged)' ($np.install -eq $n0.install -and $np.match -eq $n0.match -and $np.un -eq $n0.un -and $np.file -eq 'npp.exe' -and $np.plant_pre -eq 'Plant-NppPortable' -and $np.plant_post -eq 'Plant-NppUserFiles' -and -not $n0.plant_pre)
    Check 'x0: Get-AppFiles ff-tbafter = firefox + thunderbird' ((Get-AppFiles 'ff-tbafter') -join ',' -eq 'firefox.exe,thunderbird.exe') ((Get-AppFiles 'ff-tbafter') -join ',')
    Check 'x0: Get-AppFiles npp-userfiles includes the portable zip' ((Get-AppFiles 'npp-userfiles') -join ',' -eq 'npp.exe,npp-portable.zip') ((Get-AppFiles 'npp-userfiles') -join ',')
    Check 'x0: Get-AppFiles vscode-upgrade = vscode + vscode-1145' ((Get-AppFiles 'vscode-upgrade') -join ',' -eq 'vscode.exe,vscode-1145.exe') ((Get-AppFiles 'vscode-upgrade') -join ',')
    $tg = Get-App 'tortoisegit'
    Check 'x0: tortoisegit is the signed MSI from download.tortoisegit.org' ($tg.install -eq 'msi' -and $tg.un -eq 'msi' -and "$(& $tg.url)" -like 'https://download.tortoisegit.org/*.msi')
    # Every plant function named in apps.ps1 is defined in x0-plants.ps1 (parsed, not run: it writes the user hive).
    $tok = $null; $err = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Guest 'x0-plants.ps1'), [ref]$tok, [ref]$err)
    $defs = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
    $names = @($Apps | ForEach-Object { $_.plant_pre; $_.plant_post } | Where-Object { $_ } | Select-Object -Unique)
    $undef = @($names | Where-Object { $defs -notcontains $_ })
    Check 'x0: every plant_pre / plant_post function exists in x0-plants.ps1' ($names.Count -ge 7 -and $undef.Count -eq 0) "undefined: $($undef -join ',')"
    # Every installer of a new record and every plant file is in the host cache manifest (official URL + SHA-256).
    $manF = Join-Path $Vm 'cache\inst\cache-sources.json'
    if (Test-Path $manF) {
        $man = [IO.File]::ReadAllText($manF) | ConvertFrom-Json
        $keys = @($man.PSObject.Properties | ForEach-Object { $_.Name })
        $need = @('firefox-dev', 'firefox-esr', 'vscode-insiders', 'vscode-1145', 'tortoisegit', 'winmerge', 'git-2560' | ForEach-Object { (Get-App $_).file }) +
                @($Apps | ForEach-Object { $_.plant_files } | Where-Object { $_ })
        $absent = @($need | Select-Object -Unique | Where-Object { $keys -notcontains $_ })
        $noHash = @($keys | Where-Object { "$($man.$_.sha256)" -notmatch '^[0-9A-Fa-f]{64}$' -or "$($man.$_.url)" -notmatch '^https://' })
        Check 'x0: host cache manifest lists every new installer and plant file with an https URL and a SHA-256' ($absent.Count -eq 0 -and $noHash.Count -eq 0) "absent: $($absent -join ','); bad: $($noHash -join ',')"
    } else { Write-Host "skip x0 cache manifest check (no $manF)" }
}

# --------------------------------------------------------------- Edge pause: before any capture, in both jobs
& {
    foreach ($f in 'run-app.ps1', 'null-run.ps1') {
        $t = [IO.File]::ReadAllText((Join-Path $Guest $f))
        $p = $t.IndexOf("Phase 'edge-pause'"); $a = $t.IndexOf("Phase 'arp0'"); $l = $t.IndexOf("Phase 'lists0'"); $c = $t.IndexOf("Phase 'edge-check'"); $s2 = $t.IndexOf("Phase 'snap2'")
        Check "${f}: edge-pause before arp0 / lists0, edge-check after snap2" ($p -gt 0 -and $p -lt $a -and $p -lt $l -and $c -gt $s2) "pause=$p arp0=$a lists0=$l check=$c snap2=$s2"
    }
    $rl = [IO.File]::ReadAllText((Join-Path $Guest 'riglib.ps1'))
    Check 'riglib: Suspend-EdgeUpdate disables both services and the MicrosoftEdgeUpdate* tasks' ($rl -match "RigEdgeServices = @\('edgeupdate', 'edgeupdatem'\)" -and $rl -match 'Set-Service -Name \$n -StartupType Disabled' -and $rl -match 'Disable-ScheduledTask')
}

# ------------------------------------------------------------------------- riglib: engine helpers
& {
    . (Join-Path $Guest 'riglib.ps1')
    $ErrorActionPreference = 'Stop'
    Check 'ConvertTo-EngineArg: plain word unquoted' ((ConvertTo-EngineArg 'inventory') -eq 'inventory')
    Check 'ConvertTo-EngineArg: program id quoted' ((ConvertTo-EngineArg 'HKLM|64|Git_is1') -eq '"HKLM|64|Git_is1"')
    Check 'ConvertTo-EngineArg: trailing backslash doubled' ((ConvertTo-EngineArg 'C:\a b\') -eq '"C:\a b\\"') (ConvertTo-EngineArg 'C:\a b\')
    Check 'ConvertTo-EngineArg: embedded quote escaped' ((ConvertTo-EngineArg 'x"y') -eq '"x\"y"') (ConvertTo-EngineArg 'x"y')
    $iso = ConvertFrom-EngineFileTime 134000000000000000
    Check 'ConvertFrom-EngineFileTime round-trips' ([DateTimeOffset]::Parse($iso, [Globalization.CultureInfo]::InvariantCulture).ToFileTime() -eq 134000000000000000) $iso
    Check 'ConvertFrom-EngineFileTime: null stays null' ($null -eq (ConvertFrom-EngineFileTime $null))

    $sd = New-StubEngine (Join-Path $Work 'helpers') 'Git_is1'
    $inv = [IO.File]::ReadAllText((Join-Path $sd.stub 'inv.json')) | ConvertFrom-Json
    Check 'Find-InventoryProgramId: HKLM key, other spelling' ((Find-InventoryProgramId $inv 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1') -eq 'HKLM|64|Git_is1')
    Check 'Find-InventoryProgramId: HKEY_LOCAL_MACHINE spelling' ((Find-InventoryProgramId $inv 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\git_is1') -eq 'HKLM|64|Git_is1')
    Check 'Find-InventoryProgramId: WOW6432Node key' ((Find-InventoryProgramId $inv 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Decoy') -eq 'HKLM|32|Decoy')
    Check 'Find-InventoryProgramId: user hive key' ((Find-InventoryProgramId $inv 'HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Uninstall\Other') -eq 'HKU:S-1-5-21-1-2-3-1001|64|Other')
    $msg = $null; try { $null = Find-InventoryProgramId $inv 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Missing' } catch { $msg = $_.Exception.Message }
    Check 'Find-InventoryProgramId: no entry -> throws' ($msg -match 'no inventory entry') "got '$msg'"
    $dup = '{"entries":[{"program_id":"A","key_path":"HKLM\\SOFTWARE\\X"},{"program_id":"B","key_path":"hklm\\software\\x"}]}' | ConvertFrom-Json
    $msg = $null; try { $null = Find-InventoryProgramId $dup 'HKLM\SOFTWARE\X' } catch { $msg = $_.Exception.Message }
    Check 'Find-InventoryProgramId: two entries -> throws' ($msg -match '2 inventory entries') "got '$msg'"
    $one = '{"entries":[{"program_id":"HKLM|64|Only","key_path":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Only"}]}' | ConvertFrom-Json
    Check 'Find-InventoryProgramId: a one-entry inventory' ((Find-InventoryProgramId $one 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Only') -eq 'HKLM|64|Only')

    $RigEngine = $sd.exe
    $script:RigLogFile = Join-Path $Work 'helpers\log.txt'
    $env:STUB_DIR = $sd.stub; $env:STUB_EV = Join-Path $Work 'helpers\ev.txt'; $env:STUB_FAIL = ''
    $calls = New-Object System.Collections.ArrayList
    $fp = Join-Path $Work 'helpers\fp.json'
    $r = Invoke-EngineStep -Step 'harvest' -Arguments ('harvest ' + (ConvertTo-EngineArg 'HKLM|64|Git_is1') + ' -o ' + (ConvertTo-EngineArg $fp)) -Calls $calls
    Check 'Invoke-EngineStep: stub harvest ok, -o written, call recorded' ($r.exit -eq 0 -and (Test-Path $fp) -and $calls.Count -eq 1 -and $calls[0].step -eq 'harvest' -and $calls[0].exit -eq 0 -and $calls[0].pid -gt 0) "exit=$($r.exit) calls=$($calls.Count)"
    $ev = [IO.File]::ReadAllText($env:STUB_EV)
    Check 'Invoke-EngineStep: the program id reaches the engine as one argument' ($ev -match [regex]::Escape('engine:harvest "HKLM|64|Git_is1" -o')) $ev
    $invOut = Join-Path $Work 'helpers\inv.json'
    $null = Invoke-EngineStep -Step 'inventory' -Arguments 'inventory --json' -Calls $calls -StdoutFile $invOut
    $back = [IO.File]::ReadAllText($invOut) | ConvertFrom-Json
    Check 'Invoke-EngineStep -StdoutFile: stdout saved as JSON' (@($back.entries).Count -eq 3)
    $env:STUB_FAIL = 'scan'
    $msg = $null; try { $null = Invoke-EngineStep -Step 'scan' -Arguments 'scan --fp x -o y' -Calls $calls } catch { $msg = $_.Exception.Message }
    Check 'Invoke-EngineStep: exit 3 throws and is recorded' ($msg -match 'exited 3' -and $calls.Count -eq 3 -and $calls[2].exit -eq 3 -and @($calls[2].stderr_tail) -join ' ' -match 'stub: scan fails') "msg='$msg' calls=$($calls.Count)"
    $env:STUB_FAIL = ''
    $RigEngine = Join-Path $Work 'nonexistent\purge-engine.exe'
    $msg = $null; try { $null = Invoke-EngineStep -Step 'inventory' -Arguments 'inventory --json' -Calls $calls } catch { $msg = $_.Exception.Message }
    Check 'Invoke-EngineStep: a missing engine throws before running' ($msg -match 'missing' -and $calls.Count -eq 3) "msg='$msg'"
    Remove-Item Env:STUB_DIR, Env:STUB_EV, Env:STUB_FAIL -ErrorAction SilentlyContinue
}

# -------------------------------------------- riglib: process tree PID-reuse guard (no clock ordering)
& {
    . (Join-Path $Guest 'riglib.ps1')
    $ErrorActionPreference = 'Stop'
    $boot = [datetime]'2026-11-11T07:00:00'
    $now = [datetime]'2026-11-12T13:30:00'
    function P($id, $pp, $n, $st) { [pscustomobject]@{ pid = $id; ppid = $pp; name = $n; path = $null; cmd = $n; session = 0; start = $st } }
    # Before the root starts: csrss/wininit whose ppid is the PID of an smss.exe instance that has exited.
    $before = @((P 600 500 'csrss.exe' $boot), (P 700 500 'wininit.exe' $boot), (P 900 1 'explorer.exe' $boot))
    $pre = New-ProcKeySet $before
    # The root (installer) reuses PID 500; its child was created after a BACKWARD clock step, so its start
    # time is earlier than everything else's. It must still be part of the tree.
    $after = $before + @((P 500 900 'setup.exe' $now), (P 510 500 'setup.tmp' $boot.AddDays(-3)), (P 520 510 'helper.exe' $now.AddMinutes(1)))
    $known = New-PidSet @(500)
    $tree = @(Get-TreeProcs -Procs $after -Known $known -Preexisting $pre | ForEach-Object { $_.name } | Sort-Object)
    Check 'Get-TreeProcs: pre-existing processes with the reused ppid are not adopted' (-not ($tree -contains 'csrss.exe') -and -not ($tree -contains 'wininit.exe')) ($tree -join ',')
    Check 'Get-TreeProcs: a child with a back-stepped start time stays in the tree' (($tree -join ',') -eq 'helper.exe,setup.exe,setup.tmp') ($tree -join ',')
    $tree0 = @(Get-TreeProcs -Procs $after -Known (New-PidSet @(500)) | ForEach-Object { $_.name })
    Check 'Get-TreeProcs: without the guard the reuse case adopts csrss (documents the hazard)' ($tree0 -contains 'csrss.exe') ($tree0 -join ',')
    # A pre-existing process that exits and whose PID a new child reuses: different creation time, so it is new.
    $after2 = @((P 500 900 'setup.exe' $now), (P 900 500 'child.exe' $now.AddMinutes(2)))
    $tree2 = @(Get-TreeProcs -Procs $after2 -Known (New-PidSet @(500)) -Preexisting $pre | ForEach-Object { $_.name } | Sort-Object)
    Check 'Get-TreeProcs: a reused PID with a new creation time is a real child' (($tree2 -join ',') -eq 'child.exe,setup.exe') ($tree2 -join ',')
    # WaitTree end to end with fake polls: the adopted-system case would never go idle; with the guard it does.
    $script:polls = 0
    $gp ={ $script:polls++; if ($script:polls -le 2) { $after } else { $before } }
    $w = WaitTree -RootPid @(500) -Preexisting $pre -GetProcs $gp -MsiBusy { $false } -PollSec 0 -TimeoutSec 20 -QuietPolls 2
    Check 'WaitTree -Preexisting: ends once the real tree exits (csrss/wininit never block)' (-not $w.timed_out -and $w.cond_met) "timed_out=$($w.timed_out)"
}

# --------------------------------------------------- run-app.ps1 end to end with fakes and the stub
# The job text is generated by New-RunJobText as on the host; the guest paths point at vm\guest and a fakes
# file is dot-sourced right after apps.ps1. Every capture, install, launch and wait is a fake that appends to
# events.txt; the stub engine appends its command lines to the same file.
$Fakes = @'
$RigOut = '@W@\out'; $RigInst = '@W@\inst'; $RigTool = '@W@\rigtool.exe'; $RigEngine = '@W@\purge-engine.cmd'
$script:FakeEv = '@W@\events.txt'
$script:FakeStub = '@W@\stub'
$script:FakeInstalled = New-Object System.Collections.ArrayList
$script:FakeNames = @{ npp = 'Notepad++ (64-bit x64)'; firefox = 'Mozilla Firefox (x64 en-US)'; thunderbird = 'Mozilla Thunderbird (x64 en-US)'; 'vscode-user' = 'Microsoft Visual Studio Code (User)'; git = 'Git' }
# Never touch the host's Edge updater or plant anything on the host: the Edge pause and every plant function
# (apps.ps1 plant_pre / plant_post) are fakes that only record an event (and one planted item each).
function Get-EdgeVersions { [ordered]@{ 'fake-edge' = 'Microsoft Edge 1.0' } }
function Suspend-EdgeUpdate { Ev 'edge-pause'; [ordered]@{ method = 'fake'; versions_before = (Get-EdgeVersions); versions_after = (Get-EdgeVersions) } }
foreach ($pn in @($Apps | ForEach-Object { $_.plant_pre; $_.plant_post } | Where-Object { $_ } | Select-Object -Unique)) {
    Set-Item -Path "function:script:$pn" -Value ([scriptblock]::Create("param(`$Ctx) Ev ('plant:' + `$Ctx.Phase + ':$pn'); Add-Planted `$Ctx 'file' 'P:C:\fake\$pn.txt' 'fake'"))
}
$script:FakeMainKey = [IO.Path]::GetFileNameWithoutExtension((Get-App $Id).file)
function Ev([string]$s) { [IO.File]::AppendAllText($script:FakeEv, $s + "`r`n") }
function FakeKey([string]$b) { "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Fake-$b" }
function Gone { Test-Path -LiteralPath (Join-Path $script:FakeStub 'uninstalled.txt') }
function Visible([string]$b) { $script:FakeInstalled.Contains($b) -and -not ($b -eq $script:FakeMainKey -and (Gone)) }
function Mark-Installed([string]$Exe) {
    if ($Exe.StartsWith($RigInst + '\', [StringComparison]::OrdinalIgnoreCase)) {
        $b = [IO.Path]::GetFileNameWithoutExtension($Exe)
        if (-not $script:FakeInstalled.Contains($b)) { [void]$script:FakeInstalled.Add($b) }
    }
}
function Test-InstallerFile([string]$Path) { $true }
function Get-FileInfoRecord([string]$Path, [string]$Url = $null) { [pscustomobject]@{ file = $Path; url = $Url; size = 1; sha256 = 'FAKE'; sig = 'Valid'; signer = 'CN=Fake' } }
function Fetch { throw 'no downloads in the self-test' }
function Start-Sleep { }
function Start-Native([string]$Exe, [string]$Arguments = '', [string]$WorkDir = '') {
    Ev "start:$(Split-Path -Leaf $Exe) $Arguments"
    Mark-Installed $Exe
    if ($Exe -like 'C:\fake\uninst-*.exe') { [void]$script:FakeInstalled.Remove(($Exe -replace '^.*\\uninst-', '' -replace '\.exe$', '')) }
    $p = [pscustomobject]@{ Id = 4000000; ExitCode = 0 }
    $p | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) $true }
    $p
}
function LaunchMedium([string]$Exe, [string]$Arguments = '', [string]$WorkDir = '', [string]$TaskName = 'PurgeRigLaunch', [int]$StartTimeoutSec = 30) {
    Ev "medium:${TaskName}:$(Split-Path -Leaf $Exe)"
    Mark-Installed $Exe
    [pscustomobject]@{ task = $TaskName; exe = $Exe; args = $Arguments; start = (Get-Date); pid = 4000001; found = $true }
}
function Stop-Launch($Launch, [int]$GraceSec = 5) { [pscustomobject]@{ closed = @(); killed = @() } }
function Unregister-ScheduledTask { [CmdletBinding(SupportsShouldProcess)] param([string]$TaskName) Ev "unregister:$TaskName" }
function Get-ProcList { @() }
function WaitTree {
    param([datetime]$Since, [int]$TimeoutSec = 900, [int]$PollSec = 2, [scriptblock]$Until = $null, [int]$QuietPolls = 2,
          [int]$IdleGiveUpSec = 0, $GetProcs = $null, $MsiBusy = $null, [int[]]$RootPid = @(), $Preexisting = $null)
    if ($RootPid.Count -and $null -eq $Preexisting) { Ev 'waittree:no-preexisting' }
    [pscustomobject]@{ timed_out = $false; cond_met = $true; end = (Get-Date); still = @(); known = (New-PidSet @()) }
}
function Resolve-LaunchExe($App, $Main) { 'C:\fake\app.exe' }
function UninstallEntries {
    foreach ($b in @($script:FakeInstalled)) {
        if (-not (Visible $b)) { continue }
        [pscustomobject][ordered]@{ key = (FakeKey $b); name = $script:FakeNames[$b]; version = '1.0'; publisher = 'Fake'; sys = $false; parent = $null
            uninstall = "`"C:\fake\uninst-$b.exe`""; quiet = $null; loc = 'C:\fake'; icon = $null; msi = $null; size = 1; install_date = $null; bundle = $false }
    }
}
function Test-RegKey([string]$Canon) { foreach ($b in @($script:FakeInstalled)) { if ((FakeKey $b) -ieq $Canon) { return (Visible $b) } }; $false }
function Lists([string]$Run, [string]$Phase) { Ev "lists:$Phase"; [IO.File]::WriteAllText((Join-Path (Join-Path $RigOut $Run) "lists-$Run-$Phase.json"), '{}') }
function Snap([string]$Run, [string]$Phase) { Ev "snap:$Phase"; [IO.File]::WriteAllText((Join-Path (Join-Path $RigOut $Run) "snap-$Run-$Phase.tsv.gz"), 'x') }
'@

# Runs one generated job in a child powershell.exe. Returns {code, out, dir (C:\cr\out\<run> stand-in), run
# (run.json), phases (names), failed (names), events, engine (engine command lines), stub}.
function Invoke-FakeRunApp([string]$Scenario, [string]$Id, [string]$Run = '', [switch]$EngineMode, [string]$Fail = '', [switch]$Extra) {
    $W = Join-Path $Work "ra-$Scenario"
    foreach ($d in 'out', 'inst') { New-Item -ItemType Directory -Force (Join-Path $W $d) | Out-Null }
    . (Join-Path $Vm 'rig.ps1')
    . (Join-Path $Guest 'apps.ps1')
    $mainKey = 'Fake-' + [IO.Path]::GetFileNameWithoutExtension((Get-App $Id).file)
    $sd = New-StubEngine $W $mainKey
    [IO.File]::WriteAllText((Join-Path $W 'fakes.ps1'), $Fakes.Replace('@W@', $W), (New-Object System.Text.UTF8Encoding($true)))
    if (-not $Run) { $Run = $Id }
    $text = New-RunJobText -Id $Id -Run $Run -Engine:$EngineMode -Extra:$Extra
    $text = $text.Replace('. C:\cr\guest\riglib.ps1', ". '$Guest\riglib.ps1'")
    $text = $text.Replace('. C:\cr\guest\apps.ps1', ". '$Guest\apps.ps1'")
    # The fakes come after x0-plants.ps1, so they replace its plant functions too.
    $x0 = "if (Test-Path -LiteralPath 'C:\cr\guest\x0-plants.ps1') { . C:\cr\guest\x0-plants.ps1 }"
    if (-not $text.Contains($x0)) { throw 'run-app.ps1 no longer dot-sources x0-plants.ps1 the expected way' }
    $text = $text.Replace($x0, ". '$Guest\x0-plants.ps1'`r`n. '$W\fakes.ps1'")
    $job = Join-Path $W 'job.ps1'
    [IO.File]::WriteAllText($job, $text, (New-Object System.Text.UTF8Encoding($true)))
    $env:STUB_DIR = $sd.stub; $env:STUB_EV = Join-Path $W 'events.txt'; $env:STUB_FAIL = $Fail
    try { $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $job 2>&1; $code = $LASTEXITCODE }
    finally { Remove-Item Env:STUB_DIR, Env:STUB_EV, Env:STUB_FAIL -ErrorAction SilentlyContinue }
    $dir = Join-Path (Join-Path $W 'out') $Run
    $rj = $null
    if (Test-Path (Join-Path $dir 'run.json')) { $rj = [IO.File]::ReadAllText((Join-Path $dir 'run.json')) | ConvertFrom-Json }
    $events = @()
    if (Test-Path (Join-Path $W 'events.txt')) { $events = @([IO.File]::ReadAllLines((Join-Path $W 'events.txt')) | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $phases = @(); $failed = @()
    if ($rj) { $phases = @(@($rj.phases) | ForEach-Object { "$($_.name)" }); $failed = @(@($rj.phases) | Where-Object { -not $_.ok } | ForEach-Object { "$($_.name)" }) }
    [pscustomobject]@{
        code = $code; out = ($out -join "`n"); dir = $dir; run = $rj; phases = $phases; failed = $failed; events = $events
        engine = @($events | Where-Object { $_ -like 'engine:*' }); stub = $sd; outRoot = (Join-Path $W 'out')
    }
}
function Files($Dir) { @(Get-ChildItem -LiteralPath $Dir -File | ForEach-Object { $_.Name } | Sort-Object) -join ',' }
# The capture / install / engine events only, in order.
function Steps($R) { @($R.events | Where-Object { $_ -match '^(lists|snap|start|medium|engine):' } | ForEach-Object { ($_ -split ' ')[0] }) -join ' ' }

$M0Phases = 'edge-pause setup arp0 lists0 snap0 install detect launch lists1 snap1 uninstall lists2 snap2 edge-check entries'
# Engine inventory right after the lists of the same point (RIG.md §4a capture order).
$EnginePhases = 'edge-pause setup arp0 lists0 snap0 install detect launch lists1 engine-inventory-1 snap1 engine-harvest uninstall lists2 engine-inventory-2 snap2 edge-check entries engine-scan'

& {
    $ErrorActionPreference = 'Stop'
    # M0 mode: unchanged vendor path, no engine call.
    $r = Invoke-FakeRunApp 'm0' 'npp'
    Check 'run-app M0: exit 0, M0 phase order' ($r.code -eq 0 -and ($r.phases -join ' ') -eq $M0Phases) "exit $($r.code); phases: $($r.phases -join ' ')`n$($r.out)"
    Check 'run-app M0: vendor uninstall, no engine call, no engine record' ($r.engine.Count -eq 0 -and ($r.events -contains 'start:uninst-npp.exe /S') -and -not ($r.run.PSObject.Properties.Name -contains 'engine') -and $r.run.uninstall.entry_gone -eq $true) (Steps $r)
    Check 'run-app M0: every tree wait has the PID-reuse guard (-Preexisting)' (-not ($r.events -contains 'waittree:no-preexisting')) ($r.events -join ' | ')
    Check 'run-app M0: outputs under the app id, installer ran elevated' ((Files $r.dir) -eq 'lists-npp-0.json,lists-npp-1.json,lists-npp-2.json,run.json,run.log,snap-npp-0.tsv.gz,snap-npp-1.tsv.gz,snap-npp-2.tsv.gz' -and $r.run.install.ran_as -eq 'elevated') (Files $r.dir)

    # Engine mode, every call ok.
    $r = Invoke-FakeRunApp 'engine' 'npp' 'r0-npp' -EngineMode
    Check 'run-app engine: exit 0, documented phase order' ($r.code -eq 0 -and ($r.phases -join ' ') -eq $EnginePhases) "exit $($r.code); phases: $($r.phases -join ' ')`n$($r.out)"
    Check 'run-app engine: captures and engine calls in order' ((Steps $r) -eq 'lists:0 snap:0 start:npp.exe medium:PurgeRigLaunch:app.exe lists:1 engine:inventory snap:1 engine:harvest engine:uninstall lists:2 engine:inventory snap:2 engine:scan') (Steps $r)
    Check 'run-app engine: Edge pause is the first event, before any capture' ($r.events[0] -eq 'edge-pause' -and $r.run.edge_pause.held -eq $true -and $r.run.edge_pause.versions_end) ($r.events -join ' | ')
    Check 'run-app engine: outputs under the prefixed run name only' ((Files $r.dir) -eq 'engine-run.json,fp.json,inv-1.json,inv-2.json,lists-r0-npp-0.json,lists-r0-npp-1.json,lists-r0-npp-2.json,plan-purge.json,plan-purge.scan.json,run.json,run.log,snap-r0-npp-0.tsv.gz,snap-r0-npp-1.tsv.gz,snap-r0-npp-2.tsv.gz' -and -not (Test-Path (Join-Path $r.outRoot 'npp'))) (Files $r.dir)
    Check 'run-app engine: no extra checks without -Extra' (-not ($r.run.PSObject.Properties.Name -contains 'extra') -and -not ($r.engine -match '--mode external')) ($r.engine -join ' | ')
    Check 'run-app engine: run.json names run r0-npp of app npp' ($r.run.run -eq 'r0-npp' -and $r.run.id -eq 'npp')
    Check 'run-app engine: program_id resolved from inv-1.json by key path' ($r.run.engine.program_id -eq 'HKLM|64|Fake-npp') "$($r.run.engine.program_id)"
    Check 'run-app engine: harvest/uninstall/scan command lines' (
        ($r.engine -contains ('engine:harvest "HKLM|64|Fake-npp" -o ' + (Join-Path $r.dir 'fp.json'))) -and
        ($r.engine -contains ('engine:uninstall "HKLM|64|Fake-npp" --quiet --fp ' + (Join-Path $r.dir 'fp.json') + ' -o ' + (Join-Path $r.dir 'engine-run.json'))) -and
        ($r.engine -contains ('engine:scan --fp ' + (Join-Path $r.dir 'fp.json') + ' --mode post --app npp -o ' + (Join-Path $r.dir 'plan-purge.json')))) ($r.engine -join ' | ')
    $u = $r.run.uninstall
    $t0 = $null; if ($u.t0) { $t0 = [DateTimeOffset]::Parse("$($u.t0)", [Globalization.CultureInfo]::InvariantCulture).ToFileTime() }
    Check 'run-app engine: t0/t1/exit copied from engine-run.json' ($u.via -eq 'purge-engine' -and $u.times -eq 'engine' -and $t0 -eq $r.stub.t_start -and $u.exit -eq 0 -and $u.outcome -eq 'Success' -and $u.verify_gone.passed -eq $true -and $u.t1 -and $u.rig_t0 -and $u.rig_t1) "t0=$($u.t0) ($t0 vs $($r.stub.t_start)) times=$($u.times) exit=$($u.exit)"
    Check 'run-app engine: no vendor uninstall, entry gone' (-not ($r.events -match '^start:uninst-') -and $u.entry_gone -eq $true)
    Check 'run-app engine: every tree wait has the PID-reuse guard (-Preexisting)' (-not ($r.events -contains 'waittree:no-preexisting')) ($r.events -join ' | ')
    Check 'run-app engine: five engine calls recorded' ((@($r.run.engine.calls) | ForEach-Object { $_.step }) -join ',' -eq 'inventory-1,harvest,uninstall,inventory-2,scan') ((@($r.run.engine.calls) | ForEach-Object { $_.step }) -join ',')

    # Engine mode, harvest fails: recorded, the captures still run, uninstall runs without --fp.
    $r = Invoke-FakeRunApp 'harvest-fails' 'npp' 'r0-npp' -EngineMode -Fail 'harvest'
    Check 'run-app engine, harvest fails: exit 1, harvest and scan failed, every phase ran' ($r.code -eq 1 -and ($r.failed -join ',') -eq 'engine-harvest,engine-scan' -and ($r.phases -join ' ') -eq $EnginePhases) "exit $($r.code); failed: $($r.failed -join ',')"
    Check 'run-app engine, harvest fails: captures after it still ran' ((Steps $r) -match 'engine:harvest engine:uninstall lists:2 engine:inventory snap:2$' -and (Test-Path (Join-Path $r.dir 'snap-r0-npp-2.tsv.gz')) -and (Test-Path (Join-Path $r.dir 'inv-2.json'))) (Steps $r)
    Check 'run-app engine, harvest fails: exit code recorded, uninstall without --fp' ((@($r.run.engine.calls) | Where-Object { $_.step -eq 'harvest' }).exit -eq 3 -and ($r.engine -match '^engine:uninstall ') -notmatch '--fp') ($r.engine -join ' | ')

    # Engine mode, uninstall fails: the phase fails, rig times are used, captures and the scan still run.
    $r = Invoke-FakeRunApp 'uninstall-fails' 'npp' 'r0-npp' -EngineMode -Fail 'uninstall'
    Check 'run-app engine, uninstall fails: only uninstall failed, scan still ran' ($r.code -eq 1 -and ($r.failed -join ',') -eq 'uninstall' -and (Steps $r) -match 'lists:2 engine:inventory snap:2 engine:scan$') "failed: $($r.failed -join ','); $(Steps $r)"
    Check 'run-app engine, uninstall fails: rig times, engine exit 3, entry not gone' ($r.run.uninstall.times -eq 'rig' -and $r.run.uninstall.engine_exit -eq 3 -and $r.run.uninstall.entry_gone -eq $false -and $r.run.uninstall.t0)

    # Pre-apps: Thunderbird installed and settled before lists 0 / snap 0, and kept.
    $r = Invoke-FakeRunApp 'firefox-tb' 'firefox-tb' 'r0-firefox-tb' -EngineMode
    Check 'run-app firefox-tb: pre-thunderbird phase before arp0' ($r.code -eq 0 -and ($r.phases -join ' ') -eq $EnginePhases.Replace('setup ', 'setup pre-thunderbird ')) "exit $($r.code); $($r.phases -join ' ')`n$($r.out)"
    Check 'run-app firefox-tb: thunderbird installer before snap 0, firefox after' ((Steps $r) -match '^start:thunderbird\.exe lists:0 snap:0 start:firefox\.exe ') (Steps $r)
    Check 'run-app firefox-tb: pre entry recorded, not counted as created, main is firefox' (@($r.run.pre)[0].id -eq 'thunderbird' -and @($r.run.pre)[0].entry.key -match 'Fake-thunderbird$' -and @($r.run.entries_created).Count -eq 1 -and $r.run.main.key -match 'Fake-firefox$' -and $r.run.engine.program_id -eq 'HKLM|64|Fake-firefox') "created: $(@($r.run.entries_created | ForEach-Object { $_.key }) -join ',')"

    # vscode-user: the installer goes through the medium-integrity task, which is deleted again.
    $r = Invoke-FakeRunApp 'vscode-user' 'vscode-user'
    Check 'run-app vscode-user: installer through PurgeRigInstall, task deleted, ran_as medium' ($r.code -eq 0 -and ($r.events -contains 'medium:PurgeRigInstall:vscode-user.exe') -and ($r.events -contains 'unregister:PurgeRigInstall') -and -not ($r.events -match '^start:vscode-user\.exe') -and $r.run.install.ran_as -eq 'medium' -and $r.run.install.task -eq 'PurgeRigInstall' -and -not ($r.events -contains 'waittree:no-preexisting')) "exit $($r.code); $($r.events -join ' | ')"

    # x0 (RIG.md §4b): plants before snap 0 and after the launch, live scan and repeat scan.
    $r = Invoke-FakeRunApp 'x0-npp-userfiles' 'npp-userfiles' 'x0t-npp-userfiles' -EngineMode -Extra
    $x0Phases = 'edge-pause setup plant-pre arp0 lists0 snap0 install detect launch plant-post lists1 engine-inventory-1 snap1 engine-harvest engine-scan-live uninstall lists2 engine-inventory-2 snap2 edge-check entries engine-scan engine-scan-repeat'
    Check 'run-app x0 npp-userfiles: exit 0, plant and extra-check phases in order' ($r.code -eq 0 -and ($r.phases -join ' ') -eq $x0Phases) "exit $($r.code); $($r.phases -join ' ')`n$($r.out)"
    $ev = @($r.events | Where-Object { $_ -match '^(lists:|snap:|plant:|medium:)' }) -join ' '
    Check 'run-app x0 npp-userfiles: plant-pre before lists 0, plant-post after the launch and before lists 1' ($ev -eq 'plant:plant-pre:Plant-NppPortable lists:0 snap:0 medium:PurgeRigLaunch:app.exe plant:plant-post:Plant-NppUserFiles lists:1 snap:1 lists:2 snap:2') $ev
    Check 'run-app x0 npp-userfiles: planted[] in run.json with the phase of each item' ((@($r.run.planted) | ForEach-Object { "$($_.phase)=$($_.target)" }) -join ',' -eq 'plant-pre=P:C:\fake\Plant-NppPortable.txt,plant-post=P:C:\fake\Plant-NppUserFiles.txt') ((@($r.run.planted) | ForEach-Object { "$($_.phase)=$($_.target)" }) -join ',')
    Check 'run-app x0 npp-userfiles: live scan (--mode external, plan-live.json) after the harvest, before the uninstall' (
        ($r.engine -contains ('engine:scan --fp ' + (Join-Path $r.dir 'fp.json') + ' --mode external --app npp-userfiles -o ' + (Join-Path $r.dir 'plan-live.json'))) -and
        ((Steps $r) -match 'engine:harvest engine:scan engine:uninstall')) ($r.engine -join ' | ')
    $x = $r.run.extra
    Check 'run-app x0 npp-userfiles: extra record (live counts, root band, det_equal by plan hash)' ($x.live_items -eq 1 -and $x.live_safe -eq 0 -and $x.live_preselected -eq 0 -and (@($x.live_root_band) -join ',') -eq 'Likely' -and $x.det_equal -eq $true -and $x.det_how -eq 'plan_hash' -and $x.plan_a -eq 'abc123') ($x | ConvertTo-Json -Compress)
    Check 'run-app x0 npp-userfiles: repeat scan writes plan-purge-b.json' ((Test-Path (Join-Path $r.dir 'plan-purge-b.json')) -and ((@($r.run.engine.calls) | ForEach-Object { $_.step }) -join ',') -eq 'inventory-1,harvest,scan-live,uninstall,inventory-2,scan,scan-repeat') ((@($r.run.engine.calls) | ForEach-Object { $_.step }) -join ',')

    # pre_launch + pre_uninstall: Firefox installed, launched and removed before snap 0, then installed again.
    $r = Invoke-FakeRunApp 'x0-ff-reinstall' 'ff-reinstall' 'x0t-ff-reinstall' -EngineMode
    Check 'run-app x0 ff-reinstall: pre-app installed, launched, vendor-removed before arp0' ($r.code -eq 0 -and ($r.phases -join ' ') -eq $EnginePhases.Replace('setup ', 'setup pre-firefox pre-launch-firefox pre-uninstall-firefox ')) "exit $($r.code); $($r.phases -join ' ')`n$($r.out)"
    Check 'run-app x0 ff-reinstall: install, launch, uninst-firefox, then lists 0, then the second install' ((Steps $r) -match '^start:firefox\.exe medium:PurgeRigLaunch:app\.exe start:uninst-firefox\.exe lists:0 snap:0 start:firefox\.exe ') (Steps $r)
    Check 'run-app x0 ff-reinstall: pre record has launch and uninstall, main is the new firefox entry' (@($r.run.pre)[0].launch.done -eq $true -and @($r.run.pre)[0].uninstall.entry_gone -eq $true -and $r.run.main.key -match 'Fake-firefox$' -and @($r.run.entries_created).Count -eq 1) ($r.run.pre | ConvertTo-Json -Depth 4 -Compress)

    # post: Thunderbird installed and launched after Firefox's launch, before lists 1.
    $r = Invoke-FakeRunApp 'x0-ff-tbafter' 'ff-tbafter' 'x0t-ff-tbafter' -EngineMode
    Check 'run-app x0 ff-tbafter: post-thunderbird after the launch, before lists1' ($r.code -eq 0 -and ($r.phases -join ' ') -eq $EnginePhases.Replace('launch lists1', 'launch post-thunderbird lists1')) "exit $($r.code); $($r.phases -join ' ')`n$($r.out)"
    Check 'run-app x0 ff-tbafter: firefox launch, thunderbird install + launch, then lists 1' ((Steps $r) -match 'start:firefox\.exe medium:PurgeRigLaunch:app\.exe start:thunderbird\.exe medium:PurgeRigLaunch:app\.exe lists:1 ') (Steps $r)
    Check 'run-app x0 ff-tbafter: post entry recorded, not in entries_created, main is firefox' (@($r.run.post)[0].entry.key -match 'Fake-thunderbird$' -and @($r.run.post)[0].launch.done -eq $true -and @($r.run.entries_created).Count -eq 1 -and $r.run.main.key -match 'Fake-firefox$') "created: $(@($r.run.entries_created | ForEach-Object { $_.key }) -join ',')"

    # Install arguments: environment variables expanded (git-toolsdir installs into %USERPROFILE%\Tools).
    $r = Invoke-FakeRunApp 'x0-git-toolsdir' 'git-toolsdir'
    $want = 'start:git.exe /VERYSILENT /NORESTART /SUPPRESSMSGBOXES /DIR="' + [Environment]::ExpandEnvironmentVariables('%USERPROFILE%') + '\Tools"'
    Check 'run-app x0 git-toolsdir: %USERPROFILE% expanded in the install arguments, plant-pre before lists 0' ($r.code -eq 0 -and ($r.events -contains $want) -and (@($r.events | Where-Object { $_ -match '^(plant:|lists:0)' }) -join ' ') -eq 'plant:plant-pre:Plant-GitToolsDir lists:0') "exit $($r.code); $($r.events -join ' | ')"
}

# ---------------------------------------- rig.ps1: run names, engine push, plans, frozen dirs kept
& {
    . (Join-Path $Vm 'rig.ps1')
    $ErrorActionPreference = 'Stop'
    $H = Join-Path $Work 'host'
    $script:RunsDir = Join-Path $H 'runs'
    $script:FrozenDir = Join-Path $H 'frozen'
    New-Item -ItemType Directory -Force (Join-Path $script:FrozenDir 'npp\plans') | Out-Null
    [IO.File]::WriteAllText((Join-Path $script:FrozenDir 'npp\plans\bcu.json'), 'FROZEN bcu')

    Check 'Get-RunName: prefix + id' ((Get-RunName -Id 'npp' -RunPrefix 'r0-' -Engine) -eq 'r0-npp')
    Check 'Get-RunName: no prefix, no engine -> the id (M0)' ((Get-RunName -Id 'npp') -eq 'npp')
    $msg = $null; try { $null = Get-RunName -Id 'npp' -Engine } catch { $msg = $_.Exception.Message }
    Check 'Get-RunName: engine without a prefix throws' ($msg -match 'need -RunPrefix') "got '$msg'"
    $msg = $null; try { $null = Get-RunName -Id 'npp' -RunPrefix 'R0-' } catch { $msg = $_.Exception.Message }
    Check 'Get-RunName: an uppercase prefix throws' ($msg -match 'bad run name') "got '$msg'"

    # Get-EnginePush and Push-Tools
    $repo = Join-Path $H 'repo'
    New-Item -ItemType Directory -Force (Join-Path $repo 'kb\baselines'), (Join-Path $repo 'target\release') | Out-Null
    $ep = Get-EnginePush -RepoRoot $repo
    Check 'Get-EnginePush: nothing built -> no engine' ($null -eq $ep.engine -and $ep.baselines.Count -eq 0)
    $msg = $null; try { $null = Get-EnginePush -Engine (Join-Path $repo 'nope\purge-engine.exe') -RepoRoot $repo } catch { $msg = $_.Exception.Message }
    Check 'Get-EnginePush: a missing -Engine throws' ($msg -match 'purge-engine not found') "got '$msg'"
    $eng = Join-Path $repo 'target\release\purge-engine.exe'
    [IO.File]::WriteAllText($eng, 'MZ fake')
    foreach ($b in 'EnterpriseS-26100.1742.tsv.gz', 'Professional-26340.9882.tsv.gz') { [IO.File]::WriteAllText((Join-Path $repo "kb\baselines\$b"), 'x') }
    $ep = Get-EnginePush -RepoRoot $repo
    Check 'Get-EnginePush: default engine + baselines' ($ep.engine -eq $eng -and $ep.baselines.Count -eq 2) "engine=$($ep.engine) baselines=$($ep.baselines.Count)"

    $script:RepoRoot = $repo
    $script:GuestCalls = New-Object System.Collections.ArrayList
    function Invoke-Guest([string[]]$Sub) { [void]$script:GuestCalls.Add($Sub -join ' '); [pscustomobject]@{ code = 0; out = @() } }
    function Invoke-GuestCmd([string]$CommandLine, [int]$TimeoutSec = 120) { [void]$script:GuestCalls.Add("cmd $CommandLine"); [pscustomobject]@{ code = 0; out = @() } }
    $rt = Join-Path $H 'rigtool.exe'; [IO.File]::WriteAllText($rt, 'MZ')
    Push-Tools -RigTool $rt
    $gc = $script:GuestCalls -join "`n"
    Check 'Push-Tools: engine to C:\cr\bin, baselines to C:\cr\bin\kb\baselines, both verified' (
        $gc.Contains("copyto --target-directory C:\cr\bin\ $eng") -and
        $gc.Contains("copyto --target-directory C:\cr\bin\kb\baselines\ $(Join-Path $repo 'kb\baselines\EnterpriseS-26100.1742.tsv.gz')") -and
        $gc.Contains('stat C:\cr\bin\purge-engine.exe') -and $gc.Contains('stat C:\cr\bin\kb\baselines\Professional-26340.9882.tsv.gz') -and
        $gc.Contains('del /f /q C:\cr\guest\*.ps1 C:\cr\bin\rigtool.exe C:\cr\bin\purge-engine.exe')) $gc
    Remove-Item -LiteralPath $eng
    $script:GuestCalls.Clear()
    Push-Tools -RigTool $rt
    $gc = $script:GuestCalls -join "`n"
    Check 'Push-Tools without a built engine: no engine copy (M0)' (-not ($gc -match 'copyto[^\n]*purge-engine') -and -not ($gc -match 'copyto[^\n]*baselines') -and -not $gc.Contains('stat C:\cr\bin\purge-engine.exe') -and $gc.Contains('copyto --target-directory C:\cr\bin\ ' + $rt)) $gc
    $msg = $null; try { Push-Tools -RigTool $rt -Engine (Join-Path $H 'missing.exe') } catch { $msg = $_.Exception.Message }
    Check 'Push-Tools -Engine <missing> throws' ($msg -match 'purge-engine not found') "got '$msg'"
    [IO.File]::WriteAllText($eng, 'MZ fake')
    $script:GuestCalls.Clear()
    Push-Tools -RigTool $rt -NoBaselines
    $gc = $script:GuestCalls -join "`n"
    Check 'Push-Tools -NoBaselines: engine pushed, old baselines deleted, none copied' ($gc.Contains("copyto --target-directory C:\cr\bin\ $eng") -and $gc.Contains('C:\cr\bin\kb\baselines\*.tsv.gz') -and -not ($gc -match 'copyto[^\n]*baselines')) $gc
    # Host installer cache: Get-CachedRunFiles picks the run's files the cache holds; Push-Tools sends them + manifest.
    $cache = Join-Path $H 'cache'; New-Item -ItemType Directory -Force $cache | Out-Null
    foreach ($n in 'cache-sources.json', 'npp-portable.zip', 'thunderbird.exe') { [IO.File]::WriteAllText((Join-Path $cache $n), 'x') }
    $cf = @(Get-CachedRunFiles -Id 'npp-userfiles' -CacheDir $cache | ForEach-Object { Split-Path -Leaf $_ })
    Check 'Get-CachedRunFiles npp-userfiles: the portable zip (npp.exe is not cached)' (($cf -join ',') -eq 'npp-portable.zip') ($cf -join ',')
    $cf = @(Get-CachedRunFiles -Id 'ff-tbafter' -CacheDir $cache | ForEach-Object { Split-Path -Leaf $_ })
    Check 'Get-CachedRunFiles ff-tbafter: thunderbird.exe' (($cf -join ',') -eq 'thunderbird.exe') ($cf -join ',')
    Check 'Get-CachedRunFiles: no manifest -> nothing' (@(Get-CachedRunFiles -Id 'ff-tbafter' -CacheDir (Join-Path $H 'nocache')).Count -eq 0)
    $script:GuestCalls.Clear()
    Push-Tools -RigTool $rt -Installers @((Join-Path $cache 'thunderbird.exe'))
    $gc = $script:GuestCalls -join "`n"
    Check 'Push-Tools -Installers: manifest and file to C:\cr\inst, both verified' ($gc -match 'copyto --target-directory C:\\cr\\inst\\ [^\n]*cache-sources\.json [^\n]*thunderbird\.exe' -and $gc.Contains('stat C:\cr\inst\thunderbird.exe') -and $gc.Contains('stat C:\cr\inst\cache-sources.json')) $gc
    Remove-Item -LiteralPath $eng

    # Invoke-Run / Invoke-Campaign in engine mode with the guest faked
    $script:GuestFiles = [ordered]@{}
    $script:LastJob = $null
    function Invoke-GuestCmd([string]$CommandLine, [int]$TimeoutSec = 120) { [pscustomobject]@{ code = 0; out = @($script:GuestFiles.Keys) } }
    function Invoke-Guest([string[]]$Sub) {
        if ($Sub[0] -eq 'copyfrom') { [IO.File]::WriteAllText($Sub[2], [string]$script:GuestFiles[(Split-Path -Leaf $Sub[1])]); return [pscustomobject]@{ code = 0; out = @() } }
        throw "unexpected guest call: $($Sub -join ' ')"
    }
    function Invoke-GuestJob { param($Text, $Name, $TimeoutSec, $LogCopy) $script:LastJob = @{ text = $Text; name = $Name }; [IO.File]::WriteAllText($LogCopy, 'job log'); [pscustomobject]@{ name = $Name; done = $true; seconds = 1; log = ''; log_file = $LogCopy } }
    function Restore-Base { param($Snapshot, $AgentTimeoutSec) }
    $script:PushArgs = $null
    function Push-Tools { param([string]$RigTool = '', [string]$Engine = '', [switch]$NoBaselines, [string[]]$Installers = @()) $script:PushArgs = $Engine; $script:PushNoBl = [bool]$NoBaselines }
    function Get-PwFile { 'C:\nonexistent\pw.txt' }

    $frozenRun = Join-Path $script:RunsDir 'npp'
    New-Item -ItemType Directory -Force (Join-Path $frozenRun 'plans') | Out-Null
    foreach ($n in 'snap-npp-0.tsv.gz', 'truth.json', 'run.json', 'plans\bcu.json') { [IO.File]::WriteAllText((Join-Path $frozenRun $n), 'FROZEN') }
    # The frozen directory keeps its 4 files and was never archived (r0-npp itself may be).
    function FrozenIntact {
        (@(Get-ChildItem -LiteralPath $frozenRun -File -Recurse | Where-Object { (Get-Content -Raw -LiteralPath $_.FullName) -eq 'FROZEN' }).Count -eq 4) -and
        @(Get-ChildItem -LiteralPath (Join-Path $script:RunsDir '_old') -Directory -Filter 'npp-*' -ErrorAction SilentlyContinue).Count -eq 0
    }

    $script:GuestFiles = [ordered]@{ 'run.log' = 'NEW'; 'run.json' = (New-RunJson 'r0-npp' (Get-Date)); 'snap-r0-npp-0.tsv.gz' = 'NEW'; 'plan-purge.json' = '{"schema":"purge.plan/0","tool":"purge"}' }
    $res = Invoke-Run -Id npp -RunPrefix 'r0-' -Engine
    $rd = Join-Path $script:RunsDir 'r0-npp'
    Check 'Invoke-Run -Engine: job text for run r0-npp in engine mode' ($res.run -eq 'r0-npp' -and $script:LastJob.name -eq 'r0-npp' -and $script:LastJob.text.Contains("`$Run = 'r0-npp'") -and $script:LastJob.text.Contains("`$EngineFlag = '1'"))
    Check 'Invoke-Run -Engine: plan copied to plans\purge.json, frozen BCU plan next to it' ((Get-Content -Raw (Join-Path $rd 'plans\purge.json')) -match 'purge.plan/0' -and (Get-Content -Raw (Join-Path $rd 'plans\bcu.json')) -eq 'FROZEN bcu' -and (Test-Path (Join-Path $rd 'plan-purge.json')))
    Check 'Invoke-Run -Engine: frozen vm\runs\npp untouched' (FrozenIntact)
    $msg = $null; try { $null = Invoke-Run -Id npp -Engine } catch { $msg = $_.Exception.Message }
    Check 'Invoke-Run -Engine without -RunPrefix refuses, frozen dir untouched' ($msg -match 'need -RunPrefix' -and (FrozenIntact)) "got '$msg'"
    $script:GuestFiles = [ordered]@{ 'run.log' = 'NEW'; 'run.json' = (New-RunJson 'r0-firefox-tb' (Get-Date)); 'plan-purge.json' = '{}' }
    $null = Invoke-Run -Id firefox-tb -RunPrefix 'r0-' -Engine
    Check 'Invoke-Run -Engine firefox-tb: purge plan only (no frozen BCU plan)' ((@(Get-ChildItem (Join-Path $script:RunsDir 'r0-firefox-tb\plans') | ForEach-Object { $_.Name }) -join ',') -eq 'purge.json')

    $fakeEngine = Join-Path $H 'purge-engine.exe'; [IO.File]::WriteAllText($fakeEngine, 'MZ')
    $script:GuestFiles = [ordered]@{ 'run.log' = 'NEW'; 'run.json' = (New-RunJson 'r0-npp' (Get-Date)); 'plan-purge.json' = '{}' }
    $rec = @(Invoke-Campaign -Ids npp -Nulls 0 -RunPrefix 'r0-' -Engine $fakeEngine)[0]
    Check 'Invoke-Campaign -RunPrefix r0- -Engine: run r0-npp ok, engine pushed, frozen dir untouched' ($rec.ok -and $rec.run -eq 'r0-npp' -and $rec.id -eq 'npp' -and $rec.engine -and $script:PushArgs -eq $fakeEngine -and (FrozenIntact)) "ok=$($rec.ok) run=$($rec.run) error=$($rec.error) push=$($script:PushArgs)"
    $script:GuestFiles = [ordered]@{ 'run.log' = 'NEW'; 'run.json' = (New-RunJson 'x0-npp' (Get-Date)); 'plan-purge.json' = '{}'; 'plan-live.json' = '{}'; 'plan-purge-b.json' = '{}' }
    $rec = @(Invoke-Campaign -Ids npp -Nulls 0 -RunPrefix 'x0-' -Engine $fakeEngine -ExtraChecks -NoBaselines)[0]
    $xd = Join-Path $script:RunsDir 'x0-npp'
    Check 'Invoke-Campaign -ExtraChecks -NoBaselines: __EXTRA__ = 1, no baselines pushed, extra plans stay out of plans\' (
        $rec.ok -and $script:LastJob.text.Contains("`$ExtraFlag = '1'") -and $script:PushNoBl -and (Test-Path (Join-Path $xd 'plan-live.json')) -and
        ((@(Get-ChildItem (Join-Path $xd 'plans') | ForEach-Object { $_.Name }) -join ',') -eq 'bcu.json,purge.json')) "ok=$($rec.ok) error=$($rec.error) nobl=$($script:PushNoBl)"
    $msg = $null; try { $null = Invoke-Campaign -Ids npp -Nulls 0 -RunPrefix 'x0-' -ExtraChecks } catch { $msg = $_.Exception.Message }
    Check 'Invoke-Campaign -ExtraChecks without -Engine refuses' ($msg -match 'needs -Engine') "got '$msg'"
    $msg = $null; try { $null = Invoke-Campaign -Ids npp -Nulls 0 -Engine $fakeEngine } catch { $msg = $_.Exception.Message }
    Check 'Invoke-Campaign -Engine without -RunPrefix refuses before touching anything' ($msg -match 'need -RunPrefix' -and (FrozenIntact)) "got '$msg'"
    $msg = $null; try { $null = Invoke-Campaign -Ids npp -Nulls 0 -RunPrefix 'r0-' -Engine (Join-Path $H 'missing.exe') } catch { $msg = $_.Exception.Message }
    Check 'Invoke-Campaign -Engine <missing> refuses' ($msg -match 'purge-engine not found') "got '$msg'"
    $script:GuestFiles = [ordered]@{ 'run.log' = 'NEW'; 'run.json' = (New-RunJson 'npp' (Get-Date)) }
    $script:PushArgs = 'unset'
    $rec = @(Invoke-Campaign -Ids npp -Nulls 0)[0]
    Check 'Invoke-Campaign without -Engine: M0 run name, no plans copied, empty -Engine to Push-Tools' ($rec.ok -and $rec.run -eq 'npp' -and -not $rec.engine -and $script:PushArgs -eq '' -and -not (Test-Path (Join-Path $script:RunsDir 'npp\plans\purge.json'))) "ok=$($rec.ok) error=$($rec.error) push='$($script:PushArgs)'"
}

# ============================================================================== M2 executor runs (RIG.md §11)

# ------------------------------------------------- m2-traps / m2-fixtures dry runs (no system change)
& {
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    foreach ($n in 'm2-traps', 'm2-fixtures') {
        $od = Join-Path $Work "dry-$n"
        $out = & $exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Guest "$n.ps1") -DryRun -OutDir $od 2>&1
        $code = $LASTEXITCODE
        $files = @(Get-ChildItem -LiteralPath $od -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Sort-Object)
        $want = @("$n-manifest.json", "$n-paths.txt", "$n-select.json", "$n-targets.json")
        Check "$n.ps1 -DryRun: exit 0, manifest + targets + select + paths" ($code -eq 0 -and ($files -join ',') -eq ($want -join ',')) "exit $code; files $($files -join ','); $($out -join ' ')"
        $t = $null; try { $t = [IO.File]::ReadAllText((Join-Path $od "$n-targets.json")) | ConvertFrom-Json } catch { }
        Check "$n.ps1 -DryRun: targets are purge.rig.targets/0 with ids and groups" ($t -and $t.schema -eq 'purge.rig.targets/0' -and @($t.targets).Count -gt 0 -and -not @(@($t.targets) | Where-Object { -not $_.id -or -not $_.group }).Count) "$($t.schema) $(@($t.targets).Count)"
    }
    $a = ([IO.File]::ReadAllText((Join-Path $Work 'dry-m2-traps\m2-traps-manifest.json')) | ConvertFrom-Json | ConvertTo-Json -Depth 60 -Compress)
    $b = ([IO.File]::ReadAllText((Join-Path $Vm 'truth\m2-traps.json')) | ConvertFrom-Json | ConvertTo-Json -Depth 60 -Compress)
    Check 'm2-traps.ps1 -DryRun manifest equals vm\truth\m2-traps.json' ($a -eq $b) "lengths $($a.Length) / $($b.Length)"
}

# ----------------------------------------------------------------- riglib: M2 pure helpers
& {
    . (Join-Path $Guest 'riglib.ps1')
    $ErrorActionPreference = 'Stop'
    function Sha([string]$s) { $h = [Security.Cryptography.SHA256]::Create(); try { -join @($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($s)) | ForEach-Object { $_.ToString('x2') }) } finally { $h.Dispose() } }
    $sel = Sha "a.x`nb.y`nc"
    Check 'Get-M2SelectionHash: de-duplicated, ordinal sort, LF joined' ((Get-M2SelectionHash @('c', 'b.y', 'a.x', 'c')) -eq $sel) (Get-M2SelectionHash @('c', 'b.y', 'a.x', 'c'))
    Check 'Get-M2Confirm: SHA-256(lower(plan_hash) || selection_hash)' ((Get-M2Confirm 'ABC123' @('c', 'a.x', 'b.y')) -eq (Sha ('abc123' + $sel)))
    Check 'Get-M2SelectionHash: the empty selection hashes the empty string' ((Get-M2SelectionHash @()) -eq (Sha ''))
    $m = $null; try { $null = Get-M2Confirm 'not-hex' @('a') } catch { $m = $_.Exception.Message }
    Check 'Get-M2Confirm: a non-hex plan hash throws' ($m -match 'bad plan hash') $m
    $e = New-M2ExecArgs 'C:\cr\out\r\plan-main.json' 'ff00' 'C:\cr\out\r\select-main.json' 'C:\cr\out\r\report-main.json' -RestorePoint always
    Check 'New-M2ExecArgs: exec --plan --confirm --select --restore-point -o' ($e -ceq 'exec --plan C:\cr\out\r\plan-main.json --confirm ff00 --select C:\cr\out\r\select-main.json --restore-point always -o C:\cr\out\r\report-main.json') $e
    $e = New-M2ExecArgs 'C:\a b\p.json' 'ff' -AllowIrreversible
    Check 'New-M2ExecArgs: quotes a path with a space; --allow-irreversible' ($e -ceq 'exec --plan "C:\a b\p.json" --confirm ff --allow-irreversible') $e
    $m = $null; try { $null = New-M2ExecArgs 'p' 'c' -RestorePoint sometimes } catch { $m = $_.Exception.Message }
    Check 'New-M2ExecArgs: a bad --restore-point throws' ($m -match 'bad --restore-point') $m
    Check 'New-M2UndoArgs: --session --items -o' ((New-M2UndoArgs 's1' 'C:\i.json' '' 'C:\u.json') -ceq 'undo --session s1 --items C:\i.json -o C:\u.json')
    Check 'New-M2PlanArgs: plan from-targets <t> -o <p>' ((New-M2PlanArgs 'C:\t.json' 'C:\p.json') -ceq 'plan from-targets C:\t.json -o C:\p.json')
    Check 'New-M2JournalArgs: recover / rollback --session / fault-points' ((New-M2JournalArgs 'recover') -ceq 'journal recover' -and (New-M2JournalArgs 'rollback' 's9') -ceq 'journal rollback --session s9' -and (New-M2JournalArgs 'fault-points') -ceq 'journal fault-points')
    $m = $null; try { $null = New-M2JournalArgs 'show' } catch { $m = $_.Exception.Message }
    Check 'New-M2JournalArgs: show without a session throws' ($m -match 'needs a session') $m
    Check 'New-M2QuarantineArgs: purge --ids a b --yes-irreversible' ((New-M2QuarantineArgs 'purge' @('a', 'b')) -ceq 'quarantine purge --ids a b --yes-irreversible' -and (New-M2QuarantineArgs 'expiring') -ceq 'quarantine expiring')
    $fp = @(ConvertFrom-M2FaultPoints "journal.header  before`r`nact.after`r`n  undo.act.after: x`r`nnot a point`r`nact.after")
    Check 'ConvertFrom-M2FaultPoints: text lines, unique, dotted names only' (($fp -join ',') -eq 'journal.header,act.after,undo.act.after') ($fp -join ',')
    $fp = @(ConvertFrom-M2FaultPoints "journal.header`tbefore the header record`nregdelete.mid`thalf way through a key delete`n")
    Check 'ConvertFrom-M2FaultPoints: the engine format, <name> TAB <description>' (($fp -join ',') -eq 'journal.header,regdelete.mid') ($fp -join ',')
    $fp = @(ConvertFrom-M2FaultPoints '{"points":[{"name":"intent.flushed"},"regdelete.mid"]}')
    Check 'ConvertFrom-M2FaultPoints: JSON {points: [obj|string]}' (($fp -join ',') -eq 'intent.flushed,regdelete.mid') ($fp -join ',')
    $ids = @(Find-M2ExpiryIds '{"entries":[{"id":"q7","original":"C:\\Program Files\\X\\payload"},{"id":"q8","original":"C:\\Y"}]}' 'C:\Program Files\X\payload')
    Check 'Find-M2ExpiryIds: the entry naming the path (JSON-escaped)' (($ids -join ',') -eq 'q7') ($ids -join ',')
    $b = @('\??\C:\old.txt', '')
    $c = Compare-PfroLists $b @('\??\C:\old.txt', '', '\??\C:\Program Files\T\a.dll', '\??\C:\ProgramData\Purge\Quarantine\x') @('C:\Program Files\T\a.dll') @('C:\U\b.dll')
    Check 'Compare-PfroLists: pre-existing pair kept, expected source added once -> ok' ($c.ok -and $c.preexisting_identical -and @($c.added).Count -eq 1 -and $c.added[0].dst -eq 'C:\ProgramData\Purge\Quarantine\x')
    $c = Compare-PfroLists $b @('\??\C:\U\b.dll', '') @('C:\Program Files\T\a.dll') @('C:\U\b.dll')
    Check 'Compare-PfroLists: pre-existing pair lost, forbidden source, expected missing -> not ok' (-not $c.ok -and -not $c.preexisting_identical)
    $c = Compare-PfroLists @() @('*1\??\C:\U\b.dll', '') @() @('C:\U\b.dll')
    Check 'Compare-PfroLists: a forbidden (user-writable) source is reported' (-not $c.ok -and @($c.forbidden).Count -eq 1 -and @($c.unexpected).Count -eq 1)
    $c = Compare-PfroLists @() @('\??\C:\A', '', '\??\C:\A', '') @('C:\A')
    Check 'Compare-PfroLists: the same source registered twice is a duplicate' (-not $c.ok -and @($c.duplicates).Count -eq 1)
    $o = ConvertFrom-M2Opts ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"batch":3,"points":["a.b"]}')))
    Check 'ConvertFrom-M2Opts / Get-M2Opt: base64 JSON, defaults' ((Get-M2Opt $o 'batch' 0) -eq 3 -and (Get-M2Opt $o 'nope' 'd') -eq 'd' -and @((ConvertFrom-M2Opts ('__' + 'OPTS__')).PSObject.Properties).Count -eq 0)
    Check 'Invoke-M2Engine / Invoke-Engine: fault abort code is 0xC0000409' ($RigFaultAbortExit -eq [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]3221226505), 0))
}

# --------------------------------------------------- rig.ps1: M2 names, engine separation, job text
& {
    . (Join-Path $Vm 'rig.ps1')
    $ErrorActionPreference = 'Stop'
    $repo = Join-Path $Work 'm2repo'
    New-Item -ItemType Directory -Force (Join-Path $repo 'target\rig-exec\release'), (Join-Path $repo 'target\release') | Out-Null
    $rx = Join-Path $repo 'target\rig-exec\release\purge-engine.exe'; [IO.File]::WriteAllText($rx, 'MZ rig-exec')
    $rel = Join-Path $repo 'target\release\purge-engine.exe'; [IO.File]::WriteAllText($rel, 'MZ release')
    Check 'Get-M2RunName: <prefix><mode>' ((Get-M2RunName -Mode 'm2-traps') -eq 'm2-traps' -and (Get-M2RunName -Mode 'm2-crash' -RunPrefix 'g3-') -eq 'g3-m2-crash')
    $m = $null; try { $null = Get-M2RunName -Mode 'm2-traps' -RunPrefix 'G1-' } catch { $m = $_.Exception.Message }
    Check 'Get-M2RunName: an uppercase prefix throws' ($m -match 'bad run name') $m
    Check 'Get-M2Engine: default target\rig-exec\release\purge-engine.exe' ((Get-M2Engine -RepoRoot $repo) -eq $rx)
    $m = $null; try { $null = Get-M2Engine -Engine $rel -RepoRoot $repo } catch { $m = $_.Exception.Message }
    Check 'Get-M2Engine: the release engine target\release\purge-engine.exe is refused' ($m -match 'refusing the release engine') $m
    $m = $null; try { $null = Get-M2Engine -Engine (Join-Path $repo 'target\release\..\release\purge-engine.exe') -RepoRoot $repo } catch { $m = $_.Exception.Message }
    Check 'Get-M2Engine: the release engine through a relative path is refused too' ($m -match 'refusing the release engine') $m
    $m = $null; try { $null = Get-M2Engine -Engine (Join-Path $repo 'nope.exe') -RepoRoot $repo } catch { $m = $_.Exception.Message }
    Check 'Get-M2Engine: a missing engine throws' ($m -match 'not found') $m
    Check 'Release engine file untouched by the M2 checks' ((Get-Content -Raw $rel) -eq 'MZ release')
    $m = $null; try { Assert-RigVm 'Some-Other-VM' } catch { $m = $_.Exception.Message }
    Check 'Assert-RigVm: only the two rig VMs' ($m -match 'not a rig VM' -and $null -eq (Assert-RigVm 'Purge-CleanPro') -and $null -eq (Assert-RigVm 'Inbound-Win11-Test'))
    Check 'Get-M2Template: exec-run / m2-crash / m2-reboot' ((Get-M2Template 'm2-traps') -eq 'exec-run.ps1' -and (Get-M2Template 'm2-install') -eq 'exec-run.ps1' -and (Get-M2Template 'm2-crash') -eq 'm2-crash.ps1' -and (Get-M2Template 'm2-reboot') -eq 'm2-reboot.ps1')
    $mo = Get-M2ModeOpts -Mode 'm2-crash' -HardPowerOff -FaultPoints @('act.after')
    Check 'Get-M2ModeOpts m2-crash: batch 10 by default, hard_poweroff, points' ($mo.opts.batch -eq 10 -and $mo.opts.hard_poweroff -eq $true -and (@($mo.opts.points) -join ',') -eq 'act.after')
    foreach ($ms in @(@('m2-traps', 'app'), @('m2-crash', 'matrix'), @('m2-reboot', 'after-reboot'))) {
        $mode = $ms[0]; $stage = $ms[1]
        $t = New-M2JobText -Mode $mode -Run 'g-run' -Stage $stage -Opts ([ordered]@{ batch = 2 })
        $opts = [regex]::Match($t, "\`$OptsB64 = '([^']*)'").Groups[1].Value
        $dec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($opts)) | ConvertFrom-Json
        Check "New-M2JobText $mode`: run, mode, stage and base64 options replaced" ($t.Contains("`$Run = 'g-run'") -and $t.Contains("`$Mode = '$mode'") -and $t.Contains("`$Stage = '$stage'") -and $dec.batch -eq 2)
        $h = Test-HeadCheck $t
        Check "$(Get-M2Template $mode) head check passes a replaced job" ($h.code -eq 7) "exit $($h.code): $($h.out)"
        $raw = [IO.File]::ReadAllText((Join-Path $Guest (Get-M2Template $mode)))
        $h = Test-HeadCheck $raw
        Check "$(Get-M2Template $mode) unreplaced exits 2 before loading riglib" ($h.code -eq 2) "exit $($h.code): $($h.out)"
    }
    $m = $null; try { $null = New-M2JobText -Mode 'm2-traps' -Run 'Bad Run' } catch { $m = $_.Exception.Message }
    Check 'New-M2JobText: a bad run name throws' ($m -match 'bad run name') $m
}

# ------------------------------- M2 end to end: host loop + guest scripts with fakes and the stub engine
# Invoke-M2Mode runs as on the host; Invoke-GuestJob runs the generated job in a child powershell.exe with the
# guest paths pointing at a work dir, the stub engine, and fakes for rigtool, the locker, PFRO, the boot id and
# every system change. Continuations: Wait-GuestReboot / Invoke-HardPowerCycle advance a fake boot id.
$M2Fakes = @'
$RigOut = '@W@\out'; $RigTool = '@W@\rigtool.exe'; $RigEngine = '@W@\purge-engine.cmd'
$RigPurgeData = '@W@\pd'; $RigEngineInstalled = '@W@\absent\purge-engine.exe'; $RigInstallScript = '@W@\install.ps1'
$RigGuestDir = '@G@'; $RigWork = '@W@\work'; $RigDRoot = '@W@\dvol\'; $RigUserFpDir = '@W@\fp'
$script:FakeEv = '@W@\events.txt'
function Ev([string]$s) { [IO.File]::AppendAllText($script:FakeEv, $s + "`r`n") }
function Start-Sleep { }
function Suspend-EdgeUpdate { Ev 'edge-pause'; [ordered]@{ method = 'fake' } }
function Suspend-M2Telemetry { Ev 'telemetry-pause'; [ordered]@{ service = 'DiagTrack'; after = 'Stopped' } }
function LaunchMedium([string]$Exe, [string]$Arguments = '', [string]$WorkDir = '', [string]$TaskName = 'PurgeRigLaunch', [int]$StartTimeoutSec = 30) { Ev "medium:$Arguments"; [pscustomobject]@{ task = $TaskName; pid = 4000001; found = $true } }
function Stop-Launch($Launch, [int]$GraceSec = 5) { [pscustomobject]@{ closed = @(); killed = @() } }
function Start-Native([string]$Exe, [string]$Arguments = '', [string]$WorkDir = '') {
    Ev "start:$(Split-Path -Leaf $Exe) $Arguments"
    $p = [pscustomobject]@{ Id = 4000002; ExitCode = 0 }
    $p | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) $true }
    $p
}
function Remove-LaunchTask($Launch) { Ev "unlaunch:$($Launch.task)" }
function Set-M2RestoreFrequency([int]$Minutes) { Ev "srfreq:$Minutes"; $Minutes }
function Set-M2SystemProtection([bool]$On) { Ev "srprot:$On"; $On }
function Get-RigBootId { [IO.File]::ReadAllText('@W@\bootid.txt').Trim() }
function Invoke-RigShutdown([int]$DelaySec, [string]$Reason) { Ev "shutdown:$DelaySec" }
function Start-M2Locker([string[]]$Paths, [string]$WorkDir, [int]$TimeoutSec = 60) { Ev "lock:$($Paths -join ',')"; [pscustomobject]@{ pid = 4000003; paths = $Paths; ready = $true; stop_file = '@W@\stop' } }
function Stop-M2Locker($Locker, [int]$WaitSec = 10) { Ev 'unlock' }
function Get-PfroList { if (-not (Test-Path -LiteralPath '@W@\pfro.json')) { return $null }; $x = [IO.File]::ReadAllText('@W@\pfro.json') | ConvertFrom-Json; , @($x | ForEach-Object { "$_" }) }
function Set-PfroList([string[]]$Entries) { Ev "pfro-set:$(@($Entries).Count)"; [IO.File]::WriteAllText('@W@\pfro.json', (ConvertTo-Json -InputObject @($Entries))) }
function Set-M2RegString([string]$Canon, [string]$Name, [string]$Data) { Ev "regset:$Canon|$Name"; $true }
function Get-M2RestorePoints { @() }
function Invoke-RigTool([string]$Arguments, [int]$TimeoutSec = 3600) { Ev "rigtool:$(($Arguments -split ' ')[0])"; [pscustomobject]@{ exit = 0; stdout = '{"added":[],"removed":[],"changed":[]}'; stderr = '' } }
function Invoke-M2Snap([string]$Out, [string[]]$Roots = @()) { Ev "snap:$(Split-Path -Leaf $Out)"; [IO.File]::WriteAllText($Out, 'snap'); $Out }
function Invoke-M2Deep([string[]]$Scopes, [string]$Out) { Ev "deep:$(Split-Path -Leaf $Out)"; [IO.File]::WriteAllText($Out, '{"schema":"purge.rig.deep/1","files":[],"keys":[],"errors":0}'); $Out }
function Invoke-M2Execdiff {
    param([string]$Before, [string]$After, [string]$Journal, [string]$Report, [string[]]$Traps = @(), [string[]]$Groups = @(), [string]$DeepBefore = '', [string]$DeepAfter = '', [string]$Out)
    Ev "execdiff:$(Split-Path -Leaf $Out) groups=$($Groups -join ',') report=$(Split-Path -Leaf $Report)"
    [IO.File]::WriteAllText($Out, '{"schema":"purge.rig.execdiff/1","ok":true,"session":"stub","counts":{"guard_escapes":0,"collateral":0,"unexplained":0,"missing_effects":0,"changed_not_done":0,"trap_mismatches":0,"not_scored":0,"unverified_canaries":0,"unverified_effects":0,"inconsistencies":0,"diff_records":0,"authorised":{}},"traps":[{"id":"stub-trap","gate":"G1","verdict":"pass","canaries_intact":true,"guard_escapes":0}],"collateral":[],"unexplained":[],"warnings":[]}')
    [pscustomobject]@{ exit = 0; ok = $true; out = $Out }
}
function Invoke-M2Fidelity([string]$Before, [string]$After, [string]$Journal, [string]$Out) {
    Ev "fidelity:$(Split-Path -Leaf $Out)"
    [IO.File]::WriteAllText($Out, '{"schema":"purge.rig.fidelity/1","ok":true,"rows":[{"action":"QuarantineMove file","ops":1,"objects":1,"identical":1,"differing":0,"percent":100.0,"pass":true},{"action":"DeleteValue","ops":1,"objects":1,"identical":1,"differing":0,"percent":100.0,"pass":true},{"action":"DeleteService","ops":0,"objects":0,"identical":0,"differing":0,"percent":null,"pass":true,"note":"not executed in v1"}],"differences":[]}')
    [pscustomobject]@{ exit = 0; ok = $true; out = $Out }
}
function Invoke-M2Script([string]$Script, [string]$Arguments = '', [int]$TimeoutSec = 3600) {
    $leaf = Split-Path -Leaf $Script
    Ev "script:$leaf $Arguments"
    function Arg([string]$n) { $m = [regex]::Match($Arguments, "-$n\s+(?:`"([^`"]*)`"|(\S+))"); if ($m.Success) { $m.Groups[1].Value + $m.Groups[2].Value } else { '' } }
    $ok = [pscustomobject]@{ exit = 0; stdout = ''; stderr = ''; timed_out = $false }
    if ($leaf -eq 'install.ps1') {
        $rp = Arg 'ReportPath'
        if ($rp) { [IO.File]::WriteAllText($rp, $(if (Test-Path -LiteralPath '@W@\installed') { '{"schema":"purge.install/1","changed":false,"renamed_aside":[]}' } else { '{"schema":"purge.install/1","changed":true,"renamed_aside":[{"path":"C:\\ProgramData\\Purge","to":"C:\\ProgramData\\Purge.rejected-1"}]}' })); [IO.File]::WriteAllText('@W@\installed', 'x') }
        return $ok
    }
    $od = Arg 'OutDir'
    if ($Arguments -match '-Action\s+check') {
        $label = Arg 'Label'; $phase = Arg 'Phase'
        $name = $(if ($leaf -eq 'm2-traps.ps1') { $(if ($label) { "m2-traps-check-$label.json" } else { 'm2-traps-check.json' }) } else { "m2-fixtures-check-$phase.json" })
        [IO.File]::WriteAllText((Join-Path $od $name), '{"ok":true,"guard_escapes":0,"post_checks_failed":0,"traps":[]}')
        return $ok
    }
    if ($Arguments -match '-Action\s+(reset|swap|plant-[a-z-]+)') { return $ok }
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Invoke-Native -Exe $exe -Arguments ('-NoProfile -ExecutionPolicy Bypass -File "' + $Script + '" ' + $Arguments + ' -DryRun') -TimeoutSec 300
}
'@

& {
    . (Join-Path $Vm 'rig.ps1')
    $ErrorActionPreference = 'Stop'
    $W = Join-Path $Work 'm2'
    foreach ($d in 'out', 'pd', 'work', 'dvol', 'fp', 'host\runs', 'repo\target\rig-exec\release', 'repo\install') { New-Item -ItemType Directory -Force (Join-Path $W $d) | Out-Null }
    [IO.File]::WriteAllText((Join-Path $W 'fp\forged.json'), '{"schema":"purge.fp/0"}')
    [IO.File]::WriteAllText((Join-Path $W 'bootid.txt'), 'boot-1')
    [IO.File]::WriteAllText((Join-Path $W 'repo\target\rig-exec\release\purge-engine.exe'), 'MZ rig-exec')
    [IO.File]::WriteAllText((Join-Path $W 'repo\install\install.ps1'), '# fake')
    $sd = New-StubEngine $W 'Fake-npp'
    [IO.File]::WriteAllText((Join-Path $W 'm2fakes.ps1'), $M2Fakes.Replace('@W@', $W).Replace('@G@', $Guest), (New-Object System.Text.UTF8Encoding($true)))
    $script:RunsDir = Join-Path $W 'host\runs'
    $script:RepoRoot = Join-Path $W 'repo'
    $script:M2Jobs = New-Object System.Collections.ArrayList
    $script:M2Guest = New-Object System.Collections.ArrayList
    $script:Boot = 1

    function Get-PwFile { 'C:\nonexistent\pw.txt' }
    function Restore-Base { param($Snapshot, $AgentTimeoutSec) [void]$script:M2Guest.Add("restore $Snapshot") }
    function Push-Tools { param([string]$RigTool = '', [string]$Engine = '', [switch]$NoBaselines, [string[]]$Installers = @()) [void]$script:M2Guest.Add("push $Engine") }
    function Wait-Agent { param([int]$TimeoutSec = 300) }
    function Local([string]$GuestPath) { if ($GuestPath -like 'C:\cr\out\*') { Join-Path (Join-Path $W 'out') $GuestPath.Substring(10) } else { $null } }
    function Invoke-Guest([string[]]$Sub) {
        [void]$script:M2Guest.Add($Sub -join ' ')
        if ($Sub[0] -eq 'copyfrom') {
            $l = Local $Sub[1]
            if ($l -and (Test-Path -LiteralPath $l)) { Copy-Item -LiteralPath $l -Destination $Sub[2] -Force; return [pscustomobject]@{ code = 0; out = @() } }
            return [pscustomobject]@{ code = 1; out = @('no such file') }
        }
        [pscustomobject]@{ code = 0; out = @() }
    }
    function Invoke-GuestCmd([string]$CommandLine, [int]$TimeoutSec = 120) {
        [void]$script:M2Guest.Add("cmd $CommandLine")
        if ($CommandLine -match '^dir /b /a-d (C:\\cr\\out\\\S+)$') { return [pscustomobject]@{ code = 0; out = @(Get-ChildItem -LiteralPath (Local $Matches[1]) -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) } }
        [pscustomobject]@{ code = 0; out = @() }
    }
    function Wait-GuestReboot { param([string]$BootBefore = '', [int]$TimeoutSec = 900) $script:Boot++; [IO.File]::WriteAllText((Join-Path $W 'bootid.txt'), "boot-$($script:Boot)"); [void]$script:M2Guest.Add("reboot from $BootBefore"); "boot-$($script:Boot)" }
    function Invoke-HardPowerCycle { param([int]$AgentTimeoutSec = 600) $script:Boot++; [IO.File]::WriteAllText((Join-Path $W 'bootid.txt'), "boot-$($script:Boot)"); [void]$script:M2Guest.Add('hard power cycle') }
    function Invoke-GuestJob {
        param($Text, $Name, $TimeoutSec, $LogCopy)
        $t = $Text.Replace('. C:\cr\guest\riglib.ps1', ". '$Guest\riglib.ps1'`r`n. '$W\m2fakes.ps1'")
        $job = Join-Path $W ("job-{0:000}.ps1" -f ($script:M2Jobs.Count + 1))
        [IO.File]::WriteAllText($job, $t, (New-Object System.Text.UTF8Encoding($true)))
        $env:STUB_DIR = $sd.stub; $env:STUB_EV = Join-Path $W 'events.txt'; $env:STUB_DATA = Join-Path $W 'pd'; $env:STUB_FAIL = ''
        try { $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $job 2>&1; $code = $LASTEXITCODE }
        finally { Remove-Item Env:STUB_DIR, Env:STUB_EV, Env:STUB_DATA, Env:STUB_FAIL -ErrorAction SilentlyContinue }
        [IO.File]::WriteAllText($LogCopy, ($out -join "`r`n"))
        [void]$script:M2Jobs.Add([pscustomobject]@{ name = $Name; code = $code; out = ($out -join "`n") })
        [pscustomobject]@{ name = $Name; done = $true; seconds = 1; log = ($out -join "`n"); log_file = $LogCopy }
    }
    # The real-app runs of m2-fidelity: a finished run-app job (run.json + plan-purge.json with one Safe item).
    function Invoke-Run {
        param([string]$Id, [string]$RunPrefix = '', [switch]$Engine)
        $run = "$RunPrefix$Id"
        $g = Join-Path (Join-Path $W 'out') $run; New-Item -ItemType Directory -Force $g | Out-Null
        [IO.File]::WriteAllText((Join-Path $g 'plan-purge.json'), '{"schema":"purge.plan/0","app":"' + $Id + '","tool":"purge","mode":"post","items":[{"target":{"type":"Path","path":"C:\\fake\\left"},"band":"Safe","preselected":true,"scanner":"FS-INSTALLDIR"},{"target":{"type":"Path","path":"C:\\fake\\maybe"},"band":"Likely","preselected":false,"scanner":"FS-INSTALLDIR"},{"target":{"type":"Path","path":"C:\\fake\\shared"},"band":"Blocked","preselected":false,"scanner":"FS-INSTALLDIR"}]}')
        [IO.File]::WriteAllText((Join-Path $g 'plan-purge.scan.json'), '{"schema":"purge.scan/0","plan_hash":"abc123","items":[{"id":"c-left","target":{"type":"Path","path":"C:\\fake\\left"},"action":"Quarantine"},{"id":"c-maybe","target":{"type":"Path","path":"C:\\fake\\maybe"},"action":"Quarantine"},{"id":"c-blocked","target":{"type":"Path","path":"C:\\fake\\shared"},"action":"Quarantine"}]}')
        $h = Join-Path $script:RunsDir $run; New-Item -ItemType Directory -Force $h | Out-Null
        [IO.File]::WriteAllText((Join-Path $h 'run.json'), (New-RunJson $run (Get-Date)))
        [pscustomobject]@{ run = $run; done = $true; seconds = 1; pulled = @('run.json') }
    }
    function Ev-Lines { if (Test-Path (Join-Path $W 'events.txt')) { @([IO.File]::ReadAllLines((Join-Path $W 'events.txt'))) } else { @() } }
    function Reset-Ev { Remove-Item -LiteralPath (Join-Path $W 'events.txt') -Force -ErrorAction SilentlyContinue; $script:M2Jobs.Clear(); $script:M2Guest.Clear() }
    function RunJson([string]$Run) { [IO.File]::ReadAllText((Join-Path $script:RunsDir "$Run\run.json")) | ConvertFrom-Json }
    function Failed($J) { @(@($J.phases) | Where-Object { -not $_.ok } | ForEach-Object { "$($_.name): $($_.error)" }) -join ' | ' }
    $hex64 = '[0-9a-f]{64}'

    # --- refusals before anything runs
    $m = $null; try { $null = Invoke-M2Mode -Mode 'm2-traps' -Engine (Join-Path $W 'repo\target\release\purge-engine.exe') } catch { $m = $_.Exception.Message }
    Check 'Invoke-M2Mode: a missing engine is refused before any VM call' ($m -match 'not found' -and $script:M2Guest.Count -eq 0) $m
    $script:VmName = 'Some-Other-VM'
    $m = $null; try { $null = Invoke-M2Mode -Mode 'm2-traps' } catch { $m = $_.Exception.Message }
    Check 'Invoke-M2Mode: a VM other than the two rig VMs is refused' ($m -match 'not a rig VM' -and $script:M2Guest.Count -eq 0) $m
    $script:VmName = 'Inbound-Win11-Test'
    $m = $null; try { $null = Invoke-M2Mode -Mode 'm2-traps' -HardPowerOff } catch { $m = $_.Exception.Message }
    Check 'Invoke-M2Mode: -HardPowerOff only with m2-crash' ($m -match 'm2-crash only') $m

    # --- m2-install
    Reset-Ev
    $rec = Invoke-M2Mode -Mode 'm2-install'
    $j = RunJson 'm2-install'
    $ev = Ev-Lines
    Check 'm2-install: one stage, run ok, restored m2-base, rig-exec engine + install.ps1 pushed' ($rec.ok -and @($rec.stages).Count -eq 1 -and $script:M2Guest[0] -eq 'restore m2-base' -and ($script:M2Guest -contains "push $(Join-Path $W 'repo\target\rig-exec\release\purge-engine.exe')") -and ($script:M2Guest -match 'copyto --target-directory C:\\cr\\install\\ ').Count -eq 1) "ok=$($rec.ok) error=$($rec.error) $(Failed $j)"
    Check 'm2-install: install, re-run unchanged, check; D: queue pre-created at medium IL' ($j.results.install.exit -eq 0 -and $j.results.install.rerun_changed -eq $false -and $j.results.install.renamed_aside -eq 1 -and $j.results.d_volume.present -eq $true -and @($ev -match '^medium:/c mkdir \S+\\dvol\\\.purge-q & echo planted-by-user> ').Count -eq 1) ($j.results | ConvertTo-Json -Depth 4 -Compress)
    Check 'm2-install: the D: medium step waits for its marker, then deletes the launch task' (@($ev -match '^unlaunch:PurgeRigLaunch$').Count -eq 1) (($ev -match 'launch') -join ', ')
    Check 'm2-install: plan from-targets then exec --plan --confirm <sha256> --select -o' (@($ev -match '^engine:plan from-targets ').Count -eq 1 -and @($ev -match "^engine:exec --plan \S+plan-d-volume\.json --confirm $hex64 --select \S+select-d-volume\.json -o \S+report-d-volume\.json$").Count -eq 1) (($ev -match '^engine:') -join ' | ')
    Check 'm2-install: job log and store pulled' ((Test-Path (Join-Path $script:RunsDir 'm2-install\job-01-start.log')) -and (Test-Path (Join-Path $script:RunsDir 'm2-install\final-sessions.zip')) -and (Test-Path (Join-Path $script:RunsDir 'm2-install\final-quarantine.json')))

    # --- m2-traps
    Reset-Ev
    $rec = Invoke-M2Mode -Mode 'm2-traps' -RunPrefix 't-'
    $j = RunJson 't-m2-traps'
    $ev = Ev-Lines
    $calls = @($j.engine.calls)
    Check 'm2-traps: run t-m2-traps ok, every phase ok' ($rec.ok -and $rec.run -eq 't-m2-traps' -and -not (Failed $j)) "error=$($rec.error) $(Failed $j)"
    $rf = $j.results.refusals
    Check 'm2-traps: wrong confirm, tampered sidecar, reordered plan all refused with no new session' ($rf.wrong_confirm.refused -and $rf.tampered_sidecar.refused -and $rf.tampered_sidecar.tampered -and $rf.reordered_plan.refused -and $rf.reordered_plan.plan_hash_differs -and $rf.wrong_confirm.new_sessions -eq 0 -and $rf.no_change) ($rf | ConvertTo-Json -Depth 4 -Compress)
    $main = @($calls | Where-Object { $_.step -eq 'exec-main' })[0]
    $bad = @($calls | Where-Object { $_.step -eq 'exec-refuse-confirm' })[0]
    Check 'm2-traps: the wrong confirm differs from the main confirm in the last digit only' ($main -and $bad -and ($main.cmd -replace '^.*--confirm (\S+).*$', '$1').Substring(0, 63) -eq ($bad.cmd -replace '^.*--confirm (\S+).*$', '$1').Substring(0, 63) -and ($main.cmd -replace '^.*--confirm (\S+).*$', '$1') -ne ($bad.cmd -replace '^.*--confirm (\S+).*$', '$1'))
    Check 'm2-traps: race groups run with PURGE_FAULT_PAUSE from the manifest and the swap helper' (@($calls | Where-Object { $_.step -eq 'exec-race-a' -and $_.env -eq 'PURGE_FAULT_PAUSE=intent.flushed:8000' }).Count -eq 1 -and @($calls | Where-Object { $_.step -eq 'exec-race-b' -and $_.env -eq 'PURGE_FAULT_PAUSE=act.before:8000' }).Count -eq 1 -and @($ev -match '^start:powershell\.exe .*-Action swap -TrapId race-validate-open').Count -eq 1) (($calls | ForEach-Object { "$($_.step) [$($_.env)]" }) -join ', ')
    Check 'm2-traps: execdiff per group (main, race-a, race-b) with the trap manifest' (@($ev -match '^execdiff:execdiff-main\.json groups=main').Count -eq 1 -and @($ev -match '^execdiff:execdiff-race-a\.json groups=race-a').Count -eq 1 -and @($ev -match '^execdiff:execdiff-race-b\.json groups=race-b').Count -eq 1)
    Check 'm2-traps: expiry walk: quarantine expiring, purge --ids q1 --yes-irreversible' ((@($j.results.expiry.ids) -join ',') -eq 'q1' -and @($ev -match '^engine:quarantine purge --ids q1 --yes-irreversible$').Count -eq 1 -and @($ev -match '^script:m2-traps\.ps1 -Action plant-expiry-junction').Count -eq 1) ($j.results.expiry | ConvertTo-Json -Compress)
    Check 'm2-traps: undo keeps the expiry item quarantined' ((@($j.results.undo.main.kept_for_expiry) -join ',') -eq 'expiry-junction.dir' -and @($calls | Where-Object { $_.step -eq 'undo-main' -and $_.cmd -match '--items ' }).Count -eq 1)
    Check 'm2-traps: forged fingerprint scanned, no canary path Safe or preselected' ($j.results.forged_fp.ok -eq $true)
    $files = @(Get-ChildItem -LiteralPath (Join-Path $script:RunsDir 't-m2-traps') -File | ForEach-Object { $_.Name })
    $need = 'run.json', 'm2-traps-manifest.json', 'execdiff-main.json', 'execdiff-race-a.json', 'execdiff-race-b.json', 'fidelity-main.json', 'deep-a.json', 'deep-c.json', 'report-main.json', 'sess-main-journal.jsonl', 'm2-traps-check-final.json', 'expiring.json', 'final-index.json'
    $miss = @($need | Where-Object { $files -notcontains $_ })
    Check 'm2-traps: outputs pulled to vm\runs\t-m2-traps' (-not $miss.Count) "missing: $($miss -join ', ')"

    # --- m2-fidelity, with one real-app round trip
    Reset-Ev
    $rec = Invoke-M2Mode -Mode 'm2-fidelity' -Apps @('npp')
    $j = RunJson 'm2-fidelity'
    $calls = @($j.engine.calls)
    Check 'm2-fidelity: run ok, every phase ok (fixtures, partial, conflict, tamper, restore point, app)' ($rec.ok -and -not (Failed $j) -and @($rec.after).Count -eq 1 -and $rec.after[0].ok) "error=$($rec.error) $(Failed $j)"
    Check 'm2-fidelity: partial undo with --items, half the items' (@($calls | Where-Object { $_.step -eq 'undo-partial' -and $_.cmd -match '--items ' }).Count -eq 1 -and @($j.results.partial_undo.undone).Count -ge 1)
    Check 'm2-fidelity: backup tamper flips a byte of the intent''s backup file' ($j.results.backup_tamper.backup -eq 'b1.bin' -and $j.results.backup_tamper.undo_exit -eq 0)
    $ev = Ev-Lines
    Check 'm2-fidelity: restore point legs: created, throttled (frequency 1440), protection off then on again' (@($calls | Where-Object { $_.cmd -match '--restore-point always' }).Count -eq 3 -and $j.results.restore_point.snapshot -eq 'm2-base' -and $j.results.restore_point.frequency_value -eq 1440 -and @($ev -match '^srprot:False$').Count -eq 1 -and @($ev -match '^srprot:True$').Count -eq 1 -and $j.results.restore_point_off.reenabled -eq $true) (($ev -match '^sr') -join ', ')
    $selApp = Get-Content -Raw (Join-Path $script:RunsDir 'm2-fidelity\select-app-npp.json')
    Check 'm2-fidelity: app stage selects every Safe / Likely / Weak item of the app plan, never Blocked' ($j.results.apps.npp.selected -eq 2 -and $selApp -match 'c-left' -and $selApp -match 'c-maybe' -and $selApp -notmatch 'c-blocked' -and $j.results.fidelity.'app-npp' -eq $true) $selApp
    Check 'm2-fidelity: two stages recorded in run.json (start, app)' ((@($j.stages | ForEach-Object { $_.stage }) -join ',') -eq 'start,app')

    # --- null runs: the phases up to deep A, an idle wait instead of exec, snap B; no ambient set pushed
    Reset-Ev
    $rec = Invoke-M2Mode -Mode 'm2-fidelity' -RunPrefix 'n1-' -Null -Apps @('npp')
    $j = RunJson 'n1-m2-fidelity'
    $ev = Ev-Lines
    Check 'null run: ok, no exec / undo / execdiff, snap A and B taken, no app stage' ($rec.ok -and -not (Failed $j) -and -not @($j.engine.calls | Where-Object { $_.step -match '^(exec|undo)-' }).Count -and -not @($ev -match '^execdiff:').Count -and @($ev -match '^snap:snap-n1-m2-fidelity-[ab]\.tsv\.gz$').Count -eq 2 -and -not @($rec.after | Where-Object { $_ }).Count -and $j.null_run.null -eq $true) "error=$($rec.error) $(Failed $j) $(($ev -match '^(snap|engine)') -join ' | ')"
    Check 'null run: the guest ambient copy is deleted, none pushed' (($script:M2Guest -contains 'cmd del /f /q C:\cr\bin\m2-ambient.json') -and -not @($script:M2Guest -match 'copyto .*m2-ambient').Count)
    Check 'null run: DiagTrack paused before snap A, like a real run' (@($ev -match '^telemetry-pause$').Count -eq 1 -and [array]::IndexOf($ev, 'telemetry-pause') -lt [array]::IndexOf($ev, 'snap:snap-n1-m2-fidelity-a.tsv.gz') -and $j.telemetry_pause.after -eq 'Stopped') (($ev | Select-Object -First 8) -join ' | ')
    $m = $null; try { $null = Invoke-M2Mode -Mode 'm2-install' -Null } catch { $m = $_.Exception.Message }
    Check 'null run: refused for a mode other than m2-traps / m2-fidelity' ($m -match 'm2-traps / m2-fidelity only') $m

    # --- elevated tests: the test binary is picked by its --list output, the exact name only
    $lst = @('security::tests::elevated_set_security_assigns_system_owner: test', 'security::tests::elevated_set_security_assigns_system_owner_x: test', 'a::b: bench')
    Check 'elevated tests: Find-TestInList takes the full path of the exact name' ((Find-TestInList $lst 'elevated_set_security_assigns_system_owner') -ceq 'security::tests::elevated_set_security_assigns_system_owner')
    Check 'elevated tests: Find-TestInList never takes a longer name or a bench' (-not (Find-TestInList $lst 'assigns_system_owner_y') -and -not (Find-TestInList $lst 'b'))
    Check 'elevated tests: both specs, one per crate' (@(Get-M2ElevatedTestSpecs).Count -eq 2 -and (@(Get-M2ElevatedTestSpecs).crate -join ',') -eq 'purge-win,purge-exec')

    # --- m2-crash: batches with a reboot continuation, torn journals
    Reset-Ev
    $rec = Invoke-M2Mode -Mode 'm2-crash' -BatchSize 4
    $j = RunJson 'm2-crash'
    $mx = [IO.File]::ReadAllText((Join-Path $script:RunsDir 'm2-crash\crash-matrix.json')) | ConvertFrom-Json
    $rows = @($mx.rows)
    Check 'm2-crash: start (4 iterations) -> reboot continuation -> matrix (3 + torn); run ok' ($rec.ok -and (@($rec.stages | ForEach-Object { $_.stage }) -join ',') -eq 'start,matrix' -and $rec.stages[0].continuation.kind -eq 'reboot' -and ($script:M2Guest -contains 'reboot from boot-1') -and -not (Failed $j)) "error=$($rec.error) $(Failed $j) stages=$(($rec.stages | ConvertTo-Json -Compress -Depth 4))"
    Check 'm2-crash: matrix rows: exec points x {resume, rollback} + undo points x resume' ($rows.Count -eq 7 -and @($rows | Where-Object { $_.phase -eq 'undo' -and $_.point -eq 'undo.intent' }).Count -eq 1 -and @($rows | Where-Object { $_.point -eq 'act.after' -and $_.after -eq 'rollback' }).Count -eq 1) ($rows | ForEach-Object { "$($_.point)/$($_.phase)/$($_.after)" })
    Check 'm2-crash: every point crashed with 0xC0000409, recovered twice idempotently, passed' (@($rows | Where-Object { $_.hit -and $_.crashed -and $_.recover_idempotent -and $_.pass }).Count -eq 7) (($rows | ForEach-Object { "$($_.tag) hit=$($_.hit) pass=$($_.pass) err=$($_.error)" }) -join ' | ')
    Check 'm2-crash: an undo-phase row is resumed to Undone and not undone again (resume finishes the undo)' (@($rows | Where-Object { $_.phase -eq 'undo' -and $_.hit -and $_.undone_by_recovery -eq $true -and $null -eq $_.undo_exit }).Count -eq @($rows | Where-Object { $_.phase -eq 'undo' -and $_.hit }).Count -and @($rows | Where-Object { $_.phase -eq 'undo' -and $_.hit }).Count -ge 1) (($rows | Where-Object { $_.phase -eq 'undo' } | ForEach-Object { "$($_.tag) undone_by_recovery=$($_.undone_by_recovery) undo_exit=$($_.undo_exit)" }) -join ' | ')
    Check 'm2-crash: fault injected through PURGE_FAULT_AT, recover, resume and rollback issued' (@($j.engine.calls | Where-Object { $_.env -eq 'PURGE_FAULT_AT=act.after' }).Count -ge 2 -and @($j.engine.calls | Where-Object { $_.cmd -match ' journal rollback --session s\d+$' }).Count -ge 3 -and @($j.engine.calls | Where-Object { $_.cmd -match ' journal resume --session s\d+$' }).Count -ge 4 -and @($j.engine.calls | Where-Object { $_.cmd -match ' journal recover$' }).Count -ge 14)
    Check 'm2-crash: torn tail and torn middle variants recorded' ($j.results.torn.tail.crashed -and $j.results.torn.middle.crashed -and $null -ne $j.results.torn.middle.recover_exit -and (Test-Path (Join-Path $script:RunsDir 'm2-crash\crash-torn.json')))
    Check 'm2-crash: the continuation marker was archived as continue-1.json' ((Test-Path (Join-Path $script:RunsDir 'm2-crash\continue-1.json')) -and -not (Test-Path (Join-Path $script:RunsDir 'm2-crash\continue.json')))

    # --- m2-reboot: two reboot continuations
    Reset-Ev
    [IO.File]::WriteAllText((Join-Path $W 'pfro.json'), '["\\??\\C:\\Windows\\Temp\\old.tmp","\\??\\C:\\Windows\\Temp\\new.tmp"]')
    $rec = Invoke-M2Mode -Mode 'm2-reboot'
    $j = RunJson 'm2-reboot'
    $ev = Ev-Lines
    Check 'm2-reboot: start -> after-reboot -> after-mismatch, run ok' ($rec.ok -and (@($rec.stages | ForEach-Object { $_.stage }) -join ',') -eq 'start,after-reboot,after-mismatch' -and -not (Failed $j)) "error=$($rec.error) $(Failed $j)"
    Check 'm2-reboot: both locked files held before the exec, the guest restart requested twice' (@($ev -match '^lock:C:\\Program Files\\PurgeTrapApp\\locked\\admin-locked\.dll,C:\\PurgeTrapUW\\boot\\user-locked\.dll$').Count -eq 2 -and @($ev -match '^shutdown:').Count -eq 2)
    Check 'm2-reboot: boot ids differ across both reboots' ($j.results.reboot.boot_changed -eq $true -and $j.results.mismatch.boot_changed -eq $true)
    Check 'm2-reboot: scenario M keeps the pre-existing PFRO pair and adds only the decoy' (@($j.results.scenario_m.pfro_tampered).Count -eq 4 -and $j.results.scenario_m.pfro_tampered[0] -eq '\??\C:\Windows\Temp\old.tmp')
    Check 'm2-reboot: retry after plant-boot-junction executes only the user-writable item' (@($ev -match '^script:m2-traps\.ps1 -Action plant-boot-junction').Count -eq 1 -and (Get-Content -Raw (Join-Path $script:RunsDir 'm2-reboot\select-retry.json')) -match 'boot-uw-planted\.file' -and (Get-Content -Raw (Join-Path $script:RunsDir 'm2-reboot\select-retry.json')) -notmatch 'boot-admin')
    Check 'm2-reboot: journal show --session after each reboot' (@($j.engine.calls | Where-Object { $_.cmd -match ' journal show --session s\d+$' }).Count -eq 2)

    # --- hard power-off: marker kind poweroff without -HardPowerOff is an error, with it a power cycle
    $cont = Join-Path $W 'out\pw-run'
    New-Item -ItemType Directory -Force $cont | Out-Null
    function Invoke-GuestJob { param($Text, $Name, $TimeoutSec, $LogCopy) [IO.File]::WriteAllText($LogCopy, 'log'); $script:PwJobs++
        if ($script:PwJobs -eq 1) { [IO.File]::WriteAllText((Join-Path $cont 'continue.json'), '{"schema":"purge.rig.continue/1","seq":1,"kind":"poweroff","next":"after-poweroff","boot_before":"boot-x"}') } else { Remove-Item -LiteralPath (Join-Path $cont 'continue.json') -Force -ErrorAction SilentlyContinue }
        [pscustomobject]@{ name = $Name; done = $true; seconds = 1; log = ''; log_file = $LogCopy } }
    $script:PwJobs = 0; $script:M2Guest.Clear()
    $r = Invoke-M2Job -Run 'pw-run' -Mode 'm2-crash'
    Check 'Invoke-M2Job: a poweroff continuation without -HardPowerOff stops with an error' ($r.error -match 'HardPowerOff' -and -not ($script:M2Guest -contains 'hard power cycle'))
    $script:PwJobs = 0; $script:M2Guest.Clear()
    $r = Invoke-M2Job -Run 'pw-run' -Mode 'm2-crash' -HardPowerOff
    Check 'Invoke-M2Job -HardPowerOff: power cycle, then stage after-poweroff' (-not $r.error -and $r.done -and ($script:M2Guest -contains 'hard power cycle') -and (@($r.stages | ForEach-Object { $_.stage }) -join ',') -eq 'start,after-poweroff')
    function Invoke-GuestJob { param($Text, $Name, $TimeoutSec, $LogCopy) [IO.File]::WriteAllText($LogCopy, 'log'); [IO.File]::WriteAllText((Join-Path $cont 'continue.json'), '{"seq":1,"kind":"reboot","next":"matrix","boot_before":"b"}'); [pscustomobject]@{ name = $Name; done = $true; seconds = 1; log = ''; log_file = $LogCopy } }
    $r = Invoke-M2Job -Run 'pw-run' -Mode 'm2-crash'
    Check 'Invoke-M2Job: a marker the next stage does not take (same seq twice) stops the loop' ($r.error -match 'seen twice' -and @($r.stages).Count -eq 2)

    if ($env:RIG_SELFTEST_M2_OUT) {
        New-Item -ItemType Directory -Force $env:RIG_SELFTEST_M2_OUT | Out-Null
        Copy-Item -Path (Join-Path $script:RunsDir '*') -Destination $env:RIG_SELFTEST_M2_OUT -Recurse -Force
        Write-Host "M2 stub runs copied to $env:RIG_SELFTEST_M2_OUT"
    }
}

} catch {
    $script:fails++
    Write-Host "FAIL unexpected error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)"
} finally {
    $env:VMPWFILE = $savedPw
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("{0} passed, {1} failed" -f $script:passes, $script:fails)
if ($script:fails) { exit 1 }
exit 0
