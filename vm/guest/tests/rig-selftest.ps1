# Host self-test for the rig v2 scripts. Needs no VM: VBoxManage, the guest and Task Scheduler are
# replaced by fakes (VBoxManage by a .cmd that only reports whether the password file exists). Nothing is
# registered and nothing outside a temporary directory is written. Windows PowerShell 5.1:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File vm\guest\tests\rig-selftest.ps1
# Exit 0 when every check passes. (Not under guest\*.ps1, so Push-Tools does not copy it to the guest.)
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
