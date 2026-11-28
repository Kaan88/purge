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
foreach ($f in @(Get-ChildItem -LiteralPath $Guest -Filter '*.ps1') + @(Get-Item (Join-Path $Vm 'rig.ps1')) + @(Get-Item (Join-Path $Vm 'rig-baseline-local.ps1')) + @(Get-Item (Join-Path $Vm 'rig-m3.ps1')) + @(Get-Item (Join-Path $Vm 'truth\m3-sec-score.ps1')) + @(Get-Item (Join-Path $Vm 'rig-m3-clean.ps1')) + @(Get-Item (Join-Path $Vm 'truth\m3-clean-score.ps1')) + @(Get-Item (Join-Path $Vm 'truth\m3-e2e-score.ps1')) + @(Get-Item (Join-Path $PSScriptRoot 'ui-a11y-probe.ps1')) + @(Get-Item $PSCommandPath)) {
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

# ------------------------------------- engine-tree.ps1 and the expected baseline trust (review BL-R1 M1)
& {
    . (Join-Path $Guest 'riglib.ps1')
    $ErrorActionPreference = 'Stop'
    # The two descriptors the protect job sets, judged as purge-win sid.rs judges them.
    Check 'engine-tree: the baseline tree descriptor passes as a leaf' (@(Get-RigSddlProblems -Sddl $RigBaselineTreeSddl -Leaf).Count -eq 0)
    Check 'engine-tree: the ancestor descriptor passes as an ancestor' (@(Get-RigSddlProblems -Sddl $RigAncestorSddl).Count -eq 0)
    $p = @(Get-RigSddlProblems -Sddl $RigAncestorSddl -Leaf)
    Check 'engine-tree: the ancestor descriptor is not a leaf (users may add files there)' ($p.Count -eq 1 -and $p[0] -match '^S-1-5-11 may write') ($p -join '; ')
    # What C:\cr is before the job: Modify for Authenticated Users, inherited from the drive root.
    $p = @(Get-RigSddlProblems -Sddl 'O:BAG:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1301bf;;;AU)')
    Check 'engine-tree: inherited Modify for Authenticated Users fails an ancestor (DELETE)' ($p.Count -eq 1 -and $p[0] -match 'S-1-5-11 may write \(mask 0x10000\)') ($p -join '; ')
    $p = @(Get-RigSddlProblems -Sddl 'O:S-1-5-21-1-2-3-1001G:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' -Leaf)
    Check 'engine-tree: a file the guest user owns fails (the host copies as that user)' ($p.Count -eq 1 -and $p[0] -match '^owner S-1-5-21-1-2-3-1001 is not') ($p -join '; ')
    Check 'engine-tree: no DACL fails' ((@(Get-RigSddlProblems -Sddl 'O:BAG:BA') -join ';') -match 'no DACL')
    Check 'engine-tree: an inherit-only grant and CREATOR OWNER do not count' (@(Get-RigSddlProblems -Sddl 'O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICIIO;FA;;;CO)(A;OICIIO;0x1301bf;;;BU)(A;;0x1200a9;;;BU)' -Leaf).Count -eq 0)
    Check 'engine-tree: TrustedInstaller as owner passes' (@(Get-RigSddlProblems -Sddl 'O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:SYD:PAI(A;;FA;;;SY)').Count -eq 0)
    # Read-only on the host: System32 is admin-only writable, the test's work directory is not.
    Check 'engine-tree: System32 passes the rule on this machine' (@(Get-RigAdminOnlyProblems (Join-Path $env:SystemRoot 'System32')).Count -eq 0) (@(Get-RigAdminOnlyProblems (Join-Path $env:SystemRoot 'System32')) -join '; ')
    Check 'engine-tree: a directory in the user''s temp does not' (@(Get-RigAdminOnlyProblems $Work).Count -gt 0)
    $tree = Join-Path $Work 'tree'
    Check 'engine-tree: a tree without kb\baselines is a problem' ((@(Get-RigEngineTreeProblems $tree) -join ';') -match 'kb\\baselines is missing')
    New-Item -ItemType Directory -Force (Join-Path $tree 'kb\baselines') | Out-Null
    [IO.File]::WriteAllText((Join-Path $tree 'kb\baselines\Professional-26340.9882.tsv.gz'), 'x')
    $p = @(Get-RigEngineTreeProblems $tree)
    Check 'engine-tree: an unprotected tree names the directory and the file' (@($p | Where-Object { $_ -like '*kb\baselines:*' }).Count -ge 1 -and @($p | Where-Object { $_ -like '*Professional-26340.9882.tsv.gz:*' }).Count -ge 1) ($p -join '; ')
    Check 'engine-tree job: an unknown action fails with the FAILED line' ((Invoke-RigEngineTreeJob -Action 'nope') -match '^ENGINE-TREE nope FAILED: unknown action')

    # The baseline trust a run expects, and the comparison with engine.hello.
    $bl = @('EnterpriseSEval-26100.1742.tsv.gz', 'professional-26340.9882.tsv.gz', 'view.json')
    Check 'expected trust: the exact baseline of this Windows is there -> exact' ((Get-RigExpectedTrust '' 'Professional' 26340 9882 $bl) -eq 'exact')
    Check 'expected trust: another revision is not exact -> nothing expected' ((Get-RigExpectedTrust '' 'Professional' 26340 9883 $bl) -eq '' -and (Get-RigExpectedTrust '' 'Professional' 26340 9882 @()) -eq '')
    Check 'expected trust: the host''s choice wins' ((Get-RigExpectedTrust 'below-exact' 'Professional' 26340 9882 $bl) -eq 'below-exact' -and (Get-RigExpectedTrust 'none' 'Professional' 26340 9882 $bl) -eq 'none')
    $msg = $null; try { $null = Get-RigExpectedTrust 'sure' 'Professional' 26340 9882 $bl } catch { $msg = $_.Exception.Message }
    Check 'expected trust: an unknown choice throws' ($msg -match 'bad expected baseline trust') "got '$msg'"
    Check 'trust check: equal (any case) or nothing expected -> ok' ($null -eq (Test-RigBaselineTrust 'exact' 'Exact') -and $null -eq (Test-RigBaselineTrust '' 'None') -and $null -eq (Test-RigBaselineTrust 'merged' 'Merged'))
    Check 'trust check: exact expected, None reported -> refused' ((Test-RigBaselineTrust 'exact' 'None') -match "baseline_trust 'None'; this run is for 'exact'")
    Check 'trust check: below-exact takes merged, local and none, not exact' ($null -eq (Test-RigBaselineTrust 'below-exact' 'Merged') -and $null -eq (Test-RigBaselineTrust 'below-exact' 'Local') -and $null -eq (Test-RigBaselineTrust 'below-exact' 'None') -and (Test-RigBaselineTrust 'below-exact' 'Exact') -match 'below Exact')
    Check 'trust check: a hello without the field is refused when something is expected' ((Test-RigBaselineTrust 'exact' '') -match 'reports no baseline trust')
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

# ------------------------------------------------- rig-baseline-local.ps1 (gate M R1, R2, R5): the pure parts
& {
    . (Join-Path $Vm 'rig-baseline-local.ps1') -Library
    $ErrorActionPreference = 'Stop'
    $r1 = Get-BlRunSpec 'R1'; $r2 = Get-BlRunSpec 'R2'; $r5 = Get-BlRunSpec 'R5'
    Check 'baseline-local: R1 is Purge-CleanPro, truth Professional, neighbour EnterpriseSEval, 3D as it is' ($r1.vm -ceq 'Purge-CleanPro' -and $r1.run -ceq 'bl-r1-cleanpro' -and $r1.truth -ceq 'Professional-26340.9882' -and $r1.neighbour -ceq 'EnterpriseSEval-26100.1742' -and -not $r1.no3d)
    Check 'baseline-local: R2 is Inbound with 3D off, truth and neighbour swapped' ($r2.vm -ceq 'Inbound-Win11-Test' -and $r2.run -ceq 'bl-r2-inbound' -and $r2.truth -ceq $r1.neighbour -and $r2.neighbour -ceq $r1.truth -and $r2.no3d)
    Check 'baseline-local: R5 has no VM and both baselines' (-not $r5.vm -and $r5.run -ceq 'r5-host' -and (@($r5.baselines) -join ',') -ceq 'Professional-26340.9882,EnterpriseSEval-26100.1742')
    $msg = $null; try { $null = Get-BlRunSpec 'R3' } catch { $msg = $_.Exception.Message }
    Check 'baseline-local: an unknown mode is refused' ($msg -match 'unknown mode')
    Check 'baseline-local: busy VM states refused, poweroff and saved not' ((Test-BlVmBusyState 'running') -and (Test-BlVmBusyState 'paused') -and (Test-BlVmBusyState 'onlinesnapshotting') -and -not (Test-BlVmBusyState 'poweroff') -and -not (Test-BlVmBusyState 'saved') -and -not (Test-BlVmBusyState 'aborted'))

    $job = Get-BlBuildJob 'C:\cr\out\bl-r1-cleanpro' 'C:\cr\bin\purge-engine.exe' 'C:\cr\guest\riglib.ps1'
    $ptok = $null; $perr = $null; $null = [Management.Automation.Language.Parser]::ParseInput($job, [ref]$ptok, [ref]$perr)
    Check 'baseline-local: the build job parses, placeholders replaced' (@($perr).Count -eq 0 -and $job -notmatch '__(DIR|ENGINE|RIGLIB)__' -and $job.Contains("`$Dir = 'C:\cr\out\bl-r1-cleanpro'") -and $job.Contains("`$Engine = 'C:\cr\bin\purge-engine.exe'") -and $job.Contains("`$RigLib = 'C:\cr\guest\riglib.ps1'"))
    Check 'baseline-local: the build job builds cold, warm, settled with PURGE_TIMING and writes build.json' ($job.Contains("foreach (`$pass in 'cold', 'warm', 'settled')") -and $job.Contains("`$env:PURGE_TIMING = '1'") -and $job.Contains("'build.json'") -and $job.Contains("baseline info"))
    Check 'baseline-local: the settled pass waits with riglib Wait-M2BootSettle, a quiet CPU, then empties the standby list' ($job.Contains('. $RigLib') -and $job.Contains('Wait-M2BootSettle -MaxSec 600 -MinUptimeSec 300') -and $job.Contains('-lt 10') -and $job.Contains('NtSetSystemInformation(80') -and $job.Contains('SeProfileSingleProcessPrivilege'))
    # The C# of the settle compiles (the job's Add-Type text, run here without calling the purge).
    $cs = [regex]::Match($job, '(?s)Add-Type -TypeDefinition @"\n(.*?)\n"@').Groups[1].Value
    $cerr = $null; try { Add-Type -TypeDefinition $cs } catch { $cerr = $_.Exception.Message }
    Check 'baseline-local: the settle helper compiles' ($cs.Length -gt 0 -and -not $cerr -and ('PurgeRig.BlSettle' -as [type])) "$cerr"
    $msg = $null; try { $null = Get-BlBuildJob 'C:\d' 'C:\e.exe' '' } catch { $msg = $_.Exception.Message }
    Check 'baseline-local: an empty riglib path is refused' ($msg -match 'bad path')
    # -FirstRead (BL-GATE A0, review BL-RM S7): one pass, after the settle, loaded with baseline info.
    $fj = Get-BlBuildJob 'C:\cr\out\bl-r1-cleanpro-firstread' 'C:\cr\bin\purge-engine.exe' 'C:\cr\guest\riglib.ps1' @('first-read')
    $perr = $null; $null = [Management.Automation.Language.Parser]::ParseInput($fj, [ref]$null, [ref]$perr)
    Check 'baseline-local: the first-read job parses, builds once, settles before it' (@($perr).Count -eq 0 -and $fj.Contains("foreach (`$pass in 'first-read')") -and $fj.Contains("`$pass -eq 'first-read'") -and $fj -notmatch '__PASSES__')
    $msg = $null; try { $null = Get-BlBuildJob 'C:\d' 'C:\e.exe' 'C:\r.ps1' @('hot') } catch { $msg = $_.Exception.Message }
    Check 'baseline-local: an unknown pass is refused' ($msg -match "bad pass 'hot'")
    # the host's pass list (its own line in rig-baseline-local.ps1, evaluated here): one pass must stay an array, or
    # $passes[0] is 'f' and the pull check looks for build-f.log (BL-GATE A0 first run, 2026-11-22)
    $pl = @([IO.File]::ReadAllLines((Join-Path $Vm 'rig-baseline-local.ps1')) | Where-Object { $_ -match '^\$passes = ' })
    $pv = & { foreach ($fr in @($true, $false)) { $B = @{ first_read = $fr }; Invoke-Expression $pl[0]; ,$passes } }
    Check 'baseline-local: the pass list is an array, also with the one first-read pass' ($pl.Count -eq 1 -and $pv[0] -is [array] -and $pv[0][0] -ceq 'first-read' -and $pv[0].Count -eq 1 -and ($pv[1] -join ',') -ceq 'cold,warm,settled') ("lines=$($pl.Count) first=$($pv[0] | ConvertTo-Json -Compress)")
    $fb = [pscustomobject]@{ os = 'Professional-26340.9882'; cpus = 2; passes = @([pscustomobject]@{ pass = 'first-read'; exit = 0; seconds = 41.5; uptime_sec = 900; peak_working_set_mb = 120; file_bytes = 9000000; total_line = 't' })
        settle = [pscustomobject]@{ cpu_settled = $true; cache_purged = $true; error = $null }; network_up = [pscustomobject]@{ start = @(); settled = @() }; info = [pscustomobject]@{ seconds = 1 } }
    $ev = Get-BlFirstReadEvidence $fb $r1 60 @('id1', "#src`tS1`tcomplete")
    Check 'baseline-local: first-read evidence within budget is ok' ($ev.ok -and $ev.doc.seconds -eq 41.5 -and $ev.doc.within_budget -and $ev.doc.budget_sec -eq 60 -and $ev.doc.source_id -ceq 'id1' -and $ev.doc.schema -ceq 'purge.rig.baseline-local-firstread/1') ($ev.problems -join '; ')
    $fb.passes[0].seconds = 75; $fb.settle.cache_purged = $false; $fb.network_up.start = @('Ethernet')
    $ev = Get-BlFirstReadEvidence $fb $r1 60
    Check 'baseline-local: first-read evidence: over budget, no standby purge, online -> three problems' (-not $ev.ok -and $ev.problems.Count -eq 3 -and -not $ev.doc.within_budget) ($ev.problems -join '; ')
    $mr = @{ nic1 = 'nat'; nic2 = 'none'; nic3 = 'bridged'; nic10 = 'nat'; natnet1 = 'nat'; cableconnected1 = 'on' }
    Check 'baseline-local: NAT adapters from showvminfo, numbered, others apart' (((@(Get-BlNatNics $mr)) -join ',') -ceq '1,10' -and ((@(Get-BlOtherNics $mr)) -join ',') -ceq '3=bridged' -and @(Get-BlNatNics @{ nic1 = 'none' }).Count -eq 0)
    # Set-BlNatLink against a fake VBoxManage: only the NAT adapter is switched, and 'off' is verified.
    & {
        $script:vbCalls = @(); $script:vbCable = 'on'; $script:vbStuck = $false
        function Write-RigLog([string]$Message) { }
        function ConvertFrom-MachineReadable([string[]]$Lines) {
            $h = @{}; foreach ($l in $Lines) { $m = [regex]::Match("$l", '^"?([^"=]+)"?="?(.*?)"?$'); if ($m.Success) { $h[$m.Groups[1].Value] = $m.Groups[2].Value } }; $h }
        function Invoke-VBox([string[]]$A) {
            $script:vbCalls += ($A -join ' ')
            if ($A[0] -eq 'controlvm' -and -not $script:vbStuck) { $script:vbCable = $A[3] }
            [pscustomobject]@{ code = 0; out = @('VMState="running"', 'nic1="nat"', 'nic2="intnet"', 'nic3="none"', "cableconnected1=`"$script:vbCable`"", 'cableconnected2="on"') }
        }
        $n = @(Set-BlNatLink 'Purge-CleanPro' 'off')
        Check 'baseline-local: Set-BlNatLink off switches only nic1 (NAT) and returns it' (($n -join ',') -ceq '1' -and @($script:vbCalls | Where-Object { $_ -like 'controlvm*' }).Count -eq 1 -and ($script:vbCalls -contains 'controlvm Purge-CleanPro setlinkstate1 off') -and $script:vbCable -ceq 'off') ($script:vbCalls -join ' | ')
        $null = Set-BlNatLink 'Purge-CleanPro' 'on'
        Check 'baseline-local: Set-BlNatLink on reconnects it' (($script:vbCalls -contains 'controlvm Purge-CleanPro setlinkstate1 on') -and $script:vbCable -ceq 'on')
        $script:vbStuck = $true; $msg = $null
        try { $null = Set-BlNatLink 'Purge-CleanPro' 'off' } catch { $msg = $_.Exception.Message }
        Check 'baseline-local: Set-BlNatLink off throws when the cable still shows connected' ($msg -match 'still connected') "$msg"
    }
    $msg = $null; try { $null = Get-BlBuildJob "C:\it's" 'C:\e.exe' 'C:\r.ps1' } catch { $msg = $_.Exception.Message }
    Check 'baseline-local: a quote in a job path is refused' ($msg -match 'bad path')
    Check 'baseline-local: version hash parsed' ((Get-BlVersionHash @('rigtool 0.1.0 source-sha256 abc123')) -ceq 'abc123' -and $null -eq (Get-BlVersionHash @('rigtool 0.1.0')))
    $da = Get-BlDiffArgs 't.gz' 'l.gz' 'n.gz' 'o.json'
    Check 'baseline-local: diff arguments' (($da -join ' ') -ceq 'baseline-diff --truth t.gz --local l.gz --neighbour n.gz --areas kb\baselines\view.json --out o.json')

    # Tree hash: CRLF reads as LF, sorted by path; the value computed independently here.
    $tree = Join-Path $Work 'bltree'
    New-Item -ItemType Directory -Force (Join-Path $tree 'src\sub') | Out-Null
    $files = [ordered]@{ 'Cargo.toml' = "a`r`nb`n"; 'Cargo.lock' = 'lock'; 'build.rs' = "fn main() {}`r`n"; 'src\main.rs' = 'm'; 'src\sub\x.rs' = "x`r`n" }
    foreach ($k in $files.Keys) { [IO.File]::WriteAllText((Join-Path $tree $k), $files[$k]) }
    $sha = [Security.Cryptography.SHA256]::Create()
    $hx = { param([byte[]]$b) -join ($sha.ComputeHash($b) | ForEach-Object { $_.ToString('x2') }) }
    $want = ''
    foreach ($rel in @('Cargo.lock', 'Cargo.toml', 'build.rs', 'src/main.rs', 'src/sub/x.rs')) {
        $want += (& $hx ([Text.Encoding]::UTF8.GetBytes($files[$rel.Replace('/', '\')].Replace("`r`n", "`n")))) + '  ' + $rel + "`n"
    }
    $want = & $hx ([Text.Encoding]::UTF8.GetBytes($want))
    Check 'baseline-local: rigtool tree hash as build.rs computes it' ((Get-BlTreeSha256 $tree) -ceq $want) "got $(Get-BlTreeSha256 $tree), want $want"

    # The final check on a synthetic run: good, then one mutation per problem.
    $d = Join-Path $Work 'blrun'
    New-Item -ItemType Directory -Force $d | Out-Null
    function Write-Gz([string]$Path, [string]$Text) {
        $fs = [IO.File]::Create($Path); $g = New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Compress)
        $b = [Text.Encoding]::UTF8.GetBytes($Text); $g.Write($b, 0, $b.Length); $g.Dispose(); $fs.Dispose()
    }
    $body = "#src`tS1`tok`nK`tHKLM\SOFTWARE\A`nK`tHKLM\SOFTWARE\B`n"
    $area = [ordered]@{ id = 'classes_clsid'; truth = 10; coverage_local = 0.9; coverage_merged = 1.0; shared_shape_false_absent_local = 0; shared_shape_false_absent_merged = 0; checks = [ordered]@{ s3_local = $true; s2_merged = $true } }
    $mkRep = { param($Complete, $Name) [ordered]@{ inputs = [ordered]@{ local = [ordered]@{ name = $Name; complete = $Complete; incomplete_reasons = @($(if (-not $Complete) { 'S4 not ok' })) }
                    truth = [ordered]@{ name = 'Professional-26340.9882' }; neighbours = @([ordered]@{ name = 'EnterpriseSEval-26100.1742' }) }
                total = [ordered]@{ truth = 10; coverage_local = 0.9; coverage_merged = 1.0; false_absent_local = 1; false_absent_merged = 0; shared_shape_false_absent_local = 0; shared_shape_false_absent_merged = 0; checks = [ordered]@{ w1_scope = $true } }
                areas = @($area) } }
    $mkBuild = { param($ColdExit) [ordered]@{ cpus = 4; info = [ordered]@{ exit = 0; seconds = 0.5 }
                passes = @([ordered]@{ pass = 'cold'; exit = $ColdExit; seconds = 20.1; peak_working_set_mb = 150.2; file_bytes = 4000000 }, [ordered]@{ pass = 'warm'; exit = 0; seconds = 12.3; peak_working_set_mb = 149; file_bytes = 4000000 }) } }
    # Schema 2: three passes, the settle record and the guest's network.
    $mkBuild3 = { param($NetUp) [ordered]@{ schema = 'purge.rig.baseline-local-build/2'; cpus = 4; info = [ordered]@{ exit = 0; seconds = 0.5 }
                network_up = [ordered]@{ start = @($NetUp); settled = @() }
                settle = [ordered]@{ boot = [ordered]@{ waited_sec = 41.2; bounded = $false; uptime_sec = 300 }; cpu_settled = $true; cpu_percent = 3.4; cpu_waited_sec = 30.1; cache_purged = $true; error = $null }
                passes = @([ordered]@{ pass = 'cold'; exit = 0; seconds = 20.1; peak_working_set_mb = 150.2; file_bytes = 4000000; uptime_sec = 90 },
                           [ordered]@{ pass = 'warm'; exit = 0; seconds = 12.3; peak_working_set_mb = 149; file_bytes = 4000000; uptime_sec = 110 },
                           [ordered]@{ pass = 'settled'; exit = 0; seconds = 15.7; peak_working_set_mb = 149; file_bytes = 4000000; uptime_sec = 400 }) } }
    # Local files of the passes: a real header (source id in field 7) and #src lines; $Ids / $Bodies per pass.
    $hdr = { param($Id, $T) "#purge-baseline-local 1`t$T`tPC`tProfessional`t26340.9882`tbl.2`t$Id`n" }
    $setRun = { param($Rep, $Build, [string]$Warm, $Ids = @('aaaa', 'aaaa', 'aaaa'), $Bodies = $null)
        [IO.File]::WriteAllText((Join-Path $d 'r.json'), (ConvertTo-Json -InputObject $Rep -Depth 8))
        [IO.File]::WriteAllText((Join-Path $d 'build.json'), (ConvertTo-Json -InputObject $Build -Depth 8))
        if (-not $Bodies) { $Bodies = @($body, $Warm, $body) }
        $i = 0
        foreach ($pass in 'cold', 'warm', 'settled') {
            Write-Gz (Join-Path $d "local-$pass.tsv.gz") ((& $hdr $Ids[$i] "created=$i") + $Bodies[$i] + "#end`t2`t$i$i$i`n"); $i++
        } }
    & $setRun (& $mkRep $true 'Professional-26340.9882') (& $mkBuild 0) $body
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') 'professional-26340.9882' 'vm'
    Check 'baseline-local check: a good run passes (header and #end may differ)' ($c.ok -and -not @($c.problems).Count) (@($c.problems) -join ' | ')
    Check 'baseline-local check: the lines gate M reads' ($c.lines[0] -ceq "local Professional-26340.9882 complete=True; truth Professional-26340.9882 (10 keys in scope); neighbours ['EnterpriseSEval-26100.1742']" -and
        ($c.lines -match '^TOTAL coverage local 0\.9 merged 1; false absent local 1 merged 0; ') -and ($c.lines -match '^  classes_clsid {15} truth      10  local 0.9  merged 1  shared fa 0/0  S3 local True  S2 merged True$') -and
        ($c.lines -match '^W4: cold build 20.1 s \(budget 120 s on 4 CPUs\), warm 12.3 s; peak 150.2 MB')) ($c.lines -join ' | ')
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') '-' 'host'
    Check 'baseline-local check: no expected name, host budget 30 s' ($c.ok -and ($c.lines -match 'budget 30 s'))
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') 'EnterpriseSEval-26100.1742' 'vm'
    Check 'baseline-local check: the wrong Windows is a problem' (-not $c.ok -and @($c.problems).Count -eq 1 -and $c.problems[0] -match 'the truth is EnterpriseSEval') (@($c.problems) -join ' | ')
    & $setRun (& $mkRep $false 'Professional-26340.9882') (& $mkBuild 0) $body
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') '-' 'vm'
    Check 'baseline-local check: an incomplete local file is a problem' (-not $c.ok -and $c.problems[0] -match '^local baseline INCOMPLETE: S4 not ok') (@($c.problems) -join ' | ')
    & $setRun (& $mkRep $true 'Professional-26340.9882') (& $mkBuild 1) $body
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') '-' 'vm'
    Check 'baseline-local check: a build exit code is a problem' (-not $c.ok -and $c.problems[0] -ceq 'cold build exit 1') (@($c.problems) -join ' | ')
    & $setRun (& $mkRep $true 'Professional-26340.9882') (& $mkBuild 0) ($body + "K`tHKLM\SOFTWARE\C`n")
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') '-' 'vm'
    Check 'baseline-local check: cold and warm bodies that differ are a problem' (-not $c.ok -and $c.problems[0] -match '^cold and warm builds differ below the header') (@($c.problems) -join ' | ')
    Check 'baseline-local check: same source id and other bytes is a determinism failure, not INVALID' (-not $c.invalid -and $c.problems[0] -match 'with the same source id aaaa \(a determinism failure; every #src line equal\)') (@($c.problems) -join ' | ')

    # Gate M round 2: the source changed between the passes (another source id): INVALID, not a determinism failure.
    $b4 = "#src`tS1`tok`n#src`tS4`tok`t91`t2513`t0`tnot-inbox=14`nK`tHKLM\SOFTWARE\A`n"
    $b4w = "#src`tS1`tok`n#src`tS4`tok`t91`t2536`t0`tnot-inbox=18`nK`tHKLM\SOFTWARE\A`nK`tHKLM\SOFTWARE\B`n"
    & $setRun (& $mkRep $true 'Professional-26340.9882') (& $mkBuild 0) $b4w @('82593a02ec71a6e2', 'b06903a6c2174f0e') @($b4, $b4w)
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') '-' 'vm'
    Check 'baseline-local check: other source ids make the run INVALID (exit 3), naming the #src lines that differ' (-not $c.ok -and $c.invalid -and @($c.problems).Count -eq 1 -and
        $c.problems[0] -match '^RUN INVALID: the source changed between the cold and warm passes \(source id 82593a02ec71a6e2 vs b06903a6c2174f0e; #src lines that differ: S4\)' -and
        -not ($c.problems -match '\(a determinism failure')) (@($c.problems) -join ' | ')
    & $setRun (& $mkRep $true 'Professional-26340.9882') (& $mkBuild 0) $b4w @('82593a02ec71a6e2', '82593a02ec71a6e2') @($b4, $b4w)
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') '-' 'vm'
    Check 'baseline-local check: the same source id with other #src lines is a determinism failure' (-not $c.ok -and -not $c.invalid -and $c.problems[0] -match 'same source id 82593a02ec71a6e2 \(a determinism failure; #src lines that differ: S4\)') (@($c.problems) -join ' | ')

    # Schema 2: three passes, all equal: ok, the settled line and the phases are printed.
    & $setRun (& $mkRep $true 'Professional-26340.9882') (& $mkBuild3 @()) $body
    [IO.File]::WriteAllLines((Join-Path $d 'build-cold.log'), [string[]]@('timing: baseline.local.list 0.1 s', 'timing: baseline.local.read 400.5 s (thread time, 4 threads)', 'timing: baseline.local.s1 120.2 s (wall)', 'timing: baseline.local.total 125.0 s (wall)'))
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') 'professional-26340.9882' 'vm'
    Check 'baseline-local check: three equal passes pass; warm is the warm pass, not the last' ($c.ok -and -not $c.invalid -and ($c.lines -match '^W4: cold build 20.1 s \(budget 120 s on 4 CPUs\), warm 12.3 s; ')) (($c.lines + $c.problems) -join ' | ')
    Check 'baseline-local check: the settled pass line' (@($c.lines -match '^W4 settled: cold build 15.7 s \(budget 120 s on 4 CPUs\) at uptime 400 s, after boot settle 41.2 s \(ReadyBoot stopped, uptime 300 s\), CPU 3.4 % over 30 s \(settled after 30.1 s\), standby list purged True$').Count -eq 1) ($c.lines -join ' | ')
    Check 'baseline-local check: the phases of a pass from its log' (@($c.lines -match '^  phases cold: read 400.5 s \(thread time, 4 threads\); s1 120.2 s \(wall\); total 125.0 s \(wall\)$').Count -eq 1) ($c.lines -join ' | ')
    Remove-Item -LiteralPath (Join-Path $d 'build-cold.log') -Force
    & $setRun (& $mkRep $true 'Professional-26340.9882') (& $mkBuild3 @()) $body @('aaaa', 'aaaa', 'cccc')
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') '-' 'vm'
    Check 'baseline-local check: equal bodies with other source ids are not a problem' ($c.ok) (@($c.problems) -join ' | ')
    & $setRun (& $mkRep $true 'Professional-26340.9882') (& $mkBuild3 @()) $body @('aaaa', 'aaaa', 'cccc') @($body, $body, ($body + "K`tHKLM\SOFTWARE\Z`n"))
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') '-' 'vm'
    Check 'baseline-local check: the settled pass is compared with the cold one too' ($c.invalid -and $c.problems[0] -match '^RUN INVALID: the source changed between the cold and settled passes') (@($c.problems) -join ' | ')
    & $setRun (& $mkRep $true 'Professional-26340.9882') (& $mkBuild3 @('Ethernet')) $body
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') '-' 'vm'
    Check 'baseline-local check: a guest adapter up makes a VM run INVALID' (-not $c.ok -and $c.invalid -and $c.problems[0] -ceq 'RUN INVALID: the guest had a network adapter up (start: Ethernet); the build must run offline') (@($c.problems) -join ' | ')
    $c = Test-BlReport (Join-Path $d 'r.json') (Join-Path $d 'build.json') '-' 'host'
    Check 'baseline-local check: the host (R5) may be online' ($c.ok) (@($c.problems) -join ' | ')
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

    # M1b (RIG.md section 12): __M1B__ carries the options; no options leaves it empty (M0 / M1a behaviour).
    $plain = New-RunJobText -Id '7zip' -Run 'm1b-7zip' -Engine
    Check 'M1b: no options -> empty __M1B__' ($plain -match "\`$M1bFlag = ''" -and $plain -notmatch '__M1B__')
    $t = New-RunJobText -Id '7zip' -Run 'm1b-traps-7zip' -Engine -M1b @{ msi_tables = $true; traps = $true; trap_a = '7zip' }
    $b64 = [regex]::Match($t, "\`$M1bFlag = '([^']+)'").Groups[1].Value
    $o = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) | ConvertFrom-Json
    Check 'M1b: options round-trip (trap_b defaults to node)' ($o.msi_tables -and $o.traps -and $o.trap_a -eq '7zip' -and $o.trap_b -eq 'node')
    $r = Test-IdCheck $t
    Check 'M1b: job with options passes the id check' ($r.code -eq 7) "exit $($r.code): $($r.out)"
    $msg = $null; try { $null = ConvertTo-M1bOpts @{ traps = $true; trap_a = 'node'; trap_b = 'node' } } catch { $msg = $_.Exception.Message }
    Check 'M1b: TrapA = TrapB refused' ($msg -match 'same app')
    Check 'M1b: run prefixes' ((Get-M1bRunPrefix -Base 'rig-base' -VmName 'Inbound-Win11-Test') -ceq 'm1b-' -and
        (Get-M1bRunPrefix -Base 'dirty-base' -VmName 'Inbound-Win11-Test' -Traps) -ceq 'm1bd-traps-' -and
        (Get-M1bRunPrefix -Base 'rig-base' -VmName 'Purge-CleanPro' -RunPrefix 'g8-') -ceq 'g8-m1bcp-' -and
        (Get-M1bRunPrefix -Freeze 2) -ceq 'm1b-fz2-')
    $msg = $null; try { $null = Get-M1bRunPrefix -Base 'm2-base' } catch { $msg = $_.Exception.Message }
    Check 'M1b: a base other than rig-base / dirty-base refused' ($msg -match 'rig-base or dirty-base')
    Check 'M1b: the gate list has the 8 apps' (@(Get-M1bGateApps).Count -eq 8 -and (Get-M1bGateApps) -contains 'python313-with-312')
    # ruling 2026-11-18: dirty-base has Node.js 20.18.0 already, so G3 runs the list without node
    $dl = @(Get-M1bGateApps -Base 'dirty-base')
    Check 'M1b: the dirty-base list is the gate list without node' ($dl.Count -eq 7 -and $dl -notcontains 'node' -and ($dl -join ',') -eq (@(Get-M1bGateApps | Where-Object { $_ -ne 'node' }) -join ',')) ($dl -join ',')
    # ruling 2026-11-18 (K14): m1b-budgets refuses without the admin-only data root, before anything runs
    $msg = $null
    & {
        function Test-RigElevated { $true }
        function Get-PurgeDataRootVerdict { param([string]$DataRoot, [string]$RepoRoot) 'absent' }
        try { $null = Invoke-M1bBudgets -Engine 'C:\nonexistent\a.exe' -BaseEngine 'C:\nonexistent\b.exe' -Program 'p' } catch { $script:budgetMsg = $_.Exception.Message }
    }
    Check 'M1b: m1b-budgets refuses without an admin-only %ProgramData%\Purge' ("$script:budgetMsg" -match 'not the admin-only data root.*verdict: absent') "$script:budgetMsg"
    # review R5 N1: unelevated it says to run elevated (not to run install.ps1), before anything else
    $script:budgetMsg = $null
    & {
        function Test-RigElevated { $false }
        function Get-PurgeDataRootVerdict { param([string]$DataRoot, [string]$RepoRoot) 'reject' }
        try { $null = Invoke-M1bBudgets -Engine 'C:\nonexistent\a.exe' -BaseEngine 'C:\nonexistent\b.exe' -Program 'p' } catch { $script:budgetMsg = $_.Exception.Message }
    }
    Check 'M1b: m1b-budgets unelevated says "run elevated", not "run install.ps1"' (
        "$script:budgetMsg" -match 'run elevated' -and "$script:budgetMsg" -notmatch 'install\.ps1') "$script:budgetMsg"
    # review R5 B3: the MSI table cache is moved aside before EACH cold M1b step (the cold harvest fills it, so the
    # cold scan would be warm), and never in a warm round. Stub engines (.cmd) write a file per step into the cache.
    $savedRuns = $script:RunsDir
    try {
        $script:RunsDir = Join-Path $Work 'budget-runs'
        $dr = Join-Path $Work 'budget-data-root'; $cache = Join-Path $dr 'fp\msitables'
        New-Item -ItemType Directory -Force $cache | Out-Null
        [IO.File]::WriteAllText((Join-Path $cache 'old.bin'), 'x')
        $stub = "@echo off`r`nif not exist `"%PURGE_STUB_CACHE%`" mkdir `"%PURGE_STUB_CACHE%`"`r`necho %1> `"%PURGE_STUB_CACHE%\%1-%RANDOM%%RANDOM%.bin`"`r`necho timing: stub %1 1>&2`r`nexit /b 0`r`n"
        $ea = Join-Path $Work 'stub-m1b.cmd'; $eb = Join-Path $Work 'stub-m2.cmd'
        [IO.File]::WriteAllText($ea, $stub); [IO.File]::WriteAllText($eb, $stub + "rem m2`r`n")
        $env:PURGE_STUB_CACHE = $cache
        $bd = & {
            function Test-RigElevated { $true }
            function Get-PurgeDataRootVerdict { param([string]$DataRoot, [string]$RepoRoot) 'good' }
            # gate5 (coordinator ruling 2026-11-18): the settle wait is faked here (tested on its own below)
            function Wait-RigHostSettled { [ordered]@{ settled = $true; waited_sec = 181.0; cpu_percent = 3.2; cpu_window_sec = 30; max_wait_sec = 900; why_not = $null } }
            Invoke-M1bBudgets -Engine $ea -BaseEngine $eb -Program 'p' -DataRoot $dr
        }
        $asides = @(Get-ChildItem -LiteralPath (Join-Path $dr 'fp') -Directory | Where-Object { $_.Name -like 'msitables.m1b-budgets-*' })
        $ha = @($asides | Where-Object { $_.Name -like '*-harvest-*' }); $sa = @($asides | Where-Object { $_.Name -like '*-scan-*' })
        $harvestInScanAside = $sa.Count -eq 1 -and @(Get-ChildItem -LiteralPath $sa[0].FullName -Filter 'harvest-*.bin').Count -eq 1 -and
            -not @(Get-ChildItem -LiteralPath $sa[0].FullName -Filter 'old.bin').Count
        $bj = Get-Content -Raw -LiteralPath (Join-Path $script:RunsDir 'm1b-budgets\budgets.json') | ConvertFrom-Json
        Check 'M1b: m1b-budgets moves the cache aside before the cold harvest and again before the cold scan, not in warm rounds' (
            $asides.Count -eq 2 -and $ha.Count -eq 1 -and $harvestInScanAside -and
            @(Get-ChildItem -LiteralPath $ha[0].FullName -Filter 'old.bin').Count -eq 1 -and
            $bj.schema -eq 'purge.rig.m1b-budgets/4' -and $bj.cold_cache_steps.harvest -eq 'moved' -and $bj.cold_cache_steps.scan -eq 'moved' -and
            $bj.cold_cache_state -eq 'moved' -and $bj.cold_cache.scan -eq $sa[0].FullName -and @($bj.runs).Count -eq 20 -and
            -not @($bj.runs | Where-Object { $_.exit -ne 0 }).Count) "asides: $(@($asides.Name) -join ', '); steps: $($bj.cold_cache_steps | ConvertTo-Json -Compress); runs: $(@($bj.runs).Count)"
        # gate5 (coordinator ruling 2026-11-18): 5 rounds (1 cold, 4 warm), the engines alternating within each round
        # (m1b first in odd rounds, m2 first in even ones), the settle record, power plan and per-step host load kept
        $ord = (@($bj.runs | Sort-Object seq | ForEach-Object { "$($_.round)$($_.engine)$($_.step.Substring(0, 1))" }) -join ' ')
        $want = '1m1bh 1m1bs 1m2h 1m2s 2m2h 2m2s 2m1bh 2m1bs 3m1bh 3m1bs 3m2h 3m2s 4m2h 4m2s 4m1bh 4m1bs 5m1bh 5m1bs 5m2h 5m2s'
        Check 'M1b: m1b-budgets runs 5 rounds, engines alternating within each round, round 1 cold' ($ord -eq $want -and
            @($bj.runs | Where-Object { $_.kind -eq 'cold' }).Count -eq 4 -and -not @($bj.runs | Where-Object { $_.kind -eq 'cold' -and $_.round -ne 1 }).Count) $ord
        Check 'M1b: m1b-budgets records the settled host, the power plan and each step''s host CPU load' ($bj.settle.settled -eq $true -and
            $bj.settle.cpu_percent -eq 3.2 -and $bj.PSObject.Properties.Name -contains 'power_plan' -and $bj.rounds -eq 5 -and
            @($bj.runs | Where-Object { $_.PSObject.Properties.Name -contains 'host_cpu_percent' }).Count -eq 20) ($bj | ConvertTo-Json -Depth 3 -Compress)
    } finally { $script:RunsDir = $savedRuns; Remove-Item Env:\PURGE_STUB_CACHE -ErrorAction SilentlyContinue }
    # gate5 (coordinator ruling 2026-11-18, G7 measurement hygiene): the settled-host wait before round 1. Fakes for the
    # VM process list and the CPU load; the wait counts the quiet time from the last VM process seen, then needs CPU < 10 %.
    & {
        $script:vmCalls = 0
        function Get-RigVmProcesses { $script:vmCalls++; if ($script:vmCalls -le 2) { @('VBoxHeadless') } else { @() } }
        function Get-RigCpuLoad([int]$WindowSec = 30) { 4.5 }
        $t0 = Get-Date
        $s = Wait-RigHostSettled -QuietSec 2 -CpuWindowSec 1 -MaxWaitSec 20 -PollSec 1
        $el = ((Get-Date) - $t0).TotalSeconds
        Check 'M1b budgets settle: a VM process seen, then quiet for QuietSec, CPU under 10 %: settled' ($s.settled -eq $true -and
            @($s.vm_processes_seen) -contains 'VBoxHeadless' -and $s.vm_last_seen -and $s.cpu_percent -eq 4.5 -and $el -ge 2 -and $el -lt 15) "elapsed=$el $($s | ConvertTo-Json -Depth 3 -Compress)"
        function Get-RigVmProcesses { @() }
        function Get-RigCpuLoad([int]$WindowSec = 30) { 37.0 }
        $s = Wait-RigHostSettled -QuietSec 0 -CpuWindowSec 1 -MaxWaitSec 2 -PollSec 1
        Check 'M1b budgets settle: CPU load stays high: not settled within the bound, the reason recorded' ($s.settled -eq $false -and
            "$($s.why_not)" -match 'CPU load 37' -and @($s.cpu_samples).Count -ge 1) ($s | ConvertTo-Json -Depth 3 -Compress)
        function Get-RigVmProcesses { @('VirtualBoxVM') }
        $s = Wait-RigHostSettled -QuietSec 1 -CpuWindowSec 1 -MaxWaitSec 2 -PollSec 1
        Check 'M1b budgets settle: a VM keeps running: not settled, no CPU sample taken' ($s.settled -eq $false -and
            "$($s.why_not)" -match 'VirtualBoxVM' -and @($s.cpu_samples).Count -eq 0) ($s | ConvertTo-Json -Depth 3 -Compress)
        $cpu = Get-RigCpuPercent ([pscustomobject]@{ idle = 0; kernel = 0; user = 0 }) ([pscustomobject]@{ idle = 900; kernel = 1000; user = 0 })
        Check 'M1b budgets settle: CPU percent from GetSystemTimes deltas (kernel includes idle)' ($cpu -eq 10.0) "$cpu"
        $real = Get-RigSystemTimes
        Check 'M1b budgets settle: GetSystemTimes readable on this host' ($real.kernel -gt 0 -and $real.idle -ge 0 -and $real.kernel -ge $real.idle) ($real | ConvertTo-Json -Compress)
    }
    # an unsettled host: the mode refuses with a clear message before moving the cache or running an engine
    $savedRuns = $script:RunsDir
    try {
        $script:RunsDir = Join-Path $Work 'budget-runs-unsettled'
        $dr = Join-Path $Work 'budget-data-root-unsettled'; $cache = Join-Path $dr 'fp\msitables'
        New-Item -ItemType Directory -Force $cache | Out-Null
        $script:budgetMsg = $null
        & {
            function Test-RigElevated { $true }
            function Get-PurgeDataRootVerdict { param([string]$DataRoot, [string]$RepoRoot) 'good' }
            function Wait-RigHostSettled { [ordered]@{ settled = $false; waited_sec = 900.2; cpu_percent = 41.0; max_wait_sec = 900; why_not = 'CPU load 41 % over 30 s (needs < 10 %)' } }
            try { $null = Invoke-M1bBudgets -Engine $ea -BaseEngine $eb -Program 'p' -DataRoot $dr } catch { $script:budgetMsg = $_.Exception.Message }
        }
        Check 'M1b: m1b-budgets refuses an unsettled host before anything runs' ("$script:budgetMsg" -match 'did not settle within 900 s \(CPU load 41' -and
            (Test-Path -LiteralPath $cache) -and -not (Test-Path -LiteralPath (Join-Path $script:RunsDir 'm1b-budgets\budgets.json'))) "$script:budgetMsg"
    } finally { $script:RunsDir = $savedRuns }
    $absent = Join-Path $Work 'no-purge-data-root'
    $plain = Join-Path $Work 'plain-purge-data-root'; New-Item -ItemType Directory $plain | Out-Null
    $va = Get-PurgeDataRootVerdict -DataRoot $absent; $vp = Get-PurgeDataRootVerdict -DataRoot $plain
    Check 'M1b: data root verdict as install.ps1 -Check (absent; an inherited-DACL folder is rejected)' ($va -eq 'absent' -and $vp -eq 'reject') "absent: $va; plain: $vp"
    # review R4c S3: the build record carries the rig inputs' hashes (read-only git and file reads)
    $in = Get-M1bRigInputs -RepoRoot (Split-Path -Parent $Vm)
    $trapSha = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Vm 'truth\m1b-traps.json')).Hash.ToLowerInvariant()
    $nLab = @(Get-ChildItem -LiteralPath (Join-Path $Vm 'truth\labels') -Filter '*.json' -File).Count
    $nFz = @(Get-ChildItem -LiteralPath (Join-Path $Vm 'truth\frozen') -Recurse -File).Count
    $denySha = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Vm 'truth\deny.json')).Hash.ToLowerInvariant()
    Check 'M1b: rig inputs hash the trap file, every label file, deny.json, every frozen file, the guest scripts and rig.ps1' (
        $in['vm/truth/m1b-traps.json'] -ceq $trapSha -and $in.Contains('vm/rig.ps1') -and $in.Contains('vm/guest/m1b-traps.ps1') -and
        $in['vm/truth/deny.json'] -ceq $denySha -and $in.Contains('vm/truth/frozen/temurin/truth.json') -and
        @($in.Keys | Where-Object { $_ -like 'vm/truth/frozen/*' }).Count -eq $nFz -and $nFz -gt 0 -and
        @($in.Keys | Where-Object { $_ -like 'vm/truth/labels/*.json' }).Count -eq $nLab -and
        -not @($in.Keys | Where-Object { $_ -like 'vm/guest/tests/*' }).Count) "keys: $(@($in.Keys).Count)"
    $bi = Get-M1bBuildInfo -Path '' -RepoRoot (Split-Path -Parent $Vm)
    Check 'M1b: the build record has inputs and inputs_dirty' ($bi.inputs.Count -eq $in.Count -and $bi.Contains('inputs_dirty')) "inputs_dirty=$($bi.inputs_dirty)"
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
if "%VERB%"=="hello" (
  type "%STUB_DIR%\hello.json"
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
function New-StubEngine([string]$Dir, [string]$MainKey, [string]$Trust = 'Exact') {
    $stub = Join-Path $Dir 'stub'
    New-Item -ItemType Directory -Force $stub | Out-Null
    # engine.hello of a Professional 26340.9882 machine whose view has trust $Trust.
    $view = '{"name":"local-Professional-26340.9882+1","trust":"' + $Trust + '","local_id":"0123456789abcdef"}'
    if ($Trust -eq 'Exact') { $view = '{"name":"Professional-26340.9882","trust":"Exact","local_id":null}' }
    [IO.File]::WriteAllText((Join-Path $stub 'hello.json'), ('{"version":"0.1.0","elevated":true,"user_sid":"S-1-5-21-1-2-3-1001","shell_sid":null,"edition":"Professional","build":26340,"ubr":9882,"policy_version":"bl.1",' +
        '"baseline_available":' + $(if ($Trust -eq 'Exact') { 'true' } else { 'false' }) + ',"baseline_trust":"' + $Trust + '","baseline_view":' + $view + ',"baseline_build":{"state":"none","reason":"stub"}}'))
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
    # __TRUST__ (review BL-R1 M1): empty unless the host names the baseline trust the run is for.
    $t = New-RunJobText -Id 'npp' -Run 'r0-npp' -Engine
    Check 'New-RunJobText without -ExpectTrust: __TRUST__ empty, nothing left unreplaced' ($t.Contains("`$TrustFlag = ''") -and -not ($t -match '__(ID|RUN|ENGINE|EXTRA|M1B|TRUST)__'))
    Check 'New-RunJobText -ExpectTrust below-exact' ((New-RunJobText -Id 'npp' -Run 'r0-npp' -Engine -ExpectTrust 'below-exact').Contains("`$TrustFlag = 'below-exact'"))
    $msg = $null; try { $null = New-RunJobText -Id 'npp' -ExpectTrust 'exact' } catch { $msg = $_.Exception.Message }
    Check 'New-RunJobText -ExpectTrust without -Engine throws' ($msg -match 'needs -Engine') "got '$msg'"
    $msg = $null; try { $null = New-RunJobText -Id 'npp' -Run 'r0-npp' -Engine -ExpectTrust 'Exactly' } catch { $msg = $_.Exception.Message }
    Check 'New-RunJobText rejects an unknown -ExpectTrust' ([bool]$msg) "got '$msg'"
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

# ------------------------------------- Defender signature idle (RIG.md 12.7, ruling 2026-11-18): order in both jobs
& {
    foreach ($f in 'run-app.ps1', 'null-run.ps1') {
        $t = [IO.File]::ReadAllText((Join-Path $Guest $f))
        $p = $t.IndexOf("Phase 'edge-pause'"); $d = $t.IndexOf("Phase 'defender-idle' { `$S.defender.idle = Wait-DefenderIdle -OutDir `$Dir } `$S"); $a = $t.IndexOf("Phase 'arp0'")
        $l = $t.IndexOf("Phase 'lists0'")
        Check "${f}: defender-idle after edge-pause, right before arp0 / lists0" ($p -gt 0 -and $d -gt $p -and $d -lt $a -and $d -lt $l) "pause=$p defender=$d arp0=$a lists0=$l"
        Check "${f}: Defender versions read before snap 0 and after snap 2" ($t.Contains("Phase 'snap0' { `$S.defender.snap0 = Get-DefenderVersions; Snap `$Run 0 } `$S") -and $t.Contains("Phase 'snap2' { Snap `$Run 2; `$S.defender.snap2 = Get-DefenderVersions } `$S") -and $t.Contains('defender = [ordered]@{ idle = $null; snap0 = $null; snap2 = $null }'))
    }
}

# ---------------------- riglib: Wait-DefenderIdle is bounded and never throws (no host Defender call: all faked)
# Gate5 fix (coordinator 2026-11-18): MpCmdRun retried until it exits 0, then stable, then signatures current.
& {
    . (Join-Path $Guest 'riglib.ps1')
    $ErrorActionPreference = 'Stop'
    function Log([string]$Message) { }
    function Copy-DefenderLogs([string]$OutDir) { }
    # A virtual clock (no wall time: the checks below were load-dependent with real Get-Date/Start-Sleep and
    # PollSec 0, e.g. a busy wait overrunning the bound left one attempt where two are asserted). Get-Date without
    # arguments reads it; Start-Sleep advances it by its time (at least 100 ms, so a PollSec 0 loop still moves);
    # a fake MpCmdRun advances it by its own `sec`. Get-Date with arguments stays the real cmdlet.
    $script:clk = [datetime]'2026-01-01T00:00:00'
    function Get-Date { if ($args.Count) { Microsoft.PowerShell.Utility\Get-Date @args } else { $script:clk } }
    function Start-Sleep([int]$Milliseconds = 0, [int]$Seconds = 0) { $script:clk = $script:clk.AddMilliseconds([math]::Max(100, $Milliseconds + 1000 * $Seconds)) }
    function Step-Clock([double]$Sec) { $script:clk = $script:clk.AddSeconds($Sec) }
    # a version record: $age days old, out of date when older than 7 days (as Defender says)
    $V = { param($sig, $age = 0) [ordered]@{ source = 'fake'; av_signature = $sig; as_signature = $sig; engine = '1.1.1.1'; platform = '4.18.1.1'
            av_signature_age = $age; signatures_out_of_date = ($age -gt 7); error = $null } }
    $Fake = { param($exit, $sec = 0.1) Step-Clock $sec; [ordered]@{ exe = 'C:\fake\MpCmdRun.exe'; args = '-SignatureUpdate'; start = 'x'; exit = $exit; timed_out = $false; sec = $sec; error = $null } }
    function Get-DefenderVersions { & $V '1.437.1.0' 427 }

    # current from the start: MpCmdRun exits 0 at once, nothing changes, signatures current -> one attempt, done
    function Invoke-DefenderSignatureUpdate([int]$TimeoutSec = 300) { & $Fake 0 }
    function Get-DefenderFingerprint { [pscustomobject]@{ versions = (& $V '1.463.242.0' 0); text = 'same' } }
    $t0 = Get-Date
    $r = Wait-DefenderIdle -StableSec 1 -BusyWaitSec 1 -MaxWaitSec 10 -PollSec 0
    Check 'Wait-DefenderIdle, current from the start: one attempt (exit 0), stable, current, not bounded' ($r.stable -eq $true -and $r.current -eq $true -and -not $r.bounded -and @($r.attempts).Count -eq 1 -and $r.trigger.exit -eq 0 -and -not $r.error -and ((Get-Date) - $t0).TotalSeconds -lt 5) ($r | ConvertTo-Json -Depth 4 -Compress)

    # busy then succeeds (the gate5 m1bcp-python case): exit 2 in 0.1 s while Defender's own update downloads; the state
    # moves when it lands; MpCmdRun again exits 0; stable; current -> two attempts, updated
    $script:calls = 0; $script:polls = 0
    function Invoke-DefenderSignatureUpdate([int]$TimeoutSec = 300) { $script:calls++; if ($script:calls -eq 1) { & $Fake 2 0.1 } else { & $Fake 0 3.5 } }
    function Get-DefenderFingerprint { $script:polls++; if ($script:polls -le 3) { [pscustomobject]@{ versions = (& $V '1.437.1.0' 427); text = 'old' } } else { [pscustomobject]@{ versions = (& $V '1.463.359.0' 0); text = 'new' } } }
    $r = Wait-DefenderIdle -StableSec 1 -BusyWaitSec 5 -MaxWaitSec 20 -PollSec 0
    Check 'Wait-DefenderIdle, busy then succeeds: exit 2 then exit 0 recorded, stable, current, updated' ($r.stable -eq $true -and $r.current -eq $true -and -not $r.bounded -and $r.updated -eq $true -and (@($r.attempts | ForEach-Object { $_.exit }) -join ',') -eq '2,0' -and $r.changes -ge 1 -and $r.after.av_signature -eq '1.463.359.0') ($r | ConvertTo-Json -Depth 4 -Compress)

    # the gate5 failure itself: busy (exit 2) and NOTHING moves for longer than the stable time -> the old wait ended
    # here; the new one does not end early: it runs MpCmdRun again after the busy wait, until it exits 0
    $script:calls = 0
    function Invoke-DefenderSignatureUpdate([int]$TimeoutSec = 300) { $script:calls++; if ($script:calls -le 2) { & $Fake 2 0.1 } else { & $Fake 0 2.0 } }
    function Get-DefenderFingerprint { [pscustomobject]@{ versions = (& $V '1.463.359.0' 0); text = 'same' } }
    $r = Wait-DefenderIdle -StableSec 1 -BusyWaitSec 2 -MaxWaitSec 20 -PollSec 0
    Check 'Wait-DefenderIdle, busy with a still fingerprint: not done until MpCmdRun exits 0 (3 attempts)' ($r.stable -eq $true -and $r.current -eq $true -and (@($r.attempts | ForEach-Object { $_.exit }) -join ',') -eq '2,2,0' -and $r.waited_sec -ge 3.5) ($r | ConvertTo-Json -Depth 4 -Compress)

    # stale signature with a failing trigger: MpCmdRun always fails, the signatures stay 427 days old -> bounded, not
    # current, several attempts recorded, returns within its bound
    function Invoke-DefenderSignatureUpdate([int]$TimeoutSec = 300) { & $Fake (-2147024894) 0.2 }
    function Get-DefenderFingerprint { [pscustomobject]@{ versions = (& $V '1.437.1.0' 427); text = 'same' } }
    $t0 = Get-Date
    $r = Wait-DefenderIdle -StableSec 1 -BusyWaitSec 1 -MaxWaitSec 3 -PollSec 0
    $el = ((Get-Date) - $t0).TotalSeconds
    Check 'Wait-DefenderIdle, stale signatures, failing trigger: bounded, not current, attempts recorded, within the bound' ($r.bounded -eq $true -and $r.stable -eq $false -and $r.current -eq $false -and @($r.attempts).Count -ge 2 -and $r.trigger.exit -eq -2147024894 -and $el -lt 6) "elapsed=$el $($r | ConvertTo-Json -Depth 4 -Compress)"
    # stale and MpCmdRun exits 0 (nothing newer reached): stable but never current -> MpCmdRun again, bounded
    function Invoke-DefenderSignatureUpdate([int]$TimeoutSec = 300) { & $Fake 0 0.1 }
    $r = Wait-DefenderIdle -StableSec 1 -BusyWaitSec 1 -MaxWaitSec 3 -PollSec 0
    Check 'Wait-DefenderIdle, exit 0 but signatures stale: not done, retried, bounded, not current' ($r.bounded -eq $true -and $r.current -eq $false -and $r.stable -eq $false -and @($r.attempts).Count -ge 2) ($r | ConvertTo-Json -Depth 4 -Compress)

    # always busy: exit 2 every time, signatures current -> still bounded (the last MpCmdRun never exited 0)
    function Invoke-DefenderSignatureUpdate([int]$TimeoutSec = 300) { & $Fake 2 0.1 }
    function Get-DefenderFingerprint { [pscustomobject]@{ versions = (& $V '1.463.359.0' 0); text = 'same' } }
    $t0 = Get-Date
    $r = Wait-DefenderIdle -StableSec 1 -BusyWaitSec 1 -MaxWaitSec 3 -PollSec 0
    $el = ((Get-Date) - $t0).TotalSeconds
    Check 'Wait-DefenderIdle, always busy: bounded, not stable, every attempt exit 2, within the bound' ($r.bounded -eq $true -and $r.stable -eq $false -and @($r.attempts).Count -ge 2 -and @($r.attempts | Where-Object { $_.exit -ne 2 }).Count -eq 0 -and $el -lt 6) "elapsed=$el $($r | ConvertTo-Json -Depth 4 -Compress)"

    # never settles after exit 0: bounded, returns (no hang, no throw), not stable
    function Invoke-DefenderSignatureUpdate([int]$TimeoutSec = 300) { & $Fake 0 0.1 }
    function Get-DefenderFingerprint { [pscustomobject]@{ versions = (& $V '1.463.359.0' 0); text = [guid]::NewGuid().ToString() } }
    $t0 = Get-Date
    $r = Wait-DefenderIdle -StableSec 5 -BusyWaitSec 1 -MaxWaitSec 1 -PollSec 0
    Check 'Wait-DefenderIdle, never settles: bounded, not stable, returns within its bound' ($r.bounded -eq $true -and $r.stable -eq $false -and ((Get-Date) - $t0).TotalSeconds -lt 5) ($r | ConvertTo-Json -Depth 4 -Compress)

    # MpCmdRun hangs: its timeout is capped by what is left of the overall bound; recorded, the wait still ends
    $script:to = @()
    function Invoke-DefenderSignatureUpdate([int]$TimeoutSec = 300) { $script:to += $TimeoutSec; Step-Clock $TimeoutSec; [ordered]@{ exe = 'C:\fake\MpCmdRun.exe'; args = '-SignatureUpdate'; exit = $null; timed_out = $true; sec = $TimeoutSec; error = $null } }
    function Get-DefenderFingerprint { [pscustomobject]@{ versions = (& $V '1.463.359.0' 0); text = 'same' } }
    $r = Wait-DefenderIdle -UpdateTimeoutSec 300 -StableSec 1 -BusyWaitSec 1 -MaxWaitSec 3 -PollSec 0
    Check 'Wait-DefenderIdle, MpCmdRun timed out: recorded, its timeout within the overall bound, bounded' ($r.trigger.timed_out -eq $true -and $r.bounded -eq $true -and @($script:to | Where-Object { $_ -gt 3 }).Count -eq 0) "timeouts=$($script:to -join ',') $($r | ConvertTo-Json -Depth 4 -Compress)"

    # anything inside throws: the record carries the error, the function does not throw
    function Invoke-DefenderSignatureUpdate([int]$TimeoutSec = 300) { throw 'simulated failure' }
    $threw = $false
    try { $r = Wait-DefenderIdle -StableSec 1 -MaxWaitSec 1 -PollSec 0 } catch { $threw = $true }
    Check 'Wait-DefenderIdle, a failure inside: no throw, error recorded' (-not $threw -and "$($r.error)" -match 'simulated failure') "threw=$threw error=$($r.error)"

    # the default bounds: 600 s overall, 240 s busy wait, 60 s stable (the job timeouts leave room: app 5400 s, null 2400 s)
    Check 'Wait-DefenderIdle defaults: MaxWaitSec 600, BusyWaitSec 240, StableSec 60, MaxAgeDays 1' ([IO.File]::ReadAllText((Join-Path $Guest 'riglib.ps1')) -match '\[int\]\$StableSec = 60, \[int\]\$BusyWaitSec = 240,\s+\[int\]\$MaxWaitSec = 600, \[int\]\$PollSec = 5, \[int\]\$MaxAgeDays = 1\)')
}
& {
    . (Join-Path $Guest 'riglib.ps1')
    $ErrorActionPreference = 'Stop'
    # Test-DefenderSignaturesCurrent: Defender's flag or the age; unknown (registry fallback) is not current
    $ok = (Test-DefenderSignaturesCurrent ([ordered]@{ signatures_out_of_date = $false; av_signature_age = 427 })) -and
        (Test-DefenderSignaturesCurrent ([ordered]@{ signatures_out_of_date = $true; av_signature_age = 1 })) -and
        -not (Test-DefenderSignaturesCurrent ([ordered]@{ signatures_out_of_date = $true; av_signature_age = 2 })) -and
        -not (Test-DefenderSignaturesCurrent ([ordered]@{ signatures_out_of_date = $null; av_signature_age = $null })) -and
        -not (Test-DefenderSignaturesCurrent $null)
    Check 'Test-DefenderSignaturesCurrent: not out of date, or at most 1 day old; unknown is not current' $ok
    # Copy-DefenderLogs: MpCmdRun.log from %TEMP%, the newest Support\MPLog-*.log read while another handle writes it,
    # the tail only of a long one; no OutDir: nothing; never throws
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("rigst-deflog-" + [guid]::NewGuid().ToString('N'))
    $oldTemp = $env:TEMP
    $hold = $null
    try {
        $tdir = Join-Path $tmp 'temp'; $out = Join-Path $tmp 'out'; $sup = Join-Path $tmp 'Defender\Support'
        foreach ($d in $tdir, $out, $sup) { New-Item -ItemType Directory -Force $d | Out-Null }
        [IO.File]::WriteAllText((Join-Path $tdir 'MpCmdRun.log'), "MpCmdRun: Command Line: -SignatureUpdate`r`nexit 2`r`n")
        [IO.File]::WriteAllText((Join-Path $sup 'MPLog-20250101-000000.log'), 'old')
        (Get-Item (Join-Path $sup 'MPLog-20250101-000000.log')).LastWriteTimeUtc = (Get-Date).ToUniversalTime().AddDays(-2)
        $big = Join-Path $sup 'MPLog-20261118-100000.log'
        [IO.File]::WriteAllText($big, ('x' * 5000) + 'TAIL')
        $hold = New-Object IO.FileStream($big, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        $env:TEMP = $tdir
        $RigDefenderData = Join-Path $tmp 'Defender'
        $threw = $false
        try { $logs = @(Copy-DefenderLogs -OutDir $out -MaxBytes 1000) } catch { $threw = $true; $logs = @() }
        $mp = Join-Path $out 'defender-MPLog.log'; $mc = Join-Path $out 'defender-MpCmdRun.log'
        $mpText = $(if (Test-Path $mp) { [IO.File]::ReadAllText($mp) } else { '' })
        Check 'Copy-DefenderLogs: MpCmdRun.log and the newest MPLog (open for writing elsewhere) copied, a long one truncated to its tail' (-not $threw -and (Test-Path $mc) -and ([IO.File]::ReadAllText($mc) -match 'SignatureUpdate') -and $mpText.Length -eq 1000 -and $mpText.EndsWith('TAIL') -and @($logs | Where-Object { $_.to -eq 'defender-MPLog.log' -and $_.truncated -eq $true -and -not $_.error }).Count -eq 1) "threw=$threw logs=$($logs | ConvertTo-Json -Depth 3 -Compress)"
        $none = @(Copy-DefenderLogs -OutDir '')
        Check 'Copy-DefenderLogs: no OutDir copies nothing' ($none.Count -eq 0)
        $threw = $false
        try { $bad = @(Copy-DefenderLogs -OutDir (Join-Path $tmp 'no\such\dir')) } catch { $threw = $true }
        Check 'Copy-DefenderLogs: an unwritable OutDir: no throw, errors recorded' (-not $threw -and @($bad | Where-Object { $_.error }).Count -ge 1) "threw=$threw"
    } finally {
        $env:TEMP = $oldTemp
        if ($hold) { $hold.Dispose() }
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
& {
    . (Join-Path $Guest 'riglib.ps1')
    $ErrorActionPreference = 'Stop'
    # Defender absent or its CIM class unreachable, and the registry fallback failing too: no throw, both errors recorded
    function Get-CimInstance { throw 'Invalid namespace' }
    function Open-RegKey([string]$Canon) { throw 'access denied' }
    $threw = $false
    try { $v = Get-DefenderVersions } catch { $threw = $true }
    Check 'Get-DefenderVersions, no Defender: no throw, no version, both errors recorded' (-not $threw -and $null -eq $v.av_signature -and "$($v.error)" -match 'Invalid namespace' -and "$($v.error)" -match 'access denied') "threw=$threw error=$($v.error)"
}

# ----------------------------------------------------- m1b-crash: a task's Id value (K13 task rounds, 2026-11-19)
& {
    . (Join-Path $Guest 'm1b-crash.ps1') -Library
    $ErrorActionPreference = 'Stop'
    $g = '{1B4D5E2F-0A3C-4E6B-9D8F-7C1A2B3C4D5E}'
    Check 'ConvertTo-XTaskId: a GUID passes unchanged' ((ConvertTo-XTaskId $g) -ceq $g)
    $t = ConvertTo-XTaskId ($g + [char]0)
    Check 'ConvertTo-XTaskId: the REG_SZ terminator NUL is trimmed' ($t -ceq $g -and $t.IndexOf([char]0) -lt 0) "$($t.Length) chars"
    Check 'ConvertTo-XTaskId: several trailing NULs are trimmed' ((ConvertTo-XTaskId ($g + [char]0 + [char]0)) -ceq $g)
    # A trailing newline must not pass ('$' matches before one; the pattern uses \z, review R8 M4).
    foreach ($bad in @($null, '', 'not-a-guid', ('{1B4D5E2F-0A3C' + [char]0 + '-4E6B-9D8F-7C1A2B3C4D5E}'), ($g + ' '), [string[]]@($g), ($g + "`n"), ($g + "`r`n"), ("`n" + $g))) {
        $threw = $false; try { $null = ConvertTo-XTaskId $bad } catch { $threw = $true }
        Check "ConvertTo-XTaskId: '$("$bad" -replace "`0", '\0')' throws" $threw
    }
    $roots = @(Get-XRoots 'task' '\PurgeExecApp\Crash 001' (ConvertTo-XTaskId ($g + [char]0)))
    Check 'Get-XRoots task: the Tasks and Plain roots name the trimmed GUID' ((@($roots | Where-Object { $_ -like "*\TaskCache\Tasks\$g" -or $_ -like "*\TaskCache\Plain\$g" }).Count -eq 2) -and -not @($roots | Where-Object { "$_".IndexOf([char]0) -ge 0 }).Count) ($roots -join ' | ')
}

# ------------------------------------------------------------------------- riglib: engine helpers
& {
    . (Join-Path $Guest 'riglib.ps1')
    $ErrorActionPreference = 'Stop'
    Check 'ConvertTo-EngineArg: plain word unquoted' ((ConvertTo-EngineArg 'inventory') -eq 'inventory')
    Check 'ConvertTo-EngineArg: program id quoted' ((ConvertTo-EngineArg 'HKLM|64|Git_is1') -eq '"HKLM|64|Git_is1"')
    Check 'ConvertTo-EngineArg: trailing backslash doubled' ((ConvertTo-EngineArg 'C:\a b\') -eq '"C:\a b\\"') (ConvertTo-EngineArg 'C:\a b\')
    Check 'ConvertTo-EngineArg: embedded quote escaped' ((ConvertTo-EngineArg 'x"y') -eq '"x\"y"') (ConvertTo-EngineArg 'x"y')
    # A NUL would cut the command line there (2026-11-19: a task Id's terminator truncated `rigtool snap`).
    $nulGuid = '{1B4D5E2F-0A3C-4E6B-9D8F-7C1A2B3C4D5E}' + [char]0
    foreach ($v in @($nulGuid, ('a' + [char]0 + 'b'), [string][char]0)) {
        $threw = $false; try { $null = ConvertTo-EngineArg $v } catch { $threw = ("$($_.Exception.Message)" -match 'NUL') }
        Check "ConvertTo-EngineArg: a NUL throws ($($v.Length) chars)" $threw
    }
    $threw = $false; try { $null = Invoke-M2Snap (Join-Path $Work 'nul.tsv.gz') @('HKLM\SOFTWARE\x', "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$nulGuid") } catch { $threw = ("$($_.Exception.Message)" -match 'NUL') }
    Check 'Invoke-M2Snap: a root with a NUL throws before rigtool runs' $threw
    # Where the command line is started, too (review R8 M4): unquoted parts (--sid, --group) never pass ConvertTo-EngineArg.
    $threw = $false; try { $null = Invoke-Native "$env:SystemRoot\System32\cmd.exe" ('/c exit 0 ' + [char]0 + ' x') } catch { $threw = ("$($_.Exception.Message)" -match 'NUL') }
    Check 'Invoke-Native: a NUL in the command line throws' $threw
    $threw = $false; try { $null = Start-Native "$env:SystemRoot\System32\cmd.exe" ('/c exit 0' + [char]0) } catch { $threw = ("$($_.Exception.Message)" -match 'NUL') }
    Check 'Start-Native: a NUL in the command line throws' $threw
    $threw = $false; try { $null = Invoke-Engine -Exe "$env:SystemRoot\System32\cmd.exe" -Arguments ('--sid S-1-5-18' + [char]0) } catch { $threw = ("$($_.Exception.Message)" -match 'NUL') }
    Check 'Invoke-Engine: a NUL in the command line throws before the engine starts' $threw
    $r0 = Invoke-Native "$env:SystemRoot\System32\cmd.exe" '/c exit 0'
    Check 'Invoke-Native: a clean command line still runs' ($r0.exit -eq 0) "exit $($r0.exit)"
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
# Never trigger a signature update of the host's Defender: the idle wait and the version reads are fakes too.
function Get-DefenderVersions { [ordered]@{ source = 'fake'; av_signature = '1.463.300.0'; as_signature = '1.463.300.0'; engine = '1.1.25100.9'; platform = '4.18.25100.9'; error = $null } }
function Wait-DefenderIdle([string]$OutDir) { Ev 'defender-idle'; [ordered]@{ method = 'fake'; out_dir = $OutDir; stable = $true; current = $true; bounded = $false; before = (Get-DefenderVersions); after = (Get-DefenderVersions); attempts = @([ordered]@{ exit = 0; sec = 1.0 }) } }
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
# -Trust: the baseline trust the stub's `hello` reports. -ExactBaseline: the stub engine's kb\baselines holds the
# shipped baseline of the stub's Windows. -ExpectTrust: the host's __TRUST__.
function Invoke-FakeRunApp([string]$Scenario, [string]$Id, [string]$Run = '', [switch]$EngineMode, [string]$Fail = '', [switch]$Extra,
                           [string]$Trust = 'Exact', [switch]$ExactBaseline, [string]$ExpectTrust = '') {
    $W = Join-Path $Work "ra-$Scenario"
    foreach ($d in 'out', 'inst') { New-Item -ItemType Directory -Force (Join-Path $W $d) | Out-Null }
    if ($ExactBaseline) {
        New-Item -ItemType Directory -Force (Join-Path $W 'kb\baselines') | Out-Null
        [IO.File]::WriteAllText((Join-Path $W 'kb\baselines\professional-26340.9882.tsv.gz'), 'x')
    }
    . (Join-Path $Vm 'rig.ps1')
    . (Join-Path $Guest 'apps.ps1')
    $mainKey = 'Fake-' + [IO.Path]::GetFileNameWithoutExtension((Get-App $Id).file)
    $sd = New-StubEngine $W $mainKey $Trust
    [IO.File]::WriteAllText((Join-Path $W 'fakes.ps1'), $Fakes.Replace('@W@', $W), (New-Object System.Text.UTF8Encoding($true)))
    if (-not $Run) { $Run = $Id }
    $text = New-RunJobText -Id $Id -Run $Run -Engine:$EngineMode -Extra:$Extra -ExpectTrust $ExpectTrust
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

$M0Phases = 'edge-pause setup defender-idle arp0 lists0 snap0 install detect launch lists1 snap1 uninstall lists2 snap2 edge-check entries'
# Engine inventory right after the lists of the same point (RIG.md §4a capture order).
$EnginePhases = 'edge-pause setup defender-idle arp0 lists0 snap0 install detect launch lists1 engine-inventory-1 snap1 engine-hello engine-harvest uninstall lists2 engine-inventory-2 snap2 edge-check entries engine-scan'

& {
    $ErrorActionPreference = 'Stop'
    # M0 mode: unchanged vendor path, no engine call.
    $r = Invoke-FakeRunApp 'm0' 'npp'
    Check 'run-app M0: exit 0, M0 phase order' ($r.code -eq 0 -and ($r.phases -join ' ') -eq $M0Phases) "exit $($r.code); phases: $($r.phases -join ' ')`n$($r.out)"
    Check 'run-app M0: vendor uninstall, no engine call, no engine record' ($r.engine.Count -eq 0 -and ($r.events -contains 'start:uninst-npp.exe /S') -and -not ($r.run.PSObject.Properties.Name -contains 'engine') -and $r.run.uninstall.entry_gone -eq $true) (Steps $r)
    Check 'run-app M0: every tree wait has the PID-reuse guard (-Preexisting)' (-not ($r.events -contains 'waittree:no-preexisting')) ($r.events -join ' | ')
    Check 'run-app M0: outputs under the app id, installer ran elevated' ((Files $r.dir) -eq 'lists-npp-0.json,lists-npp-1.json,lists-npp-2.json,run.json,run.log,snap-npp-0.tsv.gz,snap-npp-1.tsv.gz,snap-npp-2.tsv.gz' -and $r.run.install.ran_as -eq 'elevated') (Files $r.dir)

    # Review R4d S4 / N5: a pinned app (temurin, apps.ps1 sha256) whose file does not hash to the pin (the fake
    # Get-FileInfoRecord gives 'FAKE'): setup fails, the record names no installer, the install phase refuses and
    # nothing is installed.
    $r = Invoke-FakeRunApp 'pin' 'temurin'
    Check 'run-app pin mismatch: setup and install fail, no installer recorded, nothing installed' (
        $r.code -eq 1 -and ($r.failed -contains 'setup') -and ($r.failed -contains 'install') -and -not $r.run.installer -and
        -not @($r.events | Where-Object { $_ -match '^start:msiexec\.exe /i' -or $_ -match 'temurin21' }).Count -and
        (@($r.run.phases) | Where-Object { $_.name -eq 'install' }).error -match 'no installer') "exit $($r.code); failed: $($r.failed -join ','); installer: $($r.run.installer); $($r.events -join ' | ')"

    # Engine mode, every call ok.
    $r = Invoke-FakeRunApp 'engine' 'npp' 'r0-npp' -EngineMode
    Check 'run-app engine: exit 0, documented phase order' ($r.code -eq 0 -and ($r.phases -join ' ') -eq $EnginePhases) "exit $($r.code); phases: $($r.phases -join ' ')`n$($r.out)"
    Check 'run-app engine: captures and engine calls in order' ((Steps $r) -eq 'lists:0 snap:0 start:npp.exe medium:PurgeRigLaunch:app.exe lists:1 engine:inventory snap:1 engine:hello engine:harvest engine:uninstall lists:2 engine:inventory snap:2 engine:scan') (Steps $r)
    Check 'run-app engine: Edge pause is the first event, before any capture' ($r.events[0] -eq 'edge-pause' -and $r.run.edge_pause.held -eq $true -and $r.run.edge_pause.versions_end) ($r.events -join ' | ')
    Check 'run-app engine: outputs under the prefixed run name only' ((Files $r.dir) -eq 'engine-hello.json,engine-run.json,fp.json,inv-1.json,inv-2.json,lists-r0-npp-0.json,lists-r0-npp-1.json,lists-r0-npp-2.json,plan-purge.json,plan-purge.scan.json,run.json,run.log,snap-r0-npp-0.tsv.gz,snap-r0-npp-1.tsv.gz,snap-r0-npp-2.tsv.gz' -and -not (Test-Path (Join-Path $r.outRoot 'npp'))) (Files $r.dir)
    Check 'run-app engine: no extra checks without -Extra' (-not ($r.run.PSObject.Properties.Name -contains 'extra') -and -not ($r.engine -match '--mode external')) ($r.engine -join ' | ')
    Check 'run-app engine: run.json names run r0-npp of app npp' ($r.run.run -eq 'r0-npp' -and $r.run.id -eq 'npp')
    Check 'run-app engine: Defender idle before the captures, versions recorded at snap 0 and snap 2' ((@($r.events | Where-Object { $_ -match '^(defender-idle|lists:0|snap:0)$' }) -join ' ') -eq 'defender-idle lists:0 snap:0' -and $r.run.defender.idle.stable -eq $true -and $r.run.defender.idle.out_dir -eq $r.dir -and $r.run.defender.snap0.av_signature -eq '1.463.300.0' -and $r.run.defender.snap2.av_signature -eq '1.463.300.0') (($r.events -join ' | ') + ' ' + ($r.run.defender | ConvertTo-Json -Depth 4 -Compress))
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
    Check 'run-app engine: six engine calls recorded' ((@($r.run.engine.calls) | ForEach-Object { $_.step }) -join ',' -eq 'inventory-1,hello,harvest,uninstall,inventory-2,scan') ((@($r.run.engine.calls) | ForEach-Object { $_.step }) -join ',')
    # engine.hello (review BL-R1 M1). No baseline in the stub's kb\baselines and no -ExpectTrust: recorded only.
    $eh = $r.run.engine.hello
    Check 'run-app engine: hello recorded, nothing expected without the exact baseline' ($eh.baseline_trust -eq 'Exact' -and $eh.baseline_view -eq 'Professional-26340.9882' -and $eh.elevated -eq $true -and $eh.expected -eq '' -and $eh.ok -eq $true -and (Test-Path (Join-Path $r.dir 'engine-hello.json'))) ($eh | ConvertTo-Json -Compress)

    # The engine has this Windows' shipped baseline: the run is an exact run, and hello must say Exact.
    $r = Invoke-FakeRunApp 'hello-exact' 'npp' 'r0-npp' -EngineMode -ExactBaseline
    Check 'run-app hello: exact baseline pushed, trust Exact -> run ok' ($r.code -eq 0 -and -not $r.failed.Count -and $r.run.engine.hello.expected -eq 'exact' -and $r.run.engine.hello.ok -eq $true) "exit $($r.code); failed: $($r.failed -join ','); $($r.run.engine.hello | ConvertTo-Json -Compress)"
    $r = Invoke-FakeRunApp 'hello-dropped' 'npp' 'r0-npp' -EngineMode -ExactBaseline -Trust 'None'
    $ph = @($r.run.phases) | Where-Object { $_.name -eq 'engine-hello' }
    Check 'run-app hello: exact baseline pushed, trust None -> engine-hello fails, the run fails' ($r.code -eq 1 -and ($r.failed -join ',') -eq 'engine-hello' -and $r.run.engine.hello.ok -eq $false -and $ph.error -match "baseline_trust 'None'; this run is for 'exact'") "exit $($r.code); failed: $($r.failed -join ','); $($ph.error)"
    Check 'run-app hello: a failed engine-hello does not stop the harvest, the captures or the scan' (($r.phases -join ' ') -eq $EnginePhases -and (Steps $r) -match 'engine:hello engine:harvest engine:uninstall lists:2 engine:inventory snap:2 engine:scan$') (Steps $r)
    # The host names the trust: a hidden-baseline run.
    $r = Invoke-FakeRunApp 'hello-hidden' 'npp' 'r0-npp' -EngineMode -Trust 'Merged' -ExpectTrust 'below-exact'
    Check 'run-app hello: -ExpectTrust below-exact, trust Merged -> ok' ($r.code -eq 0 -and $r.run.engine.hello.expected -eq 'below-exact' -and $r.run.engine.hello.asked -eq 'below-exact' -and $r.run.engine.hello.baseline_trust -eq 'Merged') "exit $($r.code); $($r.run.engine.hello | ConvertTo-Json -Compress)"
    $r = Invoke-FakeRunApp 'hello-not-hidden' 'npp' 'r0-npp' -EngineMode -Trust 'Exact' -ExpectTrust 'below-exact'
    Check 'run-app hello: -ExpectTrust below-exact, trust Exact -> fails' ($r.code -eq 1 -and ($r.failed -join ',') -eq 'engine-hello') "exit $($r.code); failed: $($r.failed -join ',')"
    $r = Invoke-FakeRunApp 'hello-merged' 'npp' 'r0-npp' -EngineMode -Trust 'None' -ExpectTrust 'merged'
    Check 'run-app hello: -ExpectTrust merged, trust None -> fails' ($r.code -eq 1 -and ($r.failed -join ',') -eq 'engine-hello') "exit $($r.code); failed: $($r.failed -join ',')"

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
    $x0Phases = 'edge-pause setup plant-pre defender-idle arp0 lists0 snap0 install detect launch plant-post lists1 engine-inventory-1 snap1 engine-hello engine-harvest engine-scan-live uninstall lists2 engine-inventory-2 snap2 edge-check entries engine-scan engine-scan-repeat'
    Check 'run-app x0 npp-userfiles: exit 0, plant and extra-check phases in order' ($r.code -eq 0 -and ($r.phases -join ' ') -eq $x0Phases) "exit $($r.code); $($r.phases -join ' ')`n$($r.out)"
    $ev = @($r.events | Where-Object { $_ -match '^(lists:|snap:|plant:|medium:)' }) -join ' '
    Check 'run-app x0 npp-userfiles: plant-pre before lists 0, plant-post after the launch and before lists 1' ($ev -eq 'plant:plant-pre:Plant-NppPortable lists:0 snap:0 medium:PurgeRigLaunch:app.exe plant:plant-post:Plant-NppUserFiles lists:1 snap:1 lists:2 snap:2') $ev
    Check 'run-app x0 npp-userfiles: planted[] in run.json with the phase of each item' ((@($r.run.planted) | ForEach-Object { "$($_.phase)=$($_.target)" }) -join ',' -eq 'plant-pre=P:C:\fake\Plant-NppPortable.txt,plant-post=P:C:\fake\Plant-NppUserFiles.txt') ((@($r.run.planted) | ForEach-Object { "$($_.phase)=$($_.target)" }) -join ',')
    Check 'run-app x0 npp-userfiles: live scan (--mode external, plan-live.json) after the harvest, before the uninstall' (
        ($r.engine -contains ('engine:scan --fp ' + (Join-Path $r.dir 'fp.json') + ' --mode external --app npp-userfiles -o ' + (Join-Path $r.dir 'plan-live.json'))) -and
        ((Steps $r) -match 'engine:harvest engine:scan engine:uninstall')) ($r.engine -join ' | ')
    $x = $r.run.extra
    Check 'run-app x0 npp-userfiles: extra record (live counts, root band, det_equal by plan hash)' ($x.live_items -eq 1 -and $x.live_safe -eq 0 -and $x.live_preselected -eq 0 -and (@($x.live_root_band) -join ',') -eq 'Likely' -and $x.det_equal -eq $true -and $x.det_how -eq 'plan_hash' -and $x.plan_a -eq 'abc123') ($x | ConvertTo-Json -Compress)
    Check 'run-app x0 npp-userfiles: repeat scan writes plan-purge-b.json' ((Test-Path (Join-Path $r.dir 'plan-purge-b.json')) -and ((@($r.run.engine.calls) | ForEach-Object { $_.step }) -join ',') -eq 'inventory-1,hello,harvest,scan-live,uninstall,inventory-2,scan,scan-repeat') ((@($r.run.engine.calls) | ForEach-Object { $_.step }) -join ',')

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
    # The guest: every guestcontrol call succeeds, except the write probe of kb\baselines when the tree is
    # "protected"; an engine-tree job is recorded as a call and answers with $script:TreeJobLog.
    $script:TreeProtected = $false
    $script:TreeJobLog = { param($Action) "ENGINE-TREE $Action OK" }
    function Invoke-Guest([string[]]$Sub) {
        [void]$script:GuestCalls.Add($Sub -join ' ')
        $code = 0
        if ($script:TreeProtected -and ($Sub -join ' ') -eq 'mkdir C:\cr\bin\kb\baselines\.rig-probe') { $code = 1 }
        [pscustomobject]@{ code = $code; out = @() }
    }
    function Invoke-GuestCmd([string]$CommandLine, [int]$TimeoutSec = 120) { [void]$script:GuestCalls.Add("cmd $CommandLine"); [pscustomobject]@{ code = 0; out = @() } }
    function Invoke-GuestJob { param($Text, $Name, $TimeoutSec, $LogCopy)
        $action = $Name -replace '^engine-tree-', ''
        [void]$script:GuestCalls.Add("job $Name")
        $script:LastTreeJob = $Text
        if ($action -eq 'open') { $script:TreeProtected = $false }
        [pscustomobject]@{ name = $Name; done = $true; seconds = 1; log = (& $script:TreeJobLog $action); log_file = '' }
    }
    $rt = Join-Path $H 'rigtool.exe'; [IO.File]::WriteAllText($rt, 'MZ')
    Push-Tools -RigTool $rt
    $gc = $script:GuestCalls -join "`n"
    # Review BL-R1 M1: the baseline tree is protected by an elevated job after the last copy into it.
    $calls = @($script:GuestCalls)
    $lastCopy = -1; for ($i = 0; $i -lt $calls.Count; $i++) { if ($calls[$i] -like 'copyto --target-directory C:\cr\bin\*') { $lastCopy = $i } }
    Check 'Push-Tools with an engine: one protect job, after the copies, no open job on a fresh tree' (
        @($calls | Where-Object { $_ -eq 'job engine-tree-protect' }).Count -eq 1 -and -not ($calls -contains 'job engine-tree-open') -and
        [array]::IndexOf($calls, 'job engine-tree-protect') -gt $lastCopy -and $lastCopy -ge 0 -and
        [array]::IndexOf($calls, 'mkdir C:\cr\bin\kb\baselines\.rig-probe') -lt [array]::IndexOf($calls, 'mkdir --parents C:\cr\bin')) $gc
    $perr = $null; $null = [Management.Automation.Language.Parser]::ParseInput($script:LastTreeJob, [ref]$null, [ref]$perr)
    Check 'Push-Tools: the protect job is guest\engine-tree.ps1 plus one call, and parses' (@($perr).Count -eq 0 -and $script:LastTreeJob.Contains('function Protect-RigEngineTree') -and $script:LastTreeJob.TrimEnd().EndsWith('Invoke-RigEngineTreeJob -Action protect')) ($script:LastTreeJob.Substring([Math]::Max(0, $script:LastTreeJob.Length - 120)))
    # A second push without a restore: the tree is protected, so it is opened before the unelevated copies.
    $script:TreeProtected = $true; $script:GuestCalls.Clear()
    Push-Tools -RigTool $rt
    $calls = @($script:GuestCalls)
    Check 'Push-Tools on a protected tree: open job first, then the copies, then protect' (
        [array]::IndexOf($calls, 'job engine-tree-open') -ge 0 -and [array]::IndexOf($calls, 'job engine-tree-open') -lt [array]::IndexOf($calls, 'mkdir --parents C:\cr\bin') -and
        [array]::IndexOf($calls, 'job engine-tree-protect') -gt [array]::IndexOf($calls, 'job engine-tree-open')) ($calls -join "`n")
    # The guest job says the tree does not pass the rule: the push fails, so no run starts on it.
    $script:TreeJobLog = { param($Action) "ENGINE-TREE $Action FAILED: C:\cr: S-1-5-11 may write (mask 0x10000)" }
    $msg = $null; try { Push-Tools -RigTool $rt } catch { $msg = $_.Exception.Message }
    Check 'Push-Tools: a protect job that fails throws with the reason' ($msg -match 'engine tree protect failed' -and $msg -match 'S-1-5-11 may write') "got '$msg'"
    $script:TreeJobLog = { param($Action) '' }
    $msg = $null; try { Push-Tools -RigTool $rt } catch { $msg = $_.Exception.Message }
    Check 'Push-Tools: a protect job without the OK line throws' ($msg -match 'engine tree protect failed') "got '$msg'"
    $script:TreeJobLog = { param($Action) "ENGINE-TREE $Action OK" }
    Check 'Test-EngineTreeLog: only the OK line of that action counts' ((Test-EngineTreeLog "x`r`nENGINE-TREE protect OK`r`n" 'protect') -and -not (Test-EngineTreeLog 'ENGINE-TREE open OK' 'protect') -and -not (Test-EngineTreeLog 'ENGINE-TREE protect FAILED: ENGINE-TREE protect OK' 'protect'))
    $script:GuestCalls.Clear()
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
    Check 'Push-Tools without an engine: no engine-tree job' (-not ($gc -match 'job engine-tree')) $gc
    $msg = $null; try { Push-Tools -RigTool $rt -Engine (Join-Path $H 'missing.exe') } catch { $msg = $_.Exception.Message }
    Check 'Push-Tools -Engine <missing> throws' ($msg -match 'purge-engine not found') "got '$msg'"
    [IO.File]::WriteAllText($eng, 'MZ fake')
    $script:GuestCalls.Clear()
    Push-Tools -RigTool $rt -NoBaselines
    $gc = $script:GuestCalls -join "`n"
    Check 'Push-Tools -NoBaselines: engine pushed, old baselines deleted, none copied' ($gc.Contains("copyto --target-directory C:\cr\bin\ $eng") -and $gc.Contains('C:\cr\bin\kb\baselines\*.tsv.gz') -and -not ($gc -match 'copyto[^\n]*baselines')) $gc
    Check 'Push-Tools -NoBaselines: the (empty) baseline tree is protected all the same' ($gc -match 'job engine-tree-protect') $gc
    # BL-GATE R4: -HideExact pushes the neighbour and view.json, never the VM's own baseline.
    $savedVm = $script:VmName; $script:VmName = 'Purge-CleanPro'
    [IO.File]::WriteAllText((Join-Path $repo 'kb\baselines\view.json'), '{}')
    $script:GuestCalls.Clear()
    Push-Tools -RigTool $rt -HideExact
    $gc = $script:GuestCalls -join "`n"
    Check 'Push-Tools -HideExact: neighbour + view.json pushed, the exact baseline not, then protected' (
        $gc.Contains("copyto --target-directory C:\cr\bin\kb\baselines\ $(Join-Path $repo 'kb\baselines\EnterpriseS-26100.1742.tsv.gz') $(Join-Path $repo 'kb\baselines\view.json')") -and
        -not ($gc -match 'copyto[^\n]*Professional-26340') -and $gc.Contains('stat C:\cr\bin\kb\baselines\view.json') -and ($gc -match 'job engine-tree-protect')) $gc
    $msg = $null; try { Push-Tools -RigTool $rt -HideExact -NoBaselines } catch { $msg = $_.Exception.Message }
    Check 'Push-Tools -HideExact -NoBaselines refused' ($msg -match 'exclude each other') "got '$msg'"
    $script:VmName = 'Inbound-Win11-Test'
    $msg = $null; try { Push-Tools -RigTool $rt -HideExact } catch { $msg = $_.Exception.Message }
    Check 'Push-Tools -HideExact: refused when the VM''s exact baseline is not there to hide' ($msg -match 'no EnterpriseSEval-26100.1742.tsv.gz to hide') "got '$msg'"
    $script:VmName = $savedVm
    Remove-Item -LiteralPath (Join-Path $repo 'kb\baselines\view.json')
    Check 'Get-RigExactBaseline: both rig VMs, others refused' ((Get-RigExactBaseline 'Inbound-Win11-Test') -ceq 'EnterpriseSEval-26100.1742' -and (Get-RigExactBaseline 'Purge-CleanPro') -ceq 'Professional-26340.9882' -and $(try { $null = Get-RigExactBaseline 'X'; $false } catch { $true }))
    Check 'Test-RigTrustAnswer: below-exact takes merged/local/none, exact only exact' ($null -eq (Test-RigTrustAnswer 'below-exact' 'Merged') -and $null -eq (Test-RigTrustAnswer 'local' 'Local') -and $null -eq (Test-RigTrustAnswer '' 'None') -and (Test-RigTrustAnswer 'below-exact' 'Exact') -and (Test-RigTrustAnswer 'merged' 'None'))
    $djt = New-DataRootJobText; $perr = $null; $null = [Management.Automation.Language.Parser]::ParseInput($djt, [ref]$null, [ref]$perr)
    Check 'New-DataRootJobText: parses, install.ps1 -DataRootOnly, warm-up harvest, hello, DATA-ROOT line' (@($perr).Count -eq 0 -and $djt.Contains("install.ps1' -DataRootOnly") -and $djt.Contains(' harvest ') -and $djt.Contains(' hello ') -and $djt.Contains('DATA-ROOT OK baseline_trust=') -and $djt.Contains('AutoDownload -Value 2') -and $djt.IndexOf('AutoDownload') -lt $djt.IndexOf(' harvest '))
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
    $m = $null; try { $null = Get-M2AmbientFile 'Some-Other-VM' } catch { $m = $_.Exception.Message }
    Check 'Get-M2AmbientFile: one ambient set per rig VM, none for another VM' ((Split-Path -Leaf (Get-M2AmbientFile 'Inbound-Win11-Test')) -ceq 'm2-ambient.json' -and (Split-Path -Leaf (Get-M2AmbientFile 'Purge-CleanPro')) -ceq 'm2-ambient-cleanpro.json' -and $m -match 'no M2 ambient set') $m
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
function Wait-M2BootSettle([int]$MaxSec = 300, [int]$AfterSec = 5, [int]$PollSec = 3, [int]$MinUptimeSec = 180) { Ev "settle:${MaxSec}:${MinUptimeSec}"; [ordered]@{ session = 'ReadyBoot'; stopped = $true; bounded = $false } }
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
function Set-RigBootPolicyIgnoreFailures { Ev 'boot-policy'; [ordered]@{ fake = 0 } }
function Save-RigDurableState([string]$Sid = '') { Ev 'durable-state'; [ordered]@{ volume = 'fake'; hives = [ordered]@{} } }
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
    Check 'null run: the boot settle wait runs right before snap A, like a real run' (@($ev -match '^settle:').Count -eq 1 -and [array]::IndexOf($ev, 'settle:300:180') -eq [array]::IndexOf($ev, 'snap:snap-n1-m2-fidelity-a.tsv.gz') - 1 -and $j.results.settle.start.stopped -eq $true) (($ev | Select-Object -First 12) -join ' | ')
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
    $script:PwNames = New-Object System.Collections.ArrayList
    function Invoke-GuestJob { param($Text, $Name, $TimeoutSec, $LogCopy) [IO.File]::WriteAllText($LogCopy, 'log'); $script:PwJobs++; [void]$script:PwNames.Add($Name)
        if ($script:PwJobs -eq 1) { [IO.File]::WriteAllText((Join-Path $cont 'continue.json'), '{"schema":"purge.rig.continue/1","seq":1,"kind":"poweroff","next":"after-poweroff","boot_before":"boot-x"}') } else { Remove-Item -LiteralPath (Join-Path $cont 'continue.json') -Force -ErrorAction SilentlyContinue }
        [pscustomobject]@{ name = $Name; done = $true; seconds = 1; log = ''; log_file = $LogCopy } }
    $script:PwJobs = 0; $script:M2Guest.Clear()
    $r = Invoke-M2Job -Run 'pw-run' -Mode 'm2-crash'
    Check 'Invoke-M2Job: a poweroff continuation without -HardPowerOff stops with an error' ($r.error -match 'HardPowerOff' -and -not ($script:M2Guest -contains 'hard power cycle'))
    $script:PwJobs = 0; $script:M2Guest.Clear(); $script:PwNames.Clear()
    $r = Invoke-M2Job -Run 'pw-run' -Mode 'm2-crash' -HardPowerOff
    Check 'Invoke-M2Job -HardPowerOff: power cycle, then stage after-poweroff' (-not $r.error -and $r.done -and ($script:M2Guest -contains 'hard power cycle') -and (@($r.stages | ForEach-Object { $_.stage }) -join ',') -eq 'start,after-poweroff')
    Check 'Invoke-M2Job -HardPowerOff: the run files are synced to disk by a guest job before the power cycle' ((@($script:PwNames) -join ',') -eq 'pw-run-start,pw-run-sync,pw-run-after-poweroff') (@($script:PwNames) -join ',')
    function Invoke-GuestJob { param($Text, $Name, $TimeoutSec, $LogCopy) [IO.File]::WriteAllText($LogCopy, 'log'); [IO.File]::WriteAllText((Join-Path $cont 'continue.json'), '{"seq":1,"kind":"reboot","next":"matrix","boot_before":"b"}'); [pscustomobject]@{ name = $Name; done = $true; seconds = 1; log = ''; log_file = $LogCopy } }
    $r = Invoke-M2Job -Run 'pw-run' -Mode 'm2-crash'
    Check 'Invoke-M2Job: a marker the next stage does not take (same seq twice) stops the loop' ($r.error -match 'seen twice' -and @($r.stages).Count -eq 2)

    if ($env:RIG_SELFTEST_M2_OUT) {
        New-Item -ItemType Directory -Force $env:RIG_SELFTEST_M2_OUT | Out-Null
        Copy-Item -Path (Join-Path $script:RunsDir '*') -Destination $env:RIG_SELFTEST_M2_OUT -Recurse -Force
        Write-Host "M2 stub runs copied to $env:RIG_SELFTEST_M2_OUT"
    }
}

# ------------------------------------------------------- M3 security modes (rig-m3.ps1 section 14 helpers)
& {
    . (Join-Path $Vm 'rig-m3.ps1')
    $ErrorActionPreference = 'Stop'
    $expect = Join-Path $Vm 'truth\m3-sec-expect.json'
    $ids = @(Get-M3SecCaseIds -ExpectFile $expect)
    $x = Get-Content -LiteralPath $expect -Raw | ConvertFrom-Json
    Check 'm3-sec: the case list is the expectations list, in order' ((($ids) -join ',') -eq (@($x.broker.cases | ForEach-Object { $_.id }) -join ','))
    Check 'm3-sec: case ids are unique' (@($ids | Sort-Object -Unique).Count -eq $ids.Count)
    Check 'm3-sec: every exit code 20-26 has a case, 27 is excluded with a reason' ((@(20..26 | Where-Object { @($x.broker.cases | ForEach-Object { [int]$_.exit }) -notcontains $_ }).Count -eq 0) -and (@($x.broker.excluded | Where-Object { [int]$_.exit -eq 27 -and $_.why }).Count -eq 1))
    Check 'm3-sec: -Cases keeps the named cases in list order' ((@(Get-M3SecCaseIds -ExpectFile $expect -Only @('junction', 'start-ok')) -join ',') -eq 'start-ok,junction')
    $threw = $false; try { $null = Get-M3SecCaseIds -ExpectFile $expect -Only @('no-such-case') } catch { $threw = $true }
    Check 'm3-sec: an unknown -Cases name throws' $threw
    Check 'm3-sec: base snapshots' ((Get-M3SecBase 'm3-broker') -eq 'rig-base' -and (Get-M3SecBase 'm3-consent') -eq 'rig-base' -and (Get-M3SecBase 'm3-uac') -eq 'm3-uac-on' -and (Get-M3SecBase 'm3-uac' 'x') -eq 'x')
    Check 'm3-sec: phase job text' ((New-M3SecPhaseText 'consent-attack' '3' 'sendinput-key' 300) -eq "& 'C:\cr\guest\m3-sec.ps1' -Phase 'consent-attack' -Tag '3' -Method 'sendinput-key' -WaitSec 300")
    $threw = $false; try { $null = New-M3SecPhaseText 'broker-case' "x'; Remove-Item C:\" } catch { $threw = $true }
    Check 'm3-sec: a tag with quotes is refused' $threw
    $ev = Join-Path $Work 'm3-evidence'
    Check 'm3-sec: no evidence dir, nothing moved' ($null -eq (Move-M3EvidenceAside $ev))
    New-Item -ItemType Directory -Force $ev | Out-Null
    Check 'm3-sec: an empty evidence dir stays' ($null -eq (Move-M3EvidenceAside $ev) -and (Test-Path -LiteralPath $ev))
    [IO.File]::WriteAllText((Join-Path $ev 'summary.json'), '{}')
    $to = Move-M3EvidenceAside $ev
    Check 'm3-sec: an evidence dir with files is moved aside' ($to -and -not (Test-Path -LiteralPath $ev) -and (Test-Path -LiteralPath (Join-Path $to 'summary.json')))
    # The payload's UI (New-M3SecPayload): the Rust Purge.exe alone, given as the file or as a cargo release folder
    # (never its engine, broker or build files); the WinUI publish folder (Purge.pri beside Purge.exe) whole.
    $pw = Join-Path $Work 'm3-payload'
    $rel = Join-Path $pw 'release'; $pub = Join-Path $pw 'ui-publish'
    New-Item -ItemType Directory -Force $rel, (Join-Path $pub 'de-DE') | Out-Null
    foreach ($n in 'purge-engine.exe', 'purge-broker.exe', 'Purge.exe', 'Purge.pdb', 'xtask.exe') { [IO.File]::WriteAllText((Join-Path $rel $n), $n) }
    foreach ($n in 'Purge.exe', 'Purge.pri', 'Microsoft.WindowsAppRuntime.dll', 'de-DE\Purge.resources.dll') { [IO.File]::WriteAllText((Join-Path $pub $n), "winui $n") }
    function Get-HostTemp { $pw }
    function Write-RigLog([string]$Message) { }
    $M3.engine = Join-Path $rel 'purge-engine.exe'; $M3.broker = Join-Path $rel 'purge-broker.exe'
    $uiOf = {
        param($Ui)
        $M3.ui = $Ui
        $z = New-M3SecPayload
        $x = Join-Path $pw ("x-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        Expand-Archive -LiteralPath $z -DestinationPath $x
        Remove-Item -LiteralPath $z -Force
        @(Get-ChildItem -LiteralPath (Join-Path $x 'ui') -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName.Substring((Join-Path $x 'ui').Length + 1) } | Sort-Object)
    }
    $a = & $uiOf (Join-Path $rel 'Purge.exe'); $b = & $uiOf $rel; $c = & $uiOf $pub
    Check 'm3 payload: the Rust UI is ui\Purge.exe alone, as a file or from a cargo release folder' (($a -join ',') -ceq 'Purge.exe' -and ($b -join ',') -ceq 'Purge.exe' -and
        [IO.File]::ReadAllText((Join-Path $rel 'Purge.exe')) -eq 'Purge.exe')
    Check 'm3 payload: the WinUI publish folder (Purge.pri beside Purge.exe) goes whole' (($c -join ',') -ceq (@('de-DE\Purge.resources.dll', 'Microsoft.WindowsAppRuntime.dll', 'Purge.exe', 'Purge.pri') -join ',') -and
        (Test-M3WinUiPublish (Join-Path $pub 'Purge.exe')) -and -not (Test-M3WinUiPublish (Join-Path $rel 'Purge.exe')))
    $M3.engine = ''; $M3.broker = ''; $M3.ui = ''
    # The guest script knows every case of the list (each id has its own switch branch or pattern).
    $guestText = [IO.File]::ReadAllText((Join-Path $Guest 'm3-sec.ps1'))
    $unknown = @($ids | Where-Object { $guestText -notmatch ("'" + [regex]::Escape($_) + "'") })
    Check 'm3-sec: m3-sec.ps1 has a branch for every case' ($unknown.Count -eq 0) ($unknown -join ', ')
    # Ruling 2026-11-22: m3-broker / m3-consent make UAC silent themselves (rig-base is at the defaults) and record it.
    $startText = (Get-Command Start-M3Sec).Definition
    Check 'm3-sec: uac-silent is a guest phase that records before/after and sets only ConsentPromptBehaviorAdmin=0' (
        $guestText -match "(?m)^\s+'uac-silent' \{" -and $guestText -match "Name 'ConsentPromptBehaviorAdmin' -Value 0" -and $guestText -match "uac_silent = \(Read-Json \(Join-Path \`$Out 'uac-silent.json'\)\)" -and
        $guestText -notmatch "Name 'EnableLUA' -Value")
    $recHost = [IO.File]::ReadAllText((Join-Path $Vm 'rig-m3-recover.ps1'))
    $recGuest = [IO.File]::ReadAllText((Join-Path $Guest 'm3-recover.ps1'))
    Check 'm3-recover: uac-silent before uac-check in Initialize-RecGuest; sr-enable at m3-extras start; both guest phases record' (
        $recHost -match "(?s)function Initialize-RecGuest.*?Invoke-RecPhase 'uac-silent'.*?Invoke-RecPhase 'uac-check'.*?Assert-M3SecUac \`$u 0" -and
        $recHost -match "(?s)function Invoke-RecExtras.*?Initialize-RecGuest.*?Invoke-RecPhase 'sr-enable'.*?Invoke-RecPhase 'sr'" -and
        $recGuest -match "(?m)^\s+'uac-silent' \{" -and $recGuest -match "(?m)^\s+'sr-enable' \{" -and $recGuest -match "Enable-ComputerRestore -Drive 'C:\\' -ErrorAction Stop" -and
        $recGuest -match "sr_enable = \(Read-Json \(Join-Path \`$Out 'sr-enable.json'\)\)")
    Check 'm3-sec: Start-M3Sec runs uac-silent for m3-broker / m3-consent and keeps the 5 check for m3-uac' (
        $startText -match "Invoke-M3SecPhase 'uac-silent'" -and $startText -match "Assert-M3SecUac \`$u 5" -and $startText -match "Invoke-M3SecPhase 'uac-check' 'silent'")
    Check 'm3-sec: m3sec.cs is ASCII (csc reads it in the guest code page)' (-not ([IO.File]::ReadAllText((Join-Path $Guest 'm3sec.cs')) -match '[^\x00-\x7F]'))
}

# ------------------------------------------------------------------------- m3-e2e (rig-m3.ps1, RIG.md section 17)
& {
    . (Join-Path $Vm 'rig-m3.ps1')
    $ErrorActionPreference = 'Stop'
    $expect = Join-Path $Vm 'truth\m3-e2e-expect.json'
    $x = Get-Content -LiteralPath $expect -Raw | ConvertFrom-Json
    $ids = @(Get-M3E2eApps -ExpectFile $expect | ForEach-Object { "$($_.id)" })
    Check 'm3-e2e: the app list is the expectations list, in order' (($ids -join ',') -eq 'vscode,vscode-user,git,firefox-tb,npp,7zip,execapp,msi1603,msi3010') ($ids -join ',')
    Check 'm3-e2e: seven executing apps (G6), the two failing uninstallers' (@($x.apps | Where-Object { $_.kind -in 'app', 'fixture' }).Count -eq 7 -and @($x.apps | Where-Object { $_.kind -like 'fail-*' }).Count -eq 2)
    Check 'm3-e2e: exactly one medium-route app (vscode-user)' ((@($x.apps | Where-Object { $_.route -eq 'medium' } | ForEach-Object { $_.id }) -join ',') -eq 'vscode-user')
    Check 'm3-e2e: the design gates (harvest 2x the walk floor and 20 s, scan 1.5x the walk floor and 20 s, 100 ms)' ([double]$x.gates.harvest_floor_factor -eq 2 -and [int]$x.gates.harvest_cap_ms -eq 20000 -and -not $x.gates.PSObject.Properties['harvest_after_uac_ms'] -and
        [double]$x.gates.scan_floor_factor -eq 1.5 -and [int]$x.gates.scan_cap_ms -eq 20000 -and -not $x.gates.PSObject.Properties['scan_ms'] -and [int]$x.gates.first_progress_ms -eq 100)
    Check 'm3-e2e: -Apps keeps the named apps in list order' ((@(Get-M3E2eApps -ExpectFile $expect -Only @('msi1603', 'npp') | ForEach-Object { $_.id }) -join ',') -eq 'npp,msi1603')
    $threw = $false; try { $null = Get-M3E2eApps -ExpectFile $expect -Only @('nope') } catch { $threw = $true }
    Check 'm3-e2e: an unknown -Apps name throws' $threw
    Check 'm3-e2e: undo apps default to the expectations (execapp: service + task restore)' ((@(Get-M3E2eUndoApps -ExpectFile $expect) -join ',') -eq 'execapp')
    $threw = $false; try { $null = Get-M3E2eUndoApps -ExpectFile $expect -Override @('msi1603') } catch { $threw = $true }
    Check 'm3-e2e: a failing uninstaller cannot be an undo app' $threw
    Check 'm3-e2e: phase job text' ((New-M3E2ePhaseText 'consent-wait' 'npp' 'plan' 300) -eq "& 'C:\cr\guest\m3-e2e.ps1' -Phase 'consent-wait' -App 'npp' -Step 'plan' -WaitSec 300")
    $threw = $false; try { $null = New-M3E2ePhaseText 'prepare' "npp'; Remove-Item C:\" } catch { $threw = $true }
    Check 'm3-e2e: an app with quotes is refused' $threw
    # The host's screenshot list and the scorer's required list agree for every app, with and without undo.
    $sc = & { . (Join-Path $Vm 'truth\m3-e2e-score.ps1'); ${function:Get-E2eShotNames} }
    $diff = @()
    foreach ($a in $x.apps) { foreach ($u in $true, $false) { foreach ($e in $true, $false) { if ((@(Get-M3E2eShotNames $a $u $e) -join ',') -ne (@(& $sc $a $u $e) -join ',')) { $diff += "$($a.id)/$u/$e" } } } }
    Check 'm3-e2e: host screenshot names == scorer required names (with and without undo, nothing preselected)' ($diff.Count -eq 0) ($diff -join ', ')
    Check 'm3-e2e: nothing preselected ends the shots at 07-move-waiting, undo or not' ((@(Get-M3E2eShotNames ($x.apps | Where-Object { $_.id -eq 'npp' }) $true $true) -join ',') -eq '01-programs-row,02-uninstall-clicked,03-confirm,04-consent-run,05-run-approved,06-scan-done,07-move-waiting')
    Check 'm3-e2e: broker-route apps have the consent shots, a failing one the failure shot' ((@(Get-M3E2eShotNames ($x.apps | Where-Object { $_.id -eq 'msi1603' }) $false) -join ',') -eq '01-programs-row,02-uninstall-clicked,03-confirm,04-consent-run,05-run-approved,06-scan-done,07-failure')
    # Every phase the host calls exists in the guest script's phase set.
    $guestText = [IO.File]::ReadAllText((Join-Path $Guest 'm3-e2e.ps1'))
    $hostText = [IO.File]::ReadAllText((Join-Path $Vm 'rig-m3.ps1'))
    $called = @([regex]::Matches($hostText, "Invoke-M3E2e(?:Phase|Step) '([a-z-]+)'") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $missing = @($called | Where-Object { $guestText -notmatch ("(?m)^\s+'" + [regex]::Escape($_) + "' \{") })
    Check 'm3-e2e: every phase the host calls has a guest branch' ($called.Count -ge 15 -and $missing.Count -eq 0) "called $($called.Count); missing: $($missing -join ', ')"
}

# ------------------------- m3-e2e rig fixes of 2026-11-23 (RIG.md section 17): empty plan docs, the watcher merge
& {
    . (Join-Path $Guest 'm3-e2e-ui.ps1')
    $ErrorActionPreference = 'Stop'
    $d = New-E2eEmptyExecDocs 'npp' ([uint64]134399194953885068)
    $lines = @($d.journal -split "`n" | Where-Object { $_ })
    $h = $lines[0] | ConvertFrom-Json; $c = $lines[1] | ConvertFrom-Json; $r = $d.report | ConvertFrom-Json
    Check 'm3-e2e empty plan: the rig journal is a header and a commit of zero items, session rig-empty-<app>' ($lines.Count -eq 2 -and $h.rec -ceq 'header' -and $h.schema -ceq 'purge.journal/1' -and
        $h.session -ceq 'rig-empty-npp' -and [int]$h.items -eq 0 -and @($h.volumes).Count -eq 0 -and $c.rec -ceq 'commit' -and [int]$c.counts.done -eq 0 -and $d.journal.EndsWith("`n")) $d.journal
    Check 'm3-e2e empty plan: the rig report is Committed, no items, the same session and hashes' ($r.schema -ceq 'purge.exec/1' -and $r.state -ceq 'Committed' -and @($r.items).Count -eq 0 -and
        $r.session -ceq $h.session -and $r.plan_hash -ceq $h.plan_hash -and $r.selection_hash -ceq $h.selection_hash -and $r.restore_point.kind -ceq 'NotRequested' -and $d.report -match '"items":\s*\[\s*\]')
    $threw = $false; try { $null = New-E2eEmptyExecDocs "npp'; x" 1 } catch { $threw = $true }
    Check 'm3-e2e empty plan: a bad app name is refused' $threw
    $m = @(Merge-E2eUninstallers @([pscustomobject]@{ pid = 10; name = 'unins000.exe'; il = 'high' }) @([pscustomobject]@{ pid = 10; name = 'unins000.exe'; il = 'unknown(5)' }, [pscustomobject]@{ pid = 11; name = '_iu14D2N.tmp'; il = 'high' }))
    Check 'm3-e2e watcher: the watcher''s record of a pid wins, the scan''s other pids are added' ($m.Count -eq 2 -and $m[0].il -ceq 'high' -and $m[1].pid -eq 11)
    Check 'm3-e2e watcher: nothing seen is an empty list' (@(Merge-E2eUninstallers $null @()).Count -eq 0)
}

# ------------------------------------------- rig.ps1 boot flake: Wait-Agent's stat error, Restore-Base retries once
& {
    . (Join-Path $Vm 'rig.ps1')
    $ErrorActionPreference = 'Stop'
    $script:log = New-Object System.Collections.ArrayList
    function Write-RigLog([string]$Message) { [void]$script:log.Add($Message) }
    function Invoke-Guest([string[]]$Sub) { [pscustomobject]@{ code = 1; out = @('VBoxManage.exe: error: The guest execution service is not ready (yet)') } }
    function Start-Sleep { param([int]$Seconds, [int]$Milliseconds) }
    $msg = $null; try { Wait-Agent -TimeoutSec 1 } catch { $msg = $_.Exception.Message }
    Check 'boot: Wait-Agent logs the stat error once and names it in the timeout, with the reworded hint' ($msg -match '^agent\.alive not visible within 1 s \(\d+ stats; last: exit 1: VBoxManage\.exe: error: The guest execution service is not ready \(yet\)\)' -and
        $msg -match 'rare boot flake' -and @($script:log | Where-Object { $_ -like '*agent.alive not visible yet (stat exit 1: *' }).Count -eq 1) $msg
    # Restore-Base: a boot whose agent never shows is retried once, with diagnostics each time; other errors are not.
    $script:boots = 0; $script:diags = New-Object System.Collections.ArrayList; $script:failBoots = 1; $script:otherError = $false
    function Restore-BaseOnce { param([string]$Snapshot, [int]$AgentTimeoutSec, [string]$ExecutionEngine, [switch]$No3D)
        $script:boots++
        if ($script:otherError) { throw 'snapshot restore rig-base failed' }
        if ($script:boots -le $script:failBoots) { throw 'agent.alive not visible within 300 s (x)' } }
    function Save-BootDiag([string]$Dir = '', [string]$Tag = 'boot') { [void]$script:diags.Add("$Dir|$Tag"); 'D:\diag' }
    Restore-Base -Snapshot 'rig-base' -DiagDir 'D:\ev\vscode-user'
    Check 'boot: one failed boot is retried and passes; its diagnostics go to -DiagDir' ($script:boots -eq 2 -and @($script:diags).Count -eq 1 -and $script:diags[0] -ceq 'D:\ev\vscode-user|rig-base-boot1') ("boots $script:boots; diags $($script:diags -join ', ')")
    $script:boots = 0; $script:diags.Clear(); $script:failBoots = 5
    $msg = $null; try { Restore-Base -Snapshot 'rig-base' } catch { $msg = $_.Exception.Message }
    Check 'boot: two failed boots throw, naming the tries and the diagnostics, diagnostics saved twice' ($script:boots -eq 2 -and @($script:diags).Count -eq 2 -and $msg -match 'boot tried 2 time\(s\), diagnostics in D:\\diag$') $msg
    $script:boots = 0; $script:diags.Clear(); $script:otherError = $true
    $msg = $null; try { Restore-Base -Snapshot 'rig-base' } catch { $msg = $_.Exception.Message }
    Check 'boot: an error that is no agent timeout is not retried' ($script:boots -eq 1 -and @($script:diags).Count -eq 0 -and $msg -ceq 'snapshot restore rig-base failed') $msg
}

# ------------------------------------- m3-e2e ambient set: null runs, one window, the build (RIG.md section 17.1)
& {
    . (Join-Path $Vm 'rig-m3.ps1')
    $ErrorActionPreference = 'Stop'
    $expect = Join-Path $Vm 'truth\m3-e2e-expect.json'
    # null_run_names / gate_run_names_never_null_shaped
    Check 'm3-e2e null: run names <prefix><k>-m3-e2e-<app> (default en)' ((Get-M3E2eNullRunName 1 'vscode') -ceq 'en1-m3-e2e-vscode' -and (Get-M3E2eNullRunName 12 'git' 'cpn') -ceq 'cpn12-m3-e2e-git')
    $threw = 0
    foreach ($bad in @(@(0, 'vscode', ''), @(1, 'VSCode', ''), @(1, "npp'; x", ''), @(1, 'npp', 'X'))) { try { $null = Get-M3E2eNullRunName $bad[0] $bad[1] $bad[2] } catch { $threw++ } }
    Check 'm3-e2e null: round 0, upper case, quotes, an upper-case prefix are refused' ($threw -eq 4) "$threw of 4"
    Check 'm3-e2e null: every null run name has the null shape' (@(1..12 | ForEach-Object { Get-M3E2eNullRunName $_ 'vscode-user' 'x' } | Where-Object { -not (Test-M3E2eNullRunShape $_) }).Count -eq 0)
    $threw = $false; try { Assert-M3E2eGateRunName 'en3-m3-e2e-vscode' } catch { $threw = $true }
    $ok = $true; try { Assert-M3E2eGateRunName 'e2e-20261123-065615'; Assert-M3E2eGateRunName 'gate-m3-e2e-vscode' } catch { $ok = $false }
    Check 'm3-e2e gate: a -RunName of the null shape is refused, the default and other names are not' ($threw -and $ok)
    # ambient_file_per_vm
    Check 'm3-e2e ambient: one file per VM' ((Get-M3E2eAmbientFile 'Inbound-Win11-Test') -eq (Join-Path $Vm 'truth\m3-e2e-ambient.json') -and (Get-M3E2eAmbientFile 'Purge-CleanPro') -eq (Join-Path $Vm 'truth\m3-e2e-ambient-cleanpro.json'))
    $threw = 0; foreach ($v in 'inbound-win11-test', 'Other') { try { $null = Get-M3E2eAmbientFile $v } catch { $threw++ } }
    Check 'm3-e2e ambient: another VM (or another case) has none' ($threw -eq 2)
    # ambient_build_keeps_added_records
    Check 'm3-e2e ambient: rigtool ambient --m2 --added --null <dirs> -o <out>' ((@(Get-M3E2eAmbientArgs @('a', 'b') 'o.json') -join ' ') -ceq 'ambient --m2 --added --null a b -o o.json')
    $threw = $false; try { $null = Get-M3E2eAmbientArgs @() 'o.json' } catch { $threw = $true }
    Check 'm3-e2e ambient: no run dirs throws' $threw
    # The phase text of a null run and the declared hash of a gate run.
    $sha = 'ab' * 32
    Check 'm3-e2e null: a null phase carries -NullRun' ((New-M3E2ePhaseText 'consent-cancel' 'vscode' 'plan' 10 -NullRun) -ceq "& 'C:\cr\guest\m3-e2e.ps1' -Phase 'consent-cancel' -App 'vscode' -Step 'plan' -WaitSec 10 -NullRun")
    Check 'm3-e2e gate: setup carries the pushed set''s SHA-256' ((New-M3E2ePhaseText 'setup' 'vscode' -AmbientSha $sha) -ceq "& 'C:\cr\guest\m3-e2e.ps1' -Phase 'setup' -App 'vscode' -AmbientSha '$sha'")
    $threw = 0
    foreach ($b in @({ New-M3E2ePhaseText 'setup' 'npp' -AmbientSha ('AB' * 32) }, { New-M3E2ePhaseText 'setup' 'npp' -AmbientSha "x'; y" }, { New-M3E2ePhaseText 'setup' 'npp' -AmbientSha $sha -NullRun })) { try { $null = & $b } catch { $threw++ } }
    Check 'm3-e2e: a bad SHA-256, quotes, or a hash on a null run are refused' ($threw -eq 3) "$threw of 3"
    # DECISIONS 2026-11-24 (D): the gate's executing apps, the medium route (vscode-user) among them.
    $nullApps = @(Get-M3E2eNullApps -ExpectFile $expect)
    Check 'm3-e2e null: null apps default to the gate''s executing apps (vscode-user on the medium route), a failing uninstaller is refused' ((@($nullApps | ForEach-Object { $_.id }) -join ',') -eq 'vscode,vscode-user,git,firefox-tb,execapp' -and
        ((@($nullApps | Where-Object { "$($_.route)" -eq 'medium' } | ForEach-Object { $_.id }) -join ',') -eq 'vscode-user') -and $(try { $null = Get-M3E2eNullApps -ExpectFile $expect -Only @('msi3010'); $false } catch { $true }))

    # guest_null_window_replaces_exec: one window function for gate and null runs; apart from the plan consent's
    # answer (approve / cancel with the null wait) the two traces are equal.
    $hostText = [IO.File]::ReadAllText((Join-Path $Vm 'rig-m3.ps1'))
    $win = [regex]::Match($hostText, '(?s)\nfunction Invoke-M3E2eWindow\(.*?\n\}')
    $outside = $hostText.Remove($win.Index, $win.Length)
    Check 'm3-e2e window: one Invoke-M3E2eWindow call, right after capture-post on the review page' ($win.Success -and ([regex]::Matches($hostText, '(?m)^\s+Invoke-M3E2eWindow ').Count -eq 1) -and
        $hostText -match "Invoke-M3E2eStep 'capture-post' \`$id -TimeoutSec 5400\r?\n\s+if \(\`$state -eq 'review'\) \{\r?\n\s+Invoke-M3E2eWindow \`$id \`$rec \`$isNull\r?\n")
    Check 'm3-e2e window: snap B (capture-exec), the plan approval and the cancel only inside the window' (
        $win.Value -match "Invoke-M3E2eStep 'capture-exec'" -and $outside -notmatch "Invoke-M3E2e(Phase|Step) 'capture-exec'" -and $outside -notmatch "'consent-approve' \`$\w+ 'plan'" -and
        $outside -notmatch "Invoke-M3E2e(Phase|Step) 'consent-cancel'" -and @([regex]::Matches($win.Value, '\$IsNull')).Count -eq 2)
    $script:trace = New-Object System.Collections.ArrayList
    $M3.null_wait = 10
    # The stub answers every phase with a success line (fail fast needs one); $script:stubLines overrides a phase.
    $script:stubLines = @{}
    function Invoke-M3E2ePhase([string]$Phase, [string]$App, [string]$Step = '', [int]$WaitSec = 0, [int]$TimeoutSec = 900, [string]$AmbientSha = '') {
        [void]$script:trace.Add("phase:$Phase$(if ($Step) { ":$Step" })$(if ($WaitSec) { " wait=$WaitSec" })")
        $k = "$Phase$(if ($Step) { ":$Step" })"
        if ($script:stubLines.ContainsKey($k)) { return $script:stubLines[$k] }
        "M3E X $App ok=True found=True state=$(if ($Phase -eq 'ui-wait-result') { if ($script:E2eNull) { 'declined' } else { 'result' } } elseif ($Phase -eq 'ui-wait-undone') { 'undone' } else { 'prompt' })"
    }
    function Save-M3E2eShot([string]$Name) { [void]$script:trace.Add("shot:$Name") }
    function Invoke-M3E2eUac([string]$Tag, [string]$App = '', [string]$Step = '') { [void]$script:trace.Add("uac:$Tag"); @() }
    $script:E2eNull = $false
    $r1 = [ordered]@{ uac_keys = [ordered]@{} }; Invoke-M3E2eWindow 'vscode' $r1 $false; $gate = @($script:trace); $script:trace.Clear()
    $script:E2eNull = $true
    $r2 = [ordered]@{ uac_keys = [ordered]@{} }; Invoke-M3E2eWindow 'vscode' $r2 $true; $nul = @($script:trace); $script:trace.Clear()
    $script:E2eNull = $false
    $gi = [array]::IndexOf($gate, 'phase:consent-approve:plan'); $ni = [array]::IndexOf($nul, 'phase:consent-cancel:plan wait=10')
    $same = ($gi -ge 0 -and $gi -eq $ni -and $gate.Count -eq $nul.Count)
    if ($same) { for ($i = 0; $i -lt $gate.Count; $i++) { if ($i -ne $gi -and $gate[$i] -cne $nul[$i]) { $same = $false } } }
    Check 'm3-e2e window: gate and null traces are equal but for approve / cancel (+ null wait)' ($same -and $gate[-1] -ceq 'phase:capture-exec' -and $gate[0] -ceq 'phase:ui-move') "gate: $($gate -join ' '); null: $($nul -join ' ')"

    # Nothing preselected: ui-move answers skip-empty; the window goes straight to capture-exec (no plan UAC check,
    # consent, approval or result wait) and the record says so.
    $script:stubLines = @{ 'ui-move' = 'M3E UI-MOVE npp ok=True state=skip-empty footer= enabled=False' }
    $r3 = [ordered]@{ uac_keys = [ordered]@{} }; Invoke-M3E2eWindow 'npp' $r3 $false; $emp = @($script:trace); $script:trace.Clear()
    Check 'm3-e2e window: nothing preselected skips the plan consent and the result wait' ((($emp -join ' ') -ceq 'phase:ui-move shot:07-move-waiting phase:capture-exec') -and $r3.empty_plan -eq $true) ($emp -join ' ')
    # Fail fast: a failed step throws (after its screenshot); nothing after it runs.
    $script:stubLines = @{ 'consent-wait:plan' = 'M3E DIALOG npp plan found=False broker=4708 footer= primary= il=' }
    $threw = $null
    try { Invoke-M3E2eWindow 'npp' ([ordered]@{ uac_keys = [ordered]@{} }) $false } catch { $threw = $_.Exception.Message }
    $ff = @($script:trace); $script:trace.Clear()
    Check 'm3-e2e fail fast: a plan dialog not found ends the window (no approve, result wait or capture-exec)' ($threw -like 'step consent-wait-plan failed: M3E DIALOG*' -and
        (($ff -join ' ') -ceq 'phase:ui-move shot:07-move-waiting uac:07u-uac phase:consent-wait:plan wait=300 shot:08-consent-plan') -and $script:E2eFailedStep -ceq 'consent-wait-plan') "$threw / $($ff -join ' ')"
    $script:stubLines = @{ 'ui-move' = 'M3E UI-MOVE npp ok=False state=no-move footer= code=' }
    $threw = $null
    try { Invoke-M3E2eWindow 'npp' ([ordered]@{ uac_keys = [ordered]@{} }) $false } catch { $threw = $_.Exception.Message }
    $ff = @($script:trace); $script:trace.Clear()
    Check 'm3-e2e fail fast: Move not pressed ends the window after its screenshot' ($threw -like 'step ui-move failed:*' -and (($ff -join ' ') -ceq 'phase:ui-move shot:07-move-waiting')) "$threw / $($ff -join ' ')"
    $script:stubLines = @{}
    # Test-M3E2eStepLine: what counts as a success line per phase.
    $sl = @(
        @('ui-start', 'M3E UI-START npp ok=True ui_pid=1 row=name scrolls=0', $false, $true), @('ui-start', 'M3E UI-START npp ok=False ui_pid=1', $false, $false),
        @('consent-wait', 'M3E DIALOG npp run found=True broker=1', $false, $true), @('consent-wait', 'M3E DIALOG npp run found=False broker=', $false, $false),
        @('consent-approve', 'M3E APPROVE npp plan ok=False broker=4708 pressed=False enabled= gone=', $false, $false),
        @('ui-wait-result', 'M3E RESULT npp state=result title=Moved_2', $false, $true), @('ui-wait-result', 'M3E RESULT npp state= title=', $false, $false),
        @('ui-wait-result', 'M3E RESULT vscode state=declined title=', $true, $true), @('ui-wait-result', 'M3E RESULT vscode state=result title=x', $true, $false),
        @('ui-wait-undone', 'M3E UNDONE npp state=undone title=Put_back', $false, $true), @('capture-exec', 'M3E REFUSED npp phase=capture-exec null=True prepared_null=False', $false, $false),
        @('ui-move', '', $false, $false), @('ui-move', 'M3 UI-MOVE ok=True', $false, $false), @('ui-move', 'M3E UI-MOVE npp ok=True state=skip-empty', $false, $true))
    $bad = @($sl | Where-Object { (Test-M3E2eStepLine $_[0] $_[1] $_[2]) -ne $_[3] } | ForEach-Object { "$($_[0]): $($_[1])" })
    Check "m3-e2e fail fast: Test-M3E2eStepLine on $($sl.Count) lines" ($bad.Count -eq 0) ($bad -join ' | ')
    # The host's app flow and undo branch use only fail-fast steps after prepare (and the scan's own state logic).
    $appFn = [regex]::Match($hostText, '(?s)\nfunction Invoke-M3E2eApp\(.*?\n\}').Value
    $plain = @([regex]::Matches($appFn, "Invoke-M3E2ePhase '([a-z-]+)'") | ForEach-Object { $_.Groups[1].Value })
    Check 'm3-e2e fail fast: Invoke-M3E2eApp calls Invoke-M3E2ePhase only for setup, prepare, the scan, fail-check and finish' ((($plain | Sort-Object -Unique) -join ',') -ceq 'fail-check,finish,prepare,setup,ui-wait-scan') ($plain -join ',')
    Check 'm3-e2e fail fast: the undo steps fail fast and are skipped for an empty plan' ($appFn -match "(?s)if \(\`$Undo -and \`$rec\.empty_plan\) \{.*undo_skipped.*\} elseif \(\`$Undo\) \{\s+\`$l = Invoke-M3E2eStep 'ui-undo'.*'continue-focused'.*Send-M3Keys 'space'.*Invoke-M3E2eUac '10u-uac'" -and $appFn -match "Invoke-M3E2eStep 'capture-undo'")
    # The guest's ui-undo (DECISIONS 2026-11-24): any "Confirm ... Purge security prompt" title, and fail fast on an
    # interrupted restore or a refusal instead of waiting out its timeout.
    $undoPhase = [regex]::Match([IO.File]::ReadAllText((Join-Path $Guest 'm3-e2e.ps1')), "(?s)\n    'ui-undo' \{.*?\n    \}").Value
    Check 'm3-e2e ui-undo: loose prompt title, interrupted and refused end the wait, the relaunch Continue is focused' (
        $undoPhase -match [regex]::Escape("-like 'Confirm*Purge security prompt*'") -and $undoPhase -match "return 'interrupted'" -and
        $undoPhase -match '\*ended during the restore\*' -and $undoPhase -match "return 'refused'" -and $undoPhase -match "Find-E2eDialogButton \`$win 'Continue'" -and
        $undoPhase -notmatch [regex]::Escape("-contains 'Confirm in the Purge security prompt.'"))
    # Setup (DECISIONS 2026-11-24, C): Windows' background task families paused next to Edge / telemetry, outside any
    # -NullRun branch (gate and null runs alike), recorded in setup.json (and so e2e.json setup.background).
    $e2eText = [IO.File]::ReadAllText((Join-Path $Guest 'm3-e2e.ps1'))
    $setupPhase = [regex]::Match($e2eText, "(?s)\n    'setup' \{.*?\n    \}").Value
    $bgList = [regex]::Match($e2eText, '(?s)\$E2eBackgroundTasks = @\((.*?)\n\)').Groups[1].Value
    Check 'm3-e2e setup: background tasks paused for gate and null runs alike, the list as decided, recorded' (
        $setupPhase -match '(?m)^        \$rec\.telemetry = Suspend-M2Telemetry\s*\r?\n(\s*#[^\n]*\n)*        \$rec\.background = Suspend-E2eBackgroundTasks' -and
        $setupPhase -match 'background = \$null' -and
        ((@([regex]::Matches($bgList, "path = '([^']+)'; name = '([^']+)'") | ForEach-Object { $_.Groups[1].Value + $_.Groups[2].Value }) -join '|') -ceq
            '\Microsoft\Windows\UpdateOrchestrator\*|\Microsoft\Windows\Device Information\Device|\Microsoft\Windows\Flighting\OneSettings\RefreshCache|\Microsoft\Windows\PushToInstall\*|\Microsoft\Windows\Application Experience\*|\Microsoft\Windows\Windows Defender\*') -and
        $e2eText -match "Stop-Service -Name 'UsoSvc'" -and $e2eText -match "Stop-Service -Name 'W32Time'" -and $e2eText -match 'time_service = \[pscustomobject\]\$tsvc' -and
        $e2eText -match [regex]::Escape("`$E2eBackgroundServices = @('DoSvc', 'wuauserv', 'WaaSMedicSvc')") -and $e2eText -match 'foreach \(\$name in \$E2eBackgroundServices\)')
    Check 'm3-e2e fail fast: the catch records the failed step; finish and the pull stay in finally' ($appFn -match 'rec\.failed_step = \$script:E2eFailedStep' -and $appFn -match "(?s)\} finally \{.*Invoke-M3E2ePhase 'finish'")

    # MSI smoke: which fixtures a smoke line lets through.
    $fx = @((Get-Content -LiteralPath $expect -Raw | ConvertFrom-Json).apps | Where-Object { $_.kind -like 'fail-*' })
    $sk = Get-M3E2eMsiSmokeSkips $fx 'M3E MSI-SMOKE msi-smoke ok=True msi1603=ok:0 msi3010=ok:0'
    Check 'm3-e2e msi smoke: both ok -> no skip' ($sk.Count -eq 0)
    $sk = Get-M3E2eMsiSmokeSkips $fx 'M3E MSI-SMOKE msi-smoke ok=False msi1603=fail:1603 msi3010=ok:0'
    Check 'm3-e2e msi smoke: a failing package skips its app only, naming the exit code' ($sk.Count -eq 1 -and "$($sk['msi1603'])" -match 'msiexec /i of the msi1603 fixture exited 1603')
    $sk = Get-M3E2eMsiSmokeSkips $fx ''
    Check 'm3-e2e msi smoke: no line skips both (fail-closed)' ($sk.Count -eq 2 -and "$($sk['msi3010'])" -match 'no result')
    $sk = Get-M3E2eMsiSmokeSkips $fx 'M3E MSI-SMOKE msi-smoke ok=False msi1603=ok:0 msi3010=fail:'
    Check 'm3-e2e msi smoke: a package that could not be built skips its app' ($sk.Count -eq 1 -and "$($sk['msi3010'])" -match 'could not be built')
    Check 'm3-e2e msi smoke: a run without an MSI fixture has no smoke' ($null -eq (Invoke-M3E2eMsiSmoke @((Get-Content -LiteralPath $expect -Raw | ConvertFrom-Json).apps | Where-Object { $_.id -eq 'npp' }) 'rig-base'))
    $e2eFn = [regex]::Match($hostText, '(?s)\nfunction Invoke-M3E2e \{.*?\n\}').Value
    Check 'm3-e2e msi smoke: the chain runs it before the first app and passes each skip reason' ($e2eFn -match '(?s)\$smoke = Invoke-M3E2eMsiSmoke \$apps \$base.*foreach \(\$a in \$apps\).*-SkipReason \$skip')

    # The guest side of a null run.
    $g = [IO.File]::ReadAllText((Join-Path $Guest 'm3-e2e.ps1'))
    $cancel = [regex]::Match($g, "(?s)\n    'consent-cancel' \{.*?\n    \}")
    Check 'm3-e2e guest: consent-cancel presses IDCANCEL (2) without a tick, then the null wait; null runs only' ($cancel.Success -and
        $cancel.Value -match 'tick = \$false; button = 2;' -and $cancel.Value -match "Save-Step \`$nw 'null-wait'" -and $cancel.Value -match "if \(-not \`$NullRun -or \`$Step -ne 'plan'\)")
    Check 'm3-e2e guest: a null run never approves the plan or undo, never mixes with a gate run' (
        $g -match "if \(\`$NullRun -and \`$Step -ne 'run'\) \{ `"M3E REFUSED" -and $g -match "\[bool\]\`$st\.null_run -ne \[bool\]\`$NullRun" -and $g -match 'null_run = \[bool\]\$NullRun \}')
    # The empty path, the watcher, t_approved and the MSI smoke on the guest side.
    $mv = [regex]::Match($g, "(?s)\n    'ui-move' \{.*?\n    \}")
    Check 'm3-e2e guest: ui-move with nothing preselected checks Move present and not enabled, skip-empty only then; a null run refuses it' ($mv.Success -and
        $mv.Value -match '(?s)if \(\$pre -eq 0\) \{.*Wait-E2eElement \{ Find-E2eById \$win ''MoveButton'' \} 60\r?\n' -and $mv.Value -match "elseif \(\`$rec\.move_enabled -ne \`$false\) \{ \`$rec\.state = 'move-enabled'" -and
        $mv.Value -match "else \{ \`$rec\.state = 'skip-empty'; \`$rec\.ok = \`$true; Set-StateValue \`$st 'empty_plan' \`$true \}" -and $mv.Value -match "if \(\`$NullRun\) \{ \`$rec\.state = 'empty-null'")
    $ap = [regex]::Match($g, "(?s)\n    'consent-approve' \{.*?\n    \}")
    Check 'm3-e2e guest: t_approved_<step> only when m3sec found the dialog and pressed' ($ap.Success -and $ap.Value -match 'if \(\$rec\.pressed\) \{ Set-StateValue \$st "t_approved_\$Step"' -and
        @([regex]::Matches($ap.Value, 't_approved_')).Count -eq 1 -and $ap.Value -match 'press\.found -eq \$true')
    $un = [regex]::Match($g, "(?s)\n    'ui-uninstall' \{.*?\n    \}").Value
    $cf = [regex]::Match($g, "(?s)\n    'ui-confirm' \{.*?\n    \}").Value
    $ws = [regex]::Match($g, "(?s)\n    'ui-wait-scan' \{.*?\n    \}").Value
    Check 'm3-e2e guest: the uninstaller watcher starts before Uninstall and before the confirm press; the scan stops and merges it' (
        $un -match '(?s)Start-E2eWatcher \$st\r?\n\s+\$rec\.invoked = Invoke-E2eElement \$w\.el' -and $cf -match '(?s)Start-E2eWatcher \$st\r?\n\s+\$rec\.invoked = Invoke-E2eElement \$btn' -and
        $ws -match 'Stop-E2eWatcher \$st' -and $ws -match 'Merge-E2eUninstallers' -and $g -match "(?s)'finish' \{.*Stop-E2eWatcher")
    $sm = [regex]::Match($g, "(?s)\n    'msi-smoke' \{.*?\n    \}").Value
    Check 'm3-e2e guest: msi-smoke installs both packages with msiexec /i and wants exit 0 and the ARP entry' ($sm -match "foreach \(\`$v in '1603', '3010'\)" -and $sm -match "'/i `"'" -and $sm -match '\$r\.ok = \(\$r\.exit -eq 0 -and \$r\.arp\)' -and $sm -match 'M3E MSI-SMOKE')
    $cx = [regex]::Match($g, "(?s)\n    'capture-exec' \{.*?\n    \}")
    Check 'm3-e2e guest: an empty capture-exec refuses a session, runs execdiff on the rig''s empty journal, compares empty with empty' ($cx.Success -and
        $cx.Value -match "(?s)elseif \(\`$st\.empty_plan -eq \`$true\) \{.*throw `"nothing was preselected, but a session was made.*New-E2eEmptyExecDocs.*Invoke-M2Execdiff.*Compare-E2eSets @\(\`$st\.cli\.preselected_keys\) @\(\).*report_state = 'Empty'")
    Check 'm3-e2e guest: a null capture-exec takes snap B and deep B, refuses a session, keeps the pair, runs no execdiff' ($cx.Success -and
        $cx.Value -match "(?s)Invoke-M2Snap \(Join-Path \`$W 'snap-b\.tsv\.gz'\).*Invoke-M2Deep.*if \(\`$NullRun\) \{.*throw `"a null run made a session.*snap-\`$s\.tsv\.gz.*\} else \{.*Invoke-M2Execdiff")
    Check 'm3-e2e guest: setup records the declared and the guest hash of the set; a gate run without it fails setup' (
        $g -match 'declared = \$\(if \(\$AmbientSha\)' -and $g -match 'guest_sha256 = \$\(if \(Test-Path -LiteralPath \$RigM2Ambient' -and $g -match "elseif \(-not \`$AmbientSha -or \`$rec\.ambient\.guest_sha256 -cne \`$AmbientSha\)")

    # Test-M3E2eNullRunDoc and the build (ambient_build_takes_only_null_runs, ambient_build_refuses_fixture_names).
    $newE2e = {
        '{"schema":"purge.rig.m3e2e.app/1","app":"vscode","null_run":true,"ambient":{"declared":null,"guest":"C:\\cr\\bin\\m2-ambient.json","guest_sha256":null},' +
        '"files":{"execdiff":false},"state":{"null_run":true,"cli":{"items":3,"preselected_keys":["Path|c:\\program files\\microsoft vs code||","RegValue|hku\\s-1-5-21-1\\environment|path|x"],' +
        '"plan_keys":["Path|c:\\program files\\microsoft vs code||","RegValue|hku\\s-1-5-21-1\\environment|path|x","Path|c:\\users\\tester\\appdata\\roaming\\code||"]}},' +
        '"steps":{"capture-post":{"ok":true},"ui-move":{"ok":true,"state":"prompt"},"consent-wait-plan":{"ok":true},"consent-cancel-plan":{"ok":true},"null-wait":{"ok":true,"seconds":10},' +
        '"ui-wait-result":{"ok":true,"state":"declined"},"capture-exec":{"ok":true,"null":true,"sessions_new":[]}}}' | ConvertFrom-Json }
    $newProv = { [pscustomobject]@{ campaign = 'null-selftest'; vm = 'Inbound-Win11-Test'; snapshot = 'rig-base'; engine_sha256 = ('e' * 64); broker_sha256 = ('b' * 64); ui_sha256 = ('d' * 64); null_wait = 10 } }
    $newDoc = { param($run) [pscustomobject]@{ schema = 'purge.rig.m3e2e.null/1'; run = $run; mode = 'm3-e2e'; app = 'vscode'; null_run = [pscustomobject]@{ null = $true; wait_sec = 10 }
                                                provenance = (& $newProv); finished = 'x'; error = $null; pulled = $true } }
    $why = @(Test-M3E2eNullRunDoc (& $newDoc 'en1-m3-e2e-vscode') (& $newE2e) 'en1-m3-e2e-vscode' 'vscode')
    Check 'm3-e2e null doc: a finished null run passes' ($why.Count -eq 0) ($why -join '; ')
    $muts = [ordered]@{
        'the plan consent approved' = { param($d, $e) $e.steps | Add-Member -NotePropertyName 'consent-approve-plan' -NotePropertyValue ([pscustomobject]@{ ok = $true }) }
        'no cancel' = { param($d, $e) $e.steps.PSObject.Properties.Remove('consent-cancel-plan') }
        'no null wait' = { param($d, $e) $e.steps.PSObject.Properties.Remove('null-wait') }
        'the result page reached' = { param($d, $e) $e.steps.'ui-wait-result'.state = 'result' }
        'a session made' = { param($d, $e) $e.steps.'capture-exec'.sessions_new = @('20261123-1') }
        'an execdiff ran' = { param($d, $e) $e.files.execdiff = $true }
        'an ambient set in the guest' = { param($d, $e) $e.ambient.guest_sha256 = ('c' * 64) }
        'the guest ran it as a gate run' = { param($d, $e) $e.state.null_run = $false }
        'capture-exec failed' = { param($d, $e) $e.steps.'capture-exec'.ok = $false }
        'another app' = { param($d, $e) $e.app = 'git' }
        'run.json of another run' = { param($d, $e) $d.run = 'en2-m3-e2e-vscode' }
        'not a null run on the host' = { param($d, $e) $d.null_run.null = $false }
        'a host error' = { param($d, $e) $d.error = 'setup failed' }
        'not pulled' = { param($d, $e) $d.pulled = $false }
        'another schema' = { param($d, $e) $d.schema = 'purge.rig.m2/1' }
        'no provenance' = { param($d, $e) $d.PSObject.Properties.Remove('provenance') }
        'provenance without the campaign' = { param($d, $e) $d.provenance.campaign = '' }
        'provenance without the snapshot' = { param($d, $e) $d.provenance.PSObject.Properties.Remove('snapshot') }
        'provenance with a bad engine hash' = { param($d, $e) $d.provenance.engine_sha256 = 'abc' }
        'provenance without the UI hash' = { param($d, $e) $d.provenance.ui_sha256 = $null }
        'provenance null wait 0' = { param($d, $e) $d.provenance.null_wait = 0; $d.null_run.wait_sec = 0 }
        'provenance null wait not the run''s' = { param($d, $e) $d.provenance.null_wait = 20 }
        'no plan_keys' = { param($d, $e) $e.state.cli.PSObject.Properties.Remove('plan_keys') }
        'plan_keys fewer than the plan items' = { param($d, $e) $e.state.cli.plan_keys = @($e.state.cli.plan_keys | Select-Object -First 2) }
    }
    $missed = @()
    foreach ($k in $muts.Keys) { $d = & $newDoc 'en1-m3-e2e-vscode'; $e = & $newE2e; & $muts[$k] $d $e; if (-not @(Test-M3E2eNullRunDoc $d $e 'en1-m3-e2e-vscode' 'vscode').Count) { $missed += $k } }
    Check "m3-e2e null doc: each of $($muts.Count) bad-run controls is refused" ($missed.Count -eq 0) ($missed -join ', ')
    Check 'm3-e2e null doc: a gate-shaped run name is refused' (@(Test-M3E2eNullRunDoc (& $newDoc 'e2e-1') (& $newE2e) 'e2e-1' 'vscode').Count -gt 0)

    $roots = @(Get-M3E2eTargetRoots @('Path|c:\program files\microsoft vs code||', 'RegValue|hku\s-1-5-21-1\environment|path|x', 'Service|svc', 'Task|\purgeexecapp\simple update', 'FirewallRule|AbC'))
    Check 'm3-e2e ambient: the plan roots (path, value, service key, task file; no rule)' ($roots.Count -eq 4 -and $roots[0].path -eq 'c:\program files\microsoft vs code' -and $roots[1].name -eq 'path' -and
        $roots[2].path -eq 'hklm\system\currentcontrolset\services\svc' -and $roots[3].path -eq 'c:\windows\system32\tasks\purgeexecapp\simple update')
    $set = { param($recs, $pats = @()) [pscustomobject]@{ schema = 'purge.rig.m2ambient/1'; runs = @([pscustomobject]@{ id = 'en1-m3-e2e-vscode'; records = @($recs); patterns = @($pats) }); records = @($recs); patterns = @($pats) } }
    $hit = { param($s) @(Get-M3E2eAmbientFixtureHits $s $roots).Count }
    Check 'm3-e2e ambient: Windows churn is no fixture' ((& $hit (& $set @('~F:C:\WINDOWS\Prefetch\TASKLIST.EXE-2448BC7D.pf', '~V:HKU\S-1-5-21-1\Environment|TEMP', '+D:C:\Program Files\Microsoft VS Code Insiders')) ) -eq 0)
    Check 'm3-e2e ambient: fixture names are refused (PurgeExec, PurgeE2eMsi, the store)' ((& $hit (& $set @('-K:HKLM\SOFTWARE\PurgeE2eMsi\1603'))) -eq 1 -and (& $hit (& $set @('~F:C:\ProgramData\Purge\index.json'))) -eq 1 -and
        (& $hit (& $set @() @('^\~K:HKLM\\SYSTEM\\CurrentControlSet\\Services\\PurgeExecSvc[0-9a-f]{16}$'))) -eq 1)
    Check 'm3-e2e ambient: a record or pattern on or under a preselected object is refused (folder, file in it, value, pattern)' ((& $hit (& $set @('~D:C:\Program Files\Microsoft VS Code'))) -eq 1 -and
        (& $hit (& $set @('-F:C:\Program Files\Microsoft VS Code\bin\code.cmd'))) -eq 1 -and (& $hit (& $set @('~V:HKU\S-1-5-21-1\Environment|Path'))) -eq 1 -and (& $hit (& $set @() @('^\~F:C:\\Program Files\\Microsoft VS Code\\[0-9a-f]{16}\.tmp$'))) -eq 1)

    # The build, against null run dirs in a temporary runs dir and a stub rigtool (a .ps1 writing the set it is given).
    $rd = Join-Path $Work 'm3e2e-runs'; New-Item -ItemType Directory -Force $rd | Out-Null
    $script:RunsDir = $rd
    $stub = Join-Path $Work 'm3e2e-rigtool.ps1'
    [IO.File]::WriteAllText($stub, @'
$o = $args[[array]::IndexOf($args, '-o') + 1]
$dirs = @(); for ($i = [array]::IndexOf($args, '--null') + 1; $args[$i] -ne '-o'; $i++) { $dirs += $args[$i] }
[IO.File]::WriteAllText((Join-Path (Split-Path -Parent $o) 'stub-args.txt'), ($args -join ' '))
$recs = @([IO.File]::ReadAllLines((Join-Path (Split-Path -Parent $o) 'stub-records.txt')) | Where-Object { $_ })
$pf = Join-Path (Split-Path -Parent $o) 'stub-patterns.txt'
$pats = @(if (Test-Path -LiteralPath $pf) { [IO.File]::ReadAllLines($pf) | Where-Object { $_ } })
$runs = @($dirs | ForEach-Object { [ordered]@{ id = (Split-Path -Leaf $_); dir = $_; records = $recs; patterns = $pats } })
[IO.File]::WriteAllText($o, (ConvertTo-Json ([ordered]@{ schema = 'purge.rig.m2ambient/1'; runs = $runs; records = $recs; patterns = $pats }) -Depth 5))
exit 0
'@)
    $env:RIG_RIGTOOL = $stub
    $out = Join-Path $Work 'm3e2e-ambient.json'
    $M3.ambient = $out; $M3.count = 6; $M3.apps = @('vscode'); $M3.prefix = ''   # the fixtures are vscode null runs (the default is the gate's five apps)
    [IO.File]::WriteAllText((Join-Path $Work 'stub-records.txt'), "~F:C:\WINDOWS\Prefetch\TASKLIST.EXE-2448BC7D.pf`r`n+F:C:\Users\tester\AppData\Local\Comms\Unistore\data\AggregateCache.uca")
    $mkRun = { param($k, $e2eAct = $null)
        $r = Get-M3E2eNullRunName $k 'vscode'
        $d = Join-Path $rd $r
        New-Item -ItemType Directory -Force $d | Out-Null
        foreach ($s in 'a', 'b') { [IO.File]::WriteAllText((Join-Path $d "snap-$r-$s.tsv.gz"), 'x') }
        $e = & $newE2e; $doc = & $newDoc $r
        if ($e2eAct) { & $e2eAct $doc $e }
        [IO.File]::WriteAllText((Join-Path $d 'e2e.json'), (ConvertTo-Json $e -Depth 8)); [IO.File]::WriteAllText((Join-Path $d 'run.json'), (ConvertTo-Json $doc -Depth 8)) }
    foreach ($k in 1..6) { & $mkRun $k }
    $dirs = @(Invoke-M3E2eBuildAmbient)
    $built = Read-M3Json $out
    Check 'm3-e2e ambient build: 6 null runs -> the set (added records kept, --added passed)' ($dirs.Count -eq 6 -and $built -and @($built.runs).Count -eq 6 -and @($built.records) -contains '+F:C:\Users\tester\AppData\Local\Comms\Unistore\data\AggregateCache.uca' -and
        ([IO.File]::ReadAllText((Join-Path $Work 'stub-args.txt'))) -match '^ambient --m2 --added --null ') "dirs $($dirs.Count), runs $(@($built.runs).Count), records $(@($built.records) -join ' | '), args $([IO.File]::ReadAllText((Join-Path $Work 'stub-args.txt')))"
    $pv = $built.provenance
    Check 'm3-e2e ambient build: the runs'' provenance is copied into the set' ($pv -and "$($pv.campaign)" -ceq 'null-selftest' -and "$($pv.vm)" -ceq 'Inbound-Win11-Test' -and "$($pv.snapshot)" -ceq 'rig-base' -and
        "$($pv.engine_sha256)" -ceq ('e' * 64) -and "$($pv.broker_sha256)" -ceq ('b' * 64) -and "$($pv.ui_sha256)" -ceq ('d' * 64) -and [int]$pv.null_wait -eq 10) "$(ConvertTo-Json $pv -Compress)"
    $before = [IO.File]::ReadAllText($out)
    $refused = { param($name, [scriptblock]$setup, [scriptblock]$undo)
        & $setup
        $msg = $null; try { $null = Invoke-M3E2eBuildAmbient } catch { $msg = $_.Exception.Message }
        & $undo
        Check "m3-e2e ambient build refuses $name and writes no file" ($msg -and [IO.File]::ReadAllText($out) -ceq $before -and -not @(Get-ChildItem -LiteralPath $Work -Filter 'm3e2e-ambient.json.tmp-*').Count) "$msg" }
    & $refused 'a gate run among the runs (plan approved, session)' { & $mkRun 3 { param($d, $e) $e.steps | Add-Member -NotePropertyName 'consent-approve-plan' -NotePropertyValue ([pscustomobject]@{ ok = $true }); $e.steps.'capture-exec'.sessions_new = @('s1') } } { & $mkRun 3 }
    & $refused 'a run without its snapshot pair' { Remove-Item -LiteralPath (Join-Path $rd 'en4-m3-e2e-vscode\snap-en4-m3-e2e-vscode-b.tsv.gz') } { & $mkRun 4 }
    & $refused 'a run whose run.json is not a null run' { & $mkRun 5 { param($d, $e) $d.null_run.null = $false } } { & $mkRun 5 }
    & $refused 'fewer than 6 null runs' { $M3.count = 5 } { $M3.count = 6 }
    & $refused 'a set naming a fixture' { [IO.File]::AppendAllText((Join-Path $Work 'stub-records.txt'), "`r`n-K:HKLM\SOFTWARE\PurgeE2eMsi\1603") } { [IO.File]::WriteAllText((Join-Path $Work 'stub-records.txt'), "~F:C:\WINDOWS\Prefetch\TASKLIST.EXE-2448BC7D.pf") }
    & $refused 'a set naming a null run''s own preselected object' { [IO.File]::AppendAllText((Join-Path $Work 'stub-records.txt'), "`r`n~F:C:\Program Files\Microsoft VS Code\Code.exe") } { [IO.File]::WriteAllText((Join-Path $Work 'stub-records.txt'), "~F:C:\WINDOWS\Prefetch\TASKLIST.EXE-2448BC7D.pf") }
    # Plan objects that were not preselected (capture-post plan_keys) refuse it too.
    & $refused 'a set naming a plan object that was not preselected' { [IO.File]::AppendAllText((Join-Path $Work 'stub-records.txt'), "`r`n+F:C:\Users\tester\AppData\Roaming\Code\User\settings.json") } { [IO.File]::WriteAllText((Join-Path $Work 'stub-records.txt'), "~F:C:\WINDOWS\Prefetch\TASKLIST.EXE-2448BC7D.pf") }
    # Purge's store: only the known null-window records are dropped; any other record or pattern there, or on a
    # .purge-q, refuses the set.
    $resetRecs = { [IO.File]::WriteAllText((Join-Path $Work 'stub-records.txt'), "~F:C:\WINDOWS\Prefetch\TASKLIST.EXE-2448BC7D.pf"); Remove-Item -LiteralPath (Join-Path $Work 'stub-patterns.txt') -ErrorAction SilentlyContinue }
    & $refused 'another record in the store (a session journal), beside the allowed ones' { [IO.File]::AppendAllText((Join-Path $Work 'stub-records.txt'), "`r`n+F:C:\ProgramData\Purge\sessions\writer.lock`r`n+F:C:\ProgramData\Purge\sessions\20261123T070000Z-1\journal.jsonl") } $resetRecs
    & $refused 'a changed writer.lock (not the known +F)' { [IO.File]::AppendAllText((Join-Path $Work 'stub-records.txt'), "`r`n~F:C:\ProgramData\Purge\sessions\writer.lock") } $resetRecs
    & $refused 'a record on a .purge-q' { [IO.File]::AppendAllText((Join-Path $Work 'stub-records.txt'), "`r`n~D:D:\.purge-q") } $resetRecs
    & $refused 'a pattern in the store' { [IO.File]::WriteAllText((Join-Path $Work 'stub-patterns.txt'), '^\+F:C:\\ProgramData\\Purge\\sessions\\[0-9a-f]{16}\.tmp$') } $resetRecs
    & $refused 'a pattern on a .purge-q' { [IO.File]::WriteAllText((Join-Path $Work 'stub-patterns.txt'), '^\+D:C:\\\.purge\-q\\[0-9a-f]{16}$') } $resetRecs
    # Provenance: one campaign, one VM (the file's), one snapshot, one set of binaries, one null wait.
    & $refused 'a mixed campaign (one run of another campaign)' { & $mkRun 2 { param($d, $e) $d.provenance.campaign = 'null-other' } } { & $mkRun 2 }
    & $refused 'a mixed VM (one run on Purge-CleanPro)' { & $mkRun 6 { param($d, $e) $d.provenance.vm = 'Purge-CleanPro' } } { & $mkRun 6 }
    & $refused 'runs of another VM than the file''s' { foreach ($k in 1..6) { & $mkRun $k { param($d, $e) $d.provenance.vm = 'Purge-CleanPro' } } } { foreach ($k in 1..6) { & $mkRun $k } }
    & $refused 'a run on another snapshot' { & $mkRun 1 { param($d, $e) $d.provenance.snapshot = 'm3-uac-on' } } { & $mkRun 1 }
    & $refused 'a run with another engine' { & $mkRun 3 { param($d, $e) $d.provenance.engine_sha256 = ('f' * 64) } } { & $mkRun 3 }
    & $refused 'a run with another null wait' { & $mkRun 4 { param($d, $e) $d.provenance.null_wait = 20; $d.null_run.wait_sec = 20 } } { & $mkRun 4 }
    & $refused 'a run without provenance' { & $mkRun 5 { param($d, $e) $d.PSObject.Properties.Remove('provenance') } } { & $mkRun 5 }
    # Purge's own store (the broker's writer.lock and sessions dir, also in a cancelled plan's window): dropped, not refused.
    [IO.File]::WriteAllText((Join-Path $Work 'stub-records.txt'), "~F:C:\WINDOWS\Prefetch\TASKLIST.EXE-2448BC7D.pf`r`n+F:C:\ProgramData\Purge\sessions\writer.lock`r`n~D:C:\ProgramData\Purge\sessions`r`n~D:C:\ProgramData\Microsoft\Windows\WER")
    $dirs = @(Invoke-M3E2eBuildAmbient)
    $built = Read-M3Json $out
    $allEntries = @(@($built.records) + @($built.patterns) + @($built.runs | ForEach-Object { @($_.records) + @($_.patterns) }))
    Check 'm3-e2e ambient build: store entries are dropped (set, every run), the rest kept, the drop noted' ($dirs.Count -eq 6 -and -not @($allEntries | Where-Object { "$_" -match '(?i)programdata\\purge\\|programdata\\purge$' }).Count -and
        @($built.records) -contains '~D:C:\ProgramData\Microsoft\Windows\WER' -and @($built.records) -contains '~F:C:\WINDOWS\Prefetch\TASKLIST.EXE-2448BC7D.pf' -and "$($built.note)" -match '2 store entries dropped' -and
        @(Get-M3E2eAmbientFixtureHits $built @()).Count -eq 0) "records $(@($built.records) -join ' | '); note $($built.note)"
    $s2 = [pscustomobject]@{ schema = 'purge.rig.m2ambient/1'; note = ''; records = @('-K:HKLM\SOFTWARE\PurgeExecApp', '+F:C:\ProgramData\Purge\sessions\writer.lock', '~d:c:\programdata\purge', '+F:C:\ProgramData\Purge\x')
                             patterns = @('^\~F:C:\\ProgramData\\Purge\\[0-9a-f]{16}$'); runs = @([pscustomobject]@{ id = 'en1-m3-e2e-vscode'; records = @('~D:C:\ProgramData\Purge\sessions', '-D:C:\ProgramData\Purge\sessions'); patterns = @() }) }
    $r2 = @(Get-M3E2eStoreRefusals $s2)
    $d2 = @(Remove-M3E2eStoreEntries $s2)
    Check 'm3-e2e ambient: the store drop takes exactly the allowed records (any case), nothing else' ($d2.Count -eq 3 -and (@($s2.records) -join '|') -ceq '-K:HKLM\SOFTWARE\PurgeExecApp|+F:C:\ProgramData\Purge\x' -and
        @($s2.patterns).Count -eq 1 -and (@($s2.runs[0].records) -join '|') -ceq '-D:C:\ProgramData\Purge\sessions') "dropped $($d2 -join ' | '); left $(@($s2.records) -join ' | ')"
    Check 'm3-e2e ambient: every other store record or pattern (a removal too) is a refusal, PurgeExec is the fixture check''s' ($r2.Count -eq 3 -and $r2 -contains '+F:C:\ProgramData\Purge\x' -and
        $r2 -contains '-D:C:\ProgramData\Purge\sessions' -and $r2 -contains '^\~F:C:\\ProgramData\\Purge\\[0-9a-f]{16}$' -and @(Get-M3E2eAmbientFixtureHits $s2 @()).Count -eq 4) "refusals $($r2 -join ' | ')"

    # The real rigtool (vm\rigtool\target\release\rigtool.exe, or $env:RIG_REAL_RIGTOOL): 6 null runs of tiny snapshots
    # -> rigtool ambient -> the PowerShell rewrite (store drop, provenance) -> rigtool execdiff --ambient on a gate window
    # loads that set: Windows churn ambient, the broker's exit records broker-exit, the store store; an extra change
    # stays collateral.
    $real = $(if ($env:RIG_REAL_RIGTOOL) { $env:RIG_REAL_RIGTOOL } else { Join-Path $Vm 'rigtool\target\release\rigtool.exe' })
    if (Test-Path -LiteralPath $real -PathType Leaf) {
        $rr = Join-Path $Work 'm3e2e-real'; $rrRuns = Join-Path $rr 'runs'; New-Item -ItemType Directory -Force $rrRuns | Out-Null
        $esc = { param($s) "$s".Replace('\', '\\') }
        $snapText = { param([string[]]$Recs)
            $roots = @('C:\Windows\Prefetch', 'C:\ProgramData\Purge', 'HKLM\SOFTWARE\ChurnSelftest', 'HKLM\SYSTEM\CurrentControlSet\Services\bam', 'HKU\S-1-5-21-1\Software') | ForEach-Object { & $esc $_ }
            "#purge-snap 1`t2026-11-23T07:00:00Z`tSELFTEST`tPro`t26100`n#roots`t$($roots -join "`t")`n" + (@($Recs | ForEach-Object { $_ }) -join "`n") + "`n" }
        $mkD = { param($p, $m) "D`t$(& $esc $p)`t10`t$m`t0" }
        $mkF = { param($p, $s, $m) "F`t$(& $esc $p)`t$s`t20`t$m`t0" }
        $mkK = { param($p, $l, $nv) "K`t$(& $esc $p)`t$l`t$nv`t0" }
        $mkV = { param($p, $n, $h) "V`t$(& $esc $p)`t$(& $esc $n)`t4`t4`t$('{0:x16}' -f $h)`tx" }
        $bam = 'HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1'
        $pca = 'HKU\S-1-5-21-1\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'
        $snapBase = @((& $mkD 'C:\Windows\Prefetch' 1), (& $mkF 'C:\Windows\Prefetch\TASKLIST.EXE-2448BC7D.pf' 100 1), (& $mkF 'C:\Windows\Prefetch\OTHER.EXE-11111111.ini' 100 1),
                  (& $mkD 'C:\ProgramData\Purge' 1), (& $mkD 'C:\ProgramData\Purge\sessions' 1), (& $mkK 'HKLM\SOFTWARE\ChurnSelftest' 1 1), (& $mkV 'HKLM\SOFTWARE\ChurnSelftest' 'Counter' 1))
        # The null window: Windows churn, the broker's writer.lock and the store dirs' mtimes.
        $churnFor = { param($om) @((& $mkD 'C:\Windows\Prefetch' 1), (& $mkF 'C:\Windows\Prefetch\TASKLIST.EXE-2448BC7D.pf' 200 2), (& $mkF 'C:\Windows\Prefetch\OTHER.EXE-11111111.ini' 100 $om),
                   (& $mkK 'HKLM\SOFTWARE\ChurnSelftest' 2 1), (& $mkV 'HKLM\SOFTWARE\ChurnSelftest' 'Counter' 2)) }
        $churn = & $churnFor 1
        $nullAfter = $churn + @((& $mkD 'C:\ProgramData\Purge' 2), (& $mkD 'C:\ProgramData\Purge\sessions' 2), (& $mkF 'C:\ProgramData\Purge\sessions\writer.lock' 0 2))
        $script:RunsDir = $rrRuns
        foreach ($k in 1..6) {
            $r = Get-M3E2eNullRunName $k 'vscode'; $d = Join-Path $rrRuns $r; New-Item -ItemType Directory -Force $d | Out-Null
            [IO.File]::WriteAllText((Join-Path $d "snap-$r-a.tsv.gz"), (& $snapText $snapBase)); [IO.File]::WriteAllText((Join-Path $d "snap-$r-b.tsv.gz"), (& $snapText $nullAfter))
            [IO.File]::WriteAllText((Join-Path $d 'e2e.json'), (ConvertTo-Json (& $newE2e) -Depth 8)); [IO.File]::WriteAllText((Join-Path $d 'run.json'), (ConvertTo-Json (& $newDoc $r) -Depth 8))
        }
        $env:RIG_RIGTOOL = $real
        $realSet = Join-Path $rr 'm3-e2e-ambient.json'
        $M3.ambient = $realSet; $M3.count = 6; $M3.apps = @('vscode'); $M3.prefix = ''
        $msg = $null; try { $null = Invoke-M3E2eBuildAmbient } catch { $msg = $_.Exception.Message }
        $rs = Read-M3Json $realSet
        Check 'm3-e2e ambient (real rigtool): 6 null runs build; the store records dropped, the provenance written' (-not $msg -and $rs -and @($rs.records).Count -eq 3 -and
            -not @(@($rs.records) | Where-Object { "$_" -match '(?i)programdata\\purge' }).Count -and "$($rs.provenance.campaign)" -ceq 'null-selftest' -and "$($rs.note)" -match '3 store entries dropped') "$msg; records $(@($rs.records) -join ' | ')"
        # A gate window: the same churn, the broker's exit records, a session in the store; journal and report of an
        # empty committed session.
        $gateBase = $snapBase + @((& $mkK $bam 1 1), (& $mkV $bam '\Device\HarddiskVolume3\Program Files\Purge\purge-broker.exe' 1), (& $mkK $pca 1 0))
        $gateAfter = $churn + @((& $mkD 'C:\ProgramData\Purge' 2), (& $mkD 'C:\ProgramData\Purge\sessions' 2), (& $mkF 'C:\ProgramData\Purge\sessions\writer.lock' 0 2),
                                (& $mkD 'C:\ProgramData\Purge\sessions\20261123T070000Z-1' 2), (& $mkK $bam 2 1), (& $mkV $bam '\Device\HarddiskVolume3\Program Files\Purge\purge-broker.exe' 2),
                                (& $mkK $pca 2 1), (& $mkV $pca 'C:\Program Files\Purge\purge-broker.exe' 3))
        $sess = '20261123T070000Z-9f3a6c1d2b7e4a50'; $ha = 'a' * 64; $hb = 'b' * 64
        $jl = Join-Path $rr 'journal.jsonl'; $rp = Join-Path $rr 'report.json'
        [IO.File]::WriteAllText($jl, ((ConvertTo-Json -Compress ([ordered]@{ rec = 'header'; schema = 'purge.journal/1'; session = $sess; created = 1; engine_version = '0.1.0'; app = 'vscode'; plan_hash = $ha
                                         selection_hash = $hb; policy_version = 'm1a.6'; mode = 'post'; items = 0; allow_irreversible = $false
                                         volumes = @([ordered]@{ root = 'C:\'; serial = 1; file_system = 'NTFS'; quarantine = "C:\ProgramData\Purge\Quarantine\$sess" }) })) + "`n" +
                                    (ConvertTo-Json -Compress ([ordered]@{ rec = 'commit'; at = 2; counts = [ordered]@{ done = 0; vanished = 0; skipped = 0; held_retry = 0; pending_reboot = 0; failed = 0 }; backup_bytes = 0 })) + "`n"))
        [IO.File]::WriteAllText($rp, (ConvertTo-Json -Depth 5 ([ordered]@{ schema = 'purge.exec/1'; session = $sess; app = 'vscode'; plan_hash = $ha; selection_hash = $hb; state = 'Committed'; started = 1; finished = 2
                                                                         items = @(); counts = [ordered]@{ done = 0; vanished = 0; skipped = 0; held_retry = 0; pending_reboot = 0; failed = 0 }
                                                                         backup_bytes = 0; pending_reboot = $false; restore_point = [ordered]@{ kind = 'NotRequested' }; warnings = @() })))
        $runExec = { param($After, $Name)
            $a = Join-Path $rr "gate-a-$Name.tsv"; $b = Join-Path $rr "gate-b-$Name.tsv"; $o = Join-Path $rr "execdiff-$Name.json"
            [IO.File]::WriteAllText($a, (& $snapText $gateBase)); [IO.File]::WriteAllText($b, (& $snapText $After))
            $ErrorActionPreference = 'Continue'
            $null = & $real execdiff --before $a --after $b --journal $jl --report $rp --ambient $realSet --sid 'S-1-5-21-1' -o $o 2>&1
            [pscustomobject]@{ exit = $LASTEXITCODE; doc = (Read-M3Json $o) } }
        $g1 = & $runExec $gateAfter 'clean'
        $c1 = $(if ($g1.doc) { $g1.doc.counts })
        # The rewritten TASKLIST .pf is execdiff's own windows-prefetch rule now (DECISIONS 2026-11-24, E), ahead of the
        # set; the other churn is the set's. OTHER.EXE-11111111.ini sits in Prefetch but is no .pf: never covered.
        Check 'm3-e2e ambient (real rigtool): execdiff loads the rewritten set: churn ambient, broker exit authorised, collateral 0' ($g1.exit -eq 0 -and $c1 -and [int]$c1.collateral -eq 0 -and [int]$c1.unexplained -eq 0 -and
            [int]$c1.authorised.ambient -eq 2 -and [int]$c1.authorised.'windows-prefetch' -eq 1 -and [int]$c1.authorised.'broker-exit' -eq 2 -and [int]$c1.authorised.store -ge 2 -and "$($g1.doc.inputs.ambient)" -eq $realSet) "exit $($g1.exit); $(if ($c1) { ConvertTo-Json $c1 -Compress -Depth 4 }); collateral $(if ($g1.doc) { ConvertTo-Json @($g1.doc.collateral) -Compress -Depth 4 })"
        $g2 = & $runExec (@(& $churnFor 3) + @($gateAfter | Select-Object -Skip @($churn).Count)) 'extra'
        Check 'm3-e2e ambient (real rigtool): a change the null runs never saw stays collateral' ($g2.exit -ne 0 -and $g2.doc -and [int]$g2.doc.counts.collateral -eq 1 -and "$(@($g2.doc.collateral)[0].path)" -match 'OTHER\.EXE') "exit $($g2.exit)"
        # Nothing preselected: the rig's empty journal and report (New-E2eEmptyExecDocs, as the guest's capture-exec
        # writes them) load in execdiff; the window's churn is ambient, a change the null runs never saw collateral.
        . (Join-Path $Guest 'm3-e2e-ui.ps1')
        $ed = New-E2eEmptyExecDocs 'npp' ([uint64]134399194953885068)
        [IO.File]::WriteAllText($jl, $ed.journal, (New-Object System.Text.UTF8Encoding($false))); [IO.File]::WriteAllText($rp, $ed.report, (New-Object System.Text.UTF8Encoding($false)))
        $e1 = & $runExec ($churn + @((& $mkD 'C:\ProgramData\Purge' 2), (& $mkD 'C:\ProgramData\Purge\sessions' 2), (& $mkF 'C:\ProgramData\Purge\sessions\writer.lock' 0 2)) + @($gateBase | Select-Object -Skip @($snapBase).Count)) 'empty'
        Check 'm3-e2e empty plan (real rigtool): execdiff reads the rig''s empty journal and report; churn ambient, collateral 0, no inconsistency' ($e1.exit -eq 0 -and $e1.doc -and
            [int]$e1.doc.counts.collateral -eq 0 -and [int]$e1.doc.counts.inconsistencies -eq 0 -and "$($e1.doc.session)" -ceq 'rig-empty-npp' -and "$($e1.doc.journal_state)" -ceq 'committed') "exit $($e1.exit); $(if ($e1.doc) { ConvertTo-Json $e1.doc.counts -Compress -Depth 4 })"
        $e2 = & $runExec (@(& $churnFor 3) + @((& $mkD 'C:\ProgramData\Purge' 2), (& $mkD 'C:\ProgramData\Purge\sessions' 2), (& $mkF 'C:\ProgramData\Purge\sessions\writer.lock' 0 2)) + @($gateBase | Select-Object -Skip @($snapBase).Count)) 'empty-extra'
        Check 'm3-e2e empty plan (real rigtool): with the empty journal, a change the null runs never saw is collateral' ($e2.exit -ne 0 -and $e2.doc -and [int]$e2.doc.counts.collateral -eq 1) "exit $($e2.exit)"
        $script:RunsDir = $rd; $M3.ambient = $out
    } else { Write-Host "skip m3-e2e ambient real-rigtool checks (no $real; cargo build --release in vm\rigtool)" }
    Remove-Item Env:\RIG_RIGTOOL

    # Save-M3E2eNullRun: the pulled pair renamed into vm\runs\<run>, run.json written, and it passes the check.
    $ev = Join-Path $Work 'm3e2e-ev\en7-m3-e2e-vscode\vscode'; New-Item -ItemType Directory -Force (Join-Path $ev 'guest') | Out-Null
    foreach ($s in 'a', 'b') { [IO.File]::WriteAllText((Join-Path $ev "guest\snap-$s.tsv.gz"), 'x') }
    [IO.File]::WriteAllText((Join-Path $ev 'guest\e2e.json'), (ConvertTo-Json (& $newE2e) -Depth 8))
    $M3.null_wait = 10
    $why = @(Save-M3E2eNullRun 'en7-m3-e2e-vscode' ([pscustomobject]@{ id = 'vscode' }) ([ordered]@{ base = 'rig-base'; started = 's'; ended = 'e'; error = $null; pulled = $true }) $ev (& $newProv))
    $saved = Read-M3Json (Join-Path $rd 'en7-m3-e2e-vscode\run.json')
    Check 'm3-e2e null: Save-M3E2eNullRun moves the pair to vm\runs\<run> as snap-<run>-a / -b, writes the provenance and passes' ($why.Count -eq 0 -and (Test-Path -LiteralPath (Join-Path $rd 'en7-m3-e2e-vscode\snap-en7-m3-e2e-vscode-b.tsv.gz')) -and
        -not (Test-Path -LiteralPath (Join-Path $ev 'guest\snap-a.tsv.gz')) -and "$($saved.provenance.campaign)" -ceq 'null-selftest' -and "$($saved.provenance.ui_sha256)" -ceq ('d' * 64)) ($why -join '; ')
    $why = @(Save-M3E2eNullRun 'en8-m3-e2e-vscode' ([pscustomobject]@{ id = 'vscode' }) ([ordered]@{ base = 'rig-base'; started = 's'; ended = 'e'; error = 'prepare failed'; pulled = $true }) (Join-Path $Work 'm3e2e-ev\none') (& $newProv))
    Check 'm3-e2e null: a failed null run (no pair, host error) is not saved as one' ($why.Count -ge 3) ($why -join '; ')
    $script:M3E2eProv = $null
    $why = @(Save-M3E2eNullRun 'en9-m3-e2e-vscode' ([pscustomobject]@{ id = 'vscode' }) ([ordered]@{ base = 'rig-base'; started = 's'; ended = 'e'; error = $null; pulled = $true }) $ev)
    Check 'm3-e2e null: a null run saved without the campaign''s provenance fails the check' (@($why | Where-Object { $_ -match 'no provenance' }).Count -eq 1) ($why -join '; ')

    # -NullWaitSec: 1..600 on the host, passed to the guest unchanged; the guest refuses another value, no default.
    $okW = (Assert-M3E2eNullWait 1) -eq 1 -and (Assert-M3E2eNullWait 600) -eq 600 -and (Assert-M3E2eNullWait 10) -eq 10
    $threw = 0; foreach ($w in 0, -1, 601, $null, 'x') { try { $null = Assert-M3E2eNullWait $w } catch { $threw++ } }
    Check 'm3-e2e null: -NullWaitSec 1..600 accepted, 0 / -1 / 601 / none / text refused' ($okW -and $threw -eq 5) "$threw of 5"
    $M3.null_wait = 0; $M3.count = 6; $M3.undo_apps = @()
    $msg = $null; try { Invoke-M3E2eNullCampaign } catch { $msg = $_.Exception.Message }
    Check 'm3-e2e null: a campaign with -NullWaitSec 0 is refused before any VM step' ($msg -match '-NullWaitSec must be 1\.\.600') "$msg"
    $M3.null_wait = 10
    Check 'm3-e2e null: the null wait reaches the guest job text unchanged' ((New-M3E2ePhaseText 'consent-cancel' 'vscode' 'plan' 37 -NullRun) -match ' -WaitSec 37 -NullRun$')
    $cancel2 = [regex]::Match([IO.File]::ReadAllText((Join-Path $Guest 'm3-e2e.ps1')), "(?s)\n    'consent-cancel' \{.*?\n    \}")
    Check 'm3-e2e guest: consent-cancel refuses a wait outside 1..600 and waits exactly -WaitSec' ($cancel2.Value -match 'if \(\$WaitSec -lt 1 -or \$WaitSec -gt 600\) \{ "M3E REFUSED' -and $cancel2.Value -match '\$nw\.seconds = \$WaitSec\r?\n' -and $cancel2.Value -notmatch 'else \{ 10 \}')
    $post = [regex]::Match([IO.File]::ReadAllText((Join-Path $Guest 'm3-e2e.ps1')), "(?s)\n    'capture-post' \{.*?\n    \}")
    Check 'm3-e2e guest: capture-post records every plan item''s key (plan_keys), not only the preselected ones' ($post.Value -match '\$planKeys = @\(\$si \| ForEach-Object \{ Get-E2eTargetKey \$_\.target \}\)' -and $post.Value -match 'plan_keys = \$planKeys')

    # The gate refuses to start without its set (no fallback to the M2 set) and pushes exactly that file.
    $ui = Join-Path $Work 'm3e2e-ui'; New-Item -ItemType Directory -Force $ui | Out-Null; [IO.File]::WriteAllText((Join-Path $ui 'Purge.exe'), 'x')
    $M3.ui = $ui; $M3.base = 'rig-base'; $M3.run = 'e2e-selftest'; $M3.apps = @('npp'); $M3.undo_apps = @()
    $bd = Join-Path $Work 'm3e2e-bin'; New-Item -ItemType Directory -Force $bd | Out-Null
    $M3.engine = Join-Path $bd 'purge-engine.exe'; $M3.broker = Join-Path $bd 'purge-broker.exe'
    [IO.File]::WriteAllText($M3.engine, 'engine'); [IO.File]::WriteAllText($M3.broker, 'broker')
    $bh = Get-M3E2eBinaryHashes
    Check 'm3-e2e: the binaries'' SHA-256 (engine, broker, the UI''s Purge.exe)' ($bh.engine_sha256 -ceq (Get-FileHash -Algorithm SHA256 -LiteralPath $M3.engine).Hash.ToLowerInvariant() -and
        $bh.ui_sha256 -ceq (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ui 'Purge.exe')).Hash.ToLowerInvariant() -and $bh.broker_sha256 -cne $bh.engine_sha256)
    $p = Get-M3E2eProvenance 'rig-base'
    Check 'm3-e2e null: the campaign provenance (campaign, VM, snapshot, hashes, null wait) is complete' ($p.campaign -ceq 'e2e-selftest' -and $p.vm -ceq 'Inbound-Win11-Test' -and $p.snapshot -ceq 'rig-base' -and $p.null_wait -eq 10 -and
        @(Test-M3E2eProvenance ([pscustomobject]$p)).Count -eq 0)
    $M3.broker = Join-Path $bd 'missing-broker.exe'
    $threw = $false; try { $null = Get-M3E2eBinaryHashes } catch { $threw = ($_.Exception.Message -match 'missing broker') }
    Check 'm3-e2e: a missing binary is refused (no provenance without it)' $threw
    $M3.broker = Join-Path $bd 'purge-broker.exe'
    $script:M3PushAmbient = $null
    function Invoke-M3E2eApp { param($AppDef, [bool]$Undo, [string]$Base, [string]$Dir = '', [string]$NullRun = '', $Ambient = $null) $script:appAmbient = $Ambient; throw 'reached the app' }
    $M3.ambient = Join-Path $Work 'no-such-ambient.json'
    $msg = $null; try { Invoke-M3E2e } catch { $msg = $_.Exception.Message }
    Check 'm3-e2e gate: no ambient set -> refused before any VM step' ($msg -match '^no m3-e2e ambient set ' -and -not $script:M3PushAmbient) "$msg"
    $M3.ambient = $out
    $msg = $null; try { Invoke-M3E2e } catch { $msg = $_.Exception.Message }
    Check 'm3-e2e gate: the set is what Push-M2Ambient pushes and its SHA-256 goes to the app' ($msg -eq 'reached the app' -and (Get-M2AmbientFile) -eq $out -and
        "$($script:appAmbient.sha256)" -ceq (Get-FileHash -Algorithm SHA256 -LiteralPath $out).Hash.ToLowerInvariant()) "$msg"
    $M3.run = 'en1-m3-e2e-npp'
    $msg = $null; try { Invoke-M3E2e } catch { $msg = $_.Exception.Message }
    Check 'm3-e2e gate: a null-shaped -RunName is refused' ($msg -match 'shape of a null run') "$msg"
    # Push-M3E2eFiles: a gate app without the resolved set throws; a null run pushes -None.
    function Push-Tools { param([string]$RigTool = '', [string]$Engine = '', [string[]]$Installers = @()) }
    function Push-M2Install { }
    function Push-M2Ambient { param([switch]$None) $script:pushNone = [bool]$None; -not $None }
    function Invoke-Guest([string[]]$Sub) { [pscustomobject]@{ code = 0; out = @() } }
    function Invoke-GuestCmd([string]$CommandLine) { [pscustomobject]@{ code = 0; out = @() } }
    function New-M3SecPayload { $z = Join-Path $Work 'm3e2e-payload.zip'; [IO.File]::WriteAllText($z, 'x'); $z }
    $app = [pscustomobject]@{ id = 'execapp'; kind = 'fixture' }
    $script:M3PushAmbient = $null
    $threw = $false; try { Push-M3E2eFiles $app $false } catch { $threw = ($_.Exception.Message -match 'no m3-e2e ambient set to push') }
    $script:pushNone = $null; Push-M3E2eFiles $app $true
    Check 'm3-e2e: a gate push needs the set, a null push sends none' ($threw -and $script:pushNone -eq $true)
}

# ------------------------------------------------------------- m3-e2e guest library (UI driver, MSI fixtures)
& {
    . (Join-Path $Guest 'm3-e2e-ui.ps1')
    $ErrorActionPreference = 'Stop'
    Check 'm3-e2e-ui: a row of the name' (Test-E2eRowText "Notepad++ (64-bit x64)`r`nNotepad++ Team" 'Notepad++ (64-bit x64)')
    Check 'm3-e2e-ui: a row with the new tag' (Test-E2eRowText "7-Zip 24.08 (x64 edition)new`nIgor Pavlov" '7-Zip 24.08 (x64 edition)')
    Check 'm3-e2e-ui: a row with the spaced new tag (0293f8f)' ((Test-E2eRowText "Git  new`r`nThe Git Development Community" 'Git') -and (Get-E2eRowName "Git  new`r`nx") -eq 'Git' -and -not (Test-E2eRowText 'Git  newer' 'Git'))
    Check 'm3-e2e-ui: the user VS Code is not the system one' (-not (Test-E2eRowText "Microsoft Visual Studio Code (User)new`nMicrosoft Corporation" 'Microsoft Visual Studio Code'))
    Check 'm3-e2e-ui: a longer name is not the row' (-not (Test-E2eRowText 'Gitnew' 'Git ') -and -not (Test-E2eRowText 'GitHub Desktop' 'Git'))
    Check 'm3-e2e-ui: the row name drops the tag' ((Get-E2eRowName "Gitnew`r`nThe Git Development Community") -eq 'Git')
    # The Rust UI (bins\purge-ui): a row is a ListItem named "Name, Publisher, Size"; dialog buttons have ids of their
    # own; a bar is one Text "Title Message".
    Check 'm3-e2e-ui: a Rust UI row of the name' ((Test-E2eRowLabel 'Notepad++ (64-bit x64), Notepad++ Team, 15.2 MB' 'Notepad++ (64-bit x64)') -and (Test-E2eRowLabel 'Unnamed, , 1.0 MB' 'Unnamed'))
    Check 'm3-e2e-ui: a Rust UI row of another name is not the row' (-not (Test-E2eRowLabel 'Microsoft Visual Studio Code (User), Microsoft Corporation, 300 MB' 'Microsoft Visual Studio Code') -and
        -not (Test-E2eRowLabel 'GitHub Desktop, GitHub, Inc., 300 MB' 'Git') -and -not (Test-E2eRowLabel 'Git' 'Git') -and -not (Test-E2eRowLabel '' 'Git') -and -not (Test-E2eRowLabel 'Git, x, 1 MB' ''))
    Check 'm3-e2e-ui: a Rust UI row whose name goes on with ", " passes the label (Select-E2eProgramRow refuses two, then checks DName)' (Test-E2eRowLabel 'Foo, Bar, Contoso, 1 MB' 'Foo')
    Check 'm3-e2e-ui: dialog ids per part (Rust UI)' ((((Get-E2eDialogIds 'PrimaryButton') -join ',') -ceq 'ConfirmUninstallButton,DialogPrimaryButton') -and
        (((Get-E2eDialogIds 'CloseButton') -join ',') -ceq 'ConfirmNotNowButton,DialogCloseButton') -and (((Get-E2eDialogIds 'SecondaryButton') -join ',') -ceq 'ConfirmCheckAgainButton,DialogSecondaryButton') -and
        @(Get-E2eDialogIds 'Other').Count -eq 0)
    Check 'm3-e2e-ui: a bar said as its own element (WinUI) or as the title or message of one Text (Rust UI)' ((Test-E2eSaid @('x', 'Not started.') 'Not started.') -and
        (Test-E2eSaid @('You cancelled the Windows prompt. Not started.') 'Not started.') -and (Test-E2eSaid @('You cancelled the Windows prompt. Not started.') 'You cancelled the Windows prompt.') -and
        (Test-E2eSaid @('Some parts remain The uninstaller ended, but its entry is still there.') 'Some parts remain'))
    Check 'm3-e2e-ui: a bar is never a looser substring or another case' (-not (Test-E2eSaid @('Nothing was not started.') 'Not started.') -and -not (Test-E2eSaid @('Not started.x') 'Not started.') -and
        -not (Test-E2eSaid @('not started.') 'Not started.') -and -not (Test-E2eSaid @() 'x') -and -not (Test-E2eSaid @('x') '') -and -not (Test-E2eSaid @($null, '') 'x'))
    $uiText = [IO.File]::ReadAllText((Join-Path $Guest 'm3-e2e-ui.ps1'))
    $selFn = [regex]::Match($uiText, '(?s)\nfunction Select-E2eProgramRow\(.*?\n\}').Value
    Check 'm3-e2e-ui: Select-E2eProgramRow refuses two rows, wants one row selected and DName to say the name' (
        $selFn -match [regex]::Escape('$rec.how = "ambiguous: $($found.Count) rows by $($try[0])"') -and $selFn -match 'return \$rec' -and
        $selFn -match [regex]::Escape('if ($sel.Count -ne 1) { $ok = $false') -and $selFn -match [regex]::Escape("(Get-E2eName `$d) -ceq `$Name") -and $selFn -match 'Test-E2eRowLabel \(Get-E2eName \$e\) \$Name')
    $dlgFn = [regex]::Match($uiText, '(?s)\nfunction Find-E2eDialogButton\(.*?\n\}').Value
    Check 'm3-e2e-ui: Find-E2eDialogButton takes the Rust UI id and name first and refuses two' ($dlgFn -match 'Get-E2eDialogIds \$Part' -and
        $dlgFn -match 'AutomationIdProperty, \$id' -and $dlgFn -match 'NameProperty, \$Name' -and $dlgFn -match [regex]::Escape('if ($hits.Count -gt 1) { return $null }') -and
        $dlgFn.IndexOf('Get-E2eDialogIds') -lt $dlgFn.IndexOf('Find-E2eButton $Root $Name $Part'))
    # The host probe (2026-11-28): the Rust UI's process has Win32 panes at the top level too (winit's event target,
    # the input indicator windows); a lookup by process id alone returned one. Every driver takes the Window.
    $winFn = [regex]::Match($uiText, '(?s)\nfunction Get-E2eWindow\(.*?\n\}').Value
    Check 'm3-e2e-ui: Get-E2eWindow takes the process''s Window (control type), not any top-level element' ($winFn -match 'ProcessIdProperty, \$ProcessId' -and
        $winFn -match 'ControlTypeProperty, \[System\.Windows\.Automation\.ControlType\]::Window' -and $winFn -match 'AndCondition' -and $winFn -notmatch 'FindFirst')
    $cleanText = [IO.File]::ReadAllText((Join-Path $Guest 'm3-clean.ps1'))
    $cleanFn = [regex]::Match($cleanText, '(?s)\nfunction Find-UiWindow\(.*?\n\}').Value
    $winCs = 'new AndCondition(new PropertyCondition(AutomationElement.ProcessIdProperty, pid), new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Window))'
    $secCs = [IO.File]::ReadAllText((Join-Path $Guest 'm3sec.cs')); $recCs = [IO.File]::ReadAllText((Join-Path $Guest 'm3rec.cs'))
    Check 'm3-clean Find-UiWindow, m3sec.cs and m3rec.cs ui take the Window too' ($cleanFn -match 'ControlType\]::Window' -and $cleanFn -match 'AndCondition' -and
        $secCs.Contains($winCs) -and $recCs.Contains($winCs) -and -not $secCs.Contains('FindFirst(TreeScope.Children, new PropertyCondition(AutomationElement.ProcessIdProperty, pid))') -and
        -not $recCs.Contains('FindFirst(TreeScope.Children, new PropertyCondition(AutomationElement.ProcessIdProperty, pid))'))
    # The Rust UI's confirmation arms its Uninstall 400 ms after it opens (screens::ARM_DELAY; a disabled AccessKit
    # button has no Invoke): the wait and the press take it only enabled.
    $e2eGuest = [IO.File]::ReadAllText((Join-Path $Guest 'm3-e2e.ps1'))
    $awaitPh = [regex]::Match($e2eGuest, "(?s)\n    'ui-await-confirm' \{.*?\n    \}").Value
    $confirmPh = [regex]::Match($e2eGuest, "(?s)\n    'ui-confirm' \{.*?\n    \}").Value
    Check 'm3-e2e: ui-await-confirm and ui-confirm wait for an enabled Uninstall' ($awaitPh -match "Find-E2eDialogButton \`$win 'Uninstall' \} .*-Enabled" -and
        $confirmPh -match "Wait-E2eElement \{ Find-E2eDialogButton \`$win 'Uninstall' \} 15 -Enabled" -and $confirmPh -match '\$btn = \$bw\.el')
    Check 'm3-e2e-ui: exit code from a step detail' ((Get-E2eExitCodeFromText 'Finished, exit code 3010 · quiet mode') -eq 3010 -and $null -eq (Get-E2eExitCodeFromText 'Confirmed gone'))
    Check 'm3-e2e-ui: target keys' ((Get-E2eTargetKey ([pscustomobject]@{ type = 'RegValue'; path = 'HKU\S-1\Software\X'; name = 'Y' })) -eq 'RegValue|hku\s-1\software\x|y|' -and (Get-E2eTargetKey ([pscustomobject]@{ type = 'Task'; path = '\PurgeExecApp\Simple Update' })) -eq 'Task|\purgeexecapp\simple update')
    $c = Compare-E2eSets @('a', 'b') @('b', 'a')
    $d = Compare-E2eSets @('a', 'b') @('a', 'c')
    $f = Compare-E2eSets @('FirewallRule|Ab') @('FirewallRule|ab')
    Check 'm3-e2e-ui: set compare (order-free; missing and extra; a rule id keeps its case)' ($c.equal -and -not $d.equal -and ($d.missing -join ',') -eq 'b' -and ($d.extra -join ',') -eq 'c' -and -not $f.equal)
}
& {
    . (Join-Path $Guest 'm3-e2e-msi.ps1')
    $ErrorActionPreference = 'Stop'
    $md = Join-Path $Work 'msi'
    foreach ($v in '1603', '3010') {
        $r = New-E2eMsi $v (Join-Path $md "purge-e2e-$v.msi")
        $b = Read-E2eMsi $r.path
        $seq = $b.sequence
        $base = ($b.property.ALLUSERS -eq '1' -and $b.property.REBOOT -eq 'ReallySuppress' -and $b.template -eq 'x64;1033' -and $b.property.ProductCode -eq $r.product -and
                 [int]$seq['InstallInitialize'][1] -eq 1500 -and [int]$seq['InstallFinalize'][1] -eq 6600 -and $seq.Contains('RegisterProduct') -and $seq.Contains('RemoveRegistryValues') -and
                 @($b.media).Count -eq 1 -and [int]$b.media[0][0] -eq 1)
        if ($v -eq '1603') {
            $ok = ($base -and $b.custom['PurgeE2eFail'][0] -eq '19' -and $seq['PurgeE2eFail'][0] -eq 'REMOVE="ALL"' -and [int]$seq['PurgeE2eFail'][1] -gt 1500 -and -not $seq.Contains('ScheduleReboot'))
            Check 'm3-e2e-msi: 1603 fixture (Media disk 1; type 19 on REMOVE="ALL" after InstallInitialize)' $ok
        } else {
            $ok = ($base -and $seq['ScheduleReboot'][0] -eq 'REMOVE="ALL"' -and [int]$seq['ScheduleReboot'][1] -lt 6600 -and $b.custom.Count -eq 0)
            Check 'm3-e2e-msi: 3010 fixture (ScheduleReboot on REMOVE="ALL", REBOOT=ReallySuppress)' $ok
        }
    }
}

# ------------------------------------------------- M3 m3-clean-start (rig-m3-clean.ps1, RIG.md section 15)
& {
    . (Join-Path $Vm 'rig-m3-clean.ps1')
    $ErrorActionPreference = 'Stop'
    $threw = $false; try { Assert-M3CleanVm 'Inbound-Win11-Test' } catch { $threw = $true }
    Check 'm3-clean: Inbound-Win11-Test is refused' $threw
    $threw = $false; try { Assert-M3CleanVm 'purge-cleanpro' } catch { $threw = $true }
    Check 'm3-clean: the VM name is case-sensitive' $threw
    $threw = $false; try { Assert-M3CleanVm 'Purge-CleanPro' } catch { $threw = $true }
    Check 'm3-clean: Purge-CleanPro is accepted' (-not $threw)
    $threw = $false; try { $null = Resolve-M3CleanSetup '' } catch { $threw = ($_.Exception.Message -match 'build-installer') }
    Check 'm3-clean: no -Setup names build-installer.ps1' $threw
    $sd = Join-Path $Work 'm3clean-setup'; New-Item -ItemType Directory -Force $sd | Out-Null
    $good = Join-Path $sd 'Purge-Setup-0.1.0.exe'; [IO.File]::WriteAllText($good, 'x')
    $bad = Join-Path $sd 'Other-Setup.exe'; [IO.File]::WriteAllText($bad, 'x')
    Check 'm3-clean: a Purge-Setup-<version>.exe is taken' ((Resolve-M3CleanSetup $good) -eq $good)
    $threw = $false; try { $null = Resolve-M3CleanSetup $bad } catch { $threw = $true }
    Check 'm3-clean: another file name is refused' $threw
    $threw = $false; try { $null = Resolve-M3CleanSetup (Join-Path $sd 'Purge-Setup-9.9.9.exe') } catch { $threw = $true }
    Check 'm3-clean: a missing setup is refused' $threw
    Check 'm3-clean: run name from the start time' ((Get-M3CleanRunName '' ([datetime]'2026-11-22T10:11:12')) -eq '20261122-101112')
    $threw = $false; try { $null = Get-M3CleanRunName '..\x' } catch { $threw = $true }
    Check 'm3-clean: a run name with a path is refused' $threw
    Check 'm3-clean: phase job text' ((New-M3CleanPhaseText 'install' '2' 900) -eq "& 'C:\cr\guest\m3-clean.ps1' -Phase 'install' -Tag '2' -WaitSec 900")
    $threw = $false; try { $null = New-M3CleanPhaseText 'install' "1'; Remove-Item C:\" } catch { $threw = $true }
    Check 'm3-clean: a tag with quotes is refused' $threw
    $steps = @(Get-M3CleanSteps 6)
    $order = @($steps | ForEach-Object { "$($_.phase)$(if ($_.tag) { ':' + $_.tag })" }) -join ' '
    Check 'm3-clean: step order' ($order -eq 'pre motw-start motw-end install:1 ui-start ui-stop bench:6 uninstall-no install:2 uninstall-yes-start uninstall-yes-answer rollback') $order
    Check 'm3-clean: Esc twice before motw-end' ((@($steps | Where-Object { $_.phase -eq 'motw-end' })[0]['keys'] -join ',') -eq 'esc,esc' -and $M3CleanKeys['esc'].Count -eq 2)
    $orderNo = @(Get-M3CleanSteps 6 -NoMotw | ForEach-Object { "$($_.phase)$(if ($_.tag) { ':' + $_.tag })" }) -join ' '
    Check 'm3-clean: -NoMotw drops the two MOTW steps' ($orderNo -eq 'pre install:1 ui-start ui-stop bench:6 uninstall-no install:2 uninstall-yes-start uninstall-yes-answer rollback') $orderNo
    $gm = [IO.File]::ReadAllText((Join-Path $Guest 'm3-clean.ps1'))
    Check 'm3-clean: the guest writes ZoneId=3 with a GitHub release HostUrl' ($gm.Contains('ZoneId=3') -and $gm.Contains('HostUrl=https://github.com/') -and $gm.Contains('-Stream Zone.Identifier'))
    . ([ScriptBlock]::Create([regex]::Match($gm, '(?s)\nfunction Test-NameShown\(.*?\n\}').Value))
    Check 'm3-clean: an ARP name shown as a WinUI row text or a Rust UI row ("Name, Publisher, Size"), not as a type name or a longer name' (
        (Test-NameShown 'Purge' @("Purge`r`nKaan")) -and (Test-NameShown 'Purge' @('Purge, Kaan, 12.0 MB')) -and -not (Test-NameShown 'Purge' @('Purge.App.ProgramRow')) -and
        -not (Test-NameShown 'Purge' @('PurgeX, Kaan, 1 MB')) -and -not (Test-NameShown 'Purge' @('Purge,x')))
    Check 'm3-clean: the notices are the InfoBarHost''s own name (the Rust UI''s one Text) and the names under it (WinUI)' ($gm -match [regex]::Escape('@(@("$($notice.Current.Name)") + @(Get-UiNames $notice) | Where-Object { $_ })'))
    Check 'm3-clean: the names and the data-folder dialog have screenshots' ((@($steps | Where-Object { $_.shot -eq 'ui-names' }).Count -eq 1) -and (@($steps | Where-Object { $_.shot -eq 'uninstall-yes-dialog' }).Count -eq 1))
    $guestText = [IO.File]::ReadAllText((Join-Path $Guest 'm3-clean.ps1'))
    $missing = @(@(@($steps | ForEach-Object { $_.phase }) + 'pack') | Sort-Object -Unique | Where-Object { $guestText -notmatch ("(?m)^\s*'" + [regex]::Escape($_) + "' \{") })
    Check 'm3-clean: m3-clean.ps1 has a branch for every step' ($missing.Count -eq 0) ($missing -join ', ')
    # The ARP key the guest checks is the setup's fixed AppId.
    $iss = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent $Vm) 'install\inno\purge.iss'))
    $m = [regex]::Match($iss, '(?m)^AppId=\{(\{[0-9A-Fa-f-]+\})')
    Check 'm3-clean: guest ARP key = purge.iss AppId' ($m.Success -and $guestText.Contains("'$($m.Groups[1].Value)_is1'")) $(if ($m.Success) { $m.Groups[1].Value })
    $o = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Vm 'truth\m3-clean-score.ps1') --self-test 2>&1 | ForEach-Object { "$_" })
    Check 'm3-clean: m3-clean-score.ps1 --self-test passes' ($LASTEXITCODE -eq 0) (@($o | Select-Object -Last 1) -join '')
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
