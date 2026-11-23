# Host self-test of the rig mode m3-elevated-ci (vm\rig-m3-ci.ps1, vm\guest\m3-ci.ps1; vm\RIG.md section 18). Needs no
# VM and starts nothing in one: the host driver is dot-sourced for its pure functions, and the guest runner runs on this
# host end to end against a fake bundle in a temporary directory (fake test executables and a fake dotnet.exe built
# with the .NET Framework csc.exe). Windows PowerShell 5.1:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File vm\guest\tests\rig-m3-ci.tests.ps1
# Exit 0 when every check passes. (Not under guest\*.ps1, so nothing copies it to the guest.)
$ErrorActionPreference = 'Stop'
$Vm = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Guest = Join-Path $Vm 'guest'
$Repo = Split-Path -Parent $Vm
$script:passes = 0; $script:fails = 0
function Check([string]$Name, [bool]$Cond, [string]$Detail = '') {
    if ($Cond) { $script:passes++; Write-Host "ok   $Name" } else { $script:fails++; Write-Host "FAIL $Name  $Detail" }
}
$Work = Join-Path ([IO.Path]::GetTempPath()) ('rig-m3-ci-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $Work | Out-Null

try {
# ------------------------------------------------------------------------------------------------ parse
$files = @((Join-Path $Vm 'rig-m3-ci.ps1'), (Join-Path $Guest 'm3-ci.ps1'), (Join-Path $Vm 'rig.ps1'), $PSCommandPath)
foreach ($f in $files) {
    $tok = $null; $err = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($f, [ref]$tok, [ref]$err)
    Check "parse $(Split-Path -Leaf $f)" (@($err).Count -eq 0) (@($err | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ')
    # Windows PowerShell reads a BOM-less script in the ANSI code page: ASCII only.
    if ($f -notmatch 'rig\.ps1$') { Check "ascii $(Split-Path -Leaf $f)" (-not ([IO.File]::ReadAllText($f) -match '[^\x00-\x7F]')) }
}
$rigText = [IO.File]::ReadAllText((Join-Path $Vm 'rig.ps1'))
Check 'rig.ps1 -Mode m3-elevated-ci hands over to rig-m3-ci.ps1' ($rigText -match "Mode -ceq 'm3-elevated-ci'" -and $rigText.Contains("'rig-m3-ci.ps1'"))

& {
    . (Join-Path $Vm 'rig-m3-ci.ps1')
    $ErrorActionPreference = 'Stop'

    # ---------------------------------------------------------------------------- xtask ci coverage (drift check)
    $mainRs = [IO.File]::ReadAllText((Join-Path $Repo 'tools\xtask\src\main.rs'))
    $xs = Get-M3CiXtaskSteps $mainRs
    Check 'xtask: seven cargo steps read from main.rs' (@($xs.cargo).Count -eq 7) (@($xs.cargo) -join ' | ')
    Check 'xtask: the constants are substituted' (@($xs.cargo) -contains 'test -p purge-exec --features purge-exec/fault-inject,purge-exec/test-support')
    Check 'xtask: the named steps' ((@($xs.named) -join ',') -eq 'check-deps,no-new-walks,baseline-sites,ui-strings,scanner-coverage,gen-dto --check,ui') (@($xs.named) -join ',')
    $miss = @(Get-M3CiUncovered $xs)
    Check 'xtask: every step of ci is run in the guest or listed host-only' ($miss.Count -eq 0) ($miss -join '; ')
    $added = $mainRs.Replace('&["test", "--workspace"],', '&["test", "--workspace"], &["test", "-p", "purge-new"],')
    $m2 = @(Get-M3CiUncovered (Get-M3CiXtaskSteps $added))
    Check 'xtask: a new cargo step is reported' ($m2.Count -eq 1 -and $m2[0] -eq 'cargo test -p purge-new') ($m2 -join '; ')
    $named = $mainRs.Replace('println!("xtask ci: ui");', 'println!("xtask ci: new-check"); println!("xtask ci: ui");')
    $m3 = @(Get-M3CiUncovered (Get-M3CiXtaskSteps $named))
    Check 'xtask: a new named step is reported' ($m3.Count -eq 1 -and $m3[0] -eq 'new-check') ($m3 -join '; ')
    $gone = $mainRs.Replace('&["test", "-p", "purge-exec", "--features", EXEC_TEST_FEATURES],', '')
    $m4 = @(Get-M3CiUncovered (Get-M3CiXtaskSteps $gone))
    Check 'xtask: a step gone from ci is reported' ($m4.Count -eq 1 -and $m4[0] -like 'gone from xtask: *') ($m4 -join '; ')
    $steps = @(Get-M3CiCargoSteps)
    Check 'steps: xtask order, ui-harness last' ((@($steps | ForEach-Object { $_.id }) -join ',') -eq 'workspace,engine-rig,exec-features,ui-harness')
    Check 'steps: each id is its args joined' (-not @($steps | Where-Object { $_.xtask -and ($_.args -join ' ') -cne $_.xtask }).Count)
    Check 'steps: ui-harness is the command the UI tests run' ([IO.File]::ReadAllText((Join-Path $Repo 'ui\Purge.Client.Tests\BrokerPipeTests.cs')).Contains('"' + ((@($steps)[3].args) -join ' ') + '"'))
    Check 'host-only: every entry has a reason' (-not @(Get-M3CiHostOnly | Where-Object { -not $_.why -or -not $_.step }).Count)
    $ex = @(Get-M3CiExclusions)
    Check 'exclusions: each has step, binary, test and reason' (-not @($ex | Where-Object { -not ($_.step -and $_.binary -and $_.test -and $_.reason) }).Count)
    Check 'exclusions: at most 5 (explicit and small)' ($ex.Count -le 5)

    # ---------------------------------------------------------------------------- cargo JSON
    $pk = @{ 'c:\r\crates\a\cargo.toml' = [pscustomobject]@{ name = 'purge-a'; version = '0.1.0' } }
    $lines = @(
        '{"reason":"compiler-artifact","package_id":"path+file:///C:/r/crates/a#purge-a@0.1.0","manifest_path":"C:\\r\\crates\\a\\Cargo.toml","target":{"kind":["lib"],"name":"purge_a"},"profile":{"test":true},"executable":"C:\\r\\target\\debug\\deps\\purge_a-1.exe","fresh":true}'
        '{"reason":"compiler-artifact","package_id":"path+file:///C:/r/crates/a#purge-a@0.1.0","manifest_path":"C:\\r\\crates\\a\\Cargo.toml","target":{"kind":["lib"],"name":"purge_a"},"profile":{"test":false},"executable":null,"fresh":true}'
        '{"reason":"compiler-artifact","package_id":"path+file:///C:/r/crates/a#purge-a@0.1.0","manifest_path":"C:\\r\\crates\\a\\Cargo.toml","target":{"kind":["bin"],"name":"a"},"profile":{"test":false},"executable":"C:\\r\\target\\debug\\a.exe","fresh":true}'
        '{"reason":"compiler-artifact","package_id":"path+file:///C:/r/crates/a#purge-a@0.1.0","manifest_path":"C:\\r\\crates\\a\\Cargo.toml","target":{"kind":["test"],"name":"it"},"profile":{"test":true},"executable":"C:\\r\\target\\debug\\deps\\it-2.exe","fresh":false}'
        '{"reason":"compiler-artifact","package_id":"path+file:///C:/r/crates/a#purge-a@0.1.0","manifest_path":"C:\\r\\crates\\a\\Cargo.toml","target":{"kind":["test"],"name":"it"},"profile":{"test":true},"executable":"C:\\r\\target\\debug\\deps\\IT-2.exe","fresh":false}'
        '{"reason":"build-finished","success":true}'
        'not json at all'
    )
    $arts = @(ConvertFrom-M3CiCargoJson $lines $pk)
    Check 'cargo json: three executables (no lib without one, no duplicate)' ($arts.Count -eq 3) (@($arts | ForEach-Object { $_.exe }) -join ', ')
    Check 'cargo json: kinds test, support, test' ((@($arts | ForEach-Object { $_.kind }) -join ',') -eq 'test,support,test')
    Check 'cargo json: package, version, directory and label' ($arts[0].package -eq 'purge-a' -and $arts[0].version -eq '0.1.0' -and $arts[0].cwd -eq 'C:\r\crates\a' -and $arts[2].label -eq 'purge-a test it')

    # ---------------------------------------------------------------------------- libtest and TRX
    $ok = "running 3 tests`r`ntest a::x ... ok`r`ntest a::y ... ignored`r`ntest a::z ... ok`r`n`r`ntest result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 4 filtered out; finished in 0.10s`r`n"
    $r = Get-M3CiLibtestResult $ok
    Check 'libtest: ok summary' ($r.summary -and $r.ok -and $r.passed -eq 2 -and $r.failed -eq 0 -and $r.ignored -eq 1 -and $r.filtered_out -eq 4 -and @($r.failing).Count -eq 0)
    $bad = "running 3 tests`ntest a::x ... ok`ntest a::y ... FAILED`ntest a::p - should panic ... FAILED`n`nfailures:`n`n---- a::y stdout ----`npanicked`n`nfailures:`n    a::p`n    a::y`n`ntest result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s`n"
    $r = Get-M3CiLibtestResult $bad
    Check 'libtest: failed summary with the failing names' ($r.summary -and -not $r.ok -and $r.failed -eq 2 -and (@($r.failing) -join ',') -eq 'a::y,a::p') (@($r.failing) -join ',')
    $r = Get-M3CiLibtestResult "running 1 test`nthread 'main' has overflowed its stack`n"
    Check 'libtest: a crash has no summary' (-not $r.summary -and $r.passed -eq 0)
    $trx = @'
<?xml version="1.0" encoding="utf-8"?>
<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Results>
    <UnitTestResult testName="Purge.Client.Tests.A.Good" outcome="Passed" />
    <UnitTestResult testName="Purge.Client.Tests.A.Bad" outcome="Failed" />
    <UnitTestResult testName="Purge.Client.Tests.A.Skip" outcome="NotExecuted" />
  </Results>
  <ResultSummary outcome="Failed">
    <Counters total="3" executed="2" passed="1" failed="1" error="0" timeout="0" aborted="0" inconclusive="0" passedButRunAborted="0" notRunnable="0" notExecuted="1" disconnected="0" warning="0" completed="0" inProgress="0" pending="0" />
  </ResultSummary>
</TestRun>
'@
    $t = Get-M3CiTrxResult $trx
    Check 'trx: counters and failing names' ($t.total -eq 3 -and $t.passed -eq 1 -and $t.failed -eq 1 -and $t.not_executed -eq 1 -and (@($t.failing) -join ',') -eq 'Purge.Client.Tests.A.Bad' -and $t.outcome -eq 'Failed')

    # ---------------------------------------------------------------------------- paths, names, job text
    $threw = $false; try { Assert-M3CiHostPath 'E:\purge-build\target' 'x' } catch { $threw = $true }
    Check 'paths: another drive is refused' $threw
    $threw = $false; try { Assert-M3CiHostPath '\\server\share\purge' 'x' } catch { $threw = $true }
    Check 'paths: a UNC path is refused' $threw
    $threw = $false; try { Assert-M3CiHostPath "C:\Users\k$([char]0xE9)\purge" 'x' } catch { $threw = $true }
    Check 'paths: a non-ASCII path is refused' $threw
    $threw = $false; try { Assert-M3CiHostPath 'C:\Users\k\purge' 'x' } catch { $threw = $true }
    Check 'paths: C: is taken' (-not $threw)
    Check 'paths: relative with /' ((@(ConvertTo-M3CiRelative @('C:\r\target\debug\a.exe', 'c:\R\Target\debug\deps\b.exe') 'C:\r\target\') -join ',') -eq 'debug/a.exe,debug/deps/b.exe')
    $threw = $false; try { $null = @(ConvertTo-M3CiRelative @('C:\r\targetx\a.exe') 'C:\r\target') } catch { $threw = $true }
    Check 'paths: a file outside the base is refused' $threw
    Check 'job text: step' ((New-M3CiPhaseText 'step' 'engine-rig') -eq "& 'C:\cr\m3ci\m3-ci.ps1' -Phase 'step' -Step 'engine-rig'")
    $threw = $false; try { $null = New-M3CiPhaseText 'step' "x'; Remove-Item C:\" } catch { $threw = $true }
    Check 'job text: a step with quotes is refused' $threw
    $threw = $false; try { Assert-M3CiRunName '..\x' } catch { $threw = $true }
    Check 'run name: a path is refused' $threw
    $threw = $false; try { Assert-M3CiRunName 'x-m3-elevated-ci' } catch { $threw = $true }
    Check 'run name: prefix + m3-elevated-ci is taken' (-not $threw)

    # ---------------------------------------------------------------------------- the guest runner, end to end
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $csc)) { Check 'runner: csc.exe present (needed for the fake executables)' $false $csc; return }
    $src = Join-Path $Work 'src'; New-Item -ItemType Directory -Force $src | Out-Null
    # A libtest stand-in: behaves by CARGO_PKG_NAME (good / bad / hang), prints its working directory, env and arguments.
    [IO.File]::WriteAllText((Join-Path $src 'fake.cs'), @'
using System;
static class FakeTest {
    static int Main(string[] a) {
        Console.WriteLine("cwd=" + Environment.CurrentDirectory);
        Console.WriteLine("manifest=" + Environment.GetEnvironmentVariable("CARGO_MANIFEST_DIR"));
        Console.WriteLine("args=" + string.Join(" ", a));
        string p = Environment.GetEnvironmentVariable("CARGO_PKG_NAME");
        if (p == "hang") { System.Threading.Thread.Sleep(60000); return 0; }
        if (p == "bad") {
            Console.WriteLine("running 2 tests\ntest t::one ... ok\ntest t::two ... FAILED\n");
            Console.Error.WriteLine("thread 't::two' panicked");
            Console.WriteLine("test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s");
            return 101;
        }
        Console.WriteLine("running 2 tests\ntest t::one ... ok\ntest t::two ... ignored\n");
        Console.WriteLine("test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s");
        return 0;
    }
}
'@)
    # A dotnet.exe stand-in: writes a TRX into --results-directory and reports what the runner set up.
    [IO.File]::WriteAllText((Join-Path $src 'dotnet.cs'), @'
using System; using System.IO;
static class FakeDotnet {
    static int Main(string[] a) {
        Console.WriteLine("args=" + string.Join(" ", a));
        Console.WriteLine("root=" + Environment.GetEnvironmentVariable("DOTNET_ROOT"));
        Console.WriteLine("target=" + Environment.GetEnvironmentVariable("CARGO_TARGET_DIR"));
        Console.WriteLine("path0=" + Environment.GetEnvironmentVariable("PATH").Split(';')[0]);
        string dir = null;
        for (int i = 0; i + 1 < a.Length; i++) if (a[i] == "--results-directory") dir = a[i + 1];
        File.WriteAllText(Path.Combine(dir, "ui.trx"), "<TestRun xmlns=\"http://microsoft.com/schemas/VisualStudio/TeamTest/2010\"><Results><UnitTestResult testName=\"X.Y\" outcome=\"Passed\" /></Results><ResultSummary outcome=\"Completed\"><Counters total=\"1\" executed=\"1\" passed=\"1\" failed=\"0\" notExecuted=\"0\" /></ResultSummary></TestRun>");
        return 0;
    }
}
'@)
    foreach ($n in 'fake', 'dotnet') {
        $o = @(& $csc /nologo /target:exe "/out:$(Join-Path $src "$n.exe")" (Join-Path $src "$n.cs") 2>&1)
        Check "runner: csc builds $n.exe" ($LASTEXITCODE -eq 0) ($o -join ' ')
    }
    $root = Join-Path $Work 'root'; $target = Join-Path $Work 'target'; $repo = Join-Path $Work 'repo'; $uidir = Join-Path $Work 'uiout'
    foreach ($d in $root, (Join-Path $target 'debug\deps'), (Join-Path $target 'debug\examples'), (Join-Path $repo 'crates\good'), (Join-Path $repo 'crates\bad'), (Join-Path $repo 'crates\hang'), $uidir, (Join-Path $Work 'dn')) { New-Item -ItemType Directory -Force $d | Out-Null }
    $exes = @{}
    foreach ($n in 'good', 'bad', 'hang') { $exes[$n] = Join-Path $target "debug\deps\$n-1.exe"; Copy-Item (Join-Path $src 'fake.exe') $exes[$n] }
    Copy-Item (Join-Path $src 'fake.exe') (Join-Path $target 'debug\examples\pipe_harness.exe')
    Copy-Item (Join-Path $src 'dotnet.exe') (Join-Path $Work 'dn\dotnet.exe')
    [IO.File]::WriteAllText((Join-Path $repo 'Cargo.toml'), '[workspace]')
    [IO.File]::WriteAllText((Join-Path $uidir 'Purge.Client.Tests.dll'), 'not a real assembly')
    $null = New-M3CiTar (Join-Path $root 'step-s1.tgz') $target @('debug/deps/good-1.exe', 'debug/deps/bad-1.exe', 'debug/deps/hang-1.exe')
    $null = New-M3CiTar (Join-Path $root 'step-ui-harness.tgz') $target @('debug/examples/pipe_harness.exe')
    $null = New-M3CiTar (Join-Path $root 'repo.tgz') $repo @('Cargo.toml')
    $null = New-M3CiTar (Join-Path $root 'ui.tgz') $uidir @('Purge.Client.Tests.dll')
    $null = New-M3CiTar (Join-Path $root 'dotnet.tgz') (Join-Path $Work 'dn') @('dotnet.exe')
    New-M3CiFakeCargo (Join-Path $root 'cargo-standin.exe')
    $sc = Join-Path $root 'cargo-standin.exe'
    $null = & $sc build -q -p purge-broker --example pipe_harness; $c1 = $LASTEXITCODE
    $ErrorActionPreference = 'Continue'
    $null = & $sc build -p purge-broker 2>&1; $c2 = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Check 'cargo stand-in: exit 0 for the harness build, 101 for anything else' ($c1 -eq 0 -and $c2 -eq 101) "$c1 $c2"
    # Remove the executables from the target: the runner must put them back from the step archive.
    Remove-Item -LiteralPath $exes['good'], $exes['bad'], $exes['hang'], (Join-Path $target 'debug\examples\pipe_harness.exe') -Force
    Remove-Item -LiteralPath (Join-Path $repo 'Cargo.toml') -Force
    $sha = @{}; foreach ($n in 'good', 'bad', 'hang') { $sha[$n] = (Get-FileHash -LiteralPath (Join-Path $src 'fake.exe') -Algorithm SHA256).Hash.ToLowerInvariant() }
    $bin = { param($n, $i, $skip) [ordered]@{ n = $i; label = "$n test it"; package = $n; version = '0.1.0'; target = 'it'; target_kind = 'test'; exe = $exes[$n]
                                              cwd = (Join-Path $repo "crates\$n"); sha256 = $sha[$n]; bytes = 1; skip = @($skip) } }
    $man = [ordered]@{ schema = 'purge.rig.m3ci.manifest/1'; commit = 'abc'; dirty = @(); rustc = 'rustc test'
                       repo = [ordered]@{ archive = 'repo.tgz'; dir = $repo }; target_dir = $target; make_dirs = @((Join-Path $target 'tmp'))
                       steps = @([ordered]@{ id = 's1'; cargo = 'test --workspace'; xtask = 'test --workspace'; archive = 'step-s1.tgz'
                                             binaries = @((& $bin 'good' '001' @('t::x', 't::y')), (& $bin 'bad' '002' @()), (& $bin 'hang' '003' @())) })
                       ui = [ordered]@{ archive = 'ui.tgz'; dir = $uidir; dll = (Join-Path $uidir 'Purge.Client.Tests.dll'); dll_sha256 = 'x'; harness_archive = 'step-ui-harness.tgz'; filter = '' }
                       dotnet = [ordered]@{ archive = 'dotnet.tgz'; sdk = '10.0.0' }; fakecargo = 'cargo-standin.exe'
                       threads = 2; timeout_bin = 5; timeout_ui = 60; host_only = @(Get-M3CiHostOnly); exclusions = @() }
    [IO.File]::WriteAllText((Join-Path $root 'manifest.json'), (ConvertTo-Json -InputObject $man -Depth 8), (New-Object Text.UTF8Encoding($false)))
    $runner = Join-Path $Guest 'm3-ci.ps1'
    $phaseOut = @{}
    foreach ($ph in @(@('unpack', ''), @('step', 's1'), @('ui', ''), @('pack', ''))) {
        $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $runner, '-Phase', $ph[0], '-Root', $root)
        if ($ph[1]) { $a += @('-Step', $ph[1]) }
        $ErrorActionPreference = 'Continue'
        $o = @(& powershell.exe @a 2>&1 | ForEach-Object { "$_" })
        $ErrorActionPreference = 'Stop'
        $phaseOut[$ph[0]] = $o
        Check "runner: phase $($ph[0]) exits 0 with its M3CI line" ($LASTEXITCODE -eq 0 -and @($o | Where-Object { $_ -match "^M3CI $($ph[0]) " }).Count -eq 1) (($o | Select-Object -Last 4) -join ' | ')
    }
    Check 'runner unpack: repo, ui, dotnet, stand-in, make_dirs in place' ((Test-Path (Join-Path $repo 'Cargo.toml')) -and (Test-Path (Join-Path $uidir 'Purge.Client.Tests.dll')) -and (Test-Path (Join-Path $root 'dotnet\dotnet.exe')) -and (Test-Path (Join-Path $root 'fakecargo\cargo.exe')) -and (Test-Path (Join-Path $target 'tmp')))
    $up = Get-Content -LiteralPath (Join-Path $root 'out\unpack.json') -Raw | ConvertFrom-Json
    Check 'runner unpack: records the token' ($null -ne $up.token -and $up.token.integrity -match 'Level')
    Check 'runner step: the step archive put the executables back' ((Test-Path $exes['good']) -and (Test-Path $exes['hang']))
    $o1 = [IO.File]::ReadAllText((Join-Path $root 'out\s1\001.txt'))
    Check 'runner step: working directory = package directory, CARGO_MANIFEST_DIR set' ($o1.Contains("cwd=$(Join-Path $repo 'crates\good')") -and $o1.Contains("manifest=$(Join-Path $repo 'crates\good')")) $o1
    Check 'runner step: --test-threads and the exclusions with --exact' ($o1.Contains('args=--test-threads=2 --skip t::x --skip t::y --exact')) $o1
    $o2 = [IO.File]::ReadAllText((Join-Path $root 'out\s1\002.txt'))
    Check 'runner step: stderr is appended to the output' ($o2.Contains('----- stderr -----') -and $o2.Contains("thread 't::two' panicked"))
    $res = Get-Content -LiteralPath (Join-Path $root 'out\s1\results.json') -Raw | ConvertFrom-Json
    $rows = @($res.binaries)
    Check 'runner step: exit codes 0, 101 and a timeout' ($rows.Count -eq 3 -and $rows[0].exit -eq 0 -and $rows[1].exit -eq 101 -and $rows[2].timed_out -and $null -eq $rows[2].exit) (ConvertTo-Json $rows -Compress)
    Check 'runner step: the hung process tree is gone' (-not @(Get-Process -Name 'hang-1' -ErrorAction SilentlyContinue).Count)
    Check 'runner step: SHA-256 of what ran' ($rows[0].sha256 -eq $sha['good'])
    $ou = [IO.File]::ReadAllText((Join-Path $root 'out\ui\dotnet-test.txt'))
    Check 'runner ui: dotnet test <dll> with TRX logger and results directory' ($ou.Contains("args=test $(Join-Path $uidir 'Purge.Client.Tests.dll') --logger trx;LogFileName=ui.trx --results-directory $(Join-Path $root 'out\ui')")) $ou
    Check 'runner ui: DOTNET_ROOT, CARGO_TARGET_DIR, the stand-in first on PATH' ($ou.Contains("root=$(Join-Path $root 'dotnet')") -and $ou.Contains("target=$target") -and $ou.Contains("path0=$(Join-Path $root 'fakecargo')")) $ou
    Check 'runner ui: the harness archive put pipe_harness.exe back' (Test-Path (Join-Path $target 'debug\examples\pipe_harness.exe'))
    Check 'runner pack: out.tgz' (Test-Path (Join-Path $root 'out.tgz'))

    # ---------------------------------------------------------------------------- result document and verdict
    $CI.run = 'selftest-m3-elevated-ci'
    $doc = New-M3CiResult ([pscustomobject]$man) (Join-Path $root 'out') 'host' (Get-Date).ToString('o') $null
    $b = @($doc.steps[0].binaries)
    Check 'result: per binary counts and failing names' ($b[0].passed -eq 1 -and $b[0].ignored -eq 1 -and $b[0].pass -and $b[1].failed -eq 1 -and (@($b[1].failing) -join ',') -eq 't::two' -and -not $b[1].pass -and $b[2].timed_out -and -not $b[2].pass)
    Check 'result: SHA-256 bound (host = guest)' ($b[0].sha_match -and $b[0].guest_sha256 -eq $b[0].sha256)
    Check 'result: the excluded tests are listed per binary' ((@($b[0].skipped_by_rig) -join ',') -eq 't::x,t::y')
    Check 'result: ui counts from the TRX, the dll hash mismatch seen' ($doc.ui.trx -and $doc.ui.total -eq 1 -and $doc.ui.passed -eq 1 -and -not $doc.ui.sha_match)
    Check 'result: totals' ($doc.totals.binaries -eq 3 -and $doc.totals.passed -eq 2 -and $doc.totals.failed -eq 1 -and $doc.totals.ui_total -eq 1)
    Check 'result: not a pass (exit 101, timeout, ui hash)' (-not $doc.pass -and @($doc.why | Where-Object { $_ -match 'exit 101' }).Count -eq 1 -and @($doc.why | Where-Object { $_ -match 'timed out' }).Count -eq 1 -and @($doc.why | Where-Object { $_ -match 'ui: the guest' }).Count -eq 1) (@($doc.why) -join ' | ')
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Check 'result: admin is what the runner''s token was' ($doc.admin -eq $isAdmin -and ($isAdmin -or @($doc.why | Where-Object { $_ -match 'admin=false' }).Count -eq 1))
    Check 'result: host-only steps carried with reasons' (@($doc.host_only).Count -eq @(Get-M3CiHostOnly).Count)
    $json = ConvertTo-Json -InputObject $doc -Depth 10
    Check 'result: schema purge.rig.m3elevatedci/1, serialises' (($json | ConvertFrom-Json).schema -eq 'purge.rig.m3elevatedci/1')

    # The verdict alone: a clean document passes; each defect fails it.
    $mk = {
        [pscustomobject]@{ error = $null; admin = $true
            steps = @([pscustomobject]@{ id = 's'; binaries = @([pscustomobject]@{ label = 'p test t'; exit = 0; timed_out = $false; summary = $true; failed = 0; failing = @(); sha_match = $true }) })
            ui = [pscustomobject]@{ skipped = $false; timed_out = $false; trx = $true; exit = 0; failed = 0; failing = @(); total = 5; sha_match = $true } }
    }
    Check 'verdict: a clean document passes' ((Get-M3CiVerdict (& $mk)).pass)
    $cases = @(
        @{ n = 'not admin'; f = { param($d) $d.admin = $false } },
        @{ n = 'an error'; f = { param($d) $d.error = 'x' } },
        @{ n = 'no summary'; f = { param($d) $d.steps[0].binaries[0].summary = $false } },
        @{ n = 'a failed count with exit 0'; f = { param($d) $d.steps[0].binaries[0].failed = 1 } },
        @{ n = 'a sha mismatch'; f = { param($d) $d.steps[0].binaries[0].sha_match = $false } },
        @{ n = 'no binary in a step'; f = { param($d) $d.steps[0].binaries = @() } },
        @{ n = 'ui skipped'; f = { param($d) $d.ui = [pscustomobject]@{ skipped = $true } } },
        @{ n = 'ui without TRX'; f = { param($d) $d.ui.trx = $false } },
        @{ n = 'ui with no test'; f = { param($d) $d.ui.total = 0 } },
        @{ n = 'ui failed'; f = { param($d) $d.ui.failed = 2 } }
    )
    foreach ($c in $cases) { $d = & $mk; & $c.f $d; Check "verdict: $($c.n) fails" (-not (Get-M3CiVerdict $d).pass) }
}

} catch {
    $script:fails++
    Write-Host "FAIL unexpected error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)"
} finally {
    Get-Process -Name 'hang-1' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("{0} passed, {1} failed" -f $script:passes, $script:fails)
if ($script:fails) { exit 1 }
exit 0
