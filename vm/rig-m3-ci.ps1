<#
  Purge rig, M3 mode m3-elevated-ci: the elevated half of gate G1, "xtask ci --require-ui passes, elevated and
  unelevated" (docs\M3_DESIGN.md 12 G1; docs\M3_FINISH_PLAN.md B2, coordinator ruling: elevated ci runs in the Inbound
  VM, not on the host). vm\RIG.md section 18. Host driver, Windows PowerShell 5.1; dot-sources rig.ps1 (-VmName
  Inbound-Win11-Test) for the VM helpers and changes nothing there. Guest side vm\guest\m3-ci.ps1. Self-test
  vm\guest\tests\rig-m3-ci.tests.ps1.

    $env:VMPWFILE = 'C:\path\to\pw.txt'
    .\vm\rig-m3-ci.ps1                       # or: .\vm\rig.ps1 -Mode m3-elevated-ci [-RunPrefix x-] [-Snapshot rig-base]
    .\vm\rig-m3-ci.ps1 -BuildOnly            # host side only: build, collect, bundle, manifest (no VM)
    .\vm\rig-m3-ci.ps1 -HostRun -Threads 2   # dry run of the guest runner on this host (no VM; the token is this shell's)

  What runs where. `cargo xtask ci --require-ui` (tools\xtask\src\main.rs) has test steps, whose result can depend on the
  token, and static steps, whose result cannot. The test steps run in the guest by the elevated rig agent:
    workspace      cargo test --workspace
    engine-rig     cargo test -p purge-engine --features purge-engine/rig-exec,purge-exec/test-support --lib --test exec_cli --test engine
    exec-features  cargo test -p purge-exec --features purge-exec/fault-inject,purge-exec/test-support
    ui             dotnet test of ui\Purge.Client.Tests (the assembly `dotnet build ui\Purge.slnx` built)
  The guest has no Rust toolchain and no .NET SDK of its own, so the host builds each cargo step with the same
  arguments, profile (dev) and features as xtask ci plus `--no-run --message-format=json`, and takes the executables from
  cargo's compiler-artifact messages: the test executables, and the binaries and examples the step built (the tests start
  them through env!("CARGO_BIN_EXE_*")). Each step's executables are archived right after its build: purge-engine.exe is
  built with and without rig-exec by different steps, and the guest gets each step's own copy before that step runs. The
  UI tests start the pipe_harness example through `cargo build -q -p purge-broker --example pipe_harness`; the host runs
  that command (step ui-harness, no tests), and the guest answers it with a stand-in cargo.exe that accepts that one
  command line and fails any other. `dotnet test` runs with a portable copy of the host's .NET SDK (dotnet.exe, host\fxr,
  shared\Microsoft.NETCore.App, sdk\<version>, sdk-manifests), whatever .NET the guest has (recorded).
  The static steps (fmt, the three clippy runs, the doctests, check-deps, no-new-walks, baseline-sites, ui-strings,
  scanner-coverage, gen-dto --check, dotnet build) stay on the host; Get-M3CiHostOnly gives each one's reason, and the
  driver refuses to run when tools\xtask\src\main.rs has a step that is neither run here nor listed host-only.

  Paths. Tests read the repository through env!("CARGO_MANIFEST_DIR") (baked in at build time: the host's absolute path)
  and run with the package directory as working directory, like cargo. The guest gets the checkout's tracked files (and
  the two untracked rig files two tests read when present, Get-M3CiRepoExtras) at the same absolute path, the
  executables at their paths under the target directory, and the UI test output at its path. The checkout and its target
  directory must be on C: (refused otherwise). Each binary runs with CARGO_MANIFEST_DIR, CARGO_PKG_NAME and
  CARGO_PKG_VERSION set as cargo sets them.

  Output: vm\runs\<run>\ (default run m3-elevated-ci; an existing one is moved to vm\runs\_old\): m3-elevated-ci.json
  (schema purge.rig.m3elevatedci/1: commit, dirty, per binary exit code, pass/fail/ignored counts, failing test names,
  SHA-256 on the host and in the guest; the UI test counts and failures; the guest token; host-only steps and
  exclusions with reasons; pass), rig.log, build\*.log (cargo and dotnet stderr), jobs\*.log, guest\ (the guest's
  outputs: <step>\<n>.txt libtest output per binary, results.json, ui\ui.trx). The bundle is built in
  %TEMP%\m3ci-<run> and deleted after a VM run unless -KeepBundle.

  Refuses (exit 2) unless VMPWFILE names a readable file, the VM exists, no VirtualBox VM runs, the lock
  vm\runs\.lock-Inbound-Win11-Test is free and the checkout is clean (-AllowDirty records the dirty files and goes on).
  Exit 0 when the verdict is pass, 1 otherwise.
#>
[CmdletBinding()]
param(
    [string] $Snapshot = 'rig-base',
    [string] $Run = 'm3-elevated-ci',
    [switch] $BuildOnly,
    [switch] $HostRun,
    [switch] $SkipUi,
    [switch] $AllowDirty,
    # libtest --test-threads (0: libtest's default, as xtask ci runs it).
    [int] $Threads = 0,
    [int] $TimeoutBinSec = 1800,
    [int] $TimeoutUiSec = 1800,
    [int] $AgentTimeoutSec = 600,
    [switch] $KeepBundle
)
$ErrorActionPreference = 'Stop'

# rig.ps1 has parameters of its own (Snapshot, Mode, RunPrefix, ...): ours are kept here first. The VM is fixed.
$CI = [ordered]@{ snapshot = $Snapshot; run = $Run; build_only = [bool]$BuildOnly; host_run = [bool]$HostRun; skip_ui = [bool]$SkipUi
                  allow_dirty = [bool]$AllowDirty; threads = $Threads; timeout_bin = $TimeoutBinSec; timeout_ui = $TimeoutUiSec
                  agent_timeout = $AgentTimeoutSec; keep_bundle = [bool]$KeepBundle; vm = 'Inbound-Win11-Test' }
. (Join-Path $PSScriptRoot 'rig.ps1') -VmName $CI.vm

$M3CiGuestRoot = 'C:\cr\m3ci'
$M3CiSchema = 'purge.rig.m3elevatedci/1'
$script:CiLock = $null

# ------------------------------------------------------------------------------------------------- pure: what runs

# The cargo steps run in the guest, in xtask ci's order. `xtask` is the step as tools\xtask\src\main.rs writes it (the
# drift check compares the two); ui-harness is not an xtask step but the cargo command the UI tests run themselves.
function Get-M3CiCargoSteps {
    @(
        [ordered]@{ id = 'workspace'; args = @('test', '--workspace'); xtask = 'test --workspace' }
        [ordered]@{ id = 'engine-rig'; args = @('test', '-p', 'purge-engine', '--features', 'purge-engine/rig-exec,purge-exec/test-support', '--lib', '--test', 'exec_cli', '--test', 'engine')
                    xtask = 'test -p purge-engine --features purge-engine/rig-exec,purge-exec/test-support --lib --test exec_cli --test engine' }
        [ordered]@{ id = 'exec-features'; args = @('test', '-p', 'purge-exec', '--features', 'purge-exec/fault-inject,purge-exec/test-support')
                    xtask = 'test -p purge-exec --features purge-exec/fault-inject,purge-exec/test-support' }
        [ordered]@{ id = 'ui-harness'; args = @('build', '-q', '-p', 'purge-broker', '--example', 'pipe_harness'); xtask = $null }
    )
}

# The steps of xtask ci that stay on the host, and why their result does not depend on the token.
function Get-M3CiHostOnly {
    $lint = 'static analysis at compile time: rustc and clippy read the sources and call no Windows API whose answer depends on the token'
    @(
        [ordered]@{ step = 'fmt --all -- --check'; why = 'compares the sources with rustfmt''s layout; reads text only' }
        [ordered]@{ step = 'clippy --workspace --all-targets -- -D warnings'; why = $lint }
        [ordered]@{ step = 'clippy -p purge-mcp --all-targets -- -D warnings'; why = $lint }
        [ordered]@{ step = 'clippy -p purge-engine -p purge-exec --features purge-engine/rig-exec,purge-exec/test-support --all-targets -- -D warnings'; why = $lint }
        [ordered]@{ step = 'doctests of test --workspace'; why = 'rustdoc compiles and runs them at test time and the guest has no toolchain; the workspace''s doctests are compile_fail type checks (purge-exec journal writer) and one example of a pure function (purge-model bind); none calls Windows' }
        [ordered]@{ step = 'check-deps'; why = 'reads cargo metadata and source text' }
        [ordered]@{ step = 'no-new-walks'; why = 'reads source text' }
        [ordered]@{ step = 'baseline-sites'; why = 'reads source text' }
        [ordered]@{ step = 'ui-strings'; why = 'compares string literals of the sources with a reference file; reads text only' }
        [ordered]@{ step = 'scanner-coverage'; why = 'compares compiled-in tables; no system call' }
        [ordered]@{ step = 'gen-dto --check'; why = 'regenerates schemas and C# glue from the Rust types and compares files' }
        [ordered]@{ step = 'dotnet build ui\Purge.slnx'; why = 'compilation; the guest runs the assembly it built' }
    )
}

# Tests that do not run in the guest for a reason unrelated to elevation: { step; binary (regex on the label
# '<package> <kind> <target>'); test (exact libtest name, or a dotnet test filter term for step ui); reason }. Kept
# explicit and small; each one is passed to libtest as `--skip <test> --exact` and listed in the report.
function Get-M3CiExclusions { @() }

# Untracked rig files that tests read when present (absent, they pass without the check); mirrored when the host has them.
function Get-M3CiRepoExtras { @('vm/runs/npp/lists-npp-2.json', 'vm/runs/dirty-base/snap-dirty-base-0.tsv.gz') }

# ------------------------------------------------------------------------------------------------- pure: parsing

# The test steps and the named steps of xtask ci, read from tools\xtask\src\main.rs: cargo steps as argument strings
# (constants substituted) and the names after "xtask ci: ".
function Get-M3CiXtaskSteps([string]$MainRs) {
    $consts = @{}
    foreach ($m in [regex]::Matches($MainRs, 'const\s+(\w+)\s*:\s*&str\s*=\s*"([^"]*)"\s*;')) { $consts[$m.Groups[1].Value] = $m.Groups[2].Value }
    $start = $MainRs.IndexOf('let cargo_steps')
    if ($start -lt 0) { throw 'xtask main.rs: no cargo_steps' }
    $eq = $MainRs.IndexOf('=', $start)
    $open = $MainRs.IndexOf('[', $eq)
    $depth = 0; $end = -1
    for ($i = $open; $i -lt $MainRs.Length; $i++) {
        $c = $MainRs[$i]
        if ($c -eq '[') { $depth++ } elseif ($c -eq ']') { $depth--; if ($depth -eq 0) { $end = $i; break } }
    }
    if ($end -lt 0) { throw 'xtask main.rs: cargo_steps not closed' }
    $body = $MainRs.Substring($open + 1, $end - $open - 1)
    $body = [regex]::Replace($body, '//[^\r\n]*', '')
    $cargo = @()
    foreach ($m in [regex]::Matches($body, '&\[([^\]]*)\]')) {
        $parts = @()
        foreach ($t in [regex]::Matches($m.Groups[1].Value, '"([^"]*)"|\b([A-Z][A-Z0-9_]+)\b')) {
            if ($t.Groups[1].Success) { $parts += $t.Groups[1].Value }
            elseif ($consts.ContainsKey($t.Groups[2].Value)) { $parts += $consts[$t.Groups[2].Value] }
            else { throw "xtask main.rs: unknown constant $($t.Groups[2].Value)" }
        }
        $cargo += ($parts -join ' ')
    }
    $named = @([regex]::Matches($MainRs, 'println!\("xtask ci: ([a-z][a-z -]*[a-z])"\)') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -ne 'all steps passed' })
    [pscustomobject]@{ cargo = $cargo; named = $named }
}

# Every xtask ci step is either run in the guest or listed host-only; returns the ones that are neither (empty = covered).
function Get-M3CiUncovered($XtaskSteps) {
    $run = @(Get-M3CiCargoSteps | Where-Object { $_.xtask } | ForEach-Object { $_.xtask })
    $host1 = @(Get-M3CiHostOnly | ForEach-Object { $_.step })
    $miss = @()
    foreach ($s in $XtaskSteps.cargo) { if ($run -cnotcontains $s -and $host1 -cnotcontains $s) { $miss += "cargo $s" } }
    foreach ($n in $XtaskSteps.named) {
        if ($n -ceq 'ui') { continue }   # dotnet build (host-only) and dotnet test (step ui)
        if ($host1 -cnotcontains $n) { $miss += $n }
    }
    # A step this script runs or lists that xtask ci no longer has is drift too.
    foreach ($s in $run) { if ($XtaskSteps.cargo -cnotcontains $s) { $miss += "gone from xtask: cargo $s" } }
    $miss
}

# Executables of cargo's --message-format=json output. $Packages maps a manifest path (lower case) to {name, version}.
# Returns one object per distinct executable: kind 'test' (a libtest harness: profile.test) or 'support' (a binary or
# example the step built), with the package, its directory, the target and a label.
function ConvertFrom-M3CiCargoJson([string[]]$Lines, [hashtable]$Packages) {
    $seen = @{}
    $out = @()
    foreach ($l in $Lines) {
        if ("$l" -notmatch '"reason":"compiler-artifact"') { continue }
        $a = "$l" | ConvertFrom-Json
        if (-not $a.executable) { continue }
        $exe = "$($a.executable)"
        if ($seen.ContainsKey($exe.ToLowerInvariant())) { continue }
        $seen[$exe.ToLowerInvariant()] = $true
        $mp = "$($a.manifest_path)"
        $pkg = $Packages[$mp.ToLowerInvariant()]
        $name = $(if ($pkg) { $pkg.name } else { "$($a.target.name)" })
        $tk = "$(@($a.target.kind)[0])"
        $isTest = [bool]$a.profile.test
        $out += [pscustomobject]@{ kind = $(if ($isTest) { 'test' } else { 'support' }); exe = $exe; package = $name
                                   version = $(if ($pkg) { $pkg.version } else { '' }); cwd = (Split-Path -Parent $mp)
                                   target = "$($a.target.name)"; target_kind = $tk; label = "$name $tk $($a.target.name)" }
    }
    $out
}

# libtest's output of one binary: counts from "test result:", the names of the failed tests, whether a summary exists.
function Get-M3CiLibtestResult([string]$Text) {
    $r = [ordered]@{ summary = $false; ok = $false; passed = 0; failed = 0; ignored = 0; measured = 0; filtered_out = 0; failing = @() }
    $m = [regex]::Matches($Text, '(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out')
    if ($m.Count) {
        $g = $m[$m.Count - 1].Groups
        $r.summary = $true; $r.ok = ($g[1].Value -eq 'ok')
        $r.passed = [int]$g[2].Value; $r.failed = [int]$g[3].Value; $r.ignored = [int]$g[4].Value; $r.measured = [int]$g[5].Value; $r.filtered_out = [int]$g[6].Value
    }
    $r.failing = @([regex]::Matches($Text, '(?m)^test (\S+)(?: - should panic)? \.\.\. FAILED\s*$') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $r
}

# A VSTest TRX file: counters and the names of failed tests.
function Get-M3CiTrxResult([string]$Xml) {
    $x = [xml]$Xml
    $ns = New-Object Xml.XmlNamespaceManager($x.NameTable)
    $ns.AddNamespace('t', 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010')
    $c = $x.SelectSingleNode('//t:ResultSummary/t:Counters', $ns)
    $outcome = $x.SelectSingleNode('//t:ResultSummary', $ns).GetAttribute('outcome')
    $failing = @($x.SelectNodes('//t:Results/t:UnitTestResult[@outcome="Failed"]', $ns) | ForEach-Object { $_.GetAttribute('testName') })
    [ordered]@{ outcome = $outcome; total = [int]$c.GetAttribute('total'); executed = [int]$c.GetAttribute('executed'); passed = [int]$c.GetAttribute('passed')
                failed = [int]$c.GetAttribute('failed'); not_executed = [int]$c.GetAttribute('notExecuted'); failing = $failing }
}

# A host path the guest can hold at the same place: absolute, on C:, ASCII (tar -T reads names in the ANSI code page).
function Assert-M3CiHostPath([string]$Path, [string]$What) {
    if ($Path -notmatch '^[Cc]:\\') { throw "$What must be on C: (the guest has its files at the same absolute path): $Path" }
    if ($Path -match '[^\x20-\x7E]') { throw "$What has a non-ASCII character: $Path" }
}

# Paths relative to $Base with '/' (tar -T list); a path outside $Base throws.
function ConvertTo-M3CiRelative([string[]]$Paths, [string]$Base) {
    $b = $Base.TrimEnd('\') + '\'
    foreach ($p in $Paths) {
        if (-not $p.StartsWith($b, [StringComparison]::OrdinalIgnoreCase)) { throw "$p is not under $Base" }
        $p.Substring($b.Length).Replace('\', '/')
    }
}

# The verdict of a result document: pass and the reasons it is not.
function Get-M3CiVerdict($Doc) {
    $why = @()
    if ($Doc.error) { $why += "error: $($Doc.error)" }
    if (-not $Doc.admin) { $why += 'the runner''s token was not elevated (admin=false)' }
    if (-not @($Doc.steps).Count) { $why += 'no step ran' }
    foreach ($s in @($Doc.steps)) {
        if (-not @($s.binaries).Count) { $why += "step $($s.id): no test binary" }
        foreach ($b in @($s.binaries)) {
            if ($b.timed_out) { $why += "$($s.id) $($b.label): timed out" }
            elseif ($b.exit -ne 0) { $why += "$($s.id) $($b.label): exit $($b.exit)$(if (@($b.failing).Count) { ' (' + (@($b.failing) -join ', ') + ')' })" }
            elseif (-not $b.summary) { $why += "$($s.id) $($b.label): no libtest summary" }
            elseif ($b.failed -gt 0) { $why += "$($s.id) $($b.label): $($b.failed) failed" }
            if (-not $b.sha_match) { $why += "$($s.id) $($b.label): the guest's SHA-256 differs from the host build" }
        }
    }
    $u = $Doc.ui
    if (-not $u -or $u.skipped) { $why += 'ui tests not run (-SkipUi); G1 needs --require-ui' }
    elseif ($u.timed_out) { $why += 'ui: timed out' }
    elseif (-not $u.trx) { $why += "ui: no TRX (exit $($u.exit))" }
    elseif ($u.exit -ne 0 -or $u.failed -gt 0) { $why += "ui: exit $($u.exit), $($u.failed) failed$(if (@($u.failing).Count) { ' (' + (@($u.failing) -join ', ') + ')' })" }
    elseif ($u.total -lt 1) { $why += 'ui: no test ran' }
    elseif (-not $u.sha_match) { $why += 'ui: the guest''s assembly SHA-256 differs from the host build' }
    [pscustomobject]@{ pass = ($why.Count -eq 0); why = $why }
}

# The job text of one guest phase.
function New-M3CiPhaseText([string]$Phase, [string]$Step = '') {
    foreach ($v in $Phase, $Step) { if ("$v" -notmatch '^[a-z0-9-]*$') { throw "bad phase argument '$v'" } }
    $t = "& '$M3CiGuestRoot\m3-ci.ps1' -Phase '$Phase'"
    if ($Step) { $t += " -Step '$Step'" }
    $t
}

# The run name: letters, digits, '.', '_' and '-'.
function Assert-M3CiRunName([string]$Name) { if ($Name -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { throw "bad run name '$Name'" } }

# ------------------------------------------------------------------------------------------------- host build

function Invoke-M3CiNative([string]$Exe, [string[]]$A, [string]$Cwd, [string]$ErrLog) {
    $ErrorActionPreference = 'Continue'
    Push-Location $Cwd
    try { $o = @(& $Exe @A 2>> $ErrLog) } finally { Pop-Location }
    [pscustomobject]@{ code = $LASTEXITCODE; out = @($o | ForEach-Object { "$_" }) }
}

function Get-M3CiDotnet {
    $c = Get-Command dotnet.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { return $c.Source }
    $p = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
    if (Test-Path -LiteralPath $p) { return $p }
    throw 'no .NET SDK (dotnet.exe) on PATH or in Program Files; G1 needs the UI tests'
}

# tar -czf $Archive -C $Base <relative paths>; the list goes through a file (-T).
function New-M3CiTar([string]$Archive, [string]$Base, [string[]]$Relative) {
    $list = "$Archive.list"
    [IO.File]::WriteAllLines($list, [string[]]$Relative, (New-Object Text.UTF8Encoding($false)))
    $ErrorActionPreference = 'Continue'
    & "$env:SystemRoot\System32\tar.exe" -czf $Archive -C $Base -T $list 2>&1 | ForEach-Object { Write-RigLog "  tar: $_" }
    $code = $LASTEXITCODE
    Remove-Item -LiteralPath $list -Force
    if ($code -ne 0) { throw "tar -c $Archive exited $code" }
    (Get-Item -LiteralPath $Archive).Length
}

# The stand-in cargo.exe of the UI step: exit 0 for exactly the harness build the UI tests run, 101 for anything else.
function New-M3CiFakeCargo([string]$OutExe) {
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $csc)) { throw "no csc.exe ($csc) to build the cargo stand-in" }
    $src = "$OutExe.cs"
    $cs = @'
static class M3CiCargo {
    static int Main(string[] a) {
        string line = string.Join(" ", a);
        if (line == "build -q -p purge-broker --example pipe_harness") return 0;
        System.Console.Error.WriteLine("m3-ci cargo stand-in: only 'cargo build -q -p purge-broker --example pipe_harness' is answered; got: cargo " + line);
        return 101;
    }
}
'@
    [IO.File]::WriteAllText($src, $cs, (New-Object Text.UTF8Encoding($false)))
    $o = @(& $csc /nologo /target:exe "/out:$OutExe" $src 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "csc failed: $($o -join ' ')" }
    Remove-Item -LiteralPath $src -Force
}

# Host side of the mode: builds every step, collects the executables, writes the bundle (archives, manifest.json,
# m3-ci.ps1) into $Bundle. Returns the manifest.
function Invoke-M3CiBuild([string]$Bundle, [string]$LogDir) {
    $repo = $script:RepoRoot
    Assert-M3CiHostPath $repo 'the checkout'
    $xs = Get-M3CiXtaskSteps ([IO.File]::ReadAllText((Join-Path $repo 'tools\xtask\src\main.rs')))
    $miss = @(Get-M3CiUncovered $xs)
    if ($miss.Count) { throw "xtask ci changed; rig-m3-ci.ps1 neither runs nor lists: $($miss -join '; ')" }
    New-Item -ItemType Directory -Force $Bundle, $LogDir | Out-Null
    $git = Invoke-M3CiNative 'git' @('rev-parse', 'HEAD') $repo (Join-Path $LogDir 'git.log')
    $head = "$($git.out | Select-Object -First 1)".Trim()
    $dirty = @((Invoke-M3CiNative 'git' @('status', '--porcelain') $repo (Join-Path $LogDir 'git.log')).out | Where-Object { $_ })
    $rustc = "$((Invoke-M3CiNative 'rustc' @('-V') $repo (Join-Path $LogDir 'rustc.log')).out | Select-Object -First 1)"
    $meta = Invoke-M3CiNative 'cargo' @('metadata', '--no-deps', '--format-version', '1') $repo (Join-Path $LogDir 'cargo-metadata.log')
    if ($meta.code -ne 0) { throw "cargo metadata exited $($meta.code)" }
    $md = ($meta.out -join "`n") | ConvertFrom-Json
    $target = "$($md.target_directory)"
    Assert-M3CiHostPath $target 'the target directory'
    $pk = @{}
    foreach ($p in @($md.packages)) { $pk["$($p.manifest_path)".ToLowerInvariant()] = [pscustomobject]@{ name = "$($p.name)"; version = "$($p.version)" } }
    $excl = @(Get-M3CiExclusions)
    $steps = @(); $n = 0; $bytes = 0; $raw = 0
    foreach ($s in Get-M3CiCargoSteps) {
        if ($CI.skip_ui -and $s.id -eq 'ui-harness') { continue }
        $a = @($s.args)
        if ($a[0] -eq 'test') { $a += '--no-run' }
        $a += '--message-format=json'
        $log = Join-Path $LogDir "cargo-$($s.id).log"
        Write-RigLog "build $($s.id): cargo $($a -join ' ')"
        $t = Get-Date
        $r = Invoke-M3CiNative 'cargo' $a $repo $log
        if ($r.code -ne 0) { throw "cargo $($a -join ' ') exited $($r.code) (log $log)" }
        $arts = @(ConvertFrom-M3CiCargoJson $r.out $pk)
        $tests = @($arts | Where-Object { $_.kind -eq 'test' })
        if ($s.id -ne 'ui-harness' -and -not $tests.Count) { throw "step $($s.id): cargo reported no test executable" }
        $files = @($arts | ForEach-Object { $_.exe })
        $rel = @(ConvertTo-M3CiRelative $files $target)
        $archive = "step-$($s.id).tgz"
        $sz = New-M3CiTar (Join-Path $Bundle $archive) $target $rel
        $bytes += $sz; $raw += ($files | ForEach-Object { (Get-Item -LiteralPath $_).Length } | Measure-Object -Sum).Sum
        $bins = @()
        foreach ($b in $tests) {
            $n++
            $skip = @($excl | Where-Object { $_.step -eq $s.id -and $b.label -match $_.binary } | ForEach-Object { $_.test })
            $bins += [ordered]@{ n = ('{0:d3}' -f $n); label = $b.label; package = $b.package; version = $b.version; target = $b.target; target_kind = $b.target_kind
                                 exe = $b.exe; cwd = $b.cwd; sha256 = (Get-FileHash -LiteralPath $b.exe -Algorithm SHA256).Hash.ToLowerInvariant()
                                 bytes = (Get-Item -LiteralPath $b.exe).Length; skip = $skip }
        }
        $support = @($arts | Where-Object { $_.kind -eq 'support' } | ForEach-Object { [ordered]@{ exe = $_.exe; label = $_.label; sha256 = (Get-FileHash -LiteralPath $_.exe -Algorithm SHA256).Hash.ToLowerInvariant() } })
        Write-RigLog "  $($tests.Count) test executable(s), $($support.Count) support executable(s), archive $([math]::Round($sz / 1MB, 1)) MB, $([int]((Get-Date) - $t).TotalSeconds) s"
        $steps += [ordered]@{ id = $s.id; cargo = ($s.args -join ' '); xtask = $s.xtask; archive = $archive; archive_bytes = $sz; binaries = $bins; support = $support }
    }
    # UI: dotnet build as xtask ci does, then the test assembly's output directory, the portable SDK and the stand-in.
    $ui = $null; $dotnetInfo = $null
    if (-not $CI.skip_ui) {
        $dotnet = Get-M3CiDotnet
        $sdkVer = "$((Invoke-M3CiNative $dotnet @('--version') $repo (Join-Path $LogDir 'dotnet.log')).out | Select-Object -First 1)".Trim()
        $droot = Split-Path -Parent $dotnet
        if (-not (Test-Path -LiteralPath (Join-Path $droot "sdk\$sdkVer"))) { throw "SDK $sdkVer not under $droot" }
        Write-RigLog "build ui: dotnet build ui\Purge.slnx (SDK $sdkVer)"
        $b = Invoke-M3CiNative $dotnet @('build', (Join-Path $repo 'ui\Purge.slnx'), '--nologo') $repo (Join-Path $LogDir 'dotnet-build.log')
        $b.out | Set-Content -LiteralPath (Join-Path $LogDir 'dotnet-build.out.log') -Encoding UTF8
        if ($b.code -ne 0) { throw "dotnet build exited $($b.code) (log $LogDir\dotnet-build.out.log)" }
        $csproj = Join-Path $repo 'ui\Purge.Client.Tests\Purge.Client.Tests.csproj'
        $tp = "$((Invoke-M3CiNative $dotnet @('msbuild', $csproj, '-nologo', '-getProperty:TargetPath') $repo (Join-Path $LogDir 'dotnet.log')).out | Where-Object { $_ -match '\.dll\s*$' } | Select-Object -First 1)".Trim()
        if (-not (Test-Path -LiteralPath $tp -PathType Leaf)) { throw "the UI test assembly is not where msbuild says: '$tp'" }
        $udir = Split-Path -Parent $tp
        Assert-M3CiHostPath $udir 'the UI test output'
        $ufiles = @(Get-ChildItem -LiteralPath $udir -Recurse -File | ForEach-Object { $_.FullName })
        $usz = New-M3CiTar (Join-Path $Bundle 'ui.tgz') $udir @(ConvertTo-M3CiRelative $ufiles $udir)
        $bytes += $usz; $raw += ($ufiles | ForEach-Object { (Get-Item -LiteralPath $_).Length } | Measure-Object -Sum).Sum
        # The portable SDK, cached per version (it does not change between runs).
        $cache = Join-Path (Get-HostTemp) "m3ci-dotnet-$sdkVer.tgz"
        $dparts = @('dotnet.exe', 'host', 'sdk-manifests', 'shared/Microsoft.NETCore.App', "sdk/$sdkVer")
        if (-not (Test-Path -LiteralPath $cache)) {
            Write-RigLog "  packing the portable SDK $sdkVer from $droot"
            $null = New-M3CiTar "$cache.part" $droot $dparts
            Move-Item -LiteralPath "$cache.part" -Destination $cache -Force
        }
        Copy-Item -LiteralPath $cache -Destination (Join-Path $Bundle 'dotnet.tgz') -Force
        $dsz = (Get-Item -LiteralPath $cache).Length
        $draw = (@($dparts | ForEach-Object { $p = Join-Path $droot $_; if (Test-Path -LiteralPath $p -PathType Leaf) { Get-Item -LiteralPath $p } else { Get-ChildItem -LiteralPath $p -Recurse -File } }) | Measure-Object Length -Sum).Sum
        $bytes += $dsz; $raw += $draw
        New-M3CiFakeCargo (Join-Path $Bundle 'cargo-standin.exe')
        $filter = (@(@(Get-M3CiExclusions) | Where-Object { $_.step -eq 'ui' } | ForEach-Object { "FullyQualifiedName!=$($_.test)" }) -join '&')
        $ui = [ordered]@{ archive = 'ui.tgz'; dir = $udir; dll = $tp; dll_sha256 = (Get-FileHash -LiteralPath $tp -Algorithm SHA256).Hash.ToLowerInvariant()
                          harness_archive = 'step-ui-harness.tgz'; filter = $filter; archive_bytes = $usz }
        $dotnetInfo = [ordered]@{ archive = 'dotnet.tgz'; sdk = $sdkVer; from = $droot; archive_bytes = $dsz; bytes = $draw }
    }
    # The checkout's tracked files (working tree) and the extras the host has.
    $tracked = @((Invoke-M3CiNative 'git' @('ls-files') $repo (Join-Path $LogDir 'git.log')).out | Where-Object { $_ })
    $extras = @(Get-M3CiRepoExtras | Where-Object { Test-Path -LiteralPath (Join-Path $repo $_) -PathType Leaf })
    $rel = @(@($tracked) + $extras | Where-Object { Test-Path -LiteralPath (Join-Path $repo $_) -PathType Leaf })
    if (@($rel | Where-Object { $_ -match '[^\x20-\x7E]' }).Count) { throw 'a tracked file name is not ASCII (tar -T)' }
    $rsz = New-M3CiTar (Join-Path $Bundle 'repo.tgz') $repo $rel
    $bytes += $rsz; $raw += ($rel | ForEach-Object { (Get-Item -LiteralPath (Join-Path $repo $_)).Length } | Measure-Object -Sum).Sum
    Copy-Item -LiteralPath (Join-Path $script:RigDir 'guest\m3-ci.ps1') -Destination (Join-Path $Bundle 'm3-ci.ps1') -Force
    $man = [ordered]@{ schema = 'purge.rig.m3ci.manifest/1'; built = (Get-Date).ToString('o'); commit = $head; dirty = $dirty; rustc = $rustc
                       repo = [ordered]@{ archive = 'repo.tgz'; dir = $repo; files = $rel.Count; extras = $extras; archive_bytes = $rsz }
                       target_dir = $target; make_dirs = @((Join-Path $target 'tmp'))
                       steps = @($steps | Where-Object { $_.id -ne 'ui-harness' }); ui = $ui; dotnet = $dotnetInfo; fakecargo = 'cargo-standin.exe'
                       threads = $CI.threads; timeout_bin = $CI.timeout_bin; timeout_ui = $CI.timeout_ui
                       host_only = @(Get-M3CiHostOnly); exclusions = @(Get-M3CiExclusions)
                       archives_bytes = $bytes; unpacked_bytes = $raw }
    [IO.File]::WriteAllText((Join-Path $Bundle 'manifest.json'), (ConvertTo-Json -InputObject $man -Depth 8), (New-Object Text.UTF8Encoding($false)))
    $nb = @($man.steps | ForEach-Object { @($_.binaries).Count } | Measure-Object -Sum).Sum
    Write-RigLog ("bundle {0}: {1} test executables in {2} steps, archives {3:N0} MB, unpacked {4:N0} MB, commit {5}{6}" -f $Bundle, $nb, @($man.steps).Count, ($bytes / 1MB), ($raw / 1MB), $head, $(if ($dirty.Count) { " (dirty: $($dirty.Count) path(s))" }))
    $man
}

# ------------------------------------------------------------------------------------------------- results

# The result document from the manifest and the runner's outputs in $GuestOut (pulled from the guest, or the host run's).
function New-M3CiResult($Man, [string]$GuestOut, [string]$Where, [string]$Started, [string]$Err) {
    $doc = [ordered]@{ schema = $M3CiSchema; run = $CI.run; mode = 'm3-elevated-ci'; where = $Where; vm = $(if ($Where -eq 'vm') { $CI.vm }); snapshot = $(if ($Where -eq 'vm') { $CI.snapshot })
                       start = $Started; end = (Get-Date).ToString('o'); commit = $Man.commit; dirty = @($Man.dirty); rustc = $Man.rustc
                       dotnet_sdk = $(if ($Man.dotnet) { $Man.dotnet.sdk }); admin = $false; integrity = $null; guest = $null
                       host_only = @($Man.host_only); exclusions = @($Man.exclusions); steps = @(); ui = $null; totals = $null; error = $Err; pass = $false; why = @() }
    $up = Join-Path $GuestOut 'unpack.json'
    if (Test-Path -LiteralPath $up) {
        $u = Get-Content -LiteralPath $up -Raw | ConvertFrom-Json
        $doc.guest = $u
    }
    $admins = @(); $integ = @()
    $tp = 0; $tf = 0; $ti = 0; $tb = 0
    foreach ($s in @($Man.steps)) {
        $rf = Join-Path $GuestOut "$($s.id)\results.json"
        $res = $null
        if (Test-Path -LiteralPath $rf) { $res = Get-Content -LiteralPath $rf -Raw | ConvertFrom-Json; $admins += [bool]$res.token.admin; $integ += "$($res.token.integrity)" }
        $rows = @()
        foreach ($b in @($s.binaries)) {
            $g = $(if ($res) { @($res.binaries | Where-Object { $_.n -eq $b.n }) | Select-Object -First 1 })
            $txt = Join-Path $GuestOut "$($s.id)\$($b.n).txt"
            $lt = Get-M3CiLibtestResult $(if (Test-Path -LiteralPath $txt) { [IO.File]::ReadAllText($txt) } else { '' })
            $row = [ordered]@{ n = $b.n; label = $b.label; package = $b.package; target = $b.target; target_kind = $b.target_kind; exe = $b.exe
                               sha256 = $b.sha256; guest_sha256 = $(if ($g) { $g.sha256 }); sha_match = [bool]($g -and $g.sha256 -eq $b.sha256)
                               exit = $(if ($g) { $g.exit }); timed_out = $(if ($g) { [bool]$g.timed_out } else { $false }); seconds = $(if ($g) { $g.seconds })
                               summary = $lt.summary; passed = $lt.passed; failed = $lt.failed; ignored = $lt.ignored; filtered_out = $lt.filtered_out
                               failing = @($lt.failing); skipped_by_rig = @($b.skip); output = "guest/$($s.id)/$($b.n).txt"
                               error = $(if (-not $g) { 'no result from the runner' } elseif ($g.start_error) { $g.start_error }) }
            $row.pass = ($g -and -not $row.timed_out -and $row.exit -eq 0 -and $row.summary -and $row.failed -eq 0 -and $row.sha_match)
            $tp += $row.passed; $tf += $row.failed; $ti += $row.ignored; $tb++
            $rows += [pscustomobject]$row
        }
        $doc.steps += [pscustomobject][ordered]@{ id = $s.id; cargo = $s.cargo; xtask = $s.xtask; binaries = $rows; pass = (@($rows | Where-Object { -not $_.pass }).Count -eq 0 -and $rows.Count -gt 0) }
    }
    if ($Man.ui) {
        $ur = Join-Path $GuestOut 'ui\results.json'
        $trx = Join-Path $GuestOut 'ui\ui.trx'
        $u = [ordered]@{ skipped = $false; dll = $Man.ui.dll; dll_sha256 = $Man.ui.dll_sha256; guest_dll_sha256 = $null; sha_match = $false; exit = $null; timed_out = $false
                         trx = $false; total = 0; passed = 0; failed = 0; not_executed = 0; failing = @(); excluded_filter = $Man.ui.filter; output = 'guest/ui/dotnet-test.txt' }
        if (Test-Path -LiteralPath $ur) {
            $g = Get-Content -LiteralPath $ur -Raw | ConvertFrom-Json
            $admins += [bool]$g.token.admin; $integ += "$($g.token.integrity)"
            $u.guest_dll_sha256 = $g.dll_sha256; $u.sha_match = ($g.dll_sha256 -eq $Man.ui.dll_sha256); $u.exit = $g.exit; $u.timed_out = [bool]$g.timed_out
        }
        if (Test-Path -LiteralPath $trx) {
            $t = Get-M3CiTrxResult ([IO.File]::ReadAllText($trx))
            $u.trx = $true; $u.total = $t.total; $u.passed = $t.passed; $u.failed = $t.failed; $u.not_executed = $t.not_executed; $u.failing = @($t.failing)
        }
        $doc.ui = [pscustomobject]$u
    } else { $doc.ui = [pscustomobject]@{ skipped = $true } }
    $doc.admin = ($admins.Count -gt 0 -and -not @($admins | Where-Object { -not $_ }).Count)
    $doc.integrity = (@($integ | Sort-Object -Unique) -join ',')
    $doc.totals = [ordered]@{ binaries = $tb; passed = $tp; failed = $tf; ignored = $ti
                              ui_total = $(if ($doc.ui.skipped) { 0 } else { $doc.ui.total }); ui_failed = $(if ($doc.ui.skipped) { 0 } else { $doc.ui.failed }) }
    $v = Get-M3CiVerdict ([pscustomobject]$doc)
    $doc.pass = $v.pass; $doc.why = @($v.why)
    $doc
}

function Save-M3CiResult($Doc, [string]$Dst) {
    $f = Join-Path $Dst 'm3-elevated-ci.json'
    [IO.File]::WriteAllText($f, (ConvertTo-Json -InputObject $Doc -Depth 10), (New-Object Text.UTF8Encoding($false)))
    Write-RigLog ("result {0}: pass={1}; {2} binaries, {3} passed, {4} failed, {5} ignored; ui {6} tests, {7} failed; admin={8}" -f $f, $Doc.pass,
                  $Doc.totals.binaries, $Doc.totals.passed, $Doc.totals.failed, $Doc.totals.ignored, $Doc.totals.ui_total, $Doc.totals.ui_failed, $Doc.admin)
    foreach ($w in @($Doc.why)) { Write-RigLog "  not pass: $w" }
}

# ------------------------------------------------------------------------------------------------- runs

function Stop-M3Ci([int]$Code, [string]$Why) {
    if ($Why) { Write-RigLog $Why }
    if ($script:CiLock) { $script:CiLock.Dispose(); $script:CiLock = $null }
    Remove-PwTemp
    exit $Code
}

function Assert-M3CiStart {
    if (-not $env:VMPWFILE -or -not (Test-Path -LiteralPath $env:VMPWFILE -PathType Leaf)) { Stop-M3Ci 2 'REFUSED: $env:VMPWFILE does not name a readable file' }
    $vms = (Invoke-VBox @('list', 'vms')).out -join "`n"
    if ($vms -notmatch ('"' + [regex]::Escape($CI.vm) + '"')) { Stop-M3Ci 2 "REFUSED: VM $($CI.vm) not found" }
    $running = @((Invoke-VBox @('list', 'runningvms')).out | Where-Object { "$_".Trim() })
    if ($running.Count) { Stop-M3Ci 2 "REFUSED: a VM is running ($($running -join '; ')); one VM at a time" }
    New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
    try { $script:CiLock = [IO.File]::Open((Join-Path $script:RunsDir ".lock-$($CI.vm)"), 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { Stop-M3Ci 2 "REFUSED: another rig script holds the lock for $($CI.vm)" }
}

# One guest phase as an agent job; keeps the job log in $Dst\jobs\ and logs the "M3CI" lines.
function Invoke-M3CiGuestPhase([string]$Phase, [string]$Step, [int]$TimeoutSec, [string]$Dst) {
    $jobs = Join-Path $Dst 'jobs'
    New-Item -ItemType Directory -Force $jobs | Out-Null
    $name = "m3ci-$Phase$(if ($Step) { "-$Step" })"
    $j = Invoke-GuestJob -Text (New-M3CiPhaseText $Phase $Step) -Name $name -TimeoutSec $TimeoutSec -LogCopy (Join-Path $jobs "$name.log")
    $lines = @("$($j.log)" -split "`r?`n" | Where-Object { $_ -match '^M3CI ' })
    foreach ($l in $lines) { Write-RigLog "  $l" }
    if (-not $j.done) { throw "phase $name did not finish within $TimeoutSec s" }
    if (-not @($lines | Where-Object { $_ -match "^M3CI $Phase " }).Count) { throw "phase $name wrote no result line; log $($j.log_file)" }
    $j
}

function Invoke-M3CiVm($Man, [string]$Bundle, [string]$Dst) {
    $script:CiVmStarted = $true
    Restore-Base -Snapshot $CI.snapshot -AgentTimeoutSec $CI.agent_timeout
    # Guest disk: the archives, what they unpack to, and 2 GB for the tests' own files.
    $need = [int64]$Man.archives_bytes + [int64]$Man.unpacked_bytes + 2GB
    $j = Invoke-GuestJob -Text "'FREE=' + (Get-PSDrive -Name C).Free" -Name 'm3ci-free' -TimeoutSec 300
    $m = [regex]::Match("$($j.log)", 'FREE=(\d+)')
    if (-not $m.Success) { throw 'could not read the guest''s free space' }
    $free = [int64]$m.Groups[1].Value
    Write-RigLog ("  guest C: free {0:N1} GB, needed {1:N1} GB" -f ($free / 1GB), ($need / 1GB))
    if ($free -lt $need) { throw ("the guest has {0:N1} GB free on C:, needs {1:N1} GB" -f ($free / 1GB), ($need / 1GB)) }
    $null = Invoke-Guest @('mkdir', '--parents', $M3CiGuestRoot)
    $files = @(Get-ChildItem -LiteralPath $Bundle -File | ForEach-Object { $_.FullName })
    $t = Get-Date
    foreach ($f in $files) {
        $r = Invoke-Guest @('copyto', '--target-directory', "$M3CiGuestRoot\", $f)
        if ($r.code -ne 0) { throw "copy $(Split-Path -Leaf $f) to the guest failed: $($r.out -join ' ')" }
    }
    Write-RigLog ("  pushed {0} files ({1:N0} MB) in {2} s" -f $files.Count, (($files | ForEach-Object { (Get-Item -LiteralPath $_).Length } | Measure-Object -Sum).Sum / 1MB), [int]((Get-Date) - $t).TotalSeconds)
    $null = Invoke-M3CiGuestPhase 'unpack' '' 3600 $Dst
    foreach ($s in @($Man.steps)) {
        $budget = [Math]::Max(1, @($s.binaries).Count) * ($CI.timeout_bin + 30) + 900
        $null = Invoke-M3CiGuestPhase 'step' $s.id $budget $Dst
    }
    if ($Man.ui) { $null = Invoke-M3CiGuestPhase 'ui' '' ($CI.timeout_ui + 900) $Dst }
    $null = Invoke-M3CiGuestPhase 'pack' '' 1800 $Dst
    $tgz = Join-Path $Dst 'guest-out.tgz'
    $r = Invoke-Guest @('copyfrom', "$M3CiGuestRoot\out.tgz", $tgz)
    if ($r.code -ne 0 -or -not (Test-Path -LiteralPath $tgz)) { throw "copyfrom out.tgz failed: $($r.out -join ' ')" }
    $g = Join-Path $Dst 'guest'
    New-Item -ItemType Directory -Force $g | Out-Null
    & "$env:SystemRoot\System32\tar.exe" -xzf $tgz -C $g
    if ($LASTEXITCODE -ne 0) { throw 'host tar -x of the guest outputs failed' }
    Remove-Item -LiteralPath $tgz -Force
}

# The dry run: the same runner, on this host, with the bundle as its root (nothing extracted over the checkout but the
# step archives, which put back the very files cargo built).
function Invoke-M3CiHost($Man, [string]$Bundle, [string]$Dst) {
    foreach ($ph in @(@{ p = 'unpack' }) + @($Man.steps | ForEach-Object { @{ p = 'step'; s = $_.id } }) + $(if ($Man.ui) { @(@{ p = 'ui' }) } else { @() })) {
        $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Bundle 'm3-ci.ps1'), '-Phase', $ph.p, '-Root', $Bundle, '-NoUnpack')
        if ($ph.s) { $a += @('-Step', $ph.s) }
        $ErrorActionPreference = 'Continue'
        $o = @(& powershell.exe @a 2>&1 | ForEach-Object { "$_" })
        $ErrorActionPreference = 'Stop'
        foreach ($l in $o) { if ($l -match '^M3CI ') { Write-RigLog "  $l" } }
        if ($LASTEXITCODE -ne 0) { throw "host run phase $($ph.p) $($ph.s) exited $LASTEXITCODE`: $(($o | Select-Object -Last 5) -join ' ')" }
    }
    $g = Join-Path $Dst 'guest'
    New-Item -ItemType Directory -Force $g | Out-Null
    Copy-Item -Path (Join-Path $Bundle 'out\*') -Destination $g -Recurse -Force
}

# ------------------------------------------------------------------------------------------------- main

# Dot-sourced (the self-test): the functions only.
if ($MyInvocation.InvocationName -eq '.') { return }

if (-not $script:OnWindows) { Write-Host 'REFUSED: m3-elevated-ci builds Windows test binaries; run it on the Windows host'; exit 2 }
try { Assert-M3CiRunName $CI.run } catch { Write-Host "REFUSED: $($_.Exception.Message)"; exit 2 }
if ($CI.build_only -and $CI.host_run) { Write-Host 'REFUSED: -BuildOnly and -HostRun exclude each other'; exit 2 }
$vmRun = -not ($CI.build_only -or $CI.host_run)
if ($vmRun) {
    Assert-M3CiStart
    # A VM run binds a commit: the tests read the working tree, so a dirty one is refused before anything is built.
    $ErrorActionPreference = 'Continue'
    $dirty0 = @(& git -C $script:RepoRoot status --porcelain 2>$null | Where-Object { $_ })
    $ErrorActionPreference = 'Stop'
    if ($dirty0.Count -and -not $CI.allow_dirty) { Stop-M3Ci 2 "REFUSED: the checkout is dirty ($($dirty0.Count) path(s), first: $($dirty0[0])); commit, or pass -AllowDirty" }
}
$script:CiVmStarted = $false
New-Item -ItemType Directory -Force $script:RunsDir | Out-Null
$null = Move-RunToOld -Run $CI.run
$dst = Join-Path $script:RunsDir $CI.run
New-Item -ItemType Directory -Force $dst | Out-Null
$script:RigLogFile = Join-Path $dst 'rig.log'
$bundle = Join-Path (Get-HostTemp) "m3ci-$($CI.run)"
if (Test-Path -LiteralPath $bundle) { Remove-Item -LiteralPath $bundle -Recurse -Force }
$started = (Get-Date).ToString('o')
Write-RigLog "m3-elevated-ci run=$($CI.run) where=$(if ($vmRun) { "vm $($CI.vm) $($CI.snapshot)" } elseif ($CI.host_run) { 'host (dry run)' } else { 'build only' }) bundle=$bundle"
$man = $null; $err = $null; $code = 0
try {
    $man = Invoke-M3CiBuild $bundle (Join-Path $dst 'build')
    Copy-Item -LiteralPath (Join-Path $bundle 'manifest.json') -Destination (Join-Path $dst 'manifest.json') -Force
    if ($CI.build_only) { Stop-M3Ci 0 "build only: bundle in $bundle, manifest $dst\manifest.json" }
    if ($vmRun) { Invoke-M3CiVm $man $bundle $dst } else { Invoke-M3CiHost $man $bundle $dst }
} catch {
    $err = $_.Exception.Message
    Write-RigLog "!! $err"
} finally {
    if ($script:CiVmStarted) {
        try {
            Write-RigLog "power off and restore $($CI.snapshot) (left off)"
            if ((Get-VmState) -in 'running', 'paused', 'stuck') { $null = Invoke-VBox @('controlvm', $CI.vm, 'poweroff'); $null = Wait-VmState @('poweroff', 'aborted') 120 }
            Start-Sleep -Seconds 3
            $r = Invoke-VBox @('snapshot', $CI.vm, 'restore', $CI.snapshot)
            if ($r.code -ne 0) { Write-RigLog "  !! restore $($CI.snapshot): $($r.out -join ' ')" }
        } catch { Write-RigLog "  !! cleanup: $($_.Exception.Message)" }
    }
}
if ($man) {
    $doc = New-M3CiResult $man (Join-Path $dst 'guest') $(if ($vmRun) { 'vm' } else { 'host' }) $started $err
    Save-M3CiResult $doc $dst
    if (-not $doc.pass) { $code = 1 }
} else { $code = 1 }
if ($vmRun -and -not $CI.keep_bundle) { Remove-Item -LiteralPath $bundle -Recurse -Force -ErrorAction SilentlyContinue }
Stop-M3Ci $code "m3-elevated-ci done, exit $code"
