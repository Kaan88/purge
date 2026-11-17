# Purge rig, M1b: typed-object executor runs (docs\M1B_DESIGN.json M1B-RIG-EXEC, gate G5; vm\RIG.md section 12).
# Template: the host (vm\rig-m1b-exec.ps1 through rig.ps1 New-M2JobText) replaces __RUN__, __MODE__
# (m1b-x-fidelity | m1b-x-traps | m1b-x-undo-traps), __STAGE__ (start) and __OPTS__ (base64 JSON: cases_b64 = the
# file vm\truth\m1b-exec-cases.json, base64; settle_max, settle_min_uptime) and submits it as an agent job
# (elevated). Windows PowerShell 5.1. `. m1b-exec.ps1 -Library` only defines the functions (m1b-crash.ps1, the host
# self-test).
#
# The app under test is fabricated and rig-owned: PurgeExecApp, C:\Program Files\PurgeExecApp, its own ARP key and
# one COM class, and the system objects of the cases file (names PurgeExec*). Objects are never planted through
# the engine. A round: clean, plant, `harvest PurgeExecApp`, the program files, ARP key and COM class removed (the
# app "uninstalled externally"), `scan --fp --mode external`. Plans come from harvest and scan only (R3b M9:
# `plan from-targets` makes no object plan), and every exec passes `--fp` (without it every object delete is
# refused).
#
# Modes (each phase recorded in run.json purge.rig.m2/1; a verdict is a measurement, vm\truth\m1b-exec.sh judges):
#   m1b-x-fidelity    every fidelity variant; the Safe selection executed; full snaps A/B, deep A/B/C, execdiff
#                     (collateral, K10), undo, fidelity (K11); refused variants byte-equal after exec and undo.
#   m1b-x-traps       the act-time traps: after the scan the rig changes six things; exec; each changed object
#                     Skipped and present unchanged, the same-name twin byte-equal (K12, first half).
#   m1b-x-undo-traps  the fidelity plants executed, then four undo traps (impostor service, impostor task, tampered
#                     definition, missing definition); undo; the expected conflict per op, nothing overwritten
#                     (K12, second half).
# Engine calls: inventory-free `harvest PurgeExecApp -o fp.json`; `scan --fp fp.json --mode external --app
# purgeexecapp -o plan.json`; `exec --plan --confirm --select --fp fp.json -o report.json`; `undo --session`.
param([switch]$Library)

# ------------------------------------------------------------------------------------------ constants

$ExApp       = 'PurgeExecApp'
$ExAppId     = 'purgeexecapp'
$ExDir       = 'C:\Program Files\PurgeExecApp'
$ExArp       = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PurgeExecApp'
$ExClsid     = '{9E3B5D17-4C2A-4F0B-8E61-7A2C5B9D0F34}'          # fabricated, the COM-handler task's class
$ExClsidKey  = "HKLM\SOFTWARE\Classes\CLSID\$ExClsid"
$ExTaskRoot  = '\PurgeExecApp'
$ExWork      = 'C:\cr\work\m1b-exec'
$ExSvcKey    = 'HKLM\SYSTEM\CurrentControlSet\Services'
$ExFwKey     = 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
$ExTaskTree  = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
$ExTaskCache = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'
$ExTasksDir  = 'C:\Windows\System32\Tasks'
# Computer names of the rig VMs (rig.ps1 Assert-RigVm checks the VM name on the host; this is the guest's side).
$ExRigComputers = @('INBOUND-WIN11-T', 'PURGE-CLEANPRO')
$ExModes = @('m1b-x-fidelity', 'm1b-x-traps', 'm1b-x-undo-traps')

# ------------------------------------------------------------------------------------------ pure helpers

# The cases document (vm\truth\m1b-exec-cases.json) from the opts (cases_b64) or a file.
function Read-ExCases($Opts, [string]$File = '') {
    $b64 = $null
    if ($Opts -and $Opts.PSObject.Properties['cases_b64']) { $b64 = "$($Opts.cases_b64)" }
    if ($b64) { $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) }
    elseif ($File -and (Test-Path -LiteralPath $File)) { $text = [IO.File]::ReadAllText($File) }
    else { throw 'no cases: opts.cases_b64 is empty and no cases file' }
    $c = $text.TrimStart([char]0xFEFF) | ConvertFrom-Json
    if ("$($c.schema)" -ne 'purge.rig.m1b-exec-cases/1') { throw "cases schema '$($c.schema)' is not purge.rig.m1b-exec-cases/1" }
    $c
}

function Get-ExVariant($Cases, [string]$Id) {
    $v = @(@($Cases.fidelity.variants) | Where-Object { $_ -and "$($_.id)" -eq $Id })
    if ($v.Count -ne 1) { throw "cases: $($v.Count) fidelity variants with id '$Id'" }
    $v[0]
}

# The object a variant or trap case names: @{kind; name} (service name, task path or firewall rule id).
function Get-ExObjectName($Def) {
    switch ("$($Def.kind)") {
        'service' { return "$($Def.name)" }
        'task' { return "$($Def.path)" }
        'firewall' { return "$($Def.rule)" }
        default { throw "unknown object kind '$($Def.kind)'" }
    }
}

# A comparable key of an object: service and task names fold case (Windows does), a rule id does not (the executor
# matches it exactly, act_firewall).
function Get-ExObjectKey([string]$Kind, [string]$Name) {
    switch ($Kind) {
        'service' { 'service:' + $Name.ToLowerInvariant() }
        'task' { 'task:' + $Name.ToLowerInvariant() }
        'firewall' { 'firewall:' + $Name }
        default { throw "unknown object kind '$Kind'" }
    }
}

# The key of a plan target (Target JSON as the plan spells it), or $null for a target that is no system object.
function Get-ExTargetKey($Target) {
    if (-not $Target) { return $null }
    switch ("$($Target.type)") {
        'Service' { return Get-ExObjectKey 'service' "$($Target.name)" }
        'Task' { return Get-ExObjectKey 'task' "$($Target.path)" }
        'FirewallRule' { return Get-ExObjectKey 'firewall' "$($Target.id)" }
        default { return $null }
    }
}

# Plan rows from the plan (band, preselected) and its sidecar (candidate id, target, action), which list the items
# in the same order (riglib Get-M2BandSelection). Each row: {i, id, band, preselected, target, key, action}.
function ConvertTo-ExPlanRows($Plan, $Sidecar) {
    $pi = @(@($Plan.items) | ForEach-Object { $_ } | Where-Object { $_ })
    $si = @(@($Sidecar.items) | ForEach-Object { $_ } | Where-Object { $_ })
    if ($pi.Count -ne $si.Count) { throw "plan has $($pi.Count) items, its sidecar $($si.Count)" }
    $rows = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $pi.Count; $i++) {
        $t = $si[$i].target; if (-not $t) { $t = $pi[$i].target }
        $act = $si[$i].action; if ($act -and -not ($act -is [string])) { $act = "$(@($act.PSObject.Properties)[0].Name)" }
        [void]$rows.Add([pscustomobject][ordered]@{ i = $i; id = "$($si[$i].id)"; band = "$($pi[$i].band)"; preselected = ($pi[$i].preselected -eq $true)
            target = $t; key = (Get-ExTargetKey $t); action = "$act" })
    }
    @($rows)
}

# The report entry of a candidate in a purge.exec/1 report: {kind, reason, blocker, op, detail} or $null.
function Get-ExOutcome($Report, [string]$ItemId) {
    $it = @(@($Report.items) | Where-Object { $_ -and "$($_.item)" -eq $ItemId })
    if (-not $it.Count) { return $null }
    $o = $it[0].outcome
    $reason = $null; $blocker = $null
    if ($o.PSObject.Properties['reason'] -and $o.reason) {
        $reason = "$($o.reason.kind)"
        if ($o.reason.PSObject.Properties['blocker'] -and $null -ne $o.reason.blocker) {
            $b = $o.reason.blocker
            $blocker = $(if ($b -is [string]) { $b } elseif ($b.PSObject.Properties['kind']) { "$($b.kind)" } else { ConvertTo-Json -InputObject $b -Compress -Depth 6 })
        }
    }
    [pscustomobject][ordered]@{ op = $it[0].op; kind = "$($o.kind)"; reason = $reason; blocker = $blocker
        detail = $(if ($o.PSObject.Properties['detail']) { "$($o.detail)" } else { $null }) }
}

# The undo entry of a candidate in a purge.undo/1 report: {result, kind} (Finished/<outcome>, Conflict/<conflict>).
function Get-ExUndoResult($Undo, [string]$ItemId) {
    $it = @(@($Undo.items) | Where-Object { $_ -and "$($_.item)" -eq $ItemId })
    if (-not $it.Count) { return $null }
    $r = $it[0].result
    $kind = $(if ("$($r.result)" -eq 'Conflict') { "$($r.conflict.kind)" } elseif ($r.outcome) { "$($r.outcome.kind)" } else { $null })
    [pscustomobject][ordered]@{ op = $it[0].op; result = "$($r.result)"; kind = $kind; detail = $(if ($r.PSObject.Properties['detail']) { "$($r.detail)" } else { $null }) }
}

# The definition file (session-relative path) of the intent of $ItemId: inverse.definition.path, the typed object's
# own definition (RecreateService / RecreateTask / RecreateFirewallRule). $null when the item has no such intent.
function Find-ExDefinition([string[]]$JournalLines, [string]$ItemId) {
    foreach ($line in $JournalLines) {
        if ($line -notmatch '"rec"\s*:\s*"intent"') { continue }
        $j = $null; try { $j = $line | ConvertFrom-Json } catch { continue }
        if ("$($j.item)" -ne $ItemId) { continue }
        if ($j.inverse -and $j.inverse.PSObject.Properties['definition'] -and $j.inverse.definition.path) {
            return [pscustomobject]@{ op = $j.op; path = "$($j.inverse.definition.path)"; inverse = "$($j.inverse.kind)" }
        }
    }
    $null
}

# A task registration XML (Task Scheduler 1.2 schema). One time trigger in 2099 so it never fires during a run, no
# RegistrationTrigger (purge-win refuses to register one). $Actions: @(@{exe; args}) and/or -ComClsid.
function New-ExTaskXml([string]$Description, $Actions = @(), [string]$ComClsid = '', [switch]$Hidden) {
    $esc = { param($s) [Security.SecurityElement]::Escape("$s") }
    $act = ''
    foreach ($a in @($Actions | Where-Object { $_ })) {
        $act += '<Exec><Command>' + (& $esc $a.exe) + '</Command>'
        if ($a.args) { $act += '<Arguments>' + (& $esc $a.args) + '</Arguments>' }
        $act += '</Exec>'
    }
    if ($ComClsid) { $act += '<ComHandler><ClassId>' + $ComClsid + '</ClassId><Data>purge-exec-rig</Data></ComHandler>' }
    if (-not $act) { throw 'a task needs at least one action' }
    @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>$(& $esc $Description)</Description></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>2099-01-01T03:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>false</StartWhenAvailable><Enabled>true</Enabled><Hidden>$(if ($Hidden) { 'true' } else { 'false' })</Hidden><ExecutionTimeLimit>PT1H</ExecutionTimeLimit></Settings>
  <Actions Context="Author">$act</Actions>
</Task>
"@
}

# A purge.rig.deepscope/0 document for rigtool deep: the objects by kind plus plan targets.
function New-ExDeepScope([string[]]$Services = @(), [string[]]$Tasks = @(), [string[]]$Rules = @(), $Targets = @()) {
    [ordered]@{ schema = 'purge.rig.deepscope/0'; paths = @(); keys = @(); values = @()
        services = @($Services | Where-Object { $_ } | Select-Object -Unique); tasks = @($Tasks | Where-Object { $_ } | Select-Object -Unique)
        firewall_rules = @($Rules | Where-Object { $_ } | Select-Object -Unique); targets = @($Targets | Where-Object { $_ }) }
}

# Splits objects ({kind; name}) into the three lists of a deep scope.
function Split-ExObjects($Objects) {
    $o = [ordered]@{ service = @(); task = @(); firewall = @() }
    foreach ($x in @($Objects | Where-Object { $_ })) { $o["$($x.kind)"] += "$($x.name)" }
    $o
}

function Get-ExSha([string]$Text) {
    if ($null -eq $Text) { return $null }
    $h = [Security.Cryptography.SHA256]::Create()
    try { -join @($h.ComputeHash((New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) } finally { $h.Dispose() }
}

function Get-ExBytesSha([byte[]]$Bytes) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { -join @($h.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $h.Dispose() }
}

# SHA-256 (lower-case hex) of the cases bytes as the host sent them (opts.cases_b64): the score compares it with the
# file it scores (review R4 S4).
function Get-ExCasesSha($Opts) {
    if (-not $Opts -or -not $Opts.PSObject.Properties['cases_b64'] -or -not "$($Opts.cases_b64)") { return $null }
    Get-ExBytesSha ([Convert]::FromBase64String("$($Opts.cases_b64)"))
}

# The engine build a run used (review R4 S6): what the host declared (opts.engine_build: sha256, commit,
# source_dirty) and the SHA-256 the guest measures of the staged and of the installed engine. The score requires the
# three equal and one build across the runs.
function Get-ExEngineBuild($Opts, [string]$Staged, [string]$Installed) {
    $decl = $(if ($Opts -and $Opts.PSObject.Properties['engine_build']) { $Opts.engine_build } else { $null })
    $f = { param($p) if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) { Get-ExBytesSha ([IO.File]::ReadAllBytes($p)) } else { $null } }
    [ordered]@{ declared = $decl; staged = $Staged; staged_sha256 = (& $f $Staged); installed = $Installed; installed_sha256 = (& $f $Installed) }
}

# ------------------------------------------------------------------------------------------ guest helpers
# (need riglib.ps1: Log, Invoke-Native, Get-RegRaw, Test-RegKey, Invoke-M2Engine, ...)

function Assert-ExRigVm {
    $n = "$env:COMPUTERNAME".ToUpperInvariant()
    if ($ExRigComputers -notcontains $n) { throw "m1b-exec: computer '$n' is not a rig VM ($($ExRigComputers -join ', ')); refusing to plant" }
}

function Assert-ExName([string]$Name, [string]$What) {
    if ($Name -notmatch '^\\?PurgeExec') { throw "$What '$Name' is not rig-owned (PurgeExec*)" }
}

# Helper binaries built with the .NET Framework csc on the image: PurgeExecSvc.exe (a do-nothing ServiceBase service,
# also the app's exe stand-in) and PurgeExecLib.dll (an empty library: the COM server file).
function Get-ExHelper([ValidateSet('exe', 'dll')][string]$Which) {
    $out = Join-Path $ExWork $(if ($Which -eq 'exe') { 'PurgeExecSvc.exe' } else { 'PurgeExecLib.dll' })
    if (Test-Path -LiteralPath $out -PathType Leaf) { return $out }
    New-Item -ItemType Directory -Force $ExWork | Out-Null
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) { throw "csc.exe not found at $csc" }
    if ($Which -eq 'exe') {
        $src = Join-Path $ExWork 'PurgeExecSvc.cs'
        [IO.File]::WriteAllText($src, @'
using System.ServiceProcess;
public class PurgeExecSvc : ServiceBase {
    public PurgeExecSvc() { ServiceName = "PurgeExecSvc"; CanStop = true; }
    protected override void OnStart(string[] args) { }
    protected override void OnStop() { }
    public static void Main() { ServiceBase.Run(new PurgeExecSvc()); }
}
'@, (New-Object System.Text.UTF8Encoding($false)))
        $a = '/nologo /target:exe /optimize /r:System.ServiceProcess.dll /out:"' + $out + '" "' + $src + '"'
    } else {
        $src = Join-Path $ExWork 'PurgeExecLib.cs'
        [IO.File]::WriteAllText($src, "namespace PurgeExec { public static class Lib { public const string Marker = `"PurgeExec`"; } }`r`n", (New-Object System.Text.UTF8Encoding($false)))
        $a = '/nologo /target:library /optimize /out:"' + $out + '" "' + $src + '"'
    }
    $r = Invoke-Native -Exe $csc -Arguments $a -TimeoutSec 120
    if ($r.exit -ne 0 -or -not (Test-Path -LiteralPath $out)) { throw "csc failed ($($r.exit)): $($r.stdout) $($r.stderr)" }
    Log "  m1b-exec: built $out"
    $out
}

function Invoke-ExSc([string]$Arguments, [switch]$AllowFail) {
    $r = Invoke-Native -Exe (Join-Path $env:SystemRoot 'System32\sc.exe') -Arguments $Arguments -TimeoutSec 60
    if ($r.exit -ne 0 -and -not $AllowFail) { throw "sc.exe $Arguments -> exit $($r.exit): $("$($r.stdout) $($r.stderr)".Trim())" }
    $r
}

function Get-ExTaskService { $s = New-Object -ComObject 'Schedule.Service'; $s.Connect(); $s }

# Folder object of a task folder path ('\PurgeExecApp\Sub'), created when -Create; $null when absent.
function Get-ExTaskFolder($Svc, [string]$Path, [switch]$Create) {
    $f = $Svc.GetFolder('\')
    foreach ($seg in @($Path.Trim('\') -split '\\' | Where-Object { $_ })) {
        $next = $null
        try { $next = $f.GetFolder($seg) } catch { $next = $null }
        if (-not $next) {
            if (-not $Create) { return $null }
            $next = $f.CreateFolder($seg)
        }
        $f = $next
    }
    $f
}

function Split-ExTaskPath([string]$Path) {
    $i = $Path.LastIndexOf('\')
    if ($i -lt 0) { throw "bad task path '$Path'" }
    @($(if ($i -eq 0) { '\' } else { $Path.Substring(0, $i) }), $Path.Substring($i + 1))
}

# Registers $Xml at $Path for SYSTEM (TASK_CREATE_OR_UPDATE, TASK_LOGON_SERVICE_ACCOUNT), with $Sddl when given.
function Register-ExTask([string]$Path, [string]$Xml, [string]$Sddl = '') {
    Assert-ExName $Path.TrimStart('\') 'task'
    $dir, $leaf = Split-ExTaskPath $Path
    $svc = Get-ExTaskService
    $f = Get-ExTaskFolder $svc $dir -Create
    if ($Sddl) { $null = $f.RegisterTask($leaf, $Xml, 6, 'SYSTEM', $null, 5, $Sddl) }
    else { $null = $f.RegisterTask($leaf, $Xml, 6, 'SYSTEM', $null, 5) }
}

# The object's state as text (independent of rigtool): a service's whole key tree but the runtime Enum subkey (every
# value's name, kind and raw data, unexpanded), a task's XML and SDDL as Task Scheduler returns them, a rule's
# registry string. $null when the object is absent.
function Get-ExObjectState([string]$Kind, [string]$Name) {
    switch ($Kind) {
        'service' {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
            $k = $base.OpenSubKey("SYSTEM\CurrentControlSet\Services\$Name", $false)
            if (-not $k) { return $null }
            $lines = New-Object System.Collections.ArrayList
            $walk = $null
            $walk = {
                param($Key, [string]$Rel)
                foreach ($vn in @($Key.GetValueNames() | Sort-Object)) {
                    $kind = $Key.GetValueKind($vn)
                    $d = $Key.GetValue($vn, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $txt = $(if ($d -is [byte[]]) { [Convert]::ToBase64String($d) } elseif ($d -is [array]) { ($d -join "`0") } else { "$d" })
                    [void]$lines.Add("V|$Rel|$vn|$kind|$txt")
                }
                foreach ($sn in @($Key.GetSubKeyNames() | Sort-Object)) {
                    if (-not $Rel -and $sn -eq 'Enum') { continue }
                    $sk = $Key.OpenSubKey($sn, $false)
                    if ($sk) { try { [void]$lines.Add("K|$Rel\$sn"); & $walk $sk "$Rel\$sn" } finally { $sk.Dispose() } }
                }
            }
            try { & $walk $k '' } finally { $k.Dispose(); $base.Dispose() }
            return ($lines -join "`n")
        }
        'task' {
            $dir, $leaf = Split-ExTaskPath $Name
            $svc = Get-ExTaskService
            $f = Get-ExTaskFolder $svc $dir
            if (-not $f) { return $null }
            $t = $null; try { $t = $f.GetTask($leaf) } catch { $t = $null }
            if (-not $t) { return $null }
            return "$($t.Xml)`n$($t.GetSecurityDescriptor(7))"
        }
        'firewall' {
            $v = Get-RegRaw $ExFwKey $Name
            if ($null -eq $v) { return $null }
            return "$v"
        }
        default { throw "unknown object kind '$Kind'" }
    }
}

# The service as the SCM sees it: {state, pid, start_mode}; $null when there is no such service. The svc-running trap
# compares it before and after exec: the service must still run, as the same process (review R4 S3).
function Get-ExScmState([string]$Name) {
    $s = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f ($Name -replace "'", "''")) -ErrorAction SilentlyContinue
    if (-not $s) { return $null }
    [ordered]@{ state = "$($s.State)"; pid = [int]$s.ProcessId; start_mode = "$($s.StartMode)" }
}

function Get-ExStateRecord([string]$Kind, [string]$Name) {
    $s = Get-ExObjectState $Kind $Name
    [ordered]@{ kind = $Kind; name = $Name; present = ($null -ne $s); sha256 = (Get-ExSha $s) }
}

# Removes rig-owned objects (names PurgeExec*), stopping a running service first; waits until each service is gone.
function Remove-ExObjects([string[]]$Services = @(), [string[]]$Tasks = @(), [string[]]$Rules = @(), [switch]$AllTasks) {
    foreach ($n in @($Services | Where-Object { $_ })) {
        Assert-ExName $n 'service'
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if (-not $s) { continue }
        if ($s.Status -ne 'Stopped') { try { Stop-Service -Name $n -Force -ErrorAction Stop; $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } catch { Log "  !! stop $n`: $($_.Exception.Message)" } }
        $null = Invoke-ExSc "delete $n" -AllowFail
        $t0 = Get-Date
        while ((Get-Service -Name $n -ErrorAction SilentlyContinue) -and ((Get-Date) - $t0).TotalSeconds -lt 30) { Start-Sleep -Milliseconds 500 }
        if (Get-Service -Name $n -ErrorAction SilentlyContinue) { throw "service $n still there 30 s after sc delete (marked for deletion?)" }
        Log "  removed service $n"
    }
    $svc = $null
    foreach ($p in @($Tasks | Where-Object { $_ })) {
        Assert-ExName $p.TrimStart('\') 'task'
        if (-not $svc) { $svc = Get-ExTaskService }
        $dir, $leaf = Split-ExTaskPath $p
        $f = Get-ExTaskFolder $svc $dir
        if ($f) { try { $f.DeleteTask($leaf, 0); Log "  removed task $p" } catch { } }
    }
    if ($AllTasks) {
        if (-not $svc) { $svc = Get-ExTaskService }
        $top = Get-ExTaskFolder $svc $ExTaskRoot
        if ($top) {
            $drop = $null
            $drop = {
                param($F)
                foreach ($sub in @($F.GetFolders(0))) { & $drop $sub }
                foreach ($t in @($F.GetTasks(1))) { try { $F.DeleteTask($t.Name, 0); Log "  removed task $($t.Path)" } catch { Log "  !! task $($t.Path): $($_.Exception.Message)" } }
            }
            & $drop $top
            $paths = New-Object System.Collections.ArrayList
            $list = $null
            $list = { param($F) foreach ($sub in @($F.GetFolders(0))) { & $list $sub; [void]$paths.Add($sub.Path) } }
            & $list $top
            [void]$paths.Add($top.Path)
            $root = $svc.GetFolder('\')
            foreach ($fp in $paths) { try { $root.DeleteFolder($fp.TrimStart('\'), 0) } catch { Log "  !! task folder $fp`: $($_.Exception.Message)" } }
        }
    }
    foreach ($id in @($Rules | Where-Object { $_ })) {
        Assert-ExName $id 'firewall rule'
        if (Get-NetFirewallRule -Name $id -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -Name $id -ErrorAction Stop; Log "  removed firewall rule $id" }
    }
}

# Every rig-owned object of the cases file (all modes), the app's files, ARP key and COM class: a clean slate.
function Clear-ExWorld($Cases) {
    $svcs = @(); $tasks = @(); $rules = @()
    foreach ($v in @($Cases.fidelity.variants) + @($Cases.act_traps.cases)) {
        if (-not $v) { continue }
        switch ("$($v.kind)") { 'service' { $svcs += "$($v.name)"; if ($v.dependent) { $svcs = @("$($v.dependent)") + $svcs } } 'task' { $tasks += "$($v.path)" } 'firewall' { $rules += "$($v.rule)"; if ($v.twin) { $rules += "$($v.twin)" } } }
    }
    $svcs += @(Get-Service -Name 'PurgeExec*' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $rules += @(Get-NetFirewallRule -Name 'PurgeExec*' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    # Dependents first (a service another depends on cannot be deleted cleanly before it).
    $svcs = @($svcs | Select-Object -Unique | Sort-Object { if ($_ -like '*Dep') { 0 } else { 1 } })
    Remove-ExObjects -Services $svcs -Tasks $tasks -Rules @($rules | Select-Object -Unique) -AllTasks
    Remove-ExAppFiles
}

# The app: folder with app.exe, tool.exe, uninst.exe (copies of the helper exe), PurgeExecCom.dll; the ARP entry; the
# COM class of the COM-handler task (InprocServer32 in the folder; written after the folder, so harvest takes it as
# the app's own class).
function New-ExApp {
    Assert-ExRigVm
    $exe = Get-ExHelper exe; $dll = Get-ExHelper dll
    New-Item -ItemType Directory -Force $ExDir | Out-Null
    foreach ($n in 'app.exe', 'tool.exe', 'uninst.exe') { Copy-Item -LiteralPath $exe -Destination (Join-Path $ExDir $n) -Force }
    Copy-Item -LiteralPath $dll -Destination (Join-Path $ExDir 'PurgeExecCom.dll') -Force
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $k = $base.CreateSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PurgeExecApp')
        try {
            $k.SetValue('DisplayName', $ExApp, 'String'); $k.SetValue('DisplayVersion', '1.0.0', 'String'); $k.SetValue('Publisher', 'Purge Rig', 'String')
            $k.SetValue('InstallLocation', $ExDir, 'String'); $k.SetValue('UninstallString', '"' + (Join-Path $ExDir 'uninst.exe') + '"', 'String')
            $k.SetValue('DisplayIcon', (Join-Path $ExDir 'app.exe'), 'String'); $k.SetValue('NoModify', 1, 'DWord'); $k.SetValue('NoRepair', 1, 'DWord')
            $k.SetValue('InstallDate', (Get-Date -Format 'yyyyMMdd'), 'String')
        } finally { $k.Dispose() }
        $c = $base.CreateSubKey("SOFTWARE\Classes\CLSID\$ExClsid")
        try {
            $c.SetValue('', 'PurgeExec COM handler', 'String')
            $ip = $c.CreateSubKey('InprocServer32')
            try { $ip.SetValue('', (Join-Path $ExDir 'PurgeExecCom.dll'), 'String'); $ip.SetValue('ThreadingModel', 'Both', 'String') } finally { $ip.Dispose() }
        } finally { $c.Dispose() }
    } finally { $base.Dispose() }
    Log "  app $ExApp planted in $ExDir (ARP $ExArp, COM $ExClsid)"
}

# The app "uninstalled externally": folder, ARP key and COM class gone; the system objects stay.
function Remove-ExAppFiles {
    if (Test-Path -LiteralPath $ExDir) {
        Remove-Item -LiteralPath $ExDir -Recurse -Force -ErrorAction Stop
        Log "  removed $ExDir"
    }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $base.DeleteSubKeyTree('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PurgeExecApp', $false)
        $base.DeleteSubKeyTree("SOFTWARE\Classes\CLSID\$ExClsid", $false)
    } finally { $base.Dispose() }
}

# One system object of a variant or trap definition ($Def.plant). Service exes are copies of the helper in the app
# folder; task and rule programs are app files ($ExDir\<exe>).
function Add-ExObject($Def) {
    Assert-ExRigVm
    $kind = "$($Def.kind)"; $name = Get-ExObjectName $Def
    Assert-ExName $name.TrimStart('\') $kind
    $p = $Def.plant
    switch ($kind) {
        'service' {
            $exeName = $(if ($p -and $p.exe) { "$($p.exe)" } else { "$name.exe" })
            $exe = Join-Path $ExDir $exeName
            Copy-Item -LiteralPath (Get-ExHelper exe) -Destination $exe -Force
            $desc = $(if ($p -and $p.description) { "$($p.description)" } else { "PurgeExec: $name" })
            $null = New-Service -Name $name -BinaryPathName ('"' + $exe + '"') -DisplayName "PurgeExec $name" -StartupType Manual -Description $desc -ErrorAction Stop
            if ($p -and $p.account -and "$($p.account)" -ne 'LocalSystem') { $null = Invoke-ExSc ('config ' + $name + ' obj= "' + $p.account + '" password= ""') }
            if ($p -and $p.failure_actions) { $null = Invoke-ExSc "failure $name reset= 86400 actions= restart/60000/restart/120000//" }
            if ($p -and $p.trigger) { $null = Invoke-ExSc "triggerinfo $name $($p.trigger)" }
            if ($p -and $p.privileges) { $null = Invoke-ExSc ("privs $name " + (@($p.privileges) -join '/')) }
            if ($p -and $p.sidtype) { $null = Invoke-ExSc "sidtype $name $($p.sidtype)" }
            if ($p -and $p.parameters) {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
                try {
                    $k = $base.CreateSubKey("SYSTEM\CurrentControlSet\Services\$name\Parameters")
                    try { $k.SetValue('PurgeExecSetting', 'planted by m1b-exec', 'String'); $k.SetValue('Level', 3, 'DWord'); $k.SetValue('Paths', [string[]]@($ExDir, 'C:\ProgramData\PurgeExecApp'), 'MultiString') } finally { $k.Dispose() }
                } finally { $base.Dispose() }
            }
        }
        'task' {
            $acts = @(@($p.actions) | Where-Object { $_ } | ForEach-Object { @{ exe = (Join-Path $ExDir "$($_.exe)"); args = "$($_.args)" } })
            $xml = New-ExTaskXml -Description "PurgeExec task $name" -Actions $acts -ComClsid $(if ($p.com_handler) { $ExClsid } else { '' }) -Hidden:([bool]$p.hidden)
            Register-ExTask $name $xml $(if ($p.sddl) { "$($p.sddl)" } else { '' })
        }
        'firewall' {
            $a = @{ Name = $name; DisplayName = "$($p.display)"; Direction = $(if ($p.direction) { "$($p.direction)" } else { 'Inbound' }); Action = 'Allow'; Description = "PurgeExec rule $name"; ErrorAction = 'Stop' }
            if ($p.program) { $a.Program = Join-Path $ExDir "$($p.program)" }
            if ($p.protocol) { $a.Protocol = "$($p.protocol)" }
            if ($p.local_port) { $a.LocalPort = "$($p.local_port)" }
            if ($p.remote_address) { $a.RemoteAddress = [string[]]@($p.remote_address) }
            if ($p.profile) { $a.Profile = "$($p.profile)" } else { $a.Profile = 'Any' }
            if ($p.service) { $a.Service = "$($p.service)" }
            $null = New-NetFirewallRule @a
        }
    }
    $st = Get-ExStateRecord $kind $name
    if (-not $st.present) { throw "planted $kind $name is not there" }
    Log "  planted $kind $name"
    $st
}

# harvest of the app (by its ARP key name), the uninstall stand-in, scan --mode external. Returns {fp, plan, rows,
# recorded (fp.sys names)}. Throws when an engine call fails.
function Invoke-ExHarvestScan([string]$Tag, [string]$Dir, $Calls) {
    $fp = Join-Path $Dir "fp-$Tag.json"
    $plan = Join-Path $Dir "plan-$Tag.json"
    $null = Invoke-M2Engine -Step "harvest-$Tag" -Arguments ('harvest ' + (ConvertTo-EngineArg $ExApp) + ' -o ' + (ConvertTo-EngineArg $fp)) -Calls $Calls -TimeoutSec 1800
    Remove-ExAppFiles
    $null = Invoke-M2Engine -Step "scan-$Tag" -Arguments ('scan --fp ' + (ConvertTo-EngineArg $fp) + ' --mode external --app ' + $ExAppId + ' -o ' + (ConvertTo-EngineArg $plan)) -Calls $Calls -TimeoutSec 1800
    $f = [IO.File]::ReadAllText($fp) | ConvertFrom-Json
    $rows = @(ConvertTo-ExPlanRows ([IO.File]::ReadAllText($plan) | ConvertFrom-Json) ([IO.File]::ReadAllText((Get-M2Sidecar $plan)) | ConvertFrom-Json))
    $rec = [ordered]@{ services = @(); tasks = @(); firewall = @() }
    if ($f.sys) {
        $rec.services = @(@($f.sys.services) | Where-Object { $_ } | ForEach-Object { "$($_.identity.name)" })
        $rec.tasks = @(@($f.sys.tasks) | Where-Object { $_ } | ForEach-Object { "$($_.identity.path)" })
        $rec.firewall = @(@($f.sys.firewall_rules) | Where-Object { $_ } | ForEach-Object { "$($_.identity.id)" })
    }
    Log ("  {0}: harvest recorded {1} service(s), {2} task(s), {3} rule(s); plan {4} item(s): {5}" -f $Tag, $rec.services.Count, $rec.tasks.Count, $rec.firewall.Count, $rows.Count,
        (@($rows | ForEach-Object { "$($_.key)=$($_.band)$(if ($_.preselected) { '*' })" }) -join ', '))
    [pscustomobject][ordered]@{ fp = $fp; plan = $plan; rows = $rows; recorded = $rec; plan_hash = (Get-M2PlanHash $plan) }
}

# The plan row of an object, or $null.
function Find-ExRow($Rows, [string]$Kind, [string]$Name) {
    $k = Get-ExObjectKey $Kind $Name
    @($Rows | Where-Object { $_.key -ceq $k }) | Select-Object -First 1
}

function New-ExExecArgs([string]$Plan, [string]$Confirm, [string]$Select, [string]$Fp, [string]$Out) {
    (New-M2ExecArgs $Plan $Confirm $Select) + ' --fp ' + (ConvertTo-EngineArg $Fp) + $(if ($Out) { ' -o ' + (ConvertTo-EngineArg $Out) } else { '' })
}

if ($Library) { return }

# ============================================================================================ main
# (The placeholders sit after the library return: a script that dot-sources this one with -Library keeps its own.)
$Run = '__RUN__'
$Mode = '__MODE__'
$Stage = '__STAGE__'
$OptsB64 = '__OPTS__'

if ($Run -eq ('__' + 'RUN__') -or $Run -cnotmatch '^[a-z0-9][a-z0-9_.-]*$') { Write-Host ("m1b-exec.ps1: bad or unreplaced run name '{0}'" -f $Run); exit 2 }
if ($ExModes -cnotcontains $Mode) { Write-Host ("m1b-exec.ps1: bad or unreplaced mode '{0}'" -f $Mode); exit 2 }
if ($Stage -eq ('__' + 'STAGE__')) { $Stage = 'start' }
if ($Stage -ne 'start') { Write-Host ("m1b-exec.ps1: bad stage '{0}'" -f $Stage); exit 2 }
. C:\cr\guest\riglib.ps1
Assert-ExRigVm

$Opts = ConvertFrom-M2Opts $OptsB64
$R = Open-M2Run $Run $Mode $Stage
$D = $R.dir
$S = $R.S
$Calls = $S.engine.calls
$PhaseCount0 = $S.phases.Count
$Cases = $null

function Q([string]$s) { ConvertTo-EngineArg $s }
function F([string]$n) { Join-Path $D $n }
function Read-Json([string]$p) { if (Test-Path -LiteralPath $p) { [IO.File]::ReadAllText($p) | ConvertFrom-Json } else { $null } }
function Add-Result([string]$Key, [string]$Sub, $Value) {
    $cur = $S.results[$Key]
    $h = [ordered]@{}
    if ($cur -is [System.Collections.IDictionary]) { foreach ($k in $cur.Keys) { $h[$k] = $cur[$k] } }
    elseif ($cur) { foreach ($p in $cur.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    $h[$Sub] = $Value
    Set-M2Result $R $Key $h
}

function Step-Install {
    $r1 = Invoke-M2Script $RigInstallScript ('-Engine ' + (Q $RigEngine) + ' -ReportPath ' + (Q (F 'install.json')))
    Set-M2Result $R 'install' ([ordered]@{ exit = $r1.exit })
    $S.engine.exe = Get-M2EngineExe
    Set-M2Result $R 'engine_build' (Get-ExEngineBuild $Opts $RigEngine $RigEngineInstalled)
    if ($r1.exit -ne 0) { throw "install.ps1 exited $($r1.exit)" }
}

# Exec of $Ids with --fp; never throws on the exit code. Returns {exit, session, report (path), journal, doc}.
function Invoke-ExExec($Scan, [string[]]$Ids, [string]$Tag, [hashtable]$Environment = @{}) {
    $sel = Write-M2IdFile $Ids (F "select-$Tag.json")
    $conf = Get-M2Confirm $Scan.plan_hash $Ids
    $before = @(Get-M2Sessions)
    $rep = F "report-$Tag.json"
    $r = Invoke-M2Engine -Step "exec-$Tag" -Arguments (New-ExExecArgs $Scan.plan $conf $sel $Scan.fp $rep) -Calls $Calls -Environment $Environment -StdoutFile (F "exec-$Tag.out") -NoThrow
    $session = $null
    if (Test-Path -LiteralPath $rep) { $session = "$((Read-Json $rep).session)" }
    if (-not $session) { $session = Get-M2NewSession $before }
    $out = [pscustomobject][ordered]@{ tag = $Tag; exit = $r.exit; crashed = $r.crashed; session = $session; report = $null; journal = $null; doc = $null }
    if (Test-Path -LiteralPath $rep) { $out.report = $rep; $out.doc = Read-Json $rep }
    if ($session) {
        $out.journal = Join-Path (Get-M2SessionDir $session) 'journal.jsonl'
        $null = Copy-M2Session $session $D "sess-$Tag"
    }
    $out
}

function Invoke-ExUndo([string]$Session, [string]$Tag) {
    $r = Invoke-M2Engine -Step "undo-$Tag" -Arguments (New-M2UndoArgs $Session '' '' (F "undo-$Tag.json")) -Calls $Calls -StdoutFile (F "undo-$Tag.out") -NoThrow
    $null = Copy-M2Session $Session $D "sess-$Tag-undo"
    [pscustomobject]@{ exit = $r.exit; doc = (Read-Json (F "undo-$Tag.json")) }
}

function Step-Pauses {
    Phase 'edge-pause' { $S.edge_pause = Suspend-EdgeUpdate } $S
    Phase 'telemetry-pause' { $S.telemetry_pause = Suspend-M2Telemetry } $S
    Phase 'install' { Step-Install } $S
}

function Step-Settle([string]$Tag) {
    Phase "settle-$Tag" { Add-Result 'settle' $Tag (Wait-M2BootSettle -MaxSec ([int](Get-M2Opt $Opts 'settle_max' 300)) -MinUptimeSec ([int](Get-M2Opt $Opts 'settle_min_uptime' 180))) } $S
}

# Plants every fidelity variant; returns the variant records (id, kind, name, expect, planted state).
function Step-PlantFidelity {
    $script:Variants = New-Object System.Collections.ArrayList
    Phase 'clean' { Clear-ExWorld $Cases } $S
    Phase 'plant' {
        New-ExApp
        foreach ($v in @($Cases.fidelity.variants)) {
            $st = Add-ExObject $v
            [void]$script:Variants.Add([ordered]@{ id = "$($v.id)"; kind = "$($v.kind)"; name = (Get-ExObjectName $v); expect = "$($v.expect)"; planted = $st })
        }
        Set-M2Result $R 'planted' @($script:Variants)
    } $S
    Phase 'harvest-scan' { $script:Scan = Invoke-ExHarvestScan 'main' $D $Calls } $S
}

# m1b-x-fidelity (G5: K10, K11).
function Invoke-FidelityMode {
    Step-Pauses
    $script:Scan = $null
    Step-PlantFidelity
    if (-not $script:Scan) { return }
    $sc = $script:Scan
    $script:Sel = @()
    Phase 'select' {
        # The Safe selection (band Safe, ticked or not): what the plan offers as Safe is what runs.
        $script:Sel = @($sc.rows | Where-Object { $_.band -eq 'Safe' } | ForEach-Object { $_.id })
        if (-not $script:Sel.Count) { throw 'the plan offers no Safe item' }
        $offered = [ordered]@{}
        foreach ($v in $script:Variants) {
            $row = Find-ExRow $sc.rows $v.kind $v.name
            $v.offered = $(if ($row) { [ordered]@{ id = $row.id; band = $row.band; preselected = $row.preselected } } else { $null })
            $v.selected = [bool]($row -and $script:Sel -contains $row.id)
            $v.recorded = [bool](@($sc.recorded[$(switch ($v.kind) { 'service' { 'services' } 'task' { 'tasks' } default { 'firewall' } })] | Where-Object { "$_" -eq $v.name }).Count)
        }
        Set-M2Result $R 'selection' ([ordered]@{ ids = $script:Sel; rows = @($sc.rows | ForEach-Object { [ordered]@{ id = $_.id; key = $_.key; band = $_.band; preselected = $_.preselected; action = $_.action } }) })
    } $S
    if (-not $script:Sel.Count) { return }
    $objs = @($script:Variants | ForEach-Object { [pscustomobject]@{ kind = $_.kind; name = $_.name } })
    $sp = Split-ExObjects $objs
    $selTargets = @($sc.rows | Where-Object { $script:Sel -contains $_.id } | ForEach-Object { $_.target })
    Write-JsonFile (New-ExDeepScope $sp.service $sp.task $sp.firewall $selTargets) (F 'deepscope-main.json') 12
    Step-Settle 'main'
    Phase 'snap-a' { $null = Invoke-M2Snap (F "snap-$Run-a.tsv.gz") } $S
    Phase 'deep-a' { $null = Invoke-M2Deep @((F 'deepscope-main.json')) (F 'deep-a.json') } $S
    $script:X = $null
    Phase 'exec-main' {
        $script:X = Invoke-ExExec $sc $script:Sel 'main'
        if (-not $script:X.report) { throw "exec main wrote no report (exit $($script:X.exit))" }
        Add-Result 'execs' 'main' ([ordered]@{ exit = $script:X.exit; session = $script:X.session; counts = $script:X.doc.counts })
    } $S
    if (-not $script:X -or -not $script:X.report) { Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S; return }
    Phase 'snap-b' { $null = Invoke-M2Snap (F "snap-$Run-b.tsv.gz") } $S
    Phase 'deep-b' { $null = Invoke-M2Deep @((F 'deepscope-main.json')) (F 'deep-b.json') } $S
    Phase 'execdiff-main' {
        $v = Invoke-M2Execdiff -Before (F "snap-$Run-a.tsv.gz") -After (F "snap-$Run-b.tsv.gz") -Journal $script:X.journal -Report $script:X.report -DeepBefore (F 'deep-a.json') -DeepAfter (F 'deep-b.json') -Out (F 'execdiff-main.json')
        Add-Result 'execdiff' 'main' $v.ok
    } $S
    Phase 'after-exec' {
        foreach ($v in $script:Variants) {
            $v.exec = $(if ($v.offered) { Get-ExOutcome $script:X.doc $v.offered.id } else { $null })
            $v.after_exec = Get-ExStateRecord $v.kind $v.name
        }
    } $S
    $script:U = $null
    Phase 'undo-main' { $script:U = Invoke-ExUndo $script:X.session 'main'; Add-Result 'undo' 'main' ([ordered]@{ exit = $script:U.exit }) } $S
    Phase 'deep-c' { $null = Invoke-M2Deep @((F 'deepscope-main.json')) (F 'deep-c.json') } $S
    Phase 'fidelity-main' { $v = Invoke-M2Fidelity (F 'deep-a.json') (F 'deep-c.json') $script:X.journal (F 'fidelity-main.json'); Add-Result 'fidelity' 'main' $v.ok } $S
    Phase 'after-undo' {
        $fid = Read-Json (F 'fidelity-main.json')
        foreach ($v in $script:Variants) {
            $v.undo = $(if ($v.offered -and $script:U -and $script:U.doc) { Get-ExUndoResult $script:U.doc $v.offered.id } else { $null })
            $v.after_undo = Get-ExStateRecord $v.kind $v.name
            $v.fidelity_op = $null
            if ($fid -and $v.exec -and $null -ne $v.exec.op) {
                $o = @(@($fid.ops) | Where-Object { $_ -and "$($_.id)" -eq "$($v.exec.op)" })
                if ($o.Count) { $v.fidelity_op = [ordered]@{ action = $o[0].action; target = $o[0].target; outcome = $o[0].outcome; objects = $o[0].objects; differing = $o[0].differing } }
            }
        }
        Set-M2Result $R 'variants' @($script:Variants)
    } $S
    Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S
}

# m1b-x-traps (G5: K12, act-time gate).
function Invoke-TrapsMode {
    Step-Pauses
    $tc = @($Cases.act_traps.cases)
    $script:Traps = New-Object System.Collections.ArrayList
    Phase 'clean' { Clear-ExWorld $Cases } $S
    Phase 'plant' {
        New-ExApp
        foreach ($c in $tc) {
            $def = [pscustomobject]@{ kind = $c.kind; name = $c.name; path = $c.path; rule = $c.rule; plant = $null }
            switch ("$($c.kind)") {
                'task' { $def.plant = [pscustomobject]@{ actions = @([pscustomobject]@{ exe = 'app.exe'; args = '/trap' }) } }
                'firewall' { $def.plant = [pscustomobject]@{ display = "PurgeExec trap $($c.id)"; program = 'app.exe'; direction = 'Inbound' } }
                default { $def.plant = [pscustomobject]@{ exe = "$($c.name).exe"; description = "PurgeExec trap $($c.id)" } }
            }
            $st = Add-ExObject $def
            [void]$script:Traps.Add([ordered]@{ id = "$($c.id)"; kind = "$($c.kind)"; name = (Get-ExObjectName $c); change = "$($c.change)"; expect = "$($c.expect)"
                reasons = @($c.reasons); blocker = $c.blocker; planted = $st; display = $(if ("$($c.kind)" -eq 'firewall') { "PurgeExec trap $($c.id)" } else { $null }) })
        }
        Set-M2Result $R 'planted' @($script:Traps)
    } $S
    $script:Scan = $null
    Phase 'harvest-scan' { $script:Scan = Invoke-ExHarvestScan 'traps' $D $Calls } $S
    if (-not $script:Scan) { Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S; return }
    $sc = $script:Scan
    $script:Sel = @()
    Phase 'select' {
        foreach ($t in $script:Traps) {
            $row = Find-ExRow $sc.rows $t.kind $t.name
            $t.offered = $(if ($row) { [ordered]@{ id = $row.id; band = $row.band; preselected = $row.preselected } } else { $null })
            if ($row -and $row.band -eq 'Safe') { $script:Sel += $row.id }
        }
        if (-not $script:Sel.Count) { throw 'no trap object is offered Safe' }
        Set-M2Result $R 'selection' ([ordered]@{ ids = $script:Sel })
    } $S
    $twins = @($tc | Where-Object { $_.twin } | ForEach-Object { "$($_.twin)" })
    $deps = @($tc | Where-Object { $_.dependent } | ForEach-Object { "$($_.dependent)" })
    $sp = Split-ExObjects @($script:Traps | ForEach-Object { [pscustomobject]@{ kind = $_.kind; name = $_.name } })
    Write-JsonFile (New-ExDeepScope (@($sp.service) + $deps) $sp.task (@($sp.firewall) + $twins)) (F 'deepscope-traps.json') 12
    Step-Settle 'traps'
    # The world changes between scan and exec (snap A after it: execdiff then sees only what exec did).
    Phase 'change' {
        foreach ($t in $script:Traps) {
            $c = @($tc | Where-Object { "$($_.id)" -eq $t.id })[0]
            try {
                switch ($t.change) {
                    'start' {
                        # The program was removed with the app; it comes back so the service can run.
                        $exe = Join-Path $ExDir "$($t.name).exe"
                        New-Item -ItemType Directory -Force $ExDir | Out-Null
                        Copy-Item -LiteralPath (Get-ExHelper exe) -Destination $exe -Force
                        Start-Service -Name $t.name -ErrorAction Stop
                        (Get-Service -Name $t.name).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
                        $t.scm_after_change = Get-ExScmState $t.name
                    }
                    'imagepath' { $null = Invoke-ExSc ('config ' + $t.name + ' binPath= "' + $c.to + '"') }
                    'add-dependent' {
                        $dexe = Join-Path $ExWork 'PurgeExecTrapDep.exe'
                        Copy-Item -LiteralPath (Get-ExHelper exe) -Destination $dexe -Force
                        $null = New-Service -Name "$($c.dependent)" -BinaryPathName ('"' + $dexe + '"') -DisplayName 'PurgeExec trap dependent' -StartupType Manual -DependsOn $t.name -ErrorAction Stop
                    }
                    'action' {
                        $dir, $leaf = Split-ExTaskPath $t.name
                        $svc = Get-ExTaskService
                        $task = (Get-ExTaskFolder $svc $dir).GetTask($leaf)
                        $def = $task.Definition
                        $def.Actions.Item(1).Path = (Join-Path $env:SystemRoot 'System32\notepad.exe')
                        $null = (Get-ExTaskFolder $svc $dir).RegisterTaskDefinition($leaf, $def, 6, 'SYSTEM', $null, 5)
                    }
                    'app' { Set-NetFirewallRule -Name $t.name -Program (Join-Path $env:SystemRoot 'System32\notepad.exe') -ErrorAction Stop }
                    'twin' { $null = New-NetFirewallRule -Name "$($c.twin)" -DisplayName $t.display -Direction Inbound -Action Allow -Program (Join-Path $ExDir 'tool.exe') -Description 'PurgeExec twin (same display name)' -ErrorAction Stop }
                    default { throw "unknown change '$($t.change)'" }
                }
                $t.changed = $true
            } catch { $t.changed = $false; $t.change_error = "$($_.Exception.Message)"; Log "  !! change $($t.id): $($t.change_error)" }
            $t.after_change = Get-ExStateRecord $t.kind $t.name
            if ($c.twin) { $t.twin = "$($c.twin)"; $t.twin_before = Get-ExStateRecord 'firewall' "$($c.twin)" }
            Log "  trap $($t.id): $($t.change) changed=$($t.changed)"
        }
    } $S
    Phase 'snap-a' { $null = Invoke-M2Snap (F "snap-$Run-a.tsv.gz") } $S
    Phase 'deep-a' { $null = Invoke-M2Deep @((F 'deepscope-traps.json')) (F 'deep-a.json') } $S
    $script:X = $null
    Phase 'exec-traps' {
        $script:X = Invoke-ExExec $sc $script:Sel 'traps'
        Add-Result 'execs' 'traps' ([ordered]@{ exit = $script:X.exit; session = $script:X.session; counts = $(if ($script:X.doc) { $script:X.doc.counts }) })
        if (-not $script:X.report) { throw "exec traps wrote no report (exit $($script:X.exit))" }
    } $S
    Phase 'after-exec' {
        foreach ($t in $script:Traps) {
            $t.exec = $(if ($t.offered -and $script:X -and $script:X.doc) { Get-ExOutcome $script:X.doc $t.offered.id } else { $null })
            $t.after_exec = Get-ExStateRecord $t.kind $t.name
            if ($t.twin) { $t.twin_after = Get-ExStateRecord 'firewall' $t.twin }
            if ($t.change -eq 'start') { $t.scm_after_exec = Get-ExScmState $t.name }
            # The guest's reading; m1b-exec.sh judges again from these fields (with its own gate constants).
            if ($t.expect -eq 'twin-untouched') {
                # The planned rule deleted by its own id, the twin with the same display name untouched (review R4 S5).
                $t.pass = [bool]($t.changed -and $t.twin_before.present -and $t.twin_after.present -and $t.twin_after.sha256 -eq $t.twin_before.sha256 -and $t.exec -and $t.exec.kind -eq 'Done' -and -not $t.after_exec.present)
            } else {
                $okReason = ($t.exec -and $t.exec.kind -eq 'Skipped' -and @($t.reasons) -contains $t.exec.reason -and (-not $t.blocker -or $t.exec.reason -ne 'GateBlocked' -or "$($t.exec.blocker)" -match [regex]::Escape("$($t.blocker)")))
                $t.pass = [bool]($t.changed -and $okReason -and $t.after_exec.present -and $t.after_exec.sha256 -eq $t.after_change.sha256)
                # A running service must still run as the same process (review R4 S3).
                if ($t.change -eq 'start') { $t.pass = [bool]($t.pass -and $t.scm_after_change -and $t.scm_after_exec -and $t.scm_after_change.state -eq 'Running' -and $t.scm_after_exec.state -eq 'Running' -and $t.scm_after_change.pid -gt 0 -and $t.scm_after_exec.pid -eq $t.scm_after_change.pid) }
            }
        }
        Set-M2Result $R 'act_traps' @($script:Traps)
    } $S
    if ($script:X -and $script:X.report) {
        Phase 'snap-b' { $null = Invoke-M2Snap (F "snap-$Run-b.tsv.gz") } $S
        Phase 'deep-b' { $null = Invoke-M2Deep @((F 'deepscope-traps.json')) (F 'deep-b.json') } $S
        Phase 'execdiff-traps' {
            $v = Invoke-M2Execdiff -Before (F "snap-$Run-a.tsv.gz") -After (F "snap-$Run-b.tsv.gz") -Journal $script:X.journal -Report $script:X.report -DeepBefore (F 'deep-a.json') -DeepAfter (F 'deep-b.json') -Out (F 'execdiff-traps.json')
            Add-Result 'execdiff' 'traps' $v.ok
        } $S
    }
    Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S
}

# m1b-x-undo-traps (G5: K12, undo conflicts).
function Invoke-UndoTrapsMode {
    Step-Pauses
    $script:Scan = $null
    Step-PlantFidelity
    if (-not $script:Scan) { return }
    $sc = $script:Scan
    $script:X = $null
    $uc = @($Cases.undo_traps.cases)
    $script:UT = New-Object System.Collections.ArrayList
    Phase 'exec-main' {
        $sel = @($sc.rows | Where-Object { $_.band -eq 'Safe' } | ForEach-Object { $_.id })
        if (-not $sel.Count) { throw 'the plan offers no Safe item' }
        $script:X = Invoke-ExExec $sc $sel 'main'
        Add-Result 'execs' 'main' ([ordered]@{ exit = $script:X.exit; session = $script:X.session; counts = $(if ($script:X.doc) { $script:X.doc.counts }) })
        if (-not $script:X.report) { throw "exec main wrote no report (exit $($script:X.exit))" }
    } $S
    if (-not $script:X -or -not $script:X.report) { Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S; return }
    Phase 'traps' {
        $lines = @([IO.File]::ReadAllLines($script:X.journal))
        $sd = Get-M2SessionDir $script:X.session
        foreach ($c in $uc) {
            $v = Get-ExVariant $Cases "$($c.variant)"
            $name = Get-ExObjectName $v
            $row = Find-ExRow $sc.rows "$($v.kind)" $name
            $t = [ordered]@{ id = "$($c.id)"; variant = "$($c.variant)"; kind = "$($v.kind)"; name = $name; trap = "$($c.trap)"; expect_conflict = "$($c.expect_conflict)"
                item = $(if ($row) { $row.id } else { $null }); exec = $null; set = $false; error = $null }
            try {
                if (-not $row) { throw 'the object is not in the plan' }
                $t.exec = Get-ExOutcome $script:X.doc $row.id
                if (-not $t.exec -or $t.exec.kind -ne 'Done') { throw "exec did not delete it ($(if ($t.exec) { $t.exec.kind } else { 'not executed' }))" }
                switch ($t.trap) {
                    'impostor-service' {
                        $t0 = Get-Date
                        while ((Get-Service -Name $name -ErrorAction SilentlyContinue) -and ((Get-Date) - $t0).TotalSeconds -lt 30) { Start-Sleep -Milliseconds 500 }
                        $iexe = Join-Path $ExWork 'PurgeExecImpostor.exe'
                        Copy-Item -LiteralPath (Get-ExHelper exe) -Destination $iexe -Force
                        $null = New-Service -Name $name -BinaryPathName ('"' + $iexe + '"') -DisplayName 'PurgeExec impostor service' -StartupType Disabled -Description 'PurgeExec: another service under the deleted name' -ErrorAction Stop
                        $t.before_undo = Get-ExStateRecord 'service' $name
                    }
                    'impostor-task' {
                        $xml = New-ExTaskXml -Description 'PurgeExec impostor task' -Actions @(@{ exe = (Join-Path $env:SystemRoot 'System32\notepad.exe'); args = '/impostor' })
                        Register-ExTask $name $xml
                        $t.before_undo = Get-ExStateRecord 'task' $name
                    }
                    'tamper-definition' {
                        $def = Find-ExDefinition $lines $row.id
                        if (-not $def) { throw 'no intent with a definition for the item' }
                        $full = Join-Path $sd $def.path
                        $bytes = [IO.File]::ReadAllBytes($full)
                        $k = [int][Math]::Floor($bytes.Length / 2)
                        $bytes[$k] = $bytes[$k] -bxor 0x5A
                        [IO.File]::WriteAllBytes($full, $bytes)
                        $t.definition = $def.path; $t.definition_sha_after_trap = (Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash
                        $t.before_undo = Get-ExStateRecord "$($v.kind)" $name
                    }
                    'delete-definition' {
                        $def = Find-ExDefinition $lines $row.id
                        if (-not $def) { throw 'no intent with a definition for the item' }
                        $full = Join-Path $sd $def.path
                        Remove-Item -LiteralPath $full -Force -ErrorAction Stop
                        $t.definition = $def.path
                        $t.before_undo = Get-ExStateRecord "$($v.kind)" $name
                    }
                    default { throw "unknown undo trap '$($t.trap)'" }
                }
                $t.set = $true
            } catch { $t.error = "$($_.Exception.Message)"; Log "  !! undo trap $($t.id): $($t.error)" }
            [void]$script:UT.Add($t)
        }
    } $S
    $script:U = $null
    Phase 'undo-main' { $script:U = Invoke-ExUndo $script:X.session 'main'; Add-Result 'undo' 'main' ([ordered]@{ exit = $script:U.exit }) } $S
    Phase 'after-undo' {
        $sd = Get-M2SessionDir $script:X.session
        foreach ($t in $script:UT) {
            $t.undo = $(if ($t.item -and $script:U -and $script:U.doc) { Get-ExUndoResult $script:U.doc $t.item } else { $null })
            $t.after_undo = Get-ExStateRecord $t.kind $t.name
            if ($t.trap -eq 'tamper-definition' -and $t.definition) {
                $full = Join-Path $sd $t.definition
                $t.definition_sha_after_undo = $(if (Test-Path -LiteralPath $full) { (Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash } else { $null })
            }
            if ($t.trap -eq 'delete-definition' -and $t.definition) { $t.definition_present_after_undo = (Test-Path -LiteralPath (Join-Path $sd $t.definition)) }
            $conflict = ($t.undo -and $t.undo.result -eq 'Conflict' -and $t.undo.kind -eq $t.expect_conflict)
            # Nothing overwritten: an impostor exactly as the rig made it; a trapped definition's object still absent and
            # its file as the rig left it.
            $kept = switch ($t.trap) {
                'impostor-service' { $t.before_undo -and $t.after_undo.present -and $t.after_undo.sha256 -eq $t.before_undo.sha256 }
                'impostor-task' { $t.before_undo -and $t.after_undo.present -and $t.after_undo.sha256 -eq $t.before_undo.sha256 }
                'tamper-definition' { (-not $t.after_undo.present) -and $t.definition_sha_after_undo -eq $t.definition_sha_after_trap }
                'delete-definition' { (-not $t.after_undo.present) -and $t.definition_present_after_undo -eq $false }
                default { $false }
            }
            $t.conflict_ok = [bool]$conflict; $t.kept = [bool]$kept
            $t.pass = [bool]($t.set -and $conflict -and $kept)
        }
        Set-M2Result $R 'undo_traps' @($script:UT)
    } $S
    Phase 'store' { Set-M2Result $R 'store' (Save-M2Store $D 'final') } $S
}

try {
    Phase 'cases' {
        $script:Cases = Read-ExCases $Opts
        Write-JsonFile $script:Cases (F 'm1b-exec-cases.json') 20
        Set-M2Result $R 'cases' ([ordered]@{ schema = "$($script:Cases.schema)"; sha256 = (Get-ExCasesSha $Opts); variants = @($script:Cases.fidelity.variants).Count; act_traps = @($script:Cases.act_traps.cases).Count; undo_traps = @($script:Cases.undo_traps.cases).Count })
    } $S
    $Cases = $script:Cases
    if ($Cases) {
        switch ($Mode) {
            'm1b-x-fidelity' { Invoke-FidelityMode }
            'm1b-x-traps' { Invoke-TrapsMode }
            'm1b-x-undo-traps' { Invoke-UndoTrapsMode }
        }
    }
} finally {
    Save-M2Run $R -Finished
}
$failed = @(@($S.phases) | Select-Object -Skip $PhaseCount0 | Where-Object { -not $_.ok })
Log "m1b-exec $Mode done: $($failed.Count) failed phase(s)"
if ($failed.Count) { exit 1 }
exit 0
