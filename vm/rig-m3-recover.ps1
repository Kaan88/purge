<#
  Purge rig, M3 recovery modes (vm\RIG.md section 15; docs\M3_DESIGN.md 11.2, 12 G8 and G9; docs\M3_FINISH_PLAN.md B8).
  Host driver, Windows PowerShell 5.1. Dot-sources vm\rig-m3.ps1 (and through it vm\rig.ps1) for the VM helpers and
  changes neither. Guest side vm\guest\m3-recover.ps1 with the tool m3rec.exe (vm\guest\m3sec.cs + vm\guest\m3rec.cs,
  built in the guest); scorer vm\truth\m3-recover-score.ps1; expectations vm\truth\m3-recover-expect.json.

    $env:VMPWFILE = 'C:\path\to\pw.txt'; $t = '<checkout>\target'
    .\vm\rig-m3-recover.ps1 -Mode m3-owner   -Engine $t\release\purge-engine.exe -Broker $t\release\purge-broker.exe
    .\vm\rig-m3-recover.ps1 -Mode m3-recover -Engine ... -Broker ... -UiPublish $t\ui-publish [-Steps 1,5,9] [-After resume]
    .\vm\rig-m3-recover.ps1 -Mode m3-extras  -Engine ... -Broker ... [-NppInstaller <cached npp.exe>]
    powershell -NoProfile -File vm\truth\m3-recover-score.ps1 -Mode owner|recover|extras -Evidence <run dir>

  m3-owner (G8, review R8b M1, threat T10). One boot of rig-base (UAC silent). Fixture PurgeRigOwn with the service
  PurgeRigOwnSvc whose Parameters\Guarded key is owned by SYSTEM and grants nobody WRITE_OWNER. Uninstall, scan and
  execute through the broker (every dialog answered from high integrity), then undo.run, cut by the journal watcher right
  after the service op's undo_intent (broker suspended and ended). The rest of that first attempt is put in place as R8b
  M1 describes it (Guarded re-created by Administrators with the recorded group and DACL, owner left) and recorded. Then
  journal.resume through the broker's dialog, answered with the host's keys (VBoxManage keyboardputscancode), while
  m3rec privmon samples the broker's tokens and the Security log audits privilege use. Evidence: SDDL of every key of the
  service before, cut, after; privilege samples; audit events; Purge events.

  m3-recover (G9). A live snapshot m3-recover-base (rig-base + payload + fixture PurgeRigRec), built when it is missing,
  when its payload hash differs, or with -Rebuild. Round cal: one uninterrupted run; its journal has N lines. Round k
  (1..N, or -Steps), for each -After (resume, rollback): restore, uninstall + scan + execute through the broker with the
  watcher suspending the broker when the journal holds k lines, hard power-off (controlvm poweroff), cold start; then
  journal.pending through a fresh broker, the real UI's History page (Check for interrupted cleanups: banner, Resume,
  Roll back), Resume or Roll back there (or through the rig client with -NoUi), the broker's dialog answered with the
  host's keys, and the store, the index, the quarantine and the fixture's disk truth recorded after. A session whose
  journal is complete but whose index entry is missing gets journal.resume without a dialog (the bookkeeping). ~6 min a
  round: N of about 20 gives ~4 h for both afters.

  m3-extras. One boot of rig-base: allow_irreversible (Notepad++'s sparse package from the official installer in the
  rig cache, forced scan, the package alone selected: off, then on with Cancel, then on with approval, then undo),
  Restart Manager report-only (two fixture files held by a running app: one held for a retry, one moved at the next
  restart; the lockers stay running; retry_held after the app closed; reboot), System Restore (off, disabled, created,
  throttled).

  Evidence: -Evidence (default E:\purge-build\gate-evidence\<mode>\<yyyyMMdd-HHmmss>): rig-m3-recover.log, *.png,
  jobs\*.log, guest\ (owner, extras) or rounds\<round>\guest\ (recover), summary.json.
  Refuses (exit 2) unless VMPWFILE names a readable file, the VM exists, no VirtualBox VM runs and the rig lock is free
  (rig-m3.ps1 Assert-M3Start). Exit 0 when every step ran, 1 when one failed; the scorer judges the evidence.
#>
[CmdletBinding()]
param(
    [ValidateSet('', 'm3-owner', 'm3-recover', 'm3-extras')] [string] $Mode = '',
    [string] $Evidence = '',
    [string] $Engine = '',
    [string] $Broker = '',
    [string] $UiPublish = '',
    [int[]] $Steps = @(),
    [ValidateSet('both', 'resume', 'rollback')] [string] $After = 'both',
    [switch] $Rebuild,
    [switch] $NoUi,
    [string] $NppInstaller = ''
)
$ErrorActionPreference = 'Stop'

# rig-m3.ps1 and rig.ps1 have parameters of their own ($Mode, $Engine, $Evidence, ...): ours are kept here first.
$RC = [ordered]@{ mode = $Mode; evidence = $Evidence; engine = $Engine; broker = $Broker; ui = $UiPublish; steps = @($Steps); after = $After
                  rebuild = [bool]$Rebuild; no_ui = [bool]$NoUi; npp = $NppInstaller; run = (Get-Date -Format 'yyyyMMdd-HHmmss') }
if (-not $RC.evidence -and $RC.mode) { $RC.evidence = "E:\purge-build\gate-evidence\$($RC.mode)\$($RC.run)" }
. (Join-Path $PSScriptRoot 'rig-m3.ps1') -Engine $RC.engine -Broker $RC.broker -UiPublish $RC.ui -Evidence $(if ($RC.evidence) { $RC.evidence } else { 'unused' })
$M3.mode = $RC.mode
$M3.evidence = $RC.evidence

$RecBase = 'm3-recover-base'
$RecGuestScripts = @('riglib.ps1', 'm3-recover.ps1', 'm3sec.cs', 'm3rec.cs')
# Set 1 scancodes besides rig-m3.ps1's: Shift+Tab and Space.
$M3Keys['shift-tab'] = @('2a', '0f', '8f', 'aa')
$M3Keys['space'] = @('39', 'b9')
$script:RecShots = New-Object System.Collections.ArrayList
$script:RecRounds = New-Object System.Collections.ArrayList
$script:RecKeys = [ordered]@{}

# ------------------------------------------------------------------------------------------------ pure

# The job text of one guest phase of m3-recover.ps1.
function New-RecPhaseText([string]$Phase, [string]$Tag = '', [string]$Fix = '', [string]$Via = '', [int]$WaitSec = 120) {
    foreach ($v in $Phase, $Tag, $Fix, $Via) { if ("$v" -notmatch '^[A-Za-z0-9_-]*$') { throw "bad phase argument '$v'" } }
    $t = "& 'C:\cr\guest\m3-recover.ps1' -Phase '$Phase'"
    if ($Tag) { $t += " -Tag '$Tag'" }
    if ($Fix) { $t += " -Fix '$Fix'" }
    if ($Via) { $t += " -Via '$Via'" }
    $t + " -WaitSec $WaitSec"
}

# The afters of -After.
function Get-RecAfters([string]$After) { switch ($After) { 'both' { @('resume', 'rollback') } 'resume' { @('resume') } 'rollback' { @('rollback') } default { throw "bad -After '$After'" } } }

# The steps a run covers: -Steps (each within 1..N), or every line of the calibration journal 1..N.
function Get-RecStepList([int]$N, [int[]]$Only = @()) {
    if ($N -lt 1) { throw "the calibration journal has no lines (N=$N)" }
    $only = @($Only | Where-Object { $_ })
    foreach ($s in $only) { if ($s -lt 1 -or $s -gt $N) { throw "step $s is outside 1..$N" } }
    if ($only.Count) { return @($only | Sort-Object -Unique) }
    @(1..$N)
}

function Get-RecRoundName([int]$K, [string]$After) { 'k{0:D2}-{1}' -f $K, $After }

# Which key the host sends next at a consent dialog, from the guest's FOCUS line: 'done' (no dialog any more), 'wait'
# (the primary is focused but still disarmed), 'space' (the box is focused and unticked, or the armed primary is
# focused), 'tab' (towards the box), 'shift-tab' (towards the primary button).
function Get-RecKeyChoice([string]$Line) {
    $f = { param($k) $m = [regex]::Match("$Line", "(?:^|\s)$([regex]::Escape($k))=('[^']*'|\S*)"); if ($m.Success) { $m.Groups[1].Value.Trim("'") } else { $null } }
    if ((& $f 'found') -ne 'True') { return 'done' }
    $focused = & $f 'focused'; $primary = & $f 'primary'; $enabled = & $f 'enabled'; $verify = & $f 'verify'; $type = & $f 'type'
    if ($verify -eq 'Off') { if ($type -eq 'ControlType.CheckBox') { return 'space' } else { return 'tab' } }
    if ($primary -and $focused -eq $primary) { if ($enabled -eq 'True') { return 'space' } else { return 'wait' } }
    'shift-tab'
}

# The hash a m3-recover-base snapshot is built from: the payload files and the guest side.
function Get-RecPayloadHash([string[]]$Files) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $sb = New-Object System.Text.StringBuilder
    foreach ($f in @($Files | Sort-Object)) {
        $h = $(if (Test-Path -LiteralPath $f -PathType Leaf) { [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($f))).Replace('-', '') } else { 'missing' })
        [void]$sb.Append("$(Split-Path -Leaf $f)=$h;")
    }
    [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sb.ToString()))).Replace('-', '').Substring(0, 16).ToLowerInvariant()
}

function Get-RecField([string]$Line, [string]$Key) {
    $m = [regex]::Match("$Line", "(?:^|\s)$([regex]::Escape($Key))=('[^']*'|\S*)")
    if ($m.Success) { $m.Groups[1].Value.Trim("'") } else { $null }
}

# ------------------------------------------------------------------------------------------------ guest

function Invoke-RecPhase([string]$Phase, [string]$Tag = '', [string]$Fix = '', [string]$Via = '', [int]$WaitSec = 120, [int]$TimeoutSec = 0) {
    if (-not $TimeoutSec) { $TimeoutSec = $WaitSec + 600 }
    $name = "rec-$Phase$(if ($Tag) { "-$Tag" })$(if ($Fix) { "-$Fix" })"
    $jobs = Join-Path $M3.evidence 'jobs'
    New-Item -ItemType Directory -Force $jobs | Out-Null
    $j = Invoke-GuestJob -Text (New-RecPhaseText $Phase $Tag $Fix $Via $WaitSec) -Name $name -TimeoutSec $TimeoutSec -LogCopy (Join-Path $jobs "$name-$(Get-Date -Format 'HHmmss').log")
    $lines = @("$($j.log)" -split "`r?`n" | Where-Object { $_ -match '^M3R ' })
    foreach ($l in $lines) { Write-RigLog "  $l"; [void]$script:M3Lines.Add($l) }
    if (-not $j.done) { Write-RigLog "  !! phase $name did not finish within $TimeoutSec s"; $script:M3Fail = $true }
    elseif (-not $lines.Count) { Write-RigLog "  !! phase $name wrote no result line; log: $($j.log_file)"; $script:M3Fail = $true }
    $lines | Select-Object -First 1
}

function Save-RecShot([string]$Name, [string]$Round = '') {
    $f = Save-M3Shot $Name
    [void]$script:RecShots.Add([ordered]@{ name = $Name; round = $Round; file = $(if ($f) { Split-Path -Leaf $f }); bytes = $(if ($f) { (Get-Item $f).Length } else { 0 }); t = (Get-Date).ToString('o') })
}

function Push-RecFiles {
    foreach ($d in 'C:\cr\guest', 'C:\cr\m3rec', 'C:\cr\out', 'C:\cr\inst') { $null = Invoke-Guest @('mkdir', '--parents', $d) }
    $files = $RecGuestScripts | ForEach-Object { Join-Path $script:RigDir "guest\$_" }
    $r = Invoke-Guest (@('copyto', '--target-directory', 'C:\cr\guest\') + $files)
    if ($r.code -ne 0) { throw "copy guest files failed: $($r.out -join ' ')" }
    Push-M2Install
    $zip = New-M3SecPayload
    try {
        $null = Invoke-GuestCmd 'del /f /q C:\cr\m3rec\payload.zip'
        $r = Invoke-Guest @('copyto', $zip, 'C:\cr\m3rec\payload.zip')
        if ($r.code -ne 0) { throw "copy payload failed: $($r.out -join ' ')" }
    } finally { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
    Write-RigLog "  pushed $($RecGuestScripts -join ', '), install.ps1, payload.zip"
}

# Build, install, UAC check (silent: ConsentPromptBehaviorAdmin=0, the rig default these modes need) on the running VM.
function Initialize-RecGuest {
    Push-RecFiles
    $b = Invoke-RecPhase 'build'
    if ("$b" -notmatch '^M3R BUILD OK') { throw "the guest build of m3rec.exe failed: $b" }
    $i = Invoke-RecPhase 'install' -WaitSec 600
    if ("$i" -notmatch '^M3R INSTALL OK') { throw "install failed: $i" }
    $u = Invoke-RecPhase 'uac-check'
    Assert-M3SecUac $u 0
}

# Pack the guest's output tree as <name> and expand it under $Dest.
function Receive-RecGuest([string]$Name, [string]$Dest) {
    $null = Invoke-RecPhase 'pack' $Name -WaitSec 300
    $zip = Join-Path $M3.evidence "guest-$Name.zip"
    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
    $c = Invoke-Guest @('copyfrom', "C:\cr\out\m3-recover-$Name.zip", $zip)
    if ($c.code -eq 0 -and (Test-Path -LiteralPath $zip)) {
        if (Test-Path -LiteralPath $Dest) { Remove-Item -LiteralPath $Dest -Recurse -Force }
        Expand-Archive -LiteralPath $zip -DestinationPath $Dest
        Remove-Item -LiteralPath $zip -Force
        Write-RigLog "  guest outputs in $Dest"
    } else { Write-RigLog "  !! copyfrom of the guest zip $Name failed: $($c.out -join ' ')"; $script:M3Fail = $true }
}

# The broker's consent dialog answered with the host's keys only: each turn the guest reports the focus (dialog-focus),
# Get-RecKeyChoice picks the key, the host sends its scancodes and takes a screenshot. Returns the record.
function Invoke-RecKeysAnswer([string]$Name, [string]$Round = '') {
    Save-RecShot "$Name-2-dialog" $Round
    $rec = [ordered]@{ name = $Name; turns = @(); answered = $false }
    for ($i = 1; $i -le 12; $i++) {
        $line = Invoke-RecPhase 'dialog-focus' "$Name-$i" -WaitSec 30
        $choice = Get-RecKeyChoice $line
        $turn = [ordered]@{ i = $i; focus = $line; key = $choice; sent = $null }
        if ($choice -eq 'done') { $rec.answered = ($i -gt 1); $rec.turns += $turn; break }
        if ($choice -eq 'wait') { Start-Sleep -Seconds 1 }
        else {
            $turn.sent = Send-M3Keys $choice
            Start-Sleep -Seconds 2
            Save-RecShot ('{0}-3-after-{1:D2}-{2}' -f $Name, $i, $choice) $Round
        }
        $rec.turns += $turn
    }
    $script:RecKeys[$Name] = $rec
    Write-RigLog "  => keys at the dialog ${Name}: answered=$($rec.answered) $(@($rec.turns | ForEach-Object { $_.key }) -join ',')"
    $rec
}

# ------------------------------------------------------------------------------------------------ modes

function Invoke-RecOwner {
    Restore-Base -Snapshot 'rig-base' -No3D
    Initialize-RecGuest
    $null = Invoke-RecPhase 'fixture' -Fix 'own'
    $e = Invoke-RecPhase 'own-exec' -WaitSec 900
    if ((Get-RecField $e 'session') -in @($null, '')) { throw "own-exec made no session: $e" }
    Save-RecShot 'own-0-executed'
    $c = Invoke-RecPhase 'own-undo-cut' -WaitSec 900
    if ("$c" -notmatch 'listed=True') { Write-RigLog '  !! the cut undo is not listed by journal.pending'; $script:M3Fail = $true }
    $s = Invoke-RecPhase 'own-resume-start' -WaitSec 300
    Save-RecShot 'own-1-resume-dialog'
    if ((Get-RecField $s 'found') -eq 'True') { $null = Invoke-RecKeysAnswer 'own' }
    else { Write-RigLog '  !! no resume dialog'; $script:M3Fail = $true }
    $null = Invoke-RecPhase 'own-resume-result' -WaitSec 900
    Save-RecShot 'own-4-end'
    Receive-RecGuest 'owner' (Join-Path $M3.evidence 'guest')
}

# The live snapshot m3-recover-base: rig-base + payload + fixture rec, agent running. Rebuilt when missing, on
# -Rebuild, or when the payload hash recorded for it (vm\runs\m3-recover-base.json, beside the rig lock) is not this run's.
function Initialize-RecBase([string]$Hash) {
    $note = Join-Path $script:RunsDir "$RecBase.json"
    $info = Invoke-VBox @('snapshot', $M3Vm, 'showvminfo', $RecBase)
    if ($info.code -eq 0) {
        $was = $(if (Test-Path -LiteralPath $note) { try { "$((Get-Content -LiteralPath $note -Raw | ConvertFrom-Json).payload)" } catch { '' } } else { '' })
        $same = ($was -eq $Hash)
        if ($same -and -not $RC.rebuild) { Write-RigLog "snapshot $RecBase exists for payload $Hash; kept"; return }
        $null = Invoke-VBox @('controlvm', $M3Vm, 'poweroff')
        $null = Wait-VmState @('poweroff', 'aborted', 'saved') 120
        $null = Invoke-VBox @('snapshot', $M3Vm, 'restore', 'rig-base')
        $r = Invoke-VBox @('snapshot', $M3Vm, 'delete', $RecBase)
        if ($r.code -ne 0) { throw "snapshot delete $RecBase failed: $($r.out -join ' ')" }
        Write-RigLog "  deleted the old $RecBase$(if (-not $same) { ' (other payload)' })"
    }
    Write-RigLog "build snapshot $RecBase (payload $Hash)"
    Restore-Base -Snapshot 'rig-base' -No3D
    Initialize-RecGuest
    $null = Invoke-RecPhase 'fixture' -Fix 'rec'
    $null = Invoke-RecPhase 'flush'
    $desc = "M3 m3-recover base: rig-base + payload + fixture PurgeRigRec, live, agent running. payload=$Hash. Built by vm\rig-m3-recover.ps1."
    $r = Invoke-VBox @('snapshot', $M3Vm, 'take', $RecBase, '--live', '--description', $desc)
    if ($r.code -ne 0) { throw "snapshot take $RecBase failed: $($r.out -join ' ')" }
    [IO.File]::WriteAllText($note, (ConvertTo-Json ([ordered]@{ snapshot = $RecBase; payload = $Hash; taken = (Get-Date).ToString('o') })), (New-Object System.Text.UTF8Encoding($false)))
    Write-RigLog "snapshot $RecBase taken"
}

function Invoke-RecRound([int]$K, [string]$After, [bool]$Ui) {
    $name = Get-RecRoundName $K $After
    Write-RigLog "round $name"
    $round = [ordered]@{ name = $name; k = $K; after = $After; t = (Get-Date).ToString('o'); arm = $null; boot = $null; class = $null; ui = $null; dialog = $null; keys = $null; result = $null; error = $null }
    try {
        Restore-Base -Snapshot $RecBase -No3D
        $round.arm = Invoke-RecPhase 'crash-arm' "$K" -WaitSec 900
        if ((Get-RecField $round.arm 'state') -ne 'suspended') { $round.error = "not suspended at step ${K}: $($round.arm)"; return }
        Save-RecShot "$name-0-suspended" $name
        Invoke-HardPowerCycle -AgentTimeoutSec 900
        $round.boot = Invoke-RecPhase 'after-boot' "$K" -WaitSec 600
        $round.class = Get-RecField $round.boot 'class'
        switch ($round.class) {
            'pending' {
                $via = $(if ($Ui) { 'ui' } else { 'client' })
                if ($Ui) {
                    $round.ui = Invoke-RecPhase 'ui-check' "$K" -WaitSec 300
                    Save-RecShot "$name-1-banner" $name
                }
                $round.dialog = Invoke-RecPhase 'recover-start' "$K-$After" -Via $via -WaitSec 300
                if ((Get-RecField $round.dialog 'found') -eq 'True') { $round.keys = Invoke-RecKeysAnswer $name $name }
                else { $round.error = 'no recover dialog'; Save-RecShot "$name-2-no-dialog" $name }
                $round.result = Invoke-RecPhase 'recover-result' "$K-$After" -WaitSec 900
                Save-RecShot "$name-4-end" $name
            }
            'unindexed' { $round.result = Invoke-RecPhase 'bookkeeping' "$K" -WaitSec 600 }
            default { }
        }
    } catch { $round.error = $_.Exception.Message; Write-RigLog "  !! round ${name}: $($round.error)" }
    finally {
        try { if ((Get-VmState) -eq 'running') { Receive-RecGuest $name (Join-Path $M3.evidence "rounds\$name\guest") } } catch { Write-RigLog "  !! pull ${name}: $($_.Exception.Message)" }
        $round.t_end = (Get-Date).ToString('o')
        [void]$script:RecRounds.Add($round)
        if ($round.error) { $script:M3Fail = $true }
    }
}

function Invoke-RecRecover {
    $ui = (-not $RC.no_ui) -and (Test-Path -LiteralPath (Join-Path $(if ($M3.ui) { $M3.ui } else { Join-Path $script:RepoRoot 'target\ui-publish' }) 'Purge.exe') -PathType Leaf)
    if (-not $ui -and -not $RC.no_ui) { Write-RigLog '  !! no UI publish folder: recovery goes through the rig client and the scorer fails the UI rows (pass -UiPublish, or -NoUi to say so)' }
    $files = @($(if ($M3.engine) { $M3.engine } else { Join-Path $script:RepoRoot 'target\release\purge-engine.exe' }), $(if ($M3.broker) { $M3.broker } else { Join-Path $script:RepoRoot 'target\release\purge-broker.exe' })) +
             @($RecGuestScripts | ForEach-Object { Join-Path $script:RigDir "guest\$_" })
    if ($ui) { $files += (Join-Path $(if ($M3.ui) { $M3.ui } else { Join-Path $script:RepoRoot 'target\ui-publish' }) 'Purge.exe') }
    $hash = Get-RecPayloadHash $files
    Initialize-RecBase $hash
    # Calibration: one run, not cut; its journal is the list of steps.
    Restore-Base -Snapshot $RecBase -No3D
    $cal = Invoke-RecPhase 'crash-arm' '0' -WaitSec 900
    Receive-RecGuest 'cal' (Join-Path $M3.evidence 'rounds\cal\guest')
    $n = [int](Get-RecField $cal 'lines')
    $steps = Get-RecStepList $n $RC.steps
    $afters = Get-RecAfters $RC.after
    Write-RigLog "calibration: N=$n lines; steps $($steps -join ','); afters $($afters -join ',')"
    $script:RecPlan = [ordered]@{ n = $n; steps = $steps; afters = $afters; ui = $ui; payload = $hash; subset = [bool]@($RC.steps).Count }
    foreach ($k in $steps) { foreach ($a in $afters) { Invoke-RecRound $k $a $ui } }
}

function Invoke-RecExtras {
    Restore-Base -Snapshot 'rig-base' -No3D
    Initialize-RecGuest
    $npp = $(if ($RC.npp) { $RC.npp } else { Join-Path $script:CacheDir 'npp.exe' })
    if (Test-Path -LiteralPath $npp -PathType Leaf) {
        $r = Invoke-Guest @('copyto', $npp, 'C:\cr\inst\npp.exe')
        Write-RigLog "  pushed the cached Notepad++ installer $npp (exit $($r.code))"
    } else { Write-RigLog "  !! no cached Notepad++ installer at $npp (official download into the rig cache first); the allow_irreversible rows fail" }
    foreach ($f in 'rm', 'sr1', 'sr2', 'sr3', 'sr4') { $null = Invoke-RecPhase 'fixture' -Fix $f }
    $null = Invoke-RecPhase 'npp-install' -WaitSec 600
    $null = Invoke-RecPhase 'irrev' -WaitSec 1500
    Save-RecShot 'x1-irrev-end'
    $null = Invoke-RecPhase 'rm-exec' -WaitSec 900
    Save-RecShot 'x2-rm-executed'
    $rt = Invoke-RecPhase 'rm-retry' -WaitSec 900
    $boot = (Invoke-GuestCmd 'powershell.exe -NoProfile -Command "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString(''o'')"' 60).out | Where-Object { "$_" -match '^\d{4}-' } | Select-Object -First 1
    Write-RigLog '  restart of the guest (boot-time moves)'
    $null = Invoke-GuestCmd 'shutdown.exe /r /t 5 /f' 60
    $null = Wait-GuestReboot -BootBefore ("$boot".Trim())
    $null = Invoke-RecPhase 'rm-after-reboot' -WaitSec 300
    foreach ($c in 'off', 'disabled', 'created', 'throttled') { $null = Invoke-RecPhase 'sr' $c -WaitSec 900; Save-RecShot "x3-sr-$c" }
    $null = Invoke-RecPhase 'extras-summary'
    Receive-RecGuest 'extras' (Join-Path $M3.evidence 'guest')
}

function Write-RecSummary([hashtable]$Extra = @{}) {
    $sum = [ordered]@{ schema = 'purge.rig.m3rec.summary/1'; mode = $RC.mode; run = $RC.run; vm = $M3Vm; started = $script:M3Started; ended = (Get-Date).ToString('o')
                       failed_step = $script:M3Fail; shots = $script:RecShots; keys = $script:RecKeys; rounds = $script:RecRounds; plan = $script:RecPlan; lines = $script:M3Lines }
    foreach ($k in $Extra.Keys) { $sum[$k] = $Extra[$k] }
    [IO.File]::WriteAllText((Join-Path $M3.evidence 'summary.json'), (ConvertTo-Json $sum -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
    Write-RigLog "summary: $(Join-Path $M3.evidence 'summary.json')"
}

# ------------------------------------------------------------------------------------------------- main

# Dot-sourced (the self-test): the functions only.
if ($MyInvocation.InvocationName -eq '.') { return }
if (-not $RC.mode) { Write-Host 'usage: rig-m3-recover.ps1 -Mode m3-owner|m3-recover|m3-extras [-Engine ...] [-Broker ...] [-UiPublish ...]'; exit 2 }

$script:RecPlan = $null
$null = Move-M3EvidenceAside $M3.evidence
New-Item -ItemType Directory -Force $M3.evidence | Out-Null
$script:RigLogFile = Join-Path $M3.evidence 'rig-m3-recover.log'
Write-RigLog "rig-m3-recover mode=$($RC.mode) vm=$M3Vm evidence=$($M3.evidence)"
Assert-M3Start
$script:M3Started = (Get-Date).ToString('o')
$code = 0
$extra = @{}
try {
    switch ($RC.mode) {
        'm3-owner' { Invoke-RecOwner }
        'm3-recover' { Invoke-RecRecover }
        'm3-extras' { Invoke-RecExtras }
    }
} catch {
    Write-RigLog "!! $($_.Exception.Message)"
    $code = 1
    $script:M3Fail = $true
    $extra.aborted = $_.Exception.Message
    if ($RC.mode -ne 'm3-recover' -and (Get-VmState) -eq 'running') {
        try { Receive-RecGuest 'partial' (Join-Path $M3.evidence 'guest') } catch { Write-RigLog "  !! partial evidence: $($_.Exception.Message)" }
    }
} finally {
    try { Write-RecSummary $extra } catch { Write-RigLog "  !! summary: $($_.Exception.Message)" }
    try {
        Write-RigLog 'power off and restore rig-base (left off)'
        if ((Get-VmState) -in 'running', 'paused', 'stuck') { $null = Invoke-VBox @('controlvm', $M3Vm, 'poweroff'); $null = Wait-VmState @('poweroff', 'aborted') 120 }
        Start-Sleep -Seconds 3
        $r = Invoke-VBox @('snapshot', $M3Vm, 'restore', 'rig-base')
        if ($r.code -ne 0) { Write-RigLog "  !! restore rig-base: $($r.out -join ' ')" }
    } catch { Write-RigLog "  !! cleanup: $($_.Exception.Message)" }
}
if ($script:M3Fail -and $code -eq 0) { $code = 1 }
Stop-M3 $code "rig-m3-recover done, exit $code"
