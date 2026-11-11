# Purge VM rig (v2)

The rig measures what each test app really leaves behind after its own quiet uninstaller, and scores a
cleaner's leftover plan against that truth. The contract between the parts is `RIG.md` (authoritative).
The plan context is `docs\ENGINE_PLAN.md` §10.2. The v1 scripts behind `docs\COMPARISON.md` are in `v1\`.

| Part | Where it runs | What it does |
|---|---|---|
| `rig.ps1` | host, Windows PowerShell 5.1 | restore snapshot, start VM, wait for agent, push tools, run job, pull outputs |
| `agent.ps1` | guest, elevated, in tester's session | runs every `C:\cr\jobs\*.ps1`, writes `<job>.log` + `<job>.done` |
| `guest\riglib.ps1` | guest (dot-sourced) | Fetch, GitHubAsset, UninstallEntries, MsiProducts, Lists, Snap, WaitTree, LaunchMedium |
| `guest\apps.ps1` | guest (dot-sourced) | the 10 test apps: URL, silent install, ARP match, quiet uninstall, launch exe |
| `guest\run-app.ps1` | guest job (template `__ID__`) | one app run, RIG.md §4 |
| `guest\null-run.ps1` | guest job (template `__RUN__`) | one null run (no install), for the ambient set |
| `guest\setup-base.ps1` | guest job, once | prepares the clean VM before the `rig-base` snapshots |
| `rigtool\` | host build, guest `C:\cr\bin\rigtool.exe` | `snap` in the guest; `ambient`, `truth`, `score`, `convert`, `baseline` on the host |
| `truth\labels\<id>.json`, `truth\deny.json` | host | label rules and deny examples (RIG.md §5, §7) |

Host prerequisites:
- VirtualBox at `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`, VM `Inbound-Win11-Test`, guest user `tester`.
- `$env:VMPWFILE` = a file holding the guest password, either bare or as a line `password=...`. The
  password goes to VBoxManage only through `--passwordfile`; `rig.ps1` never prints it.
- `rigtool.exe` built: `cargo build --release --manifest-path vm\rigtool\Cargo.toml` (static CRT, so it runs on
  clean Windows). `Push-Tools` copies `vm\rigtool\target\release\rigtool.exe`.

## Building rig-base (once)

Start from a **clean** Windows snapshot: none of the test apps, BCU or the clone installed. The VM state
left by the v1 runs is not clean (ENGINE_PLAN L15). The guest needs autologon for `tester` and the guest
additions.

1. In the guest, copy `vm\agent.ps1` to `C:\cr\agent.ps1`. Start it once with `start-agent.cmd`; this asks
   for UAC approval one time.
2. On the host:
   ```powershell
   $env:VMPWFILE = 'C:\secure\vm-pw.txt'
   . .\vm\rig.ps1
   Wait-Agent              # agent.alive visible, admin=True, ping job runs
   Push-Tools              # rigtool.exe -> C:\cr\bin, guest\*.ps1 -> C:\cr\guest
   Invoke-SetupBase        # prints the guest log; must end with "setup-base OK"
   ```
   `setup-base.ps1` creates `C:\cr\{bin,guest,out,inst,jobs,stage}`. It writes `C:\cr\start-agent-direct.cmd`
   and registers the logon task `PurgeRigAgent` (tester, interactive, highest run level, no time limit).
   It sets `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate=1`. It downloads every
   installer from `apps.ps1` into `C:\cr\inst\`, logs size, SHA-256 and Authenticode status, and records
   them in `C:\cr\inst\sources.json`. It fails if autologon is off or a test app is already installed.
3. Take the snapshots. The offline one comes first, so restoring it proves the logon task works:
   ```powershell
   Save-BaseSnapshot -Off                   # ACPI shutdown, then snapshot 'rig-base-off'
   Restore-Base -Snapshot rig-base-off      # boot, autologon, PurgeRigAgent starts the agent (<= 5 min)
   # let post-logon activity settle for ~10 min, then:
   Save-BaseSnapshot                        # live snapshot 'rig-base' (agent running)
   ```

## Running a campaign

```powershell
. .\vm\rig.ps1
Invoke-Campaign -Ids npp,7zip,vscode,git,python,node,vcredist,firefox -Nulls 3
# or: .\vm\rig.ps1 -Ids npp,firefox -Nulls 3   (-Nulls defaults to 0 when run this way)
```

Every run (null1..nullN first, then the apps) does this: `controlvm poweroff`, `snapshot restore rig-base`,
`startvm --type headless`, `Wait-Agent`, `Push-Tools`, `Invoke-Run`, `Pull-Run`. A failed run is logged and
the campaign moves on. Single steps work too: `Restore-Base`, `Invoke-Run -Id firefox`,
`Invoke-Run -Null 2`, `Pull-Run -Run firefox`. A run never mixes files from two runs: before it starts, an
existing `vm\runs\<run>\` is moved to `vm\runs\_old\<run>-<stamp>\`, and `Pull-Run` moves aside any file the
guest no longer has. A campaign marks a run ok only when its `run.json` is from that run and every phase
passed. To reuse a running VM without restoring, pass
`Invoke-Campaign -NoRestore`, but only for debugging, since the runs then contaminate each other.

What a guest run does (RIG.md §4): `lists 0` + `snap 0`, then a silent install. It waits for the installer's
process tree, at most 15 min (`WaitTree`: any process started since the install, except rig processes and
an allow-list of Windows background processes, plus the `Global\_MSIExecute` mutex), then settles 20 s.
Next it launches the main exe once at medium integrity through the one-shot task `PurgeRigLaunch`, runs it
25 s, closes its windows, kills the rest and settles 10 s. Then `lists 1` + `snap 1`. Then the vendor's
quiet uninstall: `msiexec /x {code} /qn` for MSI, `QuietUninstallString` for Burn,
`/VERYSILENT /NORESTART /SUPPRESSMSGBOXES` for Inno, `/S` for NSIS. The uninstall ends when the main ARP
entry is gone and the tree is idle, at most 30 min; NSIS `Au_.exe` relaunches are covered. Then a 30 s
settle, `lists 2` + `snap 2`, and `run.json`. Each phase is wrapped, so a failure is recorded in `run.json`
and later captures still run. Null runs wait 60 s / 0 s / 60 s instead.

Typical durations: a null run takes about 10 min (three snaps plus two minutes of idle). An app run takes
15–40 min. Restoring and waiting for the agent takes 1–5 min.

## Outputs

`vm\runs\<run>\` (copied from the guest's `C:\cr\out\<run>\`):

| File | Content |
|---|---|
| `run.log` | timestamped log of every step |
| `run.json` | `id, tech, url, installer_sha256, sid, main{…}, install{cmd,start,end,exit,timed_out}, launch{done,exe,…}, uninstall{cmd,t0,t1,exit,timed_out,entry_gone}, entries_created, entries_left, phases[]` |
| `lists-<run>-0/1/2.json` | structured lists, RIG.md §3 (plus `errors[]` per capture) |
| `snap-<run>-0/1/2.tsv.gz` | raw filesystem + registry captures, RIG.md §2 |
| `msi-install.log`, `msi-uninstall.log` | verbose MSI logs (MSI apps) |
| `job.log` | the agent's console log of the job |

`vm\runs\campaign-<stamp>.log` and `.json` hold the per-run status of a campaign.

## Truth and scoring (host)

Run `rigtool --help` for the exact flags. The flow (RIG.md §5–§7):

```powershell
$rt = '.\vm\rigtool\target\release\rigtool.exe'
& $rt ambient --null vm\runs\null1 vm\runs\null2 vm\runs\null3 -o vm\truth\ambient.json
& $rt truth --s0 vm\runs\npp\snap-npp-0.tsv.gz --s1 vm\runs\npp\snap-npp-1.tsv.gz --s2 vm\runs\npp\snap-npp-2.tsv.gz `
    --lists0 vm\runs\npp\lists-npp-0.json --lists2 vm\runs\npp\lists-npp-2.json --run vm\runs\npp\run.json `
    --ambient vm\truth\ambient.json --labels vm\truth\labels\npp.json --deny vm\truth\deny.json -o vm\runs\npp\truth.json
# put each tool's plan JSON (purge.plan/0) in vm\runs\<id>\plans\, then:
& $rt score --set vm\runs\npp --set vm\runs\firefox --deny vm\truth\deny.json --md vm\runs\score.md --json vm\runs\score.json
```

Label files (`truth\labels\<id>.json`) use `{ "id", "rules": [ { "label", "match", "why" } ] }`. `label` is one
of `rig`, `ambient`, `kept_owner`, `user_data` or `leftover`. `match` is a case-insensitive regex anchored on
the canonical target string: `P:<path>`, `K:<key>`, `V:<key>|<name>` or `C:<key>|<name>`, with keys as
`HKLM\SOFTWARE\…` and `HKU\<SID>[_Classes]\…`. `deny.json` uses the same rule shape; any offered item that
matches it scores as `danger`. Every rule carries a `why`. Keep rules narrow and add one only with
evidence from a run log or snapshot.

## Notes

- Guest scripts target Windows PowerShell 5.1. Native programs get one verbatim argument string, because
  5.1 does not escape embedded quotes. `ConvertFrom-Json` arrays are unrolled before use.
- `PurgeRigLaunch` is created and deleted inside each app run, also when the launch fails (LaunchMedium
  deletes it before rethrowing, and run-app's `finally` calls Stop-Launch either way). It is not yet in
  RIG.md's §1 rig task list or rigtool's `RIG_TASKS`; it should be added there.
- The agent and the launch task run at task priority 4 (normal). The default 7 would run every job below
  normal.
- `msedge.exe` / `msedgewebview2.exe` and `explorer.exe` are on the WaitTree allow-list, so a run never
  waits on a browser or a shell restart. Their activity shows up as ambient churn.
