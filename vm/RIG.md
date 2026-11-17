# Purge VM rig v2: contract

The rig measures what an app really leaves behind and scores leftover lists against it. This file is the
contract between the rig's parts: `rigtool` (Rust), the guest scripts (PowerShell 5.1, run elevated in the
VM by `agent.ps1`) and the host driver (`rig.ps1`). Implements `docs/ENGINE_PLAN.md` §10.2 (M0 rig fixes 1–10).

Principles:
- **Capture everything raw.** No noise filter at capture time. Filtering happens only in `rigtool truth`
  and `rigtool score`, and every filtered item is still reported with its label.
- **Every app runs from the same clean snapshot** (`rig-base`). Nothing from one app leaks into another.
- **Value granularity.** Registry values are first-class items, so "a value added to a pre-existing key" is
  a leftover, and deleting that key is danger.

## 1. VM and snapshots

- VM `Inbound-Win11-Test`: Windows 11 Enterprise LTSC evaluation 26100, user `tester` (admin, autologon).
- Snapshot `rig-base` (powered off; at autologon the scheduled task `PurgeRigAgent`, `/sc onlogon /it
  /rl highest`, starts the elevated agent). No live snapshot: with 3D acceleration on, VirtualBox hung in
  `livesnapshotting` for over an hour with a 0-byte saved state (2026-11-11). Contents: clean Windows, guest
  additions, Windows Update paused by policy, `C:\cr\agent.ps1`, all test installers in `C:\cr\inst\`.
  `C:\ut` (the original app) and `C:\cr\clone-harness.exe` are present but never run in v2 runs.
- Snapshot `dirty-base` (powered off, child of `rig-base`; ENGINE_PLAN §10.2), built by
  `guest\setup-dirty.ps1`: Thunderbird, NVDA, Steam, Zotero, Python 3.13 + 3.11 (with the Python Launcher),
  Node.js 20, VS Code, VS Build Tools 2022 (MSBuild workload), Sysinternals and ripgrep in `C:\Tools`, and
  13 planted user files inside app roots, AppData and the profile. Not included: Office C2R, the full
  Visual Studio IDE, OneDrive Known Folder Move (needs sign-in) and a Steam library on `D:` (no D: volume).
  The manifest is in `vm\truth\dirty-base.json`, and the captured state in `vm\runs\dirty-base\` (snap0 and
  lists). It is used for the danger gates on a non-clean machine: run an app with
  `Invoke-Campaign -Snapshot dirty-base`.
- Snapshot `m2-base` (powered off, child of `rig-base`; M2 executor tests, built 2026-11-15). It differs from
  `rig-base` only in: a second disk `E:\purge-vm\inbound-m2-data.vdi` (2 GB dynamic VDI, SATA port 1) holding one
  empty NTFS volume `D:` labelled `PURGE-D`; System Restore enabled on C: (shadow storage on C:, max 10 %); and
  the rig-only value `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore`
  `SystemRestorePointCreationFrequency` = 0 (DWORD), so restore points can be created back to back (the product
  never sets it). No restore point exists in the snapshot. Built by `vm\setup-m2-base.ps1` (restore `rig-base`,
  create and attach the disk, boot, agent job `guest\setup-m2.ps1`, then `-Check`, ACPI shutdown, `snapshot take
  m2-base`, restore `rig-base`); `vm\setup-m2-base.ps1 -VerifyOnly` restores it, runs the check, creates a probe
  restore point and discards it. The data disk lies outside the VM folder: `vm/fix-vbox-media.ps1` needs
  `-ExtraDisk E:\purge-vm\inbound-m2-data.vdi` for this VM from now on.
- VM `Purge-CleanPro` (ENGINE_PLAN §10.2 Clean-Pro, `E:\purge-vm`): Windows 11 **Pro** Insider
  10.0.26340.9882 from Microsoft's Insider ISO (`Windows11_InsiderPreview_Client_x64_en-us_26340_9882.iso`,
  image 6), EFI + Secure Boot + TPM 2.0, 4 vCPU, 4 GB, 3D off, user `tester`. Installed with
  `VBoxManage unattended install` (VirtualBox 7.2 template: autologon, `LabConfig` bypass values,
  `PowerdownAfterShutdown`, guest additions). The post-install command sets
  `ConsentPromptBehaviorAdmin=0` so `vm\bootstrap-vm.ps1` can start the agent elevated without a UAC
  click: guestcontrol runs with a filtered (medium) token outside the console session and cannot elevate,
  so the script arms an HKCU `RunOnce` entry (`C:\cr\start-agent-elevated.cmd`, which does
  `Start-Process -Verb RunAs`) and reboots the guest; at autologon the agent starts elevated. The script
  then runs `setup-base` (which also turns Fast Startup and hibernation off), restores the Windows default
  (5), and **ejects the unattended install media**: left attached, the next cold boot of an offline
  snapshot runs Windows Setup again over the restored disk. Snapshots: `rig-base-off` (offline, checked
  by restore + `Wait-Agent`), then `rig-base` (offline) as its child. Use it with
  `. .\vm\rig.ps1 -VmName Purge-CleanPro`. Its null run (kept in `vm\runs\cleanpro-null1\`, so it does
  not replace the LTSC `null1` that `truth/ambient.json` uses) gives the `Professional-26340.9882` baseline. **It matches the host only when the host runs build 26340**: the host
  was on 26300.9974 when it was built, so until the host moves, the engine on the host still has no
  matching baseline (values-only + X-SYSTIDY, ENGINE_PLAN §5.7.1).
  Snapshot `m2-base` on Purge-CleanPro (offline, child of `rig-base`, built 2026-11-16 by
  `vm\setup-m2-base.ps1 -VmName Purge-CleanPro -NoDataDisk`): `rig-base` + System Restore on C: (shadow storage on
  C:, 10 %) + the rig-only `SystemRestorePointCreationFrequency` = 0, as on Inbound, but **no data disk and no D:**
  (`-NoDataDisk`: setup-m2.ps1 skips the D: part and its check). It serves m2-traps and m2-fidelity (and their null
  runs, §11.8); m2-install's D: stage is not supported there. Its own M2 ambient set is
  `truth\m2-ambient-cleanpro.json` (§11.8).
- Rig-owned paths, excluded from truth and baselines (label `rig`): `C:\cr\**`, `C:\ut\**`,
  scheduled tasks `PurgeRigAgent`, `PurgeRigLaunch`, `PurgeRigInstall`, `agentstart`, `elev*`, `crshot*`, `utrun`,
  `PurgeSetup`, and their `TaskCache` entries, `%TEMP%\vmjobs\**`, and the Prefetch files of the rig's own tools
  `C:\Windows\Prefetch\RIGTOOL.EXE-*.pf` and `PURGE-ENGINE.EXE-*.pf` (engine runs, §4a).

## 2. Snapshot format (`rigtool snap`)

One file per capture: `snap-<run>-<phase>.tsv.gz` (gzip, UTF-8, LF). First line is a header:
`#purge-snap 1\t<iso time>\t<computer>\t<edition>\t<build.ubr>`. Then one record per line, fields
separated by TAB. In text fields, `\` `TAB` `LF` `CR` are escaped as `\\` `\t` `\n` `\r`, and NUL as `\0`.

| Rec | Fields | Notes |
|---|---|---|
| `D` | path, attrs (hex), mtime (FILETIME as u64), reparse tag (hex, 0 if none) | directory |
| `F` | path, size, attrs (hex), mtime, reparse tag | file |
| `K` | key, lwt (FILETIME u64), n_values, n_subkeys | registry key |
| `V` | key, name, type (u32), len, hash, preview | registry value; `name` is empty for the default value |

- `hash` = first 16 hex chars of SHA-256 of the raw data bytes.
- `preview`: REG_SZ / REG_EXPAND_SZ: the string; REG_MULTI_SZ: strings joined with `\0` (escaped);
  REG_DWORD / REG_QWORD: decimal; REG_LINK: the target; others: empty. Truncated to 1024 chars.
- Paths are absolute, as Windows returns them (no `\\?\` prefix in output). Reparse points are recorded but
  **never traversed**. Errors (access denied, vanished) are counted in a trailing line
  `#errors\t<n>\t<first 20 paths joined by |>`.
- Registry key names use canonical roots: `HKLM\SOFTWARE\…`, `HKLM\SYSTEM\CurrentControlSet\…`,
  `HKU\<SID>\…`, `HKU\<SID>_Classes\…`, `HKU\.DEFAULT\…`. The 64-bit view is read (`KEY_WOW64_64KEY`);
  `WOW6432Node` appears as an ordinary subkey. Symbolic links (`REG_OPTION_OPEN_LINK`) are recorded as keys
  with their `SymbolicLinkValue`, never followed.

Default roots (`rigtool snap` with no `--root`):

| Registry | Filesystem (recursive unless marked) |
|---|---|
| `HKLM\SOFTWARE` | `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData` |
| `HKLM\SYSTEM\CurrentControlSet` (minus `Enum`, `Control\DeviceClasses`) | `C:\Users` (all profiles, incl. Default and Public) |
| every loaded hive under `HKU` | `C:\Windows\Installer`, `C:\Windows\Prefetch`, `C:\Windows\System32\Tasks`, `C:\Windows\Tasks` |
| | depth 1 (entries directly inside, no recursion): `C:\`, `C:\Windows`, `C:\Windows\System32`, `C:\Windows\SysWOW64`, `C:\Windows\System32\drivers`, `C:\Windows\Fonts` |

`--root <spec>` (repeatable) replaces the defaults; spec is a path or registry key, `@1` suffix = depth 1.
`--no-values` writes only `D/F/K`. Must run elevated to see everything; unelevated it still works and
records access errors.

## 3. Structured lists (`guest\lists.ps1` → `lists-<run>-<phase>.json`)

```json
{ "uninstall": [ {"key","name","version","publisher","sys","parent","uninstall","quiet","loc","icon","msi":"{GUID}|null"} ],
  "msi":       [ {"code","name","version","context"} ],
  "appx":      [ {"full_name","family","install_location","users":[sid],"sparse":bool,"external_location"} ],
  "appx_provisioned": [ {"package_name"} ],
  "tasks":     [ {"path","actions":["exe args"],"enabled"} ],
  "services":  [ {"name","display","image_path","start","type"} ],
  "firewall":  [ {"id","display","program","direction","enabled"} ],
  "certs":     [ {"store","thumbprint","subject"} ],
  "fonts":     [ {"name","file"} ],
  "env":       { "machine_path": [segments], "user_path": [segments] },
  "processes": [ {"pid","name","path","start"} ] }
```

M1b (C-OBJECT, `riglib.ps1`) adds fields; the ones above keep their names. `tasks[]`: `hidden`, `logon_type`
(Principal LogonType name), `has_stored_password` (LogonType `Password` or `InteractiveOrPassword`),
`actions_detail` [ {`kind` exec|com_handler|other, `path`, `arguments`, `working_dir`, `clsid`, `data`} ].
`services[]` (from `HKLM\SYSTEM\CurrentControlSet\Services\<name>`, values as stored): `image_path_raw`,
`service_dll` (Parameters\ServiceDll, else the top-level one), `service_type` (Type), `start_value` (Start),
`object_name`, `depend_on_service` [names], `state`. `firewall[]`: `value_name` (registry value name = id),
`raw` (the rule string as stored), `reg_key` (FirewallRules, AppIso or Configurable store); null when not found.

## 4. Run protocol (one app, `guest\run-app.ps1`, phases written to `C:\cr\out\<run>\`)

`<run>` = `<app id>` for app runs, `null1..null3` for null runs. With `rig.ps1 -RunPrefix <p>` an app run is
named `<p><app id>` (e.g. `r0-vscode`): every output file and `run.json`'s `run` carry the run name, `run.json`'s
`id` stays the app id (the label file and the plan's `app`). Engine runs (§4a) always use a prefix, so the frozen
M0 run directories `vm\runs\<id>\` are never archived or overwritten. Null runs are `null<n>` without a prefix
and `<prefix>null<n>` with one (§4a).

00. **Edge pause** (phase `edge-pause`, first of every job, app and null runs alike; `riglib.ps1`
   `Suspend-EdgeUpdate`): the services `edgeupdate` and `edgeupdatem` are set to Disabled and stopped, every
   `MicrosoftEdgeUpdate*` scheduled task is disabled, and an Edge/WebView2 update already running is waited for
   (max 120 s) and then killed. Disabled services cannot be started on demand (Edge and WebView2 ask them over
   COM) and disabled tasks do not fire, so it holds for the whole job; the next snapshot restore undoes it and
   `rig-base` is unchanged. The EdgeUpdate policy (`HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate`
   `UpdateDefault=0`) is not used: Microsoft documents it as effective only on domain-joined or MDM-enrolled
   devices, which the rig VMs are not. Everything it changes happens before `lists 0` / `snap 0`, so it is part
   of the clean state and never in a diff. `run.json` `edge_pause` records services and tasks before/after, the
   updater processes seen, `versions_before` / `versions_after` (EdgeUpdate `Clients\*` `name pv`); phase
   `edge-check` after `snap 2` adds `versions_end` and `held` (`versions_after` = `versions_end`). Reason: in
   the r0 campaign an Edge update ran inside Git's install window (about 140 Edge/WebView2 items in its truth)
   and once between a lists and an inventory capture (an invdiff failure).
0. Pre-apps (`pre` in `apps.ps1`, e.g. `firefox-tb`: Thunderbird): each is installed exactly as in step 2 and
   settled, and its ARP entry recorded in `run.json` `pre[]`, **before** step 1, so everything of theirs is in
   the clean state and offering any of it scores as danger. With `pre_launch` each is then launched as in
   step 3 (`pre[].launch`), with `pre_uninstall` removed with its vendor uninstaller as in step 5
   (`pre[].uninstall`). Then `plant_pre` (§4b).
1. `lists 0`, `snap 0` (clean, from `rig-base`).
2. Install silently. Record `install_start`, `install_end`, exit code and `ran_as`: `elevated` (the agent's token)
   or, for apps with `install_il = 'medium'` (`vscode-user`, a per-user install), `medium`: the installer is
   started through the one-shot task `PurgeRigInstall` (same interactive, limited token as `PurgeRigLaunch`;
   the task is deleted afterwards, also on failure). Wait for the installer's **process
   tree** to exit (`WaitTree -RootPid`: the installer's PID and every descendant seen while polling, by
   parent PID, so a restored guest's clock jump cannot make System or maintenance processes look new), and
   for Windows Installer to be idle (`Test-MsiBusy`: the `_MSIExecute` mutex), two quiet polls in a row,
   max 15 min, then settle 20 s. On timeout the same tree is killed and `timed_out` is recorded.
3. **Launch once** (if the app defines `launch`): start the main exe at medium integrity through a one-shot
   scheduled task `PurgeRigLaunch` (interactive logon, limited run level, normal priority), wait up to 30 s
   for the exe to appear, run 25 s, close its windows (`CloseMainWindow`), wait 5 s, kill what is left,
   delete the task (also when the launch throws). This creates the user data a real user would have.
   Settle 10 s. Then the `post` apps (installed and launched, `run.json` `post[]`) and `plant_post` (§4b).
4. `lists 1`, `snap 1` (installed footprint).
5. Uninstall with the vendor's own uninstaller, quiet. Record `t0` (start) and `t1` (end). End = the main
   ARP entry is gone **and** the uninstaller's process tree has exited (NSIS relaunches itself from
   `%TEMP%\Au_.exe`, Burn and msiexec spawn children) **and** MSI is idle, max 30 min. If everything is idle
   but the entry is still there for 180 s, the wait gives up (`entry_gone` false, not a timeout). Settle 30 s.
6. `lists 2`, `snap 2`.
7. Write `run.json`: `{id, tech, url, installer_sha256, main {key,name,version,…}, install {start,end,exit},
   launch {done, exe}, uninstall {cmd, t0, t1, exit, timed_out}, entries_created, entries_left}`.

Null runs follow the same steps with no install, launch or uninstall, and the same waits (`-NullWaitSec`,
default 60 s, for install and for uninstall; 0 s launch), so their diff is pure Windows churn.

Host side (`rig.ps1`): power off → `snapshot restore rig-base` → start → wait for the agent → copy fresh
`rigtool.exe`, `purge-engine.exe` (when given with `-Engine` or built at `target\release\`) with
`kb\baselines\*.tsv.gz` (to `C:\cr\bin\kb\baselines\`; none with `-NoBaselines`), `guest\*.ps1`, and the run's
installer and plant files that the host cache `vm\cache\inst` holds (with its manifest `cache-sources.json`:
official URL, version, size, SHA-256 per file; to `C:\cr\inst\`) → run the job → copy `C:\cr\out\<run>\` to
`vm\runs\<run>\` → next app. The guest uses a cached file only when its SHA-256 matches the manifest; anything
else is downloaded from the official URL in the guest, every run (rig-base already holds the M0 installers).
`run.json` records `installer_sha256`, `installer_sig`, `installer_source` (`host cache`, `rig-base`,
`download`) and, for manifest files, `installer_version` (same fields in `pre[]`, `post[]`, `upgrade`).

## 4a. Engine mode (M1a R0, ENGINE_PLAN §10.2, §11.1)

`Invoke-Campaign -Ids ... -RunPrefix r0- -Engine <purge-engine.exe>` (or `Invoke-Run -Id <id> -RunPrefix r0-
-Engine` after `Push-Tools -Engine`) sets the job's `__ENGINE__` placeholder. The run protocol is §4 with these
changes, each engine call its own phase (command line, exit code, stdout/stderr in `run.log`, a record in
`run.json` `engine.calls[]`; a failed engine phase is recorded and the captures still run):

| After | Phase | Command (CLI contract ENGINE_PLAN §3.4) |
|---|---|---|
| `lists 1` (before `snap 1`) | `engine-inventory-1` | `purge-engine inventory --json > inv-1.json`; the `program_id` of the main ARP entry is the entry whose `key_path` is `run.json` `main.key` (compared canonically) |
| `snap 1` | `engine-harvest` | `purge-engine harvest <program_id> -o fp.json` |
| | `engine-scan-live` (`-ExtraChecks` only) | `purge-engine scan --fp fp.json --mode external --app <id> -o plan-live.json`, the still-installed app (§4b) |
| | `uninstall` | `purge-engine uninstall <program_id> --quiet --fp fp.json -o engine-run.json` **instead of** the vendor command; `run.json` `uninstall.t0/t1/exit` come from `engine-run.json` (`t_start`, `t_end`, `exit_code`; `uninstall.times` = `engine`, or `rig` when the file is missing), plus `outcome`, `verify_gone`, `engine_exit`, `rig_t0`/`rig_t1`. The rig's WaitTree (engine process tree, ARP entry gone, max 10 min) and the 30 s settle still run as a safety net. |
| `lists 2` (before `snap 2`) | `engine-inventory-2` | `purge-engine inventory --json > inv-2.json` |
| `snap 2`, `edge-check`, `entries` | `engine-scan` | `purge-engine scan --fp fp.json --mode post --app <id> -o plan-purge.json` (`--app`: the plan's `app` is the truth id, ENGINE_PLAN P40) |
| | `engine-scan-repeat` (`-ExtraChecks` only) | the same scan again `-o plan-purge-b.json` (§4b) |

**Capture order rule.** Each inventory runs right after the `lists` capture of the same point, so `invdiff`
compares two views of the same moment (in r0 an Edge update fell between `lists 2` and the old
`engine-inventory-2` after `snap 2`). This is safe for the snapshots: `inventory` only reads the Uninstall keys
and the MSI API and writes stdout to `C:\cr\out` (excluded); its one machine-side trace is its Prefetch file,
which is labelled `rig` (`items.rs`: `PURGE-ENGINE.EXE-*.pf`). The post scan stays after `snap 2` and
`entries`: it reads the whole machine, and its plan is meant to describe the post-uninstall state that `snap 2`
captured. `harvest` and the scans write only their `-o` files (and a scan its `.scan.json` sidecar) in the run
dir.
The host copies `plan-purge.json` to `vm\runs\<run>\plans\purge.json` and the frozen BCU plan
`vm\truth\frozen\<id>\plans\bcu.json` (when there is one) next to it. `vm\truth\m1a.sh` then recomputes truth
for the `r0-*` runs with the app's label file, compares it with the frozen truth, scores Purge and BCU, and
runs `rigtool invdiff` on `inv-1`/`inv-2` against `lists-1`/`lists-2`.

Campaign options (`Invoke-Campaign`, also `rig.ps1` script parameters): `-Nulls <n>` null runs; with `-RunPrefix`
they are named `<prefix>null<n>` (e.g. `r0-null1`), so the M0 `null1..3` behind `truth\ambient.json` are never
touched. `-NullOrder first` (default: nulls, then apps) or `spread` (nulls first, between the apps and last, so
the ambient set covers the same stretch of guest time). `-NullWaitSec <s>` (default 60, 0..3600) is the null
runs' idle time per wait. The gate rerun uses `-Nulls 3 -NullOrder spread -NullWaitSec 120`.

Guest waits: `WaitTree -Preexisting` takes the process identity set (PID + start time) captured **before** the
installer/uninstaller/app was started; those processes never count as part of the tree, so PID reuse cannot
pull a pre-existing process into it. For Inno Setup apps `run-app.ps1` copies `unins*.dat` from the install
location at the snap1 point to `inno-unins*.dat` in the run dir and lists them in `run.json` `inno_logs`
(parser fixtures, gate step 7).

`truth/m1a.sh` (from `vm\`, `bash truth/m1a.sh [--accept-sanity-diff]`): builds the ambient set from this
campaign's null runs (`truth/ambient-r0.json`; `M1A_AMBIENT` overrides), adds
`truth/labels/_os-servicing.json` (Windows servicing/telemetry families, `ambient`, M1a only; `M1A_SERVICING=0`
leaves it out) as a second `--labels` file, writes `truth/m1a-sanity.md`, `m1a-score.{md,json}`,
`m1a-frozen-<id>.{md,json}`, `m1a-invdiff.md` and `m1a-status.json`. `M1A_APPS` sets the apps (default the six
gate apps; add `7zip` for MSI coverage). Exit codes: 0 ok; 1 an invdiff phase did not exit 0 (gate E);
2 missing input (an app run, fewer than 2 null runs, or null runs more than 12 h from the app runs);
3 stopped before scoring because the sanity check against the frozen truth left a residual beyond random
names. `--accept-sanity-diff` (or `M1A_ACCEPT_SANITY_DIFF=1`) scores past it only when every residual item is
classified in `<out>/m1a-sanity-classified.json` (`M1A_SANITY_CLASSIFIED`; schema
`purge.rig.m1a-sanity-classified/1`: per item `app`, `side`, `key`, `class`, `evidence`); an unclassified item
still stops with exit 3, and the status file records the classification file used (2026-11-15: the gate run's
11 differences had been accepted by the wrapper script without anyone looking).

`M1A_SANITY=skip` leaves out the sanity step and the frozen cross-check. It is for campaigns the frozen M0 truth
(Inbound, clean `rig-base`) does not describe: dirty-base, Clean-Pro and no-baseline runs. Such campaigns
usually have no null runs of their own either; `M1A_AMBIENT=truth/f0/ambient-f0.json` gives them a reviewed
ambient set and `M1A_M0_RUNS=runs/_none` switches the M0 lookup off.

`mk_labels.py` (step 1 of `m1a.sh`) rewrites every label file with LF line endings. On a checkout with CRLF the
files then show as changed although nothing in them is: save `truth/labels/*.json` before a scoring run and put
back the files whose content is equal apart from line endings (the Linux campaign score scripts in
`tools/linux/campaigns/` do this; on Windows it is done by hand).

Scoring on Windows (Git Bash, from `vm\`), the short live check of 2026-11-15 as the example:

```
M1A_PREFIX=r3- M1A_APPS="firefox firefox-tb ff-esr" M1A_AMBIENT=truth/f0/ambient-f0.json \
M1A_M0_RUNS=runs/_none M1A_SANITY=skip M1A_OUT=truth/r3 RIGTOOL=rigtool/target/release/rigtool.exe \
bash truth/m1a.sh
```

M1a corpus additions (`apps.ps1`): `vscode-user` (VS Code per-user build, installed at medium integrity),
`thunderbird`, and `firefox-tb` (the `firefox` definition with `pre = thunderbird`).

## 4b. Extended M1a runs (x0-, x0-nb-, f0-, f0d-)

Goal: cases where a plan offers, above all preselects, something the removed app does not own. Variants are
`apps.ps1` records (`Copy-AppDef` of a base app) with these optional fields; their label file is
`vm\truth\labels\<variant>.json` (generated by `mk_labels.py` VARIANTS: `_os.json` + the base app's file + the
variant's rules).

| Field | Effect in `run-app.ps1` |
|---|---|
| `pre_launch` | each pre-app is launched once after its install (`pre-launch-<id>`), so its profile and first-run registrations are in `snap 0` |
| `pre_uninstall` | each pre-app is then removed with its vendor uninstaller (`pre-uninstall-<id>`; reinstall after uninstall) |
| `plant_pre` | function of `guest\x0-plants.ps1` run after the pre-apps, before `arp0` (phase `plant-pre`) |
| `plant_post` | function run after the launch and the post-apps, before `lists 1` (phase `plant-post`) |
| `post` | ids installed and launched after the main launch (`post-<id>`; a sibling installed after the app). Their installers are fetched in `setup`. `detect` has already run, so the main entry is unaffected; the sibling's ARP entry is new in `lists-2` and becomes a `kept_owner` anchor |
| `upgrade_from` | id installed first in the `install` phase (after `snap 0`; `run.json` `upgrade`), then the main installer over it |
| `plant_files` | files of the host cache a plant function unpacks (`npp-portable.zip`, `ripgrep.zip`, `vscode-archive.zip`) |

Environment variables in `install` are expanded in the guest (`git-toolsdir`: `/DIR="%USERPROFILE%\Tools"`).
Every plant write (file, dir, key, value, shortcut, PATH segment, launch) is recorded in `run.json` `planted[]`
as `{phase, kind, target, note}`; `target` is the canonical truth string (`P:`/`K:`/`V:`), user-hive writes go
to `HKU\<sid>` (the job is elevated as the interactive user). Plant zips are SHA-256 checked against the cache
manifest (`run.json` `plant_files[]`).

**Extra checks** (`-ExtraChecks`, engine runs only; `__EXTRA__` = 1): `engine-scan-live` (M-LIVE: a scan of the
still-installed app; pass = no item Safe, none preselected, the `FS-INSTALLDIR` item absent or Blocked) and
`engine-scan-repeat` (M-DET: pass = the two scans' `plan_hash` from the `.scan.json` sidecars are equal, else
the file SHA-256). `run.json` `extra` = `{live_items, live_safe, live_preselected, live_root_band, det_equal,
det_how, plan_a, plan_b}`. `plan-live.json` and `plan-purge-b.json` stay in the run dir and are **not** copied to
`plans\` (there `rigtool score --set` would score them as offers on the post-uninstall state); `truth/m1a.sh`
checks them into `$OUT/m1a-extra.md`.

**No baselines** (`-NoBaselines`, engine runs only): `Push-Tools` deletes the guest's
`C:\cr\bin\kb\baselines\*.tsv.gz` and copies none, so the engine has no (edition, build) baseline and runs
values-only, as on most users' machines. `run.json` `engine.baselines` lists what the engine could see.

**Scoring an extra campaign** (`bash truth/m1a.sh` from `vm\`): set `M1A_PREFIX`, `M1A_APPS`, and
`M1A_AMBIENT=truth/ambient-r0.json` (x0 runs have no null runs; the Edge pause happens before `snap 0`, so the
r0 ambient set stays valid), `M1A_M0_RUNS=runs/_none` (no frozen-truth cross-check for variants). `M1A_OUT`
defaults to `truth/<prefix without the dash>` for any prefix other than `r0-`, so the gate files in `truth\`
are never overwritten; reporting classes (§7) are on by default there (`M1A_CLASSES`). A variant without a
label file stops with exit 2. Sibling footprint (M-FP): `bash truth/footprint.sh x0-ff-tbafter x0-thunderbird
[out]` scores the plan again with `--s0` / `--lists0` = the solo sibling run's `snap 1` / `lists-1` and writes
`fp-<run>-diff.md` (offered items that exist on a machine with only the sibling installed).

## 5. Truth (`rigtool truth`)

Input: `snap-0`, `snap-1`, `snap-2`, `lists-0..2`, `run.json`, the ambient set, and the app's label rules
`vm\truth\labels\<id>.json`. Output `vm\runs\<id>\truth.json`.

**Microsoft Store self-updates** (built-in rule, 2026-11-15). A non-sparse package under
`C:\Program Files\WindowsApps` published by Microsoft (publisher id `8wekyb3d8bbwe`) whose full name is in exactly
one of `lists-0` and `lists-2` updated itself during the run (Photos, VCLibs and OneDrive.Photos did inside 9 of
the 16 extended runs on Clean-Pro). `leftover` and `user_data` items that name such a package's full name or
family are relabelled `ambient`, with the rule text "Microsoft Store self-update of <family>". No installer of
the corpus deploys such a package; the apps' own packages are sparse. Not covered: the Store's other registry
churn on Clean-Pro (about 550 rows per run), which still inflates the truth sets there.

Item kinds (the **Target**, same names as `purge-model`):
- `Path {path}`: file or dir in snap2, absent in snap0. Top-most only (a new dir implies its content).
- `RegKey {path}`: key in snap2, absent in snap0. Top-most only.
- `RegValue {path, name}`: value in snap2, absent in snap0, whose key existed in snap0.
- `RegValueChanged {path, name, before, after}`: value present in both with a different hash
  (e.g. PATH). Kept separate: removing it is never right, only an edit is.

Every item gets exactly one label (first matching rule wins, in this order):

| Label | Meaning | Rule source |
|---|---|---|
| `rig` | Rig's own files, keys, tasks | built in (§1) |
| `ambient` | Windows churn | the ambient set (§6), then `ambient` rules in the label file |
| `kept_owner` | Belongs to a product still installed after the uninstall (an ARP entry created by the install and still present in `lists-2`, e.g. Python Launcher), or another app that was never removed | label rules; the run's `entries_left` |
| `user_data` | Leftover that holds user data (profiles, backups, saves) | label rules |
| `leftover` | Everything else: the app's real leftovers | default |

`truth.json`: `{ id, run, counts {label → n}, items: [ {target, label, rule, size?, lwt?} ] }`.
`leftover` + `user_data` are the recall denominator. `kept_owner` and anything existing in snap0 are the
danger set.

Label rule file: `{ "id": "python", "include": ["_os.json"], "rules": [ { "label": "kept_owner", "match": "<regex on the
canonical target string>", "why": "Python Launcher MSI still installed" } ] }`. Canonical target string:
`P:<path>`, `K:<key>`, `V:<key>|<name>`, `C:<key>|<name>`; matched case-insensitively.
`include` lists other label files (relative paths) whose rules are loaded first. Every app file includes
`_os.json`: OS side effects that any install, launch or uninstall triggers and no tool can attribute
(certificate stores, CryptnetUrlCache, MUI/UFH/CloudStore/Start counters, Defender and Search state,
Restart Manager, `PendingFileRenameOperations`, AppX deployment counters…). Its rules are `ambient` and
therefore run before every per-app rule, so each one is anchored under a Windows-owned root.
`_os.json` and the generated per-app rules come from `vm\truth\mk_labels.py` (rules it adds carry
`"gen": true`); `bash truth/recompute.sh` regenerates them, recomputes every truth and re-scores. The
frozen M0 numbers are in `vm\truth\FROZEN.md`. Corpus variants get a file that includes `_os.json` and the base
app's file (`vscode-user.json` → `vscode.json`, `firefox-tb.json` → `firefox.json`), also written by
`mk_labels.py`; rules of their own are hand-written below the include. `bash truth/m1a.sh` does the same for the
M1a engine runs (§4a).

**User-data split.** `derive` collapses a new subtree to its top-most item. When that top is labelled
`leftover` and a `user_data` rule matches a path below it (a user file planted inside a new install root,
§4b), the top is split at those paths: the matching descendants become `user_data` items and the rest of the
subtree stays `leftover` item by item (the same split as at `kept_owner` boundaries). A top labelled
`user_data` itself is not split.

Two optional rule fields:
- `"split": true` (ambient rules only): the rule labels a **container** Windows creates, not what is in it.
  `derive` collapses a new subtree to its top-most key or dir; when a split rule labels that top, its new
  values and direct child keys/dirs become items of their own and go through the rule chain again
  (recursively while a child is itself a split container). Used for `Classes\PackagedCom` (+ `Package`,
  `ClassIndex`) and `Explorer\FeatureUsage` (+ its subkeys): the containers are ambient, the package
  entries and AUMID values inside belong to the app.
- `"first": true`: checked right after the rig rules, before the ambient set and every ambient rule. For
  an attributable exception under an ambient root: the app's own Prefetch files (FS-PREFETCH) and jump
  lists whose AppID hash resolves to the app (FS-JUMPLISTS; CRC-64 of the upper-cased UTF-16LE AppID).

Built-in rule (after `first`): a `RegValueChanged` list value (`;` on either side, preview not cut) whose
segments are the same before and after, compared case-insensitively without empty segments or a trailing
`\`, is `ambient` (e.g. PATH where the uninstaller removed its segment and only a `;` differs).

Label order: `rig` → `first` rules → built-in list rule → ambient set → ambient rules → kept_owner rules →
`entries_left` → user_data rules → leftover rules → default `leftover`.

`--deny` is checked after labelling: a `leftover` that matches deny is reported as a warning (it can only
be removed through an API, e.g. a package's rows through Remove-AppxPackage).

## 6. Ambient set (`rigtool ambient`)

Union of `diff(snap-0, snap-2)` over the null runs, as canonical target strings, plus generalized patterns:
a GUID, a hex run of 16+ chars, or a number of 6+ digits in a path segment becomes a wildcard, so churn
with random names still matches. Output `vm\truth\ambient.json`: `{ runs: [...], exact: [...], patterns:
[...] }`. The scorer prints how many truth items each run's ambient set removed.

## 7. Plan JSON (what a cleaner offers) and scoring (`rigtool score`)

```json
{ "schema": "purge.plan/0", "app": "firefox", "tool": "purge|clone|ut|bcu", "mode": "post|external|forced",
  "items": [ { "target": {"type":"RegKey","path":"HKLM\\SOFTWARE\\Mozilla"}, "band":"Safe|Likely|Weak|Blocked",
               "preselected": true, "scanner": "REG-SOFTWARE", "category": "Registration" } ] }
```

Target types: `Path`, `RegKey`, `RegValue {path,name}`, `RegMultiSzSegment {path,name,segment}`,
`Service {name}`, `Task {path}`, `FirewallRule {id}`, `AppxPackage {full_name}`.

Matching an offered item `o` against a truth item `t` (paths compared case-insensitively after
canonicalisation: `HKEY_LOCAL_MACHINE`→`HKLM`, `HKCU`→`HKU\<run's user SID>`, `HKCR`→`HKLM\SOFTWARE\Classes`,
trailing `\` removed):
- **covers** `t`: `o` equals `t`, or `o` is an ancestor of `t` (a key or dir containing it).
- **partial**: `o` is a descendant of `t`.
- A `RegMultiSzSegment` covers a `RegValueChanged` on the same value when the segment was added.

Per offered item, exactly one outcome. An offered item absent from snap2 (inside the captured area) is
`gone` before anything else: deleting it is a no-op, so it can neither be `danger` nor a `hit`. This
matters for plans recorded on another run (the old UT/BCU "removed" lists include what the vendor
uninstaller also removed).
Otherwise, in this order:
- `danger`: `o` existed in snap0 (per kind: a `Path`/`RegKey` that existed; a `RegValue` whose value
  existed; a `RegMultiSzSegment` whose segment was already in the value), or `o` covers a `kept_owner` item,
  or `o` lies inside a `kept_owner` item, or `o` matches `vm\truth\deny.json` (e.g. `Notepad.lnk`, the
  package stores). An `AppxPackage` offer skips the deny check: it goes through the package API.
- `hit`: covers or is partial to at least one `leftover`/`user_data` item.
- `ambient`: matches only ambient items.
- `other`: none of the above.

Delete-if-empty items (plan `action` `RemoveDirIfEmpty`/delete-if-empty): after the per-item pass, deepest
first, such an item is scored like a delete only when nothing would be left inside it once the plan's other
non-gone, non-danger removals ran. Otherwise its outcome is `noop_if_nonempty`: no coverage, outside precision,
listed in its own section of the score with `would_be_danger` (counted as `noop_danger`) when a plain delete
of it would have scored `danger`.

Existence is three-valued: present, absent, or unknown (a value under a depth-1 registry root, or a
segment of a preview cut at the capture limit). Unknown is never `gone`. `Service`, `Task`, `FirewallRule`
and `AppxPackage` offers have no snapshot record of their own (a sparse package has no readable WindowsApps
path); with `lists-<run>-0.json` (`score --set` loads it, `--lists0` in single-plan mode) an offer whose
service name, task path, firewall rule id or package full name is in `lists-0` is `danger` ("existed in
lists-0"), even if it is gone in `lists-2`.

**Danger counts** (2026-11-15, after the dirty-base and extended reviews). A `danger` item is counted by what
the plan does with it:
- `danger`: offered for removal (any band but Blocked);
- `danger_kept`: listed read-only as Blocked (the engine shows it as kept for another owner);
- `danger_listed`: both (the number reported as "danger" before this date);
- `danger_blocking`: Safe or preselected. This is the gate criterion, on a clean and on a dirty base.

**An earlier install of the same app in snap 0** (reinstall and upgrade runs, whose `pre[]` installs the app
itself first). With `score --set`, the scorer picks a reference run of the same campaign without that pre-step
(restored from the same snapshot). An offered item that exists in this run's snap 0, is absent from the
reference's snap 0 and was last written at or after the earlier install started (less two minutes) is the
app's own leftover of the first install: it is not `danger` ("excused", listed with the reference run's name
in the score). `lists-0` objects are excused the same way, without the time test.

**Reporting classes** (`score --classes`; on by default for extra campaigns in `m1a.sh`): every `danger` item
and every offer that covers a `user_data` item gets a class, and the score lists each class separately (never
hidden, only labelled): `danger_blocking` / `userdata_blocking` (Safe or preselected: gate-blocking),
`danger_unticked` / `userdata_unticked` (listed Likely/Weak, not preselected: reported), and three danger
sub-classes reported in their own lists: `preexisting_value_ref` (a value that existed in snap 0 with the same
data, created by the user or another product, whose data path dangles after the uninstall),
`old_empty_ext_key` (a `Classes\.<ext>` key, or its `OpenWithProgids`/`OpenWithList`, that existed empty in
snap 0) and `replaced_value` (a value that existed in snap 0 and whose data changed by snap 2: the slot now
holds the app's record, e.g. a shortcut-history slot Windows reused; unticked it is reported, Safe or
preselected it is blocking like any other). `userdata_safe` counts Safe items covering `user_data`,
preselected or not.

**Package coverage.** An `AppxPackage {full_name}` offer covers every truth item whose canonical string
contains the full name or the family name (`Name_PublisherId`), an `AppContainer\Mappings\S-1-15-2-*` key
whose `Moniker` is the family, and a `PackagedCom\ClassIndex\{CLSID}` key that has the full name as a child.

Metrics per (app, tool), then macro-averaged per tool over apps:
`truth_n`, `recall_listed` (covered by any band), `recall_visible` (Safe ∪ Likely), `recall_safe`,
`partial_n`, `precision_safe` (Safe items that are hits ÷ Safe items that are not `gone`),
`danger`, `danger_kept`, `danger_listed`, `danger_blocking`, `danger_preselected`, `userdata_preselected`,
**Recall rule:** only offered items whose outcome is not `danger` earn coverage (the `*_nd` columns of
`rigtool score`; these are the gated numbers). Coverage from a danger item is still shown in the plain
`recall_*` columns for comparison with how the old tools behaved.
 plus per-kind (Path / RegKey / RegValue)
recall and the lists of missed truth and danger items. Output JSON and a Markdown table.

Old tools (`rigtool convert`): clone `*-clone-uninstall.json` (`leftovers[].path`, preselected if
`checked`), UT and BCU `*-removed.json` (everything they removed counts as offered and preselected, band
Safe). Strings starting with `HKEY_`/`HK` become `RegKey`, others `Path`.

## 8. Baselines (`rigtool baseline`)

From `rig-base`'s `snap-0` minus `rig` items: the keys, value names and paths of clean Windows, for the
engine's "present on clean Windows" check. Written to `kb\baselines\<EditionID>-<build>.<ubr>.tsv.gz`,
`K`/`V`(key, name, type, hash)/`D`/`F`(path) records only.

## 9. Running the rig from Linux (CachyOS host, 2026-11-14)

The same repository (Windows `C:` mounted at `/mnt/C`) and the same two VMs (on `E:`, mounted at `/mnt/E`) are
used from Linux. Nothing in the guest changes; the guest still gets the Windows `rigtool.exe` and
`purge-engine.exe` built on Windows.

- **pwsh**: PowerShell 7.7.0 from Microsoft's GitHub release tarball, unpacked to `~/.local/opt/powershell/7.7.0`,
  linked as `~/.local/bin/pwsh` (on `PATH`). `rig.ps1` detects the host (`$script:OnWindows`; Windows PowerShell 5.1
  and pwsh on Windows behave as before) and on Linux uses `VBoxManage` from `PATH` (`$VBOXMANAGE` overrides),
  `/`-separated host paths, and `$RIG_TMP` (else `$TMPDIR`, else `/tmp`) instead of `%TEMP%` for job files. A
  temporary password copy (only for a `password=...` file) is created mode 0600.
- **VirtualBox**: 7.2.22 (`/usr/bin/VBoxManage`, user in `vboxusers`). Both VMs are registered from their
  folders: `VBoxManage registervm /mnt/E/inbound-vm/Inbound-Win11-Test/Inbound-Win11-Test.vbox` and
  `VBoxManage registervm /mnt/E/purge-vm/Purge-CleanPro/Purge-CleanPro.vbox`. The snapshots' `<NVRAM path=...>`
  were written by Windows with `\` (`Snapshots\<stamp>.nvram`); Linux VirtualBox does not resolve that, so a
  restore silently dropped the EFI/TPM NVRAM (fresh NVRAM: Secure Boot off). They were changed to `/`, which
  both hosts read. Once a Linux VirtualBox has written the file its header says `1.19-linux` and the audio
  driver `ALSA` (with `useDefault="true"`, so each host picks its own); Windows VirtualBox 7.2.20+ reads it.
  The pre-Linux settings files are in `<vmdir>/_vbox-backup-20261114/`. Power the VMs off before booting Windows;
  Windows VirtualBox still lists them under their `E:\` paths.
- **A VM shows as `<inaccessible>` after the other host used it** ("Could not find an open hard disk with UUID
  ..."). VirtualBox keeps the VM's disk tree in the host's own global `VirtualBox.xml`, not in the `.vbox`, and
  every snapshot restore makes a new current-state disk. So after one host ran a campaign, the other host's
  registry names a disk that is gone. Repair, with the VM powered off:
  `pwsh -NoProfile -File vm/fix-vbox-media.ps1 -Vbox <path to the .vbox>` (`-Print` only shows the block). It
  reads the VDI headers and writes the tree of the disks in use into the `.vbox`; VirtualBox reads it on the
  next access and moves it to its global file when it next saves the VM. A copy of the `.vbox` is kept beside
  it. Used on Windows on 2026-11-15 for Inbound (by hand, then the script was written from it and checked with
  `-Print`); not yet run on Linux, where Inbound will need it at the next switch.
- **VirtualBox with the KVM backend (since 2026-11-14 02:45).** The stock `virtualbox` package (VT-x through
  `vboxdrv`) cannot run beside a KVM guest: in a deliberate test (02:27, Android emulator running) the kernel logged
  `kvm_intel: vmread failed` / `vmwrite failed` one second after `startvm`, and the emulator's `qemu-system-x86`
  died with SIGSEGV. The host now runs `virtualbox-kvm` 20261021-1 (VirtualBox 7.2.22 + Cyberus Technology's KVM
  backend, AUR PKGBUILD built locally in `~/purge-target/vbox-kvm-build/aur`, with `VBOX_WITH_EXTPACK_VBOXDTRACE :=`
  because the DTrace lexer does not build with flex 2.6.10). It has no kernel module: VBox.log shows
  `HM: HMR3Init: Attempting fall back to NEM: Driverless mode` and the `NEM: KVM capabilities` list, i.e. KVM is used
  with the **default** execution engine; no `-ExecutionEngine` is needed. `/usr/bin/VBoxManage` (VBox.sh) warns
  "vboxdrv kernel module is not loaded" on every call; harmless, and `rig.ps1` calls
  `/usr/lib/virtualbox/VBoxManage` directly on Linux. Checked with the emulator running (same PID, adb answering every
  15 s, no kvm_intel errors): snapshot restore with NVRAM intact, TPM 2.0 present in both guests, Secure Boot as before
  (Inbound 0, as on Windows; CleanPro 1), both rig VMs and the emulator at the same time (about 4 GB free left).
  The smoke `lx1t-npp-userfiles` gave the same plan (`plan_hash` 18ddd212234f), score, extra checks and invdiff as
  `lx0t-` on the stock hypervisor, with the run 0.86x as long (270 s vs 315 s, job 274 s vs 317 s). One cold boot
  stalled for about 3.5 min (agent ready after 233 s instead of about 17 s; one `split_lock trap` from `EMT-0` in the
  kernel log); the next boots took 17 s and 33 s. Upstream asks for split-lock detection off (`split_lock_detect=off`
  on the kernel command line, or the `split_lock_mitigate` sysctl, which is already 0 here).
  Back to stock: `sudo pacman -Rdd virtualbox-kvm && sudo pacman -S virtualbox virtualbox-host-dkms && sudo modprobe
  vboxdrv`; then do not run the rig VMs beside a KVM guest.
- **Execution engine** (`rig.ps1 -ExecutionEngine <name>` or env `RIG_VM_EXECUTION_ENGINE`, Windows and Linux;
  default empty = leave the VM as it is): after each restore, with the VM powered off, the rig runs `VBoxManage modifyvm
  <vm> --vm-execution-engine <name>`. The setting is a machine attribute (`executionEngine` on `<Machine>`), not
  part of any snapshot, so a restore does not revert it. With the stock build `native-api` fails at `startvm`
  (`VERR_NEM_NOT_AVAILABLE`); with the KVM build `default` already uses KVM. Both VMs are set to `default`.
- **Host scoring** (`truth/m1a.sh`, `truth/footprint.sh`) needs a Linux `rigtool`. Build it outside the
  repository (it never goes to the guest):
  `cd vm/rigtool && CARGO_TARGET_DIR=$HOME/.cache/purge-rigtool-target cargo build --release --locked`, then pass
  `RIGTOOL=$HOME/.cache/purge-rigtool-target/release/rigtool`. `python` is the system Python 3. `mk_labels.py` (run by `m1a.sh`) rewrites `truth/labels/*.json` with LF on Linux
  (CRLF on Windows): same content, no `git diff`.

Campaign (from the repository root, same parameters as on Windows):

```bash
export VMPWFILE=/path/to/vmpw.txt                # bare guest password; never printed
export RIG_TMP=$HOME/.cache/purge-rig-tmp; mkdir -p "$RIG_TMP"
cd /mnt/C/Users/kaank/Desktop/uninstall/purge
# Inbound-Win11-Test (default VM); smoke: one app, extra checks
pwsh -NoProfile -File vm/rig.ps1 -VmName Inbound-Win11-Test -Snapshot rig-base -Ids npp-userfiles -Nulls 0 \
     -RunPrefix lx0t- -ExtraChecks -Engine ./target/release/purge-engine.exe
# Purge-CleanPro
pwsh -NoProfile -File vm/rig.ps1 -VmName Purge-CleanPro -Snapshot rig-base -Ids <ids> -Nulls 3 \
     -RunPrefix <p>- -Engine ./target/release/purge-engine.exe
```

Or interactively: `pwsh`, then `. ./vm/rig.ps1 -VmName Inbound-Win11-Test` and `Invoke-Campaign ...` (its own
default is `-Nulls 3`; pass `-Nulls 0` for none). Scoring a variant campaign without null runs (§4b), from `vm/`:

```bash
cd vm
RIGTOOL=$HOME/.cache/purge-rigtool-target/release/rigtool M1A_PREFIX=lx0t- M1A_APPS=npp-userfiles \
  M1A_AMBIENT=truth/ambient-r0.json M1A_M0_RUNS=runs/_none M1A_BCU=0 bash truth/m1a.sh --accept-sanity-diff
```

The C: and E: NTFS volumes are mounted by the kernel `ntfs` driver (fstab, `rw`, `errors=continue`). After the
unclean Windows shutdown of 2026-11-13 the kernel reported index/stale-reference errors on C: ("Run chkdsk"):
run `chkdsk C: /f` from Windows before long campaigns write there.

**Inbound guest freezes with 3D on (`-No3D`, 2026-11-14).** Inbound-Win11-Test has 3D acceleration on (its
`pre-installers` snapshot is "clean-off + 3D on"); Purge-CleanPro has it off. On this host VMSVGA 3D runs through
DXVK/Vulkan on the NVIDIA GPU, and cold boots of Inbound `rig-base` often hung the guest about 10 s after VM start,
right after logon (`VMMDev: vmmDevHeartbeatFlatlinedTimer: Guest seems to be unresponsive`, guest clock stopped,
VBoxHeadless busy, guestcontrol "Error starting guest session (current status is: starting)"). Sometimes it
recovered after 80-135 s (`GuestHeartBeat: Guest is alive (gone 134 ... ns)`), often not at all. With 3D on, 4 of 5
recorded boots stalled (3 never recovered). With `modifyvm --accelerate-3d off` after the restore, 5 of 5 had no
heartbeat loss and the agent answered after 10-20 s, at host load 7-24. Host split-lock warnings
(`x86/split lock detection: #AC: EMT-0/... took a split_lock trap`) showed up both with and without the freeze, so
they are not the cause (`kernel.split_lock_mitigate` is 0, so the guest is not throttled).

`-No3D` (rig.ps1, `Restore-Base` and `Invoke-Campaign`, or `RIG_VM_NO_3D=1`) runs `modifyvm --accelerate-3d off`
after each restore of an offline snapshot. The snapshot keeps 3D on, so the next restore brings it back; snapshots
are not changed. It is off by default, and it is ignored for a live (saved-state) snapshot. The Inbound campaign
scripts pass it. The guest just uses the WDDM driver without 3D; the rig needs no 3D.

## 10. win-unit: workspace tests on real Windows (`vm/win-unit.sh`, 2026-11-14)

What it is for: the Rust test binaries are cross-built on the Linux host (cargo-xwin, x86_64-pc-windows-msvc,
LLD) and normally run under wine, where the live-API tests fail by design (the KNOWN list of
`~/purge-target/ci-linux.sh`). win-unit runs the same binaries in a rig VM, so live Win32, registry links/ACLs,
junctions, locked files and later the M2 executor are judged by Windows itself. It does not touch the campaign
path (Invoke-Campaign, guest run-app/null-run, scoring); `vm/win-unit.ps1` dot-sources rig.ps1 for the VM helpers
and carries its own guest runner (nothing new under vm\guest).

Steps: (1) bundle: `cargo xwin test --no-run --message-format=json` (workspace, or `-p` lists, once per
`--features` set) into a target dir outside the repo; the test executables go to `<out>/bundle/bin.tgz` with
`manifest.json` (crate, target, kind, features, sha256, working dir). (2) lock: the per-VM flock
`~/purge-target/campaigns/.lock-<VM>` of the campaign scripts, then VM idle, no rig.ps1 for the VM, MemAvailable
>= 6 GiB. (3) restore the snapshot (default Inbound-Win11-Test `rig-base`), push the bundle to `C:\cr\wu` (unpacked by the elevated agent), pass
`p1-user`: every binary as the rig user through guestcontrol (UAC-filtered token, medium integrity, recorded),
`--test-threads=4`, per-binary timeout; optional pass `p2-elevated` through the elevated rig agent (default
`--include-ignored`, minus the tests whose #[ignore] says "needs ..." (PURGE_RUNS_DIR, PURGE_INNO_FIXTURES: data
not in the guest, without which they return early), listed as skipped). (4) pull the libtest
output, power off, restore the snapshot again. (5) report: per binary passed/failed/ignored, the failing tests, and
the wine comparison (a KNOWN wine failure that passes = confirmed; any Windows failure = finding). Exit 0 only
when no test failed and no binary crashed or timed out; 2 = refused (lock held, VM busy, low memory, build).

Fixtures: binaries read files through `env!("CARGO_MANIFEST_DIR")`, baked in as `/mnt/C/.../purge/<crate>`. On
Windows a path starting with `/` is rooted on the current drive, so the bundle mirrors what tests read (each
package's `tests/`, `kb/`, `vm/truth/deny.json`, `vm/runs/npp/lists-npp-2.json`) at `C:\mnt\C\...\purge\` and
runs each binary with its mirrored package dir as working directory, like cargo. A missing file makes its test
fail (the reads unwrap); nothing passes silently. A tree built elsewhere mirrors to its own path the same way.

    export VMPWFILE=<guest password file>
    bash vm/win-unit.sh                                    # whole workspace, Inbound-Win11-Test rig-base
    bash vm/win-unit.sh --name m2-exec -p purge-win -p purge-exec --features write \
         --features fault-inject,test-support --vm Purge-CleanPro --elevated
    bash vm/win-unit.sh --bundle-only --name b1            # build only; later: --bundle ~/purge-target/win-unit/b1/bundle

Results: `~/purge-target/win-unit/<name>/` (`report.md`, `report.json`, `guest/<pass>/<binary>.txt` = libtest
output, `console.log`, `bundle/`). Options: `bash vm/win-unit.sh --help`.

The agent wait is 900 s (`win-unit.ps1 -AgentTimeoutSec`): both rig-base snapshots are offline (cold boot +
autologon), which can take minutes on a loaded host. First proof (2026-11-14, Purge-CleanPro): 25 binaries, 959
passed / 0 failed unelevated (Medium) and 961 / 0 elevated with --include-ignored, all 10 KNOWN wine failures pass;
124 s from lock to snapshot restored.

## 11. M2 executor runs (`rig.ps1 -Mode m2-*`, docs/M2_DESIGN.json gate G0-G6)

Five modes, each one run from a fresh restore of `m2-base` (§1; `-Snapshot` overrides, e.g. `rig-base` for the
G6 "System Protection off" leg). Clean-Pro has its own `m2-base` without D: (§1; m2-traps and m2-fidelity only):
`.\vm\rig.ps1 -VmName Purge-CleanPro -Mode m2-traps -RunPrefix cp-`. `rig-base` alone does not serve m2-fidelity:
its G6 legs need System Restore on with the frequency value 0. Only file, registry and AppX items are
executed in v1; service, scheduled-task and firewall items are planned but deferred, so wherever a trap or
fixture plants one, the expected outcome is "untouched" (fidelity rows `DeleteService`, `DeleteTask`,
`DeleteFirewallRule` with ops 0; the gate fails if one has ops).

    $env:VMPWFILE = '<guest password file>'
    .\vm\rig.ps1 -Mode m2-install
    .\vm\rig.ps1 -Mode m2-traps
    .\vm\rig.ps1 -Mode m2-fidelity -Apps npp,firefox
    .\vm\rig.ps1 -Mode m2-crash -HardPowerOff [-FaultPoints act.after,intent.flushed] [-BatchSize 10]
    .\vm\rig.ps1 -Mode m2-reboot
    bash truth/m2.sh                       # from vm/: results/m2-gate.json + .md
    # the M2 ambient set (§11.8), once per m2-base: 6 null runs of m2-traps and m2-fidelity -> truth\m2-ambient.json
    . .\vm\rig.ps1; Invoke-M2NullCampaign -Count 6 -Engine <rig-exec purge-engine.exe>

`$env:RIG_RIGTOOL` names the rigtool.exe to push when it is not built in `vm\rigtool\target\release` (e.g. a
`CARGO_TARGET_DIR` on another drive). `-AppBands Safe,Likely` narrows the m2-fidelity app selection (§11.3).

Run names are `<RunPrefix><mode>` (`m2-traps`, or `g1-m2-traps` with `-RunPrefix g1-`); outputs go to
`vm\runs\<run>\` as usual (Pull-Run, Test-RunResult), plus `job-<n>-<stage>.log` per guest job and
`vm\runs\m2-<run>-<stamp>.log/.json` for the host side.

### 11.1 Engine and pushed files

- The engine is the `rig-exec` build (fault injection, `PURGE_FAULT_AT` / `PURGE_FAULT_PAUSE`, the expiry clock
  override), built into its own target dir: `cargo build --release -p purge-engine --features rig-exec` with
  `CARGO_TARGET_DIR=target\rig-exec`. `-Engine` defaults to `target\rig-exec\release\purge-engine.exe`;
  `target\release\purge-engine.exe` (the release engine the M1a modes push) is refused, so an M2 run can never
  replace or use it. The guest copy lands in `C:\cr\bin\purge-engine.exe` of the restored snapshot only.
- Push: Push-Tools (rigtool, engine, baselines, `vm\guest\*.ps1`) and Push-M2Install (`install\install.ps1` ->
  `C:\cr\install\install.ps1`). Every M2 job first runs install.ps1 with `-Engine C:\cr\bin\purge-engine.exe`; the
  engine calls then use `C:\Program Files\Purge\purge-engine.exe` when it is there (riglib Get-M2EngineExe).
- Guard rails in rig.ps1: Assert-RigVm (only `Inbound-Win11-Test` and `Purge-CleanPro`), run and stage names
  `[a-z0-9][a-z0-9_.-]*`, the password only through `$env:VMPWFILE` / `--passwordfile` (never logged).

### 11.2 Jobs, stages and the reboot-in-job mechanism

A guest script is a template: `rig.ps1 New-M2JobText` replaces `__RUN__`, `__MODE__`, `__STAGE__` and `__OPTS__`
(base64 of UTF-8 JSON; `mode`, `snapshot`, and per mode `batch`, `hard_poweroff`, `points`, `app`, `app_run`).
An unreplaced or unknown value exits 2 before riglib is loaded. `exec-run.ps1` serves m2-install, m2-traps and
m2-fidelity; `m2-crash.ps1` and `m2-reboot.ps1` their modes.

A stage that needs a reboot ends with riglib `Request-RigContinuation`: it writes `C:\cr\out\<run>\continue.json`
(`purge.rig.continue/1`: `seq`, `kind` reboot | poweroff, `next` stage, `data`, `boot_before` = LastBootUpTime UTC)
and, for `reboot`, schedules `shutdown /r /t 45` so the job can finish. The host (Invoke-M2Job), after each job:
reads the marker with `copyfrom`; none = run complete. `reboot`: Wait-GuestReboot polls the guest's boot time
until it differs from `boot_before`, then Wait-Agent. `poweroff` (only with `-HardPowerOff`, else an error):
Invoke-HardPowerCycle = `VBoxManage controlvm <vm> poweroff`, wait for poweroff/aborted, `startvm --type headless`,
Wait-Agent. Then the same script is submitted with `__STAGE__ = next`. The next stage reopens run.json (Open-M2Run
appends to `stages` and `phases`; only stage `start` clears the run dir) and archives the marker as
`continue-<seq>.json` with `boot_after`. A marker whose `seq` the host has seen already stops the loop (a stage
that did not take its marker), as do more than 60 continuations.

`Invoke-SnapshotJob -Run <name> -Mode <mode> [-Template <script>] [-Opts @{...}] [-Snapshot ...] [-After {...}]`
is the generic entry: Move-RunToOld, Restore-Base, Push-Tools + Push-M2Install, the stage loop, an optional
`-After` block (more jobs in the same VM session), Pull-Run, job logs, Test-RunResult. Invoke-M2Mode (the
`-Mode` footer) wraps it with the per-mode options and timeouts.

### 11.3 Modes, phases, outputs

All runs write `run.json` (`purge.rig.m2/1`: `stages`, `phases`, `engine.calls` with each command line, env,
exit and stderr tail, `results`) and `run.log`. Common files: `targets-<tag>.json` (the merged
`purge.rig.targets/0` handed to `plan from-targets`), `plan-<tag>.json` + `.scan.json`, `select-<tag>.json`,
`report-<tag>.json`, `exec-<tag>.out`, `undo-<tag>.json`, `sess-<tag>-*` (copies of the session's files),
`snap-<run>-<tag>.tsv.gz`, `deep-<tag>-{a,b,c}.json`, `execdiff-<tag>.json`, `fidelity-<tag>.json`,
`<tag>-index.json` / `<tag>-sessions.zip` / `<tag>-quarantine.json` (the store, Save-M2Store).

- **m2-install** (G0, one stage): edge-pause, traps-pre (`m2-traps.ps1 -Stage pre-install`: the attacker's
  pre-created `C:\ProgramData\Purge`), d-precreate (medium IL: `D:\.purge-q` with a marker file; the step waits for
  the marker, at most 30 s, not for the short-lived cmd.exe process), install
  (install.ps1, re-run, `-Check`: `install.json`, `install-rerun.json`, `install-check.txt`), traps-build,
  traps-check-after-install, d-exec (a payload on `D:` quarantined), store. d-exec expects (`results.d_volume`):
  `exec_exit` 0, `payload_gone`, the user's `D:\.purge-q` renamed aside to `D:\.purge-q.rejected-<utc>` still
  holding `user-marker.txt` (`renamed_aside`, `user_marker_intact`; `adopted` false) and the payload at
  `payload_in_queue` = `D:\.purge-q\<session>\000001\payload.txt`. This needs engine ceb5999 or later: `D:\` is
  owned by NETWORK SERVICE after Format-Volume, and an older engine did not accept that owner for a volume root and
  skipped the item (G0 then fails on the D: part).

Per-item rows of the execdiff reports carry `detail`, the journal `done` record's optional free text for a skipped
item (engine ceb5999 on; absent with older engines).
- **m2-traps** (G1, G5, one stage): edge-pause, traps-pre, install, traps-build, traps-check-after-install,
  plan-main (group `main`), refusals (wrong `--confirm`, a sidecar with one path changed, the targets planned in
  reverse order with the main confirm; scoped snaps before/after must not differ: `refuse-diff.json`), snap-a,
  deep-a, exec-main, snap-b, deep-b, execdiff-main (`--traps m2-traps-manifest.json --group main`, deep A/B),
  traps-check-after-exec, undo-main (every item but the expiry trap's), deep-c, fidelity-main, expiry
  (plant-expiry-junction: the junction and the file symlink replace the quarantined item's two own files, so the
  item holds no more entries than the engine counted at the move and the purge reaches the walk; an item that
  gained entries is refused before any walk, `Refused MoreEntriesThanCounted`, exit 10, which the gate run of
  2026-11-16 met while the plant still added the links; `quarantine expiring` with the clock override env,
  `quarantine purge --ids` of the entries naming the expiry item: `expiring.json`, `expiry-*` store), traps-check-after-expiry, race-a / race-b
  (each its own plan, exec with the manifest's `helper.env` PURGE_FAULT_PAUSE and the swap helper in the
  background, scoped snaps, deep, `execdiff-race-*.json`), forged-fp (`scan --fp <user-store fp> --mode post`
  -> `plan-forged.json`; no canary path Safe or preselected), traps-check-final, store.
- **m2-fidelity** (G2, G6; stages `start`, then `app` per real app): install, fixtures-build, plan-main, snap/deep
  A, exec-main, snap/deep B, execdiff-main, fixtures-check-after-exec, undo-main, deep-c, fidelity-main,
  fixtures-check-after-undo, store-main; partial (fresh fixtures, undo `--items` of the first half,
  `fidelity-partial.json`), undo-conflict (a deleted value recreated with other data before the undo; `kept` and
  `reported`), backup-tamper (one byte of the first intent's backup file flipped; `fidelity-tamper.json`),
  restore-point (G6: rp1 with `--restore-point always` under m2-base's `SystemRestorePointCreationFrequency` 0 must
  be Created; then the rig sets the value to `rp_frequency` minutes, default 1440 = Windows' default, and rp2 must
  report Throttled; the engine never touches the value), restore-point-off (G6 "System Protection off": protection
  on C: disabled, an exec with `--restore-point always` must report the restore point Disabled and still execute
  the plan, per docs\M2_DESIGN.json "never blocks the batch on failure"; undone, protection enabled again:
  `results.restore_point_off`). Per app (`-Apps`, default npp, firefox): the M1a engine run `<run>-<id>` (run-app.ps1
  installs, uninstalls, scans), then stage `app`: its `plan-purge.json` with every item the plan offers for removal
  selected (bands `app_bands`, default Safe, Likely and Weak, preselected or not; Blocked never), so real leftovers
  go through exec and undo even when the scan ticks nothing; snap/deep A, exec, snap B, execdiff, undo, deep C,
  fidelity (`*-app-<id>.*`). A plan with no such item is recorded as skipped. 7-Zip (until 2026-11-16 the
  second default app) is always skipped: its MSI writes no InstallLocation and no DisplayIcon, so the engine's
  harvest finds no root and no exe (`0 roots, 0 exes`) and the post scan offers nothing, though the uninstall
  leaves `HKU\<sid>\Software\7-Zip` (the frozen M1a score has purge recall 0/3 for 7zip). Firefox (NSIS, official
  download, frozen M1a: 20 items offered) replaced it.
- **null runs** (`-Null`, m2-traps / m2-fidelity, stage `start` only; §11.8): the mode's phases up to snap A /
  deep A, then `null-wait` (opts `null_wait`, default 3 s, where exec would run), snap B, deep B, store; no exec,
  undo, execdiff, refusals or app stage, no ambient set pushed.
- **m2-crash** (G3; stages `start`, `matrix`..., `after-poweroff`...): `journal fault-points` (`fault-points.out`);
  iterations = every exec-phase point x {resume, rollback} + every undo-phase point (undo.intent,
  undo.act.after, regrestore.mid, index.write) x resume; `-BatchSize` per job (default 10), then a reboot
  continuation. Iteration: fresh fixtures in `C:\cr\work\<run>\<tag>`, plan, deep A, scoped snap A; exec (or exec
  then undo) with `PURGE_FAULT_AT=<point>`; a crash is exit 0xC0000409; `journal recover` twice with deep after
  each (the second must change nothing); `journal resume --session` (then scoped snap B, execdiff, undo) or
  `journal rollback --session`; deep C, fidelity A/C, fixtures check. `crash-<tag>.json` per iteration, all in
  `crash-matrix.json` (`purge.rig.crashmatrix/1`). A point the plan never reaches is `hit: false` (recorded, not
  failed). Two points have their own rows (since 2026-11-16; before, both were never hit): `expiry.mid` (phase
  `expiry`, one row): exec of `nested-dirs.dir` alone, `quarantine expiring` with the clock override, scoped snap X,
  `quarantine purge --ids` with `PURGE_FAULT_AT=expiry.mid:2`; passes when it crashed with part of the item left,
  recover twice changes nothing, `expiring` lists the item `unfinished`, a second purge ends `Purged` without a
  second expire record, the item is gone and nothing outside `C:\ProgramData\Purge` was removed or changed between
  snap X and snap Y (`diff-<tag>-xy.json`). `bootmove.registered` (x {resume, rollback}): `file-ads.file` alone, its
  file held by the locker (no FILE_SHARE_DELETE), exec with the fault; passes when the pair is in PFRO after the
  crash, recover twice changes nothing, resume reports `PendingReboot` with `confirmed: true` (pair still there once)
  and undo before any reboot exits 0, or rollback exits 0; PFRO as before, fidelity A/C and the fixtures check pass.
  No execdiff for these rows (a move waiting for a boot). `-HardPowerOff`: for intent.flushed, regdelete.mid, commit.before an exec is started detached with
  `PURGE_FAULT_PAUSE=<point>:600000`; once its journal is stable for 6 s the stage asks for a `poweroff`
  continuation; `after-poweroff` checks the boot id changed, recovers twice, resumes, undoes, fidelity. Three
  rig rules keep a power cut from testing the rig instead of the engine (gate run 2026-11-16): the paused exec is
  started by shell execute, without handle inheritance (inheriting the job's output pipe kept the agent waiting
  for the engine, which sleeps 600 s at every hit, so the job never ended); right before it starts, riglib
  `Save-RigDurableState` flushes volume C: and the registry hives the fixtures live in (the cut otherwise lost
  fixture keys created seconds earlier); before each `controlvm poweroff` the host's `Sync-GuestRunFiles` flushes
  the files of `C:\cr\out\<run>` and `C:\cr\work\<run>` (the continuation marker read back as NULs after the
  boot otherwise). The start stage also sets the boot entry to `bootstatuspolicy IgnoreAllFailures` and
  `recoveryenabled No` (`Set-RigBootPolicyIgnoreFailures`): two cuts within a minute of boot otherwise stop the
  guest in WinRE. The scoped snaps of a power-off round take `Session Manager\Environment` instead of the whole
  Session Manager key (`Get-M2SnapRoots -BootStable`: Windows rewrites its Executive, kernel\RNG, Memory
  Management and Power subkeys at every boot) and the row compares PendingFileRenameOperations itself
  (`pfro_unchanged`, part of its pass). After the exec starts the rig flushes no registry hive and no file of the engine's store; the
  run-file flush commits the NTFS log, though, so file-system metadata (the engine's renames) up to the cut is
  durable in these rounds, while registry changes since the last lazy flush can be lost. Last, torn
  journals (`crash-torn.json`): after an act.after crash the journal's last record cut in half (recover must
  accept it, rollback, fidelity) and, separately, one byte of a middle record changed (recover must refuse and
  change nothing).
- **m2-reboot** (G4; stages `start`, `after-reboot`, `after-mismatch`): PFRO before (`pfro-before.json`);
  scenario U: both locked items held (locker without FILE_SHARE_DELETE), exec, PFRO must gain exactly the admin
  file's pair and never the user-writable one, undo before any reboot -> PFRO as before; scenario R: locked
  again, deep A, exec, PFRO check, reboot. after-reboot: recover twice, `journal show`, PFRO back to before,
  admin file gone; undo, deep C, fidelity; retry: plant-boot-junction, the user-writable item executed again ->
  Skipped (ReparseMismatch / ChangedSinceScan), traps check; scenario M: admin file locked, exec, the engine's PFRO
  pair replaced by a decoy pair (the boot move does not happen), reboot. after-mismatch: recover twice, `journal
  show`, admin file still in place and unchanged, undo, fidelity, PFRO, final traps check. The traps are built with
  `-RebootSafe`: `ph\cloud-tag.txt` carries the OFFLINE placeholder attribute instead of the cloud reparse tag
  0x9000101A, which does not survive a reboot without a sync root (the file reads as ERROR_FILE_CORRUPT 1392
  afterwards and every deep A/C comparison over the manifest scope fails though the file is outside the plan). The
  other modes keep the reparse tag.

Trap expectations settled by the smoke run (2026-11-16): `odd-names.*` (`name.`, `name `, `dir.`) expect
`Skipped/GateBlocked/DenyListed` (engine rule `canon.trailing-dot-or-space`): refusing a name Win32 would normalise
onto a sibling is the safe direction for M2. Fixture after-undo check: a directory a RemoveDirIfEmpty item removed
is recreated by undo with a new FileId by design, so `file_id` is not compared for it (every other field is).
(Until the gate run of 2026-11-16 the after-undo check reused the list-value variable for its per-field diff and
always reported `list values bad=1`, ok false, with no mismatch listed.)

### 11.4 Engine command lines (M2-CLI)

    plan from-targets <targets.json> -o <plan.json>                  (sidecar <plan>.scan.json: plan_hash, items[].id)
    exec --plan <plan.json> --confirm <h> --select <ids.json> [--restore-point always] -o <report.json>
    undo --session <id> [--items <ids.json>] -o <undo.json>
    journal fault-points | journal recover | journal resume --session <id> | journal rollback --session <id>
    journal show --session <id>
    quarantine expiring | quarantine purge --ids <id>... --yes-irreversible
    scan --fp <fp.json> --mode post --app purgetrapapp -o <plan.json>   (forged fingerprint, m2-traps)

`<h>` = SHA-256 (lower-case hex) of the UTF-8 text `lower(plan_hash) + selection_hash`, `selection_hash` = SHA-256 of
the selected ids, de-duplicated, sorted ordinally, joined with LF (riglib Get-M2Confirm). `--select` / `--items`
files are JSON arrays of candidate ids. The session is `report.session`, else the new directory under
`C:\ProgramData\Purge\sessions`; its `journal.jsonl` and `report.json` are read from there.

M1b system objects (services, tasks, firewall rules): `plan from-targets` makes no object plan (its candidates
carry no object digest, so `exec` skips them "no object fingerprint"), and `exec --fp` needs a fingerprint that is
the owner of every selected object and records each in `sys` with the plan's digest; its install roots pass the
guard's root rule or are dropped. A rig mode with objects (`m1b-x-crash`, M1B-RIG-EXEC) therefore drives harvest
and scan, never `plan from-targets` (M1b reviews R3b M9, S3).

### 11.5 Gate report (`truth/m2.sh`)

`bash truth/m2.sh` (env `M2_RUNS`, `M2_PREFIX`, `M2_OUT`, `PYTHON`) reads the five runs and writes
`results/m2-gate.json` (`purge.rig.m2gate/1`) and `m2-gate.md`: `inputs` (per run: present, finished, stages,
failed phases), `missing`, `g0_install`, `g1_traps` (guard_escapes, collateral, per-group execdiff, refusals,
forged fp, trap checks), `g2_fidelity` (rows of the fixture run, required rows missing, deferred rows touched,
collateral, partial undo, undo conflict, backup tamper, apps), `g3_crash` (rows, hit, failing, not_hit,
recover idempotence, power-off, torn), `g4_reboot` (undo before reboot, exec PFRO, reconcile, retry, mismatch),
`g5_expiry`, `g6_restore_point` (rp1 Created, rp2 Throttled, protection-off leg Disabled with items done and
protection re-enabled; exec exit 0 or 10 with a report, the fixture items being G2's), `g7_elevated_tests`
(§11.9), `totals` and `pass`. Exit 0
pass, 1 a gate fails, 2 a run is missing.

### 11.6 Self-test

`vm\guest\tests\rig-selftest.ps1` runs every mode end to end on the host: Invoke-M2Mode with the VM calls faked,
each guest job run in a child powershell.exe against the stub `purge-engine.cmd` (verbs plan, exec, undo,
journal, quarantine; `PURGE_FAULT_AT` -> exit 0xC0000409) and fakes for rigtool, the locker, PFRO, the boot id and
every system change; the continuation loop (reboot, power-off, a marker not taken) included. With
`RIG_SELFTEST_M2_OUT=<dir>` the stub runs are copied there for a dry run of `truth/m2.sh`.

### 11.7 Not settled by the design (the rig's reading, as M2-CLI implements it)

The confirm byte encoding above; `--select` as the full selection; `plan from-targets` keeping the rig's target
ids as candidate ids (in the document's order, origin ManualUser, band Safe, preselected; an optional `category`
per target, e.g. `UserData`); the session id and where report/journal live; the `journal fault-points` output
(one point per line, `<name>` TAB `<description>`); `quarantine purge --ids a b ...` and the ids (`<session>/<op>`)
coming from `quarantine expiring` (entries matched by the item path, `original_path`); a user-data item is
purged only when `--confirm-user-data <id>...` names it too; the expiry clock override env
(`PURGE_RIG_NOW_OFFSET_DAYS=400`, overridable with opts `expiry_env`; read by rig-exec builds only); a held item
retried with `journal retry-held --session <id>` (elevated; each held item of the finished session moved now
unless still in use, `purge.cli.retried/1` with one `{op, outcome}` per item, exit 10 while one stays held; a
session that waits for recovery is refused with 8); `journal rollback` after a crash inside undo is not run
(undo-phase crashes are resumed, which finishes the interrupted undo itself: the ops in progress and the rest
of its `undo_plan`, so the session ends `Undone` without a second `undo --session`).

`exec` prints the `purge.exec/1` report on stdout (and writes it to `-o`), progress and `session <id> <dir>` on
stderr; `undo` the `purge.undo/1` report. `journal recover` lists the sessions that need recovery
(`purge.cli.recover/1`, a probe per open intent) and changes no session (the store's integrity check, which
every verb runs, may rename a rejected session directory aside); `journal resume` / `rollback` without
`--session` recover every pending session. A new `exec` is refused while a session waits for recovery. Output
files are never written through a link anywhere on the path: each directory is opened by handle below the
previous one, a junction or symbolic link on the path is refused, and the file is renamed into place relative
to the verified directory. There is no `--data-root`: the engine always uses the
installed store. A build without `rig-exec` refuses every one of these verbs with exit code 5 and touches
nothing. Exit codes (also in `purge-engine --help`):

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | not implemented yet |
| 2 | usage error or broken precondition |
| 3 | runtime error |
| 4 | uninstall failed, cancelled or timed out |
| 5 | needs the consent dialog (executor verbs of a normal build) |
| 6 | plan refused: hash, selection, order or confirmation; nothing was done |
| 7 | needs elevation |
| 8 | needs recovery first: an interrupted session is pending (journal recover) |
| 9 | store or journal integrity failure |
| 10 | partial: not every item ended done (the document is still written) |
| 11 | undo ended with conflicts or failures (the document is still written) |
| 12 | session not closed, or its report or index entry not written (the document is still written; takes precedence over 10 and 11, which stderr then names) |

An item "ended done" when it is `Done`, `Vanished` or `Skipped(NoLongerEmpty)` (a remove-if-empty whose object
holds something). So the fixture runs exit 0 and the trap runs exit 10 (deferred and blocked items); the rig
gates neither on 10. A refusal is any exit other than 0 with no report; the engine refuses with 6. Exit 0 of
`exec`, `undo`, `journal resume` / `rollback` and `journal retry-held` also means the session is closed and its
`report.json` and index entry are written; otherwise the exit is 12 (the document is still printed), and
`journal resume` completes the record.

### 11.8 Collateral: the M2 ambient set and the engine's own side effects

`execdiff` compares full-machine snapshots (the default `rigtool snap` roots, §2) taken right before and right after
the exec; every removed (`-`) or changed (`~`) record that no rule authorises is collateral and fails G1 / G2. The
smoke run showed 20 and 120 such records that were Windows churn of the exec window (Defender signatures and
servicing, WMI tracing providers, Explorer, TaskCache, ProfileService, prefetch) plus the engine's Restart Manager
key. Two rules cover them without narrowing the snapshots:

- **engine-rm** (allowed side effect, not ambient): keys and values at or under
  `HKU\<sid>\Software\Microsoft\RestartManager`, which `RmStartSession` writes during the engine's lock query. The
  parent rule then accepts `HKU\<sid>\Software\Microsoft` changing only its LastWriteTime / subkey count.
- **telemetry pause**: every exec-run job (m2-install, m2-traps, m2-fidelity, their null runs) stops the DiagTrack
  service and sets it to Disabled right after the Edge updater pause, before snap A (riglib `Suspend-M2Telemetry`,
  run.json `telemetry_pause`). Its occasional upload rewrote `HKLM\...\Diagnostics\DiagTrack` (LastSuccessful*
  UploadTime) inside an exec window while none of 12 null runs saw it; the source is removed rather than given a
  hand-written ambient entry. The snapshot restore undoes the pause.
- **settle wait** (since 2026-11-16): right before snap A (m2-traps, m2-fidelity, their null runs, and each app
  stage) riglib `Wait-M2BootSettle` waits until the ReadyBoot ETW session (`logman query ReadyBoot -ets`) has
  stopped, then 5 s more, then until the guest's uptime is at least `settle_min_uptime` seconds (opts, default
  180), all within `settle_max` seconds (default 300); run.json `results.settle.<start | app-<id>>`. Timing on
  m2-base (gate run of 2026-11-16, `readyboot-diag` and the m2-traps execdiffs): the ReadyBoot session stops
  about 60 s after boot and deletes `C:\WINDOWS\Prefetch\ReadyBoot\ReadyBoot.etl` (a snap A taken while it ran
  left `~F ReadyBoot.etl` as collateral); Explorer's first-run writes (`Explorer\Advanced|TaskbarStateLastRun`,
  `Explorer\Discardable\PostSetup\Component Categories64\...\Enum|Implementing`) landed at uptime ~71 s, in the
  exec window of a run whose snap A came at 67 s. The 180 s floor puts both well before snap A.
- **engine-rp** (allowed side effect): keys and values at or under
  `HKLM\SYSTEM\<CurrentControlSet|ControlSetNNN>\Services\VSS\Diag` that changed or were added, which the Volume
  Shadow Copy service writes when the engine creates its restore point in the exec window. A removal there is
  never covered. Null runs create no restore point, so the ambient set cannot hold these (the validation run of
  2026-11-16 left exactly this one record, `~K ...\Services\VSS\Diag`, as m2-fidelity collateral).
- **M2 ambient set** `vm\truth\m2-ambient.json` (`purge.rig.m2ambient/1`, committed like `truth\ambient.json`):
  `Invoke-M2NullCampaign` runs N null runs (default 6; 3 missed telemetry churn in the 2026-11-16 validation) of m2-traps and m2-fidelity on m2-base (same phases and timing up
  to snap A, an idle wait instead of exec, snap B) and `rigtool ambient --m2 --null <run dirs>` records every
  removed or changed record of `diff(snap A, snap B)` as a key `<op><kind>:<path>[|<value>]`, plus a pattern where
  the key holds a random token (a GUID seen varying, a hex run of 16+, a number of 6+ digits). rig.ps1 pushes it to
  `C:\cr\bin\m2-ambient.json`; riglib passes it to every execdiff as `--ambient`. **One set per VM**
  (rig.ps1 `Get-M2AmbientFile`, chosen by `-VmName`): Inbound `truth\m2-ambient.json`, Purge-CleanPro
  `truth\m2-ambient-cleanpro.json` (another Windows build churns differently). `Invoke-M2NullCampaign` writes the
  VM's own file by default; `-RunPrefix` (default `n`) names the null runs `<prefix><k>-<mode>`. For Clean-Pro:
  `. .\vm\rig.ps1 -VmName Purge-CleanPro; Invoke-M2NullCampaign -Count 6 -RunPrefix cpn -Engine <rig-exec engine>`.

Why a real collateral delete still fails the gate: the snapshots stay machine-wide, so any delete or change the
engine makes outside its ops shows as a record. An M2 ambient entry matches one record only: the same op, the same
kind and the same path (and value name), exactly or with only the random tokens wildcarded. It never matches a
descendant (unlike the M0 / M1a set, whose entries cover subtrees), and a `~` entry (metadata seen changing) never
authorises a `-` record (a removal) of the same object or of anything under it. So an object outside the plan is
hidden only if Windows itself removed or changed that very object in a null run's exec window; the canaries of the
trap and fixture manifests are in addition verified by content hash (deep snapshots), which no ambient rule
touches. Records added (`+`) never fail the gate and are not part of the set.

The set is tied to m2-base and the rig's timing; regenerate it when m2-base is rebuilt. The committed set was
rebuilt in the gate run of 2026-11-16, the first with the telemetry pause before snap A, from 12 null runs of each
mode (`n1-` to `n12-`). None of them saw `~F C:\WINDOWS\Prefetch\ReadyBoot\ReadyBoot.etl` (the boot trace,
4 MB -> 20 MB about two minutes after boot), which one of the gate run's two m2-traps runs left as its only
collateral record. Rebuilt again the same day after the settle wait with its 180 s uptime floor (the null runs
take the same settle): `Invoke-M2NullCampaign -Count 6`, union 260 records and 28 patterns (456 and 67 before
the floor: a later, quieter window). The real-app stage (`app`) has no null analog: its exec window follows an install, launch and
uninstall, and the first gate run's npp round showed 20 records of shell churn there (AppModel HAM `LU`, bam
UserSettings, VolatileNotifications, WER TermReason) that the repeat run did not. Collateral that remains
after it is either churn the null runs did not see (add null runs) or a real finding: the execdiff report lists
each record.

### 11.9 Elevated engine tests (G7)

Two engine tests need an elevated token (they set or restore SYSTEM ownership) and are `#[ignore]`d in a normal
`cargo test`: `elevated_set_security_assigns_system_owner` (crate purge-win, features `write`) and
`elevated_restore_puts_back_a_system_owner` (crate purge-exec, features `test-support`). The guest has no Rust
toolchain, so the rig builds on the host and runs in the guest:

    . .\vm\rig.ps1; Invoke-M2ElevatedTests          # or: .\vm\rig.ps1 -Mode m2-elevated

1. host: `cargo test -p <crate> --features <f> --release --no-run --message-format=json` (CARGO_TARGET_DIR
   `$env:RIG_TEST_TARGET`, default `target\rig-elevated`); the test binary is the one whose
   `--list --ignored --format terse` lists the test (exact name, full module path taken from the list);
2. guest: fresh restore of m2-base, the binary copied to `C:\cr\tests\<crate>-<exe>`, run by the elevated agent as
   `<exe> --ignored --exact <full name> --test-threads=1 --nocapture`;
3. `vm\runs\<prefix>m2-elevated\elevated-tests.json` (`purge.rig.m2elevated/1`): per test the exit code, the
   last 30 output lines and `passed` (exit 0 and libtest's `test result: ok. 1 passed`, so a filter that runs no
   test is not a pass); `admin` (the job's token was elevated) and `pass`.

`truth/m2.sh` reads it as gate `g7_elevated_tests` (missing run: exit 2). The test list is
`Get-M2ElevatedTestSpecs` in rig.ps1. The tests exist on the m2 branch from commit e0c52f8 on; on an older base
the build or the list step reports the test as not found and G7 fails.

### 11.10 PATH segment fixtures

`path-segment-*` fixtures (m2-traps.ps1 `Invoke-M2PathSegment`) append the segment to the raw value: the original
body is kept byte for byte (empty elements and a trailing `;` included) and the new data is
`<body>;<segment><original NULs>` (just `<segment>` for an empty body); the item's index is the original element
count. Removing the segment with its one adjacent separator, as the engine's EditSegment does, therefore yields
the original value, which is the after-exec expectation (`phase_values[].after_exec_b64` = the before data). So a
user PATH ending in `...WindowsApps;` becomes `...WindowsApps;;<segment>`. (Until 2026-11-16 the build dropped
empty elements, `...WindowsApps;` became `...WindowsApps;<segment>`, and the engine's correct result
`...WindowsApps` could not match the expected `...WindowsApps;`.)

## 12. M1b scan runs (`rig.ps1 -Mode m1b-*`, `truth/m1b.sh`, docs/M1B_DESIGN.json M1B-RIG-HOST)

This section covers the scan side of the M1b gate: G1 (replay), G2 (rig-base), G3 (dirty-base), G4 (traps), G7 (budgets)
and G8 (Purge-CleanPro). The executor side (G5, G6, K10-K13) is `vm/rig-m1b-exec.ps1` (M1B-RIG-EXEC).

### 12.1 Modes

| Mode | What | Runs |
|---|---|---|
| `m1b-app -App <id> [-Base rig-base\|dirty-base] [-Traps]` | one engine run of one app (no null runs unless `-Nulls` is given) | `m1b[d]-[traps-]<id>` |
| `m1b-apps [-Base ...] [-Ids ...]` | the gate list `7zip python python312-with-313 python313-with-312 node vcredist powershell temurin` (the same list on dirty-base), with 3 null runs spread | `m1b[d]-<id>`, `m1b[d]-null<n>` |
| `m1b-traps [-Base ...]` | 7zip as TrapA and node as TrapB, with every plant of `guest/m1b-traps.ps1` | `m1b[d]-traps-7zip` |
| `m1b-freeze` | two raw runs (vendor uninstall, no engine) of powershell and temurin; Inbound rig-base only | `m1b-fz1-<id>`, `m1b-fz2-<id>` |
| `m1b-budgets -Engine <m1b> -BaseEngine <M2 head> -Program <id>` | G7 on the host, read only (12.5) | `runs/m1b-budgets/` |

- **Purge-CleanPro tag:** on Purge-CleanPro (`-VmName Purge-CleanPro`, G8) the run tag is `cp` (`m1bcp-...`).
- **Engine:** app runs use the release engine: `-Engine`, else `$env:RIG_ENGINE`, else `target\release\purge-engine.exe`. The rig-exec build (fault injection) is refused.
- **Installer cache:** `$env:RIG_CACHE_DIR` points the installer cache somewhere else. A worktree uses the main checkout's `vm\cache\inst`.
- **Cache entries added for M1b** (in the git-ignored cache-sources.json; each hash comes from the vendor's published checksum):
  - PowerShell 7.6.10 msi
  - Temurin 21.0.13+9 msi
  - Python 3.13.17 amd64 exe

### 12.2 Guest hooks (`__M1B__` in run-app.ps1)

The host passes `{msi_tables, traps, trap_a, trap_b}` to the guest as base64 UTF-8 JSON (`ConvertTo-M1bOpts`). An empty value gives the
M0/M1a run. When options are given, run.json gets an `m1b` block and run-app adds these phases:

- **`msi-tables-1` / `msi-tables-2`** run right after `snap1` / `snap2`.
  - `guest/m1b-msi-tables.ps1` reads every installed product's LocalPackage (`UserData\*\Products\*\InstallProperties`) through WindowsInstaller COM. It only reads.
  - It writes `msi-tables-<run>-<phase>.json` with schema `purge.rig.msi_tables/1`: `{"packages": {"<LocalPackage>": MsiTables}}`.
  - MsiTables has the purge-source sysobj shape: properties, components, registry, remove_registry, classes, progids, extensions, typelibs, appids, service_install, custom_action_count, truncated.
  - The limits are the same as purge-win msi_db: 200000 rows per table and 64 KiB cells. An unreadable package is written as `{"truncated": true}`.
  - A snapshot replay reads the file next to `snap-<run>-<phase>.tsv.gz`.
- **With traps:**
  - TrapB is installed first as a pre-app, before snap0.
  - `m1b-traps-pre` runs after the launch and before lists1, so the harvest sees the plants.
  - `m1b-traps-between` runs after the harvest and before the uninstall.
  - `m1b-traps-post` runs after the uninstall and before lists2, snap2 and the scan.
  - Each of these phases fails when one of its cases fails. A failed phase ends the run (`exit 1` after run.json is saved),
    and m1b-traps.ps1 refuses a later phase after a failed case of an earlier one (review R4b S1).
  - Every phase records its plants in `m1b-traps-planted.json` (`purge.rig.m1b-traps.planted/1`), which collect copies to
    `traps-planted-<run>.json` for K9.
- **Build record.** rig.ps1 writes `<run>\m1b-build.json` (`purge.rig.m1b-build/1`) for each app run: the engine's SHA-256
  before and after the campaign, HEAD, whether crates/bins/tools/kb/Cargo.*/rust-toolchain.toml differ from HEAD, and the
  SHA-256 of the pulled run.json. It does not hash the guest's copy of the engine. Since review R4c S3 it also holds
  the rig inputs (`Get-M1bRigInputs`): the SHA-256 of `truth/m1b-traps.json`, every `truth/labels/*.json`, every file
  of `guest/` (not `guest/tests`) and `rig.ps1`, before (`inputs`) and after (`inputs_after`) the campaign, and
  whether they differ from HEAD, untracked files included (`inputs_dirty`).

### 12.3 Trap expectations (`truth/m1b-traps.json`)

The file has 26 cases (one per plant) and 44 expectations, scored by `rigtool traps --plan plan-purge.scan.json --app 7zip --sid
<run sid>`. Where the design names a verdict, the file uses it as written. Where the design is silent, the choices below were made. The gate should check them (UNSURE):

- **`com-shared-class`:** expected protected with no blocker named, because the design names none.
- **TrapA's own twins:** expected `listed`, not `safe`. These are the shellex handler and its Approved value, the event-log source PurgeTrapA,
  the MuiCache and PCA entries of 7zFM. The WER report of 7zFM was in this list too; it is now `protected`
  (see the smoke corrections below).
- **`shareddlls-count`:** only the count-2 value is expected protected (SharedRefcount). The count-1 value has no
  expectation.
- **`instfolders`:** only TrapB's Folders value has an expectation (absent). TrapA's own value has none.
- **Parent keys:** no expectation targets a container (parent key), because an `inside` entry would score as an escape.

Smoke run on 2026-11-17 (`m1b-app 7zip -Traps`, Inbound rig-base, engine from 758d55f):
- Every phase was ok: 26 cases ran and 37 of 44 expectations were met.
- 1 escape: svc-svchost (the service was listed Likely).
- 6 missed_owned:
  - svc-owned, task-owned, fw-owned and com-owned were listed Likely, not Safe.
  - The WER report was Blocked.
  - The S-1-5-18 Products key was not listed.
- These are engine results for the gate to judge, not rig faults.

The smoke was run again on 2026-11-17 to check the findings above. The outputs are in
`E:\purge-build\gate-evidence\m1b-smoke-7zip\{before,after}`.
- `before` used the m1b head 3b17232 and gave the same 37 of 44.
- `after` used the fixed engine and gave 44 of 44 against the corrected file below. Against the old file it gives
  37 of 44: the escape is gone, but a new one is counted (see svc-svchost below).

What each finding turned out to be:

- **svc-svchost (engine defect, fixed).** The index resolves a service hosted by svchost to its `ServiceDll`.
  The guard's `sys.service.windows` judged that DLL, which lies in TrapA's folder, so the rule did not apply. Harvest
  recorded the service and SYS-SERVICE offered it.
  - The fix: the guard now judges such a service by its host command (`ServiceFacts::guard_program`), in the scan
    sealing, the harvest and the executor gate. Such a service is now never recorded or offered.
  - The expectation changes from `absent` to `protected`. REF-ANY still lists the `Parameters|ServiceDll` value inside
    the service key, Blocked (`reg.hklm.system`). Under `absent`, that Blocked entry alone scores as an escape. Under
    `protected`, any equal, covering or inside entry that can be acted on still fails.
- **svc-owned, task-owned, fw-owned, com-owned (expectation error, now `listed`).**
  - The design rule (D10, R3a S1): Safe needs the harvest record, the same digest, and the program proven gone. A
    program in an InstallRoot counts as gone only when the whole root is gone, on a fixed NTFS or ReFS volume with the
    recorded serial.
  - The plants copy PurgeTrap*.exe and *.dll files into `C:\Program Files\7-Zip`, and the vendor uninstall does not
    remove them. So the root survives, and so do the service exe and the COM dll themselves.
  - Likely is therefore the right answer. Safe needs a plant whose root is removed completely (not done).
  - `listed` passes at Weak too, so K9's note reports the band of the four (`owned bands: ...`) for the gate report.
    Ruling: docs/DECISIONS.md, M1b, review R4c S1.
- **wer-twins, 7zFM report (design rule, now `protected` with `DenyListed`).** Reports under `%ProgramData%` are
  denied by `fs.programdata.microsoft`, as the FS-WER module documents. The plan lists the report Blocked.
- **msi-remnants (engine recall limit, now `not_preselected`; review R4c S1 corrected the smoke fix's `absent`).**
  - The plant writes `UserData\S-1-5-18\Products\<P>\InstallProperties` (with `LocalPackage`) and a Components value.
  - A read-only probe of the guest after the scan (`after\msi-state-probe.log`, WindowsInstaller COM
    `ProductState`) returned 2 (`INSTALLSTATE_ABSENT`, "installed for a different user") for both 7-Zip's code and the
    foreign code. `Products` does not list either code.
  - REG-ARP-MSI offers a product's registration only when Windows Installer reports it unknown in every context
    (`ScanCtx::product_known`). A product another user may have installed is never treated as gone. So nothing is
    offered.
  - **Known limit (REG-ARP-MSI recall).** The plant is the remnant the scanner is for, and its usual shape: that key
    with its `InstallProperties` is enough for Windows Installer to report any code as installed for another user.
    So REG-ARP-MSI never offers it. This is safe, but it is a gap of the engine, not a design rule (docs/DECISIONS.md,
    M1b, review R4c S1).
  - `absent` would score a later engine that offers the app's own remnant (not preselected) as an escape, and made the
    case the same as msi-remnants-foreign. `not_preselected` allows that offer and still fails a Safe or preselected one.
  - To test the Safe path, the plant would have to leave a registration that Windows Installer reports as unknown
    (not done).

### 12.4 Labels (`truth/mk_labels.py`)

New label files: powershell, temurin, python313, python312-with-313, python313-with-312.

These rules are UNSURE because no capture exists yet:
- the pwsh and python 3.13 jump-list hashes (computed, never seen in a capture)
- the user_data rules for `Documents\PowerShell` and `AppData\Roaming\Microsoft\Windows\PowerShell`
- the Launcher kept_owner rules of the two Python pairs
- the first-leftover rule for the removed version's PythonCore key
- (R4b S4) python313-with-312's generic kept_owner rules for the kept launcher's MSI registration (component clients,
  upgrade code, dependency key, cached package, `Package Cache\{code}v<ver>`): generic because the launcher's product code is
  unknown; fail-closed (a stale record of a removed 3.13 package counts as protected)
- (R4b S4) powershell's Microsoft Update opt-in (`WindowsUpdate\Services\7971F918-...`), suspected from the MSI defaults

powershell and temurin stay unfrozen; no VM run was made for R4b.

Check them against the frozen and gate captures.

Checked on 2026-11-17 (m1b-freeze, 12.6): the Microsoft Update opt-in is real (service key plus
`WindowsUpdate\Services|DefaultService`, both kept_owner now); the pwsh jump list and the two PowerShell user_data rules
matched nothing (a bare launch writes neither). powershell and temurin are frozen (FROZEN.md).

**Pre-state kept_owner (review R4b S5, ruling 2026-11-17).** A product that stays installed and that the removed app
shared can predate snap 0: in python312-with-313 the 3.13 bundle installs the Python Launcher before snap 0, and in
python313-with-312 the 3.12 bundle does (the 3.13 install then upgrades it). A diff never sees those objects, so K5
had nothing to count (0 of 29). The design labels them kept_owner, so the truth now takes them from the pre-state:
- A label file may hold a hand-written top-level `prestate` block (`mk_labels.py` keeps it):
  `{"products": "<ARP name regex>", "rules": [{"label": "kept_owner", "match", "why"}]}`. The two Python pair files
  have one for the launcher (the same object families as the M0 python truth's 29: `.py*` classes, `Python.*`
  ProgIDs, the drop-handler CLSID, `WOW6432Node\Python`, `py.exe`, `pyw.exe`, the shell extension, the Package Cache
  root, the three `Classes\Installer` and three `CurrentVersion\Installer` containers, and the launcher's own MSI
  registration).
- `m1b.sh` (collect and freeze, after `rigtool truth`; pyeval `prestate`) adds every object that is in snap 0 **and**
  in snap 2 and that a rule matches as a kept_owner truth item (`"prestate": true`): top-most per rule (a match whose
  parent the same rule matches is part of the parent's item), never an object that already is a truth item, and
  never one that is or holds a leftover or user_data truth item (that object is opened to its matching children and
  listed under `prestate.opened`). An object gone by snap 2 is not kept and not added.
- Product rules use `{CODE}`, `{PACKED}`, `{LOCALPACKAGE}` (the cached package named by the product's
  `InstallProperties|LocalPackage`) and `{DEPKEY}` (the `Classes\Installer\Dependencies` key whose default value is
  the product code). They expand for each ARP entry the `products` regex names that is in lists-0 and lists-2 under
  the same key with the same product code. In python313-with-312 the launcher changes product code inside the run, so
  only the code-free rules apply there; its new registration is in the diff (the generic S4 rules above).
- truth.json gets a `prestate` summary (products, rules, matches, added, opened, skipped rules).
- The selftest checks it on a synthetic run (`k5_prestate_counts_kept_launcher`).
- First pair runs (2026-11-17, campaign `campaign-20261117-125320`, engine mode, clean set, ambient = M0 set +
  `m1b-null1`): python312-with-313 has **42** kept_owner items, all from the pre-state (36 of the launcher's own objects
  and 6 shared containers); python313-with-312 has **44**: 20 from the diff (the upgraded launcher's new MSI
  registration and cached packages, generic S4 rules) plus 24 code-free pre-state objects. Both meet K5's 29. A
  Windows Installer temp package (`ad01.msi` and the like) that a generic cached-package rule labelled kept_owner is
  ambient now unless snap 2 names it as an installed product's `LocalPackage`.

### 12.5 Gate script (`truth/m1b.sh`) and budgets

**G1 first (review R4c S2).** `bash truth/m1b.sh replay` (from `vm/`, on the host, at the gate's commit) writes the
two G1 inputs: it rewrites `truth/m1b-replay-diff.json` (`cargo xtask replay-diff`), replays the five frozen runs
(vscode, git, firefox, npp, 7zip from `$PURGE_RUNS_DIR`, else `runs/`) with `cargo xtask replay` into
`runs/m1b-replay/<id>/` (copies of the run's snaps, lists-0 and run.json, the committed `truth/frozen/<id>/truth.json`,
the plan with its sidecar actions; the frozen run directory is not written), scores them with `rigtool score --classes`
and writes `truth/m1b-replay-score.json` (+ `.md`) with a `replay` block (`purge.rig.m1b-replay/1`: runs, HEAD, engine
sources clean, frozen truth SHA-256). Exit 1 when a run could not be replayed or the diff has unexplained rows.

`bash truth/m1b.sh` (run from `vm/`) has two stages.

**Collect.** It writes everything into `truth/m1b-evidence/`:
- the ambient set from each set's null runs
- rigtool truth with the app's labels plus `_os-servicing.json`
- the plans, with the actions from the scan sidecar
- `rigtool score --classes` per set
- `rigtool traps` per trap run
- the budgets dir, the replay diff and the replay score

Collect also copies each run's run.json subset and build record to `runs/<run>.json` (null runs too), each run's
truth to `truth-<set>-<id>.json`, and writes `manifest.json` (`purge.rig.m1b-evidence/2`: config, trap file and label
digests, frozen truths, rigtool, the null runs per set).

**Evaluate.** It checks RUN, BIND, FROZEN, SANITY, K1-K9, K14 and K16:
- It prints one line per criterion and app, with value, limit and PASS/FAIL.
- It writes `truth/m1b-score.json` (`purge.rig.m1b-score/2`, with `gate` and `not_gate_because`).
- A missing input gives a FAIL line; nothing is skipped.
- **RUN**: every app and trap run finished, every phase ok; each set has at least 2 null runs for its ambient set, each
  finished with every phase ok (R4b S2 rest).
- **BIND**: each run's build record names its run.json (SHA-256), the engine did not change during the campaign, the
  sources were clean, one engine and one commit over all runs, the budgets' M1b engine is that engine, and the trap file
  and label files are the committed ones with each run's label id equal to its app id. Review R4c S3: every run holds
  the same rig input hashes (12.2), unchanged during the campaign, clean against HEAD, and their trap and label files
  are the files scored with. Review R4c S2: the replay score has its `replay` block for the five runs, the runs'
  commit, clean engine sources and the current frozen truths.
- **FROZEN**: `truth/frozen/<app>/truth.json` exists for powershell and temurin.
- **SANITY** (review R4c S4, as m1a.sh's sanity step): each rig-base run's truth against `truth/frozen/<id>/truth.json`
  where one exists (7zip, python, node, vcredist, powershell, temurin), items keyed with random names normalised as the
  freeze compares them. A frozen leftover or user_data item that the run labels otherwise fails. Items on one side only
  (a launch that did nothing, an uninstall that removed more or less) are counted and listed in the note for the gate
  report, not failed. The dirty and Clean-Pro sets have no frozen truth.
- **K4/K7 G1**: the replay score must hold a purge score for each of the five runs (one row each); another app fails.
- **K1-K6** fail on an empty plan (truth items but nothing offered) or a score without counts.
- **K9** needs every case and `com-shared-class#between` planted ok, every expectation target among the planted objects
  (an object that already existed counts and is reported; a note-only or missing one fails), TrapA 7zip and TrapB node.
- **K14** needs exactly 12 budget runs (2 engines x 2 steps x 3 rounds), each exit 0, round 1 cold and the others warm,
  and the M1b cold round's cache moved aside or absent (`cold_cache_state`; `kept` fails).
- **K16** needs `purge.replay-diff/3`, exactly the five reasons, all five replay apps, 0 unexplained rows, and every
  promotion (band rose or became preselected) marked `promotion_justified` and listed in `justified_promotions` with a cause.

Exit codes: 0 the gate passed in the default configuration; 1 a FAIL; 2 usage; 3 everything passed but it is not a gate
score (`--evaluate`, or any M1B_* list, label map or input path other than the default). `--config` prints the configuration.

Options:
- `--evaluate DIR` runs only the evaluate stage on DIR (exit 3 at best).
- `--selftest` builds a SYNTHETIC passing evidence dir (`truth/m1b-fixture.py`) and checks that it exits 0, that each
  bad-run control (missing plant, failed plant phase, empty plan, unbound or rebuilt engine, dirty sources, two commits,
  changed traps or labels, label override, budget exit/rounds/cache, unexplained or unlisted promotion; since R4c a
  replay score short of a run or unbound, rig inputs missing, dirty, differing between runs or edited before the
  campaign, a frozen leftover relabelled, a missing run truth, too few or broken null runs...) fails on its named
  criterion, that every non-default setting gives exit 3, and that `replay` with stub cargo xtask, rigtool and git
  writes a score the gate passes with (and fails K4 G1 when a run is missing).

`m1b-budgets` runs on the host and only reads:
- For each engine it runs `harvest <program>` and then `scan --mode forced` with `PURGE_TIMING=1`, for 3 rounds. Round 1 is cold; rounds 2 and 3 are warm.
- Before the M1b engine's cold round, the MSI table cache `%ProgramData%\Purge\fp\msitables` is moved aside. The moved folder is left for the operator to delete.
- The stderr of each step goes to `runs/m1b-budgets/<engine>-<step>-<round>.log`.
- m1b.sh reads two things from each log: the `[ N.NNNs]` end stamp (the total time) and the `timing: phase` lines (refscan count, ownership.components, ownership.tables).
- The warm figure is the median of the warm rounds, compared with the M2 head measured in the same session.

Notes on individual criteria:
- **K5** needs n >= 29 for each of the two Python pairs (not lowered). Before 2026-11-17 python312-with-313 reached 0 of
  the 29 (R4b S5): 3.13 and the launcher are installed before snap 0, so the diff never saw them. The truth now adds
  the kept launcher's pre-state objects (section 12.4, `prestate`); the counts of the first pair runs are in 12.4.
- **K6** (review R4b B2, following the M1a gate): a mismatch is an item whose band would offer or preselect it wrongly:
  preselected below Safe, a band the policy does not have, user data preselected, or a protected truth item listed below
  Protected. A true leftover listed Weak or Blocked is a recall miss, as the M1a gate counted it (recall_visible_nd covers
  Safe and Likely only). It is reported in K6's note, not counted. M1b has no recall criterion.
- **K7** is checked per set and on the replay.

### 12.6 Freeze

1. Run `rig.ps1 -Mode m1b-freeze` (6 VM runs: per round one null run `m1b-fz<k>-null1`, then the two apps; `-Nulls n`
   for more null runs).
2. Run `bash truth/m1b.sh freeze powershell`, then `bash truth/m1b.sh freeze temurin`. For each app this:
   - builds the freeze's ambient set: `truth/ambient.json` plus the freeze null runs (`rigtool ambient`), as M0 and M1a
     built theirs from the null runs of the same campaign (the M0 set alone is stale: the first attempt on 2026-11-17
     differed in 35 and 26 items, all Windows churn)
   - computes the truth of both runs with that set, the label file, `_os-servicing.json` and `_m1b-noise.json`, then
     the m1b.sh post step (temp packages, `prestate`)
   - applies the freeze rule (pyeval `freezecmp`): both runs must be whole (every phase ok, install and uninstall exit 0
     or 3010, ARP entry gone) and give the same label to every item they share, compared with random names normalised
     (GUIDs, numbers of 6+ digits, the random part of `%TEMP%` names, as m1a.sh's sanity step); else exit 1. An item
     present in **one run only** is churn or chance: it is excluded from the frozen truth and listed under
     `freeze.excluded` with the label it had. It is never frozen as a leftover.
   - writes `truth/frozen/<id>/{truth.json, truth-fz2.json, run.json}` (the truths carry a `freeze` block)
3. Describe the result in FROZEN.md.

**Noise list** (`truth/labels/_m1b-noise.json`, hand-written, ruling 2026-11-17). Windows-owned areas whose state
changes on Windows' own schedule or belongs to a Windows store, seen in the freeze captures: WNS channel backups and
SystemAppData activity of inbox Windows components (`MicrosoftWindows.*_cw5n1h2txyewy` only; an app's own channel stays
the app's), IRIS, Desktop Spotlight, the rules engine, the shell's component-category cache and `TaskbarStateLastRun`,
the font cache, BitLocker telemetry, the hive defrag counter, Security Center provider state, DiagTrack downloaded
settings, `Installer\TempPackages`, the Windows Update SLS cache and the .NET servicing `BreadcrumbStore`. Every rule is
`ambient` (never `first`), so it can only take an item out of the leftover set. m1b.sh passes it to every M1b truth
(collect and freeze) and hashes it into each run's label digest (BIND). A leftover `C:\Windows\Installer\<x>.msi`
that snap 2's `Installer\TempPackages` names (msiexec deletes it itself) is relabelled ambient by m1b.sh. A
`kept_owner` rule cannot be overridden by it in practice: the selftest
(`churn_noise_list_windows_owned_and_never_an_app_item`) checks that every rule lies under a Windows-owned root, matches
its recorded churn samples, and matches no leftover, user_data or kept_owner item of any frozen truth (M0 and M1b), nor
a PowerShell or Temurin object. The selftest's `churn_*` controls check the freeze rule on synthetic runs.
