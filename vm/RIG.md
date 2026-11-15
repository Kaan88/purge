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
