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
M0 run directories `vm\runs\<id>\` are never archived or overwritten. Null runs keep `null<n>`.

0. Pre-apps (`pre` in `apps.ps1`, e.g. `firefox-tb`: Thunderbird): each is installed exactly as in step 2 and
   settled, and its ARP entry recorded in `run.json` `pre[]`, **before** step 1, so everything of theirs is in
   the clean state and offering any of it scores as danger.
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
   Settle 10 s.
4. `lists 1`, `snap 1` (installed footprint).
5. Uninstall with the vendor's own uninstaller, quiet. Record `t0` (start) and `t1` (end). End = the main
   ARP entry is gone **and** the uninstaller's process tree has exited (NSIS relaunches itself from
   `%TEMP%\Au_.exe`, Burn and msiexec spawn children) **and** MSI is idle, max 30 min. If everything is idle
   but the entry is still there for 180 s, the wait gives up (`entry_gone` false, not a timeout). Settle 30 s.
6. `lists 2`, `snap 2`.
7. Write `run.json`: `{id, tech, url, installer_sha256, main {key,name,version,…}, install {start,end,exit},
   launch {done, exe}, uninstall {cmd, t0, t1, exit, timed_out}, entries_created, entries_left}`.

Null runs follow the same steps with no install, launch or uninstall, and the same waits (fixed: 60 s,
0 s, 60 s), so their diff is pure Windows churn.

Host side (`rig.ps1`): power off → `snapshot restore rig-base` → start → wait for the agent → copy fresh
`rigtool.exe`, `purge-engine.exe` (when given with `-Engine` or built at `target\release\`) with
`kb\baselines\*.tsv.gz` (to `C:\cr\bin\kb\baselines\`), and `guest\*.ps1` → run the job → copy
`C:\cr\out\<run>\` to `vm\runs\<run>\` → next app.

## 4a. Engine mode (M1a R0, ENGINE_PLAN §10.2, §11.1)

`Invoke-Campaign -Ids ... -RunPrefix r0- -Engine <purge-engine.exe>` (or `Invoke-Run -Id <id> -RunPrefix r0-
-Engine` after `Push-Tools -Engine`) sets the job's `__ENGINE__` placeholder. The run protocol is §4 with these
changes, each engine call its own phase (command line, exit code, stdout/stderr in `run.log`, a record in
`run.json` `engine.calls[]`; a failed engine phase is recorded and the captures still run):

| After | Phase | Command (CLI contract ENGINE_PLAN §3.4) |
|---|---|---|
| `snap 1` | `engine-inventory-1` | `purge-engine inventory --json > inv-1.json`; the `program_id` of the main ARP entry is the entry whose `key_path` is `run.json` `main.key` (compared canonically) |
| | `engine-harvest` | `purge-engine harvest <program_id> -o fp.json` |
| | `uninstall` | `purge-engine uninstall <program_id> --quiet --fp fp.json -o engine-run.json` **instead of** the vendor command; `run.json` `uninstall.t0/t1/exit` come from `engine-run.json` (`t_start`, `t_end`, `exit_code`; `uninstall.times` = `engine`, or `rig` when the file is missing), plus `outcome`, `verify_gone`, `engine_exit`, `rig_t0`/`rig_t1`. The rig's WaitTree (engine process tree, ARP entry gone, max 10 min) and the 30 s settle still run as a safety net. |
| `snap 2`, `entries` | `engine-scan` | `purge-engine scan --fp fp.json --mode post --app <id> -o plan-purge.json` (`--app`: the plan's `app` is the truth id, ENGINE_PLAN P40) |
| | `engine-inventory-2` | `purge-engine inventory --json > inv-2.json` |

The scan and the second inventory run only after `snap 2`, so the engine's reads cannot disturb the capture.
The host copies `plan-purge.json` to `vm\runs\<run>\plans\purge.json` and the frozen BCU plan
`vm\truth\frozen\<id>\plans\bcu.json` (when there is one) next to it. `vm\truth\m1a.sh` then recomputes truth
for the `r0-*` runs with the app's label file, compares it with the frozen truth, scores Purge and BCU, and
runs `rigtool invdiff` on `inv-1`/`inv-2` against `lists-1`/`lists-2`.

M1a corpus additions (`apps.ps1`): `vscode-user` (VS Code per-user build, installed at medium integrity),
`thunderbird`, and `firefox-tb` (the `firefox` definition with `pre = thunderbird`).

## 5. Truth (`rigtool truth`)

Input: `snap-0`, `snap-1`, `snap-2`, `lists-0..2`, `run.json`, the ambient set, and the app's label rules
`vm\truth\labels\<id>.json`. Output `vm\runs\<id>\truth.json`.

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

Existence is three-valued: present, absent, or unknown (a value under a depth-1 registry root, or a
segment of a preview cut at the capture limit). Unknown is never `gone`.

**Package coverage.** An `AppxPackage {full_name}` offer covers every truth item whose canonical string
contains the full name or the family name (`Name_PublisherId`), an `AppContainer\Mappings\S-1-15-2-*` key
whose `Moniker` is the family, and a `PackagedCom\ClassIndex\{CLSID}` key that has the full name as a child.

Metrics per (app, tool), then macro-averaged per tool over apps:
`truth_n`, `recall_listed` (covered by any band), `recall_visible` (Safe ∪ Likely), `recall_safe`,
`partial_n`, `precision_safe` (Safe items that are hits ÷ Safe items that are not `gone`),
`danger_listed`, `danger_preselected`, `userdata_preselected`,
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
