# M0 frozen truth (8 apps)

Frozen on 2026-11-11. ENGINE_PLAN §1.3 says no per-app number is frozen until the 8 apps are re-run under
per-app snapshot restore. That re-run is done; these are the numbers later milestones are gated against.

- Campaigns (`vm/runs/`): `campaign-20261111-184616` (Notepad++), `campaign-20261111-184959` (3 null runs,
  7-Zip, VS Code, Git, Python, Node.js, VC++, first Firefox run), `campaign-20261111-191857` (Firefox re-run,
  the frozen one). Each `campaign-*.json` lists its runs; each `run.json` holds hashes, signatures, times and
  phases.
- VM: `Inbound-Win11-Test`, Windows 11 Enterprise LTSC eval (EnterpriseSEval) 26100.1742, snapshot `rig-base`
  restored before every run.
- Protocol: vm/RIG.md §4 (snap0, install, launch once at medium IL, snap1, vendor uninstall, snap2). Node.js and
  VC++ have no launch (no GUI exe to start; `launch.done` is false in their `run.json`).
- Ambient: union of three null runs (`truth/ambient.json`: 102 exact items, 36 patterns) plus the shared
  OS rules in `truth/labels/_os.json` (45 anchored rules, 2 of them `split` containers), plus the built-in
  rule for list values whose segments are unchanged (RIG.md §5).
- Reproduce: `bash truth/recompute.sh` from `vm/` (regenerates the labels with `truth/mk_labels.py`, recomputes
  every `truth.json`, re-scores into `truth/m0-score.{json,md}`).
- Committed copies: `truth/frozen/<id>/{truth.json, run.json, plans/}` (vm/runs/ is git-ignored).

## Per-app truth

Recall denominator = `leftover` + `user_data`.

| App | Version | Installer | leftover | user_data | kept_owner | ambient | Kinds (leftover + user_data) |
|---|---|---|---:|---:|---:|---:|---|
| Firefox | 160.0 | NSIS (Mozilla) | 23 | 1 | 0 | 103 | Path 7, RegKey 10, RegValue 7 |
| Python | 3.12.7 | Burn | 29 | 1 | 29 | 113 | Path 25, RegValue 5 |
| VS Code | 1.146.0 | Inno | 152 | 2 | 0 | 171 | Path 13, RegKey 139, RegValue 2 |
| Git | 2.56.1 | Inno | 16 | 0 | 0 | 123 | Path 8, RegKey 2, RegValue 6 |
| 7-Zip | 24.08 | MSI | 3 | 0 | 0 | 89 | Path 2, RegKey 1 |
| Notepad++ | 8.9.9 | NSIS | 29 | 0 | 0 | 167 | Path 10, RegKey 16, RegValue 3 |
| Node.js | 20.18.0 | MSI | 4 | 0 | 0 | 94 | Path 1, RegValue 3 |
| VC++ 2015-2022 x64 | 14.44.35211 | Burn | 9 | 0 | 0 | 44 | Path 7, RegValue 2 |

Every launched app now also leaves its own **Prefetch** trace (`<EXE>-<hash>.pf`, FS-PREFETCH) and, where the
shell recorded one, a **jump list** whose AppID hash resolves to the app (FS-JUMPLISTS; the hash is a CRC-64
of the AppID, see `truth/mk_labels.py`). Shared executables (msiexec, dllhost, rundll32) stay ambient.

What the leftovers are:

- **Firefox:** `HKLM\SOFTWARE\Mozilla\{Firefox,MaintenanceService}`, `mozilla.org`, `WOW6432Node\Mozilla`,
  `HKCU\Software\Mozilla`, `Local\Mozilla`, `ProgramData\Mozilla-<guid>`, CLSID/Interface keys, `.shtml`
  values, the firewall rule, `ShimInclusionList\false`, UserAssist/JumplistData traces, the
  `FeatureUsage\AppBadgeUpdated` value of its AUMID (`308046B0AF4A39CB`), Prefetch for `firefox.exe` and
  `crashhelper.exe`, two temp files. User data: `Roaming\Mozilla`.
- **Python:** installer logs in `%TEMP%`, PCA and UserAssist traces, two new UFH `SHC` slots, two jump lists
  (`python.exe` and a Start-menu shortcut AppID), Prefetch for `python.exe`/`pythonw.exe`. User data: `.idlerc`.
  kept_owner (29): everything owned by the Python Launcher, which stays installed (`.py*` classes, `Python.*`
  ProgIDs, `py.exe`, `pyw.exe`, `pyshellext.amd64.dll`, its MSI cache and SourceHash, `WOW6432Node\Python`,
  Package Cache) (L10).
- **VS Code:** 135+ `Classes\.<ext>` / `OpenWithProgids` skeleton keys, the sparse AppX registration
  (`PolicyCache` row; removed through the package API, deny for a raw delete), `HKCU\...\Classes\vscode`,
  `DeveloperTools\deviceid`, `.vscode-shared`, `.copilot`, temp files, the `Microsoft.VisualStudioCode`
  jump list, five `CODE.EXE` Prefetch files. User data: `Roaming\Code`, `.vscode`. The two
  `AppxAllUserStore` deprovisioning tombstones are ambient (report-only, ENGINE_PLAN §1.2).
- **Git:** `Classes\LibraryFolder\background\shell`, `Classes\sh_auto_file`, an Inno temp file, UserAssist and
  JumplistData traces, two new UFH `SHC` slots, three jump lists (git-gui and two shortcut AppIDs),
  Prefetch for bash, cygwin-console-helper, git and mintty.
- **7-Zip:** `HKCU\Software\7-Zip` (written by the launch), the `7zFM.exe` jump list and Prefetch. The
  `{042D2B7D…}` CLSID is Defender's and is ambient (L11).
- **Notepad++:** the sparse package it registers for the Windows 11 context menu and its uninstaller leaves
  registered (WindowsApps folder, AppRepository, `Packages`, AppContainer/AppModel keys, AppIso firewall
  rules, its `PackagedCom` package and class-index entries). These match deny for a raw delete; only a package
  offer (Remove-AppxPackage) covers them. Also `WOW6432Node\Notepad++`, two temp files, a UserAssist trace,
  Prefetch for `notepad++.exe` and `gup.exe`. Its uninstaller removes `%APPDATA%\Notepad++` itself.
- **Node.js:** the `node.exe` jump list and three new UFH `SHC` slots (Start menu shortcuts). The user PATH
  change is ambient: the uninstaller removed its `%APPDATA%\npm` segment and only a trailing `;` differs.
- **VC++:** six `dd_vcredist_*.log` installer logs, one temp file, two PCA records.

## Old tools re-scored under the new scorer

`rigtool score` on the frozen truth with plans converted from vm/results (`truth/m0-score.md` has every
table). Outcome order: an offered item absent from snap2 scores `gone` (a no-op) first, then
danger > hit > ambient > other.

| App | Clone recall / danger | UT recall / danger | BCU recall / danger |
|---|---|---|---|
| Firefox | 0 % / 0 | 12.5 % / 1 (WMI `Wbem\Tracing` key) | 20.8 % / 0 |
| Python | 0 % / 1 (`WOW6432Node\Python`, Launcher's) | 0 % / 0 | 0 % / 1 (same key) |
| VS Code | 0 % / 0 | 0 % / 0 | 0 % / 0 |
| Git | 0 % / 0 | 0 % / 0 | 0 % / 0 |
| 7-Zip | 0 % / 0 | not run | 33.3 % / 0 |
| Notepad++ | 3.4 % / 1 (Windows' `Notepad.lnk`) | 0 % / 0 | 3.4 % / 0 |
| Node.js | 0 % / 0 | not run | 0 % / 0 |
| VC++ | 0 % / 0 | not run | 0 % / 0 |
| **Macro** | **0.4 %** (8 apps) | **2.5 %** (5 apps) | **7.2 %** (8 apps) |

UT and BCU each pre-select one user-data item on Firefox (`userdata_presel` 1). The clone's only hit is the
Notepad++ one; its Python find is danger.

The earlier findings reproduce: the clone finds almost nothing and lists Windows' `Notepad.lnk`; nobody
cleans VS Code's skeleton keys; UT and BCU get part of Firefox. Numbers differ from docs/COMPARISON.md
for known reasons:

1. **Value-level, contamination-free truth.** Per-app restore and value capture add items the old top-key
   diff could not see (Firefox 10 → 24, VS Code 137 → 154, Notepad++ 0 → 29 because the app is now launched
   and its sparse package is captured). Prefetch, jump lists and new UFH slots are attributed to the app.
2. **The old UT/BCU recall was an upper bound.** Their "removed" lists include what the vendor uninstaller
   removed in the same run. Those items are absent here and score `gone`, so Git drops from 100 % to 0 %
   (UT's own wizard reported "No leftover traces found") and Python from 21–26 % to 0 %.
3. **Relabels.** Python's `.py*` classes belong to the Python Launcher (kept_owner, so offering
   `WOW6432Node\Python` is now danger). 7-Zip's old single leftover was Defender's CLSID.
4. **Danger is no longer "existed earlier"** in a contaminated snapshot: the old `WOW6432Node\Notepad++`
   danger is gone, and Notepad.lnk / Launcher / WMI tracing are the real ones.

## Open points for later milestones

- §1.4 says VC++ should get "no candidates offered at all", but truth has 9 items: installer logs (FS-TEMP,
  Unchecked) and PCA traces (REG-PRIVACY). Either amend §1.4 to "only Unchecked temp and privacy traces" or
  label those items ambient. Not changed in M0.
- Node's §1.4 target (user PATH `npm` segment Safe) is not exercised: the uninstaller removed it. The
  dirty-baseline VM (`truth/dirty-base.json`) and the R-force path will cover it.
- Three jump-list hashes (Python 1, Node 2) did not resolve to an app exe or AUMID and stay ambient.
- Temp scratch with random names (`DEL*.tmp`, `~nsu*.tmp`, `is-*.tmp`) is labelled leftover (FS-TEMP,
  Unchecked). It counts in recall_listed but cannot reach recall_safe by design.
- Clean-Pro baseline: built for Pro 26340.9882 (`kb/baselines/Professional-26340.9882.tsv.gz`, 2026-11-12).
  The host is still on 26300.9974, so it has no matching baseline until it updates (docs/M0_REPORT.md).

## M1b: powershell and temurin (PENDING)

These two apps are not frozen yet. The freeze needs four VM runs, and this package (M1B-RIG-HOST) did not make them.

The gate package does the freeze:
1. Run `.\vm\rig.ps1 -Mode m1b-freeze`. It makes two raw runs of each app on Inbound-Win11-Test, rig-base, with the vendor uninstall and the MSI
   tables captured.
2. Run `bash truth/m1b.sh freeze powershell` and `bash truth/m1b.sh freeze temurin` (RIG.md §12.6).

The method is M0's:
- **Ambient:** `truth/ambient.json` plus `labels/_os.json`, plus `_os-servicing.json` for the rig-base drift since M0.
- **Labels:** from `truth/mk_labels.py` (powershell.json and temurin.json). Their UNSURE rules are listed in RIG.md §12.4.
- **Installers** (in cache-sources.json):
  - PowerShell-7.6.10-win-x64.msi
  - OpenJDK21U-jdk_x64_windows_hotspot_21.0.13_9.msi

Once both apps are frozen, replace this section with the campaign names, the counts per label and the open points.
