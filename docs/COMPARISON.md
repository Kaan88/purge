# Clean Remover clone vs. Uninstall Tool vs. BCU — 3-way comparison

Tested 2026-11-11 in the throwaway VM `Inbound-Win11-Test` (Windows 11 LTSC, clean, 4 GB).
Test rig, scripts and raw results: `purge\vm\` (`results\`, `shots\`).

| | Tool | Build |
|---|---|---|
| **Clone** | "Clean Remover", Rust/egui, `draft_clone\` | static-CRT debug build of current source |
| **UT** | Uninstall Tool | binaries **3.7.4** (`English.xml` says 3.8.2; the app itself offered the 3.8.2 update) |
| **BCU** | Bulk Crap Uninstaller | 6.3 (official installer, GUI + `BCU-console`) |

PARITY.md's targets (v1/v2) are shown next to each feature so the gap to the Purge plan is visible.

---

## 1. Headline findings

1. **The clone cleans up almost nothing after uninstalling.** Across 8 real installers, it found **1 of 168**
   real leftovers (Python), and it **pre-ticked one dangerous false positive**: Windows' own
   `Start Menu\Programs\Notepad.lnk` when uninstalling Notepad++ (`norm("Notepad++") == "notepad"`).
   UT and BCU both handled that case correctly.
2. **List parity with UT is exact.** On the same machine state the clone and UT 3.7.4 show identical counts:
   Apps 17, System 29, Hidden 16, Store 4.
3. **UT's wizard is conservative.** It found Firefox's and Notepad++'s profile folders and keys, and reported
   "No leftover traces found" for VS Code, Git and Python. It never touched anything that existed before the install.
4. **BCU finds the most, and it is the only tool that knows MSI/Inno/NSIS quiet switches.** But `BCU-console`
   crashed during junk deletion on Firefox (more below), and its console deletes junk **without a backup**.
   The GUI does back up.
5. **None of the three removes VS Code's 135 empty file-extension keys** (`HKLM\Software\Classes\.bash`, `.asp\OpenWithProgids` …).
   Neither does any tool remove Python's `.pyc/.pyd/.pyw/...` class keys.
6. **The clone is not a BCU port and contains UT text.** It has no `NOTICE` or BCU attribution, and 77 of UT's
   202 longer English.xml strings appear verbatim in the clone's source (e.g. `ui.rs:2058`). PARITY.md says
   "No UT code, binaries or strings are reused", so this needs fixing before Purge takes code from the clone.
7. **The clone does not start on a clean Windows install.** It needs the VC++ runtime (`vcruntime140.dll`) and
   OpenGL 2+ (glow renderer). Without either it exits silently with code 0. Needs a static CRT plus a software/wgpu fallback.

---

## 2. Leftover scan — measured on real installers

Method:
- **Truth.** Snapshot the filesystem and registry (top-most new items) before install. Install, run the vendor
  uninstaller, snapshot again. What is new and still present = the real leftovers, minus a Windows churn filter
  (`score.ps1 $Ambient`).
- **Clone.** Its `leftovers::scan()` was called through a headless harness that compiles the clone's modules unchanged.
- **UT / BCU.** Each tool was driven end to end (UT's Uninstall Wizard through its GUI; BCU-console
  `uninstall /Q /U /J=Good`). What disappeared between before and after is that tool's result.
- **Danger** = an item flagged or removed that already existed before the app was installed.

> UT/BCU recall is an **upper bound**: it also counts items the vendor uninstaller removed by itself in that
> run (e.g. for Git, UT's wizard said "No leftover traces found" yet both Git items were gone).
> The wizard dialogs (section 3) show what UT itself found.
>
> **Superseded numbers (M0, 2026-11-11).** This table used contaminated top-key snapshots. The M0 re-run
> (per-app restore, value-level capture, null-run ambient) is in `vm/truth/FROZEN.md`. Two labels here were
> wrong: 7-Zip's `{042D2B7D…}` CLSID is Defender's (ambient), and Python's `.py*` classes belong to the
> Python Launcher, which stays installed (kept_owner). Under the M0 scorer the clone's one Python find
> (`WOW6432Node\Python`) is that Launcher's key and scores **danger**, so the clone's only hit anywhere is
> Notepad++. UT's Firefox list includes a WMI `Wbem\Tracing` key that existed before the install (danger).
> Macro recall on the frozen truth: clone 0.4 %, UT 2.5 % (5 apps), BCU 7.2 %. The qualitative findings
> stand.

| App (installer) | Real leftovers | Clone found | Clone danger | UT recall | BCU recall | UT/BCU danger |
|---|---|---|---|---|---|---|
| Firefox (NSIS) | 10 | **0** | 0 | 60 % | 60 % ¹ | 0 |
| Python 3.12 (Burn) | 19 | 1 (5 %) | 0 | 21 % | 26 % | 0 |
| VS Code (Inno) | 137 | **0** | 0 | 0 % | 0 % | 0 |
| Git (Inno) | 2 | 0 | 0 | 100 % ² | 100 % | 0 |
| 7-Zip (MSI) | 1 (shell-ext CLSID) | 0 | 0 | — ³ | 0 % | 0 |
| Notepad++ (NSIS) | 0 new ⁴ | 2 flagged | **1 real** (Windows `Notepad.lnk`) | 0 | 0 | 0 ⁴ |
| Node.js 20 (MSI) | 0 | 0 | 0 | — | n/a | 0 |
| VC++ Redist (Burn) | 0 | 0 | 0 | — | n/a | 0 |

1. `BCU-console` crashed partway through Firefox's junk delete (`FileNotFoundException` on `helper.exe` after its
   folder had already been removed), so the rest of the list was skipped.
2. Vendor uninstaller removed both; UT's wizard reported nothing.
3. "—" = not run with that tool.
4. `HKLM\Software\WOW6432Node\Notepad++` already existed from an earlier test run, so it counts as "danger" in the
   scorer but is a genuine Notepad++ leftover. The only true false positive is the clone's `Notepad.lnk`.

What the clone missed (examples):

| App | Missed by the clone |
|---|---|
| Firefox | `AppData\Roaming\Mozilla`, `AppData\Local\Mozilla`, `HKCU\Software\Mozilla`, `ProgramData\Mozilla-<guid>` |
| Python | `HKLM\Software\Classes\.pyc/.pyd/.pyo/.pyw/.pyz/.pyzw` |
| Git | `Classes\LibraryFolder\Background\shell`, `Classes\SH_AUTO_FILE` |
| VS Code | 135 `Classes\.<ext>\OpenWithProgids` keys and the sparse-MSIX AppX registration |

Why: the clone only matches leftovers by **app name** (alphanumeric, ≥ 4 chars) under the install folder's
parent, AppData and `Software\<Name>` / `Software\<Publisher>\<Name>`. "Firefox" never matches `Mozilla` folders,
and it has no file-association, COM/CLSID, shell-extension or AppX scanners. `MECHANICS.md` has no leftover
rules from UT, so this scan is the clone's own design rather than a port of anything.

## 3. What UT's wizard actually reported

| App | UT wizard result |
|---|---|
| Firefox | 4 groups: `Roaming\Mozilla`, `Local\Mozilla`, `HKLM\Software\Mozilla\Firefox`, `HKCU\Software\Mozilla\Firefox` (9 files, 6 registry items) |
| Notepad++ | `Roaming\Notepad++` + one `HKLM\...\Windows\CurrentVersion` value. Did **not** flag Windows' `Notepad.lnk` |
| Python | "No leftover traces found" |
| VS Code | "No leftover traces found" |
| Git | "No leftover traces found" |

UX observations:
- No confirmation before launching the vendor uninstaller.
- "Remember my choice" is ticked by default on the first wizard prompt, so later scans run automatically.
- Online update check at startup.

## 4. Program list (same machine state)

| Tab | UT 3.7.4 | Clone | BCU 6.3 |
|---|---|---|---|
| Apps | 17 | 17 | — (one flat list) |
| System | 29 | 29 | — |
| Hidden | 16 | 16 | — |
| Store | 4 | 4 | 47 Store apps |
| **Total** | 66 | 66 | **125** |

BCU's 125 by uninstaller kind: StoreApp 47, Msiexec 38, "Unknown" 17 (Windows tweaks), WindowsFeature 15, Inno 4,
NSIS 4. 118 of the 125 can be uninstalled quietly. BCU also shows Notepad++'s and VS Code's sparse MSIX packages,
which neither UT nor the clone lists. BCU hides the 17 entries that have no DisplayName (the clone shows them under Hidden, as UT does).

---

## 5. Feature matrix

✅ present · ◐ partial · ❌ missing · — not applicable

### Uninstaller

| Feature | Purge plan | UT | BCU | Clone |
|---|---|---|---|---|
| List from HKLM/WOW6432Node/HKCU + MSI UserData | v1 | ✅ | ✅ | ✅ (exact UT counts) |
| Size (EstimatedSize, folder fallback) | v1 | ✅ | ✅ | ✅ (background folder measure) |
| Icons | v1 | ✅ | ✅ | ❌ letter tiles |
| Apps / System / Hidden categories | v1 | ✅ | ◐ (flags/filters) | ✅ |
| Update tree under parent | v1 | ✅ | ❌ flat | ❌ |
| Recently installed view + highlight | v1 | ✅ | ◐ | ✅ |
| Search / sort | v1 | ✅ | ✅ | ✅ |
| Uninstall / Modify | v1 | ✅ | ✅ | ✅ (`/I{`→`/X{` for MSI) |
| Batch uninstall | v1 | ✅ sequential | ✅ queue + concurrency | ◐ sequential, `BATCH_LIMIT = 10` |
| Quiet uninstall | v1 | ❌ | ✅ (MSI/Inno/NSIS generators) | ❌ `QuietUninstallString` read but unused |
| Uninstall failed → offer cleanup | v1 | ✅ | ✅ | ✅ |
| Running processes → offer terminate | v1 | ✅ | ✅ | ❌ |
| Force removal / remove entry (+ batch) | v1 | ✅ | ✅ | ✅ |
| Jump to registry / folder / website / web search | v1 | ✅ | ✅ | ✅ |
| Microsoft Store apps | v2 | ✅ | ✅ | ✅ (async load) |
| Steam / Scoop / Chocolatey / Windows features | v2 | ❌ | ✅ | ❌ |
| Export list to HTML | v2 | ✅ | ✅ (various) | ✅ |
| Runs elevated via manifest | (Dropped list: "always elevated") | UAC task | ✅ | ❌ shows "Standard user", restart-as-admin only |

### Leftover wizard

| Feature | Purge plan | UT | BCU | Clone |
|---|---|---|---|---|
| File / folder scan | v1 | ✅ | ✅ (most scanners) | ◐ name match only |
| Registry scan | v1 | ✅ | ✅ (COM, AppCompat, firewall, …) | ◐ `Software\<Name>` only |
| Shortcuts / startup leftovers | v1 | ✅ | ✅ | ◐ shortcuts by name → **Notepad.lnk false positive** |
| Review tree with counts/size | v1 | ✅ | ◐ list | ✅ |
| Confidence per item, only "good" preselected | v1 | ❌ | ✅ | ❌ everything pre-checked |
| Hard deny-list (Windows, shared, other apps) | v1 (AI section) | ◐ implicit | ✅ | ◐ `protected()` roots only |
| Ask / automatic / disabled | v1 | ✅ | ✅ | ✅ |
| Locked files → delete on reboot | v1 | ✅ | ✅ | ❌ no `MoveFileEx` |
| Backup + restore | v1 | ◐ | ✅ .reg backup (GUI) | ❌ plain `remove_dir_all` |
| Save log / export results | v1 | ✅ | ✅ | ◐ |

### Other

| Feature | Purge plan | UT | BCU | Clone |
|---|---|---|---|---|
| Install tracker | v2 (ETW + diff) | ✅ kernel driver | ❌ | ◐ snapshot diff (`trace.rs`) |
| Startup manager | v2 | ✅ | ✅ | ◐ `StartupApproved` const unused, so enable/disable state isn't Windows-compatible |
| System Tools menu | Dropped | ✅ | ❌ | ✅ |
| Update checker / trial | Dropped | ✅ | ✅ update | ❌ |

---

## 6. Risks and issues found

| # | Issue | Tool | Severity |
|---|---|---|---|
| 1 | Pre-checks Windows' `Notepad.lnk` as a Notepad++ leftover (name normalisation strips `++`) | Clone | **High**: deletes an OS file, no backup |
| 2 | Deletes with no backup and no delete-on-reboot | Clone | High |
| 3 | No confidence levels; everything pre-ticked | Clone | High |
| 4 | Verbatim UT strings in source; no BCU NOTICE | Clone | High (licensing / PARITY rule) |
| 5 | Silent exit on clean Windows (no VC++ runtime / no OpenGL 2) | Clone | Medium |
| 6 | Finds ~0 % of real leftovers | Clone | Medium |
| 7 | Console junk delete aborts on a missing file; no backup in console mode | BCU | Medium |
| 8 | Local UT binaries fail signature check (`HashMismatch` on UninstallTool64/32; `UninstallTool.exe` unsigned) | UT copy | Medium — the folder copy is modified |
| 9 | No tool removes per-extension `OpenWithProgids` / class keys | All | Low (empty keys) |

## 7. Test coverage gaps

- **Visual Studio Community**: installed (CoreEditor + VC.Tools) and listed by all three, but `setup.exe uninstall --quiet`
  stopped while loading its catalog, and a retry with `--force` returned exit 87. No leftover numbers.
- **VLC**: the official download came back as HTML twice; dropped.
- UT's wizard was run on 5 apps (Firefox, Notepad++, Python, VS Code, Git), not 7-Zip/Node/VC++.
- One VM, one run per app, one user profile; no reboot between uninstall and scan.

## 8. Recommendations for Purge

1. Don't reuse the clone's leftover scanner. Port BCU's `Junk` scanners and confidence model as PARITY.md plans,
   plus the file-association/`OpenWithProgids` cleanup none of the tools do.
2. Name matching must be token-aware (`Notepad++` ≠ `Notepad`), and anything outside the app's own folders/keys
   must go through a deny-list and start unchecked.
3. Backup (.reg + zip) and `MoveFileEx` delete-on-reboot before any real delete.
4. Static CRT and a renderer fallback so it runs on a clean Windows.
5. The list-building logic from the clone is good (exact UT parity) and is worth keeping, after removing
   the copied UT strings.
