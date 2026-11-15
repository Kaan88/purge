# Extended campaign x2: review of the danger counts

Reviewed 2026-11-15. Engine msvc 1d7524d4cd0c, policy m1a.5 (confirmed in all 16 `plan-purge.scan.json`).
Runs `vm/runs/x2-*`, scores `vm/truth/x2/`. Read-only review; one scratch rescore in
`/home/kaan/purge-target/gate/x2-scratch/`.

## Verdict

**No engine fault that has to be fixed before the M1a gate. But `danger_blocking` is not 0 everywhere, and
that needs an explicit decision, not silence.**

- **`danger_blocking` = 7 and `danger_preselected` = 7 on `ff-reinstall`.** 0 on the other 15 runs.
  `userdata_preselected`, `userdata_blocking` and `ud_safe` are 0 on all 16.
- The 7 are **Firefox's own leftovers from the first install** of the same product in the same folder
  (the scenario installs, removes and reinstalls Firefox before snap 0). The scorer calls them danger only
  because they existed in snap 0. Rescored against a snap 0 without the first install: **danger 0**.
  Safe and preselected is the desired band; the clean-base Firefox run gives the same bands.
  The same 7 were there with m1a.3 (x0) and m1a.4 (x1). This is a truth artefact the variant's own label
  note already predicts. It is not an engine fault, but the literal criterion fails on this run until the
  scorer is fixed or the run is waived.
- Of the 41 danger items: 11 are Blocked (kept, read-only), 6 are Weak (hidden), 17 are Likely (shown,
  unticked), 7 are Safe (the `ff-reinstall` items above).
- **7 of the Likely items are really foreign** (a user's portable copy, a user's tool, a still-installed
  sibling). All unticked, all present since x0/x1, all a known design limit ("a bare exe name is Tier B,
  never preselected"). They do not break "nothing foreign is Safe or preselected". They do break the
  stricter wording in `docs/DECISIONS.md` ("reverse if a run offers a foreign item in Safe or Likely").
  One of the two texts should be made to say what is meant.
- Nothing is worse than x1. Three false Safe items of x1 are gone.
- Extra checks, inventory check and footprint: all pass. `winmerge` offering 0 is an old recall gap.
- The Store self-update distorts recall only, not danger.

The runs are valid: 16 of 16 with every phase ok, uninstall exit 0, `entry_gone` true, `verify_gone.passed`
true, Edge pause held.

## 1. The 41 danger items by class

| Class | Count | Where | Band | Preselected |
|---|---:|---|---|---|
| A. Same product's earlier leftovers (truth artefact) | 8 | ff-reinstall | 7 Safe, 1 Likely | 7 yes, 1 no |
| B. Kept for a still-installed sibling | 11 | ff-esr 5, ff-devedition 4, vscode-with-user 2 | Blocked | no |
| C. User data shown or hidden, unticked | 8 | profiles: ff-esr 2, ff-devedition 2, ff-reinstall 2; `%APPDATA%\Code`: vscode-userstate 1, vscode-zipcopy 1 | 6 Weak, 2 Likely | no |
| D. User-made references to the app, now dangling | 5 | git-userstate | Likely | no |
| E. Value the app itself overwrote (name existed before) | 2 | vscode-zipcopy | Likely | no |
| F. Really foreign, offered unticked | 7 | npp-userfiles 3, git-toolsdir 1, vscode-userstate 1, ff-devedition 1, vscode-with-user 1 | Likely | no |

Classification in the terms of the task: A, E = (b) scorer or truth artefact; B = (b) scorer semantics, engine
correct; C, D = (c) correctly shown unticked; F = (a) real but minor and contained engine imprecision.
Nothing is (d) unclear.

### A. ff-reinstall: 7 Safe and preselected, 1 Likely

- snap 0 is taken after "install Firefox, launch, uninstall with its own uninstaller". So snap 0 already
  holds what Firefox leaves behind. Then Firefox is installed again and removed through the engine.
- The 7 Safe items: `AppBadgeUpdated|308046B0AF4A39CB`, `JumplistData|308046B0AF4A39CB` and
  `…;PrivateBrowsingAUMID`, `HKLM\SOFTWARE\Mozilla\Firefox`, `HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox`,
  `HKCU\Software\Mozilla\Firefox`, `ProgramData\Mozilla-…\updates\308046B0AF4A39CB`.
  `308046B0AF4A39CB` is the hash Firefox derives from `C:\Program Files\Mozilla Firefox`.
- Evidence: `HarvestedToken` (Tier A) + `InPreUninstallRefSnapshot` for the three values;
  `AppNamedKeyWithRootRef` (Tier A) + name evidence for the three keys; `HarvestedToken` + `TimeWindow` for
  the folder.
- Content check: `HKCU\Software\Mozilla\Firefox` holds only `Uninstalled-release` and per-path settings of
  `C:\Program Files\Mozilla Firefox\firefox.exe` in snap 0 and snap 2. No user data.
- **Rescore** with snap 0 and lists-0 of `x2-vlc` (same VM snapshot, same SID, no Firefox ever):
  danger 0, `danger_blocking` 0, `userdata_blocking` 0
  (`x2-scratch/ff-reinstall-cleans0.{json,md}`).
- Clean-base comparison (`r2-firefox`, m1a.5): same bands for the same targets. One difference:
  `JumplistData|…;PrivateBrowsingAUMID` is Likely there and Safe here, because here the value already
  existed when the reference snapshot was taken. It carries the app's own hash either way.
- The Likely item is `HKLM\SOFTWARE\Mozilla\MaintenanceService` (recorded deviation in DECISIONS).
- The two profile folders are in class C.
- Four delete-if-empty containers score `noop_would_be_danger` for the same reason. No action.

### B. Blocked: kept for the sibling (11)

- ff-esr and ff-devedition: `App Paths\firefox.exe` default value, `HKLM\…\Classes\Applications\firefox.exe`,
  `HKCU\Software\Mozilla\Firefox`, `HKLM\SOFTWARE\Mozilla\Firefox`, and on ff-esr also
  `HKLM\SOFTWARE\Mozilla\Mozilla Firefox`. Blocker `ReferencedByOtherApp` naming the sibling; text
  "Kept: still used by Mozilla Firefox ESR / Firefox Developer Edition".
- vscode-with-user: `HKCU_Classes\Applications\Code.exe` (the user install's key, unchanged in all snaps) and
  `HKCU_Classes\vscode\shell\open\command` default value. Blocker `ReferencedByOtherApp: Microsoft Visual
  Studio Code (User)`.
- The engine recognised the other owner and keeps the items. Intended behaviour. The scorer counts the
  read-only list as `danger_unticked`.

### C. User data, unticked (8)

- `%APPDATA%\Mozilla\Firefox` and `%LOCALAPPDATA%\Mozilla\Firefox`, 3 runs: Weak, blocker `UserData`.
  In ff-reinstall it is the first install's own profile. In ff-esr and ff-devedition the folder also holds
  the **sibling's live profile** (snap 2 of ff-esr: `ft2ctr9l.default-esr` next to the removed app's
  `b9i1ij1o.default-release`). See section 7, engine item 1.
- `%APPDATA%\Code`: Likely, blocker `UserData`. In vscode-userstate it holds the planted `settings.json` and
  snippets. In vscode-zipcopy the zip copy created it and still uses it.
- Not danger but also user data, unticked: `C:\Program Files\Microsoft VS Code` with the planted
  `my-workspace\notes.md` (Likely, blockers `UnmatchedChildren`, `UserData`), `%APPDATA%\Notepad++` with the
  planted macro export (Likely, `UserData`).

### D. git-userstate: 5 planted references (scorer class `preexisting_value_ref`)

`Run|GitAutoFetch`, `ContosoTools\Settings|GitExecutable`, `TortoiseGit|MSysGit`, `Environment|GIT_SSH`, and the
`Path` segment `C:\Program Files\Git\cmd` in `HKCU\Environment`. The user wrote them; all point into
`C:\Program Files\Git`, which is gone. Evidence `PointsIntoInstallRoot` + `DanglingRef` (+ reference
snapshot), capped to Tier B by `place: shared`. Text ends "nothing shows that Git put it there". Likely and
unticked is the right offer for a dead reference the app did not write.

Traps not taken: `Environment|DIGIT_HOME`, `Run|GitHubSync`, the planted `Git Bash.lnk` to PortableGit, the
planted `My Repos.lnk`, the empty `HKLM\…\Classes\.sh\OpenWithProgids`.

### E. vscode-zipcopy: `HKCU_Classes\vscode` (2)

- snap 0: `…\vscode\shell\open\command` = `"C:\Users\tester\Tools\VSCode\Code.exe" --open-url -- "%1"`
  (the zip copy registered the URL scheme when it was started).
- snap 1 and snap 2: `"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code\Code.exe" …`. The user
  install overwrote it; its uninstaller left it. It now points at a file that is gone.
- Offered: the value (Likely; `DanglingRef`, `place: shared`) and the key (Likely; CLS-PROTOCOL
  `ChainedRef`). Same pattern as `UFH\SHC|15` on the dirty base: the name existed, the content is the removed
  app's. Offering it unticked is desired. Removing it does not bring the zip copy's registration back; the
  zip copy writes it again on its next start.

### F. Really foreign, offered Likely and unticked (7)

| Run | Item | Whose it is | Evidence |
|---|---|---|---|
| npp-userfiles | `HKCU_Classes\Applications\notepad++.exe` | Planted. Its command runs `C:\Users\tester\Tools\npp-portable\notepad++.exe`, which exists in snap 2. Unchanged in all snaps | `ChainedRef` Tier B on the bare name `notepad++.exe` + name match, score 12 |
| npp-userfiles | `FileExts\.log\OpenWithList|a` (= `notepad++.exe`) | Planted, unchanged; resolves through the key above to the portable copy | `ChainedRef` Tier B, bare name |
| npp-userfiles | `FileExts\.log\OpenWithList|MRUList` segment `a` | Same entry in the order list | same |
| git-toolsdir | `HKCU\…\App Paths\rg.exe` | Planted. Points at `C:\Users\tester\Tools\ripgrep\rg.exe`, the user's tool inside the folder Git was installed into; the file exists in snap 2 | `ChainedRef` Tier B, "belongs to Git" |
| vscode-userstate | `HKCU_Classes\Applications\Code.exe` | Planted. Command names `C:\Users\tester\Tools\VSCode\Code.exe` (not on disk in this run) | `ChainedRef` Tier B, bare name |
| ff-devedition | `HKCU_Classes\Applications\updater.exe` | In snap 0, written by Developer Edition's updater; three flag values, no path | `ChainedRef` Tier B, bare name; no `ReferencedByOtherApp` although `firefox.exe` gets one |
| vscode-with-user | `HKCU_Classes\vscode` (key) | The still-installed user install's URL-scheme key. The removed system install overwrote its command (snap 0 user path, snap 1 and 2 `C:\Program Files\…`) | CLS-PROTOCOL `ChainedRef` Tier A + `TimeWindow`, score 6. Its own child value is Blocked "still used by VS Code (User)" |

- None is Safe, none preselected. Harm if a user ticks one: an "Open with" entry or an App Path of a tool
  that still works is lost; the registry action is reversible.
- The explanation text is wrong for these ("which belongs to Notepad++", "which belongs to Git").
- Cause, first five rows: `crates/purge-scan/src/reg_apppaths.rs` `exe_key`, lines 163 to 194. A
  `Classes\Applications\<exe>` key named like a main exe is listed with `ChainedRef(Tier B, exe)` even when no
  value in it leads into the app. `Foreign::in_walk` only knows registered apps, so a value that names a
  path outside every root of the app (the portable copy) raises nothing. `cls_fileexts.rs` does the same
  for `OpenWithList` by design (its header: "a bare exe name is a Tier B anchor, so these stay unticked").
  The `rg.exe` case is documented in the same file (`survived_unproven`: Tier B at most, never preselected).
- Last row: the key is Likely while a value below it is Blocked. A `DeleteKey` would take the kept value
  with it. The protocol scanner does not apply the `ReferencedByOtherApp` blocker that REF-ANY applies to
  the value.

## 2. ff-reinstall, ff-esr, ff-devedition

- **ff-reinstall (10):** reinstall residue, all Firefox's own. 7 Safe (class A), `MaintenanceService` key
  Likely, 2 profile folders Weak. With a clean snap 0 the count is 0.
- **ff-esr (7):** sibling product. 5 Blocked and kept for ESR, 2 shared profile folders Weak.
- **ff-devedition (7):** sibling product. 4 Blocked and kept, 2 shared profile folders Weak, 1 Likely
  (`Applications\updater.exe`, class F).
- The Safe items in the two sibling runs are scored as hits and are the removed install's alone:
  the values and the `updates` folder carry its path hash, and `HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox`
  is absent from snap 0 and holds only `TaskBarIDs|C:\Program Files\Mozilla Firefox` in snap 2.

## 3. Shared-value edits

Two `EditSegment` items in the 16 post plans (and one in the live plans, the same npp item). Both Likely,
not preselected, harm Medium, reversibility Full.

| Run | Value | Segment | Whole value in snap 2 | Whose text |
|---|---|---|---|---|
| git-userstate | `HKCU\Environment|Path` | `C:\Program Files\Git\cmd` | `%USERPROFILE%\AppData\Local\Microsoft\WindowsApps;C:\Program Files\Git\cmd` | Planted by the user, names Git's removed folder |
| npp-userfiles | `FileExts\.log\OpenWithList|MRUList` | `a` (index 0) | `a` | Planted; belongs to the portable copy (class F) |

- The target names exactly one segment. The other `Path` segment is not part of the item.
- `GIT_SSH` is a `DeleteValue` of the whole value, which is right: its whole content is the dead path.
- Not offered, correctly: the `Path` segment `C:\Users\tester\Tools\ripgrep` in git-toolsdir (inside Git's
  folder but alive), `DIGIT_HOME`.
- **Still not exercised: an edit of a segment the app itself wrote.** Git's own segment is in `HKLM …\Session
  Manager\Environment|Path` in snap 1 and the vendor uninstaller removes it (gone in snap 2), so the engine
  had nothing to offer there.
- M1a is a dry run. What the edit does when applied is not tested by this campaign.

## 4. Compared with x1 (m1a.4)

Plans compared item by item (target, band, preselection, action).

- No band moved up. No new foreign item.
- Gone in x2, all improvements, all in the runs' danger lists of x1:
  - vscode-userstate: `HKLM\…\Classes\.edn` and `.gemspec` (Safe and preselected in x1; planted empty keys)
    and `Applications\Code.exe\shell\open\command` default value (Likely).
  - vscode-zipcopy: `HKCU_Classes\.svg` (Safe and preselected in x1).
  - thunderbird: a bam value (Blocked).
- Otherwise only the random firewall rule GUIDs differ (ff-esr, ff-devedition, ff-tbafter). 10 of 16 plans are identical, 13 apart from those GUIDs.
- `danger_preselected`: x0 24, x1 9, x2 7. The 7 are ff-reinstall in all three.
- Positive detail in x2: `HKLM\…\Classes\.lua\OpenWithProgids` is Safe. The installer created that subkey
  (absent in snap 0, empty in snap 2); the planted `.lua` default `MyEditor.lua` is not touched.

## 5. Extra checks, footprint, winmerge

- **Live scan:** 16 of 16 pass. 0 Safe, 0 preselected. Install root Blocked on 14, absent on git-toolsdir
  and npp-userfiles (allowed).
- **Determinism:** `det_equal` true by `plan_hash` on all 16.
- **Inventory check:** all 32 exits 0.
- **Footprint** (Thunderbird in the plan of ff-tbafter): 0 shared items.
- **Sanity step:** 0 runs compared. Variants have no frozen truth, so it says nothing here.
- **winmerge offers 0:** old gap, not new. 0 in x0 and x1 too. The label file calls the app
  "out-of-sample, informational recall". Real leftovers a cleaner could reach: `JumplistData|
  Thingamahoochie.WinMerge` and `BackgroundAccessApplications\WinMerge_f62ztx9ss5ed4`. The fingerprint has
  0 tokens, so the app's AUMID and package family are not harvested. The rest is Prefetch, tile properties
  and bam, which no run covers. Recall work, not safety.

## 6. The Store self-update

- What happened: after the snapshot restore, Windows updated `Microsoft.Windows.Photos`
  (26.26090 to 2026.11090) with `VCLibs` and, in some runs, OneDrive (a per-user "Photos" ARP entry
  appears in 7 runs and is labelled `kept_owner`). It hit 9 of 16 runs at different points, which is why
  `truth_n` jumps to 460 to 1360 there. ff-reinstall has none: the update finished before snap 0.
- The ambient set is `truth/f0/ambient-f0.json`, built from another campaign's null runs. This campaign
  has no null runs, so the update is in nobody's ambient set. 5092 "leftover matches deny" warnings.
- **Danger is not affected.** Danger is computed from the offered items; no plan offers a package-store
  item, and every offered item scores hit or danger (0 `other`, 0 `ambient`).
- **Recall is useless as printed.** Without package-store items: git-toolsdir 0.4% becomes 9.3%,
  thunderbird 1.1% becomes 13.9%, vscode-upgrade 27.3% becomes 70.8%, vscode-userstate 30.7% becomes 75.3%.
  Do not quote the macro recall of this campaign (14.7%).
- What the pipeline should do: section 7, scorer items 3 to 5.

## 7. Bottom line

### Engine: nothing gate-blocking. Three items, in order of weight

1. **Shared profile folder with a sibling Firefox (before the m1a.6 band change ships).** With ESR or
   Developer Edition installed, `%APPDATA%\Mozilla\Firefox` and `%LOCALAPPDATA%\Mozilla\Firefox` hold the
   sibling's live profile. m1a.5 lists them Weak (hidden) with `UserData` and no `ReferencedByOtherApp`,
   while the registry keys of the same name are Blocked for the sibling. DECISIONS moves profile folders
   to Likely in m1a.6. That would show the sibling's profile for removal, unticked. Check the m1a.6
   re-plan of `x2-ff-esr` and `x2-ff-devedition`; the consistent result is Blocked "still used by …"
   (`crates/purge-scan/src/fs_appdata.rs`).
2. **Bare exe name with a foreign target** (class F rows 1, 2, 3, 5, 6).
   `crates/purge-scan/src/reg_apppaths.rs` `exe_key`: when the key is matched by name only and a value in
   it names a path outside the app's roots, do not list it, or list it Blocked. Same test for
   `OpenWithList` in `cls_fileexts.rs` (resolve the name through `Applications\<exe>` first). Removes 5 of
   the 7 foreign Likely items.
3. **Key offered while a value below it is Blocked** (`HKCU_Classes\vscode` in vscode-with-user): carry
   the child's `ReferencedByOtherApp` up to the key in the protocol scanner, or as a plan rule.

Items 2 and 3 can wait for M1b if DECISIONS is worded to allow foreign items in Likely. Item 1 should be
looked at with the m1a.6 re-plan, because that edit changes the band.

### Scorer and truth

1. **`vm/truth/mk_labels.py`, variant `ff-reinstall`, and `vm/truth/m1a.sh`:** score variants with
   `pre_uninstall` against a snap 0 and lists-0 that do not contain the first install (as
   `truth/footprint.sh` already does with `--s0` / `--lists0`), or add a `pre_snap` phase before the pre-app
   in `vm/guest/run-app.ps1`. Until then, record a waiver for the 7 in DECISIONS.
2. **`vm/rigtool/src/score.rs`:** the two changes already listed in the dirty review cover classes B and E
   here as well: Blocked items counted apart from `danger_listed`, and a `replaced_value` class for a value
   whose name existed and whose data the app changed (`…\vscode\shell\open\command`).
3. **`vm/guest/riglib.ps1` and `run-app.ps1`:** pause Store and OneDrive self-update before snap 0, next to
   `Suspend-EdgeUpdate`, and record in `run.json` whether the appx list is the same at the end (`held`).
4. **`vm/rigtool/src/truth.rs`:** a package whose family is in lists-0 and whose full name differs in
   lists-2 updated itself: label its items `ambient`. Label a leftover that matches the deny list `ambient`
   too and report the count, instead of one warning line per item.
5. **Campaign scripts (`~/purge-target/campaigns/cleanpro-ext.sh`):** run null runs inside the extended
   campaign and build the ambient set from them, as the gate campaigns do.
6. **`docs/DECISIONS.md` and `vm/RIG.md` §7:** state one criterion. Today: "nothing foreign Safe or
   preselected" (met, given the ff-reinstall waiver) and "no foreign item in Safe or Likely" (not met: 7).

### Not checked

- The m1a.6 re-plan of these captures.
- Why `updater.exe` gets no `ReferencedByOtherApp` when `firefox.exe` does.
- What an `EditSegment` does when applied (M2).
- `vm/runs/x2-nb-*` (another campaign, in progress during this review).

## Appendix: all 41 danger items

`<SID>` = `S-1-5-21-1871224937-2691627691-3762806239-1000`. P = preselected.

| # | Run | Target | Band | P | Class |
|---:|---|---|---|---|---|
| 1 | git-toolsdir | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe` (key) | Likely | no | F |
| 2 | git-userstate | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch` | Likely | no | D |
| 3 | git-userstate | `HKU\<SID>\Software\ContosoTools\Settings|GitExecutable` | Likely | no | D |
| 4 | git-userstate | `HKU\<SID>\Software\TortoiseGit|MSysGit` | Likely | no | D |
| 5 | git-userstate | `HKU\<SID>\Environment|GIT_SSH` | Likely | no | D |
| 6 | git-userstate | `HKU\<SID>\Environment|Path` segment `C:\Program Files\Git\cmd` | Likely | no | D |
| 7 | vscode-userstate | `HKU\<SID>_Classes\Applications\Code.exe` (key) | Likely | no | F |
| 8 | vscode-userstate | `C:\Users\tester\AppData\Roaming\Code` | Likely | no | C |
| 9 | vscode-zipcopy | `HKU\<SID>_Classes\vscode\shell\open\command|(default)` | Likely | no | E |
| 10 | vscode-zipcopy | `HKU\<SID>_Classes\vscode` (key) | Likely | no | E |
| 11 | vscode-zipcopy | `C:\Users\tester\AppData\Roaming\Code` | Likely | no | C |
| 12 | npp-userfiles | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a` | Likely | no | F |
| 13 | npp-userfiles | `…\FileExts\.log\OpenWithList|MRUList` segment `a` | Likely | no | F |
| 14 | npp-userfiles | `HKU\<SID>_Classes\Applications\notepad++.exe` (key) | Likely | no | F |
| 15 | ff-esr | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|(default)` | Blocked | no | B |
| 16 | ff-esr | `HKLM\SOFTWARE\Classes\Applications\firefox.exe` (key) | Blocked | no | B |
| 17 | ff-esr | `HKU\<SID>\Software\Mozilla\Firefox` (key) | Blocked | no | B |
| 18 | ff-esr | `HKLM\SOFTWARE\Mozilla\Firefox` (key) | Blocked | no | B |
| 19 | ff-esr | `HKLM\SOFTWARE\Mozilla\Mozilla Firefox` (key) | Blocked | no | B |
| 20 | ff-esr | `C:\Users\tester\AppData\Local\Mozilla\Firefox` | Weak | no | C |
| 21 | ff-esr | `C:\Users\tester\AppData\Roaming\Mozilla\Firefox` | Weak | no | C |
| 22 | ff-devedition | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|(default)` | Blocked | no | B |
| 23 | ff-devedition | `HKLM\SOFTWARE\Classes\Applications\firefox.exe` (key) | Blocked | no | B |
| 24 | ff-devedition | `HKU\<SID>\Software\Mozilla\Firefox` (key) | Blocked | no | B |
| 25 | ff-devedition | `HKLM\SOFTWARE\Mozilla\Firefox` (key) | Blocked | no | B |
| 26 | ff-devedition | `HKU\<SID>_Classes\Applications\updater.exe` (key) | Likely | no | F |
| 27 | ff-devedition | `C:\Users\tester\AppData\Local\Mozilla\Firefox` | Weak | no | C |
| 28 | ff-devedition | `C:\Users\tester\AppData\Roaming\Mozilla\Firefox` | Weak | no | C |
| 29 | vscode-with-user | `HKU\<SID>_Classes\vscode\shell\open\command|(default)` | Blocked | no | B |
| 30 | vscode-with-user | `HKU\<SID>_Classes\Applications\Code.exe` (key) | Blocked | no | B |
| 31 | vscode-with-user | `HKU\<SID>_Classes\vscode` (key) | Likely | no | F |
| 32 | ff-reinstall | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` | Safe | **yes** | A |
| 33 | ff-reinstall | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` | Safe | **yes** | A |
| 34 | ff-reinstall | `…\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` | Safe | **yes** | A |
| 35 | ff-reinstall | `HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox` (key) | Safe | **yes** | A |
| 36 | ff-reinstall | `HKU\<SID>\Software\Mozilla\Firefox` (key) | Safe | **yes** | A |
| 37 | ff-reinstall | `HKLM\SOFTWARE\Mozilla\Firefox` (key) | Safe | **yes** | A |
| 38 | ff-reinstall | `HKLM\SOFTWARE\Mozilla\MaintenanceService` (key) | Likely | no | A |
| 39 | ff-reinstall | `C:\Users\tester\AppData\Local\Mozilla\Firefox` | Weak | no | C |
| 40 | ff-reinstall | `C:\Users\tester\AppData\Roaming\Mozilla\Firefox` | Weak | no | C |
| 41 | ff-reinstall | `C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB` | Safe | **yes** | A |

Runs with 0 danger: git-upgrade, thunderbird, ff-tbafter, vscode-insiders-pair, vscode-upgrade, vlc, winmerge.
