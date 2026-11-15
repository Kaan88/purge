# Dirty-base campaign f2d: review of the danger counts

Reviewed 2026-11-15. Engine msvc 1d7524d4cd0c, policy m1a.5 (confirmed in every `plan-purge.scan.json`).
Runs `vm/runs/f2d-*`, scores `vm/truth/f2d/`. Read-only review; one scratch rescore in
`/home/kaan/purge-target/gate/f2d-scratch/`.

## Verdict

**No engine safety fault. Nothing has to change in the engine for the M1a gate.**

- There are **7** danger items, not 8 (vscode-user 4, git 1, npp 1, vlc 1; 8 was the f1d count).
- **None is Safe and none is preselected.** `danger_presel` is 0 and `danger_blocking` is 0 on every run.
- 4 of the 7 are **Blocked** (the read-only "kept" list). They are the still-installed system VS Code's
  items, and the engine keeps them.
- 3 of the 7 are the same value, `UFH\SHC|15`, **Likely and unticked**. At scan time it holds the removed
  app's own shortcut record. The scorer flags it only because the value *name* existed before the install.
- By the rule RIG.md §7 sets for extra campaigns (blocking = Safe or preselected), the campaign passes.
  By the literal clean-gate wording (`danger_listed = 0`) it does not, and the reason is how the scorer
  counts, not what the engine does.
- What should change is in the **scorer and truth set** (section 6). Two engine items are optional
  hardening and recall work, not gate conditions.

The runs are valid: every uninstall exited 0, `entry_gone` is true, `verify_gone.passed` is true, and all
21 phases are ok in each app run.

## 1. The danger items

All seven existed by name in snap0 of their run. All were also present with engine m1a.4 (f1d).

| # | Run | Target | Band | Presel. | In snap0 | Class |
|---|---|---|---|---|---|---|
| 1 | vscode-user | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56` value `ApplicationUserModelId` | Blocked | no | yes, unchanged | (a) minor, contained |
| 2 | vscode-user | same key, value `PackageRelativeApplicationId` | Blocked | no | yes, unchanged | (a) minor, contained |
| 3 | vscode-user | `HKLM\SOFTWARE\Classes\PackagedCom\Package\Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe\Server\0` value `ApplicationId` | Blocked | no | yes, unchanged | (a) minor, contained |
| 4 | vscode-user | key `HKLM\SOFTWARE\Classes\Applications\Code.exe` | Blocked | no | yes, unchanged | (b) scorer semantics |
| 5 | git | `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\UFH\SHC` value `15` | Likely | no | name yes, data different | (b) scorer artefact |
| 6 | npp | same value `15` | Likely | no | name yes, data different | (b) scorer artefact |
| 7 | vlc | same value `15` | Likely | no | name yes, data different | (b) scorer artefact |

### Items 1 to 3: package-store values of the system VS Code

- **Whose they are.** dirty-base has the *system* VS Code 1.146.0 installed, with its sparse package
  `Microsoft.VisualStudioCode`. The run installs VS Code (User) on top and removes only that. In snap2 the
  package is still there, with external location `C:\Program Files\Microsoft VS Code\...\appx`. These
  values describe that package. They are not the user install's.
- **Evidence the engine gave.** One piece each: `InPreUninstallRefSnapshot`, Tier B, weight 8, anchor
  `vscode`, `anchor_kind: id`. The user install's only ProgID anchor is its URL scheme `vscode`, and it
  matches the package's application id `VSCode` by name.
- **Why Blocked.** `TrustedInstallerOwned` plus `DenyListed kb.package-store-state-repository` (items 1,
  2), `DenyListed reg.packagedcom` (item 3). Explanation shown: "Kept: owned by Windows · Kept: protected
  location".
- **Classification.** A real misattribution, but a weak one and fully contained. The plan names VS Code
  (User) as owner of another product's values. The engine does not recognise them as the other app's
  (no `ReferencedByOtherApp`); only the location rules keep them. Nothing can be removed.
- **m1a.4.** Same three, plus `...\Data\56|_IndexKeys` (Blocked), which m1a.5 no longer lists.

### Item 4: `Classes\Applications\Code.exe`

- Points at `C:\Program Files\Microsoft VS Code\Code.exe`, the system install. Unchanged in all snaps.
- Evidence: REG-APPPATHS `ChainedRef` on the bare name `Code.exe`, Tier B, weight 5.
- Blocker: `ReferencedByOtherApp: Microsoft Visual Studio Code`. Explanation: "Kept: still used by
  Microsoft Visual Studio Code".
- The engine identified the other owner and kept the key. This is the intended behaviour. The scorer
  counts any listed item as danger, including the read-only Blocked list.
- m1a.4: identical.

### Items 5 to 7: `UFH\SHC|15`

- **snap0:** value `15` holds the record of `Visual Studio 2022\...\Developer PowerShell for VS 2022.lnk`
  (VS Build Tools, part of dirty-base). The list has names 0, 1, 3 to 15: fifteen values, no `2`.
- **snap1 (after install, before any engine action):** Windows has overwritten `15` with the new app's
  first shortcut record (`Git Bash.lnk`, `Notepad++.lnk`, `VLC ... reset preferences.lnk`) and appended
  16 and 17. Explorer writes at index = value count, which collides because of the hole at 2.
- **snap2:** unchanged from snap1. The VS record was already lost at install time, by Windows.
- **Evidence:** `InPreUninstallRefSnapshot`, `PointsIntoInstallRoot` and (git, vlc) `DanglingRef`, all
  capped to Tier B with `place: shared`. Explanation ends "In a place other software and you also write
  to; nothing shows that Git put it there". Hence Likely, unticked.
- **Why it is an artefact.** The scorer's rule is "a RegValue whose name existed in snap0". It does not
  compare data. The truth file of the same run lists this value as `RegValueChanged`, label `leftover`.
  So truth calls it the app's leftover and the score calls offering it danger.
- **Is offering it desired?** Yes. Deleting it removes the app's dangling record. It cannot bring back
  the VS record. Unticked is the right band for a shared list.
- **History.** f0d (m1a.3): Safe and preselected, `danger_presel` 1 on git, npp, vlc. f1d (m1a.4) and f2d
  (m1a.5): Likely, unticked. The earlier change already took it out of the preselection.

## 2. Recall

### vscode-user: 8 offered of 186 (clean base: 147 of 163)

The engine refuses correctly. Nothing is broken, but the run is not comparable with the clean one.

- Uninstall ran and was verified. Fingerprint is complete: 1 InstallRoot, 32 exes, 3711 Inno records.
- **Cause.** The fingerprint's ProgID set has 1 entry (`vscode`) instead of 144. The 143 `VSCode.<ext>`
  ProgIDs also exist in `HKLM\SOFTWARE\Classes`, where their commands run the system install's
  `Code.exe`. The harvest rule (anchors.rs: every verb command in every Classes root must run the app)
  drops them as shared. With no ProgIDs, the extension journal is empty (0 entries, 142 on clean).
- **What is missed.**
  - 142 empty `HKU\<SID>_Classes\.<ext>\OpenWithProgids` skeleton keys. These are the user install's own
    residue and harmless to remove. This is the whole gap to the clean result.
  - 27 `%APPDATA%\Code\*` items and `.vscode`: shared with the installed system VS Code. Refusing is right.
  - Temp files, Prefetch, jump list: not covered on the clean base either (Path recall 1/14 there).
- The live scan offered the sparse package as Likely while the user install held its registration. The
  post scan no longer offers it, which is right: it is the system install's again.

### Other apps

| App | Offered clean / dirty | truth_n clean / dirty | Reason for lower recall |
|---|---|---|---|
| firefox | 20 / 14 | 25 / 33 | Thunderbird in dirty-base: 6 shared Mozilla items correctly not offered (same 14 as clean `firefox-tb`). Denominator inflated by OS noise. |
| git | 4 / 5 | 17 / 27 | Same plan (SHC indexes shifted). Denominator +10, almost all OS noise. |
| npp | 2 / 3 | 28 / 33 | Same plan plus `SHC|15`. Denominator +5 noise. |
| vlc | no clean run | – / 17 | No reference. One truth item is the bam value (section 4). |

For git, npp and vlc the engine offers the same things as on the clean base. The lower percentages come
from the truth denominators.

## 3. The 50 sanity differences

The check compares against the frozen M0 truth, which was recorded on **rig-base**. On dirty-base
differences are expected by construction. Only firefox, git and npp have frozen truth; vscode-user and
vlc were not checked at all. The report lists 52 items for a residual of 50, because the count is taken
after normalising names.

| Group | Count (of the 52 listed) | Items |
|---|---|---|
| OS noise not in the 2-run ambient set | 23 | Census ×4, `AppCompatFlags\|PatchDbUpdateTickCount`, `InstallService\State`, `OneSettings ...\|RefreshAfter` (firefox, git); `hivelist\|...COMPONENTS`, `AppListBackup` ×2 (firefox, git); `DeliveryOptimization\|CPUpct`; `HKU\.DEFAULT ...FileExts\.html`; `Bags\1\Desktop\|IconLayouts` |
| dirty-base residue | 21 | Thunderbird already owns `HKCU\Software\Mozilla`, `Mozilla\MaintenanceService`, 3 Interface keys and the `.shtml` default and `Content Type`, so they are not new (frozen only) and `Mozilla\Firefox`, `CLSID\{1814...}\InprocServer32` changed, `MozillaMaintenanceService\|EstimatedSize`, `maintenanceservice_tmp.exe` appear instead; `SHC` 1, 2 became 16, 17; two random-GUID `CLSID` keys with only an `AppID` value per run ×3 apps |
| App or run behaviour | 8 | Temp files (`*.tmp`, one zip); Prefetch `git.exe`/`cygwin-console-helper` absent this run; one UserAssist value |
| Truth-set problem | (overlaps) | The random CLSID keys appear in both null runs too, but the ambient set stores them as exact names, so each app run labels its own pair `leftover`. The firefox run uses `firefox.json`, which has no Thunderbird `kept_owner` rules. |

**Was accepting justified?** In outcome, yes: none of the 50 touches danger scoring. Danger comes from
snap0 existence, deny and `kept_owner`; the residuals only move `leftover` counts, so recall. In
procedure, no: it was accepted unread, and for a dirty-base run the check answers the wrong question.

Cross-check: I rescored f2d-firefox with `firefox-tb.json` (Thunderbird rules). Result: kept_owner 2,
truth 31, offered 14, **danger 0**. Files in `/home/kaan/purge-target/gate/f2d-scratch/`.

## 4. The bam warning

Harmless for safety. It is a truth-set gap.

- The warning is from `rigtool truth`: a `leftover` item matches the deny list. The engine did not offer it.
- Cause: the bam rule ("execution record kept by the bam driver", label `ambient`) is a hand rule in the
  per-app label files. `vlc.json` (generated from `NEW_BASES` in `mk_labels.py`) does not have it. The
  other four runs label their bam values `ambient`.
- Effect: vlc `truth_n` is 17 instead of 16, with one item no cleaner may reach. Recall 3/16 = 18.8%
  instead of 17.6%.

## 5. Extra checks

All pass on all five runs.

- **Live scan:** 0 Safe, 0 preselected. Install root Blocked on firefox, vscode-user, git, vlc; absent
  from the plan on npp (allowed by the criterion; the live npp plan has only 9 items).
- **Determinism:** `det_equal` true by `plan_hash` on every run; the file hashes of plan a and b match.
- **Inventory check:** all ten invdiff exits are 0.

## 6. What should change

### Scorer and truth (needed before a dirty-base pass is used as a gate)

1. **`vm/rigtool/src/score.rs`, `eval_item` / `danger_class`.** A `RegValue` offer whose name existed in
   snap0 but whose data differs in snap2, where truth holds a `RegValueChanged` leftover for it: give it
   its own reporting class (for example `replaced_value`, next to `preexisting_value_ref`), listed with
   before and after. Do not turn it into a plain hit: deleting a changed value does not restore the old
   one, so it should stay reviewed by hand, and stay blocking when Safe or preselected.
2. **Same file, counting.** Report Blocked items that match the danger test separately from
   `danger_listed` (the Blocked list is read-only), or state in RIG.md §7 and the gate text that the
   dirty-base criterion is `danger_blocking = 0`, not `danger_listed = 0`. One of the two; today the
   documents disagree.
3. **`vm/truth/mk_labels.py`.** Move the bam rule into `_os.json`, so vlc, thunderbird and winmerge get it.
4. **`vm/truth/labels/_os-servicing.json`.** Add the noise families of section 3 (Census, AppListBackup,
   `hivelist|...COMPONENTS`, `PatchDbUpdateTickCount`, `InstallService\State`, OneSettings, Bags
   `IconLayouts`).
5. **`vm/rigtool/src/ambient.rs`.** Generalise a GUID-named key that appears with a different GUID in
   every null run into a pattern (the per-boot `CLSID\{guid}` + `AppID` keys).
6. **Labels on dirty-base.** Score firefox with the Thunderbird `kept_owner` rules (`firefox-tb.json`), and
   give vscode-user a variant that marks the system VS Code as kept owner.
7. **`vm/truth/m1a.sh`.** Skip the frozen-truth sanity step for runs that are not from rig-base, instead
   of overriding it with `--accept-sanity-diff`.

### Engine (optional, not a gate condition)

- **Noise and attribution.** A value whose only evidence is an id-only Tier B ref-snapshot hint and that
  sits in a deny-listed package store need not be listed at all (`add_value_evidence` in
  `crates/purge-scan/src/reg_software.rs`, `in_ref_snapshot` in `crates/purge-scan/src/framework.rs`).
  That removes items 1 to 3. It also closes the dependency on the location rule: the same hint outside a
  protected location would be listed Likely.
- **Recall with a sibling install.** The 142 empty HKCU `.ext\OpenWithProgids` keys could be attributed
  through the Inno log, which records the user install's `RegDeleteValue` on exactly those keys
  (`crates/purge-harvest/src/assoc.rs`, extension journal). Worth about 76 points of recall on this run.

### Not checked

- Why npp's `SHC|15` has no `DanglingRef` although `notepad++.exe` is gone in snap2 (band unaffected).
- What creates the two random CLSID keys per boot on dirty-base (Steam is the likely source; not verified).
