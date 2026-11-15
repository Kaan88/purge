# M1a gate, campaign `r2-`: bands review

Reviewer scope: the band of every item in the seven r2 plans, judged against the snapshots. The numeric criteria are in `score-review-r2.md` and are not repeated.

## Verdict

**PASS WITH NOTES.**

- **Safety invariant: met, with no exception.** All 299 Safe items in the seven plans are provably the app's. No item that existed before the install is offered in any band. No user data is preselected. No value is offered whole while holding foreign text.
- **Two Firefox band targets written in gate section D are still not met, both by under-banding** (profiles Weak instead of Likely; Maintenance Service key Likely instead of Safe). Under the rule given for this review they are not failures. Under the literal section D text they are, and the first gate failed on the same two points. They need a fix or a recorded deviation before the gate is declared passed.
- **Shared-value edits were not exercised.** No r2 plan contains an edit action; the vendor uninstallers removed every PATH segment and list value. The gate data gives no evidence for or against point 2.

Judged as captured: policy `m1a.5` in all seven sidecars. Source was read for the rules only (`crates/purge-policy/src/band.rs` already says `m1a.6`).

## How each item was checked

For every item in every `plan-purge.scan.json` I looked up the target in snap0, snap1 and snap2 of the same run:

- present in snap0 or not (was it there before the install);
- for keys and folders, everything under the target in snap2, and whether any of it existed in snap0;
- for values, the data in all three snapshots.

`plan-purge.json` agrees with the sidecar on target, band and preselection for all 326 items. `plans/purge.json` is the same plan with the action added by `m1a.sh`.

## Band counts

| Run | Items | Safe (preselected) | Likely | Weak | Blocked | Absorbed into a parent |
|---|---:|---:|---:|---:|---:|---:|
| vscode | 139 | 136 | 3 | 0 | 0 | 105 |
| vscode-user | 147 | 143 | 3 | 0 | 1 | 142 |
| git | 4 | 2 | 2 | 0 | 0 | 2 |
| firefox | 20 | 10 | 5 | 4 | 1 | 7 |
| firefox-tb | 14 | 8 | 1 | 4 | 1 | 7 |
| npp | 2 | 0 | 2 | 0 | 0 | 0 |
| 7zip | 0 | 0 | 0 | 0 | 0 | 0 |

Preselected equals Safe in every run. Every preselected item has Tier A evidence, no blocker, and a category other than UserData or System. The null runs produce no plan.

## Per app

### VS Code system (r2-vscode)

| Item | Band, action | Snapshot check | Judgement |
|---|---|---|---|
| 105 × `HKLM\SOFTWARE\Classes\.<ext>` | Safe, DeleteKey, ProvenOwnedSkeleton | All absent from snap0. In snap2 each holds one empty `OpenWithProgids` subkey and no value | Correct |
| 30 × `HKLM\SOFTWARE\Classes\.<ext>\OpenWithProgids` (the `.ext` key is Windows') | Safe, DeleteKey, ProvenOwnedSkeleton | The subkey is absent from snap0 and empty in snap2. The parent `.ext` is not offered | Correct |
| `HKCU_Classes\vscode\shell\open\command : (default)` | Safe, DeleteValue | Absent from snap0. Data: `"C:\Program Files\Microsoft VS Code\Code.exe" --open-url -- "%1"` | Correct; the whole value is the app's |
| `HKCU_Classes\vscode : (default)` = `URL:vscode` | Likely | Absent from snap0 | Correct (cautious) |
| `HKCU_Classes\vscode` key | Likely, DeleteKey | Absent from snap0; 3 subkeys, 3 values, all VS Code's | Cautious; see notes |
| `%APPDATA%\Code` | Likely, Quarantine, blocker UserData, not preselected | Absent from snap0 | Correct |

The alias duplicates of the first gate (`WOW6432Node\Classes\…`, 135 extra items) are gone.

### VS Code user (r2-vscode-user)

| Item | Band, action | Snapshot check | Judgement |
|---|---|---|---|
| 142 × `HKCU_Classes\.<ext>` | Safe, DeleteKey, ProvenOwnedSkeleton | All absent from snap0; each holds one empty `OpenWithProgids` in snap2 | Correct |
| `HKCU_Classes\Applications` | Blocked (deny-listed) | Absent from snap0, empty | Correct |
| `vscode` protocol value, key, default value; `%APPDATA%\Code` | as in the system run | as in the system run | Correct |

### Git (r2-git)

| Item | Band, action | Snapshot check | Judgement |
|---|---|---|---|
| `HKLM\SOFTWARE\Classes\LibraryFolder\background\shell` | Safe, DeleteKey, ProvenOwnedSkeleton | Absent from snap0, empty in snap2 | Correct |
| `HKLM\SOFTWARE\Classes\sh_auto_file` | Safe, DeleteKey, ProvenOwnedSkeleton + Inno manifest | Absent from snap0. snap2: `shell`, `shell\open`, `ShellEx`, no values | Correct |
| `HKCU\…\UFH\SHC : 1` and `: 2` | Likely, DeleteValue | Absent from snap0. Data names only `Start Menu\Programs\Git\*.lnk` and `C:\Program Files\Git\*.exe` | Correct. Value `0`, which existed before, is not offered |

### Firefox alone (r2-firefox)

| Item | Band, action | Snapshot check | Judgement |
|---|---|---|---|
| `HKLM\SOFTWARE\Mozilla\Firefox`, `HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox`, `HKCU\Software\Mozilla\Firefox` | Safe, DeleteKey | Absent from snap0. Content: `TaskBarIDs`, launcher and skeleton-UI settings keyed by the install path | Correct |
| `HKLM\SOFTWARE\WOW6432Node\Mozilla`, `HKCU\Software\Mozilla` | Safe, RemoveDirIfEmpty, EmptyAfterPlan | Absent from snap0; the only child is the Safe `Firefox` key | Correct (delete-if-empty only) |
| `C:\ProgramData\Mozilla-<guid>\updates\308046B0AF4A39CB` | Safe, Quarantine, HarvestedToken | Absent from snap0; holds `parent.lock` | Correct; first-gate failure fixed |
| `C:\ProgramData\Mozilla-<guid>\updates` | Safe, RemoveDirIfEmpty | Absent from snap0; only child is the folder above | Correct |
| `AppBadgeUpdated : 308046B0AF4A39CB`, `JumplistData : 308046B0AF4A39CB` | Safe, DeleteValue | Absent from snap0; named by the install hash | Correct |
| `CLSID\{1814CEEB-…}\InProcServer32 : (default)` | Safe, DeleteValue | Absent from snap0; data `C:\Program Files\Mozilla Firefox\AccessibleMarshal.dll`, which is gone | Correct here (no other Mozilla product) |
| Three `Interface\{…}\ProxyStubClsid32 : (default)` | Likely, not preselected | Absent from snap0 | Correct; first-gate failure fixed |
| `JumplistData : 308046B0AF4A39CB;PrivateBrowsingAUMID` | Likely | Absent from snap0 and snap1 | Cautious |
| `HKLM\SOFTWARE\Mozilla\MaintenanceService` | **Likely**, DeleteKey, score 4 | Absent from snap0; one value `Attempted=1`. The service and its folder are gone, and `engine-run.json` lists the service as co-removed | **Under-banded**; section D expects Safe |
| `%APPDATA%\Mozilla\Firefox` (profiles, 715 entries) | **Weak**, Quarantine, blocker UserData, not preselected | Absent from snap0 | Preselection correct. **Band under section D should be Likely**; Weak is hidden |
| `%LOCALAPPDATA%\Mozilla\Firefox` (160 entries, cache) | Weak, Quarantine, blocker UserData, not preselected | Absent from snap0 | Preselection correct; hidden |
| `%APPDATA%\Mozilla`, `%LOCALAPPDATA%\Mozilla` | Weak, RemoveDirIfEmpty | Absent from snap0 | Correct (delete-if-empty only) |
| Firewall rule value | Blocked (deny-listed) | Path is `ControlSet001`, not captured | Correct |

Not offered: `HKLM\SOFTWARE\Mozilla` (holds the image's `NativeMessagingHosts`), which is correct. `HKLM\SOFTWARE\mozilla.org` and `C:\ProgramData\Mozilla-<guid>` are no longer offered at all (missed, not a band problem).

### Firefox with Thunderbird (r2-firefox-tb)

| Point | Finding | Judgement |
|---|---|---|
| Anything that existed in snap0 | None of the 14 targets is in snap0 | Pass |
| Anything of Thunderbird's | No target names Thunderbird or lies under a Thunderbird key or folder | Pass |
| `CLSID\{1814CEEB-…}\InProcServer32` (snap0: Thunderbird's DLL; snap1 and snap2: Firefox's path) | Not offered | Pass; first-gate danger item fixed |
| Three `Interface\…\ProxyStubClsid32` values (unchanged across all three snapshots) | Not offered | Pass; first-gate danger items fixed |
| `HKCU\Software\Mozilla` (holds `Thunderbird\Installer`) | Not offered | Pass; first-gate danger item fixed |
| `HKLM\SOFTWARE\Mozilla`, `…\MaintenanceService`, the service and its folder (still installed for Thunderbird) | Not offered | Pass |
| `Mozilla\Firefox` keys (three), `updates\<hash>`, `AppBadgeUpdated`, `JumplistData` | Safe, as in the alone run; all absent from snap0 | Pass |
| `HKLM\SOFTWARE\WOW6432Node\Mozilla` | Safe, RemoveDirIfEmpty. Absent from snap0; Thunderbird (x64) never wrote there; only child is Firefox's key | Pass, see note 3 |
| `C:\ProgramData\Mozilla-<guid>\updates` | Safe, RemoveDirIfEmpty. Absent from snap0; only child is Firefox's hash folder | Pass, see note 3 |
| Profiles and vendor folders under `%APPDATA%` and `%LOCALAPPDATA%` | Weak, not preselected, as in the alone run; absent from snap0 (Thunderbird was not launched) | Preselection pass; band as above |

### Notepad++ (r2-npp)

| Item | Band, action | Judgement |
|---|---|---|
| `HKLM\SOFTWARE\WOW6432Node\Notepad++` | Likely, DeleteKey. Absent from snap0; one value `InstallerLanguage`. Evidence is name-based only (no Tier A) | Correct. The first gate's unworkable delete-if-empty is fixed |
| `AppxPackage NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` | Likely, RemovePackage, blocker ReversibilityNone | Correct |
| `Notepad.lnk` | Not offered | Correct |

### 7-Zip (r2-7zip)

Empty plan, as described. Defender's `{042D2B7D…}` is therefore not listed. `HKCU\Software\7-Zip` is a missed leftover (M1b).

## The points to judge

1. **Every Safe item provably the app's?** Yes, 299 of 299. Nothing to demote.
2. **Edits of shared values.** None in any plan. All actions are DeleteKey, DeleteValue, Quarantine, RemoveDirIfEmpty or RemovePackage. Machine and user `Path` in snap2 carry no app segment in any run; no Run, App Paths or association-list value naming an app is left. Not exercised.
3. **Firefox.** Maintenance Service key: Likely alone, not offered with Thunderbird. Profiles: Weak with a UserData blocker, never preselected. Nothing shared with Thunderbird is offered in any band; the two Safe vendor containers in firefox-tb did not exist before Firefox and hold only Firefox's items.
4. **User data.**
   - `%APPDATA%\Code`: Likely, not preselected, in both VS Code runs.
   - `~\.vscode`, `~\.vscode-shared`, `~\.copilot`: left behind, not offered in any band.
   - `.gitconfig`: the rig does not create one. Not exercised.
   - `%APPDATA%\Notepad++`: removed by the vendor uninstaller. Not exercised.
5. **Over-caution:** see notes 4 and 5.
6. **Known and accepted.**
   - (a) Waiver: no instance in r2. No offered `.ext` key existed in snap0.
   - (b) 7-Zip plan empty: confirmed.
   - (c) Whole value with foreign text: no instance. The six Safe DeleteValue items across the plans hold only a hash-named flag, a timestamp, one DLL path, or the app's own command line.

## First-gate failures, checked on r2

| First-gate finding | r2 |
|---|---|
| ISimpleDOM values Safe and preselected | Fixed: Likely alone, not offered with Thunderbird |
| Shared CLSID value preselected in firefox-tb | Fixed: not offered |
| `HKCU\Software\Mozilla` listed in firefox-tb | Fixed: not offered |
| `updates\<hash>` Likely | Fixed: Safe |
| Alias keys offered twice | Fixed |
| Notepad++ key offered with an action that cannot succeed | Fixed: Likely, DeleteKey |
| Maintenance Service key Likely | **Open** |
| Profiles Weak | **Open** |

## Must fix

None on safety.

## Must decide before the gate is declared passed

1. **Firefox profiles are in the hidden band.** `%APPDATA%\Mozilla\Firefox` scores −1 (ProductSubfolderOfVendor +3, ExecutablesPresent −4) and `%LOCALAPPDATA%\Mozilla\Firefox` scores 3, so both fall below Likely. Section D and §1.4 say Likely, and §1.4 says every truth item is visible. Either raise a UserData folder that has product-level evidence to at least Likely in m1a.6, or record the deviation in `docs/DECISIONS.md`.
2. **Maintenance Service key is Likely, section D says Safe.** The engine knows the service was co-removed (`co_removed` in `engine-run.json`) but gives the key no Tier A evidence from that. Fix or record.

## Notes

3. **Safe delete-if-empty on vendor containers.** `WOW6432Node\Mozilla`, `HKCU\Software\Mozilla` and `updates` are preselected on VendorContainer + EmptyAfterPlan. That is safe only because the action re-checks emptiness at execution. Worth one executor test in M2 with a foreign child added between plan and execution.
4. **Items that could be Safe** (not failures):
   - Git `UFH\SHC` values `1` and `2` (score 21, all Tier B);
   - Firefox `JumplistData : 308046B0AF4A39CB;PrivateBrowsingAUMID` (HarvestedToken alone, score 7);
   - `HKCU_Classes\vscode` key. Its command value is Safe while the key is Likely, so the default selection leaves a protocol key without a command.
5. **Blocked by design:** Firefox's own firewall rule, under the `HKLM\SYSTEM` deny rule.
6. **Not exercised by r2** (no leftover existed, so the band is unproven):
   - VS Code: OpenWithProgids values, ApplicationAssociationToasts values, PATH segment, sparse package;
   - Git: PATH, `.gitconfig`;
   - Firefox: ProgIDs, `StartMenuInternet`, toast AUMID, Default Browser Agent task, Maintenance Service folder and service, `plugin-container.exe` value;
   - Notepad++: `%APPDATA%\Notepad++`;
   - any edit of a shared value.
7. **Missed, safe:** `HKLM\SOFTWARE\mozilla.org`, `C:\ProgramData\Mozilla-<guid>` (offered in the first gate, not now), `ShimInclusionList\false`, `.vscode*` and `.copilot`, Prefetch, jump lists, temp files.
8. **VS Code's uninstaller left a trailing `;` on the machine `Path`.** Not an engine matter; mentioned in case the PATH scanner later treats an empty segment as its own.

Working files of this review: `/tmp/claude-1000/-mnt-C-Users-kaank-Desktop-uninstall-purge/2a88ab4a-cd5b-4ff0-bb84-ac5184aaad71/scratchpad/gate/bands/` (`dump.py`, `verify.py`, per-run outputs).
