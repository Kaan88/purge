# M1a gate report (R0, post-uninstall)

- Date: 2026-11-13
- Engine commit: `9d4b906` (branch `m1a`), `target\release\purge-engine.exe` built 2026-11-13 00:27:18,
  SHA-256 `3F94999F4F61D453C3F5F34BE3ED1D04D32E7942EDC595B3D7E67C4EDD87A509`. `crates/` and `bins/` have no
  uncommitted changes. Policy version in every plan: `m1a.2`.
- VM `Inbound-Win11-Test`, snapshot `rig-base`, baseline `EnterpriseSEval-26100.1742`.
- Procedure: `docs/M1A_DESIGN.json` `gate_procedure` A–E, `vm/RIG.md` §4a, `docs/ENGINE_PLAN.md` §1.4.
- Scope of this report: the §1.4 bands, checked by hand from `purge-engine plan show`, the scan sidecars
  (`plan-purge.scan.json`: action, evidence, score) and the snapshots. The numeric criteria are copied from
  `vm/truth/m1a-score.md` and are reviewed separately.

**Verdict: FAIL.** Danger items in `firefox-tb` (5 listed, 4 preselected), `precision_safe` 60 % there, four
band failures on Firefox, and Firefox recall below the written threshold. Most VS Code bands and the Git PATH
band were not exercised because the vendor uninstallers removed the items. Step 7 and section F were not done.

## 1. Runs and plan hashes

The gate run was interrupted; there is no runner report. All statements come from the files on disk.

| Run | Campaign | App version | `entry_gone` | `verify_gone.passed` | Items (preselected) | Plan hash (engine, `plan show`) | SHA-256 of `plans/purge.json` |
|---|---|---|---|---|---|---|---|
| r0-vscode | 002742 | VS Code 1.146.0 (system) | true | true | 274 (272) | `e151f205e91ba0242597c2b7442e9c71869bbc7fea92151e06383af62f36ead9` | `53911FC0DC94619D1D5CAA48D293DC405BCAD016906E93DB2B17F19FBD8EE922` |
| r0-vscode-user | 010413 (rerun) | VS Code 1.146.0 (user) | true | true | 147 (144) | `0acb9fe449c09c0cec2ddd2d966559dad9866f0027f45616e398db6fbdc55608` | `5A83CEB11A016E33D3C1D03BD790CB86837534F72068D478668FF0A27DBD40B5` |
| r0-git | 002742 | Git 2.56.1 | true | true | 5 (5) | `c0ba13725fc22d4726ddf43dcf4e8a0318f010a80b914f2a593689c0d1a0afe0` | `121BF3350424D68AB27DD134D2C44874D517D8B79EA26EAB4865D12E18AB8925` |
| r0-firefox | 002742 | Firefox 160.0 | true | true | 23 (11) | `57c83dbdd1f4902c37749aabf525f3300d1841aecd56b2dca5fad97d649ac754` | `30846F83780B6E2757A22D31A9FD1533E54DB42770FD1B0CF43E7CF36E829844` |
| r0-firefox-tb | 010413 (rerun) | Firefox 160.0, Thunderbird pre-installed | true | true | 22 (10) | `c8655b65786210595bc7ac0c8ceaeadc776a6527790077e393b911c393e722fb` | `DED06A9A31A0473B684E7F5F6438D00E05EA0A420FFE2674D399378E72C8EFDA` |
| r0-npp | 010413 | Notepad++ 8.9.9 | true | true | 2 (0) | `3d4e74bb3524174625fb9662bf51c0e9990ad29fe5ab2d28faf9056199c5a8ed` | `D8B213AD53B9D0B92A1F4270656C0715120A2BDF95DFDCA250666BB27119FBDF` |

`plans/purge.json` is byte-identical to `plan-purge.json` in every run. `plans/bcu.json` (vscode, git, firefox,
npp) is byte-identical to `vm/truth/frozen/<id>/plans/bcu.json`. All five engine calls exit 0 in every `run.json`.

## 2. Band table

Columns: band / preselected / action / scanner / evidence kinds (weight), from the scan sidecar. HKCU =
`HKU\S-1-5-21-…-1000`. "Not exercised" = the item named by the gate text is absent from snap2.

### VS Code system (r0-vscode)

| Gate item | Plan item | Expected | Result |
|---|---|---|---|
| OpenWithProgids values | none offered. 142 `…\.ext\OpenWithProgids : VSCode.*` values in snap1, 0 in snap2 | Safe | not exercised (vendor uninstaller removed them) |
| `.ext` / `OpenWithProgids` skeletons | 105 × `HKLM\SOFTWARE\Classes\.<ext>` and 30 × `HKLM\SOFTWARE\Classes\.<ext>\OpenWithProgids`: Safe, preselected, DeleteKey, REF-ANY, ProvenOwnedSkeleton(8). Checked against the snapshots: all 135 absent from snap0, and in snap2 none has a value or a subkey other than an empty `OpenWithProgids` | Safe | pass |
| ApplicationAssociationToasts values | none offered. No VSCode value under `ApplicationAssociationToasts` in snap1 or snap2 (the rig's launch does not create one) | Safe | not exercised |
| PATH segment | none offered. Machine `Path` has `…\Microsoft VS Code\bin` in snap1, not in snap2 | Safe if left | not exercised |
| Sparse package | none offered. `Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe` is in `lists-1` appx, not in `lists-2` | Likely | not exercised (deregistered by the vendor uninstaller) |

Other items in the plan: `%APPDATA%\Code` Likely, not preselected, Quarantine (FS-APPDATA; truth `user_data`):
correct. `HKCU_Classes\vscode` key Likely, not preselected (CLS-PROGID), while its default value and
`shell\open\command` default value are Safe, preselected (REF-ANY): truth hits, bands acceptable.

### VS Code user (r0-vscode-user)

| Gate item | Plan item | Expected | Result |
|---|---|---|---|
| OpenWithProgids values | none offered. 142 values in snap1 (`HKCU_Classes`), 0 in snap2 | Safe | not exercised |
| `.ext` skeletons | 142 × `HKCU_Classes\.<ext>`: Safe, preselected, DeleteKey, REF-ANY, ProvenOwnedSkeleton(8). All absent from snap0; none has content in snap2 | Safe | pass |
| ApplicationAssociationToasts values | none in snap1 or snap2 | Safe | not exercised |
| PATH segment | user `Path` has the VS Code segments in snap1, not in snap2 | Safe if left | not exercised |
| Sparse package | in `lists-1`, not in `lists-2` | Likely | not exercised |

Other: `HKCU_Classes\Applications` Blocked (deny-listed), `%APPDATA%\Code` Likely and not preselected,
`HKCU_Classes\vscode` as in the system run.

### Git (r0-git)

| Gate item | Plan item | Expected | Result |
|---|---|---|---|
| `LibraryFolder\background\shell` | `HKLM\SOFTWARE\Classes\LibraryFolder\background\shell`: Safe, preselected, DeleteKey, CLS-VERBS, ProvenOwnedSkeleton(8). Absent from snap0, empty in snap2; the pre-existing sibling `shellex` is not offered | Safe via ProvenOwnedSkeleton | pass |
| `sh_auto_file` | `HKLM\SOFTWARE\Classes\sh_auto_file`: Safe, preselected, DeleteKey, REF-ANY (+CLS-PROGID), ProvenOwnedSkeleton(8), InstallerManifest Inno(8), ChainedRef(5), TimeWindow(1) | Safe via ProvenOwnedSkeleton | pass |
| PATH (§1.4) | none offered. Machine `Path` has `C:\Program Files\Git\cmd` in snap1; snap2 equals snap0 | Safe | not exercised |

Other: `HKCU\…\UFH\SHC` values `1` and `2` Safe, preselected, DeleteValue (dangling references into the
install folder; truth hits). Value `0` of the same key existed in snap0 and was overwritten by the Git install;
it is not offered, which is correct. `HKLM\SOFTWARE\WOW6432Node\Classes\sh_auto_file\shell` is offered as a
separate Safe item but is the same key as `Classes\sh_auto_file\shell` (scores `gone`), see problem 6.

### Firefox alone (r0-firefox)

| Gate item | Plan item | Expected | Result |
|---|---|---|---|
| `Mozilla\Firefox` keys | `HKLM\SOFTWARE\Mozilla\Firefox`, `HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox`, `HKCU\Software\Mozilla\Firefox`: Safe, preselected, DeleteKey, REG-SOFTWARE, AppNamedKeyWithRootRef(7) + ExactFullName(4) + ProductSubfolderOfVendor(3) + NameTokenExact(3) + TimeWindow(1) (HKLM also ProvenOwnedSkeleton) | Safe | pass |
| Maintenance Service leftovers | `HKLM\SOFTWARE\Mozilla\MaintenanceService`: **Likely**, not preselected, DeleteKey, REG-SOFTWARE, ProductSubfolderOfVendor(3) + TimeWindow(1), score 4. The folder `Program Files (x86)\Mozilla Maintenance Service` and the service key are gone in snap2 | Safe | **fail** (key under-banded; folder and service not exercised) |
| `ProgramData\Mozilla-<guid>\updates\<hash>` | `C:\ProgramData\Mozilla-1de4eec8-…\updates\308046B0AF4A39CB`: **Likely**, not preselected, Quarantine, FS-APPDATA, HarvestedToken(7), score 7 | Safe | **fail** |
| Profiles (Roaming\Mozilla) | `C:\Users\tester\AppData\Roaming\Mozilla\Firefox`: **Weak**, not preselected, Quarantine, FS-APPDATA, ProductSubfolderOfVendor(3), ExecutablesPresent(−4), ManyFiles(−2), blocker UserData, score −3. `AppData\Local\Mozilla\Firefox` also Weak | Likely, not preselected | **fail** on band (Weak is the hidden band); not preselected: pass |
| Vendor parents delete-if-empty only | All vendor containers have action RemoveDirIfEmpty: `HKLM\SOFTWARE\WOW6432Node\Mozilla` (Safe, preselected, EmptyAfterPlan), `HKCU\Software\Mozilla` (Safe, preselected, EmptyAfterPlan), `HKLM\SOFTWARE\mozilla.org` (Likely), `HKLM\SOFTWARE\mozilla.org\Mozilla` (Weak), `AppData\Local\Mozilla`, `AppData\Roaming\Mozilla`, `ProgramData\Mozilla-<guid>`, `…\updates` (Weak, FS-VENDORPARENT). `HKLM\SOFTWARE\Mozilla` (holds the image's `NativeMessagingHosts`) is not offered | delete-if-empty | pass |
| `FirefoxHTML/URL/PDF-<hash>`, `StartMenuInternet\Firefox-<hash>`, `FirefoxToast-<hash>`, Default Browser Agent task | present in snap1, absent from snap2 | Safe | not exercised |
| `ShimInclusionList\plugin-container.exe` value (§1.4) | no such value in snap1 or snap2. The key `ShimInclusionList\false` is a truth leftover and is not offered | Safe | not exercised as named; `false` key missed |
| ISimpleDOM `Interface` keys (§1.4) | `HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-…}`, `{1814CEEB-…}`, `{4E747BE5-…}` `\ProxyStubClsid32 : (default)`: **Safe, preselected**, DeleteValue, REF-ANY, InPreUninstallRefSnapshot(8) only, score 8. Also `CLSID\{1814CEEB-…}\InProcServer32 : (default)` Safe, preselected, score 21 | Likely (shared IIDs) | **fail** (false Safe; becomes danger in firefox-tb) |

Other: firewall rule value under `HKLM\SYSTEM\…\FirewallRules` Blocked (deny rule `reg.hklm.system`): correct.
`FeatureUsage\AppBadgeUpdated` and `Search\JumplistData` values named by the AUMID hash Safe, preselected: hits.

### Firefox with Thunderbird (r0-firefox-tb)

| Gate item | Plan item | Expected | Result |
|---|---|---|---|
| Nothing of Thunderbird's listed | No target names Thunderbird. `HKLM\SOFTWARE\Mozilla`, `…\MaintenanceService`, the Maintenance Service folder and service, and every `Thunderbird` key and folder are not offered. Five offered items existed in snap0 (rows below) | nothing listed | **fail** |
| Shared COM registration | `CLSID\{1814CEEB-…}\InProcServer32 : (default)`: Safe, preselected, DeleteValue, REF-ANY, score 21. snap0: `C:\Program Files\Mozilla Thunderbird\AccessibleMarshal.dll`; snap1 and snap2: `C:\Program Files\Mozilla Firefox\AccessibleMarshal.dll` (overwritten by the Firefox install, not restored by its uninstaller) | not offered for deletion | **fail** (danger, preselected) |
| Shared IIDs | The three `Interface\{…}\ProxyStubClsid32 : (default)` values: Safe, preselected, DeleteValue, REF-ANY, InPreUninstallRefSnapshot(8), score 8. Their data is identical in snap0, snap1 and snap2: Firefox never changed them and Thunderbird still needs them | not offered | **fail** (danger, preselected) |
| Shared vendor key | `HKCU\Software\Mozilla`: Weak, not preselected, RemoveDirIfEmpty, REG-SOFTWARE. It holds `Thunderbird\Installer\…` in snap0 and snap2, so the action could never remove it | not listed | **fail** as scored (danger_listed); no deletion would happen |
| `Mozilla\Firefox` keys | same three keys as in the alone run: Safe, preselected, DeleteKey | Safe | pass |
| Maintenance Service | not offered; the service, its folder and `HKLM\SOFTWARE\Mozilla\MaintenanceService` belong to the still-installed service | not listed | pass |
| `ProgramData\Mozilla-<guid>\updates\<hash>` | Likely, not preselected, HarvestedToken(7) | Safe | **fail** |
| Profiles | `AppData\Roaming\Mozilla\Firefox` Weak, not preselected, UserData blocker | Likely, not preselected | **fail** on band |
| Vendor parents | `HKLM\SOFTWARE\WOW6432Node\Mozilla` (Safe, preselected, RemoveDirIfEmpty; absent from snap0), `mozilla.org` (Likely), `mozilla.org\Mozilla`, `Local\Mozilla`, `Roaming\Mozilla`, `ProgramData\Mozilla-<guid>`, `…\updates` (Weak): all RemoveDirIfEmpty, none in snap0 | delete-if-empty | pass |

### Notepad++ (r0-npp)

| Gate item | Plan item | Expected | Result |
|---|---|---|---|
| No `Notepad.lnk` | not offered. `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk` is in snap0, snap1 and snap2 | never listed | pass |
| Sparse package | `AppxPackage NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww`: Likely, not preselected, RemovePackage, SYS-APPX, AppxExternalLocation(8), blocker ReversibilityNone. Still registered in `lists-2` | Likely | pass |
| `%APPDATA%\Notepad++` (§1.4) | not offered. Present in snap1, absent from snap2 | Likely | not exercised |

Other: `HKLM\SOFTWARE\WOW6432Node\Notepad++` Weak, not preselected, RemoveDirIfEmpty, classed as a vendor
container although it is the app's own key and still has one value (it can never be removed by that action).

### Band problems not named by the gate text

- False Safe: the four COM default values in both Firefox runs (above).
- Preselected user data: none. Vendor parent deleted outright: none (every container is RemoveDirIfEmpty).
- Ambient offered: none (score: `ambient` 0 and `other` 0 in every run).
- `HKLM\SOFTWARE\mozilla.org` is Likely only because VendorContainer(2) is counted twice (score 4); its child
  `mozilla.org\Mozilla` is Weak and keeps one value, so the parent can never become empty.

## 3. Score (copied from `vm/truth/m1a-score.md`; numbers reviewed separately)

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | hit | danger | ambient | gone | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| vscode | bcu | 202 | 171 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 202 | 0 |
| vscode | purge | 274 | 171 | 80.1% | 80.1% | 78.9% | 80.1% | 80.1% | 78.9% | 100.0% | 0 | 0 | 0 | 0 | 139 | 0 | 0 | 135 | 0 |
| vscode-user | purge | 147 | 179 | 81.0% | 80.4% | 79.3% | 81.0% | 80.4% | 79.3% | 100.0% | 0 | 0 | 0 | 0 | 147 | 0 | 0 | 0 | 0 |
| git | bcu | 14 | 63 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| git | purge | 5 | 63 | 6.3% | 6.3% | 6.3% | 6.3% | 6.3% | 6.3% | 100.0% | 0 | 0 | 0 | 0 | 4 | 0 | 0 | 1 | 0 |
| firefox | bcu | 17 | 64 | 7.8% | 7.8% | 7.8% | 7.8% | 7.8% | 7.8% | 100.0% | 4 | 0 | 0 | 1 | 9 | 0 | 0 | 8 | 0 |
| firefox | purge | 23 | 64 | 18.8% | 12.5% | 7.8% | 18.8% | 12.5% | 7.8% | 100.0% | 4 | 0 | 0 | 0 | 23 | 0 | 0 | 0 | 0 |
| firefox-tb | purge | 22 | 59 | 18.6% | 11.9% | 8.5% | 18.6% | 11.9% | 8.5% | 60.0% | 0 | 5 | 4 | 0 | 17 | 5 | 0 | 0 | 0 |
| npp | bcu | 10 | 76 | 1.3% | 1.3% | 1.3% | 1.3% | 1.3% | 1.3% | 100.0% | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 9 | 0 |
| npp | purge | 2 | 76 | 30.3% | 28.9% | 0.0% | 30.3% | 28.9% | 0.0% | - | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |

Macro: bcu 4 apps, recall_visible 2.3 %, danger 0/0, userdata_presel 1; purge 6 apps, recall_visible 36.7 %,
precision_safe 92.0 %, danger_listed 5, danger_presel 4, userdata_presel 0.

Frozen cross-check (step 12, `vm/truth/m1a-frozen-<id>.md`, purge / bcu `visible_nd` on the frozen M0 truth):
vscode 89.0 % / 0.0 %, git 25.0 % / 0.0 %, firefox 33.3 % / 20.8 %, npp 75.9 % / 3.4 %; danger 0 and
precision_safe 100 % in all four (npp has no Safe item). There is no frozen set for vscode-user or firefox-tb.

## 4. Section D criteria

Numeric rows: numbers from `m1a-score.md`, reviewed separately.

| Criterion | Result |
|---|---|
| danger_listed = 0 and danger_preselected = 0 on every run | **FAIL**: firefox-tb 5 listed, 4 preselected. The other five runs are 0 / 0 |
| precision_safe = 100 % on every run | **FAIL**: firefox-tb 60.0 %. vscode, vscode-user, git, firefox 100 %; npp has no Safe item |
| userdata_preselected = 0 | pass (0 on all six runs) |
| recall_visible_nd(purge) > recall_visible_nd(bcu) | vscode 80.1 % > 0 %: pass. git 6.3 % > 0 %: pass. npp 28.9 % > 3.4 %: pass. firefox 12.5 %: above BCU on the same run (7.8 %) but **below the written threshold of 20.8 %: FAIL as written**. The r0 truth has 64 items against 24 in the frozen truth (see problem 4); on the frozen truth Firefox is 33.3 % against 20.8 % |
| §1.4 bands by hand | **FAIL**: Firefox Maintenance Service key Likely (Safe expected), `updates\<hash>` Likely (Safe expected), profiles Weak (Likely expected), ISimpleDOM values Safe and preselected (Likely expected), items existing before the install offered in firefox-tb. Pass: VS Code skeletons (both installs), Git `LibraryFolder\background\shell` and `sh_auto_file`, `Mozilla\Firefox` keys, vendor parents delete-if-empty, Notepad++ `Notepad.lnk` and sparse package |
| Not exercised | VS Code (both): OpenWithProgids values, ApplicationAssociationToasts values, PATH segment, sparse package. Git: PATH. Firefox: ProgIDs, `StartMenuInternet`, toast AUMID, Default Browser Agent task, Maintenance Service folder and service, `plugin-container.exe` value. Notepad++: `%APPDATA%\Notepad++` |

Section E (inventory): all twelve `invdiff-<n>.md` files report 0 differences. The informational run against
`results/lists-registry.json` was not found.

## 5. Not done

- Step 7: Inno fixtures. `vm/runs/r0-inno-vscode` is empty; campaign `20261113-012049` stops after "run
  r0-inno-vscode" with no result. No `unins000.dat` was pulled and the ignored parser test was not run with
  `PURGE_INNO_FIXTURES`.
- Step 9: the differences between r0 truth and frozen truth in `m1a-sanity.md` were not investigated before
  scoring.
- Section F (Purge-CleanPro pass, dirty-base danger pass): not run.
- Section A results (`cargo xtask ci`, `replay-all`) are not recorded anywhere this review could read.

## 6. Open problems

1. **Engine, REF-ANY and band policy: shared COM values Safe and preselected.** A single
   InPreUninstallRefSnapshot(8) is enough for Safe on `Interface\{…}\ProxyStubClsid32`, and the CLSID is treated
   as Firefox's own identifier. There is no check that another installed product (Thunderbird ships the same
   `AccessibleMarshal.dll` and registers the same IIDs) shares the registration. §1.4 puts these at Likely.
2. **Engine, REG-SOFTWARE: a vendor container that another product still uses is listed.**
   `HKCU\Software\Mozilla` in firefox-tb. The action is delete-if-empty, so nothing would be removed, but any
   listing of a snap0 item counts as danger. The plan schema `purge.plan/0` does not carry the action, so the
   scorer cannot tell a delete-if-empty item from a deletion.
3. **Engine, band policy: three Firefox items under-banded.** Maintenance Service key (co-removed product gets
   only ProductSubfolderOfVendor + TimeWindow), `updates\<hash>` (HarvestedToken alone gives Likely), profiles
   (negative evidence drops a UserData folder to Weak, where it is hidden instead of shown unticked).
4. **Truth: the r0 truth sets contain Windows churn.** Leftover counts against frozen: git 63 / 16, firefox
   63 / 23, npp 76 / 29, vscode 169 / 152. The additions are mostly `RegValueChanged` items under DiagTrack,
   Component Based Servicing, Windows Update and Defender, plus USOShared logs: the ambient set of 2026-11-11
   does not cover them. This lowers every recall figure in `m1a-score.md`. In firefox-tb,
   `Mozilla Maintenance Service\maintenanceservice_tmp.exe` is labelled leftover although the service is still
   installed for Thunderbird.
5. **Rig: scripts changed during the gate and are uncommitted.** `vm/guest/run-app.ps1` was modified at
   00:42:13 (after the vscode and git runs, before firefox) and `vm/guest/riglib.ps1` at 01:03:28 (before the
   second campaign). The first r0-vscode-user run failed in phase setup (`The property 'installer' cannot be
   found on this object`, run-app.ps1 line 100) and was rerun; the first r0-firefox-tb run was interrupted and
   rerun. The six runs were therefore not produced by one version of the guest scripts.
6. **Engine, registry enumeration: alias keys offered twice.** `HKLM\SOFTWARE\WOW6432Node\Classes\…` is the
   same key as `HKLM\SOFTWARE\Classes\…`. The vscode plan lists all 135 skeletons a second time under the
   alias (the 135 `gone` items; 272 preselected instead of 137), and the git plan lists
   `WOW6432Node\Classes\sh_auto_file\shell`.
7. **Engine, REG-SOFTWARE: minor.** VendorContainer counted twice on `HKLM\SOFTWARE\mozilla.org`; vendor
   containers that keep a value of their own (`mozilla.org\Mozilla`, `WOW6432Node\Notepad++`) are offered with
   an action that can never succeed; registry keys carry the action name `RemoveDirIfEmpty`.
8. **Coverage.** Sparse package (VS Code), OpenWithProgids values, ApplicationAssociationToasts and PATH
   bands have no evidence from this gate; they need a forced or external-uninstall run to be exercised.
9. **Missed leftovers of note** (visible in the score's missed lists): VS Code `.vscode`, `.vscode-shared`,
   `.copilot`, `Search\JumplistData : Microsoft.VisualStudioCode`, package remnants under
   `BackgroundAccessApplications` and `AppModel\PolicyCache`; Firefox `ShimInclusionList\false`,
   `Classes\.shtml` values; Prefetch files and jump lists in every run.
