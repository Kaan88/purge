# M1a gate report (post-uninstall plans)

- Date: 2026-11-15. This replaces the report of the first gate (2026-11-13, engine m1a.2, verdict FAIL); its
  findings and what became of them are in section 7.
- Procedure: `docs/M1A_DESIGN.json` `gate_procedure` A to E, `vm/RIG.md` §4a and §4b, `docs/ENGINE_PLAN.md` §1.4.
- Decisions taken on the way (waivers, deviations, deferrals): `docs/DECISIONS.md`. Reviews: `docs/reviews/m1a/`.

**Verdict: PASS**, with two recorded deviations (section 5) and the limits of section 6. (The live check was
repeated on Inbound later the same day, `r3i-`; the judgement in section 1 is settled by it.) The verdict was reached
without the user, under the standing instruction to decide and record; the points a reader may want to judge
again are marked "judgement" below.

## 1. What was run

| Step | Engine | Where | Result |
|---|---|---|---|
| Gate campaign `r2-` | m1a.5, `purge-engine.exe` sha256 `1d7524d4cd0c…` | VM Inbound (LTSC 26100), snapshot `rig-base`, 7 apps + 3 null runs | Numeric criteria pass (score review); bands pass with notes (bands review) |
| Dirty base `f2d-` | m1a.5 | Inbound, `dirty-base`, 5 apps + 2 nulls | Nothing dangerous offered for removal (dirty review) |
| Extended set `x2-` | m1a.5 | Clean-Pro (Pro 26340), `rig-base`, 16 runs | Nothing dangerous Safe or ticked; 7 foreign items Likely and unticked, fixed in m1a.6 |
| No baseline `x2-nb-` | m1a.5 | Clean-Pro, 5 runs, no (edition, build) baseline | 2 items, both a shortcut-history slot, unticked |
| Engine m1a.6 | commit `622c64d` (tree `8fcaab30…` by `docs/reviews/m1a/pass11/treehash.py`) | host | `cargo xtask ci` passes (981 tests); the 10 snapshot tests pass; two independent reviews of pass eleven, the second "accept"; mutation run in `docs/reviews/m1a/engine-pass11-review.md` |
| Offline re-plan | m1a.6 | 74 older captures (post and live modes), 29 captures of the four campaigns | Differences against m1a.5 are the intended ones only (section 3) |
| Live check `r3-` | m1a.6, `purge-engine.exe` sha256 `128556f84e2b…` built on Windows (msvc) from `622c64d` | Clean-Pro, `rig-base`: firefox, firefox-tb, ff-esr, with extra checks | All engine calls exit 0; plans as predicted (section 3); score in `vm/truth/r3` |
| Live check `r3i-` | the same m1a.6 binary | Inbound, `rig-base`: firefox, firefox-tb, with extra checks (run after the VM was repaired) | Both runs ok; plans equal r2 except the two intended rows; score in `vm/truth/r3i` |

The gate campaign ran on m1a.5 and the engine then moved to m1a.6. By the decision of 2026-11-14 the result
carries over where the m1a.6 plan of a capture is identical, and a run whose plan differs is repeated live.

**Judgement.** The two gate runs whose plans differ (firefox, firefox-tb) were repeated on Clean-Pro, not on
Inbound: VirtualBox on Windows cannot load the Inbound VM at present (its settings file was last written by the
Linux build and no longer carries the disk registry). The repeated plans equal the r2 plans row for row except
the two profile rows that were meant to change, so the r2 numbers are taken to stand for m1a.6.

**Settled the same day.** The Inbound VM was repaired (`vm/RIG.md`, Linux host section) and the two runs were
repeated there as `r3i-firefox` and `r3i-firefox-tb`, same snapshot and VM as r2. Result in section 3: the
plans differ from r2 only in the two profile rows.

## 2. Criteria (gate section D), r2 campaign

Numbers from `vm/truth/r2/m1a-score.md`, reproduced by the score review from the raw captures.

| Run | Danger listed / preselected | precision_safe | User data preselected | recall_visible_nd | Bar (BCU on the frozen truth) | Result |
|---|---|---|---|---|---|---|
| vscode | 0 / 0 | 100% (136 of 136 Safe) | 0 | 88.4% | > 0% | pass |
| vscode-user | 0 / 0 | 100% (143 of 143) | 0 | 88.3% | > 0% | pass |
| git | 0 / 0 | 100% (2 of 2) | 0 | 23.5% | > 0% | pass |
| firefox | 0 / 0 | 100% (10 of 10) | 0 | 28.0% | > 20.8% | pass |
| firefox-tb | 0 / 0 | 100% (8 of 8) | 0 | 31.6% | > 20.8% | pass |
| npp | 0 / 0 | no Safe item | 0 | 82.1% | > 3.4% | pass |
| 7zip | 0 / 0 | no Safe item | 0 | 0.0% | none written | outside the written scope (section 6) |

- Inventory (section E): `invdiff` exits 0 for all 14 run and phase pairs.
- Checked apart from the scorer: no offered target of any of the seven plans exists in snapshot 0, including
  firefox-tb where Thunderbird was installed first; no preselected item touches user data.
- The BCU figures are the frozen M0 BCU plans scored again on the r2 truth; BCU was not run again.
- Firefox clears its bar with or without the three servicing noise rules approved on 2026-11-14.

Sanity step (r2 truth against the frozen M0 truth): 11 differences, each classified in
`vm/truth/r2/m1a-sanity-classified.json`: 6 random `CLSID` + `AppID` key pairs and 1 `hivelist` value written by
Windows with no app involved (they sit in the denominator and lower recall), and 4 missing UserAssist `Count`
values (Explorer wrote none in any r2 run; environment). The score script no longer accepts a residual by itself.

## 3. From m1a.5 to m1a.6

Policy m1a.6 is the central content rule ("a value is offered whole only when all of its content is the app's"),
"an executable's bare file name is not ownership", "a key with a Blocked child is not offered whole", profile
folders at Likely, and the fixes of the pass-ten and pass-eleven reviews.

Offline re-plan of the 29 campaign captures, m1a.5 tree against m1a.6 tree:

| Change | Rows | Which |
|---|---:|---|
| Weak to Likely | 13 | Firefox and Thunderbird profile folders, no sibling product installed |
| Weak to Blocked | 4 | The same folders in ff-esr and ff-devedition (a sibling uses them) |
| Weak, gone | 4 | Their `...\Mozilla` containers in those two runs |
| Likely to Blocked | 2 | `HKU_Classes\vscode` beside another VS Code install |
| Likely, gone | 5 | Bare-name rows: `Applications\notepad++.exe` of a portable copy with its `OpenWithList` entry and MRU letter, `App Paths\rg.exe`, another install's `Applications\Code.exe` |
| Evidence tier only | 19 | Token snapshot evidence A to B on two Safe value kinds; bands unchanged |

No row moves up into Safe. The pass-eleven review fixes and the follow-up fixes change no row in any of the 177
re-plans (74 post, 74 live, 29 campaign).

Live check with the m1a.6 binary, against the m1a.5 plans of the same scenario:

| Run | Items | Safe (= preselected) | Likely | Weak | Blocked | Against m1a.5 |
|---|---:|---:|---:|---:|---:|---|
| r3-firefox | 20 | 10 | 7 | 2 | 1 | r2-firefox: the two profile folders Weak to Likely; nothing else |
| r3-firefox-tb | 14 | 8 | 3 | 2 | 1 | r2-firefox-tb: the same two rows; nothing else |
| r3-ff-esr | 19 | 5 | 1 | 0 | 13 | x2-ff-esr: the two profile folders Weak to Blocked, the two `Mozilla` containers gone; nothing else |

(The firewall rule value has a new random name in every run.) Score (`vm/truth/r3/m1a-score.md`): danger offered
for removal 0 in all three; ff-esr lists 7 items read-only as Blocked and kept for Firefox ESR (in x2 two of them
were offered unticked); precision_safe 100%; user data preselected 0; `invdiff` 0 differences. Extra checks: the
scan of the still-installed app has 0 Safe and 0 preselected items and the install root Blocked (101, 93 and 88
items); the repeated post scan gives the same plan hash. Recall figures of r3-firefox and r3-firefox-tb are not
comparable with r2: Clean-Pro has no null runs in this campaign and its Store churn inflates the truth set.

The same check on Inbound (`r3i-`, m1a.6, `rig-base`, the VM and snapshot of r2):

| Run | Items | Safe (= preselected) | Likely | Weak | Blocked | Against r2 (m1a.5) |
|---|---:|---:|---:|---:|---:|---|
| r3i-firefox | 20 | 10 | 7 | 2 | 1 | The two profile folders Weak to Likely; nothing else |
| r3i-firefox-tb | 14 | 8 | 3 | 2 | 1 | The same two rows; nothing else |

Against r3 (Clean-Pro) the plans differ only in the user's SID. Score (`vm/truth/r3i/m1a-score.md`, with the
ambient set of the r2 null runs): danger listed 0, precision_safe 100% (10 of 10 and 8 of 8), user data
preselected 0, every offered item a hit, `invdiff` 0 differences. Extra checks: the scan of the installed app
has 0 Safe and 0 preselected items and the install root Blocked (100 and 93 items); the repeated post scan
gives the same plan hash. recall_visible_nd is 25.9% (firefox) and 25.0% (firefox-tb) against BCU's 18.5% on
this truth, so the bar is cleared. The figures are lower than r2's 28.0% and 31.6% because the truth set is
larger (27 and 24 entries against 25 and 19): no null runs were made on the day, and the r2 nulls remove less
of this day's Windows churn. The number of covered entries is the same as in r2.

## 4. Bands (§1.4), by hand on r2 and on the live check

Safety invariant, from the bands review: all 299 Safe items of the seven r2 plans are provably the app's; no item
that existed before the install is offered in any band; no user data is preselected; no value is offered whole
while it holds foreign text. Preselected equals Safe in every plan.

| Gate item | Expected | Result |
|---|---|---|
| VS Code `.ext` and `OpenWithProgids` skeletons (system and user) | Safe | pass |
| Git `LibraryFolder\background\shell`, `sh_auto_file` | Safe | pass |
| Firefox `Mozilla\Firefox` keys | Safe | pass |
| Firefox `ProgramData\Mozilla-<guid>\updates\<hash>` | Safe | pass |
| Firefox profile folders | Likely, not preselected | pass on m1a.6 (live check); Blocked when a sibling Mozilla product is installed |
| Firefox Maintenance Service key | Safe | Likely: deviation (section 5) |
| ISimpleDOM `Interface` values | Likely | pass; not offered with Thunderbird installed |
| Vendor parents | delete-if-empty only | pass |
| Nothing of Thunderbird listed (firefox-tb) | nothing | pass |
| Notepad++: no `Notepad.lnk`; sparse package | never listed; Likely | pass |

Not exercised, because the vendor uninstallers removed the items: VS Code OpenWithProgids values,
ApplicationAssociationToasts values, PATH segment and sparse package; Git PATH and `.gitconfig`; Firefox ProgIDs,
`StartMenuInternet`, toast AUMID, Default Browser Agent task, Maintenance Service folder and service,
`plugin-container.exe` value; Notepad++ `%APPDATA%\Notepad++`; any edit of a shared value; UserAssist traces.
These bands rest on unit tests and replay only.

## 5. Waivers and deviations

| What | Why | Source |
|---|---|---|
| Deviation: `HKLM\SOFTWARE\Mozilla\MaintenanceService` is Likely; the gate text says Safe | The service is shared by Mozilla products and has its own uninstaller; under-banding costs one click | DECISIONS 2026-11-15 |
| Waiver: a pre-existing empty `.ext` key the installer wrote into directly can be offered as the app's | Telling it apart needs a pre-install snapshot the product never has; the loss is one empty key | DECISIONS 2026-11-14 |
| Dirty base: the criterion is "no dangerous item is offered for removal"; items listed read-only as Blocked are counted apart | Of the 7 danger items of `f2d-`, 4 are Blocked and kept for the installed system VS Code and 3 are a shortcut-history slot Windows overwrote with the app's record; none Safe or preselected | dirty review, DECISIONS 2026-11-15 |
| Extended set, ff-reinstall: 7 Safe "danger" items accepted as a scorer artefact | They are Firefox's own leftovers from the first of two installs; scored against a snapshot without it danger is 0 | ext review, DECISIONS 2026-11-15 |
| Three ambient-noise rules in the scorer (TrustedInstaller service values, `SIH\SLS\{GUID}`, WER `TermReason`) | Written by Windows servicing with no app involved; Firefox passes without them too | DECISIONS 2026-11-14 |
| The gate campaign ran with 3D acceleration off, on a Linux host (VirtualBox KVM build), with binaries built by cargo-xwin | The Windows host froze during the first attempts | DECISIONS 2026-11-14 |
| The live check of m1a.6 ran on Clean-Pro, not Inbound | Section 1, judgement. Closed: repeated on Inbound as `r3i-` with the same result | this report |

## 6. Limits carried forward

- **7-Zip: empty plan** (0 of 3 truth items; BCU 33.3% on the same run). MSI attribution is M1b; section D
  names four apps for the recall bar. Recorded as a gap, not as a pass on recall.
- **VS Code user install beside a system install recalls about 1%**: the shared `VSCode.<ext>` ProgIDs make the
  engine refuse 142 per-user keys. A correct refusal; attribution through the installer log is M1b.
- **M2 executor requirement** (review of pass eleven, finding 6): a ticked whole-tree parent with a Blocked
  item below it must be refused, or the Blocked item spared. One executor test is also owed for Safe
  delete-if-empty vendor containers with a foreign child added between plan and execution.
- Items that could be Safe and are Likely: Git `UFH\SHC` values, Firefox `JumplistData` private-browsing value,
  `HKCU_Classes\vscode` (its command value is Safe, so the default selection leaves a protocol key without a
  command).
- Missed, harmless: `HKLM\SOFTWARE\mozilla.org`, `C:\ProgramData\Mozilla-<guid>`, `ShimInclusionList\false`,
  `.vscode*` and `.copilot`, Prefetch, jump lists, temp files.
- Engine limits left open by the last review are listed in `docs/DECISIONS.md` (2026-11-15, "Known limits").
- Rig: Store registry churn on Clean-Pro (about 550 rows per run) still inflates denominators; no null runs
  inside the extended campaigns; UserAssist was not written under the Linux host.
- The handoff mentions "12 deferred limitations from the pass-seven review". That review is not in the
  repository (it stayed in the Linux session's scratch space), so the list could not be copied here.

## 7. The first gate's failures

| First-gate finding (m1a.2) | Now |
|---|---|
| ISimpleDOM values Safe and preselected | Likely alone; not offered with Thunderbird |
| Shared CLSID value preselected in firefox-tb | Not offered |
| `HKCU\Software\Mozilla` listed in firefox-tb | Not offered |
| `updates\<hash>` Likely | Safe |
| Alias keys offered twice | Fixed |
| Notepad++ key offered with an action that cannot succeed | Likely, DeleteKey |
| Profiles Weak (hidden) | Likely (m1a.6, live check) |
| Maintenance Service key Likely | Deviation recorded |
| Firefox recall below the written bar | 28.0% against 20.8% |
| r0 truth held Windows churn; scripts changed mid-gate; steps not recorded | Ambient set from the campaign's own null runs, servicing rules, one script version, sanity residual classified |
