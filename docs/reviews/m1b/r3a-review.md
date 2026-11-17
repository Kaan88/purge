# M1b review R3a: wave-4 scanners and the scan-side fix rounds

Reviewed at `3bbbfa1` (branch `m1b`). Scanners: SYS-SERVICE `ec78682`, SYS-FIREWALL `8f572e5`,
COM-CLASS and COM-INTERFACE `3e9ccbd`, SYS-TASK `6c867e5`, REG-ARP-MSI, REG-INSTFOLDERS and
REG-SHAREDDLLS `07c02a1`, SYS-BURNDEPS and FS-PKGCACHE `fe66615`, COM-SHELLEX `cd88e4e`, REG-PRIVACY
`0ab8ca6`, REG-DIAG and FS-WER `d542f26`, SYS-APPX `0056bab`. Fix rounds: `8b18914`, `b0d097d`, and
the merge fixes `6875311`, `424852f`. The executor is not in scope.

The reviewer changed no source code and ran no build or test (other builds and a VM were running).

## Verdict

**Accept with required changes.**

One blocking finding (B1). It cannot delete anything today, because REG-ARP-MSI is not in
`catalog.rs` yet (the catalog still lists the 19 M1a scanners). It must be fixed before
M1B-SCAN-INTEG registers REG-ARP-MSI, and the same fix is needed for the plan's `gone_msi_products`
list, which the pipeline already fills.

Six serious findings (S1 to S6). S1 to S5 are places where an object of another product, or an
object whose state is unknown, can be offered. S6 is a fix that is only partly done. They must be
fixed or decided before the gate; S2, S4 and S5 are cheap and should go in before SCAN-INTEG.

The fix rounds hold: of the twelve R2a findings, nine are fixed, three are partly fixed (S4, S5, S12),
none is worse.

Evidence labels:

- **reading**: confirmed by reading the code (and, where named, the test that asserts it).
- **suspected**: not confirmed, or the end effect depends on code or data outside this review.

No finding has the label "experiment". The parts of `8b18914` outside `purge-scan` (S4 to S7, S12)
were read by a sub-reviewer; I re-read the code behind S4. Those rows are marked "(sub-review)".

## Blocking finding

### B1. "Product gone" is judged for the calling user only, but REG-ARP-MSI offers every user's registration (reading)

`crates/purge-scan/src/framework/m1b.rs:537-544` (`product_known_in`),
`crates/purge-win/src/msi.rs:319-329` (`product_state_all_contexts`: "for the calling user in each of
the three contexts"), `crates/purge-scan/src/reg_arp_msi.rs:199-207`, `:216-223`,
`bins/purge-engine/src/pipeline.rs:991`.

- The contract says "unknown to Windows Installer in every context". The source asks three contexts
  for the calling user. A per-user install of the same ProductCode by another user is not seen.
- REG-ARP-MSI then offers `...\Installer\UserData\<sid>\Products\<P>` for every SID under `UserData`,
  with `InstallerManifest(Msi)` (Tier A, weight 8): Safe and preselected. The plan puts `P` on
  `gone_msi_products`, so the guard lets the key through.
- The test `arp_msi_per_user_context_paths` (`tests/msireg/arp_msi.rs:247-258`) asserts this: a
  per-user product of one SID gets `UserData\S-1-5-18\Products\<P>` as `(Safe, true)`.
- Scenario: users A and B each install Python 3.12 "just for me" (the same per-user MSI
  ProductCodes). A uninstalls and scans. For A the products are unknown in all three contexts, so
  they are "gone". The plan preselects `UserData\<B's SID>\Products\<P>` for each of them. After the
  run Windows Installer no longer knows B's install: B can neither repair nor uninstall it.
- Second scenario: the engine is elevated with another administrator's account. The calling user is
  that administrator, so a per-user product of the interactive user looks gone while it is installed.
- The ownership index often knows the other install (`OwnershipIndex::installed`, fed by `msi_only`
  since the S8 fix), but REG-ARP-MSI and `product_known_in` do not ask it.
- Fix:
  1. `product_known_in` answers `Some(false)` only when the product is unknown for the calling user,
     the ownership index lists it in no context, and for a per-user product the calling user is the
     product's `user_sid`. Otherwise `None`.
  2. REG-ARP-MSI offers `UserData\<sid>\Products\<P>` only for the product's own context SID
     (`context_sid`), as it already does for component values.
  3. Add a hostile test: the same code installed for a second user, expecting no candidate on that
     user's keys and an empty gone list.
- Reaches: REG-ARP-MSI, FS-PKGCACHE and SYS-BURNDEPS (b) through `product_gone`, the guard lists,
  and the executor when M1B-X-INTEG calls `m1b_lists`.

## Serious findings

### S1. SYS-TASK and SYS-FIREWALL call a program "gone" on a bare `exists()` (reading; missing-volume answer suspected)

`crates/purge-scan/src/sys_task.rs:352-366`, `crates/purge-scan/src/sys_firewall.rs:257`,
`crates/purge-scan/src/sys_service.rs:312-329`.

- The framework's dangling rule (`framework.rs:1108`) needs a fixed NTFS or ReFS volume with the
  recorded serial and the whole root gone. SYS-SERVICE checks the volume but not the root. SYS-TASK
  and SYS-FIREWALL check neither.
- "Program gone" is the only thing between Likely and Safe for a recorded object.
- Scenario: the app is on `D:`, a removable or currently unmounted disk. Every path there is absent.
  The recorded task and firewall rule become Safe and preselected, while the app may still be
  installed on that disk.
- Fix: one framework helper for all three scanners, built on `ScanCtx::dangling` for a file in an
  InstallRoot and on the SYS-SERVICE volume check for an app file outside the roots.

### S2. COM-INTERFACE attributes an interface through a TypeLib id without judging the type library now (reading)

`crates/purge-scan/src/com_interface.rs:394-412`.

- When the `TypeLib` value names an id of `fp.anchors.typelibs`, the view gets
  `ChainedRef` at Tier A to the type-library key, whatever `scan_typelib` found. A proxy is checked
  against the class's state now (`Foreign` blocks); a type library is not.
- `ChainedRef` has weight 5, so the key is Likely even after the cap to Tier B.
- Scenario: a sibling product (or a newer version in another folder) re-registered `TypeLib\{T}` to
  its own file after the harvest. Its interface `Interface\{I}` (oleaut32 proxy, `TypeLib={T}`) is
  in use. `scan_typelib` offers nothing for `{T}`, but `{I}` is listed as Likely. A kept-owner item
  below Protected fails K6.
- Fix: return the type library's standing from `scan_typelib` (own, foreign file present, absent,
  unreadable). Chain only when it is own. Add `ReferencedByOtherApp` when a platform path is an
  existing file outside the app. No candidate when it is unreadable.
- Add the test `iface_typelib_reregistered_by_other_product_protected`.

### S3. "No other referrer" is concluded from a walk whose completeness is thrown away (reading)

`crates/purge-scan/src/framework/m1b.rs:176-199` (`ScanExt::build` keeps `.hits` only),
`crates/purge-scan/src/com_class.rs:808-844` (`TreatAs`, shared-IID proxy), `:1085-1105` (AppID
referrers).

- COM-CLASS reads the walk's hits to show that no foreign class emulates the class, that no shared
  interface uses it as proxy, and that every class naming an AppID is the app's. `RefScan` has
  `is_complete()`, `unreadable_total`, `truncated` and `incomplete_values`; none reaches a scanner.
- An unreadable key under Classes is then "no referrer". The cross-package rule is that unknown
  never removes a blocker.
- The same holds for user hives the walk did not cover: a class in another user's Classes that
  names a machine AppID or `TreatAs` a machine class is not seen. COM-SHELLEX handles this case
  (`com_shellex.rs:636-639`); COM-CLASS does not.
- Fix: keep the walk's stats in `ScanExt`. When the walk is incomplete, COM-CLASS, COM-INTERFACE and
  COM-SHELLEX cap their candidates at Tier B and add one scan warning. For the AppID rule and the
  `TreatAs` rule on a machine key, either look at the other loaded hives or cap at Tier B when more
  user hives are loaded than were walked.

### S4. SYS-BURNDEPS looks in every loaded user's Classes for a per-user bundle (reading; reach suspected)

`crates/purge-scan/src/sys_burndeps.rs:228-244` (`dependency_roots`), `:172-182` (`bundle_gone`).

- R2a S6 was fixed in the harvest: a per-user bundle uses the machine's records and its own user's.
  The scanner still reads the machine and every loaded hive, and matches entries by bundle id.
- `bundle_gone` trusts the fresh inventory alone. `bundle_known` in the plan asks whether the
  bundle's own hive was read, not the other hives.
- Scenario: A and B both installed the same per-user bundle. A uninstalls. B's hive is loaded but
  its Uninstall keys failed to list (an inventory warning). The bundle is "gone", and
  `HKU\<B>_Classes\Installer\Dependencies\<P>\Dependents\<bundle id>` is offered as Safe; the guard
  list holds the bundle id.
- Fix: for a per-user bundle, read `HKLM` and the bundle's own user's root only; for a machine
  bundle, `HKLM` only for rule (a), every root only to find other dependents. The same roots in
  FS-PKGCACHE (`package_cache_roots`: the entry's own Package Cache, as the harvest does).

### S5. The Tracing rule "no other app has an exe of that stem" sees almost no exes (reading; K6 effect suspected)

`crates/purge-scan/src/reg_diag.rs:167-178`, `bins/purge-engine/src/pipeline.rs:1097-1143`.

- A tracing key is named after a file stem and is shared by every program of that name. The scanner
  drops the candidate when another app has an exe of that stem. Another app's known exes are its
  uninstaller, its `DisplayIcon` file and that file's name; nothing else.
- Scenario: Python 3.12 is removed while 3.13 stays. 3.13's entry is a Burn bundle whose icon is in
  the Package Cache. `python_RASAPI32` is offered as Likely, although 3.13's `python.exe` writes the
  same key. On the `python312-with-313` case that is a kept-owner item below Protected (K5, K6).
- Fix: also refuse the stem when the ownership index holds a component of another product whose
  file key path is named `<stem>.exe`, when `App Paths\<stem>.exe` exists and points outside the
  roots, or when a service or task program of that name lies outside the roots (all already read).
  Add the trap as a unit fixture.

### S6. The host list is exact names, and a task's working directory is never read (sub-review; reading)

`crates/purge-index/src/sysobj.rs:216-229` (`is_host`), `:361-421` (`argument_paths`,
`drive_path_start`).

- R2a S5 is partly fixed. Still open:
  - hosts are matched by exact name: `python3.exe`, `python3.12.exe`, `pypy3.exe`, `npm.cmd`,
    `npx.cmd`, `electron.exe`, `Rscript.exe`, `AutoHotkey.exe` and a renamed WinSW are not hosts;
  - relative arguments are not listed, and `working_dir` is read nowhere;
  - a drive path after `/` or a letter is not found (`file:///C:/Other/x.jar`, `-IC:\Other`).
- Scenario: uninstalling Node.js. Another product's task runs `C:\Program Files\nodejs\npm.cmd` with
  arguments `run start` and working directory `C:\Other\proj`. The harvest records it as Node's; the
  scan can make it Safe once `npm.cmd` is gone.
- Fix: match hosts by pattern (`python*`, `pypy*`, any `.cmd` or `.bat`); for a task, a working
  directory outside every root together with a relative argument makes the action nobody's; find a
  drive path after any character that is not a letter or digit.

## Minor findings

- **M1 (reading).** `crates/purge-plan/src/decide.rs:508-520`: the S10 exemption lifts
  `com.shared-iid` and `com.shared-proxy` on pre-uninstall evidence alone
  (`InPreUninstallRefSnapshot`). A value such as `Interface\{shared IID}\ProxyStubClsid32` holds a
  CLSID, which stays valid when a sibling product re-registers the class. Require that the class the
  value names is not served by an existing file outside the app now.
- **M2 (sub-review, reading).** `crates/purge-harvest/src/exes.rs:134-147`: a "related" main exe in an
  inferred root enters `fp.exes`, so an object running exactly that file is recorded as
  `ProgramIsAppExe` and the scan agrees (`ScanCtx::is_app_file`). Narrow: the file is the entry's own
  icon or main program. Record such an object at Tier B.
- **M3 (sub-review, reading).** `crates/purge-index/src/ownership.rs:1338-1367`: a user-only Burn
  record whose product has no known user is not treated as foreign. Require the product to be
  installed for that SID.
- **M4 (sub-review, reading).** `vm/rigtool/src/execdiff.rs:663-674`: the task-file excuse needs only
  a journal intent. A `Skipped` op qualifies (the test uses one). Require an undo or recovery record.
- **M5 (reading).** `sys_service.rs:71,174-189`, `sys_task.rs:369-417`: the scanners repeat the
  guard facts the sealing now builds (`m1b.rs:966-1073`), with their own copies of
  `KNOWN_TYPE_BITS` and `unquote`. Call `ScanCtx::object_guard` from the scanners so that the two
  cannot drift.
- **M6 (suspected).** `m1b.rs:758`, `sys_firewall.rs:362`, `fs_pkgcache.rs:274`: these canonicalise
  with `GuardEnv::default()`; every other call uses the context's guard. Check that a path the
  guard's environment changes (a profile, a subst drive) gives the same answer.
- **M7 (reading).** `com_interface.rs:277-318`: the Interface key is offered whole and its subkeys
  are not checked against the ones COM defines (`NumMethods`, `ProxyStubClsid`, `ProxyStubClsid32`,
  `TypeLib`, `BaseInterface`, ...). Apply the COM-CLASS rule: another subkey lowers it to Tier B.
- **M8 (reading).** `sys_appx.rs:109-118`: the `other_users` fact is written into the evidence after
  `build()`. Add a builder method. The scanning user is `sys.user_sid()`, the executor removes for
  the calling user; with over-the-shoulder elevation these differ (X-INTEG must refuse).
- **M9 (reading).** Seven scanners have no scan warnings: COM-SHELLEX, SYS-BURNDEPS, FS-PKGCACHE,
  REG-PRIVACY, REG-DIAG, FS-WER, SYS-APPX (21 `// warning:` marks). COM-SHELLEX returns nothing,
  silently, without the walk or the KB. Their module texts still say no channel exists.
- **M10 (reading).** `com_shellex.rs:138-144`: `Cached`, `ShellExecuteHooks` and
  `SharedTaskScheduler` are not in the guard's container table; only deny rules keep the keys.
  Add them to `M1B_VALUE_CONTAINERS` with the catalog change.

## Fix rounds against R2a

| Finding | Commit | Status | Note |
|---|---|---|---|
| S1 SharedRefcount | `b0d097d` | fixed | Live clients only (`m1b.rs:865-888`); directories through `shared_dlls_under`; REG-SHAREDDLLS uses the framework rule; counts summed over both views. |
| S2 object rules centrally | `b0d097d` | fixed | `seal_object` looks the object up in the index, compares the digest and applies `check_object`; the plan adds `object.no-fp`. See M5. |
| S3 service backed by name | `8b18914` | fixed | `object_backed` needs the `fp.sys` record with the same digest for every kind. |
| S4 harvest and root kinds | `8b18914` | partly (sub-review) | InstallRoot or app file only. Residue M2. |
| S5 hosts and arguments | `8b18914` | partly (sub-review) | 23 hosts, prefix rule, `argument_paths`. Residue S6. |
| S6 Burn records and hives | `8b18914` | fixed (sub-review) | Harvest side. Residue M3; the scanner side is S4 of this review. |
| S7 cache folders | `8b18914` | fixed (sub-review) | Name and own cache root checked in harvest and in FS-PKGCACHE (`fs_pkgcache.rs:100-110`). |
| S8 `msi_only` products | `b0d097d` | fixed | Fed to the index; a per-user product without a user is unreadable. |
| S9 lists and `bundle_known` | `b0d097d` | fixed, scan side | `m1b_lists` in the pipeline; the executor side is a documented hook for X-INTEG. B1 applies to `product_known`. |
| S10 shared-IID rules | `b0d097d` | fixed, by another route | The rule is lifted for single values instead of adding a replay reason. Residue M1. The flag is journalled like the M1a exemption flags. |
| S11 unreadable package | `b0d097d` | fixed | Classes targets only; paths only when the component or SharedDLLs read is incomplete; counted in a warning. |
| S12 task file in execdiff | `8b18914` | partly (sub-review) | Residue M4. |

`6875311` and `424852f` only add `msi_only`, `arg_paths` and an indexed service to test helpers; no
assertion was weakened in the lines they touch.

## R3 attack items

- **Object of another installed product offered.** B1 (another user's install), S2, S4, S5.
- **Attribution by name.** Services, tasks and rules: a name alone never makes a candidate; a
  recorded name gives a listing with `ObjectChangedSinceHarvest` when the digest differs (as
  designed). Tracing: S5. WER: the `AppPath` line decides, not the folder name. Product names: none.
- **Keys offered whole.** CLSID and TypeLib version keys lower to Tier B on a subkey COM does not
  define; Interface keys do not (M7). Handler keys are offered whole only with a default value and
  nothing else. Value containers are never offered as keys.
- **Registry views.** No candidate is spelled through `HKLM\SOFTWARE\WOW6432Node\Classes` or `HKCR`
  (`Place::key`, `split_classes` only reads such spellings). Each view of a class is judged alone.
- **Reads outside ScanCtx, walker calls.** None: no `.walker(`, `refscan::scan`, `std::fs`,
  `std::process` or `purge_win` in `purge-scan/src` outside `ref_any.rs` and `framework`.
  Budgets were read, not measured. SYS-BURNDEPS exceeds 8 opens per provider with more than about
  six loaded hives; the S4 fix removes that.
- **Safe without Tier A of matching scope; Partial preselected.** Not found. An unrecorded object
  gets Value-scope evidence only; `Reversibility::Partial` and `None` carry their soft blockers.
  The weak point is the proof of absence behind Tier A (S1).

## Rulings on the coordinator notes

- **S-SERVICE.** Warnings from `sysobj.errors`: fix in SCAN-INTEG. Every service blocked while one
  is unreadable: accept, and replace the error-text match by a typed field (R2a M12, still open).
  Driver, other-app checks, type 0: accept.
- **S-FIREWALL.** Copied `map_rule` and undo root check: accept; add a test in `purge-exec` or
  `xtask` that compares the two on generated rules. `ReversibilityNone` for an App outside the
  roots: accept (None is the true answer). Recorded-but-unresolved fallback: accept.
- **S-COM.** Walked users only: accept for recall, fix for referrers (S3). `evidence_also` without a
  constructor: accept. TypeLib-only interfaces through rows only, AppID without a referring class:
  accept. Blocked proxy class still attributes its interface: accept. Own row matching in
  COM-INTERFACE: accept; M9 of R2a (canonical target first) still applies.
- **S-TASK.** COM handler never gone: accept (Likely). Misleading reason text: fix the text.
  Unreadable recorded task: accept. `%LOCALAPPDATA%` path blocked as `sys.task.windows`: accept;
  give it its own rule id before the gate.
- **S-MSIREG.** Warnings: done in `b0d097d`. Per-user `Features\<P>` not emitted: accept. Content
  rule reading twice and capping component values: accept. Component values under the product's own
  SID only: accept, and do the same for the Products keys (B1). SharedDLLs views: settled by the S1
  fix. Count limit 0, Folders values guard-blocked unless gone: accept.
- **S-BURN.** `bundle_gone` without the inventory: decide with S4 (use `bundle_known`'s rule).
  Shared-component check on the provider key: accept. Suggestion with Tier A evidence on another
  app's key: accept while the action is ReportOnly; SCAN-INTEG asserts it is never selectable.
  `source_dirs` not on the gone list: accept (the harvest never fills them). `ScanExt::none()`
  complete and empty: accept. Read budget: fixed by S4. `MsiPackageUnreadable` on Dependencies
  keys: accept.
- **S-SHELLEX.** Evidence choice, Safe rules for key and value: accept. Containers: fix (M10).
  PropertyHandlers: accept (not in the design). Non-walked hive blocks: accept.
- **S-PRIVACY.** UFH\SHC Likely and the renamed test: accept; correct the test name in the design.
  Own-hive rule and no profile decoding elsewhere: accept. UserAssist over budget: accept with a
  warning. FeatureUsage GUID names, MSI apps without shortcuts: accept (recall).
- **S-DIAG.** Local generic stems: move them to `kb/generic-tokens.json`. WER evidence kind: accept.
  A Windows source re-pointed on a host without a baseline can be Likely: accept (never
  preselected). ProgramData reports emitted and denied: accept. Source subkeys unchecked: fix with
  one `subkeys()` (inside the budget). Warnings: fix (M9).
- **S-APPX.** Exact family, no bundles: accept. Other users give ReportOnly: accept. Unelevated
  scans turn the Notepad++ package into ReportOnly: accept; list it in `M1B_GATE.md`. Fact after
  `build()`: fix (M8). `no-new-walks`: SCAN-INTEG.

## What M1B-SCAN-INTEG must carry

1. B1 before REG-ARP-MSI enters the catalog; S2, S4, S5 before their scanners enter it.
2. Scan warnings for the seven scanners of M9 and for `sysobj.errors`; the walk's completeness in
   `ScanExt` (S3).
3. The catalog's container table: the three keys of M10; the guard's `M1B_VALUE_CONTAINERS` appended
   (R2a note).
4. `xtask no-new-walks`: the tree is clean today by grep; the allow-list is `ref_any.rs`,
   `framework.rs`, `framework/m1b.rs`.
5. New unit fixtures as end-to-end cases: the same MSI installed for a second user, a type library
   re-registered by a sibling, a tracing stem shared with an installed app, a per-user bundle of two
   users.
6. The replay diff: after the S10 fix the four Firefox items are back in their M1a bands, so no
   `guard_m1b` reason is needed. Rows changed by the S1 rule on non-MSI apps carry
   `msi_blocker_added`.

## Not reviewed

- Test bodies, beyond the tests named above and a check of required names against the design.
- Key-open budgets and timing by measurement.
- `crates/purge-exec`, `purge-win`, and the rig scripts.
- Behaviour of `exists()` on a missing volume in the live source (S1).
