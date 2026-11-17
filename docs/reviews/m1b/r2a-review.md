# M1b review R2a: scan and plan side

Reviewed at `c3b74e7` (branch `m1b`). Packages: M1B-SYSOBJ `5c17d1d`, M1B-OWNERSHIP `67af242`,
M1B-GUARD `a1d6f21`, M1B-POLICY `336c2a6`, M1B-SOURCE-IMPL `52b0e56`, M1B-RIGTOOL `dd3a22b`,
M1B-HARVEST `c5af2e8`, M1B-FRAMEWORK `56c5d2e`, M1B-PLAN `f4fa477`.
Reviewer changed no source code and ran no build or test.

## Verdict

**Accept with required changes.**

No blocking finding: nothing merged so far can delete anything, because the wave-4 scanners are not in
the catalog, the pipeline passes empty exemption lists and the executor gate passes empty lists too.
The guard's exemption shapes held against every spelling tried (see "Checked and found sound").

Twelve serious findings (S1 to S12). Most are places where a wave-4 scanner or the wave-5 integration
would inherit a wrong answer: attribution of system objects (S2 to S5), Burn facts taken from
user-writable keys (S6, S7), ownership that is silently empty (S1, S8), and two gate questions (S10,
S12). S1 to S9 must be fixed or decided before M1B-SCAN-INTEG is merged; S10 to S12 before the gate.

Evidence labels:

- **reading**: confirmed by reading the code; no run.
- **suspected**: not confirmed, or the end effect depends on code outside the reviewed packages.

No finding has the label "experiment": builds and tests were not allowed during this review.
OWNERSHIP, HARVEST, SYSOBJ, SOURCE-IMPL and RIGTOOL were read by two sub-reviewers; I re-read the
code behind S4, S6 and S7 myself. Their other findings are marked "(sub-review)".

## Answers to the coordinator's questions

1. **Guard exemptions, one segment wider or narrower.** Sound. All shapes compare whole folded
   segments of the canonical key. `HKCR` spellings are refused (`canon.hkcr`), both 32-bit Classes
   spellings and both spellings of a user's Classes give one answer, and nothing under `HKLM\SYSTEM`
   is opened by the lists. One minor point: M1.
2. **Can a scanner or a plan file put a product on the gone lists?** A scanner: no (private fields,
   `from_facts` reads the fingerprint only). A plan file: no, today. Two other ways exist: a
   user-writable Burn entry can put any Package Cache folder into the fingerprint (S7), and nobody is
   assigned the executor side, where the lists must not arrive through the plan or journal (S9).
3. **Who wires `M1bDecide::from_facts`.** M1B-SCAN-INTEG, by the design text and the commit message.
   The design rule names only `product_known`; `bundle_known` and the executor side are unassigned (S9).
4. **M1a plans moved in git and firefox.** The stored `vm/runs/*/plans/purge-replay.json` are from
   Nov 13 14:42. They predate M1a passes four to eleven (`1d72271`, Nov 15, policy m1a.6) and
   M2-POSTM1A (`e3fa263`), so they are not a valid reference for wave 2. By reading, exactly one
   wave-2 change moves M1a items: the guard's `com.shared-iid` and `com.shared-proxy` rules, which
   block four Firefox items (S10). Nothing in wave 2 touches the four git targets (`UFH\SHC` values,
   `LibraryFolder\background\shell`, `sh_auto_file`); the git difference is not explained by reading.
   A replay at `f209730` is needed to pin it.
5. **RIGTOOL and the task file.** Excuse it, narrowly (S12).

## Serious findings

### S1. SharedRefcount is excused by the app's harvest-time components, and never covers a directory (reading)

`crates/purge-scan/src/framework/m1b.rs:696-701`, `:766-777`.

- The blocker is raised only when the SharedDLLs count is larger than the number of the app's own
  components keyed on the file. Those components come from the fingerprint, so from before the
  uninstall.
- Windows Installer lowers the count when it removes the component. After a normal uninstall, every
  remaining count belongs to someone else.
- Scenario: MSI app A and a non-MSI app B both count `Common Files\Vendor\shared.dll` (count 2). A is
  uninstalled, count is 1. The scan sees 1 > 1 false, so no blocker. B is not an MSI, so no component
  client protects the file either. The file can be offered, and so can its counter (REG-SHAREDDLLS).
- A directory candidate that contains a counted file gets no SharedRefcount at all
  (`shared_dll_count` is an exact-file lookup).
- Fix: count an own component only while the fresh index still lists the app's product as a client
  of it (`clients_of`); otherwise the app explains 0. Add a lookup for counted files at or below a
  directory and use it for directory targets.
- Reaches: every FS scanner through the sealing, REG-SHAREDDLLS.

### S2. The object rules are not applied centrally; the sealing accepts any well-formed digest (reading)

`framework/m1b.rs:825-866` (`seal_object`), `crates/purge-guard/src/deny.rs:525-529` (typed targets
always pass the deny-list), `crates/purge-plan/src/decide.rs` (no `check_object` call).

- `check_object` is called by each scanner that remembers to (`sys_service.rs`, `sys_firewall.rs`,
  harvest). The sealing only checks that `object_fp` has the right kind and 64 hex digits. The plan
  step lets every typed target through.
- Scenario: a scanner offers a service without calling `check_object`, or with a digest of its own
  making. A driver, a per-user service or a task under `\Microsoft\Windows` is listed in the plan.
  The executor gate would refuse it at act time, but the plan lists it (K1 `danger_listed`).
- Fix: in `seal_object`, find the object in `ctx.ext.sysobj` by name, path or id. Not found, or its
  digest differs from the candidate's: drop and record a fault. Found: add the blocker of
  `DenyList::check_object` with the index facts and the baseline. Then no scanner can skip the rules.
- Reaches: S-SERVICE, S-TASK, S-FIREWALL.

### S3. A service is "backed" by an MSI row of the same name alone (reading)

`framework/m1b.rs:790-800`.

- `object_backed` accepts a service when any `ServiceInstall` row of the app's MSI has its name. No
  digest and no program is compared, and `OwnedSystemObject` then stays Tier A.
- Scenario: the app's MSI installed service `VendorUpdate`. After the uninstall, another product of
  the vendor (not an MSI, so no row blocker) runs a service of that name from its own folder. The
  name match keeps Tier A; the service can be Safe and preselected.
- The branch is not needed: harvest already records row services in `fp.sys` with their digest
  (`crates/purge-harvest/src/sysobj.rs:128`).
- Fix: remove the name-only branch; require the `fp.sys` record with the same digest for every kind.
- Reaches: S-SERVICE.

### S4. Harvest records system objects against every root kind (reading)

`crates/purge-harvest/src/sysobj.rs:82-84`; `harvest.rs` passes `&fp.roots`.

- `owned` tests all roots, inferred ones included. The scan side (`object_owner`) uses install roots
  only, but a harvest record is what grants Tier A.
- Scenario: an entry with only a DisplayIcon gets the inferred root `D:\Tools\bin`. Another tool's
  task that runs `D:\Tools\bin\other.exe` is recorded as `ProgramInRoot` and can come out Safe.
- Fix: count `InstallRoot` only, or record the object with a flag that keeps it at Tier B.
- Reaches: S-SERVICE, S-TASK, S-FIREWALL.

### S5. The host list is too short and arguments are never looked at (sub-review; reading, reach suspected)

`kb/hosts.json`, `crates/purge-index/src/sysobj.rs:186-213`, `:654-669`.

- The code follows C-SYSOBJ; the gap is in the contract list. Missing hosts that live inside an
  app's own root: `dotnet.exe`, `py.exe`, `pyw.exe`, `bash.exe`, `sh.exe`, `git-bash.exe`,
  `perl.exe`, `ruby.exe`, `php.exe`, `deno.exe`, `bun.exe`, `nssm.exe`, `srvany.exe`, `mshta.exe`,
  `wsl.exe`, `powershell_ise.exe`.
- Scenario: uninstalling the .NET runtime (root `C:\Program Files\dotnet`). Another product's
  service `"C:\Program Files\dotnet\dotnet.exe" C:\Other\svc.dll` resolves to a file inside the root.
- Related (M-level, same fix area): a host named without `.exe` before a relative argument
  (`C:\Python312\python scripts\run.bat`) resolves to one file (`sysobj.rs:254-290`).
- Fix: extend the list; return Unresolved when any whitespace-delimited prefix is a host; treat
  "program in root plus an absolute argument outside every root" as not owned.
- Reaches: HARVEST, S-SERVICE, S-TASK, S-FIREWALL.

### S6. Burn children can be claimed through a user-writable Dependencies key (reading; end effect suspected)

`crates/purge-index/src/ownership.rs:872-917`, `crates/purge-harvest/src/burn.rs:66-77`, `:139-149`.

- The index merges providers and dependents from HKLM and from every loaded user's Classes under one
  name, without recording where each came from. Harvest takes every provider that lists the bundle,
  and accepts a GUID-named provider as a ProductCode.
- Scenario: a standard user creates
  `HKCU\Software\Classes\Installer\Dependencies\{Victim}\Dependents\{machine bundle id}`. Victim, a
  machine MSI, becomes a child of the bundle: its folder becomes an install root, its key paths
  become the bundle's files, its services are recorded, its code enters `fp.msi`.
- While Victim is installed, `MsiProductStillRegistered` blocks paths with components and rows. Keys
  and files without a row or component are not covered, and once Victim is gone its code is on the
  gone list.
- Fix: keep the hive of each provider and dependent. A machine bundle uses HKLM records only; a
  per-user bundle uses HKLM plus its own user. Add a hostile test.
- Reaches: every FS and REG scanner through the roots, S-BURN, S-MSIREG, S-SERVICE.

### S7. Burn cache folders are not tied to the bundle or product (reading)

`crates/purge-harvest/src/burn.rs:82-103`, `:116-131`; `crates/purge-plan/src/decide.rs:140-159`.

- Any direct child of any Package Cache root is accepted as `cache_path` (from `BundleCachePath`) or
  as a package's `cache_dir` (from `LastUsedSource`). For a per-user entry both values are
  user-writable. `from_facts` copies them into `gone_cache_dirs`; the guard checks only "direct child
  of a cache root".
- Scenario: a per-user Burn entry names `C:\ProgramData\Package Cache\{another bundle}`. When that
  entry is gone, the other bundle's cache folder is exempt from `fs.package-cache`.
- Fix: require the leaf to be the bundle id (or to start with the ProductCode for a package), and
  allow a per-user entry only that user's `%LOCALAPPDATA%\Package Cache`.
- Reaches: FS-PKGCACHE, the gone lists.

### S8. MSI products outside `inventory.entries` own nothing, silently (sub-review; reading)

`crates/purge-index/src/ownership.rs:626-655`, `:929`; `ownership/msi_rows.rs:266-272`.

- Only inventory entries with MSI data are read. Products in `InventoryDoc::msi_only` (no Uninstall
  key, other users' products) have no rows and are not in `unreadable()`.
- A per-user product attached to an HKLM entry has no `user_sid`, so all its per-user rows are
  dropped without marking the product unreadable.
- This is the "could not read becomes owns nothing" case of the attack list.
- Fix: feed `msi_only` products to the index or list them as unreadable; carry `user_sid`; mark a
  product unreadable when a row is dropped for a missing SID.
- Reaches: every scanner through `msi_blockers`.

### S9. The exemption lists have no owner on the executor side, and `bundle_known` has no rule (reading)

`bins/purge-engine/src/pipeline.rs:923`, `crates/purge-exec/src/gate.rs:928-970`, design entries
M1B-SCAN-INTEG and M1B-X-INTEG.

- The executor gate drops the lists when it journals exemptions and reads them back empty. That is
  closed, but it means every Installer and Package Cache item a plan offers is refused at act time.
  No package entry assigns the fix.
- If the lists were carried in the plan or journal, a plan file could name any Package Cache folder
  or product. The executor must compute them itself: `from_facts` over the stored fingerprint with a
  fresh query at act time.
- SCAN-INTEG's rule names `product_known` only. `bundle_known` needs a rule too, including "unknown"
  for a per-user bundle whose hive is not loaded.
- Fix: decide the owner (X-INTEG) and write both rules into the design before wave 5.
- Reaches: X-INTEG, SCAN-INTEG, S-MSIREG, S-BURN, FS-PKGCACHE.

### S10. The shared-IID rules block four Firefox items that the frozen truth labels leftover (reading)

`crates/purge-guard/src/deny/rules.rs:259-281`, `kb/shared-iids.json`,
`bins/purge-engine/tests/engine/nsis.rs:339-357`, `vm/truth/m1a-frozen-firefox.md:51-53`.

- `CLSID\{1814CEEB-…}` and `Interface\{1814CEEB-…, 0D68D6D0-…, 4E747BE5-…}` were Safe or Likely hits
  in M1a. They are now Blocked (`com.shared-proxy`, `com.shared-iid`). The truth labels the CLSID and
  Interface keys `leftover`.
- This is the intended effect of C-GUARD (`com.shared-proxy` is an addition to it), and it is the
  wave-2 change that moved the Firefox bands.
- At the gate it trips K6 (a leftover item must be Safe or Likely) and K16 (the allowed reasons are
  `new_scanner`, `msi_blocker_added`, `msi_root_added`, `policy_m1b`; none fits a guard rule).
- Decide: keep the rule (my recommendation: the keys are shared on the dirty base), add the reason
  `guard_m1b` to the replay diff, and state how K6 treats a leftover that a shared rule blocks.
- Reaches: SCAN-INTEG (replay diff), S-COM, GATE.

### S11. One unreadable package lowers every Classes and Program Files item of every app (reading; frequency suspected)

`framework/m1b.rs:199-207`, `:731-733`.

- `MsiPackageUnreadable` is added whenever any product is unreadable or any of three areas is
  incomplete, to every registry target under a Classes root and every path under Program Files. A
  product without a `LocalPackage` counts as unreadable.
- On a host with hundreds of products one missing cached MSI is common. Then no such item is Safe or
  preselected, for MSI and non-MSI apps alike. The rig VMs will not show it.
- The component clients come from the registry, not from the package. For a path, an unreadable
  package hides nothing as long as the component read is complete.
- Fix: for paths, raise the blocker only when the component area is incomplete. For Classes, keep
  it, and report the count of affected items in the scan warnings. Measure on the 591-program host
  at G7.
- Reaches: every scanner; S-COM most.

### S12. execdiff does not excuse the task file after a re-registration (sub-review; reading)

`vm/rigtool/src/execdiff.rs:612`, `vm/spikes/m1b/RESULT.json` (task case 1: `file_equal: false`,
`xml_equal` and `sddl_equal` true).

- Any run in which a DeleteTask is undone or recovered shows `System32\Tasks\<path>` as collateral: a
  false K10 or K13 failure.
- Ruling: excuse exactly the task file of a DeleteTask whose task exists before and after, when its
  kind, attributes and reparse state are unchanged. Tag it `task-reregistered` and print it. The
  content stays vouched for by fidelity (XML and SDDL).
- Reaches: RIG-EXEC, GATE.

## Minor findings

- **M1 (reading).** `deny.rs:794-803`: the three `...\CurrentVersion\Installer` shapes are also open
  in the 32-bit view, where Windows Installer keeps nothing. Require the 64-bit view for them.
- **M2 (reading).** `deny/objects.rs:79-83`: a service type without a driver bit passes, type 0
  included. Allow only types with bit `0x10` or `0x20`; block the rest as `sys.driver`.
- **M3 (suspected).** `deny/objects.rs:124-160`: `under_system_root` does not resolve `..` or trailing
  dots, and `\Device\HarddiskVolumeN\Windows\...` is "not Windows". Sound while callers pass the
  output of `resolve_program`; reject such forms in `check_object_in` as well.
- **M4 (reading).** `deny.rs:829-831`: with any gone product, every named value of `Installer\Folders`
  passes the guard. Accepted by the contract; REG-INSTFOLDERS must be the only source and R3 must
  check it.
- **M5 (reading).** `decide.rs:143-146`: the provider key is exempt when `dependents_at_harvest` is
  empty. S-BURN must re-read `Dependents` at scan time and refuse the key when any remains.
- **M6 (reading).** `framework/m1b.rs:941-956`: `msi_registration` checks that the product is the
  app's, not that the target is a registration of it. Check the target shape in the builder, or R3
  checks every caller.
- **M7 (reading).** `framework/m1b.rs:671-675`: a path that does not canonicalise gets no ownership
  lookup. The guard denies such a path later; add `MsiPackageUnreadable` here so the two do not
  depend on each other.
- **M8 (reading).** `pipeline.rs:864`: `ScanExt::build` gets no table cache, so the warm budget of K14
  cannot be met until SCAN-INTEG wires it.
- **M9 (reading).** `framework/m1b.rs:440-464`: `bind_any_user` handles `_Classes` itself. A row
  `HKU\*_Classes\X` does not bind to a target spelled `HKU\<sid>\Software\Classes\X`. Recall only;
  canonicalise the target first.
- **M10 (sub-review, reading).** OWNERSHIP: Class, ProgId, TypeLib and AppId rows claim only their
  own key, not the subtree (`msi_rows.rs:426,439`); 32-bit rows on shared keys are spelled only under
  WOW6432Node in the fingerprint (`msi_rows.rs:118`); unresolved rows are dropped with a global count
  only. Reaches S-COM, S-SHELLEX, S-MSIREG.
- **M11 (sub-review, reading).** HARVEST: key paths in `Vendor\AppA` and `Vendor\Shared` give the
  root `Program Files\Vendor` (`msi.rs:455-461,514-518`); unregistered neighbours are not seen. No
  test covers it. A Burn child with an InstallLocation makes the bundle's root `HoldsOtherApp`
  (`roots.rs:442-457`); recall only.
- **M12 (sub-review, reading).** SYSOBJ: `resource_name` ignores `EmbedCtxt` (`sysobj.rs:574-577`);
  `package_bound` tests `S-1-15-` only at the start of a value (`:570-573`); "dependents unknown" is
  carried as error text that `sys_service.rs:71` matches by prefix. Use typed fields.
- **M13 (sub-review, reading).** SOURCE-IMPL: an MSI table error 2 or 3 maps to `NotFound` after the
  package was opened (`live/sysobj.rs:104`). Map it to `Other`.
- **M14 (sub-review, suspected).** RIGTOOL: an object absent in both deep captures counts as an exact
  row (`fidelity.rs:1944-1952`). Absent before must mean unverifiable.

## Checked and found sound

- **Guard shapes.** Parent, child and sibling of `Products\<P>`; packed code as a substring; the
  `Components\<C>` key (always denied, `msi.component-foreign`); `RegValueChanged` and segment targets
  (never exempt); Burn names with `\` or `*` (ignored); a cache entry that is a root, deeper than a
  direct child, outside a cache or with a short-name segment (ignored).
- **Aliases.** No second WOW64, HKCR or control-set table in GUARD, FRAMEWORK, PLAN, OWNERSHIP or
  HARVEST; all go through `canon_key`. The cross-package note on the 32-bit Classes spelling should be
  corrected to the guard's spelling.
- **Policy.** P-OBJ-1 and P-OBJ-2 as written; no other rule changed; an unbacked
  `OwnedSystemObject` is Tier B and cannot make an object Safe.
- **Sealing.** `ctx.run` is the one call site (`pipeline.rs:892`); `msi_blockers` reaches M1a
  scanners' candidates; a co-removed product is judged with its own fingerprint.
- **Path stores.** Bare names, UNC, relative names, `@` names, non-path UserAssist names and prefix
  siblings are refused; ROT13 touches ASCII letters only. A store key spelled through HKCR is not
  recognised, and such a target is denied by the guard anyway.
- **Plan.** Only `Some(false)` makes anything gone; a packed code that does not match its ProductCode
  is ignored; typed candidates never nest.
- **Sub-reviews.** `resolve_program` forms (quoted, 8.3, UNC, device, relative, ADS); MSI open
  failure is `NotFound` only on proven absence; no install or UI path; row, cell and task limits;
  stale and permanent clients count as others; truncated tables and a missing package end in
  `unreadable()`; the disk cache is admin-only and validated; R-MSI refuses Program Files, Common
  Files, volume roots and system folders; traps `absent` fails on an equal, covering or inside entry.

## Rulings on the coordinator notes

**SYSOBJ.** Skipped service: accept with M12. `package_bound`: fix (M12). "other" action: accept.
COM handler mixed with exec: accept; S-TASK must refuse a foreign handler (R3). REG_SZ
`DependOnService`: accept. Loose `_<hex>` match: accept. ServiceDll rule: accept. Signature
deviation and Cargo additions: accept; update the contract text.

**OWNERSHIP.** No LocalPackage as unreadable: accept (see S11 for the cost). Key-only rows: fix
(M10). Cap hit gives `incomplete`: accept. WOW64: accept; correct the note, fix the fact spelling
(M10). Stats fields, `build_with_limits`, cache, dependencies: accept.

**GUARD.** Separate `M1B_VALUE_CONTAINERS`: accept. M1a results changed: accept for Installer and
Package Cache; decide for Firefox (S10). `com.shared-proxy`: accept; add it to C-GUARD. Compile
fixes: accept. Journal drops the lists: decide (S9). Free `check_object` without the Windows
directory: accept; scanners and the gate must use `DenyList::check_object`. Folders values: accept
(M4). Unknown type as `sys.driver`: accept, and fix M2. WER reports denied: accept.

**POLICY.** Implied Partial for typed objects only: accept. Imprecise ScopeMismatch text: accept.
Golden property test: fix when the first typed item enters the golden set. Re-blessed golden line:
accept.

**SOURCE-IMPL.** All accepted; M13 for the table error. Unknown action kinds spelled differently:
accept (such actions are never attributed).

**RIGTOOL.** `--app`: accept. `Tree|SD`: accept. Triggers by type and length: accept. Task file:
fix (S12). SCM settings through the registry: accept. ReportOnly counted wrong: decide in
SCAN-INTEG, with K8. Order-dependent elevated failures: environment; run unelevated before the gate.

**HARVEST.** Index for MSI and Burn entries only: accept. R-MSI refusals: accept. Foreign COM
handler tasks: accept. Shared ProgIds: accept. Notes cap: accept. r4 replay: fix before the gate.
Shortcut corroboration: decide; list it as a limit. Burn children as other apps: fix (M11).
Children without an uninstall entry: accept. `is_structural`: accept.

**FRAMEWORK.** M1a replay difference: see answer 4 and S10. Private `hits_app` and `faults`: accept.
HKCR store spelling: accept. Unbacked object lowered to Tier B: accept, and tighten it (S3).
`MsiPackageUnreadable` on incomplete ownership: accept, narrow it (S11). Unknown count as a hard
blocker: accept. Exact file only: fix (S1). 143 s test suite: accept.

**PLAN.** Empty lists in the pipeline and the gate: decide (S9). "No digest" against "digest": accept.
Containers dropped: accept. Extra checks: accept. `DecideCtx` Clone: accept.

## Not reviewed

- `vm/rigtool/src/deep.rs` line by line, and the `purge-win` wrappers (R1).
- Test bodies beyond a spot check of names against the design lists (all required names are present
  in the four test files I listed).
- Real-host behaviour of S11 and the timing budgets.
