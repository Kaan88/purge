# Points for the next Fable review (wave 2 doubts)

X-FOUND (04d58c9):
- running object gets no stamp -> act refused; right?
- TaskDef doesn't check stored_password vs logon_type; FwDef doesn't check fields vs parsed rule string
- new fault points appended, not in run order
- write_def returns DefWriteError (not ExecError); read_def bounded on ObjectDef
- outside list: tests/crash.rs (3 points NotDriven), bins/purge-engine/tests/exec_cli.rs (16->19)

SYSOBJ:
- skipped unreadable service vanishes from dependents_of -> non-empty errors must mean "dependents unknown"
- package_bound: any S-1-15- value
- "other" task action never resolves; COM handler mixed with exec left to caller
- DependOnService as REG_SZ read as one entry
- per-user service `_<hex>` suffix matched loosely
- svchost ServiceDll only when exe is System32/SysWOW64 svchost
- read_services/read_firewall take env + errors (contract deviation)
- outside list: purge-index Cargo.toml (+purge-win, serde_json), Cargo.lock

Environment: the session runs elevated since 2026-11-17; 3 tests fail only elevated (gate key_actions_and_emptiness, storage strict_policy_*, purge-win set_security_round_trips*). Run CI unelevated once before gate.

OWNERSHIP (67af242):
- product with no LocalPackage counts as unreadable
- non-Registry rows and `+` rows are key-only (no values, no subtree)
- component cap hit -> only `incomplete`, products not marked unreadable
- WOW64: guard has no shared-key list, maps all HKLM\SOFTWARE 32-bit to WOW6432Node; 32-bit rows also indexed under 64-bit spelling (extra block only); ProgId/TypeLib/AppId under both views; guard spells 32-bit Classes SOFTWARE\WOW6432Node\Classes, against cross-package note
- OwnershipStats extra fields; build_with_limits; disk cache admin-only; deps serde/sha2 added
- merge: coordinator fixed duplicate serde_json in purge-index Cargo.toml

Elevation check (coordinator): at f209730 the same 3 tests fail deterministically (lib and rig-feature runs) -> environment, not regression. Merged head shows the same 3.

GUARD (after 336c2a6 cherry-pick order: GUARD then POLICY):
- new containers in separate M1B_VALUE_CONTAINERS (catalog test equality); M1B-SCAN-INTEG must append them
- M1a results changed per contract: Installer/Package Cache children denied without lists; Firefox COM test now 4 Gecko items Blocked (assertions updated)
- added rule com.shared-proxy (not in contract)
- Exemptions<'a> compile fixes in guard live.rs, plan decide.rs, exec gate.rs/execute.rs; nsis.rs test edit
- journal drops gone lists -> act-time gate denies (fail closed); X-* / X-INTEG must journal them
- free check_object finds %SystemRoot% from path text only
- Installer\Folders values open whenever any gone product listed
- unknown service type blocked as sys.driver; WER reports stay denied

POLICY (336c2a6):
- implied Partial blocker covers typed objects only (keeps golden row); stricter = one line
- MSI-only object gets imprecise ScopeMismatch explanation
- golden property test asserts Safe => not System; latent
- explain.rs Note::PartialUndo; inno.plan-show.txt golden re-blessed (hash/policy line only)

SOURCE-IMPL (1b09823):
- relative LocalPackage -> InvalidPath; MSI open failure -> NotFound only on proven absence
- stored_password=true when logon type unknown; author/run_as None in snapshots
- empty tasks section treated as NotCaptured (unknown); partial actions_detail fails the load
- new file format msi-tables-<run>-<phase>.json (purge.rig.msi_tables/1), M1B-RIG-HOST must write it
- unknown task action kinds: CIM class name in snapshots vs type_<n> live -> digests differ

RIGTOOL (2323585; crate is vm/rigtool):
- traps needs --app (not in contract CLI); deep.rs now captures task XML+SDDL and raw firewall rule string
- RESULT.json normalisation includes Tree|SD (brief omitted it); followed RESULT.json
- "5 bytes of Triggers" only same type+length enforced
- task FILE (System32\Tasks) differs after re-registration and is NOT excused -> likely false collateral at the gate; decide
- service SCM settings/SD compared via registry values; ReportOnly listing counts as wrong for protected_correct
- 2 more purge-exec tests (a_recorded_owner..., a_directory_whose_delete_is_denied...) fail elevated depending on test order; pass alone

HARVEST:
- ownership index built only for MSI and Burn entries; R-MSI refuses folders inside another app's dirs; tasks with foreign COM handler not recorded; WELL_KNOWN_SHARED ProgIds refused; warnings notes capped at 20; optional r4 replay test not done
- shortcut-target corroboration not fed (no shortcut walk at roots step); only InstallLocation + folder properties corroborate
- Burn children's own uninstall entries count as OTHER apps for RootEnv (check: blocks the bundle's own child dirs?)
- MSI products without uninstall entry never harvested as Burn children
- anchors.rs is_structural pub(crate)

X-SERVICE:
- ServiceBackend trait has 6 more calls than C-ACT
- undo of non-builtin account -> Restored without password "and says so" (should outcome be Partial per decision 3?)
- program_roots is a parameter (journal header has no roots); X-INTEG must wire
- re-run with this op's undo_intent continues its partial restore
- in_baseline passed as false; root-key SDDL not compared; program resolution copied from scanner, not shared
- fault-inject tests only run with --features fault-inject, which xtask ci never sets -> add to ci?

FRAMEWORK:
- M1a replay plans identical to 52b0e56; but stored plans/purge-replay.json (Nov 13) differ in git and firefox bands already at 52b0e56 -> which wave-2 change (GUARD Installer/PackageCache/Firefox COM?) moved M1a bands; gate M1a replay must explain
- ScanExt private hits_app/faults; HKCR spellings of a store -> None; object without harvest record lowered to Tier B (addition); MsiPackageUnreadable also when ownership incomplete
- unknown SharedDLLs count -> SharedRefcount hard blocker; SharedRefcount exact file only, not dirs
- reg test suite ~143 s

PLAN (merged on top of FRAMEWORK):
- pipeline.rs passes m1b: Default::default() -> gone lists empty in the real pipeline; must be filled with M1bDecide::from_facts (who: X-INTEG / SCAN-INTEG?) - otherwise Installer/Cache exemptions never open
- executor gate still passes empty lists -> exempted items refused at act time (same as GUARD note)
- merge treats "no fp" vs "fp" as mismatch -> ObjectChangedSinceHarvest blocker
- client-list containers (UpgradeCodes\<U>, Components\<C> delete-if-empty) dropped from plan rather than Blocked
- extra checks: bundle provider key needs empty dependents_at_harvest; packed code must match ProductCode
- DecideCtx Clone not Copy

X-TASK:
- backend has extra `flush`, register create-only flag; undo split into check + register (undo intent journalled between)
- undo takes roots param (journal header lacks roots; empty -> ProgramOutsideRoot); X-INTEG must add header field (same as X-SERVICE program_roots)
- act decides stored password from backend flag, logon type or XML; undo rechecks all three
- guard checked once per exec action (one action under %SystemRoot% blocks the task)
- XML-names-identity-actions check is text matching of escaping forms, unverified on real XML
- %LOCALAPPDATA%-style profile tokens unresolved in guard check -> those tasks blocked

X-FIREWALL:
- RISK: field mappings never re-created on a VM (Edge, Defer=App, ICMP, LSM, LOM, local addrs, Profile=Domain) are NOT refused; if a mapping is wrong, undo deletes the half-made rule and the rule is LOST. Options: refuse those fields until a VM round trip proves them, or keep the backup string so the rule is never lost.
- service rules (App=svchost) never undoable: ProgramOutsideRoot -> must not be offered/preselected
- crash between create and cleanup delete leaves ObjectExists
- refuses rules map_rule can't re-create (CannotBackUp); undo refuses fields != parse(rule string) (BackupTampered); post-delete re-read; reads retry 5 s; op id spelled differently from stored name -> ChangedSinceScan; fw.resource-name also checks EmbedCtxt
- program_roots param; X-INTEG wires

S-SERVICE (wave 4):
- scanners cannot add scan warnings; SCAN-INTEG should surface sysobj.errors as warnings
- any unreadable service -> every offered service gets HasDependents (relies on index error text "sysobj: service <name>: ...") -> may block all app services on such hosts
- added Driver, InsideOtherApp, ReferencedByOtherApp checks; type 0 -> unknown -> sys.driver

S-FIREWALL (wave 4, for R3):
- recreate_refusal copies purge-win map_rule (checked equal on 400k generated rules); undo root check copied too -> keep in sync
- App outside InstallRoot -> ReversibilityNone (soft, never preselected); None vs Partial?
- recorded-but-unresolved-now fallback; no scanner warning API

S-COM (wave 4, for R3):
- no scan-warning channel; only walked users scanned (HKU\<SID>_Classes)
- ComKeyOwnership / DanglingRef added through evidence_also (no constructor)
- TypeLib-only interface found only via MSI/Inno rows; AppID with no referring class -> no candidate
- blocked proxy class still attributes its interface (ISimpleDOMNode listed Protected); relates to R2a S10 (Firefox K6/K16)
- interface MSI-row check is own path matching, not framework code

S-TASK (wave 4, for R3):
- COM handler never treated as gone (zero key-open budget); unrecorded COM-only task reason "program_in_root" misleading
- recorded but unreadable task carries empty-actions digest -> executor never acts
- guard checks each exec path like executor gate; %LOCALAPPDATA% path -> Blocked as sys.task.windows (misleading rule name for an executor limit)

S-MSIREG (wave 4, for R3):
- ScanExt::fault private -> no scan warnings (SCAN-INTEG / framework fix)
- per-user HKU\<sid>\...\Installer\Features\<P> not emitted (reg.installer does not allow it)
- sealing content rule reads every value candidate twice (build + run)
- component values use product context SID only; existence from merged index
- content rule caps some component values at Likely
- REG-SHAREDDLLS DROPS framework SharedRefcount (sums both views, no non-MSI minimum) and counts each view alone; if SharedDLLs is WOW64-shared the views are one key -> check with R2a S1 fix
- MSI app count limit = components keyed on the file, can be 0
- INSTFOLDERS values guard-blocked unless a gone MSI product
