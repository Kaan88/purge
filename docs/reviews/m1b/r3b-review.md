# M1b review R3b: executor fixes and M1B-X-INTEG

Reviewed on `m1b` at `644a3fd`: the executor fix round `dd9f81b`, M1B-X-INTEG `f5230c7`, the rig commit
`60bcec0` and the VM results `docs/reviews/m1b/vm-objects-run.md`, against `review_points` R3 (X-INTEG
item), the X-INTEG package entry, C-ACT, C-EXECOP, C-DEF, C-FAULT and `gate_procedure` G6 of
`docs/M1B_DESIGN.json`, `r2b-review.md` (B1, S1 to S6, the carry list), `r1-review.md` (S1 to S4),
`coordinator-notes.md` and `docs/DECISIONS.md` "M1b". The reviewer wrote none of this code, changed no
source and did not delegate.

## Verdict

**No blocking finding. Four serious. The executor may go to the crash matrix after S1 and S2 are fixed;
S3 and S4 before the gate is signed and before any firewall shape is lifted.**

The fix round does what it claims. Every delete of an object with a program is now refused where its
undo would refuse, the act is bound to the backups the intent names, the service undo no longer adopts a
service after a failed create, and the journal names the roots, the key backup and the undo note.
X-INTEG puts the three kinds through one order (validated, definition, intent, `act.before`, act-time
gate, delete, `objdelete.after`, flush, `act.after`, done), takes the roots only from the journal header
at act, recovery and undo, and re-runs the act-time gate on a resumed intent. No path was found that
deletes an object other than the one the op names, deletes without a verified definition, or reports a
restore as exact when the compared state differs.

What is open:

- `cargo xtask ci` cannot pass from an unelevated shell, which DECISIONS requires before the gate (S1).
- "Without roots every object delete is refused" is not true for objects without a program (S2).
- The roots of `exec --fp` are taken as written; the guard's root rule is not applied to them (S3).
- The shape list is coarser than the VM evidence; lifting it as the VM note proposes would lift forms
  that were not proven (S4).

Two facts about readiness that are not defects of this code:

- The VM binaries were built from `b091781`. They hold the fix round, not X-INTEG. The run, journal,
  recovery, undo and CLI path with the live backends has not run on any machine.
- The mode `m1b-x-crash` (M1B-RIG-EXEC) does not exist yet. `crash_matrix_unit` is not a stand-in for it
  (M7).

Evidence labels: **experiment** (a run on this host, Windows 11 26300, elevated shell, fake backends only;
no `#[ignore]`d or rig test was run), **vm** (taken from `vm-objects-run.md`, not repeated), **reading**,
**suspected**.

Tests run (`CARGO_TARGET_DIR=E:\purge-build\review-exec`, 2 jobs):
`cargo test -p purge-exec --features fault-inject,test-support --no-fail-fast`: lib 452 passed, 2 failed,
8 ignored; `act_firewall` 42, `act_service` 49, `act_task` 24 (1 ignored each), `crash` 16, `m1b_exec` 14,
`m1b_found` 15, `no_wired_by` 1, `roundtrip` 10, all passed. The two lib failures
(`act_fs::...a_recorded_owner_the_token_cannot_assign...`, `gate::...a_directory_whose_delete_is_denied...`)
are the ones DECISIONS lists as failing in an elevated shell; neither file was touched by M1b logic.
The purge-engine tests (`--test engine m1b_exec`) were **not run**: the command was refused by the
session's permission check. They were read.

## Fix round `dd9f81b`, finding by finding

| Finding | Result | Note |
|---|---|---|
| R2b B1 (delete not bound to roots; delete where undo must refuse) | **Fixed** for every object with a program; **partly** as the second lock | `gate::file_in_roots` is used by prepare, act and undo of all three kinds; service prepare runs `scm::check_create` and `config2_to_apply` before the key backup; `Svc` rules are refused. A rule without `App` and a task without an exec action pass every root check, also with no roots (S2). |
| R2b S1 (ci runs none of the tests) | **Fixed** | `tools/xtask/src/main.rs:144` runs every purge-exec target with both features; X-INTEG added the engine target. It now runs a test that fails unelevated (S1). |
| R2b S2 (unproven shapes deleted) | **Fixed** | Executor (`act_firewall.rs:300`) and scanner read one list. The `ValueDiffers` detail names the definition file. The list is by key, not by value form (S4). |
| R2b S3 (undo adopts another install's service) | **Fixed** | `own_attempt` is "last attempt open or `Failed{VerifyFailed}`" (`undo.rs:1050`); every failure after the create is `VerifyFailed`; the continue path needs `SERVICE_STOPPED`; hostile test `undo_failed_create_never_adopts_a_later_service`. Residue M1. |
| R2b S4 (backup older than what is deleted) | **Fixed** | Service: tree and SCM definition equal to the files the intent names; task: XML, SDDL, Enabled; firewall: the rule string. A missing file on resume is `NoVerifiedBackup`. The live rig tests of the three modules passed on this code (vm), so the comparison does not refuse a real, unchanged object. |
| R2b S5 (key backup named by no record) | **Fixed** | `Intent.definition` holds it; undo and the act require intent and definition to name the same file and hash. Residue M6. |
| R2b S6 (undo note not journalled) | **Fixed in the journal, partly in use** | `UndoDone.detail` is written (`undo_done_noted`). Nothing reads `JournalState::undo_done_detail` (M5). |
| R1 S1 (roots not in the header) | **Fixed** | `Header::program_roots`, additive; M2 journals parse and write unchanged. What goes into it: S3. |
| R1 S3 (`map_rule` accepts unmeasured shapes) | **Fixed** | `Action`, `Active`, `Dir` required; `RuleMap::shapes`; one list. The VM run shows why: the ICMP mapping fails. |

Nothing was made worse.

## Blocking

None.

## Serious

### S1. `cargo xtask ci` fails from an unelevated shell: `live_read_of_a_builtin_service_is_consistent`

Evidence: vm (pass `p1-user`, Medium integrity), reading. Test defect.

File: `crates/purge-exec/tests/act_service.rs:1532`. The test is not ignored and calls
`LiveServices::capture_key("EventLog", ...)`, which opens `EventLog\Security`: error 5 without elevation.
It passes on this host only because the shell is elevated. Since the R2b S1 fix, `ci` runs this target
(`tools/xtask/src/main.rs:144`), and DECISIONS (2026-11-17) requires `ci` to pass once unelevated before
the gate. As it stands G0 cannot pass.

Not a code defect: `capture_key` is called only by the executor (`act_service.rs:1084`, `:1270`, `:2225`,
`:2326`), which refuses to start without object backends, and the CLI gives backends only to an elevated
process.

Fix: skip without elevation as `purge-win/tests/scm.rs` does (`elevated_or_skip`), or read a service
whose key a Medium token can read in full. Then run `ci` unelevated once and record it.

### S2. With no roots, objects without a program are still deleted

Evidence: reading.

Files: `crates/purge-exec/src/act_firewall.rs:330-340` (`program_refusal`: `RuleProgram::None` passes),
`crates/purge-exec/src/act_task.rs:768-780` (`program_outside_roots` looks at exec actions only);
the claim in `bins/purge-engine/src/cli/exec.rs:42`, `cli/args.rs:44`, `plan_in.rs` (`program_roots`:
"Empty refuses every object delete (fail closed)") and `Header::program_roots`.

A firewall rule with no `App` (a port rule) and a task whose actions are all COM handlers have no
program, so the root check passes for any roots, also for none. Such an item is deleted on its digest
(which the sidecar supplies and the plan hash does not cover), the guard's object rules and the shape
list alone. Undo passes the same way, so this is not the B1 case; it is the missing second lock, and the
text in four places says the opposite.

Scenario: `exec` without `--fp`, or with the fingerprint of an app whose only root was demoted to
`InferredRoot` (a shared install directory), so the header has no roots. Every service is refused, as
promised. A port rule or COM-handler task that the scanner attributed wrongly is deleted.

Fix: in prepare and the act of all three kinds, an empty `program_roots` refuses the item
(`GateBlocked{CannotBackUp}`, "the run recorded no roots"), before the per-program check. Add the hostile
test per kind (port rule, COM-handler task, no roots). Record in DECISIONS that with roots present these
two forms rest on the scanner's attribution alone (R2b M1 and M8, still open).

### S3. The roots of `exec --fp` are not checked by the guard, and the fingerprint is bound to the plan by program id only

Evidence: reading.

Files: `bins/purge-engine/src/cli/exec.rs:836-871` (`app_facts`), `crates/purge-exec/src/gate.rs:1230-1260`
(`file_in_roots`), `crates/purge-exec/src/execute.rs:1074`.

`app_facts` takes every `InstallRoot` of the file as it is. `file_in_roots` accepts any root of depth two
or more: `C:\Program Files`, `C:\ProgramData`, `C:\Windows`. Harvest refuses such roots with
`DenyList::root_rejection`; the executor does not repeat it, although for files and keys it repeats the
whole deny list. The only tie between the fingerprint and the plan is `fp.app.program_id` being an owner
of some item; a fingerprint from an older harvest, or an edited one, is accepted and its roots are
journalled as the run's.

Scenario: a fingerprint whose root is `C:\Program Files (x86)` (written by an older engine, by hand for
the rig, or by a harvest defect of the kind R2a looked for). A plan item names the stopped
`edgeupdatem` service. Digest equal, guard passes (the program is not under `%SystemRoot%`), root check
passes: deleted. The second lock that B1 asked for is as strong as this one file.

Fix: `Run::start` drops, with a warning in the report, every root that `deny.root_rejection(root, true)`
refuses or that does not canonicalise, before the header is written (the executor has the deny list).
That makes the lock independent of who wrote the fingerprint. Binding the fingerprint itself (its hash
in the sidecar) is the fuller fix and belongs with the M3 broker; say so in DECISIONS.

### S4. The shape list is coarser than the evidence: do not lift `OtherProtocol` or `LSM` as they stand

Evidence: vm, reading.

Files: `crates/purge-model/src/object.rs:94-105`, `:145-161` (`FirewallShape::used_by`).

A shape is recognised by key, in two cases by key and one value. The VM proved less than two of the
shapes cover:

- `OtherProtocol` is "`Protocol` other than 6 or 17". Proven: 47. Protocols 1 and 58 were made only with
  ICMP fields, which fail; `Protocol=1` without them, and every other number, were not made.
- `LooseSourceMapping` is "`LSM` present". Proven with `Dir=Out`; with `Dir=In` the provider refuses the
  create (0x80041001, and `New-NetFirewallRule` refuses it too). A stored inbound `LSM` rule could not be
  put back.

Scenario if the list is cut as section 3 of the VM note proposes ("8 of 10 can be lifted, and LSM too"):
a rule `Protocol=1|Name=...` (all ICMP, no type list) is deleted; whether it can be made again was never
measured, and a failed re-create ends as R1 S3 described, with the rule gone.

Ruling, per shape:

| Shape | Ruling |
|---|---|
| `EdgeTraversal`, `DeferApp`, `LocalOnlyMapping`, `LocalAddresses`, `DomainProfile`, `RemotePortRange`, `LanInterface` | Lift. Own and native round trips byte-equal, twice. `map_rule` already limits `Edge` to `TRUE` and `Defer=App` to rules with `Edge=TRUE`. |
| `OtherProtocol` | Lift for 47 only: change `used_by` to `v != "6" && v != "17" && v != "47"`, or leave the line. |
| `LooseSourceMapping` | Leave the line, or make the shape "`LSM` with `Dir` other than `Out`". The first costs nothing: Windows cannot make an inbound one. |
| `IcmpTypes` | Stays. See "VM results". |

Each lifted line needs its case in the unit test that compares `map_rule`'s shapes with the model's, and
the scanner's copy follows the same list. Results are for 26100 only; G8 (Pro 26340) should run the two
rig tests once.

## Minor

- **M1. A later attempt forgets that an earlier one created the service.** Reading, `undo.rs:1050-1057`.
  `own_attempt` looks at the last undo record only. Attempt 1 stops at `svcrestore.mid`; attempt 2 fails
  before its create with a read error (`Failed{ObjectApi}`, `act_service.rs:2203-2211`) or a conflict;
  attempt 3 sees `own_attempt` false and answers `ObjectExists` for good. The half-made service stays,
  with the backup's start type, so an auto-start one is started at the next boot without its
  `Parameters`. Fix: keep "an attempt of this op created the service and none since has settled" in
  `OpState` (set by an open intent or `VerifyFailed`, cleared only by a settled outcome). Also accepted
  as it is: an `undo_intent` left open by a crash before the create counts as created (the R2b S3 rule).
- **M2. A resumed run uses the gone lists of the day it started, also for items it validates now.**
  Reading, `execute.rs:1157`, `:1185`, `:1220`. A run that stopped inside its validate pass validates the
  rest on resume with fresh stamps and the old lists. If the product was installed again in between,
  its Installer keys pass. Fix: when `unvalidated` is true, clear the lists before `run.validate()`
  (those items are then refused), or refuse the resume. Items validated before the stop are protected by
  their stamps.
- **M3. Recovery records `Done` for an object found gone without the flush the module makes.** Reading,
  `execute.rs:1516-1521`, `recover.rs:1077-1089`. After a stop at `objdelete.after` the probe says `Done`
  and the `done` is written; the hive is flushed only at the group end, and object ops are not in
  `JournalState::unconfirmed`. A power loss in between leaves `Done` for an object that is back; undo
  then says `AlreadyRestored`, so nothing is lost. For a task the file and the TaskCache can part; the
  power-off rounds will show it. Fix: `settle_open` flushes the op's hive (`durable::flush_op_hive`, for
  a task also its directory) before the `done` of an object probe.
- **M4. "Still there" after a delete call that succeeded is journalled as unchanged.** Suspected,
  `act_service.rs:1412-1416`, `act_task.rs:1325-1338` (R2b M2, unchanged). `Failed{ObjectApi}` reads as
  `NothingToUndo`, which settles the undo. Use `Failed{VerifyFailed}` whenever the delete call returned
  success and the object is neither gone nor marked.
- **M5. Nothing reads the journalled undo note.** Reading, `journal/state.rs:428`. The undo report of
  the same run carries it; a later reader of the session does not. Wire it where a session's undo result
  is listed (M3 at the latest).
- **M6. A key backup is orphaned when the definition write fails.** Reading, `act_service.rs:1177`,
  `:1191`. The item is skipped without an intent, so no record names `reg\<op>.regbackup.json`. Remove
  it through the store on that error path.
- **M7. `crash_matrix_unit` is narrower than its name.** Reading, `tests/m1b_exec.rs:1027-1130`. It
  panics in the mock at six call boundaries per kind and asserts that a clean run hits the module
  points. It does not stop at `backup.written`, `backup.verified`, `intent.flushed`, `done.before`,
  `group.end`, `commit.before` or `journal.header` for an object op, and a panic unwinds where a kill
  does not. The real points are all wired (`fault::point` in the modules, the writer and
  `execute.rs:2010`, `:2042`, `:2078`), so `m1b-x-crash` can reach them; rename the test
  (`crash_at_backend_calls_unit`) or say so in its doc, and do not count it toward K13.
- **M8. Three item functions, three result types.** Reading, `execute.rs:1986-2090`, `undo.rs:1043-1125`.
  The design asks for one generic `typed_item` so that the record order cannot differ between kinds;
  today the three bodies are equal by copy. R2b M5's "one result shape" and M8's baseline fact were not
  carried and are not recorded in DECISIONS. Record them or do them.
- **M9. `plan from-targets` cannot make an object plan.** Reading, `cli/exec.rs:635`
  (`object_fp: None`), `:845`. The item is skipped ("no object fingerprint"), and `--fp` needs a
  fingerprint whose program id is `RIG_OWNER`. Acceptable: M1B-RIG-EXEC goes through harvest and scan.
  State it in RIG.md so the crash mode is not built on from-targets.
- **M10. The undo dependency "service before its registry values" cannot be reached.** Reading,
  `undo.rs:325-361`. The guard denies every key under `HKLM\SYSTEM` except event sources, so no registry
  op below `Services\<name>` of an app's service exists in a journal. Harmless; the test proves the
  ordering function only.

## The author's doubts: rulings

| Doubt | Ruling |
|---|---|
| Gone lists read back from the journal at act time | Accept. Only `JournalWriter::create_with_settings` writes them, inside the hash chain, in the store. A journal without the fields (older, or stripped) reads as empty lists: closed. A changed journal is the store's threat model, the same as for every backup reference. The lists are computed from fresh system queries; the fingerprint only nominates products. One fix: M2 (resume). |
| `object_fp` only in the sidecar; `plan from-targets` cannot set it | Accept (M9). It is outside the plan hash by C-OBJECT, like `item_fp`. |
| `gate.rs` interns the lists with `Box::leak` | Accept. One set per distinct list per process; the CLI runs a few sessions. Revisit for a long-lived broker. |
| Without `--fp` every object delete is refused | Not true for objects without a program. Fix (S2). |
| Prepare errors that are not integrity failures skip the item | Accept. It is C-DEF's rule and fails closed per item; M2 aborts the run for a registry backup in the same case. Record the difference. Fix the orphan (M6). |
| `crash_matrix_unit` panics in mocks | Accept as a unit test; rename, do not count it for K13 (M7). |
| Three M2 tests changed on purpose | Accept. The package rule ("Skipped ChangedSinceScan, detail 'no object fingerprint'") overrides its acceptance line "pass unchanged"; the new assertions are as strict as the old. |

## What M1B-X-INTEG had to carry

| # | Item | Result |
|---|---|---|
| 1 | Header roots, passed to prepare, act and undo | Done. See S2, S3. |
| 2 | Gone lists journalled and handed back; stale comments removed | Done (`RunSettings::gone_*`, `GateCtx::set_gone`, `undo::gate_ctx`). See M2. |
| 3 | Key backup in the journal's records | Done. |
| 4 | Detail on `undo_done` | Done; no reader (M5). |
| 5 | `own_attempt` by the S3 rule | Done for services; M1. For firewall rules it is "any `undo_intent`", which there only adds a flush. |
| 6 | Resumed intent re-verifies the definition | Done (`complete_object` runs the module's act). |
| 7 | One root check, one result shape; baseline fact | Root check done; the rest not (M8). |
| 8 | ci runs every purge-exec target | Done; S1. |

Also checked against the package rules: a typed item without `object_fp` gets `validated` and `done` only;
an unelevated run with an object op fails before the session exists; the release build has no path into
purge-exec (optional dependency, `cli::exec` under `rig-exec`); the group flush covers `SYSTEM` or
`SOFTWARE` through the writer's hive set; `PendingDelete` sets `pending_reboot` and a warning; a skipped
or failed object item gives exit `Partial`.

## VM results: what they mean for the code

| Result | Ruling |
|---|---|
| ICMP re-create fails (`PutInstance` 0x80041001), native rule lost in the test | **Code defect** in `purge-win/src/firewall.rs` (`map_rule`'s `IcmpType` value form or context type), masked by the list. `IcmpTypes` stays refused. Until the mapping is fixed and proven, make `map_rule` refuse `ICMP4`/`ICMP6` itself, so the refusal does not hang on one list line. The two failing rig tests are right to fail on ICMP. |
| `LSM` inbound create fails | **Test defect** in the own-rule case (`lsm` with `Dir=In`): the provider cannot make that rule at all. Keep the outbound case. Code: S4. |
| Nine shapes proven | Lift seven; `OtherProtocol` for 47 only; `LSM` stays or is narrowed (S4). |
| R1 S2 not observed (no start within 15 minutes, with and without `StartWhenAvailable`) | Closed for the gate. No code change: `RegistrationTrigger` stays refused, the module text "never starts a task" stands. Record in DECISIONS with its limits: build 26100, 15 minutes, no restart afterwards. Boot, logon and next-due triggers run later by design. R2b M7 is closed with it. |
| `scm::elevated::create_exists_is_distinct_error` fails | **Test defect.** 26100 allows a second service with the same display name. The executor does not depend on the error: `act_service.rs:235` maps `DuplicateName` to `Exists`, which undo reports as `ObjectExists`; if it never comes, the create succeeds, which is the right restore. Drop the `DuplicateName` assertion, keep `Exists`. |
| `act_service::live_read_of_a_builtin_service_is_consistent` fails at Medium | **Test defect** (S1). |
| Live round trips of the three modules pass elevated | They cover the modules at `b091781`. The X-INTEG path was not in the binaries. |

## Ready for the crash matrix?

The executor code is. Before `m1b-x-crash` is run for the record:

1. Fix S1 and S2; run `cargo xtask ci` once unelevated.
2. Build the rig binaries from a commit that holds `f5230c7` and run the three live round trips and the
   elevated `scm` and `firewall` tests again, then one `exec --fp`, `journal resume` and `undo` on the VM
   with real objects before the first fault is injected.
3. The mode must drive harvest and scan, not `plan from-targets` (M9), and must report each of the
   thirteen points of the RIG-EXEC rule as reached per kind.
4. S3 and S4 before the gate is signed; M3 and M4 are the two places where a power-off round may show a
   journal that says less than what happened.
