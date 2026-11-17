# M1b review R2b: executor side

Reviewed on `m1b` at `c3b74e7`: M1B-X-FOUND `04d58c9`, M1B-X-SERVICE `0e29b9c`, M1B-X-TASK `311c226`,
M1B-X-FIREWALL `f703cc8` (all in `crates/purge-exec`), against `review_points` R2 of
`docs/M1B_DESIGN.json`, the spike (`vm/spikes/m1b`), `docs/DECISIONS.md` section "M1b" and the authors'
doubts in `docs/reviews/m1b/coordinator-notes.md`. The M2 executor these modules plug into (journal,
durable, expiry, undo state) was read where the modules depend on it. The wrappers in `purge-win` belong to
R1; they were read only where they decide executor safety. The reviewer wrote none of this code, changed no
source and did not delegate.

## Verdict

**Not ready to be wired by M1B-X-INTEG as it stands. One blocking finding, six serious.**

The structure is sound and follows the M2 lessons: every act re-reads the identity and compares it with
the journalled stamp, every act and undo needs the token of a flushed intent, definitions are written
through the store and read hash-first with a size cap, every re-create is create-only, the hive is flushed
before the verdict, and a delete call that failed is followed by a fresh read in the firewall module. No
path was found that deletes an object other than the one named by the op, and no path that reports a
restore as exact when the compared state differs.

What is missing sits around that core:

- Nothing ties a typed delete to the roots of the run, and nothing checks before the delete that the
  undo's own conditions can be met (B1).
- None of the 121 tests of the four packages runs in `cargo xtask ci` (S1).
- The firewall module deletes rules whose re-create mapping was never proven, and the undo then removes the
  rule it made (S2).
- The service undo can continue "its own" restore on a service another install created (S3).
- The delete is bound to the identity digest only, so the backup can be older than what is deleted (S4).
- The service key backup is named by no journal record (S5), and an undo's note has no place in the
  journal (S6).

Evidence labels: **experiment** (a run on this host, Windows 11 26300, elevated shell, fake backends only;
no `#[ignore]`d or rig test was run), **reading**, **suspected**.

Tests run (`CARGO_TARGET_DIR=E:\purge-build\review-exec`, 2 jobs):
`cargo test -p purge-exec --features fault-inject,test-support --test act_service --test act_task
--test act_firewall --test m1b_found`: 44 + 22 + 40 + 15 passed, 0 failed, 3 ignored (the rig tests).
The same four targets and `roundtrip` without features: 0 tests each (S1).

## Blocking

### B1. A typed delete is not bound to the run's roots, and the delete goes ahead where the undo is certain to refuse

Evidence: reading.

`validate`, `prepare` and `act` of the three modules take no roots (`act_service.rs:800`, `:1057`, `:1192`;
`act_task.rs:816`, `:972`, `:1179`; `act_firewall.rs:452`, `:613`, `:688`). The roots appear only in undo
(`act_service.rs:1986-1997`, `act_task.rs:1484-1496`, `act_firewall.rs:1081-1095`), where a program outside
them is `ProgramOutsideRoot`. So the condition the undo will apply is known before the delete and is not
applied.

Failure scenarios, each for an item the plan states as `Reversibility::Full`:

1. Firewall rule `App=%SystemRoot%\System32\svchost.exe|Svc=VendorSvc|...`. `map_rule` maps `Svc`, the guard
   has no program rule for firewall rules (`rule_blocker` passes `program: None`, `act_firewall.rs:266-275`),
   the rule is deleted. Undo: `rule_program` is the System32 file, never under a root: `ProgramOutsideRoot`
   on every attempt. The rule cannot come back. (The author's note says the same.)
2. Service or rule whose program the executor's own resolver cannot resolve but the scanner's can. The
   resolvers are copies with different inputs: services and firewall rules expand the machine environment
   only (`ProgramEnv::from_guard`, `machine_vars`), tasks expand with the user SID. A rule
   `App=%LOCALAPPDATA%\Vendor\app.exe` is `Unresolved` in undo and is refused; nothing refused its delete.
3. Service with `Start` 0 or 1 and a Win32 type, or `ErrorControl` above 3. Validate passes; `scm::create`
   refuses both (`purge-win/src/scm.rs:1344`, `:1350`), so undo ends `Failed{ObjectApi}` every time.
4. A journal without roots (the header has no field yet). Every undo is `ProgramOutsideRoot`, as designed
   ("closed"), but every delete still runs.

The same gap is the missing second lock at delete time. The executor's gate for an object is: digest equal
to the plan's `object_fp` (which the plan supplies), the guard's object rules with `in_baseline: false`
(`act_service.rs:725`, `act_firewall.rs:274`), and the state. A plan item naming a Windows service whose
program is outside `%SystemRoot%` (Defender under `ProgramData`, the Edge services under
`Program Files (x86)`) passes all three when the service is stopped. For files and registry keys the
executor re-runs the whole deny list; for objects only the scanner stands between a wrong attribution and
the delete.

Fix:
- `prepare` of all three kinds takes the run's roots and applies exactly the function the undo applies
  (one shared function, see M5). A program outside the roots, an unresolved program, or no roots at all:
  `Skipped{GateBlocked{CannotBackUp}}` before any backup. The act-time gate repeats it.
- Service `prepare` builds the `ScmCreate` arguments from the captured tree (`create_args`) and refuses what
  `CreateArgs::build` would refuse (expose that check from `purge-win`).
- Firewall: a rule with `Svc` is refused in M1b, or its program is taken from the service's own program
  when that service is an item of the same run. The first is the smaller change.
- Tests: one hostile test per kind, "delete refused when the undo would refuse", plus the svchost rule.

M1B-X-INTEG adds the header field and passes the roots; the checks themselves belong in the modules.

## Serious

### S1. `cargo xtask ci` runs none of the tests of the four packages

Evidence: experiment and reading.

`tests/act_service.rs`, `act_task.rs`, `act_firewall.rs` and `m1b_found.rs` start with
`#![cfg(feature = "test-support")]`. `ci` runs `cargo test --workspace` (no features; only purge-engine
links purge-exec, and only under `rig-exec`) and then
`cargo test -p purge-engine -p purge-exec --features ... --lib --test exec_cli --test crash`
(`tools/xtask/src/main.rs:124-138`). The comment there ("the other test targets of both crates do not
depend on the features") is wrong for these four files and for M2's `roundtrip.rs`. Run without features,
each of the five targets reports `0 passed`.

Consequence: "each agent's own `cargo xtask ci` passed" says nothing about the 121 tests of these
packages, and a later fix that breaks one will pass CI. This is wider than the author's note, which names
only the fault-inject tests.

Fix: in the rig step of `ci`, drop the `--lib --test ...` selection for purge-exec (run all its targets
with `fault-inject,test-support`), or list the five targets. Do it before the fixes of this review land.

### S2. Firewall: rules with unproven field mappings are deleted, and a wrong mapping loses the rule

Evidence: reading (`act_firewall.rs:282`, `:1207-1237`; `purge-win/src/firewall.rs:354-359`;
`vm/spikes/m1b/RESULT.json` `firewall.cases`).

The six spike rules prove `Action`, `Active`, `Dir`, `Protocol` 6 and 17, `App`, `Svc`, `Name`, `Desc`,
`EmbedCtxt`, `Defer=User`, `LPort`, `LPort2_10`, `RPort`, `RA4`/`RA6` with `LocalSubnet`, masks and
ranges, `Profile=Private|Public`, `IFType=Wireless|RemoteAccess`. `map_rule` also accepts `Edge=TRUE`,
`Defer=App`, `LSM`, `LOM`, `ICMP4`/`ICMP6`, `LA4`/`LA6`, `Profile=Domain`, `IFType=Lan` and `RPort2_10`,
by inference. `rule_blocker` refuses only what `map_rule` refuses.

Scenario: a rule `...|Profile=Domain|Edge=TRUE|Defer=App|...` is deleted. On undo the provider stores the
re-created rule with other fields; `is_backup` is false; the rule is deleted by id and the undo is
`ValueDiffers`. Every later attempt ends the same way. The raw string stays in the definition file, but
no path brings the rule back.

Ruling on the author's two options: **refuse until proven.** Deleting the half-made rule is the right
reaction to a mismatch (a rule Purge invented must not stay active in the firewall), so the loss has to
be prevented before the delete. Add an executor-side list of proven keys and value forms, taken from the
spike cases, and refuse everything else at `rule_blocker` (`CannotBackUp`). M1B-RIG-EXEC round-trips the
rest on the VM and the list grows with that evidence. The `ValueDiffers` detail should also name the
definition file, as the task module does for `PasswordNeeded`.

### S3. Service undo continues "its own partial restore" on a service another install created

Evidence: reading (`act_service.rs:1888-1903`, `:2048-2051`, `:2107-2149`).

With `own_attempt` (an `undo_intent` of this op exists) a present service counts as this undo's half-made
one when name, raw `ImagePath`, type, start type and account equal the backup, `ServiceDll` is equal or
absent, and its key holds no key or value name the backup lacks. Then `run_undo` applies config2, the DACL
and the write-back to it, without a create.

An `undo_intent` is on record after any attempt that reached `run_undo`, including those that ended before
the create did anything (`Exists`, `MarkedForDelete`, a failed `CreateServiceW`), and a failed or
conflicting undo may be tried again (`journal/state.rs:184-193`).

Scenario: delete of `VendorSvc`; the first undo fails at create (1072, or access); the user installs the
app again, a newer build with the same `ImagePath`, type, start type and account; the user runs undo again.
The new service's value names are a subset of the backup's, so it is adopted: every value that differs
(`Description`, `FailureActions`, `DependOnService`, the `Parameters` subtree) is overwritten with the old
data, the old DACL is set, and the result is `Restored`. The service may be running; the undo never looks
at its state. The existing test (`undo_existing_different_is_object_exists`) uses a squatter with another
`ImagePath` and does not reach this.

Fix:
- Define `own_attempt` as "this op's last undo attempt created the service": true for an `undo_intent`
  with nothing after it (the crash at `svcrestore.mid`), and for a finished attempt only when it failed
  after the create. `run_undo` must make the two distinguishable (for example `Failed{VerifyFailed}` for
  every failure after a successful create, `ObjectApi` and the conflicts before it), and the argument's
  doc must say so, since M1B-X-INTEG computes it.
- The continue path also requires `SERVICE_STOPPED`.
- Hostile test: same identity, other `Description`, `own_attempt` true after a failed create:
  `ObjectExists`, nothing written.

### S4. The delete is bound to the identity digest only; the backup can be older than what is deleted

Evidence: reading (`act_service.rs:1215-1232`, `:922-937`; `act_task.rs:1206-1223`).

A service's digest covers six fields, a task's its path and actions. The key tree, the SCM definition, the
task XML and its SDDL are read in `prepare`. The act-time gate compares the digest and the guard, then
deletes. Whatever else changed since `prepare` is deleted without being in the backup: a task's triggers
or principal, a service's `Parameters` values or failure actions.

In a straight run the window is the intent flush. In a resumed run it is not bounded: an intent without
`done`, `probe` says `NotDone` (digest equal), `SvcRemoval::from_intent` rebuilds the removal and `act`
deletes, hours or days after the backup was taken. The resumed path also does not check that the
definition and the key backup still exist and verify. Undo then restores the older state and reports
`Restored`, because it compares with the backup.

The firewall module does not have this defect: the digest is the whole rule.

Fix: after the gate and before the delete, `act` reads the op's definition through the journal's reference
(`read_def`, for a service also `read_key_backup`), reads the live definition once more (service:
`capture_key` and `tree_difference`, plus the SCM definition; task: `definition` and `same_definition`,
`enabled`) and requires equality; otherwise `Skipped{ChangedSinceScan}`, nothing deleted. Tests: a value
below `Parameters` changed after prepare; a trigger changed after prepare; a missing definition on resume.

### S5. The service's key backup is named by no journal record

Evidence: reading (`act_service.rs:1166-1171`; `purge-model/src/exec/journal.rs:288`;
`expiry.rs:574-583`, `:699`; `report.rs:183`).

The intent of a service delete carries `Inverse::RecreateService { definition }` and `definition: None`.
`Intent::backups()` therefore yields `def\<op>.json` only. `reg\<op>.regbackup.json`, the whole
`Services\<name>` tree, is referenced from inside the definition file alone.

Expiry, the kept-bytes figure of `commit` and the report all walk `intent.backups()`. So the key backup is
never deleted when the backup class of the session expires (the definition that names it is), it is not
counted, and after expiry nothing in the journal says the file belongs to an op. A retention promise is
broken for the largest file of the item.

Fix (one of): put the key backup's `BackupRef` in the intent's `definition` slot, or add it to
`Inverse::RecreateService`, so that `backups()` yields both; `prepare_undo` then takes the reference from
the journal and checks that the definition names the same file and hash. Either is a change to what
X-SERVICE writes and must be settled before M1B-X-INTEG writes the first such journal.

### S6. An undo's note has no place in the journal: a service restored without its password reads as `Restored`

Evidence: reading (`act_service.rs:1976-1984`, `:2166`; `journal/writer.rs:609-622`).

`run_undo` returns `Restored` with the note "its stored password was lost with the delete and must be set
again". `undo_done` records `{op, outcome}` and nothing else, so the note cannot be journalled; the task
module's `TypedUndo::Done` has no detail at all, and the firewall's "stored string differs in version or
field order" goes the same way. After the process ends, the journal says `Restored` for a service that
will fail to start with a logon failure.

Ruling on the author's question (Restored or Partial): `Restored` is consistent with DECISIONS (the loss
is stated up front as `Reversibility::Partial`, and `UndoOutcome` has no partial variant), **provided the
statement survives**. Decide one of: (a) `undo_done` gains an optional `detail`, additive like `done`'s;
(b) the report derives the sentence from the item's planned reversibility and the definition's
`account_builtin`. (a) is simpler and serves all three modules. M1B-X-INTEG carries it.

## Minor

- **M1. The task's XML-to-actions binding is not one to one, and tasks without an exec action skip the
  root check.** Reading, `act_task.rs:694-716`, `:1484-1496`. `xml_binds_actions` counts `Exec` elements
  and requires each identity path to occur as some `Command`. Actions `[A, A]` with XML commands `A` and
  `B` pass. A task with only `ComHandler` or other actions passes the root loop vacuously, so the second
  lock does not exist for it. Both need a forged definition and journal, so this weakens the second lock
  only. Fix: compare the multiset of `Command` texts with the multiset of exec paths; refuse the
  re-registration of a task with no exec action under a root, or state in DECISIONS that COM-handler tasks
  are restored on the hash alone.
- **M2. A task that is unreadable after its delete is journalled as unchanged.** Suspected,
  `act_task.rs:1270-1283`. `Err(Unreadable)` after the delete call counts as "still there":
  `Failed{ObjectApi}`, which undo reads as `NothingToUndo`, and that settles the undo for good
  (`journal/state.rs:186`). A delete that removed the task file and left the cache entry would look like
  this. Use `Failed{VerifyFailed}` for an unreadable task after a delete call.
- **M3. The service restore check compares the registry only, and not the service key's own descriptor.**
  Reading, `act_service.rs:1434`, `:2161-2174`. The write-back writes `Services\<name>` directly; where
  it changes a value the SCM also holds in memory, the SCM's view differs until the next start of Windows
  while the check passes. A vendor DACL on the service key itself is not restored and not compared.
  Compare `backend.definition` with the stored `config`/`config2` after the restore, and compare the root
  descriptor (owner aside) or re-apply it as for subkeys. The author's "root-key SDDL not compared" is
  accepted for the gate only with this recorded in DECISIONS.
- **M4. Firewall undo after a failed create checks, and may delete, whatever rule is then present.**
  Reading, `act_firewall.rs:1141-1157`, `:1218-1229`. A create that fails with an error other than
  `Exists` while a rule with the id is present falls through to the exact check; a rule that is not the
  backup is deleted by id. Only a race with another creator of the same GUID reaches it. Also, a crash
  between the create and the cleanup delete leaves a rule that is not the backup, and every later undo is
  `ObjectExists` with that rule still active. With S2 fixed both are out of practical reach; state the
  second in the report text.
- **M5. Three copies of "program under a root", three result types.** Reading. `program_under_roots`
  (service, `GuardEnv::default()` for the roots), `program_in_roots` (task, the run's env and user SID),
  `file_under_roots` (firewall); `SvcUndoResult`, `TypedUndo`, `FwUndoResult`; `prepare_undo` returns
  `Option` in one module only. The design asks for one generic sequence in X-INTEG; one shared root
  function is needed for B1 anyway.
- **M6. Tests and texts.** `fault_points_reached` (service, firewall) asserts that four of its seven
  points are hit and for the others only that the constant is declared; the abort test that covers them
  needs `fault-inject` (S1). The "crash" of `undo_crash_at_svcrestore_mid_then_resume` is a failed
  config2 call, which is the S3 case rather than a crash. `FAULT_POINTS` is documented as "in the order a
  run meets them" and the three new points are appended (fix the sentence). `gate.rs:930` and `:965` still
  say "wired by M1B-X-FOUND" for the gone lists, which X-FOUND did not wire.
- **M7. A re-registered task may run at once.** Suspected. A task with a missed time trigger and
  `StartWhenAvailable` may start on registration; only `RegistrationTrigger` is refused. Not measured by
  the spike (handoff point 3). M1B-RIG-EXEC must measure it; if it runs, refuse such XML in `not_restorable`.
- **M8. `in_baseline` is always false.** Reading. B1 closes most of it (a baseline object is not under
  the app's roots). Port-only rules and COM-handler tasks stay covered by the scanner alone. Pass the
  baseline to the gate when M1B-X-INTEG has it at hand; otherwise record the limit.

## Authors' doubts: rulings

| Doubt | Ruling |
|---|---|
| X-FOUND: a running object gets no stamp, so the act is refused | Accept. Validate never emits `running: true` as validated; a journal that does binds nothing. |
| X-FOUND: `TaskDef` does not check `stored_password` against `logon_type`; `FwDef` does not check `fields` against the rule string | Accept. Both are checked where they are used (`def_needs_password`, `act_firewall.rs:1036`). Moving them into `check_fields` would make `read_def` enforce them for every caller; optional. |
| X-FOUND: fault points appended, not in run order | Accept; correct the doc sentence (M6). |
| X-FOUND: `write_def` returns `DefWriteError`; `read_def` is bounded on `ObjectDef` | Accept. |
| X-FOUND: files outside the list (`tests/crash.rs`, `exec_cli.rs`) | Accept. |
| X-SERVICE: six more backend calls than C-ACT | Accept; the spike's procedure needs them. |
| X-SERVICE: undo of a non-builtin account returns `Restored` | Decide (S6): `Restored` stays, the note must be journalled or derived. |
| X-SERVICE, X-TASK, X-FIREWALL: roots are a parameter | Fix (B1): X-INTEG adds the header field; the modules must use the roots before the delete too. |
| X-SERVICE: a re-run with this op's `undo_intent` continues its partial restore | Fix (S3). |
| X-SERVICE: `in_baseline` false; root-key SDDL not compared; program resolution copied | M8, M3, M5. |
| X-SERVICE: fault-inject tests not in `xtask ci` | Fix, and wider than stated (S1). |
| X-TASK: extra `flush`, create-only flag, undo split in check and register | Accept. |
| X-TASK: stored password from flag, logon type or XML | Accept (fail closed). |
| X-TASK: guard checked per exec action | Accept (stricter than the scan; costs recall only). |
| X-TASK: XML check is text matching, unverified on real XML | Accept for false refusals (the rig will show them); fix the one-to-one gap (M1). |
| X-TASK: `%LOCALAPPDATA%`-style tokens unresolved in the guard check | Accept (blocked, fail closed). |
| X-FIREWALL: unproven mappings not refused | Fix: refuse until proven (S2). |
| X-FIREWALL: service rules never undoable | Fix in the executor too, not only in the scanner (B1). |
| X-FIREWALL: crash between create and cleanup leaves `ObjectExists` | Accept after S2 (M4). |
| X-FIREWALL: post-delete re-read, 5 s settle reads, other spelling of the id is `ChangedSinceScan`, `EmbedCtxt` in `fw.resource-name` | Accept. |
| GUARD/PLAN: the gone lists are empty at act time | Safe (fail closed), but every item that needs an Installer or Package Cache exemption is refused at the act, so the gate cannot pass. X-INTEG journals the lists. |

## What M1B-X-INTEG must carry

1. Journal header `roots`; pass them to `prepare`, the act-time gate and undo of all three kinds (B1).
2. Journal the three gone lists with the `validated` record (or the header) and hand them back to the
   act-time gate, undo and recovery; remove the stale comments in `gate.rs`.
3. The key backup of a service in the journal's own records, so expiry, the byte count and the report see
   it (S5).
4. A detail on `undo_done`, or the derived sentence, for restores with a note (S6).
5. `own_attempt` computed by the rule of S3, not as "any `undo_intent` exists".
6. On a resumed intent, the act re-verifies the stored definition before deleting (S4).
7. One shared root check and one result shape for the three kinds (M5); the baseline fact if available (M8).
8. `cargo xtask ci` runs every purge-exec test target with `fault-inject,test-support` (S1).

The fixes of B1, S2, S3 and S4 are changes inside the three act modules and should land before X-INTEG
wires them.
