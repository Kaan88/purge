# M2 final review

Reviewed at `efcc2b1` ("M2 recovery fix pass: ..."), the head of local branch `m2`.
Reviewer changed no source code.

## Verdict

**Go to the VM gate after required fixes.**

No blocking finding. Nothing found lets a standard user redirect a move, a
boot-time move, a restore or the expiry delete to an object outside the plan,
and no path was found where a file or key is deleted without a journalled
intent and (for the registry) a verified backup.

Seven serious findings (S1 to S7). Each must be fixed, or decided and written
into `docs/DECISIONS.md`, before the gate campaign starts, because the gate
would otherwise measure behaviour that is known to be wrong:

- S1 and S7 are the two places where an elevated run can be steered by a
  standard user (a restore into a directory the user owns; an output file
  written through a junction).
- S2, S3 and S6 each leave an item in a state that neither undo, recovery nor
  expiry can finish.
- S4 and S5 are the remaining half of wave 2 S5: a key that somebody else
  changed after validation is still deleted in two cases. S4 is wider than
  the limit accepted in the decision log.

The minor findings (M1 to M24) do not hold the gate. M1, M2, M3, M7 and M19
should be fixed with the serious ones, because the gate scripts will meet
them (a second undo needed, a resume that refuses, exit code 0 with work
left).

Evidence labels:

- **experiment**: confirmed by a run against this commit (Windows 11 build
  26300, unelevated, medium integrity; the library with the relaxed test
  store, registry under `HKU\<SID>\Software\PurgeTest-*`).
- **reading**: confirmed by reading the code; no run.
- **suspected**: not confirmed.

## Reviewed

In this order of depth:

1. `crates/purge-exec/src/recover.rs`, `undo.rs`, `tests/crash.rs`,
   `tests/roundtrip.rs` (read in full).
2. `execute.rs`, `plan_in.rs`, `report.rs` (read in full);
   `purge-plan/src/hash.rs`, `decide.rs` (`deny_exemptions`),
   `collapse.rs` (what is absorbed), `purge-guard/src/live.rs`
   (`check_protected_descendants`, `admin_only_ancestors`, `check_path`).
3. `act_fs.rs`, `locked.rs`, `prepare.rs`, `act_reg.rs`, `act_typed.rs`.
4. `expiry.rs`.
5. The changes since wave 2 (`300602c..efcc2b1`) in `gate.rs`, `gate/ffi.rs`,
   `journal/*`, `storage.rs`, `storage/*`, `regbackup.rs`,
   `purge-win/src/fs_write.rs`.
6. `bins/purge-engine/src/cli/exec.rs`, `output.rs`, the feature gating,
   `tools/xtask/src/check_deps.rs`.

Parts 3 to 6 were read by four delegated readers, one per part, each with the
earlier reports as background. Their findings are included here; the code
sites of S1, S2, S3, S4 and S7 were read again for this report. Experiments
of the delegated readers ran on scratch copies of the workspace, which were
deleted.

Tests run for this report:
`cargo test -p purge-exec --features fault-inject,test-support`: 392 passed,
0 failed, 7 ignored (lib); `tests/crash.rs` 4 passed; `tests/roundtrip.rs`
8 passed. `cargo run -p xtask -- check-deps`: both rules `ok`.
`cargo build --release -p purge-engine`: no `purge-exec` in
`cargo tree -e normal`, none of the executor's marker strings in the binary,
every executor verb refused.

## Blocking

None.

## Serious

### S1. Undo restores into a parent directory that somebody else re-created

Files: `crates/purge-exec/src/act_fs.rs:1544-1550` (`recreate_dir`),
`:1428-1434` (`move_back`).

What is wrong: `recreate_dir` treats any existing plain directory at the path
as done:

```
PathNow::Object { plain_dir: true, .. } => AlreadyRestored
```

The recorded owner and DACL are not compared with the directory that is
there. `move_back` then only requires that the parent exists and passes
`gate::check_undo_path`, which looks at reparse state, volume and whether the
leaf is free, not at who owns the parent or who may write to it.

Evidence: reading.

Scenario: the session quarantines `C:\ProgramData\App\helper.exe`, removes
the admin-only directory `C:\ProgramData\App`, and deletes the HKLM `Run`
value that starts the helper. A standard user creates `C:\ProgramData\App`
(Users may create folders there) and owns it. The administrator undoes the
session. The directory is `AlreadyRestored`, `helper.exe` is renamed into it,
and the `Run` value is restored. The directory's owner can delete and replace
the file; the next administrator logon runs the replacement. Before the
session the path was writable by administrators only.

Smallest fix: an existing directory counts as restored only when its owner
and DACL equal the recorded SDDL; otherwise the op ends
`Conflict(DestinationExists)`. A `MoveBack` whose parent was removed by this
session and whose `RecreateDir` did not end `Restored` (or a verified
`AlreadyRestored`) ends as a conflict too.

### S2. A held item whose retry ended `Failed{VerifyFailed}` is undone as "nothing to undo"

Files: `crates/purge-exec/src/locked.rs:1320-1345` (`lock_state`), `:1408`
(`undo_locked`); `undo.rs:762-763`.

What is wrong: `lock_state` maps a `Retried { outcome }` record through `of`,
where every outcome but `HeldRetry`, `PendingReboot` and `Done` is
`LockState::Unchanged`. `undo_locked` returns
`Done(NothingToUndo)` for `Unchanged`, the driver journals it, and
`NothingToUndo` is a settled undo. `act_fs::plan_undo_fs` and
`undo::stands_changed` both treat `VerifyFailed` as "may have changed the
system"; this function does not.

Two ways to reach the outcome: `recover.rs:828` (an interrupted retry whose
probe is `Attention`, for example the item is at its path and in quarantine,
or the quarantine cannot be read) and `act_fs.rs:1950` (the retry moved the
item and its verification failed).

Evidence: reading.

Scenario: a held file is retried, the rename succeeds, the verify fails
(or the process dies and the probe cannot read the quarantine). The journal
holds `Retried{Failed{VerifyFailed}}`. The user undoes the session: the op is
`NothingToUndo`, the session is `Undone`, `pending()` is `None`. The file is
in quarantine and nothing but expiry will ever look at it again.

Smallest fix: in `lock_state`, `Failed{VerifyFailed}` maps to `Moved`, so the
ordinary move back runs in its completing form (it looks where the item is).
Add the missing assertion to
`retry_held_passes_the_journalled_destination_and_maps_outcomes`.

### S3. An ordinary file name inside a quarantined tree stops the purge after the expire record is written

Files: `crates/purge-exec/src/expiry.rs:1323-1329` (write-ahead),
`:1663-1672` (`Walk::act` gates every entry), `:1126-1141` (freed bytes keyed
on `expire_recorded`); `crates/purge-guard/src/live.rs:1268`
(`check_store_item` runs `canon_plain` on the walk's lexical path);
`purge-guard/src/canon.rs:434-453` (`check_segment`).

What is wrong: the root of an item is gated before `expire` is written, the
entries below it only during the walk. `check_store_item` canonicalises the
lexical path of every entry, and `check_segment` refuses a segment that ends
in a dot or a space or is a DOS device name. The executor's own tree walk at
validation (`gate.rs:1137-1210`) opens children by `\\?\` path and does not
canonicalise them, so such a tree is quarantined without complaint.

Evidence: experiment for the gate half (`check_store_item` with `Remove` and
`Capture` on `<quarantine>\<session>\000001\App\<leaf>`: `aux`, `nul`,
`NUL.txt`, `COM1.log`, `name.` and `name ` are refused `DenyListed{fs.purge}`;
`ok.txt` and `a b` pass); reading for the rest.

Scenario: a leftover directory holds a file named `nul` or `aux.h`. It is
quarantined whole. After the retention time the user consents to the purge.
The root passes, `expire` is written, the walk deletes what it meets before
the entry and stops there with `WalkError::Gate`. Every later purge stops at
the same entry. From then on: undo refuses the op as `Expired`
(`state.rs:706`) although most of the data is still there, the item can never
be purged, and the index has already subtracted its bytes, so the size cap
undercounts. `WalkError::NameNotRepresentable` (`expiry.rs:1613`, a name with
an unpaired surrogate) is the same dead end. No expiry test has a refusal
below the root.

Smallest fix: for entries below a root that passed, compare lexical and
final path segment by segment without `check_segment` (the handle-relative
open and the containment of the final path in the session's quarantine carry
the safety). Subtract index bytes only for `Purged` and `AlreadyGone`.

### S4. A change by somebody else is taken for the run's own once any earlier item of the run touched the same key

Files: `crates/purge-exec/src/gate.rs:362-380` (`OwnChanges::explain`),
`:575` (`noted_at = filetime_now()` in `note_done`).

What is wrong: the time test is a window, not a match:

```
now.last_write_time.0 >= last_write_time.0 && now.last_write_time.0 <= until.0
```

The lower bound is the last write time recorded at validation, the upper
bound the moment the gate noted the own op. Nothing ties the key's write time
to what the own op did. Any write by anybody between the validate pass and
the own op's `done` passes when the counts still balance (a rewrite of an
existing value does not change them).

Evidence: experiment. Key `App` with values `a` and `keep`; plan
`DeleteValue a`, then `DeleteKeyTree App`. After validation another writer
rewrites `keep`. Item 1 `Done`, item 2 `Done`, the key is gone. The same
change without item 1 in the plan: item 2 `Skipped{ChangedSinceScan}`.

Worse than the accepted limit: the decision log (2026-11-15) says "within one
clock tick of an own write". The real window runs from validation to the
`done` of the last own op on that key, across every backup write and journal
flush between them. On a resumed run `note_journal` stamps the effects with
the time of the resume, so the window also covers the whole time the machine
was down.

Damage is bounded: the changed data is in the item's backup, so undo brings
back the changed value. `DeleteKeyIfEmpty` is not affected (the key must
still be empty).

Smallest fix: every own registry op reads the last write time of the key it
changes on its own handle before and after its act and journals both. The
gate then requires the time before to be the expected one and the live time
to be the last "after" time, with no window.

### S5. A tree delete is bound to the root key only (wave 2 S5, second part, partly open)

Files: `crates/purge-exec/src/gate.rs:864-871` (`Stamp::Key`),
`:2197-2205`; `act_reg.rs:570-575`.

What is wrong: the recorded `RegFacts` hold subkey count, value count,
owner, link state and last write time of the root key. A write below a subkey
changes none of them. `capture_tree` backs up, and `delete_tree` deletes,
whatever is below the root at the act.

Evidence: experiment. `App\Sub` validated as a two-key tree. Then `App\Sub\s`
is rewritten, a value is added and `App\Sub\NewKey\Deeper` is created.
Result: `Done`, four keys deleted. The test
`a_key_changed_after_validation_is_refused_at_the_act` changes the root only.

The same holds for a directory moved whole: the file stamp is the identity of
the root. In an experiment for this report a plan removed the empty directory
`app\inner` and then quarantined `app`; the second item ended `Done` although
the tree had changed since its validation. For a file tree the whole content
goes to quarantine and comes back whole, and hard links and reparse points
are checked again at the act, so this half is a note, not a defect.

A resumed run never validates a journalled item again (`execute.rs:981-988`),
so after a crash the time between validation and act is unbounded.

Smallest fix: at validation journal a digest over every key of the tree
(relative name, counts, last write time; bounded by `key_limit`); at the act
compare it with the same digest of the capture, adjusted per key by own
effects as in S4.

### S6. The backup is not checked as the op's backup before the delete; a key spelled with a trailing backslash is deleted and cannot be undone

Files: `crates/purge-exec/src/act_reg.rs:613` (`write_backup`, no
`validate_for`); `regbackup.rs:530-536` (`leaf_name` trims `\`);
`crates/purge-model/src/exec/regbackup.rs:587`
(`key.rsplit('\\').next()` does not).

What is wrong: two functions derive the leaf name of the op's key in two
ways. The one used when the backup is written accepts the spelling, the one
used when the backup is read back for undo, probe and completion refuses it.
Nothing validates the document against the op between writing the backup and
deleting the key.

Evidence: experiment. `DeleteKeyTree { key: r"...\App\" }` validates and ends
`Done`, two keys deleted. Undo: `Conflict{BackupTampered}`, "the root key's
name is not the leaf of the backup's key". `probe_reg` and `complete_reg` use
the same check, so recovery would report `Attention`.

Reach: a plan whose key spelling is not canonical. Plans the engine builds
are canonical; `plan from-targets` in the rig build takes targets as typed,
and the gate campaign uses it. Not checked whether it canonicalises.

Smallest fix: `doc.validate_for(exec_op)` in `prepare_reg` before
`write_backup`, skip the item on error; one leaf function for both places.

### S7. `-o` writes follow a junction in the directory part of the path

Files: `bins/purge-engine/src/cli/output.rs:69-115`
(`write_atomic_no_follow`), used by `cli/exec.rs:359` (`exec -o`, `undo -o`,
`plan from-targets -o` and its sidecar).

What is wrong: only the last component is protected (`symlink_metadata` on
the path, `FILE_FLAG_OPEN_REPARSE_POINT` and `CREATE_NEW` on the temporary
file). The temporary file is created in `path.parent()` by path, and
`fs::rename(&tmp, path)` replaces whatever has that name in the directory the
path resolves to.

Evidence: experiment (the function called from a scratch crate): with the
parent directory a junction to another directory, the result is `Ok(())` and
`report.json` in the junction's target is replaced.

Scenario: an elevated `exec ... -o C:\Users\u\out\report.json`, where `out`
is, or is swapped for, a junction to a protected directory. The report lands
there and replaces an existing file of that name. The module text
(`exec.rs:19`, "never through a link at the path") says otherwise, and the
decision log does not list it as a limit.

Smallest fix: open the parent directory, refuse when its final path differs
from the lexical one or a component is a reparse point, and create and rename
relative to that handle. Or refuse `-o` in the elevated verbs: stdout already
carries the document.

## Minor

### Recovery and undo

**M1. Undo order: a recreated directory is tried before the directory around
it is moved back.** `undo.rs:334-356` (`undo_order` puts every `RecreateDir`
inverse before all others). Experiment: plan `RemoveDirIfEmpty app\inner`,
then `Quarantine app`. Undo all: op 1 `Conflict(ParentMissing)`, op 2
`Restored`; `app\inner` is missing. A second undo restores it. Rollback has
the same order and ends the session `PartiallyUndone`. Fix: order `RecreateDir`
inverses first only among ops that are not below a path another op of the
set moves back, or simply sort the whole set by reverse `done` order (the
order check already guarantees inner before outer in the run).

**M2. Resume after an interrupted rollback goes forward.**
`recover.rs:638-650`. A rollback that dies in its undo phase leaves an
unfinished journal with undo records and with open intents settled as
`Skipped{NotAttempted}`. `resume` on that session does not notice: ops that
are `Done` (and already undone) are `AlreadyDone`, the validated ones run,
and the run is committed. The journal state machine accepts it
(`state.rs`, `Record::Intent` does not look at undo records). The result is
neither the plan applied nor the machine as before. The own-effect notes of
undone registry ops then mismatch, which errs on the safe side (items are
skipped). Reading. Fix: `recover` in resume mode continues the rollback, or
refuses, when the unfinished journal holds any undo record.

**M3. A run interrupted in validation is resumed only when its selection is
nearly a prefix.** `plan_in.rs:430-524`. `find_selection` tries at most
65,536 combinations in lexicographic order. With 30 selectable items after
the last validated one, 10 of them selected and the first one not selected,
about ten million combinations come first; the resume ends
`JournalMismatch`. The crash matrix passes because its plan selects every
item. Nothing is guessed and rollback still works, but the documented
behaviour ("continued as if never interrupted") holds only for small or
fully selected plans. Reading. Fix: journal the selected ids (in the header
or a record after `settings`) instead of searching for them.

**M4. The ladder demands byte-equal intents.** `locked.rs:936`
(`*j != intent`). The file action's intent carries `pre` from the act-time
handle, the ladder's from the validated record. A directory in use that
gained a file since validation ends `Failed{Internal}`
(`lock.intent-differs`) instead of `HeldRetry`. Reading. Fix: compare with
`act_fs::same_action`.

**M5. An op directory left before the intent aborts every resume while the
file stays locked.** `execute.rs:1334` calls `session.create_op_dir`, not
`act_fs::create_op_dir_for`. After a crash between the directory and the
intent, `create_op_dir` returns `OpDirExists` and the run aborts through
`Abort::store`, on every resume. A `Decided` result at the ladder's first
stage also leaves the empty op directory. Reading.

**M6. Reconcile has no evidence of a restart and ignores `confirmed: false`.**
`locked.rs:1244-1248`, `:1742-1752`. A registration not found on read-back is
journalled `PendingReboot{confirmed: false}`. A reconcile in the same boot
finds the pair not listed, the destination empty and the source present, and
concludes `NotMoved`, which is final. If the session manager still performs
the move at boot the journal has no record of it. Reading. Fix: conclude
`NotMoved` or `Lost` only when the boot time is later than the `done` record.

**M7. Recovery completes a move while its boot pair may still be registered.**
`locked.rs:1288-1294`, `act_fs.rs:1791-1794`. A list error, or a pair found
more than once, yields `None`; `probe_fs` falls through to `NotDone` and
`complete_fs` moves the file by handle. The pair stays registered. If the
session is later undone, the next restart moves the restored file into
quarantine again while the journal says `Restored`. Reading. Fix: a list
error or a count above one is `Probe::Attention`; after a handle move remove
the exact pair.

**M8. Reconcile's move back of a mismatching object is not write-ahead.**
`locked.rs:1707`. A crash between the move and its record makes the next
reconcile say `NotMoved`; the state is safe, the alert is lost. Reading.

**M9. `AlreadyRestored` for a pair that is still listed.** `locked.rs:1487`,
`fs_write.rs:1354`. `list()` reads both pending values, the exact removal
only `PendingFileRenameOperations`. Theoretical: `MoveFileExW` does not write
the second value. Reading.

**M10. A new undo run replaces the `undo_plan` of an interrupted one.**
`undo.rs:912-978` does not refuse while `undo_unfinished()` is non-empty, and
`state.rs` keeps only the last plan. The ops the first run had not reached
drop off the recovery list unless the new selection names them. Reading.

### Registry and packages

**M11. The value (and the tree) is read a second time for the backup.**
`act_reg.rs:581`, `regbackup.rs:2337`. The gate compares the value with the
journalled stamp; `capture_value` reads it again and `delete_value` compares
with the backup. A write between the two reads is backed up and deleted.
Microseconds. Reading. Fix: build the document from `CheckedKey::value()`.

**M12. Package removal does not bind the user.** `act_typed.rs:527-529`
(`removal_scope` is always `CurrentUser`), `:851-858`, `:1138-1142`. An
elevated scan lists packages of all users; the executor lists and removes
for the process's user and never compares the token's SID with
`settings.user_sid`. Under elevation with another administrator account that
account's registration of the same full name is removed, irreversibly; a
package registered for another user only is journalled `Vanished`. Suspected
(not run). Fix: refuse package ops when the token SID differs from
`user_sid`.

**M13. Recovery ignores the last write times that are already in the backup.**
`regbackup.rs:1187-1243`. A key re-created identically between crash and
resume probes `Intact` and is deleted again (the accepted limit). Comparing
`node.last_write_time` for keys with no missing child would close most of it
without new journal data. Reading.

### Expiry, store, journal

**M14. A standard user can write inside their own quarantined directory.**
`expiry.rs:1617-1618`. A directory moved by rename keeps its DACL; with
bypass-traverse its former owner opens it by full path (the session id is in
`index.json`). They can plant a name that triggers S3, or rename in a
directory they could not empty; the elevated walk deletes all of it. Reading.
Fix now: stop with an alert when the walk meets more entries than
`pre.tree_entries`. Later: a protected DACL on the quarantined root, the old
one journalled for undo.

**M15. An interrupted undo run does not hold the session.**
`expiry.rs:688-696` looks at `undo_in_progress()` only. After
`undo_plan [5,4,3,2,1]` and a crash between op 5's `undo_done` and op 4's
`undo_intent`, ops 4 to 1 are purgeable. Reading. Fix: also hold when
`undo_unfinished()` is non-empty.

**M16. Expiry reads reconcile records differently from undo and the
journal.** `expiry.rs:730-751` against `undo.rs:239` and `state.rs:282`.
`HeldRetry` then `Retried{Failed{VerifyFailed}}` gives "nothing quarantined";
`Retried{PendingReboot}` then `Completed` stays held for ever. Both keep
data. Reading. Fix: derive from `undo::effective_outcome` and
`stands_changed`.

**M17. A volume that is not attached is recorded as "already gone".**
`expiry.rs:866-869`, `:1251-1259`, `storage.rs:1957`. The purge writes
`expire` and subtracts the bytes; when the volume returns the item is there
and undo is refused. Reading.

**M18. Retention counts from the header's `created`.** `expiry.rs:597`,
`:1099`. A held item retried on day 31 is due the moment it lands. Consent is
still needed. Reading.

**M19. The journal state machine is looser than its text.**
`journal/writer.rs:586-611` (`retried` "never `PendingReboot`", not
enforced); `state.rs:860-868` (`check_retry` ignores `expired` and an undo in
progress); `:871-883` (`Retried` without a `retry_intent`); `:752-771`
(`expire` of any class for any op with an intent); `:648-661` (`done` after
the op's undo settled). Only a crafted journal or a later driver bug reaches
these. `sample_journal` in `journal/tests.rs:175-197` holds none of the new
records, so the truncation and bit-flip tests do not exercise them. Reading.

### CLI, gating, build

**M20. `sidecar_path` panics on some non-ASCII file names.** `output.rs:123`
slices bytes of a `String`. Experiment: `planß.txt` and `aé.txt` panic. Also
reached in the normal build (`scan -o`, after the plan was written).

**M21. Exit code 0 with work left.** `exec.rs:1073-1088`: `journal rollback`
exits 0 when the `aborted` record could not be written and the session is
still open. `exec.rs:747-752`, `:889-891`: `exec` and `undo` exit 0 when the
index entry or `report.json` was not written. Reading. The rig reads exit
codes.

**M22. Rule 4 of `check-deps` can pass while the property is broken.**
`check_deps.rs:139-192`. Experiment on a scratch copy: an engine feature
`exec-core = ["dep:purge-exec"]` enabled by another workspace member passes
both rules while a default workspace build links the executor into the
engine; giving the engine `purge-win/write` directly passes too. In the real
tree a `--workspace` build already unifies `purge-win/write` into the engine;
only `-p purge-engine` does not. Fix: require no dependents in
`cargo tree --workspace -i purge-exec` without `--all-features`, assert that
`purge-win` lacks `write` in the engine's tree, and write down that releases
are built with `-p purge-engine`.

**M23. `xtask ci` never compiles or tests the executor CLI.**
`tools/xtask/src/main.rs:81-104` runs clippy and the tests without
`--features rig-exec`; `cli/exec.rs`, `tests/exec_cli.rs` and
`purge-exec/tests/crash.rs` are outside it. The "strings check of the release
binary" that `exec.rs:92` mentions exists nowhere in the repository. Reading.

**M24. Smaller points.**
- `exec.rs:25`, `:187`: `journal recover`, `journal show` and
  `quarantine expiring` are described as changing nothing; the store's
  integrity check they run can rename a rejected directory aside. Reading.
- `output.rs:137`: plan, sidecar, selection and target files are read with no
  size cap. Reading.
- `execute.rs:1067`, `prepare.rs:194`: `RiskItem::with_subtree_keys` is never
  called outside tests, so a whole `Classes` tree counts as one key for the
  restore-point rule. Suspected.
- `report.rs` (`quarantined`): an op that ended `VerifyFailed` is not counted
  toward the volume's usage although its item may be in quarantine. Reading.
- Decision log 2026-11-15 on `item_fp`: "an edited value can only make the
  executor skip". Removing the value from the sidecar switches the scan-time
  identity check off (`execute.rs:964-969`), so the item is then bound from
  validation only. It cannot widen what is deleted beyond the confirmed
  targets; the wording should say so. Reading.

## Tests that assert less than their name

- `tests/crash.rs`, `every_fault_point_recovers_by_resume_and_by_rollback`:
  every declared point but `expiry.mid` has a scenario, and the comparison is
  against an independent state (an uninterrupted run for resume, the machine
  before the run for rollback). It does not cover: a crash during recovery
  itself (in resume, in rollback's undo phase), a change of the machine
  between crash and recovery, resume after a partial rollback (M2), a
  selection that is not every item (M3), and several point and op pairs
  (`act.after` on the second file, `done.before` on the value and segment
  ops). `group.end` is hit only at the end of the run, because the plan has
  7 intents and a group closes after 64.
- `gate/tests.rs`,
  `own_effects_explain_only_what_the_runs_completed_ops_did` and the three
  `..._is_still_refused_after_outside_changes` tests make every outside change
  after the own ops and after a clock tick; none makes it before (S4).
- `a_key_changed_after_validation_is_refused_at_the_act` changes the root
  only (S5).
- `locked/tests.rs`,
  `retry_held_passes_the_journalled_destination_and_maps_outcomes` never
  asserts the undo of a failed retry (S2).
- `expiry/tests.rs`: `a_session_being_undone_is_not_expired` covers the open
  intent only (M15); no test has a gate refusal below an item's root (S3) or
  a `Retried`, `HeldRetry` or `VerifyFailed` op (M16).
- `locked` VM test `system_list_registers_and_removes_only_our_pair_vm` uses
  `remove_exact`, not the `remove_counted` path undo uses.

## Wave 2 findings

| Finding | Status | Evidence |
|---|---|---|
| S1 store handles for journal and backups | closed | `journal/writer.rs:173`, `:196-205`; `journal/reader.rs:45-49`; `journal/hash.rs:94`; `regbackup.rs:1023`, `:1107` take `&SessionDir`; `storage.rs:1808` returns the checked `StoreFile`; no `File::open` or `remove_file` by path left in `regbackup.rs` |
| S2 half-deleted tree reported complete | closed | `regbackup.rs:319-336` (`PartialBefore`), `:1929` `restore_missing`, `:2209-2219`; the test at `:3648` now asserts `A\A1` is back; the crash matrix drives `regdelete.mid` by resume and rollback |
| S3 key path mapping in regbackup | closed | no non-test code in `regbackup.rs` opens a key by path; `open_subkey` only on handles the gate passed in (`:1649-1771`, `:2304`) |
| S4 undo checks one open, acts on another | closed | `gate.rs:2413` returns `CheckedUndoKey` holding the open key; callers `act_reg.rs:1209`, `:1493` |
| S5 part 1, stamp and exemptions from the caller | closed | `gate.rs:1433-1452`: taken from `ctx.recorded(op)`; an op id without a record is refused |
| S5 part 2, keys not bound to validation | partly | root facts are compared (`gate.rs:2166-2204`); S4 and S5 of this report remain |
| S6 `done` of a boot move not flushed | closed | `writer.rs:349-361`, `:742`; `locked.rs:1275` (`pending_after_crash`) covers the window between registration and `done`; crash matrix `bootmove.registered` |
| S7 `resume_intent` repeatable, undo after expiry | closed | `writer.rs:391-404` (once per op); `state.rs:706` (`UndoAfterExpire`), `:767` |
| M3 directories reopened by path | closed for the quarantine directory (`QUARANTINE_DIR_DIFFERS` compares with the store's handle); session directories are still opened by path and then checked by final path (`storage.rs:1248`, `:1093`, `:1449`) |
| M5 unbounded memory | closed | `MAX_CAPTURE_BYTES`, `list_dir_capped`, 256 MiB read caps |
| M6 fault points | closed | `regrestore.mid` and both backup points are hit; all 16 declared points are used in non-test code |
| M7 journal cut at a line boundary | closed | index mark; `roundtrip.rs` `a_journal_cut_behind_its_index_mark_is_refused_as_damaged` |
| M8 `;` inside quotes | closed | `split_semicolons` honours quotes |
| M9 smaller points | partly | volatility closed (`VolatilityDiffers`); SACL and mandatory label still not captured |

## What the VM gate should try to break

Cases the unit tests cannot reach:

1. **Elevation and users.** Scan as standard user `tester`, execute
   over-the-shoulder as another administrator: `user_sid`, HKCU mapping,
   package removal (M12). Run every mutating verb unelevated and from a
   filtered admin token: all must refuse before reading a file.
2. **S1 as an attack.** After a session removed an admin-only directory under
   `C:\ProgramData`, create it as the standard user, then undo elevated.
   Check owner and DACL of the directory and of the restored file.
3. **Boot-time moves performed by SYSTEM.** A locked file under
   `Program Files`: registration, restart, reconcile `Completed`, undo. The
   same with the file under a user-writable ancestor: must be held, no pair
   written. Between registration and restart, as standard user: try to swap
   an ancestor for a junction, pre-create the destination, add a hard link.
   A foreign malformed entry in `PendingFileRenameOperations` before ours
   (M6). The real spelling of the pair (`\??\`, long path, trailing
   backslash) and `remove_counted` against the real list. Undo before the
   restart, and undo after it without a reconcile in between.
4. **A second volume.** Items on `D:` with `.purge-q` at its root: a standard
   user pre-creates `D:\.purge-q` (plain, as a junction, with a child session
   directory); the root DACL lets Users rename; the volume mounted in a
   folder; the volume detached at purge time and re-attached (M17); the size
   cap per volume.
5. **The store under ProgramData.** A standard user pre-creates
   `C:\ProgramData\Purge` or `Purge\Quarantine` before the first run, holds
   `index.json` open, and writes into a quarantined directory they owned
   (M14).
6. **Real AppX packages.** Removal with and without the acknowledgement; a
   package registered for another user only; a package reinstalled between a
   crash at `intent.flushed` and the resume; a provisioned package.
7. **System Restore.** Point requested and created; service disabled;
   creation slower than the wait; a second run inside the 24-hour throttle.
   A restore to that point after an undo, and an undo after a restore to that
   point (the store is under ProgramData and the journal may be newer than
   the registry).
8. **Real crashes.** Power-off of the VM (not a process abort) at
   `intent.flushed`, `act.after`, `regdelete.mid`, `undo.act.after`,
   `bootmove.registered` and `index.write`, on a spinning-disk image, to see
   that what the journal calls flushed is on disk. Then resume and rollback;
   then a crash inside the rollback followed by a resume (M2).
9. **Registry views and links.** A 32-bit application's keys under
   `WOW6432Node` and `HKLM\SOFTWARE\Classes` against
   `WOW6432Node\Classes` (a real link on Windows 11); a key the standard user
   turned into a `REG_LINK` under their own hive between scan and execute; a
   key name ending in a backslash through `plan from-targets` (S6).
10. **Names.** Quarantine and purge of a tree holding `aux.h`, `nul`, a name
    ending in a dot and one ending in a space (S3); an 8.3 short-name plan
    path; a case-sensitive directory.
11. **Expiry.** With the rig clock offset: purge with consent, crash at
    `expiry.mid`, purge again; a junction and a hard link inside a
    quarantined tree, their targets intact afterwards.
12. **A plan selection that is not all items**, crashed at `journal.header`
    and resumed (M3).

## Checked and found sound

- **Confirmation.** `plan_in::bind` recomputes the plan hash, refuses
  duplicate ids over items and absorbed candidates, an absorbed id, an
  unknown id and an empty selection; ids are compared exactly (no case or
  normalisation step that could alias two ids); the op list is exactly the
  selected top-level items. Everything that decides whether an item may be
  selected and what is acted on (target, action, band, child ids, order) is
  under the hash. A Blocked descendant of a ticked parent is always a
  top-level item (`collapse.rs`: only Safe, Likely-on-score or Weak-on-score
  candidates are absorbed), so its band is hashed and the protected-descendant
  refusal cannot be edited away. `rebind_interrupted` accepts a selection
  only when its SHA-256 equals the header's: it can fail (M3), not pick a
  wrong one.
- **Run.** Every action takes the token of a flushed intent; an op without an
  accepted `validated` record is never acted on (`Route::NotValidated`); a
  resumed run takes its settings and `allow_irreversible` from the journal,
  not from the caller.
- **Recovery.** The probe tables match the code; a probe of `Attention`
  changes nothing; `resume_intent`, `resume_undo` and `resume_retry` hand out
  one token per op; a second `resume` or `rollback` writes nothing (also
  asserted by the crash matrix on the store's bytes); recovery never retries
  a held item; an op whose undo settled is no longer pending and cannot be
  retried.
- **Undo.** Never overwrites: moves back and directory creation are
  handle-relative with no replace flag; a differing value, a non-empty key, a
  link or a missing parent is a conflict; conflicts and failures are not
  settled and are tried again in the completing form; an expired op is a
  conflict; the dependency pull-in is transitive.
- **File actions.** Quarantine move and move back rename the checked handle
  into a checked directory handle (`Flags 0`, `RootDirectory` set).
  `create_dir` is handle-relative with `FILE_CREATE`; `set_times`,
  `set_security` and `set_attributes` act on that handle; no privilege is
  enabled; a SACL is refused.
- **Boot-time moves.** Never a delete, never a replacing destination; the
  item and every ancestor up to the drive root must be admin-only and no
  reparse point; the destination is tied to the store-checked op directory by
  file id; the exact removal is a compared read-modify-write that preserves
  foreign bytes and requires exactly one occurrence.
- **Registry.** Keys are opened only at the probe's address with the view
  flag and `REG_OPTION_OPEN_LINK` on every component; deletes are
  `NtDeleteKey` on the inspected handle; `create_subkey` requires
  `REG_CREATED_NEW_KEY`; no restore takes a key path from a backup file;
  backup files are size- and hash-checked before parsing.
- **Expiry.** The walk is handle-relative throughout, never resolves a path
  string, removes a reparse point of any tag as the link only, re-checks file
  id and tag before descending, and will not clear read-only on a file with
  more than one link. The root is identified and gated before `expire`;
  `expire` is flushed before the first delete. Age arithmetic saturates; the
  clock offset exists only in rig builds.
- **Journal parsing.** `parse`, `unframe` and `parse_names` are
  bounds-checked with a 256 MiB cap; no `unwrap`, `expect` or unchecked index
  on data from disk was found in non-test code (the one `expect` in
  `state.rs:583` follows a successful lookup of the same key).
- **Gating.** The release engine has no dependency on `purge-exec`, no
  executor strings, and refuses every executor verb; the only gate is
  `cfg(feature = "rig-exec")`; no environment variable or argument selects
  the relaxed store; elevation is `TokenElevation` on the process token,
  fail-closed, checked before any file is read.

## Not checked

- Anything that needs elevation, a restart, a second volume, a real AppX
  package or System Restore (the list above).
- `sid::is_admin_only_writable` masks and the ancestor facts read by
  `gate::admin_only_ancestors`, beyond the owner check.
- How the session manager parses a malformed pending-rename list, and the
  real spelling `MoveFileExW` writes.
- Whether Windows and `regbackup::fold` fold key names identically.
- FAT, exFAT and ReFS volumes; Windows before 1809.
- Two engine processes at once (concurrent `update_index`, two writers on one
  journal beyond the exclusive handle).
- `vm/guest/riglib.ps1` and the rig's run modes, including which engine
  binary the rig starts and whether `plan from-targets` canonicalises.
- No experiment was run for S1, S2, M2 and M3; they are from reading.
- The test files of `storage`, `journal`, `expiry`, `act_reg` and `act_fs`
  were not read in full.

## Clean-up

The worktree holds no change but this file. A temporary test file used for
the M1 and S5 experiment was removed. Build output remains under
`E:\purge-build\review3`; `E:\purge-build\review3-cli` was deleted. No test
key is left under `HKU\<SID>\Software`. `%TEMP%\.tmpAhJmlX` (one file,
`cache.db`, created 01:30 during the review) was left in place: it has the
same form as 39 older directories there and could not be tied to this
review's runs.
