# M2 durability fix review

Reviewed `6f3a6c0` ("M2: registry effects durable before done; re-probe after an
unclean stop: gate case p902") on local branch `m2`: the diff and what it calls
(`durable.rs`, the journal writer and state, `Run::reprobe_unconfirmed`,
`recover.rs`, the undo driver's registry branch, `act_reg::probe_reg` /
`complete_reg`, `regbackup::restore_missing` / `finish_delete_tree`, the file
flushes in `act_fs.rs`, the crash-matrix seam). Reviewer changed no source code
and did not delegate.

## Verdict

**Re-run the gate as is.** No blocking finding. The order the commit promises
holds: every record that vouches for a registry change is written after a flush
of the hive the change is in, in run, undo and recovery. The p902 case
(power-off at `commit.before`) now has a marked `group_end` in front of the
fault point, so nothing is unconfirmed and the changes are flushed.

Three serious findings (S1 to S3) are in the new re-probe, not in the flush
order. They produce a wrong report or a wrong undo result, not a wrong delete.
S1 needs no power loss and no third party: an ordinary crash is enough. The
gate's crash matrix uses first-hit fault points and, as far as its fixtures
were read, does not reach S1; a numbered fault point (`done.before:2` on the
`nested-sequence` fixture) would, and would show as exit 10 instead of 0. Fix
S1 to S3 before a release.

Evidence labels: **experiment** (Windows 11 build 26300, unelevated, a
throwaway `HKCU\Software\PurgeTest-rv-*` key, removed), **test** (a temporary
test added to `tests/crash.rs`, run, and removed again; not committed),
**reading**.

Tests run (`CARGO_TARGET_DIR=E:\purge-build\review6`, features
`fault-inject,test-support`): `--test crash -- power_loss`: 2 passed;
`--lib -- durable:: journal::`: 40 passed. The rest of the suite was not run.

## Blocking

None.

## Serious

### S1. A change that a later op of the same run overtook is reported as lost

`crates/purge-exec/src/recover.rs:609-628` (`removed_with_later_key`),
`crates/purge-exec/src/execute.rs:1281-1308`,
`bins/purge-engine/src/cli/exec.rs:1165`.

Defect: an unconfirmed op whose probe is `Attention` counts as done only when a
later op is a key delete, has a `done` with outcome `Done`, and its key is
gone. Two ordinary cases fall outside:

(a) The later key delete has an open intent (the crash came after the delete
and before its `done`). `reprobe_unconfirmed` runs before `settle_open`, so the
later op has no outcome yet.

(b) The later op changed the same value: a second `EditSegment` on one value
(two PATH entries of one application), or a `DeleteValue` after an
`EditSegment`. The first edit's probe sees a value that is neither "as before"
nor "as written".

In both cases nothing is wrong on the machine, and resume writes the warning
"the journal says it was done, but ... the registry does not show it and it
could not be done again" and exits 10.

Scenario (a), no power loss: plan = value `leaf` in key `C`, then delete `C`.
The process dies after `C` is deleted and before its `done`. Resume: op 1 is
unconfirmed, its key is gone, the gate refuses it (`gate.undo-key-missing`),
op 2 has no outcome, so op 1 is reported as lost. Then `settle_open` finds
op 2 done. The run commits with all items `Done`, one false warning, exit 10.

Scenario (b), no power loss: two segments removed from one `REG_MULTI_SZ`
value, crash at the next intent. Resume reports op 1: "the value is neither
what it was nor what the edit writes".

Confirmed: **test**. (a) the commit's `power_loss_scenario` plan with the child
killed at `done.before:2`, no power-off, then `resume`: `reprobed[0]` is
`Attention { "the gate refuses the key: ChangedSinceScan
(gate.undo-key-missing)" }`, the report holds the warning, state `Committed`,
all eight outcomes `Done`. (b) a plan with two `EditSegment` ops on `Seg\List`,
killed at `intent.flushed:3`: op 1 `Attention`, op 2 `Done`, same warning.

Smallest fix: judge an `Attention` after the open intents are settled (move
the "does it match" decision behind the `settle_open` loop, or let
`removed_with_later_key` accept a later op whose probe is `Done` whatever its
journalled outcome). For (b), count a segment edit as done when a later
`Done` op of the run is on the same key and value name and that op's own probe
is `Done`. M1 below removes the plain-crash half of both.

### S2. Rollback of an unconfirmed key delete completes into a key somebody else re-created, and reports it restored

`crates/purge-exec/src/undo.rs:898-901`,
`crates/purge-exec/src/regbackup.rs:2128-2162`,
`crates/purge-exec/src/act_reg.rs:1505-1525`.

Defect: every unconfirmed `Done` is undone in the completing form
(`restore_missing`), whether or not its delete survived. The completing form
was written for a key the run itself left half deleted, where every key that
still exists is an original. For an unconfirmed op whose delete did survive, a
root key that exists is not an original: something re-created it.
`restore_missing` then keeps that key as it is, adds what is missing below it,
and returns `AlreadyRestored` or `Restored` with a difference in the detail
text. The key's own values from the backup are not put back. The ordinary form
(`restore_tree`) answers `KeyNotEmpty` here and changes nothing.

Scenario: a run deletes `Nest\A\B\C`, `Nest\A\B`, `Nest\A` and dies before its
`group_end` (crash or power loss, the deletes survive). The application starts
and creates `Nest\A` again with a value `new`. `journal rollback`: op 4
(`Nest\A`) is `AlreadyRestored`, ops 3 and 2 are `Restored` below the foreign
key, the session is `Undone`. `Nest\A` holds `new`, not the backed-up `a`.
The session then counts as undone, and its backup goes with it at expiry.

Confirmed: **test**. Child killed at `intent.flushed:7` (no power-off),
`Nest\A` created with value `new`, then `rollback`: op 4 `AlreadyRestored`,
ops 3, 2, 1 `Restored`, state `Undone`; `Nest\A\a` absent, `Nest\A\new`
present, `Nest\A\B\b` present.

Smallest fix: choose the form from the op's probe, not from "unconfirmed":
key absent or `Partial` as now; tree intact: `AlreadyRestored`; `Diverged`:
the completing form only when the difference is what earlier ops of the same
session removed (they are undone later and then report it themselves),
otherwise the conflict `restore_tree` would give. The simplest way to get
exactly that: in `rollback_run`, run the forward re-probe of resume first
(bring the unconfirmed ops to what the journal says, or have them reported),
then undo them in the ordinary form.

### S3. An op the re-probe could not match keeps its `Done` in the journal and in the report

`crates/purge-exec/src/execute.rs:1296-1308` (a warning only),
`crates/purge-exec/src/journal/state.rs:839-858` (the next marked `group_end`
or `commit` clears the set).

Defect: when the re-probe ends in `Attention`, or the redo ends in anything but
`Done`, no record is written. The run commits, the op's outcome stays `Done`,
the report's counts say it was removed, and `unconfirmed` is empty afterwards.
This is the thing the gate case was about ("resume reported removals that had
not happened"), now with a warning and exit 10 beside it. A later undo reads
`Done`, runs the ordinary restore and ends in a conflict (`ValueDiffers`,
`KeyNotEmpty`), although for a redo that stopped and put the key back
(`complete_key` ending `Skipped{ChangedSinceScan}`) there is nothing to undo.

Scenario: power loss takes the delete of value `Gone`; before resume the
application writes `Gone` with other data. Resume: `Attention`, warning,
`commit`. Report: 8 of 8 `Done`. Undo: the session ends `PartiallyUndone`.

Confirmed: **test**. Killed at `intent.flushed:7`, `Vals\Gone` set to other
data, `resume`: op 5 `Attention`, journal outcome `Done`, state `Committed`;
`undo`: `PartiallyUndone`.

Smallest fix: journal what the re-probe found. One new record (or a
`reconcile` result) that replaces the op's outcome, as `Retried` does for a
held item: `Failed{VerifyFailed}` for `Attention`, the redo's outcome
otherwise. The report and undo then read the truth, and undo takes the
completing form for `VerifyFailed` as it already does.

## Minor

### M1. Resume makes "lost" changes again without any sign that something could have been lost

`crates/purge-exec/src/execute.rs:1263-1280`.

A registry change can only be lost when Windows went down. After a process
crash with no restart, every `Done` is in the running registry. Resume still
re-probes and, on `NotDone`, deletes again: a value or key that was removed,
and that the application wrote back identically before the resume, is removed
a second time. It equals the backup exactly, so the rule in the commit is
kept; the redo is just not justified by a power loss. Confirmed: **test**
(killed at `intent.flushed:7`, `Vals\Gone` written back with the same data,
`resume`: `probe NotDone, redone Done`, value gone). Smallest fix: redo only
when the system was started after the journal's last write (boot time against
the journal's last record time, or a boot identifier in the header);
otherwise report. This also removes S1 for plain crashes.

### M2. Outcomes other than `Done` can also be made false by a lazy write

`crates/purge-exec/src/journal/state.rs:839`. A key delete that stops and
puts back what it deleted ends `Skipped{ChangedSinceScan}`, "nothing changed".
The delete and the put-back are two sets of writes; a lazy hive write between
them, then a power loss before the next flush, leaves the key half deleted on
disk with a `done` that says nothing happened, and undo answers
`NothingToUndo`. The window is milliseconds. **Reading.** Smallest fix: treat
a registry `done` of an op that wrote anything (a rollback ran) as
unconfirmed too; its probe is `NotDone` when all is well and `Partial`
otherwise.

### M3. A hive that cannot be flushed stops everything, including what it has nothing to do with

`crates/purge-exec/src/journal/writer.rs:515, 552, 573, 604, 624`. A failed
`RegFlushKey` refuses the `group_end`; the run aborts; `aborted` needs the same
flush and is refused too (twice, `execute.rs:1716`). The session stays
unfinished. That is recoverable: nothing false was written, and resume or
rollback work once the flush works. While it fails, no verb can close the
session, a resume acts on up to 64 more ops before it finds out, and rollback
performs one inverse per attempt and stops at its `undo_done`, also for file
ops. **Reading.** Smallest fix: a `group_end` whose flush failed can be written
without the mark (the unconfirmed rule already covers it); keep the hard stop
for `commit`, `aborted` and the undo records, and flush only the op's own hive
before an `undo_done`.

### M4. File changes on another volume that are found, not made, are not flushed

`crates/purge-exec/src/act_fs.rs:1339-1347` (`durable_restore` flushes only
`Restored`, not `AlreadyRestored`), `crates/purge-exec/src/execute.rs:1210-1214`
(`settle_open` writes `done` for a probe `Done`),
`crates/purge-exec/src/locked.rs:1939` (the move back of a reconcile mismatch).
Each needs two failures in a row (a crash after the move, then a power loss
after recovery wrote the record). **Reading.** Smallest fix: flush on
`AlreadyRestored` and on a probe `Done` too; flush the parent after the
reconcile move back.

### M5. The log-order argument is NTFS only; the data root is not checked to be NTFS

`crates/purge-exec/src/act_fs.rs:995-997`. Quarantine volumes may be NTFS or
ReFS (`storage.rs:310-318`); no check was found that the data root is NTFS.
On a ReFS data root the stated reason does not apply. **Reading.** Smallest
fix: `off_journal_volume` also answers true when the journal's volume is not
NTFS.

### M6. A registry op without a recognised hive is silently not tracked, and the `group_end` is still marked

`crates/purge-exec/src/durable.rs:68-80`, `journal/writer.rs:352, 518-523`.
`Hive::of_key` gives `None` for any root but `HKLM` / `HKU`. Plan intake only
lets canonical targets through, so this cannot happen today. **Reading.**
Smallest fix: `intent()` refuses a registry op whose hive is `None`.

### M7. "Gone with a later key" also covers an `Attention` that has another cause

`crates/purge-exec/src/execute.rs:1281-1295`. Any `Attention` is waved through
when a later key delete took the key, also one from an unreadable or altered
backup. The machine does match the journal; the damaged backup shows up only
at undo. **Reading.** Smallest fix: apply the rule only to the gate's
key-missing refusal.

## Question 1: durability order

Holds. By record:

| Record | Flush before it | Where |
|---|---|---|
| `group_end` | all touched hives, then the record with `registry_flushed` | `writer.rs:515-523` |
| `commit` | `end_group`, then the hives again | `writer.rs:550-552` |
| `aborted` | same | `writer.rs:572-573` |
| `undo_done`, `undo_conflict` (with and without token) | the hives | `writer.rs:604, 624, 644, 657` |
| boot-move `done` | `SYSTEM` and everything else touched | `writer.rs:388-390` |
| undo that took a boot pair back | `SYSTEM` touched, flushed by the `undo_done` | `undo.rs:804, 818` |

A hive is touched at `intent`, `resume_intent`, `reprobe_token`, `undo_intent`
and `resume_undo`; a writer opened on an existing journal starts with every
hive of the session touched (`writer.rs:229-237`), so what an earlier process
left unflushed is covered. The per-64 batching: `intent()` closes a full group
first, `done()` closes it when full and nothing is open; both go through
`end_group`.

Recovery's own writes: a `done` that `settle_open` or `rollback_run` writes for
a probe `Done` is an ordinary unflushed `done` and stays unconfirmed until the
next marked record. A redo under `reprobe_token` touches its hive and is
flushed before the run's end.

`reconcile`, `retried` and `expire` are written without a registry flush. None
of them vouches for a registry write of the engine (a retry never registers a
boot-time move; reconcile only reads the list).

Hives:

- **`HKLM\<first key>`, `HKU\<SID>`, `HKU\<SID>_Classes`**: right. Windows
  mounts hives only directly below `\Registry\Machine` and `\Registry\User`.
- **Does the flush reach the change?** Yes. **Experiment**: a handle on the
  hive root `HKU\<SID>`, opened with `KEY_READ` and `REG_OPTION_OPEN_LINK`,
  flushed after 200 value writes in a subkey three levels down: 3.4 ms; again
  with nothing pending: 0.003 ms; after 200 deletes: 3.6 ms. The flush is of
  the hive, not the key, and needs no write access. That the data is then on
  disk is Windows' documented contract and was not tested here.
- **`HKCR`, `HKCU`**: not canonical; targets are `HKLM` / `HKU` only. See M6.
- **WOW64 views**: same hive file; the name is taken before the
  `WOW6432Node` segment.
- **`HKLM\SOFTWARE\Classes` against user classes**: the first is in
  `SOFTWARE`, the second is its own hive and addressed as `HKU\<SID>_Classes`.
  `HKU\<SID>\Software\Classes` is a link, which the gate refuses.
- **Volatile keys**: nothing to make durable; after a restart the key is gone
  and the probe is `Done`.
- **Application hives** (`\Registry\A`): not addressable as `HKLM` / `HKU`.
  Hives loaded under `HKLM\X` or `HKU\X`: named by the first component.
- **`HKU\.DEFAULT`**: its own hive, flushed as `HKU\.DEFAULT`.
- **A hive that is not loaded** is skipped (`durable.rs:114`): correct, an
  unload writes the hive.
- **A flush that fails or needs a right**: nothing is written, the state is
  recoverable, not stuck; see M3.

## Question 2: the unconfirmed rule

Right at the crash points looked at:

- Between the flush and the marked record: the ops are unconfirmed, the
  changes are on disk, the probe says `Done`.
- Torn tail: the cut removes whole records; an op whose `done` is cut is
  intent-only and goes to the old probe.
- Journals without the mark: every registry `Done` of an unfinished run is
  unconfirmed. A finished old journal is taken as it is (its `commit` was
  written without a flush); nothing can be done about those.
- File-only sessions: the set is empty; the only cost is one flush of `SYSTEM`.
- A crash during the re-probe or after a redo: no record was written, the set
  is the same at the next open, the probes are repeatable.
- Other outcomes: see M2. `Failed{VerifyFailed}` is already undone in the
  completing form. `PendingReboot` is flushed at its `done`.

What is wrong is what happens after the classification: S1 and S3.

## Question 3: re-probe and redo

- **Can it delete what it should not?** Not found. The redo goes through
  `finish_delete_tree` / `delete_value` / the recorded segment hashes: each
  key is compared with its backup node (class, values, security with owner,
  no extra subkey) on the way down and again before its delete; a value by
  type and data. Anything else stops, and what was deleted is put back. What
  it does delete is an exact copy that appeared again (M1).
- **"Gone with a later key"**: cannot hide a change that is still there (the
  later key is probed and must be absent). It can hide an unusable backup
  (M7). It is too narrow (S1).
- **Order**: op order is right. Within one hive what survives is a prefix of
  the changes, and each backup was taken after the earlier ops.
- **Idempotence**: holds (tested by the commit; reading for a crash inside the
  redo: `Partial`, finished at the next resume).
- **No second `done`**: S3.
- **Rollback's completing form**: S2.

## Question 4: file side

The claim is acceptable for NTFS. A rename or directory removal is a logged
transaction; `FlushFileBuffers` on the journal forces the log at least up to
the journal's own update, and the log is written in order, so the earlier
rename is committed with it. This is how NTFS behaves, not a documented
promise, and it was not tested (it needs a power-off). The power-off rows of
the gate cover it only if a file move sits between the last flush and the
fault point; `intent.flushed` on a later op does.

No failed flush is swallowed: each of the three new flushes turns a failure
into `Failed{VerifyFailed}` (`act_fs.rs:852-862, 945-957, 1352-1359`), which
undo treats as "changed". Places with no flush at all: M4. File system: M5.

## Question 5: the crash-matrix seam

What it models: after the child dies, the test key is put back to what it was
at the last hive flush the child's observer saw. That is one of the states a
power loss can leave: the one where Windows wrote nothing by itself.

What it does not model:

- **States in between.** The lazy writer can run at any moment, so a power
  loss leaves any prefix of the changes since the last flush. The seam tests
  "everything since the flush lost" and "nothing lost". The cases the re-probe
  exists for are the mixed ones (inner op kept, later key delete lost, and so
  on).
- **The journal.** A killed process loses nothing it wrote. A power loss drops
  what was written after the last `FlushFileBuffers`. The three fault points
  chosen are ones where the journal's tail happens to be flushed.
- **Order.** The observer fires when a flush is called. A flush moved to after
  the record it should precede passes every scenario: there is no fault point
  between the flush and its record.
- **Whether `RegFlushKey` makes anything durable.** Not testable on the host.

"Fails before" is by construction because without the fix no flush is ever
observed, so the recorded state stays the one from before the run. The test
proves that some flush was called before the fault point.

What would make it real:

1. Prefix enumeration: the child records the key after every registry op (at
   `done.before`), the parent restores each recorded state from the last
   observed flush onward, and for each one resume and rollback must reach the
   reference. This is the lazy writer modelled outside the code under test,
   and it fails without the re-probe whatever the flush code does.
2. An order check: the observer logs the journal's length at each flush; the
   test asserts that every `group_end`, `commit`, `aborted` and `undo_done`
   lies behind a flush with no registry action in between. Add fault points on
   both sides of the flush.
3. The VM: hard power-off rows with numbered fault points on `nested-sequence`
   (`done.before:2`, `intent.flushed:<first file op>`, `group.end:1`,
   `undo.intent:<n>`), not only first hits. Only this shows that the flush is
   durable and that the NTFS claim holds.

## Not checked

- Durability itself: no power-off was made. That `RegFlushKey` data survives,
  and the NTFS log-order claim, rest on Windows' behaviour as known.
- "All 10 power-loss scenarios fail without the fix": not re-run against the
  parent commit.
- The gate's fixtures and crash rows were read only as far as needed to judge
  whether S1 is reached; the statement that it is not is from reading
  `m2-fixtures.ps1` and `m2-crash.ps1`, not from a run.
- Elevated runs, `HKLM` hives, another user's hive, `HKU\S-1-5-18`,
  `HKLM\SAM` / `SECURITY` (whether their root opens with `KEY_READ`): reading
  only; the experiment was on the reviewer's own user hive.
- ReFS and directory flushes on a second volume: no second volume was used.
- The retry of held items and the locked-file ladder beyond their flush points.
- `journal recover`'s listing and JSON output, `journal/tests.rs`, the model's
  serde test: read, not judged line by line.
- Performance figures in the commit message: only the single-flush cost was
  measured again (3.3 to 3.6 ms after 200 changes, 3 microseconds clean).
