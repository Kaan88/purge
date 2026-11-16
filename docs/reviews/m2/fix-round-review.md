# M2 fix-round review

Reviewed `d2f7a63..ceb5999` ("M2 fixes (volume queue, op directory, boot pair): ..."),
the head of local branch `m2`. Scope was the diff, without `vm/`. Reviewer
changed no source code and did not delegate.

## Verdict

**Go to the VM gate.**

No blocking finding and no serious finding. S1 to S7 of the final review are
closed; two of them leave a small residue that is listed as minor (F1, F7).
Nothing found in the fix round lets a standard user steer an elevated run, and
no new path deletes a file or key without a journalled intent and a verified
backup.

Two things to do before the first gate run. Neither is a change to the
engine's logic:

1. Write the open limits into `docs/DECISIONS.md` (question 2 below). Only
   M13 and the service-account rule are recorded there today; the M14 residue
   is recorded in the module text of `expiry.rs` only.
2. Run the two `#[ignore]` tests of the elevated owner restore on the gate VM
   first (F4). The code that enables `SeRestorePrivilege` has not run in any
   test on this host, and the repository holds no script that runs it.

Evidence labels: **experiment** (a run against `ceb5999`, Windows 11 build
26300, unelevated, medium integrity, the library with the relaxed test store,
registry under `HKU\<SID>\Software\PurgeTest-*`), **reading**, **suspected**.

Tests run: `cargo test -p purge-exec --features fault-inject,test-support
--lib`: 422 passed, 0 failed, 8 ignored; `--test crash`: 8 passed;
`--test roundtrip`: 10 passed. `cargo test -p purge-engine --lib output`:
8 passed. `cargo test -p purge-win --features write --lib` (the
`set_security` and restore-privilege tests): 3 passed, 1 ignored.
`xtask ci` and `check-deps` were not run.

## Blocking

None.

## Serious

None.

## Minor

### F1. A move back still goes into a parent directory that somebody else re-created, when the session did not remove that directory itself

Files: `crates/purge-exec/src/act_fs.rs:1322` (`move_back`),
`crates/purge-exec/src/undo.rs:366` (`unrestored_ancestor`).

Defect: the S1 fix covers a parent that an op of the same session removed or
moved (`unrestored_ancestor` looks at the session's ops only, and
`existing_dir` runs only for a `RecreateDir` inverse). A `MoveBack` whose
parent was not touched by the session is still checked for reparse state,
volume and a free leaf only. Owner and DACL of the parent at the act are not
journalled, so they cannot be compared.

Scenario: the session quarantines `C:\ProgramData\App\helper.exe` and deletes
its HKLM `Run` value; the directory stays because it holds other files. Later
something else removes `C:\ProgramData\App` (the application's own
uninstaller, another cleaner). A standard user creates it again and owns it.
The administrator undoes the session: `helper.exe` is renamed into the
user-owned directory and the `Run` value comes back. Same end state as S1; it
needs a third party to remove an admin-only directory between run and undo.

Smallest fix: journal the parent's file id in the `MoveBack` inverse (it is
on the handle the act already holds) and make a parent with another id a
conflict. Without a journal change: write it down as a limit.

Confirmed: reading.

### F2. A key restore merges into an existing empty key whatever its owner and DACL

Files: `crates/purge-exec/src/regbackup.rs:1960-1993` (merge, the difference
`RootSecurityKept`), `:386` (`Difference::is_security` leaves it out on
purpose).

Defect: the registry counterpart of S1. The fix round made a re-created key
whose security reads back other than recorded a failed undo, and made an
existing directory with another owner or DACL a conflict. An existing empty
key is still adopted with its own security, the values and subkeys are
restored into it, and the undo ends `Restored` with a note.

Scenario: `HKLM\SOFTWARE\Vendor\App` (administrators only) is deleted;
`HKLM\SOFTWARE\Vendor` lets Users create subkeys (some vendors' keys do). A
standard user creates an empty `App`, which they own. The undo puts the
values back into a key the user has full control of. Not reachable under
`HKLM\SOFTWARE` itself or any parent with the default DACL; in HKCU there is
nothing to gain.

Smallest fix: merge only when owner and DACL of the existing key equal the
recorded ones (the comparison `restore_security` already makes); otherwise
`Conflict(KeyExists)`.

Confirmed: reading. Not introduced by the fix round; listed because the round
set the rule for the two neighbouring cases and not for this one.

### F3. Recovery's `complete_key` reports "the key is whole" when keys came back with another owner or DACL

File: `crates/purge-exec/src/act_reg.rs:1802-1803`.

Defect: `stopped.rollback.is_complete() || restore_missing(..).is_ok()`
looks at neither rollback's `differences`. The ordinary path
(`delete_stopped`, `:1083-1089`) now turns a security difference into
`Failed{VerifyFailed}`; this one ends `Skipped{ChangedSinceScan}`, which undo
reads as nothing to undo.

Scenario: a resume finishes an interrupted tree delete, the delete stops on a
change, the put-back cannot assign an owner. The journal says skipped and
whole; the keys have the token's owner.

Smallest fix: the same `any(Difference::is_security)` test on both reports,
ending `Failed{VerifyFailed}`.

Confirmed: reading. See question 2.

### F4. The elevated owner restore is run by nothing in the repository

Files: `crates/purge-win/src/reg_write.rs:479-552` (`with_restore_privilege`),
`:2074-2080`; `crates/purge-exec/src/regbackup.rs:4736-4742`.

Defect: the only tests of the path that enables `SeRestorePrivilege`
(`elevated_set_security_assigns_system_owner`,
`elevated_restore_puts_back_a_system_owner`) are `#[ignore]`. Their comments
say "the rig runs it"; nothing under `vm/`, `tools/` or `docs/` names either
test or passes `--ignored`. On this host (unelevated) only the refusal branch
ran: `ERROR_INVALID_OWNER`, nothing changed, no impersonation left on the
thread.

Smallest fix: run both on the gate VM before the campaign and record the
result; then add them to a rig script or correct the comments.

Confirmed: reading (search), experiment for the unelevated branch.

### F5. A failed `RevertToSelf` is ignored

File: `crates/purge-win/src/reg_write.rs:467-472`.

Defect: if the revert fails, the thread keeps running with the impersonation
copy, on which `SeRestorePrivilege` is enabled. The token is the process's own
user with the same groups, so the gain is that one enabled privilege for
later opens on that thread that ask for backup semantics; Purge makes none
on keys. Windows documents that a process should stop when the revert fails.

Smallest fix: `std::process::abort()` when `RevertToSelf` returns 0.

Confirmed: reading.

### F6. The validate pass reads a key tree with the file limit, not the key limit

Files: `crates/purge-exec/src/gate.rs:2278` (`item.max_files`, 5,000 by
default), `crates/purge-exec/src/execute.rs:1481` (`settings.key_limit`,
default 50, `regbackup.rs:74`).

Defect: the digest capture at validation reads up to 5,000 keys with all
their value data (bounded by `MAX_CAPTURE_BYTES`) for a tree the act then
refuses at 51 keys. With a run whose `key_limit` is above 5,000 it is the
other way round: validation refuses (`gate.tree-not-read`, `TooLarge`) a tree
the act would have taken. Cost and a wrong skip reason, never a wrong delete.

Smallest fix: hand the run's `key_limit` to `validated_tree`.

Confirmed: reading.

### F7. Undo re-creates the root key under the plan's spelling, not the stored name

File: `crates/purge-exec/src/regbackup.rs:830` (the root's name is the leaf
of the op's key text).

Defect: a key stored as `MixedCase` and addressed by the plan as `MIXEDCASE`
is deleted and comes back as `MIXEDCASE`, with `Restored` and no difference
reported. Windows compares key names without case, so nothing breaks; the
state is not byte-equal to the state before.

Smallest fix: take the root's name from the handle (`NtQueryKey`, name
information) in `capture_tree`; keep the op's text in `RegBackup.key`.

Confirmed: experiment (a temporary test, removed): spellings `MIXEDCASE` for
`MixedCase` and `ÉTÉ` for `été` restored under the spelled name. The same
run showed no spelling that is deletable but not undoable: a trailing space,
a trailing dot, a 255-character name and a name with `/` were deleted and
restored exactly; `Sq` for the key `Sq ` and a name with an embedded NUL did
not validate and nothing was deleted. Not introduced by the fix round.

### F8. Exit code 12 hides 10 and 11; `quarantine purge` still exits 0 when the index was not updated

File: `bins/purge-engine/src/cli/exec.rs:318` (`worse` takes the higher
number), `:768`, `:930`, `:1660-1671`.

Defect: a run that is partial (10) or an undo with conflicts (11) exits 12
when the index entry or the report was also not written; the table in
`cli.rs` does not say that 12 takes precedence. `quarantine purge` prints a
warning for `IndexUpdate::Unavailable` and `Failed` and exits 0 or 10 as the
items went: the M21 case for the one verb the fix did not touch.

Smallest fix: one sentence in the exit-code table; `Exit::Unrecorded` for the
two index results of the purge.

Confirmed: reading.

### F9. Expiry: the entry count is a budget, not a list (M14 residue)

Files: `crates/purge-exec/src/expiry.rs:83-84` (stated), `:1386` (the count
before the expire record), `:1726` (the walk's budget).

Defect: as the module text says. After a walk that stopped part-way, the next
run lets through as many added entries as the first run deleted. The count
before the expire record does not help then: it runs against the full count
too.

Scenario: a standard user who could write to the directory before it was
quarantined holds a late-sorting file in it open without delete sharing. The
purge deletes N entries and stops. The user renames into the quarantined
directory a directory they may move but not empty (an admin-only subtree
inside it), up to N entries, and closes the file. The administrator's next
purge of the unfinished item deletes it. Same volume only; needs the 30 days
and two purge runs.

Smallest fix: journal the number of entries deleted when a walk stops and
subtract it from the budget of the next run; a missing record refuses the
item. The real fix is the one the final review named: a protected DACL on the
quarantined root at the move.

Confirmed: reading. See question 2.

### F10. The no-follow writer now also applies to `scan -o` and `uninstall --fp`

Files: `bins/purge-engine/src/cli/output.rs:35-37`,
`bins/purge-engine/src/cli/output/nofollow.rs:273-281`, `:72`.

Defect, two parts. (a) Every file the CLI writes now refuses a junction,
symbolic link or mount point anywhere on its path, also in the unelevated
M1a verbs: an output directory on a volume mounted in a folder, or reached
through a junction, worked before and is now an error. This is stated in the
doc comment and is the safe side; it is a behaviour change of verbs outside
M2. (b) `RENAME_NAME_OFFSET = 20` and the hand-written
`FILE_RENAME_INFORMATION` are right for 64-bit Windows only and nothing
stops a 32-bit build.

Smallest fix: (a) a line in the help text and the decision log; (b)
`#[cfg(not(target_pointer_width = "64"))] compile_error!`.

Confirmed: reading; the junction test passed here.

### F11. `Done.detail` has no length bound and is not read back

Files: `crates/purge-model/src/exec/journal.rs:329`,
`crates/purge-exec/src/execute.rs:574-583`, `crates/purge-exec/src/report.rs:317`.

Defect: the detail is engine text with a path or an SDDL string in it (both
can be tens of kilobytes; the path is the plan's). It is JSON-escaped in the
journal and only `journal show` prints it, so it is not an injection path.
The report still takes details from the process's own notes, so a report
rebuilt by recovery does not carry the reason the journal now holds.

Smallest fix: cut the detail at a fixed length when journalling; let
`report` fall back to `Done.detail`.

Confirmed: reading.

## Question 1: the serious findings, one by one

**S1, undo into existing directories. Closed; residue F1.**
`existing_dir` (`act_fs.rs:1538`) opens the path without following a final
reparse point (`secure::open_for_security`,
`FILE_FLAG_OPEN_REPARSE_POINT`), reads the descriptor on that handle and
compares the `O:` and `D:` parts of the SDDL text with the recorded one.
String comparison is sound here: both strings come from the same conversion
on the same machine. `sddl_part` cuts parts at depth 0 on a part letter
followed by `:`; no alias ends in a way that fakes that. A standard user
cannot pass: they can copy a DACL, they cannot make Administrators or SYSTEM
the owner (a filtered administrator token cannot either). A junction swapped
in between `look_at` and the open is read as the junction itself, which the
user owns. A directory whose recorded owner was the user passes, and gives
the user nothing they did not have. The comparison is strict the other way:
a parent whose inheritable ACEs changed, or a reinstall that created the
directory with another owner, is `Conflict(DestinationExists)`, and every
file below it is then `act_fs.undo-parent-not-restored` until that directory
is gone. That is the intended side. `unrestored_ancestor` (`undo.rs:366`)
reads the journal state at the time of each op, so a directory op that ended
in a conflict earlier in the same undo run blocks the ops below it. With the
fix reverted both S1 tests fail (question 3).

**S2, failed verify after a retry. Closed.** `lock_state`
(`locked.rs:1345`) maps `Failed{VerifyFailed}` to `Moved`; crash test
`a_retry_that_ended_in_a_failed_verify_is_undone_from_where_the_item_is`
passes.

**S3, names below a quarantined item. Closed.** What is deleted is still
provably inside the item: every entry is opened relative to the handle of
its parent by the one listed name with `FILE_OPEN_REPARSE_POINT`; the item's
own path still goes through the guard; `gate_below` (`expiry.rs:1877`)
requires the handle's final path to equal the walk's path segment by segment,
the item's volume serial and a valid file id, never descends into a reparse
point of any tag, and under `Recheck` requires the recorded identity. A hard
link is removed as the name opened. Case and 8.3 names do not matter: the
comparison is case-insensitive on names the listing itself returned, and a
wrong match could only be another entry of the same directory. Names with an
unpaired surrogate are compared in the same lossy decoding on both sides.
Index bytes are subtracted only once the item is gone. Entries added during
the walk stop it; the remaining window is F9.

**S4 and S5, tree content binding. Closed.**

- What is hashed (`regbackup.rs:982-1071`): per key a domain prefix, the
  class, the SDDL text, the volatile and link flags, the values in folded-name
  order (name, raw type, SHA-256 of the raw data) and the subkeys in
  folded-name order (name, digest of the subkey). Every variable part is
  length-prefixed or of fixed size, counts precede the lists, so two different
  trees cannot give the same byte stream by construction. Not in it: last
  write times, the root's own name, SACL and mandatory label (never captured).
  "No class" and "empty class" hash alike. A tree with two sibling names that
  fold alike gives no digest and is refused at validation.
- Put-back is exact for every op kind. A deleted value is inserted with the
  type and hash of the intent's `pre` and must be absent now. A segment edit
  requires the value to hold exactly the hash the edit wrote and sets the
  hash from before. A deleted subkey is inserted with the digest of its own
  `validated` record and must be absent now; that is the digest the parent's
  validation saw, because the validate pass finishes before the first act and
  the child's own act was bound to the same digest. Delete-if-empty takes the
  same route (a one-key capture with everything put back). Effects are applied
  per key in reverse op order, so an edit followed by a delete of the same
  value unwinds correctly. An own effect on a key that is no longer in the
  capture is skipped, which is right: its parent then either holds a
  `SubkeyDeleted` put-back or does not match.
- An own op whose outcome is not `Done`, or whose journal record does not give
  the change exactly, refuses every tree holding its key. Safe side.
- Resume: effects are rebuilt from the journal (`note_journal`,
  `execute.rs:911`) after the `validated` records are handed to the context.
  A journal from before the field has no digest and every key delete in it is
  skipped as changed.
- A tree that changes between the capture and the delete: unchanged from
  before the round. The capture is the backup, and `delete_walk` compares each
  key with it and puts back what it deleted when it stops.
- Cost and limits: F6.
- Accepted and recorded: content written back identically is accepted.
- With `bind_tree`'s refusal removed, four tests fail (question 3).

**S6, empty segment and backup bound to the op. Closed.** One rule in the
guard's key probe, used by validation, the act, `backup_for_op` and the undo
gate; `backup_for_op` (`act_reg.rs:710`) runs before the backup is written and
again on the file as read back. Other spellings: F7 (experiment). WOW64 views
were not run; by reading, a spelled leaf that the probe maps to another leaf
fails the root-name comparison and the item is skipped before anything is
written.

**S7, output writer. Closed.** The root is opened by path with
`FILE_FLAG_OPEN_REPARSE_POINT` and checked; only disk and UNC roots, plain or
`\\?\`, are accepted; `\\.\`, `GLOBALROOT`, stream names and `.`/`..` under a
verbatim prefix are refused. A relative path is made absolute lexically, so a
current directory behind a junction is refused at that junction. Every
directory, the temporary file (`FILE_CREATE`) and the rename are relative to
the handle of the checked directory, so nothing is resolved by name between
the check and the rename. A directory renamed elsewhere after its check takes
the file with it; that needs rights on that directory and gains nothing. An
existing file is replaced as a directory entry: a link planted at the leaf
after the check is replaced, not followed; a directory there fails the rename
and the temporary file is removed through its handle. Side effects: F10.

**Registry security restore (smoke-run fix).**

- Impersonation (`reg_write.rs:479-552`): the process token is duplicated as
  an impersonation token, the privilege is enabled on the copy only, the copy
  is set on the current thread only. A thread that already impersonates is
  left alone. Every failure before `SetThreadToken` returns without
  impersonating; after it a drop guard reverts, also on unwind. The only code
  that runs while impersonating is one `NtSetSecurityObject` on the handle of
  a key this process created. Residue: F5. Elevated path not run: F4.
- The auto-inherit request bit makes the kernel keep the `AI` flag; nothing is
  recomputed from the parent and nothing reaches subkeys (test
  `set_security_keeps_auto_inherited_protected_and_inherited_aces` asserts the
  child is unchanged; it passed here).
- A crafted backup: the security write exists only on `CreatedKey`, the value
  `create_subkey` returns when the key was created new, below a parent the
  undo gate checked. It can never reach an existing key. The backup is read
  through the store's session handle and its size and SHA-256 are compared
  with the journal's reference before parsing (`read_verified`,
  `act_reg.rs:1622-1636`), then checked as the op's backup. To change it an
  attacker needs write access to the admin-only store and a matching journal
  chain. What the restore sets is what the capture read from the key that was
  deleted.

**Volume root rule.** Sound as decided. LOCAL SERVICE or NETWORK SERVICE as
owner can rewrite the root's DACL, then rename `.purge-q` away or plant
another. They cannot read or change what is inside (the store's own
descriptor still needs Administrators or SYSTEM, test at `integrity.rs:429`),
a planted directory is never adopted, and the result is lost undo data on that
volume, which those accounts could already cause as SYSTEM-equivalent. Boot-time
moves are not widened: `admin_only_ancestors` is not touched by the diff, so an
item on such a volume is held, not registered. Rename aside
(`storage.rs:1694`): the object is opened itself, never followed, relative to
the checked root handle, its file id is compared, and it is renamed relative to
the same handle, so a planted junction is moved as a junction. The new
directory is created new with its descriptor in the create call; a name taken
again in between refuses the volume. A standard user who holds a handle inside
their planted directory, or pre-creates the 64 aside names of a second, makes
the rename fail and the volume unavailable for that run: denial only, reported
as `CannotBackUp`.

**Boot pair on move back.** `listed_before_move_back` (`locked.rs:1470`) is
asked for a quarantine move with no `done` or a failed one. Listed once: the
pair is removed under the op's undo token before the move back. Listed more
than once or unreadable: a conflict that does not settle the op. With the call
removed, `a_move_back_never_settles_while_its_boot_move_is_listed` fails
(question 3). `Done.detail`: F11.

**Journalled selection.** Resume does not trust the list by itself.
`rebind_interrupted` (`plan_in.rs:437`) recomputes the plan hash from the scan
copy and compares it with the header; `rebind_selected` (`:512`) binds the ids
as a fresh run would (unknown, absorbed and unselectable ids are refused, plan
order is checked), requires the header's item count, requires the ids to hash
to the header's selection hash, and requires every journalled op to be that
item with that target. The trust is the header's, as before the round.

**Exit code 12.** F8. **check-deps rule 4.** Reads right: no dependent of
`purge-exec` in a default workspace tree, no `write` feature on `purge-win` in
the engine's own tree, and the release build command is recorded. Its test
builds three scratch workspaces under `%TEMP%` and removes them on drop.

## Final-review findings

| Finding | Status | Evidence |
|---|---|---|
| S1 undo into a re-created parent | closed; residue F1 | `act_fs.rs:1538`, `undo.rs:366`; fix reverted: 2 tests fail |
| S2 failed verify after retry | closed | `locked.rs:1345`; crash test passes |
| S3 names below a quarantined item | closed | `expiry.rs:1877`; `entries_with_reserved_or_odd_names_below_the_item_are_deleted` |
| S4 own-op window | closed | `gate.rs:2314`; fix reverted: 4 tests fail |
| S5 tree bound to root only | closed | same |
| S6 backup not bound, trailing backslash | closed; note F7 | `live.rs:862`, `act_reg.rs:710`; experiment |
| S7 `-o` through a junction | closed; note F10 | `nofollow.rs`; junction test passes |
| M1 undo order | closed | `undo.rs:344` (plain reverse order) |
| M2 resume after interrupted rollback | closed | `recover.rs:648-658`; crash test |
| M3 selection search | closed | `RunSettings.selected`, `plan_in.rs:512` |
| M4 byte-equal intents | closed | `locked.rs:943` (`same_action`) |
| M5 op directory before the intent | closed | `execute.rs:1385`, `storage.rs:675` |
| M6 reconcile without restart evidence | open | `locked.rs:1618` |
| M7 pair registered after a handle move | closed | `locked.rs:1293`, `:1470`; fix reverted: test fails |
| M8 reconcile move back not write-ahead | open | not changed |
| M9 second pending value | open | not changed |
| M10 undo plan replaced | closed | `undo.rs:999-1005` |
| M11 second read for the backup | closed | `act_reg.rs:611` (`value_backup`) |
| M12 package user | closed when the run names a user | `gate.rs:639`; a run without `user_sid` is as before |
| M13 last write times in recovery | open, recorded | DECISIONS 2026-11-16 |
| M14 writes into the quarantined directory | partly | count and budget; F9 |
| M15 interrupted undo and expiry | closed | `expiry.rs:722` |
| M16 reconcile records in expiry | closed | `expiry.rs:747` |
| M17 volume not attached | closed | `expiry.rs:893-926` |
| M18 retention from `created` | open | not changed |
| M19 loose state machine | open | not changed |
| M20 `sidecar_path` panic | closed | `output.rs:61` |
| M21 exit 0 with work left | partly | `exec`, `undo`, recovery, retry closed; purge open (F8) |
| M22 check-deps rule 4 | closed | `check_deps.rs:204` |
| M23 executor CLI not in `ci` | closed | `xtask/src/main.rs` (two steps), strings test in `exec_cli.rs` |
| M24 smaller points | partly | texts, read cap, report count, `item_fp` wording closed; subtree count is the direct subkeys only (`execute.rs:741`) |

## Question 2: what was reported open

None of these has to be fixed in code before the gate. All but M13 have to be
written into `docs/DECISIONS.md` first, because the gate would otherwise
measure behaviour that is known and not recorded.

| Item | For the gate | Why |
|---|---|---|
| `complete_key` and security differences (F3) | documented limit | The delete is never wrong; only the outcome class is. A difference needs a descriptor the elevated token cannot put back, and with `SeRestorePrivilege` there is none known. The fix is five lines and should follow. |
| M6 reconcile without restart evidence | documented limit, with a rule for the gate | It needs a registration that is not found on read-back; the VM test that registers and finds a real pair shows the ordinary case is confirmed. When it does happen the journal ends final and wrong (`NotMoved`, the item in quarantine after the restart, undo "nothing to undo"). The gate must treat any `confirmed: false` as a failed case to investigate, and case 3's malformed-list step as an expected limit or drop it. Fix before release: no `NotMoved` or `Lost` for an unconfirmed pair in the boot of its `done`. |
| M8 move back not write-ahead | documented limit | The state is safe; a crash in a window of one rename loses an alert. |
| M9 second pending value | documented limit | `MoveFileExW` does not write that value. |
| M18 retention from `created` | documented limit | Nothing is purged without consent; a late retry is due earlier than its own age. |
| M19 loose state machine | documented limit | Reached only by a crafted journal or a driver bug. `journal retry-held` is now a CLI verb, but it refuses a session with pending recovery, and an op whose undo settled cannot be retried. Add the new records to `sample_journal` later. |
| M14 residue (F9) | documented limit for the gate; close before release | Needs write access to the directory from before the move, 30 days and two purge runs, and deletes only what the user could already move. Record it in DECISIONS, not only in `expiry.rs`. |
| M24 subtree count | documented limit | It only decides whether a restore point is asked for. The validate pass now reads the whole tree, so the exact count is one field away. |
| M13 | acceptable, already recorded | Consistent with the content binding, which accepts the same content. |

## Question 3: do the new tests fail without the fix

Three fixes were reverted locally, the tests run, and the files restored
(`git status` clean afterwards).

| Fix reverted | Tests that then fail |
|---|---|
| S1: `recreate_dir` returns `AlreadyRestored` for any plain directory | `act_fs::tests::an_existing_directory_counts_as_restored_only_with_the_recorded_owner_and_dacl`; `roundtrip::nothing_is_restored_into_a_directory_somebody_else_created_again` |
| S4/S5: `prepare_reg` ignores `bind_tree`'s refusal | `act_reg::tests::a_change_by_someone_else_before_an_own_op_on_the_key_is_refused`, `a_change_below_the_root_after_validation_is_refused`, `a_key_after_its_own_value_items_is_still_refused_after_outside_changes`, `a_tree_after_items_inside_it_is_still_refused_after_outside_changes` |
| M7: the undo driver ignores `listed_before_move_back` | `execute::tests::a_move_back_never_settles_while_its_boot_move_is_listed` |

All other tests of the library passed with the three reverts in place (416 of
422), so each test fails for its own fix.

What the new tests do not cover:

- The owner branch of `existing_dir` is tested by changing the recorded SDDL,
  not by a directory owned by another account (needs a second user: gate
  case 2).
- No test puts back a `SubkeyDeleted` or a `ValueRewritten` effect together
  with an outside change elsewhere in the same tree; the two S4 tests use a
  deleted value. The put-back of the other two kinds is covered only by the
  older same-run tests, where nothing outside changes.
- The M14 fixture computes `tree_entries` itself (`expiry/tests.rs:226`); that
  the gate's count and `count_below` agree is shown by reading only (both
  count every listed entry and enter plain directories).
- The elevated owner restore (F4).

## Not checked

- Anything elevated: `SeRestorePrivilege`, a SYSTEM or TrustedInstaller owner,
  a directory owned by another account, the strict store policy.
- WOW64 views and shared keys under `Classes`: an own op and a tree that reach
  the same key through two views would not be matched by `relative_path`; by
  reading that ends in a refusal, not in a delete.
- Whether `upcase_unit` (Rust's Unicode upper case) and the kernel fold names
  alike. A difference refuses a key or a put-back; it cannot widen a delete.
- The rename with a root handle on FAT, exFAT, ReFS and network shares.
- Where `settings.user_sid` comes from in the CLI, and so whether a run can
  reach the package removal without naming a user.
- `tests/exec_cli.rs`, `xtask ci`, `check-deps` on the real tree: read, not
  run. The test files were read only where a test is named in this report.
- `vm/` (out of scope), including whether the rig's fixtures still match the
  new skip reasons and exit code 12.
- Everything in the final review's "not checked" list that needs a VM.

## Clean-up

The worktree holds no change but this file. Three source files were edited
for question 3 and one test file for F7; all four were restored with
`git checkout`. Build output is under `E:\purge-build\review4`. No
`PurgeTest-*` key is left under `HKCU\Software`, and a listing of `%TEMP%`
before and after the runs differs only by files of other programs.
