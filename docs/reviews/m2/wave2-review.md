# M2 wave 2 review

Reviewed at `877a3e3` ("M2 integration: wave 2 (purge-exec) on the reviewed wave 1 APIs").
Reviewer changed no source code.

## Verdict

**Accept with required changes.**

No blocking finding. Nothing found lets a standard user redirect a write, and
no path was found where the store, the journal or the gate acts on an object
other than the one it checked, as long as the caller uses the handles it is
given.

Seven serious findings (S1 to S7). Each of them is a place where the wave 2
parts do not fit together, or where a result says more than is true. The
packages now being written on top (file actions, registry actions, execute,
undo, recovery) will hit every one of them. S1, S2 and S3 must be fixed before
those packages are merged; S4 to S7 must be fixed or explicitly decided before
the M2 gate.

Evidence labels used below:

- **experiment**: confirmed by a small program run against this commit
  (Windows 11 build 26300, unelevated, medium integrity).
- **reading**: confirmed by reading the code; no run.
- **suspected**: not confirmed.

## Reviewed

- `crates/purge-exec/src/storage.rs`, `storage/integrity.rs`, `storage/cap.rs`, `storage/sys.rs`
- `crates/purge-exec/src/journal.rs`, `journal/frame.rs`, `hash.rs`, `reader.rs`, `state.rs`, `writer.rs`
- `crates/purge-exec/src/regbackup.rs`, `regfile.rs`
- `crates/purge-exec/src/gate.rs`, `gate/ffi.rs`
- `crates/purge-exec/src/fault.rs`
- The review-fix commits `8d08368..7782c05` (model `ec89923`, win `0b0cfb1`,
  guard `7782c05`, and `28691a2`), against `docs/reviews/m2/wave1-review.md`:
  `purge-guard/src/live.rs`, `purge-win/src/fs_write.rs`, `purge-win/src/reg_write.rs`,
  `purge-model/src/exec/*`.

Tests: `cargo test -p purge-exec --lib -- --skip act_typed --skip prepare`
gives 103 passed, 0 failed, 2 ignored (strict-policy install tree needs
elevation; second-volume quarantine needs the VM).

Out of scope and not reviewed: `prepare.rs`, `act_typed.rs`, and the stubs
`act_fs`, `act_reg`, `locked`, `execute`, `undo`, `recover`, `expiry`,
`plan_in`, `report`.

## Blocking

None.

## Serious

### S1. The journal and the registry backups are created and opened outside the store's checks

Files:
`journal/writer.rs:101-122` (`JournalWriter::create` takes a path and an SDDL string and creates the file itself),
`journal/reader.rs:96-131` (`open_plain` by path),
`journal/hash.rs` (`verify_backup(session_dir, &BackupRef)` joins a path and opens it),
`regbackup.rs:939-976` (`write_verified` calls `create_file_secure(session_dir.join(rel))`, and on failure `remove_file` by path),
`regbackup.rs:904-930` (`read_file` uses `File::open`),
`storage.rs:1135-1145` (`SessionDir::create_file` returns an already created `File`),
`storage.rs:1149-1157` (`SessionDir::open_file` checks a handle, drops it, and returns a `PathBuf`).

What is wrong: the store checks every directory per use (owner, protected
DACL, no reparse point, final path) and hands out checked handles. The two
consumers that matter most do not take those handles. `JournalWriter::create`
and `regbackup::write_verified` cannot accept the `File` that
`SessionDir::create_file` returns, so a caller must pass
`session_dir.path().join(...)` and let them open by path again. There is no
public call that creates the checked `reg` directory without also creating a
file in it. `regbackup::read_file` uses `File::open`, which follows a reparse
point at the last component and does not look at the link count.
`SessionDir::open_file` does the right checks and then throws the handle away.

Evidence: reading.

Scenario: the store check passes at time T1. The execute package then calls
`JournalWriter::create(session.path().join("journal.jsonl"), sddl)` at T2.
Everything between `<data root>` and the file is re-resolved by name with no
check. Under the strict policy only an administrator can change those
directories, so this is not a privilege boundary today. It is still the exact
pattern (check one open, act on another) that wave 1 B1 removed from the file
moves, and under the relaxed test policy, or after any future loosening of the
store ACL, it is directly exploitable. It also means the integrity check of
the store gives no guarantee for the two file kinds whose integrity undo
depends on.

Smallest fix: make the store the only creator and opener.
`JournalWriter::create` and `open_append` take a `File` (from
`SessionDir::create_file` / a new `SessionDir::open_file_handle`);
`write_verified` and `read_verified` take a `&SessionDir` plus a relative
name and go through it; `SessionDir::open_file` returns the checked `File`;
`read_file` opens with `FILE_FLAG_OPEN_REPARSE_POINT` and refuses
`n_links != 1`. Delete the by-path variants so the wrong call cannot be made.

### S2. An interrupted tree delete can be left half deleted, with the result saying the rollback is complete

Files: `regbackup.rs:1773-1892` (`delete_walk`), `1896-1928` (`put_back`),
`1973` (`finish_delete_tree`), `1675-1727` (`complete_tree`), `1529-1558` (`restore_tree`).

What is wrong: `put_back` restores only the keys that were deleted in the
current call. When a delete is resumed after a crash and the first thing the
walk meets is a changed key, nothing has been deleted in this call, so the
result is `Rollback::NotNeeded` and `rollback.is_complete()` is `true`. The
keys deleted before the crash stay missing. `complete_tree` then refuses
(`Conflict(Diverged)`), and `restore_tree` refuses (`Conflict(KeyNotEmpty)`).
There is no call that finishes the delete and no call that puts the missing
part back.

Evidence: experiment. Tree `T{A{A1}, B}`, backup written and verified. First
run deleted `A1` and `A` (simulated crash). Then `B`'s value was changed.

```
finish_delete_tree: Err(DeleteError { at: "B", failure: Changed(ValuesDiffer), rollback: NotNeeded })
rollback.is_complete() = true
probe_tree:    Ok(Diverged { at: "B", change: ValuesDiffer })
complete_tree: Err(Conflict(Diverged { at: "B", change: ValuesDiffer }))
restore_tree:  Err(Conflict(KeyNotEmpty))
A1 exists:     Err(Win32Error(2))
```

The outcome depends on walk order. In the other order (only `A1` deleted
before the crash, so `A` is deleted in the resume call before `B` is met) the
same input gives `rollback: Done { keys: 2 }` and `A\A1` is back. So the same
function returns "complete" for two different end states.

The existing test `an_interrupted_delete_is_completed_or_finished` asserts
`!root.exists("T\\A\\A1")` in its last section, that is, it asserts the half
deleted state as the expected result.

Scenario: recovery after a crash in a registry tree delete, the application
(or the user) has written one value under the tree in the meantime. Recovery
reports the item as "changed, rolled back", the journal can record a clean
outcome, and the machine is left with a tree that matches neither the state
before nor the state after. The data is still in the backup file, but no
engine function will apply it.

Smallest fix: (1) `Rollback::NotNeeded` must mean "the tree equals the
backup". On a refusal in a resume call, compare the whole tree to the backup;
if keys are missing, return a distinct `Rollback::PartialBefore { missing }`
whose `is_complete()` is `false`. (2) Add a merge that restores only the
missing keys (never touching an existing key), so recovery can return the tree
to "backup plus the foreign change". `merge_into_empty` already has most of
the logic. (3) Change the test to assert the repaired state.

### S3. regbackup resolves key paths with its own mapping, without the alias handling the gate uses

Files: `regbackup.rs:561-579` (`native_path`), `584` (`open_key_path`),
`592` (`open_parent`); gate side `gate.rs:1241` (`open_addr`),
`purge-guard/src/live.rs:692-882` (`KeyAddress`, `key_probe`).

What is wrong: the gate canonicalises registry aliases (`CurrentControlSet`,
`HKU\<sid>\Software\Classes`) and opens by `KeyAddress`. `regbackup` has a
second, simpler mapping through `TypedTarget::parse_key_path` that does not.
The two disagree for every aliased spelling. In addition `open_parent` returns
the link key itself as the "parent" when the parent component is a link.

Evidence: experiment.

```
open_key_path HKLM\SYSTEM\CurrentControlSet\Control: Err(1921)
open_parent   HKLM\SYSTEM\CurrentControlSet\Control: Ok((is_link = true, "Control"))
open_key_path HKU\<sid>\Software\Classes\.txt:       Err(1921)
open_parent   HKU\<sid>\Software\Classes\.txt:       Ok((is_link = true, ".txt"))
open_key_path HKLM\SYSTEM\ControlSet001\Control:     Ok
open_key_path HKU\<sid>_Classes\.txt:                Ok
```

Scenario: a plan item spelled `HKLM\SYSTEM\CurrentControlSet\Services\Foo`
(purge-plan emits canonical spellings, but `plan from-targets` on the rig and
any plan read from disk need not). The gate resolves it and allows it; the
delete goes through the gate's checked handle. The backup records the
spelling from the plan. Undo and crash recovery call
`open_parent(backup.key)`, get error 1921 or a link key, and fail closed. The
delete cannot be undone by the engine. Fail-closed is the right direction,
but the item should never have been accepted in a form that undo cannot open.

Smallest fix: one mapping. Remove `native_path`/`open_key_path`/`open_parent`
from `regbackup`'s public surface, or implement them on `KeyAddress`. Record
the canonical address (the one the gate opened) in the backup document, not
the plan spelling. `open_parent` must refuse a parent that `is_link()`.

### S4. Undo of a registry operation checks one open and acts on another

Files: `gate.rs:1561-1572` (`check_undo_key` returns `Result<(), Refusal>`),
`regbackup.rs:1529` (`restore_tree(parent: &WKey, ...)`), `592` (`open_parent`).

What is wrong: for files the gate returns a handle-bearing type
(`CheckedPath`, `CheckedDest`) and the action can only be done through it.
For registry undo the gate returns `()`. The undo package must open the
parent key itself, by path, after the check, with the mapping from S3.

Evidence: reading.

Scenario: `check_undo_key` allows `HKLM\SOFTWARE\Vendor\App` at T1. At T2 the
undo code calls `open_parent(...)` and `restore_tree`. A key on the path
replaced between T1 and T2 (HKCU is user writable; a per-user link can be
created without elevation) is not seen by the check. The `WKey` component-wise
open with `REG_OPTION_OPEN_LINK` refuses links, which limits this to "wrong
key that is not a link", but the gate's verdict then no longer covers the
object written to.

Smallest fix: `check_undo_key` returns a `CheckedKeyParent { parent: WKey, leaf }`
opened by `open_addr`, and `restore_tree`/`merge_into_empty`/`complete_tree`
take that type instead of a bare `&WKey`.

### S5. The act-time gate takes the stamp and the exemptions from the caller, and key operations are not bound to what was validated

Files: `gate.rs:890-947` (`open_and_check_path(ctx, item, stamp: &PathStamp)`),
`1536-1556` (`open_and_check_key`, uses `Binding::Capture`),
`1390-1450` (`gate_key`).

What is wrong, two parts:

1. `open_and_check_path` receives the stamp, and the exemption set, as
   arguments. It does not look them up in `ctx.validated` by item id. Nothing
   forces the act-time exemptions to be the ones that were journalled (wave 1
   S4 fixed the format; the use is not enforced).
2. For keys the act-time check runs with `Binding::Capture`, not
   `Binding::Recheck`. The `RegFacts` taken at validation (subkey count, value
   count, last write time) are not compared at act time.

Evidence: reading.

Scenario for 1: the execute package passes a default or widened exemption set
at act time by mistake. The gate allows a path that validation refused, and
the journal still shows the narrower set. No test can catch it at the gate
level because the gate has no way to know.

Scenario for 2: a key is validated as "leaf key, 2 values". Before the act
another installer creates 30 subkeys under it. The act-time gate allows it
unchanged. `capture_tree` then either backs up and deletes the larger tree
(up to the 50 key limit) or fails on the limit. The user confirmed a
different object from the one deleted. For files the same change is caught by
the stamp.

Smallest fix: `open_and_check_path(ctx, item_id)` and
`open_and_check_key(ctx, item_id)`: look up the stamp and exemptions in
`ctx.validated`, refuse an unknown id. Use `Binding::Recheck` for keys and
compare last write time and counts; a mismatch is `Refusal::Changed`.

### S6. A recorded boot-move pair can be lost in a crash, because `done` is not flushed

Files: `journal/writer.rs:250-263` (`done`), `232-245` (`intent`, flushes),
`327-345` (`commit`).

What is wrong: an intent record is flushed before its token is returned. A
done record is written but not flushed until the next intent, the end of the
group, or commit. That is a deliberate saving, and for most outcomes it is
safe: a missing done after a flushed intent is exactly the "intent without
done" case recovery handles. It is not safe for
`Outcome::PendingReboot { pair, confirmed }`. The pair is the only record of
what was put in `PendingFileRenameOperations`.

Evidence: reading.

Scenario: last item of a run is a locked file. The ladder registers a boot
move, the writer appends `done(PendingReboot{pair})`, the process is killed or
the machine loses power before the next flush. After reboot the journal shows
an intent with no done; the move has been carried out by the session manager.
Recovery has no pair to match against the boot-move chain and cannot tell
"registered and executed" from "never registered". This is wave 1 S5 again,
inside that window.

Smallest fix: flush on `done` when the outcome is `PendingReboot` (or flush
every done whose outcome is not reconstructible from the disk state). Better:
write the pair in the intent record, before the registry write, so the
existing flush-before-token rule covers it. Add a fault point
`bootmove.registered` hit between the registry write and the done record, and
a test that crashes there.

### S7. `resume_intent` hands out a token on every call, and the state machine allows undo after expiry

Files: `journal/writer.rs:289-299` (`resume_intent(&self)`),
`journal/state.rs:430-610` (`apply`).

What is wrong:

1. `resume_intent` takes `&self` and returns an `IntentToken` each time it is
   called, also on a writer that was created fresh and never had an open
   intent to resume. The token is the proof "an intent for this op is on
   disk". Two tokens for one op means two `done` calls can be attempted; the
   second is refused by the state only because the first got there, so
   recovery code that takes two tokens and uses the wrong one first records
   the wrong outcome.
2. `apply` accepts `undo_intent` for an op whose session has an `expire`
   record. After expiry the quarantined files are gone.

Evidence: reading.

Scenario for 2: expiry runs and records `expire`; the UI still lists the
session; the user clicks undo. The journal accepts the undo intent, the undo
package looks for the quarantine directory, finds nothing, and has to record
a failed undo for every op. The state machine is the place that knows the
session is expired and it is silent.

Smallest fix: `resume_intent(&mut self)` returns `Option<IntentToken>`, `Some`
only if the opened journal ends in an open intent, and only once.
`apply` refuses `undo_intent` when `expired` is set, with a named rule.

## Minor

### M1. A standard user can block index reads and writes by holding `index.json` open

Files: `storage.rs:885-903` (`read_index_in`), `905-957` (`write_index_with`),
`1046-1062` (`replace_file`).

Users have read access to the index by design. A reader that opens it with
share-read only makes `write_index` fail after the retries (about 1.4 s) with
access denied; a reader with no sharing makes `read_index` fail "in use".

Evidence: experiment.

Scenario: any backup or indexing tool, or a hostile unprivileged process,
keeps the index open; every run fails at the cap check or at the summary
write. Denial of service only; nothing is written to the wrong place.

Fix: decide which operations may proceed without the index (the cap can be
recomputed from the session directories) and say so in the error. Do not let
an unreadable index stop an undo. `replace_file` should also rename through
the checked directory handle (`rename_into`), not `std::fs::rename` by path.

### M2. A rejected index is renamed aside and the next read is an empty index

Files: `storage.rs:1000-1027` (`rename_aside`), `885-903`.

Evidence: experiment (index with a second hard link, which only an
administrator can create; a read-only user cannot, see "Checked").
First `read_index` fails and renames the file aside, the second returns
`sessions: []`.

Scenario: after one integrity failure the cap accounting starts from zero
although the quarantine directories are still full, and the session history
shown to the user is empty. Sessions remain on disk and undoable only if the
caller enumerates directories.

Fix: after a rename-aside, rebuild the index from `sessions\*\journal.jsonl`
before returning, or return a distinct `IndexLost` so the caller must rebuild.
The cap must be computed from the directories, not from the index, in that
state.

### M3. Directories are opened by path a second time in three places

Files: `storage.rs:1000-1027` (`rename_aside` opens the parent `DestDir` by
path), `gate.rs:1082-1101` (`check_quarantine_destination` opens its own
`DestDir` by path and does not compare its file id with the store's
`QuarantineDir`), `storage.rs:859-883` (`volume_quarantine` calls `inspect`
with `parent_final` = `None`, so `X:\.purge-q` and the data root get no
final-path check).

Evidence: reading.

Scenario: the gate approves directory D1 as quarantine destination; the move
is done into the store's handle for D2. They are the same directory unless
something changed in between; nothing checks that they are.

Fix: pass the store's handle to the gate and compare volume serial and file
id; give `rename_aside` the checked parent handle; pass the volume root's
final path to `inspect` for `.purge-q`.

### M4. Volume-root quarantine: root DACL and mounted folders

Files: `storage.rs:859-883`, `1171-1240` (`create_op_dir`).

`X:\.purge-q` is checked, `X:\` is not. On a data volume where users have
`FILE_DELETE_CHILD` on the root (common on removable and exFAT-converted
volumes, and on NTFS data volumes with inherited Modify for Users) a user can
rename `.purge-q` away and create another in its place; the store then
rejects it and renames it aside, so the effect is loss of the quarantined
data for undo, not redirection. Separately, a volume mounted at a folder gets
a `.purge-q` although `StoreScope` refuses such volumes.

Evidence: reading; not run (needs a second volume).

Fix: refuse to create `.purge-q` when the root grants delete-child to anyone
but administrators and SYSTEM; fall back to "cannot quarantine on this
volume". Refuse mounted-folder volumes in the store as the scope does.

### M5. Unbounded memory from on-disk and registry data

Files: `regbackup.rs` `capture_tree` (key-count limit only; no limit on value
count or bytes; `MAX_BACKUP_FILE_BYTES` 256 MiB is applied at read-back, after
the delete), `journal/reader.rs` (`read` uses `read_to_end` with no cap),
`gate.rs:614-676` (`walk_tree`: `list_dir` returns the whole listing before
the item cap is tested), `storage.rs` (`MAX_INDEX_BYTES` 64 MiB is fine).

Evidence: reading.

Scenario: a key with 50 subkeys each holding large binary values is captured
(several copies in memory through serialise, write, read back, parse), the
backup file is written above 256 MiB, the delete proceeds, and
`read_verified` at undo refuses the file as too large. The delete is then not
undoable.

Fix: a byte budget in `capture_tree`, tested during capture, equal to or below
the read-back limit, refusing before anything is deleted. A size cap on the
journal read. Enumerate directories with a cap.

### M6. Fault points missing where the design names them

Files: `fault.rs`, `regbackup.rs:1198-1231` (`restore_subtree`), `939-976`.

`regrestore.mid` is declared and never hit; the restore engine is in this
wave. `write_verified` has no `backup.written` / `backup.verified` point (they
are hit in `act_typed.rs` around the call, so the window between write and
verify inside the function is not testable). The test
`a_crash_at_each_journal_point...` does not include `undo.intent`.

Evidence: reading (grep for every declared point).

Fix: hit `regrestore.mid` after the first restored key; add the two backup
points inside `write_verified`; add `undo.intent` to the test's list or
rename the test.

### M7. Journal reader does not tie the file to its directory, and a cut at a line boundary is not detectable

Files: `journal/reader.rs`, `journal/frame.rs`.

The header's `session` is not compared with the directory name. The hash
chain detects edits and reordering but not removal of whole trailing lines;
this is documented, and the head hash is stored nowhere else.

Evidence: reading.

Scenario: a journal copied from one session directory to another is read as
that session. Removal of the last `done` lines turns completed ops into open
intents; recovery then inspects the disk and mostly reaches the right answer,
but an undone op can come back as "done, undoable".

Fix: compare header session with the directory name in `read`. Store the head
hash and record count in the index summary at commit and compare on read.

### M8. Segment edits split on `;` inside quotes

File: `regbackup.rs:2138` (`List::parse`).

A `PATH`-style value with a quoted element containing `;` is split in the
middle. `plan_segment_removal` then compares fragments.

Evidence: reading.

Scenario: `"C:\Tools;Old\bin";C:\App\bin`: removal of `C:\App\bin` still
works, and the write-back is the exact original minus the segment, so no
corruption was found; but a target segment that itself needs quotes is never
matched, and the edit reports "not present".

Fix: honour quotes when splitting, or refuse values containing `"`.

### M9. Smaller points

- `regbackup.rs:1561-1665` `merge_into_empty`: when the root key already
  exists its volatility is kept; a backup of a non-volatile root restored into
  an existing volatile root is reported as success. Compare and refuse.
  (reading)
- `purge-win/src/reg_write.rs` `security_sddl`: owner, group and DACL only. A
  key with a mandatory label or SACL is restored without it. Wave 1 M2
  residue. (reading)
- `purge-win/src/fs_write.rs:377-399` `rename_into` accepts leaf names `NUL`,
  and names with trailing dot or space. Deliberate (targets may have such
  names), but a quarantine leaf must never be one; the store should generate
  the leaf and not take it from the target. (reading)
- `journal/writer.rs:495-504` `append` applies the record to the in-memory
  state before the write. A failed write leaves the state ahead of the file.
  The writer should be poisoned after any write error. (reading)
- `storage.rs:1116-1129` `parent_of` and `child_dir` rebuild paths with
  string joins; correct for the inputs they get today, not checked for `..`.
  `is_session_relative` in the model covers the journal side. (reading)

## Wave 1 findings

| Id | Status | Evidence |
|----|--------|----------|
| B1 rename to a path, not a checked handle | closed | `rename_to` removed; `MoveHandle::rename_into(dest_dir, leaf)` only (`fs_write.rs:377-399`), `DestDir` (`584-644`), gate returns `CheckedDest`. Residue: M3 above (gate and store each open the directory). |
| S1 WOW64 view not in the key address | closed in guard and gate | `KeyAddress` carries the view flag (`live.rs:692-882`); `open_addr` (`gate.rs:1241`). Not carried into regbackup: see S3. |
| S2 store scope supplied by caller | closed | `StoreScope::new` derives the directories from data root and session id, fields private (`live.rs:1134-1176`). |
| S3 volatile keys | closed | `KeyNode.volatile`; compare and restore use it; test `a_tree_with_volatile_keys_round_trips` passes. Residue: M9 first point. |
| S4 exemptions not journalled | partly | Format closed (`Validated.exemptions`, `exemptions_to_journal`/`from_journal`). Use at act time not enforced: S5. |
| S5 boot-move pair not recorded | partly | Format closed (`PendingReboot { pair, confirmed }`). Flush window: S6. |
| S6 inverse not tied to the op | closed | `undoes` (`op.rs:567-600`) checks pre kind and file id; `MoveBack.quarantine_path` is left to `open_op_dir`, which checks it. |
| S7 file creation follows a reparse point | closed | `create_file_secure` opens with `FILE_FLAG_OPEN_REPARSE_POINT` (`fs_write.rs:773-797`). Not used by all readers: S1. |
| S8 in-use directory reported as denied | closed | `FsError::DirInUseOrDenied`; `may_be_in_use` (`gate.rs:993`). |
| M1 | closed | As in the fix commit. |
| M2 backup document validation | partly | Links, duplicates, NUL refused; `validate_for` (`regbackup.rs:570-606` in model). SACL / mandatory label still not captured (M9). |
| M3 stream syntax and odd leaf names | partly | Stream syntax refused. `NUL` and trailing dot/space leaves still accepted on purpose (M9). |
| M4 | closed (decided) | Documented decision. |
| M5 serial 0 and purge dirs | closed | `FileIdentity::is_valid` (`live.rs:283`), `purge_dirs_known` (`296`). |
| M6 delete of a non-empty key | closed, with a documented window | `delete_if_empty` (`reg_write.rs:761`) for keys without values; `delete()` still used for keys with values, after compare. |
| M7 | open (documented only) | No code change. |
| M8 | partly | Some of the clean-up done. |

## Notes for the packages being written on top

File actions:

- Do not open the target, the quarantine directory, or anything in the
  session directory by path. Use `CheckedPath`, `CheckedDest` and the store's
  handles only. If an API forces a path on you, that is S1 or M3; do not work
  around it with a join.
- Do not assume the gate's destination and the store's op directory are the
  same object (M3). Compare file ids until the gate takes the store's handle.
- Do not pass your own stamp or exemption set to the act-time gate (S5). Take
  both from `ctx.validated` for the item id.
- Do not take a quarantine leaf name from the target name.
- Do not assume `.purge-q` on a second volume is safe because it passed
  `inspect` (M4).

Registry actions:

- Do not assume a key that passed the act-time gate is the tree that was
  validated (S5 part 2). Compare counts and last write time yourself until the
  gate does.
- Do not use `regbackup::open_key_path` or `open_parent` for anything the gate
  resolved (S3). Use the handle from the gate. Record the canonical address in
  the backup.
- Do not assume a backup that was written can be read back: test the size
  against `MAX_BACKUP_FILE_BYTES` before deleting anything (M5).
- Do not treat `DeleteError.rollback.is_complete()` as "the tree is as it
  was" (S2). After any refusal run `probe_tree` and record what it says.

Locked-file ladder:

- Do not rely on the `done` record to carry the boot-move pair across a crash
  (S6). Flush explicitly after it, or put the pair in the intent.
- Do not assume `DirInUseOrDenied` means in use; the gate's `may_be_in_use`
  is a hint.

Execute pipeline:

- Do not let an unreadable index stop the run or the undo (M1), and do not
  trust an empty index for the cap (M2).
- Do not call `JournalWriter::create` with a path you joined yourself once S1
  is fixed; until then, call it immediately after `open_session` with no
  other work in between, and record that as a known gap.
- After any journal write error stop; do not keep using the writer (M9).

Undo and recovery:

- Do not call `resume_intent` more than once per op, and check that the
  journal really ends in an open intent first (S7).
- Do not start an undo on a session with an `expire` record; the state
  machine will not stop you (S7).
- Do not assume `check_undo_key` protects the key you then open (S4).
- Do not assume `finish_delete_tree` followed by `complete_tree` or
  `restore_tree` always reaches one of the two clean states (S2). There is a
  third state and today no call leaves it.
- Do not assume the journal in a session directory belongs to that session
  (M7), or that its last line is the last line that was written.
- A missing `done` after an intent for a boot move does not mean the move was
  not registered (S6). Read `PendingFileRenameOperations` and, after a
  reboot, the disk.

## Checked and found sound

- Hard-link attack on the index: a user with read access only cannot create a
  hard link to `index.json`. `CreateHardLinkW` gives access denied and native
  `NtSetInformationFile(FileLinkInformation)` on a read handle gives
  `0xC0000022`. (experiment)
- Journal framing and parsing: no panic on any truncation point or single bit
  flip (existing sweep tests); torn tail is ignored on read and cut by
  `open_append`; a second writer is excluded by share mode.
- `rename_into`: refuses a destination handle that is not a directory or is a
  reparse point; uses the handle as `RootDirectory`.
- `create_file_secure`: create-new, no follow.
- Cap arithmetic: saturating and `u128`; no overflow path found.
- Guard verdict functions (`check_path`, `check_key`, `check_store_item`,
  `check_quarantine_destination`, `check_undo_path`, `check_undo_key`): pure,
  no I/O, serial 0 refused.
- `delete_walk`: compares each key with the backup before deleting it,
  post-order, refuses links.
- `.reg` generator (`regfile.rs`): escaping and hex wrapping checked by
  reading; no fault found.
- `Rollback::Done` path: after a refusal part-way through one call, the keys
  deleted in that call are put back. (experiment)

## Not checked

- Anything that needs elevation: the strict store policy on a real install
  tree, HKLM deletes and restores, SACL behaviour.
- Anything that needs a second volume or a mounted folder (M4 is by reading).
- Behaviour on ReFS, exFAT and network paths.
- The test modules were not read line by line; only the tests named above.
- `prepare.rs`, `act_typed.rs` and the stubs.

## Clean-up

The experiments used a scratch crate outside the repository and a temporary
key under `HKCU\Software\PurgeReview2-*`, which was deleted (verified with
`reg query`: no match). No file in the repository other than this report was
changed. Build output is in `E:\purge-build\review2`.
