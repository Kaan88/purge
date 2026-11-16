# M2 adoption rule review

Reviewed the adoption rule of `0aa3633` ("M2 fix-round review follow-ups") on
local branch `m2`, and nothing else of that commit: the parent record of a
quarantine move and the check on the move back (`act_fs.rs`), and the merge
into an existing empty key (`regbackup.rs`). Reviewer changed no source code
and did not delegate.

## Verdict

**Fine for the gate.** No blocking finding. One serious finding (S1) that
should be fixed before a release; it does not affect what the gate measures.

The rule itself holds: what a standard user can do to a directory or key comes
from its DACL and from owning it, and both are pinned. No way was found for a
standard user to make a directory or key that passes the owner and DACL test
and gives them more control than the original gave. The one path that skips
that test is the file-id shortcut (S1).

Evidence labels: **experiment** (Windows 11 build 26300, NTFS, unelevated),
**reading**.

Tests run: `cargo test -p purge-exec --features fault-inject,test-support
--lib -- a_move_back_goes_only an_empty_key_with_another_dacl
nested_delete_child_then_empty_parent`: 3 passed. The rest of the suite was not
run.

## Blocking

None.

## Serious

### S1. The "same directory" shortcut trusts the file id alone, and NTFS hands a file id out again

`crates/purge-exec/src/act_fs.rs:1375-1381`.

Defect: when the directory at the original place has the recorded file id, the
item is moved back with no look at owner or DACL. On NTFS the id is a 48-bit
record number plus a 16-bit sequence number. A freed record is given to the
next new file or directory with the sequence raised by one, so the same id
comes round after 65,535 reuses of that record. `ParentDir` holds no volume
serial; the volume is bound only through the gate's check of the destination.

Scenario: the recorded parent is gone (this session's `RemoveDirIfEmpty`, or
anything else) and stands below a directory where standard users may create
directories (`C:\`, `C:\ProgramData`, a user profile). A standard user creates
and deletes a directory in a loop until the freed record comes back with the
recorded sequence, then creates the directory at the original path. It has the
recorded id, the user's owner and a DACL of the user's choice. The undo moves
the quarantined executable into it. This is the F1 case the rule was written
to close.

Experiment: an unelevated create-and-delete loop on this host got the record
of its first directory back at once, with the sequence one higher each round.
In four runs of 200,000 rounds (about 21 s each) it advanced that one record
by 37,598, 9,700, 15,868 and 39,043 before another process took the record. A
full wrap of 65,535 was not reached; the host was busy with other builds. So
the id is not unique over time and an unelevated process drives the reuse, but
the complete attack was not reproduced. Whether the undo of the file still
runs after the `RecreateDir` of the same directory ended in a conflict was not
checked.

Smallest fix: on the same-id branch still require the owner test (recorded
owner, or one of the three admin-only owners). A recycled directory made by a
standard user has that user as owner and cannot be given away. The DACL of a
directory with the recorded id and an acceptable owner can stay unchecked, as
now.

Confirmed by: reading, and the experiment for the reuse mechanism.

## Minor

### M1. `parent_differs` lets the item go back when the original path has no parent

`crates/purge-exec/src/act_fs.rs:1383`. `Path::new(original).parent()?` returns
`None`, and `None` means "may go back". Not reachable today: `parent_missing`
and the gate run before it and need a parent. It is the wrong default for a
check.

Smallest fix: return the `unreadable` failure there.

Confirmed by: reading.

### M2. A directory Purge itself recreated is refused when the token's default owner is the user account

`crates/purge-exec/src/act_fs.rs:1349-1356`, `1784-1792`. When `RecreateDir`
cannot assign the recorded owner, the directory gets the token's default owner.
The exception accepts Administrators, SYSTEM and TrustedInstaller. An elevated
token whose default owner is the administrator's own account (UAC off, or the
policy that makes the creator the owner) leaves an owner outside that list, and
the files of that directory then end in `Conflict(DestinationExists)`. It fails
safe. Not run; this host's elevated default owner was not examined.

Smallest fix: in the fallback set the owner to Administrators explicitly
instead of leaving the default, or record the limit.

Confirmed by: reading.

### M3. The rule looks at the directory, not at what is in it

`crates/purge-exec/src/act_fs.rs:1396-1414`. A directory with another id, an
admin-only owner and the recorded DACL is accepted with whatever it holds. A
standard user cannot fill such a directory unless the recorded DACL let them,
so this adds nothing they did not have. A service that creates such a directory
and copies user-supplied files into it would. No such case was found; it
belongs with the known limits in `docs/DECISIONS.md`.

Confirmed by: reading.

### M4. Tests cover the DACL half only

`crates/purge-exec/src/act_fs/tests.rs` (`a_move_back_goes_only_into_a_parent_
with_the_recorded_owner_and_dacl`), `regbackup.rs`
(`an_empty_key_with_another_dacl_is_not_merged_into`). Both change the DACL. No
test has another owner with the recorded DACL, the admin-only owner passing in
place of the recorded one, a same-id directory, an intent without `parent`, or
a resume whose prepared parent differs from the journalled one. An unelevated
test cannot make another owner; these belong on the gate VM.

Confirmed by: reading.

## Answers to the questions

- **SDDL compared as text.** Both strings come from the same conversion on the
  same machine, so an equal ACL gives an equal string. Another ACE order,
  another inheritance flag (`ID`, `AI`, `P`) or another spelling is a
  difference, which is a refusal: the compare errs towards conflict. The part
  splitter (`sddl_part`, `act_fs.rs:1663-1683`) counts parentheses and does not
  know quoted text in a conditional ACE; an ACE written to confuse it still
  adds its own text to the DACL part before any false end, so it cannot make
  two different DACLs compare equal. Reading only.
- **Inherited ACEs from a user-controlled grandparent.** Equal text means the
  same ACEs with the same inherited flags today. A user who controls the
  grandparent had the same hold on the original directory. No gain.
- **A directory created by an admin process on the user's behalf, or an
  admin-owned directory with an equal permissive DACL.** Accepted. With an
  equal DACL every user has exactly the rights they had on the original; the
  admin-only owner gives none to a standard user. No gain, apart from M3.
- **The admin-only owner list.** A standard user, or an administrator running
  unelevated, cannot make Administrators, SYSTEM or TrustedInstaller the owner
  of an object. Reading; not tried.
- **File-id shortcut against reuse.** Not safe on its own: S1.
- **Old journals without `parent`.** `parent` is `Option` with
  `#[serde(default)]` (`crates/purge-model/src/exec/op.rs:490-491`); such a
  move back is unchecked, as before the commit. `docs/DECISIONS.md` records it.
  A new acted move never journals `None`: without a readable parent it is
  `Blocked(CannotBackUp)` (`act_fs.rs:665-680`). A boot-time move journals
  `None` when the parent cannot be read (`locked.rs:222-227`); the facts come
  from a read-only handle that passed the gate, and no way was found for a
  standard user to force that.
- **`same_action` ignoring `parent`.** No mismatch that helps an attacker. The
  resumed act must find the item with the journalled file id at the journalled
  path, so it is in the directory at that path. Undo then checks against the
  journalled record, the earlier one. If the directory was swapped in between,
  the journalled record refuses it. The only loose case is a journalled `None`
  (above).
- **Registry.** Owner and DACL are read from the handle the values are then
  written through (`regbackup.rs:1967-2012`), so nothing can be swapped between
  check and write. There is no admin-only exception for keys; a key recreated
  with another admin owner is a conflict. A standard user who creates the empty
  key owns it, and the owner then differs unless the recorded owner was that
  user, in which case the content was theirs already. The subkeys are created
  with the recorded security.

## Not checked

- The complete S1 attack end to end, and it on ReFS (128-bit ids).
- Any run elevated: another owner, the admin-only exception, the fallback of
  `RecreateDir`.
- `gate::check_undo_path` itself (reparse points, ancestors, volume).
- Value restore and segment re-insert into a key somebody recreated (recorded
  as a known limit).
- The other changes of `0aa3633` (F3, F5 to F11).
