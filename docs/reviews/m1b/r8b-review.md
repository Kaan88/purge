# R8b review: f000afd..c9eb0ab (engine answers to R8 S5, S6, S7, M1, M2), branch worktree-agent-a9cb7a3cb96301d5c

**Verdict: merge as is; S1 (scorer list, one line in `vm/truth/m1b-exec.sh`) must land before the E1 run counts.
0 blockers, 1 should-fix, 5 minor.** The new op stays inside the backed-up subtree, the retry converges, the S6
conclusion is right, and the outcome kinds the scorer reads are unchanged.

Checked: the full diff; the callers in `undo.rs`; `reg_write.rs` open / create / link paths. Run in the worktree, in
an **elevated** shell (so the unelevated `else` arms of two tests were not exercised here):
`cargo test -p purge-win --features write,com --lib the_creating_handle` (1 pass);
`cargo test -p purge-exec --features fault-inject,test-support --lib -- sddl_parts write_back_ops` (pass);
`--test act_service` (59 pass, 3 ignored); `--test act_service -- --include-ignored --test-threads=1 --exact` with
the two `elevated_write_back_*` names (2 pass). Not run: `rig_live_delete_and_recreate_round_trip`, the rig
self-test, anything in a VM.

## B (blockers)

None.

## S (should fix)

**S1. R8 S7 is half closed: the scorer does not require the two new elevated tests.**
`vm/truth/m1b-exec.sh:96` (`ELEVATED`, `require_names` holds only `rig_live_delete_and_recreate_round_trip`) against
`vm/truth/m1b-exec-cases.json:104` (three names) and `vm/rig-m1b-exec.ps1:582-583` (`--include-ignored --exact
<names from the cases file>`).

- The rig runs what the cases file names; the scorer passes E1 on its own list (`:444-446`). A new test that runs
  and fails is caught (`bad`, exit code). A new test that does not run is not.
- Scenario: a test is renamed, or the cases line is edited. libtest's `--exact` with a name that matches nothing
  runs fewer tests and exits 0 (confirmed here: an unknown name next to the two real ones gave "2 passed", exit 0).
  E1 passes with the SYSTEM-owner arm not exercised, which is the state S7 described.
- So yes, line 96 must change: add `elevated_write_back_restores_a_system_owned_auto_inherited_key` and
  `elevated_write_back_converges_on_a_system_owned_key_after_an_interrupted_attempt` to `require_names`. Better:
  let the scorer also fail when a `require_names` entry of the cases file is missing from `ELEVATED` (or the other
  way round), so the two lists cannot drift again.
- Rig-side, outside this commit's scope; it does not block the merge, it blocks counting E1.

## M (minor)

**M1. A key opened again never gets its recorded owner when the DACL in force grants no `WRITE_OWNER`, also
elevated.** `crates/purge-exec/src/act_service.rs:2944-2962` (`set_recorded_security`),
`crates/purge-win/src/reg_write.rs:1070-1075` (no privilege at the open).

- Scenario (elevated, the production case): recorded `O:SYG:SYD:PAI(A;CI;KR;;;BA)(A;CI;KA;;;SY)`. Attempt 1 creates
  the key without the owner (1307 arm) and the process ends before the security write. Attempt 2: the open with
  `WRITE_OWNER` is refused, the `WRITE_DAC` open succeeds (the creator owns the key), the DACL is set alone. End
  state: owner Administrators instead of SYSTEM, outcome `Restored` with the note. The uninterrupted run ends with
  owner SYSTEM. `write_back_converges_on_a_leftover_key_it_cannot_open_for_write_owner` passed in the elevated
  shell with exactly this result, so the privilege held is not used.
- Second shape: an SCM-made key owned by SYSTEM whose DACL gives administrators no `WRITE_DAC` and whose group or
  DACL is not the recorded one: both opens are refused, `VerifyFailed` on every attempt. Retryable, never
  converges (before: `ValueDiffers`). No worse than before.
- The commit message's "gets the whole recorded descriptor, owner included" holds only where the DACL grants
  `WRITE_OWNER` (the elevated test uses `KA` for BA).
- Fix, if wanted: do the reopen under the same private impersonation copy with `SeRestorePrivilege` and
  `REG_OPTION_BACKUP_RESTORE`. This widens "the one privilege, for the single `NtSetSecurityObject` call"; if that
  is not wanted, keep it and state in the doc of `set_recorded_security` that a resumed attempt may leave the
  creator as owner. The note already makes it visible.

**M2. In the own-attempt path a descriptor someone changed between two attempts is replaced without a word.**
`act_service.rs:1746-1751` (`write_back_ops`), `:2176-2193` (`own_partial_restore`), `:2345`.

- `own_partial_restore` checks identity and that the live key holds nothing the backup lacks; it does not look at
  descriptors (or value data). An attempt that ended `Failed{VerifyFailed}` can be retried days later.
- Before this commit such a key ended `ValueDiffers` (state kept, named). Now it is set to the recorded descriptor
  and the undo is `Restored`. Values of backup keys have been overwritten the same way since R2b, and the result is
  the state the backup records, so this is consistent, not a new class of write.
- The fresh path is safe: `LiveServices::read` (`:2673-2698`) fails when the key exists without an SCM service, so
  every key present at the write-back was made by the SCM inside this `run_undo`.
- Nothing can reach a key outside the subtree: only backup paths with `i != 0` are named; the parent is opened
  component by component with the link refusal (`open_below` -> `open_path`), the leaf is checked for `\`, opened
  with `REG_OPTION_OPEN_LINK`, and `set_security` refuses a link.
- Fix (optional): on an attempt with `create = None`, add the paths that got a `SetSecurity` to the outcome detail.

**M3. The module contract of `reg_write.rs` still says the security write is reachable only on a key this process
created.** `crates/purge-win/src/reg_write.rs:20-24` ("reachable solely through the value returned by
`WKey::create_subkey`"). `reopen_created_subkey` (`:1070`) is public and opens any existing direct subkey with
`WRITE_DAC`; "the caller establishes that the key is its own". Fix: correct the module doc, and name the one caller
and its evidence (`own_attempt` and `live_within_backup`, or a key the SCM made in the same `run_undo`).

**M4. Detail length.** `act_service.rs:2852-2866`: the M1 error joins every failure, then the left-out count, then
the notes; `journal_detail` cuts an `undo_done` at 2048 bytes, so with many failures the count and the owner notes
are what is lost. Put the counts first. `act_service.rs:2487` with `journal/writer.rs:642-658`: a `ValueDiffers`
conflict now carries the notes and `undo_conflict` does not cut its detail; bounded by the number of backup keys.
Fix: pass it through `journal_detail` as well.

**M5. The module-level resume tests do not go through the code that failed.** `tests/act_service.rs:1364`, `:1422`:
the leftover is put into the fake by hand, `own_attempt` is passed as `true`, and `FakeServices::write_back`
(`act_service.rs:3482-3543`) still stops at its first error, so it models neither the interruption nor R8 M1. The
real behaviour is covered by the scratch-key tests (`:1944`, `:1973`, `:2006`, `:2081`), which use the access mask
`LiveServices::write_back` opens the root with; that is enough for the merge. No K13 fault point lies inside the
write-back (as R8 S5 said); a point after the first `CreateKey` would let the gate reach it.

## N (notes)

**N1. S5.** `write_back_ops` emits `SetSecurity` before the values of the same key and before its children;
`set_recorded_security` uses the same `restore_key_security`. Idempotent: one successful `NtSetSecurityObject` call
per key, a refused call changes nothing, a second run reads the recorded descriptor and writes nothing (third pass
`write_back_ops == []` asserted on a real key). A key whose owner alone cannot be set gets a `SetSecurity` and a
note on every attempt and never an error. After `Restored`, `prepare_undo` answers `AlreadyRestored`. `WriteBack`
is not journalled; `undo.rs:1050-1057` (how `own_attempt` is read) is untouched; no journal or schema change.

**N2. S6.** The conclusion is right. `NtSetSecurityObject` is checked against the access granted to the handle
(`WRITE_DAC` for the DACL, `WRITE_OWNER` for owner and group); the handle `RegCreateKeyExW` returns for a new key
carries the access asked for (`reg_write.rs:1028`), whatever descriptor the key is created with. Only the owner's
value is validated separately (1307, `SeRestorePrivilege`). The R8 scenario therefore does not occur, and
`create_recorded` keeping the recorded DACL in force from creation is the better choice (no window with a wider
DACL). `the_creating_handle_sets_security_whatever_the_dacl_in_force` is a real test: the DACL in force gives the
token `KR` only, the whole descriptor, group, owner and DACL are set through the creating handle, and a second
handle is refused `WRITE_OWNER`. `write_back_restores_a_descriptor_whose_dacl_grants_no_write_owner` covers both
creation arms through `write_back_below`; its SYSTEM arm passed elevated here.

**N3. M1.** A key whose descriptor could not be set still exists with the recorded DACL from creation (flags and
owner aside), so the values and subkeys written after the failure are not exposed more widely than recorded;
children are created with their own explicit descriptor, not derived from the parent. Only writes at or below a
key that was not created are left out, and counted. The attempt ends `Failed{VerifyFailed}` with every failure
named, `own_attempt` holds for the next one, which emits `SetSecurity` for the key. The half-restored tree is
reported and converges. The error's kind and Win32 code are the first failure's; `run_undo` reads only code and
detail.

**N4. M2.** `ServiceBackend::write_back` has three implementors (`LiveServices`, the fake, `tests/m1b_exec.rs:316`),
all updated. Notes reach the detail of `Restored`, of `ValueDiffers`, of the flush failure and (inside the error
text) of a failed write-back; they are lost only when the capture after the restore fails. `done_noted` already
journalled a detail for service undo. Outcome kinds are unchanged; `m1b-exec.sh` and `rigtool` (`fidelity.rs:1032`,
`execdiff.rs`) read `outcome.kind` and codes, never the detail.

**N5. Existing behaviour.** The first-attempt path is unchanged except: an SCM-made subkey whose descriptor is not
the recorded one is now set (before: `ValueDiffers` when group or DACL differed, ignored when the owner differed).
When only the owner differs no error can result, at worst a note. `create_recorded` and the 1307 arm are the old
code moved. The earlier tests moved to `tests/act_service.rs` with the same assertions plus the notes.

## Summary

| Class | Count |
|---|---|
| B | 0 |
| S | 1 |
| M | 5 |

Merge c9eb0ab as is. Before the G6 / E1 rerun, add the two test names to `ELEVATED` in `vm/truth/m1b-exec.sh:96`
(S1). M1 needs a decision (privilege at the reopen, or a documented limit); M2 to M5 are doc and report polish.
