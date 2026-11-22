# M3-UNDO: writer notes

Package: `history.get`, `undo.run`, `journal.pending`, `journal.resume`, `journal.rollback`,
`journal.retry_held` through consent. Branch `m3-undo`, cut from `baseline` 8be6293.
No `purge-rpc` type changed (no gen-dto).

## Shape

| File | What |
|---|---|
| `purge-exec/src/undo.rs` | `preview` (what an undo puts back, read as the run will), `UndoPreview`, `UndoExpect`, `undo_expecting` (the run, started only against the preview), `UndoError::{NotAsShown, PlanUnbound}`, `stands_changed` public. `undo` is `undo_expecting` without the guard |
| `purge-exec/src/recover.rs` | `Want`, `preview`, `RecoverPreview`, `resume_expecting`, `rollback_expecting`, `retry_held_expecting` (journal mark guard), `RecoverError::{NotAsShown, PlanUnbound, Refused, NeedsRecovery}` |
| `purge-exec/src/review.rs` | `bind_session` (plan from the session's own scan copy and journal), `check_intents` (journal intent equals the bound plan's op) |
| `purge-broker/src/backend.rs` | trait `Backend` (the store and the machine), `BackendError` -> the client's error, `stamp_of` (FILETIME to the dialog's stamp) |
| `purge-broker/src/history.rs` | `history.get`, `journal.pending`, `check_nothing_pending` (what `plan.execute` asks first) |
| `purge-broker/src/undo.rs` | `undo.run`; `UndoMethods<B>`: the one entry the broker's handler calls (`handles`, `call`, `check_nothing_pending`) |
| `purge-broker/src/recover.rs` | the three `journal.*` runs |
| `purge-broker/src/live.rs`, `live_host.rs` | `LiveBackend` over `purge-exec` and the live machine; deny-list and object backends as the rig CLI builds them (not linkable from `purge-engine`: its `purge-exec` is optional) |
| `purge-engine` `pipeline.rs` | `canonical_dirs` is `pub` (was `pub(crate)`), nothing else |

BROKER-FLOW wires it: `UndoMethods::new(LiveBackend::new(started.store, settings.purge_dirs))`, then in its
`Handler::call`: `if UndoMethods::<LiveBackend>::handles(&call) { return undo.call(ctx, call); }`, and
`undo.check_nothing_pending()?` before the dialog of `plan.execute`. Nothing else is shared; `lib.rs`
holds one block of `pub mod` lines at its top, `Cargo.toml` two added dependencies (`purge-guard`,
`purge-harvest`).

## Choices (DECISIONS candidates)

1. **The dialog is drawn from a preview and the run is bound to it.** `undo::preview` reads the session as `undo` will
   (same refusals, same selection, same dependencies) and returns the ops it will put back; the dialog is
   `view_restore` over exactly those ops of the session's own plan (`rebind_interrupted` of the scan copy and journal).
   The run is `undo_expecting(request, env, expect)`: it refuses with `NotAsShown`, before any write, unless the journal
   is at the preview's mark and the ops it goes through are the preview's. Recovery is the same with the journal mark.
2. **What the dialog lists.** Put back: not settled, with an intent, standing changed (`stands_changed`), with an inverse
   (`!is_irreversible`), in undo order. Ops the run goes through beyond that (decided before anything was changed,
   items without an inverse, journal-only records) change nothing; every M2 fidelity fixture asserts that
   (`tests/common` `undo`: an op `Restored` is an op the preview showed). For every shown op the journal's intent must
   equal the bound plan's `exec_op` (`check_intents`), so the text the dialog draws is the op the run acts on.
3. **Conflicts.** `RestoreFacts::conflicts` is "something is there now" (`PlaceTaken`: the item will be skipped), from a
   read-only look at the live file system and registry for file moves, directory removals, key deletes and value deletes;
   what cannot be looked at counts as taken. `WillOverwrite` is never used: the library never overwrites (a taken place is
   `DestinationExists` and the existing file is untouched: `an_undo_never_overwrites_what_stands_in_an_items_place_and_says_so`).
   Services, tasks, firewall rules and segment edits have no probe; the library reports their conflicts.
4. **Recovery facts** (`RecoverFacts`): resume = ops without a `done` plus the registry ops no flush vouched for; rollback =
   ops that stand changed and have an inverse, in undo order; a finished session with an interrupted undo = the ops its
   `undo_plan` had not reached (a put-back); an interrupted retry = the ops in flight; retry = the held ops. `effective`
   is what the library will do (a resume of a run that was being rolled back, or of an interrupted undo, is a put-back and
   the dialog says so); the call is the one asked. `done` = ops with a `done` record, `total` = header items.
5. **Recovery with nothing to change runs without a dialog**: only Purge's own records are missing (index entry,
   report, `commit` after the last `done`), or every selected op is one the run leaves alone (the view says
   `NothingToRun`). Without it a session in that state would block execute for ever. B4 now reads "every request that
   changes something outside Purge's store ends in a dialog" (review M3-R2 point 2), so this is within it: the preview's
   empty (or all-"leave alone") op list is what justifies it, and the run is bound to the journal mark the preview read
   (`an_unindexed_recovery_whose_journal_changed_after_the_preview_is_not_as_shown` in purge-exec).
6. **`undo.run` with nothing to put back** is a `runtime` error ("nothing in the selection can be put back"), not a
   dialog over nothing and not a silent `complete`.
7. **Pending**: `journal.pending` lists `Run`, `Undo` and `Retry` sessions (the ones with something to recover);
   `Unindexed` and `Unstarted` are not listed and do not block (as the rig CLI's `check_nothing_pending`); a damaged journal is
   `store_integrity` wherever a pending session would stop a request, ahead of `needs_recovery`.
8. **Outcomes** are the CLI's: `undo_conflicts` when an op ended in conflict or failed, `partial` for a recovery whose run
   did not commit completely or whose retry left an item held, `not_closed` (wins) when the session was not recorded
   (journal not finished, report or index entry missing). A `Failed` undo op is counted in the outcome but, being
   no `UndoConflict`, is not a row of `conflicts[]` (History shows it).
9. **Ids**: the only ids a request carries are an executor `SessionId` (grammar fixed, re-derived: a path does not parse)
   and `OpId`s. They are looked up in the store through its checked handles; an unknown session is `gone(session)`, an
   unknown op `gone(candidate)`. Item selection by op is turned into candidate ids from the session's own journal.
10. **`undo.progress`** is sent twice at most (before the run, with the op count; the library has no progress hook).
    The `journal.*` methods send no progress (none is declared for them).

## Attack to code and test (M3-R2)

| Attack | Code | Test |
|---|---|---|
| A restore or recover runs something the dialog did not show | preview -> view -> run against the preview (choice 1); `check_intents`; count guards (`view.counts` equals the preview's ops) in `undo.rs`, `recover.rs` | `execute::tests`: `an_undo_preview_names_the_ops_the_run_then_puts_back` (run ops equal the shown ops), `an_undo_that_is_not_what_the_preview_read_is_refused_before_it_changes_anything` (another selection's ops, a changed journal), `the_ops_a_run_goes_through_beyond_the_preview_change_nothing`, `a_resume_preview_...`, `a_rollback_preview_...`, `an_interrupted_undo_is_previewed_...`, `a_retry_preview_...`; every fidelity and crash fixture runs through `Rig::undo` / `Rig::resume` / `Rig::rollback` (`tests/common`), which assert "every op restored was shown" and "every op a recovery changed was named" (`--features test-support[,fault-inject]`: `roundtrip`, `m1b_exec`, `crash` incl. `every_fault_point_recovers_...`); broker: `a_preview_the_dialog_cannot_describe_is_never_run`, `a_recovery_the_dialog_cannot_describe_is_never_run`, `a_session_that_changed_after_the_dialog_is_not_undone`, `..._recovery_dialog_is_not_recovered` |
| Restoring over a conflict silently | library never overwrites; conflicts are attention entries, gated by the verification box | `an_undo_never_overwrites_...` (real files), broker `an_undo_over_a_taken_place_lists_it_as_attention_and_needs_the_box`, `a_taken_place_that_is_not_part_of_the_run_is_not_shown` |
| Privilege left enabled beyond its scope | this package enables nothing; the restore privilege stays inside purge-win's thread-scoped closure (M3-WIN-PRIV, check-deps rule 4e) | broker `no_privilege_or_impersonation_outlives_a_request` (handler thread after an undo); VM: `elevated_privilege_scope`, `elevated_write_back_*` |
| A session corrupted by killing the UI at each step | dialog closes as Cancel on pipe or parent loss (nothing runs); after the approval the run is finished and recorded, the answer dropped; the journal is the library's write-ahead one | broker `a_dialog_closed_by_the_loss_of_the_pipe_runs_nothing`, `..._parent_runs_nothing`, `an_approved_undo_finishes_when_the_ui_is_killed_during_the_run`, `the_ui_killed_at_every_step_of_a_recovery_leaves_no_half_state`; `crash` rows through the guarded path |
| Ids not from the broker's own tables | `SessionParams`/`UndoParams` only carry `SessionId` and `OpId`; looked up in the store; unknown is `gone` | broker `a_session_that_is_not_an_executor_id_never_reaches_the_backend` (path-like, empty, extra member, none reach the backend), `an_op_that_is_not_in_the_session_is_gone_and_nothing_is_asked`, `history_get_answers_...`; `execute::tests::an_undo_preview_refuses_what_the_run_refuses` |
| Every method ends in a dialog | `undo.rs`, `recover.rs`; the exception is choice 5 | broker `undo_all_asks_first_...` (nothing runs before the answer), `a_cancelled_undo_...`, `a_cancelled_recovery_...`, `a_resume_asks_first_...`, `a_rollback_and_a_retry_have_their_own_dialogs`, `what_recovery_will_do_is_what_the_dialog_says_not_the_method_name`, `a_recovery_that_changes_nothing_on_the_machine_runs_without_a_dialog` |
| A pending session lets execute run | `history::check_nothing_pending` | broker `an_interrupted_session_blocks_execute_and_a_damaged_one_is_store_integrity` |
| A second mutating request while the dialog is open | `serve` (busy) | `a_second_mutating_request_while_the_dialog_is_open_is_busy` |
| Hostile names in the dialog | `consent::text` (M3-CONSENT) | `hostile_names_are_escaped_in_the_restore_dialog` |

## Needs the VM or elevation (not faked)

- `LiveBackend` end to end on an elevated broker: previews and runs on real sessions of the installed store, the deny-list
  built from the live machine, service/task/firewall backends, `SystemPendingRenames`, the Restart Manager.
- The restore and recover dialogs rendered by the real TaskDialog (paging, the box, the arming delay, Esc).
- `undo_fidelity` 100 % on the M2 fixtures through the broker over the pipe: the library half runs here (all fixtures through
  `preview` + `undo_expecting`); the rest is the elevated end-to-end run (service owner restore with the scoped
  `SeRestorePrivilege`).
- The conflict probe against the live registry and file system (`LiveBackend::places_taken`).

## Open points

- **"Reconcile at broker start"** (scope line): not done as a start hook. M2 reconciles inside every undo/resume/rollback
  run (`Driver::reconcile`), so a pending boot-time move is settled at the start of the first recovery or undo of its
  session. A start hook would move a foreign object found in quarantine back (`MismatchMovedBack`) with no dialog. Note
  that the same reconcile inside an approved run can do that move; it is not a line of the dialog.
- BROKER-FLOW and EXEC will want the deny-list and backends of `live_host.rs` too; the CLI has its own copy in
  `cli/exec.rs` (behind `rig-exec`). One home for both would remove the duplicate.
- `Failed` undo ops are not rows of `conflicts[]` (the DTO row is an `UndoConflict`).
- The conflict probe over-warns for a directory that exists again as the recorded one (the library would say
  `AlreadyRestored`).
- An `Unindexed` session (finished, index entry or report missing) is not offered by `journal.pending`; `journal.resume`/`rollback` on it
  runs the bookkeeping without a dialog (choice 5). An `Unstarted` one (no journal) is refused (`Refused`) and left as it is, as in M2.
