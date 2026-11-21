# M3-EXEC: writer notes

Package: `plan.execute` (`execute_bound`, the dialog from the frozen plan, object binding, progress, outcomes),
plus the two small items (the purge and undo handlers wired into the binary, an outcome on `uninstall.observed`).
Branch `m3-exec`, cut from `baseline` ae35e06 and merged with `baseline` 3876f0d (M3-UNDO).
`purge-rpc` types changed (two optional fields; `gen-dto` run, `RpcModels.cs` updated).

## Shape

| Piece | What |
|---|---|
| `purge-exec` `execute::execute_bound(plan: Arc<BoundPlan>, settings, &Fingerprint, env, restore)` | runs the very `Arc` it is given; binds nothing again. `execute` is `bind` + the same driver (`Run::start_bound`, `drive`), so the two give equal reports (M2 mixed fixture: `execute_and_execute_bound_give_equal_reports`) |
| `purge-exec` `plan_in::unbound_objects(&BoundPlan, &Fingerprint)` | moved here from the rig CLI; the rig's `exec --fp` and `execute_bound` both call it. `ExecError::ObjectsUnbound(ids)` is raised before the session exists |
| `purge-broker` `execute.rs` | `plan.execute`: `ExecBackend` (the executor and the clock), `run`, the outcome and error mapping |
| `purge-broker` `exec_live.rs` | `LiveExec`: deny-list and object backends from `live_host.rs` (the one home, no third copy), `m1b_lists` judged at execute time, `SystemRestore`, `execute_bound` |
| `purge-broker` `broker.rs` | `BrokerHandler<B>`: the one dispatch the binary wires: `Purger` (M3-PURGE) -> `UndoMethods` (M3-UNDO) -> `plan.execute` (after `check_nothing_pending`) -> `Flow` |
| `purge-broker` `scan.rs`, `plan.rs` | `Scan` and `Plan` carry the scan's `Arc<Fingerprint>` (the object binding of the run); `Plan` also carries the app name |
| `purge-rpc` | `PlanSelectedParams.allow_irreversible` (bool, default false), `ObservedParams.outcome` (optional `RunOutcome`) |

## The three contracts BROKER-FLOW left

1. **`Plan::release`.** `plan.execute` takes the plan (a plan id works once) and gives the scan's claim back
   **whenever nothing ran**: a declined dialog, a pending session, a dialog that cannot be drawn, an executor that
   refused to start. Refinement of the note's "call release after take": once the executor *started*, the claim stays.
   The scan describes a machine that has changed; a second plan from it would be a second run of the same items,
   so the user scans again (`a_plan_id_runs_once_and_its_scan_is_spent`). The spent uninstall session is removed
   from the table (design 3.6: a completed change with no session left ends the broker).
2. **The irreversible acknowledgement (decision).** The design does not settle how a package removal is acknowledged
   in a broker plan (ENGINE_PLAN 3.1 only says irreversible verbs need "a fresh prompt naming every item"). Chosen:
   `plan.create` takes an optional boolean `allow_irreversible` (selected form only; the preselected form never holds a
   package). It is frozen into the `BoundPlan` like everything else (B3). Off (the default, and what every existing
   client sends): packages are "Leave alone" in the dialog and are skipped by the executor. On: the consent dialog,
   drawn from that frozen plan, names each package as an attention entry, changes to "Remove N ... K cannot be put back",
   and gates its button behind the verification box. **The dialog is the acknowledgement; the flag only lets it be
   asked.** A client that sets the flag cannot make anything run without the user ticking the box and clicking the
   primary button. Conservative in that nothing irreversible is reachable without both the opt-in and the dialog, and
   a plan without a runnable item opens no dialog (`NothingToRun`).
   Tests: `a_removal_without_undo_runs_only_after_a_dialog_that_names_it`, `a_plan_that_cannot_run_anything_opens_no_dialog`.
3. **Dialog from the frozen plan.** `execute_plan` builds `view::view(&bound, &Facts)` from the `Arc<BoundPlan>` in the
   table, checks `describes_plan` and that the view's code is the plan's code, shows it, and only then hands that same
   `Arc` to the executor (`Arc::ptr_eq` asserted in `an_approved_plan_runs_the_plan_object_the_dialog_was_drawn_from`).

## Other choices

- **Object binding at three places.** `plan.create` refuses a service, task or firewall rule the scan's own fingerprint
  does not record with the digest the scan saw (so the review page never offers it); `execute_bound` refuses it again
  before it creates a session (the type needs a fingerprint: the broker path cannot omit it); the act-time gates compare
  each object with the live machine (M2, unchanged). The rig's `execute` keeps its optional `--fp`.
- **Restore point** is the request's enum. The dialog's "Windows is asked for a restore point first" line is shown when
  the setting is `always`, or `high_risk` and the plan's items are high-risk by `prepare::risk_reasons` over the
  candidates (a forced-mode scan is). The executor may find more risk when it reads a registry tree; it then asks without
  the dialog having said so, which only adds a restore point.
- **"Restorable until"** is the broker's clock plus `RETAIN_QUARANTINE_DAYS` (30): the earliest class.
- **M1b lists** (`GoneLists`) are computed by `LiveExec` at execute time over a fresh inventory, never taken from the plan;
  `plan.settings` holds only the account and the program roots (as `plan.create` froze them).
- **After the approval the handler never looks at `ctx.cancelled()`.** Before it, a lost pipe or parent closes the dialog
  as Cancel (core `Closer`). The journal is the library's write-ahead one: a run killed anywhere is recoverable
  (`journal.*`, M3-UNDO), and a session that was not recorded completely is `not_closed`.
- **Outcomes**: `not_closed` (journal not ended, report or index entry missing) wins; else `partial` (not committed, or an
  item not done/vanished/`NoLongerEmpty`); else `complete`. Held items (`HeldRetry`) are listed with their lockers.
- **`exec.progress`**: `session` (0 of N), `item` before and after each item (done = finished items), `aborting`.
- **Errors**: `ObjectsUnbound`/`Plan` -> `plan_refused` (per id for objects), `NeedsElevation` -> `not_elevated`, a cap ->
  `cap_exceeded`, store integrity -> `store_integrity`, anything else `runtime`.

## `uninstall.observed` outcome (item b)

`ObservedParams.outcome` is optional. `ran_ok = outcome.is_none_or(is_success) && verify_gone.passed`. A reported
failure, cancel or time-out forces the forced scan with nothing preselected even if the program is gone; a reported success
never skips the broker's verify-gone; an absent field keeps the old rule. Tests: `observed_outcome_can_only_make_the_scan_safer`,
`observed_refuses_an_outcome_it_does_not_know`.

## Attack to code and test (M3-R2)

| Attack | Code | Test |
|---|---|---|
| runs something the dialog did not show | one `Arc<BoundPlan>`: `execute::execute_plan` (view -> `describes_plan` -> code check -> ask -> `ExecJob.plan` is the same `Arc`); `execute_bound` binds nothing | `an_approved_plan_runs_the_plan_object_the_dialog_was_drawn_from`, `a_removal_without_undo_runs_only_after_a_dialog_that_names_it`, `a_plan_runs_its_own_scans_object_and_not_another`; purge-exec `execute_and_execute_bound_give_equal_reports` |
| runs a plan from another scan | the plan table holds the frozen object per id; typed ids; `plan.create` accepts only ids of its own scan (BROKER-FLOW) | `a_plan_runs_its_own_scans_object_and_not_another`, `ids_that_are_not_this_brokers_plans_never_open_a_dialog` (foreign id, scan id, session id, a path, empty, extra member), flow `plan_create_refuses_ids_that_are_not_of_this_scan` |
| runs a plan twice | `Table::take` in `execute::run`; the scan stays claimed after a run | `a_plan_id_runs_once_and_its_scan_is_spent`, `a_declined_dialog_changes_nothing_and_the_scan_can_be_planned_again`, `a_second_execute_while_the_dialog_is_open_is_busy_and_keeps_its_plan` |
| object replaced between scan and execute | `plan_in::unbound_objects` at `plan.create` and in `execute_bound` (digest + owner against the scan's fingerprint); act-time gates compare the live object (M2) | `a_system_object_the_fingerprint_does_not_vouch_for_is_never_planned` (none, other owner, replaced digest, vouched), `an_executor_that_refuses_to_start_changes_nothing_and_says_why`; purge-exec `a_selected_object_must_be_vouched_for_by_the_fingerprint_with_the_plans_digest`, `execute_bound_refuses_an_unvouched_object_before_a_session_exists`; the act-time comparison is M2's own (`act_service`, `act_task`, `act_firewall` tests) |
| UI killed with the dialog open | `Ctx::consent` + `Closer`: Cancel, nothing runs | `a_dialog_closed_by_the_loss_of_the_pipe_runs_nothing`, `..._parent_runs_nothing` |
| UI killed after the approval / during the run | the handler ignores cancellation after the approval; the serving loop waits for a running mutating request | `an_approved_run_finishes_when_the_ui_is_killed_during_it`, `..._parent_dies_during_it` |
| UI killed before the request / at the pending check | nothing was taken or run | `an_interrupted_session_blocks_execute_before_any_dialog`; core `serve` tests |
| UI killed mid-run, session consistent and journaled | the library's write-ahead journal (`Run`, `recover`) | purge-exec `crash` rows (`--features fault-inject,test-support`); VM for the real pipe (below) |
| a pending session lets execute run | `UndoMethods::check_nothing_pending` before the dialog | `an_interrupted_session_blocks_execute_before_any_dialog` (open: `needs_recovery`, damaged: `store_integrity`) |
| the client raises the irreversible acknowledgement | a boolean only offers; the dialog gates the button | `a_removal_without_undo_runs_only_after_a_dialog_that_names_it` |
| every package reachable through the one dispatch | `BrokerHandler::dispatch` | `every_packages_methods_are_wired_into_the_one_handler` (`quarantine.expiring`, `journal.pending`, `history.get`, `leftovers.stored`, `plan.execute`) |

## Needs the VM or elevation (not faked)

- `LiveExec` end to end on an elevated broker: the live deny-list, `LiveObjects` (services, tasks, firewall), Restart Manager,
  `SystemPendingRenames`, `SystemRestore`, `m1b_lists` over the real inventory, a real store. The acceptance: one app from
  Uninstall to quarantine through the real dialog, and its report equal to the rig CLI's for the same plan (compare plan hash and
  the report's items).
- The real TaskDialog for the quarantine variant with `allow_irreversible` (warning icon, box, paging) and `consent.shown`.
- The UI killed at each step over a real pipe with a real run (also the `Closer` on the real dialog).
- An object replaced after the scan on a real service, task and firewall rule (the act-time gates, through the broker).
- `exec.progress` rate and the 5 s close wait after a real run.

## Open points

- **`uninstall.observed` then `post` fails.** After a medium-route run the broker's fingerprint had no
  uninstall window (only `uninstall.run` recorded one), so `leftovers.scan` in `post` mode answered the
  pipeline's `--mode post needs a fingerprint with a completed uninstall window` as a `runtime` error.
  **Resolved (M3-GLUE):** `observed` records the window, from `prepare`'s harvest to the observation, when
  the broker's verify-gone passes and the reported outcome is not a failure; every other case stays a
  forced scan with nothing preselected. Tests: `observed_records_the_window_a_post_scan_needs`,
  `a_failed_observation_records_no_window_and_scans_forced`.
- The UI sends `outcome` on `uninstall.observed` (M3-GLUE); it does not send `allow_irreversible` yet.
- The M1b exemption lists are judged when the run starts, not when the dialog is shown (seconds to minutes apart).
- `plan_in::bind` runs at `plan.create`; `execute_bound` trusts that object (that is B3). A `BoundPlan` cannot be built outside
  `bind`/`rebind`, so the broker cannot hand the executor a plan `bind` did not check.
- `RecordingFlow` in `flow_tests.rs` still stands in for `plan.execute` in the BROKER-FLOW tests (it only takes the plan and
  releases the scan); the real handler is tested in `exec_tests.rs`.
