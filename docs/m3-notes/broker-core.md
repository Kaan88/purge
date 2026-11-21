# M3-BROKER-CORE: writer notes

Package: `bins/purge-broker` start, pipe, handshake, tables, lifetime. Branch `m3-broker-core`, cut from `baseline`
bfde762. Methods other than `engine.hello` and `broker.shutdown` are not here: they plug into `serve::Handler`
(M3-BROKER-FLOW, -EXEC, -UNDO, -PURGE). The binary wires `serve::Unwired`, which answers every other request with
a `runtime` error.

## Shape

| File | What |
|---|---|
| `start.rs` | the start checks of design 3.4, plus (S7) the client image `<dir>\Purge.exe` and every file in `<dir>\kb\baselines` judged per file; `report_exit` |
| `args.rs` | `--pipe <32 hex> --parent <pid> --parent-ctime <filetime>`, each once, nothing else |
| `link.rs` | trait `Link` (wait, identify, read, write, disconnect) and `Refusal` |
| `serve.rs` | `run(Wiring)`: accept and check, `engine.hello` first, request loop, `Handler`, `Consent`, `Host`, `Ctx`, `Limits` |
| `session.rs` | `Table`, `Tables` (sessions, scans, plans), `gone`, `unique_index` (M2), `program_hive_allowed` (S5) |
| `lifetime.rs` | `Clock`, `Parent`, `ExitReason`, exit codes, limits, `Closer` (closes an open dialog as Cancel) |
| `baseline.rs` | `BuildHandle` over the engine's `LocalBuild`, `LiveHost` (`engine.hello` from the machine) |
| `wire.rs` | `PipeLink`, `TaskDialogConsent`, `ProcessParent`: what `main.rs` wires in |
| `testkit.rs` | `cfg(test)`: in-memory link, fake clock/parent/build, `ScriptedConsent`, test handler, `Harness` |

Outside the package: `purge-win` `os::random_u64` (BCryptGenRandom) and `os::close_std_handles` (feature
`Win32_System_Console`); `purge-engine` `LocalBuild::request_stop` (checked before each cache part; a part in
progress is not interrupted). No cargo feature anywhere.

## Choices (DECISIONS candidates)

1. **Identify before reading** (R1 S1). `peer()` runs right after the client connects. `ReadFirst` and every failure to
   identify are a refused client. Verified on the dev host (identification level + static tracking is identified at
   once; a `cmd.exe` redirect client is `Unidentified`). The 5 s / small-cap fallback was not needed; after
   identification the first line has 30 s (`HELLO_WAIT`) and 4096 bytes (`HELLO_LINE_CAP`).
2. **Refused client**: disconnect, nothing answered (also for `other_account`: the binding "nothing is answered before
   `Peer::check` passed" wins over design 6.4's `other_account` error, so the UI sees a closed pipe and its own
   account pre-check names the case). Count is total, not consecutive; three end the broker with exit code 25.
   A client that connects and closes first, one whose first line is not `engine.hello` (any other request, a
   notification, garbage, over 4096 bytes), and one silent for 30 s all count.
3. **Exit codes**: 0 for every orderly end (shutdown, completed change, idle, parent lost, pipe lost); 23 bad
   arguments, 24 pipe name taken or not creatable, 25 three refused clients, 26 `--parent` is not the process claimed
   (pid or creation time), 27 pipe failure. 20 to 22 stay the start failures. Codes other than 0 go to the event log
   (event id = code).
4. **Order in `main`**: DLL search, start checks, arguments, parent opened and its creation time compared, pipe
   created (first instance), standard handles closed, baseline build started, serving. The parent handle is held from
   the start, so a parent that dies before any client connects ends the broker.
5. **Concurrency**: one supervisor thread (reads the line channel, answers `engine.hello` and `broker.shutdown`, watches
   parent, clock, build) and a thread per other request. One mutating request (set `Execute`) at a time, else `busy`;
   at most 8 non-mutating at once, else `busy`; a request id that is running is `-32600`. A job's end is
   queued *before* its answer is written, so a client that sends its next request at once is never `busy`.
6. **Ending**: completed change = `plan.execute`, `undo.run`, `journal.resume|rollback|retry_held`,
   `quarantine.purge` returning `Ok` with no session left in the tables: result, wait up to 5 s for the client to
   close, exit. The handler removes a session when its change is done (`tables.sessions.remove`). Idle is 10 minutes
   from the hello or the last request or request end, never while a request runs. After the decision to end, further
   requests get a `runtime` "the broker is closing".
7. **Loss**: parent or pipe lost sets the cancel flag of cancellable requests, fires the consent `Closer`, waits for
   every mutating request (no limit; answer dropped), gives a read-only request 10 s, then ends. `Ctx::notify` fails
   after the loss; `Ctx::cancelled` is true for cancellable and read-only code, a non-cancellable mutating request
   ignores it by its own choice.
8. **Consent trait**: `ask(pages, primary, closer) -> io::Result<Outcome>`; the implementation arms the `Closer` once
   its window is open. `Ctx::consent` returns `Declined` when the broker is ending, on error, and without asking.
9. **Baseline**: `engine.hello` carries the live build state; `baseline.changed` is sent when the state differs
   from the last one sent, with `rescan_offered` = scans added while the build was in progress, on `Done`. At the end the
   build is asked to stop before its next part and given 3 s; the process then ends without joining the build
   thread (`main` calls `process::exit` inside the thread scope): cache parts are written to a temporary name and
   renamed, so nothing partial is ever left.
10. **Hive rule** (R1 S5): `uninstall.prepare`, `leftovers.stored` and `leftovers.scan {program_id}` with a program
    id whose hive is not `HKLM` or `HKU:<checked SID>` answer `gone` (`program`) before the handler runs.
11. **Tables** are bounded (256 entries), ids come from `BCryptGenRandom`, re-drawn on collision or zero; a plan id is
    taken once (`Table::take`). `unique_index` is the check a handler makes before serving a scan whose candidate ids
    might repeat (M2).
12. **Start**: a missing or user-writable `Purge.exe` refuses the start (21): until the UI package deploys it, the
    installed broker cannot start; the VM tests copy a dummy file beside the broker.

## Test to refusal row map (design 3.3, 3.4, 3.6)

| Row | Test |
|---|---|
| 3.3 step 2: name exists, broker exits | `pipe::a_name_that_exists_is_taken_and_the_broker_would_exit` (`PipeError::NameTaken` -> exit 24 in `main`); purge-win `second_instance_fails`, `a_squatted_name_is_taken` |
| 3.3 step 4: pid | `pipe::a_client_with_another_pid_is_refused`; `serve::every_refusal_reason_is_one_refused_client` |
| 3.3 step 4: creation time | `pipe::a_client_created_at_another_time_is_refused`; same |
| 3.3 step 4: image `<dir>\Purge.exe` | `pipe::a_client_with_another_image_is_refused`; same |
| 3.3 step 4: same account (`other_account`) | `pipe::a_client_of_another_account_is_refused`; same |
| 3.3 step 4: exited, token differs | `serve::every_refusal_reason_is_one_refused_client` (reasons from `Peer::check`, tested in purge-win `peer_of_own_client_and_refusals`) |
| 3.3 step 4 + S1: not identifiable before first write | `pipe::a_client_that_cannot_be_identified_before_its_first_write_is_refused`, `pipe::an_identification_level_client_is_identified_before_it_writes_and_is_served` |
| 3.3 step 5: three failed clients | `pipe::three_refused_clients_in_a_row_end_the_broker`, `serve::three_refused_clients_end_the_broker`, `serve::a_good_client_after_refused_ones_is_served` |
| 3.3 step 6: hello first, nothing else answered | `serve::hello_comes_first`, `a_first_line_that_never_ends_is_refused_at_the_cap`, `a_hello_that_does_not_come_is_refused_and_one_that_comes_with_more_is_served`, `a_client_that_closes_before_hello_is_refused` |
| 3.3: parent held, `--parent` as claimed | `pipe::the_parent_must_be_the_process_that_was_named`, `args::*` |
| 3.4: not elevated reads no directory | `start::not_elevated_reads_no_directory`; `tests/start.rs` (unelevated, real binary: 20) |
| 3.4: own directory, own file, `kb` | `start::an_untrusted_install_never_reaches_the_store` |
| 3.4 + S7: client image, each KB file | `start::the_client_image_and_every_kb_file_are_judged` |
| 3.4: data root, store | `start::an_untrusted_data_root_is_never_opened` |
| 3.4: environment never read, planted dirs | `tests/start.rs` (unelevated); elevated variant `elevated_copies_are_judged_by_their_directory` (VM) |
| 3.4: standard handles closed | purge-win `os::std_handles_are_closed_and_cleared` (child process) |
| 3.6: one mutating request, busy | `serve::one_mutating_request_at_a_time` |
| 3.6: gone ids (session, scan, plan; plan used once) | `serve::unknown_removed_and_reused_ids_are_gone`, `session::*` |
| 3.6/S5: hive of another account | `serve::a_program_id_of_another_account_is_gone_before_the_handler` |
| 3.6: idle 10 minutes (fake clock) | `serve::idle_for_ten_minutes_ends_the_broker_and_a_request_restarts_the_count`, `idle_never_ends_a_running_request_and_counts_from_its_end`, `a_broker_nobody_connects_to_ends_when_idle` |
| 3.6: completed change, 5 s, other session | `serve::a_completed_change_ends_the_broker_after_the_client_closes`, `..._waits_five_seconds_...`, `..._with_another_session_open_does_not_end_the_broker`, `a_declined_change_does_not_end_the_broker` |
| 3.6: `broker.shutdown` | `serve::shutdown_exits_when_nothing_runs_and_says_no_while_something_does`; `pipe::an_identification_level_client_...` over a real pipe |
| 3.6: pipe lost, nothing running | `serve::pipe_loss_with_nothing_running_ends_the_broker_at_once`, `an_oversize_line_closes_the_pipe` (T13) |
| 3.6: parent lost, nothing running / before a client / waiting for hello | `serve::parent_loss_*`; real handle: `pipe::the_broker_ends_when_the_parent_process_ends` |
| 3.6: lost while a change runs | `serve::pipe_loss_while_a_change_runs_finishes_it_first`, `parent_loss_while_a_change_runs_finishes_it_first`, `a_write_that_fails_while_a_change_runs_is_a_lost_pipe` |
| 3.6: lost while the dialog is open | `serve::pipe_loss_with_the_consent_dialog_open_closes_it_as_cancel`, `parent_loss_with_the_consent_dialog_open_closes_it_as_cancel`, `no_dialog_opens_after_the_broker_decided_to_end` |
| 3.6: lost while a read runs | `serve::pipe_loss_cancels_a_running_scan`, `a_read_that_ignores_the_loss_is_waited_for_ten_seconds_only` |
| 3.6: build stops, no partial cache | `serve::the_build_is_asked_to_stop_at_every_end`, `pipe_loss_with_nothing_running...`; atomic parts: purge-index `cache.rs` `write_atomic` |
| `baseline.changed`, rescan offered | `serve::baseline_changed_is_sent_with_the_scans_made_during_the_build` |
| cancel | `serve::cancel_stops_a_cancellable_request_and_is_ignored_for_the_others` |

## Still needs the VM (the coordinator's elevated part)

- The broker elevated through `runas` (real UAC), serving `engine.hello` to the UI stub; `Purge.exe` beside it.
- `tests/start.rs` `elevated_copies_are_judged_by_their_directory` (updated here: needs a `kb` directory and a
  `Purge.exe`; first run).
- Identification before the first read from a real **medium** client of an **elevated** server (S1); N5 (a client
  cannot set its pipe pid); a low-integrity/AppContainer client refused at open; a squatter.
- A real `Purge.exe` as the client image against the broker's image check (path case, install under `-ProgramFilesDir`).
- The TaskDialog closed as Cancel by `Closer` on parent/pipe loss (`TaskDialogConsent`), and closing from the dialog's
  thread under UAC.
- A broker started through `runas` (first real elevated run): no console window appears (the binary is built for
  the Windows subsystem, `#![windows_subsystem = "windows"]`), and the consent TaskDialog is visible and in front
  (the launcher passes `SW_SHOWNORMAL`). S7 was found by reading; this is where it is confirmed.
- Local-baseline build started in the elevated broker and stopped by an exit in its middle (cache directory afterwards
  has no `.tmp` of a live build and no partial part).

## Open points

- Reasons are not sent to a refused client (see choice 2). If the UI should name `other_account`, the binding "nothing
  is answered before the check passed" needs an exception for an account-only mismatch.
- A handler that calls `ctx.consent` more than once per request is fine; two requests asking at once cannot happen
  (consent belongs to mutating requests).
- `HELLO_WAIT` 30 s and `READ_GRACE` 10 s are the writer's numbers.
- Supervisor answers (`busy`, parse errors, hello) are written inline: a client that never reads can hold the
  supervisor for one 30 s write timeout (it then counts as pipe loss).
- `Started.store` (the checked `StorageRoots`) is not used by the core; BROKER-FLOW takes it from `start::check`.
